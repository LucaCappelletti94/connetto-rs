//! Share-key deadlines stay active across network and content waits.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use core::convert::Infallible;
use core::future::{Future, ready};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use base64::Engine as _;
use connetto_client::away::{Clock, SystemClock};
use connetto_client::reconnect::{ReconnectPolicy, TransportFactory};
use connetto_client::{
    ClientBuilder, ClientError, ContentPlace, Custody, FirstThen, Gate, Grant, HeldCredential,
    Located, ReplicaKey, ReplicaPlace, ShareKeyFuture, ShareKeySet, ShareKeyStore, SyncSchema,
};
use connetto_core::Cursor;
use connetto_core::PROTOCOL_VERSION;
use connetto_core::auth::CapabilitySubject;
use connetto_core::messages::{
    BulkMessage, ContentTicketGrant, ControlMessage, FullResyncReason, FullResyncRequired,
    Handshake, HandshakeAck, MutationApplied, MutationHeader, MutationPatch, ReplaceShareKeys,
    ShareKeysReplaced, SnapshotBegin, SnapshotEnd, Subscribe, SubscriptionPriority,
    SubscriptionSpec, WriterGrant,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{IncomingFrame, MaybeSend, ReplicaKeyStore, Transport};
use connetto_file_client::{BrowserHttp, BrowserStore, ContentArchive};
use connetto_file_core::{FileIdHasher, MimeClass};
use connetto_web::content_wire::{ContentFrame, mime_code};
use connetto_web::relay::{HubReconnect, RelayHub};
use connetto_web::workers::DB_ALIVE_LOCK;
use connetto_web::{MessageTransport, locks};
use diesel::Connection;
use diesel::connection::SimpleConnection;
use diesel_sqlite_session::SqliteSessionExt;
use futures_channel::{mpsc, oneshot};
use futures_util::StreamExt;
use futures_util::future::{AbortHandle, Abortable, FutureExt};
use js_sys::{Array, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{DedicatedWorkerGlobalScope, MessagePort};

#[expect(
    dead_code,
    reason = "the fixture is shared with the archive suite, whose tests use helpers this one does not call"
)]
#[path = "content_archive/support.rs"]
mod support;

use support::{install_blocked_content_transport, install_content_transport, timeout_ms, until};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const SKD_SUBJECT: &str = "doc:7f3a9c1d";
const SKD_DDL: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT NOT NULL); \
                        CREATE VIEW visible AS SELECT * FROM notes WHERE owner = \
                        current_app_user() OR instr(',' || current_app_subjects() || ',', \
                        ',' || owner || ',') > 0;";
const PHOTOS_DDL: &str = "CREATE TABLE photos (id INTEGER PRIMARY KEY, content_id BLOB NOT NULL)";

fn skd_schema() -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            "-- connetto:major 1",
            "",
            SKD_DDL,
            Vec::<(String, String)>::new(),
            vec!["visible".to_owned()],
            None::<&str>,
        )
        .expect("the source declares major 1"),
    )
}

/// A share grant with an absolute expiry.
fn mint(seconds: i64) -> Grant {
    let payload = format!("{{\"sub\":\"{SKD_SUBJECT}\",\"exp\":{seconds}}}");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    Grant::new(format!("header.{payload}.signature"))
}

fn seconds_now() -> i64 {
    i64::try_from(SystemClock.wall().as_secs()).expect("Unix seconds fit i64")
}

fn monotonic_ms() -> f64 {
    js_sys::global()
        .unchecked_into::<DedicatedWorkerGlobalScope>()
        .performance()
        .expect("worker clock")
        .now()
}

#[derive(Default)]
struct SwapLog {
    closed: Cell<bool>,
    died: Cell<bool>,
    mutations: Cell<u32>,
    replacements: RefCell<Vec<ReplaceShareKeys>>,
    swap_at: RefCell<Vec<f64>>,
    request_at: RefCell<Vec<f64>>,
    replaced_acks: RefCell<Vec<String>>,
}

impl SwapLog {
    fn close(&self) {
        self.closed.set(true);
    }

    fn mutations(&self) -> u32 {
        self.mutations.get()
    }
}

enum Tickets {
    /// Hold each requested ticket.
    Held(Rc<RefCell<Vec<String>>>),
    /// Grant each requested ticket.
    Grants(Rc<RefCell<Vec<String>>>),
}

/// A scripted transport that acknowledges mutations and share-key replacements.
struct Upstream {
    log: Rc<SwapLog>,
    tickets: Tickets,
    dead: Rc<Cell<bool>>,
    slow_subs: Rc<Cell<bool>>,
    subs: Rc<Cell<u32>>,
    handshakes: Rc<Cell<u32>>,
    incoming: mpsc::UnboundedReceiver<IncomingFrame>,
    answers: mpsc::UnboundedSender<IncomingFrame>,
}

impl Upstream {
    fn live(log: Rc<SwapLog>, tickets: Tickets) -> (Self, mpsc::UnboundedSender<IncomingFrame>) {
        Self::live_with(log, tickets, Rc::new(Cell::new(false)))
    }

    /// A fake whose stream end the test controls with `dead`.
    fn live_with(
        log: Rc<SwapLog>,
        tickets: Tickets,
        dead: Rc<Cell<bool>>,
    ) -> (Self, mpsc::UnboundedSender<IncomingFrame>) {
        let (answers, incoming) = mpsc::unbounded();
        let ack = ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: "skd-upstream".to_owned(),
            session_token: "skd-upstream".to_owned(),
            resume_token: "skd-upstream".to_owned(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: None,
            initial_credits: 64,
            writer: Some(WriterGrant {
                number: 1,
                frontier: 0,
            }),
        });
        answers
            .unbounded_send(IncomingFrame::Control(ack))
            .expect("queue handshake ack");
        (
            Self {
                log,
                tickets,
                dead,
                slow_subs: Rc::new(Cell::new(false)),
                subs: Rc::new(Cell::new(0)),
                handshakes: Rc::new(Cell::new(0)),
                incoming,
                answers: answers.clone(),
            },
            answers,
        )
    }

    /// Hold `Subscribe` sends until the test releases them.
    fn slow_subscribes(&self) {
        self.slow_subs.set(true);
    }
}

impl Transport for Upstream {
    type Error = Infallible;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        match &message {
            ControlMessage::ReplaceShareKeys(replacement) => {
                let request_id = replacement.request_id.clone();
                self.log.replacements.borrow_mut().push(replacement.clone());
                self.log.swap_at.borrow_mut().push(monotonic_ms());
                self.answers
                    .unbounded_send(IncomingFrame::Control(ControlMessage::ShareKeysReplaced(
                        ShareKeysReplaced { request_id },
                    )))
                    .expect("queue swap ack");
            }
            ControlMessage::ContentTicketRequest(request) => match &self.tickets {
                Tickets::Held(held) => {
                    self.log.request_at.borrow_mut().push(monotonic_ms());
                    held.borrow_mut().push(request.request_id.clone());
                }
                Tickets::Grants(granted) => {
                    granted.borrow_mut().push(request.request_id.clone());
                    self.log.request_at.borrow_mut().push(monotonic_ms());
                    let mut hex = String::new();
                    for byte in request.file_id {
                        std::fmt::write(&mut hex, format_args!("{byte:02x}")).expect("hex");
                    }
                    self.answers
                        .unbounded_send(IncomingFrame::Control(ControlMessage::ContentTicketGrant(
                            ContentTicketGrant {
                                request_id: request.request_id.clone(),
                                url: format!(
                                    "https://content.invalid/files/{hex}/intent?t={}",
                                    request.request_id
                                ),
                            },
                        )))
                        .expect("queue the ticket grant");
                }
            },
            ControlMessage::Handshake(_) => {
                self.handshakes.set(self.handshakes.get() + 1);
            }
            _ => {}
        }
        let is_subscribe = matches!(message, ControlMessage::Subscribe(_));
        if is_subscribe {
            self.subs.set(self.subs.get() + 1);
        }
        let slow = Rc::clone(&self.slow_subs);
        async move {
            if is_subscribe {
                while slow.get() {
                    timeout_ms(200).await;
                }
            }
            Ok(())
        }
    }

    fn send_bulk(&mut self, message: BulkMessage) -> impl Future<Output = Result<(), Self::Error>> {
        if let BulkMessage::MutationPatch(patch) = &message {
            self.log.mutations.set(self.log.mutations.get() + 1);
            self.answers
                .unbounded_send(IncomingFrame::Control(ControlMessage::MutationApplied(
                    MutationApplied {
                        client_seq: patch.client_seq,
                    },
                )))
                .expect("queue the mutation ack");
        }
        ready(Ok(()))
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        // A close ends the stream only after what was queued drains.
        let frame = if let Some(frame) = self.incoming.next().now_or_never() {
            frame
        } else if self.log.closed.get() || self.dead.get() {
            return Ok(None);
        } else {
            self.incoming.next().await
        };
        // Record the swap's answer only when the worker actually receives it.
        if let Some(IncomingFrame::Control(ControlMessage::ShareKeysReplaced(ack))) = &frame {
            self.log
                .replaced_acks
                .borrow_mut()
                .push(ack.request_id.clone());
        }
        Ok(frame)
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        self.log.died.set(true);
        ready(Ok(()))
    }
}

fn once<T: Transport + 'static>(
    transport: T,
) -> FirstThen<impl FnMut() -> core::future::Ready<Result<T, &'static str>>> {
    FirstThen::new(transport, || core::future::ready(Err("spent")))
}

struct GatedFactory {
    gate: Rc<RefCell<Option<oneshot::Receiver<()>>>>,
    log: Rc<SwapLog>,
    dials: Rc<Cell<u32>>,
    dial_at: Rc<RefCell<Vec<f64>>>,
    handshakes: Rc<RefCell<Vec<Rc<Cell<u32>>>>>,
}

impl TransportFactory for GatedFactory {
    type Transport = Upstream;
    type Error = Infallible;

    fn connect(&mut self) -> impl Future<Output = Result<Upstream, Infallible>> + MaybeSend {
        let gate = self.gate.borrow_mut().take();
        let log = Rc::clone(&self.log);
        let dials = Rc::clone(&self.dials);
        let dial_at = Rc::clone(&self.dial_at);
        let handshakes = Rc::clone(&self.handshakes);
        dials.set(dials.get() + 1);
        dial_at.borrow_mut().push(monotonic_ms());
        async move {
            if let Some(gate) = gate {
                let _ = gate.await;
            }
            let (upstream, _answers) = Upstream::live(
                Rc::clone(&log),
                Tickets::Held(Rc::new(RefCell::new(Vec::new()))),
            );
            handshakes
                .borrow_mut()
                .push(Rc::clone(&upstream.handshakes));
            Ok(upstream)
        }
    }
}

fn real_sleeper(delay: core::time::Duration) -> impl core::future::Future<Output = ()> {
    let ms = i32::try_from(delay.as_millis().clamp(1, 500)).expect("capped above");
    async move {
        timeout_ms(ms).await;
    }
}

/// Preserve the reconnect backoff while expiry runs.
fn floor_sleeper(delay: core::time::Duration) -> impl core::future::Future<Output = ()> {
    let ms = i32::try_from(delay.as_millis().min(70_000)).expect("under the cap");
    async move {
        timeout_ms(ms).await;
    }
}

/// The hub's meta channel end attached to a fresh tab, already handshaken.
async fn attach_tab(hub: &RelayHub) -> MessageTransport<MessagePort> {
    let channel = web_sys::MessageChannel::new().expect("message channel");
    hub.attach(MessageTransport::<MessagePort>::new(channel.port1()));
    let mut tab = MessageTransport::<MessagePort>::new(channel.port2());
    tab.send_control(ControlMessage::Handshake(
        Handshake::new(PROTOCOL_VERSION, "skd-tab")
            .with_major(connetto_core::Major::new(1).expect("major 1")),
    ))
    .await
    .expect("post handshake");
    let ack = tokio::select! {
        frame = tab.recv() => frame.expect("transport").expect("open"),
        () = timeout_ms(2_000) => panic!("the hub never answered the handshake"),
    };
    assert!(
        matches!(ack, IncomingFrame::Control(ControlMessage::HandshakeAck(_))),
        "the hub's first answer is the ack, got {ack:?}"
    );
    tab
}
/// Abort the pump before its HTTP globals leave scope.
struct PumpGuard(AbortHandle);

impl Drop for PumpGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Spawn a test-scoped pump and report its termination.
fn spawn_hub(
    pump: impl core::future::Future<Output = Result<(), connetto_web::relay::RelayError>> + 'static,
) -> (mpsc::UnboundedReceiver<Option<String>>, PumpGuard) {
    let (tx, rx) = mpsc::unbounded();
    let (abort, registration) = AbortHandle::new_pair();
    spawn_local(async move {
        let report = match Abortable::new(pump, registration).await {
            Ok(Ok(())) => None,
            Ok(Err(err)) => Some(err.to_string()),
            Err(_) => Some("aborted on scope exit".to_owned()),
        };
        let _ = tx.unbounded_send(report);
    });
    (rx, PumpGuard(abort))
}

/// Collect frames through `stop` within five seconds.
async fn collect(
    tab: &mut MessageTransport<MessagePort>,
    stop: impl Fn(&IncomingFrame) -> bool,
) -> Vec<IncomingFrame> {
    let deadline = monotonic_ms() + 5_000.0;
    let mut frames = Vec::new();
    loop {
        let frame = tokio::select! {
            frame = tab.recv() => frame.expect("the tab channel stays open"),
            () = timeout_ms(50) => None,
        };
        if let Some(frame) = frame {
            frames.push(frame);
            if stop(frames.last().expect("just pushed")) {
                return frames;
            }
        }
        assert!(
            monotonic_ms() < deadline,
            "the tab stream stopped before the expected frame, received {frames:?}"
        );
    }
}

/// Snapshot patch rows addressed to `sub_id` among `frames`.
fn snapshot_rows(frames: &[IncomingFrame], sub_id: &str) -> usize {
    frames
        .iter()
        .filter(|frame| {
            matches!(
                frame,
                IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch))
                    if patch.sub_id == sub_id
            )
        })
        .count()
}

fn notes_insert(id: i64) -> Vec<u8> {
    use diesel_sqlite_session::SqliteSessionExt;
    let mut conn = diesel::SqliteConnection::establish(":memory:").expect("open");
    conn.batch_execute(SKD_DDL).expect("schema");
    let mut session = conn.create_session().expect("session");
    session.attach_all().expect("attach");
    conn.batch_execute(&format!("INSERT INTO notes VALUES ({id}, '{SKD_SUBJECT}')"))
        .expect("insert");
    session.changeset().expect("changeset")
}

async fn send_mutation(tab: &mut MessageTransport<MessagePort>, seq: u64, changeset: &[u8]) {
    tab.send_control(ControlMessage::MutationHeader(MutationHeader {
        client_seq: seq,
        op_count: 1,
        provenance: None,
    }))
    .await
    .expect("post header");
    tab.send_bulk(BulkMessage::MutationPatch(MutationPatch {
        client_seq: seq,
        patchset_zstd: zstd::encode_all(changeset, 3).expect("compress"),
    }))
    .await
    .expect("post patchset");
}

/// Expiry updates subscribed rows without an application wake.
#[expect(
    clippy::too_many_lines,
    reason = "keeps the hub, tab and fixture lifetimes in one scope"
)]
#[wasm_bindgen_test]
async fn an_expired_grant_is_swapped_without_any_request() {
    let log = Rc::new(SwapLog::default());
    let (upstream, answers) = Upstream::live(
        Rc::clone(&log),
        Tickets::Held(Rc::new(RefCell::new(Vec::new()))),
    );
    let now = seconds_now();
    let mut worker = ClientBuilder::new(skd_schema(), once(upstream))
        .with_share_keys(vec![(
            mint(now + 2),
            CapabilitySubject::<String>::new(SKD_SUBJECT),
        )])
        .signed_in(
            HeldCredential::new(Grant::new("user:skd"), "skd")
                .expect("a string identity serializes"),
        )
        .connect_driven()
        .await
        .expect("worker connect");
    let spec = SubscriptionSpec::new("SELECT * FROM notes");
    worker
        .subscribe_spec("wire-0", spec.clone())
        .await
        .expect("declare wire");
    let (hub, pump, _notices) = RelayHub::with_reconnect(
        worker,
        ":memory:",
        HubReconnect {
            factory: {
                let log = Rc::clone(&log);
                move || {
                    ready(Ok::<Upstream, String>(
                        Upstream::live(
                            Rc::clone(&log),
                            Tickets::Held(Rc::new(RefCell::new(Vec::new()))),
                        )
                        .0,
                    ))
                }
            },
            sleeper: real_sleeper,
            policy: ReconnectPolicy::new(),
            upstream: vec![("wire-0".to_owned(), spec)],
        },
    )
    .expect("hub");
    let (mut hub_err, _guard) = spawn_hub(pump);

    let mut tab = attach_tab(&hub).await;
    send_mutation(&mut tab, 1, &notes_insert(1)).await;
    tab.send_control(ControlMessage::Subscribe(Subscribe {
        sub_id: "s1".to_owned(),
        spec: SubscriptionSpec::new("SELECT * FROM notes"),
    }))
    .await
    .expect("subscribe");
    let frames = collect(&mut tab, |frame| {
        matches!(
            frame,
            IncomingFrame::Control(ControlMessage::SnapshotEnd(end)) if end.sub_id == "s1"
        )
    })
    .await;
    assert_eq!(
        snapshot_rows(&frames, "s1"),
        1,
        "the seed row applies and shows while the grant lives, hub error {err:?}, upstream saw {m} mutations",
        err = hub_err.try_recv().unwrap_or_default(),
        m = log.mutations()
    );

    let swapped = until(async || !log.replacements.borrow().is_empty()).await;
    assert!(
        swapped,
        "the hub sent the swap without any request waking it"
    );
    let replacement = log
        .replacements
        .borrow()
        .first()
        .expect("a swap was recorded")
        .clone();
    assert!(
        replacement.keys.is_empty(),
        "the expired grant is no longer presented"
    );

    answers
        .unbounded_send(IncomingFrame::Control(ControlMessage::FullResyncRequired(
            FullResyncRequired {
                sub_id: "wire-0".to_owned(),
                reason: FullResyncReason::AuthorizationChange,
            },
        )))
        .expect("queue resync");
    answers
        .unbounded_send(IncomingFrame::Control(ControlMessage::SnapshotBegin(
            SnapshotBegin {
                sub_id: "wire-0".to_owned(),
                priority: SubscriptionPriority::default(),
            },
        )))
        .expect("queue begin");
    answers
        .unbounded_send(IncomingFrame::Control(ControlMessage::SnapshotEnd(
            SnapshotEnd {
                sub_id: "wire-0".to_owned(),
                cursor: Cursor::new(vec![1, 7]),
            },
        )))
        .expect("queue end");

    let frames = collect(&mut tab, |frame| {
        matches!(
            frame,
            IncomingFrame::Control(ControlMessage::FullResyncRequired(req))
                if req.sub_id == "s1"
        )
    })
    .await;
    assert!(
        frames.iter().any(|frame| {
            matches!(
                frame,
                IncomingFrame::Control(ControlMessage::FullResyncRequired(req))
                    if req.reason == FullResyncReason::AuthorizationChange
            )
        }),
        "the resync carries the authorization reason"
    );
    let frames = collect(&mut tab, |frame| {
        matches!(
            frame,
            IncomingFrame::Control(ControlMessage::SnapshotEnd(end)) if end.sub_id == "s1"
        )
    })
    .await;
    assert_eq!(
        snapshot_rows(&frames, "s1"),
        0,
        "the expired authorization hides the row"
    );
}

struct At {
    url: String,
    exists: bool,
}

impl ReplicaPlace for At {
    fn locate(&self, name: &str) -> Result<Located, ClientError> {
        Ok(Located::new(
            name,
            self.url.clone(),
            self.exists,
            ContentPlace::InMemory,
        ))
    }
}

struct Holding(ReplicaKey);

impl ReplicaKeyStore for Holding {
    type Error = ClientError;

    fn load(&self, _name: &str) -> impl Future<Output = Result<Option<ReplicaKey>, ClientError>> {
        core::future::ready(Ok(Some(self.0.clone())))
    }

    fn store(
        &self,
        _name: &str,
        _key: &ReplicaKey,
    ) -> impl Future<Output = Result<(), ClientError>> {
        core::future::ready(Ok(()))
    }

    fn clear(&self, _name: &str) -> impl Future<Output = Result<(), ClientError>> {
        core::future::ready(Ok(()))
    }

    fn protection(&self) -> Custody {
        Custody::Ephemeral
    }
}

/// Record durable share-key writes.
struct RecordingShareStore {
    saves: Rc<Cell<u32>>,
    saves_at: Rc<RefCell<Vec<f64>>>,
}

impl ShareKeyStore for RecordingShareStore {
    type Error = ClientError;

    fn load<'a>(
        &'a self,
        _record: &'a str,
    ) -> ShareKeyFuture<'a, Option<ShareKeySet>, ClientError> {
        Box::pin(core::future::ready(Ok(None)))
    }

    fn save<'a>(
        &'a self,
        _record: &'a str,
        _set: &'a ShareKeySet,
    ) -> ShareKeyFuture<'a, (), ClientError> {
        self.saves.set(self.saves.get() + 1);
        self.saves_at.borrow_mut().push(monotonic_ms());
        Box::pin(core::future::ready(Ok(())))
    }

    fn clear<'a>(&'a self, _record: &'a str) -> ShareKeyFuture<'a, (), ClientError> {
        Box::pin(core::future::ready(Ok(())))
    }

    fn protection(&self) -> Custody {
        Custody::Ephemeral
    }
}

/// Expiry persists while reconnect backoff remains pending.
#[wasm_bindgen_test]
async fn an_expired_grant_is_swapped_during_reconnect_backoff() {
    let log = Rc::new(SwapLog::default());
    let saves = Rc::new(Cell::new(0u32));
    let dials = Rc::new(Cell::new(0u32));
    let now = seconds_now();
    let worker = ClientBuilder::new(skd_schema(), || ready(Err::<Upstream, &str>("offline")))
        .with_share_keys(vec![(
            mint(now + 2),
            CapabilitySubject::<String>::new(SKD_SUBJECT),
        )])
        .signed_in(
            HeldCredential::new(Grant::new("user:skd"), "skd")
                .expect("a string identity serializes"),
        )
        .durable(
            At {
                url: "skd-backoff".to_owned(),
                exists: false,
            },
            Holding(ReplicaKey::from_bytes([0x62; ReplicaKey::LEN])),
            RecordingShareStore {
                saves: Rc::clone(&saves),
                saves_at: Rc::new(RefCell::new(Vec::new())),
            },
        )
        .with_gate(Gate::off())
        .open_driven()
        .await
        .expect("open offline replica");
    let (hub, pump, _notices) = RelayHub::with_reconnect(
        worker,
        ":memory:",
        HubReconnect {
            factory: {
                let dials = Rc::clone(&dials);
                let log = Rc::clone(&log);
                move || {
                    dials.set(dials.get() + 1);
                    let (upstream, _answers) = Upstream::live(
                        Rc::clone(&log),
                        Tickets::Held(Rc::new(RefCell::new(Vec::new()))),
                    );
                    upstream.log.close();
                    ready(Ok::<Upstream, String>(upstream))
                }
            },
            sleeper: floor_sleeper,
            policy: ReconnectPolicy::new()
                .with_initial_backoff(core::time::Duration::from_secs(60))
                .with_max_backoff(core::time::Duration::from_secs(60)),
            upstream: Vec::new(),
        },
    )
    .expect("hub");
    let (mut hub_err, _guard) = spawn_hub(pump);

    let mut tab = attach_tab(&hub).await;
    send_mutation(&mut tab, 1, &notes_insert(1)).await;
    tab.send_control(ControlMessage::Subscribe(Subscribe {
        sub_id: "s1".to_owned(),
        spec: SubscriptionSpec::new("SELECT * FROM notes"),
    }))
    .await
    .expect("subscribe before the expiry");
    let frames = collect(&mut tab, |frame| {
        matches!(
            frame,
            IncomingFrame::Control(ControlMessage::SnapshotEnd(end)) if end.sub_id == "s1"
        )
    })
    .await;
    assert_eq!(
        snapshot_rows(&frames, "s1"),
        1,
        "the row is visible before the expiry, hub error {err:?}, upstream saw {m} mutations",
        err = hub_err.try_recv().unwrap_or_default(),
        m = log.mutations()
    );
    timeout_ms(3_000).await;
    let persisted = wait_until(async || saves.get() >= 2, 300, 10).await;
    assert!(
        persisted,
        "the backoff saved the expired set on its own clock, hub error {err:?}, saves {s}",
        err = hub_err.try_recv().unwrap_or_default(),
        s = saves.get()
    );
    assert_eq!(
        dials.get(),
        0,
        "the 60 s backoff kept the first dial pending while the expiry saved, dials {d}",
        d = dials.get()
    );
}

/// Expiry persists without replacing an unfinished recovery dial.
#[expect(
    clippy::too_many_lines,
    reason = "keeps the hub, tab and fixture lifetimes in one scope"
)]
#[wasm_bindgen_test]
async fn the_expiry_saves_while_a_recovery_dial_is_pending() {
    let log = Rc::new(SwapLog::default());
    let saves = Rc::new(Cell::new(0u32));
    let saves_at = Rc::new(RefCell::new(Vec::new()));
    let dials = Rc::new(Cell::new(0u32));
    let dial_at = Rc::new(RefCell::new(Vec::new()));
    let handshakes = Rc::new(RefCell::new(Vec::new()));
    let (release, gate) = oneshot::channel();
    let now = seconds_now();
    let grant_deadline = now + 8;
    let dead0 = Rc::new(Cell::new(false));
    let (fake0, _answers0) = Upstream::live_with(
        Rc::clone(&log),
        Tickets::Held(Rc::new(RefCell::new(Vec::new()))),
        Rc::clone(&dead0),
    );
    let worker = ClientBuilder::new(skd_schema(), once(fake0))
        .with_share_keys(vec![(
            mint(grant_deadline),
            CapabilitySubject::<String>::new(SKD_SUBJECT),
        )])
        .signed_in(
            HeldCredential::new(Grant::new("user:skd"), "skd")
                .expect("a string identity serializes"),
        )
        .durable(
            At {
                url: "skd-pending-dial".to_owned(),
                exists: false,
            },
            Holding(ReplicaKey::from_bytes([0x70; ReplicaKey::LEN])),
            RecordingShareStore {
                saves: Rc::clone(&saves),
                saves_at: Rc::clone(&saves_at),
            },
        )
        .with_gate(Gate::off())
        .open_driven()
        .await
        .expect("open the replica");
    let (hub, pump, _notices) = RelayHub::with_reconnect(
        worker,
        ":memory:",
        HubReconnect {
            factory: GatedFactory {
                gate: Rc::new(RefCell::new(Some(gate))),
                log: Rc::clone(&log),
                dials: Rc::clone(&dials),
                dial_at: Rc::clone(&dial_at),
                handshakes: Rc::clone(&handshakes),
            },
            sleeper: real_sleeper,
            policy: ReconnectPolicy::new().with_max_attempts(Some(8)),
            upstream: Vec::new(),
        },
    )
    .expect("hub");
    let (mut hub_err, guard) = spawn_hub(pump);

    let mut tab = attach_tab(&hub).await;
    send_mutation(&mut tab, 1, &notes_insert(1)).await;
    tab.send_control(ControlMessage::Subscribe(Subscribe {
        sub_id: "s1".to_owned(),
        spec: SubscriptionSpec::new("SELECT * FROM notes"),
    }))
    .await
    .expect("subscribe before the loss");
    let frames = collect(&mut tab, |frame| {
        matches!(
            frame,
            IncomingFrame::Control(ControlMessage::SnapshotEnd(end)) if end.sub_id == "s1"
        )
    })
    .await;
    assert_eq!(
        snapshot_rows(&frames, "s1"),
        1,
        "the row is visible before the loss, hub error {err:?}",
        err = hub_err.try_recv().unwrap_or_default(),
    );

    dead0.set(true);
    tab.send_control(ControlMessage::Subscribe(Subscribe {
        sub_id: "s2".to_owned(),
        spec: SubscriptionSpec::new("SELECT * FROM notes"),
    }))
    .await
    .expect("subscribe after the loss");
    assert!(
        wait_until(async || dials.get() >= 1, 400, 10).await,
        "the wake opened a recovery dial, hub error {err:?}",
        err = hub_err.try_recv().unwrap_or_default(),
    );
    let dial_started = dial_at.borrow()[0];
    let wait_ms = i64::max(0, (grant_deadline - seconds_now()) * 1000);
    timeout_ms(i32::try_from(wait_ms).expect("expiry wait fits milliseconds")).await;
    assert!(
        saves.get() >= 2,
        "the expiry persisted while the dial stayed held, dial {dial_started}, hub error {err:?}",
        err = hub_err.try_recv().unwrap_or_default(),
    );
    let last_save = *saves_at.borrow().last().expect("a save was recorded");
    assert!(
        last_save > dial_started,
        "the expiry save came after the dial was held, save {last_save}, dial {dial_started}"
    );
    assert_eq!(
        dials.get(),
        1,
        "the held dial did not restart across the expiry, dials {d}",
        d = dials.get()
    );

    release.send(()).expect("release the held dial");
    let reattached = wait_until(
        async || handshakes.borrow().iter().any(|h| h.get() >= 1),
        300,
        10,
    )
    .await;
    assert!(
        reattached,
        "the held dial completed its attach on release, hub error {err:?}",
        err = hub_err.try_recv().unwrap_or_default(),
    );
    send_mutation(&mut tab, 2, &notes_insert(2)).await;
    let deadline = monotonic_ms() + 30_000.0;
    let mut applied = false;
    while monotonic_ms() < deadline {
        let frame = tokio::select! {
            frame = tab.recv() => frame.expect("the tab channel stays open"),
            () = timeout_ms(50) => None,
        };
        if let Some(IncomingFrame::Control(ControlMessage::MutationApplied(ack))) = frame
            && ack.client_seq == 2
        {
            applied = true;
            break;
        }
    }
    assert!(
        applied,
        "the wire serves the tab on the held dial once released, dials {d}, hub error {err:?}",
        d = dials.get(),
        err = hub_err.try_recv().unwrap_or_default(),
    );
    assert_eq!(
        dials.get(),
        1,
        "no second dial after the release, dials {d}",
        d = dials.get()
    );

    drop(guard);
    let pump_stopped = wait_until(async || hub_err.try_recv().is_ok(), 600, 10).await;
    assert!(
        pump_stopped,
        "the pump ended when its guard dropped, dials {d}",
        d = dials.get()
    );
}

/// Expiry during subscription restoration preserves the attached transport.
#[expect(
    clippy::too_many_lines,
    reason = "keeps the hub, tab and fixture lifetimes in one scope"
)]
#[wasm_bindgen_test]
async fn the_key_win_resumes_a_fresh_attach_without_a_redial() {
    let log = Rc::new(SwapLog::default());
    let saves = Rc::new(Cell::new(0u32));
    let dials = Rc::new(Cell::new(0u32));
    let recovery = Rc::new(RefCell::new(Vec::new()));
    let slow = Rc::new(RefCell::new(Vec::new()));
    let now = seconds_now();
    let grant_deadline = now + 8;
    let dead0 = Rc::new(Cell::new(false));
    let (fake0, _answers0) = Upstream::live_with(
        Rc::clone(&log),
        Tickets::Held(Rc::new(RefCell::new(Vec::new()))),
        Rc::clone(&dead0),
    );
    let worker = ClientBuilder::new(skd_schema(), once(fake0))
        .with_share_keys(vec![(
            mint(grant_deadline),
            CapabilitySubject::<String>::new(SKD_SUBJECT),
        )])
        .signed_in(
            HeldCredential::new(Grant::new("user:skd"), "skd")
                .expect("a string identity serializes"),
        )
        .durable(
            At {
                url: "skd-resume-attach".to_owned(),
                exists: false,
            },
            Holding(ReplicaKey::from_bytes([0x71; ReplicaKey::LEN])),
            RecordingShareStore {
                saves: Rc::clone(&saves),
                saves_at: Rc::new(RefCell::new(Vec::new())),
            },
        )
        .with_gate(Gate::off())
        .open_driven()
        .await
        .expect("open the replica");
    let (hub, pump, _notices) = RelayHub::with_reconnect(
        worker,
        ":memory:",
        HubReconnect {
            factory: {
                let dials = Rc::clone(&dials);
                let log = Rc::clone(&log);
                let recovery = Rc::clone(&recovery);
                let slow = Rc::clone(&slow);
                move || {
                    dials.set(dials.get() + 1);
                    let (upstream, _answers) = Upstream::live(
                        Rc::clone(&log),
                        Tickets::Held(Rc::new(RefCell::new(Vec::new()))),
                    );
                    // Hold restoration across the key deadline.
                    upstream.slow_subscribes();
                    recovery.borrow_mut().push(Rc::clone(&upstream.subs));
                    slow.borrow_mut().push(Rc::clone(&upstream.slow_subs));
                    ready(Ok::<Upstream, Infallible>(upstream))
                }
            },
            sleeper: real_sleeper,
            policy: ReconnectPolicy::new().with_max_attempts(Some(8)),
            upstream: (0..5)
                .map(|i| {
                    (
                        format!("wire-{i}"),
                        SubscriptionSpec::new("SELECT * FROM notes"),
                    )
                })
                .collect(),
        },
    )
    .expect("hub");
    let (mut hub_err, guard) = spawn_hub(pump);

    let mut tab = attach_tab(&hub).await;
    send_mutation(&mut tab, 1, &notes_insert(1)).await;
    tab.send_control(ControlMessage::Subscribe(Subscribe {
        sub_id: "s1".to_owned(),
        spec: SubscriptionSpec::new("SELECT * FROM notes"),
    }))
    .await
    .expect("subscribe before the loss");
    let frames = collect(&mut tab, |frame| {
        matches!(
            frame,
            IncomingFrame::Control(ControlMessage::SnapshotEnd(end)) if end.sub_id == "s1"
        )
    })
    .await;
    assert_eq!(
        snapshot_rows(&frames, "s1"),
        1,
        "the row is visible before the loss, hub error {err:?}",
        err = hub_err.try_recv().unwrap_or_default(),
    );

    dead0.set(true);
    tab.send_control(ControlMessage::Subscribe(Subscribe {
        sub_id: "s2".to_owned(),
        spec: SubscriptionSpec::new("SELECT * FROM notes"),
    }))
    .await
    .expect("subscribe after the loss");
    assert!(
        wait_until(
            async || recovery
                .borrow()
                .first()
                .is_some_and(|subs| subs.get() >= 1),
            3000,
            10
        )
        .await,
        "the post-attach restore started before the expiry, hub error {err:?}",
        err = hub_err.try_recv().unwrap_or_default(),
    );
    assert!(
        seconds_now() < grant_deadline,
        "the grant remains live while restoration is held"
    );
    let wait_ms = i64::max(0, (grant_deadline - seconds_now()) * 1000);
    timeout_ms(i32::try_from(wait_ms).expect("expiry wait fits milliseconds")).await;
    assert!(
        saves.get() >= 2,
        "the expiry saved during the post-attach restore, dials {d}, hub error {err:?}",
        d = dials.get(),
        err = hub_err.try_recv().unwrap_or_default(),
    );
    assert_eq!(
        dials.get(),
        1,
        "the key win kept the recovery dial, dials {d}",
        d = dials.get()
    );
    assert!(
        recovery
            .borrow()
            .first()
            .is_some_and(|subs| subs.get() >= 1),
        "the restore was underway when the key won, subs {s:?}",
        s = recovery.borrow()
    );
    slow.borrow().iter().for_each(|flag| flag.set(false));
    let reattached = wait_until(async || !log.replaced_acks.borrow().is_empty(), 1500, 10).await;
    assert!(
        reattached,
        "the swap answer rode the recovery wire, dials {d}, hub error {err:?}",
        d = dials.get(),
        err = hub_err.try_recv().unwrap_or_default(),
    );

    send_mutation(&mut tab, 2, &notes_insert(2)).await;
    let deadline = monotonic_ms() + 30_000.0;
    let mut applied = false;
    while monotonic_ms() < deadline {
        let frame = tokio::select! {
            frame = tab.recv() => frame.expect("the tab channel stays open"),
            () = timeout_ms(50) => None,
        };
        if let Some(IncomingFrame::Control(ControlMessage::MutationApplied(ack))) = frame
            && ack.client_seq == 2
        {
            applied = true;
            break;
        }
    }
    assert!(
        applied,
        "the retained wire serves the tab after the resume, dials {d}, hub error {err:?}",
        d = dials.get(),
        err = hub_err.try_recv().unwrap_or_default(),
    );
    assert_eq!(
        dials.get(),
        1,
        "no redial after the key win, dials {d}",
        d = dials.get()
    );

    drop(guard);
    let pump_stopped = wait_until(async || hub_err.try_recv().is_ok(), 600, 10).await;
    assert!(
        pump_stopped,
        "the pump ended when its guard dropped, dials {d}",
        d = dials.get()
    );
}

/// Expiry preserves an unanswered content-ticket request.
#[expect(
    clippy::too_many_lines,
    reason = "keeps the hub, tab and fixture lifetimes in one scope"
)]
#[wasm_bindgen_test]
async fn a_held_ticket_keeps_its_request_through_the_swap() {
    let serial = tokio::select! {
        guard = locks::hold_lock(DB_ALIVE_LOCK) => guard,
        () = timeout_ms(15_000) => panic!("T3 hung acquiring the database lock"),
    };
    let log = Rc::new(SwapLog::default());
    let dials = Rc::new(Cell::new(0u32));
    let held = Rc::new(RefCell::new(Vec::<String>::new()));
    let (upstream, answers) = Upstream::live(Rc::clone(&log), Tickets::Held(Rc::clone(&held)));
    let now = seconds_now();
    let worker_fut = ClientBuilder::new(
        SyncSchema::new(
            SchemaBundle::new(
                "-- connetto:major 1",
                "",
                PHOTOS_DDL,
                Vec::<(String, String)>::new(),
                Vec::<String>::new(),
                None::<&str>,
            )
            .expect("the source declares major 1"),
        ),
        once(upstream),
    )
    .with_share_keys(vec![(
        mint(now + 5),
        CapabilitySubject::<String>::new(SKD_SUBJECT),
    )])
    .signed_in(
        HeldCredential::new(Grant::new("user:skd"), "skd").expect("a string identity serializes"),
    )
    .connect_driven();
    let worker = tokio::select! {
        worker = worker_fut => worker.expect("worker connect"),
        () = timeout_ms(15_000) => panic!("T3 hung connecting the worker"),
    };
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("dedicated worker");
    let store = tokio::select! {
        store = BrowserStore::install(&scope, "skd-content-hold") => store.expect("install store"),
        () = timeout_ms(15_000) => panic!("T3 hung installing the store"),
    };
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let _stubs = install_content_transport(&uploaded);
    let content = ContentArchive::new(store, [9; 32]);
    let (hub, pump, _notices) = RelayHub::with_reconnect_and_content(
        worker,
        ":memory:",
        HubReconnect {
            factory: {
                let dials = Rc::clone(&dials);
                let log = Rc::clone(&log);
                move || {
                    dials.set(dials.get() + 1);
                    ready(Ok::<Upstream, String>(
                        Upstream::live(
                            Rc::clone(&log),
                            Tickets::Held(Rc::new(RefCell::new(Vec::new()))),
                        )
                        .0,
                    ))
                }
            },
            sleeper: real_sleeper,
            policy: ReconnectPolicy::new().with_max_attempts(Some(3)),
            upstream: Vec::new(),
        },
        content,
        BrowserHttp::new(),
    )
    .expect("content relay");

    let (mut hub_err, guard) = spawn_hub(pump);

    let channel = web_sys::MessageChannel::new().expect("message channel");
    hub.attach_with_content(MessageTransport::<MessagePort>::new(channel.port1()));
    let mut tab = MessageTransport::<MessagePort>::new(channel.port2());
    tab.send_control(ControlMessage::Handshake(
        Handshake::new(PROTOCOL_VERSION, "6f1c9d2e-8a4b-4c5d-9e6f-0a1b2c3d4e5f")
            .with_major(connetto_core::Major::new(1).expect("major 1")),
    ))
    .await
    .expect("post handshake");
    let ack = tokio::select! {
        frame = tab.recv() => frame.expect("transport").expect("open"),
        () = timeout_ms(2_000) => panic!("the hub never answered the handshake"),
    };
    assert!(
        matches!(ack, IncomingFrame::Control(ControlMessage::HandshakeAck(_))),
        "the hub's first answer is the ack, got {ack:?}"
    );

    let photo: &[u8] = b"a photograph whose ticket the server holds while the grant expires";
    let mut hasher = FileIdHasher::new();
    hasher.update(photo);
    let file_id = hasher.finalize();
    let bytes = *file_id.as_bytes();
    let blob = {
        let arr = Uint8Array::from(photo);
        web_sys::Blob::new_with_u8_array_sequence(&Array::of1(&arr)).expect("blob from bytes")
    };
    let stage = ContentFrame::Stage {
        file_id: bytes,
        mime: mime_code(MimeClass::Jpeg),
    };
    tab.post_internal(&stage.to_json(), Some(&blob))
        .expect("post stage");

    let mut changeset_conn = diesel::SqliteConnection::establish(":memory:").expect("open");
    changeset_conn.batch_execute(PHOTOS_DDL).expect("schema");
    let mut session = changeset_conn.create_session().expect("session");
    session.attach_all().expect("attach");
    let mut hex = String::new();
    for byte in bytes {
        std::fmt::write(&mut hex, format_args!("{byte:02x}")).expect("string append");
    }
    changeset_conn
        .batch_execute(&format!("INSERT INTO photos VALUES (1, x'{hex}')"))
        .expect("insert");
    let changeset = session.changeset().expect("changeset");
    drop(session);
    send_mutation(&mut tab, 1, &changeset).await;

    let requested = wait_until(async || !held.borrow().is_empty(), 600, 10).await;
    assert!(
        requested,
        "the hub asked for the ticket before the expiry, hub error {err:?}",
        err = hub_err.try_recv().unwrap_or_default(),
    );
    let swapped = wait_until(async || !log.replacements.borrow().is_empty(), 600, 10).await;
    assert!(swapped, "the key work ran while the ticket was held");
    assert!(
        log.replacements.borrow()[0].keys.is_empty(),
        "the expired grant is no longer presented"
    );
    let request_id = held.borrow_mut().remove(0);
    answers
        .unbounded_send(IncomingFrame::Control(ControlMessage::ContentTicketGrant(
            ContentTicketGrant {
                request_id: request_id.clone(),
                url: format!("https://content.invalid/files/{file_id}/intent?t={request_id}"),
            },
        )))
        .expect("queue the released grant");
    let uploaded_photo = wait_until(
        async || {
            uploaded
                .borrow()
                .iter()
                .any(|body| body.as_slice() == photo)
        },
        2000,
        10,
    )
    .await;
    drop(guard);
    let pump_stopped = wait_until(async || hub_err.try_recv().is_ok(), 600, 10).await;
    assert!(
        uploaded_photo,
        "the held request still drove the upload, dials {d}, hub error {err:?}, requests at {r:?}",
        d = dials.get(),
        err = match hub_err.try_recv() {
            Ok(Some(err)) => err,
            Ok(None) => "pump ended".to_owned(),
            Err(_) => "pump running".to_owned(),
        },
        r = log.request_at.borrow()
    );
    assert!(
        pump_stopped,
        "the test's pump ended before the next test, dials {d}",
        d = dials.get()
    );
    serial.release();
}

async fn wait_until(mut ready: impl AsyncFnMut() -> bool, polls: usize, ms: i32) -> bool {
    for _ in 0..polls {
        if ready().await {
            return true;
        }
        timeout_ms(ms).await;
    }
    ready().await
}

/// An authorized upload preserves its wire across an acknowledged share-key replacement.
#[expect(
    clippy::too_many_lines,
    reason = "keeps the hub, tab and fixture lifetimes in one scope"
)]
#[wasm_bindgen_test]
async fn a_held_upload_still_reads_the_swap_answer() {
    let serial = locks::hold_lock(DB_ALIVE_LOCK).await;
    let log = Rc::new(SwapLog::default());
    let granted = Rc::new(RefCell::new(Vec::<String>::new()));
    let dials = Rc::new(Cell::new(0u32));
    let (upstream, _answers) =
        Upstream::live(Rc::clone(&log), Tickets::Grants(Rc::clone(&granted)));
    let now = seconds_now();
    let worker = ClientBuilder::new(
        SyncSchema::new(
            SchemaBundle::new(
                "-- connetto:major 1",
                "",
                PHOTOS_DDL,
                Vec::<(String, String)>::new(),
                Vec::<String>::new(),
                None::<&str>,
            )
            .expect("the source declares major 1"),
        ),
        once(upstream),
    )
    .with_share_keys(vec![(
        mint(now + 2),
        CapabilitySubject::<String>::new(SKD_SUBJECT),
    )])
    .signed_in(
        HeldCredential::new(Grant::new("user:skd"), "skd").expect("a string identity serializes"),
    )
    .connect_driven()
    .await
    .expect("worker connect");
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("dedicated worker");
    let store = BrowserStore::install(&scope, "skd-transfer-hold")
        .await
        .expect("install store");
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let held_upload = install_blocked_content_transport(&uploaded);
    let content = ContentArchive::new(store, [17; 32]);
    let (hub, pump, _notices) = RelayHub::with_reconnect_and_content(
        worker,
        ":memory:",
        HubReconnect {
            factory: {
                let dials = Rc::clone(&dials);
                let log = Rc::clone(&log);
                move || {
                    dials.set(dials.get() + 1);
                    ready(Ok::<Upstream, String>(
                        Upstream::live(
                            Rc::clone(&log),
                            Tickets::Grants(Rc::new(RefCell::new(Vec::new()))),
                        )
                        .0,
                    ))
                }
            },
            sleeper: real_sleeper,
            policy: ReconnectPolicy::new().with_max_attempts(Some(3)),
            upstream: Vec::new(),
        },
        content,
        BrowserHttp::new().with_idle_bound(core::time::Duration::from_secs(60)),
    )
    .expect("content relay");
    let (mut hub_err, guard) = spawn_hub(pump);

    let channel = web_sys::MessageChannel::new().expect("message channel");
    hub.attach_with_content(MessageTransport::<MessagePort>::new(channel.port1()));
    let mut tab = MessageTransport::<MessagePort>::new(channel.port2());
    tab.send_control(ControlMessage::Handshake(
        Handshake::new(PROTOCOL_VERSION, "b2a4c6d8-0e1f-2a3b-4c5d-6e7f8090a1b2")
            .with_major(connetto_core::Major::new(1).expect("major 1")),
    ))
    .await
    .expect("post handshake");
    let ack = tokio::select! {
        frame = tab.recv() => frame.expect("transport").expect("open"),
        () = timeout_ms(2_000) => panic!("the hub never answered the handshake"),
    };
    assert!(
        matches!(ack, IncomingFrame::Control(ControlMessage::HandshakeAck(_))),
        "the hub's first answer is the ack, got {ack:?}"
    );

    let photo: &[u8] = b"a transfer the server holds while its swap answer is due";
    let mut hasher = FileIdHasher::new();
    hasher.update(photo);
    let file_id = hasher.finalize();
    let bytes = *file_id.as_bytes();
    let blob = {
        let arr = Uint8Array::from(photo);
        web_sys::Blob::new_with_u8_array_sequence(&Array::of1(&arr)).expect("blob from bytes")
    };
    let stage = ContentFrame::Stage {
        file_id: bytes,
        mime: mime_code(MimeClass::Jpeg),
    };
    tab.post_internal(&stage.to_json(), Some(&blob))
        .expect("post stage");

    let mut changeset_conn = diesel::SqliteConnection::establish(":memory:").expect("open");
    changeset_conn.batch_execute(PHOTOS_DDL).expect("schema");
    let mut session = changeset_conn.create_session().expect("session");
    session.attach_all().expect("attach");
    let mut hex = String::new();
    for byte in bytes {
        std::fmt::write(&mut hex, format_args!("{byte:02x}")).expect("string append");
    }
    changeset_conn
        .batch_execute(&format!("INSERT INTO photos VALUES (1, x'{hex}')"))
        .expect("insert");
    let changeset = session.changeset().expect("changeset");
    drop(session);
    send_mutation(&mut tab, 1, &changeset).await;

    let started = wait_until(async || held_upload.started.get(), 600, 10).await;
    assert!(
        started,
        "the upload left before the swap was due, hub error {err:?}, tickets {t}, dials {d}",
        err = hub_err.try_recv().unwrap_or_default(),
        t = granted.borrow().len(),
        d = dials.get()
    );

    let swapped = wait_until(async || !log.replacements.borrow().is_empty(), 600, 10).await;
    assert!(
        swapped,
        "the key work ran while the upload was held, hub error {err:?}",
        err = hub_err.try_recv().unwrap_or_default(),
    );
    assert!(
        log.replacements.borrow()[0].keys.is_empty(),
        "the expired grant is no longer presented"
    );
    // Count delivery to the worker rather than a queued response.
    let acked = wait_until(
        async || {
            log.replaced_acks
                .borrow()
                .iter()
                .any(|id| *id == log.replacements.borrow()[0].request_id)
        },
        600,
        10,
    )
    .await;
    assert!(
        acked,
        "the swap's correlated answer reached the worker before the hold, hub error {err:?}",
        err = hub_err.try_recv().unwrap_or_default(),
    );

    // Hold beyond the answer bound while this upload's idle bound remains longer.
    timeout_ms(33_000).await;
    held_upload.release();

    let done = wait_until(
        async || {
            uploaded
                .borrow()
                .iter()
                .any(|body| body.as_slice() == photo)
        },
        600,
        10,
    )
    .await;
    assert!(done, "the held upload completed with the staged bytes");

    assert!(
        !log.died.get(),
        "the hub never closed the wire while the upload was held"
    );
    let mut changeset_conn = diesel::SqliteConnection::establish(":memory:").expect("open");
    changeset_conn.batch_execute(PHOTOS_DDL).expect("schema");
    let mut session = changeset_conn.create_session().expect("session");
    session.attach_all().expect("attach");
    changeset_conn
        .batch_execute(&format!("INSERT INTO photos VALUES (2, x'{hex}')"))
        .expect("insert");
    let changeset = session.changeset().expect("changeset");
    drop(session);
    send_mutation(&mut tab, 2, &changeset).await;
    let deadline = monotonic_ms() + 5_000.0;
    let mut seen = 0usize;
    let mut applied = false;
    while monotonic_ms() < deadline {
        let frame = tokio::select! {
            frame = tab.recv() => frame.expect("the tab channel stays open"),
            () = timeout_ms(50) => None,
        };
        if let Some(frame) = frame {
            if matches!(
                frame,
                IncomingFrame::Control(ControlMessage::MutationApplied(ack))
                    if ack.client_seq == 2
            ) {
                applied = true;
                break;
            }
            seen += 1;
        }
    }
    assert!(
        applied,
        "the wire still serves the tab after the hold, hub error {err:?}, dials {d}, extra frames {seen}",
        err = hub_err.try_recv().unwrap_or_default(),
        d = dials.get()
    );
    assert_eq!(
        uploaded.borrow().len(),
        1,
        "the held request drove exactly one upload"
    );
    let ids = granted.borrow().clone();
    assert!(
        !ids.is_empty() && ids.iter().all(|id| *id == ids[0]),
        "the ticket kept one request id across the key win, ids {ids:?}, swap at {s:?}, requests at {r:?}",
        s = log.swap_at.borrow(),
        r = log.request_at.borrow()
    );
    assert_eq!(
        dials.get(),
        0,
        "no new dial while the swap answer rode the transfer"
    );
    drop(guard);
    let pump_stopped = wait_until(async || hub_err.try_recv().is_ok(), 600, 10).await;
    assert!(
        pump_stopped,
        "the test's pump ended before the next test, dials {d}",
        d = dials.get()
    );
    serial.release();
}
