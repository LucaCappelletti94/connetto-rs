//! What the tabs of a relay hub learn when the hub's own upstream meets a
//! reason the hub's build can never attach under: a refusal at the attach
//! ends the hub and tells every tab the reason, a live close of that class
//! skips the first redial, and a rate-limited refusal sets the floor on the
//! next wait. Runs in a dedicated worker for the wasm SQLite build.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use core::future::ready;
use core::time::Duration;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use connetto_client::{ClientBuilder, FirstThen, ReconnectPolicy, SyncSchema};
use connetto_core::messages::{
    BulkMessage, ControlMessage, FatalError, FatalErrorReason, Handshake, HandshakeAck, SyncStatus,
    WriterGrant, WriterRequest,
};
use connetto_core::schema::{SchemaBundle, SchemaVersion};
use connetto_core::test_support::FakeTransportError;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, Major, PROTOCOL_VERSION};
use connetto_web::{HubReconnect, MessageTransport, RelayHub};
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::MessagePort;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The major line the test schema source declares.
const SOURCE: &str = "-- connetto:major 1";

/// The major [`SOURCE`] declares, which a tab built from it presents.
fn major() -> Major {
    Major::declared_in(SOURCE).expect("the source declares major 1")
}

const DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

/// The client schema over [`DDL`].
fn schema() -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            SOURCE,
            "",
            DDL,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )
        .expect("the source declares major 1"),
    )
}

/// How one fake upstream answers its handshake and then behaves.
struct Script {
    /// Refuse the handshake with this reason instead of acknowledging it.
    refuse: Option<FatalErrorReason>,
    /// Stay open after the inbox drains rather than reporting end of stream.
    silent: bool,
}

impl Script {
    fn refusing(reason: FatalErrorReason) -> Self {
        Self {
            refuse: Some(reason),
            silent: false,
        }
    }

    fn accepting(silent: bool) -> Self {
        Self {
            refuse: None,
            silent,
        }
    }
}

/// A fake upstream that answers the handshake from its script and then ends
/// its stream, or stays open until the test hands it a close reason, as a
/// server that closes a live session with a reason does.
struct FakeUpstream {
    script: Script,
    close: tokio::sync::mpsc::UnboundedReceiver<FatalErrorReason>,
    inbox: Mutex<VecDeque<IncomingFrame>>,
}

impl FakeUpstream {
    fn scripted(script: Script) -> (Self, tokio::sync::mpsc::UnboundedSender<FatalErrorReason>) {
        let (close, rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                script,
                close: rx,
                inbox: Mutex::new(VecDeque::new()),
            },
            close,
        )
    }

    fn answer(&self, writer: Option<WriterGrant>) -> IncomingFrame {
        match &self.script.refuse {
            Some(reason) => {
                IncomingFrame::Control(ControlMessage::FatalError(FatalError::new(reason.clone())))
            }
            None => IncomingFrame::Control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "connection-hub-fake".to_owned(),
                session_token: "00000000-0000-4000-8000-000000000000".to_owned(),
                resume_token: "run:00000000-0000-4000-8000-000000000000".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: None::<SchemaVersion>,
                initial_credits: 64,
                writer,
            })),
        }
    }
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the trait methods are async and the bodies finish without awaiting"
)]
impl Transport for FakeUpstream {
    type Error = FakeTransportError;

    async fn send_control(&mut self, message: ControlMessage) -> Result<(), FakeTransportError> {
        if let ControlMessage::Handshake(handshake) = &message {
            let writer = match &handshake.writer {
                WriterRequest::Device => None,
                WriterRequest::Issue | WriterRequest::Number(_) => Some(WriterGrant {
                    number: 1,
                    frontier: 0,
                }),
            };
            self.inbox.lock().unwrap().push_back(self.answer(writer));
        }
        Ok(())
    }

    async fn send_bulk(&mut self, _message: BulkMessage) -> Result<(), FakeTransportError> {
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, FakeTransportError> {
        loop {
            let pending = {
                let mut inbox = self.inbox.lock().unwrap();
                inbox.pop_front()
            };
            if let Some(frame) = pending {
                return Ok(Some(frame));
            }
            if !self.script.silent {
                return Ok(None);
            }
            let Some(reason) = self.close.recv().await else {
                return Ok(None);
            };
            self.inbox.lock().unwrap().push_back(IncomingFrame::Control(
                ControlMessage::FatalError(FatalError::new(reason)),
            ));
        }
    }

    async fn close(&mut self) -> Result<(), FakeTransportError> {
        Ok(())
    }
}

/// A dial plan the hub's reconnect factory serves in order, with a count of
/// every dial the test can assert. The fakes' close senders stay held here,
/// so a plan fake never reports end of stream on its own.
struct Plan {
    scripts: Mutex<VecDeque<Script>>,
    closers: Mutex<Vec<tokio::sync::mpsc::UnboundedSender<FatalErrorReason>>>,
    dials: AtomicUsize,
    dialed: Mutex<Vec<&'static str>>,
}

impl Plan {
    fn new(scripts: Vec<Script>) -> Self {
        Self {
            scripts: Mutex::new(scripts.into()),
            closers: Mutex::new(Vec::new()),
            dials: AtomicUsize::new(0),
            dialed: Mutex::new(Vec::new()),
        }
    }

    fn dial(&self) -> FakeUpstream {
        self.dials.fetch_add(1, Ordering::Relaxed);
        let script = self
            .scripts
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Script::accepting(false));
        self.dialed
            .lock()
            .unwrap()
            .push(if script.refuse.is_some() {
                "refusing"
            } else {
                "accepting"
            });
        let (upstream, close) = FakeUpstream::scripted(script);
        self.closers.lock().unwrap().push(close);
        upstream
    }

    fn dials(&self) -> usize {
        self.dials.load(Ordering::Relaxed)
    }

    fn dialed(&self) -> Vec<&'static str> {
        self.dialed.lock().unwrap().clone()
    }
}

/// The waits the hub asked its sleeper for, in order.
struct Waits {
    waits: Mutex<Vec<Duration>>,
}

impl Waits {
    fn new() -> Self {
        Self {
            waits: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, wait: Duration) {
        self.waits.lock().unwrap().push(wait);
    }

    fn take(&self) -> Vec<Duration> {
        self.waits.lock().unwrap().to_vec()
    }
}

/// A dialer handing out `transport` once and nothing after.
fn once<T: Transport + 'static>(
    transport: T,
) -> FirstThen<impl FnMut() -> core::future::Ready<Result<T, FakeTransportError>>> {
    FirstThen::new(transport, || ready(Err(FakeTransportError::Closed)))
}

/// A hub over a scripted upstream with the test's reconnect wiring, and the
/// tab end of a real message channel attached before the pump starts, so the
/// tab is registered before any upstream outcome can end the hub.
async fn hub_with_tab(
    worker_script: Script,
    plan: Arc<Plan>,
    waits: Arc<Waits>,
) -> (
    MessageTransport<MessagePort>,
    tokio::sync::mpsc::UnboundedSender<FatalErrorReason>,
) {
    let (worker, worker_close) = FakeUpstream::scripted(worker_script);
    let client = ClientBuilder::new(schema(), once(worker))
        .with_client_id("mismatch-worker")
        .connect_driven()
        .await
        .expect("worker connect");
    let factory = move || {
        let upstream = plan.dial();
        ready(Ok::<_, FakeTransportError>(upstream))
    };
    let sleeper = move |wait: Duration| {
        waits.record(wait);
        connetto_web::workers::sleep(wait)
    };
    let (hub, pump, _notices) = RelayHub::with_reconnect(
        client,
        ":memory:",
        HubReconnect {
            factory,
            sleeper,
            policy: ReconnectPolicy::new(),
            upstream: vec![],
        },
    )
    .expect("hub meta");
    let channel = web_sys::MessageChannel::new().expect("message channel");
    hub.attach(MessageTransport::<MessagePort>::new(channel.port1()));
    spawn_local(async move {
        pump.await.expect("hub pump");
    });
    (
        MessageTransport::<MessagePort>::new(channel.port2()),
        worker_close,
    )
}

/// One frame from the tab, or a deadline failure when the hub goes quiet.
async fn next_frame(tab: &mut MessageTransport<MessagePort>, what: &str) -> IncomingFrame {
    next_frame_within(tab, what, Duration::from_secs(5)).await
}

/// One frame from the tab within `window`, or a deadline failure.
async fn next_frame_within(
    tab: &mut MessageTransport<MessagePort>,
    what: &str,
    window: Duration,
) -> IncomingFrame {
    let frame = tokio::select! {
        frame = tab.recv() => frame.expect("the tab's transport"),
        () = connetto_web::workers::sleep(window) => {
            panic!("the hub never {what} within {window:?}")
        }
    };
    match frame {
        Some(frame) => frame,
        None => panic!("the hub closed the tab before it {what}"),
    }
}

/// The refusal the tab draws, skipping whatever the hub sends first.
async fn next_fatal(tab: &mut MessageTransport<MessagePort>) -> FatalErrorReason {
    loop {
        let frame = next_frame(tab, "refused the tab").await;
        if let IncomingFrame::Control(ControlMessage::FatalError(fatal)) = frame {
            return fatal.reason;
        }
    }
}

/// A tab handshake that lands its ack, skipping whatever the hub sends first.
async fn handshake(tab: &mut MessageTransport<MessagePort>) {
    tab.send_control(ControlMessage::Handshake(
        Handshake::new(PROTOCOL_VERSION, "a-tab").with_major(major()),
    ))
    .await
    .expect("post the tab handshake");
    loop {
        let frame = next_frame(tab, "acknowledged the tab").await;
        if matches!(
            frame,
            IncomingFrame::Control(ControlMessage::HandshakeAck(_))
        ) {
            return;
        }
    }
}

/// The hub's own attach drew a refusal its build can never attach under, so
/// the hub ends and tells every attached tab the reason it would have heard
/// from a refused handshake.
#[wasm_bindgen_test]
async fn a_hub_that_cannot_attach_tells_its_tabs_why() {
    let mismatch = FatalErrorReason::MajorMismatch {
        server: Major::new(2).expect("two is a major"),
        client: Some(major()),
    };
    let plan = Arc::new(Plan::new(vec![Script::refusing(mismatch.clone())]));
    let (mut tab, _close) = hub_with_tab(
        Script::accepting(false),
        Arc::clone(&plan),
        Arc::new(Waits::new()),
    )
    .await;
    let refusal = next_fatal(&mut tab).await;
    assert_eq!(
        refusal, mismatch,
        "the tab hears the reason the attach drew"
    );
    assert_eq!(plan.dials(), 1, "the hub dials once and ends");
    let closed = tokio::select! {
        frame = tab.recv() => frame.expect("the tab's transport"),
        () = connetto_web::workers::sleep(Duration::from_secs(5)) => {
            panic!("the hub never ended after the refusal")
        }
    };
    assert!(closed.is_none(), "the ended hub closes the tab's channel");
}

/// A live close that names a reason the hub's build can never attach under
/// skips the first redial, since the hub already answered the question the
/// redial would ask again.
#[wasm_bindgen_test]
async fn a_live_close_of_the_terminal_class_ends_the_hub_without_a_redial() {
    let mismatch = FatalErrorReason::MajorMismatch {
        server: Major::new(2).expect("two is a major"),
        client: Some(major()),
    };
    let plan = Arc::new(Plan::new(vec![]));
    let (mut tab, worker_close) = hub_with_tab(
        Script::accepting(true),
        Arc::clone(&plan),
        Arc::new(Waits::new()),
    )
    .await;
    handshake(&mut tab).await;
    worker_close
        .send(mismatch.clone())
        .expect("the worker close");
    let refusal = next_fatal(&mut tab).await;
    assert_eq!(refusal, mismatch);
    assert_eq!(
        plan.dials(),
        0,
        "the redial the close already answered was skipped"
    );
}

/// The hub's resume is refused with a rate-limit that names a window, so the
/// hub's next wait floors on that window instead of probing the answer, and the
/// tabs keep being served once the resume lands.
#[wasm_bindgen_test]
async fn a_rate_limited_refusal_floors_the_hubs_next_wait() {
    let rate_limited = FatalErrorReason::RateLimited {
        retry_after_ms: 5000,
    };
    let plan = Arc::new(Plan::new(vec![
        Script::refusing(rate_limited.clone()),
        Script::accepting(true),
    ]));
    let waits = Arc::new(Waits::new());
    let (mut tab, worker_close) =
        hub_with_tab(Script::accepting(true), Arc::clone(&plan), waits.clone()).await;
    handshake(&mut tab).await;
    worker_close
        .send(rate_limited.clone())
        .expect("the worker close");
    // The close posts an Offline, so waiting on it first skips whatever the
    // hub sent the tab while the worker was still live.
    loop {
        let frame = next_frame_within(&mut tab, "went offline", Duration::from_secs(10)).await;
        if matches!(
            frame,
            IncomingFrame::Control(ControlMessage::SyncStatus(SyncStatus::Offline))
        ) {
            break;
        }
    }
    loop {
        let frame = next_frame_within(
            &mut tab,
            "restated the connection status",
            Duration::from_secs(10),
        )
        .await;
        if matches!(
            frame,
            IncomingFrame::Control(ControlMessage::SyncStatus(SyncStatus::Connected))
        ) {
            break;
        }
    }
    let waits = waits.take();
    assert!(
        waits.len() >= 2,
        "the hub waited between every two dials, got {waits:?}, dials = {}, dialed = {:?}",
        plan.dials(),
        plan.dialed()
    );
    assert!(
        *waits.last().expect("a recorded wait") >= Duration::from_millis(5000),
        "the wait after the rate-limited refusal floors on the server's window, got {waits:?}"
    );
    assert_eq!(plan.dials(), 2);
}
