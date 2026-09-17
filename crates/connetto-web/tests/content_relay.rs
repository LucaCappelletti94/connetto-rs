//! The tab-to-worker content lane over a real message channel: staged files
//! commit with the mutation that names them, mismatches are refused, and
//! resolution answers from the worker's store, the server ticket, or nowhere.

use core::convert::Infallible;
use core::future::{Future, ready};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientConfig, ConnettoConnection, Grant, Replica};
use connetto_core::Cursor;
use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{
    BulkMessage, CONTENT_TICKET_REFUSED, ContentTicketGrant, ControlMessage, Handshake,
    HandshakeAck, MutationHeader, MutationPatch, MutationReject, MutationRejectReason,
    NonFatalError,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_file_client::{BrowserHttp, BrowserStore, ContentArchive};
use connetto_file_core::{FileId, FileIdHasher, MimeClass};
use connetto_web::content_wire::{ContentFrame, WireResolve, mime_code};
use connetto_web::relay::{HubReconnect, RelayHub};
use connetto_web::workers::DB_ALIVE_LOCK;
use connetto_web::{InternalInbound, MessageTransport, locks};
use diesel::Connection;
use diesel::connection::SimpleConnection;
use futures_channel::mpsc;
use futures_util::StreamExt;
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

use support::{install_content_transport, timeout_ms, until};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DDL: &str = "CREATE TABLE photos (id INTEGER PRIMARY KEY, content_id BLOB NOT NULL)";
const TEST_LOCK: &str = "connetto-content-relay-test";
/// A protocol-shaped id for the scripted tab; the hub stores it as the tab's
/// watermark key.
const TAB_CLIENT_ID: &str = "6f1c9d2e-8a4b-4c5d-9e6f-0a1b2c3d4e5f";

/// Distinct bytes per test: a relay a finished test left running keeps driving
/// its own outbox against whatever `fetch` the current test installed.
const COMMIT_PHOTO: &[u8] = b"a photograph whose row and bytes commit as one hub mutation";
const REFUSE_PHOTO: &[u8] = b"a photograph whose declared identity is a lie";
const UNPAIRED_PHOTO: &[u8] = b"a staged photograph no mutation ever names";
const LOCAL_PHOTO: &[u8] = b"a photograph resolved back over the lane before upload";
const REMOTE_PHOTO: &[u8] = b"a photograph resolved to its server address after upload";

struct Upstream {
    incoming: mpsc::UnboundedReceiver<IncomingFrame>,
    answers: mpsc::UnboundedSender<IncomingFrame>,
    mutations: Rc<Cell<u32>>,
    grant_tickets: bool,
}

impl Upstream {
    /// A live upstream answering the handshake, counting forwarded mutations,
    /// and answering every content ticket per `grant_tickets`.
    fn live(mutations: Rc<Cell<u32>>, grant_tickets: bool) -> Self {
        let (answers, incoming) = mpsc::unbounded();
        answers
            .unbounded_send(IncomingFrame::Control(ControlMessage::HandshakeAck(
                HandshakeAck {
                    connection_id: "r69c-relay".to_owned(),
                    session_token: "r69c-relay".to_owned(),
                    resume_token: "r69c-relay".to_owned(),
                    current_cursor: Cursor::new(Vec::new()),
                    schema_version: None,
                    initial_credits: 64,
                    last_applied_seq: None,
                },
            )))
            .expect("queue handshake");
        Self {
            incoming,
            answers,
            mutations,
            grant_tickets,
        }
    }
}

impl Transport for Upstream {
    type Error = Infallible;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        if let ControlMessage::ContentTicketRequest(request) = message {
            let reply = if self.grant_tickets {
                ControlMessage::ContentTicketGrant(ContentTicketGrant {
                    request_id: request.request_id,
                    url: format!(
                        "https://content.invalid/files/{}/intent?t=r69c",
                        FileId::from_bytes(request.file_id)
                    ),
                })
            } else {
                ControlMessage::NonFatalError(NonFatalError {
                    related_to: Some(request.request_id),
                    detail: CONTENT_TICKET_REFUSED.to_owned(),
                })
            };
            self.answers
                .unbounded_send(IncomingFrame::Control(reply))
                .expect("queue ticket");
        }
        ready(Ok(()))
    }

    fn send_bulk(&mut self, message: BulkMessage) -> impl Future<Output = Result<(), Self::Error>> {
        if matches!(message, BulkMessage::MutationPatch(_)) {
            self.mutations.set(self.mutations.get() + 1);
        }
        ready(Ok(()))
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        Ok(self.incoming.next().await)
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }
}

fn hub_config() -> ClientConfig {
    ClientConfig::new("r69c-content-relay").with_login(Some(Grant::new("user:r69c")))
}

/// A content-aware hub on a live fake upstream, plus this test's mutation
/// counter, and the tab transport on the other end of a real message channel,
/// already handshaken.
async fn relay_with_tab(
    store_name: &str,
    key: [u8; 32],
    grants: bool,
) -> (RelayHub, Rc<Cell<u32>>, MessageTransport<MessagePort>) {
    let mutations = Rc::new(Cell::new(0u32));
    let worker = ConnettoConnection::<Upstream>::connect(
        Upstream::live(Rc::clone(&mutations), grants),
        &Replica::in_memory(),
        DDL,
        &hub_config(),
        None,
    )
    .await
    .expect("connect relay replica");
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("dedicated worker");
    let store = BrowserStore::install(&scope, store_name)
        .await
        .expect("install store");
    let content = ContentArchive::new(store, key);
    let (hub, pump, _notices) = RelayHub::with_reconnect_and_content(
        worker,
        ":memory:",
        HubReconnect {
            factory: {
                let mutations = Rc::clone(&mutations);
                move || {
                    ready(Ok::<_, Infallible>(Upstream::live(
                        Rc::clone(&mutations),
                        grants,
                    )))
                }
            },
            // A refused ticket retries on this timer. An instant sleeper
            // turns that backoff into a busy loop that starves the worker,
            // so the fixture sleeps for real, capped to keep tests bounded.
            sleeper: |delay: core::time::Duration| async move {
                let ms = delay.as_millis().clamp(1, 500);
                timeout_ms(i32::try_from(ms).expect("capped above")).await;
            },
            policy: ReconnectPolicy::new(),
            upstream: Vec::new(),
        },
        content,
        BrowserHttp::new(),
    )
    .expect("content relay");
    spawn_local(async move {
        pump.await.expect("relay pump");
    });
    let channel = web_sys::MessageChannel::new().expect("message channel");
    hub.attach_with_content(MessageTransport::<MessagePort>::new(channel.port1()));
    let mut tab = MessageTransport::<MessagePort>::new(channel.port2());
    tab.send_control(ControlMessage::Handshake(Handshake::new(
        PROTOCOL_VERSION,
        TAB_CLIENT_ID,
    )))
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
    (hub, mutations, tab)
}

fn blob_of(bytes: &[u8]) -> web_sys::Blob {
    let arr = Uint8Array::from(bytes);
    web_sys::Blob::new_with_u8_array_sequence(&Array::of1(&arr)).expect("blob from bytes")
}

fn declared_id(bytes: &[u8]) -> FileId {
    let mut hasher = FileIdHasher::new();
    hasher.update(bytes);
    hasher.finalize()
}

fn stage(tab: &MessageTransport<MessagePort>, file_id: FileId, blob: &web_sys::Blob) {
    let frame = ContentFrame::Stage {
        file_id: *file_id.as_bytes(),
        mime: mime_code(MimeClass::Jpeg),
    };
    tab.post_internal(&frame.to_json(), Some(blob))
        .expect("post stage");
}

fn resolve(tab: &MessageTransport<MessagePort>, request_id: u64, file_id: FileId) {
    let frame = ContentFrame::Resolve {
        request_id,
        file_id: *file_id.as_bytes(),
    };
    tab.post_internal(&frame.to_json(), None)
        .expect("post resolve");
}

/// The changeset of one `photos` insert declaring `content_id`, captured from
/// a throwaway replica the way a tab's own capture would produce it.
fn captured_insert(content_id: &[u8]) -> Vec<u8> {
    use diesel_sqlite_session::SqliteSessionExt;
    let mut hex = String::new();
    for byte in content_id {
        std::fmt::write(&mut hex, format_args!("{byte:02x}")).expect("string append");
    }
    let mut conn = diesel::SqliteConnection::establish(":memory:").expect("open");
    conn.batch_execute(DDL).expect("schema");
    let mut session = conn.create_session().expect("session");
    session.attach_all().expect("attach");
    conn.batch_execute(&format!("INSERT INTO photos VALUES (1, x'{hex}')"))
        .expect("insert");
    session.changeset().expect("changeset")
}

async fn send_mutation(tab: &mut MessageTransport<MessagePort>, seq: u64, changeset: &[u8]) {
    tab.send_control(ControlMessage::MutationHeader(MutationHeader {
        client_seq: seq,
        op_count: 1,
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

async fn recv_control(
    tab: &mut MessageTransport<MessagePort>,
    patience: i32,
) -> Option<ControlMessage> {
    tokio::select! {
        frame = tab.recv() => match frame.expect("transport") {
            Some(IncomingFrame::Control(message)) => Some(message),
            Some(IncomingFrame::Bulk(bulk)) => panic!("unexpected bulk toward the tab: {bulk:?}"),
            None => panic!("the hub closed the tab"),
        },
        () = timeout_ms(patience) => None,
    }
}

async fn next_reply(
    inbox: &mut mpsc::UnboundedReceiver<InternalInbound>,
) -> (u64, WireResolve, Option<web_sys::Blob>) {
    let inbound = tokio::select! {
        inbound = inbox.next() => inbound.expect("the lane stays open"),
        () = timeout_ms(3_000) => panic!("the hub never answered the resolve"),
    };
    match ContentFrame::from_json(&inbound.json).expect("decodable reply") {
        ContentFrame::ResolveReply { request_id, answer } => (request_id, answer, inbound.blob),
        frame => panic!("the lane answered a resolve with {frame:?}"),
    }
}

fn blob_bytes(blob: &web_sys::Blob) -> Vec<u8> {
    let reader = web_sys::FileReaderSync::new().expect("FileReaderSync in worker");
    let buffer = reader.read_as_array_buffer(blob).expect("read blob");
    Uint8Array::new(&buffer).to_vec()
}

fn uploads_of(uploaded: &RefCell<Vec<Vec<u8>>>, photo: &[u8]) -> usize {
    uploaded
        .borrow()
        .iter()
        .filter(|body| body.as_slice() == photo)
        .count()
}

/// A staged file plus a row naming its id: the hub commits the manifest with
/// the mutation, forwards it once, and the driver uploads the bytes.
#[wasm_bindgen_test]
async fn a_staged_file_and_its_row_reach_the_hub_as_one_mutation() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let stubs = install_content_transport(&uploaded);
    let (_hub, mutations, mut tab) = relay_with_tab("r69c-staged-commit", [11; 32], true).await;
    let file_id = declared_id(COMMIT_PHOTO);
    stage(&tab, file_id, &blob_of(COMMIT_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(file_id.as_bytes())).await;
    assert!(
        until(async || uploads_of(&uploaded, COMMIT_PHOTO) == 1).await,
        "the staged file must upload"
    );
    assert_eq!(mutations.get(), 1, "the mutation reaches the server");
    for _ in 0..4 {
        let Some(message) = recv_control(&mut tab, 250).await else {
            break;
        };
        assert!(
            !matches!(message, ControlMessage::MutationReject(_)),
            "the staged mutation must be accepted, got {message:?}"
        );
    }
    drop(stubs);
    serial.release();
}

#[wasm_bindgen_test]
async fn a_declaration_that_is_not_the_blob_is_refused_and_uploads_nothing() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let stubs = install_content_transport(&uploaded);
    let (_hub, mutations, mut tab) = relay_with_tab("r69c-staged-mismatch", [12; 32], true).await;
    // The lane declares an identity the bytes do not hash to, and the row
    // names that same lie, so pairing succeeds and the recomputed hash fails.
    let lie = FileId::from_bytes([9; 32]);
    stage(&tab, lie, &blob_of(REFUSE_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(lie.as_bytes())).await;
    let mut reject = None;
    for _ in 0..8 {
        match recv_control(&mut tab, 1_000).await {
            Some(ControlMessage::MutationReject(rejection)) => {
                reject = Some(rejection);
                break;
            }
            Some(_) => {}
            None => break,
        }
    }
    let detail = match reject {
        Some(MutationReject {
            reason: MutationRejectReason::Other { detail },
            ..
        }) => detail,
        other => panic!("the lying declaration must be refused, got {other:?}"),
    };
    assert!(
        detail.contains("hash to"),
        "the refusal names the hash, got {detail}"
    );
    assert_eq!(
        mutations.get(),
        0,
        "a refused mutation never reaches the server"
    );
    timeout_ms(300).await;
    assert!(
        uploaded.borrow().is_empty(),
        "a refused commit uploads nothing"
    );
    drop(stubs);
    serial.release();
}

#[wasm_bindgen_test]
async fn content_that_no_mutation_names_uploads_nothing() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let stubs = install_content_transport(&uploaded);
    // Tickets are refused, so even a wrongly paired stage cannot upload, and
    // the age-out probe below cannot be answered from a server ticket.
    let (_hub, mutations, mut tab) = relay_with_tab("r69c-staged-unpaired", [13; 32], false).await;
    stage(&tab, declared_id(UNPAIRED_PHOTO), &blob_of(UNPAIRED_PHOTO));
    // The row names a three-byte value, not a file identity, so nothing
    // pairs and the mutation goes out as an ordinary one.
    send_mutation(&mut tab, 1, &captured_insert(&[0xAA, 0xBB, 0xCC])).await;
    assert!(
        until(async || mutations.get() == 1).await,
        "the unnamed mutation is an ordinary one and must still forward"
    );
    for _ in 0..4 {
        let Some(message) = recv_control(&mut tab, 250).await else {
            break;
        };
        assert!(
            !matches!(message, ControlMessage::MutationReject(_)),
            "an unpaired stage is no reason to refuse the mutation, got {message:?}"
        );
    }
    timeout_ms(300).await;
    assert!(
        uploaded.borrow().is_empty() && mutations.get() == 1,
        "the mutation forwards as an ordinary one and uploads nothing"
    );
    // The stage must have aged out of the hub's books too: an ordinary
    // mutation must not have left it resolvable as local content.
    let mut inbox = tab.take_internal_inbox().expect("the lane is the tab's");
    resolve(&tab, 6, declared_id(UNPAIRED_PHOTO));
    let (request_id, answer, blob) = next_reply(&mut inbox).await;
    assert_eq!(request_id, 6, "the reply answers the age-out probe");
    assert!(
        matches!(answer, WireResolve::Unavailable),
        "an unpaired stage must leave nothing resolvable, got {answer:?}"
    );
    assert!(blob.is_none(), "an Unavailable answer carries no bytes");
    drop(stubs);
    serial.release();
}

#[wasm_bindgen_test]
async fn an_unsent_staged_file_resolves_to_its_own_bytes() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    // Tickets are refused, so the upload can never complete and the file
    // stays unsent, which is exactly the state a local answer comes from.
    let (_hub, mutations, mut tab) = relay_with_tab("r69c-resolve-local", [14; 32], false).await;
    let mut inbox = tab.take_internal_inbox().expect("the lane is the tab's");
    let file_id = declared_id(LOCAL_PHOTO);
    stage(&tab, file_id, &blob_of(LOCAL_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(file_id.as_bytes())).await;
    assert!(
        until(async || mutations.get() == 1).await,
        "the row commits"
    );
    resolve(&tab, 7, file_id);
    let (request_id, answer, blob) = next_reply(&mut inbox).await;
    assert_eq!(request_id, 7, "the reply carries the request's own id");
    assert!(
        matches!(answer, WireResolve::Local),
        "an unsent file answers Local, got {answer:?}"
    );
    let bytes = blob_bytes(&blob.expect("a Local answer carries the bytes"));
    assert_eq!(
        bytes, LOCAL_PHOTO,
        "the lane carries the exact staged bytes"
    );
    serial.release();
}

#[wasm_bindgen_test]
async fn an_uploaded_file_resolves_to_a_server_address() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let stubs = install_content_transport(&uploaded);
    let (_hub, _mutations, mut tab) = relay_with_tab("r69c-resolve-remote", [15; 32], true).await;
    let mut inbox = tab.take_internal_inbox().expect("the lane is the tab's");
    let file_id = declared_id(REMOTE_PHOTO);
    stage(&tab, file_id, &blob_of(REMOTE_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(file_id.as_bytes())).await;
    assert!(
        until(async || uploads_of(&uploaded, REMOTE_PHOTO) == 1).await,
        "the file must finish uploading before the resolve"
    );
    // The recorded upload is the request's send, not the dequeuing write
    // that follows the server's answer, so the file can still read as
    // unsent for a moment here. Retry until it reads sent.
    let mut remote = None;
    for attempt in 0..30 {
        resolve(&tab, 8 + attempt, file_id);
        let (reply_id, answer, blob) = next_reply(&mut inbox).await;
        assert_eq!(reply_id, 8 + attempt, "the reply answers its own request");
        match answer {
            WireResolve::Remote { url } => {
                assert!(blob.is_none(), "a Remote answer carries no bytes");
                remote = Some(url);
                break;
            }
            WireResolve::Local => timeout_ms(100).await,
            WireResolve::Unavailable => {
                panic!("an uploaded granted file must answer Remote, not Unavailable");
            }
        }
    }
    let url = remote.expect("the uploaded file answers Remote within the retries");
    assert!(
        url.contains(&file_id.to_string()),
        "the ticket names the file, got {url}"
    );
    drop(stubs);
    serial.release();
}

#[wasm_bindgen_test]
async fn a_file_the_hub_never_saw_answers_unavailable() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let (_hub, _mutations, mut tab) = relay_with_tab("r69c-resolve-unknown", [16; 32], false).await;
    let mut inbox = tab.take_internal_inbox().expect("the lane is the tab's");
    resolve(&tab, 9, FileId::from_bytes([5; 32]));
    let (request_id, answer, blob) = next_reply(&mut inbox).await;
    assert_eq!(request_id, 9);
    assert!(
        matches!(answer, WireResolve::Unavailable),
        "no manifest and a refused ticket answer Unavailable, got {answer:?}"
    );
    assert!(blob.is_none());
    serial.release();
}
