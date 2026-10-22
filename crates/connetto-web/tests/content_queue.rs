//! The tab's queue reads and actions over the real content lane. A refused
//! upload is listed with its detail and retried once the server accepts it,
//! and a retired file is listed and forgotten, all through a tab rather than
//! the hub directly.

use core::convert::Infallible;
use core::future::{Future, ready};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientBuilder, FirstThen, Grant, HeldCredential, SyncSchema};
use connetto_core::Cursor;
use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{
    BulkMessage, ContentTicketGrant, ControlMessage, Handshake, HandshakeAck, MutationHeader,
    MutationPatch, WriterGrant,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_file_client::{BrowserHttp, BrowserStore, ContentArchive};
use connetto_file_core::{ChunkHash, ChunkInventory, ChunkStore, FileId, FileIdHasher, MimeClass};
use connetto_web::content_wire::{ContentFrame, mime_code};
use connetto_web::relay::HubReconnect;
use connetto_web::workers::DB_ALIVE_LOCK;
use connetto_web::{MessageTransport, TabContent, TabResolved, locks};
use diesel::Connection;
use diesel::connection::SimpleConnection;
use futures_channel::mpsc;
use futures_util::StreamExt;
use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, future_to_promise, spawn_local};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{DedicatedWorkerGlobalScope, MessagePort, Request};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DDL: &str = "CREATE TABLE photos (id INTEGER PRIMARY KEY, content_id BLOB NOT NULL)";
const TEST_LOCK: &str = "connetto-content-queue-test";
/// The scripted tab's client id, from which the hub derives its watermark key.
const TAB_CLIENT_ID: &str = "7a2d4e6f-1b3c-4d5e-8f9a-0b1c2d3e4f5a";

/// Distinct bytes per test: a relay a finished test left running keeps driving
/// its own outbox against whatever `fetch` the current test installed.
const REFUSED_PHOTO: &[u8] = b"a photograph the file server turns away on storage quota";
const LOST_PHOTO: &[u8] = b"a photograph whose stored bytes the test lets go";
const PINNED_PHOTO: &[u8] = b"a photograph a pin keeps after its stored bytes are lost";
const TIDY_KEPT: &[u8] = b"a photograph a pin keeps when storage is tidied";
const TIDY_FREED: &[u8] = b"a photograph no pin keeps, so tidying frees it";
const TIDY_SACRIFICE: &[u8] = b"a photograph the sweep frees so the test sees it settle";

/// How the fake upstream answers content tickets.
#[derive(Clone)]
enum Tickets {
    /// Every request is granted.
    Grants,
}

struct Upstream {
    incoming: mpsc::UnboundedReceiver<IncomingFrame>,
    answers: mpsc::UnboundedSender<IncomingFrame>,
    mutations: Rc<Cell<u32>>,
    tickets: Tickets,
}

impl Upstream {
    /// A live upstream answering the handshake, counting forwarded mutations,
    /// and answering every content ticket per `tickets`.
    fn live(mutations: Rc<Cell<u32>>, tickets: Tickets) -> Self {
        let (answers, incoming) = mpsc::unbounded();
        answers
            .unbounded_send(IncomingFrame::Control(ControlMessage::HandshakeAck(
                HandshakeAck {
                    connection_id: "r69d-queue".to_owned(),
                    session_token: "r69d-queue".to_owned(),
                    resume_token: "r69d-queue".to_owned(),
                    current_cursor: Cursor::new(Vec::new()),
                    schema_version: None,
                    initial_credits: 64,
                    writer: Some(WriterGrant {
                        number: 1,
                        frontier: 0,
                    }),
                },
            )))
            .expect("queue handshake");
        Self {
            incoming,
            answers,
            mutations,
            tickets,
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
            let reply = match &self.tickets {
                Tickets::Grants => Some(ControlMessage::ContentTicketGrant(ContentTicketGrant {
                    request_id: request.request_id.clone(),
                    url: format!(
                        "https://content.invalid/files/{}/intent?t=r69d",
                        FileId::from_bytes(request.file_id)
                    ),
                })),
            };
            if let Some(reply) = reply {
                self.answers
                    .unbounded_send(IncomingFrame::Control(reply))
                    .expect("queue ticket");
            }
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

/// The client schema over [`DDL`].
fn schema() -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "",
        "",
        DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        None::<&str>,
    ))
}

/// A dialer handing out `transport` once and nothing after.
fn once<T: Transport + 'static>(
    transport: T,
) -> FirstThen<impl FnMut() -> core::future::Ready<Result<T, &'static str>>> {
    FirstThen::new(transport, || core::future::ready(Err("spent")))
}

/// A content-aware hub on a live fake upstream plus the tab transport on the
/// other end of a real message channel, already handshaken.
///
/// Hands back the mutation counter, a sender onto the upstream's inbound
/// queue and the store the hub's archive wrote into, so a test can let the
/// stored bytes go.
async fn relay_tab(
    store_name: &str,
    key: [u8; 32],
    tickets: Tickets,
) -> (
    connetto_web::RelayHub,
    Rc<Cell<u32>>,
    MessageTransport<MessagePort>,
    mpsc::UnboundedSender<IncomingFrame>,
    BrowserStore,
) {
    let mutations = Rc::new(Cell::new(0u32));
    let upstream = Upstream::live(Rc::clone(&mutations), tickets.clone());
    let answers = upstream.answers.clone();
    let worker = ClientBuilder::new(schema(), once(upstream))
        .signed_in(
            HeldCredential::new(Grant::new("user:r69d"), "r69d")
                .expect("a string identity serializes"),
        )
        .connect_driven()
        .await
        .expect("connect relay replica");
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("dedicated worker");
    let store = BrowserStore::install(&scope, store_name)
        .await
        .expect("install store");
    let content = ContentArchive::new(store.clone(), key);
    let (hub, pump, _notices) = connetto_web::RelayHub::with_reconnect_and_content(
        worker,
        ":memory:",
        HubReconnect {
            factory: {
                let mutations = Rc::clone(&mutations);
                let tickets = tickets.clone();
                move || {
                    ready(Ok::<_, Infallible>(Upstream::live(
                        Rc::clone(&mutations),
                        tickets.clone(),
                    )))
                }
            },
            // A deferred attempt retries on this timer. An instant sleeper
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
    (hub, mutations, tab, answers, store)
}

/// A `fetch` whose commit answer carries the status the test holds in a cell,
/// while the intent answers the way the file server does. Restores the
/// original global on drop.
struct StatusFetch {
    _restore: Replaced,
}

impl StatusFetch {
    fn install(status: &Rc<Cell<u16>>) -> Self {
        let held_status = Rc::clone(status);
        let closure = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |value: JsValue| {
            let request = value.dyn_into::<Request>().expect("fetch receives Request");
            let held_status = Rc::clone(&held_status);
            future_to_promise(async move {
                let body = JsFuture::from(request.array_buffer()?).await?;
                let body = Uint8Array::new(&body).to_vec();
                if request.url().contains("/intent?") {
                    let intent: serde_json::Value =
                        serde_json::from_slice(&body).expect("decode upload intent");
                    let needed: Vec<&str> = intent["chunks"]
                        .as_array()
                        .expect("intent chunks")
                        .iter()
                        .map(|chunk| chunk["hash"].as_str().expect("chunk hash"))
                        .collect();
                    let answer = serde_json::json!({ "needed": needed }).to_string();
                    Ok(response(Some(&answer), 200))
                } else {
                    Ok(response(None, held_status.get()))
                }
            })
        });
        let replacement: JsValue = closure.as_ref().clone();
        Self {
            _restore: install_global("fetch", &replacement, closure),
        }
    }
}

impl StatusFetch {
    /// Lets the named chunk go on each intent answer, before the upload reads it.
    fn install_losing(status: &Rc<Cell<u16>>, store: BrowserStore, chunk: &'static [u8]) -> Self {
        let held_status = Rc::clone(status);
        let closure = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |value: JsValue| {
            let request = value.dyn_into::<Request>().expect("fetch receives Request");
            let held_status = Rc::clone(&held_status);
            let held_store = store.clone();
            future_to_promise(async move {
                let body = JsFuture::from(request.array_buffer()?).await?;
                let body = Uint8Array::new(&body).to_vec();
                if request.url().contains("/intent?") {
                    let _ = held_store.delete_chunk(&ChunkHash::from_data(chunk)).await;
                    let intent: serde_json::Value =
                        serde_json::from_slice(&body).expect("decode upload intent");
                    let needed: Vec<&str> = intent["chunks"]
                        .as_array()
                        .expect("intent chunks")
                        .iter()
                        .map(|c| c["hash"].as_str().expect("chunk hash"))
                        .collect();
                    let answer = serde_json::json!({ "needed": needed }).to_string();
                    Ok(response(Some(&answer), 200))
                } else {
                    Ok(response(None, held_status.get()))
                }
            })
        });
        let replacement: JsValue = closure.as_ref().clone();
        Self {
            _restore: install_global("fetch", &replacement, closure),
        }
    }
}

/// A `fetch` answering the upload intent like the file server does and every
/// other request, the commit and every granted read URL, with the served
/// bytes. Restores the original global on drop.
struct ServingFetch {
    _restore: Replaced,
}

impl ServingFetch {
    fn install(served: &'static [u8]) -> Self {
        let closure = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |value: JsValue| {
            let request = value.dyn_into::<Request>().expect("fetch receives Request");
            future_to_promise(async move {
                let body = JsFuture::from(request.array_buffer()?).await?;
                let body = Uint8Array::new(&body).to_vec();
                if body.is_empty() {
                    Ok(response_bytes(Some(served), 200))
                } else {
                    let intent: serde_json::Value =
                        serde_json::from_slice(&body).expect("decode upload intent");
                    let needed: Vec<&str> = intent["chunks"]
                        .as_array()
                        .expect("intent chunks")
                        .iter()
                        .map(|chunk| chunk["hash"].as_str().expect("chunk hash"))
                        .collect();
                    let answer = serde_json::json!({ "needed": needed }).to_string();
                    Ok(response(Some(&answer), 200))
                }
            })
        });
        let replacement: JsValue = closure.as_ref().clone();
        Self {
            _restore: install_global("fetch", &replacement, closure),
        }
    }
}

/// An `fetch` answering the upload intent like the file server does and
/// every commit with `200`, counting the commits so a test can wait for the
/// outbox to drain. Restores the original global on drop.
struct CommitFetch {
    _restore: Replaced,
}

impl CommitFetch {
    fn install(commits: &Rc<Cell<u32>>) -> Self {
        let held = Rc::clone(commits);
        let closure = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |value: JsValue| {
            let request = value.dyn_into::<Request>().expect("fetch receives Request");
            let held = Rc::clone(&held);
            future_to_promise(async move {
                let body = JsFuture::from(request.array_buffer()?).await?;
                let body = Uint8Array::new(&body).to_vec();
                if body.is_empty() {
                    held.set(held.get() + 1);
                    Ok(response(None, 200))
                } else {
                    let intent: serde_json::Value =
                        serde_json::from_slice(&body).expect("decode upload intent");
                    let needed: Vec<&str> = intent["chunks"]
                        .as_array()
                        .expect("intent chunks")
                        .iter()
                        .map(|chunk| chunk["hash"].as_str().expect("chunk hash"))
                        .collect();
                    let answer = serde_json::json!({ "needed": needed }).to_string();
                    Ok(response(Some(&answer), 200))
                }
            })
        });
        let replacement: JsValue = closure.as_ref().clone();
        Self {
            _restore: install_global("fetch", &replacement, closure),
        }
    }
}

/// An `XMLHttpRequest` that answers `204` once its body has gone out, and
/// whose progress events are what a bounded upload observes.
const UPLOAD_STUB: &str = "(record) => class ScriptedUpload {
    constructor() {
        this.upload = {};
        this.status = 0;
        this.responseURL = '';
        this.response = null;
    }
    open(method, url) {
        this.method = method;
        this.url = url;
    }
    setRequestHeader() {}
    abort() {
        this.aborted = true;
        if (this.onabort) { this.onabort(); }
    }
    send(body) {
        if (this.upload.onprogress) { this.upload.onprogress(); }
        record(body);
        this.status = 204;
        this.responseURL = this.url;
        this.response = new ArrayBuffer(0);
        if (this.onload) { this.onload(); }
    }
};";

/// The chunk-`PUT` recorder, restored on drop.
struct UploadRecorder {
    _restore: Replaced,
}

impl UploadRecorder {
    fn install(uploaded: &Rc<RefCell<Vec<Vec<u8>>>>) -> Self {
        let captured = Rc::clone(uploaded);
        let record = Closure::<dyn FnMut(JsValue)>::new(move |body: JsValue| {
            let bytes = body
                .dyn_into::<Uint8Array>()
                .expect("the upload body is a byte array");
            captured.borrow_mut().push(bytes.to_vec());
        });
        let factory = js_sys::eval(UPLOAD_STUB).expect("evaluate the upload replacement");
        let replacement = factory
            .dyn_into::<js_sys::Function>()
            .expect("the upload replacement is a factory")
            .call1(&JsValue::UNDEFINED, record.as_ref())
            .expect("build the upload replacement");
        Self {
            _restore: install_global("XMLHttpRequest", &replacement, record),
        }
    }
}

/// A global replaced for the duration of one test, restored on drop.
struct Replaced {
    global: Object,
    key: JsValue,
    previous: JsValue,
    /// The callback the replacement calls from `JavaScript`, kept alive.
    #[expect(
        dead_code,
        reason = "the replacement calls the callback from JavaScript, so it outlives the test"
    )]
    kept: Box<dyn core::any::Any + 'static>,
}

impl Drop for Replaced {
    fn drop(&mut self) {
        let _ = Reflect::set(&self.global, &self.key, &self.previous);
    }
}

/// Replaces one global, keeping the callback the replacement calls alive and
/// restoring the original value on drop.
fn install_global(
    name: &str,
    replacement: &JsValue,
    kept: impl core::any::Any + 'static,
) -> Replaced {
    let global = js_sys::global();
    let key = JsValue::from_str(name);
    let previous = Reflect::get(&global, &key).expect("read the global");
    Reflect::set(&global, &key, replacement).expect("replace the global");
    Replaced {
        global,
        key,
        previous,
        kept: Box::new(kept),
    }
}

/// Answers like a `web_sys::Response` of `status` with the given body.
fn response_with(body: Option<JsValue>, status: u16) -> JsValue {
    let global = js_sys::global();
    let constructor = Reflect::get(&global, &JsValue::from_str("Response"))
        .expect("Response global")
        .dyn_into::<js_sys::Function>()
        .expect("Response constructor");
    let init = Object::new();
    Reflect::set(
        &init,
        &JsValue::from_str("status"),
        &JsValue::from_f64(f64::from(status)),
    )
    .expect("set the status");
    let arguments = Array::new();
    arguments.push(&body.unwrap_or(JsValue::NULL));
    arguments.push(&init);
    Reflect::construct(&constructor, &arguments).expect("build the response")
}

/// Answers like a `web_sys::Response` of `status` with an optional text body.
fn response(body: Option<&str>, status: u16) -> JsValue {
    response_with(body.map(JsValue::from_str), status)
}

/// Answers like a `web_sys::Response` of `status` with an optional byte body.
fn response_bytes(body: Option<&[u8]>, status: u16) -> JsValue {
    response_with(
        body.map(|body| JsValue::from(Uint8Array::from(body))),
        status,
    )
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

/// The changeset of one `photos` insert declaring `content_id` in row `row`,
/// captured from a throwaway replica the way a tab's own capture would
/// produce it.
fn captured_insert(row: u32, content_id: &[u8]) -> Vec<u8> {
    use diesel_sqlite_session::SqliteSessionExt;
    let mut hex = String::new();
    for byte in content_id {
        std::fmt::write(&mut hex, format_args!("{byte:02x}")).expect("string append");
    }
    let mut conn = diesel::SqliteConnection::establish(":memory:").expect("open");
    conn.batch_execute(DDL).expect("schema");
    let mut session = conn.create_session().expect("session");
    session.attach_all().expect("attach");
    conn.batch_execute(&format!("INSERT INTO photos VALUES ({row}, x'{hex}')"))
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

fn uploads_of(uploaded: &RefCell<Vec<Vec<u8>>>, photo: &[u8]) -> usize {
    uploaded
        .borrow()
        .iter()
        .filter(|body| body.as_slice() == photo)
        .count()
}

/// Polls per task turn rather than per microtask, because the worker's stored
/// bytes and its timers only advance on the macrotask queue.
const POLL_MS: i32 = 10;
/// Three seconds of turns, enough for a loaded CI machine.
const POLLS: usize = 300;

async fn timeout_ms(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        let set_timeout = Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .expect("read setTimeout")
            .dyn_into::<js_sys::Function>()
            .expect("setTimeout function");
        set_timeout
            .call2(&global, &resolve, &JsValue::from_f64(f64::from(ms)))
            .expect("schedule timeout");
    });
    JsFuture::from(promise).await.expect("timeout");
}

/// Wait for `ready`, yielding a task turn between attempts.
async fn until(mut ready: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..POLLS {
        if ready().await {
            return true;
        }
        timeout_ms(POLL_MS).await;
    }
    ready().await
}

/// The file server turns the commit away on quota, the tab lists the refusal
/// with its detail, and once the refusal is cleared and the server accepts,
/// the next walk uploads the very bytes it refused.
#[wasm_bindgen_test]
async fn a_refused_upload_is_listed_then_retried() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let status = Rc::new(Cell::new(507u16));
    let _fetch = StatusFetch::install(&status);
    let _upload = UploadRecorder::install(&uploaded);
    let (_hub, mutations, mut tab, _answers, _store) =
        relay_tab("r69d-refused", [21; 32], Tickets::Grants).await;
    let content = TabContent::<MessagePort>::new(&mut tab);
    let file_id = declared_id(REFUSED_PHOTO);
    stage(&tab, file_id, &blob_of(REFUSED_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(1, file_id.as_bytes())).await;
    assert!(
        until(async || mutations.get() == 1).await,
        "the row commits"
    );
    assert!(
        until(async || {
            content.refused_content().await.is_ok_and(|refused| {
                refused
                    .iter()
                    .any(|(id, detail)| *id == file_id && detail.contains("507"))
            })
        })
        .await,
        "the walk must record the quota refusal for the tab to list"
    );
    let refused = content
        .refused_content()
        .await
        .expect("list the refused uploads");
    assert_eq!(
        refused.iter().filter(|(id, _)| *id == file_id).count(),
        1,
        "the refusal lists the file once, got {refused:?}"
    );
    status.set(200);
    content
        .retry_refused(file_id)
        .await
        .expect("retry the refused upload");
    assert!(
        until(async || uploads_of(&uploaded, REFUSED_PHOTO) == 2).await,
        "the cleared entry must be walked again and its bytes uploaded"
    );
    assert!(
        until(async || {
            content
                .refused_content()
                .await
                .is_ok_and(|refused| refused.is_empty())
        })
        .await,
        "a retried upload leaves no refusal listed"
    );
    serial.release();
}

/// The attempt's own intent answer lets the staged bytes go before its chunk read.
#[wasm_bindgen_test]
async fn a_retired_file_is_listed_then_forgotten() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let _upload = UploadRecorder::install(&uploaded);
    let (_hub, mutations, mut tab, _answers, store) =
        relay_tab("r69d-retired", [22; 32], Tickets::Grants).await;
    let _fetch =
        StatusFetch::install_losing(&Rc::new(Cell::new(200u16)), store.clone(), LOST_PHOTO);
    let content = TabContent::<MessagePort>::new(&mut tab);
    let file_id = declared_id(LOST_PHOTO);
    stage(&tab, file_id, &blob_of(LOST_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(1, file_id.as_bytes())).await;
    assert!(
        until(async || mutations.get() == 1).await,
        "the row commits"
    );
    assert!(
        until(async || {
            content
                .retired_content()
                .await
                .is_ok_and(|retired| retired == vec![file_id])
        })
        .await,
        "the outbox attempt must retire the unreadable file for the tab to list"
    );
    content
        .forget_retired_content(&[file_id])
        .await
        .expect("forget the lost bytes");
    assert!(
        until(async || {
            content
                .retired_content()
                .await
                .is_ok_and(|retired| retired.is_empty())
        })
        .await,
        "a forgotten loss leaves nothing retired"
    );
    serial.release();
}

/// The stored bytes of a pinned file are lost after the upload, and
/// `fetch_pinned` restores them from the server: the tab lists the file it
/// restored and the bytes then resolve locally from the fetched chunks.
#[wasm_bindgen_test]
async fn a_pinned_file_with_lost_bytes_is_fetched() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let _upload = UploadRecorder::install(&uploaded);
    let _fetch = ServingFetch::install(PINNED_PHOTO);
    let (_hub, _mutations, mut tab, _answers, store) =
        relay_tab("r69d-fetched", [23; 32], Tickets::Grants).await;
    let content = TabContent::<MessagePort>::new(&mut tab);
    let file_id = declared_id(PINNED_PHOTO);
    stage(&tab, file_id, &blob_of(PINNED_PHOTO));
    send_mutation(&mut tab, 1, &captured_insert(1, file_id.as_bytes())).await;
    assert!(
        until(async || uploads_of(&uploaded, PINNED_PHOTO) == 1).await,
        "the walk must upload the staged file"
    );
    content
        .pin_content("photos-pin", "SELECT content_id FROM photos", "content_id")
        .await
        .expect("pin the photo");
    let chunk = ChunkHash::from_data(PINNED_PHOTO);
    // The store may still be settling the chunk the upload just read, so the
    // drop retries until the store accepts it.
    assert!(
        until(async || store.delete_chunk(&chunk).await.is_ok()).await,
        "the stored chunk must go"
    );
    let arrived = tokio::select! {
        arrived = content.fetch_pinned() => arrived.expect("fetch the pinned file"),
        () = timeout_ms(2_000) => panic!("fetch_pinned never answered"),
    };
    assert_eq!(
        arrived,
        vec![file_id],
        "the fetch answers the file it restored"
    );
    let resolved = tokio::select! {
        resolved = content.resolve(file_id) => resolved,
        () = timeout_ms(2_000) => panic!("the resolve never answered"),
    };
    assert!(
        matches!(resolved, TabResolved::Local { .. }),
        "the fetched bytes resolve locally, got {resolved:?}"
    );
    assert!(
        store
            .stored_hashes()
            .await
            .expect("list the store")
            .contains(&chunk),
        "the fetch restored the chunk to the store"
    );
    serial.release();
}

/// Three uploaded files, two pinned at first: the hub's retention sweep frees the
/// unpinned one while the pins hold, which is how the test observes the sweep settling;
/// then the freed photo's pin goes and `tidy` releases that file's records and chunks
/// while the pinned file's bytes stay, and the freed file still resolves from the server.
#[wasm_bindgen_test]
async fn tidy_frees_unpinned_bytes_and_keeps_pinned() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let _upload = UploadRecorder::install(&uploaded);
    let commits = Rc::new(Cell::new(0u32));
    let _fetch = CommitFetch::install(&commits);
    let (_hub, _mutations, mut tab, _answers, store) =
        relay_tab("r69d-tidy", [24; 32], Tickets::Grants).await;
    let content = TabContent::<MessagePort>::new(&mut tab);
    let kept_id = declared_id(TIDY_KEPT);
    let freed_id = declared_id(TIDY_FREED);
    let sacrifice_id = declared_id(TIDY_SACRIFICE);
    // The hub's retention sweep releases any sent file no pin covers, so the pins hold
    // from the start and the test releases one only after the sweep has settled.
    content
        .pin_content(
            "kept-pin",
            "SELECT content_id FROM photos WHERE id = 1",
            "content_id",
        )
        .await
        .expect("pin the kept photo");
    content
        .pin_content(
            "freed-pin",
            "SELECT content_id FROM photos WHERE id = 2",
            "content_id",
        )
        .await
        .expect("pin the freed photo");
    stage(&tab, kept_id, &blob_of(TIDY_KEPT));
    send_mutation(&mut tab, 1, &captured_insert(1, kept_id.as_bytes())).await;
    stage(&tab, freed_id, &blob_of(TIDY_FREED));
    send_mutation(&mut tab, 2, &captured_insert(2, freed_id.as_bytes())).await;
    stage(&tab, sacrifice_id, &blob_of(TIDY_SACRIFICE));
    send_mutation(&mut tab, 3, &captured_insert(3, sacrifice_id.as_bytes())).await;
    assert!(
        until(async || {
            uploads_of(&uploaded, TIDY_KEPT) == 1
                && uploads_of(&uploaded, TIDY_FREED) == 1
                && uploads_of(&uploaded, TIDY_SACRIFICE) == 1
        })
        .await,
        "the walk must upload all three files"
    );
    assert!(
        until(async || commits.get() == 3).await,
        "the walk must commit all three uploads before retention can release them"
    );
    let sacrifice_chunk = ChunkHash::from_data(TIDY_SACRIFICE);
    assert!(
        until(async || {
            store
                .stored_hashes()
                .await
                .is_ok_and(|hashes| !hashes.contains(&sacrifice_chunk))
        })
        .await,
        "the sweep must release the unpinned file, settling the retention pass"
    );
    content
        .unpin_content("freed-pin")
        .await
        .expect("release the freed photo");
    let freed = tokio::select! {
        freed = content.tidy() => freed.expect("tidy the local store"),
        () = timeout_ms(2_000) => panic!("tidy never answered"),
    };
    assert_eq!(freed, 1, "tidy answers the one record it released");
    let held = store.stored_hashes().await.expect("list the store");
    assert!(
        held.contains(&ChunkHash::from_data(TIDY_KEPT)),
        "the pinned file's bytes stay"
    );
    assert!(
        !held.contains(&ChunkHash::from_data(TIDY_FREED)),
        "the unpinned file's bytes are freed"
    );
    let resolved = content.resolve(freed_id).await;
    assert!(
        matches!(resolved, TabResolved::Remote { .. }),
        "the freed file still resolves from the server, got {resolved:?}"
    );
    serial.release();
}
