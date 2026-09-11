//! Browser content survives archive transfer and uploads from the replacement worker.

use core::convert::Infallible;
use core::future::{Future, ready};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use connetto_client::live::ConnettoClient;
use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{
    ClientConfig, ConnettoConnection, ExportScope, Grant, ImportChoices, Replica,
};
use connetto_core::Cursor;
use connetto_core::messages::{
    BulkMessage, ContentTicketGrant, ControlMessage, HandshakeAck, SubscriptionSpec,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_file_client::{BrowserStore, ContentArchive};
use connetto_file_core::{FileId, MimeClass};
use connetto_web::relay::HubReconnect;
use connetto_web::workers::{
    DB_ALIVE_LOCK, request_export, request_import, serve_export_requests, serve_import_requests,
};
use connetto_web::{
    BrowserContentClient, BrowserResolved, RelayHub, attach_browser_content, locks,
};
use diesel::prelude::*;
use futures_channel::mpsc;
use futures_util::StreamExt;
use futures_util::future::{Either, select};
use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, future_to_promise, spawn_local};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{DedicatedWorkerGlobalScope, File, Request, Response};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DDL: &str = "CREATE TABLE photos (id INTEGER PRIMARY KEY, content_id BLOB NOT NULL)";
const TEST_LOCK: &str = "connetto-content-archive-test";
const PHOTO: &[u8] = b"a photograph written offline and restored onto a replacement browser worker";

diesel::table! {
    /// Photo rows restored with the pending content.
    photos (id) {
        /// Row identity.
        id -> Integer,
        /// Content identity.
        content_id -> Binary,
    }
}

struct TicketTransport {
    incoming: mpsc::UnboundedReceiver<IncomingFrame>,
    answers: mpsc::UnboundedSender<IncomingFrame>,
    completed_subscribes: Rc<Cell<u32>>,
    stall_subscribe: bool,
    mutation_sent: Rc<Cell<bool>>,
}

impl TicketTransport {
    fn hanging(completed_subscribes: Rc<Cell<u32>>) -> Self {
        Self {
            completed_subscribes,
            stall_subscribe: true,
            ..Self::new()
        }
    }

    fn new() -> Self {
        Self::counted(Rc::new(Cell::new(0)))
    }

    fn counted(completed_subscribes: Rc<Cell<u32>>) -> Self {
        let (answers, incoming) = mpsc::unbounded();
        answers
            .unbounded_send(IncomingFrame::Control(ControlMessage::HandshakeAck(
                HandshakeAck {
                    connection_id: "browser-content".to_owned(),
                    session_token: "browser-content".to_owned(),
                    resume_token: "browser-content".to_owned(),
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
            completed_subscribes,
            stall_subscribe: false,
            mutation_sent: Rc::new(Cell::new(false)),
        }
    }
}

impl Transport for TicketTransport {
    type Error = Infallible;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        let subscribe = matches!(&message, ControlMessage::Subscribe(_));
        let stall = self.stall_subscribe && subscribe;
        if stall {
            self.stall_subscribe = false;
        }
        let completed_subscribes = Rc::clone(&self.completed_subscribes);
        let mutation_sent = Rc::clone(&self.mutation_sent);
        if let ControlMessage::ContentTicketRequest(request) = message {
            assert!(
                mutation_sent.get(),
                "restored mutations must precede the content ticket"
            );
            let file_id = FileId::from_bytes(request.file_id);
            self.answers
                .unbounded_send(IncomingFrame::Control(ControlMessage::ContentTicketGrant(
                    ContentTicketGrant {
                        request_id: request.request_id,
                        url: format!(
                            "https://content.invalid/files/{file_id}/intent?t=browser-ticket"
                        ),
                    },
                )))
                .expect("queue content grant");
        }
        async move {
            if stall {
                core::future::pending().await
            } else {
                if subscribe {
                    completed_subscribes.set(completed_subscribes.get() + 1);
                }
                Ok(())
            }
        }
    }

    fn send_bulk(&mut self, message: BulkMessage) -> impl Future<Output = Result<(), Self::Error>> {
        if matches!(message, BulkMessage::MutationPatch(_)) {
            self.mutation_sent.set(true);
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

fn config() -> ClientConfig {
    ClientConfig::new("browser-content-archive").with_login(Some(Grant::new("user:browser")))
}

fn offline_client() -> ConnettoClient<TicketTransport> {
    let connection =
        ConnettoConnection::<TicketTransport>::open(&Replica::in_memory(), DDL, &config(), None)
            .expect("open offline replica");
    let (client, pump) = ConnettoClient::with_pump(connection);
    spawn_local(pump);
    client
}

async fn connected_client() -> ConnettoClient<TicketTransport> {
    let connection = ConnettoConnection::connect(
        TicketTransport::new(),
        &Replica::in_memory(),
        DDL,
        &config(),
        None,
    )
    .await
    .expect("connect replacement replica");
    let (client, pump) = ConnettoClient::with_pump(connection);
    spawn_local(pump);
    client
}

#[wasm_bindgen_test]
async fn an_offline_photo_restores_displays_locally_and_uploads() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let (source_archive, file_id) = stage_source().await;
    let archive = relay_round_trip(&source_archive).await;
    let replacement = restore_target(&archive).await;

    let resolved = replacement
        .resolve(file_id)
        .await
        .expect("resolve restored photo");
    let BrowserResolved::Local { url, .. } =
        BrowserResolved::from_resolved(resolved, "image/jpeg").expect("create display URL")
    else {
        panic!("restored photo must display from local bytes");
    };
    assert_eq!(
        fetch_bytes(url.as_str()).await.expect("fetch object URL"),
        PHOTO
    );

    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let fetch = install_content_fetch(&uploaded);
    assert_eq!(
        replacement
            .flush_outbox()
            .await
            .expect("upload restored photo"),
        1
    );
    drop(fetch);
    assert_eq!(*uploaded.borrow(), [PHOTO.to_vec()]);
    serial.release();
}

/// A relay import uploads restored content without a tab-owned client.
#[wasm_bindgen_test]
async fn a_relay_import_drives_the_worker_outbox() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let (archive, _) = stage_source().await;
    let worker =
        ConnettoConnection::<TicketTransport>::open(&Replica::in_memory(), DDL, &config(), None)
            .expect("open relay replica");
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("dedicated worker");
    let store = BrowserStore::install(&scope, "r68-archive-uploader")
        .await
        .expect("install content store");
    let (hub, _, _) = start_recovering_relay(worker, ContentArchive::new(store, [3; 32]));
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let fetch = install_content_fetch(&uploaded);
    hub.import_local_data(archive).await.expect("relay import");
    for _ in 0..100 {
        if !uploaded.borrow().is_empty() {
            break;
        }
        JsFuture::from(Promise::resolve(&JsValue::UNDEFINED))
            .await
            .expect("yield to uploader");
    }
    drop(fetch);
    assert_eq!(*uploaded.borrow(), [PHOTO.to_vec()]);
    serial.release();
}

#[wasm_bindgen_test]
async fn hub_requests_are_served_while_a_content_upload_is_in_flight() {
    let serial = locks::hold_lock(TEST_LOCK).await;
    let (archive, _) = stage_source().await;
    let worker =
        ConnettoConnection::<TicketTransport>::open(&Replica::in_memory(), DDL, &config(), None)
            .expect("open relay replica");
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("dedicated worker");
    let store = BrowserStore::install(&scope, "r68-concurrent-uploader")
        .await
        .expect("install content store");
    let (hub, _, _) = start_recovering_relay(worker, ContentArchive::new(store, [4; 32]));
    let uploaded = Rc::new(RefCell::new(Vec::new()));
    let fetch = install_blocked_content_fetch(&uploaded);
    hub.import_local_data(archive).await.expect("relay import");
    for _ in 0..100 {
        if fetch.started.get() {
            break;
        }
        timeout_ms(10).await;
    }
    assert!(fetch.started.get(), "the content transfer must start");

    let answer = select(Box::pin(hub.unsynced()), Box::pin(timeout_ms(1_000))).await;
    fetch.release();
    let pending = match answer {
        Either::Left((answer, _)) => answer.expect("pending-work reply"),
        Either::Right(_) => panic!("the hub did not service local work during content transfer"),
    };
    assert_eq!(pending.content_files, 1);
    for _ in 0..100 {
        if !uploaded.borrow().is_empty() {
            break;
        }
        timeout_ms(10).await;
    }
    assert_eq!(*uploaded.borrow(), [PHOTO.to_vec()]);
    let mut after = hub.unsynced().await.expect("post-upload pending work");
    for _ in 0..100 {
        if after.content_files == 0 {
            break;
        }
        timeout_ms(10).await;
        after = hub.unsynced().await.expect("retry pending-work query");
    }
    assert_eq!(after.content_files, 0);
    serial.release();
}

async fn stage_source() -> (Vec<u8>, FileId) {
    let source = attach_browser_content(offline_client(), "r68-archive-source", [1; 32])
        .await
        .expect("attach source content");
    let (file_id, ()) = source
        .stage(PHOTO, MimeClass::Jpeg, |connection, file_id| {
            diesel::insert_into(photos::table)
                .values((
                    photos::id.eq(1),
                    photos::content_id.eq(file_id.as_bytes().to_vec()),
                ))
                .execute(connection)
                .map(|_| ())
        })
        .await
        .expect("stage offline photo");
    let archive = source
        .export_local_data(ExportScope::Unsynced)
        .await
        .expect("export through content policy");
    (archive, file_id)
}

async fn relay_round_trip(archive: &[u8]) -> Vec<u8> {
    let mut worker =
        ConnettoConnection::<TicketTransport>::open(&Replica::in_memory(), DDL, &config(), None)
            .expect("open relay replica");
    worker
        .subscribe_spec("stalled", SubscriptionSpec::new("SELECT * FROM photos"))
        .await
        .expect("declare offline subscription");
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("dedicated worker");
    let store = BrowserStore::install(&scope, "r68-archive-relay")
        .await
        .expect("install content store");
    let content = ContentArchive::new(store, [3; 32]);
    let (hub, completed_subscribes, attempts) = start_recovering_relay(worker, content);
    serve_export_requests(hub.clone()).expect("export service");
    serve_import_requests(hub).expect("import service");
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let file = File::new_with_u8_array_sequence(
        &Array::of1(&Uint8Array::from(archive)),
        "offline-photo.zip",
    )
    .expect("archive file");
    let (_, collisions) = request_import(file).await.expect("relay import");
    assert_eq!(collisions, 0);
    wait_for_reconnect(&completed_subscribes).await;
    assert_eq!(
        attempts.get(),
        1,
        "local archive work must not discard a transport that completed its handshake"
    );
    request_export(ExportScope::Unsynced)
        .await
        .expect("relay export")
}

fn start_recovering_relay(
    worker: ConnettoConnection<TicketTransport>,
    content: ContentArchive<BrowserStore>,
) -> (RelayHub, Rc<Cell<u32>>, Rc<Cell<u32>>) {
    let attempts = Rc::new(Cell::new(0));
    let completed_subscribes = Rc::new(Cell::new(0));
    let reconnect = HubReconnect {
        factory: {
            let attempts = Rc::clone(&attempts);
            let completed_subscribes = Rc::clone(&completed_subscribes);
            move || {
                let attempt = attempts.get();
                attempts.set(attempt + 1);
                let transport = if attempt == 0 {
                    TicketTransport::hanging(Rc::clone(&completed_subscribes))
                } else {
                    TicketTransport::counted(Rc::clone(&completed_subscribes))
                };
                ready(Ok::<_, Infallible>(transport))
            }
        },
        sleeper: |_| ready(()),
        policy: ReconnectPolicy::new().with_max_attempts(Some(1)),
        upstream: Vec::new(),
    };
    let (hub, pump, _notices) =
        RelayHub::with_reconnect_and_content(worker, ":memory:", reconnect, content)
            .expect("content relay");
    spawn_local(async move {
        pump.await.expect("content relay pump");
    });
    (hub, completed_subscribes, attempts)
}

async fn wait_for_reconnect(completed_subscribes: &Cell<u32>) {
    for _ in 0..100 {
        if completed_subscribes.get() == 1 {
            return;
        }
        JsFuture::from(Promise::resolve(&JsValue::UNDEFINED))
            .await
            .expect("yield to relay");
    }
    assert_eq!(
        completed_subscribes.get(),
        1,
        "the replacement transport completes one subscription replay"
    );
}

async fn restore_target(archive: &[u8]) -> Rc<BrowserContentClient<TicketTransport>> {
    let replacement = Rc::new(
        attach_browser_content(connected_client().await, "r68-archive-replacement", [2; 32])
            .await
            .expect("attach replacement content"),
    );
    let plan = replacement
        .prepare_local_data_import(archive)
        .await
        .expect("prepare content archive");
    assert_eq!(plan.replica_plan().collisions().len(), 0);
    replacement
        .apply_local_data_import(&plan, &ImportChoices::keeping_the_file())
        .await
        .expect("apply content archive");
    replacement
}

struct FetchReplacement {
    global: Object,
    key: JsValue,
    previous: JsValue,
    _closure: Closure<dyn FnMut(JsValue) -> Promise>,
}

struct BlockedFetch {
    _fetch: FetchReplacement,
    started: Rc<Cell<bool>>,
    release: Function,
}

impl BlockedFetch {
    fn release(&self) {
        self.release
            .call0(&JsValue::UNDEFINED)
            .expect("release upload");
    }
}

fn install_content_fetch(uploaded: &Rc<RefCell<Vec<Vec<u8>>>>) -> FetchReplacement {
    replace_content_fetch(uploaded, None)
}

fn install_blocked_content_fetch(uploaded: &Rc<RefCell<Vec<Vec<u8>>>>) -> BlockedFetch {
    let resolver = Rc::new(RefCell::new(None));
    let release = Rc::clone(&resolver);
    let gate = Promise::new(&mut move |resolve, _reject| {
        release.borrow_mut().replace(resolve);
    });
    let release = resolver.borrow_mut().take().expect("upload gate resolver");
    let started = Rc::new(Cell::new(false));
    let fetch = replace_content_fetch(uploaded, Some((Rc::clone(&started), gate)));
    BlockedFetch {
        _fetch: fetch,
        started,
        release,
    }
}

fn replace_content_fetch(
    uploaded: &Rc<RefCell<Vec<Vec<u8>>>>,
    gate: Option<(Rc<Cell<bool>>, Promise)>,
) -> FetchReplacement {
    let captured = Rc::clone(uploaded);
    let closure = Closure::<dyn FnMut(JsValue) -> Promise>::new(move |value: JsValue| {
        let request = value.dyn_into::<Request>().expect("fetch receives Request");
        let captured = Rc::clone(&captured);
        let gate = gate.clone();
        future_to_promise(async move {
            let body = JsFuture::from(request.array_buffer()?).await?;
            let body = Uint8Array::new(&body).to_vec();
            if request.method() == "PUT" {
                if let Some((started, gate)) = gate {
                    started.set(true);
                    JsFuture::from(gate).await?;
                }
                captured.borrow_mut().push(body);
                response(None, 204)
            } else if request.url().contains("/intent?") {
                let intent: serde_json::Value =
                    serde_json::from_slice(&body).expect("decode upload intent");
                let needed: Vec<&str> = intent["chunks"]
                    .as_array()
                    .expect("intent chunks")
                    .iter()
                    .map(|chunk| chunk["hash"].as_str().expect("chunk hash"))
                    .collect();
                response(
                    Some(&serde_json::json!({ "needed": needed }).to_string()),
                    200,
                )
            } else {
                response(None, 200)
            }
        })
    });
    let global = js_sys::global();
    let key = JsValue::from_str("fetch");
    let previous = Reflect::get(&global, &key).expect("read fetch");
    Reflect::set(&global, &key, closure.as_ref()).expect("replace fetch");
    FetchReplacement {
        global,
        key,
        previous,
        _closure: closure,
    }
}

impl Drop for FetchReplacement {
    fn drop(&mut self) {
        let _ = Reflect::set(&self.global, &self.key, &self.previous);
    }
}

fn response(body: Option<&str>, status: u16) -> Result<JsValue, JsValue> {
    let global = js_sys::global();
    let constructor =
        Reflect::get(&global, &JsValue::from_str("Response"))?.dyn_into::<Function>()?;
    let init = Object::new();
    Reflect::set(
        &init,
        &JsValue::from_str("status"),
        &JsValue::from_f64(f64::from(status)),
    )?;
    let arguments = Array::new();
    arguments.push(&body.map_or(JsValue::NULL, JsValue::from_str));
    arguments.push(&init);
    Reflect::construct(&constructor, &arguments)
}

async fn fetch_bytes(url: &str) -> Result<Vec<u8>, JsValue> {
    let scope = js_sys::global().dyn_into::<DedicatedWorkerGlobalScope>()?;
    let response = JsFuture::from(scope.fetch_with_str(url))
        .await?
        .dyn_into::<Response>()?;
    let buffer = JsFuture::from(response.array_buffer()?).await?;
    Ok(Uint8Array::new(&buffer).to_vec())
}

async fn timeout_ms(ms: i32) {
    let promise = Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        let set_timeout = Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .expect("read setTimeout")
            .dyn_into::<Function>()
            .expect("setTimeout function");
        set_timeout
            .call2(&global, &resolve, &JsValue::from_f64(f64::from(ms)))
            .expect("schedule timeout");
    });
    JsFuture::from(promise).await.expect("timeout");
}
