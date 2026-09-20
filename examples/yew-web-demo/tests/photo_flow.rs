//! Photo surface browser tests for the yew web demo.
//!
//! COUPLING: `SchemaVersion` is a hash of `schema.sql`.  This file must be
//! byte-identical to `examples/wasm-smoke/schema.sql`.  The first test is the
//! permanent drift detector: it fails at the WebSocket handshake the instant
//! the two schemas diverge.  Maintain identity with
//! `cp examples/wasm-smoke/schema.sql examples/yew-web-demo/schema.sql`.
//!
//! ISOLATION: each test uses a distinct `db_worker_boot_*` function whose OPFS
//! filenames are unique, so Chrome's delayed `FileSystemSyncAccessHandle`
//! release after `Worker.terminate()` never blocks the next worker's file open.
//! `DB_ALIVE_LOCK` is shared across all connetto workers on the same origin;
//! each test holds its own `SUITE_LOCK_*` that serialises that test's lifecycle
//! and a 200 ms sleep before releasing the lock gives Chrome time to finish the
//! OPFS cleanup before the next worker starts.

#![cfg(target_arch = "wasm32")]

use connetto_client::dsl::Watchable;
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Grant, LiveQuery, Replica,
};
use connetto_file_core::{FileId, MimeClass};
use connetto_web::auth::{
    Acquired, BrowserAuthenticator, IdbKeyStore, LOGIN_CHANNEL, LoginMessage, RefreshStore,
    WorkerAuthConfig, deliver_login_code,
};
use connetto_web::storage::{ReplicaStorage, device_key};
use connetto_web::{MessageTransport, TabContent, TabResolved, locks, workers};
use connetto_yew_web_demo::{
    CALLER_FUNCTION, DEMO_TAB_DDL, demo_policy_tables, demo_schema_version, uuidv4_functions,
};
use diesel::prelude::*;
use futures_channel::oneshot;
use js_sys::{Array, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{
    BroadcastChannel, DedicatedWorkerGlobalScope, MessageEvent, Request, RequestInit, Worker,
};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const AUTH_BASE: &str = "http://127.0.0.1:18099";
const AUTH_LANDING: &str = "http://127.0.0.1:18099/dev/landing";
const AUTH_PROVIDER: &str = "dev-idp";
const AUTH_USERNAME: &str = "startup";

// Separate lock names: each test holds its own lock for its full lifecycle so
// DB_ALIVE_LOCK is never contended between a not-yet-GC'd worker and the next.
const SUITE_LOCK_ALIGN: &str = "connetto-yew-photo-suite-align";
const SUITE_LOCK_PHOTO: &str = "connetto-yew-photo-suite-photo";

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        quantity -> diesel::sql_types::BigInt,
    }
}

diesel::table! {
    photos (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        order_id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        content_id -> diesel::sql_types::Binary,
        content_state -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: rosetta_uuid::Uuid,
    owner_id: String,
    quantity: i64,
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = photos)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Photo {
    id: rosetta_uuid::Uuid,
    order_id: rosetta_uuid::Uuid,
    owner_id: String,
    content_id: Vec<u8>,
    content_state: Option<String>,
}

fn stage(msg: &str) {
    web_sys::console::log_1(&msg.into());
}

fn relay_worker_breadcrumbs() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::Relaxed) {
        return;
    }
    if let Ok(ch) = BroadcastChannel::new("connetto-debug") {
        let cb =
            wasm_bindgen::closure::Closure::<dyn FnMut(MessageEvent)>::new(|e: MessageEvent| {
                web_sys::console::log_1(&e.data());
            });
        ch.set_onmessage(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
        std::mem::forget(ch);
    }
}

fn play_the_tab() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::Relaxed) {
        return;
    }
    let ch = BroadcastChannel::new(LOGIN_CHANNEL).expect("login channel");
    let cb = wasm_bindgen::closure::Closure::<dyn FnMut(MessageEvent)>::new(|e: MessageEvent| {
        let Some(text) = e.data().as_string() else {
            return;
        };
        let Ok(LoginMessage::Request { url }) = serde_json::from_str::<LoginMessage>(&text) else {
            return;
        };
        spawn_local(async move {
            let (code, state) = walk_login(&url).await;
            deliver_login_code(&code, &state).expect("deliver login code");
        });
    });
    ch.set_onmessage(Some(cb.as_ref().unchecked_ref()));
    cb.forget();
    std::mem::forget(ch);
}

async fn global_fetch_str(url: &str) -> web_sys::Response {
    let promise = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .map(|w| w.fetch_with_str(url))
        .unwrap_or_else(|_| web_sys::window().expect("window").fetch_with_str(url));
    JsFuture::from(promise)
        .await
        .expect("fetch")
        .dyn_into()
        .expect("Response")
}

async fn global_fetch_req(req: &Request) -> web_sys::Response {
    let promise = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .map(|w| w.fetch_with_request(req))
        .unwrap_or_else(|_| web_sys::window().expect("window").fetch_with_request(req));
    JsFuture::from(promise)
        .await
        .expect("fetch req")
        .dyn_into()
        .expect("Response")
}

async fn walk_login(login_url: &str) -> (String, String) {
    let resp = global_fetch_str(login_url).await;
    let form_url = resp.url();
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_body(&JsValue::from_str(&format!("username={AUTH_USERNAME}")));
    let req = Request::new_with_str_and_init(&form_url, &init).expect("login request");
    req.headers()
        .set("content-type", "application/x-www-form-urlencoded")
        .expect("header");
    let resp = global_fetch_req(&req).await;
    assert!(
        resp.ok(),
        "login chain ended at {} with status {}",
        resp.url(),
        resp.status()
    );
    let final_url = resp.url();
    let parsed = web_sys::Url::new(&final_url).expect("parse url");
    let params = parsed.search_params();
    (
        params
            .get("code")
            .unwrap_or_else(|| panic!("no code in {final_url}")),
        params
            .get("state")
            .unwrap_or_else(|| panic!("no state in {final_url}")),
    )
}

async fn mint_session() -> (String, String) {
    let storage = ReplicaStorage::install().await;
    let keys = IdbKeyStore::open().await.expect("open key store");
    let device = device_key(&keys).await.expect("device key");
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let db = format!("yew-photo-mint-{n}.sqlite");
    let store = RefreshStore::open(&storage.db_url(&db), &device).expect("refresh store");
    let auth = BrowserAuthenticator::new(
        WorkerAuthConfig::new(AUTH_BASE, AUTH_PROVIDER, AUTH_LANDING),
        None,
    );
    let pending = match auth.acquire::<String, _>(&store).await.expect("acquire") {
        Acquired::NeedLogin(p) => p,
        Acquired::Access(_) => panic!("fresh store cannot refresh silently"),
    };
    let (code, state) = walk_login(&pending.login_url).await;
    let session = auth
        .complete::<String, _>(&pending, &code, &state, &store)
        .await
        .expect("complete login");
    drop(store);
    storage.delete_db(&db).ok();
    (session.access_token, session.user_id)
}

fn glue_url() -> String {
    let found = js_sys::eval(
        r#"performance.getEntriesByType("resource").map(e=>e.name).find(n=>n.endsWith("_bg.wasm"))"#,
    )
    .expect("resource entries")
    .as_string()
    .expect("wasm resource entry");
    let base = found.strip_suffix("_bg.wasm").expect("wasm suffix");
    format!("{base}.js")
}

fn spawn_worker(glue_url: &str, boot_fn: &str) -> Worker {
    let wasm_url = glue_url
        .strip_suffix(".js")
        .map_or_else(|| format!("{glue_url}_bg.wasm"), |b| format!("{b}_bg.wasm"));
    let src = format!(
        "const ch=new BroadcastChannel('connetto-debug');\n\
         try{{\n  const mod=await import({g:?});\n  await mod.default({{module_or_path:{w:?}}});\n  await mod.{f}();\n}}catch(e){{\n  ch.postMessage('yew worker FAILED: '+e);\n  throw e;\n}}",
        g = glue_url,
        w = wasm_url,
        f = boot_fn,
    );
    let parts = Array::of1(&JsValue::from_str(&src));
    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type("text/javascript");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &opts).expect("blob");
    let url = web_sys::Url::create_object_url_with_blob(&blob).expect("object url");
    let worker_opts = web_sys::WorkerOptions::new();
    worker_opts.set_type(web_sys::WorkerType::Module);
    let w = Worker::new_with_options(&url, &worker_opts).expect("spawn worker");
    web_sys::Url::revoke_object_url(&url).ok();
    w
}

fn photo_bytes() -> Vec<u8> {
    const SEED: [u8; 16] = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let mut v = Vec::with_capacity(4096);
    while v.len() < 4096 {
        v.extend_from_slice(&SEED);
    }
    v.truncate(4096);
    v
}

fn blob_of(bytes: &[u8]) -> web_sys::Blob {
    let arr = Uint8Array::from(bytes);
    web_sys::Blob::new_with_u8_array_sequence(&Array::of1(&arr)).expect("blob from bytes")
}

async fn fetch_bytes(url: &str) -> Vec<u8> {
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("worker");
    let resp: web_sys::Response = JsFuture::from(scope.fetch_with_str(url))
        .await
        .expect("fetch")
        .dyn_into()
        .expect("Response");
    assert!(
        resp.ok(),
        "content fetch at {} returned {}",
        resp.url(),
        resp.status()
    );
    let buf = JsFuture::from(resp.array_buffer().expect("array_buffer promise"))
        .await
        .expect("array buffer");
    Uint8Array::new(&buf).to_vec()
}

async fn connect_tab(
    client_id: &str,
    token: String,
    identity: &str,
) -> (
    TabContent<BroadcastChannel>,
    ConnettoConnection<MessageTransport<BroadcastChannel>>,
) {
    let wire = format!("connetto-wire-{client_id}");
    workers::announce_tab(&wire).await.expect("announce tab");
    let mut transport = MessageTransport::<BroadcastChannel>::new(&wire).expect("transport");
    let content = TabContent::new(&mut transport);
    let config = ClientConfig::new(client_id.to_owned())
        .with_login(Some(Grant::new(token)))
        .with_schema_version(Some(demo_schema_version()))
        .with_sql_functions(uuidv4_functions())
        .with_policy_tables(demo_policy_tables())
        .with_caller(CALLER_FUNCTION, Some(identity));
    let conn = ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        DEMO_TAB_DDL,
        &config,
        None,
    )
    .await
    .expect("tab connect");
    (content, conn)
}

// --- Test 1: alignment proof — proves version agreement before the photo test ---

#[wasm_bindgen_test]
async fn a_tab_order_reaches_the_replica_through_the_demo_boot_path() {
    relay_worker_breadcrumbs();
    play_the_tab();
    let _serial = locks::hold_lock(SUITE_LOCK_ALIGN).await;
    let worker = spawn_worker(&glue_url(), "db_worker_boot_align");
    workers::await_db_worker_ready(&[])
        .await
        .expect("db worker ready");
    stage("yew align worker booted");

    let (token, identity) = mint_session().await;
    let client_id = rosetta_uuid::Uuid::new_v4().to_string();
    let _tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let (_content, mut conn) = connect_tab(&client_id, token, &identity).await;
    conn.subscribe("align-orders", "SELECT * FROM orders")
        .await
        .expect("subscribe");
    loop {
        let event = conn.pump_one().await.expect("pump");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
        if matches!(event, ClientEvent::SnapshotEnd { .. }) {
            break;
        }
    }
    stage("orders subscription ready");

    let (client, pump) = ConnettoClient::with_pump(conn);
    let (done_tx, done_rx) = oneshot::channel::<()>();
    spawn_local(async move {
        pump.await;
        let _ = done_tx.send(());
    });

    let mut live: LiveQuery<Order> = orders::table
        .order(orders::id)
        .select(Order::as_select())
        .live(&client)
        .await
        .expect("live query");

    let qty = 77_i64;
    let id_str = identity.clone();
    client
        .with_conn(move |conn| {
            diesel::insert_into(orders::table)
                .values((
                    orders::owner_id.eq(id_str.as_str()),
                    orders::quantity.eq(qty),
                ))
                .execute(conn.conn())
        })
        .await
        .expect("order insert");
    client.replay_pending().await.expect("replay pending");
    stage("order written");

    loop {
        if live.rows().iter().any(|o| o.quantity == qty) {
            break;
        }
        live.changed().await.expect("live refresh");
    }
    stage("order arrived — version agreement confirmed");

    drop(live);
    drop(client);
    done_rx.await.expect("pump exited");
    worker.terminate();
    // Chrome headless does not release the OPFS access handle synchronously on
    // terminate; per-test file names are the isolation guarantee, this is margin.
    workers::sleep(core::time::Duration::from_millis(200)).await;
}

// --- Test 2: photo round trip ---

#[wasm_bindgen_test]
async fn a_photo_round_trips_through_stage_commit_resolve_and_http_fetch() {
    relay_worker_breadcrumbs();
    play_the_tab();
    let _serial = locks::hold_lock(SUITE_LOCK_PHOTO).await;
    let worker = spawn_worker(&glue_url(), "db_worker_photo_boot");
    workers::await_db_worker_ready(&[])
        .await
        .expect("db worker ready");
    stage("yew photo worker booted");

    let (token, identity) = mint_session().await;
    let client_id = rosetta_uuid::Uuid::new_v4().to_string();
    let _tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let (content, mut conn) = connect_tab(&client_id, token, &identity).await;
    conn.subscribe("photo-test-photos", "SELECT * FROM photos")
        .await
        .expect("subscribe");
    loop {
        let event = conn.pump_one().await.expect("pump");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
        if matches!(event, ClientEvent::SnapshotEnd { .. }) {
            break;
        }
    }
    stage("photos subscription ready");

    let (client, pump) = ConnettoClient::with_pump(conn);
    let (done_tx, done_rx) = oneshot::channel::<()>();
    spawn_local(async move {
        pump.await;
        let _ = done_tx.send(());
    });

    let mut live: LiveQuery<Photo> = photos::table
        .order(photos::id)
        .select(Photo::as_select())
        .live(&client)
        .await
        .expect("live query");

    let bytes = photo_bytes();
    let blob = blob_of(&bytes);
    let (file_id, photo_id) = content
        .stage(&blob, MimeClass::Jpeg, &client, |conn, file_id| {
            conn.transaction(|conn| {
                let before_orders: std::collections::HashSet<rosetta_uuid::Uuid> = orders::table
                    .select(orders::id)
                    .load::<rosetta_uuid::Uuid>(conn)?
                    .into_iter()
                    .collect();
                diesel::insert_into(orders::table)
                    .values((
                        orders::owner_id.eq(identity.as_str()),
                        orders::quantity.eq(1_i64),
                    ))
                    .execute(conn)?;
                let order_id = orders::table
                    .select(orders::id)
                    .load::<rosetta_uuid::Uuid>(conn)?
                    .into_iter()
                    .find(|id| !before_orders.contains(id))
                    .expect("minted order id");
                let before_photos: std::collections::HashSet<rosetta_uuid::Uuid> = photos::table
                    .select(photos::id)
                    .load::<rosetta_uuid::Uuid>(conn)?
                    .into_iter()
                    .collect();
                diesel::insert_into(photos::table)
                    .values((
                        photos::order_id.eq(order_id),
                        photos::owner_id.eq(identity.as_str()),
                        photos::content_id.eq(file_id.as_bytes().to_vec()),
                        photos::content_state.eq::<Option<String>>(None),
                    ))
                    .execute(conn)?;
                Ok::<rosetta_uuid::Uuid, diesel::result::Error>(
                    photos::table
                        .select(photos::id)
                        .load::<rosetta_uuid::Uuid>(conn)?
                        .into_iter()
                        .find(|id| !before_photos.contains(id))
                        .expect("minted photo id"),
                )
            })
        })
        .await
        .expect("stage photo and insert rows");
    client.replay_pending().await.expect("send mutation");
    assert_eq!(file_id, FileId::from_chunks([bytes.as_slice()]));
    stage("photo staged");

    let available = loop {
        if let Some(p) = live
            .rows()
            .iter()
            .find(|p| p.id == photo_id && p.content_state.as_deref() == Some("available"))
            .cloned()
        {
            break p;
        }
        live.changed().await.expect("live refresh");
    };
    assert_eq!(available.owner_id, identity);
    assert_eq!(available.content_id, file_id.as_bytes().to_vec());
    stage("photo available");

    let url = match content.resolve(file_id).await {
        TabResolved::Remote { url } => url,
        TabResolved::Local { .. } => panic!("uploaded photo must resolve to server"),
        TabResolved::Unavailable => panic!("available photo must resolve"),
    };
    assert_eq!(fetch_bytes(&url).await, bytes);
    stage("photo bytes verified");

    drop(live);
    drop(content);
    drop(client);
    done_rx.await.expect("pump exited");
    worker.terminate();
    // Chrome headless does not release the OPFS access handle synchronously on
    // terminate; per-test file names are the isolation guarantee, this is margin.
    workers::sleep(core::time::Duration::from_millis(200)).await;
}
