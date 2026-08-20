//! Shared harness for the logged-in startup suites.
//!
//! These suites boot the worker with logins on against the browser-stack auth endpoint.

#![cfg(target_arch = "wasm32")]
// A shared test module is compiled into every binary that includes it, and
// each suite uses a different subset (most want only the token mint), so the
// rest reads as dead to that binary.
#![allow(dead_code)]

use connetto_wasm_smoke::workers::{
    DB_NAME, DEMO_FRONTEND_DDL, DEMO_QUERY, DEMO_SQLITE_DDL, DEMO_WS_URL,
};
use connetto_web::auth::{
    Acquired, BrowserAuthenticator, IdbKeyStore, LoginMessage, RefreshStore, WorkerAuthConfig,
};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{BroadcastChannel, MessageEvent, Request, RequestInit, Response};

/// Where the login server listens by default.
pub const AUTH_BASE: &str = "http://127.0.0.1:18099";
/// The provider the login server registers.
pub const PROVIDER: &str = "dev-idp";
/// These suites' refresh store, kept apart from every other suite's.
pub const REFRESH_DB: &str = "e42-refresh.sqlite";

pub fn auth_config() -> WorkerAuthConfig {
    // The stack serves the navigation and the fetch calls on one origin.
    WorkerAuthConfig::new(AUTH_BASE, PROVIDER, format!("{AUTH_BASE}/dev/landing"))
}

pub fn worker_config(auth: Option<WorkerAuthConfig>) -> connetto_web::workers::DbWorkerConfig {
    connetto_web::workers::DbWorkerConfig::new(connetto_wasm_smoke::demo_schema_version())
        .with_ws_url(DEMO_WS_URL)
        .with_replica_db_prefix(DB_NAME)
        .with_replica_ddl(DEMO_SQLITE_DDL)
        .with_frontend_ddl(DEMO_FRONTEND_DDL)
        .with_upstream_sub_id("e42-upstream")
        .with_upstream_query(DEMO_QUERY)
        .with_hub_meta_name("e42-hub-meta.sqlite")
        .with_sql_functions(connetto_wasm_smoke::uuidv4_functions())
        .with_policy_tables(connetto_wasm_smoke::demo_policy_tables())
        .with_caller_function(connetto_wasm_smoke::CALLER_FUNCTION)
        .with_auth(auth)
        .with_auth_db_name(REFRESH_DB)
}

async fn fetch_str(url: &str) -> Response {
    let global = js_sys::global();
    let promise = if let Ok(worker) = global.clone().dyn_into::<web_sys::WorkerGlobalScope>() {
        worker.fetch_with_str(url)
    } else {
        web_sys::window()
            .expect("window or worker global required")
            .fetch_with_str(url)
    };
    JsFuture::from(promise)
        .await
        .expect("the auth server must be running")
        .dyn_into()
        .expect("a fetch resolves to a Response")
}

async fn fetch_request(request: &Request) -> Response {
    let global = js_sys::global();
    let promise = if let Ok(worker) = global.clone().dyn_into::<web_sys::WorkerGlobalScope>() {
        worker.fetch_with_request(request)
    } else {
        web_sys::window()
            .expect("window or worker global required")
            .fetch_with_request(request)
    };
    JsFuture::from(promise)
        .await
        .expect("submit the login form")
        .dyn_into()
        .expect("a fetch resolves to a Response")
}

/// Walk a login URL the way a navigating tab would, and return the code and state
/// the redirect chain delivers.
pub async fn walk_the_login(login_url: &str) -> (String, String) {
    let response = fetch_str(login_url).await;
    assert!(
        response.ok(),
        "the login form loaded at {} with status {}",
        response.url(),
        response.status()
    );
    let form_url = response.url();
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_body(&"username=startup".into());
    let request = Request::new_with_str_and_init(&form_url, &init).expect("build form request");
    request
        .headers()
        .set("content-type", "application/x-www-form-urlencoded")
        .expect("set form content type");
    let response = fetch_request(&request).await;
    assert!(
        response.ok(),
        "the login chain ended at {} with status {}",
        response.url(),
        response.status()
    );
    let final_url = response.url();
    let parsed = web_sys::Url::new(&final_url).expect("a parseable final url");
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

/// Play the tab: answer the worker's login request on the login channel exactly as
/// a real callback route does, by walking the login and posting the code back.
///
/// This is what makes `await_login_code` and `deliver_login_code` execute. The
/// listener is installed before the startup runs, because the worker broadcasts its
/// request and waits, and a `BroadcastChannel` buffers nothing for a late
/// subscriber.
///
/// Returns a count of the login requests served, so a test can insist the handoff
/// really ran. Without that, a startup that found a way to skip the login would
/// leave the listener idle and still pass. The listener is installed once per test
/// binary, so in a binary of several tests the count carries across them.
pub fn play_the_tab() -> Rc<Cell<u32>> {
    THE_TAB.with(|slot| Rc::clone(slot.borrow_mut().get_or_insert_with(install_the_tab)))
}

thread_local! {
    /// The listener outlives the test that installed it, because the channel is
    /// forgotten, so a binary running several tests must install exactly one.
    static THE_TAB: RefCell<Option<Rc<Cell<u32>>>> = const { RefCell::new(None) };
}

fn install_the_tab() -> Rc<Cell<u32>> {
    let served = Rc::new(Cell::new(0));
    let counter = Rc::clone(&served);
    let channel =
        BroadcastChannel::new(connetto_web::auth::LOGIN_CHANNEL).expect("open the login channel");
    let on_message = wasm_bindgen::closure::Closure::<dyn FnMut(MessageEvent)>::new(
        move |event: MessageEvent| {
            let Some(text) = event.data().as_string() else {
                return;
            };
            let Ok(LoginMessage::Request { url }) = serde_json::from_str::<LoginMessage>(&text)
            else {
                return;
            };
            counter.set(counter.get() + 1);
            wasm_bindgen_futures::spawn_local(async move {
                let (code, state) = walk_the_login(&url).await;
                connetto_web::auth::deliver_login_code(&code, &state)
                    .expect("post the code back to the worker");
            });
        },
    );
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    // The listener lives for the test's duration, and the channel with it.
    on_message.forget();
    std::mem::forget(channel);
    served
}

/// Mint a fresh access token by walking the login against the auth server.
///
/// Each call performs a complete login and returns a distinct session token.
/// Requires the auth server to be running at `AUTH_BASE`.
pub async fn mint_token() -> String {
    mint_session().await.0
}

/// Mint a fresh access token and report the identity the server binds as
/// `app.user_id` while it acts for it.
///
/// The identity comes off the acquired session rather than out of the token,
/// which is the same value the server reads from the token's `sub` claim
/// (`crates/connetto-server/src/authn/token.rs`). A test that owns a row has
/// to name that identity: writing one the policy would then hide from its own
/// author is indistinguishable from a rename that did not happen.
pub async fn mint_session() -> (String, String) {
    let storage = connetto_web::storage::ReplicaStorage::install().await;
    let keys = IdbKeyStore::open().await.expect("open the key store");
    let device = connetto_web::storage::device_key(&keys)
        .await
        .expect("device key");
    // A fresh store per call, so every mint starts empty and lands a distinct
    // server session. The name comes from a counter rather than the clock:
    // two mints inside one millisecond would otherwise pick the same OPFS
    // file, and the sahpool VFS allows only one live connection per file.
    static NEXT_MINT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = NEXT_MINT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let db_name = format!("common-mint-{unique}.sqlite");
    let store = RefreshStore::open(&storage.db_url(&db_name), &device).expect("open refresh store");
    let authenticator = BrowserAuthenticator::new(auth_config(), None);
    let pending = match authenticator
        .acquire::<String, _>(&store)
        .await
        .expect("acquire")
    {
        Acquired::NeedLogin(pending) => pending,
        Acquired::Access(_) => panic!("a fresh store cannot refresh silently"),
    };
    let (code, state) = walk_the_login(&pending.login_url).await;
    let session = authenticator
        .complete::<String, _>(&pending, &code, &state, &store)
        .await
        .expect("complete login");
    // Close the connection before removing the file: deleting an OPFS database
    // out from under a live handle is what trips the sahpool bookkeeping.
    drop(store);
    storage.delete_db(&db_name).ok();
    (session.access_token, session.user_id)
}
