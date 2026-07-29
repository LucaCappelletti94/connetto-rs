//! Shared harness for the logged-in startup suites.
//!
//! Both suites boot the worker with logins on against the login server that
//! `connetto-server`'s `auth_stack` example runs, and both have to play the tab,
//! since the worker asks a tab to carry out the login and waits for the answer.
//!
//! Needs the stack up. See `authenticated_boot.rs` for the commands.

#![cfg(target_arch = "wasm32")]

use connetto_wasm_smoke::workers::{
    DB_NAME, DEMO_FRONTEND_DDL, DEMO_QUERY, DEMO_SQLITE_DDL, DEMO_WS_URL, FRONTEND_DB_NAME,
};
use connetto_web::auth::{LoginMessage, WorkerAuthConfig};
use std::cell::Cell;
use std::rc::Rc;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{BroadcastChannel, MessageEvent, Response, WorkerGlobalScope};

/// Where the login server listens by default.
pub const AUTH_BASE: &str = "http://127.0.0.1:18099";
/// The provider the login server registers.
pub const PROVIDER: &str = "dev-idp";
/// These suites' refresh store, kept apart from every other suite's.
pub const REFRESH_DB: &str = "e42-refresh.sqlite";

pub fn auth_config() -> WorkerAuthConfig {
    WorkerAuthConfig {
        auth_base_url: AUTH_BASE.to_owned(),
        provider: PROVIDER.to_owned(),
        redirect_uri: format!("{AUTH_BASE}/dev/landing"),
    }
}

pub fn worker_config(auth: Option<WorkerAuthConfig>) -> connetto_web::workers::DbWorkerConfig {
    connetto_web::workers::DbWorkerConfig {
        ws_url: DEMO_WS_URL,
        replica_db_prefix: DB_NAME,
        replica_ddl: DEMO_SQLITE_DDL,
        frontend_db_name: FRONTEND_DB_NAME,
        frontend_ddl: DEMO_FRONTEND_DDL,
        upstream_sub_id: "e42-upstream",
        upstream_query: DEMO_QUERY,
        hub_meta_name: "e42-hub-meta.sqlite",
        client_id_prefix: "e42-worker",
        schema_version: connetto_wasm_smoke::demo_schema_version(),
        sql_functions: connetto_wasm_smoke::uuidv7_functions(),
        auth,
        auth_db_name: REFRESH_DB,
    }
}

/// Walk a login URL the way a navigating tab would, and return the code and state
/// the redirect chain delivers.
///
/// `fetch` cannot read a `Location` header, since a manual-redirect response is
/// opaque, so this follows the chain and reads the final URL. It works because the
/// login server keeps every hop on one origin.
pub async fn walk_the_login(login_url: &str) -> (String, String) {
    let global: WorkerGlobalScope = js_sys::global()
        .dyn_into()
        .expect("this test runs in a worker");
    let response: Response = JsFuture::from(global.fetch_with_str(login_url))
        .await
        .expect("the login server must be running: see authenticated_boot.rs")
        .dyn_into()
        .expect("a fetch resolves to a Response");
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
/// leave the listener idle and still pass.
pub fn play_the_tab() -> Rc<Cell<u32>> {
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
