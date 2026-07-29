//! Dioxus web demo of the connetto browser topology, end to end.
//!
//! Every window runs the same app. One window wins the Web Locks leader
//! election and spawns the dedicated DB worker, the only browsing context kind
//! with OPFS sync access handles. That worker owns the durable replica, the
//! server connection, the relay hub, and the device-private local tier. Every
//! window, leader or follower, connects a tab client to the worker over its
//! own `BroadcastChannel` and runs live queries against a local SQLite mirror.
//!
//! The synced `orders` list converges across every window of every device
//! through Postgres logical replication: a tab write rides the hub up to the
//! worker, applies to Postgres, and echoes back through CDC to every window.
//! The device-private `notes` list converges across the windows of one device
//! through the hub alone and never reaches the server: the worker replica does
//! not even contain the table.
//!
//! Two auth modes, chosen at startup from `localStorage["connetto-demo-signed-in"]`:
//! absent boots unauthenticated (shared plaintext replica, identical to the
//! original single-mode behaviour). Present boots authenticated: the worker
//! acquires connetto's own JWT through the dev OIDC provider, names the
//! replica from the identity, and encrypts it at rest.
//!
//! Switching modes reloads the page. The OAuth callback lands at
//! `/auth/callback` (registered in the dev IdP); the proxy only covers
//! `/auth/token`, `/auth/refresh`, and `/auth/logout`.
//!
//! The DB worker shares this same wasm module: the leader spawns it pointed at
//! the dx glue, appending `?signed_in=1` to the URL when authenticated mode is
//! active so the worker can read that flag from its own `self.location.search`
//! (workers cannot access `localStorage`).
//!
//! Run with: `dx serve --port 9912` from this directory.

use std::rc::Rc;
use std::sync::Arc;
use std::{cell::RefCell, time::Duration};

use connetto_client::{ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Replica};
use connetto_dioxus::use_live;
use connetto_web::{
    BroadcastTransport,
    auth::{LogoutOutcome, WorkerAuthConfig, deliver_login_code, request_logout, request_unsynced},
    leader, locks, workers,
};
use diesel::prelude::*;
use dioxus::prelude::*;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::spawn_local;
use web_sys::{BroadcastChannel, MessageEvent};

/// The tab-to-worker transport this window's client rides.
type Tab = BroadcastTransport;

/// The demo server the DB worker connects upstream to.
const DEMO_WS_URL: &str = "ws://127.0.0.1:7777/";
/// The Postgres schema source the demo server is launched with. Hashing it
/// yields the version the server advertises, so this build presents a matching
/// version at handshake and is not rejected as stale.
const SCHEMA_SQL: &str = include_str!("../schema.sql");
/// The synced replica schema (worker first boot). Matches `schema.sql`.
const DEMO_SQLITE_DDL: &str = "CREATE TABLE orders (id BLOB PRIMARY KEY DEFAULT (uuidv7()) CHECK (length(id) = 16) NOT NULL, quantity INTEGER) STRICT;";
/// The tab mirror schema: both tiers in the tab's main schema, because every
/// relayed patch applies to main. The hub, not the tab, keeps the tiers apart.
const DEMO_TAB_DDL: &str = "CREATE TABLE orders (id BLOB PRIMARY KEY DEFAULT (uuidv7()) CHECK (length(id) = 16) NOT NULL, quantity INTEGER) STRICT; \
     CREATE TABLE notes (id INTEGER PRIMARY KEY NOT NULL, body TEXT) STRICT;";
/// The upstream subscription the worker registers.
const DEMO_QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
/// The OPFS file holding the worker's durable synced replica (base name; with
/// auth enabled the worker appends the identity hash so each account gets its
/// own encrypted file).
const DB_NAME: &str = "connetto-relay.sqlite";
/// The OPFS file holding the worker's durable device-private tier.
const FRONTEND_DB_NAME: &str = "connetto-frontend.sqlite";
/// The OPFS file holding the worker-only refresh token, encrypted at rest.
const AUTH_DB_NAME: &str = "connetto-auth.sqlite";
/// The shared leader lock every window of this app races.
const LEADER_LOCK: &str = "connetto-demo-leader";
/// The local tier schema, translated from `frontend.sql` by build.rs.
const FRONTEND_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/frontend-ddl.sql"));
/// `localStorage` key that selects authenticated vs. unauthenticated mode.
const SIGNED_IN_KEY: &str = "connetto-demo-signed-in";
/// Query parameter the leader page appends to the glue URL when spawning the
/// worker in authenticated mode.
const SIGNED_IN_PARAM: &str = "signed_in=1";
/// BroadcastChannel on which the worker publishes the authenticated user id
/// once it has acquired a session.
const DEMO_UID_CHANNEL: &str = "connetto-demo-uid";
/// The origin serving `connetto-server`'s auth router, which the login navigation
/// goes to directly. The worker's `fetch` calls go through this app's own origin
/// instead, where the dev server proxies them.
const AUTH_ORIGIN: &str = "http://127.0.0.1:18081";
/// OIDC provider registered in the dev IdP.
const AUTH_PROVIDER: &str = "dev-idp";
/// Path the dev IdP redirects back to after login.
const AUTH_CALLBACK_PATH: &str = "/auth/callback";

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        quantity -> diesel::sql_types::BigInt,
    }
}

diesel::table! {
    notes (id) {
        id -> diesel::sql_types::BigInt,
        body -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: rosetta_uuid::Uuid,
    quantity: i64,
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Note {
    id: i64,
    body: String,
}

// The synced key generator: `orders.id` bakes to `DEFAULT (uuidv7())`, so a
// tab write omits the id and this registered function mints it. The impl is
// `rosetta_uuid::Uuid::utc_v7`, the same strongly typed key the `orders`
// schema uses on SQLite and Postgres. Declared as nondeterministic so SQLite
// calls it per row instead of folding the DEFAULT to a constant.
// Declared with the built-in Binary type so diesel generates
// register_nondeterministic_impl for SQLite. rosetta_uuid::Uuid implements
// ToSql<Binary, Sqlite>, so the closure still returns the right value.
#[diesel::declare_sql_function]
extern "SQL" {
    fn uuidv7() -> diesel::sql_types::Binary;
}

/// The registrar connetto installs on every connection it opens for this app.
fn uuidv7_functions() -> connetto_client::SqlFunctions {
    connetto_client::SqlFunctions::new().with(Arc::new(|conn: &mut diesel::SqliteConnection| {
        uuidv7_utils::register_nondeterministic_impl(conn, rosetta_uuid::Uuid::utc_v7)
    }))
}

/// A device-unique integer id for a local-only `notes` row. `notes` stays on
/// integer keys (device-private, never synced), so the client authors the id.
/// The millisecond clock plus a random low tag keeps two windows of one device
/// from colliding within the same millisecond.
fn fresh_note_id() -> i64 {
    let ts = js_sys::Date::now();
    // Deliberate truncation: current epoch ms (~1.7e12) fits i64 for 292 M years.
    debug_assert!(ts.is_finite() && ts >= 0.0 && ts < i64::MAX as f64);
    let ms = ts as i64;
    let r = js_sys::Math::random() * 1000.0;
    // Deliberate quantization: [0.0, 1000.0) -> [0, 999].
    debug_assert!(r.is_finite() && (0.0..1000.0).contains(&r));
    let low = r as i64;
    ms * 1000 + low
}

/// A visible order quantity inside the subscription's `quantity > 0` window.
fn fresh_quantity() -> i64 {
    let r = js_sys::Math::random() * 9.0;
    // Deliberate quantization: [0.0, 9.0) -> [0, 8], result [5, 45].
    debug_assert!(r.is_finite() && (0.0..9.0).contains(&r));
    (r as i64 + 1) * 5
}

// --- Auth-mode helpers -------------------------------------------------------

/// True when `localStorage["connetto-demo-signed-in"]` is present.
fn page_signed_in_flag() -> bool {
    js_sys::eval(&format!("localStorage.getItem('{SIGNED_IN_KEY}') !== null"))
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// If the page URL carries `?code=...&state=...`, return the pair.
fn page_login_callback() -> Option<(String, String)> {
    // Returns [code, state] or null via a self-executing function.
    let result = js_sys::eval(
        "(function(){\
            var p=new URLSearchParams(location.search);\
            var c=p.get('code'),s=p.get('state');\
            return c&&s?[c,s]:null;\
        })()",
    )
    .ok()?;
    if result.is_null() || result.is_undefined() {
        return None;
    }
    let arr = js_sys::Array::from(&result);
    let code = arr.get(0).as_string()?;
    let state = arr.get(1).as_string()?;
    Some((code, state))
}

/// Strip the query string from the current URL without a page reload so a
/// spent authorization code is not replayed on refresh.
fn clear_url_query() {
    let _ = js_sys::eval("history.replaceState(null,'',location.pathname)");
}

/// Set the signed-in flag and reload, entering authenticated mode on the next
/// boot.
fn set_flag_and_reload() {
    let _ = js_sys::eval(&format!(
        "localStorage.setItem('{SIGNED_IN_KEY}','1');location.reload();"
    ));
}

/// Clear the signed-in flag and reload, returning to unauthenticated mode.
fn clear_flag_and_reload() {
    let _ = js_sys::eval(&format!(
        "localStorage.removeItem('{SIGNED_IN_KEY}');location.reload();"
    ));
}

/// Navigate the browser to `url`. Used to send the user to the login page.
fn navigate_to(url: &str) {
    // Encode the URL as a JSON string literal so it is safe regardless of
    // what characters the IdP URL carries.
    let encoded = js_sys::JSON::stringify(&JsValue::from_str(url))
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("\"{}\"", url.replace('"', "%22")));
    let _ = js_sys::eval(&format!("location.href={encoded}"));
}

/// True when the worker's own URL carries `?signed_in=1`.
///
/// Workers cannot access `localStorage`, so the leader page appends
/// `?signed_in=1` to the glue URL when spawning in authenticated mode.
fn worker_signed_in_flag() -> bool {
    js_sys::eval(&format!(
        "self.location.search.includes('{SIGNED_IN_PARAM}')"
    ))
    .ok()
    .and_then(|v| v.as_bool())
    .unwrap_or(false)
}

/// The origin of the worker's own URL, e.g. `http://127.0.0.1:9912`.
///
/// Same as the page origin because the worker script is served from the same
/// host. Used to build `WorkerAuthConfig` entirely within the worker.
fn worker_origin() -> String {
    js_sys::eval("self.location.origin")
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

// -----------------------------------------------------------------------------

fn main() {
    // The dedicated DB worker imports this same wasm module: the leader spawns
    // it pointed straight at the dx glue (optionally with ?signed_in=1 appended),
    // which auto-initializes and runs this `main`. A worker has no `Window`.
    if web_sys::window().is_none() {
        let signed_in = worker_signed_in_flag();
        spawn_local(async move {
            if let Err(err) = run_db_worker(signed_in).await {
                web_sys::console::error_1(&format!("db worker failed: {err:?}").into());
            }
        });
        return;
    }
    dioxus::launch(App);
}

/// Boot the connetto DB tier in the worker context.
///
/// Calls [`workers::boot_db_worker`] with or without an auth config depending
/// on `signed_in`. When authenticated, `boot_db_worker` returns the resolved
/// `user_id` which is broadcast on [`DEMO_UID_CHANNEL`] so the page can display
/// which account owns the replica. The broadcast happens after `boot_db_worker`
/// returns, so the identity arrives after the worker has posted "ready" and the
/// Dashboard is already visible.
///
/// # Errors
///
/// A JS string describing the VFS, acquisition, upstream connect, or subscribe
/// failure.
async fn run_db_worker(signed_in: bool) -> Result<(), JsValue> {
    let auth = if signed_in {
        let origin = worker_origin();
        Some(WorkerAuthConfig {
            // Fetch calls go through this origin, where the dev server proxies
            // them, so they are same-origin and need no CORS.
            auth_base_url: origin.clone(),
            // The login is a navigation, which the dev server's proxy does not
            // forward, so it goes straight to the auth origin. A navigation needs
            // no CORS either way.
            login_base_url: Some(AUTH_ORIGIN.to_owned()),
            provider: AUTH_PROVIDER.to_owned(),
            redirect_uri: format!("{origin}{AUTH_CALLBACK_PATH}"),
        })
    } else {
        None
    };
    let user_id = workers::boot_db_worker::<String>(&workers::DbWorkerConfig {
        ws_url: DEMO_WS_URL,
        replica_db_prefix: DB_NAME,
        replica_ddl: DEMO_SQLITE_DDL,
        frontend_db_name: FRONTEND_DB_NAME,
        frontend_ddl: FRONTEND_DDL,
        upstream_sub_id: "db-upstream",
        upstream_query: DEMO_QUERY,
        hub_meta_name: "connetto-hub-meta.sqlite",
        client_id_prefix: "db-worker",
        schema_version: connetto_core::SchemaVersion::from_source(SCHEMA_SQL),
        sql_functions: uuidv7_functions(),
        auth,
        auth_db_name: AUTH_DB_NAME,
    })
    .await?;
    // Post the identity so the page can show which account owns the replica.
    if let (Some(uid), Ok(ch)) = (user_id, BroadcastChannel::new(DEMO_UID_CHANNEL)) {
        let _ = ch.post_message(&JsValue::from_str(&uid));
        ch.close();
    }
    Ok(())
}

/// The served URL of this app's wasm-bindgen glue module, recovered from the
/// wasm fetch the page already performed. Under `dx serve` the glue is
/// `/wasm/<name>.js` beside `/wasm/<name>_bg.wasm`, so the wasm resource entry
/// names the glue by suffix swap. Only the main thread can see these entries,
/// which is why the worker receives the glue URL as a spawn parameter.
fn glue_url() -> String {
    let found = js_sys::eval(
        r#"performance.getEntriesByType("resource").map((e) => e.name).find((n) => n.endsWith("_bg.wasm"))"#,
    )
    .ok()
    .and_then(|value| value.as_string())
    .expect("a loaded wasm resource entry");
    let base = found.strip_suffix("_bg.wasm").expect("wasm suffix");
    format!("{base}.js")
}

/// The window's live connection to the DB worker, plus the topology tokens it
/// must keep alive: leadership (this window may own the worker) and the tab
/// liveness lock (dropped on unmount, so the worker reaps this tab).
struct Boot {
    client: ConnettoClient<Tab>,
    _membership: leader::Membership,
    _tab_lock: locks::HeldLock,
}

/// Join the topology and connect this window's tab client.
///
/// When `signed_in` is true the glue URL passed to the leader election carries
/// `?signed_in=1` so the spawned worker knows to boot in authenticated mode.
/// The sequence otherwise mirrors what the browser test suite pins: join the
/// leader election (the winner spawns the worker), wait for the worker to
/// answer, hold the tab liveness lock BEFORE connecting, connect over a boot
/// wire, and wrap the connection in the reconnecting client so a worker swap
/// recovers.
async fn boot_window(signed_in: bool) -> Result<Boot, JsValue> {
    let raw_glue = glue_url();
    let glue = if signed_in {
        format!("{raw_glue}?{SIGNED_IN_PARAM}")
    } else {
        raw_glue
    };
    let client_id = format!("tab-{}", js_sys::Date::now());

    // The DB worker is the wasm-bindgen glue itself: dx auto-initializes it on
    // import and `main` boots the tier, so no separate bootstrap is needed.
    let membership = leader::join(LEADER_LOCK, &glue, workers::WorkerBootstrap::Glue);
    workers::await_db_worker_ready().await;

    let tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let wire = format!("connetto-wire-{client_id}-boot");
    workers::announce_tab(&wire).await;
    let transport = BroadcastTransport::with_peer_liveness(&wire, workers::DB_ALIVE_LOCK)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    let config = ClientConfig {
        client_id: client_id.clone(),
        auth_token: "token".to_owned(),
        schema_version: Some(connetto_core::SchemaVersion::from_source(SCHEMA_SQL)),
        sql_functions: uuidv7_functions(),
    };
    let conn =
        ConnettoConnection::connect(transport, &Replica::Ephemeral, DEMO_TAB_DDL, &config, None)
            .await
            .map_err(|err| JsValue::from_str(&err.to_string()))?;
    let policy = connetto_client::reconnect::ReconnectPolicy {
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_secs(2),
        max_attempts: None,
    };
    let (client, pump) = ConnettoClient::with_reconnect(
        conn,
        workers::tab_wire_factory(client_id),
        workers::sleep,
        policy,
    );
    spawn_local(pump);
    Ok(Boot {
        client,
        _membership: membership,
        _tab_lock: tab_lock,
    })
}

/// A short status line word for one client event, or `None` to ignore it.
fn status_label(event: &ClientEvent) -> Option<String> {
    match event {
        ClientEvent::Reconnecting { attempt } => Some(format!("reconnecting (attempt {attempt})")),
        ClientEvent::Reconnected => Some("reconnected".to_owned()),
        ClientEvent::MutationApplied { client_seq } => {
            Some(format!("mutation {client_seq} applied"))
        }
        ClientEvent::MutationRejected { client_seq, .. } => {
            Some(format!("mutation {client_seq} rejected"))
        }
        ClientEvent::MutationConflict { client_seq, .. } => {
            Some(format!("mutation {client_seq} conflicted"))
        }
        ClientEvent::Closed => Some("connection closed".to_owned()),
        _ => None,
    }
}

/// Styling kept minimal: the demo is the topology, not the paint.
const CSS: &str = r"
    body { font-family: sans-serif; margin: 0; }
    .wrap { padding: 16px; max-width: 720px; margin: 0 auto; }
    .panes { display: flex; gap: 16px; flex-wrap: wrap; }
    .pane { flex: 1 1 300px; border: 1px solid #ccc; border-radius: 8px; padding: 12px; }
    .pane h2 { margin-top: 0; font-size: 1.1em; }
    .badge { font-size: 0.7em; padding: 2px 6px; border-radius: 4px; vertical-align: middle; }
    .synced { background: #e6f0ff; color: #14458c; }
    .local { background: #fde6e6; color: #8c1414; }
    .status { color: #555; font-family: monospace; }
    table { border-collapse: collapse; width: 100%; margin-top: 8px; }
    th, td { border: 1px solid #ddd; padding: 4px 8px; text-align: left; }
    input { padding: 4px; }
    button { padding: 4px 10px; cursor: pointer; }
    .row { display: flex; gap: 6px; margin-top: 8px; flex-wrap: wrap; }
    .auth-banner { border-radius: 8px; padding: 10px 14px; margin-bottom: 12px; }
    .auth-anon { background: #f5f5f5; border: 1px solid #ddd; }
    .auth-signed-in { background: #eaf4ea; border: 1px solid #7cb97c; }
    .auth-banner p { margin: 0 0 6px; }
    .auth-banner button { margin-right: 6px; }
    .logout-confirm { background: #fff8e1; border: 1px solid #f0c040;
                      border-radius: 6px; padding: 8px 12px; }
    .logout-confirm p { margin: 0 0 6px; }
";

// Dioxus components are PascalCase by convention; the `rsx!` call sites name
// them as elements, so keep the component name and silence the lint.
#[allow(non_snake_case)]
fn App() -> Element {
    let signed_in = page_signed_in_flag();

    // Read ?code=...&state=... from the URL once, then clear it so a reload
    // does not attempt to redeem a spent authorization code.
    let pending = page_login_callback();
    if pending.is_some() {
        clear_url_query();
    }

    let mut client_slot = use_signal(|| None::<ConnettoClient<Tab>>);
    let mut status = use_signal(|| "connecting to the connetto stack".to_owned());
    // User id received from the worker after authentication.
    let mut user_id: Signal<Option<String>> = use_signal(|| None);

    use_context_provider(|| client_slot);
    use_context_provider(|| status);
    use_context_provider(|| user_id);

    // Listen for the user id the worker broadcasts after boot_db_worker returns.
    // The broadcast arrives AFTER the worker posts "ready", so the Dashboard is
    // already visible when this fires and the banner updates reactively from
    // "authenticating..." to the actual account name. Wrapped in Rc<RefCell<_>>
    // because Closure<dyn FnMut> is not Clone, but use_hook requires Clone.
    let _uid_listener = use_hook(move || {
        Rc::new(RefCell::new(if signed_in {
            let ch = BroadcastChannel::new(DEMO_UID_CHANNEL).expect("uid channel");
            let on_msg = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                if let Some(uid) = e.data().as_string() {
                    user_id.set(Some(uid));
                }
            });
            ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
            Some((ch, on_msg))
        } else {
            None
        }))
    });

    // Listen on the login channel. When the worker broadcasts its login URL:
    //   - If this page load is the OAuth callback (pending.is_some()), deliver
    //     the code and state to the worker.
    //   - Otherwise navigate the browser to the login URL.
    let _login_listener = use_hook(move || {
        Rc::new(RefCell::new(if signed_in {
            let login_ch =
                BroadcastChannel::new(connetto_web::LOGIN_CHANNEL).expect("login channel");
            let on_msg = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                let Some(text) = e.data().as_string() else {
                    return;
                };
                // Parse LoginMessage::Request via js_sys::JSON to avoid a
                // serde_json dependency in the demo.
                let val = match js_sys::JSON::parse(&text) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let kind = js_sys::Reflect::get(&val, &JsValue::from_str("kind"))
                    .ok()
                    .and_then(|v| v.as_string());
                if kind.as_deref() != Some("request") {
                    return;
                }
                let Some(url) = js_sys::Reflect::get(&val, &JsValue::from_str("url"))
                    .ok()
                    .and_then(|v| v.as_string())
                else {
                    return;
                };
                if let Some((code, state)) = &pending {
                    // This page IS the callback: deliver the code to the worker.
                    let _ = deliver_login_code(code, state);
                } else {
                    // Initial sign-in: send the user to the IdP.
                    navigate_to(&url);
                }
            });
            login_ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
            Some((login_ch, on_msg))
        } else {
            None
        }))
    });

    let boot_hold = use_hook(|| Rc::new(RefCell::new(None::<Boot>)));
    use_hook(move || {
        let boot_hold = boot_hold.clone();
        spawn(async move {
            match boot_window(signed_in).await {
                Ok(boot) => {
                    let mut events = boot.client.events();
                    client_slot.set(Some(boot.client.clone()));
                    status.set("connected".to_owned());
                    *boot_hold.borrow_mut() = Some(boot);
                    while let Ok(event) = events.recv().await {
                        if let Some(label) = status_label(&event) {
                            status.set(label);
                        }
                    }
                }
                Err(err) => status.set(format!("boot failed: {err:?}")),
            }
        });
    });

    let ready = client_slot.read().is_some();
    rsx! {
        style { {CSS} }
        div { class: "wrap",
            h1 { "connetto web demo" }
            p { class: "status", "status: " {status} }
            AuthBanner { signed_in }
            if ready {
                Dashboard {}
            } else {
                p { "Connecting to the DB worker and the connetto stack..." }
            }
        }
    }
}

/// Auth status banner shown above the dashboard.
///
/// Unauthenticated: explains the mode and offers a sign-in button. Authenticated:
/// shows which account owns the replica and provides logout controls.
#[component]
#[allow(non_snake_case)]
fn AuthBanner(signed_in: bool) -> Element {
    let user_id = use_context::<Signal<Option<String>>>();

    if !signed_in {
        rsx! {
            div { class: "auth-banner auth-anon",
                p {
                    "Unauthenticated mode: shared plaintext replica. \
                     Signing in switches to a private encrypted replica named after your account."
                }
                button {
                    onclick: move |_| set_flag_and_reload(),
                    "Sign in (private encrypted replica)"
                }
            }
        }
    } else {
        let uid_text = user_id
            .read()
            .clone()
            .unwrap_or_else(|| "authenticating...".to_owned());
        rsx! {
            div { class: "auth-banner auth-signed-in",
                p { "Signed in as: " strong { {uid_text} } }
                p {
                    "Using a private encrypted replica. \
                     Signing out returns to the shared unauthenticated replica."
                }
                LogoutControls {}
            }
        }
    }
}

/// The three possible states of the logout UI.
#[derive(Clone, PartialEq)]
enum LogoutState {
    /// Showing the two logout buttons.
    Idle,
    /// Awaiting user confirmation: delete would lose this many unsynced writes.
    ConfirmDelete { unsynced_count: usize },
    /// A logout or unsynced-count request is in flight.
    Working,
    /// The request failed.
    Error(String),
}

/// Logout controls rendered inside the signed-in auth banner.
///
/// "Log out, keep local data" keeps the encrypted replica so a future login
/// with the same account resumes from the persisted cursor. "Delete local data
/// and log out" checks for unsynced writes first and confirms before losing any.
#[component]
#[allow(non_snake_case)]
fn LogoutControls() -> Element {
    let mut state = use_signal(|| LogoutState::Idle);

    let on_keep = move |_| {
        spawn(async move {
            state.set(LogoutState::Working);
            match request_logout(false, false).await {
                Ok(LogoutOutcome::Kept | LogoutOutcome::Deleted) => clear_flag_and_reload(),
                // Refused cannot occur when delete=false; treat as success.
                Ok(LogoutOutcome::Refused { .. }) => clear_flag_and_reload(),
                Err(err) => state.set(LogoutState::Error(err.to_string())),
            }
        });
    };

    let on_delete = move |_| {
        spawn(async move {
            state.set(LogoutState::Working);
            match request_unsynced().await {
                Ok(seqs) if seqs.is_empty() => {
                    // Nothing would be lost: proceed without a confirmation prompt.
                    match request_logout(true, false).await {
                        Ok(LogoutOutcome::Kept | LogoutOutcome::Deleted) => {
                            clear_flag_and_reload();
                        }
                        Ok(LogoutOutcome::Refused { seqs }) => {
                            // A write landed between our check and the request.
                            // Show the count and let the user confirm.
                            state.set(LogoutState::ConfirmDelete {
                                unsynced_count: seqs.len(),
                            });
                        }
                        Err(err) => state.set(LogoutState::Error(err.to_string())),
                    }
                }
                Ok(seqs) => {
                    state.set(LogoutState::ConfirmDelete {
                        unsynced_count: seqs.len(),
                    });
                }
                Err(err) => state.set(LogoutState::Error(err.to_string())),
            }
        });
    };

    let on_confirm = move |_| {
        spawn(async move {
            state.set(LogoutState::Working);
            match request_logout(true, true).await {
                Ok(_) => clear_flag_and_reload(),
                Err(err) => state.set(LogoutState::Error(err.to_string())),
            }
        });
    };

    let on_cancel = move |_| state.set(LogoutState::Idle);

    match state.read().clone() {
        LogoutState::Idle => rsx! {
            div { class: "row",
                button { onclick: on_keep, "Log out, keep local data" }
                button { onclick: on_delete, "Delete local data and log out" }
            }
        },
        LogoutState::ConfirmDelete { unsynced_count } => rsx! {
            div { class: "logout-confirm",
                p {
                    "You have {unsynced_count} unsynced write(s) that would be permanently lost."
                }
                div { class: "row",
                    button { onclick: on_confirm, "Confirm: delete and log out" }
                    button { onclick: on_cancel, "Cancel" }
                }
            }
        },
        LogoutState::Working => rsx! { p { "Working..." } },
        LogoutState::Error(msg) => rsx! {
            p { style: "color:#b00;", "Error: {msg}" }
            button { onclick: on_cancel, "Dismiss" }
        },
    }
}

#[component]
fn Dashboard() -> Element {
    let client = use_context::<Signal<Option<ConnettoClient<Tab>>>>()
        .read()
        .clone()
        .expect("Dashboard mounts only once the client is ready");

    let orders = use_live::<_, _, Order>(&client, orders::table.order(orders::id));
    let notes = use_live::<_, _, Note>(&client, notes::table.order(notes::id));

    let order_rows = orders.value().read().clone();
    let note_rows = notes.value().read().clone();
    // Aggregates are computed from the live rows: the relay hub does not serve
    // aggregate subscriptions, and the tab mirror already holds every row the
    // subscription covers, so the derived totals converge as the rows do.
    let order_count = order_rows.len();
    let order_sum: i64 = order_rows.iter().map(|row| row.quantity).sum();
    let note_count = note_rows.len();
    let order_view: Vec<(rosetta_uuid::Uuid, i64)> = order_rows
        .iter()
        .map(|row| (row.id, row.quantity))
        .collect();
    let note_view: Vec<(i64, String)> = note_rows
        .iter()
        .map(|row| (row.id, row.body.clone()))
        .collect();

    let orders_error = orders.error().read().clone();
    let notes_error = notes.error().read().clone();

    let mut note_text = use_signal(String::new);

    let add_order_client = client.clone();
    let save_note_client = client;

    rsx! {
        div { class: "panes",
            div { class: "pane",
                h2 { "orders " span { class: "badge synced", "synced" } }
                p { "count {order_count}, total quantity {order_sum}. Converges across every window through Postgres." }
                div { class: "row",
                    button {
                        onclick: move |_| {
                            let client = add_order_client.clone();
                            spawn(async move {
                                // The DEFAULT mints the id, so the insert omits it.
                                let quantity = fresh_quantity();
                                let result = client
                                    .with_conn(move |conn| {
                                        diesel::insert_into(orders::table)
                                            .values(orders::quantity.eq(quantity))
                                            .execute(conn.conn())
                                    })
                                    .await;
                                if let Err(err) = result {
                                    web_sys::console::error_1(&format!("order insert failed: {err}").into());
                                }
                            });
                        },
                        "Add order"
                    }
                }
                if let Some(err) = orders_error {
                    p { style: "color:#b00;", "orders error: {err}" }
                }
                table {
                    thead { tr { th { "id" } th { "quantity" } } }
                    tbody {
                        for (id, quantity) in order_view {
                            tr { key: "{id}",
                                td { "{id}" }
                                td { "{quantity}" }
                            }
                        }
                    }
                }
            }
            div { class: "pane",
                h2 { "notes " span { class: "badge local", "device-only" } }
                p { "count {note_count}. Converges across this device's windows through the DB worker, never the server." }
                div { class: "row",
                    input {
                        r#type: "text",
                        placeholder: "note body",
                        value: "{note_text}",
                        oninput: move |event| note_text.set(event.value()),
                    }
                    button {
                        onclick: move |_| {
                            let body = note_text.peek().clone();
                            if body.is_empty() {
                                return;
                            }
                            let client = save_note_client.clone();
                            spawn(async move {
                                let id = fresh_note_id();
                                let result = client
                                    .with_conn(move |conn| {
                                        diesel::insert_into(notes::table)
                                            .values((notes::id.eq(id), notes::body.eq(body)))
                                            .execute(conn.conn())
                                    })
                                    .await;
                                match result {
                                    Ok(_) => note_text.set(String::new()),
                                    Err(err) => {
                                        web_sys::console::error_1(&format!("note save failed: {err}").into());
                                    }
                                }
                            });
                        },
                        "Save note"
                    }
                }
                if let Some(err) = notes_error {
                    p { style: "color:#b00;", "notes error: {err}" }
                }
                table {
                    thead { tr { th { "id" } th { "body" } } }
                    tbody {
                        for (id, body) in note_view {
                            tr { key: "{id}",
                                td { "{id}" }
                                td { {body} }
                            }
                        }
                    }
                }
            }
        }
    }
}
