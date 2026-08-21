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
//! The worker acquires a connetto session via the dev OIDC provider, names the
//! replica from the identity, and encrypts it at rest. The OAuth callback lands
//! at `/auth/callback`; the proxy covers `/auth/token`, `/auth/refresh`, and
//! `/auth/logout`. The DB worker shares this same wasm module and builds its
//! auth config from `self.location.origin`.
//!
//! Run: start the dev IdP (`cargo run --release -p connetto-server --example
//! dev_idp`) with `CONNETTO_AUTH_BIND=127.0.0.1:18081` set, source
//! `target/dev-idp.env`, start the server with `CONNETTO_AUTH`,
//! `CONNETTO_AUTH_BIND`, the OIDC provider vars from `target/dev-idp.env`,
//! `CONNETTO_READER_URL`, `DATABASE_URL`, `CONNETTO_BIND`, `CONNETTO_WRITABLE`, and
//! `CONNETTO_PG_DDL_FILE`, then `dx serve --port 9912` from this directory.

use std::rc::Rc;
use std::{
    cell::RefCell,
    time::{Duration, SystemTime},
};

use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Custody, NoGate, PolicyTables,
    Replica,
    teardown::{ExpiryWarning, expiry_warning},
};
use connetto_core::messages::FatalErrorReason;
use connetto_dioxus::use_live;
use connetto_web::{
    MessageTransport,
    auth::{LogoutOutcome, WorkerAuthConfig, deliver_login_code, request_logout, request_unsynced},
    leader, locks,
    unlock::{AccountChoice, serve_account_choice},
    workers,
};
use diesel::prelude::*;
use dioxus::prelude::*;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::spawn_local;
use web_sys::{BroadcastChannel, MessageEvent};

include!(concat!(env!("OUT_DIR"), "/replica-tables.rs"));

/// The tab-to-worker transport this window's client rides.
type Tab = MessageTransport<BroadcastChannel>;

/// The demo server the DB worker connects upstream to.
const DEMO_WS_URL: &str = "ws://127.0.0.1:7777/";
/// The Postgres schema source the demo server is launched with. Hashing it
/// yields the version the server advertises, so this build presents a matching
/// version at handshake and is not rejected as stale.
const SCHEMA_SQL: &str = include_str!("../schema.sql");
/// The synced replica schema (worker first boot). Matches `schema.sql`.
const DEMO_SQLITE_DDL: &str = "CREATE TABLE orders (id BLOB PRIMARY KEY DEFAULT (uuidv4()) CHECK (length(id) = 16) NOT NULL, quantity INTEGER NOT NULL CHECK (quantity >= 0)) STRICT; \
     CREATE TABLE order_lines (order_id BLOB NOT NULL REFERENCES orders(id) CHECK (length(order_id) = 16), line_no INTEGER NOT NULL, quantity INTEGER NOT NULL CHECK (quantity >= 0), PRIMARY KEY (order_id, line_no)) STRICT;";
/// The tab mirror schema: both tiers in the tab's main schema, because every
/// relayed patch applies to main. The hub, not the tab, keeps the tiers apart.
const DEMO_TAB_DDL: &str = "CREATE TABLE orders (id BLOB PRIMARY KEY DEFAULT (uuidv4()) CHECK (length(id) = 16) NOT NULL, quantity INTEGER NOT NULL CHECK (quantity >= 0)) STRICT; \
     CREATE TABLE order_lines (order_id BLOB NOT NULL REFERENCES orders(id) CHECK (length(order_id) = 16), line_no INTEGER NOT NULL, quantity INTEGER NOT NULL CHECK (quantity >= 0), PRIMARY KEY (order_id, line_no)) STRICT; \
     CREATE TABLE notes (id INTEGER PRIMARY KEY NOT NULL, body TEXT) STRICT;";
/// The upstream subscription the worker registers.
const DEMO_QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
/// The OPFS file holding the worker's durable synced replica (base name; the
/// worker appends the identity hash so each account gets its own encrypted file).
const DB_NAME: &str = "connetto-relay.sqlite";
/// The OPFS file holding the worker-only refresh token, encrypted at rest.
const AUTH_DB_NAME: &str = "connetto-auth.sqlite";
/// The shared leader lock every window of this app races.
const LEADER_LOCK: &str = "connetto-demo-leader";
/// The local tier schema, translated from `frontend.sql` by build.rs.
const FRONTEND_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/frontend-ddl.sql"));
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
/// Channel the page uses to respond to the worker's provider query at each boot.
const DEMO_PROVIDER_CHANNEL: &str = "connetto-demo-provider";
/// File name the export download is offered under.
const EXPORT_FILE_NAME: &str = "connetto-local-data.zip";

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

// The synced key generator: `orders.id` bakes to `DEFAULT (uuidv4())`, so a
// tab write omits the id and this registered function mints it. The impl is
// `rosetta_uuid::Uuid::new_v4`, the same strongly typed key the `orders`
// schema uses on SQLite and Postgres. Declared as nondeterministic so SQLite
// calls it per row instead of folding the DEFAULT to a constant.
// Declared with the built-in Binary type so diesel generates
// register_nondeterministic_impl for SQLite. rosetta_uuid::Uuid implements
// ToSql<Binary, Sqlite>, so the closure still returns the right value.
#[diesel::declare_sql_function]
extern "SQL" {
    fn uuidv4() -> diesel::sql_types::Binary;
}

/// The registrar connetto installs on every connection it opens for this app.
/// `INNOCUOUS` because the replica runs with trusted schema off and a column
/// DEFAULT is a schema object.
fn uuidv4_functions() -> connetto_client::SqlFunctions {
    connetto_client::SqlFunctions::new().with(std::sync::Arc::new(
        |conn: &mut diesel::SqliteConnection| {
            uuidv4_utils::register_impl_with_behavior(
                conn,
                diesel::sqlite::SqliteFunctionBehavior::INNOCUOUS,
                rosetta_uuid::Uuid::new_v4,
            )
        },
    ))
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

/// The tab mirror's physical footprint, read straight off the replica the
/// client holds: total pages and the free pages a trim can reclaim.
async fn replica_footprint(client: &ConnettoClient<Tab>) -> (i64, i64) {
    client
        .with_conn(|conn| {
            let db = conn.conn();
            let pages = db.page_count(None).unwrap_or(0);
            let free = db.freelist_count(None).unwrap_or(0);
            (pages, free)
        })
        .await
}

// --- Auth helpers ------------------------------------------------------------

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

/// True when this page was opened by another page on this origin, which is how a
/// login popup is distinguished from the application itself.
fn is_login_popup() -> bool {
    js_sys::eval("window.opener !== null && window.opener !== undefined")
        .ok()
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

/// Strip the query string from the current URL without a page reload so a
/// spent authorization code is not replayed on refresh.
fn clear_url_query() {
    let _ = js_sys::eval("history.replaceState(null,'',location.pathname)");
}

/// Reload the page after logout.
fn reload_page() {
    let _ = js_sys::eval("location.reload()");
}

/// Open `url` in a popup to run the login there.
///
/// Navigating this tab instead would destroy the page, and with it the dedicated
/// DB worker that asked for the login and holds the PKCE verifier. The returning
/// page would start a fresh worker with a fresh verifier, so the code it carried
/// home could never be redeemed. A popup leaves the opener and its worker alive.
fn open_login_popup(url: &str) {
    // Encode the URL as a JSON string literal so it is safe regardless of
    // what characters the IdP URL carries.
    let encoded = js_sys::JSON::stringify(&JsValue::from_str(url))
        .ok()
        .and_then(|s| s.as_string())
        .unwrap_or_else(|| format!("\"{}\"", url.replace('"', "%22")));
    let _ = js_sys::eval(&format!(
        "window.open({encoded},'connetto-login','popup=yes,width=520,height=640')"
    ));
}

/// The origin of the worker's own URL, e.g. `http://127.0.0.1:9912`.
///
/// Same as the page origin because the worker script is served from the same
/// host. Used to build `WorkerAuthConfig` within the worker.
fn worker_origin() -> String {
    js_sys::eval("self.location.origin")
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

/// Offer `bytes` to the user as a file download named `name`.
///
/// A `Blob` at an object URL plus a synthetic anchor click, which is the only
/// way a page can hand over a file the user decides where to keep. The URL is
/// revoked immediately: the click has already taken its own reference.
fn download_bytes(name: &str, bytes: &[u8]) -> Result<(), JsValue> {
    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(bytes));
    let blob = web_sys::Blob::new_with_u8_array_sequence(&parts)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)?;
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or_else(|| JsValue::from_str("no document"))?;
    let anchor: web_sys::HtmlAnchorElement = document.create_element("a")?.dyn_into()?;
    anchor.set_href(&url);
    anchor.set_download(name);
    anchor.click();
    web_sys::Url::revoke_object_url(&url)
}

// -----------------------------------------------------------------------------

fn main() {
    connetto_web::logging::init_console();
    // The dedicated DB worker imports this same wasm module: the leader spawns
    // it pointed straight at the dx glue, which auto-initializes and runs this
    // `main`. A worker has no `Window`.
    if web_sys::window().is_none() {
        spawn_local(async {
            if let Err(err) = run_db_worker().await {
                tracing::error!(error = ?err, "db worker failed");
            }
        });
        return;
    }
    // A login popup exists only to carry the code home. It must not boot a worker
    // of its own: the login belongs to the opener's worker, which holds the PKCE
    // verifier, and a second worker here would elect itself leader and open the
    // same replica.
    if is_login_popup() {
        if let Some((code, state)) = page_login_callback() {
            let _ = deliver_login_code(&code, &state);
        }
        let _ = js_sys::eval("window.close()");
        return;
    }
    dioxus::launch(App);
}

/// Worker context: ask the page which OIDC provider to use for this boot.
///
/// The page responds with the user's last choice within a few milliseconds.
/// Falls back to [`AUTH_PROVIDER`] after 200 ms so a page that never answers
/// does not stall the boot indefinitely.
async fn worker_provider() -> String {
    let Ok(ch) = BroadcastChannel::new(DEMO_PROVIDER_CHANNEL) else {
        return AUTH_PROVIDER.to_owned();
    };
    let received: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let received_clone = Rc::clone(&received);
    let on_msg = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
        if let Some(text) = e.data().as_string()
            && text != "provider?"
        {
            *received_clone.borrow_mut() = Some(text);
        }
    });
    ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
    let _ = ch.post_message(&JsValue::from_str("provider?"));
    for _ in 0..8 {
        workers::sleep(core::time::Duration::from_millis(25)).await;
        if received.borrow().is_some() {
            break;
        }
    }
    ch.set_onmessage(None);
    ch.close();
    drop(on_msg);
    received
        .borrow()
        .clone()
        .unwrap_or_else(|| AUTH_PROVIDER.to_owned())
}

/// Boot the connetto DB tier in the worker context.
///
/// Calls [`workers::boot_db_worker`] with the auth config built from the
/// worker's own origin. Once the session is acquired, `boot_db_worker` returns
/// the identity, account key, and session deadline, which are all broadcast on
/// [`DEMO_UID_CHANNEL`] so the page can display which account is live, filter
/// switch-account buttons, and warn before an offline session lapses. The
/// broadcast happens after `boot_db_worker` returns, so it arrives after the
/// worker has posted "ready" and the Dashboard is already visible.
///
/// # Errors
///
/// A JS string describing the VFS, acquisition, upstream connect, or subscribe
/// failure.
async fn run_db_worker() -> Result<(), JsValue> {
    let origin = worker_origin();
    let auth = Some(
        WorkerAuthConfig::new(
            origin.clone(),
            worker_provider().await,
            format!("{origin}{AUTH_CALLBACK_PATH}"),
        )
        // The login is a navigation, which the dev server's proxy does not
        // forward, so it goes straight to the auth origin. A navigation needs
        // no CORS either way.
        .with_login_base_url(Some(AUTH_ORIGIN.to_owned())),
    );
    let booted = workers::boot_db_worker::<String>(
        &workers::DbWorkerConfig::new(connetto_core::SchemaVersion::from_source(SCHEMA_SQL))
            .with_ws_url(DEMO_WS_URL)
            .with_replica_db_prefix(DB_NAME)
            .with_replica_ddl(DEMO_SQLITE_DDL)
            .with_frontend_ddl(FRONTEND_DDL)
            .with_upstream_sub_id("db-upstream")
            .with_upstream_query(DEMO_QUERY)
            .with_hub_meta_name("connetto-hub-meta.sqlite")
            .with_sql_functions(uuidv4_functions())
            .with_policy_tables(PolicyTables::from_translation(
                POLICY_TABLES.iter().copied(),
                POLICY_VIEWS.iter().copied(),
            ))
            .with_auth(auth)
            .with_auth_db_name(AUTH_DB_NAME)
            // Gate the replica with a passkey. leader::join installs serve_unlock,
            // so the tab handler is in place before the worker can ask.
            .with_unlock(true)
            // Ask the tab which account to sign in as when more than one is stored.
            .with_pick_account(true),
    )
    .await?;
    // Post all three session fields in one JS object so the page can show the
    // live account, warn before expiry, and populate switch-account buttons.
    if let Ok(ch) = BroadcastChannel::new(DEMO_UID_CHANNEL) {
        let obj = js_sys::Object::new();
        if let Some(uid) = &booted.identity {
            let _ = js_sys::Reflect::set(&obj, &JsValue::from_str("uid"), &JsValue::from_str(uid));
        }
        if let Some(acc) = &booted.account {
            let _ =
                js_sys::Reflect::set(&obj, &JsValue::from_str("account"), &JsValue::from_str(acc));
        }
        if let Some(secs) = booted.session_expires_at {
            // Unix seconds fit in f64 exactly: 2^53 (~9e15) >> any plausible session deadline.
            debug_assert!(
                secs <= (1u64 << 53),
                "session_expires_at exceeds f64 exact range"
            );
            let _ = js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("session_expires_at"),
                &JsValue::from_f64(secs as f64),
            );
        }
        let _ = ch.post_message(&obj);
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
    /// Shared rather than owned, because the gate ceremony is awaited and the
    /// handle has to outlive the borrow that reaches it.
    membership: Rc<leader::Membership>,
    _tab_lock: locks::HeldLock,
}

/// Join the topology and connect this window's tab client.
///
/// The sequence mirrors what the browser test suite pins: join the leader
/// election (the winner spawns the worker), wait for the worker to answer,
/// hold the tab liveness lock BEFORE connecting, connect over a boot wire, and
/// wrap the connection in the reconnecting client so a worker swap recovers.
async fn boot_window() -> Result<Boot, JsValue> {
    let glue = glue_url();
    // The relay hub keys each tab's mutation watermark by a typed UUID, so the
    // tab id must parse as one (the worker mints its own the same way).
    let client_id = rosetta_uuid::Uuid::new_v4().to_string();

    // The DB worker is the wasm-bindgen glue itself: dx auto-initializes it on
    // import and `main` boots the tier, so no separate bootstrap is needed.
    let membership = leader::join(LEADER_LOCK, &glue, workers::WorkerBootstrap::Glue);
    workers::await_db_worker_ready().await;

    let tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let wire = format!("connetto-wire-{client_id}-boot");
    workers::announce_tab(&wire).await;
    let transport =
        MessageTransport::<BroadcastChannel>::with_peer_liveness(&wire, workers::DB_ALIVE_LOCK)
            .map_err(|err| JsValue::from_str(&err.to_string()))?;
    let config = ClientConfig::new(client_id.clone())
        .with_schema_version(Some(connetto_core::SchemaVersion::from_source(SCHEMA_SQL)))
        .with_sql_functions(uuidv4_functions())
        .with_policy_tables(PolicyTables::from_translation(
            POLICY_TABLES.iter().copied(),
            POLICY_VIEWS.iter().copied(),
        ))
        // A low threshold so the free-up-space affordance reclaims after a
        // modest deletion, rather than only once the freelist is a quarter of
        // the file. Trimming still runs only when the pass is called.
        .with_trim_threshold(5);
    let conn = ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        DEMO_TAB_DDL,
        &config,
        None,
    )
    .await
    .map_err(|err| JsValue::from_str(&err.to_string()))?;
    let policy = connetto_client::reconnect::ReconnectPolicy::new()
        .with_initial_backoff(Duration::from_millis(100))
        .with_max_backoff(Duration::from_secs(2));
    let (client, pump) = ConnettoClient::with_reconnect(
        conn,
        workers::tab_wire_factory(client_id),
        workers::sleep,
        policy,
    );
    spawn_local(pump);
    Ok(Boot {
        client,
        membership: Rc::new(membership),
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
        ClientEvent::MutationConflict {
            client_seq,
            server_row,
            ..
        } => Some(server_row.as_ref().map_or_else(
            || format!("mutation {client_seq} conflicted, the server row is gone"),
            |row| {
                format!(
                    "mutation {client_seq} conflicted, the server holds {}",
                    row.row_json
                )
            },
        )),
        // The reconnect policy uses a fixed backoff and never reads retry_after_ms,
        // so this value is informational only.
        ClientEvent::RateLimited {
            related_to: _,
            retry_after_ms,
        } => Some(format!(
            "rate-limited by server: retry after {retry_after_ms} ms"
        )),
        ClientEvent::ServerClosed {
            reason: FatalErrorReason::RateLimited { retry_after_ms },
        } => Some(format!(
            "connection closed: server rate-limited this client (retry after {retry_after_ms} ms)"
        )),
        ClientEvent::ServerClosed { reason } => {
            Some(format!("server closed the session: {reason:?}"))
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
    .trim { background: #eef7e6; color: #2e6b14; }
    .status { color: #555; font-family: monospace; }
    table { border-collapse: collapse; width: 100%; margin-top: 8px; }
    th, td { border: 1px solid #ddd; padding: 4px 8px; text-align: left; }
    input { padding: 4px; }
    button { padding: 4px 10px; cursor: pointer; }
    .row { display: flex; gap: 6px; margin-top: 8px; flex-wrap: wrap; }
    .auth-banner { border-radius: 8px; padding: 10px 14px; margin-bottom: 12px; }
    .auth-signed-in { background: #eaf4ea; border: 1px solid #7cb97c; }
    .auth-banner p { margin: 0 0 6px; }
    .auth-banner button { margin-right: 6px; }
    .logout-confirm { background: #fff8e1; border: 1px solid #f0c040;
                      border-radius: 6px; padding: 8px 12px; }
    .logout-confirm p { margin: 0 0 6px; }
    .warn { color: #8c4400; font-weight: bold; background: #fff8e1;
            border: 1px solid #f0c040; border-radius: 4px; padding: 4px 8px; margin: 4px 0; }
";

/// The pending login URL, wrapped so the context lookup does not collide with the
/// identity signal, which is the same underlying type.
#[derive(Clone, Copy)]
struct LoginPrompt(Signal<Option<String>>);

/// Holds the Boot value so child components can borrow the Membership.
#[derive(Clone)]
struct BootHold(Rc<RefCell<Option<Boot>>>);

/// The credential-store key of the account currently signed in on this device.
#[derive(Clone, Copy)]
struct LiveAccount(Signal<Option<String>>);

/// Unix-second deadline after which the session lapses if never refreshed.
#[derive(Clone, Copy)]
struct SessionExpiresAt(Signal<Option<u64>>);

/// Passkey-gate custody level, fetched once after the worker reports ready.
#[derive(Clone, Copy)]
struct CustodyLevel(Signal<Option<Custody>>);

/// All stored account keys, filled by the first account-chooser invocation.
#[derive(Clone, Copy)]
struct AllAccounts(Signal<Vec<String>>);

/// Whether the account-chooser dialog is waiting for a user click.
#[derive(Clone, Copy)]
struct PickerActive(Signal<bool>);

/// The account the user chose in the picker; set by button click, consumed by the chooser.
#[derive(Clone, Copy)]
struct AccountAnswer(Signal<Option<AccountChoice>>);
// Dioxus components are PascalCase by convention; the `rsx!` call sites name
// them as elements, so keep the component name and silence the lint.
#[allow(non_snake_case)]
fn App() -> Element {
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
    // The login URL the worker is waiting on. A popup can only be opened from a
    // real click, so the URL is parked here and a button offers it.
    let login_prompt: Signal<Option<String>> = use_signal(|| None);
    // Multi-account, custody, and session-expiry state broadcast from the worker.
    let mut live_account: Signal<Option<String>> = use_signal(|| None);
    let mut session_expires_at: Signal<Option<u64>> = use_signal(|| None);
    let mut custody_level: Signal<Option<Custody>> = use_signal(|| None);
    let mut all_accounts: Signal<Vec<String>> = use_signal(Vec::new);
    let mut picker_active: Signal<bool> = use_signal(|| false);
    let mut account_answer: Signal<Option<AccountChoice>> = use_signal(|| None);

    use_context_provider(|| client_slot);
    use_context_provider(|| status);
    use_context_provider(|| user_id);
    use_context_provider(|| LoginPrompt(login_prompt));
    use_context_provider(|| LiveAccount(live_account));
    use_context_provider(|| SessionExpiresAt(session_expires_at));
    use_context_provider(|| CustodyLevel(custody_level));
    use_context_provider(|| AllAccounts(all_accounts));
    use_context_provider(|| PickerActive(picker_active));
    use_context_provider(|| AccountAnswer(account_answer));

    // Register the account chooser before the worker boots. For a single stored
    // credential the chooser returns immediately without blocking the UI. For
    // multiple it parks the list in a signal and polls for a button click.
    use_hook(|| {
        serve_account_choice(move |accounts| async move {
            if accounts.len() <= 1 {
                all_accounts.set(accounts);
                return AccountChoice::LastUsed;
            }
            all_accounts.set(accounts);
            picker_active.set(true);
            loop {
                let maybe_choice: Option<AccountChoice> = account_answer.read().clone();
                if let Some(choice) = maybe_choice {
                    picker_active.set(false);
                    account_answer.set(None);
                    return choice;
                }
                workers::sleep(Duration::from_millis(50)).await;
            }
        });
    });

    // Respond to the worker's provider query. The worker sends "provider?" on
    // DEMO_PROVIDER_CHANNEL at each boot, and this page always replies with the
    // one provider the dev stack registers.
    let _provider_listener = use_hook(move || {
        Rc::new(RefCell::new({
            let ch = BroadcastChannel::new(DEMO_PROVIDER_CHANNEL).expect("provider channel");
            let resp = ch.clone();
            let on_msg = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                if e.data().as_string().as_deref() == Some("provider?") {
                    let _ = resp.post_message(&JsValue::from_str(AUTH_PROVIDER));
                }
            });
            ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
            (ch, on_msg)
        }))
    });

    // Listen for the session fields the worker broadcasts after boot_db_worker
    // returns. uid, account key, and session_expires_at are packed into one
    // JS object so a single listener wires all three signals.
    let _uid_listener = use_hook(move || {
        Rc::new(RefCell::new({
            let ch = BroadcastChannel::new(DEMO_UID_CHANNEL).expect("uid channel");
            let on_msg = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                let data = e.data();
                if let Some(uid) = js_sys::Reflect::get(&data, &JsValue::from_str("uid"))
                    .ok()
                    .and_then(|v| v.as_string())
                {
                    user_id.set(Some(uid));
                }
                live_account.set(
                    js_sys::Reflect::get(&data, &JsValue::from_str("account"))
                        .ok()
                        .and_then(|v| v.as_string()),
                );
                session_expires_at.set(
                    js_sys::Reflect::get(&data, &JsValue::from_str("session_expires_at"))
                        .ok()
                        .and_then(|v| v.as_f64())
                        .map(|f| {
                            // Recovering unix seconds that were sent as f64.
                            // Always finite and << u64::MAX for any plausible deadline.
                            debug_assert!(
                                f.is_finite() && f >= 0.0,
                                "session_expires_at from broadcast must be finite"
                            );
                            f as u64 // deliberate truncation: integer seconds recovered from f64
                        }),
                );
            });
            ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
            (ch, on_msg)
        }))
    });

    // Listen on the login channel. When the worker broadcasts its login URL:
    //   - If this page load is the OAuth callback (pending.is_some()), deliver
    //     the code and state to the worker.
    //   - Otherwise park the URL so a button can offer it. A popup opened from
    //     this handler would be blocked, because a message is not user activation.
    let prompt = LoginPrompt(login_prompt);
    let _login_listener = use_hook(move || {
        Rc::new(RefCell::new({
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
                    prompt.0.clone().set(Some(url));
                }
            });
            login_ch.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
            (login_ch, on_msg)
        }))
    });

    let raw_boot_hold: Rc<RefCell<Option<Boot>>> = use_hook(|| Rc::new(RefCell::new(None::<Boot>)));
    use_context_provider(|| BootHold(raw_boot_hold.clone()));

    use_hook(move || {
        let boot_inner = raw_boot_hold.clone();
        spawn(async move {
            match boot_window().await {
                Ok(boot) => {
                    // Fetch the custody level now that the worker has settled.
                    custody_level.set(Some(workers::request_custody().await));
                    let mut events = boot.client.events();
                    client_slot.set(Some(boot.client.clone()));
                    status.set("connected".to_owned());
                    *boot_inner.borrow_mut() = Some(boot);
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
            AuthBanner {}
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
/// Shows the login button when interactive auth is needed, or the authenticated
/// account, custody level, expiry warning, account controls, and logout controls
/// once the session is acquired.
#[component]
#[allow(non_snake_case)]
fn AuthBanner() -> Element {
    let mut user_id = use_context::<Signal<Option<String>>>();
    let login_prompt = use_context::<LoginPrompt>().0;
    let mut live_account = use_context::<LiveAccount>().0;
    let session_expires_at = use_context::<SessionExpiresAt>().0;
    let mut custody = use_context::<CustodyLevel>().0;
    let all_accounts = use_context::<AllAccounts>().0;
    let picker_active = use_context::<PickerActive>().0;
    let mut account_answer = use_context::<AccountAnswer>().0;
    let boot_hold = use_context::<BootHold>();

    // Recomputed whenever session_expires_at changes: fetches the worker's
    // unsynced queue and warns when the session is within 7 days of lapsing.
    let mut expiry_warn: Signal<Option<ExpiryWarning>> = use_signal(|| None);
    let mut enrol_msg: Signal<Option<String>> = use_signal(|| None);
    use_effect(move || {
        let expires_secs = *session_expires_at.read();
        spawn(async move {
            let Some(secs) = expires_secs else {
                expiry_warn.set(None);
                return;
            };
            let unsynced = request_unsynced().await.unwrap_or_default();
            let now_f64 = js_sys::Date::now();
            // Deliberate truncation: milliseconds since epoch, always finite and non-negative.
            debug_assert!(
                now_f64.is_finite() && now_f64 >= 0.0,
                "Date::now() must be finite"
            );
            let now = SystemTime::UNIX_EPOCH + Duration::from_millis(now_f64 as u64);
            let expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
            expiry_warn.set(expiry_warning(
                now,
                expires_at,
                Duration::from_secs(7 * 24 * 3600),
                unsynced,
            ));
        });
    });

    if user_id.read().is_none() && login_prompt.read().is_some() {
        // The worker is waiting for an interactive login. A popup keeps this page
        // and its worker alive, and it can only be opened from a real click.
        let url = login_prompt.read().clone().unwrap_or_default();
        rsx! {
            div { class: "auth-banner auth-signed-in",
                p { "Sign in to begin." }
                button {
                    onclick: move |_| open_login_popup(&url),
                    "Sign in"
                }
            }
        }
    } else {
        let uid_text = user_id
            .read()
            .clone()
            .unwrap_or_else(|| "authenticating...".to_owned());
        let live_acc = live_account.read().clone();
        let accounts = all_accounts.read().clone();
        let is_active_picker = *picker_active.read();

        // Custody description and derived flags.
        let custody_snap = *custody.read();
        let enrol_offerable = matches!(custody_snap, Some(Custody::Unverified(NoGate::Offerable)));
        let custody_text = custody_snap.as_ref().map(|c| match c {
            Custody::Verified => "gate: verified by passkey".to_owned(),
            Custody::Unverified(NoGate::Offerable) => {
                "gate: not verified (passkey available)".to_owned()
            }
            Custody::Unverified(NoGate::Declined) => {
                "gate: not verified (passkey declined)".to_owned()
            }
            Custody::Unverified(NoGate::Unsupported) => {
                "gate: not verified (passkey not available on this device)".to_owned()
            }
            Custody::Ephemeral => "gate: no persistent key (anonymous session)".to_owned(),
        });

        // Session expiry warning text, computed outside RSX to keep the template flat.
        let expiry_line = expiry_warn.read().clone().map(|warn| {
            let n = warn.unsynced.len();
            let secs = warn
                .session_expires_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let now_f64 = js_sys::Date::now();
            // Deliberate truncation: ms to seconds, always finite and non-negative.
            debug_assert!(
                now_f64.is_finite() && now_f64 >= 0.0,
                "Date::now() must be finite"
            );
            let now_secs = (now_f64 / 1000.0) as u64;
            let days = secs.saturating_sub(now_secs) / 86400;
            format!(
                "Session lapses in {days} day(s). {n} local write(s) at risk. Connect to refresh."
            )
        });

        // Accounts the user can switch to: all stored minus the live one.
        let switch_targets: Vec<(String, String)> = accounts
            .iter()
            .filter(|a| Some(*a) != live_acc.as_ref())
            .map(|a| (a.clone(), a.clone()))
            .collect();
        // Each picker button needs its own (key, label) pair so closures can
        // capture the key by move without consuming the label.
        let picker_accounts: Vec<(String, String)> =
            accounts.iter().map(|a| (a.clone(), a.clone())).collect();

        rsx! {
            div { class: "auth-banner auth-signed-in",
                p {
                    "Signed in as: "
                    strong { {uid_text} }
                    if let Some(acc) = live_acc.clone() {
                        span { " (account: " code { {acc} } ")" }
                    }
                }
                if let Some(ct) = custody_text {
                    p { {ct} }
                }
                if enrol_offerable {
                    div { class: "row",
                        button {
                            onclick: {
                                let bh = boot_hold.clone();
                                move |_| {
                                    let bh = bh.clone();
                                    spawn(async move {
                                        // The ceremony runs for as long as the user
                                        // takes to present a finger, so the handle is
                                        // cloned out and the borrow released first.
                                        // Holding one across that await would panic
                                        // the moment anything took a mutable borrow.
                                        let membership = {
                                            let held = bh.0.borrow();
                                            match held.as_ref() {
                                                Some(bt) => Rc::clone(&bt.membership),
                                                None => return,
                                            }
                                        };
                                        let result = membership.enrol_gate().await;
                                        match result {
                                            Ok(true) => {
                                                custody.set(Some(
                                                    workers::request_custody().await,
                                                ));
                                                enrol_msg.set(None);
                                            }
                                            Ok(false) => {
                                                enrol_msg.set(Some(
                                                    "Passkey gate can only be set up in the \
                                                     window that owns the database."
                                                        .to_owned(),
                                                ));
                                            }
                                            Err(e) => {
                                                enrol_msg.set(Some(format!(
                                                    "Enrolment failed: {e:?}"
                                                )));
                                            }
                                        }
                                    });
                                }
                            },
                            "Enrol passkey gate"
                        }
                    }
                    if let Some(msg) = enrol_msg.read().clone() {
                        p { {msg} }
                    }
                }
                if let Some(line) = expiry_line {
                    p { class: "warn", {line} }
                }
                if is_active_picker {
                    p { "Choose an account to sign in as:" }
                    div { class: "row",
                        for (acc_key, acc_label) in picker_accounts {
                            button {
                                key: "{acc_label}",
                                onclick: move |_| {
                                    account_answer
                                        .set(Some(AccountChoice::Named(acc_key.clone())))
                                },
                                "Sign in as {acc_label}"
                            }
                        }
                        button {
                            onclick: move |_| account_answer.set(Some(AccountChoice::LastUsed)),
                            "Last used"
                        }
                    }
                }
                div { class: "row",
                    for (acc_key, acc_label) in switch_targets {
                        button {
                            key: "{acc_label}",
                            onclick: {
                                let bh = boot_hold.clone();
                                move |_| {
                                    let key = acc_key.clone();
                                    let bh = bh.clone();
                                    spawn(async move {
                                        // Cleared before the reboot, not after it.
                                        // The banner hides the login prompt while an
                                        // identity is held, and the replacement
                                        // worker may need one, so a stale identity
                                        // would hide the very control it is waiting
                                        // for. The worker rebroadcasts both once it
                                        // is up, which is what repopulates these.
                                        user_id.set(None);
                                        live_account.set(None);
                                        let result = {
                                            let b = bh.0.borrow();
                                            b.as_ref().map_or(Ok(()), |bt| {
                                                bt.membership.switch_account(&key)
                                            })
                                        };
                                        if let Err(e) = result {
                                            tracing::error!(error = ?e, "switch account failed");
                                        }
                                    });
                                }
                            },
                            "Switch to {acc_label}"
                        }
                    }
                    button {
                        onclick: {
                            let bh = boot_hold.clone();
                            move |_| {
                                let bh = bh.clone();
                                spawn(async move {
                                    // Same reason as the switch above, and it matters
                                    // more here: adding an account always needs an
                                    // interactive login, so the prompt must be
                                    // reachable. Nothing is reloaded either way,
                                    // because the pending choice lives in this page
                                    // and a reload would discard it.
                                    user_id.set(None);
                                    live_account.set(None);
                                    let result = {
                                        let b = bh.0.borrow();
                                        b.as_ref()
                                            .map_or(Ok(()), |bt| bt.membership.add_account())
                                    };
                                    if let Err(e) = result {
                                        tracing::error!(error = ?e, "add account failed");
                                    }
                                });
                            }
                        },
                        "Add another account"
                    }
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

/// Logout controls rendered inside the auth banner.
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
                Ok(LogoutOutcome::Kept | LogoutOutcome::Deleted) => reload_page(),
                // Refused cannot occur when delete=false; treat as success.
                Ok(LogoutOutcome::Refused { .. }) => reload_page(),
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
                            reload_page();
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
                Ok(_) => reload_page(),
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

    // R26: the last export's outcome, so a failed one is not silent.
    let mut export_status: Signal<Option<String>> = use_signal(|| None);

    // R15 retention readout: the tab mirror's page footprint, refreshed on
    // mount and whenever the covered rows move.
    let mut footprint = use_signal(|| (0_i64, 0_i64));
    {
        let client = client.clone();
        use_effect(move || {
            let _covered = orders.value().read().len() + notes.value().read().len();
            let client = client.clone();
            spawn(async move {
                footprint.set(replica_footprint(&client).await);
            });
        });
    }
    let (pages, free) = *footprint.read();
    let kb = pages * 4;
    let tidy_client = client.clone();
    let remove_order_client = client.clone();
    let newest_order = order_rows.last().map(|order| order.id);

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
                                    tracing::error!(error = %err, "order insert failed");
                                }
                            });
                        },
                        "Add order"
                    }
                    if let Some(id) = newest_order {
                        button {
                            onclick: move |_| {
                                let client = remove_order_client.clone();
                                spawn(async move {
                                    let result = client
                                        .with_conn(move |conn| {
                                            diesel::delete(
                                                orders::table.filter(orders::id.eq(id)),
                                            )
                                            .execute(conn.conn())
                                        })
                                        .await;
                                    if let Err(err) = result {
                                        tracing::error!(error = %err, "order remove failed");
                                    }
                                });
                            },
                            "Remove newest"
                        }
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
                                        tracing::error!(error = %err, "note save failed");
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
            div { class: "pane",
                h2 { "retention " span { class: "badge trim", "R15" } }
                p { "Replica mirror: {pages} pages (~{kb} KB), {free} free to reclaim. Covered rows: {order_count + note_count}." }
                p { "Ending a subscription evicts the rows no live subscription still covers, and the trimming pass hands the freed pages back to storage." }
                div { class: "row",
                    button {
                        onclick: move |_| {
                            let client = tidy_client.clone();
                            spawn(async move {
                                if let Err(err) = client.tidy().await {
                                    tracing::error!(error = %err, "free up space failed");
                                }
                                footprint.set(replica_footprint(&client).await);
                            });
                        },
                        "Free up space"
                    }
                }
            }
            div { class: "pane",
                h2 { "your data " span { class: "badge local", "R26" } }
                p { "A zip of plain SQLite databases, one per tier, readable with any SQLite tool." }
                p { "The DB worker exports, not this window: the worker holds the durable replica and the device-private tier, while a tab mirror is in memory and holds only what its subscriptions cover." }
                div { class: "row",
                    button {
                        onclick: move |_| {
                            spawn(async move {
                                let message = match workers::request_export().await {
                                    Ok(bytes) => {
                                        let len = bytes.len();
                                        match download_bytes(EXPORT_FILE_NAME, &bytes) {
                                            Ok(()) => format!("{len} bytes offered as {EXPORT_FILE_NAME}"),
                                            Err(err) => format!("download refused: {err:?}"),
                                        }
                                    }
                                    Err(err) => format!("export failed: {err}"),
                                };
                                export_status.set(Some(message));
                            });
                        },
                        "Export local data"
                    }
                }
                if let Some(message) = export_status.read().clone() {
                    p { style: "font-family:monospace;font-size:0.85em;color:#555;", {message} }
                }
            }
        }
    }
}
