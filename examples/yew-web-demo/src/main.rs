//! Yew web demo of the connetto browser topology, end to end.
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
//! The DB worker shares this same wasm module: [`db_worker_boot`] is a
//! `wasm_bindgen` export the worker bootstrap (`assets/db-worker.js`) calls.
//! The app's [`main`] returns early in a worker context, where there is no
//! `Window` and Yew cannot run.
//!
//! Run against the demo stack (dev IdP, server on 7777, `connetto-demo-pg` on
//! 55456): start the dev IdP with `CONNETTO_AUTH_BIND=127.0.0.1:18081` set,
//! source `target/dev-idp.env`, start the server with `CONNETTO_AUTH`,
//! `CONNETTO_AUTH_BIND`, the `CONNETTO_OIDC_*` vars, `CONNETTO_READER_URL`,
//! `DATABASE_URL`, `CONNETTO_BIND`, `CONNETTO_WRITABLE`, and
//! `CONNETTO_PG_DDL_FILE`, then `trunk serve` from this directory and open
//! the served URL in several windows.

use std::rc::Rc;

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Replica};
use connetto_web::auth::WorkerAuthConfig;
use connetto_web::{BroadcastTransport, deliver_login_code, leader, locks, workers};
use connetto_yew::use_live;
use diesel::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{BroadcastChannel, HtmlInputElement, MessageEvent};
use yew::prelude::*;

/// The tab-to-worker transport this window's client rides.
type Tab = BroadcastTransport;

/// The demo server the DB worker connects upstream to.
const DEMO_WS_URL: &str = "ws://127.0.0.1:7777/";
/// The origin serving `connetto-server`'s auth router, which the login navigation
/// goes to directly. The worker's `fetch` calls go through this app's own origin
/// instead, where the dev server proxies them.
const AUTH_ORIGIN: &str = "http://127.0.0.1:18081";
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
/// The OPFS file holding the worker's durable synced replica.
const DB_NAME: &str = "connetto-relay.sqlite";
/// The OPFS file holding the worker's durable device-private tier.
const FRONTEND_DB_NAME: &str = "connetto-frontend.sqlite";
/// The shared leader lock every window of this app races.
const LEADER_LOCK: &str = "connetto-demo-leader";
/// The local tier schema, translated from `frontend.sql` by build.rs. DDL rather
/// than a baked template, because a tier encrypted at rest cannot be seeded from
/// a plaintext byte image.
const FRONTEND_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/frontend-ddl.sql"));
/// The `BroadcastChannel` the worker uses to report the authenticated user_id
/// to the page after a silent refresh, so the UI can show the account name.
const DEMO_IDENTITY_CHANNEL: &str = "connetto-demo-identity";

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
// `rosetta_uuid::Uuid::utc_v7`, the same strongly typed key the `orders` schema
// uses on SQLite and Postgres.
#[diesel::declare_sql_function]
extern "SQL" {
    /// Client-authored primary key: a 16-byte UUID v7, stored as a BLOB.
    fn uuidv7() -> diesel::sql_types::Binary;
}

/// The registrar connetto installs on every connection it opens for this app.
/// Nondeterministic, so SQLite calls `uuidv7()` per row instead of folding the
/// DEFAULT to a constant.
fn uuidv7_functions() -> connetto_client::SqlFunctions {
    connetto_client::SqlFunctions::new().with(std::sync::Arc::new(
        |conn: &mut diesel::SqliteConnection| {
            uuidv7_utils::register_nondeterministic_impl(conn, rosetta_uuid::Uuid::utc_v7)
        },
    ))
}

/// A device-unique integer id for a local-only `notes` row. `notes` stays on
/// integer keys (device-private, never synced), so the client authors the id.
/// The millisecond clock plus a random low tag keeps two windows of one device
/// from colliding within the same millisecond.
fn fresh_note_id() -> i64 {
    let now = js_sys::Date::now();
    debug_assert!(now.is_finite() && now >= 0.0);
    // Intended truncation: whole milliseconds since the epoch.
    let millis = now as i64;
    let tag = js_sys::Math::random() * 1000.0;
    // Math::random is [0, 1); scale to a 0..=999 tag. Deliberate quantization.
    debug_assert!(tag.is_finite() && (0.0..1000.0).contains(&tag));
    millis * 1000 + tag as i64
}

/// A visible order quantity inside the subscription's `quantity > 0` window.
///
/// The id is minted by the DEFAULT now, so quantity cannot key off it. A random
/// `1..=9` times five gives spread while staying strictly positive.
fn fresh_quantity() -> i64 {
    let scaled = js_sys::Math::random() * 9.0;
    // Math::random is [0, 1); scale to 0..=8. Deliberate truncation.
    debug_assert!(scaled.is_finite() && (0.0..9.0).contains(&scaled));
    (scaled as i64 + 1) * 5
}

fn main() {
    // The dedicated DB worker runs this same wasm module. A worker has no
    // Window, so boot the DB tier there instead of rendering the UI.
    if web_sys::window().is_none() {
        spawn_local(async {
            if let Err(err) = run_db_worker().await {
                web_sys::console::error_1(&format!("db worker failed: {err:?}").into());
            }
        });
        return;
    }

    let win = web_sys::window().expect("window context");

    // OAuth popup callback: the auth popup lands here with ?code=&state= after
    // the user authenticates. Deliver the code to the waiting worker, then
    // close the popup so the original window continues uninterrupted.
    //
    // A same-window redirect (no opener) is handled the same way: deliver the
    // code, clear the query string, and fall through to render the app. In
    // practice the popup path is used so the original worker keeps its PKCE
    // state and can verify the returned state parameter.
    let search = win.location().search().unwrap_or_default();
    if let (Some(code), Some(state)) = (query_param(&search, "code"), query_param(&search, "state"))
    {
        let _ = deliver_login_code(&code, &state);

        // If this window was opened by window.open() for the auth popup, close
        // it now that the code has been delivered to the original window's worker.
        let has_opener = js_sys::Reflect::get(win.as_ref(), &"opener".into())
            .map(|v| !v.is_null() && !v.is_undefined())
            .unwrap_or(false);
        if has_opener {
            let _ = win.close();
            return;
        }

        // Not a popup: clear the query string so a reload does not re-deliver
        // an already-spent code.
        let pathname = win.location().pathname().unwrap_or_else(|_| "/".to_owned());
        if let Ok(history) = win.history() {
            let _ = history.replace_state_with_url(&JsValue::NULL, "", Some(&pathname));
        }
    }

    yew::Renderer::<App>::new().render();
}

/// Boot the connetto DB tier in the worker context with the demo config.
///
/// # Errors
///
/// A JS string describing the VFS, upstream connect, or subscribe failure.
async fn run_db_worker() -> Result<(), JsValue> {
    let origin = worker_origin();
    let auth = Some(WorkerAuthConfig {
        // Fetch calls go through this origin's proxy, so they are same-origin
        // and need no CORS.
        auth_base_url: origin.clone(),
        // The login is a navigation; trunk's proxy does not forward a request
        // that carries a query string, so it goes straight to the auth origin.
        login_base_url: Some(AUTH_ORIGIN.to_owned()),
        provider: "dev-idp".to_owned(),
        redirect_uri: format!("{origin}/"),
    });
    // boot_db_worker returns the authenticated user_id (if any) once the hub
    // is set up and serving. Broadcast it so the page can show the account.
    if let Some(user_id) =
        connetto_web::workers::boot_db_worker::<String>(&connetto_web::workers::DbWorkerConfig {
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
            auth_db_name: "connetto-auth.sqlite",
        })
        .await?
    {
        broadcast_identity(&user_id);
    }
    Ok(())
}

/// Worker context: broadcast the authenticated user_id to all page tabs so
/// each can show the account that owns the private encrypted replica.
fn broadcast_identity(user_id: &str) {
    if let Ok(ch) = BroadcastChannel::new(DEMO_IDENTITY_CHANNEL) {
        let _ = ch.post_message(&JsValue::from_str(&format!("identity:{user_id}")));
        ch.close();
    }
}

/// Parse one query-string parameter from a `?key=value&...` search string.
fn query_param(search: &str, key: &str) -> Option<String> {
    search.trim_start_matches('?').split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.to_owned())
    })
}

/// Reload the page after logout.
fn reload_page() {
    if let Some(win) = web_sys::window() {
        let _ = win.location().reload();
    }
}

/// The origin of the worker's own URL, e.g. `http://127.0.0.1:9911`.
///
/// Same as the page origin because the worker script is served from the same
/// host. Used to build `WorkerAuthConfig` within the worker.
fn worker_origin() -> String {
    js_sys::eval("self.location.origin")
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

/// The served URL of this app's wasm-bindgen glue module, recovered from the
/// wasm fetch the page already performed. Under trunk the glue is
/// `/<name>-<hash>.js` beside `/<name>-<hash>_bg.wasm`, so the wasm resource
/// entry names the glue by suffix swap. Only the main thread can see these
/// entries, which is why the worker receives the glue URL as a spawn parameter.
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
/// The sequence mirrors what the browser test suite pins: join the leader
/// election (the winner spawns the worker), wait for the worker to answer,
/// hold the tab liveness lock BEFORE connecting, connect over a boot wire, and
/// wrap the connection in the reconnecting client so a worker swap recovers.
async fn boot_window() -> Result<Boot, JsValue> {
    let glue = glue_url();
    let client_id = format!("tab-{}", js_sys::Date::now());

    // Trunk's glue does not self-initialize, so connetto-web spawns the worker
    // from a generated bootstrap that imports the glue and runs init.
    let membership = leader::join(LEADER_LOCK, &glue, workers::WorkerBootstrap::Generated);
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
    let policy = ReconnectPolicy {
        initial_backoff: core::time::Duration::from_millis(100),
        max_backoff: core::time::Duration::from_secs(2),
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
    .row { display: flex; gap: 6px; margin-top: 8px; }
    .auth-bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 10px 0; padding: 8px; background: #f8f8f8; border-radius: 6px; }
";

/// A cheaply clonable, identity-compared client handle for props.
///
/// One window creates exactly one client and never replaces it, so pointer
/// identity is the right equality: [`Dashboard`] mounts once with it and
/// re-renders from its own live state, not from a prop change.
#[derive(Clone)]
struct ClientHandle(Rc<ConnettoClient<Tab>>);

impl PartialEq for ClientHandle {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

#[function_component(App)]
fn app() -> Html {
    let client = use_state(|| None::<ClientHandle>);
    let status = use_state(|| "connecting to the connetto stack".to_owned());
    // The boot tokens live as long as the app: dropping them on page close
    // resigns leadership and frees the tab lock, which reaps this tab. The App
    // is the root and never unmounts, so the event-listener task holding this
    // ref for the page's life is intended.
    let boot_hold = use_mut_ref(|| None::<Boot>);

    // The worker broadcasts the user_id after a silent refresh so the UI can
    // display the account.
    let identity = use_state(|| None::<String>);
    // The worker broadcasts the login URL when interactive auth is needed.
    // The page shows a button that opens the URL in a popup so the original
    // window (and its worker with the PKCE state) stays alive.
    let login_url = use_state(|| None::<String>);
    // Confirmation state for the delete-data logout flow.
    let confirm_seqs = use_state(|| None::<Vec<u64>>);
    let refused_seqs = use_state(|| None::<Vec<u64>>);

    // Listen for the worker broadcasting the authenticated user_id.
    {
        let identity = identity.clone();
        use_effect_with((), move |()| {
            let channel = BroadcastChannel::new(DEMO_IDENTITY_CHANNEL).expect("identity channel");
            let on_msg = {
                let identity = identity.clone();
                Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                    let Some(data) = event.data().as_string() else {
                        return;
                    };
                    if let Some(uid) = data.strip_prefix("identity:") {
                        identity.set(Some(uid.to_owned()));
                    }
                })
            };
            channel.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
            move || {
                channel.set_onmessage(None);
                channel.close();
                drop(on_msg);
            }
        });
    }

    // Listen for the worker requesting an interactive login popup. Parsing the
    // JSON without serde_json by reflecting on the parsed JS object.
    {
        let login_url = login_url.clone();
        use_effect_with((), move |()| {
            let channel =
                BroadcastChannel::new(connetto_web::LOGIN_CHANNEL).expect("login channel");
            let on_msg = {
                let login_url = login_url.clone();
                Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                    let Some(text) = event.data().as_string() else {
                        return;
                    };
                    let Ok(obj) = js_sys::JSON::parse(&text) else {
                        return;
                    };
                    let kind = js_sys::Reflect::get(&obj, &"kind".into())
                        .ok()
                        .and_then(|v| v.as_string());
                    if kind.as_deref() != Some("request") {
                        return;
                    }
                    if let Some(url) = js_sys::Reflect::get(&obj, &"url".into())
                        .ok()
                        .and_then(|v| v.as_string())
                    {
                        login_url.set(Some(url));
                    }
                })
            };
            channel.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
            move || {
                channel.set_onmessage(None);
                channel.close();
                drop(on_msg);
            }
        });
    }

    // Connect to the DB worker and forward status events (existing behaviour).
    {
        let client = client.clone();
        let status = status.clone();
        let boot_hold = boot_hold.clone();
        use_effect_with((), move |()| {
            spawn_local(async move {
                match boot_window().await {
                    Ok(boot) => {
                        let mut events = boot.client.events();
                        client.set(Some(ClientHandle(Rc::new(boot.client.clone()))));
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
            || ()
        });
    }

    // Open the login URL in a popup (user gesture -> popup allowed by the browser).
    let open_popup = {
        let login_url = login_url.clone();
        Callback::from(move |_| {
            if let (Some(url), Some(win)) = ((*login_url).clone(), web_sys::window()) {
                let _ = win.open_with_url_and_target_and_features(
                    &url,
                    "_blank",
                    "popup,width=640,height=720",
                );
            }
        })
    };

    let logout_keep = {
        let status = status.clone();
        Callback::from(move |_| {
            let status = status.clone();
            spawn_local(async move {
                match connetto_web::auth::request_logout(false, false).await {
                    Ok(_) => reload_page(),
                    Err(err) => status.set(format!("logout failed: {err}")),
                }
            });
        })
    };

    let logout_delete = {
        let status = status.clone();
        let confirm_seqs = confirm_seqs.clone();
        let refused_seqs = refused_seqs.clone();
        Callback::from(move |_| {
            let status = status.clone();
            let confirm_seqs = confirm_seqs.clone();
            let refused_seqs = refused_seqs.clone();
            spawn_local(async move {
                match connetto_web::auth::request_unsynced().await {
                    Ok(seqs) if seqs.is_empty() => {
                        // No unsynced writes: proceed without asking.
                        match connetto_web::auth::request_logout(true, false).await {
                            Ok(connetto_web::auth::LogoutOutcome::Refused { seqs }) => {
                                // A write landed between the check and the request.
                                refused_seqs.set(Some(seqs));
                            }
                            Ok(_) => reload_page(),
                            Err(err) => status.set(format!("logout failed: {err}")),
                        }
                    }
                    Ok(seqs) => confirm_seqs.set(Some(seqs)),
                    Err(err) => status.set(format!("checking unsynced failed: {err}")),
                }
            });
        })
    };

    let confirm_delete = {
        let status = status.clone();
        let confirm_seqs = confirm_seqs.clone();
        Callback::from(move |_| {
            let status = status.clone();
            let confirm_seqs = confirm_seqs.clone();
            spawn_local(async move {
                confirm_seqs.set(None);
                // force=true because the user saw the count and confirmed.
                match connetto_web::auth::request_logout(true, true).await {
                    Ok(_) => reload_page(),
                    Err(err) => status.set(format!("forced delete failed: {err}")),
                }
            });
        })
    };

    let force_delete = {
        let status = status.clone();
        let refused_seqs = refused_seqs.clone();
        Callback::from(move |_| {
            let status = status.clone();
            let refused_seqs = refused_seqs.clone();
            spawn_local(async move {
                refused_seqs.set(None);
                match connetto_web::auth::request_logout(true, true).await {
                    Ok(_) => reload_page(),
                    Err(err) => status.set(format!("forced delete failed: {err}")),
                }
            });
        })
    };

    let cancel_confirm = {
        let confirm_seqs = confirm_seqs.clone();
        let refused_seqs = refused_seqs.clone();
        Callback::from(move |_| {
            confirm_seqs.set(None);
            refused_seqs.set(None);
        })
    };

    let auth_bar = {
        let account_line = match &*identity {
            Some(uid) => {
                html! { <span>{ format!("Signed in as {} (private encrypted replica).", uid) }</span> }
            }
            None => html! {
                <span>{ "Signed in (account loading)." }</span>
            },
        };

        // The prompt stands only until the account is known. The worker broadcasts
        // its login request once and never withdraws it, so a completed login has
        // to be recognised here, otherwise the prompt outlives its purpose and
        // hides the logout controls behind it.
        let awaiting_login = identity.is_none();
        let action_row = if let (Some(url), true) = ((*login_url).clone(), awaiting_login) {
            html! {
                <span>
                    { "Interactive sign-in required. " }
                    <button onclick={open_popup} title={url}>
                        { "Sign in with dev-idp" }
                    </button>
                </span>
            }
        } else {
            html! {
                <span>
                    <button onclick={logout_keep}>{ "Log out, keep local data" }</button>
                    { " " }
                    <button onclick={logout_delete}>{ "Delete local data and log out" }</button>
                </span>
            }
        };

        let confirm_html = if let Some(seqs) = &*confirm_seqs {
            let count = seqs.len();
            html! {
                <span>
                    { format!("{count} unsynced write(s) will be lost. ") }
                    <button onclick={confirm_delete}>{ "Delete anyway" }</button>
                    { " " }
                    <button onclick={cancel_confirm.clone()}>{ "Cancel" }</button>
                </span>
            }
        } else {
            html! {}
        };

        let refused_html = if let Some(seqs) = &*refused_seqs {
            let count = seqs.len();
            html! {
                <span>
                    { format!("Refused: {count} write(s) still pending. ") }
                    <button onclick={force_delete}>{ "Force delete" }</button>
                    { " " }
                    <button onclick={cancel_confirm}>{ "Cancel" }</button>
                </span>
            }
        } else {
            html! {}
        };

        html! {
            <div class="auth-bar">
                { account_line }
                { action_row }
                { confirm_html }
                { refused_html }
            </div>
        }
    };

    let dashboard = if let Some(handle) = &*client {
        html! { <Dashboard client={handle.clone()} /> }
    } else {
        html! { <p>{ "Connecting to the DB worker and the connetto stack..." }</p> }
    };

    html! {
        <>
            <style>{ CSS }</style>
            <div class="wrap">
                <h1>{ "connetto web demo (Yew)" }</h1>
                <p class="status">{ format!("status: {}", &*status) }</p>
                { auth_bar }
                { dashboard }
            </div>
        </>
    }
}

/// The client the dashboard drives, passed once from [`App`] when it is ready.
#[derive(Properties, PartialEq)]
struct DashboardProps {
    client: ClientHandle,
}

#[function_component(Dashboard)]
fn dashboard(props: &DashboardProps) -> Html {
    let client = (*props.client.0).clone();

    let orders = use_live::<_, _, Order>(&client, orders::table.order(orders::id));
    let notes = use_live::<_, _, Note>(&client, notes::table.order(notes::id));

    let order_rows = orders.value();
    let note_rows = notes.value();
    // Aggregates are computed from the live rows: the relay hub does not serve
    // aggregate subscriptions, and the tab mirror already holds every row the
    // subscription covers, so the derived totals converge as the rows do.
    let order_count = order_rows.len();
    let order_sum: i64 = order_rows.iter().map(|row| row.quantity).sum();
    let note_count = note_rows.len();

    let note_text = use_state(String::new);

    let add_order = {
        let client = client.clone();
        Callback::from(move |_| {
            let client = client.clone();
            spawn_local(async move {
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
        })
    };

    let on_note_input = {
        let note_text = note_text.clone();
        Callback::from(move |event: InputEvent| {
            let input: HtmlInputElement = event.target_unchecked_into();
            note_text.set(input.value());
        })
    };

    let save_note = {
        let client = client;
        let note_text = note_text.clone();
        Callback::from(move |_| {
            let body = (*note_text).clone();
            if body.is_empty() {
                return;
            }
            let client = client.clone();
            let note_text = note_text.clone();
            spawn_local(async move {
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
        })
    };

    let orders_error = orders.error().map(|err| {
        html! { <p style="color:#b00;">{ format!("orders error: {err}") }</p> }
    });
    let notes_error = notes.error().map(|err| {
        html! { <p style="color:#b00;">{ format!("notes error: {err}") }</p> }
    });

    html! {
        <div class="panes">
            <div class="pane">
                <h2>{ "orders " }<span class="badge synced">{ "synced" }</span></h2>
                <p>{ format!("count {order_count}, total quantity {order_sum}. Converges across every window through Postgres.") }</p>
                <div class="row">
                    <button onclick={add_order}>{ "Add order" }</button>
                </div>
                { orders_error.unwrap_or_default() }
                <table>
                    <thead><tr><th>{ "id" }</th><th>{ "quantity" }</th></tr></thead>
                    <tbody>
                        { for order_rows.iter().map(|row| {
                            let id = row.id.to_string();
                            html! {
                                <tr key={id.clone()}>
                                    <td>{ id }</td>
                                    <td>{ row.quantity.to_string() }</td>
                                </tr>
                            }
                        }) }
                    </tbody>
                </table>
            </div>
            <div class="pane">
                <h2>{ "notes " }<span class="badge local">{ "device-only" }</span></h2>
                <p>{ format!("count {note_count}. Converges across this device's windows through the DB worker, never the server.") }</p>
                <div class="row">
                    <input type="text" placeholder="note body" value={(*note_text).clone()} oninput={on_note_input} />
                    <button onclick={save_note}>{ "Save note" }</button>
                </div>
                { notes_error.unwrap_or_default() }
                <table>
                    <thead><tr><th>{ "id" }</th><th>{ "body" }</th></tr></thead>
                    <tbody>
                        { for note_rows.iter().map(|row| {
                            let id = row.id.to_string();
                            html! {
                                <tr key={id.clone()}>
                                    <td>{ id }</td>
                                    <td>{ row.body.clone() }</td>
                                </tr>
                            }
                        }) }
                    </tbody>
                </table>
            </div>
        </div>
    }
}
