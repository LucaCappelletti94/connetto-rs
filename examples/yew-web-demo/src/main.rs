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
//! Run against the demo stack (server on 7777, `connetto-demo-pg` on 55456):
//! `trunk serve` from this directory, then open the served URL in several
//! windows.

use std::rc::Rc;

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection};
use connetto_web::{BroadcastTransport, leader, locks, workers};
use connetto_yew::use_live;
use diesel::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::HtmlInputElement;
use yew::prelude::*;

/// The tab-to-worker transport this window's client rides.
type Tab = BroadcastTransport;

/// The demo server the DB worker connects upstream to.
const DEMO_WS_URL: &str = "ws://127.0.0.1:7777/";
/// The Postgres schema source the demo server is launched with. Hashing it
/// yields the version the server advertises, so this build presents a matching
/// version at handshake and is not rejected as stale.
const SCHEMA_SQL: &str = include_str!("../schema.sql");
/// The synced replica schema (worker first boot). Matches `schema.sql`.
const DEMO_SQLITE_DDL: &str = "CREATE TABLE orders (id BLOB PRIMARY KEY CHECK (length(id) = 16) NOT NULL, quantity INTEGER) STRICT;";
/// The tab mirror schema: both tiers in the tab's main schema, because every
/// relayed patch applies to main. The hub, not the tab, keeps the tiers apart.
const DEMO_TAB_DDL: &str = "CREATE TABLE orders (id BLOB PRIMARY KEY CHECK (length(id) = 16) NOT NULL, quantity INTEGER) STRICT; \
     CREATE TABLE notes (id BLOB PRIMARY KEY CHECK (length(id) = 16) NOT NULL, body TEXT) STRICT;";
/// The upstream subscription the worker registers.
const DEMO_QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
/// The OPFS file holding the worker's durable synced replica.
const DB_NAME: &str = "connetto-relay.sqlite";
/// The OPFS file holding the worker's durable device-private tier.
const FRONTEND_DB_NAME: &str = "connetto-frontend.sqlite";
/// The shared leader lock every window of this app races.
const LEADER_LOCK: &str = "connetto-demo-leader";
/// The baked local tier template, translated from `frontend.sql` by build.rs.
const FRONTEND_TEMPLATE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/frontend-template.sqlite"));

diesel::table! {
    orders (id) {
        id -> diesel::sql_types::Binary,
        quantity -> diesel::sql_types::BigInt,
    }
}

diesel::table! {
    notes (id) {
        id -> diesel::sql_types::Binary,
        body -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: Vec<u8>,
    quantity: i64,
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Note {
    id: Vec<u8>,
    body: String,
}

/// A fresh 16-byte row id: a uuid v7 built from the wall clock and random
/// counter bytes, so ids sort by creation time and never collide across the
/// demo's windows. Stored as the raw 16 bytes to match the pg2sqlite
/// `BLOB CHECK (length(id) = 16)` column and the CDC echo, never a 36-char
/// string. No ambient clock or `getrandom`: `Date::now` gives the millisecond
/// timestamp and `Math::random` the counter bytes, both wasm-safe.
fn fresh_id() -> Vec<u8> {
    let now = js_sys::Date::now();
    // Date::now is a finite, positive epoch-millisecond count, far below u64::MAX.
    debug_assert!(now.is_finite() && now >= 0.0);
    let millis = now as u64;
    let mut counter = [0u8; 10];
    for byte in &mut counter {
        let scaled = js_sys::Math::random() * 256.0;
        // Math::random is [0, 1); scale to a byte. Deliberate quantization.
        debug_assert!(scaled.is_finite() && (0.0..256.0).contains(&scaled));
        *byte = scaled as u8;
    }
    uuid::Builder::from_unix_timestamp_millis(millis, &counter)
        .into_uuid()
        .into_bytes()
        .to_vec()
}

/// A visible order quantity inside the subscription's `quantity > 0` window.
///
/// The id is opaque bytes now, so quantity can no longer key off it. A random
/// `1..=9` times five gives spread while staying strictly positive.
fn fresh_quantity() -> i64 {
    let scaled = js_sys::Math::random() * 9.0;
    // Math::random is [0, 1); scale to 0..=8. Deliberate truncation.
    debug_assert!(scaled.is_finite() && (0.0..9.0).contains(&scaled));
    (scaled as i64 + 1) * 5
}

/// Render a 16-byte id as a hyphenated uuid string for the dashboard, with a
/// hex fallback if the bytes are not a uuid width.
fn id_display(bytes: &[u8]) -> String {
    uuid::Uuid::from_slice(bytes)
        .map(|id| id.to_string())
        .unwrap_or_else(|_| bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn main() {
    // The dedicated DB worker runs this same wasm module: connetto-web spawns
    // it from a generated bootstrap that initializes the wasm, and init runs
    // this `main`. A worker has no `Window`, so boot the DB tier there instead
    // of rendering the UI.
    if web_sys::window().is_none() {
        spawn_local(async {
            if let Err(err) = run_db_worker().await {
                web_sys::console::error_1(&format!("db worker failed: {err:?}").into());
            }
        });
        return;
    }
    yew::Renderer::<App>::new().render();
}

/// Boot the connetto DB tier in the worker context with the demo config.
///
/// # Errors
///
/// A JS string describing the VFS, upstream connect, or subscribe failure.
async fn run_db_worker() -> Result<(), JsValue> {
    connetto_web::workers::boot_db_worker(&connetto_web::workers::DbWorkerConfig {
        ws_url: DEMO_WS_URL,
        replica_db_name: DB_NAME,
        replica_ddl: DEMO_SQLITE_DDL,
        frontend_db_name: FRONTEND_DB_NAME,
        frontend_template: FRONTEND_TEMPLATE,
        upstream_sub_id: "db-upstream",
        upstream_query: DEMO_QUERY,
        hub_meta_name: "connetto-hub-meta.sqlite",
        client_id_prefix: "db-worker",
        schema_version: connetto_core::SchemaVersion::from_source(SCHEMA_SQL),
    })
    .await
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
    };
    let conn = ConnettoConnection::connect(transport, ":memory:", DEMO_TAB_DDL, &config, None)
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
                let id = fresh_id();
                // Quantity in the subscription's window (> 0), varied for visibility.
                let quantity = fresh_quantity();
                let result = client
                    .with_conn(move |conn| {
                        diesel::insert_into(orders::table)
                            .values((orders::id.eq(id), orders::quantity.eq(quantity)))
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
                let id = fresh_id();
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
                            let id = id_display(&row.id);
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
                            let id = id_display(&row.id);
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
