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
//! The DB worker shares this same wasm module: [`db_worker_boot`] is a
//! `wasm_bindgen` export the worker bootstrap (`assets/db-worker.js`) calls.
//! The app's [`main`] returns early in a worker context, where there is no
//! `Window` and Dioxus cannot run.
//!
//! Run against the demo stack (server on 7777, `connetto-demo-pg` on 55456):
//! `dx serve` from this directory, then open the served URL in several windows.

use core::sync::atomic::{AtomicI64, Ordering};

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection};
use connetto_dioxus::use_live;
use connetto_web::{BroadcastTransport, leader, locks, workers};
use diesel::prelude::*;
use dioxus::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_futures::spawn_local;

/// The tab-to-worker transport this window's client rides.
type Tab = BroadcastTransport;

/// The demo server the DB worker connects upstream to.
const DEMO_WS_URL: &str = "ws://127.0.0.1:7777/";
/// The synced replica schema (worker first boot). Matches `schema.sql`.
const DEMO_SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY NOT NULL, quantity INTEGER) STRICT;";
/// The tab mirror schema: both tiers in the tab's main schema, because every
/// relayed patch applies to main. The hub, not the tab, keeps the tiers apart.
const DEMO_TAB_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY NOT NULL, quantity INTEGER) STRICT; \
     CREATE TABLE notes (id INTEGER PRIMARY KEY NOT NULL, body TEXT) STRICT;";
/// The upstream subscription the worker registers.
const DEMO_QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
/// The OPFS file holding the worker's durable synced replica.
const DB_NAME: &str = "connetto-relay.sqlite";
/// The OPFS file holding the worker's durable device-private tier.
const FRONTEND_DB_NAME: &str = "connetto-frontend.sqlite";
/// The shared leader lock every window of this app races.
const LEADER_LOCK: &str = "connetto-demo-leader";
/// The baked local tier template, translated from `frontend.sql` by build.rs.
const FRONTEND_TEMPLATE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/frontend-template.sqlite"));
/// The DB worker bootstrap script, shipped as a dioxus asset.
const DB_WORKER_JS: Asset = asset!("/assets/db-worker.js");

diesel::table! {
    orders (id) {
        id -> diesel::sql_types::BigInt,
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
    id: i64,
    quantity: i64,
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Note {
    id: i64,
    body: String,
}

/// Per-window sequence for locally written rows, combined with a random band
/// so concurrent windows never collide. Relaxed suffices: the atomic only
/// hands out distinct values, it synchronizes nothing else.
static LOCAL_SEQ: AtomicI64 = AtomicI64::new(0);

/// A fresh row id unique across the demo's windows: a per-window random band
/// (chosen once) times a wide multiplier, plus a per-window sequence.
fn fresh_id() -> i64 {
    thread_local! {
        static BAND: i64 = window_band();
    }
    BAND.with(|band| band * 1_000_000 + LOCAL_SEQ.fetch_add(1, Ordering::Relaxed))
}

/// A random per-window id band in `[0, 2^31)`.
fn window_band() -> i64 {
    // `Math::random` is in `[0, 1)`; scale to a 31-bit band. The float-to-int
    // is intended truncation of a finite value provably inside the i64 range.
    let scaled = js_sys::Math::random() * f64::from(1u32 << 31);
    debug_assert!(scaled.is_finite() && (0.0..f64::from(1u32 << 31)).contains(&scaled));
    scaled as i64
}

fn main() {
    // The dedicated DB worker imports this same wasm module, so its start runs
    // this `main`. It must not launch the UI: a worker has no `Window` and
    // Dioxus panics there. The worker path is `db_worker_boot`, which
    // `db-worker.js` calls after the module is initialized.
    if web_sys::window().is_none() {
        return;
    }
    dioxus::launch(App);
}

/// DB worker entry point: boot the connetto DB tier with the demo config. The
/// worker bootstrap imports this crate's glue and awaits this export.
///
/// # Errors
///
/// A JS string describing the VFS, upstream connect, or subscribe failure.
#[wasm_bindgen]
pub async fn db_worker_boot() -> Result<(), JsValue> {
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
    })
    .await
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
/// The sequence mirrors what the browser test suite pins: join the leader
/// election (the winner spawns the worker), wait for the worker to answer,
/// hold the tab liveness lock BEFORE connecting, connect over a boot wire, and
/// wrap the connection in the reconnecting client so a worker swap recovers.
async fn boot_window() -> Result<Boot, JsValue> {
    let glue = glue_url();
    let worker = DB_WORKER_JS.to_string();
    let client_id = format!("tab-{}", js_sys::Date::now());

    let membership = leader::join(LEADER_LOCK, &worker, &glue);
    workers::await_db_worker_ready().await;

    let tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let wire = format!("connetto-wire-{client_id}-boot");
    workers::announce_tab(&wire).await;
    let transport = BroadcastTransport::with_peer_liveness(&wire, workers::DB_ALIVE_LOCK)
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    let config = ClientConfig {
        client_id: client_id.clone(),
        auth_token: "token".to_owned(),
    };
    let conn = ConnettoConnection::connect(transport, ":memory:", DEMO_TAB_DDL, &config, None)
        .await
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    let policy = ReconnectPolicy {
        initial_backoff: core::time::Duration::from_millis(100),
        max_backoff: core::time::Duration::from_secs(2),
        max_attempts: None,
    };
    let (client, pump) =
        ConnettoClient::with_reconnect(conn, workers::tab_wire_factory(client_id), workers::sleep, policy);
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
        ClientEvent::MutationApplied { client_seq } => Some(format!("mutation {client_seq} applied")),
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

fn App() -> Element {
    let mut client_slot = use_signal(|| None::<ConnettoClient<Tab>>);
    let mut status = use_signal(|| "connecting to the connetto stack".to_owned());
    // Provided so the panes read the client and status without prop plumbing
    // through non-`PartialEq` component boundaries.
    use_context_provider(|| client_slot);
    use_context_provider(|| status);

    // The boot tokens live as long as the app: dropping them on page close
    // resigns leadership and frees the tab lock, which reaps this tab.
    let boot_hold = use_hook(|| std::rc::Rc::new(std::cell::RefCell::new(None::<Boot>)));
    use_hook(move || {
        let boot_hold = boot_hold.clone();
        spawn(async move {
            match boot_window().await {
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
            if ready {
                Dashboard {}
            } else {
                p { "Connecting to the DB worker and the connetto stack..." }
            }
        }
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
                                let id = fresh_id();
                                // Quantity in the subscription's window (> 0), varied for visibility.
                                let quantity = (id % 9 + 1).abs() * 5;
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
                        for row in order_rows {
                            tr { key: "{row.id}",
                                td { "{row.id}" }
                                td { "{row.quantity}" }
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
                        for row in note_rows {
                            tr { key: "{row.id}",
                                td { "{row.id}" }
                                td { "{row.body}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
