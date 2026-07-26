//! The leader topology in a real page: the page wins the leader lock and
//! spawns the dedicated DB worker (the only context kind with OPFS sync
//! access handles), the worker owns the sahpool replica, the server
//! connection, and the relay hub, and independent tab clients speak the
//! wire protocol to it over per-tab `BroadcastChannel`s, with Web Locks
//! based dead-tab reaping.
//!
//! One test walks every leg: a pre-existing row arrives in a tab only
//! through the DB worker's snapshot, an external write fans out to two
//! tabs through one server connection, a tab write rides up into Postgres
//! and echoes to the sibling tab, releasing a tab's liveness lock gets it
//! reaped without disturbing the survivor, and the survivor keeps
//! receiving patches afterward. Leader failover needs the client reconnect
//! machinery and is deferred with it.
//!
//! Run with the demo stack up:
//! `wasm-pack test --headless --chrome examples/wasm-smoke`

#![cfg(target_arch = "wasm32")]

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection};
use connetto_core::Transport;
use connetto_wasm_smoke::workers::{
    DEMO_QUERY, DEMO_SQLITE_DDL, DEMO_WS_URL, announce_tab, await_db_worker_ready,
};
use connetto_wasm_smoke::{BroadcastTransport, BrowserSocket, leader, locks};
use diesel::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// Progress marker for diagnosing a harness timeout: the stages appear in
/// the captured console output.
fn stage(message: &str) {
    web_sys::console::log_1(&message.into());
}

/// Relay the worker's breadcrumbs into the page console: a worker's
/// console is not always visible to the harness, so the bootstrap
/// broadcasts its progress and failures on this channel instead.
fn relay_worker_breadcrumbs() {
    let channel = web_sys::BroadcastChannel::new("connetto-debug").expect("broadcast channel");
    let on_message = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::MessageEvent)>::new(
        |event: web_sys::MessageEvent| {
            web_sys::console::log_1(&event.data());
        },
    );
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
    // The channel itself must outlive the test to keep delivering.
    core::mem::forget(channel);
}

diesel::table! {
    orders (id) {
        id -> diesel::sql_types::BigInt,
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    quantity: i64,
}

/// Base for row ids unique across smoke runs, in the topology test's band.
fn unique_base() -> i64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Date::now in milliseconds fits i64 until the year 285428751"
    )]
    let millis = js_sys::Date::now() as i64;
    50_000_000_000 + millis
}

/// The served URL of this test's wasm-bindgen glue module, recovered from
/// the wasm fetch the harness already performed. The DB worker bootstrap
/// receives it as a query parameter.
fn glue_url() -> String {
    let found = js_sys::eval(
        r#"performance.getEntriesByType("resource").map((e) => e.name).find((n) => n.endsWith("_bg.wasm"))"#,
    )
    .expect("query resource entries")
    .as_string()
    .expect("a loaded wasm resource entry");
    let base = found.strip_suffix("_bg.wasm").expect("wasm suffix");
    format!("{base}.js")
}

/// Connect a tab client to the DB worker over its own wire channel.
///
/// Announces the channel and waits for the worker's attachment ack first,
/// so the handshake cannot outrun the worker's end of the channel.
async fn connect_tab(client_id: &str) -> ConnettoConnection<BroadcastTransport> {
    let wire = format!("connetto-wire-{client_id}");
    announce_tab(&wire).await;
    let transport = BroadcastTransport::new(&wire).expect("wire channel");
    let config = ClientConfig {
        client_id: client_id.to_owned(),
        auth_token: "token".to_owned(),
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
    };
    ConnettoConnection::connect(transport, ":memory:", DEMO_SQLITE_DDL, &config, None)
        .await
        .expect("tab connect through the wire channel")
}

async fn connect_server(name: &str, tag: i64) -> ConnettoConnection<BrowserSocket> {
    let transport = BrowserSocket::connect(DEMO_WS_URL)
        .await
        .expect("connect to connetto-server");
    let config = ClientConfig {
        client_id: format!("{name}-{tag}"),
        auth_token: "token".to_owned(),
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
    };
    ConnettoConnection::connect(transport, ":memory:", DEMO_SQLITE_DDL, &config, None)
        .await
        .expect("client connect")
}

/// Pump `conn` until an event matches `pred`, applying every frame in
/// between. The harness timeout bounds the wait.
async fn pump_until<T>(
    conn: &mut ConnettoConnection<T>,
    pred: impl Fn(&ClientEvent) -> bool,
) -> ClientEvent
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        let event = conn.pump_one().await.expect("pump");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
        if pred(&event) {
            return event;
        }
    }
}

/// Pump `conn` until its local replica holds the order row `id`.
async fn pump_until_row<T>(conn: &mut ConnettoConnection<T>, id: i64)
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        let rows: Vec<Order> = orders::table
            .order(orders::id)
            .load(conn.conn())
            .expect("local read");
        if rows.iter().any(|row| row.id == id) {
            return;
        }
        let event = conn.pump_one().await.expect("pump");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
    }
}

/// Insert one row through `writer` and fence on a pong: control frames are
/// processed in order, so the pong proves the server applied the mutation.
async fn write_row(writer: &mut ConnettoConnection<BrowserSocket>, id: i64, nonce: u64) {
    diesel::insert_into(orders::table)
        .values((orders::id.eq(id), orders::quantity.eq(5_i64)))
        .execute(writer.conn())
        .expect("writer insert");
    writer.push().await.expect("push").expect("mutation sent");
    writer.ping(nonce).await.expect("ping");
    pump_until(
        writer,
        |event| matches!(event, ClientEvent::Pong { nonce: n } if *n == nonce),
    )
    .await;
}

#[wasm_bindgen_test]
async fn leader_topology_serves_tabs_and_reaps_the_dead() {
    let base = unique_base();
    relay_worker_breadcrumbs();
    let snapshot_id = base;
    let fanout_id = base + 1;
    let tab_write_id = base + 2;
    let post_reap_id = base + 3;

    // A pre-existing row: it can only reach a tab through the DB worker's
    // snapshot leg.
    let mut writer = connect_server("topology-writer", base).await;
    write_row(&mut writer, snapshot_id, 1).await;
    stage("writer seeded the snapshot row");

    // This page wins the leader election and owns the DB worker. A
    // multi-page app races the same leader lock, and the winner runs this.
    let membership = leader::join(&format!("connetto-leader-{base}"), &glue_url());
    await_db_worker_ready().await;
    stage("db worker ready");

    // Tab A holds its liveness lock BEFORE connecting, the protocol the
    // reaper requires.
    let client_a = format!("tab-a-{base}");
    let lock_a = locks::hold_lock(&locks::tab_lock_name(&client_a)).await;
    let mut tab_a = connect_tab(&client_a).await;
    stage("tab a connected");
    tab_a
        .subscribe("tab-a-orders", DEMO_QUERY)
        .await
        .expect("tab a subscribe");
    pump_until(&mut tab_a, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    pump_until_row(&mut tab_a, snapshot_id).await;
    stage("tab a snapshot verified");

    // A second tab client into the SAME DB worker.
    let client_b = format!("tab-b-{base}");
    let lock_b = locks::hold_lock(&locks::tab_lock_name(&client_b)).await;
    let mut tab_b = connect_tab(&client_b).await;
    tab_b
        .subscribe("tab-b-orders", DEMO_QUERY)
        .await
        .expect("tab b subscribe");
    pump_until(&mut tab_b, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    stage("tab b connected");

    // An external write fans out to both tabs through the one upstream
    // connection the DB worker holds.
    write_row(&mut writer, fanout_id, 2).await;
    pump_until_row(&mut tab_a, fanout_id).await;
    pump_until_row(&mut tab_b, fanout_id).await;
    stage("fanout verified");

    // A tab write rides up through hub, worker replica, and server into
    // Postgres. The sibling tab seeing it proves the full round trip: the
    // echo only exists for writes the server applied.
    diesel::insert_into(orders::table)
        .values((orders::id.eq(tab_write_id), orders::quantity.eq(7_i64)))
        .execute(tab_a.conn())
        .expect("tab a insert");
    tab_a
        .push()
        .await
        .expect("tab a push")
        .expect("mutation sent");
    pump_until_row(&mut tab_b, tab_write_id).await;
    stage("tab write round trip verified");

    // Simulated tab death: releasing the liveness lock is exactly what the
    // browser does when a tab's context dies. The reaper closes B's
    // session politely, so B observes a clean close.
    lock_b.release();
    loop {
        if matches!(
            tab_b.pump_one().await.expect("tab b pump"),
            ClientEvent::Closed
        ) {
            break;
        }
    }
    stage("tab b reaped");

    // The hub keeps serving the survivor after the reap.
    write_row(&mut writer, post_reap_id, 3).await;
    pump_until_row(&mut tab_a, post_reap_id).await;

    writer.close().await.expect("close writer");
    tab_a.close().await.expect("close tab a");
    lock_a.release();
    drop(membership);
}
