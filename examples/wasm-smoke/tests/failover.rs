//! Leader failover with the reconnect machinery: the DB worker dies
//! mid-session and a replacement (spawned by the still-leading page,
//! standing in for a freshly elected leader) takes over. The replacement
//! resumes the OPFS replica from its persisted cursor and catches up from
//! the server oplog, the tab's reconnect driver finds it through the ready
//! handshake, and the tab converges on a row that was written while no
//! worker existed at all.
//!
//! Dead-worker detection is the alive lock: a broadcast peer dies silently,
//! so the tab's transport watches the lock the worker holds for its whole
//! life and injects a clean close when the browser releases it.
//!
//! Run with the demo stack up:
//! `wasm-pack test --headless --chrome examples/wasm-smoke`

#![cfg(target_arch = "wasm32")]

use core::time::Duration;

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, LiveQuery, Replica,
    dsl::Watchable,
};
use connetto_core::Transport;
use connetto_wasm_smoke::workers::{
    DB_ALIVE_LOCK, DEMO_SQLITE_DDL, DEMO_WS_URL, announce_tab, await_db_worker_ready, sleep,
    spawn_db_worker, tab_wire_factory,
};
use connetto_wasm_smoke::{BroadcastTransport, BrowserSocket, locks};
use diesel::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// Progress marker for diagnosing a harness timeout: the stages appear in
/// the captured console output.
fn stage(message: &str) {
    web_sys::console::log_1(&message.into());
}

/// Relay the workers' breadcrumbs into the page console.
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
        id -> rosetta_uuid::sql_types::Uuid,
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: rosetta_uuid::Uuid,
    quantity: i64,
}

/// Base for row ids unique across smoke runs, in the failover test's band.
fn unique_base() -> i64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Date::now in milliseconds fits i64 until the year 285428751"
    )]
    let millis = js_sys::Date::now() as i64;
    60_000_000_000 + millis
}

/// The served URL of this test's wasm-bindgen glue module.
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

async fn connect_server(name: &str, tag: i64) -> ConnettoConnection<BrowserSocket> {
    let transport = BrowserSocket::connect(DEMO_WS_URL)
        .await
        .expect("connect to connetto-server");
    let config = ClientConfig {
        client_id: format!("{name}-{tag}"),
        auth_token: "token".to_owned(),
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
        sql_functions: connetto_wasm_smoke::uuidv7_functions(),
    };
    ConnettoConnection::connect(
        transport,
        &Replica::Ephemeral,
        DEMO_SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("client connect")
}

/// Pump `conn` until an event matches `pred`. The harness timeout bounds
/// the wait.
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

/// Insert one row through `writer`, minting its id from the `orders` DEFAULT,
/// and fence on a pong. Returns the minted 16-byte id.
async fn write_row(
    writer: &mut ConnettoConnection<BrowserSocket>,
    nonce: u64,
) -> rosetta_uuid::Uuid {
    let before: std::collections::HashSet<rosetta_uuid::Uuid> = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(writer.conn())
        .expect("ids before insert")
        .into_iter()
        .collect();
    diesel::insert_into(orders::table)
        .values(orders::quantity.eq(5_i64))
        .execute(writer.conn())
        .expect("writer insert");
    let id = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(writer.conn())
        .expect("ids after insert")
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("the newly minted id");
    writer.push().await.expect("push").expect("mutation sent");
    writer.ping(nonce).await.expect("ping");
    pump_until(
        writer,
        |event| matches!(event, ClientEvent::Pong { nonce: n } if *n == nonce),
    )
    .await;
    id
}

#[wasm_bindgen_test]
async fn worker_failover_resumes_replica_and_reconnects_the_tab() {
    let base = unique_base();
    relay_worker_breadcrumbs();

    // A row that exists before anything boots.
    let mut writer = connect_server("failover-writer", base).await;
    let before_id = write_row(&mut writer, 1).await;
    stage("writer seeded the first row");

    // This page is the leader for the whole test: it holds the leader lock
    // and spawns each worker generation. A multi-page app races the same
    // lock and the winner runs exactly this code.
    let leader_lock = locks::hold_lock(&format!("connetto-leader-{base}")).await;
    let glue = glue_url();
    let worker_one = spawn_db_worker(&glue).expect("spawn worker one");
    await_db_worker_ready().await;
    stage("worker one ready");

    // The tab client reconnects through the factory: fresh wire channel per
    // attempt, dead-worker detection through the alive lock.
    let client_id = format!("failover-tab-{base}");
    let tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let wire = format!("connetto-wire-{client_id}-boot");
    announce_tab(&wire).await;
    let transport =
        BroadcastTransport::with_peer_liveness(&wire, DB_ALIVE_LOCK).expect("boot wire");
    let config = ClientConfig {
        client_id: client_id.clone(),
        auth_token: "token".to_owned(),
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
        sql_functions: connetto_wasm_smoke::uuidv7_functions(),
    };
    let conn = ConnettoConnection::connect(
        transport,
        &Replica::Ephemeral,
        DEMO_SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("tab connect");
    let policy = ReconnectPolicy {
        initial_backoff: Duration::from_millis(50),
        max_backoff: Duration::from_millis(500),
        max_attempts: None,
    };
    let (tab, pump) =
        ConnettoClient::with_reconnect(conn, tab_wire_factory(client_id.clone()), sleep, policy);
    wasm_bindgen_futures::spawn_local(pump);
    let mut events = tab.events();
    let mut live: LiveQuery<Order> = orders::table
        .order(orders::id)
        .live(&tab)
        .await
        .expect("tab live query");
    while !live.rows().iter().any(|row| row.id == before_id) {
        live.changed().await.expect("tab snapshot refresh");
    }
    stage("tab synced through worker one");

    // Kill the worker mid-session. Termination releases its alive lock, so
    // the tab's transport reports a clean close and the reconnect driver
    // starts hunting for a replacement.
    worker_one.terminate();
    stage("worker one terminated");

    // Written while NO worker exists: only the replacement's cursor resume
    // and oplog catchup can ever deliver this row.
    let missed_id = write_row(&mut writer, 2).await;
    writer.close().await.expect("close writer");
    stage("missed row written");

    // The replacement generation: same replica file in OPFS, resumed from
    // the persisted cursor, then served to the reconnecting tab.
    let worker_two = spawn_db_worker(&glue).expect("spawn worker two");
    stage("worker two spawned");

    // The tab converges on the missed row with no local interaction: alive
    // lock close, reconnect, fresh snapshot from the resumed replica.
    while !live.rows().iter().any(|row| row.id == missed_id) {
        live.changed().await.expect("tab failover refresh");
    }
    assert!(
        live.rows().iter().any(|row| row.id == before_id),
        "pre-failover rows survive the worker swap"
    );
    stage("tab converged through worker two");

    // The reconnect vocabulary was observable: attempts, then one resume.
    let mut reconnecting = 0;
    let mut reconnected = 0;
    while let Ok(event) = events.try_recv() {
        match event {
            ClientEvent::Reconnecting { .. } => reconnecting += 1,
            ClientEvent::Reconnected => reconnected += 1,
            _ => {}
        }
    }
    assert!(reconnecting >= 1, "at least one announced attempt");
    assert_eq!(reconnected, 1, "exactly one successful resume");

    drop(worker_two);
    tab_lock.release();
    leader_lock.release();
}
