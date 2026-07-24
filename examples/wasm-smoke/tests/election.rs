//! Multi-page leader election: two candidate pages race for one leader lock,
//! the winner owns the dedicated DB worker, and dropping the leader promotes
//! the survivor, which spawns a replacement worker and serves the tab a row
//! written while the topology had no worker at all.
//!
//! This is the election leg on top of the failover machinery: `failover.rs`
//! proves that a freshly spawned replacement worker resumes the OPFS replica
//! and the tab reconnects, and this test proves the election picks which
//! surviving page spawns that replacement. Two candidates in one page model
//! the multi-page race faithfully, since Web Locks serializes lock requests
//! across every same-origin context, and dropping a leader's `Membership`
//! does what the browser does on context death: terminate the child worker
//! and release the leader lock.
//!
//! Run with the demo stack up:
//! `wasm-pack test --headless --chrome examples/wasm-smoke`

#![cfg(target_arch = "wasm32")]

use core::time::Duration;

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, LiveQuery, dsl::Watchable,
};
use connetto_core::Transport;
use connetto_wasm_smoke::workers::{
    DB_ALIVE_LOCK, DEMO_SQLITE_DDL, DEMO_WS_URL, announce_tab, await_db_worker_ready, sleep,
    tab_wire_factory,
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

/// Base for row ids unique across smoke runs, in the election test's band.
fn unique_base() -> i64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Date::now in milliseconds fits i64 until the year 285428751"
    )]
    let millis = js_sys::Date::now() as i64;
    70_000_000_000 + millis
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
    };
    ConnettoConnection::connect(transport, ":memory:", DEMO_SQLITE_DDL, &config, None)
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

/// Insert one row through `writer` and fence on a pong.
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

/// Poll `pred` on the executor until it holds, sleeping between checks. The
/// election flips leadership asynchronously, so tests observe it by polling.
async fn poll_until(mut pred: impl FnMut() -> bool) {
    while !pred() {
        sleep(Duration::from_millis(25)).await;
    }
}

#[wasm_bindgen_test]
async fn election_promotes_a_survivor_and_serves_the_tab() {
    let base = unique_base();
    relay_worker_breadcrumbs();
    let before_id = base;
    let missed_id = base + 1;

    // A row that exists before anything boots.
    let mut writer = connect_server("election-writer", base).await;
    write_row(&mut writer, before_id, 1).await;
    stage("writer seeded the first row");

    let glue = glue_url();
    let leader_lock = format!("connetto-leader-{base}");

    // Candidate A joins first: the lock is free, so it wins and spawns the
    // first DB worker.
    let membership_a = leader::join(&leader_lock, &glue);
    await_db_worker_ready().await;
    poll_until(|| membership_a.is_leader()).await;
    stage("candidate a leads, worker one ready");

    // Candidate B joins second and queues behind A: it must not lead while
    // A holds the lock.
    let membership_b = leader::join(&leader_lock, &glue);
    assert!(
        !membership_b.is_leader(),
        "the second candidate cannot lead while the first holds the lock"
    );
    stage("candidate b follows");

    // The tab reconnects through the factory: fresh wire channel per attempt,
    // dead-worker detection through the alive lock.
    let client_id = format!("election-tab-{base}");
    let tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let wire = format!("connetto-wire-{client_id}-boot");
    announce_tab(&wire).await;
    let transport =
        BroadcastTransport::with_peer_liveness(&wire, DB_ALIVE_LOCK).expect("boot wire");
    let config = ClientConfig {
        client_id: client_id.clone(),
        auth_token: "token".to_owned(),
    };
    let conn = ConnettoConnection::connect(transport, ":memory:", DEMO_SQLITE_DDL, &config, None)
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

    // The leader dies: dropping A terminates worker one and releases the
    // leader lock, exactly what the browser does when a leader page's context
    // dies.
    drop(membership_a);
    stage("candidate a resigned");

    // Written while the topology has no worker: only the replacement's cursor
    // resume and oplog catchup can ever deliver this row.
    write_row(&mut writer, missed_id, 2).await;
    writer.close().await.expect("close writer");
    stage("missed row written");

    // B is promoted with no external intervention and spawns worker two.
    poll_until(|| membership_b.is_leader()).await;
    stage("candidate b promoted, worker two spawned");

    // The tab converges on the missed row: the alive lock freed on A's death,
    // the tab reconnected, and worker two served it from the resumed replica.
    while !live.rows().iter().any(|row| row.id == missed_id) {
        live.changed().await.expect("tab failover refresh");
    }
    assert!(
        live.rows().iter().any(|row| row.id == before_id),
        "pre-handover rows survive the leadership swap"
    );
    stage("tab converged through worker two");

    // The handover was observable as a real reconnect.
    let mut reconnected = 0;
    while let Ok(event) = events.try_recv() {
        if matches!(event, ClientEvent::Reconnected) {
            reconnected += 1;
        }
    }
    assert!(
        reconnected >= 1,
        "the tab resumed at least once across the handover"
    );

    drop(membership_b);
    tab_lock.release();
}
