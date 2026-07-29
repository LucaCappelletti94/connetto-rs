//! The browser smoke: the full connetto sync loop on wasm32 inside a
//! dedicated worker, against a real `connetto-server` on `127.0.0.1:7777`
//! backed by real Postgres logical replication.
//!
//! Covers, in one test: the browser WebSocket transport, the client core
//! cross-compiled to wasm (SQLite with the session extension, capture
//! suspension, zstd, MessagePack), subscribe with a server-translated query,
//! snapshot apply, a local diesel write captured and pushed, and the
//! replication echo arriving back. This is also the full cdylib link proof
//! for the dependency stack.
//!
//! Run with the demo stack up:
//! `wasm-pack test --headless --chrome examples/wasm-smoke`

#![cfg(target_arch = "wasm32")]

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Replica};
use connetto_wasm_smoke::BrowserSocket;
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const SQLITE_DDL: &str = "CREATE TABLE orders (id BLOB PRIMARY KEY DEFAULT (uuidv7()) CHECK (length(id) = 16) NOT NULL, quantity INTEGER) STRICT;";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

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

fn local_orders(conn: &mut ConnettoConnection<BrowserSocket>) -> Vec<Order> {
    orders::table
        .order(orders::id)
        .select(Order::as_select())
        .load(conn.conn())
        .expect("read local replica")
}

/// A row id unique enough across smoke runs: milliseconds since the epoch,
/// well above the desktop demo's id bands.
fn unique_id() -> i64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Date::now in milliseconds fits i64 until the year 285428751"
    )]
    let millis = js_sys::Date::now() as i64;
    10_000_000_000 + millis
}

/// Pump the client until an event matches `pred`, applying every frame in
/// between. The harness timeout bounds the wait.
async fn pump_until(
    conn: &mut ConnettoConnection<BrowserSocket>,
    pred: impl Fn(&ClientEvent) -> bool,
) -> ClientEvent {
    loop {
        let event = conn.pump_one().await.expect("client pump failed");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
        if pred(&event) {
            return event;
        }
    }
}

#[wasm_bindgen_test]
async fn full_sync_loop_in_a_dedicated_worker() {
    let transport = BrowserSocket::connect("ws://127.0.0.1:7777/")
        .await
        .expect("connect to connetto-server");
    let config = ClientConfig {
        client_id: format!("wasm-smoke-{}", unique_id()),
        auth_token: "token".to_owned(),
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
        sql_functions: connetto_wasm_smoke::uuidv7_functions(),
    };
    let mut conn =
        ConnettoConnection::connect(transport, &Replica::Ephemeral, SQLITE_DDL, &config, None)
            .await
            .expect("client connect");

    // Subscribe and take the snapshot of whatever the backend holds.
    conn.subscribe("orders", QUERY).await.expect("subscribe");
    pump_until(&mut conn, |e| matches!(e, ClientEvent::SnapshotEnd { .. })).await;
    let baseline = local_orders(&mut conn);

    // A local diesel write: captured by the session, pushed, applied to
    // Postgres, echoed back over logical replication.
    let before: std::collections::HashSet<rosetta_uuid::Uuid> = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(conn.conn())
        .expect("ids before insert")
        .into_iter()
        .collect();
    diesel::insert_into(orders::table)
        .values(orders::quantity.eq(7_i64))
        .execute(conn.conn())
        .expect("local insert");
    let id: rosetta_uuid::Uuid = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(conn.conn())
        .expect("ids after insert")
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("minted id");
    let seq = conn.push().await.expect("push").expect("mutation sent");

    // The echo arrives as a live patch and applies under capture suspension.
    pump_until(&mut conn, |e| matches!(e, ClientEvent::LivePatch { .. })).await;
    let after = local_orders(&mut conn);
    assert_eq!(
        after.len(),
        baseline.len() + 1,
        "exactly the written row arrived, no echo duplication"
    );
    assert!(
        after.iter().any(|row| row.id == id && row.quantity == 7),
        "the written row round-tripped through Postgres"
    );

    // A second push must find an empty capture session: the echo apply ran
    // with capture suspended, so nothing is waiting to re-upload.
    assert_eq!(
        conn.push().await.expect("second push"),
        None,
        "the replication echo must not be recaptured"
    );
    let _ = seq;

    conn.close().await.expect("close");
}
