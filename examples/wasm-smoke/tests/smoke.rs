//! The browser smoke: the full connetto sync loop on wasm32 inside a
//! dedicated worker, against a real `connetto-server` at `DEMO_WS_URL`
//! backed by real Postgres logical replication.
//!
//! Covers, in one test: the browser WebSocket transport, the client core
//! cross-compiled to wasm (SQLite with the session extension, capture
//! suspension, zstd, MessagePack), subscribe with a server-translated query,
//! snapshot apply, a local diesel write captured and pushed, and the
//! replication echo arriving back. This is also the full cdylib link proof
//! for the dependency stack.
//!

#![cfg(target_arch = "wasm32")]

mod common;

use connetto_client::{ClientBuilder, ClientEvent, ConnettoConnection};
use connetto_wasm_smoke::BrowserSocket;
use connetto_wasm_smoke::build;
use connetto_wasm_smoke::workers::demo_schema;
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: rosetta_uuid::Uuid,
    owner_id: String,
    quantity: i64,
}

fn local_orders(conn: &mut ConnettoConnection<BrowserSocket>) -> Vec<Order> {
    orders::table
        .order(orders::id)
        .select(Order::as_select())
        .load(conn.conn())
        .expect("read local replica")
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
    let (token, identity) = common::mint_session().await;
    let mut conn = ClientBuilder::new(demo_schema(), build::server())
        .signed_in(build::held(token, &identity))
        .connect_driven()
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
        .values((
            orders::owner_id.eq(identity.as_str()),
            orders::quantity.eq(7_i64),
        ))
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
