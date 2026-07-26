//! Phase 3 relay parity: mutation conflict distinction through the hub.
//!
//! The server distinguishes a rejected mutation (`MutationReject`) from a
//! conflicted one (`MutationConflict`, collided with a newer server row). Both
//! roll back locally, but a direct client surfaces them as distinct events. A
//! relay tab must observe the same distinction: an upstream conflict has to
//! reach the tab as `ClientEvent::MutationConflict`, not as a plain rejection.
//!
//! Forcing a real optimistic-write conflict against Postgres is not
//! deterministic from a browser, so the worker's upstream is a fake server over
//! a loopback: it accepts the tab write the worker forwards and answers with a
//! `MutationConflict` frame, the same approach the resync test uses. The tab
//! stays attached to the hub throughout, exercising the hub's conflict path.
//!
//! Run with the demo stack up (this test needs neither the server nor Postgres):
//! `wasm-pack test --headless --chrome examples/wasm-smoke`

#![cfg(target_arch = "wasm32")]

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection};
use connetto_core::messages::{
    BulkMessage, ControlMessage, HandshakeAck, MutationConflict, SnapshotBegin, SnapshotEnd,
    SnapshotPatch, SubscriptionPriority,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackTransport, loopback};
use connetto_wasm_smoke::RelayHub;
use diesel::prelude::*;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY NOT NULL, quantity INTEGER) STRICT;";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
/// The worker's upstream subscription id.
const UPSTREAM_SUB: &str = "db-upstream";

diesel::table! {
    orders (id) {
        id -> diesel::sql_types::BigInt,
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Eq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    quantity: i64,
}

/// Ids unique across smoke runs, in this test's own band. The test never
/// touches the server, but it shares the wasm binary's id conventions.
fn unique_base() -> i64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let millis = js_sys::Date::now() as i64;
    91_000_000_000 + millis
}

/// Build the compressed insert-patchset the wire carries for one snapshot.
fn snapshot_payload(rows: &[(i64, i64)]) -> Vec<u8> {
    let mut patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new();
    for &(id, quantity) in rows {
        let table = SimpleTable::new("orders", &["id", "quantity"], &[0]);
        let insert = Insert::<_, String, Vec<u8>>::from(table)
            .set(0, Value::Integer(id))
            .expect("set id")
            .set(1, Value::Integer(quantity))
            .expect("set quantity");
        patchset = patchset.insert(insert);
    }
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress snapshot")
}

/// Send one begin, patch, end triple for `UPSTREAM_SUB`.
async fn send_snapshot(server: &mut LoopbackTransport, rows: &[(i64, i64)]) {
    server
        .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
            sub_id: UPSTREAM_SUB.to_owned(),
            priority: SubscriptionPriority::default(),
        }))
        .await
        .expect("snapshot begin");
    server
        .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch::new(
            UPSTREAM_SUB.to_owned(),
            snapshot_payload(rows),
        )))
        .await
        .expect("snapshot patch");
    server
        .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
            sub_id: UPSTREAM_SUB.to_owned(),
            cursor: Cursor::new(vec![0, 0, 0, 0, 0, 0, 0, 1]),
        }))
        .await
        .expect("snapshot end");
}

/// The fake upstream: snapshot one row, then conflict the first mutation the
/// worker forwards, echoing its sequence number so the worker can roll back.
async fn fake_upstream(mut server: LoopbackTransport, base: i64) {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        return;
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            session_id: "conflict-upstream".to_owned(),
            session_token: "conflict".to_owned(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: None,
            initial_credits: 64,
            last_applied_seq: None,
        }))
        .await
        .expect("handshake ack");
    loop {
        match server.recv().await {
            Ok(Some(IncomingFrame::Control(ControlMessage::Subscribe(_)))) => break,
            Ok(Some(_)) => {}
            _ => return,
        }
    }
    send_snapshot(&mut server, &[(base, 5)]).await;
    // Conflict the first forwarded mutation, then drain the rest so the
    // loopback never backs up.
    loop {
        match server.recv().await {
            Ok(Some(IncomingFrame::Control(ControlMessage::MutationHeader(header)))) => {
                server
                    .send_control(ControlMessage::MutationConflict(MutationConflict {
                        client_seq: header.client_seq,
                        table: "orders".to_owned(),
                        server_updated_at: String::new(),
                        server_row_json: "{}".to_owned(),
                    }))
                    .await
                    .expect("conflict reply");
            }
            Ok(Some(_)) => {}
            _ => return,
        }
    }
}

/// Pump `conn` until an event matches `pred`, applying every frame between.
async fn pump_until<T>(conn: &mut ConnettoConnection<T>, pred: impl Fn(&ClientEvent) -> bool)
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        let event = conn.pump_one().await.expect("pump");
        if matches!(event, ClientEvent::Closed) {
            panic!("connection closed before the expected event");
        }
        if pred(&event) {
            return;
        }
    }
}

/// The full `orders` mirror of `conn`, sorted by id.
fn load_orders<T>(conn: &mut ConnettoConnection<T>) -> Vec<Order>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    orders::table
        .order(orders::id.asc())
        .load(conn.conn())
        .expect("read replica")
}

#[wasm_bindgen_test]
async fn upstream_conflict_reaches_the_tab_as_a_conflict() {
    let base = unique_base();
    let seeded = base;
    let written = base + 1;

    // The worker's upstream is a fake server driven frame by frame.
    let (worker_up, fake_up) = loopback();
    spawn_local(fake_upstream(fake_up, base));

    let worker_config = ClientConfig {
        client_id: format!("conflict-worker-{base}"),
        auth_token: "token".to_owned(),
        schema_version: None,
    };
    let mut worker = ConnettoConnection::connect(worker_up, ":memory:", DDL, &worker_config, None)
        .await
        .expect("worker connect");
    worker
        .subscribe(UPSTREAM_SUB, QUERY)
        .await
        .expect("worker subscribe");
    pump_until(&mut worker, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;

    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:", None).expect("relay hub");
    spawn_local(async move {
        let _ = pump.await;
    });

    // The tab attaches and converges on the seeded row.
    let (tab_end, relay_end) = loopback();
    hub.attach(relay_end);
    let tab_config = ClientConfig {
        client_id: format!("conflict-tab-{base}"),
        auth_token: "token".to_owned(),
        schema_version: None,
    };
    let mut tab = ConnettoConnection::connect(tab_end, ":memory:", DDL, &tab_config, None)
        .await
        .expect("tab connect");
    tab.subscribe("tab-orders", QUERY)
        .await
        .expect("tab subscribe");
    pump_until(&mut tab, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    assert_eq!(
        load_orders(&mut tab)
            .iter()
            .map(|order| order.id)
            .collect::<Vec<_>>(),
        vec![seeded],
        "the tab mirror seeds the upstream row",
    );

    // The tab writes optimistically and pushes: the hub applies it to the
    // worker replica, the worker re-uploads it, and the fake upstream conflicts
    // it back.
    diesel::insert_into(orders::table)
        .values((orders::id.eq(written), orders::quantity.eq(7_i64)))
        .execute(tab.conn())
        .expect("tab insert");
    tab.push().await.expect("tab push").expect("mutation sent");

    // The tab must observe MutationConflict, never a plain rejection, and roll
    // the optimistic row back exactly as a direct client would.
    let rows = loop {
        match tab.pump_one().await.expect("tab pump") {
            ClientEvent::MutationConflict { rows, .. } => break rows,
            ClientEvent::MutationRejected { .. } => {
                panic!("the relay collapsed an upstream conflict into a rejection")
            }
            ClientEvent::Closed => panic!("tab closed before the conflict arrived"),
            _ => {}
        }
    };
    assert!(
        rows.iter().any(|row| row.table == "orders"),
        "the conflict names the rolled-back orders row",
    );
    assert_eq!(
        load_orders(&mut tab)
            .iter()
            .map(|order| order.id)
            .collect::<Vec<_>>(),
        vec![seeded],
        "the tab rolled the conflicted optimistic write back off its mirror",
    );
}
