//! R29: a full resync of one subscription must not wipe a sibling's rows.
//!
//! Ported from the preserved reproduction of the two coverage-loss defects.
//! Only the resync one lives here: the second, a row leaving one
//! subscription's window, was written against a delete frame the server does
//! not actually send, and belongs to R44.
//!
//! `clear_subscription_rows` used to issue `DELETE FROM "orders"` per table
//! the resyncing subscription read, so the fresh snapshot restored only that
//! subscription's rows and a sibling's were gone for good. It now deletes the
//! complement of what the surviving subscriptions want, taken from the
//! subscription set persisted in the replica.
//!
//! Both directions are asserted in one test, because either alone passes a
//! wrong implementation: deleting nothing keeps the sibling's rows and leaves
//! stale ones behind, and deleting the whole table removes the stale ones and
//! the sibling's with them.

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Replica};
use connetto_core::Cursor;
use connetto_core::messages::{
    BulkMessage, ControlMessage, FullResyncReason, FullResyncRequired, HandshakeAck, SnapshotBegin,
    SnapshotEnd, SnapshotPatch, SubscriptionPriority,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{LoopbackTransport, loopback};
use diesel::prelude::*;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";

diesel::table! {
    /// Orders, the one synced table both subscriptions read.
    orders (id) {
        /// Order identifier, the primary key.
        id -> BigInt,
        /// Unit price.
        price -> Double,
        /// How many units.
        quantity -> BigInt,
        /// Order state.
        status -> Text,
    }
}

fn orders_table() -> SimpleTable {
    SimpleTable::new("orders", &["id", "price", "quantity", "status"], &[0])
}

/// Raw insert-patchset bytes for one snapshot's rows, compressed the way the
/// wire carries a `SnapshotPatch`.
fn snapshot_payload(rows: &[(i64, i64)]) -> Vec<u8> {
    let mut patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new();
    for &(id, quantity) in rows {
        let insert = Insert::<_, String, Vec<u8>>::from(orders_table())
            .set(0, Value::Integer(id))
            .expect("set id")
            .set(1, Value::Real(1.0))
            .expect("set price")
            .set(2, Value::Integer(quantity))
            .expect("set quantity")
            .set(3, Value::Text("row".to_owned()))
            .expect("set status");
        patchset = patchset.insert(insert);
    }
    let bytes = patchset.build();
    zstd::encode_all(bytes.as_slice(), 3).expect("compress snapshot")
}

/// Send one begin, patch, end triple carrying `rows` for `sub_id`.
async fn send_snapshot(
    server: &mut LoopbackTransport,
    sub_id: &str,
    rows: &[(i64, i64)],
    cursor: Vec<u8>,
) {
    server
        .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
            sub_id: sub_id.to_owned(),
            priority: SubscriptionPriority::default(),
        }))
        .await
        .expect("begin");
    server
        .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch::new(
            sub_id.to_owned(),
            snapshot_payload(rows),
        )))
        .await
        .expect("patch");
    server
        .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
            sub_id: sub_id.to_owned(),
            cursor: Cursor::new(cursor),
        }))
        .await
        .expect("end");
}

async fn ack_handshake(server: &mut LoopbackTransport) {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        return;
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: "coverage".to_owned(),
            session_token: "coverage".to_owned(),
            resume_token: "coverage".to_owned(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: None,
            initial_credits: 64,
            last_applied_seq: None,
        }))
        .await
        .expect("ack");
}

/// Block until the next `Subscribe` control frame, ignoring everything else.
async fn wait_subscribe(server: &mut LoopbackTransport) {
    loop {
        match server.recv().await {
            Ok(Some(IncomingFrame::Control(ControlMessage::Subscribe(_)))) => break,
            Ok(Some(_)) => {}
            _ => return,
        }
    }
}

fn client_config() -> ClientConfig {
    ClientConfig {
        client_id: "coverage".to_owned(),
        login: Some(connetto_client::Grant::new("user:coverage")),
        capabilities: Vec::new(),
        schema_version: None,
        sql_functions: connetto_client::SqlFunctions::new(),
    }
}

/// Pump until the next snapshot completes.
async fn pump_to_snapshot_end<T>(conn: &mut ConnettoConnection<T>)
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::SnapshotEnd { .. } => return,
            ClientEvent::Closed => panic!("closed before snapshot end"),
            _ => {}
        }
    }
}

/// Every replica row id, ordered.
fn replica_ids<T>(conn: &mut ConnettoConnection<T>) -> Vec<i64>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    orders::table
        .select(orders::id)
        .order(orders::id.asc())
        .load(conn.conn())
        .expect("read replica")
}

/// A fake server for the resync test: snapshots disjoint rows into two
/// subscriptions over one table, then orders a full resync of the first,
/// whose fresh snapshot carries only the first subscription's rows.
fn resync_wipe_server() -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        ack_handshake(&mut server).await;
        wait_subscribe(&mut server).await;
        send_snapshot(
            &mut server,
            "sub-a",
            &[(1, 20), (3, 30)],
            vec![0, 0, 0, 0, 0, 0, 0, 1],
        )
        .await;
        wait_subscribe(&mut server).await;
        send_snapshot(
            &mut server,
            "sub-b",
            &[(2, 5)],
            vec![0, 0, 0, 0, 0, 0, 0, 2],
        )
        .await;
        server
            .send_control(ControlMessage::FullResyncRequired(FullResyncRequired {
                sub_id: "sub-a".to_owned(),
                reason: FullResyncReason::CursorOutsideRetention,
            }))
            .await
            .expect("resync");
        send_snapshot(
            &mut server,
            "sub-a",
            &[(1, 20)],
            vec![0, 0, 0, 0, 0, 0, 0, 3],
        )
        .await;
        while let Ok(Some(_)) = server.recv().await {}
    });
    client_end
}

/// The R29 resync demonstration. Subscription B's rows must survive a full
/// resync of subscription A over the same table. Against current code they do
/// not: `clear_subscription_rows` deletes the whole table and A's fresh
/// snapshot restores only A's rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resync_of_one_subscription_keeps_the_siblings_rows() {
    let mut conn = ConnettoConnection::connect(
        resync_wipe_server(),
        &Replica::in_memory(),
        SQLITE_DDL,
        &client_config(),
        None,
    )
    .await
    .expect("connect");

    conn.subscribe("sub-a", "SELECT * FROM orders WHERE quantity > 10")
        .await
        .expect("subscribe a");
    pump_to_snapshot_end(&mut conn).await;
    conn.subscribe("sub-b", "SELECT * FROM orders WHERE quantity <= 10")
        .await
        .expect("subscribe b");
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        replica_ids(&mut conn),
        vec![1, 2, 3],
        "control: both subscriptions' rows are present before the resync",
    );

    // A's full resync: clear, then A's fresh snapshot, which no longer carries
    // row 3 because it was deleted upstream during the outage.
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        replica_ids(&mut conn),
        vec![1, 2],
        "the resync clear spares subscription B's row 2 and still removes row \
         3, which A no longer has",
    );
}
