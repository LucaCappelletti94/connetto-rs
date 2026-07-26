//! Full-resync convergence on the client: when the server cannot resume a
//! subscription incrementally it sends `FullResyncRequired` followed by a fresh
//! snapshot. The snapshot carries only the currently authorized rows, so the
//! client must drop rows that were deleted while it was away. Without a clear
//! step the insert-only snapshot apply (`server_wins` Replace) leaves stale
//! rows in the replica.
//!
//! A deterministic fake server hand-feeds the exact frame sequence a resuming
//! session receives (`FullResyncRequired` then a fresh snapshot), so the test
//! pins the client contract without an oplog or a retention window.

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection};
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
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
const SUB: &str = "orders";

diesel::table! {
    orders (id) {
        id -> diesel::sql_types::BigInt,
        price -> diesel::sql_types::Double,
        quantity -> diesel::sql_types::BigInt,
        status -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    price: f64,
    quantity: i64,
    status: String,
}

/// Build the raw insert-patchset bytes for one snapshot's rows and compress
/// them the way the wire carries a `SnapshotPatch`.
fn snapshot_payload(rows: &[(i64, i64)]) -> Vec<u8> {
    let mut patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new();
    for &(id, quantity) in rows {
        let table = SimpleTable::new("orders", &["id", "price", "quantity", "status"], &[0]);
        let insert = Insert::<_, String, Vec<u8>>::from(table)
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

/// Send one begin, patch, end triple carrying `rows`.
async fn send_snapshot(server: &mut LoopbackTransport, rows: &[(i64, i64)], cursor: Vec<u8>) {
    server
        .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
            sub_id: SUB.to_owned(),
            priority: SubscriptionPriority::default(),
        }))
        .await
        .expect("begin");
    server
        .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch::new(
            SUB.to_owned(),
            snapshot_payload(rows),
        )))
        .await
        .expect("patch");
    server
        .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
            sub_id: SUB.to_owned(),
            cursor: Cursor::new(cursor),
        }))
        .await
        .expect("end");
}

/// A fake server that snapshots two rows, then orders a full resync whose
/// fresh snapshot drops the first row.
fn resync_server() -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await
        else {
            return;
        };
        server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                session_id: "resync".to_owned(),
                session_token: "resync".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: None,
                initial_credits: 64,
                last_applied_seq: None,
            }))
            .await
            .expect("ack");
        loop {
            match server.recv().await {
                Ok(Some(IncomingFrame::Control(ControlMessage::Subscribe(_)))) => break,
                Ok(Some(_)) => {}
                _ => return,
            }
        }
        send_snapshot(&mut server, &[(1, 3), (2, 5)], vec![0, 0, 0, 0, 0, 0, 0, 1]).await;
        server
            .send_control(ControlMessage::FullResyncRequired(FullResyncRequired {
                sub_id: SUB.to_owned(),
                reason: FullResyncReason::CursorOutsideRetention,
            }))
            .await
            .expect("resync");
        send_snapshot(&mut server, &[(2, 5)], vec![0, 0, 0, 0, 0, 0, 0, 2]).await;
        while let Ok(Some(_)) = server.recv().await {}
    });
    client_end
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

/// Every replica row, ordered by id.
fn replica_orders<T>(conn: &mut ConnettoConnection<T>) -> Vec<Order>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    orders::table
        .order(orders::id.asc())
        .load(conn.conn())
        .expect("read replica")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_resync_drops_rows_deleted_during_the_outage() {
    let config = ClientConfig {
        client_id: "resync".to_owned(),
        auth_token: "token".to_owned(),
        schema_version: None,
        sql_functions: connetto_client::SqlFunctions::new(),
    };
    let mut conn =
        ConnettoConnection::connect(resync_server(), ":memory:", SQLITE_DDL, &config, None)
            .await
            .expect("connect");
    conn.subscribe(SUB, QUERY).await.expect("subscribe");

    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        replica_orders(&mut conn)
            .iter()
            .map(|order| order.id)
            .collect::<Vec<_>>(),
        vec![1, 2],
        "the initial snapshot seeds both rows",
    );

    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        replica_orders(&mut conn)
            .iter()
            .map(|order| order.id)
            .collect::<Vec<_>>(),
        vec![2],
        "the full-resync snapshot drops the row deleted during the outage",
    );
}
