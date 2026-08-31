//! A truncated table has to leave the replica empty, and the client's own
//! unacknowledged writes have to survive the clear that empties it (R48).
//!
//! Both halves need a sibling subscription to mean anything. The resync clear
//! spares whatever another live subscription still claims, so with one
//! subscription it degenerates to `DELETE FROM orders` and any reason passes.
//! Two subscriptions whose filters overlap are the case that separates them: a
//! row satisfying both is spared on both passes and survives for ever over a
//! table that is empty upstream, unless the reason says the table was emptied.
//!
//! A deterministic fake server hand-feeds the frame sequence, so the client
//! contract is pinned with no Postgres, no oplog and no retention window.

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Grant, Replica};
use connetto_core::Cursor;
use connetto_core::messages::{
    BulkMessage, ControlMessage, FullResyncReason, FullResyncRequired, HandshakeAck, SnapshotBegin,
    SnapshotEnd, SnapshotPatch, SubscriptionPriority,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{LoopbackTransport, loopback};
use diesel::prelude::*;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

const SQLITE_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, quantity INTEGER);";
/// Two filters over one table that overlap: a row at quantity 5 satisfies both.
const QUERY_LOW: &str = "SELECT * FROM orders WHERE quantity > 0";
const QUERY_HIGH: &str = "SELECT * FROM orders WHERE quantity < 100";
const SUB_LOW: &str = "orders-low";
const SUB_HIGH: &str = "orders-high";

diesel::table! {
    /// Orders table, primary key id.
    orders (id) {
        /// Order identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Number of items in the order.
        quantity -> diesel::sql_types::BigInt,
    }
}

/// One snapshot's rows as the compressed patchset a `SnapshotPatch` carries.
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
    let bytes = patchset.build();
    zstd::encode_all(bytes.as_slice(), 3).expect("compress snapshot")
}

/// Send one begin, patch, end triple for `sub_id`.
async fn send_snapshot(
    server: &mut LoopbackTransport,
    sub_id: &str,
    rows: &[(i64, i64)],
    cursor: u8,
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
            cursor: Cursor::new(vec![0, 0, 0, 0, 0, 0, 0, cursor]),
        }))
        .await
        .expect("end");
}

/// Seed two overlapping subscriptions with the same rows, then replace both for
/// `reason`, each replacement carrying nothing because the table is empty.
fn server_replacing_both(reason: FullResyncReason) -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await
        else {
            return;
        };
        server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "truncate".to_owned(),
                session_token: "truncate".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                resume_token: "truncate".to_owned(),
                schema_version: None,
                initial_credits: 64,
                last_applied_seq: None,
            }))
            .await
            .expect("ack");
        let mut subscribed = 0;
        while subscribed < 2 {
            match server.recv().await {
                Ok(Some(IncomingFrame::Control(ControlMessage::Subscribe(_)))) => subscribed += 1,
                Ok(Some(_)) => {}
                _ => return,
            }
        }
        send_snapshot(&mut server, SUB_LOW, &[(1, 5), (2, 50)], 1).await;
        send_snapshot(&mut server, SUB_HIGH, &[(1, 5), (2, 50)], 2).await;
        for (sub, cursor) in [(SUB_LOW, 3), (SUB_HIGH, 4)] {
            server
                .send_control(ControlMessage::FullResyncRequired(FullResyncRequired {
                    sub_id: sub.to_owned(),
                    reason: reason.clone(),
                }))
                .await
                .expect("resync");
            send_snapshot(&mut server, sub, &[], cursor).await;
        }
        while let Ok(Some(_)) = server.recv().await {}
    });
    client_end
}

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

/// Connect, declare both overlapping subscriptions, and drain both snapshots.
async fn seeded(reason: FullResyncReason) -> ConnettoConnection<LoopbackTransport> {
    let config = ClientConfig::new("truncate").with_login(Some(Grant::new("user:token")));
    let mut conn = ConnettoConnection::connect(
        server_replacing_both(reason),
        &Replica::in_memory(),
        SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("connect");
    conn.subscribe(SUB_LOW, QUERY_LOW).await.expect("subscribe");
    conn.subscribe(SUB_HIGH, QUERY_HIGH)
        .await
        .expect("subscribe");
    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        replica_ids(&mut conn),
        vec![1, 2],
        "both subscriptions seed the same rows, which is what makes them overlap",
    );
    conn
}

/// **The phase's first proof obligation, read off the replica rather than off a
/// frame.**
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_truncate_empties_the_replica_even_under_an_overlapping_subscription() {
    let mut conn = seeded(FullResyncReason::TableTruncated {
        table: "orders".to_owned(),
    })
    .await;

    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        replica_ids(&mut conn),
        Vec::<i64>::new(),
        "the table is empty upstream, so no filter entitles a row to stay",
    );
}

/// The same sequence under the reason that has to keep sparing siblings, which
/// is what says the emptying above comes from the truncate and not from the
/// resync itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ordinary_resync_still_spares_what_a_sibling_claims() {
    let mut conn = seeded(FullResyncReason::CursorOutsideRetention).await;

    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        replica_ids(&mut conn),
        vec![1, 2],
        "each subscription's clear spares what the other still claims, which is \
         the rule a truncate is the one thing entitled to ignore",
    );
}

/// **The phase's third proof obligation.** The clear deletes rows the server has
/// never seen, and the replacement snapshot cannot carry them back, so without
/// the re-apply the caller's own unsent insert is destroyed by a resync.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unacknowledged_local_write_survives_the_clear() {
    let mut conn = seeded(FullResyncReason::TableTruncated {
        table: "orders".to_owned(),
    })
    .await;

    diesel::insert_into(orders::table)
        .values((orders::id.eq(99), orders::quantity.eq(7)))
        .execute(conn.conn())
        .expect("local insert");
    let seq = conn.push().await.expect("push").expect("a queued mutation");
    assert_eq!(seq, 0, "the first push takes sequence zero");

    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        replica_ids(&mut conn),
        vec![99],
        "the truncate takes the server's rows and leaves the caller's own \
         unacknowledged insert, which nothing else would put back",
    );
}
