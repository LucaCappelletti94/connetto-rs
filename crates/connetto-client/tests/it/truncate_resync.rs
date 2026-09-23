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
    BulkMessage, ControlMessage, FullResyncReason, FullResyncRequired, HandshakeAck,
    MembershipOpened, SnapshotBegin, SnapshotEnd, SnapshotPatch, SubscriptionPriority,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{LoopbackTransport, loopback};
use diesel::prelude::*;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

const SQLITE_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, quantity INTEGER); \
    CREATE TABLE members (id INTEGER PRIMARY KEY, quantity INTEGER);";
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

/// One snapshot's rows of `table` as the compressed patchset a `SnapshotPatch` carries.
fn snapshot_payload(table: &str, rows: &[(i64, i64)]) -> Vec<u8> {
    let mut patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new();
    for &(id, quantity) in rows {
        let table = SimpleTable::new(table, &["id", "quantity"], &[0]);
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

/// Send one begin, patch, end triple of `orders` rows for `sub_id`.
async fn send_snapshot(
    server: &mut LoopbackTransport,
    sub_id: &str,
    rows: &[(i64, i64)],
    cursor: u8,
) {
    send_snapshot_of(server, sub_id, "orders", rows, cursor).await;
}

/// Send one begin, patch, end triple of `table` rows for `sub_id`.
async fn send_snapshot_of(
    server: &mut LoopbackTransport,
    sub_id: &str,
    table: &str,
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
            snapshot_payload(table, rows),
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

/// Rows keyed by id with their quantity, per subscription, low then high.
type Rows = [&'static [(i64, i64)]; 2];

/// Seed two overlapping subscriptions with the same rows, then replace both for
/// `reason`, each replacement carrying nothing because the table is empty.
fn server_replacing_both(reason: FullResyncReason) -> LoopbackTransport {
    const SEED: &[(i64, i64)] = &[(1, 5), (2, 50)];
    server_scripted(reason, [SEED, SEED], [&[], &[]])
}

/// Seed each subscription with its `seeds`, then replace each for `reason` with its `replacements`.
fn server_scripted(reason: FullResyncReason, seeds: Rows, replacements: Rows) -> LoopbackTransport {
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
        send_snapshot(&mut server, SUB_LOW, seeds[0], 1).await;
        send_snapshot(&mut server, SUB_HIGH, seeds[1], 2).await;
        for ((sub, cursor), rows) in [(SUB_LOW, 3), (SUB_HIGH, 4)].into_iter().zip(replacements) {
            server
                .send_control(ControlMessage::FullResyncRequired(FullResyncRequired {
                    sub_id: sub.to_owned(),
                    reason: reason.clone(),
                }))
                .await
                .expect("resync");
            send_snapshot(&mut server, sub, rows, cursor).await;
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

/// Connect over `server`, declare both overlapping subscriptions, and drain both snapshots.
async fn connected(server: LoopbackTransport) -> ConnettoConnection<LoopbackTransport> {
    let config = ClientConfig::new("truncate").with_login(Some(Grant::new("user:token")));
    let mut conn =
        ConnettoConnection::connect(server, &Replica::in_memory(), SQLITE_DDL, &config, None)
            .await
            .expect("connect");
    conn.subscribe(SUB_LOW, QUERY_LOW).await.expect("subscribe");
    conn.subscribe(SUB_HIGH, QUERY_HIGH)
        .await
        .expect("subscribe");
    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;
    conn
}

/// Connect, declare both overlapping subscriptions, and drain both snapshots.
async fn seeded(reason: FullResyncReason) -> ConnettoConnection<LoopbackTransport> {
    let mut conn = connected(server_replacing_both(reason)).await;
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

/// A cursor past where its timeline ended resyncs every subscription, so each
/// clear has to take what a sibling claims too, or a row the promoted database
/// lost survives under two overlapping filters (R73).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cursor_beyond_history_takes_what_a_sibling_claims() {
    let mut conn = seeded(FullResyncReason::CursorBeyondHistory).await;

    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        replica_ids(&mut conn),
        Vec::<i64>::new(),
        "the promoted database holds none of these rows, so no filter entitles one to stay",
    );
}

/// The later notice arrives after the first subscription's replacement landed,
/// so it must spare what that fresh replacement claims while the lost row both
/// filters matched stays gone (R73).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cursor_beyond_history_keeps_what_an_earlier_replacement_delivered() {
    let mut conn = connected(server_scripted(
        FullResyncReason::CursorBeyondHistory,
        [&[(1, 5), (2, 50), (3, 500)], &[(1, 5), (2, 50)]],
        [&[(1, 5), (3, 500)], &[(1, 5)]],
    ))
    .await;
    assert_eq!(replica_ids(&mut conn), vec![1, 2, 3]);

    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        replica_ids(&mut conn),
        vec![1, 3],
        "order 3 only the low filter matches came back in its replacement, and order 2 was lost",
    );
}

/// Each connection's first notice empties the tables again, so a second
/// failover in the same process takes its own lost rows too (R73).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_connection_clears_its_own_lost_rows() {
    const SEED: &[(i64, i64)] = &[(4, 5)];
    let mut conn = seeded(FullResyncReason::CursorBeyondHistory).await;
    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;

    conn.attach(server_scripted(
        FullResyncReason::CursorBeyondHistory,
        [SEED, SEED],
        [&[], &[]],
    ))
    .await
    .expect("attach again");
    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(replica_ids(&mut conn), vec![4]);
    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        replica_ids(&mut conn),
        Vec::<i64>::new(),
        "the second promotion lost order 4, which both filters match"
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

diesel::table! {
    /// A membership table the server serves through a hidden subscription.
    members (id) {
        /// Member identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Unread here.
        quantity -> diesel::sql_types::BigInt,
    }
}

const MEMBERSHIP_SUB: &str = "connetto-membership:members";

/// A membership row the promoted database lost goes too, even when this process
/// learned of the hidden subscription only after the first notice, as a
/// restarted process does (R73).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cursor_beyond_history_clears_a_hidden_membership_table() {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await
        else {
            return;
        };
        server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "membership".to_owned(),
                session_token: "membership".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                resume_token: "membership".to_owned(),
                schema_version: None,
                initial_credits: 64,
                last_applied_seq: None,
            }))
            .await
            .expect("ack");
        while !matches!(
            server.recv().await,
            Ok(Some(IncomingFrame::Control(ControlMessage::Subscribe(_))) | None) | Err(_)
        ) {}
        send_snapshot_of(&mut server, MEMBERSHIP_SUB, "members", &[(7, 1)], 1).await;
        send_snapshot(&mut server, SUB_LOW, &[(1, 5)], 2).await;
        for (sub, table, cursor) in [(SUB_LOW, "orders", 3), (MEMBERSHIP_SUB, "members", 4)] {
            if sub == MEMBERSHIP_SUB {
                server
                    .send_control(ControlMessage::MembershipOpened(MembershipOpened {
                        sub_id: MEMBERSHIP_SUB.to_owned(),
                        member_table: "members".to_owned(),
                    }))
                    .await
                    .expect("announce");
            }
            server
                .send_control(ControlMessage::FullResyncRequired(FullResyncRequired {
                    sub_id: sub.to_owned(),
                    reason: FullResyncReason::CursorBeyondHistory,
                }))
                .await
                .expect("resync");
            send_snapshot_of(&mut server, sub, table, &[], cursor).await;
        }
        while let Ok(Some(_)) = server.recv().await {}
    });
    let config = ClientConfig::new("membership").with_login(Some(Grant::new("user:token")));
    let mut conn =
        ConnettoConnection::connect(client_end, &Replica::in_memory(), SQLITE_DDL, &config, None)
            .await
            .expect("connect");
    conn.subscribe(SUB_LOW, QUERY_LOW).await.expect("subscribe");
    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;
    let member_ids = |conn: &mut ConnettoConnection<LoopbackTransport>| -> Vec<i64> {
        members::table
            .select(members::id)
            .load(conn.conn())
            .expect("read members")
    };
    assert_eq!(member_ids(&mut conn), vec![7]);

    pump_to_snapshot_end(&mut conn).await;
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(
        member_ids(&mut conn),
        Vec::<i64>::new(),
        "the promoted database lost the membership row, and nothing declared covers its table"
    );
}
