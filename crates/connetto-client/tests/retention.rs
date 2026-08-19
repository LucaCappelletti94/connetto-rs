//! R15: local eviction, physical trimming, and their guards.
//!
//! Eviction is triggered here through the public `tidy` pass, which shares the
//! complement-of-union delete and the trimming pass with the automatic
//! subscription-end pass, so these prove the eviction and trimming logic
//! deterministically without driving the background pump.

use std::collections::HashMap;

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Grant, Replica};
use connetto_core::Cursor;
use connetto_core::messages::{
    BulkMessage, ControlMessage, HandshakeAck, MutationApplied, SnapshotBegin, SnapshotEnd,
    SnapshotPatch, SubscriptionPriority, SubscriptionSpec,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{LoopbackTransport, loopback};
use diesel::prelude::*;
use diesel::sqlite::AutoVacuumMode;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

const DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";

diesel::table! {
    /// The one synced table these tests subscribe, evict, and trim.
    orders (id) {
        /// Primary key.
        id -> BigInt,
        /// Unit price.
        price -> Double,
        /// How many units.
        quantity -> BigInt,
        /// Free-text payload, widened in the trimming test so eviction frees
        /// real pages.
        status -> Text,
    }
}

const LOCAL_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT);";

diesel::table! {
    /// A device-private table in the local tier, out of every subscription's
    /// reach and so out of the eviction scan.
    drafts (id) {
        /// Primary key.
        id -> BigInt,
        /// Free-text body.
        body -> Text,
    }
}

fn orders_table() -> SimpleTable {
    SimpleTable::new("orders", &["id", "price", "quantity", "status"], &[0])
}

/// Compressed insert-patchset bytes for one snapshot's rows.
fn snapshot_payload(rows: &[(i64, &str)]) -> Vec<u8> {
    let mut patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new();
    for &(id, status) in rows {
        let insert = Insert::<_, String, Vec<u8>>::from(orders_table())
            .set(0, Value::Integer(id))
            .expect("set id")
            .set(1, Value::Real(1.0))
            .expect("set price")
            .set(2, Value::Integer(id))
            .expect("set quantity")
            .set(3, Value::Text(status.to_owned()))
            .expect("set status");
        patchset = patchset.insert(insert);
    }
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress snapshot")
}

async fn ack_handshake(server: &mut LoopbackTransport) {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        return;
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: "r15".to_owned(),
            session_token: "r15".to_owned(),
            resume_token: "r15".to_owned(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: None,
            initial_credits: 256,
            last_applied_seq: None,
        }))
        .await
        .expect("ack");
}

async fn send_snapshot(
    server: &mut LoopbackTransport,
    sub_id: &str,
    rows: &[(i64, &str)],
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

/// The snapshots a [`snapshot_server`] answers, one entry per subscription id:
/// its rows and the resume cursor byte its `SnapshotEnd` carries.
type Snapshots = Vec<(&'static str, Vec<(i64, String)>, u8)>;

/// A server that acks the handshake, then answers each `Subscribe` with the
/// snapshot recorded for its id and drains everything else.
fn snapshot_server(snaps: Snapshots) -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    let map: HashMap<String, (Vec<(i64, String)>, u8)> = snaps
        .into_iter()
        .map(|(id, rows, cursor)| (id.to_owned(), (rows, cursor)))
        .collect();
    tokio::spawn(async move {
        ack_handshake(&mut server).await;
        while let Ok(Some(frame)) = server.recv().await {
            if let IncomingFrame::Control(ControlMessage::Subscribe(sub)) = frame
                && let Some((rows, cursor)) = map.get(&sub.sub_id)
            {
                let rows: Vec<(i64, &str)> = rows.iter().map(|(id, s)| (*id, s.as_str())).collect();
                send_snapshot(&mut server, &sub.sub_id, &rows, *cursor).await;
            }
        }
    });
    client_end
}

fn config() -> ClientConfig {
    ClientConfig::new("r15").with_login(Some(Grant::new("user:r15")))
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

/// Step 2: a replica created through the ordered pragma sequence carries the
/// shrink-capable auto-vacuum mode, so the trimming pass can reclaim pages.
#[tokio::test]
async fn auto_vacuum_is_incremental_on_a_created_replica() {
    let mut conn =
        ConnettoConnection::<LoopbackTransport>::open(&Replica::in_memory(), DDL, &config(), None)
            .expect("open a fresh replica");
    assert_eq!(
        conn.conn().auto_vacuum(None).expect("read auto_vacuum"),
        AutoVacuumMode::Incremental,
    );
}

/// Steps 3 and 4: a rotated subscription drops the rows outside its new bound
/// and keeps everything the new bound still covers, read off the replica.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_drops_rows_outside_the_new_bound() {
    let server = snapshot_server(vec![
        (
            "a",
            vec![(1, "x".into()), (2, "x".into()), (3, "x".into())],
            1,
        ),
        ("a2", vec![(1, "x".into()), (2, "x".into())], 2),
    ]);
    let mut conn = ConnettoConnection::connect(server, &Replica::in_memory(), DDL, &config(), None)
        .await
        .expect("connect");

    conn.subscribe("a", "SELECT * FROM orders WHERE id <= 3")
        .await
        .expect("subscribe a");
    pump_to_snapshot_end(&mut conn).await;
    assert_eq!(replica_ids(&mut conn), vec![1, 2, 3]);

    // Rotation is tearing the old bound down and taking a fresh one.
    conn.unsubscribe("a").await.expect("unsubscribe a");
    conn.subscribe("a2", "SELECT * FROM orders WHERE id <= 2")
        .await
        .expect("subscribe a2");
    pump_to_snapshot_end(&mut conn).await;

    conn.tidy().expect("tidy");
    assert_eq!(
        replica_ids(&mut conn),
        vec![1, 2],
        "row 3 is outside the new bound and no live subscription covers it",
    );
}

/// Step 4: a pinned query's rows survive an eviction pass that removes every
/// other row, and go on the first pass after the pin ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pin_keeps_its_rows_until_unpin() {
    let server = snapshot_server(vec![
        (
            "a",
            vec![(1, "x".into()), (2, "x".into()), (3, "x".into())],
            1,
        ),
        ("k", vec![(3, "x".into())], 2),
    ]);
    let mut conn = ConnettoConnection::connect(server, &Replica::in_memory(), DDL, &config(), None)
        .await
        .expect("connect");

    conn.subscribe("a", "SELECT * FROM orders WHERE id <= 3")
        .await
        .expect("subscribe a");
    pump_to_snapshot_end(&mut conn).await;
    let keep = SubscriptionSpec::new("SELECT * FROM orders WHERE id = 3");
    conn.subscribe_spec("k", keep.clone())
        .await
        .expect("subscribe k");
    pump_to_snapshot_end(&mut conn).await;
    conn.pin_subscription("keep", "k", &keep).expect("pin");

    conn.unsubscribe("a").await.expect("unsubscribe a");
    conn.tidy().expect("tidy while pinned");
    assert_eq!(
        replica_ids(&mut conn),
        vec![3],
        "the pin keeps its row while the rest are evicted",
    );

    conn.unpin_subscription("keep").expect("unpin");
    conn.tidy().expect("tidy after unpin");
    assert!(
        replica_ids(&mut conn).is_empty(),
        "the pinned row is evictable once the pin ends",
    );
}

/// Step 4 guard: a row an un-acknowledged local write touches survives a pass
/// that would otherwise evict it, and becomes evictable once the server
/// acknowledges the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_write_survives_until_it_is_acknowledged() {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        ack_handshake(&mut server).await;
        loop {
            match server.recv().await {
                Ok(Some(IncomingFrame::Control(ControlMessage::Subscribe(_)))) => break,
                Ok(Some(_)) => {}
                _ => return,
            }
        }
        send_snapshot(&mut server, "a", &[], 1).await;
        // Acknowledge the first mutation the client uploads.
        while let Ok(Some(frame)) = server.recv().await {
            if let IncomingFrame::Control(ControlMessage::MutationHeader(header)) = frame {
                server
                    .send_control(ControlMessage::MutationApplied(MutationApplied {
                        client_seq: header.client_seq,
                    }))
                    .await
                    .ok();
            }
        }
    });

    let mut conn =
        ConnettoConnection::connect(client_end, &Replica::in_memory(), DDL, &config(), None)
            .await
            .expect("connect");
    // A subscription that keeps `orders` in scope but covers none of its rows.
    conn.subscribe("a", "SELECT * FROM orders WHERE id = 999")
        .await
        .expect("subscribe");
    pump_to_snapshot_end(&mut conn).await;

    diesel::insert_into(orders::table)
        .values((
            orders::id.eq(1_i64),
            orders::price.eq(1.0),
            orders::quantity.eq(1_i64),
            orders::status.eq("x"),
        ))
        .execute(conn.conn())
        .expect("local insert");
    conn.push().await.expect("push").expect("a sequence");

    conn.tidy().expect("tidy while the write is un-acked");
    assert_eq!(
        replica_ids(&mut conn),
        vec![1],
        "the un-acked write is spared by the pending guard",
    );

    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::MutationApplied { .. } => break,
            ClientEvent::Closed => panic!("closed before the ack"),
            _ => {}
        }
    }
    conn.tidy().expect("tidy after the ack");
    assert!(
        replica_ids(&mut conn).is_empty(),
        "the first pass after the ack evicts the now-uncovered row",
    );
}

/// Step 5: after a bulk eviction the trimming pass returns pages to the
/// filesystem, which is the only observable that tells trimming from deletion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trimming_returns_pages_after_a_bulk_eviction() {
    let big = "x".repeat(400);
    let seed: Vec<(i64, String)> = (1..=800).map(|id| (id, big.clone())).collect();
    let server = snapshot_server(vec![("seed", seed, 1), ("keep", Vec::new(), 2)]);
    let mut conn = ConnettoConnection::connect(
        server,
        &Replica::in_memory(),
        DDL,
        &config().with_trim_threshold(0),
        None,
    )
    .await
    .expect("connect");

    conn.subscribe("seed", "SELECT * FROM orders")
        .await
        .expect("subscribe seed");
    pump_to_snapshot_end(&mut conn).await;
    conn.subscribe("keep", "SELECT * FROM orders WHERE id = 999999")
        .await
        .expect("subscribe keep");
    pump_to_snapshot_end(&mut conn).await;

    let before = conn.conn().page_count(None).expect("page_count before");
    conn.unsubscribe("seed").await.expect("unsubscribe seed");
    conn.tidy().expect("tidy");
    assert!(
        replica_ids(&mut conn).is_empty(),
        "every seeded row is uncovered and evicted",
    );
    let after = conn.conn().page_count(None).expect("page_count after");
    assert!(
        after < before,
        "the trimming pass reclaimed pages ({before} -> {after})",
    );
}

/// D4: the callable tidy pass reclaims the freelist an application delete left
/// behind even when it evicts nothing, so a free-up-space control shrinks the
/// file after the user deletes rows a live subscription still covers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tidy_trims_the_freelist_without_an_eviction() {
    let big = "x".repeat(400);
    let seed: Vec<(i64, String)> = (1..=800).map(|id| (id, big.clone())).collect();
    let server = snapshot_server(vec![("all", seed, 1)]);
    let mut conn = ConnettoConnection::connect(
        server,
        &Replica::in_memory(),
        DDL,
        &config().with_trim_threshold(0),
        None,
    )
    .await
    .expect("connect");

    // A whole-table watch covers every order, so no row is ever uncovered and
    // the reclaim below can only come from the delete, not from eviction.
    conn.subscribe("all", "SELECT * FROM orders")
        .await
        .expect("subscribe all");
    pump_to_snapshot_end(&mut conn).await;

    let before = conn.conn().page_count(None).expect("page_count before");
    diesel::delete(orders::table.filter(orders::id.le(700)))
        .execute(conn.conn())
        .expect("delete most orders");

    conn.tidy().expect("tidy");

    assert_eq!(
        replica_ids(&mut conn),
        (701..=800).collect::<Vec<_>>(),
        "tidy evicted nothing: every surviving row is still covered",
    );
    let after = conn.conn().page_count(None).expect("page_count after");
    assert!(
        after < before,
        "tidy reclaimed the delete's freelist with no eviction ({before} -> {after})",
    );
}

/// Step 4 guard: no eviction pass runs while the transport is down, so a row a
/// connected pass would remove is left in place until connectivity returns.
#[tokio::test]
async fn no_eviction_runs_while_the_transport_is_down() {
    let mut conn =
        ConnettoConnection::<LoopbackTransport>::open(&Replica::in_memory(), DDL, &config(), None)
            .expect("open offline");
    assert!(!conn.is_connected(), "opened with no transport");

    // Recorded offline: it keeps `orders` in scope but covers none of the rows.
    conn.subscribe_spec(
        "a",
        SubscriptionSpec::new("SELECT * FROM orders WHERE id = 999"),
    )
    .await
    .expect("record subscription");
    for id in [1_i64, 2, 3] {
        diesel::insert_into(orders::table)
            .values((
                orders::id.eq(id),
                orders::price.eq(1.0),
                orders::quantity.eq(id),
                orders::status.eq("x"),
            ))
            .execute(conn.conn())
            .expect("seed row");
    }

    conn.tidy().expect("tidy offline");
    assert_eq!(
        replica_ids(&mut conn),
        vec![1, 2, 3],
        "the eviction does not run offline, so nothing is evicted",
    );
}

/// D4: the callable tidy pass trims the freelist even while the transport is
/// down, because reclaiming local pages discards nothing and needs no server.
/// Only the eviction half waits for connectivity.
#[tokio::test]
async fn tidy_trims_while_the_transport_is_down() {
    let mut conn = ConnettoConnection::<LoopbackTransport>::open(
        &Replica::in_memory(),
        DDL,
        &config().with_trim_threshold(0),
        None,
    )
    .expect("open offline");
    assert!(!conn.is_connected(), "opened with no transport");

    let big = "x".repeat(400);
    for id in 1..=200_i64 {
        diesel::insert_into(orders::table)
            .values((
                orders::id.eq(id),
                orders::price.eq(1.0),
                orders::quantity.eq(id),
                orders::status.eq(big.as_str()),
            ))
            .execute(conn.conn())
            .expect("seed row");
    }
    diesel::delete(orders::table)
        .execute(conn.conn())
        .expect("delete every order");

    let before = conn.conn().page_count(None).expect("page_count before");
    conn.tidy().expect("tidy offline");
    let after = conn.conn().page_count(None).expect("page_count after");
    assert!(
        after < before,
        "tidy trimmed the freelist while offline ({before} -> {after})",
    );
}

/// Step 4: a device-private local-tier row survives an eviction pass that
/// removes synced rows, because a `SubscriptionSpec` can never name its table
/// so the scan has no path to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_tier_row_survives_eviction_of_synced_rows() {
    let server = snapshot_server(vec![
        ("seed", vec![(1, "x".into()), (2, "x".into())], 1),
        ("keep", Vec::new(), 2),
    ]);
    let replica = Replica::in_memory().with_tier(LOCAL_DDL);
    let mut conn = ConnettoConnection::connect(server, &replica, DDL, &config(), None)
        .await
        .expect("connect");

    conn.subscribe("seed", "SELECT * FROM orders")
        .await
        .expect("subscribe seed");
    pump_to_snapshot_end(&mut conn).await;
    conn.subscribe("keep", "SELECT * FROM orders WHERE id = 999999")
        .await
        .expect("subscribe keep");
    pump_to_snapshot_end(&mut conn).await;

    diesel::insert_into(drafts::table)
        .values((drafts::id.eq(1_i64), drafts::body.eq("local")))
        .execute(conn.conn())
        .expect("local-tier write");

    conn.unsubscribe("seed").await.expect("unsubscribe seed");
    conn.tidy().expect("tidy");

    assert!(
        replica_ids(&mut conn).is_empty(),
        "the uncovered synced rows are evicted",
    );
    let drafts: Vec<i64> = drafts::table
        .select(drafts::id)
        .load(conn.conn())
        .expect("read drafts");
    assert_eq!(drafts, vec![1], "the local-tier row survives the pass");
}
