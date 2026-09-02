//! R60 step 5: the residual pass, its measure, and its crossing event.
//!
//! Rows applied since the last `tidy` are counted per table by the update
//! hook while a server patch applies. When their sum crosses the configured
//! threshold, `ClientEvent::TidyDue` fires once, and under the default
//! `ResidualPass::Automatic` the connection runs the pass itself and resets
//! the measure. A supplanting application sees the same event and the pass
//! stays silent until it calls `tidy` on its own.

use connetto_client::{
    ClientConfig, ClientEvent, ConnettoConnection, Grant, Replica, ResidualPass,
};
use connetto_core::Cursor;
use connetto_core::messages::{
    BulkMessage, ControlMessage, HandshakeAck, LivePatch, SnapshotBegin, SnapshotEnd,
    SnapshotPatch, SubscriptionPriority,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{LoopbackTransport, loopback};
use diesel::prelude::*;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

const DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT);";

diesel::table! {
    /// The one synced table these tests accumulate into and evict from.
    orders (id) {
        /// Primary key.
        id -> BigInt,
        /// Free-text payload.
        status -> Text,
    }
}

fn orders_table() -> SimpleTable {
    SimpleTable::new("orders", &["id", "status"], &[0])
}

/// Compressed insert-patchset bytes for the given rows.
fn payload(rows: &[i64]) -> Vec<u8> {
    let mut patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new();
    for &id in rows {
        let insert = Insert::<_, String, Vec<u8>>::from(orders_table())
            .set(0, Value::Integer(id))
            .expect("set id")
            .set(1, Value::Text("x".to_owned()))
            .expect("set status");
        patchset = patchset.insert(insert);
    }
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress payload")
}

async fn ack_handshake(server: &mut LoopbackTransport) {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        return;
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: "r60".to_owned(),
            session_token: "r60".to_owned(),
            resume_token: "r60".to_owned(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: None,
            initial_credits: 256,
            last_applied_seq: None,
        }))
        .await
        .expect("ack");
}

/// A server that answers the one subscription with a one-row snapshot, then
/// streams `extra` single-row live patches (rows 2 onward) and stays up.
fn accumulating_server(extra: u8) -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        ack_handshake(&mut server).await;
        while let Ok(Some(frame)) = server.recv().await {
            match frame {
                IncomingFrame::Control(ControlMessage::Subscribe(sub)) => {
                    server
                        .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                            sub_id: sub.sub_id.clone(),
                            priority: SubscriptionPriority::default(),
                        }))
                        .await
                        .expect("begin");
                    server
                        .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch {
                            sub_id: sub.sub_id.clone(),
                            patchset_zstd: payload(&[1]),
                        }))
                        .await
                        .expect("snapshot");
                    server
                        .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
                            sub_id: sub.sub_id.clone(),
                            cursor: Cursor::new(vec![1]),
                        }))
                        .await
                        .expect("end");
                    for id in 0..extra {
                        server
                            .send_bulk(BulkMessage::LivePatch(LivePatch::new(
                                sub.sub_id.clone(),
                                Cursor::new(vec![0, 0, 0, 0, 0, 0, 2, id]),
                                payload(&[i64::from(id) + 2]),
                            )))
                            .await
                            .expect("live patch");
                    }
                }
                IncomingFrame::Control(ControlMessage::Ping(ping)) => {
                    server
                        .send_control(ControlMessage::Pong(connetto_core::messages::Pong {
                            nonce: ping.nonce,
                        }))
                        .await
                        .expect("pong");
                }
                _ => {}
            }
        }
    });
    client_end
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

/// Pump until the crossing event arrives, returning what it carried.
async fn pump_to_tidy_due<T>(conn: &mut ConnettoConnection<T>) -> u64
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::TidyDue { rows_applied } => return rows_applied,
            ClientEvent::Closed => panic!("closed before the crossing event"),
            _ => {}
        }
    }
}

/// The default: the counter crosses, the event fires, the pass has already
/// run and reset the measure, and the uncovered accumulation is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_automatic_pass_runs_at_the_crossing_and_resets_the_measure() {
    let config = ClientConfig::new("r60-auto")
        .with_login(Some(Grant::new("user:r60")))
        .with_residual_threshold(10);
    let server = accumulating_server(12);
    let mut conn = ConnettoConnection::connect(server, &Replica::in_memory(), DDL, &config, None)
        .await
        .expect("connect");
    // A narrow filter: only row 1 is covered, so everything the live stream
    // delivers past it is residual accumulation the pass may reclaim.
    conn.subscribe("w", "SELECT * FROM orders WHERE id = 1")
        .await
        .expect("subscribe");

    let rows_applied = pump_to_tidy_due(&mut conn).await;
    assert!(
        rows_applied >= 10,
        "the event carries the sum at the crossing, at least the threshold: {rows_applied}",
    );
    assert_eq!(
        replica_ids(&mut conn),
        vec![1],
        "the pass already ran: every row the narrow filter does not cover is gone",
    );
    let pressure = conn.residual_pressure().expect("pressure");
    assert!(
        pressure.rows_applied.is_empty(),
        "the pass reset the measure: {:?}",
        pressure.rows_applied,
    );
}

/// The supplanting application: it sees the event exactly once, the default
/// pass stays silent, the measure keeps standing until its own `tidy`, which
/// reclaims, resets, and re-arms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_manual_application_sees_the_event_and_the_default_pass_stays_silent() {
    let config = ClientConfig::new("r60-manual")
        .with_login(Some(Grant::new("user:r60")))
        .with_residual_threshold(10)
        .with_residual_pass(ResidualPass::Manual);
    let server = accumulating_server(15);
    let mut conn = ConnettoConnection::connect(server, &Replica::in_memory(), DDL, &config, None)
        .await
        .expect("connect");
    conn.subscribe("w", "SELECT * FROM orders WHERE id = 1")
        .await
        .expect("subscribe");

    let rows_applied = pump_to_tidy_due(&mut conn).await;
    assert!(
        rows_applied >= 10,
        "the crossing is reported: {rows_applied}"
    );

    // Drain the rest of the stream behind a ping barrier: the pass must not
    // have run, and the crossing must not fire a second time while armed.
    conn.ping(7).await.expect("ping");
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::TidyDue { .. } => {
                panic!("the crossing fired twice without a pass in between")
            }
            ClientEvent::Pong { nonce: 7 } => break,
            ClientEvent::Closed => panic!("closed before the barrier"),
            _ => {}
        }
    }
    assert_eq!(
        replica_ids(&mut conn).len(),
        16,
        "the default pass stayed silent: all sixteen rows are still held",
    );
    let pressure = conn.residual_pressure().expect("pressure");
    let total: u64 = pressure.rows_applied.iter().map(|(_, n)| n).sum();
    assert!(
        total >= 16,
        "the measure keeps standing for the application to read: {total}",
    );
    assert_eq!(
        pressure.rows_applied.first().map(|(t, _)| t.as_str()),
        Some("orders"),
        "the measure is per table",
    );

    // The application's own pass reclaims, resets, and re-arms.
    conn.tidy().expect("tidy");
    assert_eq!(
        replica_ids(&mut conn),
        vec![1],
        "the application's tidy reclaims what the filter does not cover",
    );
    let pressure = conn.residual_pressure().expect("pressure");
    assert!(
        pressure.rows_applied.is_empty(),
        "and resets the measure: {:?}",
        pressure.rows_applied,
    );
}

/// DDL for the staging-test replica: the orders table with a BEFORE INSERT
/// trigger that raises a whole-transaction rollback when the table already
/// holds a row. The first insert succeeds (hook fires), the second triggers
/// the rollback, so the transaction fails after the hook has already counted.
const STAGING_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT); \
    CREATE TRIGGER sentinel_rollback BEFORE INSERT ON orders \
    WHEN (SELECT count(*) FROM orders) > 0 \
    BEGIN SELECT RAISE(ROLLBACK, 'sentinel rollback'); END;";

/// Compressed patchset inserting two rows. Both target the same table so
/// SQLite applies them in sequence: the first when the table is empty (hook
/// fires, trigger is silent), the second when it is not (trigger rolls back
/// the whole transaction).
fn two_op_payload(id1: i64, id2: i64) -> Vec<u8> {
    let schema = orders_table();
    let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(
            Insert::from(schema.clone())
                .set(0, Value::Integer(id1))
                .expect("set id1")
                .set(1, Value::Text("x".to_owned()))
                .expect("set status1"),
        )
        .insert(
            Insert::from(schema)
                .set(0, Value::Integer(id2))
                .expect("set id2")
                .set(1, Value::Text("x".to_owned()))
                .expect("set status2"),
        );
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress two-op payload")
}

/// Server for the threshold-clamp test: sends an empty snapshot (rowless
/// `SnapshotPatch`) followed by a single one-row live patch.
fn clamp_test_server() -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        ack_handshake(&mut server).await;
        while let Ok(Some(frame)) = server.recv().await {
            match frame {
                IncomingFrame::Control(ControlMessage::Subscribe(sub)) => {
                    server
                        .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                            sub_id: sub.sub_id.clone(),
                            priority: SubscriptionPriority::default(),
                        }))
                        .await
                        .expect("begin");
                    server
                        .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch {
                            sub_id: sub.sub_id.clone(),
                            patchset_zstd: payload(&[]), // rowless: no hook fires
                        }))
                        .await
                        .expect("empty patch");
                    server
                        .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
                            sub_id: sub.sub_id.clone(),
                            cursor: Cursor::new(vec![1]),
                        }))
                        .await
                        .expect("end");
                    server
                        .send_bulk(BulkMessage::LivePatch(LivePatch::new(
                            sub.sub_id.clone(),
                            Cursor::new(vec![2]),
                            payload(&[42]),
                        )))
                        .await
                        .expect("live");
                }
                IncomingFrame::Control(ControlMessage::Ping(ping)) => {
                    server
                        .send_control(ControlMessage::Pong(connetto_core::messages::Pong {
                            nonce: ping.nonce,
                        }))
                        .await
                        .expect("pong");
                }
                _ => {}
            }
        }
    });
    client_end
}

/// Server for the staging test: empty snapshot (`SnapshotBegin` + `SnapshotEnd`,
/// no rows), then a two-op live patch whose second op fires the rollback
/// trigger. The first op's update hook fires before the rollback, producing
/// a phantom count in the pre-fix code.
fn staging_test_server() -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        ack_handshake(&mut server).await;
        while let Ok(Some(frame)) = server.recv().await {
            match frame {
                IncomingFrame::Control(ControlMessage::Subscribe(sub)) => {
                    server
                        .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                            sub_id: sub.sub_id.clone(),
                            priority: SubscriptionPriority::default(),
                        }))
                        .await
                        .expect("begin");
                    server
                        .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
                            sub_id: sub.sub_id.clone(),
                            cursor: Cursor::new(vec![1]),
                        }))
                        .await
                        .expect("end");
                    // First op (id=100) succeeds and fires the hook. Second op
                    // (id=200) hits the BEFORE INSERT trigger once the table is
                    // non-empty, which calls RAISE(ROLLBACK) and rolls back the
                    // entire transaction including op 1.
                    server
                        .send_bulk(BulkMessage::LivePatch(LivePatch::new(
                            sub.sub_id.clone(),
                            Cursor::new(vec![2]),
                            two_op_payload(100, 200),
                        )))
                        .await
                        .expect("failing live");
                }
                IncomingFrame::Control(ControlMessage::Ping(ping)) => {
                    server
                        .send_control(ControlMessage::Pong(connetto_core::messages::Pong {
                            nonce: ping.nonce,
                        }))
                        .await
                        .expect("pong");
                }
                _ => {}
            }
        }
    });
    client_end
}

/// Task 1: `with_residual_threshold(0)` must be clamped to 1. Without the
/// clamp, `residual_check`'s `total < threshold` guard is `0 < 0 = false` and
/// fires `TidyDue` after every patch, including rowless ones. With the clamp,
/// the guard is `0 < 1 = true` for rowless patches (skip) and `1 < 1 = false`
/// for the first applied row (fire).
///
/// Failing-first signal: `rows_applied` in the event is 0 instead of 1,
/// meaning `TidyDue` fired for the empty `SnapshotPatch` before the one-row
/// `LivePatch` was processed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn threshold_zero_is_clamped_to_one() {
    let config = ClientConfig::new("r60-clamp")
        .with_login(Some(Grant::new("user:r60")))
        .with_residual_threshold(0) // clamped to 1 after the fix
        .with_residual_pass(ResidualPass::Manual);
    let server = clamp_test_server();
    let mut conn = ConnettoConnection::connect(server, &Replica::in_memory(), DDL, &config, None)
        .await
        .expect("connect");
    conn.subscribe("w", "SELECT * FROM orders")
        .await
        .expect("subscribe");

    let rows_applied = pump_to_tidy_due(&mut conn).await;
    assert_eq!(
        rows_applied, 1,
        "threshold 0 is clamped to 1: TidyDue must carry the one-row count, \
        not fire for the rowless snapshot patch (got {rows_applied})",
    );
}

/// Task 2 regression (TDD): the update hook fires per-statement before the
/// transaction resolves, so a rolled-back `apply_patch` must not leave phantom
/// counts in `applied_rows`.
///
/// Seam: the `STAGING_DDL` schema includes a BEFORE INSERT trigger that calls
/// `RAISE(ROLLBACK)` when the table already holds a row. The patchset has two
/// ops for the same table. The first op inserts successfully (the hook fires,
/// incrementing the staging accumulator). The second op fires the trigger before
/// its INSERT completes, rolling back the entire transaction including op 1.
/// The hook never fires for op 2 (BEFORE INSERT fires before the write, so
/// the write and its hook fire never happen). The net phantom: op 1's hook
/// contribution sits in `applied_rows` in the pre-fix code, and is absent
/// after the fix.
///
/// Failing-first signal: `pressure.rows_applied` is non-empty (`[("orders", 1)]`)
/// because op 1's hook wrote to `applied_rows` directly before the rollback
/// cleared the database write but left the in-memory counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_apply_leaves_no_phantom_counts() {
    let config = ClientConfig::new("r60-staging")
        .with_login(Some(Grant::new("user:r60")))
        .with_residual_threshold(1)
        .with_residual_pass(ResidualPass::Manual);
    let server = staging_test_server();
    let mut conn =
        ConnettoConnection::connect(server, &Replica::in_memory(), STAGING_DDL, &config, None)
            .await
            .expect("connect");
    conn.subscribe("w", "SELECT * FROM orders")
        .await
        .expect("subscribe");

    // Drain the empty snapshot (SnapshotBegin then SnapshotEnd, no patches).
    loop {
        match conn.pump_one().await.expect("pump snapshot") {
            ClientEvent::SnapshotEnd { .. } => break,
            ClientEvent::Closed => panic!("closed during snapshot drain"),
            _ => {}
        }
    }

    // The two-op live patch: op 1 fires the hook, op 2 triggers RAISE(ROLLBACK).
    // Seam verification: if this returns Ok, the seam did not error and a
    // different seam is needed. The test asserts is_err() to confirm the trigger
    // fired and rolled back the transaction.
    let result = conn.pump_one().await;
    assert!(
        result.is_err(),
        "the two-op patch must fail: second insert fires RAISE(ROLLBACK) via the trigger",
    );

    // After a rolled-back apply, no phantom counts must appear in applied_rows.
    let pressure = conn
        .residual_pressure()
        .expect("residual_pressure must work after a failed apply");
    assert!(
        pressure.rows_applied.is_empty(),
        "a rolled-back apply must leave no phantom counts: {:?}",
        pressure.rows_applied,
    );
}

/// DDL whose orders table refuses deletes: the eviction inside an automatic
/// pass fails on the first uncovered row, the seam for proving what a failed
/// pass emits.
const ABORT_DELETE_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, status TEXT); \
    CREATE TRIGGER refuse_delete BEFORE DELETE ON orders \
    BEGIN SELECT RAISE(ABORT, 'deletes refused'); END;";

/// Server for the failed-pass test: a one-row snapshot for the narrow filter,
/// then two single-row live patches outside it, then pong echoes.
fn failing_pass_server() -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        ack_handshake(&mut server).await;
        while let Ok(Some(frame)) = server.recv().await {
            match frame {
                IncomingFrame::Control(ControlMessage::Subscribe(sub)) => {
                    server
                        .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                            sub_id: sub.sub_id.clone(),
                            priority: SubscriptionPriority::default(),
                        }))
                        .await
                        .expect("begin");
                    server
                        .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch {
                            sub_id: sub.sub_id.clone(),
                            patchset_zstd: payload(&[1]),
                        }))
                        .await
                        .expect("snapshot");
                    server
                        .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
                            sub_id: sub.sub_id.clone(),
                            cursor: Cursor::new(vec![1]),
                        }))
                        .await
                        .expect("end");
                    for id in [2_i64, 3] {
                        server
                            .send_bulk(BulkMessage::LivePatch(LivePatch::new(
                                sub.sub_id.clone(),
                                Cursor::new(vec![
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    3,
                                    u8::try_from(id).expect("small id"),
                                ]),
                                payload(&[id]),
                            )))
                            .await
                            .expect("live patch");
                    }
                }
                IncomingFrame::Control(ControlMessage::Ping(ping)) => {
                    server
                        .send_control(ControlMessage::Pong(connetto_core::messages::Pong {
                            nonce: ping.nonce,
                        }))
                        .await
                        .expect("pong");
                }
                _ => {}
            }
        }
    });
    client_end
}

/// A failed automatic pass queues no `TidyDue` and re-arms, so the event
/// never claims a pass that did not happen and the next apply retries.
///
/// The narrow filter covers row 1 alone, so rows 2 and 3 are residual. At the
/// crossing the automatic `tidy` hits the delete-refusing trigger and fails,
/// which must surface as the pump error and emit nothing. Dropping the
/// trigger lets the retry at the next applied row succeed, and only then does
/// the one event arrive, carrying the measure of the pass that actually ran.
///
/// Failing-first signal: the first `TidyDue` carries `rows_applied: 2`, the
/// count at the crossing whose pass failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_automatic_pass_emits_nothing_and_retries() {
    let config = ClientConfig::new("r60-failed-pass")
        .with_login(Some(Grant::new("user:r60")))
        .with_residual_threshold(2);
    let server = failing_pass_server();
    let mut conn = ConnettoConnection::connect(
        server,
        &Replica::in_memory(),
        ABORT_DELETE_DDL,
        &config,
        None,
    )
    .await
    .expect("connect");
    conn.subscribe("w", "SELECT * FROM orders WHERE id = 1")
        .await
        .expect("subscribe");
    loop {
        match conn.pump_one().await.expect("pump snapshot") {
            ClientEvent::SnapshotEnd { .. } => break,
            ClientEvent::Closed => panic!("closed during snapshot drain"),
            _ => {}
        }
    }

    // Row 2 crosses the threshold, the automatic pass tries to evict it, and
    // the trigger refuses the delete: the failure surfaces as the pump error.
    let result = conn.pump_one().await;
    assert!(
        result.is_err(),
        "the crossing pass must fail on the delete-refusing trigger",
    );

    // DDL the query DSL cannot express, the allowed raw category: lifting the
    // seam so the retry can succeed.
    diesel::sql_query("DROP TRIGGER refuse_delete")
        .execute(conn.conn())
        .expect("drop the refusal trigger");

    // Row 3 re-crosses, the retried pass succeeds, and only now does the one
    // event arrive, carrying the successful pass's measure of three rows.
    let rows_applied = pump_to_tidy_due(&mut conn).await;
    assert_eq!(
        rows_applied, 3,
        "the only TidyDue belongs to the pass that ran: a failed pass emitting \
        one at the earlier crossing would carry 2",
    );
    assert_eq!(
        replica_ids(&mut conn),
        vec![1],
        "the retried pass evicted both uncovered rows",
    );
    let pressure = conn.residual_pressure().expect("pressure");
    assert!(
        pressure.rows_applied.is_empty(),
        "the successful pass reset the measure: {:?}",
        pressure.rows_applied,
    );
}
