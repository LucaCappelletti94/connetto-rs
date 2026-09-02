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
