//! Phase 5 relay parity: per-tab delivery-credit flow control.
//!
//! The direct server bounds in-flight bulk frames by a per-session credit
//! window: it queues bulk frames once credits reach zero and drains them on
//! `AckCredits` (`connetto-server/src/session.rs`). A relay tab must see the
//! identical backpressure, so the hub has to honor a per-tab credit window
//! rather than pushing every bulk frame the moment it arrives.
//!
//! A normal `ConnettoConnection` tab auto-replenishes one credit per applied
//! patch, so it never stalls the window. To exercise the hub gating this test
//! attaches a raw frame-level tab over a loopback and withholds `AckCredits`.
//! Only `LivePatch` and `SnapshotPatch` are credit-gated; control frames are
//! not, so an ungated `NonFatalError` sent by the upstream after the flood acts
//! as a race-free barrier: the hub processes worker events strictly in order,
//! so the barrier control frame reaches the tab immediately after the gated
//! window, with the surplus patches still held in the hub. Without gating every
//! flood patch would arrive before the barrier.
//!
//! The worker's upstream is a fake server over a loopback, so no real server or
//! Postgres is needed.
//!
//! Run with the demo stack up:
//! `wasm-pack test --headless --chrome examples/wasm-smoke`

#![cfg(target_arch = "wasm32")]

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Replica};
use connetto_core::messages::{
    AckCredits, BulkMessage, ControlMessage, Handshake, HandshakeAck, LivePatch, NonFatalError,
    SnapshotBegin, SnapshotEnd, SnapshotPatch, Subscribe, SubscriptionPriority, SubscriptionSpec,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackError, LoopbackTransport, PROTOCOL_VERSION, loopback};
use connetto_wasm_smoke::{RelayHub, uuidv7_functions};
use connetto_web::relay::HubReconnect;
use futures_channel::oneshot;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DDL: &str = "CREATE TABLE orders (id BLOB PRIMARY KEY DEFAULT (uuidv7()) CHECK (length(id) = 16) NOT NULL, quantity INTEGER) STRICT;";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
/// The worker's upstream subscription id: it must match the hub's reconnect
/// spec so the upstream `NonFatalError` maps to the tab subscriptions reading
/// those tables.
const UPSTREAM_SUB: &str = "db-upstream";
/// The credit window the hub advertises and enforces, mirroring the server.
const INITIAL_CREDITS: u32 = 64;
/// Live patches the fake upstream floods after the tab subscribes. More than
/// one full window plus room for two replenishments.
const FLOOD: u64 = 80;

/// Ids unique across smoke runs, in this test's own band. This test never
/// touches the server, but it shares the wasm binary's id conventions.
fn unique_base() -> i64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let millis = js_sys::Date::now() as i64;
    93_000_000_000 + millis
}

/// Build the compressed insert-patchset the wire carries for one row.
fn insert_payload(id: rosetta_uuid::Uuid, quantity: i64) -> Vec<u8> {
    let table = SimpleTable::new("orders", &["id", "quantity"], &[0]);
    let insert = Insert::<_, String, Vec<u8>>::from(table)
        .set(0, Value::Blob(<[u8; 16]>::from(id).to_vec()))
        .expect("set id")
        .set(1, Value::Integer(quantity))
        .expect("set quantity");
    let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new().insert(insert);
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress patch")
}

/// The order index encoded in a cursor by the fake upstream, recovered from its
/// big-endian bytes so the test can assert FIFO delivery.
fn cursor_index(cursor: &Cursor) -> u64 {
    let bytes: [u8; 8] = cursor.as_bytes().try_into().expect("8-byte cursor");
    u64::from_be_bytes(bytes)
}

/// Send one begin, patch, end snapshot triple for `UPSTREAM_SUB`.
async fn send_snapshot(
    server: &mut LoopbackTransport,
    id: rosetta_uuid::Uuid,
    quantity: i64,
    cursor: u64,
) {
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
            insert_payload(id, quantity),
        )))
        .await
        .expect("snapshot patch");
    server
        .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
            sub_id: UPSTREAM_SUB.to_owned(),
            cursor: Cursor::new(cursor.to_be_bytes().to_vec()),
        }))
        .await
        .expect("snapshot end");
}

/// The fake upstream: seed one row, then on `trigger` flood `FLOOD` live patches
/// (cursors `1..=FLOOD`, ascending), and finally an ungated `NonFatalError` on
/// the upstream sub as the credit barrier.
async fn fake_upstream(mut server: LoopbackTransport, trigger: oneshot::Receiver<()>) {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        return;
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: "credits-upstream".to_owned(),
            session_token: "credits".to_owned(),
            current_cursor: Cursor::new(Vec::new()),
            schema_version: None,
            initial_credits: INITIAL_CREDITS,
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
    // Seed one row so the worker replica is non-empty: the tab's own snapshot
    // patch then consumes exactly one credit.
    send_snapshot(&mut server, rosetta_uuid::Uuid::utc_v7(), 5, 0).await;
    if trigger.await.is_err() {
        return;
    }
    for i in 1..=FLOOD {
        server
            .send_bulk(BulkMessage::LivePatch(LivePatch::new(
                UPSTREAM_SUB.to_owned(),
                Cursor::new(i.to_be_bytes().to_vec()),
                insert_payload(rosetta_uuid::Uuid::utc_v7(), 5),
            )))
            .await
            .expect("live patch");
    }
    // The barrier: an ungated control frame the hub fans to the tab only after
    // every flood patch has been processed into the credit window.
    server
        .send_control(ControlMessage::NonFatalError(NonFatalError {
            related_to: Some(UPSTREAM_SUB.to_owned()),
            detail: "credit window barrier".to_owned(),
        }))
        .await
        .expect("barrier");
    // Drain the worker's acks so the loopback never backs up.
    while let Ok(Some(_)) = server.recv().await {}
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

/// Receive the next frame from the raw tab end.
async fn recv(tab: &mut LoopbackTransport) -> IncomingFrame {
    tab.recv().await.expect("tab recv").expect("tab frame")
}

#[wasm_bindgen_test]
async fn hub_enforces_the_per_tab_credit_window() {
    let base = unique_base();

    // The worker's upstream is a fake server we drive frame by frame. It seeds
    // one row up front, so the worker replica is non-empty before the hub runs.
    let (worker_up, fake_up) = loopback();
    let (trigger_tx, trigger_rx) = oneshot::channel();
    spawn_local(fake_upstream(fake_up, trigger_rx));

    let worker_config = ClientConfig {
        client_id: format!("credits-worker-{base}"),
        auth_token: "token".to_owned(),
        schema_version: None,
        sql_functions: uuidv7_functions(),
    };
    let mut worker =
        ConnettoConnection::connect(worker_up, &Replica::Ephemeral, DDL, &worker_config, None)
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

    // The hub carries the upstream spec so it can map the upstream NonFatal to
    // the tab subscriptions reading those tables. The factory and sleeper are
    // never invoked: the fake upstream never drops.
    let reconnect = HubReconnect {
        factory: || core::future::pending::<Result<LoopbackTransport, LoopbackError>>(),
        sleeper: |_duration: core::time::Duration| async {},
        policy: ReconnectPolicy::default(),
        upstream: vec![(UPSTREAM_SUB.to_owned(), SubscriptionSpec::new(QUERY))],
    };
    let (hub, pump, _notices) =
        RelayHub::with_reconnect(worker, ":memory:", None, reconnect).expect("relay hub");
    spawn_local(async move {
        let _ = pump.await;
    });

    // A raw frame-level tab that withholds AckCredits, so the hub credit window
    // is what governs delivery.
    let (mut tab, relay_end) = loopback();
    hub.attach(relay_end);
    tab.send_control(ControlMessage::Handshake(Handshake::new(
        PROTOCOL_VERSION,
        format!("credits-tab-{base}"),
        "token",
    )))
    .await
    .expect("tab handshake");
    let ack = match recv(&mut tab).await {
        IncomingFrame::Control(ControlMessage::HandshakeAck(ack)) => ack,
        other => panic!("expected a handshake ack, got {other:?}"),
    };
    assert_eq!(
        ack.initial_credits, INITIAL_CREDITS,
        "the relay advertises the same credit window as the server",
    );

    tab.send_control(ControlMessage::Subscribe(Subscribe {
        sub_id: "tab-orders".to_owned(),
        spec: SubscriptionSpec::new(QUERY),
    }))
    .await
    .expect("tab subscribe");

    // Read the subscription snapshot fully before triggering the flood, so the
    // snapshot strictly precedes the live patches. Its one patch consumes one
    // credit from the window.
    let mut snapshot_patches: u32 = 0;
    loop {
        match recv(&mut tab).await {
            IncomingFrame::Control(ControlMessage::SnapshotBegin(_)) => {}
            IncomingFrame::Bulk(BulkMessage::SnapshotPatch(_)) => snapshot_patches += 1,
            IncomingFrame::Control(ControlMessage::SnapshotEnd(_)) => break,
            other => panic!("unexpected frame during the snapshot: {other:?}"),
        }
    }
    assert_eq!(
        snapshot_patches, 1,
        "the tab snapshot delivers one patch, consuming one credit",
    );

    // Flood the upstream. The barrier NonFatal ends the readable window.
    trigger_tx.send(()).expect("trigger flood");
    let mut before_barrier: Vec<u64> = Vec::new();
    loop {
        match recv(&mut tab).await {
            IncomingFrame::Bulk(BulkMessage::LivePatch(patch)) => {
                before_barrier.push(cursor_index(&patch.cursor));
            }
            IncomingFrame::Control(ControlMessage::NonFatalError(_)) => break,
            other => panic!("unexpected frame before the credit barrier: {other:?}"),
        }
    }

    // The window is exactly `INITIAL_CREDITS` bulk frames: one snapshot patch
    // plus the rest live patches, delivered in FIFO cursor order, and no more
    // until the tab replenishes.
    let window = usize::try_from(INITIAL_CREDITS).expect("window fits usize");
    let live_in_window = usize::try_from(INITIAL_CREDITS - snapshot_patches).expect("fits usize");
    assert_eq!(
        usize::try_from(snapshot_patches).expect("fits usize") + before_barrier.len(),
        window,
        "the hub delivers exactly the initial credit window before stalling",
    );
    assert_eq!(
        before_barrier,
        (1..=u64::from(INITIAL_CREDITS - snapshot_patches)).collect::<Vec<_>>(),
        "windowed live patches arrive in FIFO cursor order",
    );

    // Replenish credits in two grants and assert exactly that many more drain,
    // continuing the FIFO cursor sequence.
    let remaining = usize::try_from(FLOOD).expect("flood fits usize") - live_in_window;
    let grant1 = 10usize;
    let grant2 = remaining - grant1;
    let mut after_barrier: Vec<u64> = Vec::new();
    for grant in [grant1, grant2] {
        tab.send_control(ControlMessage::AckCredits(AckCredits {
            credits: u32::try_from(grant).expect("grant fits u32"),
        }))
        .await
        .expect("ack credits");
        for _ in 0..grant {
            match recv(&mut tab).await {
                IncomingFrame::Bulk(BulkMessage::LivePatch(patch)) => {
                    after_barrier.push(cursor_index(&patch.cursor));
                }
                other => panic!("unexpected frame after replenishing credits: {other:?}"),
            }
        }
    }
    assert_eq!(
        after_barrier,
        (u64::from(INITIAL_CREDITS - snapshot_patches) + 1..=FLOOD).collect::<Vec<_>>(),
        "replenished patches drain in FIFO order after each AckCredits",
    );
}
