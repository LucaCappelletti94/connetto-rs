//! Phase 2 relay parity: full-resync propagation through the hub.
//!
//! When the upstream cannot resume a subscription incrementally it sends
//! `FullResyncRequired` and a fresh snapshot. The fresh snapshot carries only
//! the currently authorized rows, so a row deleted while the worker was away
//! must vanish from every tab mirror. The direct client proves this natively
//! (`connetto-client/tests/full_resync.rs`); this test proves the relay tab
//! behaves identically, which is the transparency requirement.
//!
//! A real upstream retention overflow that reaches a still-attached tab is not
//! deterministically triggerable from a browser (the harness cannot sever the
//! worker's upstream socket without killing the whole worker, which makes the
//! tab reconnect instead of staying attached). So the worker's upstream is a
//! fake server over a loopback that hand-feeds the exact resume frame sequence,
//! the same approach the native test uses. The tab stays attached to the hub
//! throughout, exercising the hub's resync fan-out.
//!
//! Run with the demo stack up:
//! `wasm-pack test --headless --chrome examples/wasm-smoke`

#![cfg(target_arch = "wasm32")]

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection};
use connetto_core::messages::{
    BulkMessage, ControlMessage, FullResyncReason, FullResyncRequired, HandshakeAck, SnapshotBegin,
    SnapshotEnd, SnapshotPatch, SubscriptionPriority, SubscriptionSpec,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackError, LoopbackTransport, loopback};
use connetto_wasm_smoke::{RelayHub, uuidv7_functions};
use connetto_web::relay::HubReconnect;
use diesel::prelude::*;
use futures_channel::oneshot;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DDL: &str = "CREATE TABLE orders (id BLOB PRIMARY KEY DEFAULT (uuidv7()) CHECK (length(id) = 16) NOT NULL, quantity INTEGER) STRICT;";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
/// The worker's upstream subscription id: it must match the hub's reconnect
/// spec so the resync fan-out maps it to the affected tab subscriptions.
const UPSTREAM_SUB: &str = "db-upstream";

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Eq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: rosetta_uuid::Uuid,
    quantity: i64,
}

/// Ids unique across smoke runs so the demo Postgres does not collide, in this
/// test's own band. This test never touches the server, but it shares the wasm
/// binary's id conventions.
fn unique_base() -> i64 {
    let millis = js_sys::Date::now();
    debug_assert!(millis.is_finite(), "Date::now returned non-finite value");
    // Date::now() returns milliseconds since epoch as f64; fits i64 until year 285428751.
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    (millis as i64)
}

/// Build the compressed insert-patchset the wire carries for one snapshot.
fn snapshot_payload(rows: &[(rosetta_uuid::Uuid, i64)]) -> Vec<u8> {
    let mut patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new();
    for (id, quantity) in rows {
        let table = SimpleTable::new("orders", &["id", "quantity"], &[0]);
        // Encode the 16-byte UUID as a SQLite BLOB: <[u8; 16]>::from extracts
        // the raw bytes, matching what the server and changeset apply expect.
        let insert = Insert::<_, String, Vec<u8>>::from(table)
            .set(0, Value::Blob(<[u8; 16]>::from(*id).to_vec()))
            .expect("set id")
            .set(1, Value::Integer(*quantity))
            .expect("set quantity");
        patchset = patchset.insert(insert);
    }
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress snapshot")
}

/// Send one begin, patch, end triple for `UPSTREAM_SUB`.
async fn send_snapshot(
    server: &mut LoopbackTransport,
    rows: &[(rosetta_uuid::Uuid, i64)],
    cursor: Vec<u8>,
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
            snapshot_payload(rows),
        )))
        .await
        .expect("snapshot patch");
    server
        .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
            sub_id: UPSTREAM_SUB.to_owned(),
            cursor: Cursor::new(cursor),
        }))
        .await
        .expect("snapshot end");
}

/// The fake upstream: snapshot two rows, then on `trigger` order a full resync
/// whose fresh snapshot drops the doomed row.
async fn fake_upstream(
    mut server: LoopbackTransport,
    trigger: oneshot::Receiver<()>,
    doomed_id: rosetta_uuid::Uuid,
    survivor_id: rosetta_uuid::Uuid,
) {
    let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await else {
        return;
    };
    server
        .send_control(ControlMessage::HandshakeAck(HandshakeAck {
            connection_id: "resync-upstream".to_owned(),
            session_token: "resync".to_owned(),
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
    // Initial snapshot: the doomed row and the survivor. rosetta_uuid::Uuid is Copy.
    send_snapshot(
        &mut server,
        &[(doomed_id, 5), (survivor_id, 5)],
        vec![0, 0, 0, 0, 0, 0, 0, 1],
    )
    .await;
    // Wait until the tab has converged, then force the resync.
    if trigger.await.is_err() {
        return;
    }
    server
        .send_control(ControlMessage::FullResyncRequired(FullResyncRequired {
            sub_id: UPSTREAM_SUB.to_owned(),
            reason: FullResyncReason::CursorOutsideRetention,
        }))
        .await
        .expect("resync signal");
    send_snapshot(
        &mut server,
        &[(survivor_id, 5)],
        vec![0, 0, 0, 0, 0, 0, 0, 2],
    )
    .await;
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
async fn full_resync_is_relay_transparent() {
    let base = unique_base();

    // Generate UUIDs for both rows up front so the fake upstream and the
    // post-resync assertion reference the exact same values. rosetta_uuid::Uuid is Copy.
    let doomed_id = rosetta_uuid::Uuid::utc_v7();
    let survivor_id = rosetta_uuid::Uuid::utc_v7();

    // The worker's upstream is a fake server we drive frame by frame.
    let (worker_up, fake_up) = loopback();
    let (trigger_tx, trigger_rx) = oneshot::channel();
    spawn_local(fake_upstream(fake_up, trigger_rx, doomed_id, survivor_id));

    let worker_config = ClientConfig {
        client_id: format!("resync-worker-{base}"),
        auth_token: "token".to_owned(),
        schema_version: None,
        sql_functions: uuidv7_functions(),
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

    // The hub carries the upstream spec so it can map an upstream resync to the
    // tab subscriptions reading those tables. The factory and sleeper are never
    // invoked: the fake upstream never drops.
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

    // The tab attaches to the hub and subscribes: its mirror seeds both rows.
    let (tab_end, relay_end) = loopback();
    hub.attach(relay_end);
    let tab_config = ClientConfig {
        client_id: format!("resync-tab-{base}"),
        auth_token: "token".to_owned(),
        schema_version: None,
        sql_functions: uuidv7_functions(),
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
    // Two uuidv7 ids generated in rapid succession differ only in random low
    // bytes, so their sort order is unpredictable. Use set membership.
    let pre_ids: std::collections::HashSet<rosetta_uuid::Uuid> =
        load_orders(&mut tab).into_iter().map(|o| o.id).collect();
    assert!(
        pre_ids.contains(&doomed_id),
        "tab mirror should contain the doomed row {doomed_id:?} before the resync",
    );
    assert!(
        pre_ids.contains(&survivor_id),
        "tab mirror should contain the survivor row {survivor_id:?} before the resync",
    );
    assert_eq!(
        pre_ids.len(),
        2,
        "tab mirror should have exactly 2 rows before the resync"
    );

    // Force the upstream resync now that the tab is attached and converged.
    trigger_tx.send(()).expect("trigger resync");

    // The tab must observe the resync and drop the row deleted during the
    // outage, converging on the survivor exactly as a direct client would.
    let mut saw_resync = false;
    loop {
        match tab.pump_one().await.expect("tab pump") {
            ClientEvent::FullResync { .. } => saw_resync = true,
            ClientEvent::Closed => panic!("tab closed before it converged"),
            _ => {}
        }
        let ids: Vec<rosetta_uuid::Uuid> =
            load_orders(&mut tab).into_iter().map(|o| o.id).collect();
        if saw_resync && ids == vec![survivor_id] {
            break;
        }
    }
    assert!(
        saw_resync,
        "the tab observed FullResync forwarded through the hub"
    );
}
