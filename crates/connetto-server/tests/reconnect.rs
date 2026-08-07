//! Reconnect and oplog end-to-end tests (Phase 5).
//!
//! Drives a sequence of CDC events through the manager (which records them in an
//! in-memory oplog), then reconnects a client whose resume cursor sits at a
//! chosen point and asserts the catchup-versus-full-resync behaviour:
//!
//! * within the retained window: the client receives exactly the entries after
//!   its cursor as `LivePatch`, and its replica reaches row parity;
//! * outside the window (after a prune): the client receives
//!   `FullResyncRequired { CursorOutsideRetention }` followed by a fresh
//!   snapshot;
//! * a delete replays as a tombstone so the client drops the row.
//!
//! Reads and seeds go through typed diesel queries, matching the other tests;
//! DML against the emulated backend stays as SQL strings.

#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{
    BulkMessage, ControlMessage, FullResyncReason, Handshake, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{HandshakeAuthority, IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    InMemoryOplog, LoopbackTransport, Materializer, NoConnector, OplogConfig, PermissiveAuth,
    RequestGuard, SessionConfig, SessionManager, Snapshot, SnapshotSource, loopback,
    pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture};
use diesel::prelude::*;
use diesel::sql_query;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use subql::backend::CdcEvent;
use subql::{CdcSource, ChangeEvent, PgSqliteEmuSource};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

fn test_verifier() -> std::sync::Arc<dyn HandshakeAuthority> {
    std::sync::Arc::new(TestGrantChecker)
}

/// A snapshot source returning one seed row. Only the full-resync path delivers
/// it, and that test asserts the frame sequence rather than applying it.
struct SeedSnapshot;

impl SnapshotSource for SeedSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::Principal,
    ) -> Result<Snapshot, Self::Error> {
        let table = SimpleTable::new("orders", &["id", "price", "quantity", "status"], &[0]);
        let insert = Insert::<_, String, Vec<u8>>::from(table)
            .set(0, Value::Integer(1))
            .expect("set id")
            .set(1, Value::Real(1.0))
            .expect("set price")
            .set(2, Value::Integer(3))
            .expect("set quantity")
            .set(3, Value::Text("seed".to_owned()))
            .expect("set status");
        let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new()
            .insert(insert)
            .build();
        Ok(Snapshot {
            patchset,
            cursor: Cursor::new(Vec::new()),
        })
    }
}

diesel::table! {
    orders (id) {
        id -> diesel::sql_types::BigInt,
        price -> diesel::sql_types::Double,
        quantity -> diesel::sql_types::BigInt,
        status -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    price: f64,
    quantity: i64,
    status: String,
}

fn order(id: i64, price: f64, quantity: i64, status: &str) -> Order {
    Order {
        id,
        price,
        quantity,
        status: status.to_owned(),
    }
}

fn orders(conn: &mut SqliteConnection) -> Vec<Order> {
    orders::table
        .order(orders::id)
        .select(Order::as_select())
        .load(conn)
        .expect("read orders")
}

fn client_replica() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    conn
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

async fn next_bulk<T: Transport>(transport: &mut T) -> BulkMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Bulk(msg)) => msg,
        other => panic!("expected bulk frame, got {other:?}"),
    }
}

/// Assert no frame arrives within a short window.
async fn expect_idle<T: Transport>(transport: &mut T) {
    let outcome = tokio::time::timeout(Duration::from_millis(150), transport.recv()).await;
    assert!(outcome.is_err(), "expected no frame, got {outcome:?}");
}

/// Execute `sql` against the emulated backend, route every resulting event
/// through the manager (which appends to the oplog), and return the events.
/// The emulator stamps monotonic LSNs, which the LSN-keyed oplog relies on.
async fn drive(
    source: &mut PgSqliteEmuSource,
    manager: &SessionManager<SeedSnapshot, PermissiveAuth, ConnettoWatermark>,
    sql: &str,
) -> Vec<ChangeEvent> {
    source.execute_sql(sql).expect("execute dml");
    let mut events = Vec::new();
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
        events.push(event);
    }
    events
}

/// The resume cursor a client would persist after applying `event`.
fn cursor_of(event: &ChangeEvent) -> Cursor {
    let lsn = event
        .checkpoint()
        .expect("row event carries a checkpoint")
        .0;
    Cursor::new(lsn.to_be_bytes().to_vec())
}

/// Open a session on `manager`, send the handshake carrying `resume`, and read
/// the ack. Returns the client half and the server task handle.
async fn open_session(
    manager: &Arc<SessionManager<SeedSnapshot, PermissiveAuth, ConnettoWatermark>>,
    client_id: &str,
    resume: Option<Cursor>,
) -> (LoopbackTransport, tokio::task::JoinHandle<()>) {
    let (server_transport, mut client) = loopback();
    let server = manager.clone();
    let handle = tokio::spawn(async move {
        server.serve(server_transport).await.expect("session ok");
    });
    let mut handshake = Handshake::new(PROTOCOL_VERSION, client_id).with_grant(
        connetto_core::messages::Grant::new(format!("user:{client_id}")),
    );
    if let Some(cursor) = resume {
        handshake = handshake.with_cursor(cursor);
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };
    (client, handle)
}

/// Subscribe to `QUERY` over `client`.
async fn subscribe<T: Transport>(client: &mut T) {
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::new(QUERY),
        }))
        .await
        .expect("send subscribe");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn catchup_within_window_streams_missed_ops() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        test_verifier(),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    // Drive a stream: two inserts (the synced prefix), then update, insert,
    // delete (the events the client will miss and catch up on).
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");

    let mut events = Vec::new();
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (1, 9.5, 3, 'paid')",
        )
        .await,
    );
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (2, 4.0, 5, 'new')",
        )
        .await,
    );
    events.extend(
        drive(
            &mut source,
            &manager,
            "UPDATE orders SET quantity = 7 WHERE id = 1",
        )
        .await,
    );
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (3, 2.0, 2, 'later')",
        )
        .await,
    );
    events.extend(drive(&mut source, &manager, "DELETE FROM orders WHERE id = 2").await);
    assert_eq!(events.len(), 5, "one CDC event per statement");

    // Build the client's replica as of the second event (the synced prefix).
    let applier = Materializer::new(PG_DDL).expect("build applier");
    let mut replica = client_replica();
    for event in &events[..2] {
        let patch = applier.encode_patch(event).expect("encode prefix patch");
        applier
            .apply_diffset(&patch, &mut replica)
            .expect("apply prefix patch");
    }
    assert_eq!(
        orders(&mut replica),
        vec![order(1, 9.5, 3, "paid"), order(2, 4.0, 5, "new")],
        "prefix replica synced through event 2",
    );

    // Reconnect from the second event's cursor.
    let resume = cursor_of(&events[1]);
    let (mut client, server) = open_session(&manager, "client-a", Some(resume)).await;
    subscribe(&mut client).await;

    // Catchup delivers exactly the three events after the resume cursor, as
    // LivePatch, with no snapshot frames.
    for event in &events[2..] {
        let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
            panic!("expected a catchup live patch");
        };
        assert_eq!(live.sub_id, "orders");
        assert_eq!(
            live.cursor,
            cursor_of(event),
            "patch carries the event cursor"
        );
        applier
            .apply_diffset(&live.patchset_zstd, &mut replica)
            .expect("apply catchup patch");
    }
    expect_idle(&mut client).await;

    // The replica reached parity with the server's matching rows.
    assert_eq!(
        orders(&mut replica),
        vec![order(1, 9.5, 7, "paid"), order(3, 2.0, 2, "later")],
        "catchup brought the replica to current state",
    );

    client.close().await.expect("close client");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn cursor_outside_window_forces_full_resync() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    // A tiny window: after four inserts the oldest two are pruned.
    let oplog = InMemoryOplog::new(OplogConfig {
        max_entries: 2,
        max_age: Duration::from_secs(72 * 60 * 60),
    });
    let manager = SessionManager::with_oplog(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        test_verifier(),
        NoConnector,
        oplog,
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");

    let mut events = Vec::new();
    for id in 1..=4 {
        let sql = format!(
            "INSERT INTO orders (id, price, quantity, status) VALUES ({id}, 1.0, {id}, 'row')"
        );
        events.extend(drive(&mut source, &manager, &sql).await);
    }
    assert_eq!(events.len(), 4);

    // Resume from the first event, which the prune dropped from the window.
    let resume = cursor_of(&events[0]);
    let (mut client, server) = open_session(&manager, "client-a", Some(resume)).await;
    subscribe(&mut client).await;

    // The server signals a full resync, then delivers a fresh snapshot.
    let ControlMessage::FullResyncRequired(resync) = next_control(&mut client).await else {
        panic!("expected a full-resync signal");
    };
    assert_eq!(resync.sub_id, "orders");
    assert_eq!(resync.reason, FullResyncReason::CursorOutsideRetention);

    let ControlMessage::SnapshotBegin(begin) = next_control(&mut client).await else {
        panic!("expected snapshot begin after resync");
    };
    assert_eq!(begin.sub_id, "orders");
    let BulkMessage::SnapshotPatch(patch) = next_bulk(&mut client).await else {
        panic!("expected snapshot patch");
    };
    assert_eq!(patch.sub_id, "orders");
    let ControlMessage::SnapshotEnd(end) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };
    assert_eq!(end.sub_id, "orders");
    expect_idle(&mut client).await;

    client.close().await.expect("close client");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn tombstone_replays_the_delete() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        test_verifier(),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");

    let mut events = Vec::new();
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (1, 9.5, 3, 'paid')",
        )
        .await,
    );
    events.extend(drive(&mut source, &manager, "DELETE FROM orders WHERE id = 1").await);
    assert_eq!(events.len(), 2);

    // The client synced through the insert and holds the row locally.
    let applier = Materializer::new(PG_DDL).expect("build applier");
    let mut replica = client_replica();
    let insert_patch = applier.encode_patch(&events[0]).expect("encode insert");
    applier
        .apply_diffset(&insert_patch, &mut replica)
        .expect("apply insert");
    assert_eq!(orders(&mut replica), vec![order(1, 9.5, 3, "paid")]);

    // Reconnect from just before the delete: the delete replays as a tombstone.
    let resume = cursor_of(&events[0]);
    let (mut client, server) = open_session(&manager, "client-a", Some(resume)).await;
    subscribe(&mut client).await;

    let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
        panic!("expected the delete replayed as a live patch");
    };
    assert_eq!(live.cursor, cursor_of(&events[1]));
    applier
        .apply_diffset(&live.patchset_zstd, &mut replica)
        .expect("apply tombstone patch");
    expect_idle(&mut client).await;

    assert!(
        orders(&mut replica).is_empty(),
        "the replayed delete dropped the row from the replica",
    );

    client.close().await.expect("close client");
    server.await.expect("join server");
}
