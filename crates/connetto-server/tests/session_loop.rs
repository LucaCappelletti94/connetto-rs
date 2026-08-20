//! Session-layer end-to-end tests.
//!
//! Exercises the full session conversation over a real [`Transport`]: handshake,
//! subscribe with snapshot delivery, live CDC delivery, keepalive, flow-control
//! backpressure and resume, and unsubscribe. The loopback test covers the whole
//! matrix; the WebSocket test proves the same spine over a real localhost socket.

#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{
    AckCredits, BulkMessage, ControlMessage, Handshake, Ping, Subscribe, SubscriptionSpec,
    Unsubscribe,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    Materializer, RequestGuard, SessionConfig, SessionManager, Snapshot, SnapshotSource,
    WebSocketTransport, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};
use diesel::prelude::*;
use diesel::sql_query;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use subql::backend::Postgres;
use subql::visibility::VisibilityPolicy;
use subql::{CdcSource, PgSqliteEmuSource};
use tokio::net::{TcpListener, TcpStream};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";

/// A snapshot source that returns one seed row, standing in for the rows the
/// Connector will fetch from Postgres in Phase 4.
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
    /// Row from the orders test fixture.
    orders (id) {
        /// Order identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Unit price.
        price -> diesel::sql_types::Double,
        /// Number of units.
        quantity -> diesel::sql_types::BigInt,
        /// Order status.
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

/// Insert `sql` into the emulated backend and route every resulting CDC event
/// to the sessions through the manager.
async fn drive_cdc<S, A>(
    source: &mut PgSqliteEmuSource,
    manager: &SessionManager<S, A, ConnettoWatermark>,
    sql: &str,
) where
    S: SnapshotSource,
    A: VisibilityPolicy<Watcher = std::sync::Arc<connetto_core::Principal>, Backend = Postgres>,
    A::Error: core::fmt::Display,
{
    source.execute_sql(sql).expect("execute dml");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_session_full_lifecycle() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let config = SessionConfig::new().with_initial_credits(1);
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        RosterAuth::granting("client-a").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        config,
    );

    // A separate catalog-driven applier standing in for the client's local store.
    let applier = Materializer::new(PG_DDL).expect("build client applier");
    let mut replica = client_replica();

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));

    // Handshake.
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "client-a")
                .with_grant(connetto_core::messages::Grant::new("user:client-a")),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(ack) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };
    assert_eq!(
        ack.initial_credits, 1,
        "server granted the configured credits"
    );

    // Subscribe: snapshot begin, patch, end (the patch spends the one credit).
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM orders WHERE quantity > 0"),
        }))
        .await
        .expect("send subscribe");
    let ControlMessage::SnapshotBegin(begin) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    assert_eq!(begin.sub_id, "orders");
    let BulkMessage::SnapshotPatch(snapshot) = next_bulk(&mut client).await else {
        panic!("expected snapshot patch");
    };
    assert_eq!(snapshot.sub_id, "orders");
    applier
        .apply_diffset(&snapshot.patchset_zstd, &mut replica)
        .expect("apply snapshot");
    let ControlMessage::SnapshotEnd(end) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };
    assert_eq!(end.sub_id, "orders");
    assert_eq!(orders(&mut replica), vec![order(1, 1.0, 3, "seed")]);

    // Keepalive still works with the credit window exhausted (control is never gated).
    client
        .send_control(ControlMessage::Ping(Ping { nonce: 42 }))
        .await
        .expect("send ping");
    let ControlMessage::Pong(pong) = next_control(&mut client).await else {
        panic!("expected pong");
    };
    assert_eq!(pong.nonce, 42);

    // A matching CDC insert is queued, not delivered, while credits are zero.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    drive_cdc(
        &mut source,
        &manager,
        "INSERT INTO orders (id, price, quantity, status) VALUES (7, 9.5, 5, 'paid')",
    )
    .await;
    expect_idle(&mut client).await;

    // Replenishing credits releases the queued live patch.
    client
        .send_control(ControlMessage::AckCredits(AckCredits { credits: 4 }))
        .await
        .expect("send ack credits");
    let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
        panic!("expected live patch");
    };
    assert_eq!(live.sub_id, "orders");
    applier
        .apply_diffset(&live.patchset_zstd, &mut replica)
        .expect("apply live patch");
    assert_eq!(
        orders(&mut replica),
        vec![order(1, 1.0, 3, "seed"), order(7, 9.5, 5, "paid")]
    );

    // 3 credits remain after the id=7 patch consumed one. The withheld row
    // travels the change path but the policy suppresses it. Credits are open,
    // so absence proves the policy, not credit starvation.
    drive_cdc(
        &mut source,
        &manager,
        &format!("INSERT INTO orders (id, price, quantity, status) VALUES ({WITHHELD_ID}, 1.0, 1, 'withheld')"),
    )
    .await;
    expect_idle(&mut client).await;

    // Unsubscribe, then confirm no further delivery for that subscription.
    client
        .send_control(ControlMessage::Unsubscribe(Unsubscribe {
            sub_id: "orders".to_owned(),
        }))
        .await
        .expect("send unsubscribe");
    // Round-trip a ping so the unsubscribe is processed before the next event.
    client
        .send_control(ControlMessage::Ping(Ping { nonce: 7 }))
        .await
        .expect("send ping");
    let ControlMessage::Pong(_) = next_control(&mut client).await else {
        panic!("expected pong");
    };
    drive_cdc(
        &mut source,
        &manager,
        "INSERT INTO orders (id, price, quantity, status) VALUES (9, 2.0, 1, 'later')",
    )
    .await;
    expect_idle(&mut client).await;

    // Closing the client ends the session task cleanly.
    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_session_delivers_snapshot_and_live_patch() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        RosterAuth::granting("client-ws").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let applier = Materializer::new(PG_DDL).expect("build client applier");
    let mut replica = client_replica();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_manager = manager.clone();
    let server = tokio::spawn(async move {
        let (tcp, _peer) = listener.accept().await.expect("accept");
        let transport = WebSocketTransport::accept(tcp).await.expect("ws accept");
        server_manager
            .serve(transport)
            .await
            .expect("serve session");
    });

    let tcp = TcpStream::connect(addr).await.expect("connect");
    let mut client = WebSocketTransport::connect(&format!("ws://{addr}/"), tcp)
        .await
        .expect("ws connect");

    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "client-ws")
                .with_grant(connetto_core::messages::Grant::new("user:client-ws")),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM orders WHERE quantity > 0"),
        }))
        .await
        .expect("send subscribe");
    let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    let BulkMessage::SnapshotPatch(snapshot) = next_bulk(&mut client).await else {
        panic!("expected snapshot patch");
    };
    applier
        .apply_diffset(&snapshot.patchset_zstd, &mut replica)
        .expect("apply snapshot");
    let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };
    assert_eq!(orders(&mut replica), vec![order(1, 1.0, 3, "seed")]);

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    drive_cdc(
        &mut source,
        &manager,
        "INSERT INTO orders (id, price, quantity, status) VALUES (7, 9.5, 5, 'paid')",
    )
    .await;
    let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
        panic!("expected live patch");
    };
    applier
        .apply_diffset(&live.patchset_zstd, &mut replica)
        .expect("apply live patch");
    assert_eq!(
        orders(&mut replica),
        vec![order(1, 1.0, 3, "seed"), order(7, 9.5, 5, "paid")]
    );

    // The withheld row travels the change path but the policy suppresses it.
    // quantity=1 matches the subscription predicate, so absence proves the policy.
    drive_cdc(
        &mut source,
        &manager,
        &format!("INSERT INTO orders (id, price, quantity, status) VALUES ({WITHHELD_ID}, 1.0, 1, 'withheld')"),
    )
    .await;
    expect_idle(&mut client).await;

    client.close().await.expect("close client");
    server.await.expect("join server");
}

// ── Composite-key table fixtures ─────────────────────────────────────────────

const READINGS_PG_DDL: &str = "CREATE TABLE readings (\
    tenant_id INT NOT NULL, \
    reading_id INT NOT NULL, \
    quantity BIGINT NOT NULL, \
    PRIMARY KEY (tenant_id, reading_id)\
);";

const READINGS_SQLITE_DDL: &str = "CREATE TABLE readings (\
    tenant_id INTEGER NOT NULL, \
    reading_id INTEGER NOT NULL, \
    quantity INTEGER NOT NULL, \
    PRIMARY KEY (tenant_id, reading_id)\
);";

/// Snapshot source seeding two rows that share `tenant_id` 7 and differ on
/// `reading_id`.
///
/// Two rows sharing the first key column is the minimum that lets a live update
/// or delete of one of them assert the other was left alone, which is the whole
/// difference between a two-column key and its first column.
struct SeedReadings;

impl SnapshotSource for SeedReadings {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::Principal,
    ) -> Result<Snapshot, Self::Error> {
        let table = SimpleTable::new(
            "readings",
            &["tenant_id", "reading_id", "quantity"],
            &[0, 1],
        );
        let row1 = Insert::<_, String, Vec<u8>>::from(table.clone())
            .set(0, Value::Integer(7))
            .expect("set tenant_id")
            .set(1, Value::Integer(1))
            .expect("set reading_id")
            .set(2, Value::Integer(100))
            .expect("set quantity");
        let row2 = Insert::<_, String, Vec<u8>>::from(table)
            .set(0, Value::Integer(7))
            .expect("set tenant_id")
            .set(1, Value::Integer(2))
            .expect("set reading_id")
            .set(2, Value::Integer(200))
            .expect("set quantity");
        let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new()
            .insert(row1)
            .insert(row2)
            .build();
        Ok(Snapshot {
            patchset,
            cursor: Cursor::new(Vec::new()),
        })
    }
}

diesel::table! {
    /// Row from the readings composite-key test fixture.
    readings (tenant_id, reading_id) {
        /// Tenant partition, first key column.
        tenant_id -> diesel::sql_types::BigInt,
        /// Reading identifier, second key column.
        reading_id -> diesel::sql_types::BigInt,
        /// Measured quantity.
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq)]
#[diesel(table_name = readings)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Sample {
    tenant_id: i64,
    reading_id: i64,
    quantity: i64,
}

fn reading(tenant_id: i64, reading_id: i64, quantity: i64) -> Sample {
    Sample {
        tenant_id,
        reading_id,
        quantity,
    }
}

fn all_readings(conn: &mut SqliteConnection) -> Vec<Sample> {
    readings::table
        .order((readings::tenant_id, readings::reading_id))
        .select(Sample::as_select())
        .load(conn)
        .expect("read readings")
}

/// In-memory SQLite replica for the readings table.
///
/// Table DDL cannot be expressed through the diesel query DSL, so `sql_query`
/// is the sanctioned form here, mirroring `client_replica` above.
fn reading_replica() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(READINGS_SQLITE_DDL)
        .execute(&mut conn)
        .expect("create readings table");
    conn
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_session_composite_key_sync() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(READINGS_PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedReadings,
        RosterAuth::granting("client-ck"),
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), READINGS_PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let applier = Materializer::new(READINGS_PG_DDL).expect("build client applier");
    let mut replica = reading_replica();

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));

    // Handshake.
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "client-ck")
                .with_grant(connetto_core::messages::Grant::new("user:client-ck")),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    // Subscribe: snapshot delivers both seed rows.
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "readings".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM readings"),
        }))
        .await
        .expect("send subscribe");
    let ControlMessage::SnapshotBegin(begin) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    assert_eq!(begin.sub_id, "readings");
    let BulkMessage::SnapshotPatch(snapshot) = next_bulk(&mut client).await else {
        panic!("expected snapshot patch");
    };
    applier
        .apply_diffset(&snapshot.patchset_zstd, &mut replica)
        .expect("apply snapshot");
    let ControlMessage::SnapshotEnd(end) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };
    assert_eq!(end.sub_id, "readings");
    assert_eq!(
        all_readings(&mut replica),
        vec![reading(7, 1, 100), reading(7, 2, 200)],
        "snapshot delivered both seed rows"
    );

    // The emu CDC source is an independent in-memory SQLite; it knows nothing
    // about rows the snapshot source seeded. Insert fresh rows (7,3) and (7,4)
    // so the emu source can track them for UPDATE and DELETE events, and to
    // avoid a unique-violation when applying the live INSERT on top of the
    // snapshot-seeded (7,1) and (7,2).
    let mut source = PgSqliteEmuSource::open_in_memory(READINGS_PG_DDL).expect("open emu source");
    drive_cdc(
        &mut source,
        &manager,
        "INSERT INTO readings (tenant_id, reading_id, quantity) VALUES (7, 3, 300)",
    )
    .await;
    let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
        panic!("expected live patch for insert of (7,3)");
    };
    applier
        .apply_diffset(&live.patchset_zstd, &mut replica)
        .expect("apply insert (7,3) live patch");
    drive_cdc(
        &mut source,
        &manager,
        "INSERT INTO readings (tenant_id, reading_id, quantity) VALUES (7, 4, 400)",
    )
    .await;
    let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
        panic!("expected live patch for insert of (7,4)");
    };
    applier
        .apply_diffset(&live.patchset_zstd, &mut replica)
        .expect("apply insert (7,4) live patch");

    // Update (7, 3) only. Sibling (7, 4) shares tenant_id=7 and must keep its
    // original quantity=400. A handler that matched on only the first key column
    // would update both (7,3) and (7,4), making (7,4).quantity != 400.
    drive_cdc(
        &mut source,
        &manager,
        "UPDATE readings SET quantity = 999 WHERE tenant_id = 7 AND reading_id = 3",
    )
    .await;
    let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
        panic!("expected live patch for update of (7,3)");
    };
    applier
        .apply_diffset(&live.patchset_zstd, &mut replica)
        .expect("apply update live patch");
    assert_eq!(
        all_readings(&mut replica),
        vec![
            reading(7, 1, 100),
            reading(7, 2, 200),
            reading(7, 3, 999),
            reading(7, 4, 400),
        ],
        "update to (7,3) changed its quantity and left sibling (7,4) untouched"
    );

    // Delete (7, 4) only. Sibling (7, 3) shares tenant_id=7 and must survive
    // with the updated quantity. A handler that matched on only the first key
    // column would delete both (7,3) and (7,4), failing the assertion.
    drive_cdc(
        &mut source,
        &manager,
        "DELETE FROM readings WHERE tenant_id = 7 AND reading_id = 4",
    )
    .await;
    let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
        panic!("expected live patch for delete of (7,4)");
    };
    applier
        .apply_diffset(&live.patchset_zstd, &mut replica)
        .expect("apply delete live patch");
    assert_eq!(
        all_readings(&mut replica),
        vec![reading(7, 1, 100), reading(7, 2, 200), reading(7, 3, 999)],
        "delete of (7,4) left sibling (7,3) intact"
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}
