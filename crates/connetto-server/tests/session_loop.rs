//! Session-layer end-to-end tests.
//!
//! Exercises the full session conversation over a real [`Transport`]: handshake,
//! subscribe with snapshot delivery, live CDC delivery, keepalive, flow-control
//! backpressure and resume, and unsubscribe. The loopback test covers the whole
//! matrix; the WebSocket test proves the same spine over a real localhost socket.

#![allow(clippy::too_many_lines)]

use std::time::Duration;

use connetto_core::messages::{
    AckCredits, BulkMessage, ControlMessage, Handshake, Ping, Subscribe, SubscriptionSpec,
    Unsubscribe,
};
use connetto_core::traits::{AuthPolicy, IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    Materializer, PermissiveAuth, SessionConfig, SessionManager, Snapshot, SnapshotSource,
    WebSocketTransport, loopback, pg_write_target,
};
use connetto_test_harness::Fixture;
use diesel::prelude::*;
use diesel::sql_query;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
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
        _auth: &connetto_core::AuthContext,
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

/// Insert `sql` into the emulated backend and route every resulting CDC event
/// to the sessions through the manager.
async fn drive_cdc<S: SnapshotSource, A: AuthPolicy + Send + Sync>(
    source: &mut PgSqliteEmuSource,
    manager: &SessionManager<S, A>,
    sql: &str,
) {
    source.execute_sql(sql).expect("execute dml");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn loopback_session_full_lifecycle() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let config = SessionConfig {
        initial_credits: 1,
        ..SessionConfig::default()
    };
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        pg_write_target(fixture.admin().clone(), PG_DDL).expect("build write target"),
        config,
    );

    // A separate catalog-driven applier standing in for the client's local store.
    let applier = Materializer::new(PG_DDL).expect("build client applier");
    let mut replica = client_replica();

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));

    // Handshake.
    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "client-a",
            "token",
        )))
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
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn websocket_session_delivers_snapshot_and_live_patch() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        pg_write_target(fixture.admin().clone(), PG_DDL).expect("build write target"),
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
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "client-ws",
            "token",
        )))
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

    client.close().await.expect("close client");
    server.await.expect("join server");
}
