//! Docker-free end-to-end loop: the real client against the real server.
//!
//! Runs a `connetto-server` in-process over a localhost WebSocket, backed by the
//! SQLite emulator standing in for Postgres CDC, and drives the real
//! `connetto-client` through it:
//!
//! 1. subscribe and apply the initial snapshot into the local replica;
//! 2. receive and apply a live insert driven through the emulator;
//! 3. write locally through the client's managed connection and `push`, and see
//!    the mutation land on the server's write target.
//!
//! Reads on both sides go through typed diesel queries; backend DML stays SQL.

#![allow(clippy::too_many_lines)]

use std::time::Duration;

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection};
use connetto_core::Cursor;
use connetto_server::{
    Materializer, PermissiveAuth, RuntimeWritableCatalog, SessionConfig, SessionManager, Snapshot,
    SnapshotSource, SqliteWriteTarget, WebSocketTransport, sqlite_write_target,
};
use diesel::prelude::*;
use diesel::sql_query;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use subql::{CdcSource, PgSqliteEmuSource};
use tokio::net::{TcpListener, TcpStream};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

/// A snapshot source returning one seed row, standing in for the rows a real
/// Connector would read from Postgres at snapshot time.
struct SeedSnapshot;

impl SnapshotSource for SeedSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
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

fn server_write_target() -> SqliteWriteTarget {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    sqlite_write_target(conn)
}

/// Pump the client until it observes an event matching `pred`, applying every
/// frame in between.
async fn pump_until(
    client: &mut ConnettoConnection<WebSocketTransport<TcpStream>>,
    pred: impl Fn(&ClientEvent) -> bool,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let event = tokio::time::timeout_at(deadline, client.pump_one())
            .await
            .expect("client pump timed out")
            .expect("client pump failed");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
        if pred(&event) {
            return;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_syncs_snapshot_live_and_uploads_a_mutation() {
    // Server: orders is writable so client mutations apply; snapshot seeds one row.
    let writable = RuntimeWritableCatalog::builder().writable("orders").build();
    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable).expect("build materializer");
    let target = server_write_target();
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        target.clone(),
        SessionConfig::default(),
    );

    // Serve one connection over a localhost WebSocket.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let serve_manager = manager.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let transport = WebSocketTransport::accept(stream).await.expect("ws accept");
        serve_manager.serve(transport).await.expect("session ok");
    });

    // Client: connect over the socket with a file-backed local replica.
    let db = tempfile::Builder::new()
        .suffix(".sqlite")
        .tempfile()
        .expect("temp db");
    let db_path = db.path().to_str().expect("utf8 path").to_owned();
    let stream = TcpStream::connect(addr).await.expect("connect");
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .expect("ws connect");
    let config = ClientConfig {
        client_id: "client-a".to_owned(),
        auth_token: "token".to_owned(),
    };
    let mut client = ConnettoConnection::connect(transport, &db_path, SQLITE_DDL, &config, None)
        .await
        .expect("client connect");

    // Subscribe and apply the initial snapshot.
    client.subscribe("orders", QUERY).await.expect("subscribe");
    pump_until(&mut client, |e| {
        matches!(e, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    assert_eq!(
        orders(client.conn()),
        vec![order(1, 1.0, 3, "seed")],
        "snapshot seed row reached the local replica",
    );

    // Drive a live insert through the emulator and apply it on the client.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (7, 9.5, 5, 'paid')")
        .expect("insert 7");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }
    pump_until(&mut client, |e| matches!(e, ClientEvent::LivePatch { .. })).await;
    assert_eq!(
        orders(client.conn()),
        vec![order(1, 1.0, 3, "seed"), order(7, 9.5, 5, "paid")],
        "live insert reached the local replica",
    );

    // Write locally through the managed connection; the session captures it.
    sql_query("INSERT INTO orders (id, price, quantity, status) VALUES (9, 2.0, 1, 'local')")
        .execute(client.conn())
        .expect("local insert");
    let seq = client
        .push()
        .await
        .expect("push")
        .expect("a mutation was sent");
    assert_eq!(seq, 0, "first mutation carries client_seq 0");

    // Barrier: the pong proves the server handled the mutation frames first.
    client.ping(1).await.expect("ping");
    pump_until(
        &mut client,
        |e| matches!(e, ClientEvent::Pong { nonce } if *nonce == 1),
    )
    .await;

    // The uploaded write landed on the server's write target.
    {
        let mut conn = target.lock();
        assert_eq!(
            orders(&mut conn),
            vec![order(9, 2.0, 1, "local")],
            "the client's local write was uploaded and applied on the server",
        );
    }
    // And it is present locally too.
    assert_eq!(
        orders(client.conn()),
        vec![
            order(1, 1.0, 3, "seed"),
            order(7, 9.5, 5, "paid"),
            order(9, 2.0, 1, "local"),
        ],
        "the local write is visible in the local replica",
    );

    client.close().await.expect("close");
    server.await.expect("join server");
}

/// Drive `next_event` until an event matches `pred`, accumulating every table
/// name reported changed along the way.
async fn step_until(
    client: &mut ConnettoConnection<WebSocketTransport<TcpStream>>,
    pred: impl Fn(&ClientEvent) -> bool,
) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut changed = Vec::new();
    loop {
        let step = tokio::time::timeout_at(deadline, client.next_event())
            .await
            .expect("client step timed out")
            .expect("client step failed");
        assert_ne!(step.event, ClientEvent::Closed, "connection closed early");
        changed.extend(step.changed_tables);
        if pred(&step.event) {
            return changed;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_autosubmits_writes_and_reports_changed_tables() {
    // Same wiring as the primary test: orders is writable, the snapshot seeds one
    // row.
    let writable = RuntimeWritableCatalog::builder().writable("orders").build();
    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable).expect("build materializer");
    let target = server_write_target();
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        target.clone(),
        SessionConfig::default(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let serve_manager = manager.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let transport = WebSocketTransport::accept(stream).await.expect("ws accept");
        serve_manager.serve(transport).await.expect("session ok");
    });

    let db = tempfile::Builder::new()
        .suffix(".sqlite")
        .tempfile()
        .expect("temp db");
    let db_path = db.path().to_str().expect("utf8 path").to_owned();
    let stream = TcpStream::connect(addr).await.expect("connect");
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .expect("ws connect");
    let config = ClientConfig {
        client_id: "client-a".to_owned(),
        auth_token: "token".to_owned(),
    };
    let mut client = ConnettoConnection::connect(transport, &db_path, SQLITE_DDL, &config, None)
        .await
        .expect("client connect");

    // The snapshot arrives through next_event, which reports the changed table.
    client.subscribe("orders", QUERY).await.expect("subscribe");
    let changed = step_until(&mut client, |e| {
        matches!(e, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    assert!(
        changed.iter().any(|t| t == "orders"),
        "snapshot apply reports orders as changed",
    );
    assert_eq!(orders(client.conn()), vec![order(1, 1.0, 3, "seed")]);

    // A live insert is applied and reported through next_event.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (7, 9.5, 5, 'paid')")
        .expect("insert 7");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }
    let changed = step_until(&mut client, |e| matches!(e, ClientEvent::LivePatch { .. })).await;
    assert!(
        changed.iter().any(|t| t == "orders"),
        "live insert reports orders as changed",
    );
    assert_eq!(
        orders(client.conn()),
        vec![order(1, 1.0, 3, "seed"), order(7, 9.5, 5, "paid")],
    );

    // Auto-submit: write locally without an explicit push. The next loop step
    // flushes it (uploading to the server) while applying the queued live patch.
    sql_query("INSERT INTO orders (id, price, quantity, status) VALUES (9, 2.0, 1, 'local')")
        .execute(client.conn())
        .expect("local insert");
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (8, 4.0, 2, 'more')")
        .expect("insert 8");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }
    step_until(&mut client, |e| matches!(e, ClientEvent::LivePatch { .. })).await;

    // Barrier: the pong proves the server handled the auto-submitted mutation.
    client.ping(1).await.expect("ping");
    step_until(
        &mut client,
        |e| matches!(e, ClientEvent::Pong { nonce } if *nonce == 1),
    )
    .await;

    // The local write reached the server's write target without a push() call.
    {
        let mut conn = target.lock();
        assert_eq!(
            orders(&mut conn),
            vec![order(9, 2.0, 1, "local")],
            "the local write auto-submitted through next_event",
        );
    }
    assert_eq!(
        orders(client.conn()),
        vec![
            order(1, 1.0, 3, "seed"),
            order(7, 9.5, 5, "paid"),
            order(8, 4.0, 2, "more"),
            order(9, 2.0, 1, "local"),
        ],
    );

    client.close().await.expect("close");
    server.await.expect("join server");
}
