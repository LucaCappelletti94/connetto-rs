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

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use connetto_client::{
    AffectedRow, ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, KeyValue,
    LiveQuery, Replica, Watchable,
};
use connetto_core::Cursor;
use connetto_server::{
    Materializer, Oplog, PermissiveAuth, RuntimeWritableCatalog, SessionConfig, SessionManager,
    Snapshot, SnapshotSource, WebSocketTransport, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture};
use diesel::prelude::*;
use diesel::sql_query;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use subql::backend::{Postgres, ScalarKind, Value as PgValue};
use subql::reexec::{AsyncConnector, ScalarRowError, Snapshot as ConnectorRead};
use subql::{CdcSource, PgLsn, PgSqliteEmuSource};
use tokio::net::{TcpListener, TcpStream};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

/// The one-row `orders` seed snapshot both snapshot sources serve, so a
/// recording source and the plain seed stay byte-identical.
fn seed_snapshot() -> Snapshot {
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
    Snapshot {
        patchset,
        cursor: Cursor::new(Vec::new()),
    }
}

/// A snapshot source returning one seed row, standing in for the rows a real
/// Connector would read from Postgres at snapshot time.
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
        Ok(seed_snapshot())
    }
}

/// A snapshot source that serves the one-row seed and records every
/// subscription's `select_sql`, so a test can count how many distinct wire
/// subscriptions actually reached the server.
#[derive(Clone)]
struct RecordingSeed {
    seen: Arc<Mutex<Vec<String>>>,
}

impl SnapshotSource for RecordingSeed {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::AuthContext,
    ) -> Result<Snapshot, Self::Error> {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(select_sql.to_owned());
        }
        Ok(seed_snapshot())
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

diesel::table! {
    metrics (id) {
        id -> diesel::sql_types::BigInt,
        seen -> diesel::sql_types::Timestamp,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
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

// A second synced table exercising strongly typed, non-trivial columns through
// watch_fn: a `rosetta_uuid::Uuid` primary key (stored as a SQLite BLOB, the
// same client-authored key strategy the demos use) and a `bool` flag. The
// materializer and emulator see `BYTEA` (which pg2sqlite maps to BLOB, wire
// identical to a real `uuid` column) and `BOOLEAN`; the client replica stores
// BLOB and INTEGER.
const GADGETS_PG_DDL: &str =
    "CREATE TABLE gadgets (id BYTEA PRIMARY KEY, active BOOLEAN NOT NULL, label TEXT NOT NULL);";
const GADGETS_SQLITE_DDL: &str = "CREATE TABLE gadgets (id BLOB PRIMARY KEY NOT NULL, active \
                                  INTEGER NOT NULL, label TEXT NOT NULL);";

diesel::table! {
    gadgets (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        active -> diesel::sql_types::Bool,
        label -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = gadgets)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Gadget {
    id: rosetta_uuid::Uuid,
    active: bool,
    label: String,
}

fn gadget(id: rosetta_uuid::Uuid, active: bool, label: &str) -> Gadget {
    Gadget {
        id,
        active,
        label: label.to_owned(),
    }
}

/// A snapshot source serving a fixed set of typed `gadgets` rows, so the
/// rich-type `watch_fn` test starts from a known replica. Each row's uuid key is
/// encoded to its 16-byte blob and the bool to 0 or 1, the exact wire shapes a
/// real Postgres `uuid` and `boolean` column emit.
struct GadgetSeed {
    rows: Vec<Gadget>,
}

impl SnapshotSource for GadgetSeed {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::AuthContext,
    ) -> Result<Snapshot, Self::Error> {
        let mut patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new();
        for row in &self.rows {
            let table = SimpleTable::new("gadgets", &["id", "active", "label"], &[0]);
            let insert = Insert::<_, String, Vec<u8>>::from(table)
                .set(0, Value::Blob(<[u8; 16]>::from(row.id).to_vec()))
                .expect("set id")
                .set(1, Value::Integer(i64::from(row.active)))
                .expect("set active")
                .set(2, Value::Text(row.label.clone()))
                .expect("set label");
            patchset = patchset.insert(insert);
        }
        Ok(Snapshot {
            patchset: patchset.build(),
            cursor: Cursor::new(Vec::new()),
        })
    }
}

fn gadgets_write_target(fixture: &Fixture) -> connetto_server::PgWriteTarget<ConnettoWatermark> {
    pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), GADGETS_PG_DDL)
        .expect("build write target")
}

fn server_write_target(fixture: &Fixture) -> connetto_server::PgWriteTarget<ConnettoWatermark> {
    pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target")
}

/// A Postgres write target seeded with one `orders` row at `status`, standing in
/// for a server whose version already moved past the client's snapshot basis.
async fn seeded_orders_target(
    fixture: &Fixture,
    status: &str,
) -> connetto_server::PgWriteTarget<ConnettoWatermark> {
    reset_orders(fixture).await;
    let mut conn = fixture.admin().get().await.expect("admin connection");
    diesel_async::RunQueryDsl::execute(
        diesel::insert_into(pg_orders::orders::table).values((
            pg_orders::orders::id.eq(1_i32),
            pg_orders::orders::price.eq(1.0_f64),
            pg_orders::orders::quantity.eq(3_i32),
            pg_orders::orders::status.eq(status),
        )),
        &mut *conn,
    )
    .await
    .expect("seed order");
    pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target")
}

// The server write target schema (Postgres): INT maps to Integer (i32),
// narrower than the client replica's BigInt.
mod pg_orders {
    diesel::table! {
        orders (id) {
            id -> diesel::sql_types::Integer,
            price -> diesel::sql_types::Double,
            quantity -> diesel::sql_types::Integer,
            status -> diesel::sql_types::Text,
        }
    }
}

/// Reset the fixture to a fresh `orders` table with the watermark provisioned.
async fn reset_orders(fixture: &Fixture) {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS orders CASCADE",
            "DROP TABLE IF EXISTS _connetto_mutations",
            "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT)",
        ])
        .await;
    connetto_test_harness::provision_watermark(fixture.admin()).await;
}

/// The server target's orders, read as admin, mapped to the client `Order`.
async fn server_orders(fixture: &Fixture) -> Vec<Order> {
    let mut conn = fixture.admin().get().await.expect("admin connection");
    let query = pg_orders::orders::table
        .order(pg_orders::orders::id)
        .select((
            pg_orders::orders::id,
            pg_orders::orders::price,
            pg_orders::orders::quantity,
            pg_orders::orders::status,
        ));
    let rows: Vec<(i32, f64, i32, String)> = diesel_async::RunQueryDsl::load(query, &mut *conn)
        .await
        .expect("read server orders");
    rows.into_iter()
        .map(|(id, price, quantity, status)| {
            order(i64::from(id), price, i64::from(quantity), &status)
        })
        .collect()
}

/// Pump the client until it observes an event matching `pred`, applying every
/// frame in between.
async fn pump_until(
    client: &mut ConnettoConnection<WebSocketTransport<TcpStream>>,
    pred: impl Fn(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let event = tokio::time::timeout_at(deadline, client.pump_one())
            .await
            .expect("client pump timed out")
            .expect("client pump failed");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
        if pred(&event) {
            return event;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn client_syncs_snapshot_live_and_uploads_a_mutation() {
    let fixture = Fixture::acquire().await;
    reset_orders(&fixture).await;
    // Server: orders is writable so client mutations apply; snapshot seeds one row.
    let writable = RuntimeWritableCatalog::builder().writable("orders").build();
    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        server_write_target(&fixture),
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
        schema_version: None,
        sql_functions: connetto_client::SqlFunctions::new(),
    };
    let mut client = ConnettoConnection::connect(
        transport,
        &Replica::EncryptedFile {
            path: &db_path,
            key: connetto_core::test_support::replica_key(),
        },
        SQLITE_DDL,
        &config,
        None,
    )
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
    assert_eq!(
        server_orders(&fixture).await,
        vec![order(9, 2.0, 1, "local")],
        "the client's local write was uploaded and applied on the server",
    );
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
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn connection_autosubmits_writes_and_reports_changed_tables() {
    let fixture = Fixture::acquire().await;
    reset_orders(&fixture).await;
    // Same wiring as the primary test: orders is writable, the snapshot seeds one
    // row.
    let writable = RuntimeWritableCatalog::builder().writable("orders").build();
    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        server_write_target(&fixture),
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
        schema_version: None,
        sql_functions: connetto_client::SqlFunctions::new(),
    };
    let mut client = ConnettoConnection::connect(
        transport,
        &Replica::EncryptedFile {
            path: &db_path,
            key: connetto_core::test_support::replica_key(),
        },
        SQLITE_DDL,
        &config,
        None,
    )
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
    assert_eq!(
        server_orders(&fixture).await,
        vec![order(9, 2.0, 1, "local")],
        "the local write auto-submitted through next_event",
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn connection_is_a_diesel_connection() {
    let fixture = Fixture::acquire().await;
    reset_orders(&fixture).await;
    // orders is writable so the client mutation applies. No subscription is
    // needed: this exercises the diesel Connection impl and auto-submit.
    let writable = RuntimeWritableCatalog::builder().writable("orders").build();
    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        server_write_target(&fixture),
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
        schema_version: None,
        sql_functions: connetto_client::SqlFunctions::new(),
    };
    let mut client = ConnettoConnection::connect(
        transport,
        &Replica::EncryptedFile {
            path: &db_path,
            key: connetto_core::test_support::replica_key(),
        },
        SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("client connect");

    // Write through the diesel Connection impl: a typed insert runs on
    // `&mut client` directly, with no `.conn()` and no manual push.
    diesel::insert_into(orders::table)
        .values((
            orders::id.eq(15_i64),
            orders::price.eq(3.5_f64),
            orders::quantity.eq(2_i64),
            orders::status.eq("typed"),
        ))
        .execute(&mut client)
        .expect("typed insert through the connection");

    // Read back through the LoadConnection impl on `&mut client`.
    assert_eq!(
        orders::table
            .order(orders::id)
            .select(Order::as_select())
            .load::<Order>(&mut client)
            .expect("typed load"),
        vec![order(15, 3.5, 2, "typed")],
        "the typed write is visible through a typed load on the connection",
    );

    // The commit hook marked the write dirty; flush auto-submits it.
    let seq = client
        .flush()
        .await
        .expect("flush")
        .expect("a mutation was auto-submitted");
    assert_eq!(seq, 0, "first auto-submitted mutation carries client_seq 0");

    // Barrier: the pong proves the server handled the mutation.
    client.ping(1).await.expect("ping");
    pump_until(
        &mut client,
        |e| matches!(e, ClientEvent::Pong { nonce } if *nonce == 1),
    )
    .await;

    // The write reached the server's write target through the diesel connection.
    assert_eq!(
        server_orders(&fixture).await,
        vec![order(15, 3.5, 2, "typed")],
        "the typed write auto-submitted to the server",
    );

    client.close().await.expect("close");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn rejected_write_rolls_back_locally() {
    let fixture = Fixture::acquire().await;
    // A materializer with no writable tables rejects every client mutation, so
    // the optimistic local write must be undone when the reject arrives.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let target = server_write_target(&fixture);
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        target,
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
        schema_version: None,
        sql_functions: connetto_client::SqlFunctions::new(),
    };
    let mut client = ConnettoConnection::connect(
        transport,
        &Replica::EncryptedFile {
            path: &db_path,
            key: connetto_core::test_support::replica_key(),
        },
        SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("client connect");

    // Optimistic local write through the connection.
    diesel::insert_into(orders::table)
        .values((
            orders::id.eq(99_i64),
            orders::price.eq(1.0_f64),
            orders::quantity.eq(1_i64),
            orders::status.eq("nope"),
        ))
        .execute(&mut client)
        .expect("optimistic insert");
    assert_eq!(
        orders::table
            .order(orders::id)
            .select(Order::as_select())
            .load::<Order>(&mut client)
            .expect("load"),
        vec![order(99, 1.0, 1, "nope")],
        "the optimistic write is visible locally before the server responds",
    );

    // Auto-submit, then pump the rejection. Handling the reject rolls it back.
    client
        .flush()
        .await
        .expect("flush")
        .expect("a mutation was submitted");
    let event = pump_until(&mut client, |e| {
        matches!(e, ClientEvent::MutationRejected { .. })
    })
    .await;
    assert_eq!(
        event,
        ClientEvent::MutationRejected {
            client_seq: 0,
            rows: vec![AffectedRow {
                table: "orders".to_owned(),
                key: vec![KeyValue::Int(99)],
            }],
        },
        "the reject event names the rolled-back row by table and primary key",
    );

    // The server-rejected write was undone on the client.
    assert_eq!(
        orders::table
            .order(orders::id)
            .select(Order::as_select())
            .load::<Order>(&mut client)
            .expect("load"),
        Vec::<Order>::new(),
        "the rejected write was rolled back locally",
    );

    client.close().await.expect("close");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn conflicting_write_rolls_back_and_reports_keys() {
    let fixture = Fixture::acquire().await;
    // orders.status is the declared version column. The snapshot seeds the
    // client at status "seed", but the server row already moved to "server", so
    // the client's update carries a stale basis and the server reports a
    // conflict rather than applying it.
    let writable = RuntimeWritableCatalog::builder()
        .versioned("orders", "status")
        .build();
    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable).expect("build materializer");
    let target = seeded_orders_target(&fixture, "server").await;
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        target,
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
        schema_version: None,
        sql_functions: connetto_client::SqlFunctions::new(),
    };
    let mut client = ConnettoConnection::connect(
        transport,
        &Replica::EncryptedFile {
            path: &db_path,
            key: connetto_core::test_support::replica_key(),
        },
        SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("client connect");

    // Sync the seed row so the client has a local (stale) basis to update from.
    client.subscribe("orders", QUERY).await.expect("subscribe");
    pump_until(&mut client, |e| {
        matches!(e, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    assert_eq!(
        orders(client.conn()),
        vec![order(1, 1.0, 3, "seed")],
        "the snapshot seeded the client at the stale version",
    );

    // Optimistic update bumps the version column; its old image "seed" is stale.
    diesel::update(orders::table.find(1_i64))
        .set(orders::status.eq("mine"))
        .execute(&mut client)
        .expect("optimistic update");
    client
        .flush()
        .await
        .expect("flush")
        .expect("a mutation was submitted");

    let event = pump_until(&mut client, |e| {
        matches!(e, ClientEvent::MutationConflict { .. })
    })
    .await;
    assert_eq!(
        event,
        ClientEvent::MutationConflict {
            client_seq: 0,
            rows: vec![AffectedRow {
                table: "orders".to_owned(),
                key: vec![KeyValue::Int(1)],
            }],
        },
        "the conflict event names the rolled-back row by table and primary key",
    );

    // The conflicting write was undone locally; the stale basis is restored and
    // the server row is left for the sync stream to converge.
    assert_eq!(
        orders(client.conn()),
        vec![order(1, 1.0, 3, "seed")],
        "the conflicting write was rolled back locally",
    );

    client.close().await.expect("close");
    server.await.expect("join server");
}

/// Connect one client over the socket with a fresh file-backed replica. The
/// caller owns `db_path` (its backing temp file must outlive the connection).
async fn connect_client(
    addr: std::net::SocketAddr,
    client_id: &str,
    db_path: &str,
) -> ConnettoConnection<WebSocketTransport<TcpStream>> {
    let stream = TcpStream::connect(addr).await.expect("connect");
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .expect("ws connect");
    let config = ClientConfig {
        client_id: client_id.to_owned(),
        auth_token: "token".to_owned(),
        schema_version: None,
        sql_functions: connetto_client::SqlFunctions::new(),
    };
    ConnettoConnection::connect(
        transport,
        &Replica::EncryptedFile {
            path: db_path,
            key: connetto_core::test_support::replica_key(),
        },
        SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("client connect")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn conflicting_write_converges_to_server_after_rollback() {
    let fixture = Fixture::acquire().await;
    // Two clients share one server. Client B lands an update that moves the
    // server row past client A's basis, so A's stale update conflicts and rolls
    // back. The concurrent change then arrives on the sync stream as a live
    // patch, converging A's local row to the server's authoritative value.
    let writable = RuntimeWritableCatalog::builder()
        .versioned("orders", "status")
        .build();
    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable).expect("build materializer");
    let target = seeded_orders_target(&fixture, "seed").await;
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        target,
        SessionConfig::default(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let accept_manager = manager.clone();
    let server = tokio::spawn(async move {
        let mut sessions = Vec::new();
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.expect("accept");
            let transport = WebSocketTransport::accept(stream).await.expect("ws accept");
            let session_manager = accept_manager.clone();
            sessions.push(tokio::spawn(async move {
                session_manager.serve(transport).await.expect("session ok");
            }));
        }
        for session in sessions {
            session.await.expect("join session");
        }
    });

    let db_a = tempfile::Builder::new()
        .suffix(".sqlite")
        .tempfile()
        .expect("temp db a");
    let db_b = tempfile::Builder::new()
        .suffix(".sqlite")
        .tempfile()
        .expect("temp db b");
    let path_a = db_a.path().to_str().expect("utf8 path").to_owned();
    let path_b = db_b.path().to_str().expect("utf8 path").to_owned();
    let mut client_a = connect_client(addr, "client-a", &path_a).await;
    let mut client_b = connect_client(addr, "client-b", &path_b).await;

    // Both clients sync the seed row (status "seed").
    client_a
        .subscribe("orders", QUERY)
        .await
        .expect("subscribe a");
    pump_until(&mut client_a, |e| {
        matches!(e, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    client_b
        .subscribe("orders", QUERY)
        .await
        .expect("subscribe b");
    pump_until(&mut client_b, |e| {
        matches!(e, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    assert_eq!(
        orders(client_a.conn()),
        vec![order(1, 1.0, 3, "seed")],
        "client A synced the seed row",
    );

    // Client B lands an update, moving the server row to "server". The barrier
    // pong proves the server applied it before client A writes.
    diesel::update(orders::table.find(1_i64))
        .set(orders::status.eq("server"))
        .execute(&mut client_b)
        .expect("B update");
    client_b
        .flush()
        .await
        .expect("flush B")
        .expect("B mutation submitted");
    client_b.ping(1).await.expect("ping B");
    pump_until(
        &mut client_b,
        |e| matches!(e, ClientEvent::Pong { nonce } if *nonce == 1),
    )
    .await;

    // Client A updates from its now-stale basis "seed"; the server conflicts and
    // A rolls the optimistic write back locally.
    diesel::update(orders::table.find(1_i64))
        .set(orders::status.eq("mine"))
        .execute(&mut client_a)
        .expect("A update");
    client_a
        .flush()
        .await
        .expect("flush A")
        .expect("A mutation submitted");
    pump_until(&mut client_a, |e| {
        matches!(e, ClientEvent::MutationConflict { .. })
    })
    .await;
    assert_eq!(
        orders(client_a.conn()),
        vec![order(1, 1.0, 3, "seed")],
        "A's conflicting write rolled back to the basis",
    );

    // The server re-delivers the authoritative row for the conflicted key over
    // the sync stream. The client applies it on the un-captured connection with
    // the server-wins resolver, upserting its stale local copy: the convergence
    // path a real CDC echo of the concurrent write takes.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql(
            "INSERT INTO orders (id, price, quantity, status) VALUES (1, 1.0, 3, 'server')",
        )
        .expect("emu authoritative row");
    while let Some(event) = source.next_event().await.expect("poll event") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }

    // A converges to the server's authoritative value.
    pump_until(&mut client_a, |e| {
        matches!(e, ClientEvent::LivePatch { .. })
    })
    .await;
    assert_eq!(
        orders(client_a.conn()),
        vec![order(1, 1.0, 3, "server")],
        "A converged to the server's authoritative row",
    );

    client_a.close().await.expect("close A");
    client_b.close().await.expect("close B");
    server.await.expect("join server");
}

/// An [`AsyncConnector`] that answers `execute_scalar` from a queue of canned
/// scalars (the MIN/MAX re-execution path) and `execute_scalar_row` from a
/// queue of canned component rows (the delta aggregate seed path), standing in
/// for the Postgres backend in the Docker-free aggregate loop.
struct QueuedConnector {
    responses: Mutex<VecDeque<PgValue<Postgres>>>,
    rows: Mutex<VecDeque<Vec<PgValue<Postgres>>>>,
}

impl QueuedConnector {
    fn new(responses: impl IntoIterator<Item = i64>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().map(PgValue::Int).collect()),
            rows: Mutex::new(VecDeque::new()),
        }
    }

    /// A connector serving canned scalar re-execution values of any type, one
    /// per `execute_scalar` call, in order. Drives a typed `live()` over a
    /// column whose SQL type is outside the integer family.
    fn with_scalars(responses: impl IntoIterator<Item = PgValue<Postgres>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            rows: Mutex::new(VecDeque::new()),
        }
    }

    /// A connector that only serves delta aggregate seeds, one canned component
    /// row per `execute_scalar_row` call, in order.
    fn with_rows(rows: impl IntoIterator<Item = Vec<PgValue<Postgres>>>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::new()),
            rows: Mutex::new(rows.into_iter().collect()),
        }
    }
}

#[allow(clippy::manual_async_fn)]
impl AsyncConnector for QueuedConnector {
    type AuthContext = ();
    type Error = std::io::Error;
    type Checkpoint = PgLsn;
    type Backend = Postgres;

    fn execute_scalar(
        &self,
        _sql: &str,
        _kind: ScalarKind,
        _auth: &(),
    ) -> impl core::future::Future<
        Output = Result<(PgValue<Postgres>, Option<PgLsn>), std::io::Error>,
    > + Send {
        let next = self.responses.lock().expect("queue poisoned").pop_front();
        async move {
            next.map(|value| (value, Some(PgLsn(1))))
                .ok_or_else(|| std::io::Error::other("no more canned responses"))
        }
    }

    fn execute_rows(
        &self,
        _sql: &str,
        _auth: &(),
    ) -> impl core::future::Future<
        Output = Result<ConnectorRead<Vec<Vec<PgValue<Postgres>>>, PgLsn>, std::io::Error>,
    > + Send {
        async {
            Err(std::io::Error::other(
                "execute_rows is not used in the aggregate loop test",
            ))
        }
    }

    fn execute_scalar_row(
        &self,
        _sql: &str,
        _kinds: &[ScalarKind],
        _auth: &(),
    ) -> impl core::future::Future<
        Output = Result<(Vec<PgValue<Postgres>>, Option<PgLsn>), ScalarRowError<std::io::Error>>,
    > + Send {
        let next = self.rows.lock().expect("queue poisoned").pop_front();
        async move {
            next.map(|row| (row, Some(PgLsn(1)))).ok_or_else(|| {
                ScalarRowError::Connector(std::io::Error::other("no more canned rows"))
            })
        }
    }
}

/// Extract the JSON value from a `cheapest` aggregate event.
fn aggregate_result(event: ClientEvent) -> String {
    match event {
        ClientEvent::Aggregate {
            sub_id,
            result_json,
            ..
        } => {
            assert_eq!(sub_id, "cheapest");
            result_json
        }
        other => panic!("expected an aggregate event, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn aggregate_subscription_bootstraps_and_updates_through_the_client() {
    let fixture = Fixture::acquire().await;
    // The client subscribes to MIN(quantity). The server bootstraps the value
    // through the connector, folds a lower insert in-process, and re-executes
    // through the connector when the current extreme is deleted. Each value
    // reaches the client as a ClientEvent::Aggregate.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    // Bootstrap answers 3; the re-execution after the delete answers 9.
    let connector = QueuedConnector::new([3, 9]);
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::with_connector(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        connector,
        target,
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
    let mut client = connect_client(addr, "client-a", &db_path).await;

    // Subscribe to the scalar aggregate; the server bootstraps its value.
    client
        .subscribe("cheapest", "SELECT MIN(quantity) FROM orders")
        .await
        .expect("subscribe aggregate");
    let event = pump_until(&mut client, |e| matches!(e, ClientEvent::Aggregate { .. })).await;
    assert_eq!(
        aggregate_result(event),
        "3",
        "the bootstrap value reached the client",
    );

    // A lower value folds in-process, without consulting the connector.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (5, 1.0, 1, 'x')")
        .expect("emu insert");
    while let Some(event) = source.next_event().await.expect("poll event") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }
    let event = pump_until(&mut client, |e| matches!(e, ClientEvent::Aggregate { .. })).await;
    assert_eq!(
        aggregate_result(event),
        "1",
        "the in-process fold reached the client",
    );

    // Deleting the current extreme forces a re-execution through the connector.
    source
        .execute_sql("DELETE FROM orders WHERE id = 5")
        .expect("emu delete");
    while let Some(event) = source.next_event().await.expect("poll event") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }
    let event = pump_until(&mut client, |e| matches!(e, ClientEvent::Aggregate { .. })).await;
    assert_eq!(
        aggregate_result(event),
        "9",
        "the re-executed value reached the client",
    );

    client.close().await.expect("close");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn unsupported_subscription_is_rejected_without_closing() {
    let fixture = Fixture::acquire().await;
    // A query subql cannot register (a grouped aggregate) is refused at
    // registration and surfaces as a NonFatal event, not a dropped connection.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let target = server_write_target(&fixture);
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        target,
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
    let mut client = connect_client(addr, "client-a", &db_path).await;

    client
        .subscribe(
            "grouped",
            "SELECT status, COUNT(*) FROM orders GROUP BY status",
        )
        .await
        .expect("subscribe");
    let event = pump_until(&mut client, |e| matches!(e, ClientEvent::NonFatal { .. })).await;
    let ClientEvent::NonFatal { related_to, detail } = event else {
        unreachable!()
    };
    assert_eq!(related_to.as_deref(), Some("grouped"));
    assert!(
        detail.contains("subscription rejected"),
        "detail should explain the rejection, got {detail:?}",
    );

    // The session survives the rejection: a ping still round-trips.
    client.ping(7).await.expect("ping");
    pump_until(
        &mut client,
        |e| matches!(e, ClientEvent::Pong { nonce } if *nonce == 7),
    )
    .await;

    client.close().await.expect("close");
    server.await.expect("join server");
}

/// Drive the emulator to completion, dispatching every produced CDC event
/// through the manager so delta aggregates fold in-process.
async fn drain_events<S, C, O>(
    manager: &SessionManager<S, PermissiveAuth, ConnettoWatermark, C, O>,
    source: &mut PgSqliteEmuSource,
) where
    S: SnapshotSource,
    C: AsyncConnector<Backend = Postgres, Checkpoint = PgLsn, AuthContext = ()> + Send + Sync,
    C::Error: core::fmt::Display,
    O: Oplog,
{
    while let Some(event) = source.next_event().await.expect("poll event") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }
}

/// Pump the client until it has observed one aggregate value for each label in
/// `subs`, returning the latest `result_json` per label. Each dispatched CDC
/// event delivers exactly one update per subscribed aggregate, so one event (or
/// the bootstrap burst) yields exactly one value per label.
async fn collect_aggregates(
    client: &mut ConnettoConnection<WebSocketTransport<TcpStream>>,
    subs: &[&str],
) -> HashMap<String, String> {
    let mut seen: HashMap<String, String> = HashMap::new();
    while seen.len() < subs.len() {
        let event = pump_until(client, |e| matches!(e, ClientEvent::Aggregate { .. })).await;
        if let ClientEvent::Aggregate {
            sub_id,
            result_json,
            ..
        } = event
        {
            seen.insert(sub_id, result_json);
        }
    }
    seen
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn delta_aggregates_bootstrap_and_fold_through_the_client() {
    let fixture = Fixture::acquire().await;
    // The client subscribes to COUNT(*), SUM(quantity), and AVG(quantity) at
    // once. The server seeds each through the connector's multi-column row path,
    // then folds every CDC insert and delete in-process (no connector
    // round-trip per event) and delivers the running value to the client.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    // Seed rows in subscribe order over the empty table: COUNT(*)=0, SUM=NULL,
    // AVG=(NULL sum, 0 count).
    let connector = QueuedConnector::with_rows([
        vec![PgValue::Int(0)],
        vec![PgValue::Null],
        vec![PgValue::Null, PgValue::Int(0)],
    ]);
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::with_connector(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        connector,
        target,
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
    let mut client = connect_client(addr, "client-a", &db_path).await;

    client
        .subscribe("count", "SELECT COUNT(*) FROM orders")
        .await
        .expect("subscribe count");
    client
        .subscribe("sum", "SELECT SUM(quantity) FROM orders")
        .await
        .expect("subscribe sum");
    client
        .subscribe("avg", "SELECT AVG(quantity) FROM orders")
        .await
        .expect("subscribe avg");

    let subs = ["count", "sum", "avg"];
    let seeded = collect_aggregates(&mut client, &subs).await;
    assert_eq!(seeded["count"], "0", "COUNT(*) seed over empty table");
    assert_eq!(seeded["sum"], "0.0", "SUM seed over empty table");
    assert_eq!(
        seeded["avg"], "null",
        "AVG seed over empty table is undefined"
    );

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");

    // Insert quantity 10: COUNT 1, SUM 10, AVG 10.
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (1, 1.0, 10, 'x')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    let after_first = collect_aggregates(&mut client, &subs).await;
    assert_eq!(after_first["count"], "1");
    assert_eq!(after_first["sum"], "10.0");
    assert_eq!(after_first["avg"], "10.0");

    // Insert quantity 20: COUNT 2, SUM 30, AVG 15.
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (2, 1.0, 20, 'y')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    let after_second = collect_aggregates(&mut client, &subs).await;
    assert_eq!(after_second["count"], "2");
    assert_eq!(after_second["sum"], "30.0");
    assert_eq!(after_second["avg"], "15.0");

    // Delete quantity 10: COUNT 1, SUM 20, AVG 20.
    source
        .execute_sql("DELETE FROM orders WHERE id = 1")
        .expect("emu delete");
    drain_events(&manager, &mut source).await;
    let after_delete = collect_aggregates(&mut client, &subs).await;
    assert_eq!(after_delete["count"], "1");
    assert_eq!(after_delete["sum"], "20.0");
    assert_eq!(after_delete["avg"], "20.0");

    client.close().await.expect("close");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn aggregate_on_rls_table_is_rejected_without_closing() {
    // subql rejects an aggregator on an RLS-protected table at registration.
    // connetto surfaces that as a NonFatal event, leaving the session intact.
    const RLS_DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, \
         status TEXT); ALTER TABLE orders ENABLE ROW LEVEL SECURITY;";
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(RLS_DDL).expect("build materializer");
    let target = server_write_target(&fixture);
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        target,
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
    let mut client = connect_client(addr, "client-a", &db_path).await;

    client
        .subscribe("total", "SELECT COUNT(*) FROM orders")
        .await
        .expect("subscribe");
    let event = pump_until(&mut client, |e| matches!(e, ClientEvent::NonFatal { .. })).await;
    let ClientEvent::NonFatal { related_to, detail } = event else {
        unreachable!()
    };
    assert_eq!(related_to.as_deref(), Some("total"));
    assert!(
        detail.contains("subscription rejected"),
        "detail should explain the rejection, got {detail:?}",
    );
    assert!(
        detail.contains("RLS-protected"),
        "detail should name the RLS cause, got {detail:?}",
    );

    // The session survives the rejection: a ping still round-trips.
    client.ping(9).await.expect("ping");
    pump_until(
        &mut client,
        |e| matches!(e, ClientEvent::Pong { nonce } if *nonce == 9),
    )
    .await;

    client.close().await.expect("close");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn delta_aggregate_bootstrap_failure_is_nonfatal() {
    let fixture = Fixture::acquire().await;
    // A valid COUNT(*) registers as a delta aggregate, but this manager has no
    // connector able to run the multi-column seed (NoConnector's
    // execute_scalar_row is the trait default that rejects every seed). The
    // failed bootstrap unregisters the subscription and surfaces as a NonFatal
    // event, leaving the session intact.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let target = server_write_target(&fixture);
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        target,
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
    let mut client = connect_client(addr, "client-a", &db_path).await;

    client
        .subscribe("count", "SELECT COUNT(*) FROM orders")
        .await
        .expect("subscribe");
    let event = pump_until(&mut client, |e| matches!(e, ClientEvent::NonFatal { .. })).await;
    let ClientEvent::NonFatal { related_to, detail } = event else {
        unreachable!()
    };
    assert_eq!(related_to.as_deref(), Some("count"));
    assert!(
        detail.contains("aggregate bootstrap failed"),
        "detail should explain the bootstrap failure, got {detail:?}",
    );

    // The session survives the failed bootstrap: a ping still round-trips.
    client.ping(11).await.expect("ping");
    pump_until(
        &mut client,
        |e| matches!(e, ClientEvent::Pong { nonce } if *nonce == 11),
    )
    .await;

    client.close().await.expect("close");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn row_subscription_and_delta_aggregate_coexist() {
    let fixture = Fixture::acquire().await;
    // One client holds a row subscription and a COUNT(*) delta aggregate on the
    // same table. A single insert must fan out on both paths at once: a row
    // LivePatch to the row route and a folded AggregateUpdate to the delta
    // route. The two delivery paths are independent in one dispatch.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let connector = QueuedConnector::with_rows([vec![PgValue::Int(0)]]);
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::with_connector(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        connector,
        target,
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
    let mut client = connect_client(addr, "client-a", &db_path).await;

    client
        .subscribe("orders-live", QUERY)
        .await
        .expect("subscribe row");
    client
        .subscribe("count", "SELECT COUNT(*) FROM orders")
        .await
        .expect("subscribe aggregate");

    // Drain the subscribe phase: the row snapshot completes and the aggregate
    // bootstrap arrives (in either order).
    let mut row_ready = false;
    let mut boot = false;
    while !(row_ready && boot) {
        let event = pump_until(&mut client, |e| {
            matches!(
                e,
                ClientEvent::SnapshotEnd { .. } | ClientEvent::Aggregate { .. }
            )
        })
        .await;
        match event {
            ClientEvent::SnapshotEnd { sub_id } if sub_id == "orders-live" => row_ready = true,
            ClientEvent::Aggregate { sub_id, .. } if sub_id == "count" => boot = true,
            _ => {}
        }
    }

    // One insert (id 2 avoids the snapshot's seed row id 1) fans out on both
    // paths: a row LivePatch and the folded COUNT = 1.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (2, 1.0, 10, 'x')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;

    let mut saw_live = false;
    let mut count_val = None;
    while !(saw_live && count_val.as_deref() == Some("1")) {
        let event = pump_until(&mut client, |e| {
            matches!(
                e,
                ClientEvent::LivePatch { .. } | ClientEvent::Aggregate { .. }
            )
        })
        .await;
        match event {
            ClientEvent::LivePatch { sub_id, .. } if sub_id == "orders-live" => saw_live = true,
            ClientEvent::Aggregate {
                sub_id,
                result_json,
                ..
            } if sub_id == "count" => {
                count_val = Some(result_json);
            }
            _ => {}
        }
    }

    client.close().await.expect("close");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn unsubscribing_a_delta_aggregate_stops_updates() {
    let fixture = Fixture::acquire().await;
    // After an Unsubscribe, the server drops the accumulator and the route, so a
    // further CDC event produces no aggregate update for that consumer.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let connector = QueuedConnector::with_rows([vec![PgValue::Int(0)]]);
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::with_connector(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        connector,
        target,
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
    let mut client = connect_client(addr, "client-a", &db_path).await;

    client
        .subscribe("count", "SELECT COUNT(*) FROM orders")
        .await
        .expect("subscribe aggregate");
    let seeded = collect_aggregates(&mut client, &["count"]).await;
    assert_eq!(seeded["count"], "0");

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (1, 1.0, 10, 'x')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    let after = collect_aggregates(&mut client, &["count"]).await;
    assert_eq!(after["count"], "1");

    // Unsubscribe, then fence with a ping. Control frames are processed in
    // order, so receiving this Pong proves the server handled the Unsubscribe.
    client.unsubscribe("count").await.expect("unsubscribe");
    client.ping(1).await.expect("ping");
    pump_until(
        &mut client,
        |e| matches!(e, ClientEvent::Pong { nonce } if *nonce == 1),
    )
    .await;

    // A further insert must produce no aggregate update. Fence again and assert
    // that only the Pong arrives before it.
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (2, 1.0, 20, 'y')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    client.ping(2).await.expect("ping");
    let mut saw_aggregate = false;
    loop {
        let event = pump_until(&mut client, |e| {
            matches!(e, ClientEvent::Aggregate { .. } | ClientEvent::Pong { .. })
        })
        .await;
        match event {
            ClientEvent::Pong { nonce: 2 } => break,
            ClientEvent::Aggregate { .. } => saw_aggregate = true,
            _ => {}
        }
    }
    assert!(
        !saw_aggregate,
        "no aggregate update should arrive after unsubscribe",
    );

    client.close().await.expect("close");
    server.await.expect("join server");
}

/// Pump the broadcast stream until an event matches `pred`, with a deadline.
async fn wait_broadcast(
    events: &mut tokio::sync::broadcast::Receiver<ClientEvent>,
    pred: impl Fn(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("event stream timed out")
            .expect("event stream closed");
        if pred(&event) {
            return event;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn live_query_stays_fresh_and_unsubscribes_on_drop() {
    let fixture = Fixture::acquire().await;
    // The full live-query loop: a typed diesel query becomes a LiveQuery whose
    // rows refresh as the snapshot and CDC patches land, and dropping the
    // handle tears the server subscription down.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let target = server_write_target(&fixture);
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        target,
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
    let conn = connect_client(addr, "client-a", &db_path).await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    // An ordinary typed diesel query, no SQL strings in sight: the postfix
    // live() dispatches to a row LiveQuery at compile time.
    let mut live: LiveQuery<Order> = orders::table
        .filter(orders::quantity.gt(0))
        .order(orders::id)
        .live(&client)
        .await
        .expect("watch");
    assert!(
        live.rows().is_empty(),
        "the replica is empty before the snapshot lands",
    );

    // The server snapshot (one seed row) applies, and the handle refreshes.
    // Race the refresh against a rejection so a refused subscription names its
    // reason instead of timing out.
    tokio::select! {
        changed = tokio::time::timeout(Duration::from_secs(5), live.changed()) => {
            changed.expect("snapshot refresh timed out").expect("driver alive");
        }
        rejected = wait_broadcast(&mut events, |e| matches!(e, ClientEvent::NonFatal { .. })) => {
            panic!("subscription rejected: {rejected:?}");
        }
    }
    assert_eq!(live.rows(), vec![order(1, 1.0, 3, "seed")]);

    // A CDC insert fans out as a live patch, and the handle refreshes again.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (2, 2.0, 7, 'live')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    tokio::time::timeout(Duration::from_secs(5), live.changed())
        .await
        .expect("live refresh timed out")
        .expect("driver alive");
    assert_eq!(
        live.rows(),
        vec![order(1, 1.0, 3, "seed"), order(2, 2.0, 7, "live")],
    );

    // Dropping the handle queues the unsubscribe. Fence with a ping: control
    // frames are ordered, so the pong proves the server handled it.
    drop(live);
    client.ping(1).await.expect("ping");
    wait_broadcast(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 1 })).await;

    // A further insert must reach neither the dropped handle nor the replica.
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (3, 3.0, 9, 'x')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    client.ping(2).await.expect("ping");
    let mut saw_patch = false;
    loop {
        let event = wait_broadcast(&mut events, |e| {
            matches!(
                e,
                ClientEvent::Pong { .. }
                    | ClientEvent::LivePatch { .. }
                    | ClientEvent::SnapshotApplied { .. }
            )
        })
        .await;
        match event {
            ClientEvent::Pong { nonce: 2 } => break,
            ClientEvent::LivePatch { .. } | ClientEvent::SnapshotApplied { .. } => {
                saw_patch = true;
            }
            _ => {}
        }
    }
    assert!(!saw_patch, "no patch may arrive after the unsubscribe");
    let replica_rows = client.with_conn(|conn| orders(conn.conn()).len()).await;
    assert_eq!(replica_rows, 2, "the replica never saw the third insert");

    // Dropping the last client handle ends the pump and closes the transport.
    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn live_value_tracks_a_server_aggregate() {
    let fixture = Fixture::acquire().await;
    // A typed aggregate query becomes a LiveValue fed exclusively by server
    // pushes: the replica's subset must never answer it. The bootstrap comes
    // through the connector seed, CDC folds arrive as AggregateUpdate, and
    // dropping the handle unsubscribes. The shape guards route misuse to the
    // right method with a clear error.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    // COUNT(*) seed over the backend at subscribe time: 1 (the snapshot row).
    let connector = QueuedConnector::with_rows([vec![PgValue::Int(1)]]);
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::with_connector(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        connector,
        target,
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
    let conn = connect_client(addr, "client-a", &db_path).await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    // The shape guards: an aggregate query is refused by watch, a row query by
    // watch_value, each pointing at the right method.
    let misrouted_row = client.watch::<_, i64>(orders::table.count()).await;
    assert!(
        matches!(&misrouted_row, Err(e) if e.to_string().contains("watch_value")),
        "watch must refuse an aggregate query",
    );
    let misrouted_value = client
        .watch_value::<_, i64>(orders::table.select(orders::id))
        .await;
    assert!(
        matches!(&misrouted_value, Err(e) if e.to_string().contains("use watch")),
        "watch_value must refuse a row query",
    );

    // The real thing: COUNT(*) as a typed diesel query. The postfix live()
    // dispatches to a LiveValue and infers the value type (i64) from the
    // query itself, no annotation anywhere.
    let mut count = orders::table.count().live(&client).await.expect("live");

    // The bootstrap arrives as a server push (the connector seed), never from
    // the subset replica.
    tokio::select! {
        changed = tokio::time::timeout(Duration::from_secs(5), count.changed()) => {
            changed.expect("bootstrap timed out").expect("driver alive");
        }
        rejected = wait_broadcast(&mut events, |e| matches!(e, ClientEvent::NonFatal { .. })) => {
            panic!("aggregate subscription rejected: {rejected:?}");
        }
    }
    assert_eq!(
        count.value(),
        Some(1),
        "the bootstrap value is the server's"
    );

    // A CDC insert folds server-side and the new value is pushed.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (2, 2.0, 7, 'live')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    tokio::time::timeout(Duration::from_secs(5), count.changed())
        .await
        .expect("fold timed out")
        .expect("driver alive");
    assert_eq!(count.value(), Some(2), "the folded value is the server's");

    // Dropping the handle unsubscribes. Fence, insert, fence: no aggregate
    // push may arrive in between.
    drop(count);
    client.ping(1).await.expect("ping");
    wait_broadcast(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 1 })).await;
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (3, 3.0, 9, 'x')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    client.ping(2).await.expect("ping");
    let mut saw_aggregate = false;
    loop {
        let event = wait_broadcast(&mut events, |e| {
            matches!(e, ClientEvent::Pong { .. } | ClientEvent::Aggregate { .. })
        })
        .await;
        match event {
            ClientEvent::Pong { nonce: 2 } => break,
            ClientEvent::Aggregate { .. } => saw_aggregate = true,
            _ => {}
        }
    }
    assert!(
        !saw_aggregate,
        "no aggregate push may arrive after the unsubscribe",
    );

    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn live_value_decodes_a_temporal_aggregate() {
    // A typed live() over MAX of a TIMESTAMP column. subql re-executes MIN/MAX
    // on any orderable type, so a scalar outside the old numeric and text
    // family rides the re-execution wire, where value_to_json renders it as a
    // JSON string. The broadened AggregateWire family decodes it into
    // Option<String>, proving the new type resolves through the real server on
    // both the bootstrap and a later CDC-driven push.
    const METRICS_PG_DDL: &str = "CREATE TABLE metrics (id INT PRIMARY KEY, seen TIMESTAMP);";
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(METRICS_PG_DDL).expect("build materializer");
    let seen = chrono::NaiveDate::from_ymd_opt(2020, 1, 2)
        .expect("valid date")
        .and_hms_opt(3, 4, 5)
        .expect("valid time");
    let connector = QueuedConnector::with_scalars([PgValue::Timestamp(seen)]);
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::with_connector(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        connector,
        target,
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
    let conn = connect_client(addr, "client-ts", &db_path).await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    // MAX(seen) is Nullable<Timestamp>, so the typed live() infers a
    // LiveValue<Option<String>> with no annotation.
    let mut latest = metrics::table
        .select(diesel::dsl::max(metrics::seen))
        .live(&client)
        .await
        .expect("live temporal aggregate");

    tokio::select! {
        changed = tokio::time::timeout(Duration::from_secs(5), latest.changed()) => {
            changed.expect("bootstrap timed out").expect("driver alive");
        }
        rejected = wait_broadcast(&mut events, |e| matches!(e, ClientEvent::NonFatal { .. })) => {
            panic!("temporal aggregate subscription rejected: {rejected:?}");
        }
    }
    assert_eq!(
        latest.value(),
        Some(Some("2020-01-02 03:04:05".to_owned())),
        "the timestamp bootstrap decodes to its wire string",
    );

    // A CDC insert raises the maximum. The re-execution family folds the new
    // extreme in process and pushes it through value_to_json, and the typed
    // LiveValue decodes the updated timestamp string.
    let mut source = PgSqliteEmuSource::open_in_memory(METRICS_PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO metrics (id, seen) VALUES (1, '2021-06-07 08:09:10')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    tokio::time::timeout(Duration::from_secs(5), latest.changed())
        .await
        .expect("update timed out")
        .expect("driver alive");
    assert_eq!(
        latest.value(),
        Some(Some("2021-06-07 08:09:10".to_owned())),
        "a CDC change pushes the new maximum, decoded as a timestamp string",
    );

    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn identical_row_watches_share_one_subscription() {
    let fixture = Fixture::acquire().await;
    // Two components rendering the same query must collapse to ONE wire
    // subscription. The recording snapshot source counts how many subscribes
    // reached the server, and both handles must follow a CDC patch, survive
    // one drop, and unsubscribe only when the last sharer is gone.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let target = server_write_target(&fixture);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let manager = SessionManager::new(
        materializer,
        RecordingSeed {
            seen: Arc::clone(&seen),
        },
        PermissiveAuth,
        target,
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
    let conn = connect_client(addr, "client-a", &db_path).await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    let build = || {
        orders::table
            .filter(orders::quantity.gt(0))
            .order(orders::id)
    };
    let mut live_a: LiveQuery<Order> = build().live(&client).await.expect("watch a");
    tokio::select! {
        changed = tokio::time::timeout(Duration::from_secs(5), live_a.changed()) => {
            changed.expect("snapshot refresh timed out").expect("driver alive");
        }
        rejected = wait_broadcast(&mut events, |e| matches!(e, ClientEvent::NonFatal { .. })) => {
            panic!("subscription rejected: {rejected:?}");
        }
    }
    assert_eq!(live_a.rows(), vec![order(1, 1.0, 3, "seed")]);

    // The second identical watch shares the wire sub: no new subscribe, and it
    // reads its initial rows from the replica the first subscription filled.
    let mut live_b: LiveQuery<Order> = build().live(&client).await.expect("watch b");
    assert_eq!(
        live_b.rows(),
        vec![order(1, 1.0, 3, "seed")],
        "the late handle reads the shared replica",
    );

    // Fence: any subscribe sent before the ping is processed before the pong.
    client.ping(1).await.expect("ping");
    wait_broadcast(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 1 })).await;
    assert_eq!(
        seen.lock().expect("seen poisoned").len(),
        1,
        "two identical watches collapse to one wire subscription",
    );

    // A CDC insert fans one shared patch out to both handles.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (2, 2.0, 7, 'live')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    tokio::time::timeout(Duration::from_secs(5), live_a.changed())
        .await
        .expect("live a refresh timed out")
        .expect("driver alive");
    tokio::time::timeout(Duration::from_secs(5), live_b.changed())
        .await
        .expect("live b refresh timed out")
        .expect("driver alive");
    let both = vec![order(1, 1.0, 3, "seed"), order(2, 2.0, 7, "live")];
    assert_eq!(live_a.rows(), both);
    assert_eq!(live_b.rows(), both);

    // Dropping one sharer keeps the shared sub live for the other.
    drop(live_a);
    client.ping(2).await.expect("ping");
    wait_broadcast(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 2 })).await;
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (3, 3.0, 9, 'more')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    tokio::time::timeout(Duration::from_secs(5), live_b.changed())
        .await
        .expect("survivor refresh timed out")
        .expect("driver alive");
    assert_eq!(
        live_b.rows().len(),
        3,
        "the survivor keeps following the sub"
    );

    // Dropping the last sharer sends the one Unsubscribe: no further patch may
    // reach the replica.
    drop(live_b);
    client.ping(3).await.expect("ping");
    wait_broadcast(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 3 })).await;
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (4, 4.0, 1, 'gone')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    client.ping(4).await.expect("ping");
    let mut saw_patch = false;
    loop {
        let event = wait_broadcast(&mut events, |e| {
            matches!(
                e,
                ClientEvent::Pong { .. }
                    | ClientEvent::LivePatch { .. }
                    | ClientEvent::SnapshotApplied { .. }
            )
        })
        .await;
        match event {
            ClientEvent::Pong { nonce: 4 } => break,
            ClientEvent::LivePatch { .. } | ClientEvent::SnapshotApplied { .. } => saw_patch = true,
            _ => {}
        }
    }
    assert!(
        !saw_patch,
        "no patch may arrive after the last sharer drops"
    );
    let replica_rows = client.with_conn(|conn| orders(conn.conn()).len()).await;
    assert_eq!(replica_rows, 3, "the replica never saw the fourth insert");

    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn distinct_row_queries_do_not_collapse() {
    let fixture = Fixture::acquire().await;
    // Dedup must key on the query: two different predicates each open their own
    // wire subscription, so the recorder sees two distinct select_sql.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let target = server_write_target(&fixture);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let manager = SessionManager::new(
        materializer,
        RecordingSeed {
            seen: Arc::clone(&seen),
        },
        PermissiveAuth,
        target,
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
    let conn = connect_client(addr, "client-a", &db_path).await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    let mut live_a: LiveQuery<Order> = orders::table
        .filter(orders::quantity.gt(0))
        .order(orders::id)
        .live(&client)
        .await
        .expect("watch a");
    tokio::select! {
        changed = tokio::time::timeout(Duration::from_secs(5), live_a.changed()) => {
            changed.expect("snapshot refresh timed out").expect("driver alive");
        }
        rejected = wait_broadcast(&mut events, |e| matches!(e, ClientEvent::NonFatal { .. })) => {
            panic!("subscription rejected: {rejected:?}");
        }
    }

    // A distinct bind value: same SQL skeleton, different spec. Its own
    // subscribe reaches the server, proving the dedup key includes the binds.
    let _live_b: LiveQuery<Order> = orders::table
        .filter(orders::quantity.gt(5))
        .order(orders::id)
        .live(&client)
        .await
        .expect("watch b");
    client.ping(1).await.expect("ping");
    wait_broadcast(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 1 })).await;

    let recorded = seen.lock().expect("seen poisoned").clone();
    // The two specs share a SQL skeleton and differ only in the placeholder
    // bind, so two subscribes prove dedup keys on the full spec, not the SQL
    // text alone.
    assert_eq!(
        recorded.len(),
        2,
        "distinct queries each open their own subscription",
    );

    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn identical_value_watches_share_one_sub_and_late_joiner_resolves_from_cache() {
    let fixture = Fixture::acquire().await;
    // Two identical aggregate watches share one wire sub. The connector holds
    // exactly one bootstrap seed, so a second independent subscribe would
    // starve it: the late joiner instead resolves immediately from the cached
    // last value, and both handles fold a CDC update.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let connector = QueuedConnector::with_rows([vec![PgValue::Int(1)]]);
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::with_connector(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        connector,
        target,
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
    let conn = connect_client(addr, "client-a", &db_path).await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    let mut count_a = orders::table.count().live(&client).await.expect("live a");
    tokio::select! {
        changed = tokio::time::timeout(Duration::from_secs(5), count_a.changed()) => {
            changed.expect("bootstrap timed out").expect("driver alive");
        }
        rejected = wait_broadcast(&mut events, |e| matches!(e, ClientEvent::NonFatal { .. })) => {
            panic!("aggregate subscription rejected: {rejected:?}");
        }
    }
    assert_eq!(
        count_a.value(),
        Some(1),
        "the bootstrap value is the server's"
    );

    // The second identical watch_value shares the wire sub and resolves at once
    // from the cached bootstrap, without a second server subscribe (which would
    // starve the connector's single seed).
    let mut count_b = orders::table.count().live(&client).await.expect("live b");
    assert_eq!(
        count_b.value(),
        Some(1),
        "the late joiner resolves from the cached bootstrap",
    );
    client.ping(1).await.expect("ping");
    loop {
        let event = wait_broadcast(&mut events, |e| {
            matches!(e, ClientEvent::Pong { .. } | ClientEvent::NonFatal { .. })
        })
        .await;
        if let ClientEvent::NonFatal { .. } = event {
            panic!("a shared value watch must not trigger a second subscribe: {event:?}");
        }
        if matches!(event, ClientEvent::Pong { nonce: 1 }) {
            break;
        }
    }

    // A CDC insert folds once server-side and fans to both handles.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (2, 2.0, 7, 'live')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    tokio::time::timeout(Duration::from_secs(5), count_a.changed())
        .await
        .expect("count a fold timed out")
        .expect("driver alive");
    tokio::time::timeout(Duration::from_secs(5), count_b.changed())
        .await
        .expect("count b fold timed out")
        .expect("driver alive");
    assert_eq!(count_a.value(), Some(2));
    assert_eq!(count_b.value(), Some(2));

    // Dropping one sharer keeps the shared sub live for the other.
    drop(count_a);
    client.ping(2).await.expect("ping");
    wait_broadcast(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 2 })).await;
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (3, 3.0, 9, 'more')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    tokio::time::timeout(Duration::from_secs(5), count_b.changed())
        .await
        .expect("survivor fold timed out")
        .expect("driver alive");
    assert_eq!(count_b.value(), Some(3), "the survivor keeps folding");

    // Dropping the last sharer unsubscribes: no aggregate push may follow.
    drop(count_b);
    client.ping(3).await.expect("ping");
    wait_broadcast(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 3 })).await;
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (4, 4.0, 1, 'gone')")
        .expect("emu insert");
    drain_events(&manager, &mut source).await;
    client.ping(4).await.expect("ping");
    let mut saw_aggregate = false;
    loop {
        let event = wait_broadcast(&mut events, |e| {
            matches!(e, ClientEvent::Pong { .. } | ClientEvent::Aggregate { .. })
        })
        .await;
        match event {
            ClientEvent::Pong { nonce: 4 } => break,
            ClientEvent::Aggregate { .. } => saw_aggregate = true,
            _ => {}
        }
    }
    assert!(
        !saw_aggregate,
        "no aggregate push may arrive after the last sharer drops",
    );

    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn watch_fn_drives_a_boxed_row_query() {
    let fixture = Fixture::acquire().await;
    // The load-bearing case for watch_fn: a boxed (.into_boxed()) row query is
    // not Clone, so plain watch cannot re-run it. Its row type carries a
    // strongly typed `rosetta_uuid::Uuid` key and a `bool` flag, not raw bytes,
    // so this proves watch_fn renders the boxed query (a bool bind included),
    // decodes non-trivial column types from the replica, and refreshes on a CDC
    // patch.
    let alpha_id = rosetta_uuid::Uuid::utc_v7();
    let inactive_id = rosetta_uuid::Uuid::utc_v7();
    let beta_id = rosetta_uuid::Uuid::utc_v7();

    let materializer = Materializer::new(GADGETS_PG_DDL).expect("build materializer");
    let seed = GadgetSeed {
        rows: vec![
            gadget(alpha_id, true, "alpha"),
            gadget(inactive_id, false, "zulu"),
        ],
    };
    let manager = SessionManager::new(
        materializer,
        seed,
        PermissiveAuth,
        gadgets_write_target(&fixture),
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
    // The replica needs the gadgets schema, so connect with that DDL rather than
    // the orders-shaped connect_client helper.
    let stream = TcpStream::connect(addr).await.expect("connect");
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .expect("ws connect");
    let config = ClientConfig {
        client_id: "client-gadgets".to_owned(),
        auth_token: "token".to_owned(),
        schema_version: None,
        sql_functions: connetto_client::SqlFunctions::new(),
    };
    let conn = ConnettoConnection::connect(
        transport,
        &Replica::EncryptedFile {
            path: &db_path,
            key: connetto_core::test_support::replica_key(),
        },
        GADGETS_SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("client connect");
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    // A boxed whole-table query ordered by label. The same value handed to
    // watch would not compile: BoxedSelectStatement is not Clone. No bool
    // predicate rides the wire (subql types the column as Bool and refuses an
    // integer bind against it), so the flag is exercised on decode, not filter.
    let mut live: LiveQuery<Gadget> = client
        .watch_fn(|| gadgets::table.order(gadgets::label).into_boxed())
        .await
        .expect("watch_fn");
    assert!(
        live.rows().is_empty(),
        "the replica is empty before the snapshot lands",
    );

    tokio::select! {
        changed = tokio::time::timeout(Duration::from_secs(5), live.changed()) => {
            changed.expect("snapshot refresh timed out").expect("driver alive");
        }
        rejected = wait_broadcast(&mut events, |e| matches!(e, ClientEvent::NonFatal { .. })) => {
            panic!("subscription rejected: {rejected:?}");
        }
    }
    // Both seed rows surface, decoded from the replica: the uuid keys and the
    // bool flag in both its true and false forms.
    assert_eq!(
        live.rows(),
        vec![
            gadget(alpha_id, true, "alpha"),
            gadget(inactive_id, false, "zulu"),
        ],
    );

    // A CDC insert of a third gadget refreshes the boxed query. The typed
    // insert binds the uuid key as a blob and the flag as an integer, the exact
    // shapes the wire carries.
    let mut source = PgSqliteEmuSource::open_in_memory(GADGETS_PG_DDL).expect("open emu source");
    diesel::insert_into(gadgets::table)
        .values((
            gadgets::id.eq(beta_id),
            gadgets::active.eq(true),
            gadgets::label.eq("beta"),
        ))
        .execute(source.connection())
        .expect("emu insert gadget");
    drain_events(&manager, &mut source).await;
    tokio::time::timeout(Duration::from_secs(5), live.changed())
        .await
        .expect("live refresh timed out")
        .expect("driver alive");
    assert_eq!(
        live.rows(),
        vec![
            gadget(alpha_id, true, "alpha"),
            gadget(beta_id, true, "beta"),
            gadget(inactive_id, false, "zulu"),
        ],
    );

    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn watch_fn_shares_a_subscription_with_watch() {
    let fixture = Fixture::acquire().await;
    // A boxed watch_fn and a typed live() watch that render the same spec
    // collapse onto one wire subscription through the shared attach_wire layer,
    // so the recorder sees exactly one subscribe.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let target = server_write_target(&fixture);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let manager = SessionManager::new(
        materializer,
        RecordingSeed {
            seen: Arc::clone(&seen),
        },
        PermissiveAuth,
        target,
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
    let conn = connect_client(addr, "client-a", &db_path).await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    let mut live_a: LiveQuery<Order> = orders::table
        .filter(orders::quantity.gt(0))
        .order(orders::id)
        .live(&client)
        .await
        .expect("watch a");
    tokio::select! {
        changed = tokio::time::timeout(Duration::from_secs(5), live_a.changed()) => {
            changed.expect("snapshot refresh timed out").expect("driver alive");
        }
        rejected = wait_broadcast(&mut events, |e| matches!(e, ClientEvent::NonFatal { .. })) => {
            panic!("subscription rejected: {rejected:?}");
        }
    }
    assert_eq!(live_a.rows(), vec![order(1, 1.0, 3, "seed")]);

    // The boxed watch_fn renders the identical spec and reads its initial rows
    // from the replica the first subscription filled, opening no new subscribe.
    let live_b: LiveQuery<Order> = client
        .watch_fn(|| {
            orders::table
                .filter(orders::quantity.gt(0))
                .order(orders::id)
                .into_boxed()
        })
        .await
        .expect("watch_fn b");
    assert_eq!(
        live_b.rows(),
        vec![order(1, 1.0, 3, "seed")],
        "the late handle reads the shared replica",
    );

    client.ping(1).await.expect("ping");
    wait_broadcast(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 1 })).await;
    assert_eq!(
        seen.lock().expect("seen poisoned").len(),
        1,
        "watch_fn and watch sharing a spec collapse to one wire subscription",
    );

    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn watch_fn_rejects_an_aggregate_query() {
    let fixture = Fixture::acquire().await;
    // watch_fn drives rows. A boxed aggregate shape is refused with the
    // row-vs-value error, before any subscription is registered.
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let target = server_write_target(&fixture);
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        target,
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
    let conn = connect_client(addr, "client-a", &db_path).await;
    let client = ConnettoClient::start(conn);

    let result = client
        .watch_fn::<_, _, i64>(|| orders::table.count().into_boxed())
        .await;
    let Err(err) = result else {
        panic!("aggregate must be rejected on the row path");
    };
    assert!(
        format!("{err}").contains("aggregate"),
        "the error names the aggregate mismatch: {err}",
    );

    drop(client);
    server.await.expect("join server");
}
