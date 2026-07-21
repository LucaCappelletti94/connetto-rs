//! Docker-gated multi-process end-to-end test.
//!
//! Spawns the real `connetto-server` and two `connetto-client` binaries as
//! separate OS processes and drives a full sync loop over real Postgres logical
//! replication: each client receives the initial snapshot, then a live insert
//! fans out to both. This is the product spine end to end, unlike the in-process
//! session tests.
//!
//! `#[ignore]` by default. It needs a Postgres started with `wal_level=logical`,
//! and both binaries built in the same profile as the test. Run it with:
//!
//! ```text
//! cargo build --release -p connetto-server --features pg-async --bin connetto-server
//! cargo build --release -p connetto-client --bin connetto-client
//! DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
//!   cargo test --release -p connetto-server --features pg-async --test e2e -- --ignored
//! ```
//!
//! The whole file compiles only under the `pg-async` feature.

#![cfg(feature = "pg-async")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use diesel::sql_query;
use diesel::sqlite::SqliteConnection;
use diesel::{Connection, QueryableByName};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";
const SLOT: &str = "connetto_slot";
const PUBLICATION: &str = "connetto_pub";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned())
}

fn server_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_connetto-server"))
}

/// The client binary is a sibling of the server binary in the same target
/// profile directory. It is built by a separate crate, so it must already exist.
fn client_bin() -> PathBuf {
    server_bin()
        .parent()
        .expect("target profile directory")
        .join("connetto-client")
}

/// Kills its child on drop so a panicking assertion never leaks a process.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Row count of the `orders` table in a client's local SQLite, or 0 when the
/// database or table does not exist yet.
fn count_orders(db_path: &Path) -> i64 {
    #[derive(QueryableByName)]
    struct RowCount {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        n: i64,
    }
    let Ok(mut conn) = SqliteConnection::establish(&db_path.to_string_lossy()) else {
        return 0;
    };
    diesel::RunQueryDsl::get_result::<RowCount>(
        sql_query("SELECT COUNT(*) AS n FROM orders"),
        &mut conn,
    )
    .map_or(0, |row| row.n)
}

/// Poll a client's local store until it holds at least `want` rows or the
/// timeout elapses. Returns the last count seen.
async fn wait_for_rows(db_path: &Path, want: i64, timeout: Duration) -> i64 {
    let deadline = Instant::now() + timeout;
    loop {
        let seen = count_orders(db_path);
        if seen >= want || Instant::now() >= deadline {
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Poll until a TCP connect to `addr` succeeds or the timeout elapses.
async fn wait_for_port(addr: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// A free localhost port, released before the caller binds it.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn spawn_server(database_url: &str, bind: &str) -> ChildGuard {
    let child = Command::new(server_bin())
        .env("DATABASE_URL", database_url)
        .env("CONNETTO_BIND", bind)
        .env("CONNETTO_PG_DDL", PG_DDL)
        .env("CONNETTO_SQLITE_DDL", SQLITE_DDL)
        .env("CONNETTO_SLOT", SLOT)
        .env("CONNETTO_PUBLICATION", PUBLICATION)
        .env_remove("CONNETTO_READER_URL")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn server");
    ChildGuard(child)
}

fn spawn_client(ws: &str, db_path: &Path, client_id: &str) -> ChildGuard {
    let child = Command::new(client_bin())
        .env("CONNETTO_SERVER", ws)
        .env("CONNETTO_DB", db_path)
        .env("CONNETTO_SQLITE_DDL", SQLITE_DDL)
        .env("CONNETTO_CLIENT_ID", client_id)
        .env("CONNETTO_SUB_ID", "orders")
        .env("CONNETTO_QUERY", QUERY)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn client");
    ChildGuard(child)
}

/// Run a single DDL/DML statement in its own transaction (autocommit).
async fn exec(pool: &Pool<AsyncPgConnection>, sql: &str) {
    let mut conn = pool.get().await.expect("admin connection");
    sql_query(sql)
        .execute(&mut *conn)
        .await
        .unwrap_or_else(|err| panic!("statement failed ({sql}): {err}"));
}

#[tokio::test]
#[ignore = "requires a running Postgres with wal_level=logical (Docker) and both binaries built"]
async fn e2e_two_clients_receive_snapshot_and_live() {
    assert!(
        client_bin().exists(),
        "client binary missing at {}: build it with the same profile, \
         `cargo build --release -p connetto-client --bin connetto-client`",
        client_bin().display()
    );

    let url = database_url();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");

    // Clean slate, then table, seed, publication, and the replication slot. The
    // slot is created after the seed insert, so the seed arrives via snapshot and
    // only later writes arrive over replication.
    exec(&pool, "DROP TABLE IF EXISTS orders CASCADE").await;
    exec(
        &pool,
        "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots \
         WHERE slot_name = 'connetto_slot'",
    )
    .await;
    exec(&pool, "DROP PUBLICATION IF EXISTS connetto_pub").await;
    exec(&pool, PG_DDL).await;
    exec(&pool, "ALTER TABLE orders REPLICA IDENTITY FULL").await;
    exec(&pool, "INSERT INTO orders VALUES (1, 1.0, 3, 'seed')").await;
    exec(&pool, "CREATE PUBLICATION connetto_pub FOR TABLE orders").await;
    exec(
        &pool,
        "SELECT pg_create_logical_replication_slot('connetto_slot', 'pgoutput')",
    )
    .await;

    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let ws = format!("ws://127.0.0.1:{port}/");

    let _server = spawn_server(&url, &bind);
    assert!(
        wait_for_port(&bind, Duration::from_secs(20)).await,
        "server did not open {bind}"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let db_a = dir.path().join("client-a.db");
    let db_b = dir.path().join("client-b.db");
    let _client_a = spawn_client(&ws, &db_a, "client-a");
    let _client_b = spawn_client(&ws, &db_b, "client-b");

    // Snapshot: both clients receive the pre-existing seed row.
    let secs = Duration::from_secs(20);
    assert_eq!(wait_for_rows(&db_a, 1, secs).await, 1, "client-a snapshot");
    assert_eq!(wait_for_rows(&db_b, 1, secs).await, 1, "client-b snapshot");

    // Live: an insert on Postgres fans out over CDC to both clients.
    exec(&pool, "INSERT INTO orders VALUES (7, 9.5, 5, 'paid')").await;
    assert_eq!(
        wait_for_rows(&db_a, 2, secs).await,
        2,
        "client-a live patch"
    );
    assert_eq!(
        wait_for_rows(&db_b, 2, secs).await,
        2,
        "client-b live patch"
    );
}
