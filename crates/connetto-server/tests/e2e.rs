//! Docker-gated multi-process end-to-end tests.
//!
//! Spawn the real `connetto-server` and `connetto-client` binaries as separate
//! OS processes and drive a full sync loop over real Postgres logical
//! replication. One test covers the read direction: each client receives the
//! initial snapshot, then a live insert fans out to both, and after the
//! walsender is terminated the server's reconnect loop resumes so a further
//! insert still reaches both clients. The other covers the write direction: a
//! client applies a local insert and pushes it, the server's write path lands
//! it in Postgres, and it fans back out over CDC to a second client. This is
//! the product spine end to end, unlike the in-process session tests.
//!
//! `#[ignore]` by default. It needs a Postgres started with `wal_level=logical`,
//! both binaries built in the same profile as the test, and an `app_reader`
//! non-superuser role that the fixture creates automatically. Run it with:
//!
//! ```text
//! cargo build --release -p connetto-server --bin connetto-server
//! cargo build --release -p connetto-client --bin connetto-client --all-features
//! DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
//!   cargo test --release -p connetto-server --test e2e -- --ignored
//! ```
//!

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use diesel::sql_query;
use diesel::sqlite::SqliteConnection;
use diesel::{Connection, QueryableByName};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use connetto_client::{ReplicaKey, cipher};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";
const SLOT: &str = "connetto_slot";
const PUBLICATION: &str = "connetto_pub";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
const OWNED_PG_DDL: &str = "CREATE TABLE owned (id INT PRIMARY KEY, owner TEXT, body TEXT);";
const OWNED_SQLITE_DDL: &str =
    "CREATE TABLE owned (id INTEGER PRIMARY KEY, owner TEXT, body TEXT);";
const OWNED_QUERY: &str = "SELECT * FROM owned";

// The client replica's `orders` table, typed for the poller's count query.
diesel::table! {
    orders (id) {
        id -> Integer,
        price -> Nullable<Double>,
        quantity -> Nullable<Integer>,
        status -> Nullable<Text>,
    }
}

/// Serializes the Docker-gated tests. They reset the same Postgres and share one
/// replication slot and publication name, so they must not run concurrently.
static PG_SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

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

/// Row count of the `orders` table in a client's local SQLite, or 0 while the
/// database is absent, still locked, or not yet holding the table.
///
/// The client keeps its replica encrypted at rest with the key in the OS
/// keyring, under the binary's service and keyed by the database path, so the
/// count unlocks with that same key. The path is probed before opening,
/// because an open would create an empty file and the client refuses an
/// existing file that has no cached key.
fn count_orders(db_path: &Path) -> i64 {
    if !db_path.exists() {
        return 0;
    }
    let path = db_path.to_string_lossy();
    let Ok(entry) = keyring::Entry::new("connetto-client", &path) else {
        return 0;
    };
    let Ok(hex) = entry.get_password() else {
        return 0;
    };
    let Ok(key) = hex.parse::<ReplicaKey>() else {
        return 0;
    };
    let Ok(mut conn) = SqliteConnection::establish(&path) else {
        return 0;
    };
    if cipher::unlock(&mut conn, &key).is_err() {
        return 0;
    }
    diesel::RunQueryDsl::get_result::<i64>(
        diesel::QueryDsl::select(orders::table, diesel::dsl::count_star()),
        &mut conn,
    )
    .unwrap_or(0)
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

fn spawn_server_cfg(
    database_url: &str,
    bind: &str,
    pg_ddl: &str,
    writable: &str,
    reader_url: Option<&str>,
) -> ChildGuard {
    let mut command = Command::new(server_bin());
    command
        .env("DATABASE_URL", database_url)
        .env("CONNETTO_BIND", bind)
        .env("CONNETTO_PG_DDL", pg_ddl)
        .env("CONNETTO_WRITABLE", writable)
        .env("CONNETTO_SLOT", SLOT)
        .env("CONNETTO_PUBLICATION", PUBLICATION)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Some(reader) = reader_url {
        command.env("CONNETTO_READER_URL", reader);
    } else {
        command.env_remove("CONNETTO_READER_URL");
    }
    let child = command.spawn().expect("spawn server");
    ChildGuard(child)
}

fn spawn_client(ws: &str, db_path: &Path, client_id: &str, write: Option<&str>) -> ChildGuard {
    spawn_client_env(
        ws, db_path, client_id, SQLITE_DDL, PG_DDL, "orders", QUERY, write,
    )
}

// A test spawn helper mirroring the client binary's env surface, so its
// argument list tracks that surface rather than a smaller abstraction.
#[allow(clippy::too_many_arguments)]
fn spawn_client_env(
    ws: &str,
    db_path: &Path,
    client_id: &str,
    sqlite_ddl: &str,
    schema_sql: &str,
    sub_id: &str,
    query: &str,
    write: Option<&str>,
) -> ChildGuard {
    let mut command = Command::new(client_bin());
    command
        .env("CONNETTO_SERVER", ws)
        .env("CONNETTO_DB", db_path)
        .env("CONNETTO_SQLITE_DDL", sqlite_ddl)
        // The client hashes the SAME canonical source the server does, so the
        // handshake schema versions match. Distinct from the SQLite replica DDL.
        .env("CONNETTO_SCHEMA_SQL", schema_sql)
        .env("CONNETTO_CLIENT_ID", client_id)
        .env("CONNETTO_SUB_ID", sub_id)
        .env("CONNETTO_QUERY", query)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Some(sql) = write {
        command.env("CONNETTO_WRITE", sql);
    } else {
        command.env_remove("CONNETTO_WRITE");
    }
    let child = command.spawn().expect("spawn client");
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

/// Drop the replication slot, terminating any active walsender first and
/// retrying until the slot is gone. A prior test's server can still hold the
/// slot for a moment after it is killed, and an active slot cannot be dropped.
async fn drop_slot(pool: &Pool<AsyncPgConnection>) {
    for _ in 0..50 {
        exec(
            pool,
            "SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots \
             WHERE slot_name = 'connetto_slot' AND active_pid IS NOT NULL",
        )
        .await;
        let mut conn = pool.get().await.expect("admin connection");
        let dropped = sql_query(
            "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots \
             WHERE slot_name = 'connetto_slot'",
        )
        .execute(&mut *conn)
        .await;
        drop(conn);
        if dropped.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("replication slot connetto_slot could not be dropped");
}

/// Reset the shared Postgres fixture to a clean slate: drop the slot, table, and
/// publication, then recreate the table with `REPLICA IDENTITY FULL`, one seed
/// row, the publication, and the slot. Also creates an `app_reader` non-superuser
/// role (idempotent) and grants it the access the server needs. Grants die with
/// DROP TABLE, so they are refreshed on each call. The seed lands before the slot
/// exists, so it reaches clients via snapshot and only later writes arrive over
/// replication.
async fn reset_fixture(pool: &Pool<AsyncPgConnection>) {
    drop_slot(pool).await;
    exec(pool, "DROP TABLE IF EXISTS orders CASCADE").await;
    // Stale per-client watermarks from a previous run would suppress replayed
    // mutations (the server dedupes by them), so drop and recreate fresh.
    // connetto emits no DDL, so the test owns this table (the server no longer
    // provisions it); the shape matches the `ConnettoWatermark` reference.
    exec(pool, "DROP TABLE IF EXISTS _connetto_mutations").await;
    exec(
        pool,
        "CREATE TABLE _connetto_mutations (user_id TEXT NOT NULL, \
         session_id UUID NOT NULL, last_seq BIGINT NOT NULL, \
         PRIMARY KEY (user_id, session_id))",
    )
    .await;
    exec(pool, "DROP PUBLICATION IF EXISTS connetto_pub").await;
    exec(pool, PG_DDL).await;
    exec(pool, "ALTER TABLE orders REPLICA IDENTITY FULL").await;
    exec(
        pool,
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') \
         THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; END $$",
    )
    .await;
    exec(pool, "GRANT USAGE ON SCHEMA public TO app_reader").await;
    exec(
        pool,
        "GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO app_reader",
    )
    .await;
    exec(
        pool,
        "GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_reader",
    )
    .await;
    exec(pool, "INSERT INTO orders VALUES (1, 1.0, 3, 'seed')").await;
    exec(pool, "CREATE PUBLICATION connetto_pub FOR TABLE orders").await;
    exec(
        pool,
        "SELECT pg_create_logical_replication_slot('connetto_slot', 'pgoutput')",
    )
    .await;
}

/// Rewrite a Postgres URL's user info, keeping host, port, and database. Used to
/// point the server's write target at a non-superuser role subject to RLS.
fn with_user_url(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("url has a scheme");
    let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    format!("{scheme}://{user}:{password}@{host}")
}

/// The `(id, owner)` rows in `owned`, read through the admin pool so RLS hides
/// none.
async fn pg_owned_rows(pool: &Pool<AsyncPgConnection>) -> Vec<(i32, String)> {
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Integer)]
        id: i32,
        #[diesel(sql_type = diesel::sql_types::Text)]
        owner: String,
    }
    let mut conn = pool.get().await.expect("admin connection");
    let rows: Vec<Row> = sql_query("SELECT id, owner FROM owned ORDER BY id")
        .load(&mut *conn)
        .await
        .expect("read owned");
    rows.into_iter().map(|row| (row.id, row.owner)).collect()
}

/// Count returned by a `SELECT COUNT(*) AS n ...` query through the admin pool,
/// which sees every row regardless of Row-Level Security.
async fn pg_count(pool: &Pool<AsyncPgConnection>, sql: &str) -> i64 {
    #[derive(QueryableByName)]
    struct RowCount {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        n: i64,
    }
    let mut conn = pool.get().await.expect("admin connection");
    sql_query(sql)
        .get_result::<RowCount>(&mut *conn)
        .await
        .map_or(0, |row| row.n)
}

/// Poll the admin pool until the count query returns at least `want` or the
/// timeout elapses. Returns the last count seen.
async fn wait_for_pg_count(
    pool: &Pool<AsyncPgConnection>,
    sql: &str,
    want: i64,
    timeout: Duration,
) -> i64 {
    let deadline = Instant::now() + timeout;
    loop {
        let seen = pg_count(pool, sql).await;
        if seen >= want || Instant::now() >= deadline {
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

#[tokio::test]
#[ignore = "requires a running Postgres with wal_level=logical (Docker) and both binaries built"]
async fn e2e_two_clients_snapshot_live_and_reconnect() {
    assert!(
        client_bin().exists(),
        "client binary missing at {}: build it with the same profile, \
         `cargo build --release -p connetto-client --bin connetto-client`",
        client_bin().display()
    );

    let _serial = PG_SERIAL.lock().await;

    let url = database_url();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");

    reset_fixture(&pool).await;

    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let ws = format!("ws://127.0.0.1:{port}/");

    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let _server = spawn_server_cfg(&url, &bind, PG_DDL, "orders", Some(&reader_url));
    assert!(
        wait_for_port(&bind, Duration::from_secs(20)).await,
        "server did not open {bind}"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let db_a = dir.path().join("client-a.db");
    let db_b = dir.path().join("client-b.db");
    let _client_a = spawn_client(&ws, &db_a, "client-a", None);
    let _client_b = spawn_client(&ws, &db_b, "client-b", None);

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

    // Reliability: terminate the walsender, then insert again. The server's
    // reconnect loop must resume from the slot and fan the new row to both
    // clients.
    exec(
        &pool,
        "SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots \
         WHERE slot_name = 'connetto_slot' AND active_pid IS NOT NULL",
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    exec(&pool, "INSERT INTO orders VALUES (8, 4.0, 2, 'resumed')").await;
    assert_eq!(
        wait_for_rows(&db_a, 3, secs).await,
        3,
        "client-a did not converge after reconnect"
    );
    assert_eq!(
        wait_for_rows(&db_b, 3, secs).await,
        3,
        "client-b did not converge after reconnect"
    );
}

#[tokio::test]
#[ignore = "requires a running Postgres with wal_level=logical (Docker) and both binaries built"]
async fn e2e_client_write_lands_in_pg_and_fans_out() {
    assert!(
        client_bin().exists(),
        "client binary missing at {}: build it with the same profile, \
         `cargo build --release -p connetto-client --bin connetto-client`",
        client_bin().display()
    );

    let _serial = PG_SERIAL.lock().await;

    let url = database_url();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");

    reset_fixture(&pool).await;

    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let ws = format!("ws://127.0.0.1:{port}/");

    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let _server = spawn_server_cfg(&url, &bind, PG_DDL, "orders", Some(&reader_url));
    assert!(
        wait_for_port(&bind, Duration::from_secs(20)).await,
        "server did not open {bind}"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let db_writer = dir.path().join("writer.db");
    let db_reader = dir.path().join("reader.db");
    let secs = Duration::from_secs(20);

    // Bring the reader up first and let it snapshot the seed row, so the
    // writer's row can only reach it over CDC, not in the reader's own snapshot.
    let _reader = spawn_client(&ws, &db_reader, "reader", None);
    assert_eq!(
        wait_for_rows(&db_reader, 1, secs).await,
        1,
        "reader snapshot"
    );

    // The writer subscribes, applies its local insert, and pushes it. The
    // server applies it as app_reader; orders carries no policy so the write is allowed.
    let write = "INSERT INTO orders VALUES (42, 2.5, 4, 'from-writer')";
    let _writer = spawn_client(&ws, &db_writer, "writer", Some(write));

    // The write reaches Postgres through the server's write path.
    assert_eq!(
        wait_for_pg_count(
            &pool,
            "SELECT COUNT(*) AS n FROM orders WHERE id = 42",
            1,
            secs,
        )
        .await,
        1,
        "client write did not land in Postgres"
    );

    // The reader converges on the client-originated row over CDC.
    assert_eq!(
        wait_for_rows(&db_reader, 2, secs).await,
        2,
        "reader did not converge on the client write"
    );
}

#[tokio::test]
#[ignore = "requires a running Postgres with wal_level=logical (Docker) and both binaries built"]
async fn e2e_rls_write_enforced_owned_lands_foreign_refused() {
    assert!(
        client_bin().exists(),
        "client binary missing at {}: build it with the same profile, \
         `cargo build --release -p connetto-client --bin connetto-client`",
        client_bin().display()
    );

    let url = database_url();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let admin = Pool::builder().build(manager).await.expect("build pool");

    let _serial = PG_SERIAL.lock().await;

    // Clean slate, then a non-superuser writer role, the table with an RLS
    // policy keyed on `app.user_id`, grants, the publication, and the slot. The
    // admin role is superuser and bypasses RLS, so it is used only for setup and
    // for reading the result back. The server applies writes as `app_writer`
    // (via `CONNETTO_READER_URL`), which is subject to the policy.
    drop_slot(&admin).await;
    for stmt in [
        "DROP TABLE IF EXISTS owned CASCADE",
        "DROP TABLE IF EXISTS _connetto_mutations",
        "DROP PUBLICATION IF EXISTS connetto_pub",
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
         THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$",
        "CREATE TABLE owned (id INT PRIMARY KEY, owner TEXT, body TEXT)",
        "ALTER TABLE owned REPLICA IDENTITY FULL",
        "ALTER TABLE owned ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY owned_p ON owned USING (owner = current_setting('app.user_id', true))",
        // The exactly-once watermark table is created by the test, as a
        // deployment would: connetto emits no DDL, the restricted writer role
        // cannot CREATE in schema public on Postgres 15+ (and must not need
        // to), and the writer only needs DML on it.
        "CREATE TABLE _connetto_mutations (user_id TEXT NOT NULL, \
         session_id UUID NOT NULL, last_seq BIGINT NOT NULL, \
         PRIMARY KEY (user_id, session_id))",
        "GRANT USAGE ON SCHEMA public TO app_writer",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON owned TO app_writer",
        "GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_writer",
        "CREATE PUBLICATION connetto_pub FOR TABLE owned",
        "SELECT pg_create_logical_replication_slot('connetto_slot', 'pgoutput')",
    ] {
        exec(&admin, stmt).await;
    }

    let reader_url = with_user_url(&url, "app_writer", "app_writer");

    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let ws = format!("ws://127.0.0.1:{port}/");

    let _server = spawn_server_cfg(&url, &bind, OWNED_PG_DDL, "owned", Some(&reader_url));
    assert!(
        wait_for_port(&bind, Duration::from_secs(20)).await,
        "server did not open {bind}"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("alice.db");
    let secs = Duration::from_secs(20);

    // Alice pushes three ordered mutations on one session: an owned insert
    // (allowed), a foreign insert owned by bob (refused by the policy's implicit
    // WITH CHECK), and a second owned insert. The session applies frames in
    // order, so once the third row lands the foreign one has already been
    // processed and refused.
    let writes = "INSERT INTO owned VALUES (1, 'alice', 'mine')\n\
                  INSERT INTO owned VALUES (2, 'bob', 'theirs')\n\
                  INSERT INTO owned VALUES (3, 'alice', 'also mine')";
    let _alice = spawn_client_env(
        &ws,
        &db,
        "alice",
        OWNED_SQLITE_DDL,
        OWNED_PG_DDL,
        "owned",
        OWNED_QUERY,
        Some(writes),
    );

    // The sentinel third row landing proves the foreign write ahead of it was
    // already handled.
    assert_eq!(
        wait_for_pg_count(
            &admin,
            "SELECT COUNT(*) AS n FROM owned WHERE id = 3",
            1,
            secs
        )
        .await,
        1,
        "alice's owned sentinel write did not land under RLS"
    );

    // Postgres holds only alice's rows. Bob's foreign row was refused.
    assert_eq!(
        pg_owned_rows(&admin).await,
        vec![(1, "alice".to_owned()), (3, "alice".to_owned())],
        "RLS did not enforce the write policy through the binaries"
    );
}

/// Spawn the server with the given environment, wait up to 30 s for it to exit,
/// and return its output. Used by startup-refusal tests where the binary exits
/// before binding its port.
async fn run_server_exit_output(
    database_url: &str,
    reader_url: Option<&str>,
    extra_envs: &[(&str, &str)],
) -> std::process::Output {
    let bind = format!("127.0.0.1:{}", free_port());
    let mut command = Command::new(server_bin());
    command
        .env("DATABASE_URL", database_url)
        .env("CONNETTO_BIND", bind)
        .env("CONNETTO_PG_DDL", PG_DDL)
        .env("CONNETTO_WRITABLE", "orders")
        .env("CONNETTO_SLOT", SLOT)
        .env("CONNETTO_PUBLICATION", PUBLICATION)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(r) = reader_url {
        command.env("CONNETTO_READER_URL", r);
    } else {
        command.env_remove("CONNETTO_READER_URL");
    }
    for (k, v) in extra_envs {
        command.env(k, v);
    }
    let child = command.spawn().expect("spawn server for refusal test");
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || child.wait_with_output()),
    )
    .await
    .expect("server refusal timed out after 30 s")
    .expect("spawn_blocking task panicked")
    .expect("wait_with_output failed")
}

#[tokio::test]
#[ignore = "requires a running Postgres with wal_level=logical (Docker) and both binaries built"]
async fn e2e_startup_refuses_without_a_reader_role() {
    let _serial = PG_SERIAL.lock().await;
    let url = database_url();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool).await;

    let output = run_server_exit_output(&url, None, &[]).await;
    assert!(
        !output.status.success(),
        "expected nonzero exit without CONNETTO_READER_URL"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CONNETTO_READER_URL"),
        "expected CONNETTO_READER_URL in stderr, got: {stderr}"
    );
}

#[tokio::test]
#[ignore = "requires a running Postgres with wal_level=logical (Docker) and both binaries built"]
async fn e2e_startup_refuses_an_unrecognised_oidc_provider() {
    let _serial = PG_SERIAL.lock().await;
    let url = database_url();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool).await;

    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let output = run_server_exit_output(
        &url,
        Some(&reader_url),
        &[
            ("CONNETTO_AUTH", "in-memory"),
            ("CONNETTO_OIDC_PROVIDER", "frobnicate"),
        ],
    )
    .await;
    assert!(
        !output.status.success(),
        "expected nonzero exit for unrecognised provider"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"frobnicate\""),
        "expected Debug-quoted provider name in stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("microsoft"),
        "expected recognised provider list in stderr, got: {stderr}"
    );
}

#[tokio::test]
#[ignore = "requires a running Postgres with wal_level=logical (Docker) and both binaries built"]
async fn e2e_startup_refuses_a_miscapitalised_provider_name() {
    let _serial = PG_SERIAL.lock().await;
    let url = database_url();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool).await;

    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let output = run_server_exit_output(
        &url,
        Some(&reader_url),
        &[
            ("CONNETTO_AUTH", "in-memory"),
            ("CONNETTO_OIDC_PROVIDER", "Google"),
        ],
    )
    .await;
    assert!(
        !output.status.success(),
        "expected nonzero exit for miscapitalised provider"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"Google\""),
        "expected Debug-quoted \"Google\" in stderr, got: {stderr}"
    );
}
