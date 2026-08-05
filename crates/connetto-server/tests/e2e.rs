//! Docker-gated multi-process end-to-end tests.
//!
//! Spawn the real `connetto-server` and `connetto-client` binaries as separate
//! OS processes and drive a full sync loop over real Postgres logical
//! replication. The suite starts a loopback identity provider in-process using
//! `oauth2-test-server`, so every spawned server carries a real OIDC
//! configuration and every spawned client carries a minted connetto access
//! token. One test covers the read direction: each client receives the initial
//! snapshot, then a live insert fans out to both, and after the walsender is
//! terminated the server's reconnect loop resumes so a further insert still
//! reaches both clients. The other covers the write direction: a client applies
//! a local insert and pushes it, the server's write path lands it in Postgres,
//! and it fans back out over CDC to a second client. This is the product spine
//! end to end, unlike the in-process session tests.
//!
//! `#[ignore]` by default. It needs a Postgres started with `wal_level=logical`,
//! both binaries built in the same profile as the test, and an `app_reader`
//! non-superuser role that the fixture creates automatically. The in-process
//! identity provider requires no external setup. Run it with:
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
use tempfile::TempDir;

use connetto_client::{ReplicaKey, cipher};
use oauth2_test_server::{IssuerConfig, OAuthTestServer};
use openidconnect::reqwest;
use serde_json::json;

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

/// The keyring service the client binary provisions replica keys under.
const CLIENT_KEYRING_SERVICE: &str = "connetto-client";

/// A directory for client replicas that also removes their OS keyring entries
/// on drop, for the same reason [`ChildGuard`] kills its child.
///
/// The client binary mints a key per replica path and never deletes it, which is
/// right for a real client: the key has to outlive the process or the replica
/// stops opening. A test throws its replica away with the directory, so the
/// entry is left naming a path that no longer exists, and enough of them exhaust
/// the per-user keyring quota until every later mint fails.
struct ReplicaDir {
    dir: TempDir,
    replicas: Vec<String>,
}

impl ReplicaDir {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
            replicas: Vec::new(),
        }
    }

    /// A replica path inside the directory, registered for keyring cleanup.
    fn replica(&mut self, name: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        self.replicas.push(path.to_string_lossy().into_owned());
        path
    }
}

impl Drop for ReplicaDir {
    fn drop(&mut self) {
        for path in &self.replicas {
            if let Ok(entry) = keyring::Entry::new(CLIENT_KEYRING_SERVICE, path) {
                let _ = entry.delete_credential();
            }
        }
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
    let Ok(entry) = keyring::Entry::new(CLIENT_KEYRING_SERVICE, &path) else {
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
    auth_envs: &[(&str, &str)],
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
    for (k, v) in auth_envs {
        command.env(k, v);
    }
    let child = command.spawn().expect("spawn server");
    ChildGuard(child)
}

fn spawn_client(
    ws: &str,
    db_path: &Path,
    client_id: &str,
    token: &str,
    write: Option<&str>,
) -> ChildGuard {
    spawn_client_env(
        ws, db_path, client_id, SQLITE_DDL, PG_DDL, "orders", QUERY, token, write,
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
    token: &str,
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
        .env("CONNETTO_TOKEN", token)
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
    // Stale per-session watermarks from a previous run would suppress replayed
    // mutations, so drop and recreate fresh. connetto emits no DDL and the
    // shape keys on session_id alone (R2 re-key from the old user_id+session_id pair).
    exec(pool, "DROP TABLE IF EXISTS _connetto_mutations").await;
    exec(
        pool,
        "CREATE TABLE _connetto_mutations \
         (session_id UUID PRIMARY KEY, last_seq BIGINT NOT NULL)",
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

/// A loopback identity provider plus the env pairs the server binary needs to
/// discover and use it. Holds the `OAuthTestServer` guard alive for the test.
struct AuthStack {
    _idp: OAuthTestServer,
    /// `CONNETTO_AUTH`, `CONNETTO_AUTH_BIND`, and the `CONNETTO_OIDC_` pairs.
    env_pairs: Vec<(String, String)>,
    /// Base URL of the server binary's auth endpoints.
    auth_base: String,
}

/// Start an `oauth2-test-server` identity provider, register a client against
/// the connetto auth callback bound at `auth_port`, and return the stack.
async fn build_auth_stack(auth_port: u16) -> AuthStack {
    let callback = format!("http://127.0.0.1:{auth_port}/auth/callback");
    let idp = OAuthTestServer::start_with_config(IssuerConfig {
        host: "127.0.0.1".into(),
        port: 0,
        ..IssuerConfig::default()
    })
    .await;
    let issuer = idp.base_url.to_string();
    let issuer = issuer.trim_end_matches('/').to_owned();
    let client = idp
        .register_client(json!({
            "redirect_uris": [callback],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid",
        }))
        .await;
    let secret = client.client_secret.clone().unwrap_or_default();
    let auth_base = format!("http://127.0.0.1:{auth_port}");
    let env_pairs = vec![
        ("CONNETTO_AUTH".to_owned(), "in-memory".to_owned()),
        (
            "CONNETTO_AUTH_BIND".to_owned(),
            format!("127.0.0.1:{auth_port}"),
        ),
        ("CONNETTO_OIDC_PROVIDER".to_owned(), "generic".to_owned()),
        ("CONNETTO_OIDC_NAME".to_owned(), "mock-idp".to_owned()),
        ("CONNETTO_OIDC_ISSUER".to_owned(), issuer),
        ("CONNETTO_OIDC_CLIENT_ID".to_owned(), client.client_id),
        ("CONNETTO_OIDC_CLIENT_SECRET".to_owned(), secret),
        ("CONNETTO_OIDC_REDIRECT_URL".to_owned(), callback),
    ];
    AuthStack {
        _idp: idp,
        env_pairs,
        auth_base,
    }
}

/// Drive the login dance through the server binary's auth endpoints and return
/// the minted `(access_token, user_id)` pair.
///
/// The identity provider auto-grants consent, so a plain GET to its authorize
/// endpoint returns a redirect carrying the code. Without a client
/// `redirect_uri` in the login request the callback responds with JSON.
async fn mint_token(auth_base: &str) -> (String, String) {
    let agent = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build token-mint HTTP client");

    let login = agent
        .get(format!("{auth_base}/auth/login"))
        .query(&[("provider", "mock-idp")])
        .send()
        .await
        .expect("GET /auth/login");
    assert!(
        login.status().is_redirection(),
        "login must redirect, got {}",
        login.status()
    );
    let authorize_url = login
        .headers()
        .get("location")
        .expect("location on login redirect")
        .to_str()
        .expect("utf-8 location")
        .to_owned();

    let authorized = agent
        .get(&authorize_url)
        .send()
        .await
        .expect("GET idp authorize");
    assert!(
        authorized.status().is_redirection(),
        "idp authorize must redirect, got {}",
        authorized.status()
    );
    let callback_url = authorized
        .headers()
        .get("location")
        .expect("location on authorize redirect")
        .to_str()
        .expect("utf-8 location")
        .to_owned();

    let callback_resp = agent
        .get(&callback_url)
        .send()
        .await
        .expect("GET /auth/callback");
    let body: serde_json::Value = callback_resp.json().await.expect("callback JSON body");
    let access_token = body["access_token"]
        .as_str()
        .expect("access_token in callback JSON")
        .to_owned();
    let user_id = body["user_id"]
        .as_str()
        .expect("user_id in callback JSON")
        .to_owned();
    (access_token, user_id)
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
    let auth_port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let ws = format!("ws://127.0.0.1:{port}/");
    let auth_bind = format!("127.0.0.1:{auth_port}");

    let auth_stack = build_auth_stack(auth_port).await;
    let auth_pairs: Vec<(&str, &str)> = auth_stack
        .env_pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let _server = spawn_server_cfg(
        &url,
        &bind,
        PG_DDL,
        "orders",
        Some(&reader_url),
        &auth_pairs,
    );
    let secs = Duration::from_secs(20);
    assert!(
        wait_for_port(&bind, secs).await,
        "server did not open {bind}"
    );
    assert!(
        wait_for_port(&auth_bind, secs).await,
        "auth endpoints did not open {auth_bind}"
    );

    let (token_a, _) = mint_token(&auth_stack.auth_base).await;
    let (token_b, _) = mint_token(&auth_stack.auth_base).await;

    let mut dir = ReplicaDir::new();
    let db_a = dir.replica("client-a.db");
    let db_b = dir.replica("client-b.db");
    let _client_a = spawn_client(&ws, &db_a, "client-a", &token_a, None);
    let _client_b = spawn_client(&ws, &db_b, "client-b", &token_b, None);

    // Snapshot: both clients receive the pre-existing seed row.
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
    let auth_port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let ws = format!("ws://127.0.0.1:{port}/");
    let auth_bind = format!("127.0.0.1:{auth_port}");

    let auth_stack = build_auth_stack(auth_port).await;
    let auth_pairs: Vec<(&str, &str)> = auth_stack
        .env_pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let _server = spawn_server_cfg(
        &url,
        &bind,
        PG_DDL,
        "orders",
        Some(&reader_url),
        &auth_pairs,
    );
    let secs = Duration::from_secs(20);
    assert!(
        wait_for_port(&bind, secs).await,
        "server did not open {bind}"
    );
    assert!(
        wait_for_port(&auth_bind, secs).await,
        "auth endpoints did not open {auth_bind}"
    );

    let (token_reader, _) = mint_token(&auth_stack.auth_base).await;
    let (token_writer, _) = mint_token(&auth_stack.auth_base).await;

    let mut dir = ReplicaDir::new();
    let db_writer = dir.replica("writer.db");
    let db_reader = dir.replica("reader.db");

    // Bring the reader up first and let it snapshot the seed row, so the
    // writer's row can only reach it over CDC, not in the reader's own snapshot.
    let _reader = spawn_client(&ws, &db_reader, "reader", &token_reader, None);
    assert_eq!(
        wait_for_rows(&db_reader, 1, secs).await,
        1,
        "reader snapshot"
    );

    // The writer subscribes, applies its local insert, and pushes it. The
    // server applies it as app_reader; orders carries no policy so the write is allowed.
    let write = "INSERT INTO orders VALUES (42, 2.5, 4, 'from-writer')";
    let _writer = spawn_client(&ws, &db_writer, "writer", &token_writer, Some(write));

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

    let auth_port = free_port();
    let auth_stack = build_auth_stack(auth_port).await;
    let auth_pairs: Vec<(&str, &str)> = auth_stack
        .env_pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

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
        // to), and the writer only needs DML on it. Keyed on session_id alone (R2).
        "CREATE TABLE _connetto_mutations \
         (session_id UUID PRIMARY KEY, last_seq BIGINT NOT NULL)",
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
    let auth_bind = format!("127.0.0.1:{auth_port}");

    let _server = spawn_server_cfg(
        &url,
        &bind,
        OWNED_PG_DDL,
        "owned",
        Some(&reader_url),
        &auth_pairs,
    );
    let secs = Duration::from_secs(20);
    assert!(
        wait_for_port(&bind, secs).await,
        "server did not open {bind}"
    );
    assert!(
        wait_for_port(&auth_bind, secs).await,
        "auth endpoints did not open {auth_bind}"
    );

    // Mint alice's token and derive the row owner from the resolved user_id.
    // The in-memory store maps (issuer, subject) to a UUID v5, and the RLS
    // policy compares owner against app.user_id, so the owner must be that UUID.
    let (alice_token, alice_id) = mint_token(&auth_stack.auth_base).await;

    let mut dir = ReplicaDir::new();
    let db = dir.replica("alice.db");

    // Alice pushes three ordered mutations on one session: an owned insert
    // (allowed), a foreign insert with a literal owner that does not match
    // app.user_id (refused by the policy's implicit WITH CHECK), and a second
    // owned insert. The session applies frames in order, so once the third row
    // lands the foreign one has already been processed and refused.
    let writes = format!(
        "INSERT INTO owned VALUES (1, '{alice_id}', 'mine')\n\
         INSERT INTO owned VALUES (2, 'bob', 'theirs')\n\
         INSERT INTO owned VALUES (3, '{alice_id}', 'also mine')"
    );
    let _alice = spawn_client_env(
        &ws,
        &db,
        "alice",
        OWNED_SQLITE_DDL,
        OWNED_PG_DDL,
        "owned",
        OWNED_QUERY,
        &alice_token,
        Some(writes.as_str()),
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
        vec![(1, alice_id.clone()), (3, alice_id.clone())],
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

    // Auth must be configured so the server reaches the reader-role check.
    // The server exits before binding auth endpoints, so auth_port is a placeholder.
    let auth_port = free_port();
    let auth_stack = build_auth_stack(auth_port).await;
    let auth_pairs: Vec<(&str, &str)> = auth_stack
        .env_pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let output = run_server_exit_output(&url, None, &auth_pairs).await;
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

#[tokio::test]
#[ignore = "requires a running Postgres with wal_level=logical (Docker) and both binaries built"]
async fn e2e_startup_refuses_without_an_auth_store() {
    let _serial = PG_SERIAL.lock().await;
    let url = database_url();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool).await;

    // A reader URL is provided but CONNETTO_AUTH is deliberately absent.
    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let output = run_server_exit_output(&url, Some(&reader_url), &[]).await;
    assert!(
        !output.status.success(),
        "expected nonzero exit without CONNETTO_AUTH"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CONNETTO_AUTH"),
        "expected CONNETTO_AUTH in stderr, got: {stderr}"
    );
}

/// The structured log, read back off the real server's stdout.
///
/// R12 part A. Three properties: the destination is stdout and every line is
/// one JSON object, work serving a caller carries the durable session handle
/// and the identity without the writing site naming either, and an event that
/// belongs to no session carries no stand-in for one.
#[tokio::test]
#[ignore = "requires a running Postgres with wal_level=logical (Docker) and both binaries built"]
async fn e2e_server_logs_json_to_stdout_with_the_connection_context() {
    assert!(
        client_bin().exists(),
        "client binary missing at {}: build it with the same profile, \
         `cargo build --release -p connetto-client --bin connetto-client --all-features`",
        client_bin().display()
    );
    let _serial = PG_SERIAL.lock().await;

    let url = database_url();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool).await;

    let port = free_port();
    let auth_port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let ws = format!("ws://127.0.0.1:{port}/");
    let auth_stack = build_auth_stack(auth_port).await;
    let reader_url = with_user_url(&url, "app_reader", "app_reader");

    let mut command = Command::new(server_bin());
    command
        .env("DATABASE_URL", &url)
        .env("CONNETTO_BIND", &bind)
        .env("CONNETTO_PG_DDL", PG_DDL)
        .env("CONNETTO_WRITABLE", "orders")
        .env("CONNETTO_SLOT", SLOT)
        .env("CONNETTO_PUBLICATION", PUBLICATION)
        .env("CONNETTO_READER_URL", &reader_url)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    for (key, value) in &auth_stack.env_pairs {
        command.env(key, value);
    }
    let mut server = command.spawn().expect("spawn server");

    let secs = Duration::from_secs(20);
    assert!(
        wait_for_port(&bind, secs).await,
        "server did not open {bind}"
    );

    let (token, user_id) = mint_token(&auth_stack.auth_base).await;
    let mut dir = ReplicaDir::new();
    let db = dir.replica("log-probe.db");
    let client = spawn_client(&ws, &db, "log-probe", &token, None);
    assert_eq!(
        wait_for_rows(&db, 1, secs).await,
        1,
        "the probe client never received its snapshot"
    );
    drop(client);

    // Rust's stdout is line buffered, so every line already emitted is in the
    // pipe and a kill loses none of them.
    server.kill().expect("kill the server");
    let output = tokio::task::spawn_blocking(move || server.wait_with_output())
        .await
        .expect("spawn_blocking task panicked")
        .expect("read the server's output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("stdout line is not JSON ({err}): {line}"))
        })
        .collect();
    assert!(!lines.is_empty(), "the server wrote nothing to stdout");

    let listening = lines
        .iter()
        .find(|line| line["message"] == "sync listener started")
        .unwrap_or_else(|| panic!("no listener event on stdout: {stdout}"));
    assert_eq!(
        listening["bind"], bind,
        "the listener event lost its bind address"
    );
    assert!(
        listening["span"].is_null(),
        "an event fired before any session exists must carry no session context: {listening}"
    );

    let established = lines
        .iter()
        .find(|line| line["message"] == "connection established")
        .unwrap_or_else(|| panic!("no connection event on stdout: {stdout}"));
    assert_eq!(
        established["span"]["user"], user_id,
        "the connection context lost the caller's identity"
    );
    assert!(
        established["span"]["session"]
            .as_str()
            .is_some_and(|session| !session.is_empty()),
        "the connection context lost the durable session handle: {established}"
    );
}
