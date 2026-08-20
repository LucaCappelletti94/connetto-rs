//! Docker-gated multi-process end-to-end tests.
//!
//! Spawn the real `connetto-server` and `connetto-client` binaries as separate
//! OS processes and drive a full sync loop over real Postgres logical
//! replication. The suite starts its own containerised OIDC provider, so every
//! spawned server carries a real OIDC configuration and every spawned client
//! carries a minted connetto access token. One test covers the read direction:
//! each client receives the initial snapshot, then a live insert fans out to both,
//! and after the walsender is terminated the reconnect loop still reaches both.
//! The other covers the write direction: a client applies
//! a local insert and pushes it, the server's write path lands it in Postgres,
//! and it fans back out over CDC to a second client. This is the product spine
//! end to end, unlike the in-process session tests.
//!
//! Needs Docker: the fixture starts its own Postgres, its own `OpenFGA`, and
//! its own OIDC provider, and both binaries must be built in the same profile
//! as the test. Run it with:
//!
//! ```text
//! cargo build --release -p connetto-server --bin connetto-server
//! cargo build --release -p connetto-client --bin connetto-client --all-features
//! cargo test --release -p connetto-server --test e2e
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
use connetto_test_harness::{Fixture, MOCK_OAUTH_PROVIDER, MockOauth, PUBLICATION, SLOT};
use keyring_core::Entry;
use openidconnect::reqwest;
use serde_json::json;

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
const OWNED_PG_DDL: &str = "CREATE TABLE owned (id INT PRIMARY KEY, owner TEXT, body TEXT);";
const OWNED_SQLITE_DDL: &str =
    "CREATE TABLE owned (id INTEGER PRIMARY KEY, owner TEXT, body TEXT);";
const OWNED_QUERY: &str = "SELECT * FROM owned";
/// The policy document the `owned` fixture's server derives its model from.
///
/// The schema and the policies reach the binary as two documents, so the
/// statement enabling row-level security belongs here beside the policy rather
/// than in [`OWNED_PG_DDL`], which is what clients sync.
const OWNED_POLICIES: &str = "ALTER TABLE owned ENABLE ROW LEVEL SECURITY;\n\
     CREATE POLICY owned_p ON owned USING (owner = current_setting('app.user_id', true));";

/// `orders` carries no policy at all, so its document is empty.
///
/// The database filters none of its rows and the model has to agree, which the
/// translator reports and the change path answers with no round trip.
const NO_POLICIES: &str = "";

// The client replica's `orders` table, typed for the poller's count query.
diesel::table! {
    /// Row from the orders test fixture.
    orders (id) {
        /// Order identifier, the primary key.
        id -> Integer,
        /// Unit price.
        price -> Nullable<Double>,
        /// Number of units.
        quantity -> Nullable<Integer>,
        /// Order status.
        status -> Nullable<Text>,
    }
}

/// Serializes the Docker-gated tests. They reset the same Postgres and share one
/// replication slot and publication name, so they must not run concurrently.
static PG_SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

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
            if let Ok(entry) = keyring_entry(path) {
                let _ = entry.delete_credential();
            }
        }
    }
}

fn keyring_entry(name: &str) -> keyring_core::Result<Entry> {
    keyring_core::set_default_store(linux_keyutils_keyring_store::Store::new()?);
    Entry::new(CLIENT_KEYRING_SERVICE, name)
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
    let Ok(entry) = keyring_entry(&path) else {
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

/// What a spawned server needs to build its change-path executor: the policy
/// text its authorization model is derived from, and the store it writes that
/// model into.
///
/// A store per server rather than one shared, so two tests in one run cannot
/// read each other's rules or facts.
struct Authorization {
    policies: String,
    endpoint: String,
    store: String,
}

impl Authorization {
    async fn provision(fixture: &Fixture, policies: &str) -> Self {
        let endpoint = fixture.fga_url().await.to_owned();
        let (_channel, store) = fixture.fga_store().await;
        Self {
            policies: policies.to_owned(),
            endpoint,
            store,
        }
    }

    fn env_pairs(&self) -> [(&str, &str); 3] {
        [
            ("CONNETTO_PG_POLICIES", self.policies.as_str()),
            ("CONNETTO_FGA_URL", self.endpoint.as_str()),
            ("CONNETTO_FGA_STORE", self.store.as_str()),
        ]
    }
}

fn spawn_server_cfg(
    database_url: &str,
    bind: &str,
    pg_ddl: &str,
    writable: &str,
    reader_url: Option<&str>,
    authorization: &Authorization,
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
    for (k, v) in authorization.env_pairs() {
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

/// Reset the orders fixture, auth tables and reader role for one server run.
async fn reset_fixture(pool: &Pool<AsyncPgConnection>, fixture: &Fixture) {
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
    // The audit table the server appends access changes to when
    // `CONNETTO_AUDIT=database`. Dropped and recreated per run so a previous
    // run's rows cannot be mistaken for this one's.
    exec(pool, "DROP TABLE IF EXISTS auth_events").await;
    exec(pool, "DROP TYPE IF EXISTS connetto_auth_op").await;
    exec(
        pool,
        "CREATE TYPE connetto_auth_op AS ENUM (\
         'logged_out', 'session_revoked', 'token_replayed', 'capability_minted', \
         'permission_change', 'model_change', 'banned', 'ban_lifted')",
    )
    .await;
    exec(
        pool,
        "CREATE TABLE auth_events (\
         at TIMESTAMPTZ NOT NULL DEFAULT now(), session UUID NOT NULL, user_id TEXT, \
         op connetto_auth_op NOT NULL, table_name TEXT, pk UUID)",
    )
    .await;
    exec(pool, PG_DDL).await;
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
    fixture.start_replication(&["orders"]).await;
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
/// discover and use it. Holds the provider guard alive for the test.
struct AuthStack {
    _idp: MockOauth,
    /// `CONNETTO_AUTH`, `CONNETTO_AUTH_BIND`, and the `CONNETTO_OIDC_PROVIDERS` settings.
    env_pairs: Vec<(String, String)>,
    /// Base URL of the server binary's auth endpoints.
    auth_base: String,
}

/// Start the mock OAuth provider and configure connetto's auth callback at
/// `auth_port`.
async fn build_auth_stack(auth_port: u16) -> AuthStack {
    let callback = format!("http://127.0.0.1:{auth_port}/auth/callback");
    let idp = MockOauth::start().await;
    let auth_base = format!("http://127.0.0.1:{auth_port}");
    let mut env_pairs = vec![
        ("CONNETTO_AUTH".to_owned(), "in-memory".to_owned()),
        (
            "CONNETTO_AUTH_BIND".to_owned(),
            format!("127.0.0.1:{auth_port}"),
        ),
    ];
    env_pairs.extend(idp.env_pairs(MOCK_OAUTH_PROVIDER, &callback));
    AuthStack {
        _idp: idp,
        env_pairs,
        auth_base,
    }
}

/// Drive the login dance through the server binary's auth endpoints and return
/// the callback JSON body.
async fn token_body(auth_base: &str, subject: &str) -> serde_json::Value {
    let agent = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build token-mint HTTP client");

    let login = agent
        .get(format!("{auth_base}/auth/login"))
        .query(&[("provider", MOCK_OAUTH_PROVIDER)])
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
        .post(&authorize_url)
        .form(&[("username", subject)])
        .send()
        .await
        .expect("POST idp authorize");
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

    let callback = agent
        .get(&callback_url)
        .send()
        .await
        .expect("GET /auth/callback");
    let body = callback.text().await.expect("callback body");
    serde_json::from_str(&body).expect("callback JSON body")
}

/// Drive the login dance through the server binary's auth endpoints and return
/// the minted `(access_token, user_id)` pair.
async fn mint_token(auth_base: &str) -> (String, String) {
    let body = token_body(auth_base, "e2e-user").await;
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

/// The refresh token from the same login dance, which `mint_token` discards.
///
/// Only the audit test needs it, because logging out is the one producer
/// reachable from outside the process.
async fn mint_refresh_token(auth_base: &str) -> String {
    let body = token_body(auth_base, "e2e-user").await;
    body["refresh_token"]
        .as_str()
        .expect("refresh_token in callback JSON")
        .to_owned()
}

#[tokio::test]
async fn e2e_two_clients_snapshot_live_and_reconnect() {
    assert!(
        client_bin().exists(),
        "client binary missing at {}: build it with the same profile, \
         `cargo build --release -p connetto-client --bin connetto-client`",
        client_bin().display()
    );

    let _serial = PG_SERIAL.lock().await;

    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");

    reset_fixture(&pool, &fixture).await;

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
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let _server = spawn_server_cfg(
        &url,
        &bind,
        PG_DDL,
        "orders",
        Some(&reader_url),
        &authorization,
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
async fn e2e_client_write_lands_in_pg_and_fans_out() {
    assert!(
        client_bin().exists(),
        "client binary missing at {}: build it with the same profile, \
         `cargo build --release -p connetto-client --bin connetto-client`",
        client_bin().display()
    );

    let _serial = PG_SERIAL.lock().await;

    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");

    reset_fixture(&pool, &fixture).await;

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
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let _server = spawn_server_cfg(
        &url,
        &bind,
        PG_DDL,
        "orders",
        Some(&reader_url),
        &authorization,
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
async fn e2e_rls_write_enforced_owned_lands_foreign_refused() {
    assert!(
        client_bin().exists(),
        "client binary missing at {}: build it with the same profile, \
         `cargo build --release -p connetto-client --bin connetto-client`",
        client_bin().display()
    );

    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
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

    // The server applies writes as `app_writer`, which is subject to the policy.
    for stmt in [
        "DROP TABLE IF EXISTS owned CASCADE",
        "DROP TABLE IF EXISTS _connetto_mutations",
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
         THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$",
        "CREATE TABLE owned (id INT PRIMARY KEY, owner TEXT, body TEXT)",
        "ALTER TABLE owned ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY owned_p ON owned USING (owner = current_setting('app.user_id', true))",
        // The test creates the exactly-once watermark table. connetto emits no
        // DDL, the restricted writer role cannot CREATE in schema public on
        // Postgres 15+ and the writer only needs DML on it. Keyed on session_id
        // alone (R2).
        "CREATE TABLE _connetto_mutations \
         (session_id UUID PRIMARY KEY, last_seq BIGINT NOT NULL)",
        "GRANT USAGE ON SCHEMA public TO app_writer",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON owned TO app_writer",
        "GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_writer",
    ] {
        exec(&admin, stmt).await;
    }
    fixture.start_replication(&["owned"]).await;

    let reader_url = with_user_url(&url, "app_writer", "app_writer");

    let port = free_port();
    let bind = format!("127.0.0.1:{port}");
    let ws = format!("ws://127.0.0.1:{port}/");
    let auth_bind = format!("127.0.0.1:{auth_port}");

    let authorization = Authorization::provision(&fixture, OWNED_POLICIES).await;
    let _server = spawn_server_cfg(
        &url,
        &bind,
        OWNED_PG_DDL,
        "owned",
        Some(&reader_url),
        &authorization,
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

/// R5b's unrestricted-table evidence, relocated here by R40: R40 added a real
/// policy to `examples/wasm-smoke`'s `orders` table, the only policy-free table
/// the original browser-run demonstration used, so the proof now lives here.
///
/// The test checks that a server started with empty `CONNETTO_PG_POLICIES`
/// delivers the seed row from a policy-free `orders` fixture, and delivery
/// requires the server to answer the visibility question locally from its
/// unrestricted-table list, because delegating to an authorization service with
/// an empty model would error and the server would stall fail-closed.
///
/// The `AUTHORIZATION_CALLS` counter that proves zero round trips at scale is
/// not visible from a test that spawns the server binary, so that count is
/// proven in `fanout_counters.rs`.
#[tokio::test]
async fn e2e_unrestricted_table_delivers_without_policy() {
    assert!(
        client_bin().exists(),
        "client binary missing at {}: build it with the same profile, \
         `cargo build --release -p connetto-client --bin connetto-client`",
        client_bin().display()
    );

    let _serial = PG_SERIAL.lock().await;

    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");

    reset_fixture(&pool, &fixture).await;

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
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let _server = spawn_server_cfg(
        &url,
        &bind,
        PG_DDL,
        "orders",
        Some(&reader_url),
        &authorization,
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

    let (token, _) = mint_token(&auth_stack.auth_base).await;

    let mut dir = ReplicaDir::new();
    let db = dir.replica("client.db");
    let _client = spawn_client(&ws, &db, "client", &token, None);

    assert_eq!(
        wait_for_rows(&db, 1, secs).await,
        1,
        "unrestricted orders table did not deliver its seed row through an empty-policy server"
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
async fn e2e_startup_refuses_without_a_reader_role() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;

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
async fn e2e_startup_refuses_an_unrecognised_oidc_provider() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;

    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let output = run_server_exit_output(
        &url,
        Some(&reader_url),
        &[
            ("CONNETTO_AUTH", "in-memory"),
            ("CONNETTO_OIDC_PROVIDERS", "myprovider"),
            ("CONNETTO_OIDC_MYPROVIDER_KIND", "frobnicate"),
            ("CONNETTO_OIDC_MYPROVIDER_CLIENT_ID", "unused"),
            (
                "CONNETTO_OIDC_MYPROVIDER_REDIRECT_URL",
                "http://127.0.0.1/callback",
            ),
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

/// Asking for records without asking for logins refuses startup.
///
/// Every access change recorded comes from the login machinery, so with logins
/// off there is nothing to record. The first version of this wiring sat behind
/// the early return for no logins, so the setting was accepted and silently
/// did nothing, which is the failure this pins.
#[tokio::test]
async fn e2e_startup_refuses_audit_without_auth() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;

    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let output =
        run_server_exit_output(&url, Some(&reader_url), &[("CONNETTO_AUDIT", "database")]).await;
    assert!(
        !output.status.success(),
        "expected nonzero exit for records without logins"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CONNETTO_AUTH"),
        "the refusal must name the missing setting, got: {stderr}"
    );
}

/// An unrecognised recording mode refuses startup, matching every other mode
/// setting the binary reads.
#[tokio::test]
async fn e2e_startup_refuses_an_unrecognised_audit_mode() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;

    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let output = run_server_exit_output(
        &url,
        Some(&reader_url),
        &[("CONNETTO_AUTH", "in-memory"), ("CONNETTO_AUDIT", "sqlite")],
    )
    .await;
    assert!(
        !output.status.success(),
        "expected nonzero exit for an unrecognised audit mode"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"sqlite\""),
        "expected the Debug-quoted mode in stderr, got: {stderr}"
    );
}

#[tokio::test]
async fn e2e_startup_refuses_a_miscapitalised_provider_name() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;

    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let output = run_server_exit_output(
        &url,
        Some(&reader_url),
        &[
            ("CONNETTO_AUTH", "in-memory"),
            ("CONNETTO_OIDC_PROVIDERS", "myprovider"),
            ("CONNETTO_OIDC_MYPROVIDER_KIND", "Google"),
            ("CONNETTO_OIDC_MYPROVIDER_CLIENT_ID", "unused"),
            (
                "CONNETTO_OIDC_MYPROVIDER_REDIRECT_URL",
                "http://127.0.0.1/callback",
            ),
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
async fn e2e_startup_refuses_without_an_auth_store() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;

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
async fn e2e_server_logs_json_to_stdout_with_the_connection_context() {
    assert!(
        client_bin().exists(),
        "client binary missing at {}: build it with the same profile, \
         `cargo build --release -p connetto-client --bin connetto-client --all-features`",
        client_bin().display()
    );
    let _serial = PG_SERIAL.lock().await;

    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;

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
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    for (key, value) in authorization.env_pairs() {
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

/// A real logout against a real server leaves exactly one row saying so.
///
/// The two audit suites beside this one each attach their own collector, so
/// they prove the parts and never the whole. That is how the reference server
/// shipped without ever switching recording on: every test supplied its own
/// sink, so a green run said nothing about the wiring. This is the only test
/// that exercises the switch, the startup shape check, the ready-made writer,
/// and the table together, through a process nobody handed a collector to.
#[tokio::test]
async fn e2e_a_real_logout_is_recorded_in_the_audit_table() {
    let _serial = PG_SERIAL.lock().await;

    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;

    let port = free_port();
    let auth_port = free_port();
    let bind = format!("127.0.0.1:{port}");
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
        // The switch under test. Without it the server records nothing, which
        // is the default and is what shipped by accident.
        .env("CONNETTO_AUDIT", "database")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (key, value) in &auth_stack.env_pairs {
        command.env(key, value);
    }
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    for (key, value) in authorization.env_pairs() {
        command.env(key, value);
    }
    let _server = ChildGuard(command.spawn().expect("spawn server"));

    let secs = Duration::from_secs(20);
    assert!(
        wait_for_port(&bind, secs).await,
        "server did not open {bind}: with CONNETTO_AUDIT=database it refuses to \
         start unless the audit table matches"
    );

    assert_eq!(
        audit_ops(&pool).await,
        Vec::<String>::new(),
        "logging in changes nobody's access, so it records nothing"
    );

    let refresh_token = mint_refresh_token(&auth_stack.auth_base).await;
    let agent = reqwest::Client::new();
    let logout = agent
        .post(format!("{}/auth/logout", auth_stack.auth_base))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json!({ "refresh_token": refresh_token }).to_string())
        .send()
        .await
        .expect("POST /auth/logout");
    assert!(logout.status().is_success(), "logout: {}", logout.status());

    // The write is spawned, so it lands shortly after the response.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut ops = audit_ops(&pool).await;
    while ops.is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        ops = audit_ops(&pool).await;
    }
    assert_eq!(
        ops,
        vec!["logged_out".to_owned()],
        "a real logout leaves exactly one row, saying it was a logout"
    );
}

/// Every `op` recorded so far, in order.
async fn audit_ops(pool: &Pool<AsyncPgConnection>) -> Vec<String> {
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Text)]
        op: String,
    }
    let mut conn = pool.get().await.expect("connection");
    let rows: Vec<Row> =
        sql_query("SELECT CAST(op AS TEXT) AS op FROM auth_events ORDER BY at, op")
            .get_results(&mut conn)
            .await
            .expect("read auth_events");
    rows.into_iter().map(|row| row.op).collect()
}
