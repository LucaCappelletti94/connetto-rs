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

pub(super) const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";
pub(super) const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
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
pub(super) const NO_POLICIES: &str = "";

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
pub(super) static PG_SERIAL: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

fn server_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_connetto-server"))
}

/// The client binary is a sibling of the server binary in the same target
/// profile directory. It is built by a separate crate, so it must already exist.
pub(super) fn client_bin() -> PathBuf {
    server_bin()
        .parent()
        .expect("target profile directory")
        .join("connetto-client")
}

/// Kills its child on drop so a panicking assertion never leaks a process.
pub(super) struct ChildGuard(Option<Child>);

impl ChildGuard {
    pub(super) fn new(child: Child) -> Self {
        Self(Some(child))
    }

    /// The child's exit status, if it has exited.
    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.0.as_mut()?.try_wait().ok().flatten()
    }

    /// Kill the child and collect what it wrote to its piped streams.
    pub(super) async fn kill_and_collect(mut self) -> std::process::Output {
        let mut child = self.0.take().expect("a child the guard still holds");
        child.kill().expect("kill the child");
        tokio::task::spawn_blocking(move || child.wait_with_output())
            .await
            .expect("spawn_blocking task panicked")
            .expect("read the child's output")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
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
pub(super) struct ReplicaDir {
    dir: TempDir,
    replicas: Vec<String>,
}

impl ReplicaDir {
    pub(super) fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
            replicas: Vec::new(),
        }
    }

    /// A replica path inside the directory, registered for keyring cleanup.
    pub(super) fn replica(&mut self, name: &str) -> PathBuf {
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

pub(super) fn keyring_entry(name: &str) -> keyring_core::Result<Entry> {
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
pub(super) async fn wait_for_rows(db_path: &Path, want: i64, timeout: Duration) -> i64 {
    let deadline = Instant::now() + timeout;
    loop {
        let seen = count_orders(db_path);
        if seen >= want || Instant::now() >= deadline {
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Start a server again on the ports an earlier start of it used, and wait
/// until it serves as [`start_server`] does. The ports are not reserved in
/// between, so another process can take one, and this then fails naming the
/// exit rather than starting on fresh ports, since the test observes a
/// restart.
pub(super) async fn restart_server(
    auth: &AuthStack,
    ports: Ports,
    timeout: Duration,
    spawn: impl FnOnce(Ports, &[(&str, &str)]) -> ChildGuard,
) -> ChildGuard {
    let pairs = auth.env_pairs(ports.auth);
    let pairs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut server = spawn(ports, &pairs);
    match await_serving(&mut server, ports, timeout).await {
        Ok(()) => server,
        Err(Startup::Exited(status)) => {
            panic!("the restarted server on {ports:?} exited with {status}")
        }
        Err(Startup::Silent(seen)) => panic!(
            "the restarted server on {ports:?} did not answer within {timeout:?}, last seen {seen}"
        ),
    }
}

/// A free localhost port, released before the caller binds it, so anything
/// else may take it first. A server started on one goes through
/// [`start_server`], which notices that and starts it again.
pub(super) fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// The sync and auth ports one server listens on.
#[derive(Clone, Copy, Debug)]
pub(super) struct Ports {
    pub(super) sync: u16,
    pub(super) auth: u16,
}

impl Ports {
    fn reserve() -> Self {
        let sync = free_port();
        loop {
            let auth = free_port();
            if auth != sync {
                return Self { sync, auth };
            }
        }
    }

    pub(super) fn bind(self) -> String {
        format!("127.0.0.1:{}", self.sync)
    }

    pub(super) fn ws(self) -> String {
        format!("ws://127.0.0.1:{}/", self.sync)
    }

    /// Base URL of the auth endpoints, which also serve the file routes.
    pub(super) fn auth_base(self) -> String {
        format!("http://127.0.0.1:{}", self.auth)
    }
}

/// How many times [`start_server`] starts a server before giving up on
/// losing its ports.
const START_ATTEMPTS: u32 = 3;

/// Start a server through `spawn` on freshly reserved ports, and wait until
/// both listeners answer as that server: the login endpoint redirects to the
/// provider and the sync port completes a WebSocket handshake.
///
/// A reserved port is free only until the server binds it, and a container
/// published in between can take it. The server then exits naming the bind,
/// and this starts it again on fresh ports, at most [`START_ATTEMPTS`] times.
/// `spawn` gets the ports and the auth settings for them.
pub(super) async fn start_server(
    auth: &AuthStack,
    timeout: Duration,
    spawn: impl FnMut(Ports, &[(&str, &str)]) -> ChildGuard,
) -> (ChildGuard, Ports) {
    start_server_on(auth, timeout, Ports::reserve, spawn).await
}

/// [`start_server`] with the ports each attempt starts on coming from
/// `reserve`.
async fn start_server_on(
    auth: &AuthStack,
    timeout: Duration,
    mut reserve: impl FnMut() -> Ports,
    mut spawn: impl FnMut(Ports, &[(&str, &str)]) -> ChildGuard,
) -> (ChildGuard, Ports) {
    let mut attempt = 1;
    loop {
        let ports = reserve();
        let pairs = auth.env_pairs(ports.auth);
        let pairs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let mut server = spawn(ports, &pairs);
        match await_serving(&mut server, ports, timeout).await {
            Ok(()) => return (server, ports),
            Err(Startup::Exited(status)) if attempt < START_ATTEMPTS => {
                eprintln!(
                    "the server on {ports:?} exited with {status} while starting, starting it again"
                );
                attempt += 1;
            }
            Err(Startup::Exited(status)) => {
                panic!("the server exited with {status} while starting, {START_ATTEMPTS} times")
            }
            Err(Startup::Silent(seen)) => {
                panic!(
                    "the server on {ports:?} did not answer within {timeout:?}, last seen {seen}"
                )
            }
        }
    }
}

/// Why a started server is not serving.
enum Startup {
    Exited(std::process::ExitStatus),
    Silent(String),
}

/// How long one readiness probe may take, so a listener that accepts and
/// never answers cannot hold the wait past its deadline.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

async fn await_serving(
    server: &mut ChildGuard,
    ports: Ports,
    timeout: Duration,
) -> Result<(), Startup> {
    let agent = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(PROBE_TIMEOUT)
        .build()
        .expect("build the readiness HTTP client");
    let deadline = Instant::now() + timeout;
    let mut seen = String::from("nothing");
    loop {
        if let Some(status) = server.exited() {
            return Err(Startup::Exited(status));
        }
        if Instant::now() >= deadline {
            return Err(Startup::Silent(seen));
        }
        match agent
            .get(format!("{}/auth/login", ports.auth_base()))
            .query(&[("provider", MOCK_OAUTH_PROVIDER)])
            .send()
            .await
        {
            Ok(login) if login.status().is_redirection() => {
                let handshake = tokio::time::timeout(PROBE_TIMEOUT, async {
                    let tcp = tokio::net::TcpStream::connect(ports.bind())
                        .await
                        .map_err(|err| format!("the sync port closed ({err})"))?;
                    connetto_server::WebSocketTransport::connect(&ports.ws(), tcp)
                        .await
                        .map_err(|err| format!("the sync port refusing a handshake ({err})"))
                })
                .await;
                match handshake {
                    Ok(Ok(_)) => return Ok(()),
                    Ok(Err(why)) => seen = why,
                    Err(_) => "the sync port silent through a handshake".clone_into(&mut seen),
                }
            }
            Ok(login) => seen = format!("the login endpoint answering {}", login.status()),
            Err(err) => seen = format!("the login endpoint unreachable ({err})"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// What a spawned server needs to build its change-path executor: the policy
/// text its authorization model is derived from, and the store it writes that
/// model into.
///
/// A store per server rather than one shared, so two tests in one run cannot
/// read each other's rules or facts.
pub(super) struct Authorization {
    policies: String,
    pub(super) endpoint: String,
    pub(super) store: String,
}

impl Authorization {
    pub(super) async fn provision(fixture: &Fixture, policies: &str) -> Self {
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

pub(super) fn spawn_server_cfg(
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
    ChildGuard::new(child)
}

pub(super) fn spawn_client(
    ws: &str,
    db_path: &Path,
    client_id: &str,
    token: &str,
    write: Option<&str>,
) -> ChildGuard {
    spawn_client_env(
        ws,
        db_path,
        client_id,
        SQLITE_DDL,
        PG_DDL,
        NO_POLICIES,
        "orders",
        QUERY,
        token,
        write,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the argument list mirrors the client binary's environment surface"
)]
pub(super) fn spawn_client_env(
    ws: &str,
    db_path: &Path,
    client_id: &str,
    sqlite_ddl: &str,
    schema_sql: &str,
    policies_sql: &str,
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
        // Beside it, because the server hashes both into the version it
        // advertises: a policy decides what the replica's own views admit.
        .env("CONNETTO_POLICIES_SQL", policies_sql)
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
    ChildGuard::new(child)
}

/// Run a single DDL/DML statement in its own transaction (autocommit).
pub(super) async fn exec(pool: &Pool<AsyncPgConnection>, sql: &str) {
    let mut conn = pool.get().await.expect("admin connection");
    sql_query(sql)
        .execute(&mut *conn)
        .await
        .unwrap_or_else(|err| panic!("statement failed ({sql}): {err}"));
}

/// Reset the orders fixture, auth tables and reader role for one server run.
pub(super) async fn reset_fixture(pool: &Pool<AsyncPgConnection>, fixture: &Fixture) {
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
pub(super) fn with_user_url(url: &str, user: &str, password: &str) -> String {
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

/// A loopback identity provider the server binary signs users in through.
/// Started before any port is reserved, since the container's published port
/// comes from the same range [`free_port`] draws from.
pub(super) struct AuthStack {
    idp: MockOauth,
}

impl AuthStack {
    /// `CONNETTO_AUTH`, `CONNETTO_AUTH_BIND`, and the `CONNETTO_OIDC_PROVIDERS`
    /// settings for a server whose auth endpoints listen on `auth_port`.
    pub(super) fn env_pairs(&self, auth_port: u16) -> Vec<(String, String)> {
        let callback = format!("http://127.0.0.1:{auth_port}/auth/callback");
        let mut pairs = vec![
            ("CONNETTO_AUTH".to_owned(), "in-memory".to_owned()),
            (
                "CONNETTO_AUTH_BIND".to_owned(),
                format!("127.0.0.1:{auth_port}"),
            ),
        ];
        pairs.extend(self.idp.env_pairs(MOCK_OAUTH_PROVIDER, &callback));
        pairs
    }
}

/// Start the mock OAuth provider.
pub(super) async fn build_auth_stack() -> AuthStack {
    AuthStack {
        idp: MockOauth::start().await,
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
pub(super) async fn mint_token(auth_base: &str) -> (String, String) {
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
pub(super) async fn mint_refresh_token(auth_base: &str) -> String {
    let body = token_body(auth_base, "e2e-user").await;
    body["refresh_token"]
        .as_str()
        .expect("refresh_token in callback JSON")
        .to_owned()
}

#[tokio::test]
async fn e2e_two_clients_snapshot_live_and_reconnect() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
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

    let auth_stack = build_auth_stack().await;
    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let secs = Duration::from_secs(20);
    let (_server, ports) = start_server(&auth_stack, secs, |ports, auth_pairs| {
        spawn_server_cfg(
            &url,
            &ports.bind(),
            PG_DDL,
            "orders",
            Some(&reader_url),
            &authorization,
            auth_pairs,
        )
    })
    .await;
    let (ws, auth_base) = (ports.ws(), ports.auth_base());

    let (token_a, _) = mint_token(&auth_base).await;
    let (token_b, _) = mint_token(&auth_base).await;

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
    let _keyring = connetto_test_harness::isolated_session_keyring();
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

    let auth_stack = build_auth_stack().await;
    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let secs = Duration::from_secs(20);
    let (_server, ports) = start_server(&auth_stack, secs, |ports, auth_pairs| {
        spawn_server_cfg(
            &url,
            &ports.bind(),
            PG_DDL,
            "orders",
            Some(&reader_url),
            &authorization,
            auth_pairs,
        )
    })
    .await;
    let (ws, auth_base) = (ports.ws(), ports.auth_base());

    let (token_reader, _) = mint_token(&auth_base).await;
    let (token_writer, _) = mint_token(&auth_base).await;

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
    let _keyring = connetto_test_harness::isolated_session_keyring();
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

    let auth_stack = build_auth_stack().await;

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

    let authorization = Authorization::provision(&fixture, OWNED_POLICIES).await;
    let secs = Duration::from_secs(20);
    let (_server, ports) = start_server(&auth_stack, secs, |ports, auth_pairs| {
        spawn_server_cfg(
            &url,
            &ports.bind(),
            OWNED_PG_DDL,
            "owned",
            Some(&reader_url),
            &authorization,
            auth_pairs,
        )
    })
    .await;
    let (ws, auth_base) = (ports.ws(), ports.auth_base());

    // Mint alice's token and derive the row owner from the resolved user_id.
    // The in-memory store maps (issuer, subject) to a UUID v5, and the RLS
    // policy compares owner against app.user_id, so the owner must be that UUID.
    let (alice_token, alice_id) = mint_token(&auth_base).await;

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
        OWNED_POLICIES,
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

/// A server whose login port another process took before the server bound it
/// is started again on fresh ports, and the test proceeds against it.
#[tokio::test]
async fn e2e_a_taken_port_starts_the_server_again_on_fresh_ports() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;

    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;

    let auth_stack = build_auth_stack().await;
    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let mut taken: Option<(Ports, std::net::TcpListener)> = None;
    let reserve = || {
        let ports = Ports::reserve();
        if taken.is_none() {
            let thief = std::net::TcpListener::bind(format!("127.0.0.1:{}", ports.auth))
                .expect("take the first login port");
            taken = Some((ports, thief));
        }
        ports
    };
    let (_server, ports) = start_server_on(
        &auth_stack,
        Duration::from_secs(20),
        reserve,
        |ports, auth_pairs| {
            spawn_server_cfg(
                &url,
                &ports.bind(),
                PG_DDL,
                "orders",
                Some(&reader_url),
                &authorization,
                auth_pairs,
            )
        },
    )
    .await;

    let (first, _thief) = taken.expect("the first start reserved ports");
    assert_ne!(
        ports.auth, first.auth,
        "the server serves on fresh ports, not the taken one"
    );
    let (access, _) = mint_token(&ports.auth_base()).await;
    assert!(!access.is_empty(), "the restarted server signs a user in");
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
    let _keyring = connetto_test_harness::isolated_session_keyring();
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

    let auth_stack = build_auth_stack().await;
    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let secs = Duration::from_secs(20);
    let (_server, ports) = start_server(&auth_stack, secs, |ports, auth_pairs| {
        spawn_server_cfg(
            &url,
            &ports.bind(),
            PG_DDL,
            "orders",
            Some(&reader_url),
            &authorization,
            auth_pairs,
        )
    })
    .await;
    let (ws, auth_base) = (ports.ws(), ports.auth_base());

    let (token, _) = mint_token(&auth_base).await;

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
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;

    // Auth must be configured so the server reaches the reader-role check.
    // The server exits before binding auth endpoints, so auth_port is a placeholder.
    let auth_stack = build_auth_stack().await;
    let auth_env = auth_stack.env_pairs(free_port());
    let auth_pairs: Vec<(&str, &str)> = auth_env
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
    let _keyring = connetto_test_harness::isolated_session_keyring();
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
    let _keyring = connetto_test_harness::isolated_session_keyring();
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
    let _keyring = connetto_test_harness::isolated_session_keyring();
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
    let _keyring = connetto_test_harness::isolated_session_keyring();
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
    let _keyring = connetto_test_harness::isolated_session_keyring();
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
    let _keyring = connetto_test_harness::isolated_session_keyring();
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

    let auth_stack = build_auth_stack().await;
    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let secs = Duration::from_secs(20);
    let (server, ports) = start_server(&auth_stack, secs, |ports, auth_pairs| {
        let mut command = Command::new(server_bin());
        command
            .env("DATABASE_URL", &url)
            .env("CONNETTO_BIND", ports.bind())
            .env("CONNETTO_PG_DDL", PG_DDL)
            .env("CONNETTO_WRITABLE", "orders")
            .env("CONNETTO_SLOT", SLOT)
            .env("CONNETTO_PUBLICATION", PUBLICATION)
            .env("CONNETTO_READER_URL", &reader_url)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        command.envs(auth_pairs.iter().copied());
        command.envs(authorization.env_pairs());
        ChildGuard::new(command.spawn().expect("spawn server"))
    })
    .await;
    let (bind, ws) = (ports.bind(), ports.ws());

    let (token, user_id) = mint_token(&ports.auth_base()).await;
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
    let output = server.kill_and_collect().await;
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
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;

    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;

    let auth_stack = build_auth_stack().await;
    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    // With CONNETTO_AUDIT=database the server refuses to start unless the
    // audit table matches, which start_server reports as an exit.
    let (_server, ports) =
        start_server(&auth_stack, Duration::from_secs(20), |ports, auth_pairs| {
            let mut command = Command::new(server_bin());
            command
                .env("DATABASE_URL", &url)
                .env("CONNETTO_BIND", ports.bind())
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
            command.envs(auth_pairs.iter().copied());
            command.envs(authorization.env_pairs());
            ChildGuard::new(command.spawn().expect("spawn server"))
        })
        .await;
    let auth_base = ports.auth_base();

    assert_eq!(
        audit_ops(&pool).await,
        Vec::<String>::new(),
        "logging in changes nobody's access, so it records nothing"
    );

    let refresh_token = mint_refresh_token(&auth_base).await;
    let agent = reqwest::Client::new();
    let logout = agent
        .post(format!("{auth_base}/auth/logout"))
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

/// Removes every artifact the content tests create, so each run starts from
/// the deployment state its name describes. One statement per entry because
/// diesel sends each query prepared, and Postgres refuses a batch there.
#[cfg(feature = "content")]
const CONTENT_DROP_STATEMENTS: &[&str] = &[
    "DROP TABLE IF EXISTS photos CASCADE",
    "DROP FUNCTION IF EXISTS connetto_visible_files(BYTEA[])",
    "DROP FUNCTION IF EXISTS connetto_set_content_state(BYTEA, TEXT, TEXT)",
    "DROP TABLE IF EXISTS _cfs_manifest_chunks",
    "DROP TABLE IF EXISTS _cfs_manifests",
    "DROP TABLE IF EXISTS _cfs_chunk_registry",
];

/// The file-serving deployment contract, the same shape `content.sql` ships
/// in the demos: the metadata table the two contract functions consult and
/// the functions themselves.
#[cfg(feature = "content")]
const CONTENT_CONTRACT_STATEMENTS: &[&str] = &[
    "CREATE TABLE photos (content_id BYTEA PRIMARY KEY, content_state TEXT NOT NULL \
     DEFAULT 'staged')",
    "CREATE OR REPLACE FUNCTION connetto_visible_files(p_file_ids BYTEA[]) RETURNS BYTEA[] \
     LANGUAGE sql SECURITY INVOKER SET search_path TO '' AS $$ \
     SELECT ARRAY(SELECT f FROM UNNEST(p_file_ids) AS f \
     WHERE EXISTS (SELECT 1 FROM public.photos p WHERE p.content_id = f)) $$",
    "CREATE OR REPLACE FUNCTION connetto_set_content_state(p_file_id BYTEA, p_new_state TEXT, \
     p_caller TEXT) RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER SET search_path TO '' \
     AS $$ BEGIN UPDATE public.photos SET content_state = p_new_state \
     WHERE content_id = p_file_id; RETURN p_file_id; END; $$",
];

/// Brings the database to a content-ready deployment, or to none at all.
///
/// The shipped [`connetto_file_server::DEPLOYMENT_DDL`] is one text of several
/// statements; comment-only fragments carry no statement to send.
#[cfg(feature = "content")]
async fn apply_content_deployment(pool: &Pool<AsyncPgConnection>, ready: bool) {
    for stmt in CONTENT_DROP_STATEMENTS {
        exec(pool, stmt).await;
    }
    if !ready {
        return;
    }
    for stmt in connetto_file_server::DEPLOYMENT_DDL.split(';') {
        let meaningful = stmt
            .lines()
            .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with("--"));
        if meaningful {
            exec(pool, stmt.trim()).await;
        }
    }
    for stmt in CONTENT_CONTRACT_STATEMENTS {
        exec(pool, stmt).await;
    }
}

/// One file id of the shape the routes parse.
#[cfg(feature = "content")]
fn sample_file_id() -> String {
    "ab".repeat(32)
}

/// Writes a PKCS#8 v1 ed25519 document, the shape `CONNETTO_CONTENT_KEY`
/// loads, through the same ring keypair the signer parses.
#[cfg(feature = "content")]
fn generate_ticket_key(path: &std::path::Path) {
    let keypair = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .expect("generate the content ticket key");
    std::fs::write(path, keypair.as_ref()).expect("write the ticket key");
}

/// A server configured with `CONNETTO_CONTENT_URL` boots, mounts the four
/// file routes on the auth listener under its CORS layer, and still serves
/// the login endpoints on the same port.
///
/// The routes answer a ticket-less request with the extractor rejection (a
/// 400 naming the missing `t` query parameter), which distinguishes them
/// from the bare 404 of an unmounted path. A bad ticket answers 404, the
/// same code the router itself emits, so the 400 is what proves the mount.
#[cfg(feature = "content")]
#[tokio::test]
async fn e2e_content_routes_mount_on_the_auth_listener() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;
    // Startup checks the slot before it builds anything content-related, so
    // every boot here needs the replication objects present.
    fixture.start_replication(&["orders"]).await;
    apply_content_deployment(&pool, true).await;

    let store = TempDir::new().expect("content store dir");
    let key_dir = TempDir::new().expect("content key dir");
    let key_path = key_dir.path().join("ticket.der");
    generate_ticket_key(&key_path);
    let store_spec = format!("fs:{}", store.path().display());
    let key = key_path.to_str().expect("utf-8 path");

    let auth_stack = build_auth_stack().await;
    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let (_server, ports) =
        start_server(&auth_stack, Duration::from_secs(30), |ports, auth_pairs| {
            let content_base = ports.auth_base();
            let mut envs = auth_pairs.to_vec();
            envs.extend([
                ("CONNETTO_CONTENT_URL", content_base.as_str()),
                ("CONNETTO_CONTENT_STORE", store_spec.as_str()),
                ("CONNETTO_CONTENT_KEY", key),
                ("CONNETTO_CONTENT_SWEEP_SECS", "1"),
            ]);
            spawn_server_cfg(
                &url,
                &ports.bind(),
                PG_DDL,
                "orders",
                Some(&reader_url),
                &authorization,
                &envs,
            )
        })
        .await;
    let content_base = ports.auth_base();

    // The login dance through the same listener still works with the file
    // routes mounted beside it.
    let (_token, _user) = mint_token(&content_base).await;

    let agent = reqwest::Client::new();
    let id = sample_file_id();
    let download = agent
        .get(format!("{content_base}/files/{id}"))
        .send()
        .await
        .expect("GET /files/{id}");
    assert_eq!(
        download.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "the download route must answer a ticket-less request with the \
         extractor rejection, not the bare 404 of an unmounted path"
    );
    let intent = agent
        .post(format!("{content_base}/files/{id}/intent"))
        .send()
        .await
        .expect("POST /files/{id}/intent");
    assert_eq!(
        intent.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "the intent route must answer a ticket-less request with the \
         extractor rejection"
    );
}

/// With content configured but the file server's tables absent, startup
/// refuses naming the preflight that failed.
#[cfg(feature = "content")]
#[tokio::test]
async fn e2e_content_startup_refuses_a_deployment_without_the_file_tables() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;
    fixture.start_replication(&["orders"]).await;
    apply_content_deployment(&pool, false).await;

    let auth_port = free_port();
    let auth_stack = build_auth_stack().await;
    let auth_env = auth_stack.env_pairs(auth_port);
    let content_base = format!("http://127.0.0.1:{auth_port}");
    let store = TempDir::new().expect("content store dir");
    let store_spec = format!("fs:{}", store.path().display());
    let reader_url = with_user_url(&url, "app_reader", "app_reader");

    let mut envs: Vec<(&str, &str)> = auth_env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    envs.extend([
        ("CONNETTO_CONTENT_URL", content_base.as_str()),
        ("CONNETTO_CONTENT_STORE", store_spec.as_str()),
    ]);
    let output = run_server_exit_output(&url, Some(&reader_url), &envs).await;
    assert!(
        !output.status.success(),
        "expected refusal without the file server tables"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("content preflight"),
        "expected the refusal to name the content preflight, got: {stderr}"
    );
}

/// A `CONNETTO_CONTENT_STORE` the parser rejects names the variable in the
/// refusal.
#[cfg(feature = "content")]
#[tokio::test]
async fn e2e_content_startup_refuses_an_unparsable_store_spec() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;
    fixture.start_replication(&["orders"]).await;

    let auth_port = free_port();
    let auth_stack = build_auth_stack().await;
    let auth_env = auth_stack.env_pairs(auth_port);
    let content_base = format!("http://127.0.0.1:{auth_port}");
    let reader_url = with_user_url(&url, "app_reader", "app_reader");

    let mut envs: Vec<(&str, &str)> = auth_env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    envs.extend([
        ("CONNETTO_CONTENT_URL", content_base.as_str()),
        ("CONNETTO_CONTENT_STORE", "not a store spec"),
    ]);
    let output = run_server_exit_output(&url, Some(&reader_url), &envs).await;
    assert!(
        !output.status.success(),
        "expected refusal for an unparsable store spec"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CONNETTO_CONTENT_STORE"),
        "expected the refusal to name CONNETTO_CONTENT_STORE, got: {stderr}"
    );
}

/// Every remaining way the content settings can be wrong, each refused with
/// a message naming the setting or the file at fault. One boot per case
/// because the refusals are what the case is, not a fixture to reuse.
#[cfg(feature = "content")]
#[tokio::test]
async fn e2e_content_startup_names_each_refused_setting() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;
    fixture.start_replication(&["orders"]).await;
    // Sweep cadence is parsed after the content preflight, so the refusal
    // cases that reach it need a file-ready deployment.
    apply_content_deployment(&pool, true).await;

    let auth_port = free_port();
    let auth_stack = build_auth_stack().await;
    let auth_env = auth_stack.env_pairs(auth_port);
    let content_base = format!("http://127.0.0.1:{auth_port}");
    let query_base = format!("{content_base}/?probe=1");
    let reader_url = with_user_url(&url, "app_reader", "app_reader");

    let store = TempDir::new().expect("content store dir");
    let store_spec = format!("fs:{}", store.path().display());
    let junk_dir = TempDir::new().expect("junk key dir");
    let junk_key = junk_dir.path().join("junk.der");
    std::fs::write(&junk_key, [0u8; 16]).expect("write the junk key");
    let missing_key = "/tmp/connetto-r69-definitely-not-a-key.pem";

    let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
        (
            vec![
                ("CONNETTO_CONTENT_STORE", store_spec.as_str()),
                ("CONNETTO_CONTENT_KEY", missing_key),
            ],
            "connetto-r69-definitely-not-a-key.pem",
        ),
        (
            vec![
                ("CONNETTO_CONTENT_STORE", store_spec.as_str()),
                (
                    "CONNETTO_CONTENT_KEY",
                    junk_key.to_str().expect("utf-8 path"),
                ),
            ],
            "loading the content ticket key",
        ),
        (
            vec![("CONNETTO_CONTENT_STORE", "fs:")],
            "fs: needs a directory",
        ),
        (
            vec![("CONNETTO_CONTENT_STORE", "ftp://example.com")],
            "opening the chunk store",
        ),
        (
            vec![
                ("CONNETTO_CONTENT_STORE", store_spec.as_str()),
                ("CONNETTO_CONTENT_TICKET_TTL_SECS", "soon"),
            ],
            "parsing CONNETTO_CONTENT_TICKET_TTL_SECS",
        ),
        (
            vec![
                ("CONNETTO_CONTENT_STORE", store_spec.as_str()),
                ("CONNETTO_CONTENT_SWEEP_SECS", "soon"),
            ],
            "parsing CONNETTO_CONTENT_SWEEP_SECS",
        ),
        (
            vec![("CONNETTO_CONTENT_URL", query_base.as_str())],
            "no query or fragment",
        ),
    ];
    for (extra, expected) in cases {
        let mut envs: Vec<(&str, &str)> = auth_env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        envs.push(("CONNETTO_CONTENT_URL", content_base.as_str()));
        envs.extend(extra);
        let output = run_server_exit_output(&url, Some(&reader_url), &envs).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success() && stderr.contains(expected),
            "expected a refusal naming {expected:?}, got status {:?} and: {stderr}",
            output.status.code()
        );
    }
}

/// Drives a live session through the binary's own ticket signer: an
/// unidentified file is refused, a file the deployment makes visible mints a
/// URL that rides the query, and that URL answers its download route.
///
/// `CONNETTO_CONTENT_KEY` stays unset here, so this boot also takes the
/// ephemeral-keypair branch every other content test skips.
#[cfg(feature = "content")]
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "a live session round trip: handshake, ghost refusal, row insert, mint and download run as one ordered exchange"
)]
async fn e2e_content_ticket_round_trips_over_a_live_session() {
    use connetto_core::PROTOCOL_VERSION;
    use connetto_core::messages::{
        ContentTicketGrant, ContentTicketRequest, ContentVerb, ControlMessage, Grant, Handshake,
        HandshakeAck, NonFatalError,
    };
    use connetto_core::traits::{IncomingFrame, Transport};
    use connetto_server::WebSocketTransport;
    use tokio::net::TcpStream;

    let _keyring = connetto_test_harness::isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let url = fixture.admin_url().to_owned();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.clone());
    let pool = Pool::builder().build(manager).await.expect("build pool");
    reset_fixture(&pool, &fixture).await;
    fixture.start_replication(&["orders"]).await;
    apply_content_deployment(&pool, true).await;
    exec(&pool, "GRANT SELECT ON photos TO app_reader").await;

    let store = TempDir::new().expect("content store dir");
    let store_spec = format!("fs:{}", store.path().display());

    let auth_stack = build_auth_stack().await;
    let reader_url = with_user_url(&url, "app_reader", "app_reader");
    let authorization = Authorization::provision(&fixture, NO_POLICIES).await;
    let secs = Duration::from_secs(30);
    let (_server, ports) = start_server(&auth_stack, secs, |ports, auth_pairs| {
        let content_base = ports.auth_base();
        let mut envs = auth_pairs.to_vec();
        envs.extend([
            ("CONNETTO_CONTENT_URL", content_base.as_str()),
            ("CONNETTO_CONTENT_STORE", store_spec.as_str()),
        ]);
        spawn_server_cfg(
            &url,
            &ports.bind(),
            PG_DDL,
            "orders",
            Some(&reader_url),
            &authorization,
            &envs,
        )
    })
    .await;
    let (bind, ws, content_base) = (ports.bind(), ports.ws(), ports.auth_base());

    let (token, _user) = mint_token(&content_base).await;
    let tcp = TcpStream::connect(&bind).await.expect("connect ws");
    let mut client = WebSocketTransport::connect(&ws, tcp)
        .await
        .expect("ws handshake");
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "ticket-probe").with_grant(Grant::new(token)),
        ))
        .await
        .expect("post handshake");

    let mut acked = false;
    let mut ghost_refused = false;
    let file_id = [0xa7u8; 32];
    let mut hex = String::new();
    for byte in file_id {
        std::fmt::write(&mut hex, format_args!("{byte:02x}")).expect("string append");
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut granted: Option<ContentTicketGrant> = None;
    let mut visible_asked = false;
    while granted.is_none() {
        assert!(Instant::now() < deadline, "the ticket round trip stalled");
        let frame = tokio::time::timeout(Duration::from_secs(10), client.recv())
            .await
            .expect("a frame arrives")
            .expect("transport")
            .expect("open");
        match frame {
            IncomingFrame::Control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id,
                ..
            })) => {
                assert!(!connection_id.is_empty(), "the ack names the session");
                acked = true;
                client
                    .send_control(ControlMessage::ContentTicketRequest(ContentTicketRequest {
                        request_id: "probe-ghost".to_owned(),
                        file_id: [0x5cu8; 32],
                        verb: ContentVerb::Read,
                    }))
                    .await
                    .expect("post the ghost request");
            }
            IncomingFrame::Control(ControlMessage::NonFatalError(NonFatalError {
                related_to,
                detail,
            })) if related_to.as_deref() == Some("probe-ghost") => {
                assert!(
                    detail.contains("refused"),
                    "an invisible file is refused, got {detail}"
                );
                ghost_refused = true;
                if !visible_asked {
                    visible_asked = true;
                    exec(
                        &pool,
                        &format!("INSERT INTO photos VALUES (decode('{hex}', 'hex'), 'staged')"),
                    )
                    .await;
                    client
                        .send_control(ControlMessage::ContentTicketRequest(ContentTicketRequest {
                            request_id: "probe-visible".to_owned(),
                            file_id,
                            verb: ContentVerb::Read,
                        }))
                        .await
                        .expect("post the visible request");
                }
            }
            IncomingFrame::Control(ControlMessage::ContentTicketGrant(grant))
                if grant.request_id == "probe-visible" =>
            {
                granted = Some(grant);
            }
            IncomingFrame::Control(_) | IncomingFrame::Bulk(_) => {}
        }
    }
    assert!(acked && ghost_refused, "the ack and refusal must arrive");
    let grant = granted.expect("the visible file mints");
    assert!(
        grant.url.starts_with(&content_base) && grant.url.contains(&hex),
        "the granted URL names the base and the file, got {}",
        grant.url
    );
    assert!(
        grant.url.contains("?t="),
        "the ticket rides the query, got {}",
        grant.url
    );
    let response = reqwest::get(&grant.url).await.expect("GET the ticket");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "a minted ticket passes the extractor and misses the empty store"
    );
}
