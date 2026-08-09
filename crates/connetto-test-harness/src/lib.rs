//! In-process CDC-loop test harness over a real Postgres.
//!
//! This crate wires the full connetto sync loop in one process using only
//! production paths, so an integration test drives the same code a deployment
//! runs. The write direction goes through [`pg_write_target`] under an RLS role,
//! the read direction through [`PgSnapshotSource`] and a real
//! [`PgStreamingCdcSource`] over a live replication slot and publication, and
//! aggregate re-execution through [`PgAsyncDieselConnector`]. It mirrors the
//! wiring in `crates/connetto-server/src/bin/connetto-server.rs` main.
//!
//! Every test shares one Postgres, one replication slot, and one publication
//! name, so a test acquires the process-wide [`Fixture`] lock, resets the shared
//! state, and holds the lock for its duration. All of it needs a running
//! Postgres started with `wal_level=logical`, so the tests that use it are
//! `#[ignore]` and run against Docker.
//!
//! The fixture-setup helpers run schema, role, policy, publication, and slot
//! statements through [`diesel::sql_query`]. These are DDL and vendor
//! replication-management statements (for example
//! `pg_create_logical_replication_slot`) that the diesel query DSL cannot
//! express, which is the sanctioned raw-SQL case. Read-back assertions in a test
//! MUST instead define a typed `diesel::table!` and load through the DSL.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::auth::Principal;
use connetto_core::messages::{
    AckCredits, BulkMessage, ControlMessage, Grant, Handshake, HandshakeAck, LivePatch,
    MutationHeader, MutationPatch, Ping, SnapshotPatch, Subscribe, SubscriptionSpec,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{
    LoopbackTransport, Materializer, PermissiveAuth, PgSnapshotSource, ReconnectPolicy,
    RequestGuard, RlsAuth, RlsAuthError, RuntimeWritableCatalog, SessionConfig, SessionManager,
    loopback, pg_write_target,
};
use diesel::sql_query;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sqlite_diff_rs::{ChangeSet, DiffOps, Insert, SimpleTable, Value};
use sqlparser::dialect::PostgreSqlDialect;
use subql::backend::Postgres;
use subql::reexec::PgAsyncDieselConnector;
use subql::visibility::{RowView, Verdict, VisibilityPolicy, WriteOp};
use subql::{ParserDB, PgStreamingCdcSource, PgStreamingConfig};
use tokio::task::JoinHandle;

pub mod fanout;

/// The value type carried in an uploaded changeset: SQLite text keys and blob
/// bodies, matching `Insert::<_, String, Vec<u8>>`.
pub type RowValue = Value<String, Vec<u8>>;

/// The reference watermark schema over `Id = String`, the shape every
/// harness-backed test uses. connetto ships no schema, so the harness owns
/// this reference via the macro, matching [`WATERMARK_DDL`].
pub mod watermark {
    connetto_server::connetto_watermark_table!(String);
}
pub use watermark::ConnettoWatermark;

/// The logical replication slot the CDC source follows. Matches the server
/// binary default.
pub const SLOT: &str = "connetto_slot";
/// The publication the slot follows. Matches the server binary default.
pub const PUBLICATION: &str = "connetto_pub";

/// Serializes every harness-backed test. They reset the same Postgres and share
/// one replication slot and publication name, so they must not run concurrently.
static PG_SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

/// The admin (superuser) conninfo. The superuser has `REPLICATION`, which the
/// CDC stream needs, and bypasses RLS, which the read-back assertions need.
#[must_use]
pub fn admin_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned())
}

/// Rewrite a Postgres URL's user info, keeping host, port, and database. Used to
/// point a pool at a non-superuser role subject to RLS.
#[must_use]
pub fn with_user(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("url has a scheme");
    let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    format!("{scheme}://{user}:{password}@{host}")
}

/// Build a bb8 pool for a conninfo string.
pub async fn pool_for(url: &str) -> Pool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.to_owned());
    Pool::builder().build(manager).await.expect("build pool")
}

/// Run one DDL or vendor replication-management statement in its own transaction
/// (autocommit). These are statements the diesel query DSL cannot express, so
/// the raw string is the sanctioned case; a test's read-back assertions must use
/// the typed DSL instead.
pub async fn exec(pool: &Pool<AsyncPgConnection>, sql: &str) {
    let mut conn = pool.get().await.expect("admin connection");
    sql_query(sql)
        .execute(&mut *conn)
        .await
        .unwrap_or_else(|err| panic!("statement failed ({sql}): {err}"));
}

/// Drop the replication slot, terminating any active walsender first and
/// retrying until the slot is gone. A prior test's aborted CDC task can still
/// hold the slot for a moment, and an active slot cannot be dropped.
pub async fn drop_slot(pool: &Pool<AsyncPgConnection>) {
    for _ in 0..50 {
        exec(
            pool,
            &format!(
                "SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots \
                 WHERE slot_name = '{SLOT}' AND active_pid IS NOT NULL"
            ),
        )
        .await;
        let mut conn = pool.get().await.expect("admin connection");
        let dropped = sql_query(format!(
            "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots \
             WHERE slot_name = '{SLOT}'"
        ))
        .execute(&mut *conn)
        .await;
        drop(conn);
        if dropped.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("replication slot {SLOT} could not be dropped");
}

/// Reference DDL for the deployment-owned exactly-once watermark, keyed on the
/// session handle alone (R2). connetto emits no DDL, so the harness owns this
/// migration; the shape matches the `ConnettoWatermark` reference schema.
pub const WATERMARK_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_mutations \
    (session_id UUID PRIMARY KEY, last_seq BIGINT NOT NULL)";

/// Create the reference watermark table if missing, as admin. A restricted
/// writer role only needs `SELECT, INSERT, UPDATE` on it, granted separately.
pub async fn provision_watermark(pool: &Pool<AsyncPgConnection>) {
    exec(pool, WATERMARK_DDL).await;
}

/// The oplog table name the server binary defaults to.
pub const OPLOG_TABLE: &str = "connetto_oplog";

/// Create the reference oplog table and its enum if missing, as admin.
///
/// The server refuses to start without the table, because a reconnect log that
/// does not survive the process tells every resuming client it is already
/// current and sends it nothing (R32). Bringing up a scratch database is the
/// one job `PgOplog::ensure_schema` exists for, so this calls it rather than
/// keeping a second copy of the shape that could drift from it.
pub async fn provision_oplog(pool: &Pool<AsyncPgConnection>) {
    connetto_server::PgOplog::new(
        pool.clone(),
        OPLOG_TABLE,
        connetto_server::OplogConfig::default(),
    )
    .ensure_schema()
    .await
    .expect("provisioning the oplog table");
}

/// The shared Postgres, held under the process-wide serialization lock for the
/// lifetime of one test. Dropping it releases the lock for the next test.
pub struct Fixture {
    admin_url: String,
    admin: Pool<AsyncPgConnection>,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    /// Acquire the serialization lock and clean any replication slot a prior
    /// test left behind. The caller then creates its own schema, roles,
    /// publication, and slot.
    pub async fn acquire() -> Self {
        let guard = PG_SERIAL.lock().await;
        let admin_url = admin_url();
        let admin = pool_for(&admin_url).await;
        drop_slot(&admin).await;
        // Every session's handshake reads its client's durable mutation
        // watermark from this table, so it must exist for any session, even one
        // that never writes. Recreate it fresh per test so a watermark row a
        // prior test left for a reused client id cannot shift this test's
        // client sequence. A write-path test that grants a role on it does so
        // in its own setup, after acquire.
        exec(&admin, "DROP TABLE IF EXISTS _connetto_mutations").await;
        provision_watermark(&admin).await;
        Self {
            admin_url,
            admin,
            _guard: guard,
        }
    }

    /// The admin pool. It bypasses RLS, so read-backs through it see every row.
    #[must_use]
    pub fn admin(&self) -> &Pool<AsyncPgConnection> {
        &self.admin
    }

    /// The admin conninfo.
    #[must_use]
    pub fn admin_url(&self) -> &str {
        &self.admin_url
    }

    /// Run one fixture DDL statement as admin.
    pub async fn exec(&self, sql: &str) {
        exec(&self.admin, sql).await;
    }

    /// Run a batch of fixture DDL statements as admin, in order.
    pub async fn setup(&self, statements: &[&str]) {
        for statement in statements {
            exec(&self.admin, statement).await;
        }
    }

    /// Create the publication over the given tables and then the `pgoutput`
    /// logical replication slot. The tables must already exist with
    /// `REPLICA IDENTITY FULL`, and the slot must be created after the
    /// publication so it follows it.
    pub async fn start_replication(&self, tables: &[&str]) {
        exec(
            &self.admin,
            &format!(
                "CREATE PUBLICATION {PUBLICATION} FOR TABLE {}",
                tables.join(", ")
            ),
        )
        .await;
        exec(
            &self.admin,
            &format!("SELECT pg_create_logical_replication_slot('{SLOT}', 'pgoutput')"),
        )
        .await;
    }
}

/// The read and write authorization policy, chosen per test. A single concrete
/// type keeps the served-session and CDC-ingest futures `Send`; the async-trait
/// methods do not otherwise guarantee it for a generic parameter. Mirrors the
/// server binary's `ServerAuth`.
pub enum HarnessAuth {
    /// Authorize every read and write (no RLS).
    Permissive(PermissiveAuth),
    /// Authorize through Postgres Row-Level Security.
    Rls(Box<RlsAuth>),
}

impl HarnessAuth {
    /// The permissive policy: every read and write is allowed.
    #[must_use]
    pub fn permissive() -> Self {
        Self::Permissive(PermissiveAuth)
    }

    /// The RLS policy: reads and writes run under Postgres Row-Level Security.
    #[must_use]
    pub fn rls(auth: RlsAuth) -> Self {
        Self::Rls(Box::new(auth))
    }
}

impl VisibilityPolicy for HarnessAuth {
    type Watcher = std::sync::Arc<Principal>;
    type Error = RlsAuthError;
    type Backend = Postgres;

    async fn may_see<R>(
        &self,
        row: &R,
        watchers: &[Self::Watcher],
        verdicts: &mut [Verdict],
    ) -> Result<(), RlsAuthError>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        match self {
            Self::Permissive(auth) => auth
                .may_see(row, watchers, verdicts)
                .await
                .map_err(|e| match e {}),
            Self::Rls(auth) => auth.may_see(row, watchers, verdicts).await,
        }
    }

    async fn may_write<R>(
        &self,
        row: &R,
        watcher: &Self::Watcher,
        op: WriteOp,
    ) -> Result<Verdict, RlsAuthError>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        match self {
            Self::Permissive(auth) => auth
                .may_write(row, watcher, op)
                .await
                .map_err(|e| match e {}),
            Self::Rls(auth) => auth.may_write(row, watcher, op).await,
        }
    }
}

/// The concrete manager type the harness serves: real snapshot, the harness auth
/// policy, and the async re-execution connector.
type HarnessManager =
    SessionManager<PgSnapshotSource, HarnessAuth, ConnettoWatermark, PgAsyncDieselConnector>;

/// How to wire a harness server.
pub struct ServerConfig {
    /// The Postgres catalog DDL the materializer, write target, and CDC catalog
    /// are all built from.
    pg_ddl: String,
    /// Which tables accept client mutations, and their version columns.
    writable: RuntimeWritableCatalog,
    /// The admin conninfo the CDC stream connects with. It needs `REPLICATION`.
    admin_url: String,
    /// Per-session server configuration.
    session: SessionConfig,
    /// The counters the server meters and tallies against. Supply one built
    /// from tight thresholds to trip a limit or a ban inside a test.
    guard: Arc<RequestGuard<String>>,
}

impl ServerConfig {
    /// Build a config from the two values every site must supply.
    #[must_use]
    pub fn new(pg_ddl: impl Into<String>, admin_url: impl Into<String>) -> Self {
        Self {
            pg_ddl: pg_ddl.into(),
            admin_url: admin_url.into(),
            writable: RuntimeWritableCatalog::default(),
            session: SessionConfig::default(),
            guard: Arc::new(RequestGuard::default()),
        }
    }

    /// Which tables accept client mutations, and their version columns.
    #[must_use]
    pub fn with_writable(mut self, writable: RuntimeWritableCatalog) -> Self {
        self.writable = writable;
        self
    }

    /// Per-session server configuration.
    #[must_use]
    pub fn with_session(mut self, session: SessionConfig) -> Self {
        self.session = session;
        self
    }

    /// The counters the server meters and tallies against.
    #[must_use]
    pub fn with_guard(mut self, guard: Arc<RequestGuard<String>>) -> Self {
        self.guard = guard;
        self
    }
}

/// A running harness server: a [`SessionManager`] wired to the full production
/// paths, with a background CDC ingest task. Dropping it aborts the ingest task,
/// which closes the replication connection so the next test can drop the slot.
pub struct Server {
    manager: Arc<HarnessManager>,
    ingest: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.ingest.abort();
    }
}

impl Server {
    /// The underlying manager, for the few tests that drive it directly.
    #[must_use]
    pub fn manager(&self) -> &Arc<HarnessManager> {
        &self.manager
    }

    /// Connect a new in-process client over a loopback transport. The server
    /// side is served on a spawned task, so the returned [`Client`] talks to a
    /// live session. The session ends when the client is dropped.
    #[must_use]
    pub fn connect(&self) -> Client {
        let (server_transport, client) = loopback();
        let session = Arc::clone(&self.manager);
        tokio::spawn(async move {
            let _ = session.serve(server_transport).await;
        });
        Client { transport: client }
    }
}

/// Wire a harness server: build the materializer, write target, and re-execution
/// connector, then spawn the CDC ingest loop.
///
/// `write_pool` backs the write target (use a non-superuser RLS role so RLS is
/// not bypassed). `connector_pool` backs aggregate re-execution (the server
/// binary uses the primary pool here). The snapshot source and auth policy are
/// built by the caller from whichever pool the test wants under RLS.
#[must_use]
pub fn spawn_server(
    config: ServerConfig,
    snapshot: PgSnapshotSource,
    auth: HarnessAuth,
    write_pool: Pool<AsyncPgConnection>,
    connector_pool: Pool<AsyncPgConnection>,
) -> Server {
    let ServerConfig {
        pg_ddl,
        writable,
        admin_url,
        session,
        guard,
    } = config;
    let materializer =
        Materializer::with_write_catalog(&pg_ddl, writable).expect("build materializer");
    let write =
        pg_write_target::<ConnettoWatermark>(write_pool, &pg_ddl).expect("build write target");
    let connector = PgAsyncDieselConnector::new(connector_pool);
    // The manager requires a handshake authority with no default (R2). The
    // harness is test-only, so it installs the `test-support` stand-in that
    // reads the subject out of the grant string, which is what
    // `Client::handshake` assumes. Nothing here is reachable from a production
    // build.
    let authority: Arc<dyn connetto_core::traits::HandshakeAuthority> =
        Arc::new(connetto_core::test_support::TestGrantChecker);
    let manager = SessionManager::with_connector(
        materializer,
        snapshot,
        auth,
        authority,
        connector,
        write,
        guard,
        session,
    );

    let ingest_manager = Arc::clone(&manager);
    let ddl = pg_ddl;
    let ingest = tokio::spawn(async move {
        let connect = || {
            let (url, ddl) = (admin_url.clone(), ddl.clone());
            async move {
                let catalog = ParserDB::parse::<PostgreSqlDialect>(&ddl)
                    .map_err(|err| format!("parsing catalog DDL: {err:?}"))?;
                let config = PgStreamingConfig::new(url, SLOT.to_owned(), PUBLICATION.to_owned());
                PgStreamingCdcSource::connect(config, catalog)
                    .await
                    .map_err(|err| format!("opening CDC stream: {err}"))
            }
        };
        let _ = ingest_manager
            .ingest_with_reconnect(connect, &ReconnectPolicy::default(), |_event| {})
            .await;
    });

    Server { manager, ingest }
}

/// An in-process client over a loopback transport, with the drive helpers the
/// tests need to run a session conversation.
pub struct Client {
    transport: LoopbackTransport,
}

impl Client {
    /// Wrap a loopback client endpoint. Use this to drive a session whose
    /// manager a test built directly (custom snapshot, auth, or connector),
    /// rather than through [`spawn_server`].
    #[must_use]
    pub fn new(transport: LoopbackTransport) -> Self {
        Self { transport }
    }

    /// Send the handshake as `client_id` and wait for its ack. The client id
    /// doubles as the login subject, which the stand-in checker maps to
    /// `app.user_id` under RLS.
    pub async fn handshake(&mut self, client_id: &str) {
        self.handshake_with(client_id, &format!("user:{client_id}"))
            .await;
    }

    /// Send a handshake presenting one grant, returning the ack. The checked
    /// grant, not the client id, decides the durable handle the exactly-once
    /// watermark keys on, so a reconnect that mints a new `client_id` but
    /// presents the same grant (a worker restart) keeps its watermark.
    pub async fn handshake_with(&mut self, client_id: &str, grant: &str) -> HandshakeAck {
        self.handshake_presenting(client_id, &[grant], None).await
    }

    /// Send a handshake presenting no grant at all: a caller with no identity.
    pub async fn handshake_unidentified(&mut self, client_id: &str) -> HandshakeAck {
        self.handshake_presenting(client_id, &[], None).await
    }

    /// Send a handshake presenting `grants`, each checked on its own, plus an
    /// optional resume credential from a previous ack.
    pub async fn handshake_presenting(
        &mut self,
        client_id: &str,
        grants: &[&str],
        resume_token: Option<&str>,
    ) -> HandshakeAck {
        let mut handshake = Handshake::new(PROTOCOL_VERSION, client_id)
            .with_grants(grants.iter().map(|grant| Grant::new(*grant)));
        if let Some(token) = resume_token {
            handshake = handshake.with_resume_token(token);
        }
        self.transport
            .send_control(ControlMessage::Handshake(handshake))
            .await
            .expect("send handshake");
        let ControlMessage::HandshakeAck(ack) = self.next_control().await else {
            panic!("expected handshake ack");
        };
        ack
    }

    /// Register a subscription. The snapshot and any live patches follow on the
    /// transport; drain them with [`Client::expect_snapshot`] and
    /// [`Client::wait_for_live`].
    pub async fn subscribe(&mut self, sub_id: &str, query: &str) {
        self.transport
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: sub_id.to_owned(),
                spec: SubscriptionSpec::new(query),
            }))
            .await
            .expect("send subscribe");
    }

    /// Upload one mutation: a header naming the op count, then the compressed
    /// changeset patch.
    pub async fn upload(&mut self, client_seq: u64, changeset: Vec<u8>) {
        let payload = zstd::encode_all(changeset.as_slice(), 3).expect("compress");
        self.transport
            .send_control(ControlMessage::MutationHeader(MutationHeader::new(
                client_seq, 1,
            )))
            .await
            .expect("send mutation header");
        self.transport
            .send_bulk(BulkMessage::MutationPatch(MutationPatch::new(
                client_seq, payload,
            )))
            .await
            .expect("send mutation patch");
    }

    /// Replenish the server's delivery credits.
    pub async fn ack_credits(&mut self, credits: u32) {
        self.transport
            .send_control(ControlMessage::AckCredits(AckCredits { credits }))
            .await
            .expect("send ack credits");
    }

    /// Ping and return the next control frame. A pong proves every preceding
    /// frame was handled, so any earlier apply ack or reject arrives before it.
    pub async fn barrier(&mut self, nonce: u64) -> ControlMessage {
        self.transport
            .send_control(ControlMessage::Ping(Ping { nonce }))
            .await
            .expect("send ping");
        self.next_control().await
    }

    /// Read the next frame, asserting it is a control frame.
    pub async fn next_control(&mut self) -> ControlMessage {
        match self.recv().await {
            Some(IncomingFrame::Control(msg)) => msg,
            other => panic!("expected control frame, got {other:?}"),
        }
    }

    /// Read the next frame, asserting it is a bulk frame.
    pub async fn next_bulk(&mut self) -> BulkMessage {
        match self.recv().await {
            Some(IncomingFrame::Bulk(msg)) => msg,
            other => panic!("expected bulk frame, got {other:?}"),
        }
    }

    /// Read the next frame, returning `None` on a clean close.
    pub async fn recv(&mut self) -> Option<IncomingFrame> {
        self.transport.recv().await.expect("recv frame")
    }

    /// Drain a subscription's initial snapshot, from `SnapshotBegin` through
    /// `SnapshotEnd`, and return the snapshot patches seen in between (an empty
    /// snapshot has none).
    pub async fn expect_snapshot(&mut self, sub_id: &str) -> Vec<SnapshotPatch> {
        let ControlMessage::SnapshotBegin(begin) = self.next_control().await else {
            panic!("expected snapshot begin");
        };
        assert_eq!(begin.sub_id, sub_id, "snapshot for the wrong subscription");
        let mut patches = Vec::new();
        loop {
            match self.recv().await {
                Some(IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch))) => {
                    assert_eq!(
                        patch.sub_id, sub_id,
                        "snapshot patch for the wrong subscription"
                    );
                    patches.push(patch);
                }
                Some(IncomingFrame::Control(ControlMessage::SnapshotEnd(end))) => {
                    assert_eq!(
                        end.sub_id, sub_id,
                        "snapshot end for the wrong subscription"
                    );
                    return patches;
                }
                other => panic!("expected snapshot patch or end, got {other:?}"),
            }
        }
    }

    /// Wait for a live patch to arrive, skipping any interleaved control frames
    /// (keepalive pongs and the like). Panics if none arrives within `timeout`.
    pub async fn wait_for_live(&mut self, timeout: Duration) -> LivePatch {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let frame = tokio::time::timeout(remaining, self.transport.recv())
                .await
                .expect("timed out waiting for a live patch")
                .expect("recv frame");
            match frame {
                Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch))) => return patch,
                Some(IncomingFrame::Control(_)) => {}
                other => panic!("expected a live patch, got {other:?}"),
            }
        }
    }

    /// Close the transport cleanly.
    pub async fn close(&mut self) {
        self.transport.close().await.expect("close client");
    }
}

/// Build a compressed-on-upload changeset that inserts one fully specified row.
///
/// `columns` names the row's columns in order, `pk` gives the primary-key
/// column indices, and `values` gives one value per column in `columns` order.
#[must_use]
pub fn insert_changeset(
    table: &str,
    columns: &[&str],
    pk: &[usize],
    values: Vec<RowValue>,
) -> Vec<u8> {
    let simple = SimpleTable::new(table, columns, pk);
    let mut insert = Insert::<_, String, Vec<u8>>::from(simple);
    for (index, value) in values.into_iter().enumerate() {
        insert = insert.set(index, value).expect("set column");
    }
    ChangeSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(insert)
        .build()
}
