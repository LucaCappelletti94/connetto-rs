//! In-process CDC-loop test harness over a real Postgres.
//!
//! This crate wires the full connetto sync loop in one process using only
//! production paths, so an integration test drives the same code the server
//! binary runs. The write direction goes through [`pg_write_target`] under an RLS role,
//! the read direction through [`PgSnapshotSource`] and a real
//! [`PgStreamingCdcSource`] over a live replication slot and publication, and
//! aggregate re-execution through [`PgReadConnector`]. It mirrors the
//! wiring in `crates/connetto-server/src/bin/connetto-server.rs` main.
//!
//! Every test starts its own Postgres, and its own authorization service if it
//! asks for one, so nothing is shared and nothing is provisioned by hand: no
//! environment variable names a service, no lock orders one test against
//! another, and one replication slot name is free because one database serves
//! one test. Dropping the [`Fixture`] stops what it started.
//!
//! The fixture-setup helpers run schema, role, policy, publication, and slot
//! statements through [`diesel::sql_query`]. These are DDL and vendor
//! replication-management statements (for example
//! `pg_create_logical_replication_slot`) that the diesel query DSL cannot
//! express, which is the sanctioned raw-SQL case. Read-back assertions in a test
//! MUST instead define a typed `diesel::table!` and load through the DSL.

use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use connetto_core::auth::Principal;
use connetto_core::messages::{
    AckCredits, BulkMessage, ControlMessage, FullResyncReason, Grant, Handshake, HandshakeAck,
    LivePatch, MutationHeader, MutationPatch, Ping, SnapshotPatch, Subscribe, SubscriptionSpec,
    Unsubscribe,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::openfga::{Counted, FgaAuth};
use connetto_server::{
    LoopbackTransport, Materializer, OidcProviderConfig, PgReadConnector, PgSnapshotSource,
    ReconnectPolicy, RequestGuard, RlsAuth, RlsAuthError, RuntimeWritableCatalog, SessionConfig,
    SessionManager, loopback, pg_write_target,
};
use diesel::sql_query;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use openfga_client::client::{CreateStoreRequest, OpenFgaServiceClient};
use openfga_client::tonic::transport::Channel;
use pg2sqlite::prelude::SessionVariableMapping;
use rls2fga::translator::Translator;
use sqlite_diff_rs::{ChangeSet, DiffOps, Insert, SimpleTable, Value};
use sqlparser::dialect::PostgreSqlDialect;
use subql::backend::Postgres;
use subql::visibility::openfga::OpenFgaError;
use subql::visibility::{RowView, RowWrite, Verdict, VisibilityPolicy};
use subql::{ParserDB, PgStreamingCdcSource, PgStreamingConfig};
use testcontainers::core::wait::HttpWaitStrategy;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;

pub mod fanout;
pub mod roster;

pub use roster::{RosterAuth, WITHHELD_ID};

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

/// The images a fixture starts, pinned rather than floating: a test that cannot
/// say which server it ran against proves less than it appears to.
const POSTGRES_IMAGE: &str = "postgres";
const POSTGRES_TAG: &str = "16";
const FGA_IMAGE: &str = "openfga/openfga";
const FGA_TAG: &str = "v1.8.13";
const MOCK_OAUTH_IMAGE: &str = "ghcr.io/navikt/mock-oauth2-server";
const MOCK_OAUTH_TAG: &str = "6.0.2";

/// The ports the services listen on inside their containers. The `OpenFGA`
/// image publishes none of its own, so both of its ports are named here or the
/// container is unreachable.
const POSTGRES_PORT: u16 = 5432;
const FGA_GRPC_PORT: u16 = 8081;
const FGA_HTTP_PORT: u16 = 8080;
const MOCK_OAUTH_PORT: u16 = 8080;
const MOCK_OAUTH_ISSUER_ID: &str = "default";

/// The provider name tests and demos select through connetto.
pub const MOCK_OAUTH_PROVIDER: &str = "mock-idp";
/// Static client id accepted by the mock provider.
pub const MOCK_OAUTH_CLIENT_ID: &str = "connetto";
/// Static client secret accepted by the mock provider.
pub const MOCK_OAUTH_CLIENT_SECRET: &str = "connetto-secret";

const MOCK_OAUTH_CONFIG: &str = r#"{
  "interactiveLogin": true,
  "tokenCallbacks": [
    {
      "issuerId": "default",
      "requestMappings": [
        {
          "requestParam": "subject",
          "match": ".*",
          "claims": {
            "sub": "${subject}",
            "email": "${subject}@example.test"
          }
        }
      ]
    }
  ]
}"#;

/// What Postgres logs once it serves. The temporary server `initdb` runs logs
/// the same line to stdout first, so the wait watches stderr alone.
const POSTGRES_READY: &str = "database system is ready to accept connections";

/// Marks every container this harness starts, and records the second it
/// started, so the sweep can tell one an killed test abandoned from one a
/// concurrent test is using right now.
const CONTAINER_LABEL: &str = "io.connetto.harness";
const STARTED_LABEL: &str = "io.connetto.harness.started";

/// How old a labelled container must be before the sweep removes it. Longer
/// than any test by a wide margin, because a sibling test process owns
/// containers this process must not touch.
const STALE_AFTER: Duration = Duration::from_secs(2 * 60 * 60);

/// Seconds since the epoch, or zero if the clock is behind it.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// What one container carries: which service it is, and when it started.
fn container_labels(role: &str) -> [(String, String); 2] {
    [
        (CONTAINER_LABEL.to_owned(), role.to_owned()),
        (STARTED_LABEL.to_owned(), now_secs().to_string()),
    ]
}

/// Join a fresh anonymous session keyring for this thread and its descendants.
///
/// The OS-keyring tests used to need an external `keyctl session` wrapper: a
/// locked login collection wedged them silently, and parallel runs shared the
/// caller's real session. `KEYCTL_JOIN_SESSION_KEYRING` scopes the join to the
/// calling thread, and every thread or child process created afterwards
/// inherits it, so calling this as the FIRST statement of a test covers the
/// tokio runtime the test macro builds, the blocking pool, and any spawned
/// client binary, whose stored key the test can then read back. Each calling
/// test gets its own fresh session, so keyring tests cannot see each other's
/// entries whichever runner schedules them.
#[cfg(target_os = "linux")]
pub fn isolated_session_keyring() {
    keyutils::Keyring::join_anonymous_session().expect("join a fresh anonymous session keyring");
}

/// On non-Linux targets the platform store needs no session isolation.
#[cfg(not(target_os = "linux"))]
pub fn isolated_session_keyring() {}

/// Remove containers an earlier run abandoned, once per process.
///
/// Dropping a [`Fixture`] stops its containers on every ordinary path, panic
/// included, and the `watchdog` feature covers a signal. Neither covers
/// `SIGKILL`, which is how a runner ends a test that outran its timeout, so a
/// killed test leaks. Age is what makes removal safe: a container a sibling
/// process is using is minutes old, never hours. A container whose stamp is
/// missing or unreadable comes from an older build of this harness and goes.
fn sweep_abandoned_containers() {
    static SWEPT: LazyLock<()> = LazyLock::new(|| {
        let Ok(listed) = Command::new("docker")
            .args([
                "ps",
                "-a",
                "--filter",
                &format!("label={CONTAINER_LABEL}"),
                "--format",
                "{{.ID}} {{.Labels}}",
            ])
            .output()
        else {
            return;
        };
        let now = now_secs();
        for line in String::from_utf8_lossy(&listed.stdout).lines() {
            let Some((id, labels)) = line.split_once(' ') else {
                continue;
            };
            let started = labels
                .split(',')
                .find_map(|label| label.strip_prefix(STARTED_LABEL)?.strip_prefix('='))
                .and_then(|stamp| stamp.parse::<u64>().ok())
                .unwrap_or(0);
            if now.saturating_sub(started) < STALE_AFTER.as_secs() {
                continue;
            }
            let _ = Command::new("docker").args(["rm", "-f", id]).output();
        }
    });
    LazyLock::force(&SWEPT);
}

/// Build the admin pool, retrying while the server finishes starting.
///
/// The log line the container wait watches is the server announcing itself,
/// which precedes it accepting a connection by a moment, and building a pool
/// establishes one connection eagerly.
async fn pool_when_ready(url: &str) -> Pool<AsyncPgConnection> {
    for _ in 0..200 {
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.to_owned());
        if let Ok(pool) = Pool::builder().build(manager).await
            && pool.get().await.is_ok()
        {
            return pool;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the fixture's postgres never accepted a connection at {url}");
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

/// A containerised OIDC provider for code-flow tests.
pub struct MockOauth {
    _container: ContainerAsync<GenericImage>,
    issuer: String,
}

impl MockOauth {
    /// Start one provider and return the host-reachable issuer URL.
    pub async fn start() -> Self {
        sweep_abandoned_containers();
        let container = GenericImage::new(MOCK_OAUTH_IMAGE, MOCK_OAUTH_TAG)
            .with_exposed_port(MOCK_OAUTH_PORT.tcp())
            .with_wait_for(WaitFor::http(
                HttpWaitStrategy::new("/isalive")
                    .with_port(MOCK_OAUTH_PORT.tcp())
                    .with_expected_status_code(200_u16),
            ))
            .with_env_var("JSON_CONFIG", MOCK_OAUTH_CONFIG)
            .with_labels(container_labels("oauth"))
            .start()
            .await
            .expect(
                "this test starts its own identity provider, so it needs a reachable Docker daemon",
            );
        let host = container.get_host().await.expect("the docker host");
        let port = container
            .get_host_port_ipv4(MOCK_OAUTH_PORT.tcp())
            .await
            .expect("the mapped oauth port");
        Self {
            _container: container,
            issuer: format!("http://{host}:{port}/{MOCK_OAUTH_ISSUER_ID}"),
        }
    }

    /// The issuer URL discovered and asserted by `openidconnect`.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Build connetto's provider configuration for this mock.
    #[must_use]
    pub fn oidc_config(&self, name: &str, redirect_url: impl Into<String>) -> OidcProviderConfig {
        OidcProviderConfig::new(
            name,
            MOCK_OAUTH_CLIENT_ID,
            self.issuer.clone(),
            redirect_url,
        )
        .with_client_secret(Some(MOCK_OAUTH_CLIENT_SECRET.to_owned()))
    }

    /// Environment variables consumed by `connetto-server`.
    #[must_use]
    pub fn env_pairs(&self, name: &str, redirect_url: &str) -> Vec<(String, String)> {
        let prefix = env_prefix(name);
        vec![
            ("CONNETTO_OIDC_PROVIDERS".to_owned(), name.to_owned()),
            (format!("CONNETTO_OIDC_{prefix}_KIND"), "generic".to_owned()),
            (
                format!("CONNETTO_OIDC_{prefix}_ISSUER"),
                self.issuer.clone(),
            ),
            (
                format!("CONNETTO_OIDC_{prefix}_CLIENT_ID"),
                MOCK_OAUTH_CLIENT_ID.to_owned(),
            ),
            (
                format!("CONNETTO_OIDC_{prefix}_CLIENT_SECRET"),
                MOCK_OAUTH_CLIENT_SECRET.to_owned(),
            ),
            (
                format!("CONNETTO_OIDC_{prefix}_REDIRECT_URL"),
                redirect_url.to_owned(),
            ),
        ]
    }
}

fn env_prefix(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Run one DDL or vendor replication-management statement in its own transaction
/// (autocommit). These are statements the diesel query DSL cannot express, so
/// the raw string is the sanctioned case; a test's read-back assertions must use
/// the typed DSL instead.
pub async fn exec(pool: &Pool<AsyncPgConnection>, sql: &str) {
    let mut conn = pool.get().await.expect("admin connection");
    conn.batch_execute(sql)
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

/// Reference DDL for the exactly-once watermark keyed on the session handle
/// alone (R2). connetto emits no DDL, so the harness owns this table and keeps
/// the shape matching the `ConnettoWatermark` reference schema.
pub const WATERMARK_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_mutations \
    (session_id UUID PRIMARY KEY, last_seq BIGINT NOT NULL)";

/// Create the reference watermark table if missing, as admin. A restricted
/// writer role only needs `SELECT, INSERT, UPDATE` on it, granted separately.
pub async fn provision_watermark(pool: &Pool<AsyncPgConnection>) {
    exec(pool, WATERMARK_DDL).await;
}

/// A name no two calls in one process share.
///
/// The clock alone is not enough: two fixtures provisioned inside one
/// millisecond would share a store and then disagree about what is in it.
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos()),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
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

/// One test's own Postgres, and the authorization service it may ask for.
///
/// Dropping the fixture stops whatever it started, so a test needs no cleanup
/// and leaves nothing behind for the next one to reset around.
pub struct Fixture {
    admin_url: String,
    admin: Pool<AsyncPgConnection>,
    /// Never read: holding the handle is what keeps the database alive.
    _postgres: ContainerAsync<GenericImage>,
    /// Started on the first ask, because most tests never ask and an unused
    /// service is a container start for nothing.
    fga: OnceCell<Authorization>,
}

/// The authorization service one fixture owns, and where it listens.
struct Authorization {
    /// Never read: holding the handle is what keeps the service alive.
    _container: ContainerAsync<GenericImage>,
    url: String,
}

impl Fixture {
    /// Start this test's own `Postgres` and create the watermark table.
    pub async fn acquire() -> Self {
        if let Some(directives) = std::env::var("CONNETTO_TEST_LOG")
            .ok()
            .filter(|directives| !directives.is_empty())
        {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new(directives))
                .with_writer(std::io::stderr)
                .try_init();
        }
        sweep_abandoned_containers();
        let postgres = GenericImage::new(POSTGRES_IMAGE, POSTGRES_TAG)
            .with_exposed_port(POSTGRES_PORT.tcp())
            .with_wait_for(WaitFor::message_on_stderr(POSTGRES_READY))
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            // This replaces the image's own command outright, so every flag
            // belongs here: `wal_level=logical` is what a replication slot
            // needs, and `fsync=off` costs a database that lives for one test
            // nothing.
            .with_cmd(["-c", "wal_level=logical", "-c", "fsync=off"])
            .with_labels(container_labels("postgres"))
            .start()
            .await
            .expect("this test starts its own postgres, so it needs a reachable Docker daemon");
        let host = postgres.get_host().await.expect("the docker host");
        let port = postgres
            .get_host_port_ipv4(POSTGRES_PORT.tcp())
            .await
            .expect("the mapped postgres port");
        let admin_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
        let admin = pool_when_ready(&admin_url).await;
        // Every session's handshake reads its client's durable mutation
        // watermark from this table, so it must exist for any session, even one
        // that never writes. A write-path test that grants a role on it does so
        // in its own setup, after acquire.
        provision_watermark(&admin).await;
        Self {
            admin_url,
            admin,
            _postgres: postgres,
            fga: OnceCell::new(),
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

    /// Put each published table in full previous-image mode, then create the publication, slot and oplog table.
    pub async fn start_replication(&self, tables: &[&str]) {
        drop_slot(&self.admin).await;
        exec(
            &self.admin,
            &format!("DROP PUBLICATION IF EXISTS {PUBLICATION}"),
        )
        .await;
        for table in tables {
            exec(
                &self.admin,
                &format!("ALTER TABLE {table} REPLICA IDENTITY FULL"),
            )
            .await;
        }
        provision_oplog(&self.admin).await;
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

    /// Where this fixture's authorization service listens, starting it if this
    /// is the first ask.
    pub async fn fga_url(&self) -> &str {
        &self.authorization().await.url
    }

    /// Open a channel to this fixture's authorization service and create a
    /// store of its own.
    ///
    /// A fresh store per call, so two calls in one test cannot see each other's
    /// rules or facts.
    pub async fn fga_store(&self) -> (Channel, String) {
        let endpoint = self.fga_url().await.to_owned();
        let channel = Channel::from_shared(endpoint.clone())
            .expect("a service endpoint")
            .connect()
            .await
            .unwrap_or_else(|err| {
                panic!("connecting to the authorization service at {endpoint}: {err}")
            });
        let store = OpenFgaServiceClient::new(channel.clone())
            .create_store(CreateStoreRequest {
                name: format!("connetto-harness-{}", uuid_like()),
            })
            .await
            .expect("create a store")
            .into_inner()
            .id;
        (channel, store)
    }

    /// This fixture's authorization service, started on the first ask.
    ///
    /// Readiness is its own `/healthz`, which answers `SERVING` only once it
    /// serves. The log line naming the gRPC port is printed a moment before
    /// that port accepts anything, so it would race.
    async fn authorization(&self) -> &Authorization {
        self.fga
            .get_or_init(|| async {
                let container = GenericImage::new(FGA_IMAGE, FGA_TAG)
                    .with_exposed_port(FGA_GRPC_PORT.tcp())
                    .with_exposed_port(FGA_HTTP_PORT.tcp())
                    .with_wait_for(WaitFor::http(
                        HttpWaitStrategy::new("/healthz")
                            .with_port(FGA_HTTP_PORT.tcp())
                            .with_expected_status_code(200_u16),
                    ))
                    .with_cmd(["run"])
                    .with_labels(container_labels("openfga"))
                    .start()
                    .await
                    .expect(
                        "this test starts its own authorization service, so it needs a reachable \
                         Docker daemon",
                    );
                let host = container.get_host().await.expect("the docker host");
                let port = container
                    .get_host_port_ipv4(FGA_GRPC_PORT.tcp())
                    .await
                    .expect("the mapped grpc port");
                Authorization {
                    _container: container,
                    url: format!("http://{host}:{port}"),
                }
            })
            .await
    }
}

/// The read and write authorization policy, chosen per test. A single concrete
/// type keeps the served-session and CDC-ingest futures `Send`; the async-trait
/// methods do not otherwise guarantee it for a generic parameter. Mirrors the
/// server binary's `ServerAuth`.
pub enum HarnessAuth {
    /// Authorize the callers a fixture wrote down, and nobody else (R9).
    Roster(RosterAuth),
    /// Authorize through Postgres Row-Level Security.
    Rls(Box<RlsAuth>),
    /// Authorize the way the shipped binary does: from the changed row where
    /// the schema decides, and an `OpenFGA` server for the rest.
    Fga(Box<HarnessFga>),
    /// The shipped policy, with the service taken away and given back on a
    /// flag.
    ///
    /// A stand-in for pulling the container out, and faithful in the one way
    /// that matters: while the flag is down it returns `OpenFgaError::Transport`,
    /// which is exactly what an unreachable server produces, and which the
    /// trait documents as failure to reach an answer rather than an answer of
    /// denied. What is proven through it is connetto's response, not the
    /// service's failure mode.
    Reachable(Arc<AtomicBool>, Box<HarnessFga>),
}

/// The executor the server binary builds, as the harness holds it.
pub type HarnessFga = FgaAuth<String, String, Counted<Channel>>;

/// Whatever the chosen policy could not answer.
///
/// One enum rather than a shared error type, because the two implementations
/// fail for unrelated reasons and flattening them would make a caller read a
/// Postgres failure as a service outage.
#[derive(Debug, thiserror::Error)]
pub enum HarnessAuthError {
    /// Row-level security could not answer.
    #[error(transparent)]
    Rls(#[from] RlsAuthError),
    /// The authorization service could not be reached, or refused.
    #[error(transparent)]
    Fga(#[from] OpenFgaError),
}

impl HarnessAuth {
    /// The stand-in policy: it grants the callers the fixture named.
    #[must_use]
    pub const fn roster(auth: RosterAuth) -> Self {
        Self::Roster(auth)
    }

    /// The RLS policy: reads and writes run under Postgres Row-Level Security.
    #[must_use]
    pub fn rls(auth: RlsAuth) -> Self {
        Self::Rls(Box::new(auth))
    }

    /// The shipped policy: the changed row, then the authorization service.
    #[must_use]
    pub fn fga(auth: HarnessFga) -> Self {
        Self::Fga(Box::new(auth))
    }

    /// The shipped policy behind a flag a test lowers to stage an outage.
    #[must_use]
    pub fn reachable(reachable: Arc<AtomicBool>, auth: HarnessFga) -> Self {
        Self::Reachable(reachable, Box::new(auth))
    }
}

impl VisibilityPolicy for HarnessAuth {
    type Watcher = std::sync::Arc<Principal>;
    type Error = HarnessAuthError;
    type Backend = Postgres;

    async fn may_see<R>(
        &self,
        row: &R,
        watchers: &[Self::Watcher],
        verdicts: &mut [Verdict],
    ) -> Result<(), HarnessAuthError>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        match self {
            Self::Roster(auth) => auth
                .may_see(row, watchers, verdicts)
                .await
                .map_err(|e| match e {}),
            Self::Rls(auth) => Ok(auth.may_see(row, watchers, verdicts).await?),
            Self::Fga(auth) => Ok(auth.may_see(row, watchers, verdicts).await?),
            Self::Reachable(up, auth) => {
                // Spelled out because diesel's blanket `load` shadows the atomic's.
                if AtomicBool::load(up, std::sync::atomic::Ordering::Acquire) {
                    Ok(auth.may_see(row, watchers, verdicts).await?)
                } else {
                    Err(unreachable_service())
                }
            }
        }
    }

    async fn may_write<R>(
        &self,
        write: RowWrite<'_, R>,
        watcher: &Self::Watcher,
    ) -> Result<Verdict, HarnessAuthError>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        match self {
            Self::Roster(auth) => auth.may_write(write, watcher).await.map_err(|e| match e {}),
            Self::Rls(auth) => Ok(auth.may_write(write, watcher).await?),
            Self::Fga(auth) => Ok(auth.may_write(write, watcher).await?),
            Self::Reachable(up, auth) => {
                // Spelled out because diesel's blanket `load` shadows the atomic's.
                if AtomicBool::load(up, std::sync::atomic::Ordering::Acquire) {
                    Ok(auth.may_write(write, watcher).await?)
                } else {
                    Err(unreachable_service())
                }
            }
        }
    }
}

/// The failure an unreachable authorization service produces, spelled the way
/// the real client spells it so a caller cannot tell the stand-in apart.
fn unreachable_service() -> HarnessAuthError {
    HarnessAuthError::Fga(OpenFgaError::Transport {
        attempts: 3,
        message: "the authorization service is unreachable".to_owned(),
    })
}

/// The concrete manager type the harness serves: real snapshot, the harness auth
/// policy, and the async re-execution connector.
type HarnessManager =
    SessionManager<PgSnapshotSource, HarnessAuth, ConnettoWatermark, PgReadConnector>;

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
    /// The rls2fga translator the materializer's engine uses to classify a
    /// membership subquery at registration. `None` for a fixture with no
    /// membership term.
    translator: Option<Translator>,
    /// The caller mapping reverse translation rewrites the client's local caller
    /// function with. `None` when no policy names the caller.
    caller: Option<SessionVariableMapping>,
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
            translator: None,
            caller: None,
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

    /// Hand the materializer's engine the rls2fga translator, and the caller
    /// mapping reverse translation rewrites the client's local caller function
    /// with.
    #[must_use]
    pub fn with_translation(
        mut self,
        translator: Translator,
        caller: Option<SessionVariableMapping>,
    ) -> Self {
        self.translator = Some(translator);
        self.caller = caller;
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

    /// Maintain the authorization store from the change stream, as the binary
    /// does.
    ///
    /// # Panics
    ///
    /// When one is already installed, which would answer events either side of
    /// the swap against two different stores.
    pub fn install_store_upkeep(&self, upkeep: Arc<dyn connetto_server::openfga::StoreUpkeep>) {
        assert!(
            self.manager.install_store_upkeep(upkeep).is_ok(),
            "a store upkeep is already installed on this server"
        );
    }

    /// Ask Postgres row-level security about every current row alongside the
    /// executor that delivers, so the suites can assert the two never disagree.
    ///
    /// # Panics
    ///
    /// When one is already installed, which would compare events either side of
    /// the swap against two different executors.
    pub fn install_second_opinion(&self, second: Arc<RlsAuth>) {
        assert!(
            self.manager.install_second_opinion(second).is_ok(),
            "a second opinion is already installed on this server"
        );
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

    /// Connect a new in-process session and hand back the bare client end, for
    /// the tests that drive a real `ConnettoConnection` from `connetto-client`
    /// rather than the frame-level [`Client`] above.
    ///
    /// A claim about what a device still holds has to be read off a replica the
    /// real client maintains, because clearing on a resync notice is the
    /// client's own step.
    #[must_use]
    pub fn attach(&self) -> LoopbackTransport {
        let (server_transport, client) = loopback();
        let session = Arc::clone(&self.manager);
        tokio::spawn(async move {
            let _ = session.serve(server_transport).await;
        });
        client
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
        translator,
        caller,
    } = config;
    let engine_connector = PgReadConnector::with_session_setup(connector_pool.clone());
    let materializer =
        Materializer::with_read_connector(&pg_ddl, writable, translator, caller, engine_connector)
            .expect("build materializer");
    let write =
        pg_write_target::<ConnettoWatermark>(write_pool, &pg_ddl).expect("build write target");
    let withdrawal_pool = connector_pool.clone();
    let connector = PgReadConnector::with_session_setup(connector_pool);
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
    // R27 decision 6: move-out withdrawals are read on the admin pool, as the
    // binary reads them on DATABASE_URL's, because the caller can no longer
    // see the rows a lost membership exposes. Keys only are sent.
    let withdrawals =
        PgSnapshotSource::from_ddl(withdrawal_pool, &pg_ddl).expect("build withdrawal source");
    assert!(
        manager.install_withdrawal_source(withdrawals).is_ok(),
        "nothing else installs a withdrawal source"
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

    /// Send a handshake presenting `grant` and the cursor a client persisted, so
    /// the server catches the subscription up from that point instead of
    /// snapshotting it afresh.
    pub async fn handshake_resuming(
        &mut self,
        client_id: &str,
        grant: &str,
        cursor: Cursor,
    ) -> HandshakeAck {
        let handshake = Handshake::new(PROTOCOL_VERSION, client_id)
            .with_grant(Grant::new(grant))
            .with_cursor(cursor);
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

    /// Cancel a subscription.
    pub async fn unsubscribe(&mut self, sub_id: &str) {
        self.transport
            .send_control(ControlMessage::Unsubscribe(Unsubscribe {
                sub_id: sub_id.to_owned(),
            }))
            .await
            .expect("send unsubscribe");
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
        let frame = self.next_control().await;
        let ControlMessage::SnapshotBegin(begin) = frame else {
            panic!("expected snapshot begin, got {frame:?}");
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
        self.try_live(timeout)
            .await
            .expect("timed out waiting for a live patch")
    }

    /// The next live patch, or [`None`] when none arrives within `timeout`.
    ///
    /// The waiting form above panics, which cannot express the opposite
    /// assertion: that nothing is delivered. A confidentiality test needs that
    /// one, because silence is the correct outcome for a caller who may not see
    /// the row.
    pub async fn try_live(&mut self, timeout: Duration) -> Option<LivePatch> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let Ok(frame) = tokio::time::timeout(remaining, self.transport.recv()).await else {
                return None;
            };
            match frame.expect("recv frame") {
                Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch))) => return Some(patch),
                Some(IncomingFrame::Control(_)) => {}
                other => panic!("expected a live patch, got {other:?}"),
            }
        }
    }

    /// Wait for a server-initiated replacement of one subscription: the resync
    /// notice, then the snapshot behind it, returned as its patches.
    ///
    /// [`None`] when no notice arrives within `timeout`, which is the assertion
    /// a caller nothing changed for needs: silence.
    pub async fn try_resync(
        &mut self,
        sub_id: &str,
        timeout: Duration,
    ) -> Option<(FullResyncReason, Vec<SnapshotPatch>)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let Ok(frame) = tokio::time::timeout(remaining, self.transport.recv()).await else {
                return None;
            };
            match frame.expect("recv frame") {
                Some(IncomingFrame::Control(ControlMessage::FullResyncRequired(resync))) => {
                    assert_eq!(resync.sub_id, sub_id, "resync for the wrong subscription");
                    let patches = self.expect_snapshot(sub_id).await;
                    return Some((resync.reason, patches));
                }
                // A live patch may be in flight from an earlier commit, and a
                // keepalive pong may interleave. Neither is what this waits for.
                Some(
                    IncomingFrame::Bulk(BulkMessage::LivePatch(_)) | IncomingFrame::Control(_),
                ) => {}
                other => panic!("expected a resync notice, got {other:?}"),
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
