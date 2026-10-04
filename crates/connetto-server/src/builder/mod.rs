//! The one assembly path for the connetto server.
//!
//! [`ServerBuilder`] holds the named collaborators a deployment hands over,
//! [`ServerBuilder::build`] assembles them and returns the unbound
//! [`ServerParts`], and [`ServerBuilder::serve`] owns the serving lifecycle
//! until the shutdown signal or a terminal change-stream outcome. The library
//! never calls `std::process::exit`, installs no signal handlers, and
//! initializes no logging.
//!
//! The sync route answers at [`SYNC_PATH`] on the same listener
//! the login endpoints and file routes answer on.

mod content;
mod ws;

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use thiserror::Error;
use tokio::net::TcpListener;
use tower_http::cors::{AllowCredentials, AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

use crate::audit::pg_audit_hook;
use crate::defaults::{ConnettoAudit, ConnettoAuthSchema, ConnettoBans, ConnettoWatermark};
use crate::manager_builder::ManagerBuilder;
use crate::materializer::Materializer;
use crate::openfga::{Counted, FgaAuth, ModelState, ModelSubject, SetupError, Translated};
use crate::oplog::{OplogConfig, PgOplog};
use crate::reach::GrantReach;
use crate::reserve::{ReaderGate, ReaderReserve};
use crate::session::{
    ReconnectEvent, ReconnectPolicy, ResumePoint, SessionConfig, SessionError, SessionManager,
    StreamCheck, StreamCheckError,
};
use crate::throttle::ThrottleConfig;
use connetto_core::auth::{CapabilityKey, DEFAULT_USER_SETTING};
use connetto_core::messages::{ContentVerb, FatalErrorReason};
use connetto_core::traits::{ContentTicketSigner, HandshakeAuthority};
use connetto_core::{CALLER_FUNCTION, SUBJECTS_FUNCTION, SchemaVersion};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use openfga_client::client::OpenFgaServiceClient;
use openfga_client::tonic::transport::Channel;
use pg2sqlite::prelude::SessionVariableMapping;
use rls2fga::translator::Translator;
use sqlparser::dialect::PostgreSqlDialect;
use subql::backend::Postgres;
use subql::visibility::openfga::OpenFgaPolicy;
use subql::{ParserDB, PgStreamingCdcSource, PgStreamingConfig};

use crate::{
    AbuseConfig, Artifact, AuthConfig, AuthService, CallerMappings, CookieSameSite, DbAuthStore,
    DefaultUuidResolver, GenericOidcProvider, OidcProviderConfig, PgReadConnector,
    PgSnapshotSource, PgWriteTarget, ProviderRegistry, RedirectPolicy, RequestGuard, RlsAuth,
    RuntimeWritableCatalog, TokenAuthority, auth_router, is_loopback_host, pg_ban_store,
    pg_write_target, preflight,
};

/// The path the sync route answers on.
pub const SYNC_PATH: &str = ws::SYNC_PATH;

/// How long a shutdown waits for the live sessions to flush their close frame
/// and tear down before returning anyway.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// The file-serving half of the assembled server.
pub use content::{ContentBuildError, ContentSettings, StoreSpec};

/// The auth service the assembled server runs, over the database store of
/// connetto's auth tables.
type Service = AuthService<DbAuthStore<ConnettoAuthSchema>>;

/// The Postgres pool every assembled server owns.
type PgPool = Pool<AsyncPgConnection>;

/// The change-path executor the assembled server serves through.
type ServerAuth = FgaAuth<String, String, Counted<Channel>>;

/// The concrete session manager the assembled server runs.
pub type ServerManager = SessionManager<
    PgSnapshotSource,
    ServerAuth,
    ConnettoWatermark,
    PgReadConnector,
    PgOplog,
    String,
    String,
    ContentSigner,
>;

/// The content ticket signer the built server mints with.
pub enum ContentSigner {
    /// The deployment serves no files.
    None,
    /// The file server's signer, boxed so the variant stays small.
    #[cfg(feature = "content")]
    Files(Box<connetto_file_server::TicketSigner>),
}

/// Why one mint through [`ContentSigner`] failed.
#[derive(Debug, Error)]
pub enum ContentSignerError {
    /// The deployment serves no files.
    #[error("this deployment serves no files")]
    NotConfigured,
    /// The file server's signer refused.
    #[cfg(feature = "content")]
    #[error(transparent)]
    Ticket(#[from] connetto_file_server::ticket::TicketError),
}

impl ContentTicketSigner for ContentSigner {
    type Error = ContentSignerError;

    async fn mint(
        &self,
        caller: &connetto_core::auth::ContentCaller,
        file_id: [u8; 32],
        verb: ContentVerb,
    ) -> Result<String, Self::Error> {
        // The no-content build has no file arm, so keep the parameters used.
        let _ = (caller, file_id, verb);
        match self {
            Self::None => Err(ContentSignerError::NotConfigured),
            #[cfg(feature = "content")]
            Self::Files(signer) => {
                ContentTicketSigner::mint(signer.as_ref(), caller, file_id, verb)
                    .await
                    .map_err(ContentSignerError::Ticket)
            }
        }
    }
}

/// Why a Postgres connection pool could not be built.
#[derive(Debug, Error)]
#[error("building the Postgres pool at {url}: {source}")]
pub struct PoolError {
    /// The conninfo the pool tried to open against, its password redacted.
    pub url: String,
    /// The pool builder's own error.
    #[source]
    pub source: diesel_async::pooled_connection::PoolError,
}

/// The conninfo for the error text and the `Debug` line, its password made
/// unreadable in a URL's userinfo or query string and in a key-value conninfo.
fn redact_password(conninfo: &str) -> String {
    if conninfo.contains("://") {
        redact_query_password(&redact_userinfo(conninfo))
    } else {
        redact_key_value_password(conninfo)
    }
}

/// A URL with the password in its userinfo replaced.
fn redact_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_owned();
    };
    let userinfo_start = scheme_end + "://".len();
    let authority_end = url[userinfo_start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |end| userinfo_start + end);
    let Some(at) = url[userinfo_start..authority_end].rfind('@') else {
        return url.to_owned();
    };
    let at = userinfo_start + at;
    match url[userinfo_start..at].find(':') {
        Some(colon) => {
            let mut redacted = url.to_owned();
            redacted.replace_range(userinfo_start + colon + 1..at, "****");
            redacted
        }
        None => url.to_owned(),
    }
}

/// A URL with the value of a `password` query parameter replaced.
fn redact_query_password(url: &str) -> String {
    let Some(query_start) = url.find('?') else {
        return url.to_owned();
    };
    let (base, query) = url.split_at(query_start + 1);
    let query = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if key.eq_ignore_ascii_case("password") => format!("{key}=****"),
            _ => pair.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}{query}")
}

/// A key-value conninfo with the value of its `password` key replaced,
/// quoted or not.
fn redact_key_value_password(conninfo: &str) -> String {
    let mut redacted = String::with_capacity(conninfo.len());
    let mut rest = conninfo;
    while let Some(start) = rest.find("password") {
        let (before, from_key) = rest.split_at(start);
        redacted.push_str(before);
        let after_key = from_key["password".len()..].trim_start();
        let Some(value) = after_key.strip_prefix('=') else {
            redacted.push_str("password");
            rest = &from_key["password".len()..];
            continue;
        };
        let value = value.trim_start();
        let end = if let Some(quoted) = value.strip_prefix('\'') {
            quoted.find('\'').map_or(value.len(), |close| close + 2)
        } else {
            value.find(char::is_whitespace).unwrap_or(value.len())
        };
        redacted.push_str("password=****");
        rest = &value[end..];
    }
    redacted.push_str(rest);
    redacted
}

async fn build_pool(url: &str, size: u32) -> Result<PgPool, PoolError> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.to_owned());
    Pool::builder()
        .max_size(size)
        .build(manager)
        .await
        .map_err(|source| PoolError {
            url: redact_password(url),
            source,
        })
}

/// The two database roles the server runs over.
#[derive(Clone)]
pub struct Database {
    owner_url: String,
    reader_url: String,
}

impl fmt::Debug for Database {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Database")
            .field("owner_url", &redact_password(&self.owner_url))
            .field("reader_url", &redact_password(&self.reader_url))
            .finish()
    }
}

impl Database {
    /// Name the two roles, the owner for connetto's bookkeeping and the
    /// non-superuser reader subject to row-level security for everything a
    /// caller touches.
    #[must_use]
    pub fn new(owner_url: impl Into<String>, reader_url: impl Into<String>) -> Self {
        Self {
            owner_url: owner_url.into(),
            reader_url: reader_url.into(),
        }
    }
}

/// The deployment schema, catalog DDL and read policies.
#[derive(Clone, Debug)]
pub struct ServerSchema {
    pg_ddl: String,
    pg_policies: String,
}

impl ServerSchema {
    /// Name the catalog DDL and the policies that decide which view a logical
    /// name resolves to.
    #[must_use]
    pub fn new(pg_ddl: impl Into<String>, pg_policies: impl Into<String>) -> Self {
        Self {
            pg_ddl: pg_ddl.into(),
            pg_policies: pg_policies.into(),
        }
    }
}

/// The persisted JWT keypair, both halves PKCS8 PEM Ed25519.
#[derive(Clone)]
pub struct TokenKeys {
    private: Vec<u8>,
    public: Vec<u8>,
}

impl fmt::Debug for TokenKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenKeys")
            .field("private", &"present")
            .field("public", &"present")
            .finish()
    }
}

impl TokenKeys {
    /// Hold the private and public halves as read from the deployment's key
    /// files.
    #[must_use]
    pub fn from_pem(private: impl Into<Vec<u8>>, public: impl Into<Vec<u8>>) -> Self {
        Self {
            private: private.into(),
            public: public.into(),
        }
    }
}

/// The authorization endpoint and the store its model lands in.
#[derive(Clone, Debug)]
pub struct OpenFga {
    url: String,
    store: String,
}

impl OpenFga {
    /// Name the endpoint and the store the deployment owns.
    #[must_use]
    pub fn new(url: impl Into<String>, store: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            store: store.into(),
        }
    }
}

/// An identity provider the login endpoints serve.
#[derive(Clone, Debug)]
pub enum OidcProvider {
    /// Google's fixed issuer.
    Google(OidcProviderConfig),
    /// Microsoft's fixed issuer.
    Microsoft(OidcProviderConfig),
    /// A deployment's own issuer, discovered from the config's.
    Generic(OidcProviderConfig),
}

/// Why [`ServerBuilder::build`] refused to assemble the server.
#[derive(Debug, Error)]
pub enum BuildError {
    /// A Postgres connection pool could not be built.
    #[error(transparent)]
    Pool(#[from] PoolError),
    /// A deployment artifact the server needs is absent.
    #[error(transparent)]
    Preflight(#[from] crate::preflight::PreflightError),
    /// The JWT keypair failed to load.
    #[error("loading the JWT keypair: {0}")]
    TokenKeys(#[source] crate::authn::token::TokenError),
    /// An identity provider could not be configured.
    #[error("configuring the identity providers: {0}")]
    Providers(String),
    /// No identity provider is configured, so no client can log in.
    #[error("no identity providers configured, so no client can log in")]
    NoProviders,
    /// A pool named no connections, which the pool builder panics on.
    #[error("the {what} is zero, and a pool needs at least one connection")]
    PoolSizeZero {
        /// Which pool named no connections.
        what: String,
    },
    /// A reader reserve that overruns the pool it reserves.
    #[error("the reader reserve of {reserved} connections overruns the reader pool's {total}")]
    ReserveOverTotal {
        /// How many connections the reserve holds back.
        reserved: u32,
        /// The reader pool the reserve is expressed against.
        total: u32,
    },
    /// The authorization store refused the model or the facts behind it.
    #[error(transparent)]
    Authorization(#[from] SetupError),
    /// The connection to the authorization endpoint failed.
    #[error("connecting to the authorization endpoint: {0}")]
    AuthorizationEndpoint(String),
    /// The snapshot source failed to build.
    #[error(transparent)]
    Snapshot(#[from] crate::snapshot::SnapshotError),
    /// The materializer failed to build.
    #[error(transparent)]
    Materializer(#[from] crate::materializer::MaterializerError),
    /// The replica schema documents did not translate.
    #[error(transparent)]
    Schema(#[from] connetto_schema::SchemaError),
    /// The reader role's second opinion failed to build.
    #[error("building the reader second opinion: {0}")]
    SecondOpinion(String),
    /// The database's cluster and the slot could not be settled before
    /// serving.
    #[error(transparent)]
    Settle(#[from] SettleError),
    /// The change feed could not be checked before serving.
    #[error(transparent)]
    StreamCheck(#[from] StreamCheckError),
    /// The file half refused to build.
    #[error(transparent)]
    Content(#[from] ContentBuildError),
}

/// Why settling the cluster and the slot refused.
#[derive(Debug, Error)]
pub enum SettleError {
    /// The recorded cluster could not be read or written.
    #[error(transparent)]
    Epoch(#[from] crate::epoch::EpochError),
    /// Every session could not be revoked after a restore.
    #[error(transparent)]
    Revoke(#[from] crate::authn::service::AuthError),
    /// The reconnect log could not be trimmed past a gap.
    #[error(transparent)]
    Reconcile(#[from] SessionError),
}

/// Why reconnecting the change stream could not open a source.
#[derive(Debug, Error)]
pub enum StreamConnectError {
    /// The catalog DDL did not parse.
    #[error("parsing catalog DDL: {0}")]
    Catalog(String),
    /// The change feed could not be checked.
    #[error(transparent)]
    Check(#[from] StreamCheckError),
    /// The cluster and slot could not be settled.
    #[error(transparent)]
    Settle(#[from] SettleError),
    /// The CDC stream would not open.
    #[error("opening the CDC stream: {0}")]
    Open(String),
}

/// Why [`ServerBuilder::serve`] stopped.
#[derive(Debug, Error)]
pub enum ServeError {
    /// Building the server refused.
    #[error(transparent)]
    Build(#[from] BuildError),
    /// The stream cannot answer what a row looked like before it changed.
    #[error("the change stream is unusable: {0}")]
    ChangeStreamUnusable(String),
    /// The stream gave up reconnecting, or its source ended.
    #[error("the change stream stopped: {0}")]
    ChangeStreamStopped(String),
    /// The HTTP listener failed.
    #[error("the HTTP server failed: {0}")]
    Http(#[source] std::io::Error),
    /// A spawned half of the server failed to join.
    #[error("the server task failed: {0}")]
    Task(String),
}

/// The assembled server, unbound.
pub struct ServerParts {
    /// The merged router, sync route and HTTP routes.
    pub router: Router,
    /// The sync route alone, for a deployment that serves WebSocket traffic
    /// from a dedicated host.
    pub sync_routes: Router,
    /// The HTTP routes alone, login endpoints and file routes under the CORS
    /// layer.
    pub http_routes: Router,
    /// The change stream. Serve it, for example with `tokio::spawn`, and it
    /// ends with a [`ServeError`] when delivery can no longer be live.
    pub change_stream: ChangeStream,
    /// The shutdown handle.
    pub handle: ServerHandle,
}

/// The change-stream future the parts hand over.
pub type ChangeStream = Pin<Box<dyn Future<Output = Result<(), ServeError>> + Send>>;

/// One background loop the build started, the slot-lag watcher and the
/// content sweep, shared by the handle's clones and stopped by the last one.
#[derive(Clone)]
struct BackgroundTask {
    task: Arc<AbortOnDrop>,
}

/// The spawned loop, aborted when the last clone sharing it is dropped.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl BackgroundTask {
    /// Own one spawned loop, so its stop follows the handle's clones.
    fn new(task: tokio::task::JoinHandle<()>) -> Self {
        Self {
            task: Arc::new(AbortOnDrop(task)),
        }
    }

    /// Stop the loop now, idempotent, so an explicit stop and the last drop compose.
    fn stop(&self) {
        self.task.0.abort();
    }
}

/// The shutdown half of a built server.
#[derive(Clone)]
pub struct ServerHandle {
    manager: Arc<ServerManager>,
    lag_watch: Option<BackgroundTask>,
    sweep: Option<BackgroundTask>,
}

impl ServerHandle {
    /// Stop the background loops the build started, close every live session
    /// with `ServerShuttingDown` and wait up to [`SHUTDOWN_GRACE`] for their
    /// own close, so the close frame is delivered rather than raced. Returns
    /// how many were told.
    pub async fn shutdown(&self) -> usize {
        if let Some(watch) = &self.lag_watch {
            watch.stop();
        }
        if let Some(sweep) = &self.sweep {
            sweep.stop();
        }
        let told = self.manager.shutdown().await;
        await_sessions_drained(&self.manager).await;
        told
    }

    /// How many sessions are live right now.
    pub async fn live_connections(&self) -> usize {
        self.manager.live_connections().await
    }
}

async fn close_every_session(manager: &Arc<ServerManager>) {
    let told = manager.shutdown().await;
    tracing::info!(closed = told, "closed every session");
    await_sessions_drained(manager).await;
}

// The close frame is queued, not sent, and the registry drains at the
// moment of the close, so the exit waits on the run loops that are still
// open rather than on the registry.
async fn await_sessions_drained(manager: &ServerManager) {
    let poll = async {
        while manager.open_sessions() > 0 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    if tokio::time::timeout(SHUTDOWN_GRACE, poll).await.is_err() {
        tracing::warn!("shutdown grace elapsed with sessions still open");
    }
}

/// The one assembly path for the connetto server.
#[derive(Debug)]
pub struct ServerBuilder {
    database: Database,
    schema: ServerSchema,
    keys: TokenKeys,
    openfga: OpenFga,
    slot: String,
    publication: String,
    oplog_table: String,
    owner_pool_size: u32,
    slot_lag_watch: Duration,
    oplog_config: OplogConfig,
    reader_reserve: ReaderReserve,
    throttle: ThrottleConfig,
    abuse: AbuseConfig,
    audit: bool,
    bans: bool,
    oidc_providers: Vec<OidcProvider>,
    auth_config: AuthConfig,
    redirect_allowlist: Vec<String>,
    cors_origins: Vec<String>,
    cookie_same_site: CookieSameSite,
    session_config: SessionConfig,
    reconnect_policy: ReconnectPolicy,
    writable: RuntimeWritableCatalog,
    second_opinion: bool,
    content: Option<ContentSettings>,
}

impl ServerBuilder {
    /// Name the required collaborators, the two database roles, the schema
    /// documents, the persisted JWT keypair, and the authorization endpoint
    /// and store.
    #[must_use]
    pub fn new(
        database: Database,
        schema: ServerSchema,
        keys: TokenKeys,
        openfga: OpenFga,
    ) -> Self {
        Self {
            database,
            schema,
            keys,
            openfga,
            slot: "connetto_slot".to_owned(),
            publication: "connetto_pub".to_owned(),
            oplog_table: "connetto_oplog".to_owned(),
            owner_pool_size: 10,
            slot_lag_watch: Duration::from_secs(60),
            oplog_config: OplogConfig::default(),
            reader_reserve: ReaderReserve::new(),
            throttle: ThrottleConfig::default(),
            abuse: AbuseConfig::default(),
            audit: false,
            bans: false,
            oidc_providers: Vec::new(),
            auth_config: AuthConfig::default(),
            redirect_allowlist: Vec::new(),
            cors_origins: Vec::new(),
            cookie_same_site: CookieSameSite::default(),
            session_config: SessionConfig::new(),
            reconnect_policy: ReconnectPolicy::default(),
            writable: RuntimeWritableCatalog::default(),
            second_opinion: false,
            content: None,
        }
    }

    /// Name the logical replication slot, `pgoutput` plugin.
    #[must_use]
    pub fn slot(mut self, slot: impl Into<String>) -> Self {
        self.slot = slot.into();
        self
    }

    /// Name the publication the change stream reads.
    #[must_use]
    pub fn publication(mut self, publication: impl Into<String>) -> Self {
        self.publication = publication.into();
        self
    }

    /// Name the table the reconnect log lives in.
    #[must_use]
    pub fn oplog_table(mut self, table: impl Into<String>) -> Self {
        self.oplog_table = table.into();
        self
    }

    /// Size the owner pool.
    #[must_use]
    pub fn owner_pool_size(mut self, size: u32) -> Self {
        self.owner_pool_size = size;
        self
    }

    /// How often the slot's retained write-ahead log is written to the log,
    /// zero turning the watch off.
    #[must_use]
    pub fn slot_lag_watch(mut self, every: Duration) -> Self {
        self.slot_lag_watch = every;
        self
    }

    /// The reconnect log's own settings.
    #[must_use]
    pub fn oplog_config(mut self, config: OplogConfig) -> Self {
        self.oplog_config = config;
        self
    }

    /// The reader pool's size and its reserved share.
    #[must_use]
    pub fn reader_reserve(mut self, reserve: ReaderReserve) -> Self {
        self.reader_reserve = reserve;
        self
    }

    /// The request limits.
    #[must_use]
    pub fn throttle(mut self, config: ThrottleConfig) -> Self {
        self.throttle = config;
        self
    }

    /// The abuse thresholds.
    #[must_use]
    pub fn abuse(mut self, config: AbuseConfig) -> Self {
        self.abuse = config;
        self
    }

    /// Record access changes to `auth_events` when set.
    #[must_use]
    pub fn audit(mut self, record: bool) -> Self {
        self.audit = record;
        self
    }

    /// Ban an identity that crosses an abuse threshold, reading and writing
    /// `connetto_bans` on the owner pool, when set.
    #[must_use]
    pub fn bans(mut self, ban: bool) -> Self {
        self.bans = ban;
        self
    }

    /// The identity providers the login endpoints serve, at least one.
    #[must_use]
    pub fn oidc_providers(mut self, providers: Vec<OidcProvider>) -> Self {
        self.oidc_providers = providers;
        self
    }

    /// The auth service's own settings, the refresh lifetimes above all.
    #[must_use]
    pub fn auth_config(mut self, config: AuthConfig) -> Self {
        self.auth_config = config;
        self
    }

    /// The exact non-loopback client redirect URIs that are permitted.
    #[must_use]
    pub fn redirect_allowlist(mut self, uris: Vec<String>) -> Self {
        self.redirect_allowlist = uris;
        self
    }

    /// The exact origins whose script may read a login response, credentials
    /// riding only these.
    #[must_use]
    pub fn cors_origins(mut self, origins: Vec<String>) -> Self {
        self.cors_origins = origins;
        self
    }

    /// The session cookie's same-site policy.
    #[must_use]
    pub fn cookie_same_site(mut self, same_site: CookieSameSite) -> Self {
        self.cookie_same_site = same_site;
        self
    }

    /// The session's own settings.
    #[must_use]
    pub fn session_config(mut self, config: SessionConfig) -> Self {
        self.session_config = config;
        self
    }

    /// How the change stream retries.
    #[must_use]
    pub fn reconnect_policy(mut self, policy: ReconnectPolicy) -> Self {
        self.reconnect_policy = policy;
        self
    }

    /// The write policy, the writable tables and their version columns.
    #[must_use]
    pub fn writable(mut self, catalog: RuntimeWritableCatalog) -> Self {
        self.writable = catalog;
        self
    }

    /// Ask the reader role about every current row alongside the delivery,
    /// costing one Postgres round trip per watcher per changed row.
    #[must_use]
    pub fn second_opinion(mut self, install: bool) -> Self {
        self.second_opinion = install;
        self
    }

    /// The file settings, `None` for the no-files deployment.
    #[must_use]
    pub fn content(mut self, settings: Option<ContentSettings>) -> Self {
        self.content = settings;
        self
    }

    /// Assemble the server from the named collaborators.
    ///
    /// Everything is built, checked and wired here so no setting is applied
    /// in a place a reader has to hunt for. The epoch is settled before any
    /// route is returned, and the withdrawal source and the revocation and
    /// ban hooks are installed once the manager exists.
    ///
    /// # Errors
    ///
    /// [`BuildError`] when any collaborator refuses.
    #[expect(
        clippy::too_many_lines,
        reason = "startup reads as one straight deployment, in the order the checks must run"
    )]
    pub async fn build(self) -> Result<ServerParts, BuildError> {
        let Self {
            database,
            schema,
            keys,
            openfga,
            slot,
            publication,
            oplog_table,
            owner_pool_size,
            slot_lag_watch,
            oplog_config,
            reader_reserve,
            throttle,
            abuse,
            audit,
            bans,
            oidc_providers,
            auth_config,
            redirect_allowlist,
            cors_origins,
            cookie_same_site,
            session_config,
            reconnect_policy,
            writable,
            second_opinion,
            content,
        } = self;

        if oidc_providers.is_empty() {
            return Err(BuildError::NoProviders);
        }

        // The pool builder panics on a zero size and the gate on an overrun
        // reserve, so the arithmetic is refused before anything starts.
        if owner_pool_size == 0 {
            return Err(BuildError::PoolSizeZero {
                what: "owner pool".to_owned(),
            });
        }
        if reader_reserve.total() == 0 {
            return Err(BuildError::PoolSizeZero {
                what: "reader pool".to_owned(),
            });
        }
        if reader_reserve.reserved() > reader_reserve.total() {
            return Err(BuildError::ReserveOverTotal {
                reserved: reader_reserve.reserved(),
                total: reader_reserve.total(),
            });
        }
        if content
            .as_ref()
            .is_some_and(|settings| settings.owner_pool_size == 0)
        {
            return Err(BuildError::PoolSizeZero {
                what: "content owner pool".to_owned(),
            });
        }

        let pool = build_pool(&database.owner_url, owner_pool_size).await?;
        let (oplog, lag_watch) = prepare_change_log(
            &pool,
            &slot,
            &publication,
            &oplog_table,
            oplog_config,
            slot_lag_watch,
        )
        .await?;
        // The engine's reads are global statistics with no RLS by construction, so they take their own connector handle.
        let connector = PgReadConnector::with_session_setup(pool.clone());
        let engine_connector = PgReadConnector::with_session_setup(pool.clone());
        let reader_pool_size = reader_reserve.total();
        let guard = build_guard(&pool, reader_reserve.gate(), &throttle, abuse, bans);
        let (service, registry) = build_auth(
            &pool,
            Arc::clone(&guard),
            audit,
            &oidc_providers,
            &keys,
            &auth_config,
        )
        .await?;
        let authority: Arc<dyn HandshakeAuthority> = Arc::new(service.handshake_authority());

        let reader =
            build_reader_side(&database, reader_pool_size, &schema, &publication, content).await?;
        let write_side = build_write_side(
            Pools {
                owner: pool.clone(),
                reader: reader.pool,
            },
            &schema,
            &publication,
            &openfga,
            second_opinion,
            writable,
            engine_connector,
        )
        .await?;
        let feed = Feed {
            database_url: database.owner_url,
            slot,
            publication,
            pg_ddl: schema.pg_ddl,
        };
        let file_router = reader.file_router;
        let sweep = reader.sweep;
        // Move-out withdrawals read on the owner pool, where the membership that ended no longer hides the rows (R27 decision 6).
        let withdrawals = PgSnapshotSource::from_ddl(pool.clone(), &feed.pg_ddl)?;
        let manager = ManagerBuilder::new(
            write_side.materializer,
            reader.snapshot,
            write_side.auth,
            authority,
            connector,
            write_side.write,
        )
        .with_oplog(oplog)
        .with_guard(Arc::clone(&guard))
        .with_session(session_config.with_schema_version(Some(write_side.version)))
        .with_upkeep(write_side.upkeep)
        .with_signer(reader.signer)
        .with_withdrawal_source(withdrawals);
        let manager = match write_side.second {
            Some(second) => manager.with_second_opinion(Arc::new(second)),
            None => manager,
        }
        .build();
        wire_manager(&manager, &service, &guard, &pool, &feed).await?;

        Ok(assemble_parts(
            Arc::clone(&manager),
            Arc::clone(&service),
            pool,
            registry,
            Routes {
                redirect_allowlist,
                cookie_same_site,
                file_router,
                cors_origins,
            },
            StreamWiring {
                feed,
                policy: reconnect_policy,
                lag_watch,
                sweep,
            },
        ))
    }

    /// Assemble the server and serve it on `listener` until the shutdown
    /// signal or a terminal change-stream outcome.
    ///
    /// The shutdown signal stops accepting, closes every session with
    /// `ServerShuttingDown`, a handshake still in flight told the same
    /// instead of registering, waits up to [`SHUTDOWN_GRACE`] for the
    /// sessions' own close, stops the change stream, the slot-lag watcher and
    /// the content sweep, and returns `Ok`. A change stream that cannot answer
    /// what a row looked like before it changed, gives up reconnecting, or
    /// ends its source closes every session the same way and returns the
    /// outcome, and the embedder decides what to do with it.
    ///
    /// # Errors
    ///
    /// [`ServeError`] when the build refused, the change stream ended
    /// terminally, or the HTTP listener failed.
    pub async fn serve<S>(self, listener: TcpListener, shutdown: S) -> Result<(), ServeError>
    where
        S: Future<Output = ()> + Send + 'static,
    {
        let parts = self.build().await?;
        let router = parts.router;
        let mut change_stream = tokio::spawn(parts.change_stream);
        let mut http = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .map_err(ServeError::Http)
        });
        tokio::select! {
            outcome = &mut change_stream => {
                http.abort();
                outcome
                    .map_err(|err| ServeError::Task(format!("the change stream task failed: {err}")))
                    .flatten()
            }
            outcome = &mut http => {
                let told = parts.handle.shutdown().await;
                tracing::info!(closed = told, "shutting down");
                change_stream.abort();
                outcome
                    .map_err(|err| ServeError::Task(format!("the HTTP task failed: {err}")))
                    .flatten()
            }
            () = shutdown => {
                // Stop accepting before the drain, so no session registers
                // into the registry the drain empties.
                http.abort();
                let told = parts.handle.shutdown().await;
                tracing::info!(closed = told, "shutting down");
                // A stream that ends while the shutdown waits is of interest
                // only for its error, so give it the grace to end and log it.
                tokio::select! {
                    outcome = &mut change_stream => match outcome {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            tracing::error!(
                                error = %err,
                                "the change stream stopped while shutting down"
                            );
                        }
                        Err(err) => {
                            tracing::error!(
                                error = %err,
                                "the change stream task failed while shutting down"
                            );
                        }
                    },
                    () = tokio::time::sleep(SHUTDOWN_GRACE) => {
                        change_stream.abort();
                    }
                }
                Ok(())
            }
        }
    }
}

/// Check what the change stream needs, then set up the reconnect log and the
/// slot watch, handing back the watch's stop handle so a refusal after it
/// started cannot leave it running. Everything here reads or writes connetto's
/// own bookkeeping, so it runs on the owner pool.
async fn prepare_change_log(
    pool: &PgPool,
    slot: &str,
    publication: &str,
    oplog_table: &str,
    oplog_config: OplogConfig,
    lag_watch: Duration,
) -> Result<(PgOplog, Option<BackgroundTask>), BuildError> {
    // Absent, these turn the change stream into a retry loop that never
    // succeeds and the first change into a failure on a boot that looked
    // healthy (R32), and a table without its previous image cannot answer
    // whether a caller could see the version that just went (R6).
    let commit_table = PgOplog::commit_table(oplog_table);
    preflight::require(
        pool,
        &[
            Artifact::ReplicationSlot(slot),
            Artifact::Publication(publication),
            Artifact::Table(oplog_table),
            Artifact::Table(&commit_table),
            Artifact::PreviousImages { publication },
        ],
    )
    .await?;
    let watch = if lag_watch.is_zero() {
        tracing::warn!(
            "the slot lag watch is off, so nothing will report a slot filling \
             the primary's disk before it does"
        );
        None
    } else {
        Some(BackgroundTask::new(tokio::spawn(
            crate::slot::log_lag_forever(pool.clone(), slot.to_owned(), lag_watch),
        )))
    };
    Ok((PgOplog::new(pool.clone(), oplog_table, oplog_config), watch))
}

/// Build the guard both surfaces share, the request limits and the abuse
/// thresholds, plus the ban list when asked.
fn build_guard(
    pool: &PgPool,
    reader_gate: ReaderGate,
    throttle: &ThrottleConfig,
    abuse: AbuseConfig,
    bans: bool,
) -> Arc<RequestGuard<String>> {
    // Bans read and write on the owner pool, because on the reader pool RLS turns an invisible row into zero rows and the fail-closed check never fires.
    let guard = RequestGuard::new(*throttle, abuse).with_reader_gate(reader_gate);
    let guard = if bans {
        tracing::info!("banning identities that cross an abuse threshold");
        guard.with_bans(pg_ban_store::<ConnettoBans>(pool.clone()))
    } else {
        guard
    };
    Arc::new(guard)
}

/// Build the auth service and provider registry, the database store and the
/// persisted keypair.
async fn build_auth(
    pool: &PgPool,
    guard: Arc<RequestGuard<String>>,
    audit: bool,
    providers: &[OidcProvider],
    keys: &TokenKeys,
    config: &AuthConfig,
) -> Result<
    (
        Arc<AuthService<DbAuthStore<ConnettoAuthSchema>>>,
        Arc<ProviderRegistry>,
    ),
    BuildError,
> {
    let store = DbAuthStore::new(
        pool.clone(),
        config.refresh_lifetimes(),
        Arc::new(DefaultUuidResolver),
    );
    let authority = TokenAuthority::from_ed_pem(&keys.private, &keys.public, config)
        .map_err(BuildError::TokenKeys)?;
    let http = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| BuildError::Providers(err.to_string()))?;
    let mut registry = ProviderRegistry::new();
    for provider in providers {
        let discovered = match provider {
            OidcProvider::Google(config) => {
                GenericOidcProvider::google(config.clone(), http.clone()).await
            }
            OidcProvider::Microsoft(config) => {
                GenericOidcProvider::microsoft(config.clone(), http.clone()).await
            }
            OidcProvider::Generic(config) => {
                GenericOidcProvider::discover(config.clone(), http.clone()).await
            }
        }
        .map_err(|err| BuildError::Providers(err.to_string()))?;
        registry.register(Arc::new(discovered));
    }
    tracing::info!(providers = providers.len(), "identity providers registered");
    let registry = Arc::new(registry);
    let service = Arc::new(
        AuthService::new(Arc::new(authority), Arc::new(store), guard)
            .with_registry(Arc::clone(&registry)),
    );
    if audit {
        // The same sink on both, because a ban is detected in the guard and
        // every other access change is produced here.
        let hook = pg_audit_hook::<ConnettoAudit>(pool.clone());
        service.guard().set_audit_hook(Arc::clone(&hook));
        service.set_audit_hook(hook);
        tracing::info!("recording access changes to auth_events");
    }
    Ok((service, registry))
}

/// The reader pool's three consumers, the pool itself, the file half and the
/// snapshot source, all built from the same conninfos.
async fn build_reader_side(
    database: &Database,
    reader_pool_size: u32,
    schema: &ServerSchema,
    publication: &str,
    content: Option<ContentSettings>,
) -> Result<ReaderSide, BuildError> {
    let pool = build_pool(&database.reader_url, reader_pool_size).await?;
    let (signer, file_router, sweep) = content::build(
        content,
        &database.owner_url,
        &database.reader_url,
        reader_pool_size,
    )
    .await?;
    let snapshot =
        PgSnapshotSource::from_ddl(pool.clone(), &schema.pg_ddl)?.with_publication(publication);
    Ok(ReaderSide {
        pool,
        signer,
        file_router,
        sweep,
        snapshot,
    })
}

/// The auth listener's `CorsLayer`, loopback origins plus what is listed.
///
/// Credentials ride only the listed origins, so under `SameSite=None` no
/// local page can spend a user's refresh cookie and read the token.
fn cors_layer(cors_origins: &[String]) -> CorsLayer {
    let answered = cors_origins.to_vec();
    let credentialed = cors_origins.to_vec();
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _parts| {
            origin.to_str().is_ok_and(|origin| {
                is_loopback_origin(origin) || answered.iter().any(|allowed| allowed == origin)
            })
        }))
        .allow_credentials(AllowCredentials::predicate(move |origin, _parts| {
            origin
                .to_str()
                .is_ok_and(|origin| credentialed.iter().any(|allowed| allowed == origin))
        }))
        // Wildcards are illegal with credentials, so the answer mirrors what
        // the preflight asked for.
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request())
}

/// Whether `origin` is a loopback origin, so script served from it may read a
/// login response without being listed.
// No scheme condition, unlike the redirect policy's own loopback rule, because
// a page served over `https` from a loopback development server is still the
// developer's own.
fn is_loopback_origin(origin: &str) -> bool {
    url::Url::parse(origin).is_ok_and(|parsed| is_loopback_host(&parsed))
}

/// The deployment's caller pairing for reverse translation (R27), the
/// SQLite functions the deployment named paired against the settings the
/// server binds them to.
fn caller_mapping() -> CallerMappings {
    CallerMappings {
        identity: SessionVariableMapping::current_setting(DEFAULT_USER_SETTING, CALLER_FUNCTION),
        subjects: Some(
            SessionVariableMapping::current_setting(
                <String as CapabilityKey>::SETTING,
                SUBJECTS_FUNCTION,
            )
            .holding_set(<String as CapabilityKey>::SEPARATOR),
        ),
    }
}

/// The change path's executor, the deployment's policies translated, the
/// rules put on the authorization service, and the facts behind them filled
/// if they are new.
///
/// Two clients over one endpoint, questions through [`Counted`] which is
/// where the counter lives and the setup calls outside it.
async fn build_authorization(
    owner_pool: &PgPool,
    reader_pool: &PgPool,
    schema: &ServerSchema,
    publication: &str,
    openfga: &OpenFga,
) -> Result<(ServerAuth, Translator, GrantReach), BuildError> {
    let translated =
        Translated::of::<String>(&schema.pg_ddl, &schema.pg_policies, DEFAULT_USER_SETTING)?;
    // A policy reading a table the change stream does not carry never hears
    // of a grant given or taken, so the store goes stale and then answers
    // confidently and wrongly, and this set difference names the table.
    let required: Vec<Artifact<'_>> = translated
        .policy_tables()
        .iter()
        .map(|table| Artifact::PublishedTable { publication, table })
        .collect();
    preflight::require(owner_pool, &required).await?;

    let channel = Channel::from_shared(openfga.url.clone())
        .map_err(|err| BuildError::AuthorizationEndpoint(format!("parsing the endpoint: {err}")))?
        .connect()
        .await
        .map_err(|err| {
            BuildError::AuthorizationEndpoint(format!(
                "connecting to the authorization service at {}: {err}",
                openfga.url
            ))
        })?;

    let mut setup = OpenFgaServiceClient::new(channel.clone());
    let model = translated.install_model(&mut setup, &openfga.store).await?;
    // Both the Written and the Adopted pass use the loader, the uncounted
    // client keeping boot writes out of the authorization-call counter.
    let loader = OpenFgaPolicy::<_, _, ModelSubject<String, String>, Postgres>::new(
        translated.shapes_arc(),
        setup,
        openfga.store.clone(),
    )
    .map_err(SetupError::from)?
    .authorization_model_id(model.id().to_owned());
    match &model {
        ModelState::Written(_) => {
            let n = translated.load_into(reader_pool, &loader).await?;
            tracing::info!(
                model = model.id(),
                facts = n,
                "authorization rules are new, loading the facts behind them"
            );
        }
        ModelState::Adopted(_) => {
            translated
                .reconcile_materialised(reader_pool, &loader)
                .await?;
            tracing::info!(
                model = model.id(),
                "authorization rules already installed, reconciling whole-shape regions"
            );
        }
    }

    let naming = translated.naming();
    let (shapes, translator, reach) = translated.into_parts();
    let delegate = OpenFgaPolicy::new(
        Arc::clone(&shapes),
        OpenFgaServiceClient::new(Counted::new(channel)),
        openfga.store.clone(),
    )
    .map_err(SetupError::from)?
    .authorization_model_id(model.id().to_owned());
    Ok((FgaAuth::new(shapes, delegate, naming), translator, reach))
}

/// The manager's write side, the authorization model installed, the
/// materializer, the second opinion when asked, the upkeep and the write
/// target.
async fn build_write_side(
    pools: Pools,
    schema: &ServerSchema,
    publication: &str,
    openfga: &OpenFga,
    second_opinion: bool,
    writable: RuntimeWritableCatalog,
    engine_connector: PgReadConnector,
) -> Result<WriteSide, BuildError> {
    let (auth, translator, reach) =
        build_authorization(&pools.owner, &pools.reader, schema, publication, openfga).await?;
    // The engine and the upkeep each classify membership against the deployment's policies, so each takes a translator.
    let upkeep_translator = translator.clone();
    let materializer = Materializer::builder(&schema.pg_ddl)
        .with_write_catalog(writable)
        .with_translator(translator)
        .with_caller(caller_mapping())
        .with_read_connector(engine_connector)
        .build()?;
    // The second opinion reads as the reader role, so it takes its pool before the write target consumes it.
    let second = if second_opinion {
        Some(
            RlsAuth::<String>::from_ddl(pools.reader.clone(), &schema.pg_ddl)
                .map_err(|err| BuildError::SecondOpinion(err.to_string()))?,
        )
    } else {
        None
    };
    let upkeep = auth.upkeep(reach, upkeep_translator, pools.reader.clone());
    let write = pg_write_target::<ConnettoWatermark>(pools.reader, &schema.pg_ddl)?;
    // A changed policy makes an existing replica stale, so a client holding one is told through the advertised version.
    let version =
        connetto_schema::translate::<String>(&schema.pg_ddl, &schema.pg_policies)?.version();
    Ok(WriteSide {
        auth,
        materializer,
        second,
        upkeep,
        write,
        version,
    })
}

/// Report one change-stream or authorization retry, so reconnect churn and an
/// authorization outage are both visible to whatever the embedder already
/// runs.
fn log_reconnect(event: &ReconnectEvent<'_>) {
    let millis = |backoff: &Duration| u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);
    match event {
        ReconnectEvent::Retrying {
            attempt,
            backoff,
            error,
        } => tracing::warn!(
            attempt,
            backoff_ms = millis(backoff),
            error,
            "change stream lost, retrying"
        ),
        ReconnectEvent::GaveUp { attempts, error } => tracing::error!(
            attempts,
            error,
            "change stream gave up reconnecting, live delivery has stopped"
        ),
        ReconnectEvent::AuthRetrying {
            attempt,
            backoff,
            error,
        } => tracing::warn!(
            attempt,
            backoff_ms = millis(backoff),
            error,
            "authorization service unreachable, holding the event and retrying"
        ),
        ReconnectEvent::ReadRetrying {
            attempt,
            backoff,
            error,
        } => tracing::warn!(
            attempt,
            backoff_ms = millis(backoff),
            error,
            "computed read unreachable, holding the event and retrying"
        ),
    }
}

/// Revoke every login session when the feed reads from another cluster, or at
/// boot when the slot resumed past the reconnect log, then record the cluster
/// and trim the log (R70 decisions 5, 10 and 18).
async fn settle_epoch(
    manager: &ServerManager,
    service: &Service,
    pool: &PgPool,
    check: StreamCheck,
    found: crate::epoch::Found,
) -> Result<(), SettleError> {
    let settled = crate::epoch::compare(pool, check.system).await?;
    if let Some(cause) = crate::epoch::revocation(settled, check, found) {
        let revoked = service.revoke_every_session().await?;
        tracing::error!(
            revoked,
            cause = %cause,
            "the database was restored or replaced, so every login session was revoked \
             and each device logs in again"
        );
    }
    // Recorded and trimmed only once the revocation held, so a failure meets
    // the same restore on the next try.
    if settled != crate::epoch::Epoch::Same {
        crate::epoch::record(pool, check.system).await?;
    }
    if let Some(resume) = check.gap {
        manager.reconcile_stream(resume).await?;
    }
    Ok(())
}

/// The manager's post-boot wiring, the live-close hooks and the epoch
/// settlement.
async fn wire_manager(
    manager: &Arc<ServerManager>,
    service: &Service,
    guard: &Arc<RequestGuard<String>>,
    pool: &PgPool,
    feed: &Feed,
) -> Result<(), BuildError> {
    // Revoking a session closes its live connection rather than refusing its next handshake, so the close rides a spawned task.
    let revoke_manager = Arc::clone(manager);
    service.set_revocation_hook(Arc::new(move |session_id| {
        let manager = Arc::clone(&revoke_manager);
        tokio::spawn(async move {
            manager
                .close_session(session_id, FatalErrorReason::SessionRevoked)
                .await;
        });
    }));
    let ban_manager = Arc::clone(manager);
    guard.set_close_hook(Arc::new(move |user| {
        let manager = Arc::clone(&ban_manager);
        tokio::spawn(async move {
            manager.close_person(&user).await;
        });
    }));
    // A restore rewinds the session store with the rows, so the cluster and the slot settle before any route is returned (R70 decisions 5 and 10).
    preflight::require(pool, &[Artifact::Table(crate::epoch::EPOCH_TABLE)]).await?;
    let check = manager
        .check_before_stream(&feed.database_url, pool, &feed.slot)
        .await?;
    settle_epoch(manager, service, pool, check, crate::epoch::Found::AtBoot).await?;
    Ok(())
}

/// Where the change feed reads from.
struct Feed {
    database_url: String,
    slot: String,
    publication: String,
    pg_ddl: String,
}

/// The two pools the write side takes over.
struct Pools {
    owner: PgPool,
    reader: PgPool,
}

/// The reader pool's three consumers, the pool, the file half, its sweep's
/// stop handle and the snapshot source.
struct ReaderSide {
    pool: PgPool,
    signer: ContentSigner,
    file_router: Option<Router>,
    sweep: Option<BackgroundTask>,
    snapshot: PgSnapshotSource,
}

/// The login and file routes' settings.
struct Routes {
    redirect_allowlist: Vec<String>,
    cookie_same_site: CookieSameSite,
    file_router: Option<Router>,
    cors_origins: Vec<String>,
}

/// The manager's write side, the change-path executor, the materializer, the
/// second opinion when asked, the upkeep, the write target and the schema
/// version the sessions advertise.
struct WriteSide {
    auth: ServerAuth,
    materializer: Materializer<ParserDB, RuntimeWritableCatalog, PgReadConnector>,
    second: Option<RlsAuth<String>>,
    upkeep: Arc<dyn crate::openfga::StoreUpkeep>,
    write: PgWriteTarget<ConnettoWatermark>,
    version: SchemaVersion,
}

/// The change-stream future, one reconnecting ingestion that closes every
/// session before returning a terminal outcome.
fn change_stream(
    manager: Arc<ServerManager>,
    service: Arc<Service>,
    pool: PgPool,
    feed: Feed,
    policy: ReconnectPolicy,
) -> ChangeStream {
    Box::pin(async move {
        let connect = |resume: ResumePoint| {
            let (url, slot, publication, ddl) = (
                feed.database_url.clone(),
                feed.slot.clone(),
                feed.publication.clone(),
                feed.pg_ddl.clone(),
            );
            let (pool, manager, service) =
                (pool.clone(), Arc::clone(&manager), Arc::clone(&service));
            async move {
                let catalog = ParserDB::parse::<PostgreSqlDialect>(&ddl)
                    .map_err(|err| StreamConnectError::Catalog(format!("{err:?}")))?;
                let check = manager.check_before_stream(&url, &pool, &slot).await?;
                settle_epoch(
                    &manager,
                    &service,
                    &pool,
                    check,
                    crate::epoch::Found::WhileRunning,
                )
                .await?;
                // Read after the checks, which clear it on a changed timeline
                // or a skipped stretch.
                let config = PgStreamingConfig::new(url, slot, publication).start(resume.get());
                PgStreamingCdcSource::connect(config, catalog)
                    .await
                    .map_err(|err| StreamConnectError::Open(err.to_string()))
            }
        };
        match manager
            .ingest_with_reconnect(connect, &policy, |event| log_reconnect(&event))
            .await
        {
            Ok(()) => {
                // The source ended cleanly, which for a change stream is an
                // outcome the embedder has to act on, not a success, and the
                // sessions it would leave have no live delivery.
                close_every_session(&manager).await;
                Err(ServeError::ChangeStreamStopped(
                    "the change stream source ended".to_owned(),
                ))
            }
            Err(err @ SessionError::ChangeStreamUnusable(_)) => {
                // No restart of the stream changes the table's definition, so
                // the server closes every session and returns the refusal
                // rather than retrying for ever (R6 decision 4).
                close_every_session(&manager).await;
                Err(ServeError::ChangeStreamUnusable(err.to_string()))
            }
            Err(err) => {
                close_every_session(&manager).await;
                Err(ServeError::ChangeStreamStopped(err.to_string()))
            }
        }
    })
}

/// The change stream's feed and reconnect policy, beside the background loop
/// guards the builder spawned, carried as one param beside the shared
/// collaborators.
struct StreamWiring {
    feed: Feed,
    policy: ReconnectPolicy,
    lag_watch: Option<BackgroundTask>,
    sweep: Option<BackgroundTask>,
}

/// The assembled server's parts, the three routers and the change stream.
fn assemble_parts(
    manager: Arc<ServerManager>,
    service: Arc<Service>,
    pool: PgPool,
    registry: Arc<ProviderRegistry>,
    settings: Routes,
    wiring: StreamWiring,
) -> ServerParts {
    let http_routes = auth_router(
        Arc::clone(&service),
        registry,
        RedirectPolicy::new(settings.redirect_allowlist),
        settings.cookie_same_site,
    )
    .merge(settings.file_router.unwrap_or_default())
    .layer(cors_layer(&settings.cors_origins));
    let sync_routes = ws::sync_routes(Arc::clone(&manager));
    let router = sync_routes.clone().merge(http_routes.clone());
    ServerParts {
        router,
        sync_routes,
        http_routes,
        change_stream: change_stream(
            Arc::clone(&manager),
            service,
            pool,
            wiring.feed,
            wiring.policy,
        ),
        handle: ServerHandle {
            manager,
            lag_watch: wiring.lag_watch,
            sweep: wiring.sweep,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::{Layer, ServiceExt};

    /// A caller carrying only an identity, which is what these mints exercise.
    fn identified(user_id: &str) -> connetto_core::auth::ContentCaller {
        connetto_core::auth::ContentCaller::new(Some(user_id.to_owned()), None)
    }

    #[tokio::test]
    async fn an_unset_deployment_refuses_every_ticket() {
        let err = ContentTicketSigner::mint(
            &ContentSigner::None,
            &identified("u-1"),
            [0u8; 32],
            ContentVerb::Read,
        )
        .await
        .expect_err("no signer is configured");
        assert!(matches!(err, ContentSignerError::NotConfigured));
    }

    /// The password the redaction tests plant in a conninfo.
    const PLANTED: &str = "owner-secret";

    /// A conninfo for `user` carrying `password`, built at run time so the
    /// source holds no literal credential.
    fn conninfo(user: &str, password: &str) -> String {
        format!("postgres://{user}:{password}@127.0.0.1:1/db")
    }

    /// Whatever shape a conninfo has, its password never reaches the pool
    /// error's text, while the target stays named.
    #[test]
    fn a_pool_error_keeps_the_password_to_itself() {
        let source = diesel_async::pooled_connection::PoolError::ConnectionError(
            diesel::result::ConnectionError::BadConnection("refused".to_owned()),
        );
        let err = PoolError {
            url: redact_password(&conninfo("owner", PLANTED)),
            source,
        };
        assert!(
            !err.to_string().contains(PLANTED),
            "the pool error keeps the password to itself: {err}"
        );
        assert!(
            err.to_string().contains("127.0.0.1:1"),
            "but it still names the target: {err}"
        );
    }

    /// A conninfo with no password, or no userinfo at all, is redacted to
    /// itself, and a passworded one keeps its shape.
    #[test]
    fn redaction_leaves_a_passwordless_conninfo_alone() {
        assert_eq!(
            redact_password("postgres://owner@127.0.0.1:1/db"),
            "postgres://owner@127.0.0.1:1/db"
        );
        assert_eq!(
            redact_password("postgres://127.0.0.1:1/db"),
            "postgres://127.0.0.1:1/db"
        );
        assert_eq!(
            redact_password(&conninfo("owner", PLANTED)),
            conninfo("owner", "****")
        );
    }

    /// A password in a key-value conninfo, quoted or not, or in a URL's query
    /// string stays out of the redacted text and the `Debug` line alike.
    #[test]
    fn every_conninfo_form_keeps_its_password_out() {
        for form in [
            format!("host=localhost user=owner password={PLANTED} dbname=db"),
            format!("host=localhost password='{PLANTED} with spaces' dbname=db"),
            format!("postgres://localhost/db?sslmode=disable&password={PLANTED}"),
            format!("postgresql://owner@localhost/db?password={PLANTED}&sslmode=disable"),
        ] {
            let redacted = redact_password(&form);
            assert!(!redacted.contains(PLANTED), "{form} redacted to {redacted}");
            assert!(
                redacted.contains("localhost"),
                "the target stays named: {redacted}"
            );
            let shown = format!("{:?}", Database::new(form.clone(), form.clone()));
            assert!(
                !shown.contains(PLANTED),
                "the Debug line keeps it out: {shown}"
            );
        }
    }

    /// The settings a deployment hands the builder keep their passwords, key
    /// material and client secret out of the `Debug` line the builder and its
    /// pieces print.
    #[test]
    fn the_builder_pieces_keep_their_secrets_out_of_their_debug_line() {
        let database = Database::new(
            conninfo("owner", PLANTED),
            conninfo("reader", "reader-secret"),
        );
        let keys = TokenKeys::from_pem(b"PRIVATE-PEM-BYTES".to_vec(), b"PUBLIC-PEM-BYTES".to_vec());
        let provider = OidcProvider::Generic(
            OidcProviderConfig::new(
                "dev",
                "dev-client",
                "https://idp.example",
                "https://app.example/callback",
            )
            .with_client_secret(Some("oidc-secret".to_owned())),
        );
        let settings = ContentSettings {
            base_url: "http://127.0.0.1:8099".to_owned(),
            ttl: Duration::from_secs(60),
            read_ceiling: 1 << 20,
            grace: Duration::ZERO,
            cadence: Duration::from_secs(1),
            quota_identity: 0,
            storage_ceiling: 0,
            bandwidth_ceiling: 0,
            bandwidth_window_days: 30,
            warn_fraction: 0.8,
            ceiling_refresh: Duration::from_secs(10),
            owner_pool_size: 2,
            store: StoreSpec::Fs(std::env::temp_dir()),
            key: vec![191, 208, 187],
        };
        let builder = ServerBuilder::new(
            database,
            ServerSchema::new("CREATE TABLE t (id INT PRIMARY KEY);", ""),
            keys,
            OpenFga::new("http://127.0.0.1:1", "store"),
        )
        .oidc_providers(vec![provider])
        .content(Some(settings));
        let shown = format!("{builder:?}");
        for secret in [
            "owner-secret",
            "reader-secret",
            "PRIVATE-PEM-BYTES",
            "PUBLIC-PEM-BYTES",
            "oidc-secret",
            "[191, 208, 187]",
        ] {
            assert!(
                !shown.contains(secret),
                "the Debug line keeps its secrets: {shown}"
            );
        }
    }

    /// Credentials ride only the origins `CONNETTO_AUTH_CORS_ORIGINS` lists. A
    /// loopback page is still answered without being listed, and without
    /// credentials, whatever address the listener binds, so under
    /// `SameSite=None` no local page can spend a refresh cookie it was not
    /// listed for. A development page lists its own origin to carry one.
    #[tokio::test]
    async fn the_cors_layer_carries_credentials_only_for_trusted_origins() {
        async fn answer(listed: &[&str], origin: &str) -> axum::response::Response {
            let listed: Vec<String> = listed.iter().map(|&origin| origin.to_owned()).collect();
            let layer = cors_layer(&listed);
            let router = layer.layer(axum::Router::new().route(
                "/auth/refresh",
                axum::routing::post(|| async { StatusCode::NO_CONTENT }),
            ));
            router
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/auth/refresh")
                        .header("origin", origin)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response")
        }
        fn credentialed(response: &axum::response::Response) -> bool {
            response
                .headers()
                .get("access-control-allow-credentials")
                .is_some_and(|value| value == "true")
        }
        const APP: &str = "https://app.example";
        const DEV: &str = "http://127.0.0.1:5173";

        let trusted = answer(&[APP], APP).await;
        assert_eq!(
            trusted.headers()["access-control-allow-origin"],
            APP,
            "the configured origin is answered"
        );
        assert!(
            credentialed(&trusted),
            "and the answer permits the cookie to ride"
        );

        let unlisted = answer(&[APP], DEV).await;
        assert_eq!(
            unlisted.headers()["access-control-allow-origin"],
            DEV,
            "a loopback page is answered without being configured"
        );
        assert!(
            !credentialed(&unlisted),
            "but its cookie never rides until its origin is listed"
        );

        let listed = answer(&[APP, DEV], DEV).await;
        assert!(
            credentialed(&listed),
            "a development page that lists its origin carries the cookie"
        );

        for hostile in ["https://evil.example", "http://evil.localhost:5173"] {
            let answered = answer(&[APP], hostile).await;
            assert!(
                !answered
                    .headers()
                    .contains_key("access-control-allow-origin"),
                "{hostile} gets no answer, so the browser refuses it the response"
            );
            assert!(!credentialed(&answered), "and no credentials for {hostile}");
        }
    }

    /// The file routes mount on the same router the login endpoints answer
    /// on, under the same CORS layer, so an origin the deployment lists for
    /// logins uploads as well, a loopback page always may, and nothing else
    /// is handed a response.
    #[tokio::test]
    async fn the_file_routes_share_the_login_routes_cors_layer() {
        let file_routes =
            axum::Router::new().route("/files/{id}", axum::routing::get(|| async { "served" }));
        let app = axum::Router::new()
            .merge(file_routes)
            .layer(cors_layer(&["https://app.example".to_owned()]));

        let preflight = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/files/abc")
                    .header("origin", "https://app.example")
                    .header("access-control-request-method", "PUT")
                    .body(Body::empty())
                    .expect("a preflight request"),
            )
            .await
            .expect("the layer answers the preflight");
        assert_eq!(preflight.status(), StatusCode::OK);
        assert_eq!(
            allowed_origin(&preflight).as_deref(),
            Some("https://app.example"),
            "a listed origin may upload"
        );

        let served = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/files/abc")
                    .header("origin", "http://localhost:5173")
                    .body(Body::empty())
                    .expect("a get request"),
            )
            .await
            .expect("the merged router serves the file route");
        assert_eq!(served.status(), StatusCode::OK);
        assert_eq!(
            allowed_origin(&served).as_deref(),
            Some("http://localhost:5173"),
            "a loopback origin is always allowed"
        );

        let refused = app
            .oneshot(
                Request::builder()
                    .uri("/files/abc")
                    .header("origin", "https://elsewhere.example")
                    .body(Body::empty())
                    .expect("a get request"),
            )
            .await
            .expect("the router still serves the body");
        assert!(
            allowed_origin(&refused).is_none(),
            "an unlisted origin must not be handed the response"
        );
    }

    /// The `access-control-allow-origin` header, if the CORS layer granted one.
    fn allowed_origin(response: &axum::http::Response<Body>) -> Option<String> {
        response
            .headers()
            .get("access-control-allow-origin")
            .map(|value| value.to_str().expect("ascii header").to_owned())
    }
}
