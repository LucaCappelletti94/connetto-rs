//! The connetto sync server as a runnable process.
//!
//! Configuration comes from the environment:
//!
//! - `CONNETTO_BIND`: listen address (default `127.0.0.1:8080`).
//! - `DATABASE_URL`: Postgres conninfo for the CDC replication stream, snapshot
//!   reads, and aggregate re-execution. The role needs `REPLICATION`.
//! - `CONNETTO_PG_DDL` or `CONNETTO_PG_DDL_FILE`: the Postgres catalog DDL.
//! - `CONNETTO_WRITABLE`: comma-separated tables that accept client mutations,
//!   each `table` or `table:version_column` (the version column conflict-checks
//!   version-bearing updates and deletes). Unset means no table is writable, so
//!   every client mutation is rejected. Writes apply to the source Postgres.
//! - `CONNETTO_SLOT`: pre-created logical replication slot (default
//!   `connetto_slot`).
//! - `CONNETTO_PUBLICATION`: publication the slot follows (default
//!   `connetto_pub`).
//! - `CONNETTO_READER_URL`: required non-superuser conninfo. Snapshots, read
//!   authorization, and mutation applies run under Postgres Row-Level Security
//!   as that role, and the server refuses to start without it, because the
//!   owner pool bypasses every policy (Postgres applies none to a superuser or
//!   table owner). The role needs `SELECT, INSERT, UPDATE` on
//!   `_connetto_mutations` (the exactly-once watermark table). connetto emits
//!   no DDL, so the deployment creates that table (see
//!   `docs/architecture/11-authentication.md`) alongside the auth tables. A
//!   restricted role cannot `CREATE` in schema `public` on Postgres 15 and
//!   later, so the admin runs the migration.
//! - `CONNETTO_OIDC_PROVIDER`: which identity provider `CONNETTO_AUTH` logs
//!   users in with, one of `google`, `microsoft`, or `generic` (lowercase).
//!   Anything else, including an unset or miscapitalised value, refuses
//!   startup.
//!
//! The publication and replication slot (with the `pgoutput` plugin) must
//! already exist. The server does not create them.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};
use connetto_core::messages::FatalErrorReason;
use connetto_core::traits::HandshakeAuthority;
use connetto_core::{SchemaVersion, SessionId};
use connetto_server::watermark_schema::check_watermark_shape;
use connetto_server::{
    AuthConfig, AuthService, AuthStore, AuthStoreError, DbAuthStore, DefaultUuidResolver,
    GenericOidcProvider, InMemoryAuthStore, IssuedSession, Materializer, OidcProviderConfig,
    PgSnapshotSource, ProviderRegistry, ReconnectEvent, ReconnectPolicy, RedirectPolicy,
    RefreshOutcome, ResolvedIdentity, RetainedProviderToken, RlsAuth, RuntimeWritableCatalog,
    SessionConfig, SessionManager, TokenAuthority, WebSocketTransport, auth_router,
    connetto_auth_tables, connetto_watermark_table, pg_write_target,
};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use sqlparser::dialect::PostgreSqlDialect;
use subql::reexec::PgAsyncDieselConnector;
use subql::{ParserDB, PgStreamingCdcSource, PgStreamingConfig};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

/// Whether `origin` is a loopback origin, so script served from it may read a
/// login response without being listed.
///
/// Parsed rather than string-matched, mirroring the redirect policy's own
/// loopback rule, so a host like `127.0.0.1.evil.example` cannot pass.
fn is_loopback_origin(origin: &str) -> bool {
    let Ok(parsed) = url::Url::parse(origin) else {
        return false;
    };
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

// The reference binary uses the default connetto auth and watermark tables over
// `Id = String` (Text `user_id`), matching the `DefaultUuidResolver`. These
// generate the `connetto_sessions`/`connetto_provider_tokens` tables plus
// `ConnettoAuthSchema`, and the `_connetto_mutations` table plus
// `ConnettoWatermark`. connetto emits no DDL; the deployment runs the migration.
connetto_auth_tables!(String, diesel::sql_types::Text);
connetto_watermark_table!(String);

/// The auth store chosen at startup. A single concrete type so the auth
/// service and session-verifier futures stay `Send`.
/// Each `async fn` erases the two arm future types through `.await`.
enum ServerStore {
    /// Single-server, ephemeral, deterministic identity mapping.
    InMemory(InMemoryAuthStore),
    /// Durable and mesh-capable, identity resolved by the deployment.
    Db(DbAuthStore<ConnettoAuthSchema>),
}

impl AuthStore for ServerStore {
    type Id = String;

    async fn create_session(
        &self,
        identity: &ResolvedIdentity,
        now: SystemTime,
    ) -> Result<IssuedSession, AuthStoreError> {
        match self {
            Self::InMemory(store) => store.create_session(identity, now).await,
            Self::Db(store) => store.create_session(identity, now).await,
        }
    }

    async fn session_is_live(
        &self,
        session_id: SessionId,
        now: SystemTime,
    ) -> Result<bool, AuthStoreError> {
        match self {
            Self::InMemory(store) => store.session_is_live(session_id, now).await,
            Self::Db(store) => store.session_is_live(session_id, now).await,
        }
    }

    async fn rotate_refresh(
        &self,
        refresh_token: &str,
        now: SystemTime,
    ) -> Result<RefreshOutcome, AuthStoreError> {
        match self {
            Self::InMemory(store) => store.rotate_refresh(refresh_token, now).await,
            Self::Db(store) => store.rotate_refresh(refresh_token, now).await,
        }
    }

    async fn revoke_session(&self, session_id: SessionId) -> Result<(), AuthStoreError> {
        match self {
            Self::InMemory(store) => store.revoke_session(session_id).await,
            Self::Db(store) => store.revoke_session(session_id).await,
        }
    }

    async fn session_for_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<Option<SessionId>, AuthStoreError> {
        match self {
            Self::InMemory(store) => store.session_for_refresh(refresh_token).await,
            Self::Db(store) => store.session_for_refresh(refresh_token).await,
        }
    }

    async fn set_retained_provider_token(
        &self,
        session_id: SessionId,
        token: &RetainedProviderToken,
        now: SystemTime,
    ) -> Result<(), AuthStoreError> {
        match self {
            Self::InMemory(store) => {
                store
                    .set_retained_provider_token(session_id, token, now)
                    .await
            }
            Self::Db(store) => {
                store
                    .set_retained_provider_token(session_id, token, now)
                    .await
            }
        }
    }

    async fn retained_provider_token(
        &self,
        session_id: SessionId,
    ) -> Result<Option<RetainedProviderToken>, AuthStoreError> {
        match self {
            Self::InMemory(store) => store.retained_provider_token(session_id).await,
            Self::Db(store) => store.retained_provider_token(session_id).await,
        }
    }
}

/// Build the auth service and provider registry when `CONNETTO_AUTH` selects a
/// store (`in-memory` or `database`). Unset leaves the trusting verifier and no
/// auth endpoints, which suits dev and the pre-acquisition client loops until
/// phases 4 and 5.
async fn build_auth(
    pool: &Pool<AsyncPgConnection>,
) -> Result<Option<(Arc<AuthService<ServerStore>>, Arc<ProviderRegistry>)>> {
    let mode = env_or("CONNETTO_AUTH", "");
    if mode.is_empty() {
        return Ok(None);
    }
    let config = AuthConfig::default();
    let store = match mode.as_str() {
        "in-memory" => ServerStore::InMemory(InMemoryAuthStore::new(config.refresh_lifetimes())),
        "database" => {
            // connetto emits no DDL: the deployment owns and migrates the
            // `connetto_sessions`/`connetto_provider_tokens` tables. The
            // reference binary resolves identity to a deterministic UUID v5.
            ServerStore::Db(DbAuthStore::new(
                pool.clone(),
                config.refresh_lifetimes(),
                Arc::new(DefaultUuidResolver),
            ))
        }
        other => {
            return Err(anyhow!(
                "unknown CONNETTO_AUTH mode {other:?}, expected in-memory or database"
            ));
        }
    };
    let authority = build_token_authority(&config)?;
    let registry = Arc::new(build_registry(&config).await?);
    let service = Arc::new(
        AuthService::new(Arc::new(authority), Arc::new(store)).with_registry(Arc::clone(&registry)),
    );
    Ok(Some((service, registry)))
}

/// Build the provider registry from `CONNETTO_OIDC_PROVIDER`.
///
/// `google` and `microsoft` discover the respective provider and `generic`
/// discovers `CONNETTO_OIDC_ISSUER`. Anything else, including an unset or
/// miscapitalised value, refuses startup naming the value, so a typo cannot
/// silently select a different provider. A provider reads
/// `CONNETTO_OIDC_CLIENT_ID`, `CONNETTO_OIDC_CLIENT_SECRET` (optional),
/// `CONNETTO_OIDC_REDIRECT_URL`, and `CONNETTO_OIDC_SCOPES` (comma-separated).
async fn build_registry(config: &AuthConfig) -> Result<ProviderRegistry> {
    let mut registry = ProviderRegistry::new();
    let kind = env_or("CONNETTO_OIDC_PROVIDER", "");
    match kind.as_str() {
        "google" | "microsoft" | "generic" => {
            let http = openidconnect::reqwest::ClientBuilder::new()
                .redirect(openidconnect::reqwest::redirect::Policy::none())
                .build()
                .context("building the OIDC HTTP client")?;
            let provider_config = oidc_config_from_env(config)?;
            let provider = match kind.as_str() {
                "google" => GenericOidcProvider::google(provider_config, http).await,
                "microsoft" => GenericOidcProvider::microsoft(provider_config, http).await,
                _ => GenericOidcProvider::discover(provider_config, http).await,
            }
            .map_err(|err| anyhow!("configuring the {kind} provider: {err}"))?;
            registry.register(Arc::new(provider));
        }
        "" => {
            return Err(anyhow!(
                "CONNETTO_OIDC_PROVIDER is unset, expected one of google, microsoft, or generic"
            ));
        }
        other => {
            return Err(anyhow!(
                "unrecognised CONNETTO_OIDC_PROVIDER {other:?}, expected one of google, \
                 microsoft, or generic (names are lowercase)"
            ));
        }
    }
    Ok(registry)
}

/// The generic provider configuration from the `CONNETTO_OIDC_*` environment.
fn oidc_config_from_env(config: &AuthConfig) -> Result<OidcProviderConfig> {
    let scopes = env_or("CONNETTO_OIDC_SCOPES", "")
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect();
    Ok(OidcProviderConfig {
        name: env_or("CONNETTO_OIDC_NAME", "oidc"),
        client_id: std::env::var("CONNETTO_OIDC_CLIENT_ID")
            .context("set CONNETTO_OIDC_CLIENT_ID")?,
        client_secret: std::env::var("CONNETTO_OIDC_CLIENT_SECRET").ok(),
        issuer: env_or("CONNETTO_OIDC_ISSUER", &config.issuer),
        redirect_url: std::env::var("CONNETTO_OIDC_REDIRECT_URL")
            .context("set CONNETTO_OIDC_REDIRECT_URL")?,
        scopes,
        assurance: connetto_server::AssuranceRequirement::none(),
    })
}

/// Load the Ed25519 signing keypair from `CONNETTO_JWT_PRIVATE_KEY_FILE` and
/// `CONNETTO_JWT_PUBLIC_KEY_FILE` (PKCS#8 PEM), or generate an ephemeral one.
/// An ephemeral key does not survive a restart, so a durable or mesh deployment
/// supplies a stable key.
fn build_token_authority(config: &AuthConfig) -> Result<TokenAuthority> {
    if let (Ok(private_path), Ok(public_path)) = (
        std::env::var("CONNETTO_JWT_PRIVATE_KEY_FILE"),
        std::env::var("CONNETTO_JWT_PUBLIC_KEY_FILE"),
    ) {
        let private =
            std::fs::read(&private_path).with_context(|| format!("reading {private_path}"))?;
        let public =
            std::fs::read(&public_path).with_context(|| format!("reading {public_path}"))?;
        TokenAuthority::from_ed_pem(&private, &public, config)
            .map_err(|err| anyhow!("loading JWT keypair: {err}"))
    } else {
        tracing::warn!(
            "no CONNETTO_JWT_*_KEY_FILE set, generating an ephemeral Ed25519 keypair, so \
             tokens do not survive a restart"
        );
        TokenAuthority::generate(config).map_err(|err| anyhow!("generating JWT keypair: {err}"))
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

/// Read a DDL from `<key>` directly, or from the path in `<key>_FILE`.
fn read_ddl(key: &str) -> Result<String> {
    if let Ok(inline) = std::env::var(key) {
        return Ok(inline);
    }
    let file_key = format!("{key}_FILE");
    let path = std::env::var(&file_key).map_err(|_| anyhow!("set {key} or {file_key}"))?;
    std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))
}

/// Parse `CONNETTO_WRITABLE` into a runtime write policy. Each comma-separated
/// entry is a table, or `table:version_column` to conflict-check version-bearing
/// updates and deletes on that table. Unset or empty yields no writable tables,
/// so every client mutation is rejected.
fn writable_catalog() -> RuntimeWritableCatalog {
    let spec = env_or("CONNETTO_WRITABLE", "");
    let mut builder = RuntimeWritableCatalog::builder();
    for entry in spec.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        builder = match entry.split_once(':') {
            Some((table, version)) => builder.versioned(table.trim(), version.trim()),
            None => builder.writable(entry),
        };
    }
    builder.build()
}

async fn build_pool(url: &str) -> Result<Pool<AsyncPgConnection>> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.to_owned());
    Pool::builder()
        .build(manager)
        .await
        .context("building the Postgres connection pool")
}

#[tokio::main]
async fn main() -> Result<()> {
    // `pg_walstream` reports every standby status update at `info`, which is one
    // line per ten seconds per server whether or not anything happened, and it
    // buries this server's own events. `RUST_LOG` brings it back.
    connetto_core::logging::init_stdout_with_default("info,pg_walstream=warn");
    let bind = env_or("CONNETTO_BIND", "127.0.0.1:8080");
    let database_url = std::env::var("DATABASE_URL").context("set DATABASE_URL")?;
    let pg_ddl = read_ddl("CONNETTO_PG_DDL")?;
    let slot = env_or("CONNETTO_SLOT", "connetto_slot");
    let publication = env_or("CONNETTO_PUBLICATION", "connetto_pub");
    let pool = build_pool(&database_url).await?;
    // connetto emits no DDL. The deployment owns the `_connetto_mutations`
    // watermark table (see `docs/architecture/11-authentication.md`) and the
    // `ConnettoWatermark` reference schema keys on it.
    let connector = PgAsyncDieselConnector::new(pool.clone());
    let materializer = Materializer::with_write_catalog(&pg_ddl, writable_catalog())
        .map_err(|err| anyhow!("building materializer: {err}"))?;

    // The handshake authority is a required constructor argument with no
    // default (R2), so the auth service is built first and the server refuses
    // to run without one: an unset CONNETTO_AUTH would otherwise mean a
    // handshake with nothing to check a grant against.
    let Some((service, registry)) = build_auth(&pool).await? else {
        return Err(anyhow!(
            "set CONNETTO_AUTH to in-memory or database: the server refuses to run \
             without a handshake authority, because it would otherwise have no way to \
             check a grant or to sign the credential a run resumes on"
        ));
    };
    let authority: Arc<dyn HandshakeAuthority> = Arc::new(service.handshake_authority());

    // Snapshots, read authorization, and the write apply all run under RLS as
    // the reader role, which must be subject to RLS (non-superuser, not the
    // table owner). Postgres applies no policy to a superuser or table owner,
    // so serving reads or writes from the owner pool would bypass RLS
    // entirely, and the server refuses to start instead of falling back to it.
    let reader_url = std::env::var("CONNETTO_READER_URL").map_err(|_| {
        anyhow!(
            "set CONNETTO_READER_URL to a non-superuser conninfo subject to Row-Level \
             Security (the server does not serve reads or writes from the owner pool)"
        )
    })?;
    let reader_pool = build_pool(&reader_url).await?;
    // Refuse a watermark table whose shape mismatches this build's key: a
    // mis-keyed exactly-once record stays silent until a replay happens.
    {
        let mut conn = reader_pool
            .get()
            .await
            .map_err(|err| anyhow!("connecting as the reader role: {err}"))?;
        check_watermark_shape::<ConnettoWatermark>(&mut conn)
            .await
            .map_err(|err| anyhow!("{err}"))?;
    }
    let snapshot = PgSnapshotSource::from_ddl(reader_pool.clone(), &pg_ddl)
        .map_err(|err| anyhow!("building snapshot source: {err}"))?;
    let auth = RlsAuth::from_ddl(reader_pool.clone(), &pg_ddl)
        .map_err(|err| anyhow!("building RLS auth: {err}"))?;
    let write = pg_write_target::<ConnettoWatermark>(reader_pool, &pg_ddl)
        .map_err(|err| anyhow!("building write target: {err}"))?;

    let manager = SessionManager::with_connector(
        materializer,
        snapshot,
        auth,
        authority,
        connector,
        write,
        SessionConfig {
            schema_version: Some(SchemaVersion::from_source(&pg_ddl)),
            ..SessionConfig::default()
        },
    );
    // Revoking a session closes its live connection rather than only refusing
    // its next handshake. The hook fires synchronously inside the revoke, so
    // the close itself rides a spawned task.
    {
        let revoke_manager = Arc::clone(&manager);
        service.set_revocation_hook(Arc::new(move |session_id| {
            let manager = Arc::clone(&revoke_manager);
            tokio::spawn(async move {
                manager
                    .close_session(session_id, FatalErrorReason::SessionRevoked)
                    .await;
            });
        }));
    }
    spawn_auth_endpoints(&service, registry);
    run(&manager, &database_url, &slot, &publication, &pg_ddl, &bind).await
}

/// Serve the login and refresh endpoints beside the sync listener.
fn spawn_auth_endpoints(service: &Arc<AuthService<ServerStore>>, registry: Arc<ProviderRegistry>) {
    let auth_bind = env_or("CONNETTO_AUTH_BIND", "127.0.0.1:8081");
    // CONNETTO_AUTH_REDIRECT_ALLOWLIST is a comma-separated list of exact
    // non-loopback client redirect URIs that are permitted (a browser client
    // lists its own callback). Loopback redirects are always allowed, so a
    // native client needs no entry.
    let allowlist = env_or("CONNETTO_AUTH_REDIRECT_ALLOWLIST", "")
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect();
    // CONNETTO_AUTH_CORS_ORIGINS is a comma-separated list of exact origins
    // whose script may read a login response. An app served from a different
    // origin than these endpoints needs one, because without it the browser
    // refuses to hand the response to the page. Loopback origins are always
    // allowed, mirroring the redirect policy's loopback rule and for the same
    // reason: script on a loopback origin is already on the machine.
    let cors_origins: Vec<String> = env_or("CONNETTO_AUTH_CORS_ORIGINS", "")
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _parts| {
            origin.to_str().is_ok_and(|origin| {
                is_loopback_origin(origin) || cors_origins.iter().any(|allowed| allowed == origin)
            })
        }))
        .allow_methods(Any)
        .allow_headers(Any);
    let router = auth_router(
        Arc::clone(service),
        registry,
        RedirectPolicy::new(allowlist),
    )
    .layer(cors);
    tokio::spawn(async move {
        match TcpListener::bind(&auth_bind).await {
            Ok(listener) => {
                tracing::info!(bind = %auth_bind, "auth endpoints listening");
                if let Err(err) = axum::serve(listener, router).await {
                    tracing::error!(error = %err, "auth endpoint server stopped");
                }
            }
            Err(err) => {
                tracing::error!(bind = %auth_bind, error = %err, "binding the auth endpoints failed");
            }
        }
    });
}

/// How long a shutdown waits for the live sessions to flush their close frame
/// and tear down before the process exits anyway.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Resolve on the first SIGINT or SIGTERM. On a platform without SIGTERM only
/// the interrupt arm can fire.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::warn!(error = %err, "no SIGTERM handler, interrupt only");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}

/// Start CDC ingestion and serve connections until the listener fails or a
/// shutdown signal arrives.
async fn run(
    manager: &Arc<
        SessionManager<PgSnapshotSource, RlsAuth, ConnettoWatermark, PgAsyncDieselConnector>,
    >,
    database_url: &str,
    slot: &str,
    publication: &str,
    pg_ddl: &str,
    bind: &str,
) -> Result<()> {
    // Fail fast on a bad catalog DDL; the reconnect loop rebuilds the catalog
    // per connect and must not spin on a deterministic parse error.
    ParserDB::parse::<PostgreSqlDialect>(pg_ddl)
        .map_err(|err| anyhow!("parsing catalog DDL: {err:?}"))?;

    let ingest_manager = manager.clone();
    let url = database_url.to_owned();
    let slot = slot.to_owned();
    let publication = publication.to_owned();
    let ddl = pg_ddl.to_owned();
    tokio::spawn(async move {
        // Reconnect the replication stream forever; the slot resumes from its
        // confirmed position, so a dropped connection loses no events.
        let connect = || {
            let (url, slot, publication, ddl) =
                (url.clone(), slot.clone(), publication.clone(), ddl.clone());
            async move {
                let catalog = ParserDB::parse::<PostgreSqlDialect>(&ddl)
                    .map_err(|err| anyhow!("parsing catalog DDL: {err:?}"))?;
                let config = PgStreamingConfig::new(url, slot, publication);
                PgStreamingCdcSource::connect(config, catalog)
                    .await
                    .map_err(|err| anyhow!("opening CDC stream: {err}"))
            }
        };
        if let Err(err) = ingest_manager
            .ingest_with_reconnect(connect, &ReconnectPolicy::default(), |event| match event {
                ReconnectEvent::Retrying {
                    attempt,
                    backoff,
                    error,
                } => tracing::warn!(
                    attempt,
                    backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX),
                    error,
                    "change stream lost, retrying"
                ),
                ReconnectEvent::GaveUp { attempts, error } => tracing::error!(
                    attempts,
                    error,
                    "change stream gave up reconnecting, live delivery has stopped"
                ),
            })
            .await
        {
            tracing::error!(error = %err, "change stream ingest stopped");
        }
    });

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(bind = %bind, "sync listener started");
    let mut sessions = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = shutdown_signal() => break,
        };
        let (tcp, _peer) = accepted.context("accepting a connection")?;
        // Reap the finished ones here, so the set holds only live sessions.
        while sessions.try_join_next().is_some() {}
        let session = manager.clone();
        sessions.spawn(async move {
            let transport = match WebSocketTransport::accept(tcp).await {
                Ok(transport) => transport,
                Err(err) => {
                    tracing::warn!(error = %err, "websocket handshake failed");
                    return;
                }
            };
            if let Err(err) = session.serve(transport).await {
                tracing::warn!(error = %err, "session ended with an error");
            }
        });
    }

    let told = manager.shutdown().await;
    tracing::info!(closed = told, "shutting down");
    // The close frame is queued, not sent: each session's own loop delivers it
    // and then tears down, so the exit waits on those rather than racing them.
    if tokio::time::timeout(SHUTDOWN_GRACE, async {
        while sessions.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tracing::warn!("shutdown grace elapsed with sessions still open");
    }
    Ok(())
}
