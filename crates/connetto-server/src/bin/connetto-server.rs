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
//! - `CONNETTO_READER_URL`: optional non-superuser conninfo. When set, snapshots,
//!   read authorization, and mutation applies run under Postgres Row-Level
//!   Security as that role. Otherwise the server authorizes reads permissively.
//!   The role needs `SELECT, INSERT, UPDATE` on `_connetto_mutations` (the
//!   exactly-once watermark table). connetto emits no DDL, so the deployment
//!   creates that table (see `docs/architecture/11-authentication.md`)
//!   alongside the auth tables; a restricted role cannot `CREATE` in schema
//!   `public` on Postgres 15 and later, so the admin runs the migration.
//!
//! The publication and replication slot (with the `pgoutput` plugin) must
//! already exist. The server does not create them.

use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result, anyhow};
use connetto_core::SchemaVersion;
use connetto_core::auth::AuthContext;
use connetto_core::traits::{AuthPolicy, MutationOp, SessionVerifier};
use connetto_server::{
    AuthConfig, AuthService, AuthStore, AuthStoreError, DbAuthStore, DefaultUuidResolver,
    GenericOidcProvider, InMemoryAuthStore, IssuedSession, Materializer, OidcProviderConfig,
    PermissiveAuth, PermissiveProvider, PgSnapshotSource, ProviderRegistry, ReconnectPolicy,
    RedirectPolicy, RefreshOutcome, ResolvedIdentity, RetainedProviderToken, RlsAuth, RlsAuthError,
    RuntimeWritableCatalog, SessionConfig, SessionManager, TokenAuthority, WebSocketTransport,
    auth_router, connetto_auth_tables, connetto_watermark_table, pg_write_target,
};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use sqlparser::dialect::PostgreSqlDialect;
use subql::reexec::PgAsyncDieselConnector;
use subql::{ParserDB, PgStreamingCdcSource, PgStreamingConfig};
use tokio::net::TcpListener;

// The reference binary uses the default connetto auth and watermark tables over
// `Id = String` (Text `user_id`), matching the `DefaultUuidResolver`. These
// generate the `connetto_sessions`/`connetto_provider_tokens` tables plus
// `ConnettoAuthSchema`, and the `_connetto_mutations` table plus
// `ConnettoWatermark`. connetto emits no DDL; the deployment runs the migration.
connetto_auth_tables!(String, diesel::sql_types::Text);
connetto_watermark_table!(String, diesel::sql_types::Text);

/// The read-authorization policy chosen at startup.
///
/// A single concrete type so the served session future stays `Send` (an
/// `AuthPolicy`'s async-trait methods do not otherwise guarantee it for a
/// generic parameter).
enum ServerAuth {
    /// Authorize every read (no `CONNETTO_READER_URL`).
    Permissive(PermissiveAuth),
    /// Authorize reads through Postgres Row-Level Security.
    Rls(Box<RlsAuth>),
}

impl AuthPolicy for ServerAuth {
    type Error = RlsAuthError;

    async fn can_read(
        &self,
        ctx: &AuthContext,
        table: &str,
        pk: &[u8],
    ) -> Result<bool, RlsAuthError> {
        match self {
            Self::Permissive(auth) => auth.can_read(ctx, table, pk).await.map_err(|e| match e {}),
            Self::Rls(auth) => auth.can_read(ctx, table, pk).await,
        }
    }

    async fn can_write(
        &self,
        ctx: &AuthContext,
        table: &str,
        pk: &[u8],
        op: MutationOp,
    ) -> Result<bool, RlsAuthError> {
        match self {
            Self::Permissive(auth) => auth
                .can_write(ctx, table, pk, op)
                .await
                .map_err(|e| match e {}),
            Self::Rls(auth) => auth.can_write(ctx, table, pk, op).await,
        }
    }
}

/// The auth store chosen at startup. A single concrete type so the auth
/// service and session-verifier futures stay `Send`, mirroring [`ServerAuth`].
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
        session_id: &str,
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

    async fn revoke_session(&self, session_id: &str) -> Result<(), AuthStoreError> {
        match self {
            Self::InMemory(store) => store.revoke_session(session_id).await,
            Self::Db(store) => store.revoke_session(session_id).await,
        }
    }

    async fn set_retained_provider_token(
        &self,
        session_id: &str,
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
        session_id: &str,
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
/// `google` and `microsoft` discover the respective provider, `generic`
/// discovers `CONNETTO_OIDC_ISSUER`, and anything else (or unset) registers a
/// [`PermissiveProvider`] dev stand-in that verifies nothing. A real provider
/// reads `CONNETTO_OIDC_CLIENT_ID`, `CONNETTO_OIDC_CLIENT_SECRET` (optional),
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
        _ => {
            eprintln!(
                "connetto-server: no CONNETTO_OIDC_PROVIDER set, registering a permissive dev \
                 provider that verifies nothing (do not use in production)"
            );
            let identity = ResolvedIdentity {
                issuer: "connetto-dev".to_owned(),
                subject: env_or("CONNETTO_DEV_SUBJECT", "dev-user"),
                email: None,
                name: None,
                amr: Vec::new(),
                acr: None,
                tenant_id: None,
                roles: Vec::new(),
                claims: std::collections::BTreeMap::new(),
            };
            registry.register(Arc::new(PermissiveProvider::new("permissive", identity)));
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
        tenant_id: std::env::var("CONNETTO_OIDC_TENANT").ok(),
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
        eprintln!(
            "connetto-server: no CONNETTO_JWT_*_KEY_FILE set, generating an ephemeral \
             Ed25519 keypair (tokens do not survive a restart)"
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
    let bind = env_or("CONNETTO_BIND", "127.0.0.1:8080");
    let database_url = std::env::var("DATABASE_URL").context("set DATABASE_URL")?;
    let pg_ddl = read_ddl("CONNETTO_PG_DDL")?;
    let slot = env_or("CONNETTO_SLOT", "connetto_slot");
    let publication = env_or("CONNETTO_PUBLICATION", "connetto_pub");
    let pool = build_pool(&database_url).await?;
    // connetto emits no DDL. The deployment owns the `_connetto_mutations`
    // watermark table (see `docs/architecture/11-authentication.md`) and the
    // `ConnettoWatermark` reference schema keys on it; the operator runs the
    // migration alongside the auth tables.
    let connector = PgAsyncDieselConnector::new(pool.clone());
    let materializer = Materializer::with_write_catalog(&pg_ddl, writable_catalog())
        .map_err(|err| anyhow!("building materializer: {err}"))?;

    // Snapshots, read authorization, and the write apply all run under RLS when
    // a reader role is configured. That role must be subject to RLS
    // (non-superuser, not the table owner). Otherwise reads are permissive and
    // writes apply under the primary role.
    let (snapshot, auth, write) = if let Ok(reader_url) = std::env::var("CONNETTO_READER_URL") {
        let reader_pool = build_pool(&reader_url).await?;
        let snapshot = PgSnapshotSource::from_ddl(reader_pool.clone(), &pg_ddl)
            .map_err(|err| anyhow!("building snapshot source: {err}"))?;
        let auth = RlsAuth::from_ddl(reader_pool.clone(), &pg_ddl)
            .map_err(|err| anyhow!("building RLS auth: {err}"))?;
        let write = pg_write_target::<ConnettoWatermark>(reader_pool, &pg_ddl)
            .map_err(|err| anyhow!("building write target: {err}"))?;
        (snapshot, ServerAuth::Rls(Box::new(auth)), write)
    } else {
        let snapshot = PgSnapshotSource::from_ddl(pool.clone(), &pg_ddl)
            .map_err(|err| anyhow!("building snapshot source: {err}"))?;
        let write = pg_write_target::<ConnettoWatermark>(pool.clone(), &pg_ddl)
            .map_err(|err| anyhow!("building write target: {err}"))?;
        (snapshot, ServerAuth::Permissive(PermissiveAuth), write)
    };

    let manager = SessionManager::with_connector(
        materializer,
        snapshot,
        auth,
        connector,
        write,
        SessionConfig {
            schema_version: Some(SchemaVersion::from_source(&pg_ddl)),
            ..SessionConfig::default()
        },
    );
    // When CONNETTO_AUTH is set, mint and verify connetto's own tokens: serve
    // the login and refresh endpoints and inject the real session verifier so
    // the handshake trusts only a token connetto signed. Injection happens here
    // while the manager is still solely owned, before run clones it.
    let manager = match build_auth(&pool).await? {
        Some((service, registry)) => {
            let auth_bind = env_or("CONNETTO_AUTH_BIND", "127.0.0.1:8081");
            let verifier: Arc<dyn SessionVerifier> = Arc::new(service.verifier());
            // CONNETTO_AUTH_REDIRECT_ALLOWLIST is a comma-separated list of exact
            // non-loopback client redirect URIs the deployment permits (a browser
            // deployment lists its own callback). Loopback redirects are always
            // allowed, so a native client needs no entry.
            let allowlist = env_or("CONNETTO_AUTH_REDIRECT_ALLOWLIST", "")
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_owned)
                .collect();
            let router = auth_router(
                Arc::clone(&service),
                registry,
                RedirectPolicy::new(allowlist),
            );
            tokio::spawn(async move {
                match TcpListener::bind(&auth_bind).await {
                    Ok(listener) => {
                        eprintln!("connetto-server auth endpoints on {auth_bind}");
                        if let Err(err) = axum::serve(listener, router).await {
                            eprintln!("auth server stopped: {err}");
                        }
                    }
                    Err(err) => eprintln!("binding auth endpoints {auth_bind}: {err}"),
                }
            });
            manager.with_session_verifier(verifier)
        }
        None => manager,
    };
    run(&manager, &database_url, &slot, &publication, &pg_ddl, &bind).await
}

/// Start CDC ingestion and serve connections until the listener fails.
async fn run(
    manager: &Arc<
        SessionManager<PgSnapshotSource, ServerAuth, ConnettoWatermark, PgAsyncDieselConnector>,
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
            .ingest_with_reconnect(connect, &ReconnectPolicy::default(), |event| {
                eprintln!("cdc reconnect: {event:?}");
            })
            .await
        {
            eprintln!("cdc ingest stopped: {err}");
        }
    });

    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    eprintln!("connetto-server listening on {bind}");
    loop {
        let (tcp, _peer) = listener.accept().await.context("accepting a connection")?;
        let session = manager.clone();
        tokio::spawn(async move {
            let transport = match WebSocketTransport::accept(tcp).await {
                Ok(transport) => transport,
                Err(err) => {
                    eprintln!("websocket handshake failed: {err}");
                    return;
                }
            };
            if let Err(err) = session.serve(transport).await {
                eprintln!("session ended: {err}");
            }
        });
    }
}
