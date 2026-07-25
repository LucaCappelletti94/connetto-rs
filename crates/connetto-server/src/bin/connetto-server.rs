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
//!   exactly-once watermark table), provisioned by the admin like any other
//!   DDL, since a restricted role cannot `CREATE` in schema `public` on
//!   Postgres 15 and later.
//!
//! The publication and replication slot (with the `pgoutput` plugin) must
//! already exist. The server does not create them.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use connetto_core::auth::AuthContext;
use connetto_core::traits::{AuthPolicy, MutationOp};
use connetto_server::{
    Materializer, PermissiveAuth, PgSnapshotSource, ReconnectPolicy, RlsAuth, RlsAuthError,
    RuntimeWritableCatalog, SessionConfig, SessionManager, WebSocketTransport, pg_write_target,
};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use sqlparser::dialect::PostgreSqlDialect;
use subql::reexec::PgAsyncDieselConnector;
use subql::{ParserDB, PgStreamingCdcSource, PgStreamingConfig};
use tokio::net::TcpListener;

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
    // The exactly-once watermark table is provisioned here, under the admin
    // role: the write pool may be a restricted RLS role that cannot (and
    // must not need to) CREATE in schema public.
    connetto_server::provision_watermark_table(&pool)
        .await
        .map_err(|err| anyhow!("provisioning the watermark table: {err}"))?;
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
        let write = pg_write_target(reader_pool, &pg_ddl)
            .map_err(|err| anyhow!("building write target: {err}"))?;
        (snapshot, ServerAuth::Rls(Box::new(auth)), write)
    } else {
        let snapshot = PgSnapshotSource::from_ddl(pool.clone(), &pg_ddl)
            .map_err(|err| anyhow!("building snapshot source: {err}"))?;
        let write = pg_write_target(pool.clone(), &pg_ddl)
            .map_err(|err| anyhow!("building write target: {err}"))?;
        (snapshot, ServerAuth::Permissive(PermissiveAuth), write)
    };

    let manager = SessionManager::with_connector(
        materializer,
        snapshot,
        auth,
        connector,
        write,
        SessionConfig::default(),
    );
    run(&manager, &database_url, &slot, &publication, &pg_ddl, &bind).await
}

/// Start CDC ingestion and serve connections until the listener fails.
async fn run(
    manager: &Arc<SessionManager<PgSnapshotSource, ServerAuth, PgAsyncDieselConnector>>,
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
