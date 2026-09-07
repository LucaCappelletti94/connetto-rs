//! Axum router, application state, and configuration.
//!
//! The public entry point is [`serve`], which runs preflight and then builds
//! the router.  [`router`] is intentionally private: callers must go through
//! [`serve`] so the server never accepts requests before its deployment
//! artifacts are verified.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use axum::{Router, extract::DefaultBodyLimit, routing};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::bb8::Pool;

use crate::preflight::PreflightError;
use crate::schema::ConnettoFileSchema;
use crate::store::AnyStore;
use crate::ticket::TicketVerifier;
use crate::{preflight, serve as file_serve, upload};

/// Diesel-async bb8 connection pool over Postgres.
pub type DbPool = Pool<AsyncPgConnection>;

/// Two connection pools with different privilege levels.
///
/// `admin` connects as a role that owns the file-server tables (and bypasses
/// their RLS).  `reader` connects as the least-privilege file-server reader
/// role subject to RLS, used only for the needed-hashes query after
/// `set_config` threads the caller identity in.
pub struct AppPools {
    /// Owner/superuser pool for writes, refcount updates, and sweep.
    pub admin: DbPool,
    /// Reader-role pool for RLS-gated needed-hashes queries.
    pub reader: DbPool,
}

/// Application configuration shared across all request handlers.
///
/// Generic over `S: ConnettoFileSchema` so the table names chosen by the
/// deployment flow through every database operation without storing them at
/// runtime.
pub struct Config<S: ConnettoFileSchema> {
    /// Two-pool pair: admin for writes, reader for RLS-gated queries.
    pub pools: AppPools,
    /// Chunk storage backend.
    pub store: AnyStore,
    /// Verifies upload and download tickets.
    pub verifier: TicketVerifier,
    /// SQL function name the server calls after a successful commit.
    pub content_state_fn: String,
    /// Grace window for the GC sweep.
    pub grace: Duration,
    /// Carries the schema type without a runtime value.
    pub _schema: PhantomData<fn() -> S>,
}

/// Shared state pointer passed to every axum handler.
pub type AppState<S> = Arc<Config<S>>;

/// Runs preflight, then builds and returns an axum [`Router`].
///
/// Preflight verifies every required deployment artifact (own tables, column
/// types, and the two deployment SQL functions) before the router is
/// constructed.  If any artifact is missing or misconfigured, this function
/// returns an error and no router is built.
///
/// Routes:
/// - `POST /files/{id}/intent` — declare a manifest and receive needed hashes
/// - `PUT /chunks/{hash}` — upload one chunk
/// - `POST /files/{id}/commit` — finalize the upload
/// - `GET /files/{id}` — range-aware download under a read ticket
pub async fn serve<S: ConnettoFileSchema>(config: Config<S>) -> Result<Router, PreflightError> {
    let mut conn = config
        .pools
        .admin
        .get()
        .await
        .map_err(|e| PreflightError::Pool(e.to_string()))?;
    preflight::preflight::<S>(&mut conn).await?;
    drop(conn);
    let mut reader_conn = config
        .pools
        .reader
        .get()
        .await
        .map_err(|e| PreflightError::Pool(e.to_string()))?;
    preflight::preflight_reader::<S>(&mut reader_conn).await?;
    drop(reader_conn);
    Ok(router(config))
}

/// Builds the axum router without running preflight.
///
/// Private: all external callers must go through [`serve`] to ensure the
/// deployment artifacts are verified before the server accepts requests.
pub(crate) fn router<S: ConnettoFileSchema>(config: Config<S>) -> Router {
    // Largest chunk file-core can emit is MEDIA_PARAMS.max (16 MiB fixed
    // slab).  A 1 KiB margin covers HTTP framing.  Only the PUT route needs a
    // higher limit; all other routes keep axum's 2 MiB default.
    const PUT_CHUNK_LIMIT: usize = connetto_file_core::MEDIA_PARAMS.max as usize + 1024;
    let state: AppState<S> = Arc::new(config);
    Router::new()
        .route(
            "/files/{id}/intent",
            routing::post(upload::post_intent::<S>),
        )
        .route(
            "/chunks/{hash}",
            routing::put(upload::put_chunk::<S>).layer(DefaultBodyLimit::max(PUT_CHUNK_LIMIT)),
        )
        .route(
            "/files/{id}/commit",
            routing::post(upload::post_commit::<S>),
        )
        .route("/files/{id}", routing::get(file_serve::get_file::<S>))
        .with_state(state)
}
