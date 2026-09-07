//! Shared test fixture.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use bytes::Bytes;
use connetto_file_core::{ChunkHash, ChunkMeta, FileId};
use connetto_file_server::{
    AnyStore, AppPools, Config, CustomStore, DEPLOYMENT_DDL, DefaultFileSchema, FsStore,
    ObjectStoreBackend, StoreError, TicketSigner, TicketVerifier, serve,
};
use diesel_async::{
    AsyncConnection, AsyncPgConnection, RunQueryDsl,
    pooled_connection::{AsyncDieselConnectionManager, bb8::Pool},
};
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

// ---------------------------------------------------------------------------
// Test-only fixture DDL (NOT part of the shipped DDL const)
// ---------------------------------------------------------------------------

/// Individual DDL statements applied by tests (not part of the shipped DDL const).
///
/// Each entry is a complete Postgres statement. Using a slice avoids splitting
/// on `;` inside dollar-quoted function bodies.
pub const FIXTURE_STMTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS test_file_metadata (
         file_id     BYTEA NOT NULL PRIMARY KEY,
         uploaded_by TEXT  NOT NULL
     )",
    "ALTER TABLE test_file_metadata ENABLE ROW LEVEL SECURITY",
    "CREATE POLICY test_metadata_rls ON test_file_metadata FOR SELECT
         USING (uploaded_by = current_setting('app.user_id', TRUE))",
    "DO $$ BEGIN
         CREATE ROLE connetto_file_server LOGIN PASSWORD 'cfs_reader' NOINHERIT;
     EXCEPTION WHEN duplicate_object THEN NULL;
     END $$",
    "GRANT SELECT ON _cfs_manifests        TO connetto_file_server",
    "GRANT SELECT ON _cfs_manifest_chunks  TO connetto_file_server",
    "GRANT SELECT ON test_file_metadata    TO connetto_file_server",
    // Predicate-based variant: connetto_visible_files filters on current_setting directly.
    // Works even when called as a role that bypasses RLS.
    // SET search_path TO '' pins the path to prevent privilege escalation.
    "CREATE OR REPLACE FUNCTION connetto_visible_files(p_file_ids BYTEA[])
     RETURNS BYTEA[] LANGUAGE sql SECURITY INVOKER
         SET search_path TO '' AS $$
         SELECT ARRAY(
             SELECT f FROM UNNEST(p_file_ids) AS f
             WHERE EXISTS (
                 SELECT 1 FROM public.test_file_metadata m
                 WHERE m.file_id = f
                   AND m.uploaded_by = current_setting('app.user_id', TRUE)
             )
         )
     $$",
    "GRANT EXECUTE ON FUNCTION connetto_visible_files TO connetto_file_server",
    // SET search_path TO '' pins the path; p_caller carries the uploader identity.
    "CREATE OR REPLACE FUNCTION connetto_set_content_state(
         p_file_id   BYTEA,
         p_new_state TEXT,
         p_caller    TEXT
     ) RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER
         SET search_path TO '' AS $$
     BEGIN
         UPDATE public.test_file_metadata
         SET    uploaded_by = uploaded_by
         WHERE  file_id = p_file_id;
         RETURN p_file_id;
     END;
     $$",
    "GRANT EXECUTE ON FUNCTION connetto_set_content_state TO connetto_file_server",
];

/// DDL statements for a deployment whose `connetto_visible_files` relies on RLS
/// alone, with no `current_setting` predicate in its body.
///
/// When called as admin (table owner, RLS bypassed) the function returns every
/// file that exists in `test_file_metadata`, regardless of `app.user_id`.  When
/// called as the reader role (non-owner, RLS enforced) it returns only files
/// where the RLS policy allows access.  This shape exposes the defect that the
/// previous admin-pool implementation introduced: `all_chunks_satisfied` running
/// as admin would see every file and accept invisible dedup targets.
pub const FIXTURE_STMTS_RLS_ONLY: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS test_file_metadata (
         file_id     BYTEA NOT NULL PRIMARY KEY,
         uploaded_by TEXT  NOT NULL
     )",
    "ALTER TABLE test_file_metadata ENABLE ROW LEVEL SECURITY",
    "CREATE POLICY test_metadata_rls ON test_file_metadata FOR SELECT
         USING (uploaded_by = current_setting('app.user_id', TRUE))",
    "DO $$ BEGIN
         CREATE ROLE connetto_file_server LOGIN PASSWORD 'cfs_reader' NOINHERIT;
     EXCEPTION WHEN duplicate_object THEN NULL;
     END $$",
    "GRANT SELECT ON _cfs_manifests        TO connetto_file_server",
    "GRANT SELECT ON _cfs_manifest_chunks  TO connetto_file_server",
    "GRANT SELECT ON test_file_metadata    TO connetto_file_server",
    // RLS-only variant: no current_setting predicate in the function body.
    // Visibility is enforced entirely by the RLS policy on test_file_metadata.
    // SET search_path TO '' pins the path to prevent privilege escalation.
    "CREATE OR REPLACE FUNCTION connetto_visible_files(p_file_ids BYTEA[])
     RETURNS BYTEA[] LANGUAGE sql SECURITY INVOKER
         SET search_path TO '' AS $$
         SELECT ARRAY(
             SELECT f FROM UNNEST(p_file_ids) AS f
             WHERE EXISTS (
                 SELECT 1 FROM public.test_file_metadata m
                 WHERE m.file_id = f
             )
         )
     $$",
    "GRANT EXECUTE ON FUNCTION connetto_visible_files TO connetto_file_server",
    "CREATE OR REPLACE FUNCTION connetto_set_content_state(
         p_file_id   BYTEA,
         p_new_state TEXT,
         p_caller    TEXT
     ) RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER
         SET search_path TO '' AS $$
     BEGIN
         UPDATE public.test_file_metadata
         SET    uploaded_by = uploaded_by
         WHERE  file_id = p_file_id;
         RETURN p_file_id;
     END;
     $$",
    "GRANT EXECUTE ON FUNCTION connetto_set_content_state TO connetto_file_server",
];

// ---------------------------------------------------------------------------
// Container
// ---------------------------------------------------------------------------

pub struct Pg {
    pub _container: ContainerAsync<GenericImage>,
    pub url_admin: String,
    pub url_reader: String,
}

impl Pg {
    pub async fn start() -> Self {
        Self::start_with_fixture_stmts(FIXTURE_STMTS).await
    }

    /// Starts a container whose `connetto_visible_files` relies on RLS alone.
    pub async fn start_rls_only() -> Self {
        Self::start_with_fixture_stmts(FIXTURE_STMTS_RLS_ONLY).await
    }

    async fn start_with_fixture_stmts(fixture_stmts: &[&str]) -> Self {
        let container = GenericImage::new("postgres", "16")
            .with_wait_for(WaitFor::message_on_stderr("ready to accept connections"))
            .with_env_var("POSTGRES_PASSWORD", "postgres")
            .with_env_var("POSTGRES_DB", "test")
            .start()
            .await
            .expect("postgres container");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("postgres port");
        let url_admin = format!("postgresql://postgres:postgres@127.0.0.1:{port}/test");
        let url_reader =
            format!("postgresql://connetto_file_server:cfs_reader@127.0.0.1:{port}/test");
        let pg = Pg {
            _container: container,
            url_admin,
            url_reader,
        };
        pg.apply_ddl(fixture_stmts).await;
        pg
    }

    async fn apply_ddl(&self, fixture_stmts: &[&str]) {
        let mut conn = connect_admin(&self.url_admin).await;
        // DEPLOYMENT_DDL and fixture_stmts are DDL: CREATE TABLE, ALTER TABLE,
        // CREATE ROLE, GRANT, CREATE FUNCTION.  The typed DSL cannot express DDL.
        for stmt in split_simple(DEPLOYMENT_DDL) {
            diesel::sql_query(stmt).execute(&mut conn).await.ok();
        }
        for stmt in fixture_stmts {
            diesel::sql_query(*stmt)
                .execute(&mut conn)
                .await
                .expect("fixture DDL");
        }
    }

    pub async fn admin_pool(&self) -> Pool<AsyncPgConnection> {
        make_pool(&self.url_admin).await
    }

    pub async fn reader_pool(&self) -> Pool<AsyncPgConnection> {
        make_pool(&self.url_reader).await
    }
}

pub async fn connect_admin(url: &str) -> AsyncPgConnection {
    AsyncPgConnection::establish(url)
        .await
        .expect("admin connection")
}

async fn make_pool(url: &str) -> Pool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    Pool::builder()
        .max_size(4)
        .build(manager)
        .await
        .expect("pool")
}

// ---------------------------------------------------------------------------
// Store construction
// ---------------------------------------------------------------------------

pub fn fs_store(dir: &tempfile::TempDir) -> AnyStore {
    AnyStore::Fs(FsStore::new(dir.path()).expect("fs store"))
}

pub fn object_store_local(dir: &tempfile::TempDir) -> AnyStore {
    let s = object_store::local::LocalFileSystem::new_with_prefix(dir.path())
        .expect("local object store");
    AnyStore::Object(ObjectStoreBackend::new(Arc::new(s)))
}

/// Returns an `AnyStore` that injects exactly one write failure then delegates
/// all subsequent writes to the backing `FsStore`.
pub fn fail_once_write_store(inner: FsStore) -> AnyStore {
    AnyStore::Custom(Box::new(FaultStore {
        inner: AnyStore::Fs(inner),
        has_failed: Arc::new(AtomicBool::new(false)),
        fault: Fault::Write,
    }))
}

/// Returns an `AnyStore` that injects exactly one delete failure then delegates
/// all subsequent deletes to the backing `FsStore`.
pub fn fail_once_delete_store(inner: FsStore) -> AnyStore {
    AnyStore::Custom(Box::new(FaultStore {
        inner: AnyStore::Fs(inner),
        has_failed: Arc::new(AtomicBool::new(false)),
        fault: Fault::Delete,
    }))
}

pub fn gated_read_store(
    inner: FsStore,
    gate_at_read: usize,
) -> (AnyStore, Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let store = AnyStore::Custom(Box::new(GatedReadStore {
        inner: AnyStore::Fs(inner),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
        count: Arc::new(AtomicUsize::new(0)),
        gate_at: gate_at_read,
    }));
    (store, entered, release)
}

pub fn gated_write_store(
    inner: FsStore,
) -> (AnyStore, Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let store = AnyStore::Custom(Box::new(GatedWriteStore {
        inner: AnyStore::Fs(inner),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    }));
    (store, entered, release)
}

// ---------------------------------------------------------------------------
// CustomStore implementations (test-only; not shipped in the library)
//
// Each implementation wraps an `AnyStore` internally so it can delegate
// non-faulting operations through the same dispatch path as production code,
// without needing access to any private function in the library crate.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Fault {
    Write,
    Delete,
}

/// Single-fault-injection store: fails the first call of the selected
/// operation, then delegates all subsequent calls to the inner `AnyStore`.
struct FaultStore {
    inner: AnyStore,
    has_failed: Arc<AtomicBool>,
    fault: Fault,
}

impl CustomStore for FaultStore {
    fn write<'a>(
        &'a self,
        hash: &'a ChunkHash,
        data: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + 'a>> {
        Box::pin(async move {
            if matches!(self.fault, Fault::Write) && !self.has_failed.swap(true, Ordering::Relaxed)
            {
                return Err(StoreError::Io(std::io::Error::other(
                    "injected one-time store write failure",
                )));
            }
            self.inner.write(hash, data).await
        })
    }

    fn read<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn Future<Output = Result<Bytes, StoreError>> + Send + 'a>> {
        Box::pin(async move { self.inner.read(hash).await })
    }

    fn exists<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + 'a>> {
        Box::pin(async move { self.inner.exists(hash).await })
    }

    fn delete<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + 'a>> {
        Box::pin(async move {
            if matches!(self.fault, Fault::Delete) && !self.has_failed.swap(true, Ordering::Relaxed)
            {
                return Err(StoreError::Io(std::io::Error::other(
                    "injected one-time store delete failure",
                )));
            }
            self.inner.delete(hash).await
        })
    }
}

struct GatedWriteStore {
    inner: AnyStore,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl CustomStore for GatedWriteStore {
    fn write<'a>(
        &'a self,
        hash: &'a ChunkHash,
        data: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + 'a>> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            self.inner.write(hash, data).await
        })
    }

    fn read<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn Future<Output = Result<Bytes, StoreError>> + Send + 'a>> {
        Box::pin(async move { self.inner.read(hash).await })
    }

    fn exists<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + 'a>> {
        Box::pin(async move { self.inner.exists(hash).await })
    }

    fn delete<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + 'a>> {
        Box::pin(async move { self.inner.delete(hash).await })
    }
}

struct GatedReadStore {
    inner: AnyStore,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    count: Arc<AtomicUsize>,
    gate_at: usize,
}

impl CustomStore for GatedReadStore {
    fn write<'a>(
        &'a self,
        hash: &'a ChunkHash,
        data: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + 'a>> {
        Box::pin(async move { self.inner.write(hash, data).await })
    }

    fn read<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn Future<Output = Result<Bytes, StoreError>> + Send + 'a>> {
        Box::pin(async move {
            let n = self.count.fetch_add(1, Ordering::Relaxed) + 1;
            if n == self.gate_at {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.inner.read(hash).await
        })
    }

    fn exists<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + 'a>> {
        Box::pin(async move { self.inner.exists(hash).await })
    }

    fn delete<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + 'a>> {
        Box::pin(async move { self.inner.delete(hash).await })
    }
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

pub async fn build_router(pg: &Pg, store: AnyStore) -> (Router, TicketSigner) {
    let (signer, verifier) = make_signer();
    let cfg: Config<DefaultFileSchema> = Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: pg.reader_pool().await,
        },
        store,
        verifier,
        content_state_fn: "connetto_set_content_state".into(),
        grace: Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    };
    (
        serve(cfg).await.expect("preflight passed in build_router"),
        signer,
    )
}

pub fn make_signer() -> (TicketSigner, TicketVerifier) {
    let (signer, pub_key) = TicketSigner::generate().expect("signer");
    let verifier = TicketVerifier::new(pub_key);
    (signer, verifier)
}

// ---------------------------------------------------------------------------
// DB helpers
//
// These insert directly via sql_query because the library's schema module is
// private (not re-exported) and integration tests therefore cannot use the
// typed DSL against those tables.  The raw SQL mirrors the schema.sql DDL
// exactly; any drift will surface as a test failure.
// ---------------------------------------------------------------------------

/// Inserts an uncommitted manifest and chunk rows, bypassing intent validation.
///
/// Use in adversarial tests that need manifests whose chunk sums exceed the
/// ticket ceiling, isolating the PUT-time tally guard.
pub async fn insert_manifest_bypassing_intent(
    conn: &mut AsyncPgConnection,
    file_id: &FileId,
    caller: &str,
    chunks: &[ChunkMeta],
) {
    let total_len: i64 = chunks
        .iter()
        .map(|c| i64::try_from(c.len).expect("chunk len fits i64"))
        .sum();
    // The library schema is private; sql_query is the only path available
    // from integration-test code.
    diesel::sql_query(
        "INSERT INTO _cfs_manifests
             (file_id, total_len, accepted_bytes, committed, uploaded_by, created_at)
         VALUES ($1, $2, 0, FALSE, $3, NOW())
         ON CONFLICT DO NOTHING",
    )
    .bind::<diesel::sql_types::Bytea, _>(file_id.as_bytes().as_ref())
    .bind::<diesel::sql_types::BigInt, _>(total_len)
    .bind::<diesel::sql_types::Text, _>(caller)
    .execute(conn)
    .await
    .expect("insert manifest header");

    for (i, chunk) in chunks.iter().enumerate() {
        let position = i32::try_from(i).expect("chunk count fits i32");
        let chunk_len = i64::try_from(chunk.len).expect("chunk len fits i64");
        diesel::sql_query(
            "INSERT INTO _cfs_manifest_chunks
                 (file_id, uploaded_by, position, chunk_hash, chunk_len, stored)
             VALUES ($1, $2, $3, $4, $5, FALSE)
             ON CONFLICT DO NOTHING",
        )
        .bind::<diesel::sql_types::Bytea, _>(file_id.as_bytes().as_ref())
        .bind::<diesel::sql_types::Text, _>(caller)
        .bind::<diesel::sql_types::Integer, _>(position)
        .bind::<diesel::sql_types::Bytea, _>(chunk.hash.as_bytes().as_ref())
        .bind::<diesel::sql_types::BigInt, _>(chunk_len)
        .execute(conn)
        .await
        .expect("insert chunk row");
        diesel::sql_query(
            "INSERT INTO _cfs_chunk_registry (chunk_hash, state)
             VALUES ($1, 'pending')
             ON CONFLICT (chunk_hash) DO NOTHING",
        )
        .bind::<diesel::sql_types::Bytea, _>(chunk.hash.as_bytes().as_ref())
        .execute(conn)
        .await
        .expect("insert pending registry row");
    }
}

/// Inserts a committed manifest keyed to `caller`.
///
/// Use when a test needs a file that can be served without going through the
/// full upload flow (e.g. streaming behaviour tests).  The caller is
/// responsible for writing the chunk bytes to the store first.
pub async fn insert_committed_manifest(
    conn: &mut AsyncPgConnection,
    file_id: &FileId,
    caller: &str,
    chunks: &[ChunkMeta],
) {
    insert_manifest_bypassing_intent(conn, file_id, caller, chunks).await;

    // Mark all chunk rows stored for this (file_id, caller) pair.
    diesel::sql_query(
        "UPDATE _cfs_manifest_chunks SET stored = TRUE \
         WHERE file_id = $1 AND uploaded_by = $2",
    )
    .bind::<diesel::sql_types::Bytea, _>(file_id.as_bytes().as_ref())
    .bind::<diesel::sql_types::Text, _>(caller)
    .execute(conn)
    .await
    .expect("mark chunks stored");

    // Mark manifest committed for this (file_id, caller) pair.
    diesel::sql_query(
        "UPDATE _cfs_manifests SET committed = TRUE \
         WHERE file_id = $1 AND uploaded_by = $2",
    )
    .bind::<diesel::sql_types::Bytea, _>(file_id.as_bytes().as_ref())
    .bind::<diesel::sql_types::Text, _>(caller)
    .execute(conn)
    .await
    .expect("mark manifest committed");

    // Upsert registry rows in `stored` state.
    // The library schema is private; sql_query is the only path from integration-test code.
    for chunk in chunks {
        diesel::sql_query(
            "INSERT INTO _cfs_chunk_registry (chunk_hash, state)
             VALUES ($1, 'stored')
             ON CONFLICT (chunk_hash) DO UPDATE SET state = 'stored'",
        )
        .bind::<diesel::sql_types::Bytea, _>(chunk.hash.as_bytes().as_ref())
        .execute(conn)
        .await
        .expect("upsert registry row");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Splits simple DDL (no dollar-quoted strings) on semicolons.
/// Used only for the shipped `DEPLOYMENT_DDL` which contains only table DDL.
pub fn split_simple(ddl: &str) -> Vec<&str> {
    ddl.split(';')
        .map(str::trim)
        .filter(|s| {
            !s.is_empty()
                && s.lines()
                    .any(|l| !l.trim().is_empty() && !l.trim().starts_with("--"))
        })
        .collect()
}

/// Registers `file_id` as owned by `caller` in the test fixture metadata table,
/// making it visible to that caller through the RLS-gated function.
pub async fn register_file_ownership(conn: &mut AsyncPgConnection, file_id: &FileId, caller: &str) {
    diesel::sql_query(
        "INSERT INTO test_file_metadata (file_id, uploaded_by)
         VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
    )
    .bind::<diesel::sql_types::Bytea, _>(file_id.as_bytes().as_ref())
    .bind::<diesel::sql_types::Text, _>(caller)
    .execute(conn)
    .await
    .expect("register file ownership");
}

/// Returns the number of rows in `_cfs_chunk_registry` for `hash`.
///
/// The library schema is private; `sql_query` is the only path from integration-test code.
pub async fn registry_row_count(
    conn: &mut AsyncPgConnection,
    hash: &connetto_file_core::ChunkHash,
) -> i64 {
    #[derive(diesel::QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        n: i64,
    }
    let rows: Vec<CountRow> = diesel::sql_query(
        "SELECT COUNT(*)::bigint AS n FROM _cfs_chunk_registry WHERE chunk_hash = $1",
    )
    .bind::<diesel::sql_types::Bytea, _>(hash.as_bytes().as_ref())
    .load(conn)
    .await
    .expect("count registry rows");
    rows.into_iter().next().map_or(0, |r| r.n)
}
