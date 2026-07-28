//! The server's write target: where an authorized client mutation lands.
//!
//! A mutation applies to the source Postgres inside a transaction that first
//! sets `app.user_id`, so the database's Row-Level Security policies gate the
//! write: `USING` blocks touching invisible rows and `WITH CHECK` blocks
//! inserting or updating rows the user could not own. This is the enforced
//! production path, and writes flow back as CDC to every subscriber.
//!
//! [`PgWriteTarget`]'s commit path runs the conflict probe and the apply for one
//! upload and reports the outcome, leaving the wire reply to the session layer.

use connetto_core::auth::AuthContext;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Text};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use sqlparser::dialect::PostgreSqlDialect;
use subql::ParserDB;
use subql::patchset::{PgAdapter, apply_diffset_bytes_async_with_catalog};

use crate::materializer::{
    ConflictProbe, MaterializerError, PlannedConflict, ServerRow, WritePlan, probe_conflict_pg,
};

/// The outcome of committing one mutation upload.
pub(crate) enum WriteOutcome {
    /// The whole changeset applied.
    Applied,
    /// A version-bearing op found a stale or missing row. Carries the current
    /// server row for the conflict reply.
    Conflict {
        /// Table carrying the conflicting row.
        table: String,
        /// Current server version, rendered as text.
        server_updated_at: String,
        /// Current server row as JSON, or `null` when the row is gone.
        server_row_json: String,
    },
}

/// A failure while committing a mutation.
pub(crate) enum WriteError {
    /// Row-Level Security refused the write, or fewer rows changed than the
    /// upload carried (rows the user cannot see).
    Unauthorized,
    /// The changeset failed to parse or apply.
    Materializer(MaterializerError),
    /// A pool, transaction, or watermark storage failure.
    Backend(String),
}

impl WriteError {
    /// Human-readable detail for logging and error mapping.
    pub(crate) fn detail(&self) -> String {
        match self {
            Self::Unauthorized => "unauthorized".to_owned(),
            Self::Materializer(err) => err.to_string(),
            Self::Backend(detail) => detail.clone(),
        }
    }
}

impl From<diesel::result::Error> for WriteError {
    fn from(err: diesel::result::Error) -> Self {
        Self::Backend(err.to_string())
    }
}

/// DDL for the durable per-client mutation watermark. It lives in the write
/// target's own database, so advancing it commits atomically with the apply it
/// belongs to.
const WATERMARK_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_mutations \
    (user_id TEXT NOT NULL, client_id TEXT NOT NULL, last_seq BIGINT NOT NULL, \
    PRIMARY KEY (user_id, client_id))";

/// Watermark row shape.
#[derive(diesel::QueryableByName)]
struct WatermarkRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    last_seq: i64,
}

/// Decode a loaded watermark row set into the watermark value.
fn watermark_value(rows: Vec<WatermarkRow>) -> Option<u64> {
    rows.into_iter()
        .next()
        .and_then(|row| u64::try_from(row.last_seq).ok())
}

/// The client sequence as the storage integer.
fn seq_storage(client_seq: u64) -> Result<i64, WriteError> {
    i64::try_from(client_seq)
        .map_err(|_| WriteError::Backend("client sequence overflows storage".to_owned()))
}

/// Build the conflict outcome for a stale op.
fn conflict_outcome(conflict: &PlannedConflict, row: Option<ServerRow>) -> WriteOutcome {
    let (server_updated_at, server_row_json) = row.map_or_else(
        || (String::new(), "null".to_owned()),
        |row| (row.version, row.row_json),
    );
    WriteOutcome::Conflict {
        table: conflict.table.clone(),
        server_updated_at,
        server_row_json,
    }
}

/// A Postgres write target that applies under the caller's RLS context.
///
/// Holds the pool and the parsed catalog. `commit` applies the changeset through
/// subql's catalog-only entry point, so the catalog is shared by reference
/// across the apply `await` (`ParserDB` is `Sync`) with no per-write engine to
/// build.
pub struct PgWriteTarget {
    pool: Pool<AsyncPgConnection>,
    catalog: ParserDB,
}

/// Build a Postgres write target over a pool and the catalog DDL.
///
/// # Errors
///
/// [`MaterializerError::Catalog`] when the DDL does not parse.
pub fn pg_write_target(
    pool: Pool<AsyncPgConnection>,
    pg_ddl: &str,
) -> Result<PgWriteTarget, MaterializerError> {
    let catalog = ParserDB::parse::<PostgreSqlDialect>(pg_ddl)
        .map_err(|err| MaterializerError::Catalog(format!("{err:?}")))?;
    Ok(PgWriteTarget { pool, catalog })
}

/// A failure while provisioning the watermark table.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// Checking a connection out of the pool failed.
    #[error("pool checkout: {0}")]
    Pool(#[from] diesel_async::pooled_connection::bb8::RunError),
    /// The DDL failed.
    #[error(transparent)]
    Db(#[from] diesel::result::Error),
}

/// Create the exactly-once watermark table if missing, through a connection with
/// DDL privilege (the admin pool), once at startup.
///
/// Deliberately kept out of the handshake path: a restricted writer role cannot
/// `CREATE` in schema `public` on Postgres 15 and later (the check fires even
/// when the table already exists), and concurrent handshakes racing
/// `CREATE TABLE IF NOT EXISTS` collide on `pg_type_typname_nsp_index`. The
/// writer role itself only needs `SELECT, INSERT, UPDATE` on the table.
///
/// # Errors
///
/// [`ProvisionError`] when the pool checkout or the DDL fails.
pub async fn provision_watermark_table(
    pool: &Pool<AsyncPgConnection>,
) -> Result<(), ProvisionError> {
    let mut conn = pool.get().await?;
    sql_query(WATERMARK_DDL).execute(&mut conn).await?;
    Ok(())
}

/// A failure inside the apply transaction, mapped to a [`WriteError`] after the
/// transaction resolves.
enum CommitError {
    Db(diesel::result::Error),
    Probe(MaterializerError),
    /// Fewer rows changed than the upload carried: RLS hid the rest.
    Denied,
}

impl From<diesel::result::Error> for CommitError {
    fn from(err: diesel::result::Error) -> Self {
        Self::Db(err)
    }
}

/// True when a Postgres error is an RLS policy violation.
fn is_rls_violation(text: &str) -> bool {
    text.to_lowercase().contains("row-level security")
}

impl PgWriteTarget {
    /// Probe conflicts, apply one upload, and advance the client's durable
    /// watermark in the same transaction, reporting the outcome. The apply runs
    /// under `ctx.user_id`, so Postgres RLS gates it, and the watermark is keyed
    /// by `(user id, client id)`.
    pub(crate) async fn commit<Id: core::fmt::Display>(
        &self,
        ctx: &AuthContext<Id>,
        plan: &WritePlan,
        payload_zstd: &[u8],
        client_id: &str,
        client_seq: u64,
    ) -> Result<WriteOutcome, WriteError> {
        let seq = seq_storage(client_seq)?;
        let bytes = zstd::decode_all(payload_zstd)
            .map_err(|err| WriteError::Backend(format!("decompress: {err}")))?;
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|err| WriteError::Backend(err.to_string()))?;
        let user_id = ctx.user_id.to_string();
        let watermark_user = ctx.user_id.to_string();
        let expected = plan.ops.len();
        let catalog = &self.catalog;
        let outcome = conn
            .transaction::<WriteOutcome, CommitError, _>(|c| {
                async move {
                    sql_query("SELECT set_config('app.user_id', $1, true)")
                        .bind::<Text, _>(user_id)
                        .execute(c)
                        .await?;
                    for op in &plan.ops {
                        let Some(conflict) = &op.conflict else {
                            continue;
                        };
                        if let ConflictProbe::Stale(row) = probe_conflict_pg(conflict, c)
                            .await
                            .map_err(CommitError::Probe)?
                        {
                            return Ok(conflict_outcome(conflict, row));
                        }
                    }
                    let adapter = PgAdapter::new(catalog);
                    let affected =
                        apply_diffset_bytes_async_with_catalog(catalog, &bytes, c, &adapter)
                            .await?;
                    if affected < expected {
                        return Err(CommitError::Denied);
                    }
                    // Advance the durable watermark in the SAME transaction: the
                    // apply and its dedupe record are one atomic step.
                    sql_query(
                        "INSERT INTO _connetto_mutations (user_id, client_id, last_seq) \
                         VALUES ($1, $2, $3) \
                         ON CONFLICT (user_id, client_id) DO UPDATE SET last_seq = \
                         GREATEST(_connetto_mutations.last_seq, EXCLUDED.last_seq)",
                    )
                    .bind::<Text, _>(watermark_user)
                    .bind::<Text, _>(client_id)
                    .bind::<BigInt, _>(seq)
                    .execute(c)
                    .await?;
                    Ok(WriteOutcome::Applied)
                }
                .scope_boxed()
            })
            .await;
        match outcome {
            Ok(outcome) => Ok(outcome),
            Err(CommitError::Denied) => Err(WriteError::Unauthorized),
            Err(CommitError::Db(err)) if is_rls_violation(&err.to_string()) => {
                Err(WriteError::Unauthorized)
            }
            Err(CommitError::Db(err)) => Err(WriteError::Backend(err.to_string())),
            Err(CommitError::Probe(err)) => Err(WriteError::Materializer(err)),
        }
    }

    /// The highest `client_seq` durably applied for `(ctx, client_id)`, read at
    /// handshake so the ack can carry it. Requires the watermark table
    /// provisioned up front, see [`provision_watermark_table`].
    pub(crate) async fn last_applied<Id: core::fmt::Display>(
        &self,
        ctx: &AuthContext<Id>,
        client_id: &str,
    ) -> Result<Option<u64>, WriteError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|err| WriteError::Backend(err.to_string()))?;
        let rows: Vec<WatermarkRow> = sql_query(
            "SELECT last_seq FROM _connetto_mutations WHERE user_id = $1 AND client_id = $2",
        )
        .bind::<Text, _>(ctx.user_id.to_string())
        .bind::<Text, _>(client_id)
        .load(&mut conn)
        .await
        .map_err(|err| WriteError::Backend(err.to_string()))?;
        Ok(watermark_value(rows))
    }
}
