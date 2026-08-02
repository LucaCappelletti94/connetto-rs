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

use core::marker::PhantomData;

use connetto_core::SessionId;
use connetto_core::auth::AuthContext;
use diesel::OptionalExtension;
use diesel::query_dsl::methods::{FilterDsl, SelectDsl};
use diesel::sql_query;
use diesel::sql_types::Text;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use sqlparser::dialect::PostgreSqlDialect;
use subql::ParserDB;
use subql::patchset::{PgAdapter, apply_diffset_bytes_async_with_catalog};

use crate::watermark_schema::ConnettoWatermarkSchema;

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
pub struct PgWriteTarget<W> {
    pool: Pool<AsyncPgConnection>,
    catalog: ParserDB,
    /// The deployment's watermark schema, carried only in the type system so
    /// `commit`/`last_applied` name its table. `fn() -> W` keeps the target
    /// `Send`/`Sync` regardless of `W`.
    _watermark: PhantomData<fn() -> W>,
}

/// Build a Postgres write target over a pool and the catalog DDL.
///
/// # Errors
///
/// [`MaterializerError::Catalog`] when the DDL does not parse.
pub fn pg_write_target<W: ConnettoWatermarkSchema>(
    pool: Pool<AsyncPgConnection>,
    pg_ddl: &str,
) -> Result<PgWriteTarget<W>, MaterializerError> {
    let catalog = ParserDB::parse::<PostgreSqlDialect>(pg_ddl)
        .map_err(|err| MaterializerError::Catalog(format!("{err:?}")))?;
    Ok(PgWriteTarget {
        pool,
        catalog,
        _watermark: PhantomData,
    })
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

impl<W: ConnettoWatermarkSchema> PgWriteTarget<W> {
    /// Probe conflicts, apply one upload, and advance the durable watermark in
    /// the same transaction, reporting the outcome. The apply runs under
    /// `ctx.user_id`, so Postgres RLS gates it, and the watermark is keyed by
    /// `session_id` alone, the durable handle from the verified access token,
    /// so a reconnect reusing the same session dedupes replayed uploads.
    pub(crate) async fn commit(
        &self,
        ctx: &AuthContext<W::Id>,
        plan: &WritePlan,
        payload_zstd: &[u8],
        session_id: SessionId,
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
        // The RLS GUC binds `user_id` as text via `Display`; a genuine text
        // boundary. The identity gates the APPLY only: the watermark below
        // keys on the session handle alone.
        let guc_user = ctx.user_id.to_string();
        let watermark_session = session_id;
        let expected = plan.ops.len();
        let catalog = &self.catalog;
        let outcome = conn
            .transaction::<WriteOutcome, CommitError, _>(|c| {
                async move {
                    // set_config is a vendor function the query DSL cannot
                    // express, so this one statement stays raw.
                    sql_query("SELECT set_config('app.user_id', $1, true)")
                        .bind::<Text, _>(guc_user)
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
                    // apply and its dedupe record are one atomic step. The
                    // deployment owns the table; connetto keeps the monotone
                    // GREATEST advance inside `watermark_upsert`.
                    W::watermark_upsert(watermark_session, seq)
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

    /// The highest `client_seq` durably applied for this session handle, read
    /// at handshake so the ack can carry it. The deployment owns the watermark
    /// table; connetto emits no DDL for it.
    pub(crate) async fn last_applied(
        &self,
        session_id: SessionId,
    ) -> Result<Option<u64>, WriteError> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|err| WriteError::Backend(err.to_string()))?;
        let filtered = FilterDsl::filter(W::WatermarkQuery::default(), W::wm_pk(session_id));
        let query = SelectDsl::select(filtered, W::LastSeq::default());
        let last_seq: Option<i64> = query
            .first(&mut conn)
            .await
            .optional()
            .map_err(|err| WriteError::Backend(err.to_string()))?;
        Ok(last_seq.and_then(|seq| u64::try_from(seq).ok()))
    }
}
