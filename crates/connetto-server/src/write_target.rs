//! The server's write target: where an authorized client mutation lands.
//!
//! A mutation is applied to one of two backends behind [`WriteTarget`]:
//!
//! * [`WriteTarget::Sqlite`] applies to a local SQLite connection. It carries no
//!   Row-Level Security, so it is the Docker-free target for tests and the
//!   apply-mechanics path.
//! * [`WriteTarget::Postgres`] applies to the source Postgres inside a
//!   transaction that first sets `app.user_id`, so the database's RLS policies
//!   gate the write: `USING` blocks touching invisible rows and `WITH CHECK`
//!   blocks inserting or updating rows the user could not own. This is the
//!   enforced production path, and writes flow back as CDC to every subscriber.
//!
//! [`WriteTarget`]'s commit path runs the conflict probe and the apply for one
//! upload and reports the outcome, leaving the wire reply to the session layer.

use std::sync::Arc;

use connetto_core::auth::AuthContext;
use diesel::connection::SimpleConnection;
use diesel::sqlite::SqliteConnection;
use diesel::{Connection, RunQueryDsl};
use parking_lot::Mutex as SyncMutex;
use tokio::sync::Mutex;

use crate::materializer::{
    ConflictProbe, Materializer, MaterializerError, PlannedConflict, ServerRow, WritePlan,
    probe_conflict_sqlite,
};

/// A shared, synchronous SQLite write target. The lock is never held across an
/// `.await`.
pub type SqliteWriteTarget = Arc<SyncMutex<SqliteConnection>>;

/// Wrap a SQLite connection as a shared [`SqliteWriteTarget`].
#[must_use]
pub fn sqlite_write_target(conn: SqliteConnection) -> SqliteWriteTarget {
    Arc::new(SyncMutex::new(conn))
}

/// Where the server applies an authorized client mutation.
pub enum WriteTarget {
    /// A local SQLite connection, with no Row-Level Security.
    Sqlite(SqliteWriteTarget),
    /// The source Postgres, applying under the requesting user's RLS context.
    #[cfg(feature = "pg-async")]
    Postgres(Box<PgWriteTarget>),
}

impl From<SqliteWriteTarget> for WriteTarget {
    fn from(target: SqliteWriteTarget) -> Self {
        Self::Sqlite(target)
    }
}

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
    /// upload carried (rows the user cannot see). Only the Postgres path
    /// produces this.
    #[cfg_attr(not(feature = "pg-async"), allow(dead_code))]
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
/// target's own database, so advancing it commits atomically with the apply
/// it belongs to. Valid SQLite and Postgres alike.
const WATERMARK_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_mutations \
    (user_id TEXT NOT NULL, client_id TEXT NOT NULL, last_seq BIGINT NOT NULL, \
    PRIMARY KEY (user_id, client_id))";

/// Watermark row shape shared by both backends.
#[derive(diesel::QueryableByName)]
pub(crate) struct WatermarkRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    pub(crate) last_seq: i64,
}

/// Decode a loaded watermark row set into the watermark value.
pub(crate) fn watermark_value(rows: Vec<WatermarkRow>) -> Option<u64> {
    rows.into_iter()
        .next()
        .and_then(|row| u64::try_from(row.last_seq).ok())
}

/// The client sequence as the storage integer.
pub(crate) fn seq_storage(client_seq: u64) -> Result<i64, WriteError> {
    i64::try_from(client_seq)
        .map_err(|_| WriteError::Backend("client sequence overflows storage".to_owned()))
}

impl WriteTarget {
    /// Probe conflicts, apply one upload, and advance the client's durable
    /// watermark in the same transaction, reporting the outcome.
    ///
    /// The SQLite path ignores `ctx` for authorization (it has no RLS), the
    /// Postgres path applies under `ctx.user_id`. Both key the watermark by
    /// `(user id, client id)`.
    pub(crate) async fn commit(
        &self,
        materializer: &Mutex<Materializer>,
        ctx: &AuthContext,
        plan: &WritePlan,
        payload_zstd: &[u8],
        client_id: &str,
        client_seq: u64,
    ) -> Result<WriteOutcome, WriteError> {
        match self {
            Self::Sqlite(target) => {
                commit_sqlite(
                    target,
                    materializer,
                    plan,
                    payload_zstd,
                    ctx,
                    client_id,
                    client_seq,
                )
                .await
            }
            #[cfg(feature = "pg-async")]
            Self::Postgres(target) => {
                target
                    .commit(ctx, plan, payload_zstd, client_id, client_seq)
                    .await
            }
        }
    }

    /// The highest `client_seq` durably applied for `(ctx, client_id)`, read
    /// at handshake so the ack can carry it. The SQLite path ensures the
    /// watermark table exists inline (one privileged connection, no
    /// concurrency); the Postgres path requires it provisioned up front, see
    /// [`provision_watermark_table`].
    // Without `pg-async` the Postgres arm is compiled out and the remaining
    // SQLite arm never awaits, so clippy sees an async fn with no await. The
    // async is load-bearing under `pg-async`, so only silence it otherwise.
    #[cfg_attr(
        not(feature = "pg-async"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    pub(crate) async fn last_applied(
        &self,
        ctx: &AuthContext,
        client_id: &str,
    ) -> Result<Option<u64>, WriteError> {
        match self {
            Self::Sqlite(target) => {
                let mut conn = target.lock();
                conn.batch_execute(WATERMARK_DDL)?;
                let rows: Vec<WatermarkRow> = diesel::sql_query(
                    "SELECT last_seq FROM _connetto_mutations WHERE user_id = ? AND client_id = ?",
                )
                .bind::<diesel::sql_types::Text, _>(&ctx.user_id)
                .bind::<diesel::sql_types::Text, _>(client_id)
                .load(&mut *conn)?;
                Ok(watermark_value(rows))
            }
            #[cfg(feature = "pg-async")]
            Self::Postgres(target) => target.last_applied(ctx, client_id).await,
        }
    }
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

async fn commit_sqlite(
    target: &SqliteWriteTarget,
    materializer: &Mutex<Materializer>,
    plan: &WritePlan,
    payload_zstd: &[u8],
    ctx: &AuthContext,
    client_id: &str,
    client_seq: u64,
) -> Result<WriteOutcome, WriteError> {
    for op in &plan.ops {
        let Some(conflict) = &op.conflict else {
            continue;
        };
        let probe = {
            let mut conn = target.lock();
            probe_conflict_sqlite(conflict, &mut conn).map_err(WriteError::Materializer)?
        };
        if let ConflictProbe::Stale(row) = probe {
            return Ok(conflict_outcome(conflict, row));
        }
    }
    let seq = seq_storage(client_seq)?;
    let materializer = materializer.lock().await;
    let mut conn = target.lock();
    conn.transaction::<_, WriteError, _>(|conn| {
        materializer
            .apply_diffset(payload_zstd, conn)
            .map_err(WriteError::Materializer)?;
        diesel::sql_query(
            "INSERT INTO _connetto_mutations (user_id, client_id, last_seq) VALUES (?, ?, ?) \
             ON CONFLICT (user_id, client_id) DO UPDATE SET \
             last_seq = MAX(last_seq, excluded.last_seq)",
        )
        .bind::<diesel::sql_types::Text, _>(&ctx.user_id)
        .bind::<diesel::sql_types::Text, _>(client_id)
        .bind::<diesel::sql_types::BigInt, _>(seq)
        .execute(conn)?;
        Ok(())
    })?;
    Ok(WriteOutcome::Applied)
}

#[cfg(feature = "pg-async")]
pub use pg::{PgWriteTarget, ProvisionError, pg_write_target, provision_watermark_table};

#[cfg(feature = "pg-async")]
mod pg {
    use diesel::sql_query;
    use diesel::sql_types::{BigInt, Text};
    use diesel_async::pooled_connection::bb8::Pool;
    use diesel_async::scoped_futures::ScopedFutureExt;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
    use sqlparser::dialect::PostgreSqlDialect;
    use subql::ParserDB;
    use subql::patchset::{PgAdapter, apply_diffset_bytes_async_with_catalog};

    use super::{
        WATERMARK_DDL, WatermarkRow, WriteError, WriteOutcome, conflict_outcome, seq_storage,
        watermark_value,
    };
    use crate::materializer::{ConflictProbe, MaterializerError, WritePlan, probe_conflict_pg};
    use connetto_core::auth::AuthContext;

    /// A Postgres write target that applies under the caller's RLS context.
    ///
    /// Holds the pool and the parsed catalog. `commit` applies the changeset
    /// through subql's catalog-only entry point, so the catalog is shared by
    /// reference across the apply `await` (`ParserDB` is `Sync`) with no
    /// per-write engine to build.
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

    impl From<PgWriteTarget> for super::WriteTarget {
        fn from(target: PgWriteTarget) -> Self {
            Self::Postgres(Box::new(target))
        }
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

    /// Create the exactly-once watermark table if missing, through a
    /// connection with DDL privilege (the admin pool), once at startup.
    ///
    /// Deliberately kept out of the handshake path: a restricted writer role
    /// cannot `CREATE` in schema `public` on Postgres 15 and later (the
    /// check fires even when the table already exists), and concurrent
    /// handshakes racing `CREATE TABLE IF NOT EXISTS` collide on
    /// `pg_type_typname_nsp_index`. The writer role itself only needs
    /// `SELECT, INSERT, UPDATE` on the table.
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

    /// A failure inside the apply transaction, mapped to a [`WriteError`] after
    /// the transaction resolves.
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
        pub(crate) async fn commit(
            &self,
            ctx: &AuthContext,
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
            let user_id = ctx.user_id.clone();
            let watermark_user = ctx.user_id.clone();
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
                        // Advance the durable watermark in the SAME
                        // transaction: the apply and its dedupe record are
                        // one atomic step.
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

        pub(crate) async fn last_applied(
            &self,
            ctx: &AuthContext,
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
            .bind::<Text, _>(&ctx.user_id)
            .bind::<Text, _>(client_id)
            .load(&mut conn)
            .await
            .map_err(|err| WriteError::Backend(err.to_string()))?;
            Ok(watermark_value(rows))
        }
    }
}
