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

/// Diesel SQL function declarations for the file visibility check.
///
/// `connetto_visible_files` is a deployment contract: a SECURITY INVOKER
/// function that filters a bytea array to the subset the current caller may
/// see, so RLS policies evaluate under the caller's identity rather than the
/// admin's. `set_config` threads that identity in just before the call, inside
/// the same transaction so the setting stays in scope.
mod visibility {
    use diesel::sql_types::{Array, Bytea};
    diesel::define_sql_function! {
        fn connetto_visible_files(file_ids: Array<Bytea>) -> Array<Bytea>;
    }
}

use connetto_core::SessionId;
use connetto_core::auth::Principal;
use connetto_core::messages::ConflictRow;
use diesel::OptionalExtension;
use diesel::query_dsl::methods::{FilterDsl, SelectDsl};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use sqlparser::dialect::PostgreSqlDialect;
use subql::ParserDB;
use subql::patchset::{PgAdapter, apply_diffset_bytes_async_with_catalog};

use crate::capability::{CallerBinding, CapabilityKey};
use crate::watermark_schema::ConnettoWatermarkSchema;

use crate::materializer::{
    ConflictProbe, MaterializerError, PlannedConflict, ServerRow, WritePlan, probe_conflict_pg,
};

/// The outcome of committing one mutation upload.
#[derive(Debug)]
pub(crate) enum WriteOutcome {
    /// The whole changeset applied.
    Applied,
    /// A version-bearing op found a stale or missing row. Carries the current
    /// server row for the conflict reply, absent when the row is gone.
    Conflict {
        /// Table carrying the conflicting row.
        table: String,
        /// The server's copy of the row.
        server_row: Option<ConflictRow>,
    },
}

/// A failure while committing a mutation.
#[derive(Debug)]
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
    WriteOutcome::Conflict {
        table: conflict.table.clone(),
        server_row: row.map(|row| ConflictRow {
            updated_at: row.version,
            row_json: row.row_json,
        }),
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
    /// The setting a policy reads the caller's identity from.
    user_setting: std::sync::Arc<str>,
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
        user_setting: crate::capability::DEFAULT_USER_SETTING.into(),
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
    /// Read the caller's identity from `setting` rather than the default.
    ///
    /// The share-key setting has been the application's choice since R4; this
    /// is its counterpart, so an application fitting connetto into rules that
    /// already name things its own way can rename both.
    #[must_use]
    pub fn with_user_setting(mut self, setting: impl Into<std::sync::Arc<str>>) -> Self {
        self.user_setting = setting.into();
        self
    }

    /// Probe conflicts, apply one upload, and advance the durable watermark in
    /// the same transaction, reporting the outcome. The apply runs under the
    /// caller's identity and share keys, so Postgres RLS gates it, and the
    /// watermark is keyed by `session_id` alone, the durable handle every run
    /// has, so a reconnect reusing the same run dedupes replayed uploads.
    ///
    /// A caller with neither an identity nor a capability binds nothing, so
    /// every owner policy's `WITH CHECK` fails and the write is refused. A
    /// caller holding a capability writes wherever that capability's relations
    /// allow, which is the second row of the arrival table in
    /// `docs/architecture/08-authorization.md`.
    pub(crate) async fn commit<Key: CapabilityKey>(
        &self,
        caller: &Principal<W::Id, Key>,
        plan: &WritePlan,
        payload_zstd: &[u8],
        session_id: SessionId,
        client_seq: u64,
    ) -> Result<WriteOutcome, WriteError> {
        let seq = seq_storage(client_seq)?;
        let bytes = crate::materializer::decompress(payload_zstd)
            .map_err(|err| WriteError::Backend(format!("decompress: {err}")))?;
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|err| WriteError::Backend(err.to_string()))?;
        let binding = CallerBinding::of(caller, std::sync::Arc::clone(&self.user_setting));
        let watermark_session = session_id;
        let expected = plan.ops.len();
        let catalog = &self.catalog;
        let outcome = conn
            .transaction::<WriteOutcome, CommitError, _>(async move |c| {
                binding.apply(c).await?;
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
                let adapter = PgAdapter::new(catalog)
                    .map_err(|e| CommitError::Probe(MaterializerError::Catalog(e.to_string())))?;
                let affected =
                    apply_diffset_bytes_async_with_catalog(catalog, &bytes, c, &adapter).await?;
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

    /// Whether `caller` may see `file_id` per the deployment's
    /// `connetto_visible_files` function.
    ///
    /// Runs inside a transaction on the pool so the `set_config` call that
    /// threads the caller identity in stays in scope for the duration. The pool
    /// must be the reader (non-owner) role: the admin role bypasses RLS, so
    /// running this check as admin makes it decorative.
    pub(crate) async fn file_visible_to_caller(
        &self,
        file_id: [u8; 32],
        caller: &str,
    ) -> Result<bool, WriteError> {
        use crate::capability::set_config;
        use visibility::connetto_visible_files;
        let caller = caller.to_owned();
        let user_setting = std::sync::Arc::clone(&self.user_setting);
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|err| WriteError::Backend(err.to_string()))?;
        // file_id is [u8; 32] (Copy): derive bytes twice inside the async
        // block so no clone is needed across the await.
        conn.transaction::<bool, diesel::result::Error, _>(async move |c| {
            diesel::select(set_config(&*user_setting, &caller, true))
                .get_result::<String>(c)
                .await?;
            let visible: Vec<Vec<u8>> =
                diesel::select(connetto_visible_files(vec![file_id.to_vec()]))
                    .get_result(c)
                    .await?;
            let expected = file_id.to_vec();
            Ok(visible.into_iter().any(|v| v == expected))
        })
        .await
        .map_err(|err| WriteError::Backend(err.to_string()))
    }
}
