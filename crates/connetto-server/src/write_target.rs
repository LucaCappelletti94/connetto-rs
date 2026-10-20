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

use connetto_core::auth::Principal;
use connetto_core::messages::ConflictRow;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use sqlparser::dialect::PostgreSqlDialect;
use subql::ParserDB;
use subql::patchset::{PgAdapter, apply_diffset_bytes_async_with_catalog};

use crate::capability::CallerBinding;
use crate::schema::ConnettoSchema;
use crate::writer_schema::{
    ConnettoWriterSchema, SettlePath, SettledOutcome, SettledRow, WriterRow,
};
use connetto_core::auth::CapabilityKey;

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
    /// The sequence is already settled: answer from the stored row, never apply again.
    Settled {
        /// The stored settled row.
        row: SettledRow,
        /// Whether the stored entry hash matches this upload's.
        hash_matches: bool,
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
    /// A transaction or watermark storage failure that trying again cannot clear.
    Backend(String),
    /// The writer's frontier moved under this write, so the write re-races the settled record.
    Frontier,
    /// The database could not be reached or cut the connection, so the same write may succeed later.
    Transient(String),
}

impl WriteError {
    /// Human-readable detail for logging and error mapping.
    pub(crate) fn detail(&self) -> String {
        match self {
            Self::Unauthorized => "unauthorized".to_owned(),
            Self::Materializer(err) => err.to_string(),
            Self::Backend(detail) | Self::Transient(detail) => detail.clone(),
            Self::Frontier => "the writer's frontier moved".to_owned(),
        }
    }
}

impl From<diesel::result::Error> for WriteError {
    fn from(err: diesel::result::Error) -> Self {
        match crate::reexec::diesel_failure(&err) {
            crate::reexec::ReadFailure::Transient => Self::Transient(err.to_string()),
            crate::reexec::ReadFailure::Timeout | crate::reexec::ReadFailure::Other => {
                Self::Backend(err.to_string())
            }
        }
    }
}

/// A pool that could not hand out a connection is an unreachable database.
fn pool_failure(err: impl core::fmt::Display) -> WriteError {
    WriteError::Transient(err.to_string())
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

/// One entry's settle instruction, what `commit` records once it applies.
pub(crate) struct SettleSpec {
    /// The writer the entry settles under.
    pub writer: i64,
    /// The entry's sequence for that writer.
    pub seq: u64,
    /// The entry's chain hash.
    pub entry_hash: [u8; 32],
    /// The chain head the entry hashed under.
    pub previous_hash: [u8; 32],
    /// The path that settles the entry.
    pub path: SettlePath,
}

/// A Postgres write target that applies under the caller's RLS context.
///
/// Holds the pool and the parsed catalog. `commit` applies the changeset through
/// subql's catalog-only entry point, so the catalog is shared by reference
/// across the apply `await` (`ParserDB` is `Sync`) with no per-write engine to
/// build.
pub struct PgWriteTarget<D> {
    pool: Pool<AsyncPgConnection>,
    catalog: ParserDB,
    /// The setting a policy reads the caller's identity from.
    user_setting: std::sync::Arc<str>,
    /// The deployment's writer schema, carried only in the type system so
    /// `commit` names its writer tables. `fn() -> D` keeps the target
    /// `Send`/`Sync` regardless of `D`.
    _writers: PhantomData<fn() -> D>,
}

/// Build a Postgres write target over a pool and the catalog DDL.
///
/// # Errors
///
/// [`MaterializerError::Catalog`] when the DDL does not parse.
pub fn pg_write_target<D: ConnettoSchema>(
    pool: Pool<AsyncPgConnection>,
    pg_ddl: &str,
) -> Result<PgWriteTarget<D>, MaterializerError> {
    let catalog = ParserDB::parse::<PostgreSqlDialect>(pg_ddl)
        .map_err(|err| MaterializerError::Catalog(format!("{err:?}")))?;
    Ok(PgWriteTarget {
        user_setting: connetto_core::auth::DEFAULT_USER_SETTING.into(),
        pool,
        catalog,
        _writers: PhantomData,
    })
}

/// A failure inside the apply transaction, mapped to a [`WriteError`] after the
/// transaction resolves.
enum CommitError {
    Db(diesel::result::Error),
    Probe(MaterializerError),
    /// Fewer rows changed than the upload carried: RLS hid the rest.
    Denied,
    /// The frontier did not advance because it moved: the write must re-race the record.
    Frontier,
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

impl<D: ConnettoSchema> PgWriteTarget<D> {
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

    /// The setting this target binds the caller's identity to.
    ///
    /// The one configured name for it, so the per-viewer read and the ticket
    /// path cannot bind under a different name than the write and the
    /// visibility check.
    pub(crate) fn user_setting(&self) -> std::sync::Arc<str> {
        std::sync::Arc::clone(&self.user_setting)
    }

    /// A fresh number writer issued for the account `user_id` at frontier 0,
    /// bound to `session_id` when the caller has no identity.
    pub(crate) async fn issue_writer(
        &self,
        user_id: Option<D::Id>,
        session_id: Option<uuid::Uuid>,
    ) -> Result<(i64, i64), WriteError> {
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        D::Writers::issue(&mut conn, user_id, session_id)
            .await
            .map_err(WriteError::from)
    }

    /// The number writer `writer` of the caller, absent when no such writer
    /// exists. An identified caller is admitted to a writer of its account and
    /// nothing else; an anonymous caller is admitted to the writer its run
    /// handle `session_id` holds and nothing else.
    pub(crate) async fn writer_by_number(
        &self,
        writer: i64,
        user_id: Option<&D::Id>,
        session_id: Option<&uuid::Uuid>,
    ) -> Result<Option<WriterRow<D::Id>>, WriteError> {
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        D::Writers::by_number(&mut conn, writer, user_id, session_id)
            .await
            .map_err(WriteError::from)
    }

    /// The settled row of `(writer, seq)`, absent when pruned or never settled.
    pub(crate) async fn settled_row(
        &self,
        writer: i64,
        seq: u64,
    ) -> Result<Option<SettledRow>, WriteError> {
        let seq = seq_storage(seq)?;
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        D::Writers::settled(&mut conn, writer, seq)
            .await
            .map_err(WriteError::from)
    }

    /// The current row a re-answered settled conflict reads fresh, under the
    /// caller's RLS context on the owner pool.
    pub(crate) async fn settled_conflict_row<Key: CapabilityKey>(
        &self,
        caller: &Principal<D::Id, Key>,
        table: &str,
        version_column: &str,
        pk_columns: &[String],
        pk_values: &[crate::writer_schema::StoredValue],
    ) -> Result<Option<ServerRow>, WriteError> {
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        CallerBinding::of(caller, std::sync::Arc::clone(&self.user_setting))
            .apply(&mut conn)
            .await
            .map_err(WriteError::from)?;
        crate::materializer::read_settled_conflict_row(
            &mut conn,
            table,
            version_column,
            pk_columns,
            pk_values,
        )
        .await
        .map_err(|err| WriteError::Backend(err.to_string()))
    }

    /// Drop the settled rows of `writer` at or below `seq`.
    pub(crate) async fn prune_settled(&self, writer: i64, seq: u64) -> Result<(), WriteError> {
        let seq = seq_storage(seq)?;
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        D::Writers::prune(&mut conn, writer, seq)
            .await
            .map_err(WriteError::from)?;
        Ok(())
    }

    /// Probe conflicts, apply one upload, and settle its sequence in the same
    /// transaction, reporting the outcome. The apply runs under the caller's
    /// identity and share keys, so Postgres RLS gates it.
    ///
    /// The entry settles by `(writer, seq)`, so a redelivery of a settled
    /// sequence is answered from the stored row and never applies twice. The
    /// reserved settle row rolls back with a lost apply, so an indeterminate
    /// write settles nothing and the client may retry it.
    ///
    /// A caller with neither an identity nor a capability binds nothing, so
    /// every owner policy's `WITH CHECK` fails and the write is refused. A
    /// caller holding a capability writes wherever that capability's relations
    /// allow, which is the second row of the arrival table in
    /// `docs/architecture/08-authorization.md`.
    pub(crate) async fn commit<Key: CapabilityKey>(
        &self,
        caller: &Principal<D::Id, Key>,
        plan: &WritePlan,
        payload_zstd: &[u8],
        settle: &SettleSpec,
    ) -> Result<WriteOutcome, WriteError> {
        let seq = seq_storage(settle.seq)?;
        let bytes = crate::materializer::decompress(payload_zstd)
            .map_err(|err| WriteError::Backend(format!("decompress: {err}")))?;
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        let binding = CallerBinding::of(caller, std::sync::Arc::clone(&self.user_setting));
        let expected = plan.ops.len();
        let catalog = &self.catalog;
        let outcome = conn
            .transaction::<WriteOutcome, CommitError, _>(async move |c| {
                // Reserve the sequence before touching any table, so a settled
                // entry is answered from the record and a lost apply leaves no row.
                let reserved = D::Writers::settle(
                    c,
                    settle.writer,
                    seq,
                    &settle.entry_hash,
                    &settle.previous_hash,
                    &SettledOutcome::Applied.json(),
                    settle.path,
                )
                .await?;
                if !reserved {
                    let row = D::Writers::settled(c, settle.writer, seq)
                        .await?
                        .ok_or(diesel::result::Error::NotFound)?;
                    return Ok(WriteOutcome::Settled {
                        hash_matches: row.entry_hash == settle.entry_hash,
                        row,
                    });
                }
                binding.apply(c).await?;
                for op in &plan.ops {
                    let Some(conflict) = &op.conflict else {
                        continue;
                    };
                    if let ConflictProbe::Stale(row) = probe_conflict_pg(conflict, c)
                        .await
                        .map_err(CommitError::Probe)?
                    {
                        // The reserved row keeps the sequence; restate its outcome
                        // to the conflict so the record matches the refusal.
                        let outcome = SettledOutcome::Conflict {
                            table: conflict.table.clone(),
                            version_column: conflict.version_column.clone(),
                            pk_columns: conflict.pk_columns.clone(),
                            pk_values: conflict
                                .pk_values
                                .iter()
                                .map(crate::materializer::stored_value)
                                .collect(),
                        };
                        D::Writers::settle_outcome(c, settle.writer, seq, &outcome.json()).await?;
                        D::Writers::advance(c, settle.writer, seq, &settle.entry_hash).await?;
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
                if !D::Writers::advance(c, settle.writer, seq, &settle.entry_hash).await? {
                    return Err(CommitError::Frontier);
                }
                Ok(WriteOutcome::Applied)
            })
            .await;
        outcome.map_err(commit_failure)
    }

    /// Settle a refused entry after its apply rolled back, in its own transaction.
    /// Loses silently when a concurrent copy settled the sequence first.
    pub(crate) async fn settle_refusal(
        &self,
        settle: &SettleSpec,
        outcome: &SettledOutcome,
    ) -> Result<(), WriteError> {
        let seq = seq_storage(settle.seq)?;
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        conn.transaction::<(), CommitError, _>(async move |c| {
            let text = outcome.json();
            let won = D::Writers::settle(
                c,
                settle.writer,
                seq,
                &settle.entry_hash,
                &settle.previous_hash,
                &text,
                settle.path,
            )
            .await?;
            if won {
                D::Writers::advance(c, settle.writer, seq, &settle.entry_hash).await?;
            }
            Ok(())
        })
        .await
        .map_err(commit_failure)
    }

    /// Whether `caller` may see `file_id` per the deployment's
    /// `connetto_visible_files` function.
    ///
    /// Runs inside a transaction on the pool so the binding stays in scope for
    /// the duration, through the same [`CallerBinding`] the write takes, so a
    /// caller holding only a share key is answered on its keys. The pool must
    /// be the reader (non-owner) role: the admin role bypasses RLS, so running
    /// this check as admin makes it decorative.
    pub(crate) async fn file_visible_to_caller<Key: CapabilityKey>(
        &self,
        file_id: [u8; 32],
        caller: &Principal<D::Id, Key>,
    ) -> Result<bool, WriteError> {
        use visibility::connetto_visible_files;
        let binding = CallerBinding::of(caller, std::sync::Arc::clone(&self.user_setting));
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        // file_id is [u8; 32] (Copy): derive bytes twice inside the async
        // block so no clone is needed across the await.
        conn.transaction::<bool, diesel::result::Error, _>(async move |c| {
            binding.apply(c).await?;
            let visible: Vec<Vec<u8>> =
                diesel::select(connetto_visible_files(vec![file_id.to_vec()]))
                    .get_result(c)
                    .await?;
            let expected = file_id.to_vec();
            Ok(visible.into_iter().any(|v| v == expected))
        })
        .await
        .map_err(WriteError::from)
    }
}

/// The write error a failed commit transaction reports.
fn commit_failure(err: CommitError) -> WriteError {
    match err {
        CommitError::Frontier => WriteError::Frontier,
        CommitError::Denied => WriteError::Unauthorized,
        CommitError::Db(err) if is_rls_violation(&err.to_string()) => WriteError::Unauthorized,
        CommitError::Db(err) => err.into(),
        // The conflict probe reads inside the same transaction, so its connection failing is the same outage.
        CommitError::Probe(MaterializerError::Apply(err))
            if crate::reexec::diesel_failure(&err) == crate::reexec::ReadFailure::Transient =>
        {
            WriteError::Transient(err.to_string())
        }
        CommitError::Probe(err) => WriteError::Materializer(err),
    }
}

#[cfg(test)]
mod tests {
    use super::{CommitError, MaterializerError, WriteError, commit_failure};
    use diesel::result::{DatabaseErrorKind, Error};

    fn db_error(kind: DatabaseErrorKind, message: &str) -> Error {
        Error::DatabaseError(kind, Box::new(message.to_owned()))
    }

    /// The conflict probe reads inside the commit transaction, so a connection cut there is the outage the apply retries.
    #[test]
    fn a_probe_cut_off_mid_read_is_retried_like_the_apply() {
        let closed = || {
            db_error(
                DatabaseErrorKind::ClosedConnection,
                "server closed the connection",
            )
        };
        assert!(matches!(
            commit_failure(CommitError::Probe(MaterializerError::Apply(closed()))),
            WriteError::Transient(_)
        ));
        assert!(matches!(
            commit_failure(CommitError::Db(closed())),
            WriteError::Transient(_)
        ));
        let duplicate = db_error(DatabaseErrorKind::UniqueViolation, "duplicate key");
        assert!(matches!(
            commit_failure(CommitError::Probe(MaterializerError::Apply(duplicate))),
            WriteError::Materializer(_)
        ));
    }
}
