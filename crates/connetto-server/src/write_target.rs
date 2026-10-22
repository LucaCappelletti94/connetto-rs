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
    /// server row for the conflict reply, absent when the row is gone, and
    /// the row locator the settle record re-answers a conflict from.
    Conflict {
        /// Table carrying the conflicting row.
        table: String,
        /// The server's copy of the row.
        server_row: Option<ConflictRow>,
        /// The version column the conflict checked.
        version_column: String,
        /// The primary key columns naming the row.
        pk_columns: Vec<String>,
        /// The primary key values naming the row, one per column.
        pk_values: Vec<crate::writer_schema::StoredValue>,
    },
    /// The write resolves to a first-seen settlement without another apply.
    Settled(Settlement),
}

/// The winning current or original record and its current-identity fork check.
#[derive(Debug)]
pub(crate) struct Settlement {
    pub(crate) row: SettledRow,
    pub(crate) forked: bool,
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
        version_column: conflict.version_column.clone(),
        pk_columns: conflict.pk_columns.clone(),
        pk_values: conflict
            .pk_values
            .iter()
            .map(crate::materializer::stored_value)
            .collect(),
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
    /// The original writer, sequence, entry hash and predecessor for shared settlement.
    pub original: Option<(i64, u64, [u8; 32], [u8; 32])>,
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

    /// The device writer `device_key`, absent when none exists.
    pub(crate) async fn writer_by_key(
        &self,
        device_key: &[u8],
    ) -> Result<Option<WriterRow<D::Id>>, WriteError> {
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        D::Writers::by_key(&mut conn, device_key)
            .await
            .map_err(WriteError::from)
    }

    /// The first bind or first provenance of a device writer, absent when the
    /// row stood already.
    pub(crate) async fn insert_device_writer(
        &self,
        user_id: Option<D::Id>,
        device_key: &[u8],
    ) -> Result<Option<(i64, i64)>, WriteError> {
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        D::Writers::insert_key(&mut conn, user_id, device_key)
            .await
            .map_err(WriteError::from)
    }

    /// The same insert opening the row retired, the retirement of a device key
    /// that never bound, absent when the row stood already.
    pub(crate) async fn insert_retired_device_writer(
        &self,
        user_id: Option<D::Id>,
        device_key: &[u8],
    ) -> Result<Option<i64>, WriteError> {
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        D::Writers::insert_retired_key(&mut conn, user_id, device_key)
            .await
            .map_err(WriteError::from)
    }

    /// Retire the writer `writer`, reporting whether this call retired it.
    pub(crate) async fn mark_writer_retired(
        &self,
        writer: i64,
        device_key: Option<&[u8]>,
    ) -> Result<bool, WriteError> {
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        D::Writers::mark_retired(&mut conn, writer, device_key)
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

    /// Drop every settled row of `writer`.
    pub(crate) async fn prune_writer(&self, writer: i64) -> Result<(), WriteError> {
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        D::Writers::prune_all(&mut conn, writer)
            .await
            .map_err(WriteError::from)?;
        Ok(())
    }

    /// Every device writer, the sweep's input.
    pub(crate) async fn device_writers(&self) -> Result<Vec<(i64, Option<Vec<u8>>)>, WriteError> {
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        D::Writers::device_writers(&mut conn)
            .await
            .map_err(WriteError::from)
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
        let original = settle
            .original
            .filter(|(writer, seq, _, _)| *writer != settle.writer || *seq != settle.seq)
            .map(|(writer, seq, hash, previous)| {
                seq_storage(seq).map(|seq| (writer, seq, hash, previous))
            })
            .transpose()?;
        let bytes = crate::materializer::decompress(payload_zstd)
            .map_err(|err| WriteError::Backend(format!("decompress: {err}")))?;
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        let binding = CallerBinding::of(caller, std::sync::Arc::clone(&self.user_setting));
        let expected = plan.ops.len();
        let catalog = &self.catalog;
        let outcome = conn
            .transaction::<WriteOutcome, CommitError, _>(async move |c| {
                let applied = SettledOutcome::Applied.json();
                let reserved = D::Writers::settle(
                    c,
                    settle.writer,
                    seq,
                    &settle.entry_hash,
                    &settle.previous_hash,
                    &applied,
                    settle.path,
                )
                .await?;
                if !reserved {
                    let row = D::Writers::settled(c, settle.writer, seq)
                        .await?
                        .ok_or(diesel::result::Error::NotFound)?;
                    return Ok(WriteOutcome::Settled(Settlement {
                        forked: row.entry_hash != settle.entry_hash,
                        row,
                    }));
                }
                if let Some(row) = Self::reserve_original(c, original, &applied).await? {
                    let text = std::str::from_utf8(&row.outcome).map_err(|err| {
                        diesel::result::Error::DeserializationError(Box::new(err))
                    })?;
                    D::Writers::settle_outcome(c, settle.writer, seq, text).await?;
                    if !D::Writers::advance(c, settle.writer, seq, &settle.entry_hash).await? {
                        return Err(CommitError::Frontier);
                    }
                    return Ok(WriteOutcome::Settled(Settlement { row, forked: false }));
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
                        let text = outcome.json();
                        D::Writers::settle_outcome(c, settle.writer, seq, &text).await?;
                        if let Some((writer, oseq, _, _)) = original {
                            D::Writers::settle_outcome(c, writer, oseq, &text).await?;
                        }
                        Self::advance_original(c, original).await?;
                        if !D::Writers::advance(c, settle.writer, seq, &settle.entry_hash).await? {
                            return Err(CommitError::Frontier);
                        }
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
                Self::advance_original(c, original).await?;
                if !D::Writers::advance(c, settle.writer, seq, &settle.entry_hash).await? {
                    return Err(CommitError::Frontier);
                }
                Ok(WriteOutcome::Applied)
            })
            .await;
        outcome.map_err(commit_failure)
    }

    async fn reserve_original(
        conn: &mut AsyncPgConnection,
        original: Option<(i64, i64, [u8; 32], [u8; 32])>,
        outcome: &str,
    ) -> Result<Option<SettledRow>, CommitError> {
        let Some((writer, seq, hash, previous)) = original else {
            return Ok(None);
        };
        if D::Writers::settle(
            conn,
            writer,
            seq,
            &hash,
            &previous,
            outcome,
            SettlePath::Restore,
        )
        .await?
        {
            return Ok(None);
        }
        Ok(Some(
            D::Writers::settled(conn, writer, seq)
                .await?
                .ok_or(diesel::result::Error::NotFound)?,
        ))
    }

    async fn advance_original(
        conn: &mut AsyncPgConnection,
        original: Option<(i64, i64, [u8; 32], [u8; 32])>,
    ) -> Result<(), CommitError> {
        if let Some((writer, seq, hash, _)) = original
            && !D::Writers::advance(conn, writer, seq, &hash).await?
        {
            return Err(CommitError::Frontier);
        }
        Ok(())
    }

    /// Settles a terminal outcome and returns the first-seen record.
    pub(crate) async fn settle_refusal(
        &self,
        settle: &SettleSpec,
        outcome: &SettledOutcome,
    ) -> Result<Settlement, WriteError> {
        let seq = seq_storage(settle.seq)?;
        let original = settle
            .original
            .filter(|(writer, seq, _, _)| *writer != settle.writer || *seq != settle.seq)
            .map(|(writer, seq, hash, previous)| {
                seq_storage(seq).map(|seq| (writer, seq, hash, previous))
            })
            .transpose()?;
        let mut conn = self.pool.get().await.map_err(pool_failure)?;
        conn.transaction::<Settlement, CommitError, _>(async move |c| {
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
            if !won {
                let row = D::Writers::settled(c, settle.writer, seq)
                    .await?
                    .ok_or(diesel::result::Error::NotFound)?;
                return Ok(Settlement {
                    forked: row.entry_hash != settle.entry_hash,
                    row,
                });
            }
            let result = if let Some(row) = Self::reserve_original(c, original, &text).await? {
                let stored = std::str::from_utf8(&row.outcome)
                    .map_err(|err| diesel::result::Error::DeserializationError(Box::new(err)))?;
                D::Writers::settle_outcome(c, settle.writer, seq, stored).await?;
                Settlement { row, forked: false }
            } else {
                Self::advance_original(c, original).await?;
                Settlement {
                    row: SettledRow {
                        entry_hash: settle.entry_hash.to_vec(),
                        previous_hash: settle.previous_hash.to_vec(),
                        outcome: text.into_bytes(),
                        path: settle.path,
                    },
                    forked: false,
                }
            };
            if !D::Writers::advance(c, settle.writer, seq, &settle.entry_hash).await? {
                return Err(CommitError::Frontier);
            }
            Ok(result)
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
