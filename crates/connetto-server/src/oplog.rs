//! Retention-bounded, commit-ordered oplog and the reconnect catchup decision.
//!
//! The oplog is an ordered log of [`ChangeRecord`]s keyed by their commit position.
//! On reconnect the server replays the records a client missed instead of
//! re-snapshotting, falling back to a full snapshot only when the client's
//! resume position has fallen outside the retained window. Deletes are kept as
//! tombstones so they replay too.
//!
//! [`Oplog`] is the seam, shaped like
//! [`SnapshotSource`](crate::session::SnapshotSource): an async, `Send + Sync`
//! trait. [`InMemoryOplog`] is the ring-buffer test double. [`PgOplog`] is the
//! production target, a Postgres table, so the log survives a restart and a
//! promoted standby carries it with every other table (`06-reconnect.md`).
//!
//! # Pruning policy
//!
//! `06-reconnect.md` contradicts itself: line 69 prunes unconditionally on the
//! retention window with no per-client cursor tracking, while the Notes at line
//! 173 say never prune tombstones older than the oldest client cursor. This
//! crate resolves the conflict in favor of line 69: pruning is unconditional on
//! the window, and a client whose resume LSN has fallen behind the window gets a
//! [`FullResyncRequired`](connetto_core::messages::FullResyncRequired) instead of
//! a partial replay. It is simpler, needs no cross-client bookkeeping, and is the
//! stated default.
//!
//! # Retention window
//!
//! [`OplogConfig`] bounds the log by entry count and age, whichever is hit first
//! (default one million entries or 72 hours). Both are configurable per
//! deployment.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

use diesel::deserialize::{self, FromSql, FromSqlRow};
use diesel::expression::AsExpression;
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, IsNull, Output, ToSql};
use parking_lot::Mutex;
use subql::backend::CdcEvent;
use subql::{ClockHandle, EventKind, PgChangeEvent, PgCommit, PgCommitPosition, PgLsn, StdClock};

/// Default retention age: 72 hours (`06-reconnect.md` line 69).
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(72 * 60 * 60);
/// Default retention count: one million entries (`06-reconnect.md` line 69).
const DEFAULT_MAX_ENTRIES: usize = 1_000_000;

/// Retention window for an [`Oplog`]: entries older than either bound are
/// pruned, whichever bound is hit first.
#[derive(Debug, Clone)]
pub struct OplogConfig {
    /// Maximum number of retained entries. The oldest are dropped first.
    max_entries: usize,
    /// Maximum age of a retained entry, measured against the oplog's clock.
    max_age: Duration,
}

impl Default for OplogConfig {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_age: DEFAULT_MAX_AGE,
        }
    }
}

impl OplogConfig {
    /// Returns the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of retained entries.
    #[must_use]
    pub const fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Sets the maximum age of a retained entry.
    #[must_use]
    pub const fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }
}

/// One change retained in the oplog, keyed by its commit position.
///
/// The [`PgChangeEvent`] is the source of truth replayed on catchup: catchup runs
/// it back through the same matching and patchset encoding the live path uses.
/// The table name and primary-key bytes are resolved once at append time (they
/// need the catalog, which the oplog impls do not carry) so the auth read filter
/// on the catchup path has them without a second catalog pass.
#[derive(Debug, Clone)]
pub struct ChangeRecord {
    table: String,
    pk: Vec<u8>,
    event: PgChangeEvent,
}

impl ChangeRecord {
    /// Build a record from its resolved parts.
    ///
    /// `event` must be a row DML event (Insert, Update, Delete, or Truncate);
    /// the dispatch path only appends such events, since a non-row event never
    /// reaches a successful dispatch. [`op`](Self::op) and
    /// [`is_tombstone`](Self::is_tombstone) rely on that invariant.
    #[must_use]
    pub fn new(table: impl Into<String>, pk: Vec<u8>, event: PgChangeEvent) -> Self {
        Self {
            table: table.into(),
            pk,
            event,
        }
    }

    /// The change's commit position, the oplog key. The wire cursor is this
    /// value stamped with the timeline it was read on ([`crate::timeline`]).
    #[must_use]
    pub const fn position(&self) -> PgCommitPosition {
        self.event.position()
    }

    /// The table the change touched.
    #[must_use]
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Stable primary-key bytes for the auth read filter.
    #[must_use]
    pub fn pk(&self) -> &[u8] {
        &self.pk
    }

    /// The retained CDC event, replayed on catchup.
    #[must_use]
    pub const fn event(&self) -> &PgChangeEvent {
        &self.event
    }

    /// Whether this record is a delete tombstone.
    #[must_use]
    pub fn is_tombstone(&self) -> bool {
        matches!(self.event.kind(), EventKind::Delete)
    }

    /// The change verb, for the Postgres oplog `op` column.
    #[must_use]
    pub fn op(&self) -> ChangeOp {
        ChangeOp::from(self.event.kind())
    }
}

/// The Postgres enum type name the oplog's `op` column carries. Declared here
/// so the DDL, the `postgres_type` attribute and the documented shape cannot
/// drift apart.
pub const CHANGE_OP_TYPE: &str = "connetto_change_op";

/// The Postgres enum type backing the oplog's `op` column.
///
/// A deployment creates it beside the table (see `06-reconnect.md`). Naming it
/// here is what lets the column bind as its own type rather than as text.
#[derive(diesel::SqlType, diesel::query_builder::QueryId)]
#[diesel(postgres_type(name = "connetto_change_op"))]
pub struct ChangeOpSql;

/// The verb a retained change carries.
///
/// A closed set of four, so it is an enum on both sides: a value outside it is
/// unrepresentable in Rust and rejected by Postgres. The column used to be
/// `TEXT` carrying one of four words, which is a contract nothing enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsExpression, FromSqlRow)]
#[diesel(sql_type = ChangeOpSql)]
pub enum ChangeOp {
    /// The row was created.
    Insert,
    /// The row's values were replaced.
    Update,
    /// The row was removed.
    Delete,
    /// The whole table was emptied.
    Truncate,
}

impl ChangeOp {
    /// The label this verb carries in Postgres, and the one the enum type
    /// declares.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Truncate => "truncate",
        }
    }
}

impl From<EventKind> for ChangeOp {
    fn from(kind: EventKind) -> Self {
        match kind {
            EventKind::Insert => Self::Insert,
            EventKind::Update => Self::Update,
            EventKind::Delete => Self::Delete,
            EventKind::Truncate => Self::Truncate,
        }
    }
}

impl ToSql<ChangeOpSql, Pg> for ChangeOp {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        out.write_all(self.label().as_bytes())?;
        Ok(IsNull::No)
    }
}

impl FromSql<ChangeOpSql, Pg> for ChangeOp {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"insert" => Ok(Self::Insert),
            b"update" => Ok(Self::Update),
            b"delete" => Ok(Self::Delete),
            b"truncate" => Ok(Self::Truncate),
            other => Err(format!(
                "unrecognised connetto_change_op label {:?}",
                String::from_utf8_lossy(other)
            )
            .into()),
        }
    }
}

/// A retention-bounded, commit-ordered log of [`ChangeRecord`]s.
///
/// The seam the session layer appends to on every dispatched event and reads
/// from on reconnect. Shaped like [`SnapshotSource`](crate::session::SnapshotSource):
/// async, `Send + Sync`, one associated error.
#[expect(
    async_fn_in_trait,
    reason = "the futures are bound by MaybeSend, which is Send on native, so the auto trait warning does not apply"
)]
pub trait Oplog: Send + Sync {
    /// Oplog-source error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// Whether a read that failed with `err` may succeed if made again, as when the database cut the connection.
    fn is_transient(err: &Self::Error) -> bool {
        let _ = err;
        false
    }

    /// Append one record, then drop whatever the retention window no longer
    /// covers. Pruning is not a separate seam: an external caller would race
    /// the append it belongs to. A record at a position already appended is
    /// ignored, since a source resuming after a failed dispatch delivers it again.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backing-store write failure.
    async fn append(&self, record: ChangeRecord) -> Result<(), Self::Error>;

    /// Records strictly after `after`, in commit order.
    ///
    /// The client already applied `after`, so catchup replays everything past it,
    /// the rest of `after`'s own transaction included.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backing-store read failure.
    async fn entries_since(
        &self,
        after: PgCommitPosition,
    ) -> Result<Vec<ChangeRecord>, Self::Error>;

    /// The earliest retained position, or `None` when the log holds no entries.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backing-store read failure.
    async fn min_position(&self) -> Result<Option<PgCommitPosition>, Self::Error>;

    /// The server's current watermark: the latest position ever appended. It
    /// does not decrease when the window prunes, so it names the server's live
    /// position. `None` when nothing has been appended.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backing-store read failure.
    async fn current_position(&self) -> Result<Option<PgCommitPosition>, Self::Error>;

    /// Remember `commit` as the last transaction the change feed delivered in full,
    /// unless a later one is already recorded.
    ///
    /// Its `end_lsn` is where the replication slot resumes once the commit is
    /// acknowledged, so it is recorded before the acknowledgement, and a slot past
    /// it on the next connect names changes this log never received.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backing-store write failure.
    async fn record_commit(&self, commit: PgCommit) -> Result<(), Self::Error>;

    /// The last commit [`record_commit`](Self::record_commit) kept, `None` before the first.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backing-store read failure.
    async fn last_commit(&self) -> Result<Option<PgCommit>, Self::Error>;

    /// Drop every record at or before `through`, because continuity across it can no
    /// longer be proven.
    ///
    /// This is retention with a different trigger, not a new concept: the log
    /// is a bounded window that already deletes what it no longer covers, and a
    /// gap in the feed means it no longer covers anything before the point the
    /// feed resumed. Forgetting is what makes [`catchup_decision`] tell the
    /// truth afterwards, with no second thing to consult and nothing to keep in
    /// step (R32).
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backing-store write failure.
    async fn forget_through(&self, through: PgCommitPosition) -> Result<(), Self::Error>;
}

/// Decide whether a client resuming from `resume` can catch up from the
/// oplog, given its `min` (earliest retained) and `current` (watermark).
///
/// `true` replays the gap; `false` forces a full resync. The rule:
///
/// * A resume at the origin (never synced) always resyncs.
/// * A non-empty log replays when `resume >= min`: everything the client is
///   missing (positions after `resume`) is then retained. The check is
///   deliberately conservative at the exact boundary, favoring a full resync
///   over a replay it cannot prove complete.
/// * An empty log resyncs, whichever kind of empty it is. Nothing in it can
///   prove the client has everything, and a log that has recorded nothing is
///   most often a process that has just started rather than a world in which
///   nothing happened. Reading it the other way lost data on every restart,
///   silently, because the shipped binary keeps the log in memory (R32).
#[must_use]
pub fn catchup_decision(
    resume: PgCommitPosition,
    min: Option<PgCommitPosition>,
    current: Option<PgCommitPosition>,
) -> CatchupDecision {
    if resume.commit_lsn() == PgLsn(0) {
        return CatchupDecision::FullResync;
    }
    match (min, current) {
        // Non-empty log: replay when the client sits at or after the oldest
        // retained entry, so nothing it is missing has been pruned.
        (Some(min), _) => {
            if resume >= min {
                CatchupDecision::Catchup
            } else {
                CatchupDecision::FullResync
            }
        }
        // Empty either way: nothing retained can prove the client is current,
        // so it resyncs.
        (None, _) => CatchupDecision::FullResync,
    }
}

/// Outcome of [`catchup_decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchupDecision {
    /// Replay the oplog gap since the client's resume position.
    Catchup,
    /// The resume position is outside the retained window: send a full snapshot.
    FullResync,
}

/// One retained entry plus the clock reading taken when it was appended.
struct Entry {
    appended_micros: u64,
    record: ChangeRecord,
}

/// Mutable interior of an [`InMemoryOplog`].
struct Inner {
    /// Entries in commit order (equivalently, ascending append time).
    entries: VecDeque<Entry>,
    /// Latest position ever appended. Monotone: never lowered by pruning.
    max_position: Option<PgCommitPosition>,
    /// The last commit recorded, the one ending furthest along the log.
    last_commit: Option<PgCommit>,
}

/// An in-memory ring-buffer [`Oplog`] for Docker-free tests and single-node use.
///
/// Guarded by a synchronous [`Mutex`]; no lock is ever held across an `.await`
/// because the operations do no async work. Age-based retention reads a
/// [`ClockHandle`] (a real clock by default, a
/// [`ManualClock`](subql::ManualClock) in tests that need deterministic aging).
pub struct InMemoryOplog {
    inner: Mutex<Inner>,
    config: OplogConfig,
    clock: ClockHandle,
}

impl InMemoryOplog {
    /// Build an oplog with the given retention window and a real clock.
    #[must_use]
    pub fn new(config: OplogConfig) -> Self {
        Self::with_clock(config, Arc::new(StdClock::new()))
    }

    /// Build an oplog with an explicit clock, for deterministic age tests.
    #[must_use]
    pub fn with_clock(config: OplogConfig, clock: ClockHandle) -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: VecDeque::new(),
                max_position: None,
                last_commit: None,
            }),
            config,
            clock,
        }
    }

    /// Drop entries outside the window. `now` is the current clock reading.
    fn prune_locked(&self, inner: &mut Inner, now: u64) {
        // `Duration::as_micros` is u128; saturate into u64 the same way
        // `StdClock` does, so an absurd configured age never wraps.
        let max_age_micros = u64::try_from(self.config.max_age.as_micros()).unwrap_or(u64::MAX);
        while let Some(front) = inner.entries.front() {
            let too_old = now.saturating_sub(front.appended_micros) > max_age_micros;
            let too_many = inner.entries.len() > self.config.max_entries;
            if too_old || too_many {
                inner.entries.pop_front();
            } else {
                break;
            }
        }
    }
}

impl Default for InMemoryOplog {
    fn default() -> Self {
        Self::new(OplogConfig::default())
    }
}

impl Oplog for InMemoryOplog {
    type Error = Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn append(&self, record: ChangeRecord) -> Result<(), Infallible> {
        let now = self.clock.now_micros();
        let mut inner = self.inner.lock();
        let position = record.position();
        // Positions arrive in commit order, so one at or before the latest was appended already.
        if inner.max_position.is_some_and(|latest| position <= latest) {
            return Ok(());
        }
        inner.max_position = Some(position);
        inner.entries.push_back(Entry {
            appended_micros: now,
            record,
        });
        self.prune_locked(&mut inner, now);
        Ok(())
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn entries_since(
        &self,
        after: PgCommitPosition,
    ) -> Result<Vec<ChangeRecord>, Infallible> {
        let inner = self.inner.lock();
        Ok(inner
            .entries
            .iter()
            .filter(|entry| entry.record.position() > after)
            .map(|entry| entry.record.clone())
            .collect())
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn min_position(&self) -> Result<Option<PgCommitPosition>, Infallible> {
        let inner = self.inner.lock();
        Ok(inner.entries.front().map(|entry| entry.record.position()))
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn current_position(&self) -> Result<Option<PgCommitPosition>, Infallible> {
        Ok(self.inner.lock().max_position)
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn record_commit(&self, commit: PgCommit) -> Result<(), Infallible> {
        let mut inner = self.inner.lock();
        if inner
            .last_commit
            .is_none_or(|last| last.end_lsn() < commit.end_lsn())
        {
            inner.last_commit = Some(commit);
        }
        Ok(())
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn last_commit(&self) -> Result<Option<PgCommit>, Infallible> {
        Ok(self.inner.lock().last_commit)
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn forget_through(&self, through: PgCommitPosition) -> Result<(), Infallible> {
        self.inner
            .lock()
            .entries
            .retain(|e| e.record.position() > through);
        Ok(())
    }
}

pub use pg::{PgOplog, PgOplogError};

mod pg {
    use connetto_core::quote_ident;
    use diesel::sql_types::{BigInt, Binary, Bool, Text};
    use diesel::{QueryableByName, sql_query};
    use diesel_async::RunQueryDsl;
    use diesel_async::pooled_connection::bb8::Pool;
    use subql::{ChangeEvent, PgChangeEvent, PgCommit, PgCommitPosition, PgLsn};

    use super::{CHANGE_OP_TYPE, ChangeOp, ChangeOpSql, ChangeRecord, Oplog, OplogConfig};

    /// Failure surfaced by [`PgOplog`].
    #[derive(Debug, thiserror::Error)]
    pub enum PgOplogError {
        /// The connection pool could not hand out a connection.
        #[error("oplog pool error: {0}")]
        Pool(String),
        /// A query against the oplog table failed.
        #[error(transparent)]
        Query(#[from] diesel::result::Error),
        /// A retained event could not be (de)serialized.
        #[error("oplog event codec error: {0}")]
        Codec(#[from] serde_json::Error),
        /// A commit LSN or ordinal did not fit its signed BIGINT column. Real
        /// values are far below this bound, so this signals corruption or a bad write.
        #[error("oplog position part {0} is out of BIGINT range")]
        LsnRange(u64),
    }

    /// A Postgres-table [`Oplog`], the production target.
    ///
    /// The last recorded commit lives in a one-row companion table named after
    /// the log with `_commit` appended ([`PgOplog::commit_table`]).
    ///
    /// The log is a single table, which a promoted standby carries with every
    /// other table. The row image plus routing metadata
    /// (`table_name`, `op`, `pk`, `is_tombstone`) are stored as typed columns for
    /// indexing and observability, and the decoded change is stored as a
    /// serialized blob beside its position so catchup replays it losslessly.
    pub struct PgOplog {
        pool: Pool<diesel_async::AsyncPgConnection>,
        table: String,
        config: OplogConfig,
    }

    /// A row read back from the oplog table.
    #[derive(QueryableByName)]
    struct OplogRow {
        #[diesel(sql_type = BigInt)]
        commit_lsn: i64,
        #[diesel(sql_type = BigInt)]
        ordinal: i64,
        #[diesel(sql_type = Text)]
        table_name: String,
        #[diesel(sql_type = Binary)]
        pk: Vec<u8>,
        #[diesel(sql_type = Binary)]
        event: Vec<u8>,
    }

    /// The recorded commit, read back from the companion table.
    #[derive(QueryableByName)]
    struct CommitRow {
        #[diesel(sql_type = BigInt)]
        commit_lsn: i64,
        #[diesel(sql_type = BigInt)]
        end_lsn: i64,
    }

    /// One end of the retained window, read back from an ordered single-row query.
    #[derive(QueryableByName)]
    struct PositionRow {
        #[diesel(sql_type = BigInt)]
        commit_lsn: i64,
        #[diesel(sql_type = BigInt)]
        ordinal: i64,
    }

    /// Widen one position part into its signed BIGINT column. Both fit i64, so an
    /// overflow is corruption, surfaced rather than silently wrapped.
    fn part_to_i64(part: u64) -> Result<i64, PgOplogError> {
        i64::try_from(part).map_err(|_| PgOplogError::LsnRange(part))
    }

    /// The two BIGINT columns a position is stored as.
    fn position_to_i64(position: PgCommitPosition) -> Result<(i64, i64), PgOplogError> {
        Ok((
            part_to_i64(position.commit_lsn().0)?,
            part_to_i64(position.ordinal())?,
        ))
    }

    /// Read a position back from its two BIGINT columns.
    fn position_from_i64(commit_lsn: i64, ordinal: i64) -> PgCommitPosition {
        // The columns only ever hold values written by `part_to_i64`, which are
        // non-negative, so this widening is lossless.
        let part = |value: i64| u64::try_from(value).unwrap_or(0);
        PgCommitPosition::new(PgLsn(part(commit_lsn)), part(ordinal))
    }

    impl PgOplog {
        /// Build an oplog over `pool`, storing rows in `table`.
        #[must_use]
        pub fn new(
            pool: Pool<diesel_async::AsyncPgConnection>,
            table: impl Into<String>,
            config: OplogConfig,
        ) -> Self {
            Self {
                pool,
                table: table.into(),
                config,
            }
        }

        /// The companion table holding the last recorded commit, the log's name with `_commit` appended.
        #[must_use]
        pub fn commit_table(table: &str) -> String {
            format!("{table}_commit")
        }

        /// Create the `op` enum type, the oplog table and its commit table if any is absent.
        ///
        /// Postgres has no `CREATE TYPE IF NOT EXISTS`, so the type goes in
        /// through a `DO` block that swallows only `duplicate_object`.
        ///
        /// # Errors
        ///
        /// [`PgOplogError`] when the pool or the DDL fails.
        pub async fn ensure_schema(&self) -> Result<(), PgOplogError> {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let labels = [
                ChangeOp::Insert,
                ChangeOp::Update,
                ChangeOp::Delete,
                ChangeOp::Truncate,
            ]
            .map(|op| format!("'{}'", op.label()))
            .join(", ");
            let create_type = format!(
                "DO $$ BEGIN CREATE TYPE {CHANGE_OP_TYPE} AS ENUM ({labels}); \
                 EXCEPTION WHEN duplicate_object THEN NULL; END $$"
            );
            sql_query(create_type).execute(&mut *conn).await?;
            let ddl = format!(
                "CREATE TABLE IF NOT EXISTS {table} (\
                     commit_lsn BIGINT NOT NULL, \
                     ordinal BIGINT NOT NULL, \
                     table_name TEXT NOT NULL, \
                     op {CHANGE_OP_TYPE} NOT NULL, \
                     pk BYTEA NOT NULL, \
                     is_tombstone BOOLEAN NOT NULL, \
                     event BYTEA NOT NULL, \
                     appended_at TIMESTAMPTZ NOT NULL DEFAULT now(), \
                     PRIMARY KEY (commit_lsn, ordinal))",
                table = quote_ident(&self.table),
            );
            sql_query(ddl).execute(&mut *conn).await?;
            let commit_ddl = format!(
                "CREATE TABLE IF NOT EXISTS {table} (\
                     only_row BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (only_row), \
                     commit_lsn BIGINT NOT NULL, \
                     end_lsn BIGINT NOT NULL)",
                table = quote_ident(&Self::commit_table(&self.table)),
            );
            sql_query(commit_ddl).execute(&mut *conn).await?;
            Ok(())
        }

        /// One end of the window, `direction` being `ASC` for the earliest or `DESC` for the latest.
        async fn end(&self, direction: &str) -> Result<Option<PgCommitPosition>, PgOplogError> {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let sql = format!(
                "SELECT commit_lsn, ordinal FROM {table} \
                 ORDER BY commit_lsn {direction}, ordinal {direction} LIMIT 1",
                table = quote_ident(&self.table),
            );
            let rows: Vec<PositionRow> = sql_query(sql).load(&mut *conn).await?;
            Ok(rows
                .into_iter()
                .next()
                .map(|row| position_from_i64(row.commit_lsn, row.ordinal)))
        }

        /// Drop whatever the retention window no longer covers. Called by
        /// `append`, which is the only moment the window can have moved.
        async fn prune(&self) -> Result<(), PgOplogError> {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let table = quote_ident(&self.table);
            // Count-based: keep the newest `max_entries` rows, drop the rest.
            let keep = i64::try_from(self.config.max_entries).unwrap_or(i64::MAX);
            let by_count = format!(
                "DELETE FROM {table} WHERE (commit_lsn, ordinal) IN (\
                     SELECT commit_lsn, ordinal FROM {table} \
                     ORDER BY commit_lsn DESC, ordinal DESC OFFSET $1)",
            );
            sql_query(by_count)
                .bind::<BigInt, _>(keep)
                .execute(&mut *conn)
                .await?;
            // Age-based: drop rows older than the window.
            let secs = i64::try_from(self.config.max_age.as_secs()).unwrap_or(i64::MAX);
            let by_age = format!(
                "DELETE FROM {table} WHERE appended_at < now() - make_interval(secs => $1)"
            );
            sql_query(by_age)
                .bind::<BigInt, _>(secs)
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
    }

    fn pool_err<E: core::fmt::Display>(err: E) -> PgOplogError {
        PgOplogError::Pool(err.to_string())
    }

    impl Oplog for PgOplog {
        type Error = PgOplogError;

        fn is_transient(err: &PgOplogError) -> bool {
            match err {
                PgOplogError::Pool(_) => true,
                PgOplogError::Query(err) => matches!(
                    crate::reexec::diesel_failure(err),
                    crate::reexec::ReadFailure::Transient
                ),
                PgOplogError::Codec(_) | PgOplogError::LsnRange(_) => false,
            }
        }

        async fn append(&self, record: ChangeRecord) -> Result<(), PgOplogError> {
            let event_bytes = serde_json::to_vec(record.event().change())?;
            let (commit_lsn, ordinal) = position_to_i64(record.position())?;
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let sql = format!(
                "INSERT INTO {table} (commit_lsn, ordinal, table_name, op, pk, is_tombstone, event) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (commit_lsn, ordinal) DO NOTHING",
                table = quote_ident(&self.table),
            );
            sql_query(sql)
                .bind::<BigInt, _>(commit_lsn)
                .bind::<BigInt, _>(ordinal)
                .bind::<Text, _>(record.table().to_owned())
                .bind::<ChangeOpSql, _>(record.op())
                .bind::<Binary, _>(record.pk().to_vec())
                .bind::<Bool, _>(record.is_tombstone())
                .bind::<Binary, _>(event_bytes)
                .execute(&mut *conn)
                .await?;
            self.prune().await
        }

        async fn entries_since(
            &self,
            after: PgCommitPosition,
        ) -> Result<Vec<ChangeRecord>, PgOplogError> {
            let (commit_lsn, ordinal) = position_to_i64(after)?;
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let sql = format!(
                "SELECT commit_lsn, ordinal, table_name, pk, event FROM {table} \
                 WHERE (commit_lsn, ordinal) > ($1, $2) ORDER BY commit_lsn, ordinal",
                table = quote_ident(&self.table),
            );
            let rows: Vec<OplogRow> = sql_query(sql)
                .bind::<BigInt, _>(commit_lsn)
                .bind::<BigInt, _>(ordinal)
                .load(&mut *conn)
                .await?;
            rows.into_iter()
                .map(|row| {
                    let change: ChangeEvent = serde_json::from_slice(&row.event)?;
                    let position = position_from_i64(row.commit_lsn, row.ordinal);
                    Ok(ChangeRecord::new(
                        row.table_name,
                        row.pk,
                        PgChangeEvent::new(change, position),
                    ))
                })
                .collect()
        }

        async fn min_position(&self) -> Result<Option<PgCommitPosition>, PgOplogError> {
            self.end("ASC").await
        }

        async fn current_position(&self) -> Result<Option<PgCommitPosition>, PgOplogError> {
            self.end("DESC").await
        }

        async fn record_commit(&self, commit: PgCommit) -> Result<(), PgOplogError> {
            let commit_lsn = part_to_i64(commit.position().commit_lsn().0)?;
            let end_lsn = part_to_i64(commit.end_lsn().0)?;
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let table = quote_ident(&Self::commit_table(&self.table));
            let sql = format!(
                "INSERT INTO {table} (commit_lsn, end_lsn) VALUES ($1, $2) \
                 ON CONFLICT (only_row) DO UPDATE SET \
                 commit_lsn = EXCLUDED.commit_lsn, end_lsn = EXCLUDED.end_lsn \
                 WHERE {table}.end_lsn < EXCLUDED.end_lsn",
            );
            sql_query(sql)
                .bind::<BigInt, _>(commit_lsn)
                .bind::<BigInt, _>(end_lsn)
                .execute(&mut *conn)
                .await?;
            Ok(())
        }

        async fn last_commit(&self) -> Result<Option<PgCommit>, PgOplogError> {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let sql = format!(
                "SELECT commit_lsn, end_lsn FROM {table}",
                table = quote_ident(&Self::commit_table(&self.table)),
            );
            let rows: Vec<CommitRow> = sql_query(sql).load(&mut *conn).await?;
            let part = |value: i64| PgLsn(u64::try_from(value).unwrap_or(0));
            Ok(rows.into_iter().next().map(|row| {
                PgCommit::new(
                    PgCommitPosition::at_commit(part(row.commit_lsn)),
                    part(row.end_lsn),
                )
            }))
        }

        async fn forget_through(&self, through: PgCommitPosition) -> Result<(), PgOplogError> {
            let (commit_lsn, ordinal) = position_to_i64(through)?;
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let sql = format!(
                "DELETE FROM {table} WHERE (commit_lsn, ordinal) <= ($1, $2)",
                table = quote_ident(&self.table),
            );
            sql_query(sql)
                .bind::<BigInt, _>(commit_lsn)
                .bind::<BigInt, _>(ordinal)
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a failure to reach the database may pass on a second read, so the default of no never hides a missing override.
    #[test]
    fn only_an_unreachable_database_is_a_transient_log_failure() {
        use diesel::result::{DatabaseErrorKind, Error};
        let cut =
            |kind| Error::DatabaseError(kind, Box::new(String::from("the connection went away")));
        assert!(PgOplog::is_transient(&PgOplogError::Pool(
            "timed out".to_owned()
        )));
        assert!(PgOplog::is_transient(&PgOplogError::Query(cut(
            DatabaseErrorKind::ClosedConnection
        ))));
        assert!(PgOplog::is_transient(&PgOplogError::Query(cut(
            DatabaseErrorKind::UnableToSendCommand
        ))));
        assert!(!PgOplog::is_transient(&PgOplogError::Query(
            Error::NotFound
        )));
        assert!(!PgOplog::is_transient(&PgOplogError::LsnRange(u64::MAX)));
        let codec = serde_json::from_str::<u8>("not a number").expect_err("malformed");
        assert!(!PgOplog::is_transient(&PgOplogError::Codec(codec)));
    }

    /// A row of one transaction at `lsn`.
    fn at(lsn: u64) -> PgCommitPosition {
        PgCommitPosition::new(PgLsn(lsn), 1)
    }

    #[test]
    fn decision_zero_resume_always_resyncs() {
        assert_eq!(
            catchup_decision(at(0), Some(at(1)), Some(at(9))),
            CatchupDecision::FullResync,
        );
        assert_eq!(
            catchup_decision(at(0), None, None),
            CatchupDecision::FullResync
        );
    }

    #[test]
    fn decision_within_window_catches_up() {
        // Client at or after the oldest retained position replays the gap.
        assert_eq!(
            catchup_decision(at(5), Some(at(3)), Some(at(9))),
            CatchupDecision::Catchup,
        );
        assert_eq!(
            catchup_decision(at(3), Some(at(3)), Some(at(9))),
            CatchupDecision::Catchup,
        );
    }

    #[test]
    fn decision_behind_window_resyncs() {
        assert_eq!(
            catchup_decision(at(2), Some(at(3)), Some(at(9))),
            CatchupDecision::FullResync,
        );
    }

    #[test]
    fn decision_empty_log_resyncs() {
        // Never recorded, which is what every restart looks like: the log
        // cannot prove the client is current, so it must not claim to.
        assert_eq!(
            catchup_decision(at(5), None, None),
            CatchupDecision::FullResync
        );
        // Recorded then fully pruned: same answer for the same reason.
        assert_eq!(
            catchup_decision(at(5), None, Some(at(9))),
            CatchupDecision::FullResync,
        );
    }

    /// An insert of `id` into `orders` at `position`.
    fn row(id: i64, position: PgCommitPosition) -> ChangeRecord {
        use subql::ChangeEvent;
        let mut data = pg_walstream::RowData::with_capacity(1);
        data.push(
            Arc::from("id"),
            pg_walstream::ColumnValue::text(&id.to_string()),
        );
        let change = ChangeEvent::insert(
            "public",
            "orders",
            1,
            data,
            pg_walstream::Lsn::new(position.commit_lsn().0),
        );
        ChangeRecord::new(
            "orders",
            id.to_be_bytes().to_vec(),
            PgChangeEvent::new(change, position),
        )
    }

    /// Two rows of one transaction share its commit LSN, so a client holding the first still catches up the second.
    #[tokio::test]
    async fn a_cursor_at_a_transactions_first_row_replays_its_second() {
        let log = InMemoryOplog::default();
        let first = PgCommitPosition::new(PgLsn(0x100), 1);
        let second = PgCommitPosition::new(PgLsn(0x100), 2);
        log.append(row(1, first)).await.expect("append");
        log.append(row(2, second)).await.expect("append");
        let replayed: Vec<_> = log
            .entries_since(first)
            .await
            .expect("read")
            .iter()
            .map(ChangeRecord::position)
            .collect();
        assert_eq!(replayed, vec![second]);
    }

    /// A row delivered again after a failed dispatch is kept once.
    #[tokio::test]
    async fn a_row_appended_again_is_kept_once() {
        let log = InMemoryOplog::default();
        let position = PgCommitPosition::new(PgLsn(0x100), 1);
        log.append(row(1, position)).await.expect("append");
        log.append(row(1, position)).await.expect("append again");
        assert_eq!(
            log.entries_since(PgCommitPosition::before_commit(PgLsn(0)))
                .await
                .expect("read")
                .len(),
            1
        );
    }
}
