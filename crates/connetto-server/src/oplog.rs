//! Retention-bounded, LSN-keyed oplog and the reconnect catchup decision.
//!
//! The oplog is an ordered log of [`ChangeRecord`]s keyed by their source LSN.
//! On reconnect the server replays the records a client missed instead of
//! re-snapshotting, falling back to a full snapshot only when the client's
//! resume position has fallen outside the retained window. Deletes are kept as
//! tombstones so they replay too.
//!
//! [`Oplog`] is the seam, shaped like
//! [`SnapshotSource`](crate::session::SnapshotSource): an async, `Send + Sync`
//! trait. [`InMemoryOplog`] is the ring-buffer test double. [`PgOplog`] is the
//! production target, a Postgres table so every
//! node in the mesh sees the same log (`06-reconnect.md` line 163).
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
use subql::{ChangeEvent, ClockHandle, EventKind, StdClock};

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

/// One change retained in the oplog, keyed by its source LSN.
///
/// The [`ChangeEvent`] is the source of truth replayed on catchup: catchup runs
/// it back through the same matching and patchset encoding the live path uses.
/// The table name and primary-key bytes are resolved once at append time (they
/// need the catalog, which the oplog impls do not carry) so the auth read filter
/// on the catchup path has them without a second catalog pass.
#[derive(Debug, Clone)]
pub struct ChangeRecord {
    lsn: u64,
    table: String,
    pk: Vec<u8>,
    event: ChangeEvent,
}

impl ChangeRecord {
    /// Build a record from its resolved parts.
    ///
    /// `event` must be a row DML event (Insert, Update, Delete, or Truncate);
    /// the dispatch path only appends such events, since a non-row event never
    /// reaches a successful dispatch. [`op`](Self::op) and
    /// [`is_tombstone`](Self::is_tombstone) rely on that invariant.
    #[must_use]
    pub fn new(lsn: u64, table: impl Into<String>, pk: Vec<u8>, event: ChangeEvent) -> Self {
        Self {
            lsn,
            table: table.into(),
            pk,
            event,
        }
    }

    /// The source LSN, the oplog key. The opaque wire cursor is this value
    /// big-endian.
    #[must_use]
    pub const fn lsn(&self) -> u64 {
        self.lsn
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
    pub const fn event(&self) -> &ChangeEvent {
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

/// A retention-bounded, LSN-keyed log of [`ChangeRecord`]s.
///
/// The seam the session layer appends to on every dispatched event and reads
/// from on reconnect. Shaped like [`SnapshotSource`](crate::session::SnapshotSource):
/// async, `Send + Sync`, one associated error.
#[allow(async_fn_in_trait)]
pub trait Oplog: Send + Sync {
    /// Oplog-source error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// Append one record, then drop whatever the retention window no longer
    /// covers. Pruning is not a separate seam: an external caller would race
    /// the append it belongs to.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backing-store write failure.
    async fn append(&self, record: ChangeRecord) -> Result<(), Self::Error>;

    /// Records with an LSN strictly greater than `lsn`, in ascending LSN order.
    ///
    /// The client already applied `lsn`, so catchup replays everything after it.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backing-store read failure.
    async fn entries_since(&self, lsn: u64) -> Result<Vec<ChangeRecord>, Self::Error>;

    /// The smallest retained LSN, or `None` when the log holds no entries.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backing-store read failure.
    async fn min_lsn(&self) -> Result<Option<u64>, Self::Error>;

    /// The server's current LSN watermark: the highest LSN ever appended. It
    /// does not decrease when the window prunes, so it names the server's live
    /// position. `None` when nothing has been appended.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backing-store read failure.
    async fn current_lsn(&self) -> Result<Option<u64>, Self::Error>;

    /// Drop every record at or below `lsn`, because continuity across it can no
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
    async fn forget_through(&self, lsn: u64) -> Result<(), Self::Error>;
}

/// Decide whether a client resuming from `resume_lsn` can catch up from the
/// oplog, given its `min_lsn` (smallest retained) and `current_lsn` (watermark).
///
/// `true` replays the gap; `false` forces a full resync. The rule:
///
/// * `resume_lsn == 0` (never synced) always resyncs.
/// * A non-empty log replays when `resume_lsn >= min_lsn`: everything the client
///   is missing (LSNs greater than `resume_lsn`) is then retained. The check is
///   deliberately conservative at the exact boundary, favoring a full resync
///   over a replay it cannot prove complete.
/// * An empty log resyncs, whichever kind of empty it is. Nothing in it can
///   prove the client has everything, and a log that has recorded nothing is
///   most often a process that has just started rather than a world in which
///   nothing happened. Reading it the other way lost data on every restart,
///   silently, because the shipped binary keeps the log in memory (R32).
#[must_use]
pub fn catchup_decision(
    resume_lsn: u64,
    min_lsn: Option<u64>,
    current_lsn: Option<u64>,
) -> CatchupDecision {
    if resume_lsn == 0 {
        return CatchupDecision::FullResync;
    }
    match (min_lsn, current_lsn) {
        // Non-empty log: replay when the client sits at or after the oldest
        // retained entry, so nothing it is missing has been pruned.
        (Some(min), _) => {
            if resume_lsn >= min {
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
    /// Replay the oplog gap since the client's resume LSN.
    Catchup,
    /// The resume LSN is outside the retained window: send a full snapshot.
    FullResync,
}

/// One retained entry plus the clock reading taken when it was appended.
struct Entry {
    appended_micros: u64,
    record: ChangeRecord,
}

/// Mutable interior of an [`InMemoryOplog`].
struct Inner {
    /// Entries ordered by ascending LSN (equivalently, ascending append time).
    entries: VecDeque<Entry>,
    /// Highest LSN ever appended. Monotone: never lowered by pruning.
    max_lsn: Option<u64>,
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
                max_lsn: None,
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

    #[allow(clippy::unused_async_trait_impl)]
    async fn append(&self, record: ChangeRecord) -> Result<(), Infallible> {
        let now = self.clock.now_micros();
        let mut inner = self.inner.lock();
        let lsn = record.lsn();
        inner.max_lsn = Some(inner.max_lsn.map_or(lsn, |prev| prev.max(lsn)));
        inner.entries.push_back(Entry {
            appended_micros: now,
            record,
        });
        self.prune_locked(&mut inner, now);
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn entries_since(&self, lsn: u64) -> Result<Vec<ChangeRecord>, Infallible> {
        let inner = self.inner.lock();
        Ok(inner
            .entries
            .iter()
            .filter(|entry| entry.record.lsn() > lsn)
            .map(|entry| entry.record.clone())
            .collect())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn min_lsn(&self) -> Result<Option<u64>, Infallible> {
        let inner = self.inner.lock();
        Ok(inner.entries.front().map(|entry| entry.record.lsn()))
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn current_lsn(&self) -> Result<Option<u64>, Infallible> {
        Ok(self.inner.lock().max_lsn)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn forget_through(&self, lsn: u64) -> Result<(), Infallible> {
        self.inner.lock().entries.retain(|e| e.record.lsn() > lsn);
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
    use subql::ChangeEvent;

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
        /// An LSN did not fit the signed BIGINT column. Real `pg_lsn` values are
        /// far below this bound, so this signals corruption or a bad write.
        #[error("oplog lsn {0} is out of BIGINT range")]
        LsnRange(u64),
    }

    /// A Postgres-table [`Oplog`], the production target.
    ///
    /// The log is a single table so every node in the mesh reads the same
    /// history (`06-reconnect.md` line 163). The row image plus routing metadata
    /// (`table_name`, `op`, `pk`, `is_tombstone`) are stored as typed columns for
    /// indexing and observability, and the full [`ChangeEvent`] is stored as a
    /// serialized blob so catchup replays it losslessly.
    pub struct PgOplog {
        pool: Pool<diesel_async::AsyncPgConnection>,
        table: String,
        config: OplogConfig,
    }

    /// A row read back from the oplog table.
    #[derive(QueryableByName)]
    struct OplogRow {
        #[diesel(sql_type = BigInt)]
        lsn: i64,
        #[diesel(sql_type = Text)]
        table_name: String,
        #[diesel(sql_type = Binary)]
        pk: Vec<u8>,
        #[diesel(sql_type = Binary)]
        event: Vec<u8>,
    }

    /// A single scalar LSN read back from an aggregate query.
    #[derive(QueryableByName)]
    struct LsnRow {
        #[diesel(sql_type = diesel::sql_types::Nullable<BigInt>)]
        lsn: Option<i64>,
    }

    /// Widen an LSN into the signed BIGINT column. `pg_lsn` values fit i64, so an
    /// overflow is corruption, surfaced rather than silently wrapped.
    fn lsn_to_i64(lsn: u64) -> Result<i64, PgOplogError> {
        i64::try_from(lsn).map_err(|_| PgOplogError::LsnRange(lsn))
    }

    /// Read an LSN back from the signed BIGINT column.
    fn lsn_from_i64(value: i64) -> u64 {
        // The column only ever holds values written by `lsn_to_i64`, which are
        // non-negative, so this widening is lossless.
        u64::try_from(value).unwrap_or(0)
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

        /// Create the `op` enum type and the oplog table if either is absent.
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
                     lsn BIGINT PRIMARY KEY, \
                     table_name TEXT NOT NULL, \
                     op {CHANGE_OP_TYPE} NOT NULL, \
                     pk BYTEA NOT NULL, \
                     is_tombstone BOOLEAN NOT NULL, \
                     event BYTEA NOT NULL, \
                     appended_at TIMESTAMPTZ NOT NULL DEFAULT now())",
                table = quote_ident(&self.table),
            );
            sql_query(ddl).execute(&mut *conn).await?;
            Ok(())
        }

        /// The LSN watermark from `expr` (`MIN(lsn)` or `MAX(lsn)`).
        async fn watermark(&self, expr: &str) -> Result<Option<u64>, PgOplogError> {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let sql = format!(
                "SELECT {expr} AS lsn FROM {table}",
                table = quote_ident(&self.table),
            );
            let row: LsnRow = sql_query(sql).get_result(&mut *conn).await?;
            Ok(row.lsn.map(lsn_from_i64))
        }

        /// Drop whatever the retention window no longer covers. Called by
        /// `append`, which is the only moment the window can have moved.
        async fn prune(&self) -> Result<(), PgOplogError> {
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let table = quote_ident(&self.table);
            // Count-based: keep the newest `max_entries` rows, drop the rest.
            let keep = i64::try_from(self.config.max_entries).unwrap_or(i64::MAX);
            let by_count = format!(
                "DELETE FROM {table} WHERE lsn IN (\
                     SELECT lsn FROM {table} ORDER BY lsn DESC OFFSET $1)",
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

        async fn append(&self, record: ChangeRecord) -> Result<(), PgOplogError> {
            let event_bytes = serde_json::to_vec(record.event())?;
            let lsn = lsn_to_i64(record.lsn())?;
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let sql = format!(
                "INSERT INTO {table} (lsn, table_name, op, pk, is_tombstone, event) \
                 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (lsn) DO NOTHING",
                table = quote_ident(&self.table),
            );
            sql_query(sql)
                .bind::<BigInt, _>(lsn)
                .bind::<Text, _>(record.table().to_owned())
                .bind::<ChangeOpSql, _>(record.op())
                .bind::<Binary, _>(record.pk().to_vec())
                .bind::<Bool, _>(record.is_tombstone())
                .bind::<Binary, _>(event_bytes)
                .execute(&mut *conn)
                .await?;
            self.prune().await
        }

        async fn entries_since(&self, lsn: u64) -> Result<Vec<ChangeRecord>, PgOplogError> {
            let lsn = lsn_to_i64(lsn)?;
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let sql = format!(
                "SELECT lsn, table_name, pk, event FROM {table} WHERE lsn > $1 ORDER BY lsn",
                table = quote_ident(&self.table),
            );
            let rows: Vec<OplogRow> = sql_query(sql)
                .bind::<BigInt, _>(lsn)
                .load(&mut *conn)
                .await?;
            rows.into_iter()
                .map(|row| {
                    let event: ChangeEvent = serde_json::from_slice(&row.event)?;
                    Ok(ChangeRecord::new(
                        lsn_from_i64(row.lsn),
                        row.table_name,
                        row.pk,
                        event,
                    ))
                })
                .collect()
        }

        async fn min_lsn(&self) -> Result<Option<u64>, PgOplogError> {
            self.watermark("MIN(lsn)").await
        }

        async fn current_lsn(&self) -> Result<Option<u64>, PgOplogError> {
            self.watermark("MAX(lsn)").await
        }

        async fn forget_through(&self, lsn: u64) -> Result<(), PgOplogError> {
            let lsn = lsn_to_i64(lsn)?;
            let mut conn = self.pool.get().await.map_err(pool_err)?;
            let sql = format!(
                "DELETE FROM {table} WHERE lsn <= $1",
                table = quote_ident(&self.table),
            );
            sql_query(sql)
                .bind::<BigInt, _>(lsn)
                .execute(&mut *conn)
                .await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_zero_resume_always_resyncs() {
        assert_eq!(
            catchup_decision(0, Some(1), Some(9)),
            CatchupDecision::FullResync,
        );
        assert_eq!(catchup_decision(0, None, None), CatchupDecision::FullResync);
    }

    #[test]
    fn decision_within_window_catches_up() {
        // Client at or after the oldest retained LSN replays the gap.
        assert_eq!(
            catchup_decision(5, Some(3), Some(9)),
            CatchupDecision::Catchup,
        );
        assert_eq!(
            catchup_decision(3, Some(3), Some(9)),
            CatchupDecision::Catchup,
        );
    }

    #[test]
    fn decision_behind_window_resyncs() {
        assert_eq!(
            catchup_decision(2, Some(3), Some(9)),
            CatchupDecision::FullResync,
        );
    }

    #[test]
    fn decision_empty_log_resyncs() {
        // Never recorded, which is what every restart looks like: the log
        // cannot prove the client is current, so it must not claim to.
        assert_eq!(catchup_decision(5, None, None), CatchupDecision::FullResync);
        // Recorded then fully pruned: same answer for the same reason.
        assert_eq!(
            catchup_decision(5, None, Some(9)),
            CatchupDecision::FullResync,
        );
    }
}
