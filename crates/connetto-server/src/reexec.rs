//! The re-execution connector connetto owns, and the budget one read spends.
//!
//! R58 bounded the row snapshot with a per-tier `SET LOCAL statement_timeout`
//! (see [`snapshot`](crate::snapshot)) and the aggregate paths never got it: an
//! aggregate's seed and every re-execution triggered by a change ran a full
//! query with no time limit, on the owner pool that also carries the ingest
//! loop, the oplog, the ban store and the audit hook. So one aggregate over an
//! unindexed table could stall live delivery for every client.
//!
//! The read happens inside a connector, and subql ships one
//! (`PgAsyncDieselConnector`) for callers that want no ceilings. connetto is
//! not such a caller, so it brings its own: the same transaction shape, plus
//! the limit. The value cannot live upstream because it is per tier, and a
//! tier is whether the handshake resolved an identity, which subql does not
//! model. `docs/upstream-subql-grouped-and-reexecution-tiers.md` records the
//! same split from the other side.
//!
//! The budget travels as the connector's
//! [`AuthContext`](AsyncConnector::AuthContext), which subql passes verbatim
//! to each call, so the caller of the moment decides: a seed spends its own
//! caller's tier, and a triggered re-execution spends the shorter shared bound
//! ([`ThrottleConfig::reexec_timeout`](crate::ThrottleConfig::reexec_timeout))
//! because what it delays is the change stream rather than its owner.

use core::future::Future;
use core::time::Duration;

use diesel::sql_types::{BigInt, Double, Nullable, Text};
use diesel::{QueryResult, QueryableByName, sql_query};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use subql::PgLsn;
use subql::backend::{Postgres, ScalarKind, Value as PgValue};
use subql::reexec::{AsyncConnector, DieselBackend, ScalarRowError, Snapshot as ConnectorRead};

/// What one re-execution read may spend, passed per call.
///
/// One number today. It is a struct rather than a bare [`Duration`] because
/// R58's other two read limits (the page budget and the row ceiling) belong to
/// a row read that returns rows, and the shapes this connector serves return
/// one value or one row of values, so the ceilings that would join it here are
/// the ones the grouped and per-viewer tiers bring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadBudget {
    /// Wall-clock ceiling on this read, enforced by Postgres itself.
    pub timeout: Duration,
}

impl ReadBudget {
    /// A budget of `timeout`.
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

/// Whether a connector failure was the read exceeding the budget connetto set.
///
/// The distinction is load-bearing rather than cosmetic: a failure is an outage
/// and retrying it can succeed, while a timeout is policy, so retrying it
/// replaces nothing and the subscription ends instead (R81 decision 3, the
/// split R58 introduced for the row path). Asking the connector's own error
/// type keeps the classification where the limit was set.
pub trait TimedOutRead {
    /// Whether this failure is the read running past its budget.
    fn timed_out(&self) -> bool;
}

/// A read this connector could not complete.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// No connection was available from the pool.
    #[error("the connection pool refused a connection: {0}")]
    Pool(String),
    /// Postgres cancelled the read at the budget connetto set.
    #[error("the read ran past its {0:?} budget")]
    TimedOut(Duration),
    /// The read reached the database and failed there.
    #[error("the read failed: {0}")]
    Backend(String),
    /// Row-returning re-execution has no producer yet: subql captures no such
    /// query at the pinned revision, so nothing can call this. It arrives with
    /// the grouped and re-execution tiers (R82), whose rows need the catalog
    /// wire types the snapshot path reads, not a scalar decode.
    #[error("row-returning re-execution is not built (R82)")]
    RowsUnbuilt,
}

impl TimedOutRead for ReadError {
    fn timed_out(&self) -> bool {
        matches!(self, Self::TimedOut(_))
    }
}

/// A connector that cannot time out because it never reaches a database.
impl TimedOutRead for std::io::Error {
    fn timed_out(&self) -> bool {
        false
    }
}

/// A source that cannot fail cannot have timed out.
impl TimedOutRead for core::convert::Infallible {
    fn timed_out(&self) -> bool {
        match *self {}
    }
}

/// A source whose error is only its text says nothing about a limit.
impl TimedOutRead for String {
    fn timed_out(&self) -> bool {
        false
    }
}

impl TimedOutRead for crate::snapshot::SnapshotError {
    fn timed_out(&self) -> bool {
        matches!(self, Self::TimedOut(_))
    }
}

/// Whether a diesel error is Postgres cancelling a statement at its timeout.
///
/// By message, because the SQLSTATE is dropped on the way here: `diesel-async`
/// maps every code it does not name to `DatabaseErrorKind::Unknown` and its
/// `DatabaseErrorInformation` exposes no code, so 57014 (`query_canceled`)
/// arrives indistinguishable from any other unnamed error except by its text.
/// Postgres spells a cancellation's cause in that text, and a user request
/// (which connetto never issues) spells a different one.
pub(crate) fn is_statement_timeout(err: &diesel::result::Error) -> bool {
    matches!(err, diesel::result::Error::DatabaseError(_, info)
        if info.message().contains("statement timeout"))
}

/// One scalar read back as a nullable integer.
#[derive(QueryableByName)]
struct IntRow {
    #[diesel(sql_type = Nullable<BigInt>)]
    v: Option<i64>,
}

/// One scalar read back as a nullable double.
#[derive(QueryableByName)]
struct FloatRow {
    #[diesel(sql_type = Nullable<Double>)]
    v: Option<f64>,
}

/// One scalar read back as nullable text, which every non-numeric kind travels
/// as so a decimal keeps its precision.
#[derive(QueryableByName)]
struct TextRow {
    #[diesel(sql_type = Nullable<Text>)]
    v: Option<String>,
}

/// The current WAL position, so a value and the position it was read at agree.
#[derive(QueryableByName)]
struct LsnRow {
    #[diesel(sql_type = Text)]
    lsn: String,
}

/// Read one value back as the type its [`ScalarKind`] decodes through.
///
/// The kind is coarse: `Int` covers every Postgres integer width, so
/// `MIN(int_column)` returns `int4` where the decode reads `int8`, and
/// `SUM(bigint_column)` returns `numeric` where it reads a float. The width is
/// not knowable from the kind, so the read asks Postgres for the one the decode
/// wants. A single-column derived table takes a column alias, which is what
/// lets this wrap a query whose own projection has no name to reuse.
///
/// The wrap costs nothing: Postgres flattens it (measured under R58 decision 6).
fn as_decoded(sql: &str, kind: ScalarKind) -> Option<String> {
    let cast = match kind {
        ScalarKind::Int => "BIGINT",
        ScalarKind::Float => Postgres::double_cast_type(),
        _ => return None,
    };
    Some(format!(
        "SELECT CAST(v AS {cast}) AS v FROM ({sql}) AS agg_read(v)"
    ))
}

/// Route the projected column through the row shape that matches `kind`, then
/// lift it into a subql value.
async fn load_scalar(
    conn: &mut AsyncPgConnection,
    sql: &str,
    kind: ScalarKind,
) -> QueryResult<PgValue<Postgres>> {
    let widened = as_decoded(sql, kind);
    let sql = widened.as_deref().unwrap_or(sql);
    let value = match kind {
        ScalarKind::Int => sql_query(sql)
            .get_result::<IntRow>(conn)
            .await?
            .v
            .map_or(PgValue::Null, Postgres::value_from_i64),
        ScalarKind::Float => sql_query(sql)
            .get_result::<FloatRow>(conn)
            .await?
            .v
            .map_or(PgValue::Null, Postgres::value_from_f64),
        ScalarKind::Bool
        | ScalarKind::String
        | ScalarKind::Bytes
        | ScalarKind::Uuid
        | ScalarKind::Timestamp
        | ScalarKind::TimestampTz
        | ScalarKind::Date
        | ScalarKind::Time
        | ScalarKind::Decimal
        | ScalarKind::Json
        | ScalarKind::Jsonb => sql_query(sql)
            .get_result::<TextRow>(conn)
            .await?
            .v
            .map_or(PgValue::Null, Postgres::value_from_string),
    };
    Ok(value)
}

/// Read the position this transaction's snapshot sits at.
async fn read_lsn(conn: &mut AsyncPgConnection) -> QueryResult<Option<PgLsn>> {
    let row: LsnRow = sql_query("SELECT pg_current_wal_lsn()::text AS lsn")
        .get_result(conn)
        .await?;
    Ok(PgLsn::parse(&row.lsn))
}

/// The value Postgres accepts for `statement_timeout`, in milliseconds, for a
/// read that must be bounded.
///
/// Both ends matter and both ends are traps. Zero means no limit at all to
/// Postgres, which is the opposite of a spent budget, so the floor is one
/// millisecond. The setting is a signed 32-bit integer, so a budget past about
/// 24 days is outside its range and Postgres refuses the `SET` itself, failing
/// every read underneath a limit meant to be generous, so the ceiling clamps
/// rather than refuses.
pub(crate) fn statement_timeout_ms(budget: Duration) -> u32 {
    let ceiling = u128::try_from(i32::MAX).unwrap_or(u128::MAX);
    u32::try_from(budget.as_millis().clamp(1, ceiling)).unwrap_or(u32::MAX)
}

/// Give the rest of this transaction `left` to finish in.
async fn set_read_timeout(conn: &mut AsyncPgConnection, left: Duration) -> QueryResult<()> {
    let timeout_ms = statement_timeout_ms(left);
    sql_query(format!("SET LOCAL statement_timeout = {timeout_ms}"))
        .execute(conn)
        .await?;
    Ok(())
}

/// The statements every read of this connector opens with: a read-only
/// repeatable-read snapshot so the value and its position agree, then the
/// caller's time limit.
///
/// Both are `SET LOCAL`, so they last exactly as long as the transaction and
/// leave nothing behind on a pooled connection the ingest loop takes next.
async fn open_read(conn: &mut AsyncPgConnection, budget: ReadBudget) -> QueryResult<()> {
    sql_query("SET TRANSACTION READ ONLY ISOLATION LEVEL REPEATABLE READ")
        .execute(conn)
        .await?;
    set_read_timeout(conn, budget.timeout).await
}

/// An [`AsyncConnector`] over a `bb8` pool that bounds every read it runs.
///
/// The pool is connetto's own, which is what makes the limit connetto's to set.
pub struct PgReadConnector {
    pool: Pool<AsyncPgConnection>,
}

impl PgReadConnector {
    /// Read through `pool`, bounding each read by the budget its caller passes.
    #[must_use]
    pub const fn new(pool: Pool<AsyncPgConnection>) -> Self {
        Self { pool }
    }

    /// Classify a diesel failure against the budget that produced it.
    fn failed(err: &diesel::result::Error, budget: ReadBudget) -> ReadError {
        if is_statement_timeout(err) {
            ReadError::TimedOut(budget.timeout)
        } else {
            ReadError::Backend(err.to_string())
        }
    }
}

#[allow(clippy::manual_async_fn)]
impl AsyncConnector for PgReadConnector {
    type AuthContext = ReadBudget;
    type Error = ReadError;
    type Checkpoint = PgLsn;
    type Backend = Postgres;

    fn execute_scalar(
        &self,
        sql: &str,
        kind: ScalarKind,
        budget: &ReadBudget,
    ) -> impl Future<Output = Result<(PgValue<Postgres>, Option<PgLsn>), ReadError>> + Send {
        let sql = sql.to_owned();
        let budget = *budget;
        async move {
            let mut pooled = self
                .pool
                .get()
                .await
                .map_err(|err| ReadError::Pool(err.to_string()))?;
            let conn: &mut AsyncPgConnection = &mut pooled;
            conn.transaction::<(PgValue<Postgres>, Option<PgLsn>), diesel::result::Error, _>(|c| {
                async move {
                    open_read(c, budget).await?;
                    let value = load_scalar(c, &sql, kind).await?;
                    let lsn = read_lsn(c).await?;
                    Ok((value, lsn))
                }
                .scope_boxed()
            })
            .await
            .map_err(|err| Self::failed(&err, budget))
        }
    }

    fn execute_scalar_row(
        &self,
        sql: &str,
        kinds: &[ScalarKind],
        budget: &ReadBudget,
    ) -> impl Future<
        Output = Result<(Vec<PgValue<Postgres>>, Option<PgLsn>), ScalarRowError<ReadError>>,
    > + Send {
        let sql = sql.to_owned();
        let kinds = kinds.to_vec();
        let budget = *budget;
        async move {
            let mut pooled = self
                .pool
                .get()
                .await
                .map_err(|err| ScalarRowError::Connector(ReadError::Pool(err.to_string())))?;
            let conn: &mut AsyncPgConnection = &mut pooled;
            conn.transaction::<(Vec<PgValue<Postgres>>, Option<PgLsn>), diesel::result::Error, _>(
                |c| {
                    async move {
                        let started = std::time::Instant::now();
                        open_read(c, budget).await?;
                        // One component per column, all under the one snapshot,
                        // so a seed's components answer the same moment. The
                        // inner query names its columns `c0` onward; the width
                        // each kind decodes through is `load_scalar`'s to fix.
                        //
                        // `statement_timeout` bounds one statement and a seed is
                        // several, so each component is given what is left of the
                        // budget rather than a fresh copy of it: otherwise a
                        // three-component seed could spend three times the limit.
                        // A budget already spent asks for a millisecond and lets
                        // Postgres cancel, so a refusal always arrives as the
                        // database's own and is classified the one way.
                        let mut out = Vec::with_capacity(kinds.len());
                        for (i, kind) in kinds.iter().enumerate() {
                            if i > 0 {
                                let left = budget.timeout.saturating_sub(started.elapsed());
                                set_read_timeout(c, left).await?;
                            }
                            let component = format!("SELECT c{i} AS v FROM ({sql}) AS agg_seed");
                            out.push(load_scalar(c, &component, *kind).await?);
                        }
                        let lsn = read_lsn(c).await?;
                        Ok((out, lsn))
                    }
                    .scope_boxed()
                },
            )
            .await
            .map_err(|err| ScalarRowError::Connector(Self::failed(&err, budget)))
        }
    }

    fn execute_rows(
        &self,
        _sql: &str,
        _budget: &ReadBudget,
    ) -> impl Future<Output = Result<ConnectorRead<Vec<Vec<PgValue<Postgres>>>, PgLsn>, ReadError>> + Send
    {
        async { Err(ReadError::RowsUnbuilt) }
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, statement_timeout_ms};

    /// The floor is the one that would fail silently: `statement_timeout = 0`
    /// is Postgres for "no limit", so a budget already spent would buy an
    /// unbounded read, which is the failure this phase exists to remove.
    #[test]
    fn a_spent_budget_asks_for_a_millisecond_rather_than_for_no_limit() {
        assert_eq!(statement_timeout_ms(Duration::ZERO), 1);
        assert_eq!(statement_timeout_ms(Duration::from_micros(1)), 1);
    }

    #[test]
    fn an_ordinary_budget_travels_as_its_own_milliseconds() {
        assert_eq!(statement_timeout_ms(Duration::from_millis(250)), 250);
        assert_eq!(statement_timeout_ms(Duration::from_secs(30)), 30_000);
    }

    /// A budget past the setting's range is clamped, because Postgres refuses
    /// the `SET` itself and that would fail every read under a limit the
    /// deployment meant to be generous.
    #[test]
    fn a_budget_past_the_settings_range_is_clamped_to_it() {
        let ceiling = u32::try_from(i32::MAX).expect("the setting's own maximum");
        assert_eq!(statement_timeout_ms(Duration::MAX), ceiling);
        assert_eq!(
            statement_timeout_ms(Duration::from_secs(60 * 60 * 24 * 365)),
            ceiling
        );
    }
}
