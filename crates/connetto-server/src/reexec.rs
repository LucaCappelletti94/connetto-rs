//! The read budget one re-execution spends, and the session setup that
//! carries it into subql's shipped connector.
//!
//! R58 bounded the row snapshot with a per-tier `SET LOCAL statement_timeout`
//! (see [`snapshot`](crate::snapshot)) and the aggregate paths never got it: an
//! aggregate's seed and every re-execution triggered by a change ran a full
//! query with no time limit, on the owner pool that also carries the ingest
//! loop, the oplog, the ban store and the audit hook. So one aggregate over an
//! unindexed table could stall live delivery for every client.
//!
//! subql's `PgAsyncDieselConnector` runs the reads (the scalar and seed
//! shapes, budgeted pages, and the held cursors a whole-answer read needs) and
//! takes a [`SessionSetup`] whose statements run inside every transaction it
//! opens, the cursor's held transaction included. connetto's setup carries the
//! one statement its ceilings need today, the timeout, and the R85 per-viewer
//! binding rides beside it, the identity and the packed subjects the caller
//! holds. The timeout cannot live upstream because it is per tier, and a tier
//! is whether the handshake resolved an identity, which subql does not model.
//!
//! The setup travels as the connector's `AuthContext`, stored per registered
//! subscription and passed verbatim to each call, so the caller of the moment
//! decides: a fold's seed spends its own caller's tier, and everything the
//! engine drives spends the shorter shared bound
//! ([`ThrottleConfig::reexec_timeout`](crate::ThrottleConfig::reexec_timeout))
//! because what it delays is the change stream rather than its owner.

use core::future::Future;
use core::time::Duration;

use subql::PgCommitPosition;
use subql::backend::{Postgres, ScalarFamily, Value as PgValue};
use subql::reexec::{
    AsyncConnector, DieselAsyncError, PgAsyncDieselConnector, ReadQuery, RowPage, SessionSetup,
    Snapshot,
};

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

/// The transaction-scoped statements connetto's reads run under, rendered
/// once per registration and handed to the connector as its auth context.
///
/// Today one statement, the budget's `SET LOCAL statement_timeout`. `SET
/// LOCAL` lasts exactly as long as the transaction and leaves nothing behind
/// on a pooled connection the ingest loop takes next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnettoReadSetup {
    statements: Vec<String>,
}

impl ConnettoReadSetup {
    /// The setup enforcing `budget`.
    #[must_use]
    pub fn of(budget: ReadBudget) -> Self {
        let timeout_ms = statement_timeout_ms(budget.timeout);
        Self {
            statements: vec![format!("SET LOCAL statement_timeout = {timeout_ms}")],
        }
    }

    /// The same setup with `extra` statements appended, in order, after the
    /// budget. This is where a per-viewer registration's caller binding rides
    /// (R85): the statements run inside every transaction the connector opens
    /// for the subscription, so each of its reads answers as that viewer.
    #[must_use]
    pub fn with_statements(mut self, extra: Vec<String>) -> Self {
        self.statements.extend(extra);
        self
    }
}

impl From<ReadBudget> for ConnettoReadSetup {
    fn from(budget: ReadBudget) -> Self {
        Self::of(budget)
    }
}

impl SessionSetup for ConnettoReadSetup {
    fn setup_statements(&self) -> &[String] {
        &self.statements
    }
}

/// The connector connetto hands the engine and the session: subql's shipped
/// async Postgres connector carrying connetto's setup. An alias rather than a
/// wrapper, because the seam made the downstream reimplementation deletable.
pub type PgReadConnector = PgAsyncDieselConnector<ConnettoReadSetup>;

/// The disposition one connector failure earns (R89 decision 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFailure {
    /// Postgres cancelled at connetto's own limit. Policy, the subscription ends at once (R81 decision 3).
    Timeout,
    /// The database or its pool was unreachable or cut off. Delivery pauses and retries in place (R89 decision 2).
    Transient,
    /// Everything unnamed, including transients whose SQLSTATE diesel drops. One retry, then the subscription ends.
    Other,
}

impl core::fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Timeout => "timeout",
            Self::Transient => "transient",
            Self::Other => "unknown",
        })
    }
}

/// The failure class of a connector error, asked where the limit and the
/// connection live.
pub trait FailedRead {
    /// The class this failure belongs to.
    fn read_failure(&self) -> ReadFailure;
}

/// upstream's `#[non_exhaustive]` forces the catch-all, so rows-unsupported
/// and future variants arrive as `Other`, the class that costs one retry and
/// no stall.
impl FailedRead for DieselAsyncError {
    fn read_failure(&self) -> ReadFailure {
        match self {
            Self::Pool(_) => ReadFailure::Transient,
            Self::Diesel(err) => diesel_failure(err),
            _ => ReadFailure::Other,
        }
    }
}

/// Bounded floor until the SQLSTATE reaches a diesel error
/// (`upstream/diesel-sqlstate-not-recoverable-from-database-error-information.md`).
/// Deadlock arrives as `Unknown`, so it classifies as `Other`, one retry rather than an outage loop.
pub(crate) fn diesel_failure(err: &diesel::result::Error) -> ReadFailure {
    use diesel::result::{DatabaseErrorKind, Error};
    if is_statement_timeout(err) {
        return ReadFailure::Timeout;
    }
    match err {
        Error::DatabaseError(
            DatabaseErrorKind::SerializationFailure
            | DatabaseErrorKind::ReadOnlyTransaction
            | DatabaseErrorKind::ClosedConnection
            | DatabaseErrorKind::UnableToSendCommand,
            _,
        ) => ReadFailure::Transient,
        _ => ReadFailure::Other,
    }
}

impl FailedRead for std::io::Error {
    fn read_failure(&self) -> ReadFailure {
        ReadFailure::Other
    }
}

impl FailedRead for core::convert::Infallible {
    fn read_failure(&self) -> ReadFailure {
        match *self {}
    }
}

impl FailedRead for String {
    fn read_failure(&self) -> ReadFailure {
        ReadFailure::Other
    }
}

impl FailedRead for crate::snapshot::SnapshotError {
    fn read_failure(&self) -> ReadFailure {
        match self {
            Self::TimedOut(_) => ReadFailure::Timeout,
            _ => ReadFailure::Other,
        }
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

/// An [`AsyncConnector`] that fails every call: the default when a manager runs
/// no re-execution backend, appropriate when no computed subscriptions exist.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoConnector;

#[expect(
    clippy::manual_async_fn,
    reason = "the trait names the future type so the Send bound is stated on the signature"
)]
impl AsyncConnector for NoConnector {
    type AuthContext = ConnettoReadSetup;
    type Error = std::io::Error;
    type Checkpoint = PgCommitPosition;
    type Backend = Postgres;

    fn execute_scalar(
        &self,
        _query: &ReadQuery<'_, Postgres>,
        _kind: ScalarFamily,
        _setup: &ConnettoReadSetup,
    ) -> impl Future<Output = Result<(PgValue<Postgres>, Option<PgCommitPosition>), std::io::Error>> + Send
    {
        async {
            Err(std::io::Error::other(
                "no re-execution connector configured",
            ))
        }
    }

    fn read_page(
        &self,
        _query: &ReadQuery<'_, Postgres>,
        _max_bytes: usize,
        _setup: &ConnettoReadSetup,
    ) -> impl Future<Output = Result<Snapshot<RowPage<Postgres>, PgCommitPosition>, std::io::Error>> + Send
    {
        async {
            Err(std::io::Error::other(
                "no re-execution connector configured",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConnettoReadSetup, Duration, FailedRead, ReadBudget, ReadFailure, SessionSetup,
        statement_timeout_ms,
    };
    use diesel::result::{DatabaseErrorKind, Error};
    use subql::reexec::DieselAsyncError;

    /// The floor is the one that would fail silently: `statement_timeout = 0`
    /// is Postgres for "no limit", so a budget already spent would buy an
    /// unbounded read, which is the failure this phase exists to remove.
    #[test]
    fn a_spent_budget_still_sets_a_limit() {
        assert_eq!(statement_timeout_ms(Duration::ZERO), 1);
        assert_eq!(statement_timeout_ms(Duration::from_millis(250)), 250);
    }

    /// The ceiling clamps rather than refuses: a value Postgres cannot accept
    /// would fail every read underneath a limit meant to be generous.
    #[test]
    fn an_oversized_budget_clamps_to_what_postgres_accepts() {
        let clamped = statement_timeout_ms(Duration::from_secs(u64::MAX / 4));
        assert_eq!(clamped, u32::try_from(i32::MAX).expect("positive"));
    }

    /// The setup renders the budget as the one transaction-scoped statement
    /// the connector runs before the read.
    #[test]
    fn the_setup_carries_the_timeout_statement() {
        let setup = ConnettoReadSetup::of(ReadBudget::new(Duration::from_millis(1500)));
        assert_eq!(
            setup.setup_statements(),
            ["SET LOCAL statement_timeout = 1500".to_owned()]
        );
    }

    /// Stands in for a diesel database error once the SQLSTATE is dropped, `String` being diesel's own information type.
    fn db_error(kind: DatabaseErrorKind, message: &str) -> Error {
        Error::DatabaseError(kind, Box::new(message.to_owned()))
    }

    /// A pool that cannot hand out a connection is an outage, not an unknown.
    #[test]
    fn pool_exhaustion_is_transient() {
        let err = DieselAsyncError::Pool(diesel_async::pooled_connection::bb8::RunError::TimedOut);
        assert_eq!(err.read_failure(), ReadFailure::Transient);
    }

    #[test]
    fn the_statement_cancellation_text_is_the_timeout_class() {
        let err = DieselAsyncError::Diesel(db_error(
            DatabaseErrorKind::Unknown,
            "canceling statement due to statement timeout",
        ));
        assert_eq!(err.read_failure(), ReadFailure::Timeout);
    }

    /// A user cancellation spells a different cause in the same sentence.
    #[test]
    fn a_user_cancellation_is_not_the_timeout_class() {
        let err = DieselAsyncError::Diesel(db_error(
            DatabaseErrorKind::Unknown,
            "canceling statement due to user request",
        ));
        assert_eq!(err.read_failure(), ReadFailure::Other);
    }

    /// The outage kinds diesel-async names, `ReadOnlyTransaction` being the standby recovery conflict.
    #[test]
    fn the_named_outage_kinds_are_transient() {
        for kind in [
            DatabaseErrorKind::SerializationFailure,
            DatabaseErrorKind::ReadOnlyTransaction,
            DatabaseErrorKind::ClosedConnection,
            DatabaseErrorKind::UnableToSendCommand,
        ] {
            let err = DieselAsyncError::Diesel(db_error(kind, "whatever the server said"));
            assert_eq!(
                err.read_failure(),
                ReadFailure::Transient,
                "for kind {kind:?}"
            );
        }
    }

    /// A dropped view arrives as `Unknown`, the poisoned query that must cost one retry and end.
    #[test]
    fn unnamed_database_errors_are_other() {
        let dropped_view = DieselAsyncError::Diesel(db_error(
            DatabaseErrorKind::Unknown,
            "relation \"v\" does not exist",
        ));
        assert_eq!(dropped_view.read_failure(), ReadFailure::Other);
        let syntax = DieselAsyncError::Diesel(Error::QueryBuilderError(Box::new(
            std::io::Error::other("nope"),
        )));
        assert_eq!(syntax.read_failure(), ReadFailure::Other);
    }

    /// Constraint violations are deterministic refusals of the query.
    #[test]
    fn constraint_violations_are_other() {
        let err = DieselAsyncError::Diesel(db_error(
            DatabaseErrorKind::UniqueViolation,
            "duplicate key value violates unique constraint",
        ));
        assert_eq!(err.read_failure(), ReadFailure::Other);
    }

    /// Configuration refusals clear no retry.
    #[test]
    fn configuration_refusals_are_other() {
        assert_eq!(
            DieselAsyncError::RowsUnsupported.read_failure(),
            ReadFailure::Other
        );
        let err = std::io::Error::other("no re-execution connector configured");
        assert_eq!(err.read_failure(), ReadFailure::Other);
        assert_eq!("boom".to_owned().read_failure(), ReadFailure::Other);
    }

    /// The snapshot path keeps its own timeout marker and classifies with it.
    #[test]
    fn the_snapshot_timeout_keeps_the_timeout_class() {
        let timed_out = crate::snapshot::SnapshotError::TimedOut(Duration::from_millis(1));
        assert_eq!(timed_out.read_failure(), ReadFailure::Timeout);
    }
}
