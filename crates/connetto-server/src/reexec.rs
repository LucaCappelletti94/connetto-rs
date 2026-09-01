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
//! one statement its ceilings need today, the timeout, and is where the R85
//! per-viewer identity (`set_config('app.user_id', ...)`) will ride later.
//! The value cannot live upstream because it is per tier, and a tier is
//! whether the handshake resolved an identity, which subql does not model.
//!
//! The setup travels as the connector's `AuthContext`, stored per registered
//! subscription and passed verbatim to each call, so the caller of the moment
//! decides: a fold's seed spends its own caller's tier, and everything the
//! engine drives spends the shorter shared bound
//! ([`ThrottleConfig::reexec_timeout`](crate::ThrottleConfig::reexec_timeout))
//! because what it delays is the change stream rather than its owner.

use core::future::Future;
use core::time::Duration;

use subql::PgLsn;
use subql::backend::{BuiltinKind, Postgres, Value as PgValue};
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

/// Whether a connector failure was the read exceeding the budget connetto set.
///
/// The distinction is load-bearing rather than cosmetic: a failure is an outage
/// and retrying it can succeed, while a timeout is policy, so retrying it
/// replaces nothing and the subscription ends instead (R81 decision 3, the
/// split R58 introduced for the row path). Asking the connector's own error
/// type keeps the classification where the limit was set.
pub trait TimedOutRead {
    /// `true` when this failure is Postgres cancelling at the set limit.
    fn timed_out(&self) -> bool;
}

/// The shipped connector's failure: a timeout is the database cancelling the
/// statement at the limit the setup installed.
impl TimedOutRead for DieselAsyncError {
    fn timed_out(&self) -> bool {
        match self {
            Self::Diesel(err) => is_statement_timeout(err),
            _ => false,
        }
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

#[allow(clippy::manual_async_fn)]
impl AsyncConnector for NoConnector {
    type AuthContext = ConnettoReadSetup;
    type Error = std::io::Error;
    type Checkpoint = PgLsn;
    type Backend = Postgres;

    fn execute_scalar(
        &self,
        _query: &ReadQuery<'_, Postgres>,
        _kind: BuiltinKind,
        _setup: &ConnettoReadSetup,
    ) -> impl Future<Output = Result<(PgValue<Postgres>, Option<PgLsn>), std::io::Error>> + Send
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
    ) -> impl Future<Output = Result<Snapshot<RowPage<Postgres>, PgLsn>, std::io::Error>> + Send
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
    use super::{ConnettoReadSetup, Duration, ReadBudget, SessionSetup, statement_timeout_ms};

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
}
