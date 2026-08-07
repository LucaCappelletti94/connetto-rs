//! Abuse detection: what a caller named and was told no about.
//!
//! [`crate::throttle`] bounds how much a caller may ask for. This bounds what
//! it may ask for, by tallying the four moments where a caller names something
//! precise and is refused, and acting when a tally crosses a threshold.
//!
//! Two tiers, and they are not two allowances of one shape. A caller that
//! resolved an identity is tallied against that person over a window, because a
//! ban names a person and a session handle is minted fresh at every login. A
//! caller with no identity is tallied against its connection, because that is
//! the only thing it has and a closed socket is the only outcome available.
//!
//! Reads never count. A read denial is silent by principle 4 of
//! `docs/architecture/08-authorization.md`, happens to everyone constantly, and
//! scales with how much data exists rather than with anyone's behaviour, so
//! counting it would measure the database and ban every honest user.

use std::time::Duration;

use connetto_core::SessionId;

use crate::throttle::Limit;

/// One day, the window every per-person default uses.
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// One act of naming something precise and being told no.
///
/// A closed set of four. Connection attempts are absent because counting how
/// often somebody connects is volume, which the throttle answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    /// A share key that did not check out. Expiry, a bad signature, or the
    /// wrong issuer or audience, since a capability is checked for nothing else.
    RefusedGrant,
    /// A subscription naming a table or column that does not resolve.
    UnresolvableSubscription,
    /// A write the policy rejected.
    RejectedWrite,
    /// A session renewal refused on the credential it presented.
    ///
    /// Not a failed login: connetto never sees one, because the password is
    /// typed at the identity provider and every failure at connetto's own
    /// sign-in endpoints identifies nobody.
    FailedRenewal,
}

impl Signal {
    /// The label this signal carries in the log and in a ban's reason.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RefusedGrant => "refused_grant",
            Self::UnresolvableSubscription => "unresolvable_subscription",
            Self::RejectedWrite => "rejected_write",
            Self::FailedRenewal => "failed_renewal",
        }
    }

    /// Every signal, for iterating the thresholds.
    pub(crate) const ALL: [Self; 4] = [
        Self::RefusedGrant,
        Self::UnresolvableSubscription,
        Self::RejectedWrite,
        Self::FailedRenewal,
    ];
}

impl core::fmt::Display for Signal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}

/// How many of each signal one person may produce, and over how long.
///
/// Ordinary behaviour for all four is zero, which is what makes generous
/// numbers cheap: a correct client never names a table that does not resolve.
/// Nothing measured these, so a deployment with real traffic should expect to
/// move them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersonLimits {
    refused_grants: Limit,
    unresolvable_subscriptions: Limit,
    rejected_writes: Limit,
    failed_renewals: Limit,
}

impl Default for PersonLimits {
    fn default() -> Self {
        Self::new()
    }
}

impl PersonLimits {
    /// The shipped thresholds, per person per day.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            refused_grants: Limit::new(200, DAY),
            unresolvable_subscriptions: Limit::new(1000, DAY),
            // The loosest on purpose: it is the one signal the throttle sets no
            // ceiling above, and the one an offline queue flushes into.
            rejected_writes: Limit::new(1000, DAY),
            failed_renewals: Limit::new(100, DAY),
        }
    }

    /// How many refused share keys one person may produce per window.
    #[must_use]
    pub const fn refused_grants(mut self, max: u32, window: Duration) -> Self {
        self.refused_grants = Limit::new(max, window);
        self
    }

    /// How many subscriptions naming something that does not resolve one person
    /// may produce per window.
    #[must_use]
    pub const fn unresolvable_subscriptions(mut self, max: u32, window: Duration) -> Self {
        self.unresolvable_subscriptions = Limit::new(max, window);
        self
    }

    /// How many writes the policy rejects one person may produce per window.
    #[must_use]
    pub const fn rejected_writes(mut self, max: u32, window: Duration) -> Self {
        self.rejected_writes = Limit::new(max, window);
        self
    }

    /// How many failed session renewals one person may produce per window.
    #[must_use]
    pub const fn failed_renewals(mut self, max: u32, window: Duration) -> Self {
        self.failed_renewals = Limit::new(max, window);
        self
    }

    /// The threshold for `signal`.
    #[must_use]
    pub const fn limit(&self, signal: Signal) -> Limit {
        match signal {
            Signal::RefusedGrant => self.refused_grants,
            Signal::UnresolvableSubscription => self.unresolvable_subscriptions,
            Signal::RejectedWrite => self.rejected_writes,
            Signal::FailedRenewal => self.failed_renewals,
        }
    }
}

/// How many of each signal one connection may produce.
///
/// Three rather than four, and no window at all. A refresh token is
/// `<session>.<secret>` and so always names an account, meaning an unidentified
/// failed renewal does not exist, and the connection is the window because the
/// tally dies with the socket. Both absences are compile errors rather than
/// runtime refusals.
///
/// The numbers are far smaller than the per-person ones because the span is far
/// shorter and because being wrong here is cheap: the outcome is a closed
/// connection with no durable record, which a reconnect undoes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLimits {
    refused_grants: u32,
    unresolvable_subscriptions: u32,
    rejected_writes: u32,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionLimits {
    /// The shipped thresholds, per connection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            refused_grants: 50,
            unresolvable_subscriptions: 100,
            rejected_writes: 200,
        }
    }

    /// How many refused share keys one connection may produce.
    #[must_use]
    pub const fn refused_grants(mut self, max: u32) -> Self {
        self.refused_grants = max;
        self
    }

    /// How many subscriptions naming something that does not resolve one
    /// connection may produce.
    #[must_use]
    pub const fn unresolvable_subscriptions(mut self, max: u32) -> Self {
        self.unresolvable_subscriptions = max;
        self
    }

    /// How many writes the policy rejects one connection may produce.
    #[must_use]
    pub const fn rejected_writes(mut self, max: u32) -> Self {
        self.rejected_writes = max;
        self
    }

    /// The threshold for `signal`, absent for the one signal that always names
    /// an account.
    #[must_use]
    pub const fn limit(&self, signal: Signal) -> Option<u32> {
        match signal {
            Signal::RefusedGrant => Some(self.refused_grants),
            Signal::UnresolvableSubscription => Some(self.unresolvable_subscriptions),
            Signal::RejectedWrite => Some(self.rejected_writes),
            Signal::FailedRenewal => None,
        }
    }
}

/// The thresholds under construction, checked by [`build`](Self::build).
///
/// A chain of calls rather than a struct of public fields, because the shape is
/// nested: a count and a window per signal, across two tiers that differ in
/// shape. Deliberately not a predicate language, because a second rule language
/// beside row-level security and `OpenFGA` is the thing to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AbuseLimits {
    person: PersonLimits,
    connection: ConnectionLimits,
}

impl AbuseLimits {
    /// Start from the shipped thresholds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            person: PersonLimits::new(),
            connection: ConnectionLimits::new(),
        }
    }

    /// Replace what one person may produce.
    #[must_use]
    pub const fn person(mut self, limits: PersonLimits) -> Self {
        self.person = limits;
        self
    }

    /// Replace what one connection may produce.
    #[must_use]
    pub const fn connection(mut self, limits: ConnectionLimits) -> Self {
        self.connection = limits;
        self
    }

    /// Check the three refusals and produce the config the detector runs on.
    ///
    /// # Errors
    ///
    /// [`AbuseConfigError`] for a zero window, a zero count, or a per-connection
    /// count that is not below its matching per-person count.
    pub fn build(self) -> Result<AbuseConfig, AbuseConfigError> {
        for signal in Signal::ALL {
            let person = self.person.limit(signal);
            if person.window().is_zero() {
                return Err(AbuseConfigError::ZeroWindow { signal });
            }
            if person.max() == 0 {
                return Err(AbuseConfigError::ZeroCount {
                    tier: "person",
                    signal,
                });
            }
            let Some(connection) = self.connection.limit(signal) else {
                continue;
            };
            if connection == 0 {
                return Err(AbuseConfigError::ZeroCount {
                    tier: "connection",
                    signal,
                });
            }
            if connection >= person.max() {
                return Err(AbuseConfigError::ConnectionNotBelowPerson {
                    signal,
                    connection,
                    person: person.max(),
                });
            }
        }
        Ok(AbuseConfig {
            person: self.person,
            connection: self.connection,
        })
    }
}

/// The thresholds the detector runs on, obtainable only through
/// [`AbuseLimits::build`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbuseConfig {
    person: PersonLimits,
    connection: ConnectionLimits,
}

impl Default for AbuseConfig {
    fn default() -> Self {
        // The shipped numbers satisfy every refusal by construction.
        AbuseLimits::new()
            .build()
            .expect("the shipped abuse thresholds are valid")
    }
}

impl AbuseConfig {
    /// What one person may produce.
    #[must_use]
    pub const fn person(&self) -> &PersonLimits {
        &self.person
    }

    /// What one connection may produce.
    #[must_use]
    pub const fn connection(&self) -> &ConnectionLimits {
        &self.connection
    }

    /// The longest window any per-person tally reads, which is how long those
    /// counters must keep a key.
    pub(crate) fn person_retain(&self) -> Duration {
        Signal::ALL
            .into_iter()
            .map(|signal| self.person.limit(signal).window())
            .max()
            .unwrap_or(DAY)
    }
}

/// A threshold that cannot do the job it was written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AbuseConfigError {
    /// A window of zero resets the tally before it can reach anything, so the
    /// threshold silently never fires.
    #[error("the {signal} window is zero, so its tally resets before it can reach the threshold")]
    ZeroWindow {
        /// Which signal.
        signal: Signal,
    },
    /// A count of zero acts on the very first refusal, which is almost always a
    /// slip given the default answer is a permanent ban.
    #[error("the {tier} threshold for {signal} is zero, so the first one acts")]
    ZeroCount {
        /// Which tier, `person` or `connection`.
        tier: &'static str,
        /// Which signal.
        signal: Signal,
    },
    /// A per-connection count at or above its per-person count leaves the cheap
    /// defence unable to fire before the severe one.
    #[error(
        "the per-connection threshold for {signal} is {connection} and the per-person one is \
         {person}, so closing the connection could never happen before banning"
    )]
    ConnectionNotBelowPerson {
        /// Which signal.
        signal: Signal,
        /// The per-connection count.
        connection: u32,
        /// The per-person count.
        person: u32,
    },
}

/// What happens to a person whose tally crossed a threshold.
///
/// Connetto proposes [`BanPermanently`](Self::BanPermanently): earning a ban
/// should be hard, and it comes after throttling rather than instead of it, so
/// crossing means sustained behaviour inside an allowance rather than a burst.
/// A deployment wanting leniency overrides one method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// Nothing durable happens. The crossing is still logged.
    Ignore,
    /// Ban until this long from now.
    BanFor(Duration),
    /// Ban with no expiry, liftable only through [`crate::ban::BanStore::lift`].
    BanPermanently,
}

/// What connetto observed when a tally crossed, handed to the application.
///
/// Only ever built for a caller that can actually be banned, so the verdict and
/// the duration it carries always mean something. A caller with no identity has
/// its connection closed and produces none of these.
#[derive(Debug, Clone)]
pub struct Crossing<Id> {
    /// The person, in the deployment's own id type rather than the rendering
    /// connetto tallies against.
    pub user_id: Id,
    /// The handle the crossing happened on.
    pub session: SessionId,
    /// Which signal crossed.
    pub signal: Signal,
    /// The threshold that was crossed.
    pub limit: u32,
    /// The window the tally accumulated over.
    pub window: Duration,
    /// What the tally holds, which is the threshold at the moment of crossing.
    pub count: u32,
    /// What connetto would do, and what the default answer returns.
    pub proposed: Enforcement,
}

/// The answer to one crossing.
pub type EnforcementFuture<'a> =
    core::pin::Pin<Box<dyn core::future::Future<Output = Enforcement> + Send + 'a>>;

/// Decides what a crossing costs.
///
/// The application is asked rather than told, so it can make the ban fit the
/// offence. The one method has a default body returning connetto's own
/// proposal, so an application that does not care implements nothing at all and
/// still gets automatic behaviour.
///
/// Called from a spawned task: a slow answer must not delay the caller, and an
/// attacker triggering many crossings must not turn the defence into the
/// amplifier.
pub trait EnforcementPolicy<Id>: Send + Sync + 'static {
    /// Answer one crossing.
    fn on_threshold<'a>(&'a self, crossing: &'a Crossing<Id>) -> EnforcementFuture<'a> {
        let proposed = crossing.proposed;
        Box::pin(async move { proposed })
    }
}

/// Who a signal is attributed to.
///
/// Two things per site, because the two features key differently: the handle
/// meters the rate and the person tallies the abuse.
#[derive(Debug)]
pub struct Caller<'a, Id> {
    /// The durable handle this run holds, and the tally key for a caller with
    /// no identity.
    pub session: SessionId,
    /// The person, when the handshake resolved one.
    pub user: Option<&'a Id>,
}

impl<Id> Clone for Caller<'_, Id> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Id> Copy for Caller<'_, Id> {}

/// What the site that reported a signal must do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Reaction {
    /// Carry on serving.
    Continue,
    /// Close this connection, telling the caller nothing. Only a caller with no
    /// identity draws this, because one that can be named is banned instead and
    /// that happens off this path.
    Close,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn the_shipped_thresholds_pass_their_own_checks() {
        assert!(AbuseLimits::new().build().is_ok());
    }

    #[test]
    fn a_zero_window_is_refused() {
        let err = AbuseLimits::new()
            .person(PersonLimits::new().rejected_writes(10, Duration::ZERO))
            .build()
            .expect_err("a window of zero never fires");
        assert_eq!(
            err,
            AbuseConfigError::ZeroWindow {
                signal: Signal::RejectedWrite
            }
        );
    }

    #[test]
    fn a_zero_count_is_refused_in_either_tier() {
        let person = AbuseLimits::new()
            .person(PersonLimits::new().refused_grants(0, MINUTE))
            .build()
            .expect_err("acting on the first refusal is a slip");
        assert_eq!(
            person,
            AbuseConfigError::ZeroCount {
                tier: "person",
                signal: Signal::RefusedGrant
            }
        );

        let connection = AbuseLimits::new()
            .connection(ConnectionLimits::new().rejected_writes(0))
            .build()
            .expect_err("acting on the first refusal is a slip");
        assert_eq!(
            connection,
            AbuseConfigError::ZeroCount {
                tier: "connection",
                signal: Signal::RejectedWrite
            }
        );
    }

    #[test]
    fn a_connection_count_at_or_above_its_person_count_is_refused() {
        let equal = AbuseLimits::new()
            .person(PersonLimits::new().unresolvable_subscriptions(10, MINUTE))
            .connection(ConnectionLimits::new().unresolvable_subscriptions(10))
            .build()
            .expect_err("the cheap defence must be able to fire first");
        assert_eq!(
            equal,
            AbuseConfigError::ConnectionNotBelowPerson {
                signal: Signal::UnresolvableSubscription,
                connection: 10,
                person: 10,
            }
        );

        assert!(
            AbuseLimits::new()
                .person(PersonLimits::new().unresolvable_subscriptions(10, MINUTE))
                .connection(ConnectionLimits::new().unresolvable_subscriptions(9))
                .build()
                .is_ok()
        );
    }

    #[test]
    fn the_connection_tier_has_no_threshold_for_a_failed_renewal() {
        assert!(
            ConnectionLimits::new()
                .limit(Signal::FailedRenewal)
                .is_none()
        );
    }
}
