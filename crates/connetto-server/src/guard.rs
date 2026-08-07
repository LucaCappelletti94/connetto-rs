//! One owner for the request limiter and the abuse detector, so each signal is
//! defined in one place and both features observe it.
//!
//! A rate limit asks whether a caller is going too fast in the last minute and a
//! ban asks whether it has done too much over a much longer span, so the two
//! keep their own tallies with their own windows. What must not be duplicated is
//! the definition of the moment: a site calls this once, gets the limiter's
//! answer, and the detector has recorded behind it. Counting separately in both
//! would mean a later change to what counts as a refusal landing in two places
//! or the two quietly disagreeing.
//!
//! One instance is injected into both [`SessionManager`](crate::SessionManager)
//! and [`AuthService`](crate::AuthService), because three of the four signals
//! occur in the first and the fourth in the second, and those two share no other
//! state.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use connetto_core::SessionId;

use crate::abuse::{
    AbuseConfig, Caller, Crossing, Enforcement, EnforcementPolicy, Reaction, Signal,
};
use crate::audit::{AuditHook, AuthEvent, AuthOp};
use crate::ban::{Ban, BanError, BanStore, NewBan};
use crate::throttle::{AuthThrottle, Counters, HandleThrottle, ThrottleConfig, Tier};

/// Closes every live connection one banned person holds, telling them nothing.
///
/// Fired from the spawned ban task, so an async close belongs on a spawned task
/// inside the hook, exactly as
/// [`SessionRevocationHook`](crate::authn::service::SessionRevocationHook) does.
/// The argument is the identity's rendering, which is what the connection
/// registry holds.
pub type PersonCloseHook = Arc<dyn Fn(String) + Send + Sync>;

/// Who a session belongs to, as this process saw it succeed.
///
/// Both forms are kept: the rendering because an `Id` guarantees no `Eq + Hash`,
/// and the id itself because the enforcement callback must receive the same type
/// the application sees everywhere else.
#[derive(Debug)]
struct Owner<Id> {
    rendering: String,
    id: Id,
    seen: Instant,
}

/// The per-person tallies, one per signal.
#[derive(Debug)]
struct PersonTallies {
    refused_grants: Counters<String>,
    unresolvable_subscriptions: Counters<String>,
    rejected_writes: Counters<String>,
    failed_renewals: Counters<String>,
}

impl PersonTallies {
    fn new() -> Self {
        Self {
            refused_grants: Counters::new(),
            unresolvable_subscriptions: Counters::new(),
            rejected_writes: Counters::new(),
            failed_renewals: Counters::new(),
        }
    }

    const fn of(&self, signal: Signal) -> &Counters<String> {
        match signal {
            Signal::RefusedGrant => &self.refused_grants,
            Signal::UnresolvableSubscription => &self.unresolvable_subscriptions,
            Signal::RejectedWrite => &self.rejected_writes,
            Signal::FailedRenewal => &self.failed_renewals,
        }
    }
}

/// The per-connection tallies, three because a failed renewal always names an
/// account and so has no unidentified form.
#[derive(Debug)]
struct ConnectionTallies {
    refused_grants: Counters<SessionId>,
    unresolvable_subscriptions: Counters<SessionId>,
    rejected_writes: Counters<SessionId>,
}

impl ConnectionTallies {
    fn new() -> Self {
        Self {
            refused_grants: Counters::new(),
            unresolvable_subscriptions: Counters::new(),
            rejected_writes: Counters::new(),
        }
    }

    const fn of(&self, signal: Signal) -> Option<&Counters<SessionId>> {
        match signal {
            Signal::RefusedGrant => Some(&self.refused_grants),
            Signal::UnresolvableSubscription => Some(&self.unresolvable_subscriptions),
            Signal::RejectedWrite => Some(&self.rejected_writes),
            Signal::FailedRenewal => None,
        }
    }
}

/// Owns every counter connetto keeps about a caller.
///
/// Built before the session manager and the auth service and handed to both.
/// The ban list, the enforcement policy and the audit sink are all optional:
/// without a ban list connetto has no table to write, since the table is the
/// deployment's and connetto emits no DDL, so a crossing is logged and nothing
/// else. The per-connection close needs no table and works regardless.
pub struct RequestGuard<Id> {
    handles: HandleThrottle,
    auth: AuthThrottle,
    owners: Mutex<HashMap<SessionId, Owner<Id>>>,
    abuse: AbuseConfig,
    person_retain: Duration,
    key_cap: usize,
    person: PersonTallies,
    connection: ConnectionTallies,
    bans: Option<Arc<dyn BanStore<Id>>>,
    enforcement: Option<Arc<dyn EnforcementPolicy<Id>>>,
    audit: OnceLock<AuditHook<Id>>,
    close: OnceLock<PersonCloseHook>,
}

// Hand-written because four fields are trait objects. What a reader wants is
// the thresholds and which collaborators are attached.
impl<Id> core::fmt::Debug for RequestGuard<Id> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RequestGuard")
            .field("abuse", &self.abuse)
            .field("key_cap", &self.key_cap)
            .field("bans", &self.bans.is_some())
            .field("enforcement", &self.enforcement.is_some())
            .field("audit", &self.audit.get().is_some())
            .field("close", &self.close.get().is_some())
            .finish_non_exhaustive()
    }
}

impl<Id> Default for RequestGuard<Id>
where
    Id: Clone + core::fmt::Display + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new(ThrottleConfig::default(), AbuseConfig::default())
    }
}

impl<Id> RequestGuard<Id>
where
    Id: Clone + core::fmt::Display + Send + Sync + 'static,
{
    /// Build every counter for `throttle` and `abuse`.
    #[must_use]
    pub fn new(throttle: ThrottleConfig, abuse: AbuseConfig) -> Self {
        Self {
            key_cap: throttle.key_cap(),
            auth: AuthThrottle::new(throttle),
            handles: HandleThrottle::new(throttle),
            owners: Mutex::new(HashMap::new()),
            person_retain: abuse.person_retain(),
            abuse,
            person: PersonTallies::new(),
            connection: ConnectionTallies::new(),
            bans: None,
            enforcement: None,
            audit: OnceLock::new(),
            close: OnceLock::new(),
        }
    }

    /// Attach the ban list. Without one connetto cannot ban and cannot refuse a
    /// banned caller at the handshake, so a crossing is only logged.
    #[must_use]
    pub fn with_bans(mut self, bans: Arc<dyn BanStore<Id>>) -> Self {
        self.bans = Some(bans);
        self
    }

    /// Attach the application's answer to a crossing. Without one connetto uses
    /// its own proposal, which is a permanent ban.
    #[must_use]
    pub fn with_enforcement(mut self, policy: Arc<dyn EnforcementPolicy<Id>>) -> Self {
        self.enforcement = Some(policy);
        self
    }

    /// Attach the audit sink, once, so an impose and a lift reach `auth_events`.
    ///
    /// A second call is ignored, matching the sink on
    /// [`AuthService`](crate::AuthService).
    pub fn set_audit_hook(&self, hook: AuditHook<Id>) {
        let _ = self.audit.set(hook);
    }

    /// Attach the observer that closes a banned person's live connections, once,
    /// after the session manager exists.
    pub fn set_close_hook(&self, hook: PersonCloseHook) {
        let _ = self.close.set(hook);
    }

    /// Whether a ban list is attached, which is whether banning is possible.
    #[must_use]
    pub fn bans_configured(&self) -> bool {
        self.bans.is_some()
    }

    /// Take one subscription creation, returning the wait when refused.
    pub(crate) fn subscription(&self, handle: SessionId, tier: Tier) -> Option<Duration> {
        self.handles.subscription(handle, tier)
    }

    /// Take one connection, returning the wait when refused.
    pub(crate) fn connection(&self, handle: SessionId, tier: Tier) -> Option<Duration> {
        self.handles.connection(handle, tier)
    }

    /// Take one refused grant against the rate limit.
    ///
    /// The abuse tally for the same refusals is [`Self::refused_grants`], which
    /// runs once the handshake has resolved who the caller is: a login grant may
    /// follow a bad key in the list, so at this point the person is not known.
    pub(crate) fn credential_refusal(&self, handle: SessionId, tier: Tier) -> Option<Duration> {
        self.handles.credential_refusal(handle, tier)
    }

    /// Record that `session` belongs to `account`, learned from an attempt that
    /// succeeded, so a later failure naming it can be attributed.
    pub(crate) fn learn_owner(&self, session: SessionId, account: &Id) {
        let now = Instant::now();
        let retain = self.auth.retain();
        let mut owners = self.owners.lock().expect("guard owners poisoned");
        owners.retain(|_, owner| now.saturating_duration_since(owner.seen) < retain);
        owners.insert(
            session,
            Owner {
                rendering: account.to_string(),
                id: account.clone(),
                seen: now,
            },
        );
    }

    /// Whether renewals naming `session` are already refused.
    pub(crate) fn refresh_blocked(&self, session: SessionId) -> Option<Duration> {
        let owner = self.owner_of(session);
        self.auth.refresh_blocked(
            session,
            owner.as_ref().map(|(rendering, _)| rendering.as_str()),
        )
    }

    /// Report one failed renewal naming `session`, returning the wait when a
    /// limit is now exhausted.
    ///
    /// A failure naming a session this process has not seen succeed recently
    /// counts against nobody, so it feeds the rate limit alone. Attributing it
    /// would mean a store lookup per guess, which is the cost the limit exists
    /// to avoid.
    pub(crate) fn refresh_failed(&self, session: SessionId) -> Option<Duration> {
        let owner = self.owner_of(session);
        let wait = self.auth.refresh_failed(
            session,
            owner.as_ref().map(|(rendering, _)| rendering.as_str()),
        );
        if let Some((_, id)) = owner {
            self.person_signal(&id, session, Signal::FailedRenewal, 1);
        }
        wait
    }

    /// Report `refusals` refused share keys, attributed to the caller the
    /// handshake resolved.
    pub(crate) fn refused_grants(&self, caller: Caller<'_, Id>, refusals: u32) -> Reaction {
        self.signal(caller, Signal::RefusedGrant, refusals)
    }

    /// Report one subscription naming a table or column that does not resolve.
    pub(crate) fn unresolvable_subscription(&self, caller: Caller<'_, Id>) -> Reaction {
        self.signal(caller, Signal::UnresolvableSubscription, 1)
    }

    /// Report one write the policy rejected.
    pub(crate) fn rejected_write(&self, caller: Caller<'_, Id>) -> Reaction {
        self.signal(caller, Signal::RejectedWrite, 1)
    }

    /// Retire a connection's tallies, which nothing else expires because the
    /// connection is their window.
    pub(crate) fn forget_connection(&self, session: SessionId) {
        for signal in Signal::ALL {
            if let Some(counters) = self.connection.of(signal) {
                counters.forget(&session);
            }
        }
    }

    /// The ban that refuses `user_id` right now, if any.
    ///
    /// Fails closed: an unreadable list is an error rather than an absence, so a
    /// ban can never lapse because a table was briefly unreadable, and an
    /// attacker who can cause an outage cannot suspend their own ban.
    pub(crate) async fn banned(&self, user_id: &Id) -> Result<Option<Ban>, BanError> {
        let Some(bans) = self.bans.as_ref() else {
            return Ok(None);
        };
        let now = chrono::Utc::now();
        Ok(bans.check(user_id).await?.filter(|ban| ban.applies_at(now)))
    }

    /// Lift the ban on `user_id`, recording it, and report whether there was one.
    ///
    /// The only way a ban ends with a trace. An expiry that passes stops
    /// applying immediately and leaves its row behind, so a deployment wanting
    /// rows cleared schedules its own task calling this.
    ///
    /// # Errors
    ///
    /// [`BanError`] if the ban list cannot be reached.
    pub async fn lift_ban(&self, user_id: &Id) -> Result<bool, BanError> {
        let Some(bans) = self.bans.as_ref() else {
            return Ok(false);
        };
        let Some(ban) = bans.check(user_id).await? else {
            return Ok(false);
        };
        if !bans.lift(user_id).await? {
            return Ok(false);
        }
        tracing::info!(user = %user_id, reason = %ban.reason, "ban lifted");
        if let Some(audit) = self.audit.get() {
            audit(AuthEvent::new(
                ban.session,
                Some(user_id.clone()),
                AuthOp::BanLifted,
            ));
        }
        Ok(true)
    }

    /// The account `session` belongs to, when this process has seen it succeed.
    fn owner_of(&self, session: SessionId) -> Option<(String, Id)> {
        let now = Instant::now();
        let retain = self.auth.retain();
        let owners = self.owners.lock().expect("guard owners poisoned");
        owners
            .get(&session)
            .filter(|owner| now.saturating_duration_since(owner.seen) < retain)
            .map(|owner| (owner.rendering.clone(), owner.id.clone()))
    }

    /// Route one signal to the tier that can act on it.
    fn signal(&self, caller: Caller<'_, Id>, signal: Signal, times: u32) -> Reaction {
        if times == 0 {
            return Reaction::Continue;
        }
        match caller.user {
            Some(user) => {
                self.person_signal(user, caller.session, signal, times);
                Reaction::Continue
            }
            None => self.connection_signal(caller.session, signal, times),
        }
    }

    /// Tally against the person, and ask what a crossing costs.
    ///
    /// The person rather than the handle, because in production the handle is
    /// the `sid` claim inside the access token, minted fresh at every login, so
    /// keying there would let a signed-in caller clear every tally by signing
    /// out and back in and would give one person on three devices three tallies.
    fn person_signal(&self, user: &Id, session: SessionId, signal: Signal, times: u32) {
        let limit = self.abuse.person().limit(signal);
        let key = user.to_string();
        let now = Instant::now();
        let mut crossed = None;
        for _ in 0..times {
            let count = self.person.of(signal).tally(
                &key,
                Some(limit.window()),
                self.person_retain,
                self.key_cap,
                now,
            );
            // The moment it reaches the threshold, and only that moment, so a
            // caller still asking does not draw a fresh answer per attempt.
            if count == limit.max() {
                crossed = Some(count);
            }
        }
        let Some(count) = crossed else {
            return;
        };
        self.enforce(Crossing {
            user_id: user.clone(),
            session,
            signal,
            limit: limit.max(),
            window: limit.window(),
            count,
            proposed: Enforcement::BanPermanently,
        });
    }

    /// Tally against the connection, and close it on a crossing.
    ///
    /// The application is not asked, so the enforcement trait only ever receives
    /// a caller that can actually be banned and its answer always means
    /// something.
    fn connection_signal(&self, session: SessionId, signal: Signal, times: u32) -> Reaction {
        let (Some(limit), Some(counters)) = (
            self.abuse.connection().limit(signal),
            self.connection.of(signal),
        ) else {
            return Reaction::Continue;
        };
        let now = Instant::now();
        let mut reached = false;
        for _ in 0..times {
            // No window: the connection is the window, so nothing rolls over and
            // `forget_connection` is what retires the key.
            let count = counters.tally(&session, None, Duration::MAX, self.key_cap, now);
            reached |= count >= limit;
        }
        if !reached {
            return Reaction::Continue;
        }
        tracing::warn!(
            signal = signal.label(),
            limit,
            "connection closed, threshold crossed by a caller with no identity to ban"
        );
        Reaction::Close
    }

    /// Ask what the crossing costs and carry the answer out, off the caller's
    /// path.
    fn enforce(&self, crossing: Crossing<Id>) {
        let Some(bans) = self.bans.clone() else {
            tracing::warn!(
                user = %crossing.user_id,
                signal = crossing.signal.label(),
                count = crossing.count,
                "threshold crossed and no ban list is configured, so nothing was written"
            );
            return;
        };
        let policy = self.enforcement.clone();
        let audit = self.audit.get().cloned();
        let close = self.close.get().cloned();
        tokio::spawn(async move {
            let verdict = match policy {
                Some(policy) => policy.on_threshold(&crossing).await,
                None => crossing.proposed,
            };
            let ttl = match verdict {
                Enforcement::Ignore => {
                    tracing::warn!(
                        user = %crossing.user_id,
                        signal = crossing.signal.label(),
                        count = crossing.count,
                        "threshold crossed and the application declined to ban"
                    );
                    return;
                }
                Enforcement::BanFor(ttl) => Some(ttl),
                Enforcement::BanPermanently => None,
            };
            let reason = format!(
                "{} {} per {}s",
                crossing.signal.label(),
                crossing.limit,
                crossing.window.as_secs()
            );
            let ban = NewBan::starting_now(crossing.user_id.clone(), crossing.session, reason, ttl);
            if let Err(error) = bans.impose(ban).await {
                tracing::error!(
                    %error,
                    user = %crossing.user_id,
                    "the ban could not be written, so the caller is not banned"
                );
                return;
            }
            tracing::warn!(
                user = %crossing.user_id,
                session = %crossing.session,
                signal = crossing.signal.label(),
                count = crossing.count,
                permanent = ttl.is_none(),
                "identity banned"
            );
            if let Some(audit) = audit {
                audit(AuthEvent::new(
                    crossing.session,
                    Some(crossing.user_id.clone()),
                    AuthOp::Banned,
                ));
            }
            // Without the hook the ban is durable but the caller keeps whatever
            // connections it holds until they end on their own, which defeats
            // "immediately" for a transport whose connections are long lived.
            if let Some(close) = close {
                close(crossing.user_id.to_string());
            } else {
                tracing::warn!(
                    user = %crossing.user_id,
                    "no close observer is attached, so the banned caller keeps its live connections"
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abuse::{AbuseLimits, ConnectionLimits, PersonLimits};

    const MINUTE: Duration = Duration::from_secs(60);

    fn handle() -> SessionId {
        SessionId::from_uuid(uuid::Uuid::new_v4())
    }

    fn guard(person: u32, connection: u32) -> RequestGuard<String> {
        let abuse = AbuseLimits::new()
            .person(PersonLimits::new().unresolvable_subscriptions(person, MINUTE))
            .connection(ConnectionLimits::new().unresolvable_subscriptions(connection))
            .build()
            .expect("valid thresholds");
        RequestGuard::new(ThrottleConfig::default(), abuse)
    }

    /// A caller with no identity is closed on its own connection's threshold.
    #[tokio::test]
    async fn an_unidentified_caller_is_closed_on_its_connection_threshold() {
        let guard = guard(10, 2);
        let session = handle();
        let caller = Caller::<String> {
            session,
            user: None,
        };
        assert_eq!(guard.unresolvable_subscription(caller), Reaction::Continue);
        assert_eq!(guard.unresolvable_subscription(caller), Reaction::Close);
    }

    /// A connection's tally dies with the socket, so a reconnect starts over.
    #[tokio::test]
    async fn forgetting_a_connection_returns_its_allowance() {
        let guard = guard(10, 2);
        let session = handle();
        let caller = Caller::<String> {
            session,
            user: None,
        };
        assert_eq!(guard.unresolvable_subscription(caller), Reaction::Continue);
        guard.forget_connection(session);
        assert_eq!(
            guard.unresolvable_subscription(caller),
            Reaction::Continue,
            "a new connection on the same handle starts from zero"
        );
    }

    /// An identified caller is never closed by the connection tier, because a
    /// ban is what reaches it and that happens off this path.
    #[tokio::test]
    async fn an_identified_caller_is_not_closed_by_the_connection_tier() {
        let guard = guard(10, 2);
        let user = "alice".to_owned();
        let caller = Caller {
            session: handle(),
            user: Some(&user),
        };
        for _ in 0..5 {
            assert_eq!(guard.unresolvable_subscription(caller), Reaction::Continue);
        }
    }

    /// Two connections of one person share one tally, so the second crosses a
    /// threshold the first left one short of.
    ///
    /// Observed through the connection tier of a caller with the same handles and
    /// no identity, which is the only outcome a unit test can see: a person's
    /// crossing needs a ban list to land in, and `abuse.rs` asserts that against
    /// a real table.
    #[tokio::test]
    async fn two_handles_of_one_person_share_a_tally() {
        let guard = guard(2, 1);
        let user = "alice".to_owned();
        let first = Caller {
            session: handle(),
            user: Some(&user),
        };
        let second = Caller {
            session: handle(),
            user: Some(&user),
        };
        // Neither is closed, because an identified caller is banned rather than
        // closed, and the person threshold of two is what the pair reaches.
        assert_eq!(guard.unresolvable_subscription(first), Reaction::Continue);
        assert_eq!(guard.unresolvable_subscription(second), Reaction::Continue);

        // The same two handles with no identity are two separate tallies, which
        // is the contrast that makes the pairing above meaningful: each gets its
        // own per-connection allowance of one.
        let anon_first = Caller::<String> {
            session: first.session,
            user: None,
        };
        let anon_second = Caller::<String> {
            session: second.session,
            user: None,
        };
        assert_eq!(guard.unresolvable_subscription(anon_first), Reaction::Close);
        assert_eq!(
            guard.unresolvable_subscription(anon_second),
            Reaction::Close
        );
    }

    /// Without a ban list there is nothing to lift and nothing to check.
    #[tokio::test]
    async fn no_ban_list_means_no_ban() {
        let guard = guard(2, 1);
        assert!(!guard.bans_configured());
        assert!(!guard.lift_ban(&"alice".to_owned()).await.expect("lift"));
        assert!(
            guard
                .banned(&"alice".to_owned())
                .await
                .expect("check")
                .is_none()
        );
    }
}
