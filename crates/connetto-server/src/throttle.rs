//! Request throttling, tiered by whether the caller has an identity.
//!
//! Bounds how much a caller may ask for, which is a different job from
//! [`SessionConfig::initial_credits`](crate::SessionConfig): that bounds how
//! much undelivered data a session accumulates, and nothing before this bounded
//! what a caller may request.
//!
//! Everything counts against the durable session handle rather than a
//! connection counter, so a limit survives a reconnect, and against the caller's
//! own key rather than a network address, which connetto never reads: by the
//! time it could consult a ceiling it has accepted the connection, completed the
//! upgrade and allocated a session, which is the whole cost an attacker wanted
//! to impose. That belongs to the edge.
//!
//! Windows are fixed rather than sliding. An event over the limit is refused and
//! not counted, so hammering does not extend the wait, and the refusal states
//! how long is left so a caller waits once instead of probing.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use connetto_core::SessionId;

/// One minute, the window every per-connection default uses.
const MINUTE: Duration = Duration::from_secs(60);
/// Five minutes, the window the credential-guessing defaults use, longer
/// because guessing is patient and a legitimate refresh is rare.
const FIVE_MINUTES: Duration = Duration::from_secs(300);

/// How many of something a caller may ask for, over how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    max: u32,
    window: Duration,
}

impl Limit {
    /// A limit of `max` events per `window`.
    #[must_use]
    pub const fn new(max: u32, window: Duration) -> Self {
        Self { max, window }
    }

    /// How many events the window allows.
    #[must_use]
    pub const fn max(self) -> u32 {
        self.max
    }

    /// How long the window lasts.
    #[must_use]
    pub const fn window(self) -> Duration {
        self.window
    }
}

/// Which set of limits a caller gets.
///
/// An authenticated caller is accountable: there is a user to attribute cost to,
/// a session to revoke, and a login that already cost them something. An
/// unidentified caller has none of that by definition, so its allowance is
/// smaller rather than absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// A caller whose handshake resolved an identity.
    Identified,
    /// A caller with no identity, which is a supported way to connect.
    Anonymous,
}

/// The limits one tier gets, built by naming only what differs from the
/// tier's default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierLimits {
    subscriptions: Limit,
    connections: Limit,
    credential_refusals: Limit,
}

impl TierLimits {
    /// The defaults for a caller that signed in.
    #[must_use]
    pub const fn identified() -> Self {
        Self {
            subscriptions: Limit::new(120, MINUTE),
            connections: Limit::new(30, MINUTE),
            credential_refusals: Limit::new(30, MINUTE),
        }
    }

    /// The defaults for a caller with no identity.
    #[must_use]
    pub const fn anonymous() -> Self {
        Self {
            subscriptions: Limit::new(30, MINUTE),
            connections: Limit::new(15, MINUTE),
            credential_refusals: Limit::new(10, MINUTE),
        }
    }

    /// How many subscriptions this tier may create per window. The expensive
    /// one: each takes a full snapshot of the subscribed shape.
    #[must_use]
    pub const fn subscriptions(mut self, max: u32, window: Duration) -> Self {
        self.subscriptions = Limit::new(max, window);
        self
    }

    /// How many connections this tier may open per window on one handle.
    #[must_use]
    pub const fn connections(mut self, max: u32, window: Duration) -> Self {
        self.connections = Limit::new(max, window);
        self
    }

    /// How many grants this tier may present and have refused per window.
    #[must_use]
    pub const fn credential_refusals(mut self, max: u32, window: Duration) -> Self {
        self.credential_refusals = Limit::new(max, window);
        self
    }
}

/// Every limit connetto enforces, per tier and per credential surface.
///
/// Built as a chain of calls rather than a struct of public fields, because the
/// shape is nested: a limit and a window per signal, doubled across two tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrottleConfig {
    identified: TierLimits,
    anonymous: TierLimits,
    refresh_failures_per_session: Limit,
    refresh_failures_per_account: Limit,
    max_tracked: usize,
}

/// How many distinct keys one signal tracks before it starts evicting.
///
/// Generous enough that an ordinary deployment never reaches it, and small
/// enough that reaching it costs tens of megabytes rather than the process.
const DEFAULT_MAX_TRACKED: usize = 100_000;

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            identified: TierLimits::identified(),
            anonymous: TierLimits::anonymous(),
            refresh_failures_per_session: Limit::new(10, FIVE_MINUTES),
            refresh_failures_per_account: Limit::new(30, FIVE_MINUTES),
            max_tracked: DEFAULT_MAX_TRACKED,
        }
    }
}

impl ThrottleConfig {
    /// The default limits, generous enough that no honest client meets them.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the limits a signed-in caller gets.
    #[must_use]
    pub const fn identified(mut self, limits: TierLimits) -> Self {
        self.identified = limits;
        self
    }

    /// Replace the limits a caller with no identity gets.
    #[must_use]
    pub const fn anonymous(mut self, limits: TierLimits) -> Self {
        self.anonymous = limits;
        self
    }

    /// How many refresh attempts naming one session may fail per window.
    ///
    /// The session is named inside the presented token, so a caller guessing a
    /// secret still says which session it is guessing at, and that is the key.
    #[must_use]
    pub const fn refresh_failures_per_session(mut self, max: u32, window: Duration) -> Self {
        self.refresh_failures_per_session = Limit::new(max, window);
        self
    }

    /// How many refresh attempts naming one account may fail per window,
    /// across every session of that account this process has seen succeed.
    #[must_use]
    pub const fn refresh_failures_per_account(mut self, max: u32, window: Duration) -> Self {
        self.refresh_failures_per_account = Limit::new(max, window);
        self
    }

    /// How many distinct keys one signal tracks before the least recently
    /// touched is evicted to make room.
    ///
    /// This is the memory bound. Raise it for a deployment with more live
    /// callers than the default, since a real caller evicted early gets its
    /// allowance back.
    #[must_use]
    pub const fn max_tracked(mut self, keys: usize) -> Self {
        self.max_tracked = keys;
        self
    }

    /// How many distinct keys any one counter tracks, which the abuse tallies
    /// share so one setting bounds every map connetto keeps about a caller.
    #[must_use]
    pub(crate) const fn key_cap(&self) -> usize {
        self.max_tracked
    }

    /// The limits for `tier`.
    #[must_use]
    const fn tier(&self, tier: Tier) -> TierLimits {
        match tier {
            Tier::Identified => self.identified,
            Tier::Anonymous => self.anonymous,
        }
    }

    /// How long the per-connection counters must keep a key, which is their own
    /// longest window and not the whole config's: a key older than every window
    /// that could read it cannot change any decision, and keeping it only makes
    /// the map bigger and the sweep longer.
    fn handle_retain(&self) -> Duration {
        [
            self.identified.subscriptions.window,
            self.identified.connections.window,
            self.identified.credential_refusals.window,
            self.anonymous.subscriptions.window,
            self.anonymous.connections.window,
            self.anonymous.credential_refusals.window,
        ]
        .into_iter()
        .max()
        .unwrap_or(MINUTE)
    }

    /// The same, for the credential counters.
    fn auth_retain(&self) -> Duration {
        self.refresh_failures_per_session
            .window
            .max(self.refresh_failures_per_account.window)
    }
}

/// One fixed window: when it opened and how many events it has taken.
#[derive(Debug, Clone, Copy)]
struct Window {
    started: Instant,
    count: u32,
}

impl Window {
    /// Take one event against `limit`, returning how long is left when the
    /// window is full.
    ///
    /// A refused event is not counted, so a caller that keeps asking does not
    /// push its own wait further out.
    fn take(&mut self, limit: Limit, now: Instant) -> Option<Duration> {
        let elapsed = now.saturating_duration_since(self.started);
        if elapsed >= limit.window {
            self.started = now;
            self.count = 1;
            return None;
        }
        if self.count >= limit.max {
            return Some(limit.window.saturating_sub(elapsed));
        }
        self.count += 1;
        None
    }

    /// Count one event over `window`, returning the running total.
    ///
    /// Nothing is refused, so an over-threshold event still counts: a tally
    /// reports what a caller did, where a limit decides what it may do. `None`
    /// never rolls over, which is what a per-connection tally wants because the
    /// connection is the window.
    fn add(&mut self, window: Option<Duration>, now: Instant) -> u32 {
        if let Some(window) = window
            && now.saturating_duration_since(self.started) >= window
        {
            self.started = now;
            self.count = 1;
            return self.count;
        }
        self.count = self.count.saturating_add(1);
        self.count
    }

    /// A fresh window already holding this event.
    const fn opened(now: Instant) -> Self {
        Self {
            started: now,
            count: 1,
        }
    }
}

/// One tracked key: its window, and where it sits in touch order.
#[derive(Debug, Clone, Copy)]
struct Tracked {
    window: Window,
    touched: u64,
}

/// The keys one signal is counting, in touch order, with when they were last
/// swept.
///
/// `order` is the touch sequence to key index that makes eviction exact rather
/// than sampled: its first entry is always the least recently touched key.
#[derive(Debug)]
struct CounterState<K> {
    windows: HashMap<K, Tracked>,
    order: BTreeMap<u64, K>,
    next_touch: u64,
    last_sweep: Instant,
}

/// Fixed-window counters for one signal, keyed by whatever identifies the
/// caller or the target.
#[derive(Debug)]
pub(crate) struct Counters<K> {
    state: Mutex<CounterState<K>>,
}

impl<K: Eq + Hash + Clone> Counters<K> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(CounterState {
                windows: HashMap::new(),
                order: BTreeMap::new(),
                next_touch: 0,
                last_sweep: Instant::now(),
            }),
        }
    }

    /// Take one event for `key`, returning the wait when it is over `limit`.
    ///
    /// Three bounds meet here. Expired entries are dropped, but sweeping walks
    /// every key so it runs at most once per retention period rather than on
    /// every call: a reconnect storm is when this path is hottest and the map
    /// largest, and a sweep per request under the lock would make the defence
    /// the amplifier. Age alone is not a bound though, since a caller minting a
    /// fresh key per attempt allocates faster than the window retires, so the
    /// map is also capped. Eviction takes the least recently touched key, which
    /// is what keeps the cap safe: a caller at its limit keeps asking and so
    /// keeps its place, while the flood's single-touch keys go first.
    fn take(
        &self,
        key: &K,
        limit: Limit,
        retain: Duration,
        cap: usize,
        now: Instant,
    ) -> Option<Duration> {
        let mut state = self.state.lock().expect("throttle counters poisoned");
        if now.saturating_duration_since(state.last_sweep) >= retain {
            state.sweep(retain, now);
        }
        if let Some(mut tracked) = state.windows.get(key).copied() {
            let wait = tracked.window.take(limit, now);
            state.touch(key, &mut tracked);
            return wait;
        }
        state.admit(key, cap, now);
        None
    }

    /// Whether `key` is already out of allowance, without spending any.
    ///
    /// The credential surfaces ask this before doing the work an attempt costs,
    /// so a caller past its limit is turned away rather than served, and cannot
    /// interleave guesses with valid attempts to keep going. It does not count
    /// as a touch: asking whether you are blocked must not buy you a longer
    /// place in the map than asking for something does.
    fn peek(&self, key: &K, limit: Limit, now: Instant) -> Option<Duration> {
        let state = self.state.lock().expect("throttle counters poisoned");
        let tracked = state.windows.get(key)?;
        let elapsed = now.saturating_duration_since(tracked.window.started);
        if elapsed < limit.window && tracked.window.count >= limit.max {
            return Some(limit.window.saturating_sub(elapsed));
        }
        None
    }

    /// Count one event for `key` over `window`, returning the running total.
    ///
    /// The same three bounds as [`Counters::take`], and the same eviction
    /// direction for the same reason. A `None` window never rolls over, so
    /// `retain` should be [`Duration::MAX`] beside it and the caller is
    /// responsible for [`Counters::forget`] when the key dies.
    pub(crate) fn tally(
        &self,
        key: &K,
        window: Option<Duration>,
        retain: Duration,
        cap: usize,
        now: Instant,
    ) -> u32 {
        let mut state = self.state.lock().expect("throttle counters poisoned");
        if now.saturating_duration_since(state.last_sweep) >= retain {
            state.sweep(retain, now);
        }
        if let Some(mut tracked) = state.windows.get(key).copied() {
            let count = tracked.window.add(window, now);
            state.touch(key, &mut tracked);
            return count;
        }
        state.admit(key, cap, now);
        1
    }

    /// Stop tracking `key`.
    pub(crate) fn forget(&self, key: &K) {
        let mut state = self.state.lock().expect("throttle counters poisoned");
        if let Some(tracked) = state.windows.remove(key) {
            state.order.remove(&tracked.touched);
        }
    }
}

impl<K: Eq + Hash + Clone> CounterState<K> {
    /// Drop every key whose window can no longer affect a decision.
    fn sweep(&mut self, retain: Duration, now: Instant) {
        let expired: Vec<(K, u64)> = self
            .windows
            .iter()
            .filter(|(_, tracked)| now.saturating_duration_since(tracked.window.started) >= retain)
            .map(|(key, tracked)| (key.clone(), tracked.touched))
            .collect();
        for (key, touched) in expired {
            self.windows.remove(&key);
            self.order.remove(&touched);
        }
        self.last_sweep = now;
    }

    /// Move `key` to the most recently touched position, carrying its updated
    /// window back into the map.
    fn touch(&mut self, key: &K, tracked: &mut Tracked) {
        self.order.remove(&tracked.touched);
        tracked.touched = self.next_touch;
        self.next_touch = self.next_touch.wrapping_add(1);
        self.order.insert(tracked.touched, key.clone());
        self.windows.insert(key.clone(), *tracked);
    }

    /// Start tracking `key`, evicting the least recently touched key first when
    /// the map is full.
    fn admit(&mut self, key: &K, cap: usize, now: Instant) {
        while self.windows.len() >= cap.max(1) {
            let Some((_, evicted)) = self.order.pop_first() else {
                break;
            };
            self.windows.remove(&evicted);
        }
        let mut tracked = Tracked {
            window: Window::opened(now),
            touched: 0,
        };
        self.touch(key, &mut tracked);
    }
}

/// The counters every sync connection is metered against, keyed by the durable
/// session handle so a limit survives a reconnect.
///
/// Not keyed by the per-connection counter: that resets on every reconnect, so
/// it would cap one connection and not a reconnect loop, which is the shape of
/// abuse worth bounding.
///
/// Reached through [`RequestGuard`](crate::guard::RequestGuard) rather than on
/// its own, so one call per site defines the moment for both the limiter and
/// the abuse detector behind it.
#[derive(Debug)]
pub(crate) struct HandleThrottle {
    config: ThrottleConfig,
    retain: Duration,
    subscriptions: Counters<SessionId>,
    connections: Counters<SessionId>,
    credential_refusals: Counters<SessionId>,
}

impl HandleThrottle {
    /// Build the counters for `config`.
    pub(crate) fn new(config: ThrottleConfig) -> Self {
        Self {
            retain: config.handle_retain(),
            config,
            subscriptions: Counters::new(),
            connections: Counters::new(),
            credential_refusals: Counters::new(),
        }
    }

    /// Take one subscription creation, returning the wait when refused.
    pub(crate) fn subscription(&self, handle: SessionId, tier: Tier) -> Option<Duration> {
        self.subscriptions.take(
            &handle,
            self.config.tier(tier).subscriptions,
            self.retain,
            self.config.max_tracked,
            Instant::now(),
        )
    }

    /// Take one connection, returning the wait when refused.
    pub(crate) fn connection(&self, handle: SessionId, tier: Tier) -> Option<Duration> {
        self.connections.take(
            &handle,
            self.config.tier(tier).connections,
            self.retain,
            self.config.max_tracked,
            Instant::now(),
        )
    }

    /// Record one refused grant, returning the wait when the handle has had
    /// too many.
    pub(crate) fn credential_refusal(&self, handle: SessionId, tier: Tier) -> Option<Duration> {
        self.credential_refusals.take(
            &handle,
            self.config.tier(tier).credential_refusals,
            self.retain,
            self.config.max_tracked,
            Instant::now(),
        )
    }
}

/// The counters the token endpoints are metered against.
///
/// Two keys, because the two attacks differ. A caller guessing the secret of one
/// session is opposed by the per-session key, which the presented token names
/// even when the secret is wrong. A caller working through several sessions of
/// one person is opposed by the per-account key, which the caller supplies from
/// the sessions this process has seen succeed rather than by asking the store,
/// since a store lookup per guess is the cost the limit exists to avoid.
///
/// The account arrives as its [`Display`](core::fmt::Display) rendering rather
/// than typed, because an `Id` guarantees no `Eq + Hash` and widening that
/// public bound would impose on every application that owns the type. Remembering
/// which account a session belongs to is [`RequestGuard`](crate::guard::RequestGuard)'s
/// job, since the enforcement callback beside this needs the typed id too.
#[derive(Debug)]
pub(crate) struct AuthThrottle {
    config: ThrottleConfig,
    retain: Duration,
    per_session: Counters<SessionId>,
    per_account: Counters<String>,
}

impl AuthThrottle {
    /// Build the counters for `config`.
    pub(crate) fn new(config: ThrottleConfig) -> Self {
        Self {
            retain: config.auth_retain(),
            config,
            per_session: Counters::new(),
            per_account: Counters::new(),
        }
    }

    /// How long this surface keeps a key, which is how long an owner memory
    /// feeding it has to last to be read.
    pub(crate) const fn retain(&self) -> Duration {
        self.retain
    }

    /// Whether attempts naming `session` are already refused, checked before
    /// the attempt so a caller past its limit cannot interleave guesses with
    /// valid attempts to keep going.
    pub(crate) fn refresh_blocked(
        &self,
        session: SessionId,
        account: Option<&str>,
    ) -> Option<Duration> {
        let now = Instant::now();
        let by_session =
            self.per_session
                .peek(&session, self.config.refresh_failures_per_session, now);
        let by_account = account.and_then(|account| {
            self.per_account.peek(
                &account.to_owned(),
                self.config.refresh_failures_per_account,
                now,
            )
        });
        match (by_session, by_account) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (wait, None) | (None, wait) => wait,
        }
    }

    /// Record one failed attempt naming `session`, returning the wait when
    /// either its own limit or its owner's is now exhausted.
    pub(crate) fn refresh_failed(
        &self,
        session: SessionId,
        account: Option<&str>,
    ) -> Option<Duration> {
        let now = Instant::now();
        let by_session = self.per_session.take(
            &session,
            self.config.refresh_failures_per_session,
            self.retain,
            self.config.max_tracked,
            now,
        );
        let by_account = account.and_then(|account| {
            self.per_account.take(
                &account.to_owned(),
                self.config.refresh_failures_per_account,
                self.retain,
                self.config.max_tracked,
                now,
            )
        });
        match (by_session, by_account) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (wait, None) | (None, wait) => wait,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle() -> SessionId {
        SessionId::from_uuid(uuid::Uuid::new_v4())
    }

    /// The map is capped, and a caller being limited survives the flood.
    ///
    /// Keys are only ever forgotten by age, so a caller that discards its
    /// handle every connection, which step 5 accepts cannot be throttled,
    /// allocates an entry per attempt that nothing can evict early. Capping is
    /// what bounds that. Evicting the least recently touched is what makes the
    /// cap safe: a caller at its limit keeps touching its key, so the flood it
    /// is causing cannot push it out and hand it a fresh allowance, while the
    /// flood's own single-touch keys are the first to go.
    #[test]
    fn a_capped_map_evicts_the_flood_and_keeps_the_caller_it_is_limiting() {
        const CAP: usize = 4;
        let throttle = HandleThrottle::new(
            ThrottleConfig::new()
                .anonymous(TierLimits::anonymous().subscriptions(2, MINUTE))
                .max_tracked(CAP),
        );

        let hot = handle();
        assert!(throttle.subscription(hot, Tier::Anonymous).is_none());
        assert!(throttle.subscription(hot, Tier::Anonymous).is_none());
        assert!(
            throttle.subscription(hot, Tier::Anonymous).is_some(),
            "the caller is at its limit before the flood starts"
        );

        for _ in 0..50 {
            let _ = throttle.subscription(handle(), Tier::Anonymous);
            // The limited caller keeps asking, as one that is being refused does.
            let _ = throttle.subscription(hot, Tier::Anonymous);
        }

        let tracked = throttle
            .subscriptions
            .state
            .lock()
            .expect("counters poisoned")
            .windows
            .len();
        assert!(tracked <= CAP, "the map is capped: {tracked} tracked");
        assert!(
            throttle.subscription(hot, Tier::Anonymous).is_some(),
            "the flood evicted the caller it was limiting, resetting its allowance"
        );
    }

    /// A counter set must not hold keys far longer than its own longest window.
    ///
    /// `retain` was taken across the whole config, so the per-connection
    /// counters, whose windows are a minute, kept every handle for the five
    /// minutes the credential windows use. That is five times the entries a
    /// sweep walks and five times the memory, for keys that can no longer
    /// affect any decision.
    #[test]
    fn a_counter_set_retains_only_as_long_as_its_own_windows() {
        let brief = Duration::from_millis(60);
        let short_tier = |limits: TierLimits| {
            limits
                .subscriptions(5, brief)
                .connections(5, brief)
                .credential_refusals(5, brief)
        };
        // The credential windows stay long, which is the point: the connection
        // counters must not inherit their retention.
        let throttle = HandleThrottle::new(
            ThrottleConfig::new()
                .anonymous(short_tier(TierLimits::anonymous()))
                .identified(short_tier(TierLimits::identified()))
                .refresh_failures_per_session(5, FIVE_MINUTES)
                .refresh_failures_per_account(5, FIVE_MINUTES),
        );
        for _ in 0..8 {
            let _ = throttle.subscription(handle(), Tier::Anonymous);
        }
        std::thread::sleep(brief * 2);

        // One more call sweeps, and every earlier key is long past its window.
        let _ = throttle.subscription(handle(), Tier::Anonymous);
        let live = throttle
            .subscriptions
            .state
            .lock()
            .expect("counters poisoned")
            .windows
            .len();
        assert_eq!(
            live, 1,
            "the eight abandoned handles outlived every window that could use them"
        );
    }

    #[test]
    fn a_window_admits_its_limit_then_refuses() {
        let config =
            ThrottleConfig::new().anonymous(TierLimits::anonymous().subscriptions(2, MINUTE));
        let throttle = HandleThrottle::new(config);
        let key = handle();

        assert!(throttle.subscription(key, Tier::Anonymous).is_none());
        assert!(throttle.subscription(key, Tier::Anonymous).is_none());
        let wait = throttle
            .subscription(key, Tier::Anonymous)
            .expect("the third is over the limit");
        assert!(
            wait <= MINUTE && !wait.is_zero(),
            "states the wait: {wait:?}"
        );
    }

    #[test]
    fn the_tiers_are_separate_allowances() {
        let config = ThrottleConfig::new()
            .anonymous(TierLimits::anonymous().subscriptions(1, MINUTE))
            .identified(TierLimits::identified().subscriptions(3, MINUTE));
        let throttle = HandleThrottle::new(config);
        let signed_in = handle();
        let visitor = handle();

        assert!(throttle.subscription(visitor, Tier::Anonymous).is_none());
        assert!(throttle.subscription(visitor, Tier::Anonymous).is_some());

        for _ in 0..3 {
            assert!(throttle.subscription(signed_in, Tier::Identified).is_none());
        }
        assert!(throttle.subscription(signed_in, Tier::Identified).is_some());
    }

    #[test]
    fn one_handles_limit_does_not_spend_anothers() {
        let config =
            ThrottleConfig::new().anonymous(TierLimits::anonymous().subscriptions(1, MINUTE));
        let throttle = HandleThrottle::new(config);
        let first = handle();
        let second = handle();

        assert!(throttle.subscription(first, Tier::Anonymous).is_none());
        assert!(throttle.subscription(first, Tier::Anonymous).is_some());
        assert!(
            throttle.subscription(second, Tier::Anonymous).is_none(),
            "a different handle carries its own allowance"
        );
    }

    #[test]
    fn a_refused_event_does_not_extend_the_wait() {
        let mut window = Window::opened(Instant::now());
        let limit = Limit::new(1, MINUTE);
        let now = Instant::now();
        let first = window.take(limit, now).expect("already at the limit");
        let second = window.take(limit, now).expect("still refused");
        assert!(
            second >= first.saturating_sub(Duration::from_millis(50)),
            "hammering must not push the wait out: {first:?} then {second:?}"
        );
        assert_eq!(window.count, 1, "a refused event is not counted");
    }

    #[test]
    fn a_failure_counts_against_the_account_once_its_session_is_known() {
        let config = ThrottleConfig::new()
            .refresh_failures_per_session(10, MINUTE)
            .refresh_failures_per_account(2, MINUTE);
        let throttle = AuthThrottle::new(config);
        let (first, second) = (handle(), handle());

        assert!(throttle.refresh_failed(first, Some("alice")).is_none());
        assert!(throttle.refresh_failed(second, Some("alice")).is_none());
        assert!(
            throttle.refresh_failed(first, Some("alice")).is_some(),
            "two of alice's sessions share her account allowance"
        );
    }

    #[test]
    fn an_unknown_session_is_capped_alone() {
        let config = ThrottleConfig::new()
            .refresh_failures_per_session(1, MINUTE)
            .refresh_failures_per_account(1, MINUTE);
        let throttle = AuthThrottle::new(config);
        let guessed = handle();

        assert!(throttle.refresh_failed(guessed, None).is_none());
        assert!(
            throttle.refresh_failed(guessed, None).is_some(),
            "a session naming nobody still spends its own allowance"
        );
    }
}
