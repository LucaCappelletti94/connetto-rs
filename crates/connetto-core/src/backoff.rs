//! Exponential-backoff retry policy shared across every reconnect driver.
//!
//! The server-side CDC reconnect loop, the native/wasm client reconnect
//! driver and the ingest loop's delivery-pause arm share one schedule, with
//! each caller free to wrap it with its own fields.
//! [`RetryPolicy`] holds the parameters, [`Backoff`] drives one episode of
//! them.
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

/// Each driver gets a distinct seed, so episodes that start together spread their retries apart.
static SEED: AtomicU64 = AtomicU64::new(0x243F_6A88_85A3_08D3);

/// splitmix64, enough to decorrelate retry offsets, not cryptographic.
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Exponential backoff and attempt-limit policy.
///
/// [`RetryPolicy::backoff`] returns `initial_backoff * 2^(attempt - 1)`,
/// saturating arithmetic throughout, capped at `max_backoff`. The
/// total-wait cap bounds a sum of waits, which only [`Backoff`] sees.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Wait before the first retry. Doubles each subsequent attempt.
    initial_backoff: Duration,
    /// Ceiling for the exponential backoff.
    max_backoff: Duration,
    /// Give up after this many consecutive failed attempts. `None` retries
    /// forever.
    max_attempts: Option<u32>,
    /// Total wait ceiling of one episode. `None` waits forever.
    max_total_backoff: Option<Duration>,
    /// Whether [`Backoff`] spreads waits with equal jitter, keeping half each wait and drawing the other half uniformly.
    jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(5),
            max_attempts: None,
            max_total_backoff: None,
            jitter: true,
        }
    }
}

impl RetryPolicy {
    /// The defaults: 200 ms initial backoff, 5 s ceiling, retry forever,
    /// jitter on.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wait before the first retry. Doubles each subsequent attempt.
    #[must_use]
    pub const fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }

    /// Ceiling for the exponential backoff.
    #[must_use]
    pub const fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    /// Attempts this episode may wait for, giving up on failure number one past it. `None` retries forever.
    #[must_use]
    pub const fn with_max_attempts(mut self, max_attempts: Option<u32>) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// Ceiling on the total wait time of one episode. `None` never caps.
    #[must_use]
    pub const fn with_max_total_backoff(mut self, max_total_backoff: Option<Duration>) -> Self {
        self.max_total_backoff = max_total_backoff;
        self
    }

    /// Whether the [`Backoff`] driver spreads waits with equal jitter.
    #[must_use]
    pub const fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }

    /// Wait before the first retry.
    #[must_use]
    pub const fn initial_backoff(&self) -> Duration {
        self.initial_backoff
    }

    /// Ceiling for the exponential backoff.
    #[must_use]
    pub const fn max_backoff(&self) -> Duration {
        self.max_backoff
    }

    /// Attempt limit. `None` retries forever.
    #[must_use]
    pub const fn max_attempts(&self) -> Option<u32> {
        self.max_attempts
    }

    /// Total-wait ceiling of an episode. `None` never caps.
    #[must_use]
    pub const fn max_total_backoff(&self) -> Option<Duration> {
        self.max_total_backoff
    }

    /// Whether the [`Backoff`] driver spreads waits.
    #[must_use]
    pub const fn jitter(&self) -> bool {
        self.jitter
    }

    /// Backoff before the `attempt`-th retry (1-based).
    ///
    /// Computes `initial_backoff * 2^(attempt - 1)`, saturating throughout,
    /// capped at `max_backoff`, deterministic so single-shot callers and
    /// tests read the formula itself. [`Backoff`] adds jitter on top.
    #[must_use]
    pub fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2u128.saturating_pow(attempt.saturating_sub(1));
        let millis = self
            .initial_backoff
            .as_millis()
            .saturating_mul(factor)
            .min(self.max_backoff.as_millis());
        Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
    }

    /// Start a retry episode under this policy, seeded so concurrent episodes
    /// spread their waits apart.
    #[must_use]
    pub fn start(&self) -> Backoff<'_> {
        Backoff::new(self)
    }
}

/// The stateful driver of one retry episode, ending it with `None` once a
/// hard cap says stop. The total cap counts the waits handed out, not wall
/// clock: the attempt's own work is not backoff.
#[derive(Debug)]
pub struct Backoff<'p> {
    policy: &'p RetryPolicy,
    attempt: u32,
    waited: Duration,
    seed: u64,
}

impl<'p> Backoff<'p> {
    /// A fresh episode, seeded so episodes that start together do not wait identically.
    #[must_use]
    pub fn new(policy: &'p RetryPolicy) -> Self {
        let seed = mix(SEED.fetch_add(1, Ordering::Relaxed));
        Self::with_seed(policy, seed)
    }

    /// A fresh episode whose waits are reproducible, for tests.
    #[must_use]
    pub const fn with_seed(policy: &'p RetryPolicy, seed: u64) -> Self {
        Self {
            policy,
            attempt: 0,
            waited: Duration::ZERO,
            seed,
        }
    }

    /// The wait before the next retry, or `None` once a cap ends the episode.
    /// Calling this counts the attempt, also on the `None`.
    #[must_use]
    pub fn next_wait(&mut self) -> Option<Duration> {
        self.attempt = self.attempt.saturating_add(1);
        if self
            .policy
            .max_attempts
            .is_some_and(|max| self.attempt > max)
        {
            return None;
        }
        let mut wait = self.policy.backoff(self.attempt);
        if self.policy.jitter {
            wait = self.jittered(wait);
        }
        if let Some(cap) = self.policy.max_total_backoff {
            let left = cap.saturating_sub(self.waited);
            if left.is_zero() {
                return None;
            }
            wait = wait.min(left);
        }
        self.waited = self.waited.saturating_add(wait);
        Some(wait)
    }

    /// Attempts counted, the one-based index of the last [`Backoff::next_wait`].
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The total time handed out as waits in this episode.
    #[must_use]
    pub const fn waited(&self) -> Duration {
        self.waited
    }

    /// Fresh schedule, earned by a connection healthy enough to have been worth holding.
    pub fn reset(&mut self) {
        self.attempt = 0;
        self.waited = Duration::ZERO;
    }

    /// Equal jitter: `[wait / 2, wait]`, uniform in it, so the schedule still
    /// grows and a shared outage spreads across the window.
    fn jittered(&self, wait: Duration) -> Duration {
        let total = u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX);
        let half = total / 2;
        let span = total - half;
        let draw = mix(self.seed ^ mix(u64::from(self.attempt)));
        Duration::from_nanos(half + draw % span.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::{Backoff, Duration, RetryPolicy};

    #[test]
    fn defaults_are_two_hundred_millis_to_five_seconds_forever() {
        let policy = RetryPolicy::new();
        assert_eq!(policy.initial_backoff(), Duration::from_millis(200));
        assert_eq!(policy.max_backoff(), Duration::from_secs(5));
        assert_eq!(policy.max_attempts(), None);
        assert_eq!(policy.max_total_backoff(), None);
        assert!(policy.jitter());
    }

    #[test]
    fn backoff_sequence_5s_ceiling() {
        let policy = RetryPolicy::new();
        let expected_ms: [u64; 6] = [200, 400, 800, 1600, 3200, 5000];
        for (i, &ms) in expected_ms.iter().enumerate() {
            let attempt = u32::try_from(i + 1).unwrap();
            assert_eq!(policy.backoff(attempt), Duration::from_millis(ms));
        }
    }

    #[test]
    fn backoff_sequence_30s_ceiling() {
        let policy = RetryPolicy::new().with_max_backoff(Duration::from_secs(30));
        let expected_ms: [u64; 6] = [200, 400, 800, 1600, 3200, 6400];
        for (i, &ms) in expected_ms.iter().enumerate() {
            let attempt = u32::try_from(i + 1).unwrap();
            assert_eq!(policy.backoff(attempt), Duration::from_millis(ms));
        }
    }

    /// With jitter off the driver walks the pinned formula.
    #[test]
    fn a_jitterless_episode_walks_the_formula() {
        let policy = RetryPolicy::new().with_jitter(false);
        let mut episode = policy.start();
        let expected_ms: [u64; 4] = [200, 400, 800, 1600];
        for ms in expected_ms {
            assert_eq!(episode.next_wait(), Some(Duration::from_millis(ms)));
        }
        assert_eq!(episode.attempt(), 4);
        assert_eq!(episode.waited(), Duration::from_millis(3000));
    }

    /// Equal jitter bounds: never under half, never over the computed wait.
    #[test]
    fn jitter_stays_inside_its_window() {
        let policy = RetryPolicy::new();
        for seed in 0..64_u64 {
            let mut episode = Backoff::with_seed(&policy, seed);
            let wait = episode.next_wait().expect("no attempt cap");
            assert!(
                wait >= Duration::from_millis(100) && wait <= Duration::from_millis(200),
                "seed {seed} drew {wait:?} outside [100ms, 200ms]"
            );
        }
    }

    /// Distinct seeds draw distinct waits, so a fleet does not come back at one instant.
    #[test]
    fn distinct_seeds_spread_the_waits_apart() {
        let policy = RetryPolicy::new();
        let drawn: Vec<Duration> = (0..16_u64)
            .map(|seed| {
                Backoff::with_seed(&policy, seed)
                    .next_wait()
                    .expect("no attempt cap")
            })
            .collect();
        let first = drawn[0];
        assert!(
            drawn.iter().filter(|w| **w != first).count() > 8,
            "jitter must spread, most draws were {first:?}: {drawn:?}"
        );
    }

    #[test]
    fn the_attempt_cap_ends_the_episode_on_the_next_call() {
        let policy = RetryPolicy::new()
            .with_jitter(false)
            .with_max_attempts(Some(2));
        let mut episode = policy.start();
        assert_eq!(episode.next_wait(), Some(Duration::from_millis(200)));
        assert_eq!(episode.next_wait(), Some(Duration::from_millis(400)));
        assert_eq!(episode.next_wait(), None);
        assert_eq!(episode.attempt(), 3);
    }

    /// The episode ends when the wait budget is spent, whatever the attempt count says.
    #[test]
    fn the_total_wait_cap_ends_the_episode_when_spent() {
        let policy = RetryPolicy::new()
            .with_jitter(false)
            .with_max_total_backoff(Some(Duration::from_millis(500)));
        let mut episode = policy.start();
        assert_eq!(episode.next_wait(), Some(Duration::from_millis(200)));
        assert_eq!(episode.next_wait(), Some(Duration::from_millis(300)));
        assert_eq!(episode.next_wait(), None);
        assert_eq!(episode.waited(), Duration::from_millis(500));
    }

    /// The last wait is trimmed to the budget left rather than skipped whole.
    #[test]
    fn the_total_wait_cap_trims_the_last_wait() {
        let policy = RetryPolicy::new()
            .with_jitter(false)
            .with_max_total_backoff(Some(Duration::from_millis(250)));
        let mut episode = policy.start();
        assert_eq!(episode.next_wait(), Some(Duration::from_millis(200)));
        assert_eq!(episode.next_wait(), Some(Duration::from_millis(50)));
        assert_eq!(episode.next_wait(), None);
    }

    /// A healthy connection earns a fresh schedule: both counters restart.
    #[test]
    fn reset_earns_a_fresh_schedule() {
        let policy = RetryPolicy::new().with_jitter(false);
        let mut episode = policy.start();
        assert_eq!(episode.next_wait(), Some(Duration::from_millis(200)));
        assert_eq!(episode.next_wait(), Some(Duration::from_millis(400)));
        episode.reset();
        assert_eq!(episode.attempt(), 0);
        assert_eq!(episode.waited(), Duration::ZERO);
        assert_eq!(episode.next_wait(), Some(Duration::from_millis(200)));
    }

    /// Half a millisecond plus a draw of the other half never lands on zero.
    #[test]
    fn jitter_never_collapses_a_smallest_wait_to_zero() {
        let policy = RetryPolicy::new().with_initial_backoff(Duration::from_millis(1));
        for seed in 0..16_u64 {
            let mut episode = Backoff::with_seed(&policy, seed);
            let wait = episode.next_wait().expect("no attempt cap");
            assert!(
                wait >= Duration::from_micros(500) && wait <= Duration::from_millis(1),
                "seed {seed} drew {wait:?} outside [500us, 1ms]"
            );
        }
    }
}
