//! Exponential-backoff retry policy shared across every reconnect driver.
//!
//! The server-side CDC reconnect loop and the native/wasm client reconnect
//! driver both need the same three-field backoff shape. Centralising it here
//! keeps the computation in one place and lets each caller add its own wrapper
//! fields (the server adds `healthy_after`, the client re-exports the type
//! directly).

use core::time::Duration;

/// Exponential backoff and attempt-limit policy.
///
/// [`RetryPolicy::backoff`] returns `initial_backoff * 2^(attempt - 1)`,
/// saturating arithmetic throughout, capped at `max_backoff`.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Wait before the first retry. Doubles each subsequent attempt.
    initial_backoff: Duration,
    /// Ceiling for the exponential backoff.
    max_backoff: Duration,
    /// Give up after this many consecutive failed attempts. `None` retries
    /// forever.
    max_attempts: Option<u32>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(5),
            max_attempts: None,
        }
    }
}

impl RetryPolicy {
    /// The defaults: 200 ms initial backoff, 5 s ceiling, retry forever.
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

    /// Give up after this many attempts. `None` retries forever.
    #[must_use]
    pub const fn with_max_attempts(mut self, max_attempts: Option<u32>) -> Self {
        self.max_attempts = max_attempts;
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

    /// Backoff before the `attempt`-th retry (1-based).
    ///
    /// Computes `initial_backoff * 2^(attempt - 1)`, saturating throughout,
    /// capped at `max_backoff`.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirms the first six backoff values for the 5 s ceiling (default)
    /// and verifies saturation at a large attempt number.
    #[test]
    fn backoff_sequence_5s_ceiling() {
        let policy = RetryPolicy::new();
        let expected_ms: [u64; 6] = [200, 400, 800, 1600, 3200, 5000];
        for (i, &ms) in expected_ms.iter().enumerate() {
            let attempt = u32::try_from(i + 1).unwrap();
            assert_eq!(
                policy.backoff(attempt),
                Duration::from_millis(ms),
                "attempt {attempt}"
            );
        }
        assert_eq!(
            policy.backoff(u32::MAX),
            Duration::from_secs(5),
            "saturates at max_backoff"
        );
    }

    /// Confirms the first six backoff values for the 30 s ceiling (server
    /// default) and verifies saturation at a large attempt number.
    #[test]
    fn backoff_sequence_30s_ceiling() {
        let policy = RetryPolicy::new().with_max_backoff(Duration::from_secs(30));
        let expected_ms: [u64; 6] = [200, 400, 800, 1600, 3200, 6400];
        for (i, &ms) in expected_ms.iter().enumerate() {
            let attempt = u32::try_from(i + 1).unwrap();
            assert_eq!(
                policy.backoff(attempt),
                Duration::from_millis(ms),
                "attempt {attempt}"
            );
        }
        assert_eq!(
            policy.backoff(u32::MAX),
            Duration::from_secs(30),
            "saturates at max_backoff"
        );
    }
}
