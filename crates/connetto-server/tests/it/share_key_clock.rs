//! A per-fixture clock for session share-key expiry.

use std::time::{Duration, SystemTime};

use connetto_server::SessionConfig;
use tokio::sync::watch;

/// One fixture's expiry clock, starting at the fixed Unix second 1000.
pub(super) struct ExpiryClock {
    now: watch::Sender<SystemTime>,
}

impl ExpiryClock {
    /// A clock at its fixed starting second.
    pub(super) fn new() -> Self {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let (now, _) = watch::channel(start);
        Self { now }
    }

    pub(super) fn session_config(&self) -> SessionConfig {
        SessionConfig::new().with_key_expiry_clock(self.now.subscribe())
    }

    /// A grant for `key` that dies one second after the clock's current second.
    pub(super) fn grant(&self, key: &str) -> String {
        format!("{key}@{}", self.seconds() + 1)
    }

    /// Move the clock forward by `by`, waking the sessions waiting on it.
    pub(super) fn advance(&self, by: Duration) {
        self.now.send_modify(|now| *now += by);
    }

    fn seconds(&self) -> u64 {
        self.now
            .borrow()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("the clock stays after the epoch")
            .as_secs()
    }
}
