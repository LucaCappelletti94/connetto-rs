//! A strict reserved share of the reader pool for identified callers (R39).
//!
//! Admission rather than rate limiting: the limits in
//! [`throttle`](crate::throttle) bound what one caller may ask for over time,
//! while this bounds what unidentified callers may hold in flight at once. A
//! rate limit has to recognise the caller, so a caller that discards its name
//! escapes it. A reservation only has to count, so nothing escapes it.
//!
//! The guarantee is arithmetic. Unidentified callers may occupy the reader
//! pool's total less the reserve and no more, so a connection stays reachable
//! for an identified caller whatever volume of unidentified traffic arrives
//! and however many identities it cycles through. The share is held back even
//! when no identified caller wants it (strict, not work-conserving), because
//! draining in-flight anonymous work can take as long as a snapshot transfer.
//! The design record is `docs/architecture/16-server-capacity.md`.
//!
//! One [`ReaderGate`] guards one pool. Every holder must clone the same gate,
//! since a second gate built from the same [`ReaderReserve`] would grant its
//! own unreserved share.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::throttle::Tier;

/// How long an over-share unidentified checkout queues before it is refused.
///
/// The cheap occupants of the share (visibility questions, watermark reads)
/// turn over in milliseconds, so a short queue absorbs bursts without a
/// client-visible refusal, and the queue is fair because the permits are
/// first-come-first-served. The long occupant is a snapshot read, which no
/// short wait rides out, so past this deadline the refusal is honest. A
/// queued caller holds no connection.
const ANONYMOUS_WAIT: Duration = Duration::from_secs(1);

/// How the reader pool is split between the tiers.
///
/// Built as a chain of calls like [`ThrottleConfig`](crate::ThrottleConfig).
/// The `total` must match the pool this split gates, and the default numbers
/// are revisited against the post-R5b load measurement rather than tuned here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderReserve {
    total: u32,
    reserved: u32,
}

impl Default for ReaderReserve {
    fn default() -> Self {
        Self::new()
    }
}

impl ReaderReserve {
    /// The default reader pool size: bb8's own default of ten, made explicit.
    pub const DEFAULT_TOTAL: u32 = 10;
    /// The default reserve, chosen generous: three of the ten connections are
    /// reachable only by identified callers.
    pub const DEFAULT_RESERVED: u32 = 3;

    /// The default split: [`DEFAULT_RESERVED`](Self::DEFAULT_RESERVED) of
    /// [`DEFAULT_TOTAL`](Self::DEFAULT_TOTAL) connections held back.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            total: Self::DEFAULT_TOTAL,
            reserved: Self::DEFAULT_RESERVED,
        }
    }

    /// The reader pool's configured total.
    #[must_use]
    pub const fn with_total(mut self, connections: u32) -> Self {
        self.total = connections;
        self
    }

    /// How many of those connections only identified callers may reach.
    ///
    /// Equal to the total, unidentified callers never reach the database.
    #[must_use]
    pub const fn with_reserved(mut self, connections: u32) -> Self {
        self.reserved = connections;
        self
    }

    /// Build the gate enforcing this split.
    ///
    /// # Panics
    ///
    /// When the reserve exceeds the total, at configuration time, because no
    /// such split exists.
    #[must_use]
    pub fn gate(self) -> ReaderGate {
        assert!(
            self.reserved <= self.total,
            "reader reserve ({}) exceeds the pool total ({})",
            self.reserved,
            self.total
        );
        let share = usize::try_from(self.total - self.reserved).expect("u32 fits in usize");
        ReaderGate {
            anonymous: Arc::new(Semaphore::new(share)),
        }
    }
}

/// The permit split over one reader pool.
///
/// Cloning shares the split: hand the same gate to the
/// [`RequestGuard`](crate::RequestGuard) and to a
/// [`CapabilityIssuer`](crate::CapabilityIssuer) reading through the same
/// pool.
#[derive(Debug, Clone)]
pub struct ReaderGate {
    anonymous: Arc<Semaphore>,
}

impl ReaderGate {
    /// A permit to check out one reader connection as `tier`.
    ///
    /// An identified caller is never gated: the pool itself is its bound, and
    /// the reserve exists so this call can always say yes to it. An
    /// unidentified caller takes from the unreserved share, queuing up to
    /// [`ANONYMOUS_WAIT`] when the share is full and drawing the refusal with
    /// retry advice past that. The permit returns on drop, so every exit path
    /// releases it.
    pub(crate) async fn acquire(&self, tier: Tier) -> Result<ReaderPermit, Duration> {
        match tier {
            Tier::Identified => Ok(ReaderPermit { _permit: None }),
            Tier::Anonymous => {
                let acquire = Arc::clone(&self.anonymous).acquire_owned();
                match tokio::time::timeout(ANONYMOUS_WAIT, acquire).await {
                    Ok(permit) => Ok(ReaderPermit {
                        _permit: Some(permit.expect("the reader gate semaphore is never closed")),
                    }),
                    Err(_deadline) => Err(ANONYMOUS_WAIT),
                }
            }
        }
    }
}

/// Occupancy of the unreserved share for the span of one reader-pool
/// operation. Dropping it returns the share.
#[derive(Debug)]
pub(crate) struct ReaderPermit {
    _permit: Option<OwnedSemaphorePermit>,
}

impl ReaderPermit {
    /// The no-op permit, for hosts with no gate configured.
    pub(crate) const fn none() -> Self {
        Self { _permit: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn identified_callers_never_take_from_the_share() {
        // The share is zero wide, yet every identified acquire succeeds.
        let gate = ReaderReserve::new().with_total(1).with_reserved(1).gate();
        let _a = gate.acquire(Tier::Identified).await.expect("first");
        let _b = gate.acquire(Tier::Identified).await.expect("second");
    }

    #[tokio::test(start_paused = true)]
    async fn the_share_is_the_total_less_the_reserve() {
        let gate = ReaderReserve::new().with_total(3).with_reserved(1).gate();
        let held = gate.acquire(Tier::Anonymous).await.expect("first of two");
        let _second = gate.acquire(Tier::Anonymous).await.expect("second of two");
        // The third is over the share, queued to the deadline, then refused
        // with the wait as retry advice.
        let wait = gate
            .acquire(Tier::Anonymous)
            .await
            .expect_err("the share is full");
        assert_eq!(wait, ANONYMOUS_WAIT);
        // A permit returning by drop reopens the share on every exit path.
        drop(held);
        let _third = gate.acquire(Tier::Anonymous).await.expect("after return");
    }

    #[tokio::test(start_paused = true)]
    async fn a_reserve_equal_to_the_total_turns_anonymous_access_off() {
        let gate = ReaderReserve::new().with_total(2).with_reserved(2).gate();
        gate.acquire(Tier::Anonymous)
            .await
            .expect_err("the share is zero wide");
        let _identified = gate.acquire(Tier::Identified).await.expect("identified");
    }

    #[tokio::test(start_paused = true)]
    async fn clones_share_one_split() {
        let gate = ReaderReserve::new().with_total(2).with_reserved(1).gate();
        let sibling = gate.clone();
        let _held = gate.acquire(Tier::Anonymous).await.expect("first");
        sibling
            .acquire(Tier::Anonymous)
            .await
            .expect_err("one split across clones");
    }

    #[test]
    #[should_panic(expected = "exceeds the pool total")]
    fn a_reserve_over_the_total_refuses_configuration() {
        let _ = ReaderReserve::new().with_total(2).with_reserved(3).gate();
    }
}
