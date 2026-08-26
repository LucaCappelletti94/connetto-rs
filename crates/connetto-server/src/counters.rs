//! Always-on measurement counters for the change-dispatch path (phase R0).
//!
//! Decided with the maintainer: plain relaxed atomics, never feature-gated. An
//! uncontended relaxed increment costs single-digit nanoseconds beside the
//! operations these count (a mutex take, a payload copy, a per-subscriber
//! Postgres round trip), and gating them would make the measured binary a
//! different binary from the shipped one. They are a permanent instrument, not
//! a probe: the fan-out counter test reads them through [`snapshot`] and stays
//! in the gate, pinning the round trips R5b removed at zero and holding the
//! three per-subscriber costs R14 measured on 2026-08-16 and left in place.
//!
//! **This module is instrumentation carried in the shipped binary on purpose,
//! and it is removable.** Decided with the maintainer on 2026-08-07, settling
//! R0 part B's timing instrument: the cost is accepted while the project is
//! pre-alpha, on the condition that its presence stays visible rather than
//! quietly permanent. Deleting it later is this module, the [`timed_lock`]
//! calls in `SessionManager::dispatch_event`, and the two harness readers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::{Mutex, MutexGuard};

/// Materializer mutex acquisitions on the dispatch path: the `dispatch` and
/// `oplog_record` takes once per event, plus the `advance_cursor` take once
/// per delivered subscriber per event. Counted by [`timed_lock`], which is the
/// only way the dispatch path takes that lock, so this and
/// [`MATERIALIZER_LOCK_WAIT_NANOS`] always describe the same set of
/// acquisitions.
pub static MATERIALIZER_LOCK_TAKES: AtomicU64 = AtomicU64::new(0);

/// Nanoseconds the dispatch path spent blocked waiting for the materializer
/// lock, summed over every acquisition [`MATERIALIZER_LOCK_TAKES`] counts.
///
/// This is the number that says whether the mutex hurts, which a count cannot:
/// an uncontended acquisition costs tens of nanoseconds, so `3 + K` of them per
/// event can look alarming and be free. Read it as a share of a run's
/// wall-clock duration. The sum runs across tasks, so a share above one means
/// callers were queued behind each other rather than merely waiting.
pub static MATERIALIZER_LOCK_WAIT_NANOS: AtomicU64 = AtomicU64::new(0);

/// Compressed payload bytes copied in the fan-out: one full copy of the
/// event's `payload_zstd` per matched consumer, so this grows with patch size
/// as well as with subscriber count.
pub static FANOUT_PAYLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

/// `Route` clones in the fan-out, one per delivered subscriber per event, each
/// carrying an owned identity context.
pub static FANOUT_ROUTE_CLONES: AtomicU64 = AtomicU64::new(0);

/// Round trips the change path spends asking whether a row is visible: one per
/// `SELECT EXISTS` sent, not one per trait call. R5a answers the trait once per
/// event for every watcher at once while still running a query per watcher, so
/// a counter on the call would read 1 and hide the round trips R5b removes.
pub static AUTHORIZATION_CALLS: AtomicU64 = AtomicU64::new(0);

/// Rows the two executors disagreed about, one per watcher per changed row.
///
/// **Zero is the only acceptable reading and every Docker-backed suite asserts
/// it.** One policy source compiles to two executors, and nothing else in this
/// tree can notice them drifting apart: the snapshot answers from row-level
/// security and the change path answers from the model, so a divergence shows
/// up to a client as a row that is there and then is not. A count above zero
/// is that, caught before anybody sees it.
///
/// Only a [`SecondOpinion`](crate::parity::SecondOpinion) moves it, asked from
/// the two delivery sites about the row as it is now, which is the only version
/// row-level security can answer about.
pub static VISIBILITY_DISAGREEMENTS: AtomicU64 = AtomicU64::new(0);

/// Maintenance-tier transitions: a subscription that outgrew its fold budget
/// or lost an image it needed and now answers by database read (R30's
/// demotion). Correctness is unchanged, cost is not, which is why this is a
/// counter beside a log line rather than a client-visible signal.
pub static TIER_TRANSITIONS: AtomicU64 = AtomicU64::new(0);

/// Increment `counter` by `n`, relaxed.
#[inline]
pub fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

/// Take `lock`, counting the acquisition and adding any time spent blocked to
/// [`MATERIALIZER_LOCK_WAIT_NANOS`].
///
/// **An acquisition that does not wait reads no clock.** Timing every
/// acquisition unconditionally would cost two clock reads where the
/// uncontended take costs one atomic exchange, the same order, so the
/// instrument would become a visible part of the number it reports once R5b
/// removed the Postgres round trips that used to dominate this path, which is
/// the state R14 re-read it in on 2026-08-16.
///
/// Trying first cannot cut ahead of a caller already queued: tokio hands a
/// released permit straight to the head of its wait list and returns it to the
/// permit count only when nobody is queued, so `try_lock` succeeds precisely
/// when `lock` would have succeeded without parking.
pub async fn timed_lock<T: ?Sized>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    add(&MATERIALIZER_LOCK_TAKES, 1);
    if let Ok(guard) = lock.try_lock() {
        return guard;
    }
    let blocked_since = Instant::now();
    let guard = lock.lock().await;
    add(
        &MATERIALIZER_LOCK_WAIT_NANOS,
        u64::try_from(blocked_since.elapsed().as_nanos()).unwrap_or(u64::MAX),
    );
    guard
}

/// A point-in-time reading of every dispatch-path counter.
///
/// The counters are process-global and monotonic, so a measurement brackets
/// its window with two readings and takes [`since`](Self::since).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountersSnapshot {
    /// [`MATERIALIZER_LOCK_TAKES`] at the reading.
    pub materializer_lock_takes: u64,
    /// [`MATERIALIZER_LOCK_WAIT_NANOS`] at the reading.
    pub materializer_lock_wait_nanos: u64,
    /// [`FANOUT_PAYLOAD_BYTES`] at the reading.
    pub fanout_payload_bytes: u64,
    /// [`FANOUT_ROUTE_CLONES`] at the reading.
    pub fanout_route_clones: u64,
    /// [`AUTHORIZATION_CALLS`] at the reading.
    pub authorization_calls: u64,
    /// [`VISIBILITY_DISAGREEMENTS`] at the reading.
    pub visibility_disagreements: u64,
}

impl CountersSnapshot {
    /// The per-counter change from `earlier` to `self`.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            materializer_lock_takes: self.materializer_lock_takes - earlier.materializer_lock_takes,
            materializer_lock_wait_nanos: self.materializer_lock_wait_nanos
                - earlier.materializer_lock_wait_nanos,
            fanout_payload_bytes: self.fanout_payload_bytes - earlier.fanout_payload_bytes,
            fanout_route_clones: self.fanout_route_clones - earlier.fanout_route_clones,
            authorization_calls: self.authorization_calls - earlier.authorization_calls,
            visibility_disagreements: self.visibility_disagreements
                - earlier.visibility_disagreements,
        }
    }
}

/// Read every counter, relaxed.
#[must_use]
pub fn snapshot() -> CountersSnapshot {
    CountersSnapshot {
        materializer_lock_takes: MATERIALIZER_LOCK_TAKES.load(Ordering::Relaxed),
        materializer_lock_wait_nanos: MATERIALIZER_LOCK_WAIT_NANOS.load(Ordering::Relaxed),
        fanout_payload_bytes: FANOUT_PAYLOAD_BYTES.load(Ordering::Relaxed),
        fanout_route_clones: FANOUT_ROUTE_CLONES.load(Ordering::Relaxed),
        authorization_calls: AUTHORIZATION_CALLS.load(Ordering::Relaxed),
        visibility_disagreements: VISIBILITY_DISAGREEMENTS.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{
        MATERIALIZER_LOCK_TAKES, MATERIALIZER_LOCK_WAIT_NANOS, Mutex, Ordering, timed_lock,
    };

    /// How long the contended take is made to wait.
    const HELD: Duration = Duration::from_millis(200);
    /// How much of that the assertion insists on seeing, leaving room for the
    /// contender to be scheduled and park.
    const AT_LEAST: Duration = Duration::from_millis(100);

    /// R0 part B reports the wait as **zero** at both subscriber counts, which
    /// is a finding only if an instrument that always reported zero would look
    /// different. Both halves are asserted here, in one test rather than two,
    /// because the counters are process-global and a second test running
    /// beside this one would move them under it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_wait_instrument_reports_a_wait_and_only_a_wait() {
        let lock = Arc::new(Mutex::new(()));
        let takes = MATERIALIZER_LOCK_TAKES.load(Ordering::Relaxed);
        let waited = MATERIALIZER_LOCK_WAIT_NANOS.load(Ordering::Relaxed);

        drop(timed_lock(&lock).await);
        assert_eq!(
            MATERIALIZER_LOCK_WAIT_NANOS.load(Ordering::Relaxed),
            waited,
            "a take that never waited reported a wait"
        );

        let guard = timed_lock(&lock).await;
        let contender = tokio::spawn({
            let lock = Arc::clone(&lock);
            async move {
                drop(timed_lock(&lock).await);
            }
        });
        tokio::time::sleep(HELD).await;
        drop(guard);
        contender.await.expect("the contender panicked");

        let recorded = MATERIALIZER_LOCK_WAIT_NANOS.load(Ordering::Relaxed) - waited;
        assert!(
            recorded >= u64::try_from(AT_LEAST.as_nanos()).expect("the bound fits"),
            "a take blocked for {HELD:?} recorded {recorded}ns of waiting"
        );
        assert_eq!(
            MATERIALIZER_LOCK_TAKES.load(Ordering::Relaxed) - takes,
            3,
            "the count and the wait must describe the same acquisitions"
        );
    }
}
