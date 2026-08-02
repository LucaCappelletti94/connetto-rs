//! Always-on measurement counters for the change-dispatch path (phase R0).
//!
//! Decided with the maintainer: plain relaxed atomics, never feature-gated. An
//! uncontended relaxed increment costs single-digit nanoseconds beside the
//! operations these count (a mutex take, a payload copy, a per-subscriber
//! Postgres round trip), and gating them would make the measured binary a
//! different binary from the shipped one. They are a permanent instrument, not
//! a probe: the fan-out counter test reads them through [`snapshot`] and stays
//! in the gate as the regression guard on per-event work staying independent
//! of subscriber count once R5b and R14 deliver that property.

use std::sync::atomic::{AtomicU64, Ordering};

/// Materializer mutex acquisitions on the dispatch path: the `dispatch` and
/// `oplog_record` takes once per event, plus the `advance_cursor` take once
/// per delivered subscriber per event.
pub static MATERIALIZER_LOCK_TAKES: AtomicU64 = AtomicU64::new(0);

/// Compressed payload bytes copied in the fan-out: one full copy of the
/// event's `payload_zstd` per matched consumer, so this grows with patch size
/// as well as with subscriber count.
pub static FANOUT_PAYLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

/// `Route` clones in the fan-out, one per delivered subscriber per event, each
/// carrying an owned identity context.
pub static FANOUT_ROUTE_CLONES: AtomicU64 = AtomicU64::new(0);

/// Authorization questions asked on the change path. Until R5a this sits on
/// `RlsAuth::can_read` and relocates onto the subql visibility trait with it,
/// after which it never moves again.
pub static AUTHORIZATION_CALLS: AtomicU64 = AtomicU64::new(0);

/// Increment `counter` by `n`, relaxed.
#[inline]
pub fn add(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

/// A point-in-time reading of every dispatch-path counter.
///
/// The counters are process-global and monotonic, so a measurement brackets
/// its window with two readings and takes [`since`](Self::since).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountersSnapshot {
    /// [`MATERIALIZER_LOCK_TAKES`] at the reading.
    pub materializer_lock_takes: u64,
    /// [`FANOUT_PAYLOAD_BYTES`] at the reading.
    pub fanout_payload_bytes: u64,
    /// [`FANOUT_ROUTE_CLONES`] at the reading.
    pub fanout_route_clones: u64,
    /// [`AUTHORIZATION_CALLS`] at the reading.
    pub authorization_calls: u64,
}

impl CountersSnapshot {
    /// The per-counter change from `earlier` to `self`.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            materializer_lock_takes: self.materializer_lock_takes - earlier.materializer_lock_takes,
            fanout_payload_bytes: self.fanout_payload_bytes - earlier.fanout_payload_bytes,
            fanout_route_clones: self.fanout_route_clones - earlier.fanout_route_clones,
            authorization_calls: self.authorization_calls - earlier.authorization_calls,
        }
    }
}

/// Read every counter, relaxed.
#[must_use]
pub fn snapshot() -> CountersSnapshot {
    CountersSnapshot {
        materializer_lock_takes: MATERIALIZER_LOCK_TAKES.load(Ordering::Relaxed),
        fanout_payload_bytes: FANOUT_PAYLOAD_BYTES.load(Ordering::Relaxed),
        fanout_route_clones: FANOUT_ROUTE_CLONES.load(Ordering::Relaxed),
        authorization_calls: AUTHORIZATION_CALLS.load(Ordering::Relaxed),
    }
}
