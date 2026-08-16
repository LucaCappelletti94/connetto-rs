//! R5b acceptance: the change path asks the authorization service nothing.
//!
//! Two runs an order of magnitude apart in subscriber count. **The
//! authorization counter must read exactly zero in both**, which is stronger
//! than the "does not grow" the phase originally promised, and it is what
//! connetto's own policy shape earns: the caller's identity and the keys the
//! caller holds are both read from the changed row, so no watcher costs a round
//! trip at any audience size.
//!
//! **This file used to assert the opposite** and pinned the defect R5b existed
//! to remove: one Postgres round trip per subscriber per event. The three other
//! assertions are unchanged and still pin costs that do grow. R14 was to remove
//! them and was dropped on 2026-08-16, measured immaterial beside the per-event
//! floor, so they travel with the shared payload to the phase that builds the
//! frame split.
//!
//! What the counter does not claim: that no policy ever costs a round trip. A
//! policy that reads another table is delegated and is linear in the watchers
//! the row does not settle, divided by the batch cap. That case is asserted in
//! `fanout_delegated.rs`, so neither half can quietly become the other.
//!
//! `#[ignore]` by default: it needs a Postgres started with
//! `wal_level=logical` and an `OpenFGA` server. Run under Docker with
//! `DATABASE_URL` and `CONNETTO_TEST_FGA_URL` pointed at them and `-- --ignored`.

use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::{PolicyShape, fanout_run};

/// The small run's subscriber count.
const SMALL: u64 = 10;
/// The large run's subscriber count, an order of magnitude above [`SMALL`].
const LARGE: u64 = 100;
/// Rows written per run, one CDC event each.
const EVENTS: u64 = 5;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical and an OpenFGA server (Docker)"]
async fn the_change_path_asks_the_service_nothing_whatever_the_audience() {
    let fixture = Fixture::acquire().await;
    let small = fanout_run(&fixture, SMALL, EVENTS, PolicyShape::Row).await;
    let large = fanout_run(&fixture, LARGE, EVENTS, PolicyShape::Row).await;

    // Zero, not merely flat. Both arms of the policy are read from the changed
    // row, so the service is never asked, and a single call here would mean a
    // relation stopped being decidable from one row.
    assert_eq!(
        small.counters.authorization_calls, 0,
        "authorization round trips at {SMALL} subscribers"
    );
    assert_eq!(
        large.counters.authorization_calls, 0,
        "authorization round trips at {LARGE} subscribers"
    );

    // One Route clone per subscriber per event, exactly.
    assert_eq!(
        small.counters.fanout_route_clones,
        SMALL * EVENTS,
        "route clones at {SMALL} subscribers"
    );
    assert_eq!(
        large.counters.fanout_route_clones,
        LARGE * EVENTS,
        "route clones at {LARGE} subscribers"
    );

    // The dispatch and oplog_record takes are per event regardless of the
    // subscriber count, and any transaction-control events cost the same in
    // both runs, so the difference between the runs isolates the
    // per-subscriber advance_cursor takes. A lower bound rather than equality,
    // since time-based source events would only ever add takes.
    let extra_lock_takes =
        large.counters.materializer_lock_takes - small.counters.materializer_lock_takes;
    assert!(
        extra_lock_takes >= (LARGE - SMALL) * EVENTS,
        "per-subscriber lock takes grew by {extra_lock_takes}, expected at least {}",
        (LARGE - SMALL) * EVENTS
    );

    // Both runs write identical rows, so per-event payloads match up to
    // cursor jitter inside the compressed patchset, and the copied bytes
    // scale with the subscriber ratio.
    assert!(
        large.counters.fanout_payload_bytes >= small.counters.fanout_payload_bytes * 8,
        "payload bytes copied did not grow with subscriber count: {} vs {}",
        large.counters.fanout_payload_bytes,
        small.counters.fanout_payload_bytes
    );
    assert!(
        large.counters.fanout_payload_bytes <= small.counters.fanout_payload_bytes * 12,
        "payload bytes copied grew faster than the subscriber ratio: {} vs {}",
        large.counters.fanout_payload_bytes,
        small.counters.fanout_payload_bytes
    );
}
