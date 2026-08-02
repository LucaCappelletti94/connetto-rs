//! R0 part A acceptance: the fan-out scaling defect, stated executably.
//!
//! Two runs an order of magnitude apart in subscriber count, and per-event
//! dispatch work is asserted to GROW with that count: one authorization round
//! trip, one route clone, one materializer lock take, and one full payload
//! copy per subscriber per event. These assertions pin today's defect rather
//! than a target. R5b's acceptance criterion is flipping them to their
//! negation (per-event work independent of subscriber count), so this file is
//! where that flip lands.
//!
//! `#[ignore]` by default: it needs a Postgres started with
//! `wal_level=logical`. Run under Docker with `DATABASE_URL` pointed at it and
//! `-- --ignored`.

use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::fanout_run;

/// The small run's subscriber count.
const SMALL: u64 = 10;
/// The large run's subscriber count, an order of magnitude above [`SMALL`].
const LARGE: u64 = 100;
/// Rows written per run, one CDC event each.
const EVENTS: u64 = 5;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker)"]
async fn per_event_dispatch_work_grows_with_subscriber_count() {
    let fixture = Fixture::acquire().await;
    let small = fanout_run(&fixture, SMALL, EVENTS).await;
    let large = fanout_run(&fixture, LARGE, EVENTS).await;

    // One authorization round trip per subscriber per event, exactly: the
    // whole cost R5b exists to remove from the change path.
    assert_eq!(
        small.counters.authorization_calls,
        SMALL * EVENTS,
        "authorization calls at {SMALL} subscribers"
    );
    assert_eq!(
        large.counters.authorization_calls,
        LARGE * EVENTS,
        "authorization calls at {LARGE} subscribers"
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
