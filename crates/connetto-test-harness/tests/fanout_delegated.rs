//! The other half of R5b's criterion: a policy the row does not settle is
//! honestly linear, and says so.
//!
//! `fanout_counters.rs` asserts zero round trips for the policy shape connetto
//! writes. On its own that is a number a fixture can be chosen to produce, so
//! this asserts the case that costs: a policy that has to read another table is
//! delegated, one question per watcher, packed into calls capped at the
//! server's `MaxChecksPerBatchCheck`.
//!
//! **Both halves exist so neither can quietly become the other.** A change that
//! made every relation delegate would leave the zero assertion failing. A
//! change that made an undecidable relation answer locally would leave this one
//! failing, and that is the direction that grants wrongly.
//!
//! The count is exact rather than a bound: watchers divided by the cap, rounded
//! up, per event.
//!
//! `#[ignore]` by default: it needs a Postgres started with
//! `wal_level=logical` and an `OpenFGA` server.

use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::{PolicyShape, fanout_run};

/// The small run's subscriber count.
const SMALL: u64 = 10;
/// The large run's subscriber count, an order of magnitude above [`SMALL`].
const LARGE: u64 = 100;
/// Rows written per run, one CDC event each.
const EVENTS: u64 = 5;
/// `OpenFGA`'s own default for `MaxChecksPerBatchCheck`, which subql matches
/// because no call on the service reports the server's limit.
const BATCH: u64 = 50;

/// Calls one event costs at `watchers`, which is the batch count and not the
/// watcher count.
const fn calls_per_event(watchers: u64) -> u64 {
    watchers.div_ceil(BATCH)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical and an OpenFGA server (Docker)"]
async fn a_policy_the_row_does_not_settle_costs_one_batch_per_fifty_watchers() {
    let fixture = Fixture::acquire().await;
    let small = fanout_run(&fixture, SMALL, EVENTS, PolicyShape::CrossTable).await;
    let large = fanout_run(&fixture, LARGE, EVENTS, PolicyShape::CrossTable).await;

    assert_eq!(
        small.counters.authorization_calls,
        calls_per_event(SMALL) * EVENTS,
        "whether the caller is a member of the row's team is not in the row, so \
         every watcher is a question, and {SMALL} of them fit one call"
    );
    assert_eq!(
        large.counters.authorization_calls,
        calls_per_event(LARGE) * EVENTS,
        "{LARGE} watchers exceed the batch cap of {BATCH}, so each event costs \
         two calls rather than one"
    );

    // The half that would be a wrong allow: this shape must never be answered
    // from the row. Zero here would mean an undecidable relation started being
    // decided locally, which grants whoever the row happens to name.
    assert!(
        small.counters.authorization_calls > 0,
        "a relation the row cannot settle must reach the service"
    );
}
