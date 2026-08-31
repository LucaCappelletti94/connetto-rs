//! The two executors answer the same, checked rather than assumed.
//!
//! The design rests on one policy source compiling to two executors that must
//! not disagree: row-level security answers the snapshot, the model answers the
//! change path. A divergence reaches a client as a row that is in the snapshot
//! and then withdrawn on the first change, with nothing anywhere saying why.
//!
//! **This is the only thing in the tree that can notice it.** Every other test
//! asks one executor or the other, so a drift between them passes everything.
//!
//! It runs both over the same change stream, delivers on the shipped one, and
//! asserts they never differed. Both policy shapes, because the two take
//! different paths through the composition: the row settles one of them locally
//! and the other is asked of the service.
//!
//! The cost is the point of it being its own suite. Asking row-level security
//! is one Postgres round trip per watcher per event, which is exactly what the
//! counter suites assert is gone, so this run cannot also be that run.
//!
//! Needs Docker: the fixture starts its own Postgres and its own `OpenFGA`.

use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::{PolicyShape, fanout_parity_run};

/// Enough watchers that a disagreement about one of them is not a coin toss,
/// and few enough that the Postgres round trips stay quick.
const WATCHERS: u64 = 10;
/// Rows written per run, one change event each.
const EVENTS: u64 = 5;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_two_executors_never_disagree_about_a_row() {
    let fixture = Fixture::acquire().await;

    let settled = fanout_parity_run(&fixture, WATCHERS, EVENTS, PolicyShape::Row).await;
    assert_eq!(
        settled.counters.visibility_disagreements, 0,
        "the row settles this policy locally, so the model answered without \
         asking anybody, and Postgres has to reach the same answer"
    );

    let delegated = fanout_parity_run(&fixture, WATCHERS, EVENTS, PolicyShape::CrossTable).await;
    assert_eq!(
        delegated.counters.visibility_disagreements, 0,
        "this policy is answered by the service from facts the store was told, \
         and Postgres answers it from the table those facts were derived from, \
         so the two agreeing is what says the store is not stale"
    );

    // The check is worth nothing if nothing was compared. Both runs asked
    // Postgres once per watcher per event, so the round trips prove the second
    // opinion actually ran rather than being skipped.
    assert!(
        settled.counters.authorization_calls > 0,
        "a parity run that asked Postgres nothing compared nothing"
    );
}
