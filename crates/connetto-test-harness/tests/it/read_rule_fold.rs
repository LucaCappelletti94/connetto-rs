//! The harness server registers each subscription the way the shipped server
//! does: the materializer's catalog carries the fixture's policy beside the
//! DDL, so on a row-policy table the read rule folds into the subscription at
//! registration and a change matches only the callers the row admits.
//!
//! Without the policy in that catalog the materializer matches the query alone,
//! so the change matches every watcher and the delivery check drops the rest,
//! which is what the fan-out counters and the reconnect storm measure on that
//! path.
//!
//! Needs Docker: the fixture starts its own Postgres and its own `OpenFGA`.

use std::time::Duration;

use connetto_server::counters;
use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::visibility_fixture;

/// The subscription both callers register.
const QUERY: &str = "SELECT * FROM items WHERE id > 0";

/// How long a patch that should arrive is given.
const DELIVERY: Duration = Duration::from_secs(30);

/// How long to wait before concluding a caller receives nothing.
const QUIET: Duration = Duration::from_secs(5);

/// A change matches the callers the policy admits, so the fan-out costs one
/// route rather than one per watcher.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changed_row_matches_only_the_caller_its_policy_admits() {
    let fixture = Fixture::acquire_exclusive().await;
    let server = visibility_fixture(&fixture).await;

    let mut alice = server.connect();
    alice.handshake_with("fold-alice", "user:alice#fold").await;
    alice.subscribe("items", QUERY).await;
    alice.expect_snapshot("items").await;

    let mut bob = server.connect();
    bob.handshake_with("fold-bob", "user:bob#fold").await;
    bob.subscribe("items", QUERY).await;
    bob.expect_snapshot("items").await;

    let before = counters::snapshot();
    fixture
        .exec("INSERT INTO items (id, owner, label) VALUES (41, 'alice', 'hers')")
        .await;
    let patch = alice.wait_for_live(DELIVERY).await;
    assert!(
        !patch.patchset_zstd.is_empty(),
        "the row alice owns reaches her, which is what makes the next assertions \
         about bob mean anything"
    );
    assert!(
        bob.try_live(QUIET).await.is_none(),
        "the row admits nobody else, so bob receives nothing"
    );
    let since = counters::snapshot().since(&before);
    assert_eq!(
        since.fanout_route_clones, 1,
        "the row admits one watcher, so the materializer routed it once rather \
         than once per watcher"
    );

    alice.close().await;
    bob.close().await;
    drop(server);
}
