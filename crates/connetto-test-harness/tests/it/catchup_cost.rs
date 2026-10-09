//! What a reconnecting caller costs the server to catch up.
//!
//! The log holds every caller's changes, so a caller returning from its cursor
//! walks changes it will never receive as well as its own. Each change's patch
//! is compressed once, when it is logged, so walking them compresses nothing:
//! not the other callers' changes, which this caller is never sent, and not its
//! own, which go out as logged. A compression per walked change is what made a
//! thousand callers reconnecting at once take minutes.
//!
//! Needs Docker: the fixture starts its own Postgres and its own `OpenFGA`.

use std::time::Duration;

use connetto_core::messages::{BulkMessage, ControlMessage};
use connetto_core::traits::IncomingFrame;
use connetto_server::counters;
use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::visibility_fixture;

/// The subscription both connections of the returning caller register.
const QUERY: &str = "SELECT * FROM items WHERE id > 0";
/// How long a live patch may take before the test is declared hung.
const DELIVERY: Duration = Duration::from_secs(30);
/// How long the catchup is given to send anything after its last patch.
const QUIET: Duration = Duration::from_secs(3);
/// Changes other callers make while this one is away.
const OTHERS: u64 = 20;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_catchup_compresses_nothing_for_the_changes_it_walks() {
    let fixture = Fixture::acquire_exclusive().await;
    let server = visibility_fixture(&fixture).await;

    // Stays connected, so its live patch says when the changes made while the
    // other connection is away have all been logged.
    let mut stayed = server.connect();
    stayed
        .handshake_with("catchup-stayed", "user:alice#stayed")
        .await;
    stayed.subscribe("items", QUERY).await;
    stayed.expect_snapshot("items").await;

    let mut away = server.connect();
    away.handshake_with("catchup-away", "user:alice#away").await;
    away.subscribe("items", QUERY).await;
    away.expect_snapshot("items").await;

    fixture
        .exec("INSERT INTO items (id, owner, label) VALUES (1, 'alice', 'before')")
        .await;
    stayed.wait_for_live(DELIVERY).await;
    let resume_from = away.wait_for_live(DELIVERY).await.cursor;
    away.close().await;

    fixture
        .exec(&format!(
            "INSERT INTO items (id, owner, label) \
             SELECT g, 'other-' || g, 'theirs' FROM generate_series(2, {}) AS g",
            OTHERS + 1
        ))
        .await;
    fixture
        .exec(&format!(
            "INSERT INTO items (id, owner, label) VALUES ({}, 'alice', 'away')",
            OTHERS + 2
        ))
        .await;
    // Logged before fan-out, and the log is in commit order, so every change
    // above is in the log once this arrives.
    stayed.wait_for_live(DELIVERY).await;

    let before = counters::snapshot();
    let mut back = server.connect();
    back.handshake_resuming("catchup-away", "user:alice#away", resume_from)
        .await;
    back.subscribe("items", QUERY).await;
    let mut received = 0;
    loop {
        match tokio::time::timeout(QUIET, back.recv()).await {
            Ok(Some(IncomingFrame::Bulk(BulkMessage::LivePatch(_)))) => received += 1,
            Ok(Some(IncomingFrame::Control(ControlMessage::FullResyncRequired(_)))) => {
                panic!("the caller was sent a fresh copy, so this run says nothing about catchup")
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    let spent = counters::snapshot().since(&before);

    assert_eq!(
        received, 1,
        "the catchup sends the one change the caller may see and none of the {OTHERS} it may not"
    );
    assert_eq!(
        spent.patch_compressions,
        0,
        "the catchup compressed {} patches walking {} logged changes, each of which was \
         compressed once already when it was logged",
        spent.patch_compressions,
        OTHERS + 1
    );

    stayed.close().await;
    back.close().await;
}
