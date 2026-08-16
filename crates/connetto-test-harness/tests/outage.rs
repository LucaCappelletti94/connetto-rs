//! R5b's outage behaviour, tested rather than asserted.
//!
//! Fail closed is the decision: no patch is delivered and no mutation is
//! accepted while the answer is unknown, because a patch sent to a caller who
//! may not be allowed to see it cannot be recalled, whereas a stall can. That
//! is a claim about what a client observes, so it is driven end to end through
//! a real change stream rather than checked at a function boundary.
//!
//! Five things, in one run because they are one outage:
//!
//! 1. No patch is delivered while the service is unreachable.
//! 2. The client is told delivery is paused, rather than left in silence.
//! 3. A fresh connection can still take a snapshot, which is the documented
//!    asymmetry: snapshots run on Postgres row-level security permanently.
//! 4. Bringing the service back delivers the withheld row on the connection
//!    that was already open, with no reconnect.
//! 5. A mutation is rejected as cannot-determine and **not** as unauthorized,
//!    which is the second test here because the four above are one run and this
//!    one needs no live patch at all.
//!
//! The service is taken away with a flag rather than by stopping a container,
//! and the flag makes every question fail exactly as an unreachable server
//! makes it fail. What that proves is connetto's response, which is the part
//! this phase owns.
//!
//! `#[ignore]` by default: it needs a Postgres started with `wal_level=logical`
//! and an `OpenFGA` server.

use std::sync::atomic::Ordering;
use std::time::Duration;

use connetto_core::messages::{ControlMessage, MutationRejectReason, PauseCause};
use connetto_core::traits::IncomingFrame;
use connetto_test_harness::fanout::outage_fixture;
use connetto_test_harness::{Fixture, insert_changeset};
use sqlite_diff_rs::Value as RowValue;

/// How long to wait before concluding that nothing is being delivered.
///
/// Long enough that the change stream has certainly carried the row, so the
/// silence is a decision rather than a race. The authorization retry starts at
/// 200 ms, so several attempts have been made and refused by the time this
/// elapses.
const QUIET: Duration = Duration::from_secs(3);

/// How long a withheld row may take to arrive once the service is back.
const RECOVERY: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical and an OpenFGA server (Docker)"]
async fn an_outage_stalls_delivery_loudly_and_recovers_without_a_reconnect() {
    let fixture = Fixture::acquire().await;
    let (server, reachable) = outage_fixture(&fixture).await;

    let mut watcher = server.connect();
    watcher
        .handshake_with("outage-watcher", "user:fanout-owner#watch")
        .await;
    watcher
        .subscribe("items", "SELECT * FROM items WHERE id > 0")
        .await;
    watcher.expect_snapshot("items").await;

    // The service goes away, then a row is written. Nothing about the row is
    // in doubt: its owner is the watcher, so a reachable service would deliver
    // it immediately.
    reachable.store(false, Ordering::Release);
    fixture
        .exec("INSERT INTO items (id, owner, label) VALUES (7, 'fanout-owner', 'withheld')")
        .await;

    // No delivery, and said so. Everything that arrives inside the quiet window
    // is collected, so the assertions read the whole picture rather than the
    // first frame.
    let mut paused = false;
    let mut live = 0_u32;
    let deadline = tokio::time::Instant::now() + QUIET;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, watcher.recv()).await {
            Ok(Some(IncomingFrame::Control(ControlMessage::DeliveryPaused { cause }))) => {
                assert_eq!(
                    cause,
                    PauseCause::AuthServiceUnreachable,
                    "the pause has to name why, or an operator cannot tell an \
                     authorization outage from a stalled change stream"
                );
                paused = true;
            }
            Ok(Some(IncomingFrame::Bulk(_))) => live += 1,
            Ok(Some(IncomingFrame::Control(_))) => {}
            Ok(None) => panic!("the session closed, which is not what failing closed means"),
            Err(_) => break,
        }
    }
    assert_eq!(
        live, 0,
        "a row must not be delivered while whether the caller may see it is unknown"
    );
    assert!(
        paused,
        "an outage a client cannot distinguish from nothing happening leaves it \
         waiting forever without telling anybody"
    );

    // A fresh connection during the same outage: a fresh connection still reads, because
    // the snapshot runs on Postgres row-level security and not on the service.
    let mut fresh = server.connect();
    fresh
        .handshake_with("outage-fresh", "user:fanout-owner#fresh")
        .await;
    fresh
        .subscribe("items", "SELECT * FROM items WHERE id > 0")
        .await;
    let snapshot = fresh.expect_snapshot("items").await;
    assert!(
        !snapshot.is_empty(),
        "an outage stops live delivery and writes, and a fresh connection must \
         still be able to read, which is the asymmetry this phase documents"
    );

    // The service comes back and the row the outage withheld arrives on
    // the connection that was open the whole time.
    reachable.store(true, Ordering::Release);
    let mut resumed = false;
    let mut delivered = false;
    let deadline = tokio::time::Instant::now() + RECOVERY;
    // Both, in either order. The resume is broadcast by the ingest loop and the
    // patch travels the session's own outbound queue, so which lands first is
    // not something this promises and not something to assert.
    while !(resumed && delivered) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "after the service came back: row delivered {delivered}, resume told {resumed}"
        );
        match tokio::time::timeout(remaining, watcher.recv()).await {
            Ok(Some(IncomingFrame::Bulk(_))) => delivered = true,
            Ok(Some(IncomingFrame::Control(ControlMessage::DeliveryResumed))) => resumed = true,
            Ok(Some(IncomingFrame::Control(_))) => {}
            Ok(None) => panic!("the session closed instead of resuming"),
            Err(elapsed) => panic!(
                "after the service came back, waited {elapsed}: row delivered \
                 {delivered}, resume told {resumed}"
            ),
        }
    }
}

/// A write the server cannot judge is refused as cannot-determine, never as
/// unauthorized.
///
/// Its own test rather than a fifth act in the one above, because it needs no
/// live patch and the run reads better without it.
///
/// **The two reasons are not interchangeable and that is the whole point.** A
/// client told it lacks permission stops retrying and may throw the write away,
/// so collapsing an outage into a refusal turns something transient into
/// permanent loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical and an OpenFGA server (Docker)"]
async fn a_write_the_server_cannot_judge_is_not_called_unauthorized() {
    let fixture = Fixture::acquire().await;
    let (server, reachable) = outage_fixture(&fixture).await;

    let mut watcher = server.connect();
    watcher
        .handshake_with("outage-writer", "user:fanout-owner#write")
        .await;
    reachable.store(false, Ordering::Release);

    // Part 3: a write the server cannot judge is refused as cannot-determine.
    // Collapsing this into unauthorized is the data-loss bug the variant exists
    // to prevent: a client told it lacks permission stops retrying and may
    // throw the write away, so a transient outage becomes permanent loss.
    watcher
        .upload(
            1,
            insert_changeset(
                "items",
                &["id", "owner", "label"],
                &[0],
                vec![
                    RowValue::Integer(9),
                    RowValue::Text("fanout-owner".to_owned()),
                    RowValue::Text("refused".to_owned()),
                ],
            ),
        )
        .await;
    let reject = loop {
        match watcher.recv().await {
            Some(IncomingFrame::Control(ControlMessage::MutationReject(reject))) => break reject,
            Some(IncomingFrame::Control(_)) => {}
            other => panic!("expected a mutation reject, got {other:?}"),
        }
    };
    assert_eq!(
        reject.reason,
        MutationRejectReason::Indeterminate,
        "the server could not tell whether the caller may write, and saying \
         unauthorized instead would tell the client to stop trying"
    );
    assert_ne!(
        reject.reason,
        MutationRejectReason::Unauthorized,
        "a refusal and a failure to reach an answer are different things to a \
         client, and only one of them is safe to act on"
    );
}
