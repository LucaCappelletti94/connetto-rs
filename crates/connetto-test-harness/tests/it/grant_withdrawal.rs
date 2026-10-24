//! `R86`'s client half: a grant taken away in the database reaches the device.
//!
//! `R49` measured the failure this inverts. A caller held a share, the share
//! row was deleted, and the caller kept reading the rows, because the store
//! still held a fact nobody had removed. The store side is proven next to the
//! executor in `connetto-server`'s `openfga_live`. What is proven here is the
//! rest of the sentence: the device stops holding the row.
//!
//! The subscription carries the policy's term through the read rule the
//! materializer folds at registration, so the withdrawal arrives as the
//! membership move (`R27` decision 2). The move takes the rows off the
//! device live, and the resync it suppresses is the absence asserted at the
//! end of the test.
//!
//! Needs Docker: the fixture starts its own Postgres and its own `OpenFGA`.

use std::time::Duration;

use connetto_core::messages::{BulkMessage, ControlMessage};
use connetto_core::traits::IncomingFrame;
use connetto_server::Position;
use connetto_test_harness::fanout::membership_term_fixture;
use connetto_test_harness::{Client, Fixture, snapshot_rows};

use sqlite_diff_rs::{ParsedDiffSet, PatchsetOp, Value as WireValue};

type Wire = WireValue<String, Vec<u8>>;

/// Long enough for a container round trip, short enough to fail rather than
/// hang when the replacement never comes.
const DELIVERY: Duration = Duration::from_secs(30);

/// Silence short enough to trust, long enough not to be a container hiccup.
const QUIET: Duration = Duration::from_secs(5);

/// Everything the subscription can see, so what arrives is the authorization
/// answer rather than a filter the client wrote.
const EVERYTHING: &str = "SELECT * FROM items";

/// Read until the live patch of a change written at or past `before` arrives, consuming any replacement on the way.
///
/// Changes fan out in commit order through one ordered queue, so once that patch is here every replacement an
/// earlier change caused has arrived too.
async fn settle_past(client: &mut Client, before: u64) {
    loop {
        match tokio::time::timeout(DELIVERY, client.recv())
            .await
            .expect("the marker's live patch arrives")
        {
            Some(IncomingFrame::Control(ControlMessage::FullResyncRequired(_))) => {
                client.expect_snapshot("docs").await;
            }
            // The hidden membership subscription's snapshot (R27 step 5)
            // is the server's own bookkeeping.
            Some(IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch))) => {
                assert!(
                    patch.sub_id.starts_with("connetto-membership:"),
                    "a snapshot patch on the real subscription, got {}",
                    patch.sub_id
                );
            }
            // The hidden subscription's own live frames settle alongside.
            Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch)))
                if patch.sub_id.starts_with("connetto-membership:") => {}
            Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch))) => {
                let at = Position::from_cursor_bytes(patch.cursor.as_bytes())
                    .expect("a live cursor carries a position")
                    .at
                    .commit_lsn()
                    .0;
                if at >= before {
                    return;
                }
            }
            Some(IncomingFrame::Control(_)) => {}
            other => panic!("expected a live patch or a replacement, got {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawn_grant_takes_the_row_off_the_device() {
    let fixture = Fixture::acquire().await;
    let server = membership_term_fixture(&fixture).await;

    // alice is in team 1, which holds the fixture's row 0.
    fixture
        .exec("INSERT INTO team_members (team_id, member) VALUES (1, 'alice')")
        .await;

    let mut alice = server.connect();
    alice.handshake_with("r86-alice", "user:alice").await;
    alice.subscribe("docs", EVERYTHING).await;
    let first = snapshot_rows(&alice.expect_snapshot("docs").await);
    assert!(
        first > 0,
        "a member of the team sees the team's rows, which is what makes the \
         withdrawal below mean anything"
    );

    // The membership insert moves a grant too, and its replacement, read before
    // the withdrawal, may still be on its way. A marker row settles it.
    let before = fixture.committed_position().await;
    fixture
        .exec("INSERT INTO items (id, owner, team_id, label) VALUES (90, 'bob', 1, 'marker')")
        .await;
    settle_past(&mut alice, before).await;

    // The withdrawal, in the database, exactly as an application would write
    // it. Nothing tells the client directly.
    fixture
        .exec("DELETE FROM team_members WHERE team_id = 1 AND member = 'alice'")
        .await;

    // The move takes the rows off live, and every row the device held is one
    // of the deletions it carries.
    let mut withdrawn = [false, false];
    let deadline = tokio::time::Instant::now() + DELIVERY;
    while !withdrawn.iter().all(|done| *done) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "the move's frames arrive within the delivery window, got {withdrawn:?}"
        );
        let frame = tokio::time::timeout(remaining, alice.recv())
            .await
            .expect("the move's frames arrive");
        match frame {
            Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch)))
                if !patch.sub_id.starts_with("connetto-membership:") =>
            {
                for id in deleted_ids(&patch.patchset_zstd) {
                    match id {
                        0 => withdrawn[0] = true,
                        90 => withdrawn[1] = true,
                        other => {
                            panic!("a row the device never held was withdrawn, got {other}")
                        }
                    }
                }
            }
            Some(IncomingFrame::Control(ControlMessage::FullResyncRequired(resync))) => {
                panic!(
                    "the move suppresses the replacement the withdrawal would \
                     otherwise cause, got {resync:?}"
                )
            }
            Some(IncomingFrame::Bulk(_) | IncomingFrame::Control(_)) => {}
            other => panic!("expected a live patch from the move, got {other:?}"),
        }
    }

    // The move serves the withdrawal, so the resync it suppresses never
    // comes.
    assert!(
        alice.try_resync("docs", QUIET).await.is_none(),
        "the move suppresses the replacement the withdrawal would otherwise cause"
    );
}

/// The ids a patchset deletes, read off the delete ops.
fn deleted_ids(patchset_zstd: &[u8]) -> Vec<i32> {
    let bytes = zstd::decode_all(patchset_zstd).expect("decompress the patch");
    let ParsedDiffSet::Patchset(set) = ParsedDiffSet::parse(&bytes).expect("parse the patch")
    else {
        panic!("expected a patchset payload");
    };
    set.iter()
        .filter_map(|op| match op {
            PatchsetOp::Delete { pk, .. } => Some(int_of(&pk[0])),
            _ => None,
        })
        .collect()
}

/// An integer key straight off the wire.
fn int_of(value: &Wire) -> i32 {
    match value {
        Wire::Integer(id) => i32::try_from(*id).expect("an item id fits"),
        other => panic!("expected an integer key, got {other:?}"),
    }
}
