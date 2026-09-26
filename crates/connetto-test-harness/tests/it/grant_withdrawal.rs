//! `R86`'s client half: a grant taken away in the database reaches the device.
//!
//! `R49` measured the failure this inverts. A caller held a share, the share
//! row was deleted, and the caller kept reading the rows, because the store
//! still held a fact nobody had removed. The store side is proven next to the
//! executor in `connetto-server`'s `openfga_live`. What is proven here is the
//! rest of the sentence: the device stops holding the row.
//!
//! **The subscription deliberately carries no membership term.** A term is
//! served incrementally by the membership move (`R27` decision 2) and the
//! server suppresses the replacement for exactly that case, so a term here
//! would prove the other path and pass without the grant ever being consulted.
//!
//! Needs Docker: the fixture starts its own Postgres and its own `OpenFGA`.

use std::time::Duration;

use connetto_core::messages::{BulkMessage, ControlMessage, FullResyncReason, SnapshotPatch};
use connetto_core::traits::IncomingFrame;
use connetto_server::Position;
use connetto_test_harness::fanout::membership_term_fixture;
use connetto_test_harness::{Client, Fixture};
use sqlite_diff_rs::{ParsedDiffSet, PatchsetOp};

/// Long enough for a container round trip, short enough to fail rather than
/// hang when the replacement never comes.
const DELIVERY: Duration = Duration::from_secs(30);

/// Everything the subscription can see, so what arrives is the authorization
/// answer rather than a filter the client wrote.
const EVERYTHING: &str = "SELECT * FROM items";

/// Rows a set of patches actually carries.
///
/// Counted rather than measured by byte length: an empty result still arrives
/// as a patchset with a header, so a length test passes for the wrong reason.
fn rows(patches: &[SnapshotPatch]) -> usize {
    patches
        .iter()
        .map(|patch| {
            let bytes = zstd::decode_all(patch.patchset_zstd.as_slice()).expect("decompress");
            // A snapshot carrying no rows is not a patchset at all, and that is
            // the answer this counts rather than a shape to assert on.
            let ParsedDiffSet::Patchset(set) = ParsedDiffSet::parse(&bytes).expect("parse") else {
                return 0;
            };
            set.iter()
                .filter(|op| matches!(op, PatchsetOp::Insert { .. }))
                .count()
        })
        .sum()
}

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
    let first = rows(&alice.expect_snapshot("docs").await);
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

    let (reason, replacement) = alice
        .try_resync("docs", DELIVERY)
        .await
        .expect("a grant taken away has to reach the device, or it reads rows it may not");
    assert_eq!(
        reason,
        FullResyncReason::AuthorizationChange,
        "the client is told why, so an application can tell a permission change \
         from a truncated table"
    );
    assert_eq!(
        rows(&replacement),
        0,
        "the replacement carries what the caller may see now, which is nothing"
    );
}
