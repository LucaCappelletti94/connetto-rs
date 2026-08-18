//! R27's proof: a subscription whose membership depends on another table
//! receives a row when the relationship is created and loses it when the
//! relationship is removed, without the client receiving `FullResyncRequired`,
//! and without ever receiving a row the policy forbids.
//!
//! Each half is driven by the membership row and only the membership row: the
//! subscribed rows never change during a move, so a row that arrived because
//! of a re-snapshot would trip the resync assertion instead of passing by
//! accident, and a row that left because it changed would prove nothing.
//!
//! The intersection with the policy is proven on a second fixture whose policy
//! never reads the membership, so interest and permission can disagree in both
//! directions.
//!
//! `#[ignore]` by default: it needs a Postgres started with `wal_level=logical`
//! and an `OpenFGA` server (Docker).

use std::time::Duration;

use connetto_core::messages::{ControlMessage, LivePatch};
use connetto_test_harness::Client;
use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::{membership_term_fixture, term_over_owner_fixture};
use diesel::prelude::*;
use sqlite_diff_rs::{ParsedDiffSet, PatchsetOp, Value as WireValue};

/// The motivating filter, in the client's own SQLite dialect: the caller is
/// the no-arg function the deployment mapped `current_setting` onto.
const TERM_QUERY: &str = "SELECT * FROM items WHERE team_id IN \
    (SELECT team_id FROM team_members WHERE member = current_app_user())";

/// How long a patch that should arrive is given.
const DELIVERY: Duration = Duration::from_secs(30);

/// How long to wait before concluding nothing is being delivered. Silence is
/// one of the assertions here, so it has to outlast the change stream.
const QUIET: Duration = Duration::from_secs(5);

/// The replica's own shape, mirroring the cross-table fixture's `items`.
/// `INTEGER PRIMARY KEY` rather than `INT`, because SQLite only treats the
/// former as the rowid alias a patchset delete matches on.
const REPLICA_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, \
    owner TEXT NOT NULL, team_id INTEGER NOT NULL, label TEXT)";

diesel::table! {
    /// The replica's copy of the fixture's subscribed table.
    items (id) {
        /// Row key.
        id -> Integer,
        /// Whose row it is, which is what the owner policy reads.
        owner -> Text,
        /// The team the row belongs to, which is what the term compares.
        team_id -> Integer,
        /// Payload, unread here.
        label -> Nullable<Text>,
    }
}

/// One row of the replica, as a patchset insert carries it.
#[derive(Insertable)]
#[diesel(table_name = items)]
struct ReplicaRow {
    id: i32,
    owner: String,
    team_id: i32,
    label: Option<String>,
}

/// The wire value flavor a parsed patchset carries.
type Wire = WireValue<String, Vec<u8>>;

fn int_of(value: &Wire) -> i32 {
    match value {
        Wire::Integer(i) => i32::try_from(*i).expect("id fits i32"),
        other => panic!("expected an integer cell, got {other:?}"),
    }
}

fn text_of(value: &Wire) -> String {
    match value {
        Wire::Text(t) => t.clone(),
        other => panic!("expected a text cell, got {other:?}"),
    }
}

fn label_of(value: &Wire) -> Option<String> {
    match value {
        Wire::Null => None,
        Wire::Text(t) => Some(t.clone()),
        other => panic!("expected a nullable text cell, got {other:?}"),
    }
}

/// One caller's replica: every patch delivered to it, applied in order, the
/// way the real client applies (`apply_patchset` with the server winning): a
/// repeated insert replaces, which is R28's documented snapshot overlap, and
/// a delete keys on the primary key alone.
struct Replica {
    conn: SqliteConnection,
}

impl Replica {
    fn new() -> Self {
        let mut conn = SqliteConnection::establish(":memory:").expect("open replica");
        diesel::sql_query(REPLICA_DDL)
            .execute(&mut conn)
            .expect("replica ddl");
        Self { conn }
    }

    fn apply(&mut self, patchset_zstd: &[u8]) {
        let bytes = zstd::decode_all(patchset_zstd).expect("decompress patch");
        let ParsedDiffSet::Patchset(set) = ParsedDiffSet::parse(&bytes).expect("parse patch")
        else {
            panic!("expected a patchset payload");
        };
        for op in set.iter() {
            match &op {
                PatchsetOp::Insert { values, .. } => {
                    let row = ReplicaRow {
                        id: int_of(&values[0]),
                        owner: text_of(&values[1]),
                        team_id: int_of(&values[2]),
                        label: values.get(3).and_then(label_of),
                    };
                    diesel::replace_into(items::table)
                        .values(&row)
                        .execute(&mut self.conn)
                        .expect("apply insert");
                }
                PatchsetOp::Update { pk, entries, .. } => {
                    let id = int_of(&pk[0]);
                    if let Some(owner) = entries.get(1).and_then(|((), new)| new.as_ref()) {
                        diesel::update(items::table.filter(items::id.eq(id)))
                            .set(items::owner.eq(text_of(owner)))
                            .execute(&mut self.conn)
                            .expect("apply owner update");
                    }
                    if let Some(team) = entries.get(2).and_then(|((), new)| new.as_ref()) {
                        diesel::update(items::table.filter(items::id.eq(id)))
                            .set(items::team_id.eq(int_of(team)))
                            .execute(&mut self.conn)
                            .expect("apply team update");
                    }
                    if let Some(label) = entries.get(3).and_then(|((), new)| new.as_ref()) {
                        diesel::update(items::table.filter(items::id.eq(id)))
                            .set(items::label.eq(label_of(label)))
                            .execute(&mut self.conn)
                            .expect("apply label update");
                    }
                }
                PatchsetOp::Delete { pk, .. } => {
                    let id = int_of(&pk[0]);
                    diesel::delete(items::table.filter(items::id.eq(id)))
                        .execute(&mut self.conn)
                        .expect("apply delete");
                }
            }
        }
    }

    fn ids(&mut self) -> Vec<i32> {
        items::table
            .order(items::id)
            .select(items::id)
            .load(&mut self.conn)
            .expect("read replica")
    }
}

/// The hidden membership subscription's label over `team_members`, in R27
/// decision 7's reserved namespace.
const MEMBERSHIP_SUB: &str = "connetto-membership:team_members";

/// Read the announce and the hidden subscription's own snapshot, which the
/// server sends right behind the term subscription's frames (R27 step 5), and
/// assert the snapshot carries the caller's own membership rows.
async fn expect_membership_opened(client: &mut Client) {
    let msg = client.next_control().await;
    let ControlMessage::MembershipOpened(opened) = msg else {
        panic!("expected the membership announce, got {msg:?}");
    };
    assert_eq!(opened.sub_id, MEMBERSHIP_SUB);
    assert_eq!(opened.member_table, "team_members");
    let patches = client.expect_snapshot(MEMBERSHIP_SUB).await;
    assert!(
        !patches.is_empty(),
        "the caller's own membership rows arrive on the hidden subscription"
    );
    let bytes = zstd::decode_all(patches[0].patchset_zstd.as_slice()).expect("decompress");
    let ParsedDiffSet::Patchset(set) = ParsedDiffSet::parse(&bytes).expect("parse") else {
        panic!("expected a patchset");
    };
    let op = set.iter().next().expect("one membership row");
    assert_eq!(op.table().name(), "team_members");
}

/// The next live patch for `sub_id`. Frames for the hidden membership
/// subscription may interleave, because its own table's rows move too, and
/// are tolerated without applying: the test replica holds `items` alone.
async fn live_for(client: &mut Client, sub_id: &str, timeout: Duration) -> LivePatch {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match client.try_live(remaining).await {
            Some(patch) if patch.sub_id == sub_id => return patch,
            Some(patch) => assert_eq!(
                patch.sub_id, MEMBERSHIP_SUB,
                "only the hidden subscription may interleave"
            ),
            None => panic!("timed out waiting for a {sub_id} patch"),
        }
    }
}

/// Assert no live patch for `sub_id` arrives within `timeout`. Hidden
/// membership patches may arrive and are tolerated, which is what makes the
/// silence assertion about the subscription rather than about the wire.
async fn no_live_for(client: &mut Client, sub_id: &str, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match client.try_live(remaining).await {
            Some(patch) => assert_ne!(
                patch.sub_id, sub_id,
                "a frame arrived for {sub_id} where silence was owed"
            ),
            None => return,
        }
    }
}

/// The phase's central proof, on the motivating shape: the policy on the
/// subscribed table is itself written in terms of the membership.
///
/// A membership created moves the rows in, a membership removed moves them
/// out, and neither direction re-snapshots: `try_resync` asserts the absence
/// of `FullResyncRequired`, because reaching for R7's resend is exactly the
/// shortcut decision 2 refuses. The subscribed rows never change, so both
/// moves are driven by the membership row alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical and an OpenFGA server (Docker)"]
async fn a_membership_change_moves_rows_without_a_resync() {
    let fixture = Fixture::acquire().await;
    let server = membership_term_fixture(&fixture).await;

    // Teams 2 and 3 beside the fixture's team 1, alice a member of team 1
    // only, and rows that never change again for the rest of the test.
    fixture.exec("INSERT INTO teams (id) VALUES (2), (3)").await;
    fixture
        .exec("INSERT INTO team_members (team_id, member) VALUES (1, 'alice')")
        .await;
    fixture
        .exec(
            "INSERT INTO items (id, owner, team_id, label) VALUES \
             (11, 'alice', 1, 'one'), (21, 'bob', 2, 'two'), \
             (22, 'bob', 2, 'more'), (31, 'bob', 3, 'three')",
        )
        .await;

    let mut alice = server.connect();
    alice.handshake_with("r27-alice", "user:alice").await;
    alice.subscribe("docs", TERM_QUERY).await;
    let mut replica = Replica::new();
    for patch in alice.expect_snapshot("docs").await {
        replica.apply(&patch.patchset_zstd);
    }
    expect_membership_opened(&mut alice).await;
    // Events committed before the subscription registered may still be in the
    // change stream and repeat snapshot rows (R28's documented overlap, which
    // replaces harmlessly). Drain to silence so the next frame is the move's.
    while let Some(patch) = alice.try_live(QUIET).await {
        if patch.sub_id == "docs" {
            replica.apply(&patch.patchset_zstd);
        }
    }
    // Row 0 is the fixture's seed row in team 1, which alice is a member of.
    assert_eq!(
        replica.ids(),
        vec![0, 11],
        "the snapshot carries only rows of teams the caller is in"
    );

    // Move-in: the membership row and only the membership row changes.
    fixture
        .exec("INSERT INTO team_members (team_id, member) VALUES (2, 'alice')")
        .await;
    let patch = live_for(&mut alice, "docs", DELIVERY).await;
    replica.apply(&patch.patchset_zstd);
    assert_eq!(
        replica.ids(),
        vec![0, 11, 21, 22],
        "joining team 2 moves its rows in"
    );
    assert!(
        alice.try_resync("docs", QUIET).await.is_none(),
        "a membership change must move rows without a resync (decision 2)"
    );

    // A later change to a moved-in row is an ordinary live patch, which pins
    // that the engine's set really moved rather than rows being copied once.
    fixture
        .exec("UPDATE items SET label = 'renamed' WHERE id = 21")
        .await;
    let patch = live_for(&mut alice, "docs", DELIVERY).await;
    replica.apply(&patch.patchset_zstd);

    // Move-out: leaving team 2 withdraws its rows, again with no resync.
    fixture
        .exec("DELETE FROM team_members WHERE team_id = 2 AND member = 'alice'")
        .await;
    let patch = live_for(&mut alice, "docs", DELIVERY).await;
    replica.apply(&patch.patchset_zstd);
    assert_eq!(
        replica.ids(),
        vec![0, 11],
        "leaving team 2 takes its rows off the device"
    );
    assert!(
        alice.try_resync("docs", QUIET).await.is_none(),
        "a membership removal must withdraw rows without a resync (decision 2)"
    );

    // Rows of teams the caller never joined were never delivered.
    fixture.exec("DELETE FROM items WHERE id = 31").await;
    no_live_for(&mut alice, "docs", QUIET).await;

    // Torn down together (decision 7): after the term subscription ends, the
    // membership subscription is gone too, so a membership change moves
    // nothing and draws no frame on either label.
    alice.unsubscribe("docs").await;
    let pong = alice.barrier(7).await;
    assert!(matches!(pong, ControlMessage::Pong(_)));
    fixture
        .exec("INSERT INTO team_members (team_id, member) VALUES (3, 'alice')")
        .await;
    assert!(
        alice.try_live(QUIET).await.is_none(),
        "nothing is subscribed any more, on either label"
    );
}

/// The intersection with the policy, in both directions, on a policy that
/// never reads the membership: items are visible to their owner alone.
///
/// A row the term admits and the policy forbids must not arrive, a row the
/// policy admits and the term excludes must not arrive, and a membership
/// removal under a policy that still admits the rows sends neither a delete
/// nor a resync: the withdrawal question is `may_see` on the current row, and
/// an allowed row is the replica's own membership copy's to stop matching.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical and an OpenFGA server (Docker)"]
async fn the_term_intersects_the_policy_and_never_widens_it() {
    let fixture = Fixture::acquire().await;
    let server = term_over_owner_fixture(&fixture).await;

    fixture.exec("INSERT INTO teams (id) VALUES (2), (9)").await;
    fixture
        .exec("INSERT INTO team_members (team_id, member) VALUES (1, 'alice')")
        .await;
    // Team 2 holds one of alice's rows and one of bob's. Team 9 holds one of
    // alice's rows, but alice is never a member of team 9.
    fixture
        .exec(
            "INSERT INTO items (id, owner, team_id, label) VALUES \
             (11, 'alice', 1, 'one'), (21, 'alice', 2, 'two'), \
             (22, 'bob', 2, 'not-hers'), (91, 'alice', 9, 'excluded')",
        )
        .await;

    let mut alice = server.connect();
    alice.handshake_with("r27-owner", "user:alice").await;
    alice.subscribe("docs", TERM_QUERY).await;
    let mut replica = Replica::new();
    for patch in alice.expect_snapshot("docs").await {
        replica.apply(&patch.patchset_zstd);
    }
    expect_membership_opened(&mut alice).await;
    // Drain the R28 backlog overlap, as above, so the next frame is the move's.
    while let Some(patch) = alice.try_live(QUIET).await {
        if patch.sub_id == "docs" {
            replica.apply(&patch.patchset_zstd);
        }
    }
    // Row 0 belongs to the fixture's owner, so the policy hides it from alice
    // however much the term admits team 1. Row 91 is alice's, but the term
    // excludes team 9: the policy never widens the subscription.
    assert_eq!(
        replica.ids(),
        vec![11],
        "the snapshot is the intersection of the term and the policy"
    );

    // Term admits, policy forbids: joining team 2 moves in only what the
    // policy grants. Bob's row 22 is admitted by the term and must not arrive.
    fixture
        .exec("INSERT INTO team_members (team_id, member) VALUES (2, 'alice')")
        .await;
    let patch = live_for(&mut alice, "docs", DELIVERY).await;
    replica.apply(&patch.patchset_zstd);
    assert_eq!(
        replica.ids(),
        vec![11, 21],
        "a move-in delivers only rows the policy admits"
    );
    assert!(
        alice.try_resync("docs", QUIET).await.is_none(),
        "the move-in must not re-snapshot"
    );

    // Policy admits, term excludes: alice's own row in team 9 never arrives,
    // because the subscription's filter is interest and interest excludes it.
    fixture
        .exec("UPDATE items SET label = 'still excluded' WHERE id = 91")
        .await;
    no_live_for(&mut alice, "docs", QUIET).await;

    // Move-out under a policy that still admits the rows: no delete arrives
    // (the withdrawal question is may_see on the current row, and the answer
    // is allow), and no resync either. The replica's own membership copy is
    // what stops the local query matching, which R27 step 5 serves.
    fixture
        .exec("DELETE FROM team_members WHERE team_id = 2 AND member = 'alice'")
        .await;
    no_live_for(&mut alice, "docs", QUIET).await;
    assert!(
        alice.try_resync("docs", QUIET).await.is_none(),
        "a term exit under a still-allowing policy must not re-snapshot"
    );
    assert_eq!(
        replica.ids(),
        vec![11, 21],
        "the rows the policy still grants stay on the device"
    );
}
