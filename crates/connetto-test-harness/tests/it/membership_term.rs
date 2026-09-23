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
//! Needs Docker: the fixture starts its own Postgres and its own `OpenFGA`.

use std::time::Duration;

use connetto_core::Cursor;
use connetto_core::messages::{BulkMessage, ControlMessage, LivePatch};
use connetto_core::traits::Transport;
use connetto_core::transport::{LoopbackTransport, loopback};
use connetto_server::Position;
use connetto_test_harness::Client;
use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::{
    SHARE_KEY, membership_term_fixture, subject_set_term_fixture, term_over_owner_fixture,
};
use diesel::prelude::*;
use sqlite_diff_rs::{
    DiffOps, Insert, ParsedDiffSet, PatchSet, PatchsetOp, SimpleTable, Value as WireValue,
};

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

/// Apply the next `sub_id` frame caused by a change past everything
/// `accounted` covers.
///
/// The settling tail of an earlier change may be waiting on the wire or in the
/// client's backlog, and applying it is harmless, but it must not stand in for
/// the change this waits for. Frames for the hidden membership subscription may
/// interleave, because its own table's rows move too, and are tolerated without
/// applying: the test replica holds `items` alone.
async fn live_past(
    client: &mut Client,
    sub_id: &str,
    replica: &mut Replica,
    accounted: &mut Accounted,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match client.try_live(remaining).await {
            Some(patch) if patch.sub_id == sub_id => {
                let fresh = !accounted.covers(&patch.cursor);
                accounted.note(&patch.cursor);
                replica.apply(&patch.patchset_zstd);
                if fresh {
                    return;
                }
            }
            Some(patch) => assert_eq!(
                patch.sub_id, MEMBERSHIP_SUB,
                "only the hidden subscription may interleave"
            ),
            None => panic!(
                "timed out waiting for a {sub_id} patch past {:?}",
                accounted.0
            ),
        }
    }
}

/// The latest change this test has accounted for on one subscription.
///
/// A frame carries the position of the change that caused it, so a frame at or
/// below this one belongs to a change the test already waited for and a frame
/// past it belongs to a change nothing here asked to see.
///
/// The frames a test meets understate the change it waited for, because a
/// membership move reads the live table and can deliver a row before the
/// row's own event is dispatched, whose frame then arrives above every
/// position seen so far. Before writing the change it wants silence about, a
/// test therefore accounts for everything the database has committed
/// ([`note_committed`](Self::note_committed)), which is exactly the set of
/// changes it asked for and nothing after.
#[derive(Default)]
struct Accounted(Option<u64>);

impl Accounted {
    fn note(&mut self, cursor: &Cursor) {
        self.note_position(position_of(cursor));
    }

    async fn note_committed(&mut self, fixture: &Fixture) {
        self.note_position(fixture.committed_position().await);
    }

    fn note_position(&mut self, position: u64) {
        self.0 = Some(self.0.map_or(position, |seen| seen.max(position)));
    }

    fn covers(&self, cursor: &Cursor) -> bool {
        self.0.is_some_and(|seen| position_of(cursor) <= seen)
    }
}

/// A live cursor is the causing event's position.
fn position_of(cursor: &Cursor) -> u64 {
    Position::from_cursor_bytes(cursor.as_bytes())
        .expect("a live cursor carries a position")
        .lsn
}

/// The wire cursor of `lsn` on a database never promoted.
fn cursor_at(lsn: u64) -> Cursor {
    Cursor::new(Position { timeline: 1, lsn }.to_cursor_bytes())
}

/// A patchset's operations, one verb and a key each, for a refusal to name.
fn describe(patchset_zstd: &[u8]) -> String {
    let bytes = zstd::decode_all(patchset_zstd).expect("decompress patch");
    let ParsedDiffSet::Patchset(set) = ParsedDiffSet::parse(&bytes).expect("parse patch") else {
        return "a non-patchset payload".to_owned();
    };
    let ops: Vec<String> = set
        .iter()
        .map(|op| match &op {
            PatchsetOp::Insert { values, .. } => format!("insert {}", int_of(&values[0])),
            PatchsetOp::Update { pk, .. } => format!("update {}", int_of(&pk[0])),
            PatchsetOp::Delete { pk, .. } => format!("delete {}", int_of(&pk[0])),
        })
        .collect();
    if ops.is_empty() {
        "no operation".to_owned()
    } else {
        ops.join(", ")
    }
}

/// Apply every `sub_id` frame until the replica holds exactly `expected`. A
/// straggler frame from the settling phase can reach the wire ahead of the
/// row a test just wrote (seen on 2-core CI runners, 2026-09-02), so waiting
/// for one frame races while waiting for content does not.
async fn live_until(
    client: &mut Client,
    sub_id: &str,
    replica: &mut Replica,
    accounted: &mut Accounted,
    expected: &[i32],
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if replica.ids() == expected {
            return;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match client.try_live(remaining).await {
            Some(patch) if patch.sub_id == sub_id => {
                accounted.note(&patch.cursor);
                replica.apply(&patch.patchset_zstd);
            }
            Some(patch) => assert_eq!(
                patch.sub_id, MEMBERSHIP_SUB,
                "only the hidden subscription may interleave"
            ),
            None => panic!(
                "timed out waiting for {sub_id} to reach {expected:?}, the replica holds {:?}",
                replica.ids()
            ),
        }
    }
}

/// Assert that nothing past `accounted` arrives for `sub_id` within `timeout`,
/// and that what does arrive changes nothing.
///
/// The settling tail of a change the test already waited for may still be in
/// flight, and so may a frame for the hidden membership subscription, so the
/// assertion weighs the position a frame carries rather than the wire being
/// quiet. A tail frame is applied on arrival, because one that repeats what
/// the replica holds is the shape the design permits and one that adds a row
/// is the delivery this assertion exists to catch. A frame past every
/// accounted change is applied before it is refused, so the refusal says
/// whether it delivered a row or carried nothing.
async fn no_live_past(
    client: &mut Client,
    sub_id: &str,
    replica: &mut Replica,
    accounted: &Accounted,
    timeout: Duration,
) {
    let held = replica.ids();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match client.try_live(remaining).await {
            Some(patch) if patch.sub_id == sub_id => {
                replica.apply(&patch.patchset_zstd);
                let now = replica.ids();
                assert!(
                    accounted.covers(&patch.cursor),
                    "a frame for {sub_id} at {} arrived, past the change this test accounted for at {:?}, carrying {} and taking the replica from {held:?} to {now:?}",
                    position_of(&patch.cursor),
                    accounted.0,
                    describe(&patch.patchset_zstd)
                );
                assert_eq!(
                    now, held,
                    "a frame at an accounted change added to the replica"
                );
            }
            Some(patch) => assert_eq!(
                patch.sub_id, MEMBERSHIP_SUB,
                "only the hidden subscription may interleave"
            ),
            None => return,
        }
    }
}

/// A compressed patchset inserting one `items` row, as a frame carries it.
fn items_patch(id: i64, label: &str) -> Vec<u8> {
    let table = SimpleTable::new("items", &["id", "owner", "team_id", "label"], &[0]);
    let mut insert = Insert::<_, String, Vec<u8>>::from(table);
    for (index, value) in [
        WireValue::Integer(id),
        WireValue::Text("bob".to_owned()),
        WireValue::Integer(1),
        WireValue::Text(label.to_owned()),
    ]
    .into_iter()
    .enumerate()
    {
        insert = insert.set(index, value).expect("set column");
    }
    let bytes = PatchSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(insert)
        .build();
    zstd::encode_all(bytes.as_slice(), 0).expect("compress the patch")
}

/// A connection carrying the given frames, with the sending end handed back so
/// it stays open for the assertion under test.
async fn frames(frames: Vec<(u64, Vec<u8>)>) -> (Client, LoopbackTransport) {
    let (mut server_end, client_end) = loopback();
    for (position, patchset_zstd) in frames {
        server_end
            .send_bulk(BulkMessage::LivePatch(LivePatch::new(
                "docs",
                cursor_at(position),
                patchset_zstd,
            )))
            .await
            .expect("send the frame");
    }
    (Client::new(client_end), server_end)
}

/// A change at position 9, accounted for, and a replica holding the row that
/// change delivered.
fn accounted_at_nine() -> (Replica, Accounted) {
    let mut replica = Replica::new();
    replica.apply(&items_patch(7, "delivered"));
    let mut accounted = Accounted::default();
    accounted.note(&cursor_at(9));
    (replica, accounted)
}

/// A frame repeating what an accounted change already delivered is the
/// settling tail the design permits, not a violation.
#[tokio::test]
async fn a_settling_frame_at_an_accounted_change_is_not_a_violation() {
    let (mut client, _server) = frames(vec![(9, items_patch(7, "delivered"))]).await;
    let (mut replica, accounted) = accounted_at_nine();
    no_live_past(
        &mut client,
        "docs",
        &mut replica,
        &accounted,
        Duration::from_millis(50),
    )
    .await;
    assert_eq!(replica.ids(), vec![7]);
}

/// A frame at an accounted change that adds a row is a delivery nothing asked
/// for, whatever position it carries.
#[tokio::test]
#[should_panic(expected = "added to the replica")]
async fn a_frame_at_an_accounted_change_that_adds_a_row_is_a_violation() {
    let (mut client, _server) = frames(vec![(9, items_patch(8, "unasked"))]).await;
    let (mut replica, accounted) = accounted_at_nine();
    no_live_past(
        &mut client,
        "docs",
        &mut replica,
        &accounted,
        Duration::from_millis(50),
    )
    .await;
}

/// A frame carrying a later change than anything accounted for is a row that
/// should never have been delivered.
#[tokio::test]
#[should_panic(expected = "past the change")]
async fn a_frame_past_every_accounted_change_is_a_violation() {
    let (mut client, _server) = frames(vec![(10, items_patch(8, "unasked"))]).await;
    let (mut replica, accounted) = accounted_at_nine();
    no_live_past(
        &mut client,
        "docs",
        &mut replica,
        &accounted,
        Duration::from_millis(50),
    )
    .await;
}

/// Waiting for a change is not satisfied by the settling tail of an earlier
/// one, which may already be sitting in the client's backlog.
#[tokio::test]
#[should_panic(expected = "timed out waiting for a docs patch past")]
async fn a_settling_frame_does_not_stand_in_for_the_change_awaited() {
    let (mut client, _server) = frames(vec![(9, items_patch(7, "delivered"))]).await;
    let (mut replica, mut accounted) = accounted_at_nine();
    live_past(
        &mut client,
        "docs",
        &mut replica,
        &mut accounted,
        Duration::from_millis(50),
    )
    .await;
}

/// The change itself, behind that tail, is what the wait returns on.
#[tokio::test]
async fn the_change_behind_a_settling_frame_is_the_one_awaited() {
    let (mut client, _server) = frames(vec![
        (9, items_patch(7, "delivered")),
        (10, items_patch(8, "the change")),
    ])
    .await;
    let (mut replica, mut accounted) = accounted_at_nine();
    live_past(
        &mut client,
        "docs",
        &mut replica,
        &mut accounted,
        Duration::from_millis(50),
    )
    .await;
    assert_eq!(replica.ids(), vec![7, 8]);
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
    let mut accounted = Accounted::default();
    for patch in alice.expect_snapshot("docs").await {
        replica.apply(&patch.patchset_zstd);
    }
    expect_membership_opened(&mut alice).await;
    // Events committed before the subscription registered may still be in the
    // change stream and repeat snapshot rows (R28's documented overlap, which
    // replaces harmlessly). Drain to silence so the next frame is the move's.
    while let Some(patch) = alice.try_live(QUIET).await {
        if patch.sub_id == "docs" {
            accounted.note(&patch.cursor);
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
    live_until(
        &mut alice,
        "docs",
        &mut replica,
        &mut accounted,
        &[0, 11, 21, 22],
        DELIVERY,
    )
    .await;
    assert!(
        alice.try_resync("docs", QUIET).await.is_none(),
        "a membership change must move rows without a resync (decision 2)"
    );

    // A later change to a moved-in row is an ordinary live patch, which pins
    // that the engine's set really moved rather than rows being copied once.
    fixture
        .exec("UPDATE items SET label = 'renamed' WHERE id = 21")
        .await;
    live_past(&mut alice, "docs", &mut replica, &mut accounted, DELIVERY).await;

    // Move-out: leaving team 2 withdraws its rows, again with no resync.
    fixture
        .exec("DELETE FROM team_members WHERE team_id = 2 AND member = 'alice'")
        .await;
    live_until(
        &mut alice,
        "docs",
        &mut replica,
        &mut accounted,
        &[0, 11],
        DELIVERY,
    )
    .await;
    assert!(
        alice.try_resync("docs", QUIET).await.is_none(),
        "a membership removal must withdraw rows without a resync (decision 2)"
    );

    // Rows of teams the caller never joined were never delivered.
    accounted.note_committed(&fixture).await;
    fixture.exec("DELETE FROM items WHERE id = 31").await;
    no_live_past(&mut alice, "docs", &mut replica, &accounted, QUIET).await;

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

/// The first row of a team the caller already belonged to.
///
/// A team holding nothing at registration appears in no snapshot row and moves
/// no membership row afterwards, so its admission comes from what registration
/// read rather than from anything the change stream carries.
///
/// **Measured while writing this, 2026-08-23: the term seed is not the only
/// path that supplies it.** Emptying the seed entirely leaves this test green,
/// because the hidden membership subscription's own snapshot moves the same
/// term. So this pins the behaviour and not the mechanism, and it cannot fail
/// for a defect in the seed read alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_row_of_a_team_already_joined_arrives_live() {
    let fixture = Fixture::acquire().await;
    let server = membership_term_fixture(&fixture).await;

    // Team 2 exists and holds nothing, and alice is in it before she
    // subscribes. She is in team 1 too, which holds the fixture's row, so the
    // snapshot is non-empty and teaches the engine team 1 and only team 1.
    // Team 3 she never joins.
    fixture.exec("INSERT INTO teams (id) VALUES (2), (3)").await;
    fixture
        .exec("INSERT INTO team_members (team_id, member) VALUES (1, 'alice'), (2, 'alice')")
        .await;

    let mut alice = server.connect();
    alice.handshake_with("r27-alice", "user:alice").await;
    alice.subscribe("docs", TERM_QUERY).await;
    let mut replica = Replica::new();
    let mut accounted = Accounted::default();
    for patch in alice.expect_snapshot("docs").await {
        replica.apply(&patch.patchset_zstd);
    }
    expect_membership_opened(&mut alice).await;
    while let Some(patch) = alice.try_live(QUIET).await {
        if patch.sub_id == "docs" {
            accounted.note(&patch.cursor);
            replica.apply(&patch.patchset_zstd);
        }
    }
    assert_eq!(
        replica.ids(),
        vec![0],
        "team 2 holds nothing yet, so the snapshot taught the engine team 1 alone"
    );

    // No membership row moves from here on, so only the seed can admit team 2.
    fixture
        .exec("INSERT INTO items (id, owner, team_id, label) VALUES (21, 'bob', 2, 'first')")
        .await;
    // Content-targeted: a team admitted only by the seed still admits its
    // first row, however many settling frames interleave before it.
    live_until(
        &mut alice,
        "docs",
        &mut replica,
        &mut accounted,
        &[0, 21],
        DELIVERY,
    )
    .await;

    // A team she never joined stays out, so the seed admitted one team rather
    // than everything.
    accounted.note_committed(&fixture).await;
    fixture
        .exec("INSERT INTO items (id, owner, team_id, label) VALUES (31, 'bob', 3, 'nope')")
        .await;
    no_live_past(&mut alice, "docs", &mut replica, &accounted, QUIET).await;
}

/// A membership move delivers a row before the row's own event does.
///
/// The move's read runs against the live table, so when one commit carries a
/// membership row and the first row of the team it admits, the move already
/// sees that row and delivers it at the membership event's position, and the
/// row's own event follows above it carrying the same row again. That second
/// frame is a legitimate repeat, and the silence check after it must account
/// for the change by what the database committed rather than by the frames
/// met, or it refuses the repeat as a delivery nobody asked for. Seen twice in
/// CI on 2026-09-16 with the two events in separate commits, where a slow
/// runner produced the same order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_membership_move_may_deliver_a_row_ahead_of_its_own_event() {
    let fixture = Fixture::acquire().await;
    let server = membership_term_fixture(&fixture).await;

    fixture.exec("INSERT INTO teams (id) VALUES (2), (3)").await;
    fixture
        .exec("INSERT INTO team_members (team_id, member) VALUES (1, 'alice')")
        .await;

    let mut alice = server.connect();
    alice.handshake_with("r27-alice", "user:alice").await;
    alice.subscribe("docs", TERM_QUERY).await;
    let mut replica = Replica::new();
    let mut accounted = Accounted::default();
    for patch in alice.expect_snapshot("docs").await {
        replica.apply(&patch.patchset_zstd);
    }
    expect_membership_opened(&mut alice).await;
    while let Some(patch) = alice.try_live(QUIET).await {
        if patch.sub_id == "docs" {
            accounted.note(&patch.cursor);
            replica.apply(&patch.patchset_zstd);
        }
    }
    assert_eq!(replica.ids(), vec![0], "alice is in team 1 alone");

    // One commit: the membership row first, then the team's first row, so the
    // move's read sees the row and the row's own event still follows.
    fixture
        .exec(
            "BEGIN; \
             INSERT INTO team_members (team_id, member) VALUES (2, 'alice'); \
             INSERT INTO items (id, owner, team_id, label) VALUES (21, 'bob', 2, 'first'); \
             COMMIT",
        )
        .await;
    live_until(
        &mut alice,
        "docs",
        &mut replica,
        &mut accounted,
        &[0, 21],
        DELIVERY,
    )
    .await;

    // The repeat of row 21 from its own event may still be in flight, and a
    // row of a team she never joined must not arrive at all.
    accounted.note_committed(&fixture).await;
    fixture
        .exec("INSERT INTO items (id, owner, team_id, label) VALUES (31, 'bob', 3, 'nope')")
        .await;
    no_live_past(&mut alice, "docs", &mut replica, &accounted, QUIET).await;
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
    let mut accounted = Accounted::default();
    for patch in alice.expect_snapshot("docs").await {
        replica.apply(&patch.patchset_zstd);
    }
    expect_membership_opened(&mut alice).await;
    // Drain the R28 backlog overlap, as above, so the next frame is the move's.
    while let Some(patch) = alice.try_live(QUIET).await {
        if patch.sub_id == "docs" {
            accounted.note(&patch.cursor);
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
    live_until(
        &mut alice,
        "docs",
        &mut replica,
        &mut accounted,
        &[11, 21],
        DELIVERY,
    )
    .await;
    assert!(
        alice.try_resync("docs", QUIET).await.is_none(),
        "the move-in must not re-snapshot"
    );

    // Policy admits, term excludes: alice's own row in team 9 never arrives,
    // because the subscription's filter is interest and interest excludes it.
    accounted.note_committed(&fixture).await;
    fixture
        .exec("UPDATE items SET label = 'still excluded' WHERE id = 91")
        .await;
    no_live_past(&mut alice, "docs", &mut replica, &accounted, QUIET).await;

    // Move-out under a policy that still admits the rows: no delete arrives
    // (the withdrawal question is may_see on the current row, and the answer
    // is allow), and no resync either. The replica's own membership copy is
    // what stops the local query matching, which R27 step 5 serves.
    accounted.note_committed(&fixture).await;
    fixture
        .exec("DELETE FROM team_members WHERE team_id = 2 AND member = 'alice'")
        .await;
    no_live_past(&mut alice, "docs", &mut replica, &accounted, QUIET).await;
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

/// R63 decision 3: the dialect a developer writes first, a direct caller
/// comparison with no subquery, registers and self-seeds as a term.
///
/// Withdrawn while `upstream/subql-caller-term-subscriber-kind-not-answerable.md`
/// was open, restored when `describe_terms` gained the `Caller` entry naming
/// the compared column's kind. No membership table is involved, so no
/// `MembershipOpened` announce is expected either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_caller_comparison_registers_and_self_seeds() {
    let fixture = Fixture::acquire().await;
    let server = term_over_owner_fixture(&fixture).await;

    fixture
        .exec(
            "INSERT INTO items (id, owner, team_id, label) VALUES \
             (51, 'alice', 1, 'hers'), (52, 'bob', 1, 'his')",
        )
        .await;

    let mut alice = server.connect();
    alice.handshake_with("r63-direct", "user:alice").await;
    alice
        .subscribe(
            "mine",
            "SELECT * FROM items WHERE owner = current_app_user()",
        )
        .await;
    let mut replica = Replica::new();
    let mut accounted = Accounted::default();
    for patch in alice.expect_snapshot("mine").await {
        replica.apply(&patch.patchset_zstd);
    }
    // Drain the R28 backlog overlap, as above, so the next frame is the
    // insert's own.
    while let Some(patch) = alice.try_live(QUIET).await {
        if patch.sub_id == "mine" {
            accounted.note(&patch.cursor);
            replica.apply(&patch.patchset_zstd);
        }
    }
    assert_eq!(replica.ids(), vec![51], "the seed is the caller's own rows");

    // A live row owned by the caller arrives.
    fixture
        .exec("INSERT INTO items (id, owner, team_id, label) VALUES (53, 'alice', 1, 'new')")
        .await;
    live_until(
        &mut alice,
        "mine",
        &mut replica,
        &mut accounted,
        &[51, 53],
        DELIVERY,
    )
    .await;

    // One owned by somebody else stays silent.
    accounted.note_committed(&fixture).await;
    fixture
        .exec("INSERT INTO items (id, owner, team_id, label) VALUES (54, 'bob', 1, 'not-hers')")
        .await;
    no_live_past(&mut alice, "mine", &mut replica, &accounted, QUIET).await;
}

/// The set half of the same feature: the team is granted to a share key, the
/// filter names the subjects the caller holds rather than its identity, and
/// the rows reach a caller who owns none of them.
///
/// The client spells the set test the one way that survives the round trip,
/// since that is the shape pg2sqlite restores to `= ANY(string_to_array(...))`
/// and the only one subql compiles as a caller-set term.
#[tokio::test(flavor = "multi_thread")]
async fn a_share_key_admits_the_rows_its_membership_grants() {
    // The guarded shape pg2sqlite emits for `= ANY(string_to_array(...))`,
    // which is the one its reverse direction reads back as that membership.
    // A bare `instr` search is read as a position query and refused.
    const SET_QUERY: &str = "SELECT * FROM items WHERE team_id IN \
        (SELECT team_id FROM team_members WHERE CASE WHEN current_app_subjects() IS NOT NULL \
          THEN current_app_subjects() <> '' AND instr(member, ',') = 0 \
          AND instr(',' || current_app_subjects() || ',', ',' || member || ',') > 0 END)";

    let fixture = Fixture::acquire().await;
    let server = subject_set_term_fixture(&fixture).await;
    fixture
        .exec("INSERT INTO items (id, owner, team_id, label) VALUES (11, 'nobody', 1, 'one')")
        .await;

    // Owns nothing, is a member of nothing, holds the key the team is
    // granted to.
    let mut holder = server.connect();
    holder
        .handshake_presenting("r27-holder", &["user:stranger", SHARE_KEY], None)
        .await;
    holder.subscribe("docs", SET_QUERY).await;
    let mut replica = Replica::new();
    for patch in holder.expect_snapshot("docs").await {
        replica.apply(&patch.patchset_zstd);
    }
    expect_membership_opened(&mut holder).await;
    while let Some(patch) = holder.try_live(QUIET).await {
        if patch.sub_id == "docs" {
            replica.apply(&patch.patchset_zstd);
        }
    }
    assert_eq!(
        replica.ids(),
        vec![0, 11],
        "the key's membership admits the team's rows, which its holder owns none of"
    );
}
