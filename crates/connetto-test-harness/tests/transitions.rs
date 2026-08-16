//! What a change does to a caller's copy of a row, in both directions (R6).
//!
//! The change path asks about a row and delivers to whoever may see it. Two
//! things follow that are not features:
//!
//! 1. A row whose new version the caller may not see is dropped, so that caller
//!    keeps the last version it saw, on its own device, for ever.
//! 2. A deleted row's key is forwarded to every subscriber of the table,
//!    including callers who could never see it.
//!
//! Both are checked against a real replica rather than a frame, because a
//! confidentiality claim about a device has to be read off the device. The
//! replica here is the same SQLite file a client would hold: every patch that
//! arrives is applied to it in order, and the assertions read rows back out.
//!
//! `#[ignore]` by default: it needs a Postgres started with `wal_level=logical`
//! and an `OpenFGA` server.

use std::time::Duration;

use connetto_core::messages::{BulkMessage, ControlMessage};
use connetto_core::traits::IncomingFrame;
use connetto_server::Materializer;
use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::{FANOUT_PG_DDL, visibility_fixture};
use diesel::prelude::*;

/// The subscription every caller here registers.
const QUERY: &str = "SELECT * FROM items WHERE id > 0";

/// How long a patch that should arrive is given.
const DELIVERY: Duration = Duration::from_secs(30);

/// How long to wait before concluding nothing is being delivered.
///
/// Silence is the assertion in one half of this file, so it has to outlast the
/// change stream carrying the row rather than merely the scheduler.
const QUIET: Duration = Duration::from_secs(5);

/// The replica's own shape. `INTEGER PRIMARY KEY` rather than `INT`, because
/// SQLite only treats the former as the rowid alias a patchset delete matches
/// on.
const REPLICA_DDL: &str =
    "CREATE TABLE items (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, label TEXT)";

diesel::table! {
    /// The replica's copy of the fixture's table.
    items (id) {
        /// Row key.
        id -> Integer,
        /// Whose row it is, which is what the policy reads.
        owner -> Text,
        /// Payload, unread here.
        label -> Text,
    }
}

/// One caller's replica: every patch delivered to it, applied in order.
struct Replica {
    conn: SqliteConnection,
    applier: Materializer,
}

impl Replica {
    fn new() -> Self {
        let mut conn = SqliteConnection::establish(":memory:").expect("open replica");
        diesel::sql_query(REPLICA_DDL)
            .execute(&mut conn)
            .expect("replica ddl");
        Self {
            conn,
            applier: Materializer::new(FANOUT_PG_DDL).expect("applier"),
        }
    }

    fn apply(&mut self, patchset_zstd: &[u8]) {
        self.applier
            .apply_diffset(patchset_zstd, &mut self.conn)
            .expect("apply patch");
    }

    fn ids(&mut self) -> Vec<i32> {
        items::table
            .order(items::id)
            .select(items::id)
            .load(&mut self.conn)
            .expect("read replica")
    }
}

/// A row that stops being visible to a caller is taken off that caller's
/// replica.
///
/// Read off the replica and not off the frame: what makes this a leak rather
/// than a missing notification is that the row is still there afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical and an OpenFGA server (Docker)"]
async fn a_row_that_leaves_a_caller_s_reach_is_taken_off_their_replica() {
    let fixture = Fixture::acquire().await;
    let server = visibility_fixture(&fixture).await;

    let mut alice = server.connect();
    alice.handshake_with("r6-alice", "user:alice#reach").await;
    alice.subscribe("items", QUERY).await;
    let mut replica = Replica::new();
    for patch in alice.expect_snapshot("items").await {
        replica.apply(&patch.patchset_zstd);
    }

    // Alice's own row, so she holds it on her device.
    fixture
        .exec("INSERT INTO items (id, owner, label) VALUES (41, 'alice', 'hers')")
        .await;
    let patch = alice.wait_for_live(DELIVERY).await;
    replica.apply(&patch.patchset_zstd);
    assert_eq!(
        replica.ids(),
        vec![41],
        "the row alice owns reaches her replica, which is what makes the next \
         assertion about losing it mean anything"
    );

    // The same row, handed to somebody else. Alice may no longer see it.
    fixture
        .exec("UPDATE items SET owner = 'bob' WHERE id = 41")
        .await;
    if let Some(patch) = alice.try_live(DELIVERY).await {
        replica.apply(&patch.patchset_zstd);
    }
    assert_eq!(
        replica.ids(),
        Vec::<i32>::new(),
        "alice may no longer see row 41, so it must not still be on her device"
    );

    alice.close().await;
    drop(server);
}

/// A deleted row is not announced to a caller who could never see it.
///
/// The tombstone carries the row's key, so forwarding it discloses that the row
/// existed, what it was called and when it went, which is what principle 4 of
/// `docs/architecture/08-authorization.md` forbids.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical and an OpenFGA server (Docker)"]
async fn a_deleted_row_is_not_announced_to_a_caller_who_never_saw_it() {
    let fixture = Fixture::acquire().await;
    let server = visibility_fixture(&fixture).await;

    let mut alice = server.connect();
    alice.handshake_with("r6-alice", "user:alice#tomb").await;
    alice.subscribe("items", QUERY).await;
    alice.expect_snapshot("items").await;

    // Bob's row. Alice is subscribed to the table and cannot see this row, so
    // nothing about it should ever reach her.
    fixture
        .exec("INSERT INTO items (id, owner, label) VALUES (42, 'bob', 'his')")
        .await;
    assert!(
        alice.try_live(QUIET).await.is_none(),
        "a row alice cannot see must not be delivered to her, which the read \
         filter already does and this pins before the deletion below"
    );

    fixture.exec("DELETE FROM items WHERE id = 42").await;
    let announced = alice.try_live(QUIET).await;
    assert!(
        announced.is_none(),
        "alice was told row 42 was deleted, which tells her it existed and what \
         its key was: {announced:?}"
    );

    alice.close().await;
    drop(server);
}

/// Catching up from the reconnect log leaves a caller holding exactly what
/// staying connected would have left them holding.
///
/// The phase's substantial proof, and the one that catches a fix applied to one
/// path only. Both callers are the same person under the same policy over the
/// same events, so the two replicas are compared against each other rather than
/// against a list somebody typed: a rule applied differently on the two paths
/// shows up as a difference here whatever the rule is.
///
/// The sequence exercises all three answers. Row 51 becomes visible, then leaves
/// alice's reach. Row 52 is never hers, and is then deleted. Row 53 arrives last
/// so a truncated replay cannot pass by accident.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical and an OpenFGA server (Docker)"]
async fn catching_up_leaves_the_same_rows_as_staying_connected() {
    let fixture = Fixture::acquire().await;
    let server = visibility_fixture(&fixture).await;

    let mut stayed = server.connect();
    stayed
        .handshake_with("r6-stayed", "user:alice#stayed")
        .await;
    stayed.subscribe("items", QUERY).await;
    let mut stayed_replica = Replica::new();
    for patch in stayed.expect_snapshot("items").await {
        stayed_replica.apply(&patch.patchset_zstd);
    }

    let mut resumed = server.connect();
    resumed
        .handshake_with("r6-resumed", "user:alice#resumed")
        .await;
    resumed.subscribe("items", QUERY).await;
    let mut resumed_replica = Replica::new();
    for patch in resumed.expect_snapshot("items").await {
        resumed_replica.apply(&patch.patchset_zstd);
    }

    // One event both callers see, so the resuming one has a cursor to come back
    // with and a row on its device to be taken back later.
    fixture
        .exec("INSERT INTO items (id, owner, label) VALUES (51, 'alice', 'hers')")
        .await;
    let patch = stayed.wait_for_live(DELIVERY).await;
    stayed_replica.apply(&patch.patchset_zstd);
    let patch = resumed.wait_for_live(DELIVERY).await;
    resumed_replica.apply(&patch.patchset_zstd);
    let resume_from = patch.cursor;
    assert_eq!(
        resumed_replica.ids(),
        vec![51],
        "the resuming caller holds the row before it goes away"
    );

    // It goes offline for the rest of the sequence.
    resumed.close().await;

    for sql in [
        "INSERT INTO items (id, owner, label) VALUES (52, 'bob', 'his')",
        "UPDATE items SET owner = 'bob' WHERE id = 51",
        "DELETE FROM items WHERE id = 52",
        "INSERT INTO items (id, owner, label) VALUES (53, 'alice', 'hers too')",
    ] {
        fixture.exec(sql).await;
    }
    while let Some(patch) = stayed.try_live(QUIET).await {
        stayed_replica.apply(&patch.patchset_zstd);
    }

    // Back, from the cursor it persisted. Every frame is read by kind, because a
    // full resync would also end with the right rows and would prove nothing
    // about the path this test exists for.
    let mut back = server.connect();
    back.handshake_resuming("r6-resumed", "user:alice#resumed", resume_from)
        .await;
    back.subscribe("items", QUERY).await;
    let mut replaced = false;
    loop {
        match tokio::time::timeout(QUIET, back.recv()).await {
            Ok(Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch)))) => {
                resumed_replica.apply(&patch.patchset_zstd);
            }
            Ok(Some(IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch)))) => {
                replaced = true;
                resumed_replica.apply(&patch.patchset_zstd);
            }
            Ok(Some(IncomingFrame::Control(ControlMessage::FullResyncRequired(_)))) => {
                replaced = true;
            }
            Ok(Some(IncomingFrame::Control(_))) => {}
            Ok(Some(IncomingFrame::Bulk(other))) => panic!("unexpected bulk frame: {other:?}"),
            Ok(None) | Err(_) => break,
        }
    }
    assert!(
        !replaced,
        "the reconnect was answered with a fresh copy instead of a catchup, so \
         this run says nothing about what the catchup path delivers"
    );

    assert_eq!(
        stayed_replica.ids(),
        resumed_replica.ids(),
        "catching up and staying connected have to leave the same rows, or the \
         same policy means two different things depending on whether a client \
         happened to be online"
    );
    assert_eq!(
        stayed_replica.ids(),
        vec![53],
        "and that set is the one the policy allows: 51 was taken back, 52 was \
         never alice's, 53 is"
    );

    stayed.close().await;
    back.close().await;
    drop(server);
}
