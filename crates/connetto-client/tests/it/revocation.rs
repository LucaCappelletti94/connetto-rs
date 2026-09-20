//! Revocation has to reach the device (R7).
//!
//! A grant here is a row of a membership table: `items` is visible to a member
//! of the row's team, so withdrawing access produces **no event at all on the
//! table the client subscribes to**. Nothing on the change path can hang a
//! decision on it, which is why the server has to notice the grant itself and
//! replace what the caller holds.
//!
//! Driven through the real client against the real server, and every assertion
//! reads the replica rather than a frame: what makes this a leak rather than a
//! missing notification is that the rows are still on the device afterwards.
//!
//! Needs Docker: the fixture starts its own Postgres and its own `OpenFGA`.

use std::time::Duration;

use connetto_client::{
    ClientConfig, ClientEvent, ConnettoConnection, FullResyncReason, Grant, Replica,
};
use connetto_core::traits::Transport;
use connetto_server::LoopbackTransport;
use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::{
    SHARE_KEY_A, SHARE_KEY_B, cross_table_visibility_fixture, keyed_share_fixture,
};
use diesel::prelude::*;

/// The subscription every caller here registers. Row 0 is the fixture's own
/// seed, left out so the assertions read only what this test wrote.
const QUERY: &str = "SELECT * FROM items WHERE id > 0";
const SUB: &str = "items";

/// The replica's shape. `INTEGER PRIMARY KEY` rather than `INT`, because SQLite
/// only treats the former as the rowid alias a patchset delete matches on.
const SQLITE_DDL: &str = "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, \
                          owner TEXT NOT NULL, team_id INTEGER NOT NULL, label TEXT);";

/// The member the fixture seeds, so this one's access is never touched.
const SETTLED: &str = "fanout-owner";

/// The member whose grant is withdrawn.
const WITHDRAWN: &str = "r7-alice";

/// How long a frame that should arrive is given.
const DELIVERY: Duration = Duration::from_secs(30);

/// How long to wait before concluding nothing is being delivered. Silence is an
/// assertion here, so it has to outlast the change stream carrying the
/// withdrawal rather than merely the scheduler.
const QUIET: Duration = Duration::from_secs(5);

/// The keyed-share subscription. Row 0 is the fixture's own seed, left out for
/// the same reason.
const PAPERS_QUERY: &str = "SELECT * FROM papers WHERE id > 0";
const PAPERS_SUB: &str = "papers";

/// The keyed replica's shape.
const PAPERS_SQLITE_DDL: &str = "CREATE TABLE IF NOT EXISTS papers (id INTEGER PRIMARY KEY, \
                                 owner TEXT NOT NULL);";

diesel::table! {
    /// The replica's copy of the fixture's table.
    items (id) {
        /// Row key.
        id -> Integer,
        /// Whose row it is, unread by the policy here.
        owner -> Text,
        /// The team whose members may read the row.
        team_id -> Integer,
        /// Payload, unread here.
        label -> Nullable<Text>,
    }
}

diesel::table! {
    /// The keyed replica's copy of the shared table.
    papers (id) {
        /// Row key.
        id -> Integer,
        /// Whose row it is, which the identity arm of the policy reads.
        owner -> Text,
    }
}

/// Open a real client session for one person.
async fn connect_as(
    transport: LoopbackTransport,
    person: &str,
) -> ConnettoConnection<LoopbackTransport> {
    let config = ClientConfig::new(person).with_login(Some(Grant::new(format!("user:{person}"))));
    ConnettoConnection::connect(transport, &Replica::in_memory(), SQLITE_DDL, &config, None)
        .await
        .expect("connect")
}

/// Every row the replica holds, by id.
fn ids<T>(conn: &mut ConnettoConnection<T>) -> Vec<i32>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    items::table
        .order(items::id.asc())
        .select(items::id)
        .load(conn.conn())
        .expect("read replica")
}

/// Open a real client session for a caller holding one share key and no
/// identity, which is what a share link produces.
async fn connect_with_key(
    transport: LoopbackTransport,
    client_id: &str,
    key: &str,
) -> ConnettoConnection<LoopbackTransport> {
    let config = ClientConfig::new(client_id).with_capabilities([Grant::new(key.to_owned())]);
    ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        PAPERS_SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("connect")
}

/// Open a real client session for one person over the shared table.
async fn connect_owner(
    transport: LoopbackTransport,
    person: &str,
) -> ConnettoConnection<LoopbackTransport> {
    let config = ClientConfig::new(person).with_login(Some(Grant::new(format!("user:{person}"))));
    ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        PAPERS_SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("connect")
}

/// Every paper the replica holds, by id.
fn paper_ids<T>(conn: &mut ConnettoConnection<T>) -> Vec<i32>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    papers::table
        .order(papers::id.asc())
        .select(papers::id)
        .load(conn.conn())
        .expect("read replica")
}

/// Pump until the next snapshot completes.
async fn pump_to_snapshot_end<T>(conn: &mut ConnettoConnection<T>)
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    pump_until(conn, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await
    .expect("a snapshot must complete");
}

/// Pump until one live patch has been applied.
async fn pump_to_live<T>(conn: &mut ConnettoConnection<T>)
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    pump_until(conn, |event| matches!(event, ClientEvent::LivePatch { .. }))
        .await
        .expect("a live patch must arrive");
}

/// Pump until the server replaces this subscription, returning the reason it
/// gave, then on to the end of the replacement snapshot.
async fn pump_to_resync<T>(conn: &mut ConnettoConnection<T>) -> Option<FullResyncReason>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    let mut seen = None;
    pump_until(conn, |event| match event {
        ClientEvent::FullResync { reason, .. } => {
            seen = Some(reason.clone());
            false
        }
        ClientEvent::SnapshotEnd { .. } => seen.is_some(),
        _ => false,
    })
    .await?;
    seen
}

/// Pump events until `done` accepts one, or give up after [`DELIVERY`].
async fn pump_until<T>(
    conn: &mut ConnettoConnection<T>,
    mut done: impl FnMut(&ClientEvent) -> bool,
) -> Option<()>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    let deadline = tokio::time::Instant::now() + DELIVERY;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Ok(event) = tokio::time::timeout(remaining, conn.pump_one()).await else {
            return None;
        };
        let event = event.expect("pump");
        assert!(
            !matches!(event, ClientEvent::Closed),
            "the session closed before what the test waited for"
        );
        if done(&event) {
            return Some(());
        }
    }
}

/// Whether nothing at all is delivered for [`QUIET`].
async fn stays_quiet<T>(conn: &mut ConnettoConnection<T>) -> bool
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    tokio::time::timeout(QUIET, conn.pump_one()).await.is_err()
}

/// **The phase's proof.** A withdrawn grant takes the rows away from the person
/// who lost it, and disturbs nobody else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawn_grant_takes_the_rows_off_the_device() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let fixture = Fixture::acquire().await;
    let server = cross_table_visibility_fixture(&fixture).await;

    // The grant: a row of the membership table, which the client never reads.
    fixture
        .exec(&format!(
            "INSERT INTO team_members (team_id, member) VALUES (1, '{WITHDRAWN}')"
        ))
        .await;

    let mut withdrawn = connect_as(server.attach(), WITHDRAWN).await;
    withdrawn.subscribe(SUB, QUERY).await.expect("subscribe");
    pump_to_snapshot_end(&mut withdrawn).await;

    // A row of the team, written after the stream is live. Its arrival also
    // proves the membership above has reached the store, because the stream
    // preserves order.
    fixture
        .exec("INSERT INTO items (id, owner, team_id, label) VALUES (41, 'someone', 1, 'shared')")
        .await;
    pump_to_live(&mut withdrawn).await;
    assert_eq!(
        ids(&mut withdrawn),
        vec![41],
        "the team's row reaches a member's device, which is what makes losing \
         it below mean anything"
    );

    // A second member of the same team, whose own access nothing changes.
    let mut settled = connect_as(server.attach(), SETTLED).await;
    settled.subscribe(SUB, QUERY).await.expect("subscribe");
    pump_to_snapshot_end(&mut settled).await;
    assert_eq!(ids(&mut settled), vec![41], "both members see the row");

    fixture
        .exec(&format!(
            "DELETE FROM team_members WHERE member = '{WITHDRAWN}'"
        ))
        .await;
    assert_eq!(
        pump_to_resync(&mut withdrawn).await,
        Some(FullResyncReason::AuthorizationChange),
        "the withdrawal has to reach the client, naming its real cause"
    );
    assert_eq!(
        ids(&mut withdrawn),
        Vec::<i32>::new(),
        "the row is no longer visible to this caller, so it must not still be \
         on the device"
    );

    assert!(
        stays_quiet(&mut settled).await,
        "the other member's access did not change, so nothing at all should \
         reach them: a resync here would re-download a set that is unaltered"
    );
    assert_eq!(
        ids(&mut settled),
        vec![41],
        "and their copy is untouched by somebody else's withdrawal"
    );

    drop(withdrawn);
    drop(settled);
    drop(server);
}

/// Open the three sessions that read the keyed-share fixture, and pin what each
/// one starts with.
///
/// Returns the bearer of [`SHARE_KEY_A`], the bearer of [`SHARE_KEY_B`], and the owner, in
/// that order. The fixture wrote the papers and both shares before the
/// replication slot existed, so nothing here reaches the change stream and no
/// test can mistake its own seed for the grant it moves.
async fn three_bearers(
    server: &connetto_test_harness::Server,
) -> (
    ConnettoConnection<LoopbackTransport>,
    ConnettoConnection<LoopbackTransport>,
    ConnettoConnection<LoopbackTransport>,
) {
    let mut bearer_a = connect_with_key(server.attach(), "bearer-a", SHARE_KEY_A).await;
    bearer_a
        .subscribe(PAPERS_SUB, PAPERS_QUERY)
        .await
        .expect("subscribe");
    pump_to_snapshot_end(&mut bearer_a).await;
    assert_eq!(
        paper_ids(&mut bearer_a),
        vec![1],
        "the key grants exactly the paper its share row names"
    );

    let mut bearer_b = connect_with_key(server.attach(), "bearer-b", SHARE_KEY_B).await;
    bearer_b
        .subscribe(PAPERS_SUB, PAPERS_QUERY)
        .await
        .expect("subscribe");
    pump_to_snapshot_end(&mut bearer_b).await;
    assert_eq!(
        paper_ids(&mut bearer_b),
        vec![2],
        "the second key grants its own paper and nothing else"
    );

    let mut owner = connect_owner(server.attach(), SETTLED).await;
    owner
        .subscribe(PAPERS_SUB, PAPERS_QUERY)
        .await
        .expect("subscribe");
    pump_to_snapshot_end(&mut owner).await;
    assert_eq!(
        paper_ids(&mut owner),
        vec![1, 2, 3],
        "the owner reads its own rows by identity, whoever else was shared them"
    );

    (bearer_a, bearer_b, owner)
}

/// **The narrowing's proof.** A withdrawn share reaches the bearer that lost
/// it, and nobody else.
///
/// The two silences are what this test is for. Under the wide announcement
/// every subscriber of the shared table replaced its whole set on one share
/// row changing, which is correct and costs a full snapshot per unconcerned
/// caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawn_share_reaches_its_bearer_alone() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let fixture = Fixture::acquire().await;
    let server = keyed_share_fixture(&fixture).await;
    let (mut bearer_a, mut bearer_b, mut owner) = three_bearers(&server).await;

    fixture
        .exec(&format!(
            "DELETE FROM paper_shares WHERE viewer = '{SHARE_KEY_A}'"
        ))
        .await;

    assert_eq!(
        pump_to_resync(&mut bearer_a).await,
        Some(FullResyncReason::AuthorizationChange),
        "the bearer that lost the share has to hear it, naming its real cause"
    );
    assert_eq!(
        paper_ids(&mut bearer_a),
        Vec::<i32>::new(),
        "the paper is no longer visible to this key, so it must not still be \
         on the device"
    );

    assert!(
        stays_quiet(&mut bearer_b).await,
        "the other bearer's own share was not touched, so nothing at all \
         should reach it"
    );
    assert_eq!(
        paper_ids(&mut bearer_b),
        vec![2],
        "and its copy is untouched by another key's withdrawal"
    );

    assert!(
        stays_quiet(&mut owner).await,
        "the owner reads by identity, which a share row says nothing about"
    );
    assert_eq!(
        paper_ids(&mut owner),
        vec![1, 2, 3],
        "and the owner still holds every row it owns"
    );

    drop(bearer_a);
    drop(bearer_b);
    drop(owner);
    drop(server);
}

/// The mirror. A share given reaches the bearer that gained it, and nobody
/// else.
///
/// A grant counts as much as a withdrawal here, because the rows it reveals
/// exist already and no row event announces them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_granted_share_reaches_its_new_bearer_alone() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let fixture = Fixture::acquire().await;
    let server = keyed_share_fixture(&fixture).await;
    let (mut bearer_a, mut bearer_b, mut owner) = three_bearers(&server).await;

    fixture
        .exec(&format!(
            "INSERT INTO paper_shares (paper_id, viewer) VALUES (1, '{SHARE_KEY_B}')"
        ))
        .await;

    assert_eq!(
        pump_to_resync(&mut bearer_b).await,
        Some(FullResyncReason::AuthorizationChange),
        "the bearer that gained the share has to hear it, since no row event \
         carries a paper that already existed"
    );
    assert_eq!(
        paper_ids(&mut bearer_b),
        vec![1, 2],
        "and it now reads the paper the new share names"
    );

    assert!(
        stays_quiet(&mut bearer_a).await,
        "the first bearer already held that paper, so nothing changed for it"
    );
    assert_eq!(
        paper_ids(&mut bearer_a),
        vec![1],
        "and its own copy is unaltered"
    );

    assert!(
        stays_quiet(&mut owner).await,
        "the owner's identity arm is untouched by a share it did not gain"
    );
    assert_eq!(
        paper_ids(&mut owner),
        vec![1, 2, 3],
        "and the owner still holds every row it owns"
    );

    drop(bearer_a);
    drop(bearer_b);
    drop(owner);
    drop(server);
}
