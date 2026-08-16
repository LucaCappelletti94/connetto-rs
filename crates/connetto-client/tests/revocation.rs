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
//! `#[ignore]` by default: it needs a Postgres started with `wal_level=logical`
//! and an `OpenFGA` server.

use std::time::Duration;

use connetto_client::{
    ClientConfig, ClientEvent, ConnettoConnection, FullResyncReason, Grant, Replica,
};
use connetto_core::traits::Transport;
use connetto_server::LoopbackTransport;
use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::cross_table_visibility_fixture;
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
            seen = Some(*reason);
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
#[ignore = "requires a running Postgres with wal_level=logical and an OpenFGA server (Docker)"]
async fn a_withdrawn_grant_takes_the_rows_off_the_device() {
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
