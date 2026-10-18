//! R31 Proof: an app spanning two majors, end to end.
//!
//! A test-local router stands in for the deployment proxy. It owns the one
//! listener, reads the first control frame of each connection, the
//! `Handshake`, and hands the connection to the manager at the declared
//! `schema_major` with the handshake replayed, or to the newest hosted major
//! when none matches. That fallback is how a decommissioned major reaches
//! the newer server and gets the `MajorMismatch` refusal. The hosted set
//! changes during the test, the deployment's migration and decommission.
//! Two in-process `connetto-server` managers share the fixture's Postgres.
//! Major 1 serves `items (id, label)`, and major 2 serves the same table
//! after the test migrates it with the additive `note` column, so the major
//! 1 manager keeps writing while its major is retired.
//!
//! `an_app_updates_with_pending_work_and_drains_the_held_major` proves the
//! update story from the Proof. Device A writes under major 1, one row
//! acknowledged in Postgres and one left pending with no server reachable,
//! and the gate reports the pending write before the update. The app
//! updates with it still pending, the replica rebuilds at once and serves
//! major 2, the main wire reaches the major 2 manager, the full snapshot
//! brings the acked row with the `note` column, the held write drains to
//! the major 1 manager and lands in Postgres as `HeldWork::Applied` and
//! then `Drained`, and the tier converts through its generated and
//! hand-written steps exactly once. The gate reports nothing after the
//! drain.
//!
//! `a_decommissioned_major_is_update_required_and_its_drain_loses_its_work`
//! proves the decommission half. A build at major 1 connecting through the
//! router with major 1 no longer hosted receives the typed `UpdateRequired`
//! signal naming server major 2. Device B's pending write, reopened at
//! major 2, reaches its drain as `HeldWork::Lost` naming the write's
//! sequence, never reaches Postgres, and device B keeps working on major 2
//! with its snapshot arriving.
//!
//! Needs Docker: the fixture starts its own Postgres.

#![expect(
    clippy::too_many_lines,
    reason = "the tests walk their scenarios in order and a split would hide the sequence"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use connetto_client::{
    ClientBuilder, ClientError, ClientEvent, ConnettoClient, ConnettoConnection, CoreClient,
    CorePump, DataDir, Grant, HeldCredential, LiveQuery, MemoryRefreshStore, PendingWork,
    ReconnectPolicy, SyncSchema, TierStepError, TransportFactory,
};
use connetto_core::messages::HeldWork;
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::TestGrantChecker;
use connetto_core::{MAJOR_DIRECTIVE, Major, SchemaVersion, TierBoundary, TierHistory};
use connetto_server::{
    ManagerBuilder, Materializer, PgReadConnector, PgSnapshotSource, RuntimeWritableCatalog,
    SessionConfig, SessionManager, WebSocketTransport, pg_write_target,
};
use connetto_test_harness::router::{HostedEntry, Relay, Router};
use connetto_test_harness::{ConnettoDefaults, Fixture, RosterAuth};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::sql_query;
use tempfile::tempdir;
use tokio::net::TcpStream;

/// The Postgres source each major's manager parses, its major line the way
/// the deployment's schema file carries it.
const PG_DDL_V1: &str = "-- connetto:major 1\nCREATE TABLE items (id INT PRIMARY KEY, label TEXT);";
const PG_DDL_V2: &str =
    "-- connetto:major 2\nCREATE TABLE items (id INT PRIMARY KEY, label TEXT, note TEXT);";

/// The replica DDL the build bakes, `IF NOT EXISTS` because `connect`
/// replays the caller's DDL on every open.
const SQLITE_DDL_V1: &str = "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, label TEXT)";
const SQLITE_DDL_V2: &str =
    "CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, label TEXT, note TEXT)";

/// The device-private tier at each major, and the generated step between
/// them, the SQL a real build would export and diff.
const TIER_V1: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)";
const TIER_V2: &str =
    "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, pinned INTEGER NOT NULL DEFAULT 0)";
const ADD_PINNED: &str = "ALTER TABLE notes ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0";

diesel::table! {
    /// The synced table at major 1.
    #[sql_name = "items"]
    items_v1 (id) {
        /// Item identifier, the primary key.
        id -> Integer,
        /// Optional item label.
        label -> Nullable<Text>,
    }
}

diesel::table! {
    /// The synced table at major 2, the note column the deployment added.
    #[sql_name = "items"]
    items_v2 (id) {
        /// Item identifier, the primary key.
        id -> Integer,
        /// Optional item label.
        label -> Nullable<Text>,
        /// Optional note, absent from the table at major 1.
        note -> Nullable<Text>,
    }
}

diesel::table! {
    /// The device-private tier table at major 1, named bare as an application names it.
    notes (id) {
        /// Note identifier, the primary key.
        id -> Integer,
        /// Optional body.
        body -> Nullable<Text>,
    }
}

diesel::table! {
    /// The tier table at major 2, past what the major 1 `notes` names.
    #[sql_name = "notes"]
    notes_v2 (id) {
        /// Note identifier, the primary key.
        id -> Integer,
        /// Optional body.
        body -> Nullable<Text>,
        /// The pin flag the migration added.
        pinned -> Integer,
    }
}

diesel::table! {
    /// The Postgres target the managers write to, read as admin.
    #[sql_name = "items"]
    pg_items (id) {
        /// Item identifier, the primary key.
        id -> Integer,
        /// Optional item label.
        label -> Nullable<Text>,
    }
}

/// One `user_version` reading, which no `table!` can name.
#[derive(QueryableByName)]
struct UserVersion {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    user_version: i32,
}

/// A dial through the router that failed, at the socket or the handshake
/// step.
#[derive(Debug, thiserror::Error)]
#[error("the dial to the router failed: {0}")]
struct DialFailed(String);

/// A manager whose computed subscriptions read through connetto's connector.
type Manager = SessionManager<PgSnapshotSource, RosterAuth, ConnettoDefaults, PgReadConnector>;

/// The router entry that serves `manager` with whatever connection the
/// router routed, the replayed handshake included.
fn entry(manager: Arc<Manager>) -> HostedEntry {
    Arc::new(move |relay: Relay| {
        let manager = Arc::clone(&manager);
        Box::pin(async move {
            let _ = manager.serve(relay).await;
        })
    })
}

/// The one dialer a build names, the socket connect and the upgrade.
/// Routing by major stays the router's business.
fn dial(
    addr: std::net::SocketAddr,
) -> impl TransportFactory<Transport = WebSocketTransport<TcpStream>, Error = DialFailed> {
    move || async move {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|err| DialFailed(err.to_string()))?;
        WebSocketTransport::connect("ws://127.0.0.1/", stream)
            .await
            .map_err(|err| DialFailed(err.to_string()))
    }
}

/// A manager for one hosted major over the fixture's Postgres, serving `ddl`
/// and advertising the version a build over the same source declares.
fn manager(fixture: &Fixture, ddl: &str, major: Major, version: SchemaVersion) -> Arc<Manager> {
    let pool = fixture.admin().clone();
    ManagerBuilder::new(
        Materializer::builder(ddl)
            .with_write_catalog(RuntimeWritableCatalog::builder().writable("items").build())
            .with_read_connector(PgReadConnector::with_session_setup(pool.clone()))
            .build()
            .expect("build materializer"),
        PgSnapshotSource::from_ddl(pool.clone(), ddl).expect("snapshot source"),
        RosterAuth::granting("token"),
        Arc::new(TestGrantChecker),
        PgReadConnector::with_session_setup(pool.clone()),
        pg_write_target::<ConnettoDefaults>(pool, ddl).expect("build write target"),
    )
    .with_session(
        SessionConfig::new()
            .with_schema_major(Some(major))
            .with_schema_version(Some(version)),
    )
    .build()
}

/// The build at `major` over `ddl` with tier `tier`, the source the real
/// `build.rs` would translate.
#[must_use]
fn build(major: u32, ddl: &str, tier: Option<&str>) -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            format!("{MAJOR_DIRECTIVE} {major}"),
            "",
            ddl,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            tier,
        )
        .expect("the source declares its major"),
    )
}

/// The version a manager built from the same source advertises, so a
/// matching build passes the hash check at the ack.
#[must_use]
fn advertised(major: u32, ddl: &str) -> SchemaVersion {
    build(major, ddl, None).version()
}

/// The major 2 bundle, its tier the pinned column and its history the
/// generated `ADD` step.
#[must_use]
fn bundle_two() -> SchemaBundle {
    SchemaBundle::new(
        format!("{MAJOR_DIRECTIVE} 2"),
        "",
        SQLITE_DDL_V2,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        Some(TIER_V2),
    )
    .expect("the source declares its major")
    .with_tier_history(TierHistory::new(
        one(),
        Some(one()),
        vec![TierBoundary::new(one(), ADD_PINNED)],
    ))
    .expect("the history reaches the build")
}

/// The major 2 build with the application's data step beside the generated
/// one, counting its runs the way the test reads the tier.
#[must_use]
fn build_two(ran: &Arc<AtomicUsize>) -> SyncSchema {
    let counted = Arc::clone(ran);
    SyncSchema::new(bundle_two())
        .with_tier_step(
            one(),
            move |tier: &mut SqliteConnection| -> Result<(), TierStepError> {
                counted.fetch_add(1, Ordering::Relaxed);
                // The data change the application owes, beside the generated step.
                tier.batch_execute("UPDATE notes SET pinned = 1 WHERE id = 1")?;
                Ok(())
            },
        )
        .expect("a step at the build's only boundary")
}

/// The held credential for a device, the grant the test grant checker
/// resolves.
#[must_use]
fn credential(device: &str) -> HeldCredential {
    super::support::held_grant(Grant::new(format!("user:token#{device}")), "token")
}

/// Open the build at `dir` with no server reachable, the way an app opens
/// offline.
async fn open_offline(
    dir: &std::path::Path,
    schema: SyncSchema,
    device: &str,
) -> ConnettoConnection<WebSocketTransport<TcpStream>> {
    let held = credential(device);
    let store = super::support::key_store(&held).await;
    ClientBuilder::new(
        schema,
        super::support::NeverDial::<WebSocketTransport<TcpStream>>::default(),
    )
    .signed_in(held)
    .durable(
        DataDir::new(dir.to_path_buf()),
        store,
        MemoryRefreshStore::default(),
    )
    .open_driven()
    .await
    .expect("open with no server")
}

/// The reconnect policy the test pumps drive, with a short backoff so a
/// broken dial surfaces inside the test bounds.
#[must_use]
fn test_policy() -> ReconnectPolicy {
    ReconnectPolicy::new()
        .with_initial_backoff(Duration::from_millis(1))
        .with_max_backoff(Duration::from_millis(20))
}

/// Connect the build at `dir` through the router with the live pump, the
/// path a deployed app takes.
async fn connect_pumped(
    router: &Router,
    schema: SyncSchema,
    device: &str,
    dir: &std::path::Path,
) -> Result<(CoreClient<WebSocketTransport<TcpStream>, ()>, CorePump), ClientError> {
    let held = credential(device);
    let store = super::support::key_store(&held).await;
    ClientBuilder::new(schema, dial(router.addr()))
        .with_reconnect(test_policy())
        .with_sleeper(|d| tokio::time::sleep(d))
        .signed_in(held)
        .durable(
            DataDir::new(dir.to_path_buf()),
            store,
            MemoryRefreshStore::default(),
        )
        .connect_with_pump()
        .await
}

/// The major the replica records in `main`'s `user_version`.
async fn replica_major(client: &ConnettoClient<WebSocketTransport<TcpStream>>) -> i32 {
    let version: UserVersion = client
        .with_conn(|conn| {
            // A vendor pragma, which the typed DSL cannot express.
            sql_query("PRAGMA user_version")
                .get_result(conn.conn())
                .expect("read the replica major")
        })
        .await
        .expect("gate open");
    version.user_version
}

/// The major the tier records in its own `user_version`.
async fn tier_major(client: &ConnettoClient<WebSocketTransport<TcpStream>>) -> i32 {
    let version: UserVersion = client
        .with_conn(|conn| {
            // A vendor pragma, which the typed DSL cannot express.
            sql_query("PRAGMA connetto_local.user_version")
                .get_result(conn.conn())
                .expect("read the tier major")
        })
        .await
        .expect("gate open");
    version.user_version
}

/// The tier rows at major 2, the columns the migration added.
async fn tier_rows(
    client: &ConnettoClient<WebSocketTransport<TcpStream>>,
) -> Vec<(i32, Option<String>, i32)> {
    client
        .with_conn(|conn| notes_v2::table.load(conn.conn()).expect("read the tier"))
        .await
        .expect("gate open")
}

/// The Postgres `items` rows, read as admin.
async fn server_items(fixture: &Fixture) -> Vec<(i32, Option<String>)> {
    let mut conn = fixture.admin().get().await.expect("admin connection");
    diesel_async::RunQueryDsl::load(pg_items::table.order(pg_items::id), &mut *conn)
        .await
        .expect("read the server target")
}

/// Wait for the Postgres `items` rows to reach `count`, bounded, the write
/// target committing on its own pipeline past the client's ack.
async fn wait_rows(fixture: &Fixture, count: usize) {
    let until = deadline();
    loop {
        let rows = server_items(fixture).await;
        if rows.len() == count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            tokio::time::Instant::now() < until,
            "the server rows settle within the bound"
        );
    }
}

/// Read events until `wanted` arrives by `deadline`, failing on any event
/// `forbidden` names.
async fn await_event(
    events: &mut tokio::sync::broadcast::Receiver<ClientEvent>,
    deadline: tokio::time::Instant,
    wanted: impl Fn(&ClientEvent) -> bool,
    forbidden: impl Fn(&ClientEvent) -> bool,
) {
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("the awaited event arrives within the deadline")
            .expect("event stream closed");
        assert!(!forbidden(&event), "unexpected event {event:?}");
        if wanted(&event) {
            return;
        }
    }
}

/// A refused write, which no step of the drain may cause, since it carries
/// no write of the application's own.
fn rejected(event: &ClientEvent) -> bool {
    matches!(event, ClientEvent::MutationRejected { .. })
}

/// The bound every wait in this file honors, so a wedged path fails, not
/// hangs.
fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(10)
}

fn one() -> Major {
    Major::new(1).expect("one is a major")
}

fn two() -> Major {
    Major::new(2).expect("two is a major")
}

/// The update story. Device A writes two rows and a tier row under major 1
/// while offline, updates with all of it still pending, the replica rebuilds
/// and serves major 2 at once, the held writes drain to the major 1 manager,
/// and the tier converts through its generated and hand-written steps exactly
/// once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_app_updates_with_pending_work_and_drains_the_held_major() {
    let fixture = Fixture::acquire().await;
    fixture
        .exec("CREATE TABLE items (id INT PRIMARY KEY, label TEXT)")
        .await;
    let manager1 = manager(&fixture, PG_DDL_V1, one(), advertised(1, SQLITE_DDL_V1));
    let router = Router::start(vec![(one(), entry(manager1))]).await;
    let dir = tempdir().expect("device A's replica dir");

    // Device A at major 1, offline. Both rows stay pending, beside a tier
    // row the server never sees.
    let (seq1, seq2) = {
        let mut offline = open_offline(
            dir.path(),
            build(1, SQLITE_DDL_V1, Some(TIER_V1)),
            "device-a",
        )
        .await;
        diesel::insert_into(items_v1::table)
            .values((items_v1::id.eq(1), items_v1::label.eq("one")))
            .execute(offline.conn())
            .expect("write row 1 offline");
        let seq1 = offline.push().await.expect("queue").expect("a seq");
        diesel::insert_into(items_v1::table)
            .values((items_v1::id.eq(2), items_v1::label.eq("two")))
            .execute(offline.conn())
            .expect("write row 2 offline");
        diesel::insert_into(notes::table)
            .values((notes::id.eq(1), notes::body.eq("private")))
            .execute(offline.conn())
            .expect("write the tier row");
        let seq2 = offline.push().await.expect("queue").expect("a seq");
        // DRAIN GATE, the plan's "the gate reports them". The pending writes
        // are named the moment the app updates, through the un-acked
        // sequences the connection exposes.
        assert_eq!(
            offline
                .unsynced()
                .iter()
                .map(|write| write.seq)
                .collect::<Vec<_>>(),
            [seq1, seq2],
            "the gate names the pending writes before the update"
        );
        (seq1, seq2)
    };

    // The deployment migrates Postgres and starts the major 2 manager.
    fixture.exec("ALTER TABLE items ADD COLUMN note TEXT").await;
    let ran = Arc::new(AtomicUsize::new(0));
    let manager2 = manager(&fixture, PG_DDL_V2, two(), advertised(2, SQLITE_DDL_V2));
    router.host(two(), entry(manager2));

    // Device A reopens on the same replica directory with the major 2 build.
    let (core, pump) = connect_pumped(&router, build_two(&ran), "device-a", dir.path())
        .await
        .expect("the update opens");
    let client = core.client();
    // DRAIN GATE, after the update and before the drain. The rebuilt
    // replica reports the writes still queued under the major they were
    // captured in, the one only the major 1 manager can apply.
    let work = client.pending_work().await.expect("the gate answers");
    assert_eq!(
        work.unsynced
            .iter()
            .map(|write| (write.seq, write.major))
            .collect::<Vec<_>>(),
        [(seq1, Some(one())), (seq2, Some(one()))],
        "the rebuilt replica reports the older major's writes before the drain"
    );
    let pump = tokio::spawn(pump);
    let mut events = client.events();

    // The replica serves major 2 at once.
    assert_eq!(
        replica_major(client).await,
        2,
        "the rebuilt replica records the new major"
    );

    // The held writes drain to the major 1 manager and land in Postgres.
    await_event(
        &mut events,
        deadline(),
        |event| {
            matches!(
                event,
                ClientEvent::Held(HeldWork::Applied { major, write })
                    if *major == one() && write.seq == seq1
            )
        },
        rejected,
    )
    .await;
    await_event(
        &mut events,
        deadline(),
        |event| {
            matches!(
                event,
                ClientEvent::Held(HeldWork::Applied { major, write })
                    if *major == one() && write.seq == seq2
            )
        },
        rejected,
    )
    .await;
    await_event(
        &mut events,
        deadline(),
        |event| matches!(event, ClientEvent::Held(HeldWork::Drained { major }) if *major == one()),
        rejected,
    )
    .await;
    wait_rows(&fixture, 2).await;
    assert_eq!(
        server_items(&fixture).await,
        vec![(1, Some("one".to_owned())), (2, Some("two".to_owned()))],
        "the drained writes land in Postgres"
    );

    // DRAIN GATE, after the drain. The gate reports nothing.
    let work = client.pending_work().await.expect("the gate answers");
    assert_eq!(
        work,
        PendingWork::default(),
        "nothing is pending after the drain"
    );

    // The synced table resyncs from the major 2 manager, both rows present
    // with the note column queryable.
    let mut live: LiveQuery<(i32, Option<String>, Option<String>)> = client
        .watch(items_v2::table.order(items_v2::id))
        .await
        .expect("live items");
    let until = deadline();
    loop {
        if live.rows().as_slice()
            == [
                (1, Some("one".to_owned()), None),
                (2, Some("two".to_owned()), None),
            ]
        {
            break;
        }
        tokio::time::timeout_at(until, live.changed())
            .await
            .expect("the resynced rows arrive within the bound")
            .expect("the live query is alive");
    }

    // The tier converted through its generated and hand-written steps.
    assert_eq!(
        tier_major(client).await,
        2,
        "the tier records the new major"
    );
    assert_eq!(
        tier_rows(client).await,
        vec![(1, Some("private".to_owned()), 1)],
        "the tier row is readable with pinned"
    );
    assert_eq!(
        ran.load(Ordering::Relaxed),
        1,
        "the application step ran once"
    );

    // Reopened on the same build once the live client has let the file go,
    // the step does not run a second time.
    client.close().await;
    pump.await.expect("the pump ends on close");
    drop(core);
    let mut reopened = open_offline(dir.path(), build_two(&ran), "device-a").await;
    assert_eq!(
        ran.load(Ordering::Relaxed),
        1,
        "the step did not run a second time"
    );
    let tier: Vec<(i32, Option<String>, i32)> = notes_v2::table
        .load(reopened.conn())
        .expect("read the tier");
    assert_eq!(
        tier,
        vec![(1, Some("private".to_owned()), 1)],
        "the tier row stays readable on the reopen"
    );

    router.close();
}

/// The decommission half. With major 1 no longer hosted, a build at major 1
/// receives the typed `UpdateRequired` signal naming server major 2, and
/// device B's pending write, reopened at major 2, reaches its drain as
/// `HeldWork::Lost` naming the write's sequence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_decommissioned_major_is_update_required_and_its_drain_loses_its_work() {
    let fixture = Fixture::acquire().await;
    fixture
        .exec("CREATE TABLE items (id INT PRIMARY KEY, label TEXT, note TEXT)")
        .await;
    fixture
        .exec("INSERT INTO items VALUES (1, 'one', NULL)")
        .await;
    let manager1 = manager(&fixture, PG_DDL_V1, one(), advertised(1, SQLITE_DDL_V1));
    let manager2 = manager(&fixture, PG_DDL_V2, two(), advertised(2, SQLITE_DDL_V2));
    // The deployment migrates and hosts both majors, then retires major 1.
    // The fallback routes what is left to the newest hosted major.
    let router = Router::start(vec![(one(), entry(manager1)), (two(), entry(manager2))]).await;
    router.decommission(one());

    // A build at major 1 is told to update, naming the server's major.
    let dir_stale = tempdir().expect("the stale build's replica dir");
    match connect_pumped(
        &router,
        build(1, SQLITE_DDL_V1, Some(TIER_V1)),
        "stale",
        dir_stale.path(),
    )
    .await
    {
        Err(ClientError::UpdateRequired { client, server }) => {
            assert_eq!(client, Some(one()), "the build's major is named");
            assert_eq!(server, two(), "the server's major is named");
        }
        Err(other) => panic!("expected the typed update-required signal, got {other:?}"),
        Ok(_) => panic!("a major 1 build connected after the decommission"),
    }

    // Device B, a separate replica. One pending write at major 1 while
    // offline, reopened at major 2 after the decommission.
    let dir_b = tempdir().expect("device B's replica dir");
    let ran = Arc::new(AtomicUsize::new(0));
    let seq_b = {
        let mut offline = open_offline(
            dir_b.path(),
            build(1, SQLITE_DDL_V1, Some(TIER_V1)),
            "device-b",
        )
        .await;
        diesel::insert_into(items_v1::table)
            .values((items_v1::id.eq(9), items_v1::label.eq("lost")))
            .execute(offline.conn())
            .expect("write offline");
        offline.push().await.expect("queue").expect("a seq")
    };

    let (core, pump) = connect_pumped(&router, build_two(&ran), "device-b", dir_b.path())
        .await
        .expect("device B updates");
    let client = core.client();
    tokio::spawn(pump);
    let mut events = client.events();

    // The drain reports the held work lost, naming the write's sequence.
    await_event(
        &mut events,
        deadline(),
        |event| {
            matches!(
                event,
                ClientEvent::Held(HeldWork::Lost { major, writes, .. })
                    if *major == one() && writes.iter().map(|write| write.seq).eq([seq_b])
            )
        },
        |_| false,
    )
    .await;

    // The lost row never reaches Postgres.
    assert_eq!(
        server_items(&fixture).await,
        vec![(1, Some("one".to_owned()))],
        "the lost write never reaches Postgres"
    );

    // Device B keeps working on major 2, its snapshot arriving.
    let mut live: LiveQuery<(i32, Option<String>, Option<String>)> = client
        .watch(items_v2::table.order(items_v2::id))
        .await
        .expect("live items");
    loop {
        if live.rows().iter().any(|(id, ..)| *id == 1) {
            break;
        }
        tokio::time::timeout_at(deadline(), live.changed())
            .await
            .expect("the snapshot arrives within the bound")
            .expect("the live query is alive");
    }
    assert_eq!(
        live.rows(),
        vec![(1, Some("one".to_owned()), None)],
        "device B's snapshot arrives on major 2"
    );

    client.close().await;
    router.close();
}
