//! R84: the keyed grouped handle, end to end.
//!
//! Runs a `connetto-server` in-process over a localhost WebSocket with the
//! real read connector against the fixture's Postgres, and drives
//! [`ConnettoClient::watch_groups`] through it: the seeded groups arrive as a
//! typed map, a fold delta moves one entry, a group born on the change stream
//! appears, an emptied one leaves, and a restart with no server reachable
//! reads the last synced map from the resting table (R83 extended to groups).
//!
//! Needs Docker: the fixture starts its own Postgres.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Grant, Replica, Watchable,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_server::{
    AbuseConfig, Materializer, PgReadConnector, PgSnapshotSource, RequestGuard,
    RuntimeWritableCatalog, SessionConfig, SessionManager, ThrottleConfig, TierLimits,
    WebSocketTransport, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth};
use diesel::prelude::*;
use subql::{CdcSource, PgSqliteEmuSource};
use tokio::net::{TcpListener, TcpStream};

const PG_DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, status TEXT);";
// `IF NOT EXISTS` because `connect` replays the caller's DDL on every open.
const SQLITE_DDL: &str = "CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, status TEXT);";

diesel::table! {
    orders (id) {
        id -> BigInt,
        status -> Nullable<Text>,
    }
}

/// A manager whose computed subscriptions read through connetto's connector.
type Manager = SessionManager<PgSnapshotSource, RosterAuth, ConnettoWatermark, PgReadConnector>;

fn manager(fixture: &Fixture) -> Arc<Manager> {
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default()
            .with_identified(TierLimits::identified().with_read_timeout(Duration::from_secs(30))),
        AbuseConfig::default(),
    ));
    let pool = fixture.admin().clone();
    SessionManager::with_connector(
        Materializer::with_read_connector(
            PG_DDL,
            RuntimeWritableCatalog::default(),
            None,
            None,
            PgReadConnector::with_session_setup(pool.clone()),
        )
        .expect("build materializer"),
        PgSnapshotSource::from_ddl(pool.clone(), PG_DDL).expect("snapshot source"),
        // A grouped count is global, so the row policy never sees it.
        RosterAuth::granting("token"),
        Arc::new(TestGrantChecker),
        PgReadConnector::with_session_setup(pool.clone()),
        pg_write_target::<ConnettoWatermark>(pool, PG_DDL).expect("build write target"),
        guard,
        SessionConfig::default(),
    )
}

/// Serve one session on a fresh localhost listener.
async fn spawn_server(
    manager: Arc<Manager>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let transport = WebSocketTransport::accept(stream).await.expect("ws accept");
        let _ = manager.serve(transport).await;
    });
    (addr, server)
}

/// Connect a client over a real WebSocket against a file replica at `db_path`.
async fn connect(
    addr: std::net::SocketAddr,
    client_id: &str,
    db_path: &str,
) -> ConnettoConnection<WebSocketTransport<TcpStream>> {
    let stream = TcpStream::connect(addr).await.expect("connect");
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .expect("ws connect");
    let config = ClientConfig::new(client_id.to_owned())
        .with_login(Some(Grant::new(format!("user:token#{client_id}"))));
    ConnettoConnection::connect(
        transport,
        &Replica::encrypted_file(db_path, Some(connetto_core::test_support::replica_key()))
            .expect("key provided"),
        SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("client connect")
}

/// The typed grouped query every test watches: one count per status.
fn by_status() -> impl diesel::query_builder::QueryFragment<diesel::sqlite::Sqlite> {
    orders::table
        .group_by(orders::status)
        .select((orders::status, diesel::dsl::count_star()))
}

/// Run `sql` on the emulated source and dispatch every event it produced.
async fn apply(source: &mut PgSqliteEmuSource, manager: &Arc<Manager>, sql: &str) {
    source.execute_sql(sql).expect("execute dml");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager.dispatch_event(&event).await.expect("dispatch");
    }
}

/// Await the next map change, bounded so a wedged path fails, not hangs.
async fn next_change(groups: &mut connetto_client::LiveGroups<Option<String>, i64>) {
    tokio::time::timeout(Duration::from_secs(5), groups.changed())
        .await
        .expect("map change timed out")
        .expect("driver alive");
}

fn entry(status: &str, count: i64) -> (Option<String>, i64) {
    (Some(status.to_owned()), count)
}

/// R84 step 1's live half: the seed arrives as a typed map, a fold delta
/// moves one entry, a group born on the change stream appears under its own
/// key, and an emptied one leaves the map.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grouped_watch_maintains_one_entry_per_group() {
    let fixture = Fixture::acquire().await;
    fixture.exec("DROP TABLE IF EXISTS orders CASCADE").await;
    fixture
        .exec("CREATE TABLE orders (id INT PRIMARY KEY, status TEXT)")
        .await;
    fixture
        .exec("INSERT INTO orders VALUES (1, 'open'), (2, 'open')")
        .await;
    let manager = manager(&fixture);
    let (addr, server) = spawn_server(Arc::clone(&manager)).await;

    let db = tempfile::Builder::new()
        .suffix(".sqlite")
        .tempfile()
        .expect("temp db");
    let db_path = db.path().to_str().expect("utf8 path").to_owned();
    let conn = connect(addr, "grouped", &db_path).await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    let mut groups = orders::table
        .group_by(orders::status)
        .select((orders::status, diesel::dsl::count_star()))
        .live(&client)
        .await
        .expect("live groups");
    assert!(groups.map().is_empty(), "nothing has arrived yet");

    // The seeded group arrives as one keyed upsert and lands in the map.
    tokio::select! {
        () = next_change(&mut groups) => {}
        refused = async {
            loop {
                if let Ok(ClientEvent::NonFatal { detail, .. }) = events.recv().await {
                    break detail;
                }
            }
        } => panic!("the grouped subscription was refused: {refused}"),
    }
    assert_eq!(
        groups.map(),
        HashMap::from([entry("open", 2)]),
        "the seed is the fixture's one group"
    );
    assert!(groups.as_of_secs().is_some(), "the map carries its as-of");

    // A fold delta moves the existing entry.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    apply(
        &mut source,
        &manager,
        "INSERT INTO orders VALUES (4, 'open')",
    )
    .await;
    next_change(&mut groups).await;
    assert_eq!(groups.map(), HashMap::from([entry("open", 3)]));

    // A group born on the change stream appears beside it.
    apply(
        &mut source,
        &manager,
        "INSERT INTO orders VALUES (100, 'done')",
    )
    .await;
    next_change(&mut groups).await;
    assert_eq!(
        groups.map(),
        HashMap::from([entry("open", 3), entry("done", 1)]),
    );

    // Emptying the young group removes exactly its entry.
    apply(&mut source, &manager, "DELETE FROM orders WHERE id = 100").await;
    next_change(&mut groups).await;
    assert_eq!(groups.map(), HashMap::from([entry("open", 3)]));

    drop(groups);
    drop(client);
    server.await.expect("join server");
}

/// R84 step 1's resting half, R83's done-when extended to groups: a client
/// restarted offline shows the last synced map from the resting table, not an
/// empty one, before any reconnect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_reads_the_last_synced_map_from_the_resting_table() {
    let fixture = Fixture::acquire().await;
    fixture.exec("DROP TABLE IF EXISTS orders CASCADE").await;
    fixture
        .exec("CREATE TABLE orders (id INT PRIMARY KEY, status TEXT)")
        .await;
    fixture
        .exec("INSERT INTO orders VALUES (1, 'open'), (2, 'done')")
        .await;
    let manager = manager(&fixture);
    let (addr, server) = spawn_server(Arc::clone(&manager)).await;

    let db = tempfile::Builder::new()
        .suffix(".sqlite")
        .tempfile()
        .expect("temp db");
    let db_path = db.path().to_str().expect("utf8 path").to_owned();

    // First run: watch, see the seeded map, and let the pump rest it. Driven
    // through `with_pump` so the reopen waits for a fully closed connection.
    let conn = connect(addr, "resting", &db_path).await;
    let (client, pump) = ConnettoClient::with_pump(conn);
    let pump = tokio::spawn(pump);
    let mut groups = client
        .watch_groups::<_, Option<String>, i64>(by_status())
        .await
        .expect("watch groups");
    while groups.map().len() < 2 {
        next_change(&mut groups).await;
    }
    assert_eq!(
        groups.map(),
        HashMap::from([entry("open", 1), entry("done", 1)]),
    );
    drop(groups);
    drop(client);
    pump.await.expect("first pump ends");
    server.abort();

    // Restart offline against the same file, before any server is reachable.
    let replica =
        Replica::encrypted_file(&db_path, Some(connetto_core::test_support::replica_key()))
            .expect("key provided");
    let config = ClientConfig::new("resting").with_login(Some(Grant::new("user:token#resting")));
    let conn = ConnettoConnection::<WebSocketTransport<TcpStream>>::open(
        &replica, SQLITE_DDL, &config, None,
    )
    .expect("reopen offline");
    assert!(!conn.is_connected(), "the restart reaches no server");
    let (client, pump) = ConnettoClient::with_pump(conn);
    let pump = tokio::spawn(pump);
    let groups = client
        .watch_groups::<_, Option<String>, i64>(by_status())
        .await
        .expect("watch groups offline");
    assert_eq!(
        groups.map(),
        HashMap::from([entry("open", 1), entry("done", 1)]),
        "the last synced map rests through the restart, read before any reconnect",
    );
    assert!(
        groups.as_of_secs().is_some(),
        "the rested map carries its as-of time",
    );
    drop(groups);
    drop(client);
    pump.await.expect("second pump ends");
}

/// One answer row of the top-orders window, decoded from the whole answer's
/// object by column name.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
struct TopOrder {
    id: i64,
    status: Option<String>,
}

/// R84 step 2: a row-shaped query the server computes (here a latest-N
/// window, which registers as a whole re-read) renders as a live answer that
/// is replaced whole on every move, and a restart with no server reachable
/// reads the last synced answer from the resting table.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_shaped_watch_replaces_the_answer_whole() {
    let fixture = Fixture::acquire().await;
    fixture.exec("DROP TABLE IF EXISTS orders CASCADE").await;
    fixture
        .exec("CREATE TABLE orders (id INT PRIMARY KEY, status TEXT)")
        .await;
    fixture
        .exec("INSERT INTO orders VALUES (1, 'a'), (2, 'b'), (3, 'c')")
        .await;
    let manager = manager(&fixture);
    let (addr, server) = spawn_server(Arc::clone(&manager)).await;

    let db = tempfile::Builder::new()
        .suffix(".sqlite")
        .tempfile()
        .expect("temp db");
    let db_path = db.path().to_str().expect("utf8 path").to_owned();
    let conn = connect(addr, "rows", &db_path).await;
    let (client, pump) = ConnettoClient::with_pump(conn);
    let pump = tokio::spawn(pump);

    let top_two = || {
        orders::table
            .order(orders::id.desc())
            .limit(2)
            .select((orders::id, orders::status))
    };
    let mut top = client
        .watch_rows::<_, TopOrder>(top_two())
        .await
        .expect("watch rows");
    assert!(top.rows().is_empty(), "nothing has arrived yet");

    // The first answer arrives whole, newest first.
    tokio::time::timeout(Duration::from_secs(5), top.changed())
        .await
        .expect("first answer timed out")
        .expect("driver alive");
    let expect = |ids: &[(i64, &str)]| {
        ids.iter()
            .map(|(id, status)| TopOrder {
                id: *id,
                status: Some((*status).to_owned()),
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(top.rows(), expect(&[(3, "c"), (2, "b")]));
    assert!(top.as_of_secs().is_some(), "the answer carries its as-of");

    // A new row enters the window: the change stream triggers a re-read
    // against the fixture, whose data moved the same way, and the answer is
    // replaced whole.
    fixture.exec("INSERT INTO orders VALUES (100, 'z')").await;
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    apply(
        &mut source,
        &manager,
        "INSERT INTO orders VALUES (100, 'z')",
    )
    .await;
    tokio::time::timeout(Duration::from_secs(5), top.changed())
        .await
        .expect("re-read timed out")
        .expect("driver alive");
    assert_eq!(top.rows(), expect(&[(100, "z"), (3, "c")]));

    drop(top);
    drop(client);
    pump.await.expect("first pump ends");
    server.abort();

    // Restart offline against the same file: the last synced answer rests.
    let replica =
        Replica::encrypted_file(&db_path, Some(connetto_core::test_support::replica_key()))
            .expect("key provided");
    let config = ClientConfig::new("rows").with_login(Some(Grant::new("user:token#rows")));
    let conn = ConnettoConnection::<WebSocketTransport<TcpStream>>::open(
        &replica, SQLITE_DDL, &config, None,
    )
    .expect("reopen offline");
    assert!(!conn.is_connected(), "the restart reaches no server");
    let (client, pump) = ConnettoClient::with_pump(conn);
    let pump = tokio::spawn(pump);
    let top = client
        .watch_rows::<_, TopOrder>(top_two())
        .await
        .expect("watch rows offline");
    assert_eq!(
        top.rows(),
        expect(&[(100, "z"), (3, "c")]),
        "the last synced answer rests through the restart, read before any reconnect",
    );
    drop(top);
    drop(client);
    pump.await.expect("second pump ends");
}
