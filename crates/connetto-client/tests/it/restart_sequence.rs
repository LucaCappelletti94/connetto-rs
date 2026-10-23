//! Writes retain their writer sequence across replica restarts.

use core::time::Duration;
use std::sync::Arc;

use connetto_client::{
    ClientBuilder, ClientEvent, ConnettoClient, ConnettoConnection, DataDir, Grant, HeldCredential,
    MemoryRefreshStore,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_server::{
    ManagerBuilder, Materializer, PgReadConnector, PgSnapshotSource, RuntimeWritableCatalog,
    SessionManager, WebSocketTransport, pg_write_target,
};
use connetto_test_harness::{ConnettoDefaults, Fixture, RosterAuth};
use diesel::prelude::*;
use tokio::net::{TcpListener, TcpStream};

const PG_DDL: &str = "-- connetto:major 1\nCREATE TABLE orders (id INT PRIMARY KEY, status TEXT);";
// `IF NOT EXISTS` because `connect` replays the caller's DDL on every open.
const SQLITE_DDL: &str = "CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY, status TEXT);";

diesel::table! {
    orders (id) {
        id -> BigInt,
        status -> Nullable<Text>,
    }
}

/// The same table as the server's target holds it.
mod pg {
    diesel::table! {
        orders (id) {
            id -> Integer,
            status -> Nullable<Text>,
        }
    }
}

type Manager = SessionManager<PgSnapshotSource, RosterAuth, ConnettoDefaults, PgReadConnector>;

fn manager(fixture: &Fixture) -> Arc<Manager> {
    let pool = fixture.admin().clone();
    ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .with_write_catalog(RuntimeWritableCatalog::builder().writable("orders").build())
            .with_read_connector(PgReadConnector::with_session_setup(pool.clone()))
            .build()
            .expect("build materializer"),
        PgSnapshotSource::from_ddl(pool.clone(), PG_DDL).expect("snapshot source"),
        RosterAuth::granting("token"),
        Arc::new(TestGrantChecker),
        PgReadConnector::with_session_setup(pool.clone()),
        pg_write_target::<ConnettoDefaults>(pool, PG_DDL).expect("build write target"),
    )
    .build()
}

/// Serve one session on a fresh localhost listener.
async fn spawn_server(manager: Arc<Manager>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let transport = WebSocketTransport::accept(stream).await.expect("ws accept");
        let _ = manager.serve(transport).await;
    });
    addr
}

/// The login credential reused across restarts.
fn credential() -> HeldCredential {
    super::support::held_grant(Grant::new("user:token#restart"), "token")
}

/// Connect the durable replica in `dir` to the server at `addr`.
async fn connect(
    addr: std::net::SocketAddr,
    dir: &std::path::Path,
) -> ConnettoConnection<WebSocketTransport<TcpStream>> {
    let stream = TcpStream::connect(addr).await.expect("connect");
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .expect("ws connect");
    let held = credential();
    let store = super::support::key_store(&held).await;
    ClientBuilder::new(
        super::support::bundle(SQLITE_DDL),
        super::support::Once::new(transport),
    )
    .signed_in(held)
    .durable(
        DataDir::new(dir.to_path_buf()),
        store,
        MemoryRefreshStore::default(),
    )
    .connect_driven()
    .await
    .expect("client connect")
}

/// Open the durable replica in `dir` with no server reachable.
async fn open_offline(dir: &std::path::Path) -> ConnettoConnection<WebSocketTransport<TcpStream>> {
    let held = credential();
    let store = super::support::key_store(&held).await;
    ClientBuilder::new(
        super::support::bundle(SQLITE_DDL),
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

/// The ids Postgres holds, read as admin.
async fn server_ids(fixture: &Fixture) -> Vec<i32> {
    let mut conn = fixture.admin().get().await.expect("admin connection");
    diesel_async::RunQueryDsl::load(
        pg::orders::table
            .select(pg::orders::id)
            .order(pg::orders::id),
        &mut *conn,
    )
    .await
    .expect("read the server target")
}

/// Wait until Postgres holds `wanted`, bounded so a lost write fails.
async fn wait_for_ids(fixture: &Fixture, wanted: &[i32]) {
    let until = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let ids = server_ids(fixture).await;
        if ids == wanted {
            return;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "Postgres holds {ids:?}, the writes made {wanted:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Run until the server applies `seq`, bounded.
async fn applied(conn: ConnettoConnection<WebSocketTransport<TcpStream>>, seq: u64) {
    let (client, pump) = ConnettoClient::with_pump(conn);
    let mut events = client.events();
    let pump = tokio::spawn(pump);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(ClientEvent::MutationApplied { client_seq }) = events.recv().await
                && client_seq == seq
            {
                break;
            }
        }
    })
    .await
    .expect("the server applies the write");
    drop(client);
    pump.await.expect("the pump ends with its client");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_after_a_restart_reaches_the_server() {
    let fixture = Fixture::acquire().await;
    fixture.exec("DROP TABLE IF EXISTS orders CASCADE").await;
    fixture
        .exec("CREATE TABLE orders (id INT PRIMARY KEY, status TEXT)")
        .await;
    let manager = manager(&fixture);
    let dir = tempfile::tempdir().expect("temp dir");

    // The first run writes and the server applies it.
    let mut first = connect(spawn_server(Arc::clone(&manager)).await, dir.path()).await;
    diesel::insert_into(orders::table)
        .values((orders::id.eq(1), orders::status.eq("first run")))
        .execute(first.conn())
        .expect("write in the first run");
    let seq = first.push().await.expect("send").expect("a seq");
    applied(first, seq).await;
    wait_for_ids(&fixture, &[1]).await;

    // The app restarts with no server reachable and writes again.
    {
        let mut offline = open_offline(dir.path()).await;
        diesel::insert_into(orders::table)
            .values((orders::id.eq(2), orders::status.eq("after the restart")))
            .execute(offline.conn())
            .expect("write after the restart");
        offline.push().await.expect("queue").expect("a seq");
    }

    // The next connection delivers it.
    let reconnected = connect(spawn_server(Arc::clone(&manager)).await, dir.path()).await;
    let (client, pump) = ConnettoClient::with_pump(reconnected);
    let pump = tokio::spawn(pump);
    wait_for_ids(&fixture, &[1, 2]).await;
    drop(client);
    pump.await.expect("the pump ends with its client");
}
