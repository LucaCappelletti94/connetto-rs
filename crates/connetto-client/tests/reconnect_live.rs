//! Client reconnect end to end, against the real server machinery over
//! loopback transports: a live query survives a transport drop, resumes
//! from the applied cursor, and catches up from the server oplog WITHOUT a
//! second snapshot, and a local write captured while offline re-flushes
//! after the resume.
//!
//! The factory's offline gate makes the outage deterministic: reconnect
//! attempts fail while the flag is set, so everything driven in between is
//! strictly missed and must arrive through resume machinery.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, LiveQuery, ReconnectPolicy,
    Replica, TokioSleeper,
};
use connetto_core::{Cursor, test_support::TestSessionVerifier, traits::SessionVerifier};
use connetto_server::{
    LoopbackTransport, Materializer, PermissiveAuth, RuntimeWritableCatalog, SessionConfig,
    SessionManager, Snapshot, SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture};
use diesel::prelude::*;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use subql::{CdcSource, PgSqliteEmuSource};
use tokio::sync::Mutex;

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";

/// A snapshot source returning one seed row, so the initial subscribe has a
/// real (and countable) snapshot leg.
struct SeedSnapshot;

impl SnapshotSource for SeedSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::AuthContext,
    ) -> Result<Snapshot, Self::Error> {
        let table = SimpleTable::new("orders", &["id", "price", "quantity", "status"], &[0]);
        let insert = Insert::<_, String, Vec<u8>>::from(table)
            .set(0, Value::Integer(1))
            .expect("set id")
            .set(1, Value::Real(1.0))
            .expect("set price")
            .set(2, Value::Integer(3))
            .expect("set quantity")
            .set(3, Value::Text("seed".to_owned()))
            .expect("set status");
        let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new()
            .insert(insert)
            .build();
        Ok(Snapshot {
            patchset,
            cursor: Cursor::new(Vec::new()),
        })
    }
}

diesel::table! {
    orders (id) {
        id -> BigInt,
        price -> Nullable<Double>,
        quantity -> Nullable<BigInt>,
        status -> Nullable<Text>,
    }
}

// The server write target schema (Postgres): INT maps to Integer (i32),
// narrower than the replica's BigInt.
mod pg_readback {
    diesel::table! {
        orders (id) {
            id -> diesel::sql_types::Integer,
            price -> diesel::sql_types::Nullable<diesel::sql_types::Double>,
            quantity -> diesel::sql_types::Nullable<diesel::sql_types::Integer>,
            status -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
        }
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    price: Option<f64>,
    quantity: Option<i64>,
    status: Option<String>,
}

type Manager = SessionManager<SeedSnapshot, PermissiveAuth, ConnettoWatermark>;

/// One `orders` row as the Postgres target reports it (`INT` -> `i32`).
type PgOrderRow = (i32, Option<f64>, Option<i32>, Option<String>);

fn test_verifier() -> Arc<dyn SessionVerifier> {
    Arc::new(TestSessionVerifier)
}

/// Rows in the Postgres write target matching `id`, read as admin.
async fn target_rows(fixture: &Fixture, id: i64) -> Vec<Order> {
    let mut conn = fixture.admin().get().await.expect("admin connection");
    let query = pg_readback::orders::table
        .filter(pg_readback::orders::id.eq(i32::try_from(id).expect("id fits i32")))
        .select((
            pg_readback::orders::id,
            pg_readback::orders::price,
            pg_readback::orders::quantity,
            pg_readback::orders::status,
        ));
    let rows: Vec<PgOrderRow> = diesel_async::RunQueryDsl::load(query, &mut *conn)
        .await
        .expect("read target");
    rows.into_iter()
        .map(|(id, price, quantity, status)| Order {
            id: i64::from(id),
            price,
            quantity: quantity.map(i64::from),
            status,
        })
        .collect()
}

/// Execute `sql` against the emulated backend and route every resulting CDC
/// event through the manager, which appends it to the oplog and fans it out
/// to whatever sessions are alive.
async fn drive(source: &mut PgSqliteEmuSource, manager: &Manager, sql: &str) {
    source.execute_sql(sql).expect("execute dml");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }
}

/// The latest serve task, so a test can kill the live session.
type ServeSlot = Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>;

/// Open one server session and hand back the client transport, recording
/// the serve task in `slot`.
async fn open_session(manager: &Arc<Manager>, slot: &ServeSlot) -> LoopbackTransport {
    let (server_end, client_end) = loopback();
    let server = Arc::clone(manager);
    let handle = tokio::spawn(async move {
        let _ = server.serve(server_end).await;
    });
    *slot.lock().await = Some(handle);
    client_end
}

/// Kill the live server session: the client observes a clean close on its
/// loopback transport.
async fn kill_session(slot: &ServeSlot) {
    if let Some(handle) = slot.lock().await.take() {
        handle.abort();
        let _ = handle.await;
    }
}

/// A transport factory reconnecting to `manager`, failing fast while the
/// offline gate is set.
fn session_factory(
    manager: Arc<Manager>,
    slot: ServeSlot,
    offline: Arc<AtomicBool>,
) -> impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = Result<LoopbackTransport, String>> + Send>>
{
    move || {
        let manager = Arc::clone(&manager);
        let slot = Arc::clone(&slot);
        let offline = Arc::clone(&offline);
        Box::pin(async move {
            // Relaxed: a test toggle, no ordering dependency.
            if offline.load(Ordering::Relaxed) {
                return Err("offline".to_owned());
            }
            Ok(open_session(&manager, &slot).await)
        })
    }
}

/// A policy with test-sized backoff so the harness never waits long.
fn fast_policy() -> ReconnectPolicy {
    ReconnectPolicy {
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(20),
        max_attempts: None,
    }
}

/// Barrier: control frames are processed in order, so the pong proves the
/// server fully handled everything sent before the ping, the subscribe and
/// its route registration included. Without it a drive can outrun the
/// registration and its patch is never delivered to this session.
async fn fence(client: &ConnettoClient<LoopbackTransport>, nonce: u64) {
    let mut events = client.events();
    client.ping(nonce).await.expect("ping");
    loop {
        match events.recv().await.expect("events") {
            ClientEvent::Pong { nonce: n } if n == nonce => return,
            _ => {}
        }
    }
}

/// The client identity every test in this file presents, differing only by the
/// client id it labels its connection with.
fn config(client_id: &str) -> ClientConfig {
    ClientConfig {
        client_id: client_id.to_owned(),
        auth_token: "token".to_owned(),
        schema_version: None,
        sql_functions: connetto_client::SqlFunctions::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn live_query_resumes_from_cursor_without_a_second_snapshot() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        test_verifier(),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        SessionConfig::default(),
    );
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    let slot: ServeSlot = Arc::new(Mutex::new(None));
    let offline = Arc::new(AtomicBool::new(false));

    let transport = open_session(&manager, &slot).await;
    let config = config("reconnect-live");
    let conn =
        ConnettoConnection::connect(transport, &Replica::Ephemeral, SQLITE_DDL, &config, None)
            .await
            .expect("client connect");
    let (client, pump) = ConnettoClient::with_reconnect(
        conn,
        session_factory(
            Arc::clone(&manager),
            Arc::clone(&slot),
            Arc::clone(&offline),
        ),
        TokioSleeper,
        fast_policy(),
    );
    tokio::spawn(pump);
    let mut events = client.events();

    let mut live: LiveQuery<Order> = client
        .watch(orders::table.order(orders::id))
        .await
        .expect("live query");
    fence(&client, 1).await;

    // A row synced BEFORE the drop pins the client's resume cursor.
    drive(
        &mut source,
        &manager,
        "INSERT INTO orders (id, price, quantity, status) VALUES (10, 1.0, 5, 'before')",
    )
    .await;
    while !live.rows().iter().any(|row| row.id == 10) {
        live.changed().await.expect("live refresh");
    }

    // Deterministic outage: reconnect attempts fail while offline, so the
    // row driven now is strictly missed and only the oplog can deliver it.
    offline.store(true, Ordering::Relaxed);
    kill_session(&slot).await;
    drive(
        &mut source,
        &manager,
        "INSERT INTO orders (id, price, quantity, status) VALUES (20, 2.0, 7, 'during')",
    )
    .await;
    offline.store(false, Ordering::Relaxed);

    // The missed row arrives through resume plus catchup, into the SAME
    // handle, with no interaction on this side.
    while !live.rows().iter().any(|row| row.id == 20) {
        live.changed().await.expect("live refresh after resume");
    }

    // The event stream pins the mechanism: attempts were announced, the
    // session resumed exactly once, and the initial subscribe was the only
    // snapshot (catchup replays, it never re-snapshots).
    let mut reconnecting = 0;
    let mut reconnected = 0;
    let mut snapshots = 0;
    while let Ok(event) = events.try_recv() {
        match event {
            ClientEvent::Reconnecting { .. } => reconnecting += 1,
            ClientEvent::Reconnected => reconnected += 1,
            ClientEvent::SnapshotBegin { .. } => snapshots += 1,
            _ => {}
        }
    }
    assert!(reconnecting >= 1, "at least one announced attempt");
    assert_eq!(reconnected, 1, "exactly one successful resume");
    assert_eq!(snapshots, 1, "the initial subscribe is the only snapshot");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn offline_write_reflushes_after_resume() {
    let fixture = Fixture::acquire().await;

    // Create the server write target schema and provision the watermark so
    // the write target can record applied sequence numbers.
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS orders CASCADE",
            "DROP TABLE IF EXISTS _connetto_mutations",
            "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT)",
        ])
        .await;
    connetto_test_harness::provision_watermark(fixture.admin()).await;
    // Writes need an explicitly writable table: a default materializer
    // rejects every client mutation.
    let materializer = Materializer::with_write_catalog(
        PG_DDL,
        RuntimeWritableCatalog::builder().writable("orders").build(),
    )
    .expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        test_verifier(),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        SessionConfig::default(),
    );
    let slot: ServeSlot = Arc::new(Mutex::new(None));
    let offline = Arc::new(AtomicBool::new(false));

    let transport = open_session(&manager, &slot).await;
    let config = config("reconnect-write");
    let conn =
        ConnettoConnection::connect(transport, &Replica::Ephemeral, SQLITE_DDL, &config, None)
            .await
            .expect("client connect");
    let (client, pump) = ConnettoClient::with_reconnect(
        conn,
        session_factory(
            Arc::clone(&manager),
            Arc::clone(&slot),
            Arc::clone(&offline),
        ),
        TokioSleeper,
        fast_policy(),
    );
    tokio::spawn(pump);
    let mut events = client.events();

    // Cut the transport, then write locally: the capture session records
    // the change, the send fails, and nothing is lost.
    offline.store(true, Ordering::Relaxed);
    kill_session(&slot).await;
    client
        .with_conn(|conn| {
            diesel::insert_into(orders::table)
                .values((
                    orders::id.eq(30_i64),
                    orders::price.eq(3.0_f64),
                    orders::quantity.eq(9_i64),
                    orders::status.eq("offline"),
                ))
                .execute(conn.conn())
                .expect("offline insert")
        })
        .await;
    offline.store(false, Ordering::Relaxed);

    // After the resume the forced flush re-uploads the captured write, and
    // the server applies it to its Postgres write target.
    loop {
        if !target_rows(&fixture, 30).await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The upload was accepted, never rejected or conflicted.
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(
                event,
                ClientEvent::MutationRejected { .. } | ClientEvent::MutationConflict { .. }
            ),
            "the re-flushed write must apply cleanly, got {event:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn persisted_replica_resumes_across_restarts_without_a_snapshot() {
    let fixture = Fixture::acquire().await;
    let replica_file = tempfile::NamedTempFile::new().expect("replica file");
    let replica_path = replica_file
        .path()
        .to_str()
        .expect("utf8 temp path")
        .to_owned();

    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        PermissiveAuth,
        test_verifier(),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        SessionConfig::default(),
    );
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    let slot: ServeSlot = Arc::new(Mutex::new(None));

    // First run: a file-backed replica, one live query, one synced row. The
    // applied cursor lands in the replica's meta table transactionally.
    let transport = open_session(&manager, &slot).await;
    let first = config("restart-first");
    let conn = ConnettoConnection::connect(
        transport,
        &Replica::EncryptedFile {
            path: &replica_path,
            key: connetto_core::test_support::replica_key(),
        },
        SQLITE_DDL,
        &first,
        None,
    )
    .await
    .expect("first connect");
    let (client, pump) = ConnettoClient::with_pump(conn);
    let pump_handle = tokio::spawn(pump);
    let mut live: LiveQuery<Order> = client
        .watch(orders::table.order(orders::id))
        .await
        .expect("first live query");
    fence(&client, 1).await;
    drive(
        &mut source,
        &manager,
        "INSERT INTO orders (id, price, quantity, status) VALUES (40, 4.0, 4, 'first-run')",
    )
    .await;
    while !live.rows().iter().any(|row| row.id == 40) {
        live.changed().await.expect("first live refresh");
    }

    // Full shutdown, the process-restart stand-in: every handle drops and
    // the pump runs to completion, closing the replica file.
    drop(live);
    drop(client);
    pump_handle.await.expect("first pump ends");
    kill_session(&slot).await;

    // Missed while down.
    drive(
        &mut source,
        &manager,
        "INSERT INTO orders (id, price, quantity, status) VALUES (50, 5.0, 6, 'while-down')",
    )
    .await;

    // Second run: reopen the SAME replica with no explicit cursor. The
    // persisted cursor makes the new subscription catch up from the oplog,
    // never re-snapshot.
    let transport = open_session(&manager, &slot).await;
    let second = config("restart-second");
    let conn = ConnettoConnection::connect_existing(
        transport,
        &Replica::EncryptedFile {
            path: &replica_path,
            key: connetto_core::test_support::replica_key(),
        },
        &second,
        None,
    )
    .await
    .expect("second connect");
    let (client, pump) = ConnettoClient::with_pump(conn);
    tokio::spawn(pump);
    let mut audit = client.events();
    let mut live: LiveQuery<Order> = client
        .watch(orders::table.order(orders::id))
        .await
        .expect("second live query");

    // The first run's row answers instantly from the reopened file.
    assert!(
        live.rows().iter().any(|row| row.id == 40),
        "the persisted replica answers offline before any frame arrives"
    );
    while !live.rows().iter().any(|row| row.id == 50) {
        live.changed().await.expect("second live refresh");
    }

    // Catchup replayed the missed row: no snapshot leg ran at all.
    let mut snapshots = 0;
    while let Ok(event) = audit.try_recv() {
        if matches!(event, ClientEvent::SnapshotBegin { .. }) {
            snapshots += 1;
        }
    }
    assert_eq!(
        snapshots, 0,
        "a persisted cursor resumes without a snapshot"
    );
}
