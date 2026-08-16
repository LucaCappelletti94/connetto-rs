//! Exactly-once mutation uploads, end to end against the real session
//! machinery: a mutation that was sent but never processed replays after a
//! resume, a mutation that was applied but never acknowledged is retired by
//! the handshake watermark WITHOUT a second apply, and pending records
//! persisted in the replica replay across a full process restart.
//!
//! The deterministic stand-ins: a black hole completes the handshake and
//! swallows every frame (a connection that died with frames in flight), and
//! a man-in-the-middle forwards frames into a real session but drops the
//! acknowledgement (a connection that died just before the ack arrived).
//!
//! The server write target is the real Postgres path, so the exactly-once
//! landing is read back from Postgres. `#[ignore]` by default: needs Docker.

use std::sync::Arc;

use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Grant, Replica};
use connetto_core::messages::{ControlMessage, HandshakeAck};
use connetto_core::traits::{HandshakeAuthority, IncomingFrame, Transport};
use connetto_core::{Cursor, test_support::TestGrantChecker};
use connetto_server::{
    LoopbackTransport, Materializer, RequestGuard, RuntimeWritableCatalog, SessionConfig,
    SessionManager, Snapshot, SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};
use diesel::prelude::*;
use diesel::sql_query;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";

/// A snapshot source returning one seed row. No test here subscribes, but
/// the manager requires one.
struct SeedSnapshot;

impl SnapshotSource for SeedSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &connetto_core::Principal,
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

// The client replica schema (SQLite): local writes and the pending-record read.
diesel::table! {
    /// Orders table, primary key id.
    orders (id) {
        /// Order identifier, the primary key.
        id -> BigInt,
        /// Unit price per item, nullable while written.
        price -> Nullable<Double>,
        /// Number of items in the order, nullable while written.
        quantity -> Nullable<BigInt>,
        /// Order state as a string, nullable while written.
        status -> Nullable<Text>,
    }
}

// The server write target schema (Postgres): the exactly-once landing read-back.
// `INT` maps to `Integer` (`i32`), narrower than the replica's `BigInt`.
mod pg_readback {
    diesel::table! {
        /// Orders table, primary key id.
        orders (id) {
            /// Order identifier, the primary key.
            id -> diesel::sql_types::Integer,
            /// Unit price per item, nullable.
            price -> diesel::sql_types::Nullable<diesel::sql_types::Double>,
            /// Number of items in the order, nullable.
            quantity -> diesel::sql_types::Nullable<diesel::sql_types::Integer>,
            /// Order state as a string, nullable.
            status -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
        }
    }
}

/// One `orders` row as the Postgres target reports it (`INT` -> `i32`).
type PgOrderRow = (i32, Option<f64>, Option<i32>, Option<String>);

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    price: Option<f64>,
    quantity: Option<i64>,
    status: Option<String>,
}

type Manager = SessionManager<SeedSnapshot, RosterAuth, ConnettoWatermark>;

fn test_verifier() -> Arc<dyn HandshakeAuthority> {
    Arc::new(TestGrantChecker)
}

/// Reset the fixture to a fresh `orders` table with the watermark provisioned.
async fn reset_orders(fixture: &Fixture) {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS orders CASCADE",
            "DROP TABLE IF EXISTS _connetto_mutations",
            "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT)",
        ])
        .await;
    connetto_test_harness::provision_watermark(fixture.admin()).await;
}

/// A manager whose `orders` table accepts client writes into the real Postgres
/// target the test reads back through the admin pool.
fn writable_manager(fixture: &Fixture) -> Arc<Manager> {
    let materializer = Materializer::with_write_catalog(
        PG_DDL,
        RuntimeWritableCatalog::builder().writable("orders").build(),
    )
    .expect("build materializer");
    SessionManager::new(
        materializer,
        SeedSnapshot,
        RosterAuth::granting("token").withholding(WITHHELD_ID),
        test_verifier(),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    )
}

/// Open one real server session and hand back the client transport.
fn open_session(manager: &Arc<Manager>) -> LoopbackTransport {
    let (server_end, client_end) = loopback();
    let server = Arc::clone(manager);
    tokio::spawn(async move {
        let _ = server.serve(server_end).await;
    });
    client_end
}

/// Complete the wire handshake as a fake server, then swallow every frame:
/// the deterministic stand-in for a connection that died with mutation
/// frames in flight.
fn black_hole() -> LoopbackTransport {
    let (mut fake_server, client_end) = loopback();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) =
            fake_server.recv().await
        else {
            return;
        };
        let _ = fake_server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "black-hole".to_owned(),
                session_token: "black-hole".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                resume_token: "black-hole".to_owned(),
                schema_version: None,
                initial_credits: 64,
                last_applied_seq: None,
            }))
            .await;
        while let Ok(Some(_)) = fake_server.recv().await {}
    });
    client_end
}

/// Forward one frame from `from` to `to`, whatever its plane.
async fn forward(from: &mut LoopbackTransport, to: &mut LoopbackTransport) {
    match from.recv().await.expect("mitm recv").expect("mitm frame") {
        IncomingFrame::Control(message) => to.send_control(message).await.expect("mitm control"),
        IncomingFrame::Bulk(message) => to.send_bulk(message).await.expect("mitm bulk"),
    }
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

/// Rows still recorded in the replica's pending table.
fn pending_count<T>(conn: &mut ConnettoConnection<T>) -> i64
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    #[derive(diesel::QueryableByName)]
    struct CountRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        n: i64,
    }
    let rows: Vec<CountRow> = sql_query("SELECT COUNT(*) AS n FROM _connetto_pending")
        .load(conn.conn())
        .expect("count pending");
    rows.first().map_or(0, |row| row.n)
}

fn config(client_id: &str) -> ClientConfig {
    ClientConfig::new(client_id).with_login(Some(Grant::new("user:token")))
}

/// Insert one local order row through the connection.
fn insert_local<T>(conn: &mut ConnettoConnection<T>, id: i64)
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    diesel::insert_into(orders::table)
        .values((
            orders::id.eq(id),
            orders::price.eq(2.0_f64),
            orders::quantity.eq(4_i64),
            orders::status.eq("local"),
        ))
        .execute(conn.conn())
        .expect("local insert");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn sent_but_unprocessed_mutation_replays_after_resume() {
    let fixture = Fixture::acquire().await;
    reset_orders(&fixture).await;
    let manager = writable_manager(&fixture);

    // Push into the black hole: both frames leave successfully and nothing
    // ever processes them.
    let mut conn = ConnettoConnection::connect(
        black_hole(),
        &Replica::in_memory(),
        SQLITE_DDL,
        &config("replay"),
        None,
    )
    .await
    .expect("connect");
    insert_local(&mut conn, 60);
    let seq = conn.push().await.expect("push").expect("mutation sent");
    assert_eq!(pending_count(&mut conn), 1, "the pending record is durable");

    // Resume against the real server: the handshake carries no watermark for
    // this client, so the pending mutation replays and applies.
    conn.attach(open_session(&manager)).await.expect("resume");
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::MutationApplied { client_seq } => {
                assert_eq!(client_seq, seq);
                break;
            }
            ClientEvent::Closed => panic!("closed before the replay was acknowledged"),
            _ => {}
        }
    }
    assert_eq!(
        target_rows(&fixture, 60).await.len(),
        1,
        "the replay applied"
    );
    assert_eq!(pending_count(&mut conn), 0, "the ack retired the record");
    insert_local(&mut conn, WITHHELD_ID);
    let withheld_seq = conn
        .push()
        .await
        .expect("push")
        .expect("withheld mutation sent");
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::MutationRejected { client_seq, .. } => {
                assert_eq!(client_seq, withheld_seq, "withheld row write refused");
                break;
            }
            ClientEvent::Closed => panic!("closed before withheld rejection"),
            _ => {}
        }
    }
    assert_eq!(
        target_rows(&fixture, WITHHELD_ID).await.len(),
        0,
        "withheld row must not appear in Postgres"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn applied_but_unacked_mutation_dedupes_on_resume() {
    let fixture = Fixture::acquire().await;
    reset_orders(&fixture).await;
    let manager = writable_manager(&fixture);

    // A man in the middle forwards the handshake and the mutation into a
    // real session, reads the acknowledgement (the durable apply happened),
    // and dies without delivering it.
    let (mut mitm_end, client_end) = loopback();
    let mut real = open_session(&manager);
    let relay = tokio::spawn(async move {
        forward(&mut mitm_end, &mut real).await; // handshake
        forward(&mut real, &mut mitm_end).await; // ack
        forward(&mut mitm_end, &mut real).await; // mutation header
        forward(&mut mitm_end, &mut real).await; // mutation patchset
        let applied = real.recv().await.expect("mitm recv ack");
        assert!(
            matches!(
                applied,
                Some(IncomingFrame::Control(ControlMessage::MutationApplied(_)))
            ),
            "the real session acknowledged the apply, got {applied:?}"
        );
        // Dropping both ends here loses the acknowledgement forever.
    });

    let mut conn = ConnettoConnection::connect(
        client_end,
        &Replica::in_memory(),
        SQLITE_DDL,
        &config("dedupe"),
        None,
    )
    .await
    .expect("connect");
    insert_local(&mut conn, 61);
    conn.push().await.expect("push").expect("mutation sent");
    relay.await.expect("mitm relay");
    assert_eq!(pending_count(&mut conn), 1, "no ack arrived, record kept");

    // Resume with the SAME client id: the handshake watermark retires the
    // pending record without a replay, so the row applies exactly once.
    conn.attach(open_session(&manager)).await.expect("resume");
    assert_eq!(
        pending_count(&mut conn),
        0,
        "the watermark retired the record at handshake"
    );
    assert_eq!(
        target_rows(&fixture, 61).await.len(),
        1,
        "exactly one apply, the dedupe swallowed the would-be replay"
    );
    insert_local(&mut conn, WITHHELD_ID);
    let withheld_seq = conn
        .push()
        .await
        .expect("push")
        .expect("withheld mutation sent");
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::MutationRejected { client_seq, .. } => {
                assert_eq!(client_seq, withheld_seq, "withheld row write refused");
                break;
            }
            ClientEvent::Closed => panic!("closed before withheld rejection"),
            _ => {}
        }
    }
    assert_eq!(
        target_rows(&fixture, WITHHELD_ID).await.len(),
        0,
        "withheld row must not appear in Postgres"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn restart_replays_persisted_pending() {
    let fixture = Fixture::acquire().await;
    reset_orders(&fixture).await;
    let replica = tempfile::NamedTempFile::new().expect("replica file");
    let replica_path = replica.path().to_str().expect("utf8 path").to_owned();
    let manager = writable_manager(&fixture);

    // First process: push into the black hole, then die outright.
    {
        let mut conn = ConnettoConnection::connect(
            black_hole(),
            &Replica::encrypted_file(
                &replica_path,
                Some(connetto_core::test_support::replica_key()),
            )
            .expect("key provided"),
            SQLITE_DDL,
            &config("restart"),
            None,
        )
        .await
        .expect("first connect");
        insert_local(&mut conn, 62);
        conn.push().await.expect("push").expect("mutation sent");
    }

    // Second process: reopening the replica loads the persisted pending
    // record, and the connect-time reconcile replays it.
    let mut conn = ConnettoConnection::connect_existing(
        open_session(&manager),
        &Replica::encrypted_file(
            &replica_path,
            Some(connetto_core::test_support::replica_key()),
        )
        .expect("key provided"),
        &config("restart"),
        None,
    )
    .await
    .expect("second connect");
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::MutationApplied { client_seq } => {
                assert_eq!(client_seq, 0);
                break;
            }
            ClientEvent::Closed => panic!("closed before the replay was acknowledged"),
            _ => {}
        }
    }
    assert_eq!(
        target_rows(&fixture, 62).await.len(),
        1,
        "the restart replay applied"
    );
    assert_eq!(pending_count(&mut conn), 0, "the ack retired the record");
    insert_local(&mut conn, WITHHELD_ID);
    let withheld_seq = conn
        .push()
        .await
        .expect("push")
        .expect("withheld mutation sent");
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::MutationRejected { client_seq, .. } => {
                assert_eq!(client_seq, withheld_seq, "withheld row write refused");
                break;
            }
            ClientEvent::Closed => panic!("closed before withheld rejection"),
            _ => {}
        }
    }
    assert_eq!(
        target_rows(&fixture, WITHHELD_ID).await.len(),
        0,
        "withheld row must not appear in Postgres"
    );
}
