//! Docker-gated async Postgres apply test.
//!
//! Exercises the real-Postgres write path: `subql`'s diesel-async apply over a
//! bb8-pooled `AsyncPgConnection`, driven by [`Materializer::apply_diffset_async`].
//! `#[ignore]` by default because it needs a running Postgres. Point
//! `DATABASE_URL` at one and run with `--ignored` after explicit approval.
//!
//! The whole file compiles only under the `pg-async` feature.

#![cfg(feature = "pg-async")]

use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{ControlMessage, Handshake, Subscribe, SubscriptionSpec};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{
    Materializer, Oplog, OplogConfig, PermissiveAuth, PgOplog, PgSnapshotSource, SessionConfig,
    SessionManager, Snapshot, SnapshotSource, loopback, sqlite_write_target,
};
use diesel::prelude::{ExpressionMethods, QueryDsl, Queryable, Selectable, SelectableHelper};
use diesel::{Connection, SqliteConnection, sql_query};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sqlite_diff_rs::{ChangeSet, DiffOps, Insert, SimpleTable, Value};
use subql::reexec::PgAsyncDieselConnector;
use subql::{CdcSource, PgSqliteEmuSource};

diesel::table! {
    notes (id) {
        id -> diesel::sql_types::BigInt,
        body -> diesel::sql_types::Text,
        edited_at -> diesel::sql_types::Text,
    }
}
diesel::table! {
    orders (id) {
        id -> diesel::sql_types::BigInt,
        price -> diesel::sql_types::Double,
        quantity -> diesel::sql_types::BigInt,
        status -> diesel::sql_types::Text,
    }
}
diesel::table! {
    aggs (id) {
        id -> diesel::sql_types::BigInt,
        amount -> diesel::sql_types::BigInt,
    }
}

const PG_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT, edited_at TEXT);";

fn insert_changeset(id: i64, body: &str, edited_at: &str) -> Vec<u8> {
    let table = SimpleTable::new("notes", &["id", "body", "edited_at"], &[0]);
    let insert = Insert::<_, String, Vec<u8>>::from(table)
        .set(0, Value::Integer(id))
        .expect("set id")
        .set(1, Value::Text(body.to_owned()))
        .expect("set body")
        .set(2, Value::Text(edited_at.to_owned()))
        .expect("set edited_at");
    ChangeSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(insert)
        .build()
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn async_pg_apply_inserts_row() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let pool = Pool::builder().build(manager).await.expect("build pool");
    let mut conn = pool.get().await.expect("get connection");

    sql_query("DROP TABLE IF EXISTS notes")
        .execute(&mut *conn)
        .await
        .expect("drop table");
    sql_query(PG_DDL)
        .execute(&mut *conn)
        .await
        .expect("create table");

    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let payload =
        zstd::encode_all(insert_changeset(1, "async", "t0").as_slice(), 3).expect("compress");
    let affected = materializer
        .apply_diffset_async(&payload, &mut conn)
        .await
        .expect("async apply");
    assert_eq!(affected, 1, "one row applied through the async path");

    let count: i64 = notes::table
        .filter(notes::id.eq(1_i64))
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count rows");
    assert_eq!(count, 1);
}

const ORDERS_PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const ORDERS_SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";

#[derive(Queryable, Selectable, Debug, PartialEq)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    price: f64,
    quantity: i64,
    status: String,
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn async_pg_snapshot_reads_rows() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let pool = Pool::builder().build(manager).await.expect("build pool");
    {
        let mut conn = pool.get().await.expect("get connection");
        sql_query("DROP TABLE IF EXISTS orders")
            .execute(&mut *conn)
            .await
            .expect("drop table");
        sql_query(ORDERS_PG_DDL)
            .execute(&mut *conn)
            .await
            .expect("create table");
        diesel::insert_into(orders::table)
            .values(vec![
                (
                    orders::id.eq(7_i64),
                    orders::price.eq(9.5_f64),
                    orders::quantity.eq(1_i64),
                    orders::status.eq("paid"),
                ),
                (
                    orders::id.eq(8_i64),
                    orders::price.eq(4.0_f64),
                    orders::quantity.eq(2_i64),
                    orders::status.eq("new"),
                ),
                (
                    orders::id.eq(9_i64),
                    orders::price.eq(1.0_f64),
                    orders::quantity.eq(0_i64),
                    orders::status.eq("void"),
                ),
            ])
            .execute(&mut *conn)
            .await
            .expect("seed rows");
    }

    let source = PgSnapshotSource::from_ddl(pool, ORDERS_PG_DDL).expect("build source");
    let snapshot = source
        .snapshot(
            "SELECT * FROM orders WHERE quantity > 0",
            &connetto_core::AuthContext::new("test-user"),
        )
        .await
        .expect("produce snapshot");
    assert!(
        !snapshot.cursor.as_bytes().is_empty(),
        "a real read carries an LSN cursor"
    );

    // The snapshot reproduces the matching rows on a SQLite replica.
    let mut replica = SqliteConnection::establish(":memory:").expect("open sqlite");
    diesel::RunQueryDsl::execute(sql_query(ORDERS_SQLITE_DDL), &mut replica)
        .expect("create replica");
    let applier = Materializer::new(ORDERS_PG_DDL).expect("build applier");
    let compressed = zstd::encode_all(snapshot.patchset.as_slice(), 3).expect("compress");
    applier
        .apply_diffset(&compressed, &mut replica)
        .expect("apply snapshot");
    let rows: Vec<Order> = diesel::RunQueryDsl::load(
        orders::table.order(orders::id).select(Order::as_select()),
        &mut replica,
    )
    .expect("read replica");
    assert_eq!(
        rows,
        vec![
            Order {
                id: 7,
                price: 9.5,
                quantity: 1,
                status: "paid".to_owned()
            },
            Order {
                id: 8,
                price: 4.0,
                quantity: 2,
                status: "new".to_owned()
            },
        ],
        "only quantity > 0 rows, void row excluded by the SELECT"
    );
}

const AGGS_PG_DDL: &str = "CREATE TABLE aggs (id INT PRIMARY KEY, amount BIGINT);";

/// Aggregate subscriptions never snapshot.
struct NoSnapshot;

impl SnapshotSource for NoSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _auth: &connetto_core::AuthContext,
    ) -> Result<Snapshot, Self::Error> {
        Ok(Snapshot {
            patchset: Vec::new(),
            cursor: connetto_core::Cursor::new(Vec::new()),
        })
    }
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn async_pg_reexec_bootstraps_min() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let pool = Pool::builder().build(manager).await.expect("build pool");
    {
        let mut conn = pool.get().await.expect("get connection");
        sql_query("DROP TABLE IF EXISTS aggs")
            .execute(&mut *conn)
            .await
            .expect("drop table");
        sql_query(AGGS_PG_DDL)
            .execute(&mut *conn)
            .await
            .expect("create table");
        diesel::insert_into(aggs::table)
            .values(vec![
                (aggs::id.eq(1_i64), aggs::amount.eq(5_i64)),
                (aggs::id.eq(2_i64), aggs::amount.eq(10_i64)),
            ])
            .execute(&mut *conn)
            .await
            .expect("seed rows");
    }

    let connector = PgAsyncDieselConnector::new(pool);
    let materializer = Materializer::new(AGGS_PG_DDL).expect("build materializer");
    let target = sqlite_write_target(SqliteConnection::establish(":memory:").expect("open sqlite"));
    let session = SessionManager::with_connector(
        materializer,
        NoSnapshot,
        PermissiveAuth,
        connector,
        target,
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(session.clone().serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "aggregator",
            "token",
        )))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "cheapest".to_owned(),
            spec: SubscriptionSpec::new("SELECT MIN(amount) FROM aggs"),
        }))
        .await
        .expect("send subscribe");
    let update = match next_control(&mut client).await {
        ControlMessage::AggregateUpdate(update) => update,
        other => panic!("expected aggregate update, got {other:?}"),
    };
    assert_eq!(update.sub_id, "cheapest");
    assert_eq!(
        update.result_json, "5",
        "bootstrap reflects the real MIN in PG"
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn pg_oplog_appends_and_reads_back() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let pool = Pool::builder().build(manager).await.expect("build pool");

    {
        let mut conn = pool.get().await.expect("get connection");
        sql_query("DROP TABLE IF EXISTS connetto_oplog_test")
            .execute(&mut *conn)
            .await
            .expect("drop oplog table");
    }
    let oplog = PgOplog::new(pool.clone(), "connetto_oplog_test", OplogConfig::default());
    oplog.ensure_schema().await.expect("ensure schema");

    // Turn insert, update, and delete events from the emulator into oplog
    // records and append each. The emulator now stamps monotonic LSNs, so no
    // test-side stamping is needed.
    let mat = Materializer::new(ORDERS_PG_DDL).expect("build materializer");
    let mut source = PgSqliteEmuSource::open_in_memory(ORDERS_PG_DDL).expect("open emu source");
    let mut expected: Vec<(u64, String, bool)> = Vec::new();
    for sql in [
        "INSERT INTO orders (id, price, quantity, status) VALUES (1, 9.5, 3, 'paid')",
        "UPDATE orders SET quantity = 7 WHERE id = 1",
        "DELETE FROM orders WHERE id = 1",
    ] {
        source.execute_sql(sql).expect("execute dml");
        while let Some(event) = source.next_event().await.expect("poll source") {
            let record = mat.oplog_record(&event).expect("build oplog record");
            expected.push((
                record.lsn(),
                record.table().to_owned(),
                record.is_tombstone(),
            ));
            oplog.append(record).await.expect("append record");
        }
    }
    assert_eq!(expected.len(), 3, "one record per statement");
    let first_lsn = expected[0].0;
    let last_lsn = expected[expected.len() - 1].0;

    assert_eq!(oplog.min_lsn().await.expect("min lsn"), Some(first_lsn));
    assert_eq!(
        oplog.current_lsn().await.expect("current lsn"),
        Some(last_lsn)
    );

    let entries = oplog.entries_since(0).await.expect("read entries");
    let got: Vec<(u64, String, bool)> = entries
        .iter()
        .map(|record| {
            (
                record.lsn(),
                record.table().to_owned(),
                record.is_tombstone(),
            )
        })
        .collect();
    assert_eq!(
        got, expected,
        "records round-trip through Postgres in LSN order",
    );
    assert!(
        entries.last().expect("has entries").is_tombstone(),
        "the delete round-trips as a tombstone",
    );

    // A mid-stream read returns only the entries after the given LSN.
    let tail = oplog.entries_since(first_lsn).await.expect("read tail");
    assert_eq!(
        tail.len(),
        2,
        "entries_since is strictly greater than the lsn"
    );

    let mut conn = pool.get().await.expect("get connection");
    sql_query("DROP TABLE IF EXISTS connetto_oplog_test")
        .execute(&mut *conn)
        .await
        .expect("drop oplog table");
}

/// Subscribe to an aggregate and return the bootstrap value the server seeds
/// through the connector, asserting it is a full result for `sub_id`.
async fn bootstrap_agg<T: Transport>(client: &mut T, sub_id: &str, query: &str) -> String {
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: sub_id.to_owned(),
            spec: SubscriptionSpec::new(query),
        }))
        .await
        .expect("send subscribe");
    match next_control(client).await {
        ControlMessage::AggregateUpdate(update) => {
            assert_eq!(update.sub_id, sub_id);
            assert!(update.is_full_result);
            update.result_json
        }
        other => panic!("expected aggregate update, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn async_pg_delta_aggregate_bootstraps_family() {
    // The delta aggregate family seeds through the real connector's
    // multi-column `execute_scalar_row`, which the SQLite-emulator tests cannot
    // exercise. It pins the Postgres decode: `SUM` over a `BIGINT` column comes
    // back as `NUMERIC` and must decode to a double, and the two- and
    // three-column seeds (`AVG`, `VAR_POP`) must line up with the accumulator.
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let pool = Pool::builder().build(manager).await.expect("build pool");
    {
        // A dedicated table so this test never races the shared `aggs` DDL of
        // `async_pg_reexec_bootstraps_min` under the concurrent test harness.
        let mut conn = pool.get().await.expect("get connection");
        sql_query("DROP TABLE IF EXISTS agg_family")
            .execute(&mut *conn)
            .await
            .expect("drop table");
        sql_query("CREATE TABLE agg_family (id INT PRIMARY KEY, amount BIGINT)")
            .execute(&mut *conn)
            .await
            .expect("create table");
        sql_query("INSERT INTO agg_family (id, amount) VALUES (1, 10), (2, 20), (3, 30)")
            .execute(&mut *conn)
            .await
            .expect("seed rows");
    }

    let connector = PgAsyncDieselConnector::new(pool);
    let materializer =
        Materializer::new("CREATE TABLE agg_family (id INT PRIMARY KEY, amount BIGINT);")
            .expect("build materializer");
    let target = sqlite_write_target(SqliteConnection::establish(":memory:").expect("open sqlite"));
    let session = SessionManager::with_connector(
        materializer,
        NoSnapshot,
        PermissiveAuth,
        connector,
        target,
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(session.clone().serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "aggregator",
            "token",
        )))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    // COUNT(*) is an exact integer.
    assert_eq!(
        bootstrap_agg(&mut client, "count", "SELECT COUNT(*) FROM agg_family").await,
        "3",
    );
    // SUM(amount) over BIGINT arrives from PG as NUMERIC and decodes to a double.
    assert_eq!(
        bootstrap_agg(&mut client, "sum", "SELECT SUM(amount) FROM agg_family").await,
        "60.0",
    );
    // AVG exercises the two-column (SUM, COUNT) seed.
    assert_eq!(
        bootstrap_agg(&mut client, "avg", "SELECT AVG(amount) FROM agg_family").await,
        "20.0",
    );
    // VAR_POP exercises the three-column (SUM, SUM(x*x), COUNT) seed. Assert with
    // a tolerance since the value is not exactly representable.
    let var_json =
        bootstrap_agg(&mut client, "var", "SELECT VAR_POP(amount) FROM agg_family").await;
    let var: f64 = var_json.parse().expect("parse var_pop");
    assert!(
        (var - 200.0_f64 / 3.0).abs() < 1e-9,
        "VAR_POP over [10, 20, 30] should be 200/3, got {var_json}",
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}
