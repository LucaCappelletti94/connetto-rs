//! Docker-gated async Postgres apply test.
//!
//! Exercises the real-Postgres write path: `subql`'s diesel-async apply over a
//! bb8-pooled `AsyncPgConnection`, driven by [`Materializer::apply_diffset_async`].
//! `#[ignore]` by default because it needs a running Postgres. Point
//! `DATABASE_URL` at one and run with `--ignored` after explicit approval.
//!
// A Docker-gated test that stands up a database, drives DML and asserts several
// properties of one round trip is legitimately long, and splitting it would
// duplicate the fixture on a suite that already costs a container. Seven test
// files here take the same allow.
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{ControlMessage, Handshake, Subscribe, SubscriptionSpec};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{
    CHANGE_OP_TYPE, ChangeOp, ChangeOpSql, Materializer, Oplog, OplogConfig, PgOplog,
    PgSnapshotSource, RequestGuard, SessionConfig, SessionManager, Snapshot, SnapshotSource,
    loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, RosterAuth, WITHHELD_ID};
use diesel::prelude::{ExpressionMethods, QueryDsl, Queryable, Selectable, SelectableHelper};
use diesel::{Connection, SqliteConnection, sql_query};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sqlite_diff_rs::{ChangeSet, DiffOps, Insert, ParsedDiffSet, PatchsetOp, SimpleTable, Value};
use subql::reexec::PgAsyncDieselConnector;
use subql::{CdcSource, PgSqliteEmuSource};

diesel::table! {
    /// Row from the notes test fixture.
    notes (id) {
        /// Note identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Note text.
        body -> diesel::sql_types::Text,
        /// Timestamp of the last edit.
        edited_at -> diesel::sql_types::Text,
    }
}
diesel::table! {
    /// Row from the orders test fixture.
    orders (id) {
        /// Order identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Unit price.
        price -> diesel::sql_types::Double,
        /// Number of units.
        quantity -> diesel::sql_types::BigInt,
        /// Order status.
        status -> diesel::sql_types::Text,
    }
}
diesel::table! {
    /// Aggregate value row.
    aggs (id) {
        /// Aggregate identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Aggregate amount.
        amount -> diesel::sql_types::BigInt,
    }
}
diesel::table! {
    /// Row with a UUID key and bigint value.
    things (id) {
        /// Thing identifier, the primary key.
        id -> diesel::sql_types::Uuid,
        /// Integer value.
        n -> diesel::sql_types::BigInt,
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
            &[],
            &connetto_core::Principal::<String, String>::unidentified(
                connetto_core::SessionId::from_token_hash("test-user"),
            ),
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

const THINGS_PG_DDL: &str = "CREATE TABLE things (id UUID PRIMARY KEY, n BIGINT);";

/// The uuid identity guard at the connetto seam: a `uuid` primary key must
/// snapshot as the same 16-byte [`Value::Blob`] the CDC path emits, or a row
/// present in both a snapshot and a later CDC patch would carry two identities
/// and duplicate. Reads a real uuid row in Postgres binary through
/// [`PgSnapshotSource`] and asserts the produced insert carries the raw 16 uuid
/// bytes as a blob and the bigint as an integer.
#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn async_pg_snapshot_uuid_is_blob16() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let pool = Pool::builder().build(manager).await.expect("build pool");
    let id = uuid::Uuid::from_bytes([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ]);
    {
        let mut conn = pool.get().await.expect("get connection");
        sql_query("DROP TABLE IF EXISTS things")
            .execute(&mut *conn)
            .await
            .expect("drop table");
        sql_query(THINGS_PG_DDL)
            .execute(&mut *conn)
            .await
            .expect("create table");
        diesel::insert_into(things::table)
            .values((things::id.eq(id), things::n.eq(42_i64)))
            .execute(&mut *conn)
            .await
            .expect("seed row");
    }

    let source = PgSnapshotSource::from_ddl(pool, THINGS_PG_DDL).expect("build source");
    let snapshot = source
        .snapshot(
            "SELECT * FROM things",
            &[],
            &connetto_core::Principal::<String, String>::unidentified(
                connetto_core::SessionId::from_token_hash("test-user"),
            ),
        )
        .await
        .expect("produce snapshot");

    let ParsedDiffSet::Patchset(diff) =
        ParsedDiffSet::parse(snapshot.patchset.as_slice()).expect("parse patchset")
    else {
        panic!("snapshot is not a patchset");
    };
    let ops: Vec<_> = diff.iter().collect();
    assert_eq!(ops.len(), 1, "one inserted row");
    let PatchsetOp::Insert { table, values, .. } = &ops[0] else {
        panic!("expected an insert op, got {:?}", ops[0]);
    };
    assert_eq!(table.name(), "things");
    assert_eq!(
        values.to_vec(),
        vec![Value::Blob(id.as_bytes().to_vec()), Value::Integer(42),],
        "uuid lands as the raw 16-byte blob, bigint as an integer"
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
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::Principal,
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

    let connector = PgAsyncDieselConnector::new(pool.clone());
    let materializer = Materializer::new(AGGS_PG_DDL).expect("build materializer");
    let target =
        pg_write_target::<ConnettoWatermark>(pool, AGGS_PG_DDL).expect("build write target");
    let session = SessionManager::with_connector(
        materializer,
        NoSnapshot,
        // Aggregate results never go through the policy.
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        connector,
        target,
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(session.clone().serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "aggregator")
                .with_grant(connetto_core::messages::Grant::new("user:aggregator")),
        ))
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

/// One `op` cell read back from the oplog table, decoded as the enum rather
/// than as text.
#[derive(diesel::QueryableByName)]
struct OpRow {
    #[diesel(sql_type = ChangeOpSql)]
    op: ChangeOp,
}

/// The `pg_typeof` of a column, as text.
#[derive(diesel::QueryableByName)]
struct TypeNameRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
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
    let mut expected: Vec<(u64, String, bool, Vec<u8>)> = Vec::new();
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
                record.pk().to_vec(),
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
    let got: Vec<(u64, String, bool, Vec<u8>)> = entries
        .iter()
        .map(|record| {
            (
                record.lsn(),
                record.table().to_owned(),
                record.is_tombstone(),
                record.pk().to_vec(),
            )
        })
        .collect();
    assert_eq!(
        got, expected,
        "records round-trip through Postgres in LSN order, key included",
    );
    assert!(
        entries.iter().all(|record| !record.pk().is_empty()),
        "an empty key would round-trip unnoticed without this",
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

    // Nothing in the read path consults the verb column, so these three
    // assertions are the only thing standing between it and going back to
    // text. Each pins something the others do not: the values written, the
    // column's declared type, and the refusal.
    let mut conn = pool.get().await.expect("get connection");
    let ops: Vec<OpRow> = sql_query("SELECT op FROM connetto_oplog_test ORDER BY lsn")
        .load(&mut *conn)
        .await
        .expect("read the verbs back");
    assert_eq!(
        ops.iter().map(|row| row.op).collect::<Vec<_>>(),
        vec![ChangeOp::Insert, ChangeOp::Update, ChangeOp::Delete],
        "each record carries the verb of the change it retains",
    );
    // Postgres sends an enum label as its text, so decoding alone would pass
    // against a text column. Only the declared type separates the two.
    let declared: Vec<TypeNameRow> =
        sql_query("SELECT pg_typeof(op)::text AS name FROM connetto_oplog_test LIMIT 1")
            .load(&mut *conn)
            .await
            .expect("read the column type");
    assert_eq!(
        declared.as_slice().first().map(|row| row.name.as_str()),
        Some(CHANGE_OP_TYPE),
        "the verb column is the enum type rather than text",
    );
    // No cast, so the column's own type is what rejects this.
    let refused = sql_query(
        "INSERT INTO connetto_oplog_test \
         (lsn, table_name, op, pk, is_tombstone, event) \
         VALUES (9999, 'orders', 'nonsense', '\\x00', false, '\\x00')",
    )
    .execute(&mut *conn)
    .await;
    assert!(
        refused.is_err(),
        "a verb outside the set is refused, which is what the enum buys over text",
    );

    sql_query("DROP TABLE IF EXISTS connetto_oplog_test")
        .execute(&mut *conn)
        .await
        .expect("drop oplog table");
}

/// A two-column key survives the oplog, and two rows differing only in the
/// second column stay distinct.
///
/// The key is one `BYTEA` holding an encoding of every key value, which is
/// reasonable because connetto is the only reader, but a composite key is where
/// a single opaque blob has to carry the most. Every other oplog test uses a
/// single-column key, and until this one the stored key was written, read back,
/// and never compared to anything.
#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn pg_oplog_round_trips_a_composite_key() {
    const PAIRS_DDL: &str = "CREATE TABLE pairs (tenant TEXT NOT NULL, id INT NOT NULL, note TEXT, \
         PRIMARY KEY (tenant, id));";

    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let pool = Pool::builder().build(manager).await.expect("build pool");
    {
        let mut conn = pool.get().await.expect("get connection");
        sql_query("DROP TABLE IF EXISTS connetto_oplog_composite")
            .execute(&mut *conn)
            .await
            .expect("drop oplog table");
    }
    let oplog = PgOplog::new(
        pool.clone(),
        "connetto_oplog_composite",
        OplogConfig::default(),
    );
    oplog.ensure_schema().await.expect("ensure schema");

    let mat = Materializer::new(PAIRS_DDL).expect("build materializer");
    let mut source = PgSqliteEmuSource::open_in_memory(PAIRS_DDL).expect("open emu source");
    let mut appended: Vec<Vec<u8>> = Vec::new();
    for sql in [
        "INSERT INTO pairs (tenant, id, note) VALUES ('acme', 1, 'first')",
        // Same second column, different first: the encoding must not collapse
        // them, which a key carrying only one column would.
        "INSERT INTO pairs (tenant, id, note) VALUES ('other', 1, 'second')",
        // Same first column, different second.
        "INSERT INTO pairs (tenant, id, note) VALUES ('acme', 2, 'third')",
    ] {
        source.execute_sql(sql).expect("execute dml");
        while let Some(event) = source.next_event().await.expect("poll source") {
            let record = mat.oplog_record(&event).expect("build oplog record");
            appended.push(record.pk().to_vec());
            oplog.append(record).await.expect("append record");
        }
    }
    assert_eq!(appended.len(), 3, "one record per insert");

    let entries = oplog.entries_since(0).await.expect("read entries");
    let read_back: Vec<Vec<u8>> = entries.iter().map(|r| r.pk().to_vec()).collect();
    assert_eq!(
        read_back, appended,
        "a two-column key round-trips through Postgres unchanged"
    );

    let distinct: std::collections::HashSet<&Vec<u8>> = read_back.iter().collect();
    assert_eq!(
        distinct.len(),
        3,
        "three different key pairs must encode to three different keys, got {read_back:?}"
    );

    let mut conn = pool.get().await.expect("get connection");
    sql_query("DROP TABLE IF EXISTS connetto_oplog_composite")
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

    let connector = PgAsyncDieselConnector::new(pool.clone());
    let materializer =
        Materializer::new("CREATE TABLE agg_family (id INT PRIMARY KEY, amount BIGINT);")
            .expect("build materializer");
    let target = pg_write_target::<ConnettoWatermark>(
        pool,
        "CREATE TABLE agg_family (id INT PRIMARY KEY, amount BIGINT);",
    )
    .expect("build write target");
    let session = SessionManager::with_connector(
        materializer,
        NoSnapshot,
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        connector,
        target,
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(session.clone().serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "aggregator")
                .with_grant(connetto_core::messages::Grant::new("user:aggregator")),
        ))
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

const TRANSLATED_PG_DDL: &str = "CREATE TABLE translated (id INT PRIMARY KEY, quantity INT);";
const TRANSLATED_SQLITE_DDL: &str =
    "CREATE TABLE translated (id INTEGER PRIMARY KEY, quantity INTEGER);";

diesel::table! {
    /// Row from the translated query fixture.
    translated (id) {
        /// Row identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Quantity value.
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq)]
#[diesel(table_name = translated)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct TranslatedRow {
    id: i64,
    quantity: i64,
}

/// The coverage cell the desktop e2e caught missing: the exact wire shape a
/// typed live query produces (backticked SQLite rendering with a `?` bind),
/// registered through the materializer and snapshotted through the real
/// [`PgSnapshotSource`] with the bind attached. The registration's
/// translation is the snapshot's input, never the client dialect.
#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn snapshot_runs_the_translated_diesel_shape_with_binds() {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    let pool = Pool::builder().build(manager).await.expect("build pool");
    {
        let mut conn = pool.get().await.expect("get connection");
        sql_query("DROP TABLE IF EXISTS translated")
            .execute(&mut *conn)
            .await
            .expect("drop table");
        sql_query(TRANSLATED_PG_DDL)
            .execute(&mut *conn)
            .await
            .expect("create table");
        sql_query("INSERT INTO translated VALUES (1, 5), (2, 0), (3, 9)")
            .execute(&mut *conn)
            .await
            .expect("seed rows");
    }

    // Register the diesel-rendered SQLite shape with a typed bind and keep
    // the translation the registration used.
    let mut materializer = Materializer::new(TRANSLATED_PG_DDL).expect("build materializer");
    let binds = vec![connetto_core::messages::BindValue::Integer(0)];
    let reg = materializer
        .register_sqlite(
            1,
            "SELECT `translated`.`id`, `translated`.`quantity` FROM `translated` \
             WHERE (`translated`.`quantity` > ?) ORDER BY `translated`.`id`",
            &binds,
        )
        .expect("register the diesel shape");
    assert!(
        reg.pg_sql.contains("$1"),
        "the translation is parameterized, got {}",
        reg.pg_sql
    );

    // Snapshot with the translated SQL plus the same binds, on real Postgres.
    let source = PgSnapshotSource::from_ddl(pool, TRANSLATED_PG_DDL).expect("build source");
    let snapshot = source
        .snapshot(
            &reg.pg_sql,
            &binds,
            &connetto_core::Principal::<String, String>::unidentified(
                connetto_core::SessionId::from_token_hash("test-user"),
            ),
        )
        .await
        .expect("snapshot the translated query");

    // The snapshot applies onto a SQLite replica and carries only the rows
    // the bound predicate admits.
    let mut replica = SqliteConnection::establish(":memory:").expect("open sqlite");
    diesel::RunQueryDsl::execute(sql_query(TRANSLATED_SQLITE_DDL), &mut replica)
        .expect("create replica");
    let applier = Materializer::new(TRANSLATED_PG_DDL).expect("build applier");
    let compressed = zstd::encode_all(snapshot.patchset.as_slice(), 3).expect("compress");
    applier
        .apply_diffset(&compressed, &mut replica)
        .expect("apply snapshot");
    let rows: Vec<TranslatedRow> = diesel::RunQueryDsl::load(
        translated::table
            .order(translated::id)
            .select(TranslatedRow::as_select()),
        &mut replica,
    )
    .expect("read replica");
    assert_eq!(
        rows,
        vec![
            TranslatedRow { id: 1, quantity: 5 },
            TranslatedRow { id: 3, quantity: 9 },
        ],
        "the bound predicate filtered on the backend"
    );
}
