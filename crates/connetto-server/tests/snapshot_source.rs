//! Phase 4a acceptance test: encoding backend rows into a snapshot patchset.
//!
//! Docker-free: drives the pure `encode_json_rows` with canned JSON rows (the
//! shape `to_jsonb` produces on the backend) and asserts the encoded patchset
//! reproduces the rows on a SQLite replica. The live Postgres read path is
//! covered by the Docker-gated `PgSnapshotSource` test in `pg_async.rs`.

use connetto_server::{Materializer, encode_json_rows};
use diesel::prelude::*;
use diesel::sql_query;
use serde_json::json;
use sqlparser::dialect::PostgreSqlDialect;
use subql::ParserDB;

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";

diesel::table! {
    orders (id) {
        id -> diesel::sql_types::BigInt,
        price -> diesel::sql_types::Double,
        quantity -> diesel::sql_types::BigInt,
        status -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    price: f64,
    quantity: i64,
    status: String,
}

fn order(id: i64, price: f64, quantity: i64, status: &str) -> Order {
    Order {
        id,
        price,
        quantity,
        status: status.to_owned(),
    }
}

fn orders(conn: &mut SqliteConnection) -> Vec<Order> {
    orders::table
        .order(orders::id)
        .select(Order::as_select())
        .load(conn)
        .expect("read orders")
}

fn replica() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    conn
}

fn catalog() -> ParserDB {
    ParserDB::parse::<PostgreSqlDialect>(PG_DDL).expect("parse ddl")
}

#[test]
fn encode_json_rows_reproduces_backend_rows() {
    let db = catalog();
    let rows = vec![
        json!({"id": 7, "price": 9.5, "quantity": 1, "status": "paid"}),
        json!({"id": 8, "price": 4.0, "quantity": 2, "status": "new"}),
    ];
    let patchset = encode_json_rows(&db, "orders", &rows).expect("encode rows");

    let applier = Materializer::new(PG_DDL).expect("build applier");
    let mut replica = replica();
    let compressed = zstd::encode_all(patchset.as_slice(), 3).expect("compress");
    applier
        .apply_diffset(&compressed, &mut replica)
        .expect("apply snapshot patchset");
    assert_eq!(
        orders(&mut replica),
        vec![order(7, 9.5, 1, "paid"), order(8, 4.0, 2, "new")]
    );
}

#[test]
fn encode_json_rows_handles_empty_result() {
    let db = catalog();
    let patchset = encode_json_rows(&db, "orders", &[]).expect("encode empty");

    let applier = Materializer::new(PG_DDL).expect("build applier");
    let mut replica = replica();
    let compressed = zstd::encode_all(patchset.as_slice(), 3).expect("compress");
    applier
        .apply_diffset(&compressed, &mut replica)
        .expect("apply empty snapshot");
    assert!(orders(&mut replica).is_empty(), "no rows applied");
}

#[test]
fn encode_json_rows_rejects_unknown_table() {
    let db = catalog();
    let err = encode_json_rows(&db, "widgets", &[json!({"id": 1})]).unwrap_err();
    assert!(err.to_string().contains("unknown table"), "got {err}");
}
