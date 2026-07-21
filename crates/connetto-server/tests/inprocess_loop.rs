//! In-process end-to-end smoke test for the Phase 1 materializer spine.
//!
//! Drives INSERT, UPDATE, and DELETE against a Docker-free `PgSqliteEmuSource`
//! (a fake Postgres over SQLite), routes each CDC event through the
//! [`Materializer`] to a `LivePatch`, applies each patch to a client replica,
//! and asserts row parity after every step. Then applies a client-authored
//! `MutationPatch` to a separate backend target through the inbound path.

use connetto_core::messages::MutationPatch;
use connetto_server::Materializer;
use diesel::prelude::*;
use diesel::sql_query;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use subql::{CdcSource, PgSqliteEmuSource};

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

fn sqlite_target() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    conn
}

/// Drain every event the source has queued and fan each matched patch out to
/// the replica through the materializer.
async fn drain_to_replica(
    source: &mut PgSqliteEmuSource,
    mat: &mut Materializer,
    replica: &mut SqliteConnection,
) {
    while let Some(event) = source.next_event().await.expect("poll source") {
        for patch in mat.dispatch(&event).expect("dispatch event").patches {
            mat.apply_diffset(&patch.payload_zstd, replica)
                .expect("apply matched patch to replica");
        }
    }
}

/// Hand-build the SQLite session patchset bytes a client would upload for a
/// full-row insert, compressed as the bulk wire expects.
fn mutation_insert(
    client_seq: u64,
    id: i64,
    price: f64,
    quantity: i64,
    status: &str,
) -> MutationPatch {
    let table = SimpleTable::new("orders", &["id", "price", "quantity", "status"], &[0]);
    let insert = Insert::<_, String, Vec<u8>>::from(table)
        .set(0, Value::Integer(id))
        .expect("set id")
        .set(1, Value::Real(price))
        .expect("set price")
        .set(2, Value::Integer(quantity))
        .expect("set quantity")
        .set(3, Value::Text(status.to_owned()))
        .expect("set status");
    let bytes = PatchSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(insert)
        .build();
    let payload = zstd::encode_all(bytes.as_slice(), 3).expect("compress mutation");
    MutationPatch::new(client_seq, payload)
}

#[tokio::test]
async fn in_process_loop_round_trips_cdc_and_a_mutation() {
    let mut mat = Materializer::new(PG_DDL).expect("build materializer");
    let registration = mat
        .register(1, "SELECT * FROM orders WHERE quantity > 0")
        .expect("register subscription");
    assert!(
        matches!(registration, connetto_server::Registration::Row(id) if id >= 1),
        "engine assigned a row subscription id"
    );

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    let mut replica = sqlite_target();

    // INSERT: the row enters the result set and reaches the replica.
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (7, 9.5, 1, 'paid')")
        .expect("insert 7");
    drain_to_replica(&mut source, &mut mat, &mut replica).await;
    assert_eq!(orders(&mut replica), vec![order(7, 9.5, 1, "paid")]);

    // A second INSERT.
    source
        .execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (8, 4.0, 2, 'new')")
        .expect("insert 8");
    drain_to_replica(&mut source, &mut mat, &mut replica).await;
    assert_eq!(
        orders(&mut replica),
        vec![order(7, 9.5, 1, "paid"), order(8, 4.0, 2, "new")]
    );

    // UPDATE: the row stays in the set, only quantity changes on the replica.
    source
        .execute_sql("UPDATE orders SET quantity = 5 WHERE id = 7")
        .expect("update 7");
    drain_to_replica(&mut source, &mut mat, &mut replica).await;
    assert_eq!(
        orders(&mut replica),
        vec![order(7, 9.5, 5, "paid"), order(8, 4.0, 2, "new")]
    );

    // DELETE: the row leaves the set and is removed from the replica.
    source
        .execute_sql("DELETE FROM orders WHERE id = 8")
        .expect("delete 8");
    drain_to_replica(&mut source, &mut mat, &mut replica).await;
    assert_eq!(orders(&mut replica), vec![order(7, 9.5, 5, "paid")]);

    // Ack the last consumed position back to the source loop.
    source.ack(subql::PgLsn(0)).await.expect("ack source");

    // Inbound write path: a client MutationPatch lands on a backend target.
    let mut target = sqlite_target();
    let affected = mat
        .apply_mutation(&mutation_insert(1, 9, 1.5, 3, "pending"), &mut target)
        .expect("apply mutation");
    assert_eq!(affected, 1, "one row inserted by the mutation");
    assert_eq!(orders(&mut target), vec![order(9, 1.5, 3, "pending")]);
}
