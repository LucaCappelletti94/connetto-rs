//! R15 step 6: the typed write-and-keep surface.
//!
//! `insert_watched`, `insert_pinned`, and `update_watched` compose a write with
//! keeping its row: the table is inferred from the row type and the primary key
//! read back through the row's `Identifiable` impl. Driven offline, so the write
//! stays local and the assertions read the client's own replica.

use core::time::Duration;

use connetto_client::{ClientConfig, ConnettoConnection, Grant, LiveQuery, Replica};
use connetto_server::LoopbackTransport;
use diesel::prelude::*;

const DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";

diesel::table! {
    /// The table the write surface infers from the row type.
    orders (id) {
        /// Primary key.
        id -> BigInt,
        /// Unit price.
        price -> Double,
        /// How many units.
        quantity -> BigInt,
        /// Free-text payload.
        status -> Text,
    }
}

#[derive(Insertable)]
#[diesel(table_name = orders)]
struct NewOrder {
    id: i64,
    price: f64,
    quantity: i64,
    status: String,
}

#[derive(Queryable, Selectable, Identifiable, Debug, Clone, PartialEq)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    price: f64,
    quantity: i64,
    status: String,
}

fn config() -> ClientConfig {
    ClientConfig::new("r15-write").with_login(Some(Grant::new("user:r15")))
}

/// An offline client whose pump never reaches a server, so a written row stays
/// local and the live query answers from the replica alone.
fn offline_client() -> connetto_client::ConnettoClient<LoopbackTransport> {
    let conn =
        ConnettoConnection::<LoopbackTransport>::open(&Replica::in_memory(), DDL, &config(), None)
            .expect("open offline");
    connetto_client::ConnettoClient::start(conn)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn insert_watched_tracks_the_written_row() {
    let client = offline_client();
    let (row, mut live): (Order, LiveQuery<Order>) = client
        .insert_watched::<NewOrder, Order, i64>(NewOrder {
            id: 1,
            price: 2.0,
            quantity: 3,
            status: "new".to_owned(),
        })
        .await
        .expect("insert_watched");
    assert_eq!(row.id, 1);
    assert_eq!(row.status, "new");
    assert_eq!(
        live.rows(),
        vec![row.clone()],
        "the live query holds the written row"
    );

    // Delete the row and the live query reports it gone.
    client
        .with_conn(|conn| {
            diesel::delete(orders::table.find(1_i64))
                .execute(conn.conn())
                .expect("delete");
        })
        .await;
    tokio::time::timeout(Duration::from_secs(5), live.changed())
        .await
        .expect("the delete refreshes the live query")
        .expect("live query still driven");
    assert!(
        live.rows().is_empty(),
        "the live query reports the row vanishing",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn insert_pinned_pins_the_written_row() {
    let client = offline_client();
    let row: Order = client
        .insert_pinned::<NewOrder, Order, i64>(
            "keeper",
            NewOrder {
                id: 7,
                price: 1.0,
                quantity: 1,
                status: "pinned".to_owned(),
            },
        )
        .await
        .expect("insert_pinned");
    assert_eq!(row.id, 7);

    let pins = client.pins().await.expect("pins");
    assert_eq!(pins.len(), 1, "exactly one pin was recorded");
    assert_eq!(pins[0].0, "keeper", "under the chosen name");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_watched_returns_the_updated_row() {
    let client = offline_client();
    client
        .with_conn(|conn| {
            diesel::insert_into(orders::table)
                .values((
                    orders::id.eq(2_i64),
                    orders::price.eq(1.0),
                    orders::quantity.eq(1_i64),
                    orders::status.eq("before"),
                ))
                .execute(conn.conn())
                .expect("seed");
        })
        .await;

    let (row, live): (Order, LiveQuery<Order>) = client
        .update_watched::<_, _, Order, i64>(orders::table.find(2_i64), orders::price.eq(9.0))
        .await
        .expect("update_watched");
    assert_eq!(row.id, 2);
    assert!(
        (row.price - 9.0).abs() < 1e-9,
        "the returned row carries the update"
    );
    assert_eq!(
        live.rows(),
        vec![row],
        "the live query holds the updated row"
    );
}
