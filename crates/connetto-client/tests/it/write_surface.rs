//! R15 step 6: the typed write-and-keep surface.
//!
//! `insert_watched`, `insert_pinned`, and `update_watched` compose a write with
//! keeping its row: the table is inferred from the row type and the primary key
//! read back through the row's `Identifiable` impl. Driven offline while the
//! pump redials, so the write stays local and the assertions read the
//! client's own replica.

use core::time::Duration;

use connetto_client::{ClientBuilder, CoreClient, LiveQuery, ReconnectPolicy};
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

/// A running client that never reaches its server, so a written row stays
/// local and the live query answers from the replica while the pump redials.
async fn offline_client() -> CoreClient<LoopbackTransport> {
    let (client, pump) = ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::NeverDial::<LoopbackTransport>::default(),
    )
    .with_reconnect(
        ReconnectPolicy::new()
            .with_initial_backoff(Duration::from_secs(30))
            .with_max_backoff(Duration::from_secs(30)),
    )
    .signed_in(super::support::held("r15"))
    .connect_with_pump()
    .await
    .expect("the builder opens offline");
    tokio::spawn(pump);
    client
}

/// A write made while the client waits to redial is queued durably at once,
/// so a restart before the server returns still uploads it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_write_is_queued_while_the_client_waits_to_redial() {
    let client = offline_client().await;
    client
        .client()
        .with_conn(|conn| {
            diesel::insert_into(orders::table)
                .values((
                    orders::id.eq(9_i64),
                    orders::price.eq(1.0),
                    orders::quantity.eq(1_i64),
                    orders::status.eq("queued"),
                ))
                .execute(conn.conn())
                .expect("insert");
        })
        .await
        .expect("gate not locked");
    let queued = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let unsynced = client
                .client()
                .with_conn(|conn| conn.unsynced())
                .await
                .expect("gate not locked");
            if !unsynced.is_empty() {
                break unsynced;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the write is queued without waiting for the server");
    assert_eq!(queued.len(), 1, "one write, one queued mutation");
}

/// A write made just before a close is queued by the close, so neither a
/// guard reading the queue nor a restart can miss it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_made_just_before_a_close_is_queued_by_the_close() {
    let client = offline_client().await;
    client
        .client()
        .with_conn(|conn| {
            diesel::insert_into(orders::table)
                .values((
                    orders::id.eq(11_i64),
                    orders::price.eq(1.0),
                    orders::quantity.eq(1_i64),
                    orders::status.eq("last"),
                ))
                .execute(conn.conn())
                .expect("insert");
        })
        .await
        .expect("gate not locked");
    client.close().await;
    let unsynced = client
        .client()
        .with_conn(|conn| conn.unsynced())
        .await
        .expect("gate not locked");
    assert_eq!(unsynced.len(), 1, "the close queued the last write");
}

/// The unsynced writes a client reports include the ones not yet queued, so a
/// guard reading them right after a write cannot miss it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsynced_counts_a_write_the_pump_has_not_queued_yet() {
    let client = offline_client().await;
    client
        .client()
        .with_conn(|conn| {
            diesel::insert_into(orders::table)
                .values((
                    orders::id.eq(12_i64),
                    orders::price.eq(1.0),
                    orders::quantity.eq(1_i64),
                    orders::status.eq("fresh"),
                ))
                .execute(conn.conn())
                .expect("insert");
        })
        .await
        .expect("gate not locked");
    let unsynced = client.client().unsynced().await.expect("gate not locked");
    assert_eq!(unsynced.len(), 1, "the write counts at once");
}

/// Closing a client that is waiting out a reconnect backoff ends its pump at
/// once rather than after the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_client_closes_while_it_waits_to_redial() {
    let client = offline_client().await;
    let mut events = client.client().events();
    tokio::time::timeout(Duration::from_secs(5), client.close())
        .await
        .expect("close returns without waiting out the backoff");
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Ok(connetto_client::ClientEvent::Closed) => break true,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break false,
            }
        }
    })
    .await
    .expect("the pump announces its end");
    assert!(closed, "a closed client tells its subscribers it closed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn insert_watched_tracks_the_written_row() {
    let client = offline_client().await;
    let (row, mut live): (Order, LiveQuery<Order>) = client
        .client()
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
        .client()
        .with_conn(|conn| {
            diesel::delete(orders::table.find(1_i64))
                .execute(conn.conn())
                .expect("delete");
        })
        .await
        .expect("gate not locked");
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
    let client = offline_client().await;
    let row: Order = client
        .client()
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

    let pins = client.client().pins().await.expect("pins");
    assert_eq!(pins.len(), 1, "exactly one pin was recorded");
    assert_eq!(pins[0].0, "keeper", "under the chosen name");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn update_watched_returns_the_updated_row() {
    let client = offline_client().await;
    client
        .client()
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
        .await
        .expect("gate not locked");

    let (row, live): (Order, LiveQuery<Order>) = client
        .client()
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
