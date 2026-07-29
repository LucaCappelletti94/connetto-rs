//! Active reloading on the PAGE main thread, no worker, no proxy: the full
//! client (memory VFS replica, pump under `spawn_local`, typed `live()`)
//! runs directly in the page, and a change made by a SECOND client arrives
//! through the real server and refreshes the first client's live handle.
//!
//! This pins the baseline the tab proxy work builds on: single tab apps
//! without OPFS persistence need no worker at all, the page is just another
//! replication tier. The worker topology adds persistence and multi tab
//! sharing, not reactivity.
//!
//! Run with the demo stack up:
//! `wasm-pack test --headless --chrome examples/wasm-smoke`

#![cfg(target_arch = "wasm32")]

use connetto_client::dsl::Watchable;
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, LiveQuery, Replica,
};
use connetto_wasm_smoke::BrowserSocket;
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

const SQLITE_DDL: &str = "CREATE TABLE orders (id BLOB PRIMARY KEY DEFAULT (uuidv7()) CHECK (length(id) = 16) NOT NULL, quantity INTEGER) STRICT;";

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: rosetta_uuid::Uuid,
    quantity: i64,
}

/// A row id unique enough across smoke runs, above every other band in use.
fn unique_id() -> i64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Date::now in milliseconds fits i64 until the year 285428751"
    )]
    let millis = js_sys::Date::now() as i64;
    30_000_000_000 + millis
}

async fn connect(name: &str) -> ConnettoConnection<BrowserSocket> {
    let transport = BrowserSocket::connect("ws://127.0.0.1:7777/")
        .await
        .expect("connect to connetto-server");
    let config = ClientConfig {
        client_id: format!("{name}-{}", unique_id()),
        auth_token: "token".to_owned(),
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
        sql_functions: connetto_wasm_smoke::uuidv7_functions(),
    };
    ConnettoConnection::connect(transport, &Replica::Ephemeral, SQLITE_DDL, &config, None)
        .await
        .expect("client connect")
}

#[wasm_bindgen_test]
async fn page_live_query_reloads_on_another_clients_write() {
    // The observing client lives on the page main thread.
    let (observer, pump) = ConnettoClient::with_pump(connect("page-observer").await);
    wasm_bindgen_futures::spawn_local(pump);
    let mut live: LiveQuery<Order> = orders::table
        .order(orders::id)
        .live(&observer)
        .await
        .expect("typed live query on the page");

    // A second, independent client writes: the change must reach the page
    // through the server (apply to Postgres, replication echo, live patch),
    // never through anything local to the observer.
    let mut writer = connect("page-writer").await;
    let before: std::collections::HashSet<rosetta_uuid::Uuid> = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(writer.conn())
        .expect("ids before insert")
        .into_iter()
        .collect();
    diesel::insert_into(orders::table)
        .values(orders::quantity.eq(5_i64))
        .execute(writer.conn())
        .expect("writer insert");
    let id: rosetta_uuid::Uuid = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(writer.conn())
        .expect("ids after insert")
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("minted id");
    writer.push().await.expect("push").expect("mutation sent");
    // The writer has no subscription, and an applied mutation gets no
    // dedicated reply (the CDC echo is the ack, and it goes to subscribers).
    // Fence with a ping: control frames are ordered, so the pong proves the
    // server consumed the mutation frames.
    writer.ping(1).await.expect("ping");
    loop {
        let event = writer.pump_one().await.expect("writer pump");
        if matches!(event, ClientEvent::Pong { nonce: 1 }) {
            break;
        }
        assert_ne!(event, ClientEvent::Closed, "writer closed early");
    }
    writer.close().await.expect("close writer");

    // Active reload on the page: the observer's handle refreshes with no
    // local interaction at all. The snapshot and the echo each bump the
    // handle once, in either interleaving, so wait until the written row is
    // visible rather than counting refreshes. The harness timeout bounds
    // the loop.
    loop {
        if live.rows().iter().any(|row| row.id == id) {
            break;
        }
        live.changed().await.expect("page live refresh");
    }
}
