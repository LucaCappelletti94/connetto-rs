//! Two independent clients against the real server: the full client (memory
//! VFS replica, pump under `spawn_local`, typed `live()`) running in a
//! dedicated worker, and a change made by a second client arriving through
//! the real server refreshing the first client's live handle.
//!
//! This pins the baseline the tab proxy work builds on: single-context apps
//! without OPFS persistence need no worker separation. The worker topology
//! adds persistence and multi-tab sharing, not reactivity.
//!
//! **Needs the stack up.** See `authenticated_boot.rs` for the commands.
//! Run this suite with:
//! `wasm-pack test --headless --chrome examples/wasm-smoke --test page`

#![cfg(target_arch = "wasm32")]

mod common;

use connetto_client::dsl::Watchable;
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Grant, LiveQuery, Replica,
};
use connetto_wasm_smoke::BrowserSocket;
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: rosetta_uuid::Uuid,
    owner_id: String,
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

async fn connect(name: &str, token: String, identity: String) -> ConnettoConnection<BrowserSocket> {
    let transport = BrowserSocket::connect("ws://127.0.0.1:7777/")
        .await
        .expect("connect to connetto-server");
    let config = ClientConfig::new(format!("{name}-{}", unique_id()))
        .with_login(Some(Grant::new(token)))
        .with_schema_version(Some(connetto_wasm_smoke::demo_schema_version()))
        .with_sql_functions(connetto_wasm_smoke::uuidv4_functions())
        .with_policy_tables(connetto_wasm_smoke::demo_policy_tables())
        .with_caller(connetto_wasm_smoke::CALLER_FUNCTION, identity.as_str());
    ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        connetto_wasm_smoke::workers::DEMO_SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("client connect")
}

#[wasm_bindgen_test]
async fn page_live_query_reloads_on_another_clients_write() {
    let (token, identity) = common::mint_session().await;
    // The observing client runs in a dedicated worker, same as the data tier.
    let (observer, pump) =
        ConnettoClient::with_pump(connect("page-observer", token.clone(), identity.clone()).await);
    wasm_bindgen_futures::spawn_local(pump);
    let mut live: LiveQuery<Order> = orders::table
        .order(orders::id)
        .live(&observer)
        .await
        .expect("typed live query on the page");

    // A second, independent client writes: the change must reach the page
    // through the server (apply to Postgres, replication echo, live patch),
    // never through anything local to the observer.
    // A separate login, so the writer holds its own session rather than
    // superseding the observer's. Same fixed user, so it owns what it writes
    // and the observer, that user too, is allowed to see it.
    let (writer_token, _) = common::mint_session().await;
    let mut writer = connect("page-writer", writer_token, identity.clone()).await;
    let before: std::collections::HashSet<rosetta_uuid::Uuid> = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(writer.conn())
        .expect("ids before insert")
        .into_iter()
        .collect();
    diesel::insert_into(orders::table)
        .values((
            orders::owner_id.eq(identity.as_str()),
            orders::quantity.eq(5_i64),
        ))
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

    // Active reload: the observer's handle refreshes with no local interaction
    // at all. The snapshot and the echo each bump the handle once, in either
    // interleaving, so wait until the written row is visible. The harness
    // timeout bounds the loop.
    loop {
        if live.rows().iter().any(|row| row.id == id) {
            break;
        }
        live.changed().await.expect("page live refresh");
    }
}
