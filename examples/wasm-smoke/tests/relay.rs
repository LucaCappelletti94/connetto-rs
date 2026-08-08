//! The browser relay, increment 2: generic snapshots, per-table patch
//! routing, tab write forwarding, and the `MessagePort` transport.
//!
//! Two tests, both against the real server and Postgres. The first drives an
//! unmodified full client (pump plus typed live queries) over the in-memory
//! loopback: a row written before the worker connects can only arrive
//! through the relay's generic snapshot, a worker-local row in a second
//! table proves per-table snapshot coverage, and a row written afterward can
//! only arrive as a routed live patch. The second runs a raw client over a
//! real `MessageChannel` and pushes a tab write through the relay: the row
//! must land in Postgres (an independent observer sees it) and the echo must
//! flow back down to the tab.
//!
//! **Needs the stack up.** See `authenticated_boot.rs` for the commands.
//! Run this suite with:
//! `wasm-pack test --headless --chrome examples/wasm-smoke --test relay`

#![cfg(target_arch = "wasm32")]

mod common;

use connetto_client::dsl::Watchable;
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Grant, LiveQuery, Replica,
};
use connetto_core::{Transport, loopback};
use connetto_wasm_smoke::{BrowserSocket, PortTransport, RelayHub};
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The replica schema: `orders` is the server-synced table, `notes` exists
/// only in the worker replica and the tab mirrors, giving the routing tests a
/// second table the server never sees.
const SQLITE_DDL: &str = "\
CREATE TABLE orders (id BLOB PRIMARY KEY DEFAULT (uuidv4()) CHECK (length(id) = 16) NOT NULL, quantity INTEGER) STRICT;\
CREATE TABLE notes (id INTEGER PRIMARY KEY NOT NULL, body TEXT) STRICT;";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        quantity -> diesel::sql_types::BigInt,
    }
}

diesel::table! {
    notes (id) {
        id -> diesel::sql_types::BigInt,
        body -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: rosetta_uuid::Uuid,
    quantity: i64,
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Note {
    id: i64,
    body: String,
}

/// Base for row ids unique across smoke runs, in the relay test's own band.
fn unique_base() -> i64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Date::now in milliseconds fits i64 until the year 285428751"
    )]
    let millis = js_sys::Date::now() as i64;
    40_000_000_000 + millis
}

async fn connect(name: &str, tag: i64) -> ConnettoConnection<BrowserSocket> {
    let transport = BrowserSocket::connect("ws://127.0.0.1:7777/")
        .await
        .expect("connect to connetto-server");
    let config = ClientConfig {
        client_id: format!("{name}-{tag}"),
        login: Some(Grant::new(common::mint_token().await)),
        capabilities: Vec::new(),
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
        sql_functions: connetto_wasm_smoke::uuidv4_functions(),
    };
    ConnettoConnection::connect(transport, &Replica::in_memory(), SQLITE_DDL, &config, None)
        .await
        .expect("client connect")
}

/// Pump `conn` until an event matches `pred`, applying every frame in
/// between. The harness timeout bounds the wait.
async fn pump_until<T>(
    conn: &mut ConnettoConnection<T>,
    pred: impl Fn(&ClientEvent) -> bool,
) -> ClientEvent
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    loop {
        let event = conn.pump_one().await.expect("pump");
        assert_ne!(event, ClientEvent::Closed, "connection closed early");
        if pred(&event) {
            return event;
        }
    }
}

/// Insert one row through `writer`, minting its id from the `orders` DEFAULT,
/// and fence on a pong: control frames are processed in order, so the pong
/// proves the server applied the mutation. Returns the minted 16-byte id.
async fn write_row(
    writer: &mut ConnettoConnection<BrowserSocket>,
    nonce: u64,
) -> rosetta_uuid::Uuid {
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
    let id = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(writer.conn())
        .expect("ids after insert")
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("the newly minted id");
    writer.push().await.expect("push").expect("mutation sent");
    writer.ping(nonce).await.expect("ping");
    pump_until(
        writer,
        |event| matches!(event, ClientEvent::Pong { nonce: n } if *n == nonce),
    )
    .await;
    id
}

#[wasm_bindgen_test]
async fn relay_serves_generic_snapshots_and_routes_live_patches() {
    let base = unique_base();

    // A row that exists before the worker connects: it can only reach the
    // tab through the relay's snapshot leg.
    let mut writer = connect("relay-writer", base).await;
    let snapshot_id = write_row(&mut writer, 1).await;

    // The worker-held upstream connection: subscribe and drain to the
    // snapshot end, so its replica holds the current table.
    let mut worker = connect("relay-worker", base).await;
    worker
        .subscribe("relay-upstream", QUERY)
        .await
        .expect("worker subscribe");
    pump_until(&mut worker, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;

    // A worker-local row in the second table: it can only reach the tab
    // through a generic snapshot of `notes`, which the server never serves.
    diesel::insert_into(notes::table)
        .values((notes::id.eq(1_i64), notes::body.eq("local note")))
        .execute(worker.conn())
        .expect("seed the worker-local note");

    // The relay owns the worker connection and one loopback end. The tab
    // speaks the ordinary wire protocol over the other end.
    let (tab_end, relay_end) = loopback();
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("relay hub meta");
    wasm_bindgen_futures::spawn_local(async move {
        pump.await.expect("relay hub");
    });
    hub.attach(relay_end);

    let config = ClientConfig {
        client_id: rosetta_uuid::Uuid::new_v4().to_string(),
        login: Some(Grant::new(common::mint_token().await)),
        capabilities: Vec::new(),
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
        sql_functions: connetto_wasm_smoke::uuidv4_functions(),
    };
    let tab =
        ConnettoConnection::connect(tab_end, &Replica::in_memory(), SQLITE_DDL, &config, None)
            .await
            .expect("tab connect through relay");
    let (tab, pump) = ConnettoClient::with_pump(tab);
    wasm_bindgen_futures::spawn_local(pump);
    let mut orders_live: LiveQuery<Order> = orders::table
        .order(orders::id)
        .live(&tab)
        .await
        .expect("typed orders live query in the tab");
    let mut notes_live: LiveQuery<Note> = notes::table
        .order(notes::id)
        .live(&tab)
        .await
        .expect("typed notes live query in the tab");

    // Snapshot leg, orders: the pre-existing server row arrives from the
    // worker replica.
    loop {
        if orders_live.rows().iter().any(|row| row.id == snapshot_id) {
            break;
        }
        orders_live
            .changed()
            .await
            .expect("orders snapshot refresh");
    }

    // Snapshot leg, notes: the worker-local row arrives through the second
    // subscription's own snapshot, TEXT value intact.
    loop {
        if notes_live
            .rows()
            .iter()
            .any(|row| row.id == 1 && row.body == "local note")
        {
            break;
        }
        notes_live.changed().await.expect("notes snapshot refresh");
    }

    // Live leg: a fresh external write reaches the tab only through server,
    // worker pump, and relay routing.
    let live_id = write_row(&mut writer, 2).await;
    writer.close().await.expect("close writer");
    loop {
        if orders_live.rows().iter().any(|row| row.id == live_id) {
            break;
        }
        orders_live.changed().await.expect("orders live refresh");
    }

    // Routing left the local-only table alone.
    assert_eq!(notes_live.rows().len(), 1, "notes gained a phantom row");
}

#[wasm_bindgen_test]
async fn relay_forwards_tab_writes_upstream_over_a_message_port() {
    let base = unique_base();
    let stage = |message: &str| web_sys::console::log_1(&message.into());

    let mut worker = connect("port-worker", base).await;
    worker
        .subscribe("relay-upstream", QUERY)
        .await
        .expect("worker subscribe");
    pump_until(&mut worker, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    stage("worker synced");

    // A real browser MessageChannel carries the wire protocol between the
    // tab client and the relay.
    let channel = web_sys::MessageChannel::new().expect("message channel");
    let relay_end = PortTransport::new(channel.port1());
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("relay hub meta");
    wasm_bindgen_futures::spawn_local(async move {
        pump.await.expect("relay hub");
    });
    hub.attach(relay_end);
    stage("hub attached");

    let config = ClientConfig {
        client_id: rosetta_uuid::Uuid::new_v4().to_string(),
        login: Some(Grant::new(common::mint_token().await)),
        capabilities: Vec::new(),
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
        sql_functions: connetto_wasm_smoke::uuidv4_functions(),
    };
    let mut tab = ConnettoConnection::connect(
        PortTransport::new(channel.port2()),
        &Replica::in_memory(),
        SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("tab connect through the port");
    stage("tab connected");
    tab.subscribe("tab-orders", QUERY)
        .await
        .expect("tab subscribe");
    pump_until(&mut tab, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    stage("tab snapshot done");

    // The tab writes locally and pushes: the relay applies the changeset to
    // the worker replica with capture active and the worker re-uploads it.
    let before: std::collections::HashSet<rosetta_uuid::Uuid> = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(tab.conn())
        .expect("ids before tab insert")
        .into_iter()
        .collect();
    diesel::insert_into(orders::table)
        .values(orders::quantity.eq(7_i64))
        .execute(tab.conn())
        .expect("tab insert");
    let write_id: rosetta_uuid::Uuid = orders::table
        .select(orders::id)
        .load::<rosetta_uuid::Uuid>(tab.conn())
        .expect("ids after tab insert")
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("newly minted tab write id");
    tab.push().await.expect("tab push").expect("mutation sent");
    stage("tab pushed");

    // Round trip proof: an independent observer on the real server sees the
    // row, so it landed in Postgres, not just in a local mirror.
    let mut observer = connect("port-observer", base).await;
    observer
        .subscribe("observer", QUERY)
        .await
        .expect("observer subscribe");
    loop {
        let event = observer.pump_one().await.expect("observer pump");
        assert_ne!(event, ClientEvent::Closed, "observer closed early");
        let seen: Vec<Order> = orders::table
            .order(orders::id)
            .load(observer.conn())
            .expect("observer local read");
        if seen.iter().any(|row| row.id == write_id) {
            break;
        }
    }
    stage("observer saw the row");
    observer.close().await.expect("close observer");

    // The echo leg converges the tab too: server to worker to relay to tab.
    // The optimistic row is already present, so the patch applies
    // idempotently, and its arrival proves post-write routing stays live.
    pump_until(&mut tab, |event| {
        matches!(event, ClientEvent::LivePatch { .. })
    })
    .await;
    tab.close().await.expect("close tab");
}
