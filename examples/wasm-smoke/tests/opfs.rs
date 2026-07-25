//! The OPFS leg of the browser spike: sahpool persistence, template first
//! boot, the pump under `spawn_local`, and the typed `live()` verb, all in a
//! dedicated worker against the real server.
//!
//! First boot imports the baked replica template through the VFS utility
//! (never the filesystem, `std::fs` is a stub on wasm) and connects with
//! `connect_existing`, so no DDL ever runs in the browser. A typed live
//! query then follows a local write through the pump, and a second
//! connection to the same OPFS file proves the write persisted.
//!
//! Run with the demo stack up:
//! `wasm-pack test --headless --chrome examples/wasm-smoke`

#![cfg(target_arch = "wasm32")]

use connetto_client::{ClientConfig, ConnettoClient, ConnettoConnection, dsl::Watchable};
use connetto_wasm_smoke::BrowserSocket;
use diesel::prelude::*;
use futures_channel::oneshot;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The replica template baked by build.rs from schema.sql through pg2sqlite.
const REPLICA_TEMPLATE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/replica-template.sqlite"));
const DB_NAME: &str = "opfs-smoke.sqlite";

diesel::table! {
    orders (id) {
        id -> diesel::sql_types::BigInt,
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    quantity: i64,
}

/// A row id unique enough across smoke runs, above every other band in use.
fn unique_id() -> i64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Date::now in milliseconds fits i64 until the year 285428751"
    )]
    let millis = js_sys::Date::now() as i64;
    20_000_000_000 + millis
}

async fn connect(config: &ClientConfig) -> ConnettoConnection<BrowserSocket> {
    let transport = BrowserSocket::connect("ws://127.0.0.1:7777/")
        .await
        .expect("connect to connetto-server");
    ConnettoConnection::connect_existing(transport, DB_NAME, config, None)
        .await
        .expect("client connect")
}

#[wasm_bindgen_test]
async fn opfs_template_boot_live_query_and_persistence() {
    // Install sahpool as the default VFS and first-boot the replica from the
    // baked template bytes: OPFS write, zero DDL execution.
    let util = sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    .expect("install sahpool vfs");
    util.import_db(DB_NAME, REPLICA_TEMPLATE)
        .expect("import replica template");

    let config = ClientConfig {
        client_id: format!("wasm-opfs-{}", unique_id()),
        auth_token: "token".to_owned(),
        schema_version: connetto_wasm_smoke::demo_schema_version(),
    };
    let conn = connect(&config).await;

    // The pump under spawn_local: the wasm driving mode for the same client
    // machinery the native demo runs under tokio.
    let (client, pump) = ConnettoClient::with_pump(conn);
    let (pump_done_tx, pump_done) = oneshot::channel::<()>();
    wasm_bindgen_futures::spawn_local(async move {
        pump.await;
        let _ = pump_done_tx.send(());
    });

    // The typed verb, in the browser: compile-time dispatch to a LiveQuery.
    let mut live: connetto_client::LiveQuery<Order> = orders::table
        .order(orders::id)
        .live(&client)
        .await
        .expect("typed live query");
    let baseline = live.rows().len();

    // A local write through the managed connection: captured, pushed by the
    // pump, and refreshed into the live handle.
    let id = unique_id();
    client
        .with_conn(move |conn| {
            diesel::insert_into(orders::table)
                .values((orders::id.eq(id), orders::quantity.eq(3_i64)))
                .execute(conn.conn())
        })
        .await
        .expect("local insert");
    live.changed().await.expect("live refresh");
    let rows = live.rows();
    assert_eq!(rows.len(), baseline + 1, "the live handle saw the write");
    assert!(rows.iter().any(|row| row.id == id));

    // RAII teardown: dropping the handle and the last client clone makes the
    // pump unsubscribe, close the transport, and exit.
    drop(live);
    drop(client);
    pump_done.await.expect("pump exited");

    // Reopen the same OPFS file on a fresh connection: the write persisted
    // in the browser's origin private file system, visible before any
    // subscription runs.
    let mut conn = connect(&config).await;
    let persisted: Vec<Order> = orders::table
        .order(orders::id)
        .select(Order::as_select())
        .load(conn.conn())
        .expect("read persisted replica");
    assert!(
        persisted.iter().any(|row| row.id == id),
        "the write survived in OPFS across connections"
    );
    conn.close().await.expect("close");
}
