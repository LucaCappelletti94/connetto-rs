//! The OPFS leg of the browser spike: sahpool persistence, an encrypted first
//! boot from DDL, the pump under `spawn_local`, and the typed `live()` verb, all
//! in a dedicated worker against the real server.
//!
//! First boot applies the translated DDL through `connect`, because a durable
//! replica is encrypted and an encrypted database cannot be seeded from a
//! plaintext byte image. A typed live query then follows a local write through
//! the pump, and a second connection to the same OPFS file proves the write
//! persisted and still decrypts.
//!
//! Run with the demo stack up:
//! `wasm-pack test --headless --chrome examples/wasm-smoke`

#![cfg(target_arch = "wasm32")]

use connetto_client::{
    ClientConfig, ConnettoClient, ConnettoConnection, Replica, ReplicaKey, cipher::cipher_url,
    dsl::Watchable,
};
use connetto_wasm_smoke::BrowserSocket;
use diesel::prelude::*;
use futures_channel::oneshot;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The replica schema, translated from `schema.sql` by build.rs.
const REPLICA_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/replica-ddl.sql"));
const DB_NAME: &str = "opfs-smoke.sqlite";

/// A fixed key for this suite. What is under test here is OPFS persistence, not
/// the codec, which `connetto-web/tests/encrypted_replica.rs` covers.
fn replica_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x5a; ReplicaKey::LEN])
}

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
    20_000_000_000 + millis
}

/// The replica URL: the codec shim over the installed sahpool VFS, because the
/// browser codec intercepts as a VFS layer and a bare name would leave it out.
fn replica_url() -> String {
    cipher_url(DB_NAME, "opfs-sahpool")
}

/// Open the replica, applying `ddl` on a first boot and nothing on a reopen.
async fn connect(config: &ClientConfig, ddl: Option<&str>) -> ConnettoConnection<BrowserSocket> {
    let transport = BrowserSocket::connect("ws://127.0.0.1:7777/")
        .await
        .expect("connect to connetto-server");
    let url = replica_url();
    let replica = Replica::EncryptedFile {
        path: &url,
        key: replica_key(),
    };
    match ddl {
        Some(ddl) => ConnettoConnection::connect(transport, &replica, ddl, config, None).await,
        None => ConnettoConnection::connect_existing(transport, &replica, config, None).await,
    }
    .expect("client connect")
}

#[wasm_bindgen_test]
async fn opfs_encrypted_boot_live_query_and_persistence() {
    // Install sahpool as the default VFS. The replica itself is created by the
    // first connect below, which applies the DDL: an encrypted database is born
    // encrypted and takes its schema from statements, never from an image.
    sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    .expect("install sahpool vfs");

    let config = ClientConfig {
        client_id: format!("wasm-opfs-{}", unique_id()),
        auth_token: "token".to_owned(),
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
        sql_functions: connetto_wasm_smoke::uuidv7_functions(),
    };
    let conn = connect(&config, Some(REPLICA_DDL)).await;

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
    let id: rosetta_uuid::Uuid = client
        .with_conn(|conn| {
            let before: std::collections::HashSet<rosetta_uuid::Uuid> = orders::table
                .select(orders::id)
                .load::<rosetta_uuid::Uuid>(conn.conn())?
                .into_iter()
                .collect();
            diesel::insert_into(orders::table)
                .values(orders::quantity.eq(3_i64))
                .execute(conn.conn())?;
            Ok::<rosetta_uuid::Uuid, diesel::result::Error>(
                orders::table
                    .select(orders::id)
                    .load::<rosetta_uuid::Uuid>(conn.conn())?
                    .into_iter()
                    .find(|id| !before.contains(id))
                    .expect("minted id"),
            )
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

    // Reopen the same OPFS file on a fresh connection: the write persisted in the
    // browser's origin private file system and still decrypts under the cached
    // key, visible before any subscription runs.
    let mut conn = connect(&config, None).await;
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
