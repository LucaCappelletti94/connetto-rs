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

#![cfg(target_arch = "wasm32")]

mod common;

use connetto_client::{
    ClientBuilder, ConnettoClient, ConnettoConnection, Gate, HeldCredential, ReplicaKey,
    dsl::Watchable,
};
use connetto_wasm_smoke::BrowserSocket;
use connetto_wasm_smoke::build;
use connetto_wasm_smoke::workers::demo_schema;

use diesel::prelude::*;
use futures_channel::oneshot;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const DB_NAME: &str = "opfs-smoke.sqlite";

/// A fixed key for this suite. What is under test here is OPFS persistence, not
/// the codec, which `connetto-web/tests/encrypted_replica.rs` covers.
fn replica_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x5a; ReplicaKey::LEN])
}

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

/// Open the replica, creating it on a first boot and reopening it after.
async fn connect(
    credential: &HeldCredential,
    first_boot: bool,
) -> ConnettoConnection<BrowserSocket> {
    ClientBuilder::new(demo_schema(), build::server())
        .signed_in(credential.clone())
        .durable(
            build::SuitePlace::new(DB_NAME, !first_boot),
            build::keys_for(credential, replica_key()).await,
        )
        .with_gate(Gate::off())
        .connect_driven()
        .await
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

    let (token, user_id) = common::mint_session().await;
    let credential = build::held(token, &user_id);
    let conn = connect(&credential, true).await;

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
                .values((
                    orders::owner_id.eq(user_id.as_str()),
                    orders::quantity.eq(3_i64),
                ))
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
        .expect("gate not locked")
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
    let mut conn = connect(&credential, false).await;
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
