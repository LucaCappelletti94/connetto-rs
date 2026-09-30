//! The local tier in a real browser: a second sahpool-backed OPFS file created
//! through the replica connection, re-attached with attach-create disabled,
//! tier-dispatched live queries, and persistence across connections, in a
//! dedicated worker against the real server.
//!
//! Pins the wasm-specific legs the native tier suite cannot: `ATTACH` of a
//! sahpool file, the attach-create dbconfig, and `json_quote` in the wasm SQLite
//! build (the local aggregate probe rides it).
//!
//! The tier comes from the schema's local tier, created with the replica on
//! a first boot and reopened with it after, decrypting under the replica's
//! key.

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

const DB_NAME: &str = "tier-smoke.sqlite";

/// A fixed key for this suite. One device, one key: the tier inherits it through
/// the `ATTACH` rather than carrying its own.
fn replica_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x5a; ReplicaKey::LEN])
}

diesel::table! {
    notes (id) {
        id -> diesel::sql_types::BigInt,
        body -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Note {
    id: i64,
    body: Option<String>,
}

/// A row id unique enough across smoke runs, above every other band in use.
fn unique_id() -> i64 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Date::now in milliseconds fits i64 until the year 285428751"
    )]
    let millis = js_sys::Date::now() as i64;
    50_000_000_000 + millis
}

/// Connect to the shared replica file, the local tier beside it.
///
/// A first boot creates both files and applies both schemas, the tier
/// decrypting under the replica's key. A reopen refuses to create the tier
/// file if it is missing, so a failed persist fails loudly.
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
async fn local_tier_placement_dispatch_and_persistence() {
    // Only the VFS is installed here. Both tiers are created by the first
    // connect below, which applies their DDL, because neither can be seeded from
    // a plaintext image once the replica is encrypted.
    sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    .expect("install sahpool vfs");

    let (token, user_id) = common::mint_session().await;
    let credential = build::held(token, &user_id);
    let mut conn = connect(&credential, true).await;
    assert!(
        conn.local_tables().contains("notes"),
        "the tier lookup sees the attached notes table"
    );

    // Placement: a note lands outside the capture session, so push has
    // nothing to upload and no MutationHeader can ever carry it.
    let id = unique_id();
    diesel::insert_into(notes::table)
        .values((notes::id.eq(id), notes::body.eq("draft")))
        .execute(conn.conn())
        .expect("insert note");
    assert_eq!(
        conn.push().await.expect("push after a note"),
        None,
        "a local tier write must never produce a mutation"
    );

    // Tier-dispatched live handles through the pump under spawn_local.
    let (client, pump) = ConnettoClient::with_pump(conn);
    let (pump_done_tx, pump_done) = oneshot::channel::<()>();
    wasm_bindgen_futures::spawn_local(async move {
        pump.await;
        let _ = pump_done_tx.send(());
    });

    let mut live: connetto_client::LiveQuery<Note> = notes::table
        .filter(notes::id.ge(id))
        .order(notes::id)
        .live(&client)
        .await
        .expect("local live query");
    assert_eq!(live.rows().len(), 1, "the note answers locally");

    // The local aggregate probe (json_quote in the wasm SQLite build): the
    // bootstrap is immediate, and a local write recomputes it.
    let mut count = notes::table
        .filter(notes::id.ge(id))
        .count()
        .live(&client)
        .await
        .expect("local live aggregate");
    assert_eq!(count.value(), Some(1), "bootstrap is answered locally");

    client
        .with_conn(move |conn| {
            diesel::insert_into(notes::table)
                .values((notes::id.eq(id + 1), notes::body.eq("second")))
                .execute(conn.conn())
        })
        .await
        .expect("gate not locked")
        .expect("insert second note");
    live.changed().await.expect("local row refresh");
    assert_eq!(live.rows().len(), 2, "the row handle refreshed locally");
    count.changed().await.expect("local recompute");
    assert_eq!(count.value(), Some(2), "the aggregate re-executed locally");

    drop(live);
    drop(count);
    drop(client);
    pump_done.await.expect("pump exited");

    // The notes persisted in their own OPFS file: a fresh connection re-attaches
    // it with attach-create disabled, so this also proves the tier file really
    // exists and decrypts under the replica's key.
    let mut conn = connect(&credential, false).await;
    let persisted: Vec<Note> = notes::table
        .filter(notes::id.ge(id))
        .order(notes::id)
        .select(Note::as_select())
        .load(conn.conn())
        .expect("read persisted notes");
    assert_eq!(
        persisted.len(),
        2,
        "the notes survived in OPFS across connections"
    );
    conn.close().await.expect("close");
}
