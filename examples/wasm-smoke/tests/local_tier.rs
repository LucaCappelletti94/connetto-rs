//! The local tier in a real browser: a second sahpool-backed OPFS file
//! imported from the baked frontend template, attached with attach-create
//! disabled, tier-dispatched live queries, and persistence across
//! connections, in a dedicated worker against the real server.
//!
//! Pins the wasm-specific legs the native tier suite cannot: ATTACH of a
//! sahpool file, the attach-create dbconfig, and `json_quote` in the wasm
//! SQLite build (the local aggregate probe rides it).
//!
//! Run with the demo stack up:
//! `wasm-pack test --headless --chrome examples/wasm-smoke`

#![cfg(target_arch = "wasm32")]

use connetto_client::{ClientConfig, ConnettoClient, ConnettoConnection, Replica, dsl::Watchable};
use connetto_wasm_smoke::BrowserSocket;
use diesel::prelude::*;
use futures_channel::oneshot;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The tier templates baked by build.rs from the two source documents.
const REPLICA_TEMPLATE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/replica-template.sqlite"));
const FRONTEND_TEMPLATE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/frontend-template.sqlite"));
const DB_NAME: &str = "tier-smoke.sqlite";
const FRONTEND_DB_NAME: &str = "tier-smoke-frontend.sqlite";

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

/// Connect to the shared replica file and attach the local tier file.
async fn connect(config: &ClientConfig) -> ConnettoConnection<BrowserSocket> {
    let transport = BrowserSocket::connect("ws://127.0.0.1:7777/")
        .await
        .expect("connect to connetto-server");
    let mut conn = ConnettoConnection::connect_existing(
        transport,
        &Replica::PlaintextFile { path: DB_NAME },
        config,
        None,
    )
    .await
    .expect("client connect");
    conn.attach_local_tier(FRONTEND_DB_NAME)
        .expect("attach the local tier file");
    conn
}

#[wasm_bindgen_test]
async fn local_tier_placement_dispatch_and_persistence() {
    // First boot: both tiers imported from their baked templates through the
    // VFS utility, zero DDL execution in the browser.
    let util = sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    .expect("install sahpool vfs");
    util.import_db(DB_NAME, REPLICA_TEMPLATE)
        .expect("import replica template");
    util.import_db(FRONTEND_DB_NAME, FRONTEND_TEMPLATE)
        .expect("import frontend template");

    let config = ClientConfig {
        client_id: format!("wasm-tier-{}", unique_id()),
        auth_token: "token".to_owned(),
        schema_version: Some(connetto_wasm_smoke::demo_schema_version()),
        sql_functions: connetto_wasm_smoke::uuidv7_functions(),
    };
    let mut conn = connect(&config).await;
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
        .expect("insert second note");
    live.changed().await.expect("local row refresh");
    assert_eq!(live.rows().len(), 2, "the row handle refreshed locally");
    count.changed().await.expect("local recompute");
    assert_eq!(count.value(), Some(2), "the aggregate re-executed locally");

    drop(live);
    drop(count);
    drop(client);
    pump_done.await.expect("pump exited");

    // The notes persisted in their own OPFS file: a fresh connection with a
    // fresh attach reads them back before any subscription runs.
    let mut conn = connect(&config).await;
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
