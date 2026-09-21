//! A tab whose rights come from a share key, through the real DB worker.
//!
//! The row the stack seeded is owned by the key's own rendering, so nothing
//! about the signed-in user reaches it. Seeing it exercises the membership arm
//! of `photos_p` at both ends at once: the server admits the row by splitting
//! the setting it binds, and the replica admits it by searching the string its
//! translated policy reads from the registered function.

#![cfg(target_arch = "wasm32")]

mod common;
mod harness;

use connetto_client::dsl::Watchable;
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Grant, LiveQuery, Replica,
};
use connetto_wasm_smoke::workers::{DEMO_TAB_DDL, announce_tab, await_db_worker_ready};
use connetto_wasm_smoke::{CALLER_FUNCTION, MessageTransport, locks};
use diesel::prelude::*;
use futures_channel::oneshot;
use js_sys::Array;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::BroadcastChannel;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

diesel::table! {
    photos (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        order_id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        content_id -> diesel::sql_types::Binary,
        content_state -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = photos)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Photo {
    id: rosetta_uuid::Uuid,
    order_id: rosetta_uuid::Uuid,
    owner_id: String,
    content_id: Vec<u8>,
    content_state: Option<String>,
}

/// Boot the photo tier in a worker holding the stack's share key.
fn spawn_share_worker(glue_url: &str) -> web_sys::Worker {
    let wasm_url = glue_url.strip_suffix(".js").map_or_else(
        || format!("{glue_url}_bg.wasm"),
        |base| format!("{base}_bg.wasm"),
    );
    let source = format!(
        "const debug = new BroadcastChannel(\"connetto-debug\");\ntry {{\n  const mod = await import(\"{g}\");\n  await mod.default({{ module_or_path: \"{w}\" }});\n  await mod.db_worker_share_boot();\n  debug.postMessage(\"db worker: serving\");\n}} catch (err) {{\n  debug.postMessage(\"db worker FAILED: \" + err);\n  throw err;\n}}\n",
        g = glue_url,
        w = wasm_url,
    );
    let parts = Array::of1(&wasm_bindgen::JsValue::from_str(&source));
    let blob_opts = web_sys::BlobPropertyBag::new();
    blob_opts.set_type("text/javascript");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &blob_opts)
        .expect("bootstrap blob");
    let url = web_sys::Url::create_object_url_with_blob(&blob).expect("bootstrap url");
    let worker_opts = web_sys::WorkerOptions::new();
    worker_opts.set_type(web_sys::WorkerType::Module);
    worker_opts.set_name("connetto-db-share");
    let worker = web_sys::Worker::new_with_options(&url, &worker_opts).expect("spawn share worker");
    let _ = web_sys::Url::revoke_object_url(&url);
    worker
}

/// A tab holding the same key the worker booted with.
///
/// The tab reads its own replica, so it registers the key too. A tab given
/// only the identity would be shown nothing, whatever the worker holds.
async fn connect_tab(
    client_id: &str,
    token: String,
    identity: &str,
    grant: &str,
    subject: &str,
) -> ConnettoConnection<MessageTransport<BroadcastChannel>> {
    let wire = format!("connetto-wire-{client_id}");
    announce_tab(&wire).await.expect("announce the tab");
    let transport = MessageTransport::<BroadcastChannel>::new(&wire).expect("wire channel");
    let config = ClientConfig::new(client_id.to_owned())
        .with_login(Some(Grant::new(token)))
        .with_schema_version(Some(connetto_wasm_smoke::demo_schema_version()))
        .with_sql_functions(connetto_wasm_smoke::uuidv4_functions())
        .with_policy_tables(connetto_wasm_smoke::demo_policy_tables())
        .with_caller(CALLER_FUNCTION, Some(identity))
        .with_share_keys::<String>(
            connetto_wasm_smoke::SUBJECTS_FUNCTION,
            [(
                Grant::new(grant.to_owned()),
                connetto_core::auth::CapabilitySubject::new(subject.to_owned()),
            )],
        );
    ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        DEMO_TAB_DDL,
        &config,
        None,
    )
    .await
    .expect("tab connect through the wire channel")
}

/// A caller holding only a share key sees the row that key owns, and a caller
/// holding no key sees nothing of it.
#[wasm_bindgen_test]
async fn a_key_holder_sees_the_row_its_key_owns() {
    harness::relay_worker_breadcrumbs();
    common::play_the_tab();

    let (grant, subject, shared) = connetto_wasm_smoke::fetch_share()
        .await
        .expect("the browser stack serves the share key it minted");

    let worker = spawn_share_worker(&harness::glue_url());
    await_db_worker_ready(&[]).await.expect("db worker ready");

    // The signed-in user owns nothing here, so every row it sees arrives
    // through the key rather than through the identity.
    let (token, identity) = common::mint_session().await;
    let client_id = rosetta_uuid::Uuid::new_v4().to_string();
    let _tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let mut conn = connect_tab(&client_id, token, &identity, &grant, &subject).await;
    conn.subscribe("photo-share-photos", "SELECT * FROM photos")
        .await
        .expect("photo subscribe");
    harness::pump_until(&mut conn, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;

    let (client, pump) = ConnettoClient::with_pump(conn);
    let (pump_done_tx, pump_done) = oneshot::channel::<()>();
    spawn_local(async move {
        pump.await;
        let _ = pump_done_tx.send(());
    });

    let live: LiveQuery<Photo> = photos::table
        .order(photos::id)
        .select(Photo::as_select())
        .live(&client)
        .await
        .expect("photo live query");
    let rows = live.rows().to_vec();

    assert_eq!(
        rows.iter()
            .map(|row| row.id.to_string())
            .collect::<Vec<_>>(),
        vec![shared.clone()],
        "the key's holder sees exactly the row its key owns"
    );
    assert_eq!(
        rows[0].owner_id, subject,
        "the row is owned by the key itself, not by the signed-in user"
    );
    assert_ne!(
        rows[0].owner_id, identity,
        "nothing about the identity reaches this row"
    );

    drop(live);
    drop(client);
    let _ = pump_done.await;
    worker.terminate();
}
