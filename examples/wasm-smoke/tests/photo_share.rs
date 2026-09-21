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

/// A tab, holding the key the worker booted with or holding none.
///
/// The tab reads its own replica, so it registers what it holds. A tab given
/// only the identity is shown nothing of the key's rows, whatever the worker
/// holds, which is the second half of this suite.
async fn connect_tab(
    client_id: &str,
    token: String,
    identity: &str,
    key: Option<(&str, &str)>,
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
            key.map(|(grant, subject)| {
                (
                    Grant::new(grant.to_owned()),
                    connetto_core::auth::CapabilitySubject::new(subject.to_owned()),
                )
            }),
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

/// A caller holding only a share key sees the row that key owns, and the same
/// caller without the key does not.
///
/// The row is owned by the key's own rendering, so the signed-in identity
/// reaches it by no route at all. Presence rather than exclusivity is what is
/// asserted, because the demo identity owns photos other suites wrote against
/// the same deployment, and those are its own rows by the identity arm.
#[wasm_bindgen_test]
async fn a_key_holder_sees_the_row_its_key_owns() {
    harness::relay_worker_breadcrumbs();
    common::play_the_tab();

    let (grant, subject, shared) = connetto_wasm_smoke::fetch_share()
        .await
        .expect("the browser stack serves the share key it minted");

    let worker = spawn_share_worker(&harness::glue_url());
    await_db_worker_ready(&[]).await.expect("db worker ready");

    let (token, identity) = common::mint_session().await;
    let client_id = rosetta_uuid::Uuid::new_v4().to_string();
    let _tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let mut conn = connect_tab(&client_id, token, &identity, Some((&grant, &subject))).await;
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
    let held = live
        .rows()
        .iter()
        .find(|row| row.id.to_string() == shared)
        .cloned()
        .expect("the key's holder sees the row its key owns");
    assert_eq!(
        held.owner_id, subject,
        "the row is owned by the key itself, not by the signed-in user"
    );
    assert_ne!(
        held.owner_id, identity,
        "nothing about the identity reaches this row"
    );

    drop(live);
    drop(client);
    let _ = pump_done.await;

    // The same identity, the same worker, no key: the row goes away. This is
    // what makes the assertion above about the key rather than about the row
    // existing at all.
    let bare_id = rosetta_uuid::Uuid::new_v4().to_string();
    let _bare_lock = locks::hold_lock(&locks::tab_lock_name(&bare_id)).await;
    let (bare_token, bare_identity) = common::mint_session().await;
    let mut bare = connect_tab(&bare_id, bare_token, &bare_identity, None).await;
    bare.subscribe("photo-share-bare", "SELECT * FROM photos")
        .await
        .expect("photo subscribe");
    harness::pump_until(&mut bare, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    let (bare_client, bare_pump) = ConnettoClient::with_pump(bare);
    let (bare_done_tx, bare_done) = oneshot::channel::<()>();
    spawn_local(async move {
        bare_pump.await;
        let _ = bare_done_tx.send(());
    });
    let bare_live: LiveQuery<Photo> = photos::table
        .order(photos::id)
        .select(Photo::as_select())
        .live(&bare_client)
        .await
        .expect("photo live query");
    assert!(
        !bare_live
            .rows()
            .iter()
            .any(|row| row.id.to_string() == shared),
        "a caller holding no key does not see the row the key owns"
    );

    drop(bare_live);
    drop(bare_client);
    let _ = bare_done.await;
    worker.terminate();
}
