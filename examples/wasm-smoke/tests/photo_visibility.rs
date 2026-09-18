//! Photo visibility through the real DB worker and content routes.

#![cfg(target_arch = "wasm32")]

mod common;
mod harness;

use connetto_client::dsl::Watchable;
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Grant, LiveQuery, Replica,
};
use connetto_file_client::{BrowserHttp, BrowserStore, ContentClient, ContentError};
use connetto_file_core::{FileId, MimeClass};
use connetto_wasm_smoke::workers::{DEMO_TAB_DDL, announce_tab, await_db_worker_ready};
use connetto_wasm_smoke::{CALLER_FUNCTION, MessageTransport, locks};
use connetto_web::{TabContent, TabResolved};
use diesel::prelude::*;
use futures_channel::oneshot;
use js_sys::{Array, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{JsFuture, spawn_local};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{BroadcastChannel, DedicatedWorkerGlobalScope, Response};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        quantity -> diesel::sql_types::BigInt,
    }
}

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

fn photo_bytes() -> Vec<u8> {
    const SEED: [u8; 16] = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let mut bytes = Vec::with_capacity(4096);
    while bytes.len() < 4096 {
        bytes.extend_from_slice(&SEED);
    }
    bytes.truncate(4096);
    bytes
}

fn blob_of(bytes: &[u8]) -> web_sys::Blob {
    let array = Uint8Array::from(bytes);
    web_sys::Blob::new_with_u8_array_sequence(&Array::of1(&array)).expect("blob from bytes")
}

async fn fetch_bytes(url: &str) -> Vec<u8> {
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("dedicated worker");
    let response: Response = JsFuture::from(scope.fetch_with_str(url))
        .await
        .expect("fetch content")
        .dyn_into()
        .expect("response");
    assert!(
        response.ok(),
        "content fetch ended at {} with status {}",
        response.url(),
        response.status()
    );
    let buffer = JsFuture::from(response.array_buffer().expect("array buffer promise"))
        .await
        .expect("array buffer");
    Uint8Array::new(&buffer).to_vec()
}

fn spawn_photo_worker(glue_url: &str) -> web_sys::Worker {
    let wasm_url = glue_url.strip_suffix(".js").map_or_else(
        || format!("{glue_url}_bg.wasm"),
        |base| format!("{base}_bg.wasm"),
    );
    let source = format!(
        "const debug = new BroadcastChannel(\"connetto-debug\");\ntry {{\n  debug.postMessage(\"db worker: importing {g}\");\n  const mod = await import(\"{g}\");\n  await mod.default({{ module_or_path: \"{w}\" }});\n  debug.postMessage(\"db worker: module ready, booting the db tier\");\n  await mod.db_worker_photo_boot();\n  debug.postMessage(\"db worker: serving\");\n}} catch (err) {{\n  debug.postMessage(\"db worker FAILED: \" + err);\n  throw err;\n}}\n",
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
    worker_opts.set_name("connetto-db-photo");
    let worker = web_sys::Worker::new_with_options(&url, &worker_opts).expect("spawn photo worker");
    let _ = web_sys::Url::revoke_object_url(&url);
    worker
}

async fn connect_tab(
    client_id: &str,
    token: String,
    identity: &str,
) -> (
    TabContent<BroadcastChannel>,
    ConnettoConnection<MessageTransport<BroadcastChannel>>,
) {
    let wire = format!("connetto-wire-{client_id}");
    announce_tab(&wire).await.expect("announce the tab");
    let mut transport = MessageTransport::<BroadcastChannel>::new(&wire).expect("wire channel");
    let content = TabContent::new(&mut transport);
    let config = ClientConfig::new(client_id.to_owned())
        .with_login(Some(Grant::new(token)))
        .with_schema_version(Some(connetto_wasm_smoke::demo_schema_version()))
        .with_sql_functions(connetto_wasm_smoke::uuidv4_functions())
        .with_policy_tables(connetto_wasm_smoke::demo_policy_tables())
        .with_caller(CALLER_FUNCTION, identity);
    let conn = ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        DEMO_TAB_DDL,
        &config,
        None,
    )
    .await
    .expect("tab connect through the wire channel");
    (content, conn)
}

#[wasm_bindgen_test]
async fn a_second_viewer_cannot_resolve_another_users_photo() {
    harness::relay_worker_breadcrumbs();
    common::play_the_tab();
    let worker = spawn_photo_worker(&harness::glue_url());
    await_db_worker_ready(&[]).await.expect("db worker ready");
    harness::stage("db worker booted");

    let (token, identity) = common::mint_session().await;
    let client_id = rosetta_uuid::Uuid::new_v4().to_string();
    let _tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let (content, mut conn) = connect_tab(&client_id, token, &identity).await;
    conn.subscribe("photo-visibility-photos", "SELECT * FROM photos")
        .await
        .expect("photo subscribe");
    harness::pump_until(&mut conn, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    harness::stage("photo subscription ready");

    let (client, pump) = ConnettoClient::with_pump(conn);
    let (pump_done_tx, pump_done) = oneshot::channel::<()>();
    spawn_local(async move {
        pump.await;
        let _ = pump_done_tx.send(());
    });

    let mut live: LiveQuery<Photo> = photos::table
        .order(photos::id)
        .select(Photo::as_select())
        .live(&client)
        .await
        .expect("photo live query");

    let bytes = photo_bytes();
    let blob = blob_of(&bytes);
    let (file_id, photo_id) = content
        .stage(&blob, MimeClass::Jpeg, &client, |connection, file_id| {
            connection.transaction(|connection| {
                let before_orders: std::collections::HashSet<rosetta_uuid::Uuid> = orders::table
                    .select(orders::id)
                    .load::<rosetta_uuid::Uuid>(connection)?
                    .into_iter()
                    .collect();
                diesel::insert_into(orders::table)
                    .values((
                        orders::owner_id.eq(identity.as_str()),
                        orders::quantity.eq(5_i64),
                    ))
                    .execute(connection)?;
                let order_id = orders::table
                    .select(orders::id)
                    .load::<rosetta_uuid::Uuid>(connection)?
                    .into_iter()
                    .find(|id| !before_orders.contains(id))
                    .expect("minted order id");

                let before_photos: std::collections::HashSet<rosetta_uuid::Uuid> = photos::table
                    .select(photos::id)
                    .load::<rosetta_uuid::Uuid>(connection)?
                    .into_iter()
                    .collect();
                diesel::insert_into(photos::table)
                    .values((
                        photos::order_id.eq(order_id),
                        photos::owner_id.eq(identity.as_str()),
                        photos::content_id.eq(file_id.as_bytes().to_vec()),
                        photos::content_state.eq::<Option<String>>(None),
                    ))
                    .execute(connection)?;
                Ok::<rosetta_uuid::Uuid, diesel::result::Error>(
                    photos::table
                        .select(photos::id)
                        .load::<rosetta_uuid::Uuid>(connection)?
                        .into_iter()
                        .find(|id| !before_photos.contains(id))
                        .expect("minted photo id"),
                )
            })
        })
        .await
        .expect("stage photo and write rows");
    client.replay_pending().await.expect("send photo mutation");
    assert_eq!(file_id, FileId::from_chunks([bytes.as_slice()]));
    harness::stage("photo staged");

    let available = loop {
        if let Some(photo) = live
            .rows()
            .iter()
            .find(|photo| {
                photo.id == photo_id && photo.content_state.as_deref() == Some("available")
            })
            .cloned()
        {
            break photo;
        }
        live.changed().await.expect("photo refresh");
    };
    assert_eq!(available.owner_id, identity);
    assert_eq!(available.content_id, file_id.as_bytes().to_vec());
    harness::stage("photo available");

    // Owner resolves first, then the viewer gets Unavailable, then the owner
    // resolves again. That order proves policy refusal rather than timing.
    let owner_url = match content.resolve(file_id).await {
        TabResolved::Remote { url } => url,
        TabResolved::Local { .. } => {
            panic!("an uploaded available photo must resolve to the server")
        }
        TabResolved::Unavailable => panic!("an available photo must resolve"),
    };
    assert_eq!(fetch_bytes(&owner_url).await, bytes);
    harness::stage("owner fetched");

    let (viewer_token, viewer_identity) = common::mint_session_as("viewer").await;
    let viewer_conn = harness::connect_server(
        "photo-visibility-viewer",
        harness::unique_base(),
        viewer_token,
        &viewer_identity,
    )
    .await;
    let (viewer_client, viewer_pump) = ConnettoClient::with_pump(viewer_conn);
    let (viewer_done_tx, viewer_done) = oneshot::channel::<()>();
    spawn_local(async move {
        viewer_pump.await;
        let _ = viewer_done_tx.send(());
    });
    let viewer_content = ContentClient::attach(
        viewer_client,
        BrowserStore::ephemeral(),
        [7; 32],
        BrowserHttp::new(),
    )
    .await
    .expect("attach viewer content client");
    match viewer_content.resolve(file_id).await {
        Err(ContentError::TicketRefused { file_id: refused }) if refused == file_id => {}
        other => {
            panic!("the second viewer must be refused another user's photo, got {other:?}")
        }
    }
    harness::stage("viewer refused");
    drop(viewer_content);
    viewer_done.await.expect("viewer pump exited");

    let owner_url = match content.resolve(file_id).await {
        TabResolved::Remote { url } => url,
        TabResolved::Local { .. } => panic!("owner access must survive the viewer refusal"),
        TabResolved::Unavailable => panic!("owner access must survive the viewer refusal"),
    };
    assert_eq!(fetch_bytes(&owner_url).await, bytes);
    harness::stage("owner fetched again");

    drop(live);
    drop(content);
    drop(client);
    pump_done.await.expect("pump exited");
    worker.terminate();
}
