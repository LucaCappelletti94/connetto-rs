//! Offline photo staging through the real DB worker and later reconnect.

#![cfg(target_arch = "wasm32")]

mod common;
mod harness;

use connetto_client::dsl::Watchable;
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Grant, LiveQuery, Replica,
};
use connetto_file_core::{FileId, MimeClass};
use connetto_wasm_smoke::workers::{
    DEMO_TAB_DDL, PHOTO_CONNECT_CHANNEL, announce_tab, await_db_worker_ready,
};
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

fn spawn_offline_photo_worker(glue_url: &str) -> web_sys::Worker {
    let wasm_url = glue_url.strip_suffix(".js").map_or_else(
        || format!("{glue_url}_bg.wasm"),
        |base| format!("{base}_bg.wasm"),
    );
    let source = format!(
        "const debug = new BroadcastChannel(\"connetto-debug\");\ntry {{\n  debug.postMessage(\"db worker: importing {g}\");\n  const mod = await import(\"{g}\");\n  await mod.default({{ module_or_path: \"{w}\" }});\n  debug.postMessage(\"db worker: module ready, booting the db tier\");\n  await mod.db_worker_photo_offline_boot();\n  debug.postMessage(\"db worker: serving\");\n}} catch (err) {{\n  debug.postMessage(\"db worker FAILED: \" + err);\n  throw err;\n}}\n",
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
    worker_opts.set_name("connetto-db-photo-offline");
    let worker =
        web_sys::Worker::new_with_options(&url, &worker_opts).expect("spawn offline photo worker");
    let _ = web_sys::Url::revoke_object_url(&url);
    worker
}

fn open_photo_connect_gate() {
    let channel = BroadcastChannel::new(PHOTO_CONNECT_CHANNEL).expect("connect gate channel");
    channel
        .post_message(&wasm_bindgen::JsValue::from_str("connect"))
        .expect("open connect gate");
    channel.close();
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
    harness::stage("announcing tab");
    announce_tab(&wire).await.expect("announce the tab");
    harness::stage("tab announced");
    let mut transport = MessageTransport::<BroadcastChannel>::new(&wire).expect("wire channel");
    let content = TabContent::new(&mut transport);
    let config = ClientConfig::new(client_id.to_owned())
        .with_login(Some(Grant::new(token)))
        .with_schema_version(Some(connetto_wasm_smoke::demo_schema_version()))
        .with_sql_functions(connetto_wasm_smoke::uuidv4_functions())
        .with_policy_tables(connetto_wasm_smoke::demo_policy_tables())
        .with_caller(CALLER_FUNCTION, Some(identity))
        .with_subjects::<String>(connetto_wasm_smoke::SUBJECTS_FUNCTION, &[]);
    let conn = ConnettoConnection::connect(
        transport,
        &Replica::in_memory(),
        DEMO_TAB_DDL,
        &config,
        None,
    )
    .await
    .expect("tab connect through the wire channel");
    harness::stage("tab connected");
    (content, conn)
}
fn load_photos<T>(conn: &mut ConnettoConnection<T>) -> Vec<Photo>
where
    T: connetto_core::Transport,
{
    photos::table
        .order(photos::id)
        .select(Photo::as_select())
        .load(conn.conn())
        .expect("local read")
}

#[wasm_bindgen_test]
async fn an_offline_photo_replays_on_connect_and_flips_available() {
    harness::relay_worker_breadcrumbs();
    common::play_the_tab();
    let worker = spawn_offline_photo_worker(&harness::glue_url());
    await_db_worker_ready(&[]).await.expect("db worker ready");
    harness::stage("db worker booted");

    let (token, identity) = common::mint_session().await;
    let client_id = rosetta_uuid::Uuid::new_v4().to_string();
    let _tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let (content, mut conn) = connect_tab(&client_id, token.clone(), &identity).await;
    conn.subscribe("photo-offline-photos", "SELECT * FROM photos")
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
    client.replay_pending().await.expect("queue photo mutation");
    assert_eq!(file_id, FileId::from_chunks([bytes.as_slice()]));
    harness::stage("photo staged offline");

    let offline = loop {
        if let Some(photo) = live
            .rows()
            .iter()
            .find(|photo| photo.id == photo_id && photo.content_state.is_none())
            .cloned()
        {
            break photo;
        }
        live.changed().await.expect("photo refresh");
    };
    assert_eq!(offline.owner_id, identity);
    assert_eq!(offline.content_id, file_id.as_bytes().to_vec());
    assert!(matches!(
        content.resolve(file_id).await,
        TabResolved::Local { .. }
    ));
    harness::stage("photo present offline");

    let mut server = harness::connect_server(
        "photo-offline-server",
        harness::unique_base(),
        token,
        &identity,
    )
    .await;
    server
        .subscribe("photo-offline-server-photos", "SELECT * FROM photos")
        .await
        .expect("server photo subscribe");
    harness::pump_until(&mut server, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    assert!(
        !load_photos(&mut server)
            .iter()
            .any(|photo| photo.id == photo_id),
        "the server must not see the offline photo before connect"
    );
    harness::stage("server still empty");

    open_photo_connect_gate();
    harness::stage("connect gate opened");

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

    let url = match content.resolve(file_id).await {
        TabResolved::Remote { url } => url,
        TabResolved::Local { .. } => {
            panic!("a connected available photo must resolve to the server")
        }
        TabResolved::Unavailable => {
            panic!("a connected available photo must resolve")
        }
    };
    assert_eq!(fetch_bytes(&url).await, bytes);
    harness::stage("photo fetched");

    drop(server);
    drop(live);
    drop(content);
    drop(client);
    pump_done.await.expect("pump exited");
    worker.terminate();
}
