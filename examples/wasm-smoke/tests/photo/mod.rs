//! What every photo suite shares, the photo worker, a tab on it, staging and the live wait.

#![cfg(target_arch = "wasm32")]

use connetto_client::{ClientBuilder, ConnettoClient, ConnettoConnection, LiveQuery};
use connetto_file_core::{FileId, MimeClass};
use connetto_wasm_smoke::MessageTransport;
use connetto_wasm_smoke::build::Once;
use connetto_wasm_smoke::workers::announce_tab;
use connetto_wasm_smoke::workers::demo_schema;
use connetto_web::TabContent;
use diesel::prelude::*;
use js_sys::{Array, Uint8Array};
use wasm_bindgen::JsCast;

use wasm_bindgen_futures::JsFuture;
use web_sys::{BroadcastChannel, DedicatedWorkerGlobalScope, Response};

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        quantity -> diesel::sql_types::BigInt,
        created_at -> diesel::sql_types::Timestamp,
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
pub struct Photo {
    pub id: rosetta_uuid::Uuid,
    pub order_id: rosetta_uuid::Uuid,
    pub owner_id: String,
    pub content_id: Vec<u8>,
    pub content_state: Option<String>,
}

/// Four kilobytes of photo, distinct per `salt`.
pub fn photo_bytes(salt: u8) -> Vec<u8> {
    const SEED: [u8; 16] = [
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let mut bytes = Vec::with_capacity(4096);
    while bytes.len() < 4096 {
        bytes.extend_from_slice(&SEED);
    }
    bytes.truncate(4096);
    bytes[0] = bytes[0].wrapping_add(salt);
    bytes
}

pub fn blob_of(bytes: &[u8]) -> web_sys::Blob {
    let array = Uint8Array::from(bytes);
    web_sys::Blob::new_with_u8_array_sequence(&Array::of1(&array)).expect("blob from bytes")
}

pub async fn fetch_bytes(url: &str) -> Vec<u8> {
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

pub fn spawn_photo_worker(
    glue_url: &str,
) -> (web_sys::Worker, connetto_web::workers::BootIdentity) {
    connetto_web::workers::spawn_db_worker(
        glue_url,
        &connetto_web::workers::WorkerBootstrap::GeneratedCalling(
            "db_worker_photo_boot()".to_owned(),
        ),
    )
    .expect("spawn the photo worker")
}

pub async fn connect_tab(
    client_id: &str,
) -> (
    TabContent<BroadcastChannel>,
    ConnettoConnection<MessageTransport<BroadcastChannel>>,
) {
    let wire = format!("connetto-wire-{client_id}");
    announce_tab(&wire).await.expect("announce the tab");
    let mut transport = MessageTransport::<BroadcastChannel>::new(&wire).expect("wire channel");
    let content = TabContent::new(&mut transport);
    let conn = ClientBuilder::new(demo_schema().relay_mirror(), Once::new(transport))
        .with_client_id(client_id.to_owned())
        .connect_driven()
        .await
        .expect("tab connect through the wire channel");
    (content, conn)
}

/// Stages `bytes` as a photo on a new order owned by `identity`, returning the file and row ids.
pub async fn stage_photo(
    content: &TabContent<BroadcastChannel>,
    client: &ConnettoClient<MessageTransport<BroadcastChannel>>,
    identity: &str,
    bytes: &[u8],
) -> (FileId, rosetta_uuid::Uuid) {
    let staged = content
        .stage(
            &blob_of(bytes),
            MimeClass::Jpeg,
            client,
            |connection, file_id| {
                connection.transaction(|connection| {
                    let before_orders: std::collections::HashSet<rosetta_uuid::Uuid> =
                        orders::table
                            .select(orders::id)
                            .load::<rosetta_uuid::Uuid>(connection)?
                            .into_iter()
                            .collect();
                    diesel::insert_into(orders::table)
                        .values((orders::owner_id.eq(identity), orders::quantity.eq(5_i64)))
                        .execute(connection)?;
                    let order_id = orders::table
                        .select(orders::id)
                        .load::<rosetta_uuid::Uuid>(connection)?
                        .into_iter()
                        .find(|id| !before_orders.contains(id))
                        .expect("minted order id");

                    let before_photos: std::collections::HashSet<rosetta_uuid::Uuid> =
                        photos::table
                            .select(photos::id)
                            .load::<rosetta_uuid::Uuid>(connection)?
                            .into_iter()
                            .collect();
                    diesel::insert_into(photos::table)
                        .values((
                            photos::order_id.eq(order_id),
                            photos::owner_id.eq(identity),
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
            },
        )
        .await
        .expect("stage photo and write rows");
    client.replay_pending().await.expect("send photo mutation");
    assert_eq!(staged.0, FileId::from_chunks([bytes]));
    staged
}

/// Waits until the live photo `photo_id` reads `state`.
pub async fn until_state(
    live: &mut LiveQuery<Photo>,
    photo_id: rosetta_uuid::Uuid,
    state: &str,
) -> Photo {
    loop {
        if let Some(photo) = live
            .rows()
            .iter()
            .find(|photo| photo.id == photo_id && photo.content_state.as_deref() == Some(state))
            .cloned()
        {
            return photo;
        }
        live.changed().await.expect("photo refresh");
    }
}
