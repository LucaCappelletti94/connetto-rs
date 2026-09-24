//! Photo visibility through the real DB worker and content routes.

#![cfg(target_arch = "wasm32")]

mod common;
mod harness;
mod photo;

use connetto_client::dsl::Watchable;
use connetto_client::{ClientEvent, ConnettoClient, LiveQuery};
use connetto_file_client::{BrowserHttp, BrowserStore, ContentClient, ContentError};
use connetto_wasm_smoke::locks;
use connetto_wasm_smoke::workers::await_db_worker_ready;
use connetto_web::TabResolved;
use diesel::prelude::*;
use futures_channel::oneshot;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn a_second_viewer_cannot_resolve_another_users_photo() {
    harness::relay_worker_breadcrumbs();
    common::play_the_tab();
    let worker = photo::spawn_photo_worker(&harness::glue_url());
    await_db_worker_ready(&[]).await.expect("db worker ready");
    harness::stage("db worker booted");

    let (token, identity) = common::mint_session().await;
    let client_id = rosetta_uuid::Uuid::new_v4().to_string();
    let _tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let (content, mut conn) = photo::connect_tab(&client_id, token, &identity).await;
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

    let mut live: LiveQuery<photo::Photo> = photo::photos::table
        .order(photo::photos::id)
        .select(photo::Photo::as_select())
        .live(&client)
        .await
        .expect("photo live query");

    let bytes = photo::photo_bytes(0);
    let (file_id, photo_id) = photo::stage_photo(&content, &client, &identity, &bytes).await;
    harness::stage("photo staged");

    let available = photo::until_state(&mut live, photo_id, "available").await;
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
    assert_eq!(photo::fetch_bytes(&owner_url).await, bytes);
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
    assert_eq!(photo::fetch_bytes(&owner_url).await, bytes);
    harness::stage("owner fetched again");

    drop(live);
    drop(content);
    drop(client);
    pump_done.await.expect("pump exited");
    worker.terminate();
}
