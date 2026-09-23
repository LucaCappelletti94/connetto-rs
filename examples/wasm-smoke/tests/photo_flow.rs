//! Photo staging through the real DB worker and content routes.

#![cfg(target_arch = "wasm32")]

mod common;
mod harness;
mod photo;

use connetto_client::dsl::Watchable;
use connetto_client::{ConnettoClient, LiveQuery};
use connetto_wasm_smoke::locks;
use connetto_wasm_smoke::workers::await_db_worker_ready;
use connetto_web::TabResolved;
use diesel::prelude::*;
use futures_channel::oneshot;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn a_photo_round_trips_through_stage_commit_resolve_and_http_fetch() {
    harness::relay_worker_breadcrumbs();
    common::play_the_tab();
    let worker = photo::spawn_photo_worker(&harness::glue_url());
    await_db_worker_ready(&[]).await.expect("db worker ready");
    harness::stage("db worker booted");

    let (token, identity) = common::mint_session().await;
    let client_id = rosetta_uuid::Uuid::new_v4().to_string();
    let _tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let (content, mut conn) = photo::connect_tab(&client_id, token, &identity).await;
    conn.subscribe("photo-flow-photos", "SELECT * FROM photos")
        .await
        .expect("photo subscribe");
    harness::pump_until(&mut conn, |event| {
        matches!(event, connetto_client::ClientEvent::SnapshotEnd { .. })
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

    let url = match content.resolve(file_id).await {
        TabResolved::Remote { url } => url,
        TabResolved::Local { .. } => {
            panic!("an uploaded available photo must resolve to the server")
        }
        TabResolved::Unavailable => {
            panic!("an available photo must resolve")
        }
    };
    assert_eq!(photo::fetch_bytes(&url).await, bytes);
    harness::stage("photo fetched");

    drop(live);
    drop(content);
    drop(client);
    pump_done.await.expect("pump exited");
    worker.terminate();
}
