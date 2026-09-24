//! A pinned photo stays in the browser and heals the server's copy after the store is lost.

#![cfg(target_arch = "wasm32")]

mod common;
mod harness;
mod photo;

use connetto_client::dsl::Watchable;
use connetto_client::{ClientEvent, ConnettoClient, LiveQuery};
use connetto_file_client::{BrowserHttp, BrowserStore, ContentClient, Resolved};
use connetto_file_core::FileId;
use connetto_wasm_smoke::locks;
use connetto_wasm_smoke::workers::await_db_worker_ready;
use connetto_web::TabResolved;
use diesel::prelude::*;
use futures_channel::oneshot;
use js_sys::Uint8Array;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{JsFuture, spawn_local};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{Request, RequestInit, Response, WorkerGlobalScope};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

fn hex_of(file_id: FileId) -> String {
    file_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Deletes the stored bytes of `files` and restarts the server, which marks them lost.
async fn lose_the_server_copies(files: &[FileId]) {
    let body: Vec<String> = files.iter().copied().map(hex_of).collect();
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_body(&body.join(" ").into());
    let request =
        Request::new_with_str_and_init(&format!("{}/dev/lose-content", common::AUTH_BASE), &init)
            .expect("build the lose-content request");
    let scope = js_sys::global()
        .dyn_into::<WorkerGlobalScope>()
        .expect("worker scope");
    let response: Response = JsFuture::from(scope.fetch_with_request(&request))
        .await
        .expect("the browser stack must be running")
        .dyn_into()
        .expect("response");
    assert!(
        response.ok(),
        "the stack refused to lose the content with status {}",
        response.status()
    );
}

async fn blob_bytes(blob: &web_sys::Blob) -> Vec<u8> {
    let buffer = JsFuture::from(blob.array_buffer())
        .await
        .expect("blob bytes");
    Uint8Array::new(&buffer).to_vec()
}

#[wasm_bindgen_test]
async fn a_pinned_photo_stays_local_and_heals_the_lost_server_copy() {
    harness::relay_worker_breadcrumbs();
    common::play_the_tab();
    let worker = photo::spawn_photo_worker(&harness::glue_url());
    await_db_worker_ready(&[]).await.expect("db worker ready");
    harness::stage("db worker booted");

    let (token, identity) = common::mint_session().await;
    let client_id = rosetta_uuid::Uuid::new_v4().to_string();
    let _tab_lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
    let (content, mut conn) = photo::connect_tab(&client_id, token, &identity).await;
    conn.subscribe("photo-heal-photos", "SELECT * FROM photos")
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
    let mut live: LiveQuery<photo::Photo> = photo::photos::table
        .order(photo::photos::id)
        .select(photo::Photo::as_select())
        .live(&client)
        .await
        .expect("photo live query");
    harness::stage("photo subscription ready");

    let kept = photo::photo_bytes(1);
    let kept_id = FileId::from_chunks([kept.as_slice()]);
    let pin_query = format!(
        "SELECT content_id FROM photos WHERE content_id = X'{}'",
        hex_of(kept_id)
    );
    content
        .pin_content("photo-heal-kept", &pin_query, "content_id")
        .await
        .expect("pin the kept photo");
    assert_eq!(
        content.content_pins().await.expect("list pins"),
        vec![(
            "photo-heal-kept".to_owned(),
            pin_query.clone(),
            "content_id".to_owned()
        )]
    );
    harness::stage("kept photo pinned");

    let loose = photo::photo_bytes(2);
    let (_, kept_photo) = photo::stage_photo(&content, &client, &identity, &kept).await;
    let (loose_id, loose_photo) = photo::stage_photo(&content, &client, &identity, &loose).await;
    photo::until_state(&mut live, kept_photo, "available").await;
    photo::until_state(&mut live, loose_photo, "available").await;
    harness::stage("both photos available");

    match content.resolve(kept_id).await {
        TabResolved::Local { blob } => assert_eq!(blob_bytes(&blob).await, kept),
        other => panic!("a pinned uploaded photo must stay in the browser, got {other:?}"),
    }
    match content.resolve(loose_id).await {
        TabResolved::Remote { .. } => {}
        other => panic!("an unpinned uploaded photo must leave the browser, got {other:?}"),
    }
    harness::stage("pinned photo local, unpinned photo remote");

    lose_the_server_copies(&[kept_id, loose_id]).await;
    harness::stage("server content lost");
    photo::until_state(&mut live, loose_photo, "lost").await;
    photo::until_state(&mut live, kept_photo, "lost").await;
    photo::until_state(&mut live, kept_photo, "available").await;
    harness::stage("pinned photo healed");

    let (other_token, other_identity) = common::mint_session().await;
    let other = harness::connect_server(
        "photo-heal-other",
        harness::unique_base(),
        other_token,
        &other_identity,
    )
    .await;
    let (other_client, other_pump) = ConnettoClient::with_pump(other);
    let (other_done_tx, other_done) = oneshot::channel::<()>();
    spawn_local(async move {
        other_pump.await;
        let _ = other_done_tx.send(());
    });
    let other_content = ContentClient::attach(
        other_client,
        BrowserStore::ephemeral(),
        [9; 32],
        BrowserHttp::new(),
    )
    .await
    .expect("attach the other device's content client");
    match other_content.resolve(kept_id).await {
        Ok(Resolved::Remote { url }) => assert_eq!(photo::fetch_bytes(&url).await, kept),
        other => panic!("the healed photo must be served again, got {other:?}"),
    }
    harness::stage("healed photo served to another device");
    drop(other_content);
    other_done.await.expect("other pump exited");

    content
        .unpin_content("photo-heal-kept")
        .await
        .expect("unpin the kept photo");
    assert!(content.content_pins().await.expect("list pins").is_empty());
    assert!(
        live.rows()
            .iter()
            .any(|photo| photo.id == loose_photo && photo.content_state.as_deref() == Some("lost")),
        "no device holds the unpinned photo, so it stays lost"
    );

    drop(live);
    drop(content);
    drop(client);
    pump_done.await.expect("pump exited");
    worker.terminate();
}
