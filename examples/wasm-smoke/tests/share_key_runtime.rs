//! Share keys added and removed in a running browser, through the real DB
//! worker and server (R95 step 6).
//!
//! A tab's call reaches the worker that holds the keys, every tab of the relay
//! answers its views with the result, the server resends the rows the key
//! reaches, and the worker keeps the key across a restart.

#![cfg(target_arch = "wasm32")]

mod common;
mod harness;

use core::time::Duration;

use connetto_client::dsl::Watchable;
use connetto_client::{
    ClientBuilder, ClientEvent, ConnettoClient, ConnettoConnection, Grant, LiveQuery,
};
use connetto_core::auth::CapabilitySubject;
use connetto_wasm_smoke::build::Once;
use connetto_wasm_smoke::workers::{announce_tab, await_db_worker_ready, demo_schema, sleep};
use connetto_wasm_smoke::{MessageTransport, locks};
use diesel::prelude::*;
use futures_channel::oneshot;
use js_sys::Array;
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::BroadcastChannel;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// How long a tab may take to show what the worker and server settled.
const SETTLE: Duration = Duration::from_secs(20);

diesel::table! {
    photos (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = photos)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Photo {
    id: rosetta_uuid::Uuid,
    owner_id: String,
}

/// Boot the photo tier in a worker holding no share key.
fn spawn_photo_worker() -> web_sys::Worker {
    let glue_url = harness::glue_url();
    let wasm_url = glue_url.strip_suffix(".js").map_or_else(
        || format!("{glue_url}_bg.wasm"),
        |base| format!("{base}_bg.wasm"),
    );
    let source = format!(
        "const debug = new BroadcastChannel(\"connetto-debug\");\ntry {{\n  const mod = await import(\"{glue_url}\");\n  await mod.default({{ module_or_path: \"{wasm_url}\" }});\n  await mod.db_worker_photo_boot();\n  debug.postMessage(\"db worker: serving\");\n}} catch (err) {{\n  debug.postMessage(\"db worker FAILED: \" + err);\n  throw err;\n}}\n",
    );
    let parts = Array::of1(&wasm_bindgen::JsValue::from_str(&source));
    let blob_opts = web_sys::BlobPropertyBag::new();
    blob_opts.set_type("text/javascript");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &blob_opts)
        .expect("bootstrap blob");
    let url = web_sys::Url::create_object_url_with_blob(&blob).expect("bootstrap url");
    let worker_opts = web_sys::WorkerOptions::new();
    worker_opts.set_type(web_sys::WorkerType::Module);
    worker_opts.set_name("connetto-db-share-runtime");
    let worker = web_sys::Worker::new_with_options(&url, &worker_opts).expect("spawn photo worker");
    let _ = web_sys::Url::revoke_object_url(&url);
    worker
}

/// A relay tab whose mirror routes share-key changes to the worker.
async fn connect_tab(client_id: &str) -> ConnettoConnection<MessageTransport<BroadcastChannel>> {
    let wire = format!("connetto-wire-{client_id}");
    announce_tab(&wire).await.expect("announce the tab");
    let transport = MessageTransport::<BroadcastChannel>::new(&wire).expect("wire channel");
    ClientBuilder::new(demo_schema().relay_mirror(), Once::new(transport))
        .with_client_id(client_id)
        .connect_driven()
        .await
        .expect("tab connect through the wire channel")
}
/// One tab of the worker, its lock held, its pump running, watching photos.
struct Tab {
    client: ConnettoClient<MessageTransport<BroadcastChannel>>,
    live: LiveQuery<Photo>,
    pumped: oneshot::Receiver<()>,
    _lock: locks::HeldLock,
}

impl Tab {
    async fn open(name: &str) -> Self {
        let client_id = format!("{name}-{}", rosetta_uuid::Uuid::new_v4());
        let lock = locks::hold_lock(&locks::tab_lock_name(&client_id)).await;
        let mut conn = connect_tab(&client_id).await;
        conn.subscribe(&format!("{name}-photos"), "SELECT * FROM photos")
            .await
            .expect("photo subscribe");
        harness::pump_until(&mut conn, |event| {
            matches!(event, ClientEvent::SnapshotEnd { .. })
        })
        .await;
        let (client, pump) = ConnettoClient::with_pump(conn);
        let (done, pumped) = oneshot::channel::<()>();
        spawn_local(async move {
            pump.await;
            let _ = done.send(());
        });
        let live = photos::table
            .order(photos::id)
            .select(Photo::as_select())
            .live(&client)
            .await
            .expect("photo live query");
        Self {
            client,
            live,
            pumped,
            _lock: lock,
        }
    }

    fn shows(&self, photo: &str) -> bool {
        self.live
            .rows()
            .iter()
            .any(|row| row.id.to_string() == photo)
    }

    /// Wait until the tab shows `photo` or not, failing after [`SETTLE`].
    async fn settle(&self, photo: &str, shown: bool) {
        let deadline = js_sys::Date::now() + SETTLE.as_secs_f64() * 1000.0;
        while self.shows(photo) != shown {
            assert!(
                js_sys::Date::now() < deadline,
                "the tab {} the photo its key reaches",
                if shown { "never showed" } else { "still shows" }
            );
            sleep(Duration::from_millis(50)).await;
        }
    }

    async fn close(self) {
        let Self {
            client,
            live,
            pumped,
            ..
        } = self;
        drop(live);
        drop(client);
        let _ = pumped.await;
    }
}

#[wasm_bindgen_test]
async fn a_tab_key_reaches_every_tab_and_survives_a_restart() {
    harness::relay_worker_breadcrumbs();
    common::play_the_tab();
    let (grant, subject, shared) = connetto_wasm_smoke::fetch_share()
        .await
        .expect("the browser stack serves the share key it minted");
    let grant = Grant::new(grant);
    let subject = CapabilitySubject::<String>::new(subject);

    let worker = spawn_photo_worker();
    await_db_worker_ready(&[]).await.expect("db worker ready");
    let first = Tab::open("share-first").await;
    let second = Tab::open("share-second").await;
    assert!(!first.shows(&shared), "no tab sees the row before its key");
    assert!(!second.shows(&shared), "no tab sees the row before its key");
    harness::stage("two tabs watch photos without the key");

    first
        .client
        .add_share_key(&grant, &subject)
        .await
        .expect("the worker holds the key");
    first.settle(&shared, true).await;
    second.settle(&shared, true).await;
    harness::stage("both tabs see the row the added key reaches");

    first.close().await;
    second.close().await;
    worker.terminate();
    let worker = spawn_photo_worker();
    await_db_worker_ready(&[])
        .await
        .expect("db worker ready again");
    let first = Tab::open("share-restarted").await;
    let second = Tab::open("share-restarted-second").await;
    first.settle(&shared, true).await;
    harness::stage("the restarted worker still holds the key");

    second
        .client
        .remove_share_key(&subject)
        .await
        .expect("the worker drops the key");
    second.settle(&shared, false).await;
    first.settle(&shared, false).await;
    harness::stage("both tabs lose the row once the key is removed");

    first.close().await;
    second.close().await;
    worker.terminate();
    let worker = spawn_photo_worker();
    await_db_worker_ready(&[])
        .await
        .expect("db worker ready a third time");
    let third = Tab::open("share-removed").await;
    third.settle(&shared, false).await;
    assert!(!third.shows(&shared), "the removal survives a restart");
    third.close().await;
    worker.terminate();
}
