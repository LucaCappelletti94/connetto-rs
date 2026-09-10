use connetto_client::ExportScope;
use connetto_file_client::BrowserStore;
use connetto_file_core::{ChunkHash, ChunkStore};
use js_sys::Date;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::DedicatedWorkerGlobalScope;

use super::{content_store_namespace, request_export};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

#[wasm_bindgen_test]
async fn one_seed_keeps_two_account_replicas_in_separate_content_namespaces() {
    let worker: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let alice = content_store_namespace("shared-seed", "replica-alice");
    let bob = content_store_namespace("shared-seed", "replica-bob");
    let hash = ChunkHash::from_bytes([0x41; 32]);
    BrowserStore::remove(&worker, &alice)
        .await
        .expect("clear alice store");
    BrowserStore::remove(&worker, &bob)
        .await
        .expect("clear bob store");

    let alice_store = BrowserStore::install(&worker, &alice)
        .await
        .expect("open alice store");
    alice_store
        .write_chunk(&hash, b"alice content")
        .await
        .expect("stage alice content");
    let bob_store = BrowserStore::install(&worker, &bob)
        .await
        .expect("open bob store");

    assert_ne!(alice, bob);
    assert!(!bob_store.has_chunk(&hash).await.expect("probe bob store"));
    BrowserStore::remove(&worker, &alice)
        .await
        .expect("remove alice store");
    BrowserStore::remove(&worker, &bob)
        .await
        .expect("remove bob store");
}

#[wasm_bindgen_test]
async fn export_without_a_worker_follows_the_liveness_lock() {
    let started = Date::now();
    let error = request_export(ExportScope::Unsynced)
        .await
        .expect_err("no worker can answer");

    assert!(matches!(error, crate::relay::ExportRefused::Gone(_)));
    assert!(
        Date::now() - started < 1_000.0,
        "worker absence must not wait for an archive-size deadline"
    );
}
