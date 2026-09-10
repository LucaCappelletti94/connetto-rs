use connetto_file_core::{ChunkHash, ChunkInventory, ChunkStore};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::DedicatedWorkerGlobalScope;

use super::opfs_api::type_error;
use super::{BrowserStore, BrowserStoreError, OpfsStore};

wasm_bindgen_test_configure!(run_in_dedicated_worker);
#[wasm_bindgen_test]
fn unexpected_browser_types_are_definitive_read_failures() {
    let store = BrowserStore::ephemeral();
    assert!(
        store.read_failure_is_ambiguous(&BrowserStoreError::Browser {
            operation: "read chunk file",
            message: "temporarily unavailable".to_owned(),
        })
    );
    let unexpected = type_error("decode chunk file", &JsValue::NULL);
    assert!(!store.read_failure_is_ambiguous(&unexpected));
}

#[wasm_bindgen_test]
async fn inventory_excludes_a_closed_chunk_until_atomic_landing() {
    let worker: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let store = OpfsStore::open(&worker, "r68-atomic-landing")
        .await
        .expect("open OPFS");
    let hash = ChunkHash::from_bytes([0x53; 32]);
    store.delete_chunk(&hash).await.expect("clear old chunk");
    let pending = store
        .stage_chunk(&hash, b"complete bytes")
        .await
        .expect("stage chunk");
    assert!(!store.has_chunk(&hash).await.expect("probe staged chunk"));
    assert!(
        !store
            .stored_hashes()
            .await
            .expect("list staged store")
            .contains(&hash)
    );

    store.land_chunk(pending).await.expect("land chunk");
    assert_eq!(
        store.read_chunk(&hash).await.expect("read landed chunk"),
        b"complete bytes"
    );
    store.delete_chunk(&hash).await.expect("delete chunk");
}

#[wasm_bindgen_test]
async fn writing_an_existing_hash_atomically_replaces_its_bytes() {
    let worker: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let store = OpfsStore::open(&worker, "r68-atomic-replacement")
        .await
        .expect("open OPFS");
    let hash = ChunkHash::from_bytes([0x54; 32]);
    store.delete_chunk(&hash).await.expect("clear old chunk");

    store
        .write_chunk(&hash, b"corrupt")
        .await
        .expect("write first bytes");
    store
        .write_chunk(&hash, b"complete replacement")
        .await
        .expect("replace bytes");

    assert_eq!(
        store.read_chunk(&hash).await.expect("read replacement"),
        b"complete replacement"
    );
    store.delete_chunk(&hash).await.expect("delete chunk");
}
