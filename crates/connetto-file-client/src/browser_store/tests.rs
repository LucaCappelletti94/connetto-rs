use connetto_file_core::{ChunkHash, ChunkInventory, ChunkStore};
use wasm_bindgen::JsCast;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::DedicatedWorkerGlobalScope;

use super::OpfsStore;

wasm_bindgen_test_configure!(run_in_dedicated_worker);

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
