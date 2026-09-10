//! Browser chunk storage contracts.

use connetto_file_client::{BrowserStore, BrowserStoreError};
use connetto_file_core::{ChunkHash, ChunkInventory, ChunkStore, EncryptingStore};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{
    DedicatedWorkerGlobalScope, FileSystemDirectoryHandle, FileSystemGetDirectoryOptions,
    FileSystemGetFileOptions,
};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const STORE: &str = "r68-content-store";

#[wasm_bindgen_test]
async fn an_opfs_chunk_survives_reopening_and_inventory_names_it() {
    let worker: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let hash = ChunkHash::from_bytes([0x31; 32]);
    let store = BrowserStore::install(&worker, STORE)
        .await
        .expect("install content store");
    assert!(store.is_persistent(), "headless Chrome must provide OPFS");
    store.delete_chunk(&hash).await.expect("clear old chunk");
    store
        .write_chunk(&hash, b"browser chunk")
        .await
        .expect("write chunk");
    drop(store);

    let reopened = BrowserStore::install(&worker, STORE)
        .await
        .expect("reopen content store");
    assert_eq!(
        reopened.read_chunk(&hash).await.expect("read chunk"),
        b"browser chunk"
    );
    assert!(
        reopened
            .stored_hashes()
            .await
            .expect("list chunks")
            .contains(&hash)
    );
    reopened.delete_chunk(&hash).await.expect("delete chunk");
    reopened.delete_chunk(&hash).await.expect("repeat delete");
    assert!(!reopened.has_chunk(&hash).await.expect("probe deletion"));
}

#[wasm_bindgen_test]
async fn opening_an_opfs_store_removes_an_interrupted_temporary_chunk() {
    let worker: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let hash = ChunkHash::from_bytes([0x61; 32]);
    let temporary = format!(".{hash}.7.tmp");
    let fanout = raw_fanout(&worker, "r68-temp-content-store", &hash.to_string()[..2]).await;
    let options = FileSystemGetFileOptions::new();
    options.set_create(true);
    JsFuture::from(fanout.get_file_handle_with_options(&temporary, &options))
        .await
        .expect("create interrupted temporary chunk");

    let store = BrowserStore::install(&worker, "r68-temp-content-store")
        .await
        .expect("reopen content store");

    assert!(store.is_persistent(), "headless Chrome must provide OPFS");
    assert!(
        JsFuture::from(fanout.get_file_handle(&temporary))
            .await
            .is_err(),
        "opening the store must collect an interrupted temporary chunk"
    );
}

async fn raw_fanout(
    worker: &DedicatedWorkerGlobalScope,
    namespace: &str,
    fanout: &str,
) -> FileSystemDirectoryHandle {
    let root = JsFuture::from(worker.navigator().storage().get_directory())
        .await
        .expect("open OPFS root")
        .unchecked_into::<FileSystemDirectoryHandle>();
    let options = FileSystemGetDirectoryOptions::new();
    options.set_create(true);
    let app = JsFuture::from(root.get_directory_handle_with_options("connetto-content", &options))
        .await
        .expect("open content root")
        .unchecked_into::<FileSystemDirectoryHandle>();
    let store = JsFuture::from(app.get_directory_handle_with_options(namespace, &options))
        .await
        .expect("open store namespace")
        .unchecked_into::<FileSystemDirectoryHandle>();
    JsFuture::from(store.get_directory_handle_with_options(fanout, &options))
        .await
        .expect("open fanout")
        .unchecked_into::<FileSystemDirectoryHandle>()
}

#[wasm_bindgen_test]
async fn an_invalid_store_namespace_is_not_downgraded_to_memory() {
    let worker: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let error = BrowserStore::install(&worker, "../shared")
        .await
        .expect_err("invalid namespace");

    assert!(matches!(error, BrowserStoreError::InvalidNamespace { .. }));
}

#[wasm_bindgen_test]
async fn opfs_holds_ciphertext_while_the_encrypting_view_returns_plaintext() {
    let worker: DedicatedWorkerGlobalScope = js_sys::global().unchecked_into();
    let hash = ChunkHash::from_bytes([0x42; 32]);
    let raw = BrowserStore::install(&worker, "r68-encrypted-content-store")
        .await
        .expect("install encrypted content store");
    raw.delete_chunk(&hash).await.expect("clear old chunk");
    let encrypted = EncryptingStore::new(raw.clone(), &[0x17; 32]);

    encrypted
        .write_chunk(&hash, b"photo bytes")
        .await
        .expect("write encrypted chunk");

    assert_ne!(
        raw.read_chunk(&hash).await.expect("read ciphertext"),
        b"photo bytes"
    );
    assert_eq!(
        encrypted.read_chunk(&hash).await.expect("decrypt chunk"),
        b"photo bytes"
    );
    raw.delete_chunk(&hash).await.expect("delete chunk");
}
