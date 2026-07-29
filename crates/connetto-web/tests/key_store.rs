//! Phase E1 browser acceptance: the replica key store under real `IndexedDB` and
//! real `WebCrypto`, in a dedicated worker, which is the context the DB worker
//! runs in and the only one that owns token custody.
//!
//! The claims under test are the ones a compile cannot make: that a key
//! survives a cold reopen, that records are isolated per identity, that a
//! clear crypto-shreds exactly one of them, and that what lands in `IndexedDB`
//! is wrapped rather than the raw key.

use connetto_core::ReplicaKey;
use connetto_web::auth::{ReplicaKeyStore, resolve_replica_key};
use indexed_db_futures::database::Database as IdbDatabase;
use indexed_db_futures::prelude::*;
use indexed_db_futures::query_source::QuerySource;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The database and object store the implementation uses. Hard-coded rather
/// than imported, so a rename has to be a deliberate change here too.
const KEY_STORE_DB: &str = "connetto-key-store";
const STORE_WRAPPED: &str = "wrapped";

fn key_from_byte(byte: u8) -> ReplicaKey {
    ReplicaKey::from_bytes([byte; ReplicaKey::LEN])
}

/// A record name unique to each test, so the tests share one `IndexedDB`
/// database (as production does) without colliding on records.
fn name(test: &str) -> String {
    format!("replica-{test}")
}

#[wasm_bindgen_test]
async fn a_saved_key_loads_back() {
    let store = ReplicaKeyStore::open().await.expect("open the key store");
    let record = name("roundtrip");
    let key = key_from_byte(0x5a);

    store.save(&record, &key).await.expect("save");
    let loaded = store.load(&record).await.expect("load").expect("a key");

    assert_eq!(loaded, key);
}

#[wasm_bindgen_test]
async fn an_absent_record_loads_as_nothing() {
    let store = ReplicaKeyStore::open().await.expect("open the key store");
    assert_eq!(
        store.load(&name("never-written")).await.expect("load"),
        None,
        "a device that never provisioned has no key, rather than an error"
    );
}

#[wasm_bindgen_test]
async fn a_cold_reopen_reads_the_key_back() {
    let record = name("cold-start");
    let key = key_from_byte(0x33);

    {
        let store = ReplicaKeyStore::open().await.expect("open the key store");
        store.save(&record, &key).await.expect("save");
    }

    // A fresh handle, as a new worker generation gets: the wrapping key has to
    // be recovered from IndexedDB rather than regenerated, or this returns a
    // different key or fails to decrypt. This is the offline property, the
    // replica opens with no credential and no network.
    let reopened = ReplicaKeyStore::open().await.expect("reopen the key store");
    let loaded = reopened.load(&record).await.expect("load").expect("a key");

    assert_eq!(loaded, key, "the key survives a cold reopen");
}

#[wasm_bindgen_test]
async fn keys_are_isolated_per_record_and_a_clear_shreds_only_one() {
    let store = ReplicaKeyStore::open().await.expect("open the key store");
    let alice = name("alice");
    let bob = name("bob");

    store
        .save(&alice, &key_from_byte(0x11))
        .await
        .expect("save");
    store.save(&bob, &key_from_byte(0x22)).await.expect("save");

    assert_eq!(
        store.load(&alice).await.expect("load"),
        Some(key_from_byte(0x11))
    );
    assert_eq!(
        store.load(&bob).await.expect("load"),
        Some(key_from_byte(0x22)),
        "a second identity's key is not overwritten by the first"
    );

    // Crypto-shredding one identity must leave the other decryptable, which is
    // the precondition phase E3's wipe rests on.
    store.clear(&alice).await.expect("clear");
    assert_eq!(store.load(&alice).await.expect("load"), None);
    assert_eq!(
        store.load(&bob).await.expect("load"),
        Some(key_from_byte(0x22)),
        "wiping one identity on a shared device leaves the other intact"
    );
}

#[wasm_bindgen_test]
async fn what_lands_in_indexeddb_is_wrapped_not_the_raw_key() {
    let record = name("wrapped");
    // A key of distinct, non-repeating bytes, so finding it in the record
    // cannot be a coincidence of a constant fill.
    let mut bytes = [0u8; ReplicaKey::LEN];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::try_from(index).expect("below the key length") ^ 0x5a;
    }
    let key = ReplicaKey::from_bytes(bytes);

    let store = ReplicaKeyStore::open().await.expect("open the key store");
    store.save(&record, &key).await.expect("save");

    let stored = read_raw_record(&record).await;

    assert_ne!(
        stored.len(),
        ReplicaKey::LEN,
        "a raw key would be exactly {} bytes",
        ReplicaKey::LEN
    );
    assert!(
        !stored
            .windows(ReplicaKey::LEN)
            .any(|window| window == bytes),
        "the raw key must not appear anywhere in the stored record"
    );
    // 12-byte IV plus the AES-GCM ciphertext of 32 bytes plus its 16-byte tag.
    assert_eq!(
        stored.len(),
        12 + ReplicaKey::LEN + 16,
        "the record is an IV followed by the wrapped key and its tag"
    );
}

#[wasm_bindgen_test]
async fn provision_once_prefers_the_cached_key() {
    let store = ReplicaKeyStore::open().await.expect("open the key store");
    let record = name("provision-once");

    // First sight: nothing cached, so the provisioned key is adopted and
    // written through.
    let first = resolve_replica_key(&store, &record, Some(key_from_byte(0xaa)))
        .await
        .expect("resolve")
        .expect("a key");
    assert_eq!(first, key_from_byte(0xaa));

    // A later login mints different material. The cached key still wins, or a
    // re-login would re-key the replica and strand everything in it.
    let effective = resolve_replica_key(&store, &record, Some(key_from_byte(0xbb)))
        .await
        .expect("resolve")
        .expect("a key");
    assert_eq!(effective, key_from_byte(0xaa));
    assert_eq!(
        store.load(&record).await.expect("load"),
        Some(key_from_byte(0xaa)),
        "the wire key never overwrites the cache"
    );

    // A refresh carries no key, and the cached one still resolves.
    let offline = resolve_replica_key(&store, &record, None)
        .await
        .expect("resolve")
        .expect("a key");
    assert_eq!(offline, key_from_byte(0xaa));
}

/// The bytes `IndexedDB` actually holds for `record`, read straight out of the
/// database rather than through the store, so the assertion is about what is at
/// rest and not about what the store chooses to report.
async fn read_raw_record(record: &str) -> Vec<u8> {
    let db = IdbDatabase::open(KEY_STORE_DB)
        .await
        .expect("open the key store database");
    let tx = db
        .transaction(STORE_WRAPPED)
        .build()
        .expect("read transaction");
    let store = tx.object_store(STORE_WRAPPED).expect("object store");
    let value: wasm_bindgen::JsValue = store
        .get(record)
        .primitive()
        .expect("get")
        .await
        .expect("get await")
        .expect("the record exists");
    js_sys::Uint8Array::new(&value).to_vec()
}
