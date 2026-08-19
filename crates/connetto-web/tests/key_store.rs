//! Phase E1 browser acceptance: the replica key store under real `IndexedDB` and
//! real `WebCrypto`, in a dedicated worker, which is the context the DB worker
//! runs in and the only one that owns token custody.
//!
//! The claims under test are the ones a compile cannot make: that a key
//! survives a cold reopen, that records are isolated per identity, that a
//! clear crypto-shreds exactly one of them, what lands in `IndexedDB` is
//! wrapped rather than the raw key, and the passkey-derived rung works end to
//! end from `adopt_derived` through the locked-refusal invariant.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use connetto_core::ReplicaKey;
use connetto_core::traits::ReplicaKeyStore as _;
use connetto_web::auth::{IdbKeyStore, LOCKED_MESSAGE, provision_replica_key};
use indexed_db_futures::database::Database as IdbDatabase;
use indexed_db_futures::prelude::*;
use indexed_db_futures::query_source::QuerySource;
use wasm_bindgen::JsCast as _;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The database and object store the implementation uses. Hard-coded rather
/// than imported, so a rename has to be a deliberate change here too.
const KEY_STORE_DB: &str = "connetto-key-store";
const STORE_KEK: &str = "kek";
const STORE_WRAPPED: &str = "wrapped";
const STORE_CREDENTIALS: &str = "credentials";

fn key_from_byte(byte: u8) -> ReplicaKey {
    ReplicaKey::from_bytes([byte; ReplicaKey::LEN])
}

/// A record name unique to each test, so the tests share one `IndexedDB`
/// database (as production does) without colliding on records.
fn name(test: &str) -> String {
    format!("replica-{test}")
}

/// Empty all three object stores, so a test starts on the ungated rung with
/// nothing inherited.
///
/// One browser profile means one key store shared by every test in this binary,
/// and enrolment is profile-wide by design: once a credential is recorded, a
/// handle with no derived key is refused, which is the invariant the gate exists
/// for. Without this the first enrolling test would lock every test after it.
/// `wrapped` has to go too: a record left behind by another test was encrypted
/// under the `kek` this reset deletes, so it is inert afterwards, and
/// `adopt_derived` rightly refuses to enrol while any ungated record cannot be
/// decrypted rather than orphan it under a key it is about to destroy.
async fn on_the_ungated_rung() {
    // Through the real opener first, so the stores exist. Opening raw at a
    // version with no upgrade handler would create the database empty, and
    // `IdbKeyStore::open` would then see the version it wants and never build
    // anything.
    drop(IdbKeyStore::open().await.expect("open the key store"));
    let db = IdbDatabase::open(KEY_STORE_DB)
        .await
        .expect("reopen the key store");
    let tx = db
        .transaction([STORE_CREDENTIALS, STORE_KEK, STORE_WRAPPED])
        .with_mode(indexed_db_futures::transaction::TransactionMode::Readwrite)
        .build()
        .expect("reset tx");
    for store_name in [STORE_CREDENTIALS, STORE_KEK, STORE_WRAPPED] {
        tx.object_store(store_name)
            .expect("reset store")
            .clear()
            .expect("clear")
            .await
            .expect("clear await");
    }
    tx.commit().await.expect("reset commit");
}

#[wasm_bindgen_test]
async fn a_saved_key_loads_back() {
    on_the_ungated_rung().await;
    let store = IdbKeyStore::open().await.expect("open the key store");
    let record = name("roundtrip");
    let key = key_from_byte(0x5a);

    store.store(&record, &key).await.expect("save");
    let loaded = store.load(&record).await.expect("load").expect("a key");

    assert_eq!(loaded, key);
}

#[wasm_bindgen_test]
async fn an_absent_record_loads_as_nothing() {
    on_the_ungated_rung().await;
    let store = IdbKeyStore::open().await.expect("open the key store");
    assert_eq!(
        store.load(&name("never-written")).await.expect("load"),
        None,
        "a device that never provisioned has no key, rather than an error"
    );
}

#[wasm_bindgen_test]
async fn a_cold_reopen_reads_the_key_back() {
    on_the_ungated_rung().await;
    let record = name("cold-start");
    let key = key_from_byte(0x33);

    {
        let store = IdbKeyStore::open().await.expect("open the key store");
        store.store(&record, &key).await.expect("save");
    }

    // A fresh handle, as a new worker generation gets: the wrapping key has to
    // be recovered from IndexedDB rather than regenerated, or this returns a
    // different key or fails to decrypt. This is the offline property, the
    // replica opens with no credential and no network.
    let reopened = IdbKeyStore::open().await.expect("reopen the key store");
    let loaded = reopened.load(&record).await.expect("load").expect("a key");

    assert_eq!(loaded, key, "the key survives a cold reopen");
}

#[wasm_bindgen_test]
async fn keys_are_isolated_per_record_and_a_clear_shreds_only_one() {
    on_the_ungated_rung().await;
    let store = IdbKeyStore::open().await.expect("open the key store");
    let alice = name("alice");
    let bob = name("bob");

    store
        .store(&alice, &key_from_byte(0x11))
        .await
        .expect("save");
    store.store(&bob, &key_from_byte(0x22)).await.expect("save");

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
    on_the_ungated_rung().await;
    let record = name("wrapped");
    // A key of distinct, non-repeating bytes, so finding it in the record
    // cannot be a coincidence of a constant fill.
    let mut bytes = [0u8; ReplicaKey::LEN];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::try_from(index).expect("below the key length") ^ 0x5a;
    }
    let key = ReplicaKey::from_bytes(bytes);

    let store = IdbKeyStore::open().await.expect("open the key store");
    store.store(&record, &key).await.expect("save");

    // The ungated rung stores the record under `name#` (empty holder suffix).
    let stored = read_raw_record(&format!("{record}#")).await;

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
async fn provision_once_mints_then_prefers_the_cached_key() {
    on_the_ungated_rung().await;
    let store = IdbKeyStore::open().await.expect("open the key store");
    let record = name("provision-once");

    // First sight: nothing cached, so a key is minted in the worker and written
    // through before it is handed back.
    let first = provision_replica_key(&store, &record)
        .await
        .expect("a key is minted");
    assert_eq!(
        store.load(&record).await.expect("load"),
        Some(first.clone()),
        "the minted key is cached for a later cold start"
    );

    // A second call never mints again, or a re-login would re-key the replica
    // and strand everything in it.
    let effective = provision_replica_key(&store, &record)
        .await
        .expect("resolve");
    assert_eq!(effective, first, "the cached key wins over minting another");

    // The mint is real randomness, not a constant or a hash of the name: a
    // second record on the same device gets its own key.
    let other = provision_replica_key(&store, &name("provision-once-other"))
        .await
        .expect("a second key is minted");
    assert_ne!(other, first, "each record mints its own key");
    assert_ne!(
        other,
        key_from_byte(0),
        "an all-zero key would mean the fill never ran"
    );
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

/// A credential id used across all derived-rung tests. Distinct from zero so a
/// wrong encoding is not silently correct.
const TEST_CRED_ID: &[u8] = &[0x42u8; 16];

/// Import raw bytes as a non-extractable HKDF key for use in `use_derived` and
/// `adopt_derived`.
async fn hkdf_key_from_bytes(seed: &[u8]) -> web_sys::CryptoKey {
    let scope: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let subtle = scope.crypto().expect("crypto").subtle();
    let raw: js_sys::Object = js_sys::Uint8Array::from(seed).unchecked_into();
    let usages = js_sys::Array::new();
    usages.push(&wasm_bindgen::JsValue::from_str("deriveBits"));
    let promise = subtle
        .import_key_with_str("raw", &raw, "HKDF", false, usages.as_ref())
        .expect("importKey promise");
    JsFuture::from(promise)
        .await
        .expect("importKey await")
        .unchecked_into::<web_sys::CryptoKey>()
}

/// True when the `kek` object store contains no entry.
async fn kek_is_absent() -> bool {
    let db = IdbDatabase::open(KEY_STORE_DB)
        .await
        .expect("open key store database");
    let tx = db.transaction(STORE_KEK).build().expect("kek read tx");
    let store = tx.object_store(STORE_KEK).expect("kek store");
    let value: Option<wasm_bindgen::JsValue> = store
        .get(1u32)
        .primitive()
        .expect("kek get")
        .await
        .expect("kek get await");
    value.is_none()
}

/// True when the `wrapped` object store has an entry under `key`.
async fn has_wrapped_key(key: &str) -> bool {
    let db = IdbDatabase::open(KEY_STORE_DB)
        .await
        .expect("open key store database");
    let tx = db
        .transaction(STORE_WRAPPED)
        .build()
        .expect("wrapped read tx");
    let store = tx.object_store(STORE_WRAPPED).expect("wrapped store");
    let value: Option<wasm_bindgen::JsValue> = store
        .get(key)
        .primitive()
        .expect("has_wrapped_key get")
        .await
        .expect("has_wrapped_key get await");
    value.is_some()
}

/// Read all credential ids from the `credentials` object store.
async fn read_enrolled_ids() -> Vec<String> {
    let db = IdbDatabase::open(KEY_STORE_DB)
        .await
        .expect("open key store database");
    let tx = db
        .transaction(STORE_CREDENTIALS)
        .build()
        .expect("credentials read tx");
    let store = tx
        .object_store(STORE_CREDENTIALS)
        .expect("credentials store");
    store
        .get_all_keys::<String>()
        .primitive()
        .expect("get_all_keys")
        .await
        .expect("get_all_keys await")
        .collect::<Result<Vec<_>, _>>()
        .expect("decode keys")
}

// ────────────────────────── derived-rung tests ────────────────────────────

#[wasm_bindgen_test]
async fn after_adopt_derived_the_stored_kek_is_absent() {
    on_the_ungated_rung().await;
    let store = IdbKeyStore::open().await.expect("open the key store");
    // Write a record first so the stored KEK is created.
    store
        .store(&name("kek-absent"), &key_from_byte(0x01))
        .await
        .expect("store under ungated kek");

    let hkdf = hkdf_key_from_bytes(&[0x11u8; 32]).await;
    store
        .adopt_derived(hkdf, TEST_CRED_ID)
        .await
        .expect("adopt derived key");

    assert!(
        kek_is_absent().await,
        "the stored KEK must be gone after enrolment"
    );
}

#[wasm_bindgen_test]
async fn a_derived_wrapped_record_is_opaque_to_a_fresh_store_without_the_key() {
    on_the_ungated_rung().await;
    let record = name("derived-opaque");
    let key = key_from_byte(0x77);
    let cred_id = [0x55u8; 16];

    // Write the record through a store that holds a derived key.
    {
        let store = IdbKeyStore::open().await.expect("open");
        let hkdf = hkdf_key_from_bytes(&[0xaau8; 32]).await;
        store
            .use_derived(hkdf, &cred_id)
            .await
            .expect("use derived");
        store
            .store(&record, &key)
            .await
            .expect("store under derived key");
    }

    // A fresh handle with no derived key set cannot decrypt the record.
    let fresh = IdbKeyStore::open().await.expect("reopen");
    let result = fresh.load(&record).await;
    assert!(
        result.is_err() || result.unwrap().is_none(),
        "a record under a derived key is inert without that key"
    );

    // The raw bytes in IndexedDB are not the raw key.
    let holder = URL_SAFE_NO_PAD.encode(cred_id);
    let raw = read_raw_record(&format!("{record}#{holder}")).await;
    assert!(
        !raw.windows(ReplicaKey::LEN).any(|w| w == key.as_bytes()),
        "the raw key must not appear in the stored record"
    );
}

#[wasm_bindgen_test]
async fn a_pre_enrolment_record_is_rewrapped_with_the_credential_suffix_on_adopt() {
    on_the_ungated_rung().await;
    let record = name("rewrap");
    let key = key_from_byte(0x88);
    let cred_id = TEST_CRED_ID;
    let holder = URL_SAFE_NO_PAD.encode(cred_id);

    let store = IdbKeyStore::open().await.expect("open");
    // Write before enrolment: the record lives under the ungated rung.
    store
        .store(&record, &key)
        .await
        .expect("store before enrolment");
    assert!(
        has_wrapped_key(&format!("{record}#")).await,
        "ungated record present"
    );

    let hkdf = hkdf_key_from_bytes(&[0x22u8; 32]).await;
    store
        .adopt_derived(hkdf, cred_id)
        .await
        .expect("adopt derived");

    // The old ungated key is gone.
    assert!(
        !has_wrapped_key(&format!("{record}#")).await,
        "ungated record must be gone after adopt"
    );
    // The new enrolled key is present.
    assert!(
        has_wrapped_key(&format!("{record}#{holder}")).await,
        "enrolled record must be present after adopt"
    );

    // Loading through the same handle (derived key already set) returns the original key.
    let loaded = store
        .load(&record)
        .await
        .expect("load after adopt")
        .expect("key present");
    assert_eq!(
        loaded, key,
        "adopt re-wrapped the key without changing its value"
    );
}

#[wasm_bindgen_test]
async fn clear_removes_the_enrolled_record_given_the_plain_name() {
    on_the_ungated_rung().await;
    let record = name("clear-enrolled");
    let key = key_from_byte(0x99);
    let cred_id = [0xddu8; 16];
    let holder = URL_SAFE_NO_PAD.encode(cred_id);

    let store = IdbKeyStore::open().await.expect("open");
    store
        .store(&record, &key)
        .await
        .expect("store before enrolment");
    let hkdf = hkdf_key_from_bytes(&[0x33u8; 32]).await;
    store
        .adopt_derived(hkdf, &cred_id)
        .await
        .expect("adopt derived");

    // Confirm the enrolled record exists before clearing.
    assert!(
        has_wrapped_key(&format!("{record}#{holder}")).await,
        "enrolled record must exist before clear"
    );

    store.clear(&record).await.expect("clear by plain name");

    assert!(
        !has_wrapped_key(&format!("{record}#{holder}")).await,
        "enrolled record must be gone after clear"
    );
    assert_eq!(
        store.load(&record).await.expect("load after clear"),
        None,
        "loading after clear returns nothing"
    );
}

#[wasm_bindgen_test]
async fn enrolled_is_empty_before_adoption_and_holds_the_credential_afterwards() {
    on_the_ungated_rung().await;
    let store = IdbKeyStore::open().await.expect("open");
    let cred_id = [0x7fu8; 16];
    let holder = URL_SAFE_NO_PAD.encode(cred_id);

    // Before any adoption the credentials store is empty for this test.
    // Other tests may have enrolled, so we check the new id is absent.
    let before = read_enrolled_ids().await;
    assert!(
        !before.contains(&holder),
        "the credential must not be enrolled before adoption"
    );

    // Write something so there is a record to re-wrap.
    store
        .store(&name("enrolled-check"), &key_from_byte(0x20))
        .await
        .expect("store");
    let hkdf = hkdf_key_from_bytes(&[0x44u8; 32]).await;
    store.adopt_derived(hkdf, &cred_id).await.expect("adopt");

    let after = read_enrolled_ids().await;
    assert!(
        after.contains(&holder),
        "the credential id must appear in the enrolled list after adoption"
    );
    // The id appears exactly once per adoption call.
    assert_eq!(
        after.iter().filter(|k| *k == &holder).count(),
        1,
        "the credential id must appear exactly once"
    );
}

#[wasm_bindgen_test]
async fn an_enrolled_store_without_a_derived_key_refuses_load_and_store() {
    on_the_ungated_rung().await;
    let record = name("locked-refusal");
    let cred_id = [0xeeu8; 16];

    // Enrol through one handle.
    {
        let writer = IdbKeyStore::open().await.expect("open writer");
        writer
            .store(&record, &key_from_byte(0x50))
            .await
            .expect("store before enrolment");
        let hkdf = hkdf_key_from_bytes(&[0x55u8; 32]).await;
        writer.adopt_derived(hkdf, &cred_id).await.expect("adopt");
    }

    // A fresh handle has no derived key, so reads and writes are refused.
    let locked = IdbKeyStore::open().await.expect("open locked handle");

    let load_err = locked
        .load(&record)
        .await
        .expect_err("load must fail on a locked enrolled store");
    assert!(
        load_err.to_string().contains(LOCKED_MESSAGE),
        "load error must start with the locked message, got: {load_err}"
    );

    let store_err = locked
        .store(&record, &key_from_byte(0x51))
        .await
        .expect_err("store must fail on a locked enrolled store");
    assert!(
        store_err.to_string().contains(LOCKED_MESSAGE),
        "store error must start with the locked message, got: {store_err}"
    );
}

#[wasm_bindgen_test]
async fn two_hkdf_source_keys_derive_different_encryption_keys() {
    on_the_ungated_rung().await;
    let record = name("different-keys");
    let key = key_from_byte(0xab);
    let cred_id = [0x11u8; 16];

    // Write the record through a derived key from seed A.
    {
        let store_a = IdbKeyStore::open().await.expect("open store a");
        let hkdf_a = hkdf_key_from_bytes(&[0x01u8; 32]).await;
        store_a
            .use_derived(hkdf_a, &cred_id)
            .await
            .expect("use derived a");
        store_a
            .store(&record, &key)
            .await
            .expect("store under key a");
    }

    // Try to read through a derived key from seed B: decryption must fail,
    // proving the two seeds produce different key-encryption keys.
    let store_b = IdbKeyStore::open().await.expect("open store b");
    let hkdf_b = hkdf_key_from_bytes(&[0x02u8; 32]).await;
    store_b
        .use_derived(hkdf_b, &cred_id)
        .await
        .expect("use derived b");
    let result = store_b.load(&record).await;
    assert!(
        result.is_err(),
        "loading with a different derived key must fail, proving the keys differ"
    );
}
