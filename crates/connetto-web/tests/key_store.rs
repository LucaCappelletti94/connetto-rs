//! Phase E1 browser acceptance: the replica key store under real `IndexedDB` and
//! real `WebCrypto`, in a dedicated worker, which is the context the DB worker
//! runs in and the only one that owns token custody.
//!
//! The claims under test are the ones a compile cannot make: that a key
//! survives a cold reopen, that records are isolated per identity, that a
//! clear crypto-shreds exactly one of them, what lands in `IndexedDB` is
//! wrapped rather than the raw key, and the passkey-derived rung works end to
//! end from `adopt_derived` through the locked-refusal invariant.

use std::rc::Rc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use connetto_client::share_keys::share_key_record;
use connetto_client::{Grant, ShareKeySet, ShareKeyStore};
use connetto_core::CapabilitySubject;
use connetto_core::ReplicaKey;
use connetto_core::traits::ReplicaKeyStore as _;
use connetto_web::auth::{BuilderKeyStore, IdbKeyStore, LOCKED_MESSAGE, provision_replica_key};
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

/// The record a share-key set persists under, named from the replica it rides
/// beside.
fn share_record(replica: &str) -> String {
    share_key_record(replica)
}

/// The two grant tokens the fixture set holds, the strings a store that
/// leaked the set would sit on.
const SHARE_GRANT_ONE: &str = "connetto-share-grant-0f1e2d3c4b5a6978";
const SHARE_GRANT_TWO: &str = "connetto-share-grant-9a8b7c6d5e4f3021";

/// A variable-length share-key set, so a roundtrip or a re-wrap that assumed
/// the 32-byte replica-key length fails loudly. The subjects differ in length
/// and content, so a swapped or truncated pair is not silently correct.
fn share_set() -> ShareKeySet {
    ShareKeySet::new::<String>(vec![
        (
            Grant::new(SHARE_GRANT_ONE),
            CapabilitySubject::new("doc:7f3a9c1d"),
        ),
        (
            Grant::new(SHARE_GRANT_TWO),
            CapabilitySubject::new("doc:2b4d6e8f0a1c3d5e7f90:long-subject"),
        ),
    ])
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
async fn a_boot_approval_keeps_the_browser_gate_open_until_it_locks() {
    use connetto_client::away::GateMechanism as _;
    use connetto_web::gate::BrowserGateMechanism;
    use std::rc::Rc;

    on_the_ungated_rung().await;
    let store = Rc::new(IdbKeyStore::open().await.expect("open"));
    let record = name("gate-approval");
    let key = key_from_byte(0x32);
    let hkdf = hkdf_key_from_bytes(&[0x41; 32]).await;
    store
        .adopt_derived(hkdf.clone(), TEST_CRED_ID)
        .await
        .expect("approve enrolment");
    store.store(&record, &key).await.expect("store");
    let mechanism = BrowserGateMechanism::new(Rc::clone(&store));

    assert!(mechanism.is_open(), "boot already verified the user");
    mechanism.lock();
    assert!(!mechanism.is_open(), "a re-check drops the approval");
    assert!(matches!(
        store.load(&record).await,
        Err(connetto_web::auth::AuthError::Locked { .. })
    ));

    store
        .use_derived(hkdf, TEST_CRED_ID)
        .await
        .expect("approve unlock");
    assert!(mechanism.is_open(), "unlock restores the approval");
    assert_eq!(store.load(&record).await.expect("load"), Some(key));
}

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

#[wasm_bindgen_test]
async fn a_share_key_set_survives_a_cold_reopen() {
    on_the_ungated_rung().await;
    let replica = name("share-cold");
    let record = share_record(&replica);
    let set = share_set();

    {
        let store = IdbKeyStore::open().await.expect("open the key store");
        let adapter = BuilderKeyStore::new(Rc::new(store));
        ShareKeyStore::save(&adapter, &record, &set)
            .await
            .expect("save the share keys");
    }

    // A fresh handle, as a new worker generation gets. The wrapping key has
    // to come from IndexedDB and the variable-length payload has to come
    // back whole.
    let reopened = IdbKeyStore::open().await.expect("reopen the key store");
    let adapter = BuilderKeyStore::new(Rc::new(reopened));
    let loaded = ShareKeyStore::load(&adapter, &record)
        .await
        .expect("load the share keys")
        .expect("a set");

    assert_eq!(loaded, set, "the share keys survive a cold reopen");

    // The record at rest is wrapped, and a bearer grant is not readable
    // straight out of it.
    let raw = read_raw_record(&format!("{record}#")).await;
    let at_rest = String::from_utf8_lossy(&raw);
    assert!(
        !at_rest.contains(SHARE_GRANT_ONE) && !at_rest.contains(SHARE_GRANT_TWO),
        "a bearer grant must not sit in the stored record"
    );
}

#[wasm_bindgen_test]
async fn an_enrolled_store_refuses_share_key_access_without_a_derived_key() {
    on_the_ungated_rung().await;
    let replica = name("share-locked");
    let record = share_record(&replica);
    let cred_id = [0xcbu8; 16];

    // Enrol through one handle, after a replica record exists so the re-wrap
    // has something to move.
    {
        let writer = IdbKeyStore::open().await.expect("open the writer");
        writer
            .store(&replica, &key_from_byte(0x61))
            .await
            .expect("store before enrolment");
        let hkdf = hkdf_key_from_bytes(&[0x66u8; 32]).await;
        writer
            .adopt_derived(hkdf, &cred_id)
            .await
            .expect("adopt derived");
    }

    // A fresh handle holds no derived key, so both halves are refused.
    let locked = IdbKeyStore::open().await.expect("open the locked handle");
    let adapter = BuilderKeyStore::new(Rc::new(locked));

    let load_err = ShareKeyStore::load(&adapter, &record)
        .await
        .expect_err("a share load must fail on a locked enrolled store");
    assert!(
        load_err.to_string().contains(LOCKED_MESSAGE),
        "the share load error must carry the locked message, got: {load_err}"
    );

    let save_err = ShareKeyStore::save(&adapter, &record, &share_set())
        .await
        .expect_err("a share save must fail on a locked enrolled store");
    assert!(
        save_err.to_string().contains(LOCKED_MESSAGE),
        "the share save error must carry the locked message, got: {save_err}"
    );
}

#[wasm_bindgen_test]
async fn a_share_record_is_rewrapped_with_the_credential_suffix_on_adopt() {
    on_the_ungated_rung().await;
    let replica = name("share-rewrap");
    let record = share_record(&replica);
    let set = share_set();
    let cred_id = TEST_CRED_ID;
    let holder = URL_SAFE_NO_PAD.encode(cred_id);
    // The payload is variable length by construction, so this is a test of
    // the re-wrap against a length assumption, not of a 32-byte key.
    assert_ne!(
        serde_json::to_vec(&set).expect("encode the set").len(),
        32,
        "the fixture must not be 32 bytes long"
    );

    let store = Rc::new(IdbKeyStore::open().await.expect("open the key store"));
    // Write before enrolment. The record lives under the ungated rung.
    {
        let adapter = BuilderKeyStore::new(Rc::clone(&store));
        ShareKeyStore::save(&adapter, &record, &set)
            .await
            .expect("store before enrolment");
    }
    assert!(
        has_wrapped_key(&format!("{record}#")).await,
        "the ungated share record is present"
    );

    let hkdf = hkdf_key_from_bytes(&[0x23u8; 32]).await;
    store
        .adopt_derived(hkdf, cred_id)
        .await
        .expect("adopt derived");

    // The old ungated key is gone, and the enrolled one is present.
    assert!(
        !has_wrapped_key(&format!("{record}#")).await,
        "the ungated share record is gone after adopt"
    );
    assert!(
        has_wrapped_key(&format!("{record}#{holder}")).await,
        "the enrolled share record is present after adopt"
    );

    // Loading through the same handle returns the original set byte for
    // byte, the re-wrap having changed only the key and the suffix.
    let adapter = BuilderKeyStore::new(Rc::clone(&store));
    let loaded = ShareKeyStore::load(&adapter, &record)
        .await
        .expect("load after adopt")
        .expect("a set");
    assert_eq!(
        loaded, set,
        "adopt re-wrapped the share keys without changing them"
    );
}

#[wasm_bindgen_test]
async fn a_clear_shreds_the_share_record_of_one_identity_only() {
    on_the_ungated_rung().await;
    let store = Rc::new(IdbKeyStore::open().await.expect("open the key store"));
    let alice = name("share-wipe-alice");
    let bob = name("share-wipe-bob");
    let alice_record = share_record(&alice);
    let bob_record = share_record(&bob);
    let set = share_set();

    // Both identities hold a replica key and a share set on the ungated rung.
    store
        .store(&alice, &key_from_byte(0x31))
        .await
        .expect("save alice's key");
    store
        .store(&bob, &key_from_byte(0x32))
        .await
        .expect("save bob's key");
    {
        let adapter = BuilderKeyStore::new(Rc::clone(&store));
        ShareKeyStore::save(&adapter, &alice_record, &set)
            .await
            .expect("save alice's set");
        ShareKeyStore::save(&adapter, &bob_record, &set)
            .await
            .expect("save bob's set");
    }

    // The wipe names alice's replica only, and her share record rides along.
    store.clear(&alice).await.expect("wipe alice");

    assert_eq!(
        store.load(&alice).await.expect("load"),
        None,
        "alice's key is shredded"
    );
    assert!(
        !has_wrapped_key(&format!("{alice_record}#")).await,
        "alice's share record is shredded with her replica key"
    );

    // Bob is untouched. The other identity keeps its key and its set.
    assert_eq!(
        store.load(&bob).await.expect("load"),
        Some(key_from_byte(0x32)),
        "bob's key survives alice's wipe"
    );
    let adapter = BuilderKeyStore::new(Rc::clone(&store));
    assert_eq!(
        ShareKeyStore::load(&adapter, &bob_record)
            .await
            .expect("load"),
        Some(set),
        "bob's share set survives alice's wipe"
    );
}

#[wasm_bindgen_test]
async fn a_share_record_clear_removes_only_that_record() {
    on_the_ungated_rung().await;
    let store = Rc::new(IdbKeyStore::open().await.expect("open the key store"));
    let alice = name("share-forget-alice");
    let bob = name("share-forget-bob");
    let alice_record = share_record(&alice);
    let bob_record = share_record(&bob);
    let set = share_set();

    store
        .store(&alice, &key_from_byte(0x41))
        .await
        .expect("save alice's key");
    store
        .store(&bob, &key_from_byte(0x42))
        .await
        .expect("save bob's key");
    let adapter = BuilderKeyStore::new(Rc::clone(&store));
    ShareKeyStore::save(&adapter, &alice_record, &set)
        .await
        .expect("save alice's set");
    ShareKeyStore::save(&adapter, &bob_record, &set)
        .await
        .expect("save bob's set");

    // The forget path names the record, not the replica.
    ShareKeyStore::clear(&adapter, &alice_record)
        .await
        .expect("clear alice's share record");

    assert_eq!(
        ShareKeyStore::load(&adapter, &alice_record)
            .await
            .expect("load"),
        None,
        "alice's share record is gone"
    );
    assert_eq!(
        ShareKeyStore::load(&adapter, &bob_record)
            .await
            .expect("load"),
        Some(set),
        "bob's share record survives"
    );
    assert_eq!(
        store.load(&alice).await.expect("load"),
        Some(key_from_byte(0x41)),
        "the replica keys were never named by this clear"
    );
    assert_eq!(
        store.load(&bob).await.expect("load"),
        Some(key_from_byte(0x42))
    );
}

/// A marker a codec that echoed the stored bytes would print into its
/// error.
const MALFORMED_MARKER: &str = "R95-browser-share-marker-c3a91d77";

/// Replace an ungated record with encrypted malformed plaintext.
async fn write_malformed_wrapped(key: &str, plaintext: &[u8]) {
    let db = IdbDatabase::open(KEY_STORE_DB)
        .await
        .expect("open the key store database");
    let tx = db.transaction([STORE_KEK]).build().expect("malformed tx");
    let kek_value: wasm_bindgen::JsValue = tx
        .object_store(STORE_KEK)
        .expect("kek store")
        .get(1u32)
        .primitive()
        .expect("kek get")
        .await
        .expect("kek get await")
        .expect("the at-rest kek exists");
    let kek: web_sys::CryptoKey = kek_value.unchecked_into();
    tx.commit().await.expect("finish reading the wrapping key");
    let scope: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let subtle = scope.crypto().expect("crypto").subtle();
    let iv = js_sys::Uint8Array::from([0u8; 12].as_slice());
    let params = js_sys::Object::new();
    js_sys::Reflect::set(
        &params,
        &wasm_bindgen::JsValue::from("name"),
        &wasm_bindgen::JsValue::from("AES-GCM"),
    )
    .expect("AES-GCM name");
    js_sys::Reflect::set(&params, &wasm_bindgen::JsValue::from("iv"), iv.as_ref())
        .expect("AES-GCM iv");
    let promise = subtle
        .encrypt_with_object_and_u8_array(&params, &kek, plaintext)
        .expect("encrypt promise");
    let ct = JsFuture::from(promise).await.expect("encrypt await");
    let ct = js_sys::Uint8Array::new(&ct);
    let ct_len = usize::try_from(ct.length()).expect("ciphertext length fits");
    let mut record = Vec::with_capacity(12 + ct_len);
    record.extend_from_slice([0u8; 12].as_slice());
    record.extend_from_slice(&ct.to_vec());
    let value: wasm_bindgen::JsValue = js_sys::Uint8Array::from(record.as_slice()).into();
    let tx = db
        .transaction([STORE_WRAPPED])
        .with_mode(indexed_db_futures::transaction::TransactionMode::Readwrite)
        .build()
        .expect("malformed write transaction");
    tx.object_store(STORE_WRAPPED)
        .expect("wrapped store")
        .put(value)
        .with_key(key)
        .primitive()
        .expect("put")
        .await
        .expect("put await");
    tx.commit().await.expect("malformed commit");
}

#[wasm_bindgen_test]
async fn a_malformed_share_record_error_does_not_echo_its_bytes() {
    on_the_ungated_rung().await;
    let replica = name("share-malformed");
    let record = share_record(&replica);
    // A valid save first, so the ungated rung and its wrapping key exist.
    {
        let store = IdbKeyStore::open().await.expect("open the key store");
        let adapter = BuilderKeyStore::new(Rc::new(store));
        ShareKeyStore::save(&adapter, &record, &share_set())
            .await
            .expect("seed the rung");
    }
    // A record whose separator field is the marker. An unsanitized read
    // would print the marker back from serde's refused value.
    let malformed = format!(r#"{{"separator":"{MALFORMED_MARKER}","keys":[]}}"#);
    write_malformed_wrapped(&format!("{record}#"), malformed.as_bytes()).await;
    let reopened = IdbKeyStore::open().await.expect("reopen the key store");
    let adapter = BuilderKeyStore::new(Rc::new(reopened));
    let err = ShareKeyStore::load(&adapter, &record)
        .await
        .expect_err("a malformed record refuses");
    let rendered = err.to_string();
    assert!(
        !rendered.contains(MALFORMED_MARKER),
        "the error must not echo the stored record, got: {rendered}"
    );
}
