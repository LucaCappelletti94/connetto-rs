//! R41: the browser half of the two secret-store seams.
//!
//! The callers are `connetto_core::test_support::two_accounts_keep_their_own_token`
//! and `..._key`, written against the traits and knowing nothing about
//! `IndexedDB`, `SubtleCrypto`, or an encrypted OPFS file. `connetto-client`'s
//! `secret_stores.rs` runs the same two functions against the native stores, so
//! one caller covers both targets and the seam is proven rather than the rename.
//!
//! The pre-login case is here too, because only the browser has one: the device
//! key is read under a literal name before any account exists, which is why both
//! stores address the account per call instead of baking it into the object.

use connetto_core::test_support::{
    two_accounts_keep_their_own_key, two_accounts_keep_their_own_token,
};
use connetto_core::traits::ReplicaKeyStore;
use connetto_web::auth::{IdbKeyStore, RefreshStore};
use connetto_web::storage::{ReplicaStorage, clear_device_key, device_key};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The OPFS file this suite keeps its refresh store in, distinct from every
/// other suite's so a shared origin cannot cross them.
const REFRESH_DB: &str = "r41-secret-stores.sqlite";

#[wasm_bindgen_test]
async fn the_browser_key_store_keeps_two_accounts_apart() {
    let store = IdbKeyStore::open().await.expect("open the key store");
    two_accounts_keep_their_own_key(&store, "r41-alice", "r41-bob").await;
}

#[wasm_bindgen_test]
async fn the_browser_refresh_store_keeps_two_accounts_apart() {
    let storage = ReplicaStorage::install().await;
    let keys = IdbKeyStore::open().await.expect("open the key store");
    storage
        .delete_db(REFRESH_DB)
        .expect("clear any earlier file");
    clear_device_key(&keys)
        .await
        .expect("clear any earlier key");

    let device = device_key(&keys).await.expect("mint the device key");
    let store =
        RefreshStore::open(&storage.db_url(REFRESH_DB), &device).expect("open the refresh store");
    two_accounts_keep_their_own_token(&store, "r41-alice", "r41-bob");
}

/// The case decision 4 of R41 turns on, and the one native has no equivalent of.
///
/// A boot reads the device key under a literal name before any account is known,
/// because the refresh token is what reveals the account. It has to come back
/// from the same store the per-account records live in, and it has to be the same
/// key on the boot after that, or the refresh store it wraps stops opening.
#[wasm_bindgen_test]
async fn the_pre_login_record_reads_before_any_account_exists() {
    let keys = IdbKeyStore::open().await.expect("open the key store");
    clear_device_key(&keys).await.expect("start from nothing");

    let minted = device_key(&keys).await.expect("mint on first sight");
    assert_eq!(
        device_key(&keys).await.expect("read it back"),
        minted,
        "the literal record is provision-once, so the wrapped store still opens"
    );

    // The per-account records live in the same store and neither reaches it.
    let account = "r41-pre-login-account";
    let account_key = connetto_web::auth::provision_replica_key(&keys, account)
        .await
        .expect("provision an account's key");
    assert_ne!(
        account_key, minted,
        "a derived name and the literal address different records"
    );
    keys.clear(account).await.expect("shred the account record");
    assert_eq!(
        device_key(&keys).await.expect("the device key survives"),
        minted,
        "clearing an account leaves the pre-login record alone"
    );
}
