//! Phase E4.2: the last of the logged-in startup paths that had never run.
//!
//! A refresh store is encrypted under the device key. If that key is gone, the
//! credential inside is unreachable, and the startup treats the store as lost
//! rather than as a fatal error: it discards it and asks for a fresh login. That
//! recovery had never executed, because nothing had ever booted with logins on.
//!
//! The test rotates the device key behind a stored credential, which is what a
//! cleared key store or a wiped device leaves behind, and then boots. A startup
//! missing the recovery would fail on the undecryptable store instead of logging in.
//!
//! Needs the stack up. See `authenticated_boot.rs` for the commands.

#![cfg(target_arch = "wasm32")]

mod common;

use common::{REFRESH_DB, auth_config, play_the_tab, worker_config};
use connetto_web::auth::{RefreshStore, ReplicaKeyStore};
use connetto_web::storage::{ReplicaStorage, clear_device_key, device_key, take_pending_wipes};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// A stored credential the device key no longer opens is discarded, not fatal.
#[wasm_bindgen_test]
async fn a_refresh_store_that_does_not_decrypt_is_replaced_by_a_fresh_login() {
    let storage = ReplicaStorage::install().await;
    let keys = ReplicaKeyStore::open().await.expect("open the key store");
    take_pending_wipes().await.expect("drain any earlier wipes");

    // Plant a refresh store holding a credential, then rotate the device key out
    // from under it. Rotating is enough on its own: the store's bytes stay put and
    // stop being readable, which is the state this recovery exists for.
    storage
        .delete_db(REFRESH_DB)
        .expect("clear an earlier refresh store");
    let stale_device = device_key(&keys).await.expect("mint a device key");
    let auth_db_url = storage.db_url(REFRESH_DB, true);
    RefreshStore::open(&auth_db_url, &stale_device)
        .expect("open the refresh store")
        .save("a-refresh-token-the-device-key-can-no-longer-reach")
        .expect("store a credential");
    clear_device_key(&keys).await.expect("lose the device key");
    let live_device = device_key(&keys).await.expect("mint a new device key");
    assert_ne!(
        live_device, stale_device,
        "the rotation produced a different key, so the store cannot be read"
    );
    assert!(
        RefreshStore::open(&auth_db_url, &live_device).is_err(),
        "the planted store does not decrypt under the new device key"
    );

    // The startup meets that store, discards it, and logs in through the tab.
    let logins_served = play_the_tab();
    connetto_web::workers::boot_db_worker::<String>(&worker_config(Some(auth_config())))
        .await
        .expect("the startup recovers from an unreadable refresh store");
    assert_eq!(
        logins_served.get(),
        1,
        "the discarded store forced exactly one fresh login"
    );

    // The store the startup left behind is readable under the current device key and
    // holds the credential from that login, so the next startup refreshes silently.
    let recovered =
        RefreshStore::open(&auth_db_url, &live_device).expect("the replacement store decrypts");
    assert!(
        recovered
            .load()
            .expect("read the replacement store")
            .is_some(),
        "the fresh login left a credential behind"
    );
}
