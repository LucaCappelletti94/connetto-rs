//! The logout channel, driven the way a page drives it.
//!
//! The worker owns the token, the replica, and its key, so a tab can only ask. This
//! boots the worker with logins on and then speaks to it exactly as a signed-out
//! button would: ask how much is unsynced, log out keeping the data, log out
//! destroying it.
//!
//! Needs the stack up. See `authenticated_boot.rs` for the commands.

#![cfg(target_arch = "wasm32")]

mod common;

use common::{REFRESH_DB, auth_config, play_the_tab, worker_config};
use connetto_wasm_smoke::workers::DB_NAME;
use connetto_web::auth::{
    LogoutOutcome, RefreshStore, ReplicaKeyStore, request_logout, request_unsynced,
};
use connetto_web::storage::{ReplicaStorage, clear_device_key, device_key, take_pending_wipes};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Query, log out and keep, log out and delete, against a live worker.
#[wasm_bindgen_test]
async fn a_tab_queries_the_count_then_logs_out_keeping_and_then_deleting() {
    let storage = ReplicaStorage::install().await;
    let keys = ReplicaKeyStore::open().await.expect("open the key store");
    take_pending_wipes().await.expect("drain any earlier wipes");
    clear_device_key(&keys).await.expect("clear the device key");
    storage
        .delete_db(REFRESH_DB)
        .expect("clear an earlier refresh store");

    let logins_served = play_the_tab();
    connetto_web::workers::boot_db_worker::<String>(&worker_config(Some(auth_config())))
        .await
        .expect("boot with logins on");
    assert_eq!(logins_served.get(), 1, "the boot logged in through the tab");

    // The count comes back from the connection the hub's pump owns, which is the
    // whole point of the query: nothing outside that task can read it directly.
    // Getting an answer at all is the proof, because a worker that cannot ask the
    // pump stays silent rather than reporting zero.
    let unsynced = request_unsynced().await.expect("the worker answers");
    assert!(
        unsynced.is_empty(),
        "a freshly synced replica has nothing queued, got {unsynced:?}"
    );

    // Logging out without deleting revokes the session and clears the credential,
    // and leaves the replica for the next login by this identity.
    assert_eq!(
        request_logout(false, false)
            .await
            .expect("the worker answers"),
        LogoutOutcome::Kept
    );
    assert!(
        take_pending_wipes().await.expect("drain").is_empty(),
        "keeping the data asks for no deletion"
    );
    let device = device_key(&keys).await.expect("the device key survives");
    let store =
        RefreshStore::open(&storage.db_url(REFRESH_DB), &device).expect("the store still opens");
    assert!(
        store.load().expect("read the store").is_none(),
        "the credential is gone, so the next boot cannot refresh silently"
    );
    drop(store);

    // Logging out and deleting records the wipe for the next startup, because this
    // worker holds the replica open and OPFS cannot delete a live file.
    assert_eq!(
        request_logout(true, true)
            .await
            .expect("the worker answers"),
        LogoutOutcome::Deleted
    );
    let pending = take_pending_wipes().await.expect("drain");
    assert_eq!(pending.len(), 1, "one replica was marked, got {pending:?}");
    assert!(
        pending[0].starts_with(DB_NAME) && pending[0] != DB_NAME,
        "the marked replica is this identity's, got {}",
        pending[0]
    );
}
