//! The logout channel, driven the way a page drives it.
//!
//! The worker owns the token, the replica, and its key, so a tab can only ask. This
//! boots the worker with logins on and then speaks to it exactly as a signed-out
//! button would: ask how much is unsynced, log out keeping the data, log out
//! destroying it.
//!

#![cfg(target_arch = "wasm32")]

mod common;

use common::{ACCOUNT_DB, auth_config, play_the_tab, worker_config};
use connetto_wasm_smoke::workers::DB_NAME;
use connetto_web::auth::{AccountStore, LogoutOutcome, request_logout, request_unsynced};
use connetto_web::storage::{ReplicaStorage, take_pending_wipes};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Query, log out and keep, log out and delete, against a live worker.
#[wasm_bindgen_test]
async fn a_tab_queries_the_count_then_logs_out_keeping_and_then_deleting() {
    let storage = ReplicaStorage::install().await;
    take_pending_wipes().await.expect("drain any earlier wipes");
    storage
        .delete_db(ACCOUNT_DB)
        .expect("clear an earlier account index");

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
    let store =
        AccountStore::open(&storage.db_url(ACCOUNT_DB)).expect("the account index still opens");
    assert!(
        store.accounts().expect("list accounts").is_empty(),
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
        pending[0].replica.starts_with(DB_NAME) && pending[0].replica != DB_NAME,
        "the marked replica is this identity's, got {}",
        pending[0].replica
    );
}
