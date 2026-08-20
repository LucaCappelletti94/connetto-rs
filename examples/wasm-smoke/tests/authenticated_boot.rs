//! Phase E4.2: the logged-in startup path, which had never run.
//!
//! `auth` is `None` in every application, so while each piece of the logged-in
//! startup is tested on its own, the routine that strings them together had only
//! ever run with logins off. This boots it with logins on, against a real login
//! server and a real sync server, and drives the parts of it no other test reaches.
//!
//! Three of the four never-run paths are covered here. The tab-to-worker login
//! handoff runs for real, because the test plays the tab: it listens on the login
//! channel, walks the login the way a navigating tab would, and posts the result
//! back, so `await_login_code` and `deliver_login_code` both execute. The assembly
//! runs: log in, name the replica from the account, get its key, open it encrypted,
//! open the private tables under the same key, connect, subscribe. And the
//! delete-at-startup step runs inside the startup rather than being replayed by a
//! test, which is asserted through the key: a wipe destroys the old key, and the
//! fresh replica the startup then creates is keyed anew, so a changed key is proof
//! the branch fired. The fourth, recovering from a refresh store that no longer
//! decrypts, is in `authenticated_boot_recovery.rs`.
//!
//! The browser-stack runner supplies Postgres, OpenFGA, the provider, keys, and the sync server.

#![cfg(target_arch = "wasm32")]

mod common;

use common::{REFRESH_DB, auth_config, play_the_tab, walk_the_login, worker_config};
use connetto_client::{encode_identity, replica_db_name};
use connetto_core::traits::ReplicaKeyStore;
use connetto_wasm_smoke::workers::DB_NAME;
use connetto_web::auth::{
    Acquired, BrowserAuthenticator, IdbKeyStore, RefreshStore, provision_replica_key,
    remembered_account, remembered_identity,
};
use connetto_web::storage::{
    ReplicaStorage, clear_device_key, device_key, mark_wipe_pending, take_pending_wipes,
    tier_db_name,
};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The logged-in startup, end to end, including the delete-at-startup step.
#[wasm_bindgen_test]
async fn the_logged_in_startup_runs_and_carries_out_a_pending_delete() {
    let storage = ReplicaStorage::install().await;
    let keys = IdbKeyStore::open().await.expect("open the key store");

    // Start from nothing, so a rerun is not resuming an earlier session.
    take_pending_wipes().await.expect("drain any earlier wipes");
    clear_device_key(&keys).await.expect("clear the device key");
    storage
        .delete_db(REFRESH_DB)
        .expect("clear an earlier refresh store");

    // A first login outside the startup, only to learn which replica this account
    // owns, which the test needs in order to plant a delete request for it. The
    // refresh token it leaves is thrown away below, so the startup cannot refresh
    // silently and has to log in through the tab.
    let device = device_key(&keys).await.expect("mint the device key");
    let user_id = {
        let store = RefreshStore::open(&storage.db_url(REFRESH_DB), &device)
            .expect("open the refresh store");
        let authenticator = BrowserAuthenticator::new(auth_config(), None);
        let pending = match authenticator
            .acquire::<String, _>(&store)
            .await
            .expect("acquire")
        {
            Acquired::NeedLogin(pending) => pending,
            Acquired::Access(_) => panic!("an empty store cannot refresh"),
        };
        let (code, state) = walk_the_login(&pending.login_url).await;
        authenticator
            .complete::<String, _>(&pending, &code, &state, &store)
            .await
            .expect("complete the first login")
            .user_id
    };
    let replica_name = replica_db_name(DB_NAME, &user_id).expect("a replica name");
    storage
        .delete_db(REFRESH_DB)
        .expect("discard the first login's refresh token");

    // Plant a replica for that account with a key of its own, then ask for it to be
    // deleted. This is the state a user leaves behind by pressing the delete button.
    storage
        .delete_db(&replica_name)
        .expect("clear an earlier replica");
    keys.clear(&replica_name).await.expect("clear its key");
    let doomed_key = provision_replica_key(&keys, &replica_name)
        .await
        .expect("key the doomed replica");
    mark_wipe_pending(&replica_name, &[], false)
        .await
        .expect("ask for the delete");

    // The startup. It has no refresh token, so it asks the tab to log in and the
    // test answers. Then it drains the delete request and carries it out before
    // opening anything, then creates a fresh replica for the same
    // account, opens it encrypted, opens the private tables under the same key,
    // connects to the sync server, and subscribes.
    let logins_served = play_the_tab();
    let booted_as =
        connetto_web::workers::boot_db_worker::<String>(&worker_config(Some(auth_config())))
            .await
            .expect("the logged-in startup completes");

    // The startup reports the identity it acquired, which is the same account the
    // first login named. An application needs this to say who is signed in without
    // acquiring a second session of its own.
    assert_eq!(
        booted_as.identity.as_deref(),
        Some(user_id.as_str()),
        "the startup reports the account it opened the replica for"
    );

    // The login went through the tab, so the tab-to-worker handoff ran rather than
    // being bypassed by a silent refresh.
    assert_eq!(
        logins_served.get(),
        1,
        "the startup asked the tab to log in exactly once"
    );

    // The delete happened inside the startup: the request is gone, and the key the
    // doomed replica was encrypted under has been destroyed and replaced by the one
    // the fresh replica was created with. A startup that skipped the delete would
    // have kept the old key and reused it.
    assert!(
        take_pending_wipes().await.expect("drain").is_empty(),
        "the startup took the delete request"
    );
    let live_key = keys
        .load(&replica_name)
        .await
        .expect("load")
        .expect("the fresh replica has a key");
    assert_ne!(
        live_key, doomed_key,
        "the old key was destroyed and the fresh replica keyed anew"
    );

    // And the account owns its replica, named from its identity rather than from
    // the bare prefix an unauthenticated startup would have used. The
    // device-private database beside it is named from the replica in turn, which
    // is what R17 closed: it used to carry one name for the whole device while
    // its key was per identity, so the second account to sign in opened the first
    // one's file and could not unlock it.
    let listed = storage.list();
    assert!(
        listed.iter().any(|entry| entry == &replica_name),
        "the account's replica is in the pool"
    );
    assert_ne!(
        replica_name, DB_NAME,
        "a logged-in startup names the replica after the account"
    );
    assert!(
        listed
            .iter()
            .any(|entry| entry == &tier_db_name(&replica_name)),
        "and the startup opened the device-private database the derivation names"
    );

    // R20 step 0: the startup wrote down which account it signed in as, beside
    // the credential it stored. This is what a later start with no network has
    // to read, because the account otherwise only ever arrives inside a token
    // response and fetching one needs the network. The test deleted this
    // database before the startup ran, so the record here was written by the
    // login the startup itself performed.
    let device = device_key(&keys).await.expect("the device key");
    let store = RefreshStore::open(&storage.db_url(REFRESH_DB), &device).expect("reopen the store");
    let remembered: Option<String> = remembered_identity(&store).expect("read the record");
    assert_eq!(
        remembered.as_deref(),
        Some(user_id.as_str()),
        "the startup remembered the account it signed in as"
    );
    let account = remembered_account(&store)
        .expect("read account")
        .expect("startup stored an account marker");
    let expected_account = encode_identity(&user_id).expect("encode the account key");
    assert_eq!(
        account, expected_account,
        "the account marker holds the encoded id and is the store key for the credential"
    );
    assert_eq!(
        replica_db_name(DB_NAME, &remembered.expect("remembered")).expect("derive"),
        replica_name,
        "and the remembered account names the very replica the startup opened"
    );
}
