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
//! **Needs the stack up.** Database, sync server, and login server:
//!
//! ```text
//! docker run -d --rm --name connetto-e42-pg -e POSTGRES_PASSWORD=postgres \
//!   -p 55470:5432 postgres:16 -c wal_level=logical
//! psql -c "$(cat examples/wasm-smoke/schema.sql)"
//! psql -c "CREATE PUBLICATION connetto_pub FOR TABLE orders"
//! psql -c "SELECT pg_create_logical_replication_slot('connetto_slot', 'pgoutput')"
//! psql -c "CREATE TABLE _connetto_mutations (user_id TEXT NOT NULL, \
//!   session_id UUID NOT NULL, last_seq BIGINT NOT NULL, \
//!   PRIMARY KEY (user_id, session_id))"
//!
//! CONNETTO_BIND=127.0.0.1:7777 CONNETTO_WRITABLE=orders \
//!   CONNETTO_PG_DDL_FILE=examples/wasm-smoke/schema.sql \
//!   DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55470/postgres \
//!   cargo run --release --all-features -p connetto-server --bin connetto-server
//! cargo run --release --all-features -p connetto-server --example auth_stack
//! wasm-pack test --headless --chrome examples/wasm-smoke --test authenticated_boot
//! ```
//!
//! The server reads the schema from the same file the client hashes, because the
//! handshake compares the two and a reworded copy is a different schema. It must
//! also be started WITHOUT `CONNETTO_AUTH`, so the handshake trusts the token: the
//! login here comes from `auth_stack`, whose sessions a database-backed server
//! knows nothing about, and it would refuse them.
//!
//! One honest limit of this topology. The login server and the sync server are
//! separate processes here, and cross-process token verification needs them to
//! share a session store, which is what a real deployment gets by having one
//! process do both jobs. So the sync server accepts the token without verifying
//! it. That verification is not what this test is for. It is proven, against one
//! `connetto-server` minting and verifying its own tokens over a Postgres session
//! store, by `connetto-client/tests/verified_topology.rs`.

#![cfg(target_arch = "wasm32")]

mod common;

use common::{REFRESH_DB, auth_config, play_the_tab, walk_the_login, worker_config};
use connetto_client::replica_db_name;
use connetto_wasm_smoke::workers::DB_NAME;
use connetto_web::auth::{
    Acquired, BrowserAuthenticator, RefreshStore, ReplicaKeyStore, provision_replica_key,
};
use connetto_web::storage::{
    ReplicaStorage, clear_device_key, device_key, mark_wipe_pending, take_pending_wipes,
};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The logged-in startup, end to end, including the delete-at-startup step.
#[wasm_bindgen_test]
async fn the_logged_in_startup_runs_and_carries_out_a_pending_delete() {
    let storage = ReplicaStorage::install().await;
    let keys = ReplicaKeyStore::open().await.expect("open the key store");

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
        let store = RefreshStore::open(&storage.db_url(REFRESH_DB, true), &device)
            .expect("open the refresh store");
        let authenticator = BrowserAuthenticator::new(auth_config());
        let pending = match authenticator
            .acquire::<String>(&store)
            .await
            .expect("acquire")
        {
            Acquired::NeedLogin(pending) => pending,
            Acquired::Access(_) => panic!("an empty store cannot refresh"),
        };
        let (code, state) = walk_the_login(&pending.login_url).await;
        authenticator
            .complete::<String>(&pending, &code, &state, &store)
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
        booted_as.as_deref(),
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
    // the bare prefix an unauthenticated startup would have used.
    assert!(
        storage.list().iter().any(|entry| entry == &replica_name),
        "the account's replica is in the pool"
    );
    assert_ne!(
        replica_name, DB_NAME,
        "a logged-in startup names the replica after the account"
    );
}
