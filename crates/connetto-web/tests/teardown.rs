//! Browser acceptance for phase E3: the data-teardown half of the logout grid,
//! against real OPFS and real `IndexedDB`.
//!
//! Runs in a dedicated worker, because the OPFS sahpool VFS needs synchronous
//! access handles and only a worker has them. That is also the context the real
//! DB worker runs in, so this exercises the same stack `boot_db_worker` does.
//!
//! The wipe's central claim is a negative, so nothing here trusts a delete's
//! return value. A wiped replica is gone from the pool's own listing and its
//! wrapped key is gone from `IndexedDB`, while a second identity's replica is
//! still listed and still opens and reads under its own key.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::cipher::ReplicaKey;
use connetto_web::auth::{AuthError, RefreshStore, ReplicaKeyStore, provision_replica_key};
use connetto_web::storage::{
    ReplicaStorage, WipeError, clear_device_key, device_key, mark_wipe_pending, take_pending_wipes,
    wipe_replica,
};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// A string written into each replica, so "still readable" is a claim about a
/// specific value rather than about an open succeeding.
const MARKER: &str = "connetto-teardown-canary-9d4e21b7";

/// The refresh token the encrypted store round-trips, and the string that must
/// not appear in the store's bytes at rest.
const REFRESH_TOKEN: &str = "session-id.connetto-refresh-canary-3f80ba61";

diesel::table! {
    canary (id) {
        id -> Integer,
        note -> Text,
    }
}

/// The sahpool utility, for reading raw OPFS bytes back. `install` registers once
/// per worker, so this and [`ReplicaStorage::install`] are handles to one pool.
async fn pool() -> sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil {
    sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    .expect("install the sahpool VFS")
}

/// Open `name` encrypted under `key` through the storage seam's own URL, which is
/// what the worker boot hands its connection.
///
/// The returned connection must be dropped before the name is deleted or reopened:
/// `sqlite-wasm-rs` allows one connection per database. Dropping is enough and
/// needs no await, which is the precondition phase E2 measured.
fn open(storage: &ReplicaStorage, name: &str, key: &ReplicaKey) -> SqliteConnection {
    let mut conn = SqliteConnection::establish(&storage.db_url(name)).expect("open the database");
    connetto_client::cipher::unlock(&mut conn, key).expect("apply the key");
    conn
}

fn write_marker(conn: &mut SqliteConnection) {
    conn.batch_execute("CREATE TABLE canary (id INTEGER PRIMARY KEY, note TEXT NOT NULL);")
        .expect("create the canary table");
    diesel::insert_into(canary::table)
        .values((canary::id.eq(1), canary::note.eq(MARKER)))
        .execute(conn)
        .expect("insert the canary row");
}

fn read_marker(storage: &ReplicaStorage, name: &str, key: &ReplicaKey) -> String {
    canary::table
        .select(canary::note)
        .first(&mut open(storage, name, key))
        .expect("read the canary row back")
}

/// Whether `haystack` contains `needle` as a contiguous byte run.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Leave no trace of `name` from an earlier run, so each test starts from nothing
/// rather than from whatever the last one left in this origin's OPFS.
async fn reset(storage: &ReplicaStorage, keys: &ReplicaKeyStore, name: &str) {
    storage.delete_db(name).expect("clear any earlier file");
    keys.clear(name).await.expect("clear any earlier key");
}

/// Wipe mode, and the shared-device case that makes it dangerous: a wipe names one
/// pool entry and one key record, and reaches nothing else.
#[wasm_bindgen_test]
async fn a_wipe_shreds_one_identitys_replica_and_leaves_the_others_readable() {
    let storage = ReplicaStorage::install().await;
    let keys = ReplicaKeyStore::open().await.expect("open the key store");
    let alice = "e3-wipe-alice.sqlite";
    let bob = "e3-wipe-bob.sqlite";
    reset(&storage, &keys, alice).await;
    reset(&storage, &keys, bob).await;

    // Each identity mints its own key, which is what makes opening the wrong
    // identity's file fail rather than merely be impolite.
    let alice_key = provision_replica_key(&keys, alice)
        .await
        .expect("mint alice's key");
    let bob_key = provision_replica_key(&keys, bob)
        .await
        .expect("mint bob's key");
    assert_ne!(alice_key, bob_key, "identities do not share a key");

    write_marker(&mut open(&storage, alice, &alice_key));
    write_marker(&mut open(&storage, bob, &bob_key));
    assert!(
        storage.exists(alice) && storage.exists(bob),
        "both are here"
    );

    wipe_replica(&storage, &keys, alice, &[], false)
        .await
        .expect("wipe alice");

    // The negative claim, read off the pool's own listing rather than the delete.
    assert!(
        !storage.list().iter().any(|entry| entry == alice),
        "the wiped replica is no longer in the pool"
    );
    assert!(!storage.exists(alice), "and does not exist by name either");
    // Crypto-shredded: a forensic copy of the ciphertext has no key left.
    assert_eq!(
        keys.load(alice).await.expect("load"),
        None,
        "the wrapped key is gone from IndexedDB, so leftover ciphertext is inert"
    );

    // Isolation, which is the bug this ordering exists to avoid.
    assert!(
        storage.list().iter().any(|entry| entry == bob),
        "the other identity's replica is still in the pool"
    );
    assert_eq!(
        keys.load(bob).await.expect("load"),
        Some(bob_key.clone()),
        "and still has its key"
    );
    assert_eq!(
        read_marker(&storage, bob, &bob_key),
        MARKER,
        "the other identity's replica still decrypts under its own key"
    );
}

/// The guard. A wipe with unsynced work and no force destroys nothing, so the
/// queued writes can still be uploaded with the credential that is still live.
#[wasm_bindgen_test]
async fn a_wipe_refuses_to_drop_unsynced_writes_and_destroys_nothing() {
    let storage = ReplicaStorage::install().await;
    let keys = ReplicaKeyStore::open().await.expect("open the key store");
    let name = "e3-guard.sqlite";
    reset(&storage, &keys, name).await;

    let key = provision_replica_key(&keys, name)
        .await
        .expect("mint a key");
    write_marker(&mut open(&storage, name, &key));

    match wipe_replica(&storage, &keys, name, &[7, 9], false).await {
        Err(WipeError::Unsynced(blocked)) => assert_eq!(blocked, vec![7, 9]),
        Err(other) => panic!("expected Unsynced, got {other:?}"),
        Ok(()) => panic!("a wipe must not silently drop queued writes"),
    }

    // Nothing was destroyed, and specifically not the key: shredding it and then
    // refusing the delete would leave the queued work unreachable anyway.
    assert!(storage.exists(name), "the blocked wipe deletes nothing");
    assert_eq!(
        keys.load(name).await.expect("load"),
        Some(key.clone()),
        "the blocked wipe keeps the key"
    );
    assert_eq!(
        read_marker(&storage, name, &key),
        MARKER,
        "the replica is untouched and still readable"
    );
}

/// The refresh store is ciphertext at rest under this device's own key, and it
/// survives a cold reopen, which is what a worker restart or a leader failover
/// performs.
#[wasm_bindgen_test]
async fn the_refresh_store_is_encrypted_under_the_device_key_and_survives_a_reopen() {
    let storage = ReplicaStorage::install().await;
    let keys = ReplicaKeyStore::open().await.expect("open the key store");
    let name = "e3-refresh.sqlite";
    storage.delete_db(name).expect("clear any earlier file");
    clear_device_key(&keys)
        .await
        .expect("clear any earlier key");

    let device = device_key(&keys).await.expect("mint the device key");
    let url = storage.db_url(name);
    {
        let store = RefreshStore::open(&url, &device).expect("open the refresh store");
        store.save(REFRESH_TOKEN).expect("save the token");
        assert_eq!(
            store.load().expect("load").as_deref(),
            Some(REFRESH_TOKEN),
            "the token round-trips through the encrypted store"
        );
    }

    // Read the OPFS bytes back: the credential must not be sitting there in the
    // clear, which is what it did before this phase.
    let bytes = pool().await.export_db(name).expect("export the OPFS bytes");
    assert!(
        !contains(&bytes, REFRESH_TOKEN.as_bytes()),
        "the refresh token must not survive as plaintext in OPFS"
    );
    assert!(
        !contains(&bytes, b"CREATE TABLE"),
        "nor must the schema text"
    );

    // A cold reopen finds the same device key cached and reads the token back, so
    // a worker restart still refreshes silently.
    let cached = device_key(&keys).await.expect("the device key is cached");
    assert_eq!(
        cached, device,
        "the device key is minted once, not per boot"
    );
    let store = RefreshStore::open(&url, &cached).expect("reopen the refresh store");
    assert_eq!(
        store.load().expect("load").as_deref(),
        Some(REFRESH_TOKEN),
        "the stored credential survives a cold reopen"
    );
}

/// Destroying the device key makes the refresh store unreadable, which is exactly
/// what the worker boot recovers from by discarding the store: the credential
/// inside is unreachable and the only way forward is a fresh login.
#[wasm_bindgen_test]
async fn a_destroyed_device_key_makes_the_refresh_store_undecryptable_and_discardable() {
    let storage = ReplicaStorage::install().await;
    let keys = ReplicaKeyStore::open().await.expect("open the key store");
    let name = "e3-refresh-shred.sqlite";
    storage.delete_db(name).expect("clear any earlier file");
    clear_device_key(&keys)
        .await
        .expect("clear any earlier key");

    let device = device_key(&keys).await.expect("mint the device key");
    let url = storage.db_url(name);
    {
        let store = RefreshStore::open(&url, &device).expect("open the refresh store");
        store.save(REFRESH_TOKEN).expect("save the token");
    }

    clear_device_key(&keys).await.expect("shred the device key");
    let reminted = device_key(&keys).await.expect("a later boot mints again");
    assert_ne!(
        reminted, device,
        "the mint is fresh randomness, not a constant"
    );
    match RefreshStore::open(&url, &reminted) {
        Err(AuthError::Undecryptable(_)) => {}
        Err(other) => panic!("expected Undecryptable, got {other:?}"),
        Ok(_) => panic!("a re-minted device key must not open the old store"),
    }

    // The boot's recovery: discard the unreachable store and start an empty one,
    // which forces the interactive login.
    storage.delete_db(name).expect("discard the store");
    let store = RefreshStore::open(&url, &reminted).expect("a fresh store opens");
    assert_eq!(
        store.load().expect("load"),
        None,
        "the discarded credential is gone, so the next boot must log in"
    );
}

/// A wipe the application asks for is deferred to the next boot, because nothing
/// can delete the replica while the hub's pump holds a connection to it. The record
/// survives being written and is taken exactly once, so the wipe happens on the
/// next boot and not on the one after that too.
#[wasm_bindgen_test]
async fn a_pending_wipe_is_taken_exactly_once() {
    let name = "e4c-pending.sqlite";

    // Whatever an earlier test or run left, start from nothing.
    take_pending_wipes().await.expect("drain");

    mark_wipe_pending(name, &[], false)
        .await
        .expect("mark a clean replica");
    // Marking twice is the same as marking once, which matters because a user can
    // press the button twice.
    mark_wipe_pending(name, &[], false)
        .await
        .expect("mark again");

    let taken = take_pending_wipes().await.expect("take");
    assert_eq!(
        taken,
        vec![name.to_owned()],
        "the boot after the request finds it, once"
    );
    assert!(
        take_pending_wipes().await.expect("take again").is_empty(),
        "and the boot after that finds nothing, so a wipe is not repeated"
    );
}

/// Nothing about acting on a pending wipe needs an identity, which is what lets the
/// boot do it before any login. Two identities' replicas marked in turn come back
/// from one drain, with no login and no name given.
#[wasm_bindgen_test]
async fn pending_wipes_are_drained_without_naming_anyone() {
    take_pending_wipes().await.expect("drain");

    let alice = "e4c-drain-alice.sqlite";
    let bob = "e4c-drain-bob.sqlite";
    mark_wipe_pending(alice, &[], false).await.expect("mark");
    mark_wipe_pending(bob, &[], false).await.expect("mark");

    let mut taken = take_pending_wipes().await.expect("take");
    taken.sort();
    assert_eq!(
        taken,
        vec![alice.to_owned(), bob.to_owned()],
        "one drain returns every outstanding wipe, whoever asked for it"
    );
}

/// The unsynced guard lives at the marking, not at the boot, and this is why: at
/// boot the replica is closed and its queued writes are unreadable, so the only
/// moment the guard can protect anything is while the connection is open and the
/// credential still works.
#[wasm_bindgen_test]
async fn marking_a_wipe_refuses_to_discard_unsynced_writes() {
    let name = "e4c-pending-guard.sqlite";
    take_pending_wipes().await.expect("drain");

    match mark_wipe_pending(name, &[3, 4], false).await {
        Err(WipeError::Unsynced(blocked)) => assert_eq!(blocked, vec![3, 4]),
        Err(other) => panic!("expected Unsynced, got {other:?}"),
        Ok(()) => panic!("marking must not silently accept losing queued writes"),
    }
    assert!(
        take_pending_wipes().await.expect("take").is_empty(),
        "a refused request leaves nothing pending, so the next boot opens normally"
    );

    // Forcing is the app telling the user what is being discarded and proceeding.
    mark_wipe_pending(name, &[3, 4], true)
        .await
        .expect("a forced request is accepted");
    assert_eq!(
        take_pending_wipes().await.expect("take"),
        vec![name.to_owned()],
        "and it is pending for the next boot"
    );
}

/// The deferred wipe destroys the same things the immediate one does, which is the
/// point: deferring moves *when* it happens, never *what* happens.
#[wasm_bindgen_test]
async fn a_deferred_wipe_destroys_the_replica_and_its_key() {
    let storage = ReplicaStorage::install().await;
    let keys = ReplicaKeyStore::open().await.expect("open the key store");
    let name = "e4c-deferred.sqlite";
    reset(&storage, &keys, name).await;
    take_pending_wipes().await.expect("drain");

    let key = provision_replica_key(&keys, name)
        .await
        .expect("mint a key");
    write_marker(&mut open(&storage, name, &key));
    assert!(storage.exists(name), "the replica is here to begin with");

    // What the application does at the prompt.
    mark_wipe_pending(name, &[], false).await.expect("mark");

    // What the next boot does before its login and before it opens anything, which
    // is exactly the sequence `boot_db_worker` runs.
    for pending in take_pending_wipes().await.expect("take") {
        wipe_replica(&storage, &keys, &pending, &[], true)
            .await
            .expect("carry out the deferred wipe");
    }

    assert!(
        !storage.list().iter().any(|entry| entry == name),
        "the replica is gone from the pool"
    );
    assert_eq!(
        keys.load(name).await.expect("load"),
        None,
        "and its key is gone, so the leftover ciphertext is inert"
    );
}
