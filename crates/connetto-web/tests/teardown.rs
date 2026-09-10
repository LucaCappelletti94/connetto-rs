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
use connetto_core::traits::{RefreshTokenStore, ReplicaKeyStore};
use connetto_web::auth::{
    AuthError, IdbKeyStore, PendingWork, RefreshStore, provision_replica_key,
};
use connetto_web::storage::{
    PendingWipe, ReplicaStorage, WipeError, clear_device_key, device_key, mark_wipe_pending,
    take_pending_wipes, tier_db_name, wipe_replica,
};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use indexed_db_futures::database::Database as IdbDatabase;
use indexed_db_futures::prelude::*;
use indexed_db_futures::transaction::TransactionMode;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// A string written into each replica, so "still readable" is a claim about a
/// specific value rather than about an open succeeding.
const MARKER: &str = "connetto-teardown-canary-9d4e21b7";

/// The refresh token the encrypted store round-trips, and the string that must
/// not appear in the store's bytes at rest.
const REFRESH_TOKEN: &str = "session-id.connetto-refresh-canary-3f80ba61";
/// The account key used in store round-trip tests: JSON form of a `String` id.
const ACCOUNT: &str = "\"tester\"";

diesel::table! {
    /// Table with a marker string to verify encryption at rest
    canary (id) {
        /// Row identifier, the primary key
        id -> Integer,
        /// Marker string for encryption verification
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

fn work(seqs: &[u64]) -> PendingWork {
    PendingWork {
        mutation_seqs: seqs.to_vec(),
        content_files: 0,
    }
}

fn pending_wipe(name: &str) -> PendingWipe {
    PendingWipe::new(name, None)
}

/// Leave no trace of `name` from an earlier run, so each test starts from nothing
/// rather than from whatever the last one left in this origin's OPFS.
async fn reset(storage: &ReplicaStorage, keys: &IdbKeyStore, name: &str) {
    storage.delete_db(name).expect("clear any earlier file");
    keys.clear(name).await.expect("clear any earlier key");
}

/// Wipe mode, and the shared-device case that makes it dangerous: a wipe names one
/// pool entry and one key record, and reaches nothing else.
#[wasm_bindgen_test]
async fn a_wipe_shreds_one_identitys_replica_and_leaves_the_others_readable() {
    let storage = ReplicaStorage::install().await;
    let keys = IdbKeyStore::open().await.expect("open the key store");
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

    wipe_replica(&storage, &keys, alice, &work(&[]), false)
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

/// R17: the device-private database goes with the replica, because it shares the
/// key being shredded and has no key record of its own.
///
/// Left behind it would outlive the key that opens it, and the next boot for this
/// identity would mint a fresh key, meet the surviving file and die at the unlock.
/// That is the same failure R17 closed for a second identity, arriving through the
/// wipe path instead, and naming the tier per identity does not fix it because the
/// name stays stable for that identity.
#[wasm_bindgen_test]
async fn a_wipe_destroys_the_tier_beside_the_replica() {
    let storage = ReplicaStorage::install().await;
    let keys = IdbKeyStore::open().await.expect("open the key store");
    let alice = "e3-tier-wipe-alice.sqlite";
    let bob = "e3-tier-wipe-bob.sqlite";
    reset(&storage, &keys, alice).await;
    reset(&storage, &keys, bob).await;
    storage.delete_db(&tier_db_name(alice)).expect("clear");
    storage.delete_db(&tier_db_name(bob)).expect("clear");
    // Four databases at once and a rollback journal for each, against a pool
    // that ships six slots and holds whatever the earlier tests left.
    // `boot_db_worker` reserves for the same reason.
    storage.reserve(8).await.expect("room in the pool");

    // Two identities, each with a replica and the device-private database beside
    // it, both under that identity's one key.
    for name in [alice, bob] {
        let key = provision_replica_key(&keys, name).await.expect("mint");
        write_marker(&mut open(&storage, name, &key));
        write_marker(&mut open(&storage, &tier_db_name(name), &key));
    }
    assert!(
        storage.exists(&tier_db_name(alice)) && storage.exists(&tier_db_name(bob)),
        "both device-private databases are here"
    );

    wipe_replica(&storage, &keys, alice, &work(&[]), false)
        .await
        .expect("wipe alice");

    // Read off the pool's own listing, not off what the delete returned.
    let listed = storage.list();
    assert!(
        !listed.iter().any(|entry| entry == &tier_db_name(alice)),
        "the wiped identity's device-private database is gone too"
    );
    assert!(
        listed.iter().any(|entry| entry == &tier_db_name(bob)),
        "and the other identity's is untouched"
    );
}

/// The guard. A wipe with unsynced work and no force destroys nothing, so the
/// queued writes can still be uploaded with the credential that is still live.
#[wasm_bindgen_test]
async fn a_wipe_refuses_to_drop_unsynced_writes_and_destroys_nothing() {
    let storage = ReplicaStorage::install().await;
    let keys = IdbKeyStore::open().await.expect("open the key store");
    let name = "e3-guard.sqlite";
    reset(&storage, &keys, name).await;

    let key = provision_replica_key(&keys, name)
        .await
        .expect("mint a key");
    write_marker(&mut open(&storage, name, &key));

    let blocked = work(&[7, 9]);
    match wipe_replica(&storage, &keys, name, &blocked, false).await {
        Err(WipeError::Unsynced(actual)) => assert_eq!(actual, blocked),
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
    let keys = IdbKeyStore::open().await.expect("open the key store");
    let name = "e3-refresh.sqlite";
    storage.delete_db(name).expect("clear any earlier file");
    clear_device_key(&keys)
        .await
        .expect("clear any earlier key");

    let device = device_key(&keys).await.expect("mint the device key");
    let url = storage.db_url(name);
    {
        let store = RefreshStore::open(&url, &device).expect("open the refresh store");
        store.store(ACCOUNT, REFRESH_TOKEN).expect("save the token");
        assert_eq!(
            store.load(ACCOUNT).expect("load").as_deref(),
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
        store.load(ACCOUNT).expect("load").as_deref(),
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
    let keys = IdbKeyStore::open().await.expect("open the key store");
    let name = "e3-refresh-shred.sqlite";
    storage.delete_db(name).expect("clear any earlier file");
    clear_device_key(&keys)
        .await
        .expect("clear any earlier key");

    let device = device_key(&keys).await.expect("mint the device key");
    let url = storage.db_url(name);
    {
        let store = RefreshStore::open(&url, &device).expect("open the refresh store");
        store.store(ACCOUNT, REFRESH_TOKEN).expect("save the token");
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
        store.load(ACCOUNT).expect("load"),
        None,
        "the discarded credential is gone, so the next boot must log in"
    );
}

/// A wipe record survives being written and one successful acknowledgement
/// clears it, so a completed wipe is not repeated on the next boot.
#[wasm_bindgen_test]
async fn a_pending_wipe_is_taken_exactly_once() {
    let name = "e4c-pending.sqlite";

    // Whatever an earlier test or run left, start from nothing.
    take_pending_wipes().await.expect("drain");

    mark_wipe_pending(&pending_wipe(name), &work(&[]), false)
        .await
        .expect("mark a clean replica");
    // Marking twice is the same as marking once, which matters because a user can
    // press the button twice.
    mark_wipe_pending(&pending_wipe(name), &work(&[]), false)
        .await
        .expect("mark again");

    let taken = take_pending_wipes().await.expect("take");
    assert_eq!(
        taken,
        vec![pending_wipe(name)],
        "the boot after the request finds it, once"
    );
    assert!(
        take_pending_wipes().await.expect("take again").is_empty(),
        "and the boot after that finds nothing, so a wipe is not repeated"
    );
}

#[wasm_bindgen_test]
async fn a_legacy_replica_only_wipe_is_preserved() {
    take_pending_wipes().await.expect("drain");
    let name = "e4c-legacy-pending.sqlite";
    let db = IdbDatabase::open("connetto-pending-wipes")
        .await
        .expect("open pending wipes");
    let tx = db
        .transaction("pending")
        .with_mode(TransactionMode::Readwrite)
        .build()
        .expect("write transaction");
    tx.object_store("pending")
        .expect("wipe store")
        .put(name)
        .with_key(name)
        .primitive()
        .expect("legacy put")
        .await
        .expect("legacy put await");
    tx.commit().await.expect("legacy commit");

    assert_eq!(
        take_pending_wipes().await.expect("read legacy wipe"),
        vec![PendingWipe::new(name, None)]
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
    mark_wipe_pending(&pending_wipe(alice), &work(&[]), false)
        .await
        .expect("mark");
    mark_wipe_pending(&pending_wipe(bob), &work(&[]), false)
        .await
        .expect("mark");

    let mut taken = take_pending_wipes().await.expect("take");
    taken.sort();
    assert_eq!(
        taken,
        vec![pending_wipe(alice), pending_wipe(bob)],
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

    let blocked = work(&[3, 4]);
    match mark_wipe_pending(&pending_wipe(name), &blocked, false).await {
        Err(WipeError::Unsynced(actual)) => assert_eq!(actual, blocked),
        Err(other) => panic!("expected Unsynced, got {other:?}"),
        Ok(()) => panic!("marking must not silently accept losing queued writes"),
    }
    assert!(
        take_pending_wipes().await.expect("take").is_empty(),
        "a refused request leaves nothing pending, so the next boot opens normally"
    );

    // Forcing is the app telling the user what is being discarded and proceeding.
    mark_wipe_pending(&pending_wipe(name), &blocked, true)
        .await
        .expect("a forced request is accepted");
    assert_eq!(
        take_pending_wipes().await.expect("take"),
        vec![pending_wipe(name)],
        "and it is pending for the next boot"
    );
}

/// The deferred wipe destroys the same things the immediate one does, which is the
/// point: deferring moves *when* it happens, never *what* happens.
#[wasm_bindgen_test]
async fn a_deferred_wipe_destroys_the_replica_and_its_key() {
    let storage = ReplicaStorage::install().await;
    let keys = IdbKeyStore::open().await.expect("open the key store");
    let name = "e4c-deferred.sqlite";
    reset(&storage, &keys, name).await;
    take_pending_wipes().await.expect("drain");

    let key = provision_replica_key(&keys, name)
        .await
        .expect("mint a key");
    write_marker(&mut open(&storage, name, &key));
    assert!(storage.exists(name), "the replica is here to begin with");

    // What the application does at the prompt.
    mark_wipe_pending(&pending_wipe(name), &work(&[]), false)
        .await
        .expect("mark");

    // What the next boot does before its login and before it opens anything, which
    // is exactly the sequence `boot_db_worker` runs.
    for pending in take_pending_wipes().await.expect("take") {
        wipe_replica(
            &storage,
            &keys,
            &pending.replica,
            &PendingWork::default(),
            true,
        )
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
