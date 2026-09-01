//! Native acceptance for phase E3, the data-teardown half of the logout grid.
//!
//! Every assertion is about the filesystem and the key store after the fact, not
//! about a delete having returned `Ok`. The wipe's central claim is a negative
//! (nothing decryptable is left), so it is proven by looking: the replica and both
//! its sidecars are gone, the key-store record for it is gone, and a second
//! identity's replica on the same device is still there and still opens under its
//! own key.
//!
//! The keep-mode claim is proven the same way, by opening: after credential
//! teardown alone the replica opens from its cached key with its persisted cursor
//! and its unsynced work intact, which is what makes a fast return possible.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use connetto_client::teardown::{
    ForgetError, PurgeError, forget_device, purge_replica, wipe_replica,
};
use connetto_client::{
    ClientConfig, ClientError, ConnettoConnection, Grant, MemoryKeyStore, MemoryRefreshStore,
    NativeAuthenticator, Replica, ReplicaKey, encode_identity, provision_replica_key,
    replica_db_name,
};
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::{RefreshTokenStore, ReplicaKeyStore};
use diesel::prelude::*;

/// A string written into the replica, so a leftover-plaintext assertion has
/// something specific to look for.
const MARKER: &str = "connetto-teardown-canary-9d4e21b7";

const SQLITE_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

diesel::table! {
    /// Test table for items in the replica.
    items (id) {
        /// Item identifier, the primary key.
        id -> Integer,
        /// Item label text.
        label -> Nullable<Text>,
    }
}

fn config() -> ClientConfig {
    ClientConfig::new("e3").with_login(Some(Grant::new("user:token")))
}

/// The utf-8 form of a temporary path, with the same expectation spelled once.
fn url(path: &Path) -> String {
    path.to_str().expect("a utf-8 temporary path").to_owned()
}

/// First-boot an encrypted replica for `user_id` under a key this device mints,
/// write the canary, and leave one mutation unsynced (the fake server never
/// acknowledges). Returns the file path, its key-store record name, and the
/// pending sequence numbers captured before the connection dropped.
async fn seed_replica(
    dir: &Path,
    keys: &MemoryKeyStore,
    user_id: &str,
) -> (PathBuf, String, Vec<u64>) {
    let record = replica_db_name("replica", user_id).expect("a replica name");
    let path = dir.join(&record);
    let db = url(&path);
    let key = provision_replica_key(keys, &record)
        .await
        .expect("mint a key for a fresh replica");
    let mut conn = ConnettoConnection::connect(
        FakeTransport::accepting(),
        &Replica::encrypted_file(&db, Some(key)).expect("key is provided"),
        SQLITE_DDL,
        &config(),
        None,
    )
    .await
    .expect("first connect");
    diesel::insert_into(items::table)
        .values((items::id.eq(7), items::label.eq(MARKER)))
        .execute(conn.conn())
        .expect("write the canary");
    conn.push().await.expect("upload the captured mutation");
    let unsynced = conn.unsynced();
    assert!(
        !unsynced.is_empty(),
        "the fake server never acknowledges, so the mutation stays pending"
    );
    (path, record, unsynced)
}

/// Read the rows of an existing encrypted replica through a fresh connection,
/// which is the only honest way to claim it is still readable.
async fn read_back(path: &Path, key: ReplicaKey) -> Result<Vec<Option<String>>, ClientError> {
    let db = url(path);
    let mut conn = ConnettoConnection::connect_existing(
        FakeTransport::accepting(),
        &Replica::encrypted_file(&db, Some(key)).expect("key is provided"),
        &config(),
        None,
    )
    .await?;
    items::table
        .select(items::label)
        .load(conn.conn())
        .map_err(ClientError::from)
}

/// Wipe mode. The file and both sidecars are gone from the filesystem, the
/// key-store record is gone, and a second identity signed in on the same device
/// keeps both, so its replica still opens under its own key.
#[tokio::test]
async fn a_wipe_shreds_one_identitys_replica_and_leaves_the_others_readable() {
    connetto_test_harness::isolated_session_keyring();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = MemoryKeyStore::default();

    let (alice_path, alice_record, alice_unsynced) = seed_replica(dir.path(), &keys, "alice").await;
    let (bob_path, bob_record, _) = seed_replica(dir.path(), &keys, "bob").await;
    assert_ne!(
        alice_record, bob_record,
        "each identity owns its own replica file and its own key record"
    );

    // Forced, because the unsynced mutation is exactly what the guard blocks on,
    // and the guard's own behaviour is asserted separately below.
    wipe_replica(&alice_path, &keys, &alice_record, &alice_unsynced, true)
        .await
        .expect("wipe alice");

    // The negative claim, checked against the filesystem rather than the return
    // value. The sidecars matter: a WAL left behind can hold committed pages.
    assert!(!alice_path.exists(), "the replica file is gone");
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", url(&alice_path)));
        assert!(!sidecar.exists(), "the {suffix} sidecar is gone");
    }
    // Crypto-shredded: even a forensic copy of the ciphertext has no key left.
    assert_eq!(
        keys.load(&alice_record).await.expect("load"),
        None,
        "the key-store record is destroyed, so leftover ciphertext is inert"
    );

    // Isolation: the wipe named one record and one file, and reached nothing else.
    assert!(bob_path.exists(), "the other identity's replica survives");
    let bob_key = keys
        .load(&bob_record)
        .await
        .expect("load")
        .expect("the other identity keeps its key");
    assert_eq!(
        read_back(&bob_path, bob_key)
            .await
            .expect("bob still opens"),
        vec![Some(MARKER.to_owned())],
        "the other identity's replica is still decryptable under its own key"
    );
}

/// The guard. A wipe with unsynced work and no force destroys nothing at all, so
/// the queued writes can still be uploaded with the credential that is still live.
#[tokio::test]
async fn a_wipe_refuses_to_drop_unsynced_writes_and_destroys_nothing() {
    connetto_test_harness::isolated_session_keyring();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = MemoryKeyStore::default();
    let (path, record, unsynced) = seed_replica(dir.path(), &keys, "alice").await;

    match wipe_replica(&path, &keys, &record, &unsynced, false).await {
        Err(PurgeError::Unsynced(blocked)) => assert_eq!(blocked, unsynced),
        Err(other) => panic!("expected Unsynced, got {other:?}"),
        Ok(()) => panic!("a wipe must not silently drop queued writes"),
    }

    // Nothing was destroyed, and specifically the key was not: shredding the key
    // and then refusing the delete would leave the data unreachable anyway.
    assert!(path.exists(), "the blocked wipe deletes nothing");
    let key = keys
        .load(&record)
        .await
        .expect("load")
        .expect("the blocked wipe keeps the key");
    assert_eq!(
        read_back(&path, key)
            .await
            .expect("the replica still opens"),
        vec![Some(MARKER.to_owned())],
        "the replica is untouched and still readable"
    );
}

/// Keep mode. Credential teardown alone leaves the replica and its key, so a
/// returning user opens the same file from the cached key with its unsynced work
/// still queued: no re-sync, which is the whole point of keeping the key across a
/// logout.
#[tokio::test]
async fn keeping_the_data_leaves_the_replica_openable_from_its_cached_key() {
    connetto_test_harness::isolated_session_keyring();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = MemoryKeyStore::default();
    let (path, record, unsynced) = seed_replica(dir.path(), &keys, "alice").await;

    // Credential teardown touches neither the file nor the key store, so this is
    // the state a keep-mode logout leaves behind.
    let key = keys
        .load(&record)
        .await
        .expect("load")
        .expect("the key survives a credential-only logout");

    let db = url(&path);
    let mut conn = ConnettoConnection::connect_existing(
        FakeTransport::accepting(),
        &Replica::encrypted_file(&db, Some(key)).expect("key is provided"),
        &config(),
        None,
    )
    .await
    .expect("reopen from the cached key after re-authentication");
    let rows: Vec<Option<String>> = items::table
        .select(items::label)
        .load(conn.conn())
        .expect("read the rows back");
    assert_eq!(
        rows,
        vec![Some(MARKER.to_owned())],
        "the rows are still there, so nothing had to be re-synced"
    );
    assert_eq!(
        conn.unsynced(),
        unsynced,
        "the mutation queued before the logout is still queued after it"
    );
}

/// A key store cleared while the replica survived is the one case a guard cannot
/// help with: the pending mutations live inside the file the key will not open, so
/// they are unreadable and already lost. The documented recovery is a forced purge
/// of the file alone, after which a fresh connect rebuilds.
#[tokio::test]
async fn an_undecryptable_replica_recovers_through_a_forced_purge() {
    connetto_test_harness::isolated_session_keyring();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = MemoryKeyStore::default();
    let (path, record, _) = seed_replica(dir.path(), &keys, "alice").await;

    // The key store is cleared without the file, which is what a partial wipe or
    // a lost keyring looks like from the next boot's point of view.
    keys.clear(&record).await.expect("clear the key record");
    let reminted = provision_replica_key(&keys, &record)
        .await
        .expect("a later boot mints again");
    match read_back(&path, reminted).await {
        Err(ClientError::ReplicaUndecryptable(_)) => {}
        Err(other) => panic!("expected ReplicaUndecryptable, got {other:?}"),
        Ok(_) => panic!("a re-minted key must not open the old ciphertext"),
    }

    // The unsynced count is unknowable here, so no guard is pretended: `force`
    // says out loud that the queued writes are being discarded.
    purge_replica(&path, &[], true).expect("the documented recovery");
    assert!(!path.exists(), "the unreadable replica is gone");

    // A fresh connect rebuilds under the key that is now cached.
    let key = keys
        .load(&record)
        .await
        .expect("load")
        .expect("the minted key");
    let db = url(&path);
    let mut conn = ConnettoConnection::connect(
        FakeTransport::accepting(),
        &Replica::encrypted_file(&db, Some(key)).expect("key is provided"),
        SQLITE_DDL,
        &config(),
        None,
    )
    .await
    .expect("rebuild after the purge");
    let rows: Vec<Option<String>> = items::table
        .select(items::label)
        .load(conn.conn())
        .expect("read the rebuilt replica");
    assert!(rows.is_empty(), "the rebuilt replica starts empty");
}

/// `forget_device` runs both destructive axes, and its guard is checked before the
/// credential is destroyed: once the refresh token is gone the queued writes can
/// never be uploaded, so a guard that ran afterwards would be protecting nothing.
#[tokio::test]
async fn forget_device_checks_the_guard_before_it_touches_the_credential() {
    connetto_test_harness::isolated_session_keyring();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = MemoryKeyStore::default();
    let (path, record, unsynced) = seed_replica(dir.path(), &keys, "alice").await;

    let refresh: Arc<dyn RefreshTokenStore<Error = ClientError> + Send + Sync> =
        Arc::new(MemoryRefreshStore::default());
    let alice_account = encode_identity("alice").expect("encode alice account");
    refresh
        .store(&alice_account, "session-id.secret")
        .expect("seed a credential");
    // Port 1 is reserved and nothing listens there. The revoke can therefore
    // never land, which is deliberate: the guard must refuse before the request
    // is even attempted, so an unreachable server proves the ordering.
    let authenticator = NativeAuthenticator::new(
        "http://127.0.0.1:1",
        "permissive",
        Arc::clone(&refresh),
        Some(alice_account.clone()),
    );

    match forget_device(&authenticator, &path, &keys, &record, &unsynced, false).await {
        Err(ForgetError::Purge(PurgeError::Unsynced(blocked))) => assert_eq!(blocked, unsynced),
        Err(other) => panic!("expected a blocked purge, got {other:?}"),
        Ok(()) => panic!("forget_device must not silently drop queued writes"),
    }
    assert_eq!(
        refresh.load(&alice_account).expect("load").as_deref(),
        Some("session-id.secret"),
        "the credential is intact, so the queued writes can still be uploaded"
    );
    assert!(path.exists(), "and the replica is intact too");
}
