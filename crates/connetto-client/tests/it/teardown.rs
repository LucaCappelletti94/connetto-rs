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

use connetto_client::teardown::{
    ForgetError, PurgeError, content_dir, purge_replica, wipe_replica,
};
use connetto_client::{
    ClientBuilder, ClientError, DataDir, Gate, NativeClientBuilder, ReplicaKey, SyncSchema,
    provision_replica_key,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_core::traits::ReplicaKeyStore;
use diesel::prelude::*;

/// A string written into the replica, so a leftover-plaintext assertion has
/// something specific to look for.
const MARKER: &str = "connetto-teardown-canary-9d4e21b7";

const SQLITE_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)";

diesel::table! {
    /// Test table for items in the replica.
    items (id) {
        /// Item identifier, the primary key.
        id -> Integer,
        /// Item label text.
        label -> Nullable<Text>,
    }
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
    keys: &super::support::SharedKeys,
    user_id: &str,
) -> (PathBuf, String, Vec<u64>) {
    let credential = super::support::held(user_id);
    let record = credential.replica_name().to_owned();
    let path = dir.join(&record);
    let mut conn = ClientBuilder::new(
        super::support::bundle(SQLITE_DDL),
        super::support::Once::new(FakeTransport::accepting()),
    )
    .signed_in(credential)
    .durable(DataDir::new(dir.to_path_buf()), keys.clone())
    .connect_driven()
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
async fn read_back(
    path: &Path,
    user_id: &str,
    key: ReplicaKey,
) -> Result<Vec<Option<String>>, ClientError> {
    let credential = super::support::held(user_id);
    let store = super::support::key_store_with(&credential, key).await;
    let dir = path.parent().expect("the replica lives in a directory");
    let mut conn = ClientBuilder::new(
        super::support::bundle(SQLITE_DDL),
        super::support::Once::new(FakeTransport::accepting()),
    )
    .signed_in(credential)
    .durable(DataDir::new(dir.to_path_buf()), store)
    .connect_driven()
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
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = super::support::SharedKeys::default();

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
        read_back(&bob_path, "bob", bob_key)
            .await
            .expect("bob still opens"),
        vec![Some(MARKER.to_owned())],
        "the other identity's replica is still decryptable under its own key"
    );
}

/// First-boot an encrypted replica for `user_id` with a device-private tier
/// beside it, so a teardown has a tier to remove. Returns the replica path, its
/// key-store record name, and the pending sequence numbers.
async fn seed_replica_with_tier(
    dir: &Path,
    keys: &super::support::SharedKeys,
    user_id: &str,
) -> (PathBuf, String, Vec<u64>) {
    let credential = super::support::held(user_id);
    let record = credential.replica_name().to_owned();
    let path = dir.join(&record);
    let schema = SyncSchema::new(SchemaBundle::new(
        "",
        "",
        SQLITE_DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        Some(TIER_DDL),
    ));
    let mut conn = ClientBuilder::new(
        schema,
        super::support::Once::new(FakeTransport::accepting()),
    )
    .signed_in(credential)
    .durable(DataDir::new(dir.to_path_buf()), keys.clone())
    .connect_driven()
    .await
    .expect("first connect");
    diesel::insert_into(items::table)
        .values((items::id.eq(7), items::label.eq(MARKER)))
        .execute(conn.conn())
        .expect("write the canary");
    conn.push().await.expect("upload the captured mutation");
    (path, record, conn.unsynced())
}

/// A wipe removes everything the replica key opens: the replica and its
/// sidecars, the device-private tier, and the content directory beside them,
/// then destroys the key. Each is checked against the filesystem after the fact.
#[tokio::test]
async fn a_wipe_removes_the_tier_and_content_directory_beside_the_replica() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = super::support::SharedKeys::default();

    let (path, record, unsynced) = seed_replica_with_tier(dir.path(), &keys, "alice").await;
    let tier = PathBuf::from(format!("{}-tier", url(&path)));
    assert!(tier.exists(), "the tier was created beside the replica");

    // A chunk under the content directory, which a wipe orphans and must remove.
    let content = content_dir(&path);
    std::fs::create_dir_all(&content).expect("create the content directory");
    std::fs::write(content.join("chunk-0"), b"orphaned content").expect("write a content chunk");

    wipe_replica(&path, &keys, &record, &unsynced, true)
        .await
        .expect("wipe the replica");

    assert!(!path.exists(), "the replica file is gone");
    assert!(!tier.exists(), "the device-private tier is gone");
    assert!(!content.exists(), "the content directory is gone");
    assert_eq!(
        keys.load(&record).await.expect("load"),
        None,
        "the key-store record is destroyed, so leftover ciphertext is inert"
    );
}

/// `purge_replica` keeps the key but still removes the content directory, because
/// a fresh replica has empty manifest tables and every chunk under the old
/// directory is an orphan the sweep would otherwise reclaim one file at a time.
#[tokio::test]
async fn a_purge_removes_the_content_directory_but_keeps_the_key() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = super::support::SharedKeys::default();

    let (path, record, unsynced) = seed_replica_with_tier(dir.path(), &keys, "alice").await;
    let content = content_dir(&path);
    std::fs::create_dir_all(&content).expect("create the content directory");
    std::fs::write(content.join("chunk-0"), b"orphaned content").expect("write a content chunk");

    purge_replica(&path, &unsynced, true).expect("purge the replica");

    assert!(!path.exists(), "the replica file is gone");
    assert!(!content.exists(), "the content directory is gone");
    assert!(
        keys.load(&record).await.expect("load").is_some(),
        "a purge keeps the key, unlike a wipe"
    );
}

/// The session guard leaves the persistent keyring where it found it. A real
/// credential stored under the guard is linked into the persistent keyring, and
/// once the guard drops it is gone again, so a passing or panicking keyring test
/// frees its keys rather than leaking one per run against the per-user quota.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_session_guard_leaves_the_persistent_keyring_as_it_found_it() {
    use connetto_client::{KeyringStore, LinuxStore};
    use connetto_core::traits::RefreshTokenStore as _;

    let service = format!("connetto-guard-{}", std::process::id());
    assert!(
        !connetto_test_harness::persistent_keyring_holds_service(&service),
        "no key of this service exists before the guarded write"
    );
    {
        let _keyring = connetto_test_harness::isolated_session_keyring();
        let store = KeyringStore::with_linux_store(&service, LinuxStore::Keyutils);
        store
            .store("\"alice\"", "token")
            .await
            .expect("store one account under the guard");
        assert!(
            connetto_test_harness::persistent_keyring_holds_service(&service),
            "the credential is linked into the persistent keyring while the guard is held"
        );
    }
    assert!(
        !connetto_test_harness::persistent_keyring_holds_service(&service),
        "the guard unlinked the credential, so the persistent keyring is back where it started"
    );
}

/// The guard. A wipe with unsynced work and no force destroys nothing at all, so
/// the queued writes can still be uploaded with the credential that is still live.
#[tokio::test]
async fn a_wipe_refuses_to_drop_unsynced_writes_and_destroys_nothing() {
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = super::support::SharedKeys::default();
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
        read_back(&path, "alice", key)
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
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = super::support::SharedKeys::default();
    let (_path, record, unsynced) = seed_replica(dir.path(), &keys, "alice").await;

    // Credential teardown touches neither the file nor the key store, so this is
    // the state a keep-mode logout leaves behind.
    let key = keys
        .load(&record)
        .await
        .expect("load")
        .expect("the key survives a credential-only logout");

    let credential = super::support::held("alice");
    let store = super::support::key_store_with(&credential, key).await;
    let mut conn = ClientBuilder::new(
        super::support::bundle(SQLITE_DDL),
        super::support::Once::new(FakeTransport::accepting()),
    )
    .signed_in(credential)
    .durable(DataDir::new(dir.path().to_path_buf()), store)
    .connect_driven()
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
    let _keyring = connetto_test_harness::isolated_session_keyring();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = super::support::SharedKeys::default();
    let (path, record, _) = seed_replica(dir.path(), &keys, "alice").await;

    // The key store is cleared without the file, which is what a partial wipe or
    // a lost keyring looks like from the next boot's point of view.
    keys.clear(&record).await.expect("clear the key record");
    let reminted = provision_replica_key(&keys, &record)
        .await
        .expect("a later boot mints again");
    match read_back(&path, "alice", reminted).await {
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
    let credential = super::support::held("alice");
    let store = super::support::key_store_with(&credential, key).await;
    let mut conn = ClientBuilder::new(
        super::support::bundle(SQLITE_DDL),
        super::support::Once::new(FakeTransport::accepting()),
    )
    .signed_in(credential)
    .durable(DataDir::new(dir.path().to_path_buf()), store)
    .connect_driven()
    .await
    .expect("rebuild after the purge");
    let rows: Vec<Option<String>> = items::table
        .select(items::label)
        .load(conn.conn())
        .expect("read the rebuilt replica");
    assert!(rows.is_empty(), "the rebuilt replica starts empty");
}

/// A durable client forgets its device only past the unsynced guard, which it
/// reads itself before anything is destroyed, since once the credential is
/// gone the queued writes can never be uploaded. Past the guard the replica,
/// its key record and its content are gone.
#[tokio::test]
async fn a_durable_client_forgets_its_device_only_past_the_unsynced_guard() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = super::support::SharedKeys::default();
    let credential = super::support::held("alice");
    let record = credential.replica_name().to_owned();
    let path = dir.path().join(&record);
    keys.store(&record, &connetto_core::test_support::replica_key())
        .await
        .expect("seed the key");
    let client = NativeClientBuilder::new("ws://127.0.0.1:1/", super::support::bundle(SQLITE_DDL))
        .with_dialer(super::support::NeverDial::<FakeTransport>::default())
        .signed_in(credential)
        .durable(dir.path(), keys.clone())
        .with_gate(Gate::off())
        .connect()
        .await
        .expect("the durable client opens offline");
    client
        .client()
        .with_conn(|conn| {
            diesel::insert_into(items::table)
                .values((items::id.eq(7), items::label.eq(MARKER)))
                .execute(conn.conn())
                .expect("write the canary");
        })
        .await
        .expect("the gate is off");

    let queued = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let unsynced = client
                .client()
                .with_conn(|conn| conn.unsynced())
                .await
                .expect("the gate is off");
            if !unsynced.is_empty() {
                break unsynced;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the offline write is queued");
    match client.forget_device(false).await {
        Err(ForgetError::Purge(PurgeError::Unsynced(blocked))) => assert_eq!(blocked, queued),
        Err(other) => panic!("expected a blocked forget, got {other:?}"),
        Ok(()) => panic!("forget_device must not silently drop queued writes"),
    }
    assert!(path.exists(), "the refused forget leaves the replica");
    assert!(
        keys.load(&record).await.expect("load").is_some(),
        "and its key"
    );

    client
        .forget_device(true)
        .await
        .expect("a forced forget wipes the device");
    assert!(!path.exists(), "the replica is gone");
    assert!(!content_dir(&path).exists(), "and its content");
    assert!(
        keys.load(&record).await.expect("load").is_none(),
        "and its key record"
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        open_handles_to(&path),
        0,
        "the live client keeps no handle on the deleted replica, which Windows needs to delete it"
    );
}

/// A schema with row-level-security policies still forgets its device, since
/// the stand-in that replaces the closed replica holds none of its views.
#[tokio::test]
async fn a_client_whose_schema_has_policies_forgets_its_device() {
    let ddl = "
CREATE TABLE orders_rls (id INTEGER PRIMARY KEY, owner_id TEXT NOT NULL) STRICT;
CREATE VIEW orders AS SELECT id, owner_id FROM orders_rls WHERE owner_id = current_app_user();
";
    let schema = SyncSchema::new(SchemaBundle::new(
        "",
        "",
        ddl,
        vec![("orders", "orders_rls")],
        vec!["orders"],
        None::<&str>,
    ));
    let dir = tempfile::tempdir().expect("a temporary directory");
    let keys = super::support::SharedKeys::default();
    let credential = super::support::held("alice");
    let record = credential.replica_name().to_owned();
    let path = dir.path().join(&record);
    keys.store(&record, &connetto_core::test_support::replica_key())
        .await
        .expect("seed the key");
    let client = NativeClientBuilder::new("ws://127.0.0.1:1/", schema)
        .with_dialer(super::support::NeverDial::<FakeTransport>::default())
        .signed_in(credential)
        .durable(dir.path(), keys.clone())
        .with_gate(Gate::off())
        .connect()
        .await
        .expect("the durable client opens offline");

    client
        .forget_device(true)
        .await
        .expect("a schema with policies forgets its device");
    assert!(!path.exists(), "the replica is gone");
    assert!(
        keys.load(&record).await.expect("load").is_none(),
        "and its key record"
    );
}

/// How many of this process's open file descriptors point at `path` or its sidecars.
#[cfg(target_os = "linux")]
fn open_handles_to(path: &std::path::Path) -> usize {
    let prefix = path.to_string_lossy().into_owned();
    std::fs::read_dir("/proc/self/fd")
        .expect("list this process's descriptors")
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .filter(|target| target.to_string_lossy().starts_with(&prefix))
        .count()
}

/// A build that kept nothing on the device has nothing to forget.
#[tokio::test]
async fn an_in_memory_client_has_no_device_to_forget() {
    let client = NativeClientBuilder::new("ws://127.0.0.1:1/", super::support::bundle(SQLITE_DDL))
        .with_dialer(super::support::NeverDial::<FakeTransport>::default())
        .signed_in(super::support::held("alice"))
        .connect()
        .await
        .expect("the in-memory client opens offline");
    assert!(
        matches!(
            client.forget_device(true).await,
            Err(ForgetError::NoReplica)
        ),
        "an in-memory build refuses to forget"
    );
}
