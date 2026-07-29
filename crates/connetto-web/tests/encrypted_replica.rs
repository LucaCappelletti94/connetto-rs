//! Browser acceptance for phase E2: the OPFS replica and the device-local tier
//! are both ciphertext at rest, under the key phase E1 resolves.
//!
//! Runs in a dedicated worker, because the OPFS sahpool VFS needs synchronous
//! access handles and only a worker has them. That is also the context the real
//! DB worker runs in, so this exercises the same stack `boot_db_worker` does.
//!
//! Every assertion reads real bytes back out of OPFS through the pool's own
//! export, not a pragma result. The codec is `SQLite3` Multiple Ciphers, reached
//! by opening through a `multipleciphers-opfs-sahpool` URL, which is what
//! [`cipher_url`] composes and what `ReplicaStorage::db_url` hands the connection.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::cipher::{ReplicaKey, UnlockError, cipher_url, unlock};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// A string written into the database that must never appear in the file bytes.
const MARKER: &str = "connetto-plaintext-canary-a7f31c0e";

/// The file magic a plaintext SQLite database starts with. An encrypted file
/// opens with the 16-byte per-database salt instead.
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

diesel::table! {
    canary (id) {
        id -> Integer,
        note -> Text,
    }
}

fn key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x5a; ReplicaKey::LEN])
}

fn other_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0xa5; ReplicaKey::LEN])
}

/// Install the sahpool VFS and hand back its management utility, which is also
/// how a test reads raw file bytes back out of OPFS.
///
/// `install` registers once per worker: a second call under the same VFS name
/// returns the utility for the existing registration.
async fn pool() -> sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil {
    sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    .expect("install the sahpool VFS")
}

/// Open `name` in OPFS under `key`, exactly as `ReplicaStorage::db_url` plus the
/// worker's own unlock do: an encrypted database names the codec shim over the
/// sahpool VFS, a plaintext one opens under its bare name.
fn open(name: &str, key: Option<&ReplicaKey>) -> SqliteConnection {
    let url = match key {
        None => name.to_owned(),
        Some(_) => cipher_url(name, "opfs-sahpool"),
    };
    let mut conn = SqliteConnection::establish(&url).expect("open the database");
    if let Some(key) = key {
        unlock(&mut conn, key).expect("apply the key");
    }
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

/// Whether `haystack` contains `needle` as a contiguous byte run.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[wasm_bindgen_test]
async fn an_encrypted_opfs_replica_round_trips_and_is_ciphertext_at_rest() {
    let util = pool().await;
    let name = "e2-encrypted.sqlite";
    let _ = util.delete_db(name);
    let cipher = Some(key());

    write_marker(&mut open(name, cipher.as_ref()));

    let bytes = util.export_db(name).expect("export the OPFS file bytes");
    assert!(
        !bytes.starts_with(SQLITE_MAGIC),
        "an encrypted database opens with the key salt, not the SQLite magic"
    );
    assert!(
        !contains(&bytes, MARKER.as_bytes()),
        "the row value must not survive as plaintext in OPFS"
    );
    assert!(
        !contains(&bytes, b"CREATE TABLE canary"),
        "the schema text must not survive as plaintext either"
    );

    // A fresh connection with the cached key, which is the cold start a worker
    // restart or a leader failover performs.
    let note: String = canary::table
        .select(canary::note)
        .first(&mut open(name, cipher.as_ref()))
        .expect("read the canary row back");
    assert_eq!(note, MARKER);
}

#[wasm_bindgen_test]
async fn a_plaintext_opfs_replica_leaves_everything_readable() {
    // The control that makes the assertions above mean something: the same write
    // through a plaintext database keeps both the magic and the row on disk.
    let util = pool().await;
    let name = "e2-plaintext.sqlite";
    let _ = util.delete_db(name);

    write_marker(&mut open(name, None));

    let bytes = util.export_db(name).expect("export the OPFS file bytes");
    assert!(bytes.starts_with(SQLITE_MAGIC));
    assert!(contains(&bytes, MARKER.as_bytes()));
    assert!(contains(&bytes, b"CREATE TABLE canary"));
}

#[wasm_bindgen_test]
async fn a_process_without_the_key_cannot_read_the_opfs_replica() {
    let util = pool().await;
    let name = "e2-wrongkey.sqlite";
    let _ = util.delete_db(name);

    write_marker(&mut open(name, Some(&key())));

    // The reachable benign cause is a device whose IndexedDB key store was
    // cleared while its OPFS replica survived, which the next login re-keys.
    //
    // Each open below is scoped so only one connection to this file is ever
    // live: `sqlite-wasm-rs` supports one connection per database, and the
    // sahpool VFS keys its open-file bookkeeping by name, so two at once trip a
    // debug assertion in its `xClose`. connetto never holds two either.
    {
        let mut conn = SqliteConnection::establish(&cipher_url(name, "opfs-sahpool"))
            .expect("reopen the encrypted replica");
        let error = unlock(&mut conn, &other_key()).expect_err("a wrong key must not decrypt");
        assert!(
            matches!(error, UnlockError::WrongKey(_)),
            "the wrong key surfaces on the first schema read, got {error:?}"
        );
    }

    // Claiming the replica is plaintext fails too, and not by silently reading
    // garbage: the codec is never keyed, so the first header read fails.
    let mut unkeyed = SqliteConnection::establish(name).expect("open the file with no codec");
    assert!(
        unkeyed
            .batch_execute("SELECT count(*) FROM sqlite_schema;")
            .is_err(),
        "no key at all must not read the replica either"
    );
}

#[wasm_bindgen_test]
async fn the_local_tier_is_encrypted_under_the_same_key_as_its_own_connection() {
    // In the browser the tier is a separate connection whose main schema IS the
    // tier file, so it carries its own key salt and is unlocked independently.
    // Native attaches the tier to the replica and inherits instead. Same key
    // either way: one device, one key.
    let util = pool().await;
    let replica = "e2-tier-replica.sqlite";
    let tier = "e2-tier-frontend.sqlite";
    let _ = util.delete_db(replica);
    let _ = util.delete_db(tier);
    let cipher = Some(key());

    write_marker(&mut open(replica, cipher.as_ref()));
    {
        let mut conn = open(tier, cipher.as_ref());
        conn.batch_execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT) STRICT;")
            .expect("first-boot the tier from DDL");
        conn.batch_execute("INSERT INTO notes VALUES (1, 'connetto-tier-canary-4b90d215');")
            .expect("write into the tier");
    }

    let bytes = util.export_db(tier).expect("export the tier bytes");
    assert!(
        !bytes.starts_with(SQLITE_MAGIC) && !contains(&bytes, b"connetto-tier-canary-4b90d215"),
        "the tier file is ciphertext too, which matters most of all: it has no server copy to re-sync from"
    );

    // Two independently salted encrypted files under one key, each reopened on
    // its own, which is the shape the DB worker holds open.
    let note: String = canary::table
        .select(canary::note)
        .first(&mut open(replica, cipher.as_ref()))
        .expect("reopen the replica");
    assert_eq!(note, MARKER);
    open(tier, cipher.as_ref())
        .batch_execute("SELECT count(*) FROM notes;")
        .expect("reopen the tier");
}

#[wasm_bindgen_test]
async fn the_sync_access_handle_is_released_when_an_encrypted_connection_drops() {
    let util = pool().await;
    let name = "e2-handle.sqlite";
    let _ = util.delete_db(name);

    write_marker(&mut open(name, Some(&key())));

    // No await between the drop above and the delete below. If the handle were
    // released asynchronously, OPFS would still hold it and this would fail. The
    // codec shim sits between SQLite and sahpool, so this re-proves the property
    // through the extra layer: it is what an explicit data wipe rests on.
    util.delete_db(name)
        .expect("delete the replica immediately after the connection dropped");
    assert!(
        !util.exists(name).expect("query the pool for the file"),
        "the file is gone once the handle is released"
    );
}
