//! Browser half of the phase E0 acceptance, run in a dedicated worker because
//! the OPFS sahpool VFS needs synchronous access handles.
//!
//! The codec is `SQLite3` Multiple Ciphers, layered over the already installed
//! `opfs-sahpool` VFS by opening through a `multipleciphers-opfs-sahpool` URI.
//! Alongside the round trip this establishes the precondition phase E3's wipe
//! depends on: the sync access handle is released when the connection drops,
//! synchronously, with no await in between.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_at_rest_encryption_spike::{ReplicaKey, sahpool_cipher_url, unlock};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// A string written into the replica that must never appear in the file bytes.
const MARKER: &str = "connetto-plaintext-canary-a7f31c0e";

/// The SQLite file magic a plaintext database starts with.
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

diesel::table! {
    canary (id) {
        id -> Integer,
        note -> Text,
    }
}

fn test_key() -> ReplicaKey {
    ReplicaKey::new([0x5a; ReplicaKey::LEN])
}

/// Install the sahpool VFS and hand back its management util, which is also
/// how the test reads raw file bytes back out of OPFS.
///
/// `install` only registers once per worker: a second call with the same VFS
/// name returns the management tool for the existing registration.
async fn pool() -> sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil {
    sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    .expect("install the sahpool VFS")
}

fn write_marker(conn: &mut SqliteConnection) {
    conn.batch_execute("CREATE TABLE canary (id INTEGER PRIMARY KEY, note TEXT NOT NULL);")
        .expect("create the canary table");
    diesel::insert_into(canary::table)
        .values((canary::id.eq(1), canary::note.eq(MARKER)))
        .execute(conn)
        .expect("insert the canary row");
}

#[wasm_bindgen_test]
async fn encrypted_opfs_replica_round_trips_and_is_ciphertext_at_rest() {
    let util = pool().await;
    let name = "e0-encrypted.db";
    let _ = util.delete_db(name);
    let url = sahpool_cipher_url(name);

    {
        let mut conn = SqliteConnection::establish(&url).expect("open the encrypted replica");
        unlock(&mut conn, &test_key()).expect("unlock a fresh replica");
        write_marker(&mut conn);
    }

    let bytes = util.export_db(name).expect("export the OPFS file bytes");
    assert!(
        !bytes.starts_with(SQLITE_MAGIC),
        "an encrypted database does not carry the SQLite magic"
    );
    assert!(
        !bytes
            .windows(MARKER.len())
            .any(|window| window == MARKER.as_bytes()),
        "the marker must not survive as plaintext in OPFS"
    );

    {
        let mut conn = SqliteConnection::establish(&url).expect("reopen the encrypted replica");
        unlock(&mut conn, &test_key()).expect("unlock with the same key");
        let note: String = canary::table
            .select(canary::note)
            .first(&mut conn)
            .expect("read the canary row back");
        assert_eq!(note, MARKER);
    }
}

#[wasm_bindgen_test]
async fn a_wrong_key_cannot_read_the_opfs_replica() {
    let util = pool().await;
    let name = "e0-wrongkey.db";
    let _ = util.delete_db(name);
    let url = sahpool_cipher_url(name);

    {
        let mut conn = SqliteConnection::establish(&url).expect("open the encrypted replica");
        unlock(&mut conn, &test_key()).expect("unlock a fresh replica");
        write_marker(&mut conn);
    }

    let mut conn = SqliteConnection::establish(&url).expect("reopen the encrypted replica");
    let error = unlock(&mut conn, &ReplicaKey::new([0xa5; ReplicaKey::LEN]))
        .expect_err("a wrong key must not decrypt");
    assert!(
        matches!(
            error,
            connetto_at_rest_encryption_spike::UnlockError::WrongKey(_)
        ),
        "the wrong key surfaces on the first schema read, got {error:?}"
    );
}

#[wasm_bindgen_test]
async fn the_sync_access_handle_is_released_when_the_connection_drops() {
    let util = pool().await;
    let name = "e0-handle.db";
    let _ = util.delete_db(name);
    let url = sahpool_cipher_url(name);

    {
        let mut conn = SqliteConnection::establish(&url).expect("open the encrypted replica");
        unlock(&mut conn, &test_key()).expect("unlock a fresh replica");
        write_marker(&mut conn);
    }

    // No await between the drop above and the delete below: if the handle were
    // released asynchronously, OPFS would still hold it and this would fail.
    // This is the precondition phase E3's explicit wipe rests on.
    util.delete_db(name)
        .expect("delete the replica immediately after the connection dropped");
    assert!(
        !util.exists(name).expect("query the pool for the file"),
        "the file is gone once the handle is released"
    );
}
