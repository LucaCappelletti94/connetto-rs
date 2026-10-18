//! R11 slice 1 in the browser: the shared public store, attached under its
//! own device-scoped key to replica connections each keyed for one identity.
//!
//! Runs in a dedicated worker against real OPFS, because the codec is
//! `SQLite3` Multiple Ciphers through the sahpool VFS and only a worker has the
//! synchronous access handles it needs. Every connection is scoped so only one
//! is ever live per file, as the pool requires.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::cipher::{ReplicaKey, UnlockError, cipher_url, unlock};
use connetto_client::harden::{AttachPermits, attach_keyed_in_window};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The schema the shared store is attached as.
const SHARED: &str = "connetto_shared";

/// A row value that must never appear in the store's bytes.
const MARKER: &str = "connetto-shared-canary-5e1d93a7";

diesel::table! {
    /// A public table in the shared store.
    connetto_shared.entries (id) {
        /// Entry identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Which identity wrote the entry.
        author -> diesel::sql_types::Text,
    }
}

/// The same table read with the store opened as its own main database.
mod standalone {
    diesel::table! {
        /// The public table, unqualified.
        entries (id) {
            /// Entry identifier, the primary key.
            id -> diesel::sql_types::BigInt,
            /// Which identity wrote the entry.
            author -> diesel::sql_types::Text,
        }
    }
}

fn alice_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x11; ReplicaKey::LEN])
}

fn bob_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x22; ReplicaKey::LEN])
}

fn device_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x33; ReplicaKey::LEN])
}

async fn pool() -> sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil {
    sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    .expect("install the sahpool VFS")
}

/// The OPFS database `name` through the page codec, keyed with `key`.
fn open(name: &str, key: &ReplicaKey) -> SqliteConnection {
    let mut conn =
        SqliteConnection::establish(&cipher_url(name, "opfs-sahpool")).expect("open the database");
    unlock(&mut conn, key).expect("key the database");
    conn
}

/// `name`'s replica connection with the shared store attached under the
/// device key.
fn replica_with_store(
    name: &str,
    key: &ReplicaKey,
    store: &str,
    permits: AttachPermits,
) -> SqliteConnection {
    let mut conn = open(name, key);
    attach_keyed_in_window(
        &mut conn,
        &cipher_url(store, "opfs-sahpool"),
        SHARED,
        permits,
        &device_key(),
    )
    .expect("attach the shared store under the device key");
    conn
}

fn authors(conn: &mut SqliteConnection) -> Vec<String> {
    entries::table
        .order(entries::id)
        .select(entries::author)
        .load(conn)
        .expect("read the shared store")
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[wasm_bindgen_test]
async fn a_second_identity_reads_and_writes_the_store_the_first_created() {
    let util = pool().await;
    let (alice, bob, store) = ("r11-alice", "r11-bob", "r11-shared");
    for name in [alice, bob, store] {
        let _ = util.delete_db(name);
    }

    {
        let mut conn =
            replica_with_store(alice, &alice_key(), store, AttachPermits::CreateAndWrite);
        conn.batch_execute(
            "CREATE TABLE connetto_shared.entries (id INTEGER PRIMARY KEY NOT NULL, author TEXT NOT NULL) STRICT;",
        )
        .expect("a public table in the shared store");
        diesel::insert_into(entries::table)
            .values((entries::id.eq(1), entries::author.eq(MARKER)))
            .execute(&mut conn)
            .expect("alice writes");
    }
    {
        let mut conn = replica_with_store(bob, &bob_key(), store, AttachPermits::Write);
        assert_eq!(authors(&mut conn), [MARKER]);
        diesel::insert_into(entries::table)
            .values((entries::id.eq(2), entries::author.eq("bob")))
            .execute(&mut conn)
            .expect("bob writes");
    }
    {
        let mut conn = replica_with_store(alice, &alice_key(), store, AttachPermits::Write);
        assert_eq!(authors(&mut conn), [MARKER, "bob"]);
    }

    let bytes = util.export_db(store).expect("export the store's bytes");
    assert!(
        !contains(&bytes, MARKER.as_bytes()),
        "the shared store is ciphertext in OPFS"
    );
}

#[wasm_bindgen_test]
async fn the_store_opens_under_the_device_key_and_under_no_replica_key() {
    let util = pool().await;
    let (alice, store) = ("r11-solo-alice", "r11-solo-shared");
    for name in [alice, store] {
        let _ = util.delete_db(name);
    }
    {
        let mut conn =
            replica_with_store(alice, &alice_key(), store, AttachPermits::CreateAndWrite);
        conn.batch_execute(
            "CREATE TABLE connetto_shared.entries (id INTEGER PRIMARY KEY NOT NULL, author TEXT NOT NULL) STRICT;
             INSERT INTO connetto_shared.entries VALUES (1, 'alice');",
        )
        .expect("write the shared store");
    }

    // Opened as its own main database with the codec configured as the replica's
    // is, which proves the attach wrote the layout and the key the replica uses.
    {
        let mut conn = open(store, &device_key());
        let rows: Vec<String> = standalone::entries::table
            .select(standalone::entries::author)
            .load(&mut conn)
            .expect("read it alone");
        assert_eq!(rows, ["alice"]);
    }
    for (who, key) in [("alice", alice_key()), ("bob", bob_key())] {
        let mut conn = SqliteConnection::establish(&cipher_url(store, "opfs-sahpool"))
            .expect("open the store alone");
        assert!(
            matches!(unlock(&mut conn, &key), Err(UnlockError::WrongKey(_))),
            "{who}'s replica key must not decrypt the shared store"
        );
    }
}
