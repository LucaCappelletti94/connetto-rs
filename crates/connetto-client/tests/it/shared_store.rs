//! R11 slice 1: one store per device, keyed with its own device-scoped key and
//! attached to every identity's replica connection.
//!
//! Each identity's connection is keyed with that identity's replica key, and
//! the shared store with a third key. The store one identity created is read
//! and written by another, and it opens on its own under the device key and
//! under no replica key.

use connetto_client::ReplicaKey;
use connetto_client::cipher::{self, UnlockError};
use connetto_client::harden::{AttachPermits, attach_keyed_in_window};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;

/// The schema the shared store is attached as.
const SHARED: &str = "connetto_shared";

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

/// A replica connection at `path` under `key`, as the open path keys one.
fn replica(path: &str, key: &ReplicaKey) -> SqliteConnection {
    let mut conn = SqliteConnection::establish(path).expect("open the replica");
    cipher::unlock(&mut conn, key).expect("key the replica");
    conn.batch_execute("PRAGMA journal_mode=WAL")
        .expect("the replica's journal mode");
    conn
}

fn authors(conn: &mut SqliteConnection) -> Vec<String> {
    entries::table
        .order(entries::id)
        .select(entries::author)
        .load(conn)
        .expect("read the shared store")
}

fn url(path: &std::path::Path) -> String {
    path.to_str().expect("a utf-8 temporary path").to_owned()
}

#[test]
fn a_second_identity_reads_and_writes_the_store_the_first_created() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let alice = url(&dir.path().join("connetto-alice"));
    let bob = url(&dir.path().join("connetto-bob"));
    let shared = url(&dir.path().join("connetto-shared"));

    {
        let mut conn = replica(&alice, &alice_key());
        attach_keyed_in_window(
            &mut conn,
            &shared,
            SHARED,
            AttachPermits::CreateAndWrite,
            &device_key(),
        )
        .expect("alice creates the shared store");
        conn.batch_execute(
            "CREATE TABLE connetto_shared.entries (id INTEGER PRIMARY KEY NOT NULL, author TEXT NOT NULL) STRICT;",
        )
        .expect("a public table in the shared store");
        diesel::insert_into(entries::table)
            .values((entries::id.eq(1), entries::author.eq("alice")))
            .execute(&mut conn)
            .expect("alice writes");
    }

    {
        let mut conn = replica(&bob, &bob_key());
        attach_keyed_in_window(
            &mut conn,
            &shared,
            SHARED,
            AttachPermits::Write,
            &device_key(),
        )
        .expect("bob attaches the store alice created");
        assert_eq!(authors(&mut conn), ["alice"]);
        diesel::insert_into(entries::table)
            .values((entries::id.eq(2), entries::author.eq("bob")))
            .execute(&mut conn)
            .expect("bob writes");
    }

    let mut conn = replica(&alice, &alice_key());
    attach_keyed_in_window(
        &mut conn,
        &shared,
        SHARED,
        AttachPermits::Write,
        &device_key(),
    )
    .expect("alice attaches again");
    assert_eq!(authors(&mut conn), ["alice", "bob"]);
}

#[test]
fn the_store_opens_under_the_device_key_and_under_no_replica_key() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let alice = url(&dir.path().join("connetto-alice"));
    let shared = url(&dir.path().join("connetto-shared"));
    {
        let mut conn = replica(&alice, &alice_key());
        attach_keyed_in_window(
            &mut conn,
            &shared,
            SHARED,
            AttachPermits::CreateAndWrite,
            &device_key(),
        )
        .expect("create the shared store");
        conn.batch_execute(
            "CREATE TABLE connetto_shared.entries (id INTEGER PRIMARY KEY NOT NULL, author TEXT NOT NULL) STRICT;
             INSERT INTO connetto_shared.entries VALUES (1, 'alice');",
        )
        .expect("write the shared store");
    }

    let mut standalone = SqliteConnection::establish(&shared).expect("open the store alone");
    cipher::unlock(&mut standalone, &device_key()).expect("the device key decrypts it");
    let rows: Vec<String> = standalone::entries::table
        .select(standalone::entries::author)
        .load(&mut standalone)
        .expect("read it alone");
    assert_eq!(rows, ["alice"]);

    for (who, key) in [("alice", alice_key()), ("bob", bob_key())] {
        let mut conn = SqliteConnection::establish(&shared).expect("open the store alone");
        assert!(
            matches!(
                cipher::unlock(&mut conn, &key),
                Err(UnlockError::WrongKey(_))
            ),
            "{who}'s replica key must not decrypt the shared store"
        );
    }
}

#[test]
fn an_attach_under_the_wrong_key_fails_and_leaves_nothing_attached() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let alice = url(&dir.path().join("connetto-alice"));
    let bob = url(&dir.path().join("connetto-bob"));
    let shared = url(&dir.path().join("connetto-shared"));
    {
        let mut conn = replica(&alice, &alice_key());
        attach_keyed_in_window(
            &mut conn,
            &shared,
            SHARED,
            AttachPermits::CreateAndWrite,
            &device_key(),
        )
        .expect("create the shared store");
        conn.batch_execute(
            "CREATE TABLE connetto_shared.entries (id INTEGER PRIMARY KEY NOT NULL, author TEXT NOT NULL) STRICT;",
        )
        .expect("write the shared store");
    }

    let mut conn = replica(&bob, &bob_key());
    let attached =
        attach_keyed_in_window(&mut conn, &shared, SHARED, AttachPermits::Write, &bob_key());
    assert!(
        attached.is_err(),
        "the wrong key must fail the attach itself"
    );
    attach_keyed_in_window(
        &mut conn,
        &shared,
        SHARED,
        AttachPermits::Write,
        &device_key(),
    )
    .expect("the failed attach left the schema name and the ceiling free");
    assert_eq!(authors(&mut conn), Vec::<String>::new());
}
