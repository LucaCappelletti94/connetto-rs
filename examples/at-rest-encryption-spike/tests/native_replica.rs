//! Native half of the phase E0 acceptance: an encrypted replica opens, round
//! trips writes, and closes, with the key supplied in memory, and the file left
//! behind is demonstrably ciphertext.
//!
//! The codec here is `SQLCipher`, vendored by `libsqlite3-sys` under
//! `bundled-sqlcipher` and linked in place of the vanilla amalgamation.

#![cfg(not(all(target_family = "wasm", target_os = "unknown")))]

use connetto_at_rest_encryption_spike::{ReplicaKey, unlock};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;

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
    let mut bytes = [0u8; ReplicaKey::LEN];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::try_from(index).expect("index below the key length fits in a byte") ^ 0x5a;
    }
    ReplicaKey::new(bytes)
}

fn other_key() -> ReplicaKey {
    ReplicaKey::new([0xa5; ReplicaKey::LEN])
}

fn write_marker(conn: &mut SqliteConnection) {
    conn.batch_execute("CREATE TABLE canary (id INTEGER PRIMARY KEY, note TEXT NOT NULL);")
        .expect("create the canary table");
    diesel::insert_into(canary::table)
        .values((canary::id.eq(1), canary::note.eq(MARKER)))
        .execute(conn)
        .expect("insert the canary row");
}

fn read_marker(conn: &mut SqliteConnection) -> String {
    canary::table
        .select(canary::note)
        .first::<String>(conn)
        .expect("read the canary row back")
}

#[test]
fn plaintext_control_leaves_the_marker_readable_on_disk() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("plain.db");
    let url = path.to_str().expect("a utf-8 temporary path").to_owned();

    {
        let mut conn = SqliteConnection::establish(&url).expect("open the plaintext replica");
        write_marker(&mut conn);
    }

    let bytes = std::fs::read(&path).expect("read the plaintext replica back");
    assert!(
        bytes.starts_with(SQLITE_MAGIC),
        "an unkeyed database starts with the SQLite magic"
    );
    assert!(
        contains(&bytes, MARKER.as_bytes()),
        "an unkeyed database stores the marker verbatim, which is the control this test establishes"
    );
}

#[test]
fn encrypted_replica_round_trips_and_is_ciphertext_at_rest() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("encrypted.db");
    let url = path.to_str().expect("a utf-8 temporary path").to_owned();

    {
        let mut conn = SqliteConnection::establish(&url).expect("open the encrypted replica");
        unlock(&mut conn, &test_key()).expect("unlock a fresh replica");
        write_marker(&mut conn);
    }

    let bytes = std::fs::read(&path).expect("read the encrypted replica back");
    assert!(
        !bytes.starts_with(SQLITE_MAGIC),
        "an encrypted database does not carry the SQLite magic: the first 16 bytes are the key salt"
    );
    assert!(
        !contains(&bytes, MARKER.as_bytes()),
        "the marker must not survive as plaintext anywhere in the file"
    );
    assert!(
        !contains(&bytes, b"canary"),
        "the schema text must not survive as plaintext either"
    );

    {
        let mut conn = SqliteConnection::establish(&url).expect("reopen the encrypted replica");
        unlock(&mut conn, &test_key()).expect("unlock with the same key");
        assert_eq!(read_marker(&mut conn), MARKER);
    }
}

#[test]
fn a_wrong_key_cannot_read_the_replica() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("encrypted.db");
    let url = path.to_str().expect("a utf-8 temporary path").to_owned();

    {
        let mut conn = SqliteConnection::establish(&url).expect("open the encrypted replica");
        unlock(&mut conn, &test_key()).expect("unlock a fresh replica");
        write_marker(&mut conn);
    }

    let mut conn = SqliteConnection::establish(&url).expect("reopen the encrypted replica");
    let error = unlock(&mut conn, &other_key()).expect_err("a wrong key must not decrypt");
    assert!(
        matches!(
            error,
            connetto_at_rest_encryption_spike::UnlockError::WrongKey(_)
        ),
        "the wrong key surfaces on the first schema read, got {error:?}"
    );

    let mut conn = SqliteConnection::establish(&url).expect("reopen the encrypted replica");
    conn.batch_execute("SELECT count(*) FROM sqlite_schema;")
        .expect_err("no key at all must not decrypt either");
}

#[test]
fn changeset_capture_still_works_under_the_codec() {
    use diesel_sqlite_session::SqliteSessionExt as _;

    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("encrypted.db");
    let url = path.to_str().expect("a utf-8 temporary path").to_owned();

    let mut conn = SqliteConnection::establish(&url).expect("open the encrypted replica");
    unlock(&mut conn, &test_key()).expect("unlock a fresh replica");
    conn.batch_execute("CREATE TABLE canary (id INTEGER PRIMARY KEY, note TEXT NOT NULL);")
        .expect("create the canary table");

    let mut session = conn.create_session().expect("create a capture session");
    session
        .attach::<canary::table>()
        .expect("attach the canary table");
    diesel::insert_into(canary::table)
        .values((canary::id.eq(1), canary::note.eq(MARKER)))
        .execute(&mut conn)
        .expect("insert the canary row");
    let changeset = session.changeset().expect("capture the changeset");

    assert!(
        !changeset.is_empty(),
        "the session extension must still capture writes when the pages are encrypted, since the replica's mutation capture depends on it"
    );
}

/// Whether `haystack` contains `needle` as a contiguous byte run.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
