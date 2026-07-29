//! Native acceptance for phase E2: the replica actually stops being plaintext.
//!
//! Every assertion here is about a real file on disk written by a real
//! `ConnettoConnection`, not about a pragma having been issued. The four
//! properties E2 owes are proven in order: the replica is ciphertext at rest, a
//! fresh process holding the cached key resumes with its unsynced work intact, a
//! process without the key cannot read a byte, and the device-local tier is
//! covered rather than quietly left in the clear.
//!
//! The codec is `SQLCipher`, vendored by `libsqlite3-sys` under
//! `bundled-sqlcipher` and linked in place of the vanilla amalgamation. That
//! substitution is itself under test: [`cipher::unlock`] refuses to
//! pretend when no codec is linked, because in a codec-less SQLite `PRAGMA key`
//! is an unrecognised pragma that succeeds and encrypts nothing.

use std::collections::VecDeque;

use connetto_client::{
    ClientConfig, ClientError, ConnettoConnection, Replica, ReplicaKey, SqlFunctions, cipher,
};
use connetto_core::messages::{BulkMessage, ControlMessage, HandshakeAck};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, SchemaVersion};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;

/// A string written into the replica that must never appear in the file bytes.
const MARKER: &str = "connetto-plaintext-canary-a7f31c0e";

/// A string written into the local tier, kept distinct so a tier assertion
/// cannot pass on the replica's canary by accident.
const TIER_MARKER: &str = "connetto-tier-canary-4b90d215";

/// The file magic a plaintext SQLite database starts with. An encrypted file
/// opens with the 16-byte per-database salt instead.
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

const SQLITE_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const TIER_DDL: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)";

diesel::table! {
    items (id) {
        id -> Integer,
        label -> Nullable<Text>,
    }
}

// Unqualified, like the tier suite: SQLite resolves the name across the attached
// schemas, so one declaration serves the tier wherever it is attached.
diesel::table! {
    notes (id) {
        id -> Integer,
        body -> Nullable<Text>,
    }
}

diesel::allow_tables_to_appear_in_same_query!(items, notes);

/// A transport that acknowledges the handshake and swallows everything else, so
/// `connect` completes with no server and an uploaded mutation is never retired.
struct FakeTransport {
    inbox: VecDeque<IncomingFrame>,
}

/// The trait needs a concrete typed error even though this fake never fails.
#[derive(Debug, thiserror::Error)]
#[error("fake transport closed")]
struct FakeClosed;

impl Transport for FakeTransport {
    type Error = FakeClosed;

    #[allow(clippy::unused_async_trait_impl)]
    async fn send_control(&mut self, message: ControlMessage) -> Result<(), FakeClosed> {
        if matches!(message, ControlMessage::Handshake(_)) {
            self.inbox
                .push_back(IncomingFrame::Control(ControlMessage::HandshakeAck(
                    HandshakeAck {
                        connection_id: "connection-fake".to_owned(),
                        session_token: "token-fake".to_owned(),
                        current_cursor: Cursor::new(Vec::new()),
                        schema_version: None::<SchemaVersion>,
                        initial_credits: 64,
                        last_applied_seq: None,
                    },
                )));
        }
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn send_bulk(&mut self, _message: BulkMessage) -> Result<(), FakeClosed> {
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn recv(&mut self) -> Result<Option<IncomingFrame>, FakeClosed> {
        Ok(self.inbox.pop_front())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn close(&mut self) -> Result<(), FakeClosed> {
        Ok(())
    }
}

fn transport() -> FakeTransport {
    FakeTransport {
        inbox: VecDeque::new(),
    }
}

fn config() -> ClientConfig {
    ClientConfig {
        client_id: "e2".to_owned(),
        auth_token: "token".to_owned(),
        schema_version: None,
        sql_functions: SqlFunctions::new(),
    }
}

fn key() -> ReplicaKey {
    let mut bytes = [0u8; ReplicaKey::LEN];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index).expect("the key is shorter than 256 bytes");
    }
    ReplicaKey::from_bytes(bytes)
}

fn other_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0xa5; ReplicaKey::LEN])
}

/// Whether `haystack` contains `needle` as a contiguous byte run.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Create a standalone database at `path` under `cipher` and apply `ddl`, which
/// is the first boot of any database that owns its own connection: there is no
/// plaintext-to-encrypted transform that works on both page codecs, so an
/// encrypted database is born encrypted and takes its schema from DDL.
fn first_boot_standalone(path: &str, key: Option<&ReplicaKey>, ddl: &str) {
    let mut conn = SqliteConnection::establish(path).expect("create the database");
    if let Some(key) = key {
        cipher::unlock(&mut conn, key).expect("apply the key");
    }
    conn.batch_execute(ddl).expect("apply the schema");
}

#[tokio::test]
async fn an_encrypted_replica_is_ciphertext_at_rest_and_a_plaintext_one_is_not() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let encrypted = dir.path().join("encrypted.sqlite");
    let plaintext = dir.path().join("plaintext.sqlite");

    let encrypted_url = url(&encrypted);
    let plaintext_url = url(&plaintext);
    for replica in [
        Replica::EncryptedFile {
            path: &encrypted_url,
            key: key(),
        },
        Replica::PlaintextFile {
            path: &plaintext_url,
        },
    ] {
        let mut conn =
            ConnettoConnection::connect(transport(), &replica, SQLITE_DDL, &config(), None)
                .await
                .expect("connect");
        diesel::insert_into(items::table)
            .values((items::id.eq(1), items::label.eq(MARKER)))
            .execute(conn.conn())
            .expect("write the canary");
    }

    let cipher_bytes = std::fs::read(&encrypted).expect("read the encrypted replica");
    assert!(
        !cipher_bytes.starts_with(SQLITE_MAGIC),
        "an encrypted database opens with the key salt, not the SQLite magic"
    );
    assert!(
        !contains(&cipher_bytes, MARKER.as_bytes()),
        "the row value must not survive as plaintext anywhere in the file"
    );
    assert!(
        !contains(&cipher_bytes, b"CREATE TABLE items"),
        "the schema text must not survive as plaintext either"
    );

    // The control proves the assertions above are testing the codec rather than
    // the absence of the string: the same write through a plaintext replica
    // leaves both readable on disk.
    let plain_bytes = std::fs::read(&plaintext).expect("read the plaintext replica");
    assert!(plain_bytes.starts_with(SQLITE_MAGIC));
    assert!(contains(&plain_bytes, MARKER.as_bytes()));
    assert!(contains(&plain_bytes, b"CREATE TABLE items"));
}

#[tokio::test]
async fn a_fresh_process_with_the_cached_key_resumes_with_its_unsynced_work() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("replica.sqlite");
    let db = url(&path);
    let replica = Replica::EncryptedFile {
        path: &db,
        key: key(),
    };

    let unsynced = {
        let mut conn =
            ConnettoConnection::connect(transport(), &replica, SQLITE_DDL, &config(), None)
                .await
                .expect("first connect");
        diesel::insert_into(items::table)
            .values((items::id.eq(7), items::label.eq(MARKER)))
            .execute(conn.conn())
            .expect("write a row");
        conn.push().await.expect("upload the captured mutation");
        let unsynced = conn.unsynced();
        assert!(
            !unsynced.is_empty(),
            "the fake server never acknowledges, so the mutation stays pending"
        );
        unsynced
    };

    // A different connection, a different capture session, the same file and the
    // same cached key: this is the cold start an offline reboot performs.
    let mut conn = ConnettoConnection::connect_existing(transport(), &replica, &config(), None)
        .await
        .expect("reopen with the cached key");
    let rows: Vec<Option<String>> = items::table
        .select(items::label)
        .load(conn.conn())
        .expect("read the rows back");
    assert_eq!(rows, vec![Some(MARKER.to_owned())]);
    assert_eq!(
        conn.unsynced(),
        unsynced,
        "the pending mutation survives the encrypted round trip and replays"
    );
}

#[tokio::test]
async fn a_process_without_the_key_cannot_read_the_replica() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("replica.sqlite");
    let db = url(&path);

    {
        let mut conn = ConnettoConnection::connect(
            transport(),
            &Replica::EncryptedFile {
                path: &db,
                key: key(),
            },
            SQLITE_DDL,
            &config(),
            None,
        )
        .await
        .expect("first connect");
        diesel::insert_into(items::table)
            .values((items::id.eq(1), items::label.eq(MARKER)))
            .execute(conn.conn())
            .expect("write the canary");
    }

    // A device whose key store was cleared while its replica survived gets fresh
    // material at the next login, which is the benign path into this error. It is
    // reported as its own variant rather than as corruption, because the recovery
    // is discard and re-sync.
    let wrong = ConnettoConnection::connect_existing(
        transport(),
        &Replica::EncryptedFile {
            path: &db,
            key: other_key(),
        },
        &config(),
        None,
    )
    .await;
    match wrong {
        Err(ClientError::ReplicaUndecryptable(_)) => {}
        Err(other) => panic!("expected ReplicaUndecryptable, got {other:?}"),
        Ok(_) => panic!("a wrong key must not open the replica"),
    }

    // Claiming the replica is plaintext fails too, and specifically not by
    // silently reading garbage: the codec never gets a key, so the first header
    // read fails.
    let unkeyed = ConnettoConnection::connect_existing(
        transport(),
        &Replica::PlaintextFile { path: &db },
        &config(),
        None,
    )
    .await;
    assert!(
        unkeyed.is_err(),
        "no key at all must not open the replica either"
    );

    // And the discard the error documents actually clears the file, so the next
    // connect rebuilds. `force` is set because the pending mutations live inside
    // the file this key will not open, so there is nothing left to guard.
    connetto_client::teardown::purge_replica(&path, &[], true).expect("discard the replica");
    let mut fresh = ConnettoConnection::connect(
        transport(),
        &Replica::EncryptedFile {
            path: &db,
            key: other_key(),
        },
        SQLITE_DDL,
        &config(),
        None,
    )
    .await
    .expect("a discarded replica re-boots under the new key");
    let rows: Vec<Option<String>> = items::table
        .select(items::label)
        .load(fresh.conn())
        .expect("read the empty replica");
    assert!(
        rows.is_empty(),
        "the rebuilt replica is empty and re-syncs from the server"
    );
}

#[tokio::test]
async fn the_durable_local_tier_is_encrypted_under_the_replica_key_and_resumes() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let replica_url = url(&dir.path().join("replica.sqlite"));
    let tier_path = dir.path().join("tier.sqlite");
    let tier = url(&tier_path);
    let replica = Replica::EncryptedFile {
        path: &replica_url,
        key: key(),
    };

    // First boot. The tier is created through the replica connection, which is
    // what makes its key salt agree with the replica's, and nothing else does.
    {
        let mut conn =
            ConnettoConnection::connect(transport(), &replica, SQLITE_DDL, &config(), None)
                .await
                .expect("connect the encrypted replica");
        conn.attach_local_tier_ddl(&tier, TIER_DDL)
            .expect("first-boot the durable tier through the replica connection");
        assert!(conn.local_tables().contains("notes"));
        diesel::insert_into(notes::table)
            .values((notes::id.eq(1), notes::body.eq(TIER_MARKER)))
            .execute(conn.conn())
            .expect("write into the tier");
    }

    let bytes = std::fs::read(&tier_path).expect("read the tier file");
    assert!(
        !bytes.starts_with(SQLITE_MAGIC),
        "the tier file is ciphertext too, which matters most of all: it has no server copy to re-sync from"
    );
    assert!(!contains(&bytes, TIER_MARKER.as_bytes()));
    assert!(!contains(&bytes, b"CREATE TABLE notes"));

    // Second run: the existing tier file re-attaches with no DDL and no key
    // clause, and its rows come back. This is the resume path, and it works
    // because the first boot made the two salts agree.
    let mut conn = ConnettoConnection::connect_existing(transport(), &replica, &config(), None)
        .await
        .expect("reopen the encrypted replica");
    conn.attach_local_tier(&tier)
        .expect("re-attach the tier a previous run created");
    let rows: Vec<Option<String>> = notes::table
        .select(notes::body)
        .load(conn.conn())
        .expect("read the tier rows back");
    assert_eq!(rows, vec![Some(TIER_MARKER.to_owned())]);
}

#[tokio::test]
async fn a_tier_file_from_another_connection_cannot_attach_to_an_encrypted_replica() {
    let dir = tempfile::tempdir().expect("a temporary directory");

    // Two ways an app reaches this: a plaintext baked template, which is what a
    // build-time artifact always is, and an encrypted file some other connection
    // created, which carries its own key salt. Neither can attach, and the point
    // is that neither silently leaves the tier in the clear.
    for (name, tier_key) in [("plaintext.sqlite", None), ("foreign.sqlite", Some(key()))] {
        let tier = url(&dir.path().join(name));
        let replica_url = url(&dir.path().join(format!("replica-for-{name}")));
        first_boot_standalone(&tier, tier_key.as_ref(), TIER_DDL);
        let mut conn = ConnettoConnection::connect(
            transport(),
            &Replica::EncryptedFile {
                path: &replica_url,
                key: key(),
            },
            SQLITE_DDL,
            &config(),
            None,
        )
        .await
        .expect("connect the encrypted replica");
        assert!(
            conn.attach_local_tier(&tier).is_err(),
            "attaching {name} must fail rather than leaving the tier readable"
        );
    }
}

/// The utf-8 form of a temporary path, with the same expectation spelled once.
fn url(path: &std::path::Path) -> String {
    path.to_str().expect("a utf-8 temporary path").to_owned()
}
