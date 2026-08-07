//! Browser acceptance for phase E4: the account switch, against real OPFS.
//!
//! This is the claim the plan carried longest without ever running. Phases
//! `41e2888` and `bcc20a0` both deferred it, and E2 and E3 proved the pieces it
//! rests on (a distinct replica per identity, a distinct key per identity) without
//! ever putting two identities on one OPFS pool and switching between them.
//!
//! Runs in a dedicated worker, because the OPFS sahpool VFS needs synchronous
//! access handles and only a worker has them, and drives a real
//! [`ConnettoConnection`] over a fake transport rather than a bare
//! `SqliteConnection`, so the replica opens through exactly the path
//! `boot_db_worker` uses: the codec URL, the key, and the WAL pragma.
//!
//! The keys are two fixed values rather than minted ones, because the link from an
//! identity to its own key is what the `key_store` and `teardown` suites prove.
//! What this suite owes is that two identities' replicas are mutually opaque and
//! that a switch destroys nothing.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::{
    ClientConfig, ClientError, ConnettoConnection, Replica, ReplicaKey, SqlFunctions,
    replica_db_name,
};
use connetto_core::test_support::FakeTransport;
use connetto_web::storage::ReplicaStorage;
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const SQLITE_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

/// The replica-name prefix, distinct from the other suites' so one OPFS pool
/// holds them all without collision.
const PREFIX: &str = "e4-switch";

diesel::table! {
    /// Test table for replica contents
    items (id) {
        /// Item identifier, the primary key
        id -> Integer,
        /// Optional item label
        label -> Nullable<Text>,
    }
}

fn config() -> ClientConfig {
    ClientConfig {
        client_id: "e4".to_owned(),
        login: Some(connetto_client::Grant::new("user:tester")),
        capabilities: Vec::new(),
        schema_version: None,
        sql_functions: SqlFunctions::new(),
    }
}

fn key_from_byte(byte: u8) -> ReplicaKey {
    ReplicaKey::from_bytes([byte; ReplicaKey::LEN])
}

/// First-boot the encrypted replica at `url` under `key`, write a row, and leave
/// the captured mutation queued, since the fake server acknowledges the handshake
/// and nothing else. Returns the pending sequence numbers, captured before the
/// connection drops, which it must: one connection per database.
async fn first_boot_with_a_queued_row(url: &str, key: ReplicaKey) -> Vec<u64> {
    let mut conn = ConnettoConnection::connect(
        FakeTransport::accepting(),
        &Replica::encrypted_file(url, Some(key)).expect("a resolved key"),
        SQLITE_DDL,
        &config(),
        None,
    )
    .await
    .expect("first connect");
    assert!(
        conn.unsynced().is_empty(),
        "no unsynced work on a fresh replica"
    );
    diesel::insert_into(items::table)
        .values((items::id.eq(1), items::label.eq("alice-row")))
        .execute(conn.conn())
        .expect("insert the row");
    conn.push().await.expect("upload the captured mutation");
    let unsynced = conn.unsynced();
    assert!(
        !unsynced.is_empty(),
        "the unacknowledged mutation stays pending"
    );
    unsynced
}

/// Phase E4 acceptance, the browser half of the account switch: a distinct
/// replica per identity, each undecryptable with the other's key, neither
/// deleted, all against a real OPFS pool.
#[wasm_bindgen_test]
async fn an_account_switch_opens_a_distinct_opaque_replica_and_deletes_nothing() {
    let storage = ReplicaStorage::install().await;

    // The pool is shared with the other suites in this origin, so start from a
    // known state rather than from whatever an earlier run left.
    let alice = replica_db_name(PREFIX, "alice").expect("derive alice");
    let bob = replica_db_name(PREFIX, "bob").expect("derive bob");
    storage.delete_db(&alice).expect("clear alice");
    storage.delete_db(&bob).expect("clear bob");

    assert_ne!(alice, bob, "distinct identities select distinct replicas");
    assert_eq!(
        alice,
        replica_db_name(PREFIX, "alice").expect("derive alice again"),
        "one identity always returns to the same replica",
    );

    let alice_key = key_from_byte(0x11);
    let bob_key = key_from_byte(0x22);
    let alice_url = storage.db_url(&alice);
    let bob_url = storage.db_url(&bob);

    // Alice's boot: a fresh replica, a synced row, and a mutation left queued
    // because the fake server acknowledges the handshake and nothing else.
    let alice_unsynced = first_boot_with_a_queued_row(&alice_url, alice_key.clone()).await;

    // The switch. Bob's boot derives a different name, so it first-boots an empty
    // replica rather than resuming onto Alice's rows or her pending mutations.
    {
        let mut conn = ConnettoConnection::connect(
            FakeTransport::accepting(),
            &Replica::encrypted_file(&bob_url, Some(bob_key)).expect("a resolved key"),
            SQLITE_DDL,
            &config(),
            None,
        )
        .await
        .expect("connect bob");
        let seen: Vec<Option<String>> = items::table
            .select(items::label)
            .load(conn.conn())
            .expect("read bob");
        assert!(seen.is_empty(), "bob's replica holds none of alice's rows");
        assert!(
            conn.unsynced().is_empty(),
            "and none of her pending mutations either"
        );
    }

    // Nothing was deleted by the switch, read off the pool's own listing. This is
    // what makes a return fast and what makes a wipe have to be explicit.
    let listed = storage.list();
    assert!(
        listed.iter().any(|entry| entry == &alice) && listed.iter().any(|entry| entry == &bob),
        "a switch deletes neither replica"
    );

    // The two files are mutually opaque. Naming the other identity's replica
    // while holding this identity's key does not read it, so a switch cannot
    // degrade into a cross-identity resume even if the file selection were wrong.
    let crossed = ConnettoConnection::connect_existing(
        FakeTransport::accepting(),
        &Replica::encrypted_file(&bob_url, Some(alice_key.clone())).expect("a resolved key"),
        &config(),
        None,
    )
    .await;
    match crossed {
        Err(ClientError::ReplicaUndecryptable(_)) => {}
        Err(other) => panic!("expected ReplicaUndecryptable, got {other:?}"),
        Ok(_) => panic!("one identity's key must not open another's replica"),
    }

    // Switching back resumes the replica that was left alone, with its rows and
    // its queued mutation, so no snapshot leg is needed.
    let mut conn = ConnettoConnection::connect_existing(
        FakeTransport::accepting(),
        &Replica::encrypted_file(&alice_url, Some(alice_key)).expect("a resolved key"),
        &config(),
        None,
    )
    .await
    .expect("switch back to alice");
    let seen: Vec<Option<String>> = items::table
        .select(items::label)
        .load(conn.conn())
        .expect("read alice");
    assert_eq!(seen, vec![Some("alice-row".to_owned())]);
    assert_eq!(
        conn.unsynced(),
        alice_unsynced,
        "her unuploaded mutation survived the switch and replays"
    );
}
