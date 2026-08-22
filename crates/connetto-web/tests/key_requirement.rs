//! R62 in the browser: the key requirement holds on the worker's own replica
//! and on the device-private database beside it.
//!
//! The tier matters more here than on native. A tab does not read the tier
//! directly: the worker holds it and the relay builds a tab's copy as a
//! session diff, which records nothing for a table whose only key is the
//! implicit `rowid`, so an unkeyed tier table is empty from every tab and no
//! error says why. Runs against real OPFS, because the refusals are read off
//! the live schema of files the pool owns.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::{ClientConfig, ClientError, ConnettoConnection, Replica, ReplicaKey};
use connetto_core::test_support::FakeTransport;
use connetto_web::storage::{ReplicaStorage, tier_db_name};
use diesel::connection::SimpleConnection;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const REPLICA_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const UNKEYED_TIER_DDL: &str = "CREATE TABLE scratch (body TEXT)";

fn config() -> ClientConfig {
    ClientConfig::new("r62")
}

fn key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x62; ReplicaKey::LEN])
}

/// The refused names, or a panic naming what came back instead.
fn refused<T>(result: Result<T, ClientError>) -> Vec<String> {
    match result {
        Err(ClientError::WritesNotRecorded { tables }) => tables,
        Err(other) => panic!("expected a key-requirement refusal, got {other}"),
        Ok(_) => panic!("expected a refusal, got success"),
    }
}

/// Clear both files of one replica and make room for them.
async fn fresh(storage: &ReplicaStorage, replica: &str) -> String {
    let tier = tier_db_name(replica);
    storage.delete_db(replica).expect("clear the replica");
    storage.delete_db(&tier).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");
    tier
}

/// A schema carrying an unkeyed table is refused where the worker opens it,
/// with the same message the native client gives.
#[wasm_bindgen_test]
async fn a_rowid_only_table_is_refused_in_the_worker() {
    let storage = ReplicaStorage::install().await;
    let name = "r62-main.sqlite";
    fresh(&storage, name).await;
    let url = storage.db_url(name);

    let tables = refused(ConnettoConnection::<FakeTransport>::open(
        &Replica::encrypted_file(&url, Some(key())).expect("a resolved key"),
        "CREATE TABLE items (id INTEGER PRIMARY KEY); CREATE TABLE prefs (name TEXT, value TEXT)",
        &config(),
        None,
    ));
    assert_eq!(tables.len(), 1, "one refusal: {tables:?}");
    assert!(
        tables[0].contains("prefs"),
        "names the table: {}",
        tables[0]
    );
    storage.delete_db(name).expect("the refused open let go");
}

/// The tier is refused when connetto creates it, because a tab reads a tier
/// table through a session diff.
#[wasm_bindgen_test]
async fn an_unkeyed_tier_table_is_refused_on_the_create_path() {
    let storage = ReplicaStorage::install().await;
    let name = "r62-tier-create.sqlite";
    let tier = fresh(&storage, name).await;
    let url = storage.db_url(name);

    let tables = refused(ConnettoConnection::<FakeTransport>::open(
        &Replica::encrypted_file(&url, Some(key()))
            .expect("a resolved key")
            .with_tier(&tier, UNKEYED_TIER_DDL),
        REPLICA_DDL,
        &config(),
        None,
    ));
    assert!(
        tables.iter().any(|refusal| refusal.contains("scratch")),
        "names the tier table: {tables:?}"
    );
    assert!(
        tables
            .iter()
            .any(|refusal| refusal.contains("device-private")),
        "and says which database holds it: {tables:?}"
    );

    storage.delete_db(&tier).expect("the tier handle is free");
    storage.delete_db(name).expect("and the replica's");
}

/// And again when it attaches the tier a previous run left behind, which is
/// every reload after the first.
#[wasm_bindgen_test]
async fn an_unkeyed_tier_table_is_refused_on_the_existing_path() {
    let storage = ReplicaStorage::install().await;
    let name = "r62-tier-existing.sqlite";
    let tier = fresh(&storage, name).await;
    let url = storage.db_url(name);

    // Written once with the table accepted, which is the only way such a tier
    // gets created at all, then reopened without the acceptance.
    drop(
        ConnettoConnection::<FakeTransport>::open(
            &Replica::encrypted_file(&url, Some(key()))
                .expect("a resolved key")
                .with_tier(&tier, UNKEYED_TIER_DDL),
            REPLICA_DDL,
            &config().with_unrecorded_tables(["scratch"]),
            None,
        )
        .expect("the accepted tier opens"),
    );
    let tables = refused(ConnettoConnection::<FakeTransport>::open_existing(
        &Replica::encrypted_file(&url, Some(key()))
            .expect("a resolved key")
            .with_existing_tier(&tier),
        &config(),
        None,
    ));
    assert!(
        tables.iter().any(|refusal| refusal.contains("scratch")),
        "names the tier table: {tables:?}"
    );

    storage.delete_db(&tier).expect("the tier handle is free");
    storage.delete_db(name).expect("and the replica's");
}

/// An accepted tier table opens and records nothing, which is the consented
/// behaviour, and a tier table created mid-run is caught at the next write
/// rather than at the next reload.
#[wasm_bindgen_test]
async fn an_accepted_tier_table_records_nothing_and_a_later_one_is_caught() {
    let storage = ReplicaStorage::install().await;
    let name = "r62-accepted.sqlite";
    let tier = fresh(&storage, name).await;
    let url = storage.db_url(name);

    {
        let mut conn = ConnettoConnection::<FakeTransport>::open(
            &Replica::encrypted_file(&url, Some(key()))
                .expect("a resolved key")
                .with_tier(&tier, UNKEYED_TIER_DDL),
            REPLICA_DDL,
            &config().with_unrecorded_tables(["scratch"]),
            None,
        )
        .expect("the accepted tier opens");
        conn.batch_execute("INSERT INTO scratch (body) VALUES ('kept locally')")
            .expect("write an accepted row");
        assert_eq!(
            conn.push().await.expect("push"),
            None,
            "nothing was recorded, which is what the acceptance means"
        );

        conn.batch_execute("CREATE TABLE connetto_local.later (body TEXT)")
            .expect("create an unaccepted tier table mid-run");
        let tables = refused(conn.push().await);
        assert!(
            tables.iter().any(|refusal| refusal.contains("later")),
            "the next write catches it: {tables:?}"
        );
    }

    storage.delete_db(&tier).expect("the tier handle is free");
    storage.delete_db(name).expect("and the replica's");
}
