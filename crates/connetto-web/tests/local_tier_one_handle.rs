//! R43: the device-private database has exactly one handle, and it is the
//! replica connection's own attachment.
//!
//! The worker used to hold two at once for its whole life, one from the
//! client's `ATTACH` and one standalone connection the relay served from. The
//! browser's storage pool cannot support that: it keys open files by name, so
//! the two shared a single underlying handle while keeping separate page
//! caches, and closing both tripped the pool's own `DB closed without open`
//! assertion.
//!
//! Runs in a dedicated worker against real OPFS, because the property under
//! test is about the pool's handle bookkeeping and an in-memory VFS has none.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::{ClientConfig, ConnettoConnection, Replica, ReplicaKey, SqlFunctions};
use connetto_core::test_support::FakeTransport;
use connetto_web::storage::{ReplicaStorage, tier_db_name};
use diesel::prelude::*;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const REPLICA_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)";

diesel::table! {
    /// Device-private test table, named bare exactly as an application names it.
    drafts (id) {
        /// Draft identifier, the primary key
        id -> Integer,
        /// Optional draft body
        body -> Nullable<Text>,
    }
}

#[derive(diesel::QueryableByName)]
struct SchemaName {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}

fn config() -> ClientConfig {
    ClientConfig {
        client_id: "r43".to_owned(),
        login: Some(connetto_client::Grant::new("user:tester")),
        capabilities: Vec::new(),
        schema_version: None,
        sql_functions: SqlFunctions::new(),
    }
}

/// The tier is reached through the replica connection, and the pool gets its
/// file back the moment that one connection drops.
#[wasm_bindgen_test]
async fn the_tier_is_attached_to_the_replica_and_frees_with_it() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r43-one-handle.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");

    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x5a; ReplicaKey::LEN]);
    {
        let replica = Replica::encrypted_file(&replica_url, Some(key))
            .expect("a resolved key")
            .with_tier(&tier_name, TIER_DDL);
        let mut conn = ConnettoConnection::connect(
            FakeTransport::accepting(),
            &replica,
            REPLICA_DDL,
            &config(),
            None,
        )
        .await
        .expect("connect");

        // The attachment is the mechanism, so say so rather than inferring it.
        let attached: Vec<SchemaName> = diesel::sql_query("PRAGMA database_list")
            .load(conn.conn())
            .expect("list the attached schemas");
        let names: Vec<&str> = attached.iter().map(|row| row.name.as_str()).collect();
        assert!(
            names.contains(&"connetto_local"),
            "the tier is attached to the replica connection, got {names:?}"
        );

        // Reachable by a bare name from that same connection, which is what
        // lets one connection serve both tiers.
        diesel::insert_into(drafts::table)
            .values((drafts::id.eq(1), drafts::body.eq("draft")))
            .execute(conn.conn())
            .expect("write a device-private row");
        assert_eq!(
            conn.push().await.expect("push"),
            None,
            "a device-private write is outside the capture session and can never upload"
        );
    }

    // No await between the drop above and the deletes below. A second live
    // handle on either file would have left the pool holding it, and in this
    // build the pool asserts on the mismatched close rather than reporting it.
    storage
        .delete_db(&tier_name)
        .expect("the tier's handle was released with the connection");
    storage
        .delete_db(replica_name)
        .expect("and so was the replica's");
    let listed = storage.list();
    assert!(
        !listed.iter().any(|entry| entry == &tier_name),
        "the tier file is gone from the pool"
    );
}

/// Reopening finds the row, which is the half a page-cache split would break:
/// two handles can each hold pages the other has superseded.
#[wasm_bindgen_test]
async fn a_device_private_row_survives_a_reopen_through_the_attachment() {
    let storage = ReplicaStorage::install().await;
    let replica_name = "r43-reopen.sqlite";
    let tier_name = tier_db_name(replica_name);
    storage.delete_db(replica_name).expect("clear the replica");
    storage.delete_db(&tier_name).expect("clear the tier");
    storage.reserve(4).await.expect("room in the pool");

    let replica_url = storage.db_url(replica_name);
    let key = ReplicaKey::from_bytes([0x6b; ReplicaKey::LEN]);
    {
        let replica = Replica::encrypted_file(&replica_url, Some(key.clone()))
            .expect("a resolved key")
            .with_tier(&tier_name, TIER_DDL);
        let mut conn = ConnettoConnection::connect(
            FakeTransport::accepting(),
            &replica,
            REPLICA_DDL,
            &config(),
            None,
        )
        .await
        .expect("connect");
        diesel::insert_into(drafts::table)
            .values((drafts::id.eq(7), drafts::body.eq("kept")))
            .execute(conn.conn())
            .expect("write a device-private row");
    }

    let replica = Replica::encrypted_file(&replica_url, Some(key))
        .expect("a resolved key")
        .with_existing_tier(&tier_name);
    let mut conn =
        ConnettoConnection::connect_existing(FakeTransport::accepting(), &replica, &config(), None)
            .await
            .expect("reopen");
    let seen: Vec<Option<String>> = drafts::table
        .select(drafts::body)
        .load(conn.conn())
        .expect("read the tier back");
    assert_eq!(seen, vec![Some("kept".to_owned())]);
}
