//! R26 through the relay: a tab asks, the DB worker exports.
//!
//! The worker connection is the only durable copy in this topology, so the
//! archive has to come from the hub rather than from the asking tab's own
//! in-memory mirror. This drives the real channel protocol: a real
//! [`RelayHub`] over a real encrypted OPFS replica with a device-private tier
//! beside it, the export service installed on it, and the page-side request
//! function asking for the bytes.
//!
//! Runs in a dedicated worker for the sahpool VFS, and reads the reply back as
//! a plain zip of plain SQLite databases, which is the promise the format
//! makes. Asserting the bytes rather than the call's success is the point: the
//! export attaches a scratch database through a URI, and whether the browser's
//! SQLite build honours one is not something to assume.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::{ClientConfig, ConnettoConnection, Replica, ReplicaKey};
use connetto_core::test_support::FakeTransport;
use connetto_web::RelayHub;
use connetto_web::storage::{ReplicaStorage, tier_db_name};
use connetto_web::workers::{request_export, serve_export_requests};
use diesel::prelude::*;
use std::io::{Cursor, Read};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const REPLICA_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)";

/// Distinct from the other suites' names so one OPFS pool holds them all.
const REPLICA: &str = "r26-export.sqlite";

diesel::table! {
    /// The synced tier's table.
    items (id) {
        /// Item identifier, the primary key.
        id -> Integer,
        /// Item label.
        label -> Nullable<Text>,
    }
}

diesel::table! {
    /// The device-private tier's table.
    drafts (id) {
        /// Draft identifier, the primary key.
        id -> Integer,
        /// Draft body.
        body -> Nullable<Text>,
    }
}

#[derive(diesel::QueryableByName)]
struct NameRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}

fn config() -> ClientConfig {
    ClientConfig::new("r26-export").with_login(Some(connetto_client::Grant::new("user:tester")))
}

/// The archive a tab receives holds both tiers as readable SQLite, with the
/// rows this device wrote and none of connetto's own bookkeeping.
#[wasm_bindgen_test]
async fn a_tab_receives_both_tiers_as_plain_sqlite() {
    let storage = ReplicaStorage::install().await;
    let tier = tier_db_name(REPLICA);
    storage.delete_db(REPLICA).expect("clear an earlier replica");
    storage.delete_db(&tier).expect("clear an earlier tier");
    storage.reserve(4).await.expect("room in the pool");
    let replica_url = storage.db_url(REPLICA);
    let replica = Replica::encrypted_file(
        &replica_url,
        Some(ReplicaKey::from_bytes([0x26; ReplicaKey::LEN])),
    )
    .expect("a resolved key")
    .with_tier(&tier, TIER_DDL);
    let mut worker = ConnettoConnection::connect(
        // Silent, not merely accepting: an accepting transport reports a close
        // once its scripted frames run out, and the hub pump ends with it.
        FakeTransport::accepting_but_silent(),
        &replica,
        REPLICA_DDL,
        &config(),
        None,
    )
    .await
    .expect("connect");
    diesel::insert_into(items::table)
        .values((items::id.eq(1), items::label.eq("synced")))
        .execute(worker.conn())
        .expect("write a synced row");
    diesel::insert_into(drafts::table)
        .values((drafts::id.eq(7), drafts::body.eq("device-private")))
        .execute(worker.conn())
        .expect("write a device-private row");

    // The hub takes the connection, so from here the archive is only reachable
    // by asking the core, which is exactly what the export service does.
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("hub meta");
    wasm_bindgen_futures::spawn_local(async move {
        pump.await.expect("hub pump");
    });
    serve_export_requests(hub).expect("install the export service");

    let bytes = request_export().await.expect("the worker answers");
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("a plain zip");
    let manifest: serde_json::Value =
        serde_json::from_slice(&entry(&mut archive, "manifest.json")).expect("manifest json");
    assert_eq!(manifest["format"], "connetto-local-data");
    assert_eq!(manifest["databases"][0]["tier"], "synced");
    assert_eq!(
        manifest["databases"][1]["tier"], "device_private",
        "the tier this device could otherwise lose is in the archive"
    );

    let synced = entry(&mut archive, "synced.sqlite");
    let private = entry(&mut archive, "device-private.sqlite");
    assert!(
        synced.starts_with(SQLITE_MAGIC) && private.starts_with(SQLITE_MAGIC),
        "each entry is a database any SQLite tool opens, not an encrypted page image"
    );

    let mut synced = opened(&synced);
    assert_eq!(
        items::table
            .select(items::label)
            .load::<Option<String>>(&mut synced)
            .expect("read the exported synced rows"),
        vec![Some("synced".to_owned())]
    );
    let mut private = opened(&private);
    assert_eq!(
        drafts::table
            .select(drafts::body)
            .load::<Option<String>>(&mut private)
            .expect("read the exported device-private rows"),
        vec![Some("device-private".to_owned())]
    );
    // The hub keys a durable write counter per tab inside the tier. It is
    // connetto's bookkeeping, not the user's data, so it stays behind.
    assert!(
        !objects(&mut private).iter().any(|name| name.starts_with('_')),
        "connetto's own tables are not part of a user's export"
    );
}

/// One archive entry, read whole.
fn entry(archive: &mut zip::ZipArchive<Cursor<Vec<u8>>>, name: &str) -> Vec<u8> {
    let mut entry = archive.by_name(name).expect("the entry is present");
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).expect("read the entry");
    bytes
}

/// An exported database, opened read-only from its bytes.
fn opened(bytes: &[u8]) -> diesel::SqliteConnection {
    let mut conn = diesel::SqliteConnection::establish(":memory:").expect("open sqlite");
    conn.deserialize_readonly_database_from_buffer(bytes)
        .expect("the bytes are a database");
    conn
}

/// Every schema object name in an exported database.
fn objects(conn: &mut diesel::SqliteConnection) -> Vec<String> {
    diesel::sql_query("SELECT name FROM sqlite_schema")
        .load::<NameRow>(conn)
        .expect("read the schema")
        .into_iter()
        .map(|row| row.name)
        .collect()
}
