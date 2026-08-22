//! R26/R56 through the relay: a tab asks, the DB worker exports.
//!
//! The archive format changed in R56: entries are SQLite change records
//! (patchsets), not plain databases. Each patchset is decompressed and
//! applied to a fresh in-memory connection, and the rows are read back.
//! The bytes are checked before the rows: the wasm SQLite build has
//! silently returned empty results before.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::{ClientConfig, ConnettoConnection, ExportScope, Replica, ReplicaKey};
use connetto_core::test_support::FakeTransport;
use diesel::connection::SimpleConnection;
use connetto_web::RelayHub;
use connetto_web::storage::{ReplicaStorage, tier_db_name};
use connetto_web::workers::{request_export, serve_export_requests};
use diesel::prelude::*;
use diesel_sqlite_session::{ConflictAction, SqliteSessionExt};
use std::io::{Cursor, Read};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

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

fn config() -> ClientConfig {
    ClientConfig::new("r26-export").with_login(Some(connetto_client::Grant::new("user:tester")))
}

/// The archive a tab receives carries both tiers as patchsets. Applying each
/// patchset to a fresh in-memory connection reads back the rows this device
/// wrote.
#[wasm_bindgen_test]
async fn a_tab_receives_both_tiers_as_patchsets() {
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

    // The hub takes the connection, so from here the data is only reachable
    // by asking the core, which is exactly what the export service does.
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("hub meta");
    wasm_bindgen_futures::spawn_local(async move {
        pump.await.expect("hub pump");
    });
    serve_export_requests(hub).expect("install the export service");

    let bytes = request_export(ExportScope::Everything)
        .await
        .expect("the worker answers");
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("a plain zip");

    // Verify the manifest describes the new format.
    let manifest: serde_json::Value =
        serde_json::from_slice(&entry_raw(&mut archive, "manifest.json"))
            .expect("manifest json");
    assert_eq!(manifest["format"], "connetto-local-data");
    assert_eq!(manifest["version"], 2, "R56 version");
    assert_eq!(
        manifest["entries"][0]["path"], "synced.patchset",
        "synced rows travel as a patchset"
    );
    assert_eq!(
        manifest["entries"][1]["path"], "device-private.patchset",
        "device-private rows travel as a patchset"
    );

    // Read both patchsets (stored zstd-compressed inside the zip entry).
    let synced_zstd = entry_raw(&mut archive, "synced.patchset");
    let private_zstd = entry_raw(&mut archive, "device-private.patchset");
    assert!(!synced_zstd.is_empty(), "the synced patchset is not empty");
    assert!(!private_zstd.is_empty(), "the device-private patchset is not empty");

    let synced_patch = zstd::decode_all(synced_zstd.as_slice()).expect("decompress synced");
    let private_patch = zstd::decode_all(private_zstd.as_slice()).expect("decompress private");
    assert!(!synced_patch.is_empty(), "synced patchset decompresses to real bytes");
    assert!(!private_patch.is_empty(), "private patchset decompresses to real bytes");

    // Apply each patchset to a fresh in-memory connection and read the rows.
    // This is the definitive proof: the wasm SQLite build has silently returned
    // empty results before, so the byte check above and these queries are both
    // required.
    let mut synced_conn = diesel::SqliteConnection::establish(":memory:").expect("open sqlite");
    synced_conn.batch_execute(REPLICA_DDL).expect("synced schema");
    synced_conn
        .apply_patchset(&synced_patch, |_| ConflictAction::Abort)
        .expect("apply synced patchset");
    assert_eq!(
        items::table
            .select(items::label)
            .load::<Option<String>>(&mut synced_conn)
            .expect("read synced rows"),
        vec![Some("synced".to_owned())]
    );

    let mut private_conn = diesel::SqliteConnection::establish(":memory:").expect("open sqlite");
    private_conn.batch_execute(TIER_DDL).expect("tier schema");
    private_conn
        .apply_patchset(&private_patch, |_| ConflictAction::Abort)
        .expect("apply private patchset");
    assert_eq!(
        drafts::table
            .select(drafts::body)
            .load::<Option<String>>(&mut private_conn)
            .expect("read private rows"),
        vec![Some("device-private".to_owned())]
    );
}

/// One archive entry as raw bytes. Data entries are zstd-compressed; the
/// manifest is plain JSON. The caller decides which is which.
fn entry_raw(archive: &mut zip::ZipArchive<Cursor<Vec<u8>>>, name: &str) -> Vec<u8> {
    let mut e = archive.by_name(name).expect("the entry is present");
    let mut bytes = Vec::new();
    e.read_to_end(&mut bytes).expect("read the entry");
    bytes
}
