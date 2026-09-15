//! R26/R56 through the relay: a tab asks, the DB worker exports.
//!
//! The archive format changed in R56: entries are SQLite change records
//! (patchsets), not plain databases. Each patchset is decompressed and
//! applied to a fresh in-memory connection, and the rows are read back.
//! The blob size is checked as well as the rows, because the wasm SQLite
//! build has silently returned empty results before.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::{ClientConfig, ConnettoConnection, ExportScope, Replica, ReplicaKey};
use connetto_core::test_support::FakeTransport;
use connetto_web::storage::{ReplicaStorage, tier_db_name};
use connetto_web::workers::{
    BlobSink, BlobSource, DB_ALIVE_LOCK, request_export, serve_export_requests,
};
use connetto_web::{RelayHub, locks};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel_sqlite_session::{ConflictAction, SqliteSessionExt};
use std::io::{BufReader, Read};
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
    storage
        .delete_db(REPLICA)
        .expect("clear an earlier replica");
    storage.delete_db(&tier).expect("clear an earlier tier");
    storage.reserve(4).await.expect("room in the pool");
    let replica_url = storage.db_url(REPLICA);
    let replica = Replica::encrypted_file(
        &replica_url,
        Some(ReplicaKey::from_bytes([0x26; ReplicaKey::LEN])),
    )
    .expect("a resolved key")
    .with_tier(TIER_DDL);
    let mut worker = ConnettoConnection::connect(
        // accepting_but_silent avoids a close after the scripted frames run out.
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

    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("hub meta");
    wasm_bindgen_futures::spawn_local(async move {
        pump.await.expect("hub pump");
    });
    serve_export_requests(hub).expect("install the export service");
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;

    let blob = request_export(ExportScope::Everything)
        .await
        .expect("the worker answers");
    assert!(blob.size() > 0.0, "the blob carries archive bytes");
    let source = BlobSource::new(blob).expect("BlobSource in dedicated worker");
    let mut archive =
        zip::ZipArchive::new(BufReader::new(source)).expect("a zip readable via BlobSource");

    let manifest: serde_json::Value =
        serde_json::from_slice(&entry_raw(&mut archive, "manifest.json")).expect("manifest json");
    assert_eq!(manifest["format"], "connetto-local-data");
    assert_eq!(manifest["version"], 3, "archive version");
    assert_eq!(
        manifest["entries"][0]["path"], "synced.patchset",
        "synced rows travel as a patchset"
    );
    assert_eq!(
        manifest["entries"][1]["path"], "device-private.patchset",
        "device-private rows travel as a patchset"
    );

    let synced_patch = decompress_entry(&mut archive, "synced.patchset");
    let private_patch = decompress_entry(&mut archive, "device-private.patchset");
    apply_and_assert_label(&synced_patch, REPLICA_DDL, "synced");
    apply_and_assert_body(&private_patch, TIER_DDL, "device-private");
}

/// Reads a zip entry and decompresses it from zstd.
fn decompress_entry(archive: &mut zip::ZipArchive<BufReader<BlobSource>>, name: &str) -> Vec<u8> {
    let raw = entry_raw(archive, name);
    assert!(!raw.is_empty(), "{name} must not be empty");
    let patch = zstd::decode_all(raw.as_slice()).expect("decompress patchset");
    assert!(!patch.is_empty(), "{name} must decompress to bytes");
    patch
}

/// Applies a patchset to a fresh `items` table and asserts the label.
fn apply_and_assert_label(patch: &[u8], ddl: &str, expected: &str) {
    let mut conn = diesel::SqliteConnection::establish(":memory:").expect("open sqlite");
    conn.batch_execute(ddl).expect("schema");
    conn.apply_patchset(patch, |_| ConflictAction::Abort)
        .expect("apply patchset");
    assert_eq!(
        items::table
            .select(items::label)
            .load::<Option<String>>(&mut conn)
            .expect("read rows"),
        vec![Some(expected.to_owned())]
    );
}

/// Applies a patchset to a fresh `drafts` table and asserts the body.
fn apply_and_assert_body(patch: &[u8], ddl: &str, expected: &str) {
    let mut conn = diesel::SqliteConnection::establish(":memory:").expect("open sqlite");
    conn.batch_execute(ddl).expect("schema");
    conn.apply_patchset(patch, |_| ConflictAction::Abort)
        .expect("apply patchset");
    assert_eq!(
        drafts::table
            .select(drafts::body)
            .load::<Option<String>>(&mut conn)
            .expect("read rows"),
        vec![Some(expected.to_owned())]
    );
}

/// One archive entry as raw bytes, which are zstd for a row entry and plain
/// for the manifest.
fn entry_raw(archive: &mut zip::ZipArchive<BufReader<BlobSource>>, name: &str) -> Vec<u8> {
    let mut e = archive.by_name(name).expect("the entry is present");
    let mut bytes = Vec::new();
    e.read_to_end(&mut bytes).expect("read the entry");
    bytes
}

/// Bytes written into a `BlobSink` produce an archive a `BlobSource` reads
/// back without a copy.
///
/// This also exercises data descriptors, because the streaming zip writer that
/// `BlobSink` sees emits them after each entry.
#[wasm_bindgen_test]
async fn blob_sink_to_blob_source_round_trip() {
    let storage = ReplicaStorage::install().await;
    let replica = "r26-blob-sink-rt.sqlite";
    let tier = tier_db_name(replica);
    storage.delete_db(replica).expect("clear earlier replica");
    storage.delete_db(&tier).expect("clear earlier tier");
    storage.reserve(2).await.expect("room in the pool");
    let url = storage.db_url(replica);
    let rep = Replica::encrypted_file(&url, Some(ReplicaKey::from_bytes([0x27; ReplicaKey::LEN])))
        .expect("a resolved key")
        .with_tier(TIER_DDL);
    let mut conn = ConnettoConnection::connect(
        FakeTransport::accepting_but_silent(),
        &rep,
        REPLICA_DDL,
        &ClientConfig::new("r26-sink-rt"),
        None,
    )
    .await
    .expect("connect");
    diesel::insert_into(drafts::table)
        .values((drafts::id.eq(42), drafts::body.eq("round-tripped")))
        .execute(conn.conn())
        .expect("write tier row");

    // Export using BlobSink directly, proving the streaming writer path works.
    let sink = BlobSink::new();
    let sink = conn
        .export_local_data(ExportScope::Unsynced, sink)
        .expect("export to sink");
    let blob = sink.into_blob().expect("sink into blob");
    assert!(blob.size() > 0.0, "the blob is non-empty");

    // Read it back with BlobSource and verify the tier row survives.
    let source = BlobSource::new(blob).expect("BlobSource in dedicated worker");
    let mut archive = zip::ZipArchive::new(BufReader::new(source)).expect("zip from BlobSource");
    let private_zstd = {
        let mut e = archive
            .by_name("device-private.patchset")
            .expect("private patchset entry");
        let mut v = Vec::new();
        e.read_to_end(&mut v).expect("read patchset entry");
        v
    };
    let patch = zstd::decode_all(private_zstd.as_slice()).expect("decompress patchset");
    let mut check = diesel::SqliteConnection::establish(":memory:").expect("check db");
    check.batch_execute(TIER_DDL).expect("tier schema");
    check
        .apply_patchset(&patch, |_| ConflictAction::Abort)
        .expect("apply patchset");
    assert_eq!(
        drafts::table
            .select(drafts::body)
            .load::<Option<String>>(&mut check)
            .expect("read rows"),
        vec![Some("round-tripped".to_owned())],
        "the row written to the BlobSink survives a BlobSource read"
    );
}
