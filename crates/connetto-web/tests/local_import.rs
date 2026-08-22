//! R56 import crossing through the relay: a page hands a File, the worker
//! applies it, and the reply carries the row counts.
//!
//! The file object is posted on [`IMPORT_CHANNEL`] as a structured-clone
//! handle, so the worker reads the bytes inside the worker and the archive
//! is never held twice. The bytes and row values are both asserted: the
//! wasm SQLite build has silently returned empty results before.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::{ClientConfig, ConnettoConnection, ExportScope, Replica, ReplicaKey};
use connetto_core::test_support::FakeTransport;
use connetto_web::RelayHub;
use diesel::connection::SimpleConnection;
use connetto_web::locks;
use connetto_web::storage::{ReplicaStorage, tier_db_name};
use connetto_web::workers::{
    DB_ALIVE_LOCK, request_export, request_import, serve_export_requests, serve_import_requests,
};
use diesel::prelude::*;
use diesel_sqlite_session::{ConflictAction, SqliteSessionExt};
use std::io::{Cursor, Read};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const REPLICA_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)";

/// Source replica: has the data to export.
const SRC: &str = "r56-import-src.sqlite";
/// Destination replica: empty tier, receives the import.
const DST: &str = "r56-import-dst.sqlite";

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
    // Same account on both sides so the import accepts the archive.
    ClientConfig::new("r56-import").with_login(Some(connetto_client::Grant::new("user:importer")))
}

/// A page hands a real archive across as a File, the worker applies it, and
/// the reply carries the counts. The rows are verified by a subsequent export
/// rather than trusting the counts alone.
#[wasm_bindgen_test]
async fn a_file_lands_in_the_worker_tier() {
    let storage = ReplicaStorage::install().await;
    let src_tier = tier_db_name(SRC);
    let dst_tier = tier_db_name(DST);
    storage.delete_db(SRC).expect("clear earlier src replica");
    storage.delete_db(&src_tier).expect("clear earlier src tier");
    storage.delete_db(DST).expect("clear earlier dst replica");
    storage.delete_db(&dst_tier).expect("clear earlier dst tier");
    // Four slots: one replica + one tier per connection, two connections in
    // sequence (src is dropped before dst opens), so four slots at most.
    storage.reserve(4).await.expect("room in the pool");

    // Build source archive: a replica with a known device-private row.
    let archive_bytes = {
        let src_url = storage.db_url(SRC);
        let src_replica =
            Replica::encrypted_file(&src_url, Some(ReplicaKey::from_bytes([0x56; ReplicaKey::LEN])))
                .expect("resolved src key")
                .with_tier(&src_tier, TIER_DDL);
        let mut src = ConnettoConnection::connect(
            FakeTransport::accepting_but_silent(),
            &src_replica,
            REPLICA_DDL,
            &config(),
            None,
        )
        .await
        .expect("src connect");
        diesel::insert_into(drafts::table)
            .values((drafts::id.eq(7), drafts::body.eq("restored-value")))
            .execute(src.conn())
            .expect("write tier row on src");
        // Scope: Unsynced exports the device-private tier without the synced
        // replica cache, which is what an import restores anyway.
        src.export_local_data(ExportScope::Unsynced)
            .expect("export src")
        // src is dropped here, releasing the OPFS files.
    };

    // Open the destination worker with an empty tier and no source data.
    let dst_url = storage.db_url(DST);
    let dst_replica =
        Replica::encrypted_file(&dst_url, Some(ReplicaKey::from_bytes([0x56; ReplicaKey::LEN])))
            .expect("resolved dst key")
            .with_tier(&dst_tier, TIER_DDL);
    let mut worker = ConnettoConnection::connect(
        FakeTransport::accepting_but_silent(),
        &dst_replica,
        REPLICA_DDL,
        &config(),
        None,
    )
    .await
    .expect("dst connect");
    // Confirm the tier is empty before the import.
    assert_eq!(
        drafts::table
            .count()
            .get_result::<i64>(worker.conn())
            .expect("count before import"),
        0,
        "dst tier is empty before import"
    );

    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("hub meta");
    wasm_bindgen_futures::spawn_local(async move {
        pump.await.expect("hub pump");
    });
    serve_import_requests(hub.clone()).expect("install the import service");
    serve_export_requests(hub.clone()).expect("install the export service");

    // Hold the alive lock for the duration of the call. Without it
    // `request_import` would see no worker and return Gone immediately,
    // because the liveness check looks for this lock rather than timing out.
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;

    // Hand the archive as a File so the worker reads the bytes inside the
    // worker, never materialising them in the page process.
    let file = make_file(&archive_bytes, "archive.zip");
    let (outcome, collisions) = request_import(file).await.expect("import succeeds");

    assert_eq!(collisions, 0, "a fresh tier has no collisions");
    assert!(
        outcome.rows_restored >= 1,
        "at least one device-private row was restored"
    );

    // Verify the row is actually in the worker's tier by re-exporting and
    // applying the patchset to a check connection. Trusting the counts alone
    // is not enough: the wasm build has silently returned empty results before.
    let export_bytes = request_export(ExportScope::Unsynced)
        .await
        .expect("re-export after import");
    let mut archive = zip::ZipArchive::new(Cursor::new(export_bytes)).expect("archive");
    let tier_zstd = read_entry(&mut archive, "device-private.patchset");
    assert!(!tier_zstd.is_empty(), "the tier patchset is non-empty");
    let tier_patch = zstd::decode_all(tier_zstd.as_slice()).expect("decompress");
    assert!(!tier_patch.is_empty(), "the tier patchset decompresses");

    let mut check = diesel::SqliteConnection::establish(":memory:").expect("check db");
    check.batch_execute(TIER_DDL).expect("tier schema");
    check
        .apply_patchset(&tier_patch, |_| ConflictAction::Abort)
        .expect("apply tier patchset");
    assert_eq!(
        drafts::table
            .select(drafts::body)
            .load::<Option<String>>(&mut check)
            .expect("read rows after import"),
        vec![Some("restored-value".to_owned())],
        "the exact value written on the source device is restored"
    );
}

/// Wrap bytes in a `web_sys::File` so the page-side request can post it as a
/// structured-clone handle.
fn make_file(bytes: &[u8], name: &str) -> web_sys::File {
    let array = js_sys::Uint8Array::from(bytes);
    let sequence = js_sys::Array::of1(&array);
    web_sys::File::new_with_u8_array_sequence(&sequence, name).expect("file from bytes")
}

/// One archive entry as raw bytes (zstd-compressed for data entries).
fn read_entry(archive: &mut zip::ZipArchive<Cursor<Vec<u8>>>, name: &str) -> Vec<u8> {
    let mut e = archive.by_name(name).expect("the entry is present");
    let mut bytes = Vec::new();
    e.read_to_end(&mut bytes).expect("read");
    bytes
}
