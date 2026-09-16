//! R56 import crossing the relay, where a page hands over a `Blob`, the
//! worker reads it with `FileReaderSync`, applies it, and the reply carries
//! the row counts.
//!
//! The `Blob` handle crosses `postMessage` without copying its bytes, so the
//! archive is never held twice. The blob size is asserted as well as the row
//! values, because the wasm SQLite build has silently returned empty results
//! before.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_client::{ClientConfig, ConnettoConnection, ExportScope, Replica, ReplicaKey};
use connetto_core::test_support::FakeTransport;
use connetto_web::RelayHub;
use connetto_web::locks;
use connetto_web::storage::{ReplicaStorage, tier_db_name};
use connetto_web::workers::{
    BlobSink, BlobSource, DB_ALIVE_LOCK, request_export_on, request_import_on,
    serve_export_requests_on, serve_import_requests_on,
};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel_sqlite_session::{ConflictAction, SqliteSessionExt};
use std::io::{BufReader, Read};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

const REPLICA_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)";

/// The replica holding the data the blob test exports.
const SRC: &str = "r56-import-src.sqlite";
/// The replica the blob test imports into.
const DST: &str = "r56-import-dst.sqlite";
/// The replica holding the data the round-trip test exports.
///
/// Its own name because the suite runs every test at once in one page, where
/// two tests sharing a database delete each other's while it is open.
const RT_SRC: &str = "r56-rt-src.sqlite";
/// The replica the round-trip test imports into.
const RT_DST: &str = "r56-rt-dst.sqlite";
/// Every replica and tier the tests in this file hold at once.
///
/// The suite runs them together in one page, so each reserves the whole
/// figure rather than its own four, since a reservation counts the databases
/// that exist when it is made and cannot see a sibling's yet.
const POOL_SLOTS: u32 = 8;
/// Export channel unique to this test so concurrent tests do not race.
const BLOB_EXPORT_CH: &str = "r56-blob-tier-export";
/// Import channel unique to this test so concurrent tests do not race.
const BLOB_IMPORT_CH: &str = "r56-blob-tier-import";
/// Export channel for the round-trip test.
const RT_EXPORT_CH: &str = "r56-rt-export";
/// Import channel for the round-trip test.
const RT_IMPORT_CH: &str = "r56-rt-import";

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

/// A page hands over a `Blob` holding the archive, and the worker reads it
/// with `FileReaderSync`, applies it, and answers with the counts.
/// The restored rows are read back through an export rather than trusted from
/// the counts alone.
#[wasm_bindgen_test]
async fn a_blob_lands_in_the_worker_tier() {
    let storage = ReplicaStorage::install().await;
    let src_tier = tier_db_name(SRC);
    let dst_tier = tier_db_name(DST);
    storage.delete_db(SRC).expect("clear earlier src replica");
    storage
        .delete_db(&src_tier)
        .expect("clear earlier src tier");
    storage.delete_db(DST).expect("clear earlier dst replica");
    storage
        .delete_db(&dst_tier)
        .expect("clear earlier dst tier");

    storage.reserve(POOL_SLOTS).await.expect("room in the pool");

    let archive_blob = {
        let src_url = storage.db_url(SRC);
        let src_replica = Replica::encrypted_file(
            &src_url,
            Some(ReplicaKey::from_bytes([0x56; ReplicaKey::LEN])),
        )
        .expect("resolved src key")
        .with_tier(TIER_DDL);
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
        // Unsynced scope exports the private tier without the synced replica cache.
        let sink = BlobSink::new();
        let sink = src
            .export_local_data(ExportScope::Unsynced, sink)
            .expect("export src");
        sink.into_blob().expect("sink into blob")
    };

    let dst_url = storage.db_url(DST);
    let dst_replica = Replica::encrypted_file(
        &dst_url,
        Some(ReplicaKey::from_bytes([0x56; ReplicaKey::LEN])),
    )
    .expect("resolved dst key")
    .with_tier(TIER_DDL);
    let mut worker = ConnettoConnection::connect(
        FakeTransport::accepting_but_silent(),
        &dst_replica,
        REPLICA_DDL,
        &config(),
        None,
    )
    .await
    .expect("dst connect");
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
    serve_import_requests_on(hub.clone(), BLOB_IMPORT_CH).expect("install the import service");
    serve_export_requests_on(hub.clone(), BLOB_EXPORT_CH).expect("install the export service");

    // Without this lock request_import sees no worker and returns Gone immediately.
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;

    assert!(archive_blob.size() > 0.0, "the archive blob carries bytes");
    let (outcome, collisions) = request_import_on(archive_blob, BLOB_IMPORT_CH)
        .await
        .expect("import succeeds");

    assert_eq!(collisions, 0, "a fresh tier has no collisions");
    assert!(
        outcome.rows_restored >= 1,
        "at least one device-private row was restored"
    );

    verify_tier_row_restored(
        ExportScope::Unsynced,
        "device-private.patchset",
        "restored-value",
        BLOB_EXPORT_CH,
    )
    .await;
}

/// One archive entry as raw bytes (zstd-compressed for data entries).
fn read_entry(archive: &mut zip::ZipArchive<BufReader<BlobSource>>, name: &str) -> Vec<u8> {
    let mut e = archive.by_name(name).expect("the entry is present");
    let mut bytes = Vec::new();
    e.read_to_end(&mut bytes).expect("read");
    bytes
}

/// Re-exports via the relay on `export_channel`, reads the private-tier patchset,
/// and asserts that `expected_body` is the stored value.
async fn verify_tier_row_restored(
    scope: ExportScope,
    entry: &str,
    expected_body: &str,
    export_channel: &str,
) {
    let export_blob = request_export_on(scope, export_channel)
        .await
        .expect("re-export after import");
    let source = BlobSource::new(export_blob).expect("BlobSource in dedicated worker");
    let mut archive = zip::ZipArchive::new(BufReader::new(source)).expect("archive");
    let tier_zstd = read_entry(&mut archive, entry);
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
        vec![Some(expected_body.to_owned())],
        "the exact value written on the source device is restored"
    );
}

/// The `Blob` the export reply carries goes straight back into import, which
/// is the archive crossing from one side to the other with no copy on the
/// page.
#[wasm_bindgen_test]
async fn export_reply_blob_round_trips_into_import() {
    let storage = ReplicaStorage::install().await;
    let src_tier = tier_db_name(RT_SRC);
    let dst_tier = tier_db_name(RT_DST);
    storage
        .delete_db(RT_SRC)
        .expect("clear earlier src replica");
    storage
        .delete_db(&src_tier)
        .expect("clear earlier src tier");
    storage
        .delete_db(RT_DST)
        .expect("clear earlier dst replica");
    storage
        .delete_db(&dst_tier)
        .expect("clear earlier dst tier");
    storage.reserve(POOL_SLOTS).await.expect("room in the pool");

    let export_blob = {
        let src_url = storage.db_url(RT_SRC);
        let src_replica = Replica::encrypted_file(
            &src_url,
            Some(ReplicaKey::from_bytes([0x57; ReplicaKey::LEN])),
        )
        .expect("resolved key")
        .with_tier(TIER_DDL);
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
            .values((drafts::id.eq(9), drafts::body.eq("blob-round-trip")))
            .execute(src.conn())
            .expect("write tier row");
        let (hub, pump, _notices) = RelayHub::new(src, ":memory:").expect("hub meta");
        wasm_bindgen_futures::spawn_local(async move {
            pump.await.expect("hub pump");
        });
        serve_export_requests_on(hub, RT_EXPORT_CH).expect("install export service");
        let alive = locks::hold_lock(DB_ALIVE_LOCK).await;
        let blob = request_export_on(ExportScope::Unsynced, RT_EXPORT_CH)
            .await
            .expect("export succeeds");
        alive.release();
        blob
        // The hub and worker go out of scope here.
    };

    assert!(
        export_blob.size() > 0.0,
        "export blob must carry bytes before import"
    );

    let dst_url = storage.db_url(RT_DST);
    let dst_replica = Replica::encrypted_file(
        &dst_url,
        Some(ReplicaKey::from_bytes([0x57; ReplicaKey::LEN])),
    )
    .expect("resolved key")
    .with_tier(TIER_DDL);
    let worker = ConnettoConnection::connect(
        FakeTransport::accepting_but_silent(),
        &dst_replica,
        REPLICA_DDL,
        &config(),
        None,
    )
    .await
    .expect("dst connect");
    let (hub, pump, _notices) = RelayHub::new(worker, ":memory:").expect("hub meta");
    wasm_bindgen_futures::spawn_local(async move {
        pump.await.expect("hub pump");
    });
    serve_import_requests_on(hub, RT_IMPORT_CH).expect("install import service");
    let _alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    let (outcome, collisions) = request_import_on(export_blob, RT_IMPORT_CH)
        .await
        .expect("import of export blob succeeds");
    assert_eq!(collisions, 0, "fresh destination has no collisions");
    assert!(outcome.rows_restored >= 1, "at least one row was restored");
}
