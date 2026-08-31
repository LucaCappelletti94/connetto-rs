//! Local data export contract tests.

use connetto_client::{ClientConfig, ConnettoConnection, ExportScope, PolicyTables, Replica};
use diesel::prelude::*;
use sqlite_diff_rs::{ParsedDiffSet, PatchsetOp, Value};
use std::io::{Cursor, Read};
use zip::ZipArchive;

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const SYNCED_DDL: &str = "
CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT NOT NULL, payload BLOB NOT NULL) STRICT;
CREATE INDEX items_label_idx ON items(label);
";
const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT NOT NULL) STRICT;";

diesel::table! {
    /// Synced test table for items.
    items (id) {
        /// Item identifier, the primary key.
        id -> Integer,
        /// Label text, may contain NUL bytes.
        label -> Text,
        /// Binary payload.
        payload -> Binary,
    }
}

diesel::table! {
    /// Device-private test table for drafts.
    drafts (id) {
        /// Draft identifier, the primary key.
        id -> Integer,
        /// Draft body text, may contain NUL bytes.
        body -> Text,
    }
}

diesel::table! {
    /// Physical backing table for the policy-split orders table.
    orders_rls (id) {
        /// Order identifier, the primary key.
        id -> Integer,
        /// Owner identity column, used by the row-level-security view.
        owner_id -> Text,
        /// Binary order payload.
        payload -> Binary,
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn archive_carries_manifest_and_compressed_patchset_entries() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let replica_path = dir.path().join("replica.sqlite");
    let tier_path = dir.path().join("tier.sqlite");
    let replica_path_str = replica_path.to_str().expect("utf-8 path").to_owned();
    let tier_path_str = tier_path.to_str().expect("utf-8 path").to_owned();
    let replica = Replica::encrypted_file(
        &replica_path_str,
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("replica key")
    .with_tier(&tier_path_str, TIER_DDL);
    let mut conn = ConnettoConnection::<connetto_core::test_support::FakeTransport>::open(
        &replica,
        SYNCED_DDL,
        &ClientConfig::new("export-test".to_owned()),
        None,
    )
    .expect("open replica");

    diesel::insert_into(items::table)
        .values(&[
            (
                items::id.eq(1),
                items::label.eq("alpha"),
                items::payload.eq(vec![0u8, 1, 255]),
            ),
            (
                items::id.eq(2),
                items::label.eq("nul\0text"),
                items::payload.eq(vec![2u8, 3]),
            ),
        ])
        .execute(conn.conn())
        .expect("seed items");
    diesel::insert_into(drafts::table)
        .values(&[
            (drafts::id.eq(7), drafts::body.eq("draft")),
            (drafts::id.eq(8), drafts::body.eq("draft\0body")),
        ])
        .execute(conn.conn())
        .expect("seed drafts");

    let bytes = conn
        .export_local_data(ExportScope::Everything)
        .expect("export local data");

    // Encrypted replica files are not readable as plain SQLite.
    assert!(
        !std::fs::read(&replica_path)
            .expect("read replica file")
            .starts_with(SQLITE_MAGIC)
    );
    assert!(
        !std::fs::read(&tier_path)
            .expect("read tier file")
            .starts_with(SQLITE_MAGIC)
    );

    let mut archive = ZipArchive::new(Cursor::new(bytes)).expect("open zip");

    // Manifest carries format, version 2, scope, schema fingerprint, and account.
    let manifest: serde_json::Value =
        serde_json::from_slice(&zip_entry(&mut archive, "manifest.json")).expect("manifest json");
    assert_eq!(manifest["format"], "connetto-local-data");
    assert_eq!(manifest["version"], 2);
    assert_eq!(manifest["scope"], "everything");
    assert!(
        manifest["schema_fingerprint"].is_string(),
        "schema_fingerprint must be a string"
    );
    assert!(
        manifest.get("account").is_some(),
        "account must be present in the manifest"
    );

    // Entries are not SQLite databases: the magic must be absent.
    let synced_raw = zip_entry(&mut archive, "synced.patchset");
    let device_raw = zip_entry(&mut archive, "device-private.patchset");
    assert!(
        !synced_raw.starts_with(SQLITE_MAGIC),
        "synced.patchset must not be a SQLite database"
    );
    assert!(
        !device_raw.starts_with(SQLITE_MAGIC),
        "device-private.patchset must not be a SQLite database"
    );

    // Entries are zstd-compressed and parse as patchsets.
    let synced_bytes = zstd::decode_all(synced_raw.as_slice()).expect("decompress synced");
    let device_bytes = zstd::decode_all(device_raw.as_slice()).expect("decompress device-private");
    let synced = ParsedDiffSet::parse(&synced_bytes).expect("parse synced patchset");
    let device = ParsedDiffSet::parse(&device_bytes).expect("parse device-private patchset");
    assert!(synced.is_patchset(), "synced must be a patchset");
    assert!(device.is_patchset(), "device-private must be a patchset");

    // No connetto-internal or sqlite-internal tables appear in the patchsets.
    for schema in synced.table_schemas() {
        let name = schema.name();
        assert!(
            !name.starts_with("_connetto"),
            "internal table {name} must not appear in synced patchset"
        );
        assert!(
            !name.to_ascii_lowercase().starts_with("sqlite"),
            "sqlite table {name} must not appear in synced patchset"
        );
    }
    for schema in device.table_schemas() {
        let name = schema.name();
        assert!(
            !name.starts_with("_connetto"),
            "internal table {name} must not appear in device-private patchset"
        );
        assert!(
            !name.to_ascii_lowercase().starts_with("sqlite"),
            "sqlite table {name} must not appear in device-private patchset"
        );
    }

    // Binary values and text holding NUL survive in the patchset records.
    let item_rows: Vec<_> = patchset_inserts(&synced)
        .into_iter()
        .filter(|(t, _)| t == "items")
        .map(|(_, v)| v)
        .collect();
    assert!(
        item_rows
            .iter()
            .any(|row| row.contains(&Value::Blob(vec![0u8, 1, 255]))),
        "binary blob must survive in the synced patchset"
    );
    assert!(
        item_rows
            .iter()
            .any(|row| row.contains(&Value::Text("nul\0text".to_owned()))),
        "text with NUL must survive in the synced patchset"
    );

    let draft_rows: Vec<_> = patchset_inserts(&device)
        .into_iter()
        .filter(|(t, _)| t == "drafts")
        .map(|(_, v)| v)
        .collect();
    assert!(
        draft_rows
            .iter()
            .any(|row| row.contains(&Value::Text("draft\0body".to_owned()))),
        "text with NUL must survive in the device-private patchset"
    );
}

#[test]
fn everything_scope_carries_both_tiers_unsynced_omits_synced_replica() {
    let replica = Replica::in_memory().with_tier(TIER_DDL);
    let mut conn = ConnettoConnection::<connetto_core::test_support::FakeTransport>::open(
        &replica,
        SYNCED_DDL,
        &ClientConfig::new("scope-test".to_owned()),
        None,
    )
    .expect("open replica");

    diesel::insert_into(items::table)
        .values((
            items::id.eq(1),
            items::label.eq("row"),
            items::payload.eq(vec![1u8]),
        ))
        .execute(conn.conn())
        .expect("seed synced row");
    diesel::insert_into(drafts::table)
        .values((drafts::id.eq(1), drafts::body.eq("draft")))
        .execute(conn.conn())
        .expect("seed private row");

    // ExportScope::Everything carries both tiers.
    let bytes_all = conn
        .export_local_data(ExportScope::Everything)
        .expect("export everything");
    let mut arch_all = ZipArchive::new(Cursor::new(bytes_all)).expect("open zip");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&zip_entry(&mut arch_all, "manifest.json"))
            .expect("manifest")["scope"],
        "everything"
    );
    assert!(
        arch_all.by_name("synced.patchset").is_ok(),
        "synced.patchset must be present under everything"
    );
    assert!(
        arch_all.by_name("device-private.patchset").is_ok(),
        "device-private.patchset must be present under everything"
    );

    // ExportScope::Unsynced omits the synced replica but keeps the private tier.
    let bytes_unsynced = conn
        .export_local_data(ExportScope::Unsynced)
        .expect("export unsynced");
    let mut arch_unsynced = ZipArchive::new(Cursor::new(bytes_unsynced)).expect("open zip");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&zip_entry(
            &mut arch_unsynced,
            "manifest.json"
        ))
        .expect("manifest")["scope"],
        "unsynced"
    );
    assert!(
        arch_unsynced.by_name("synced.patchset").is_err(),
        "synced.patchset must be absent under unsynced"
    );
    assert!(
        arch_unsynced.by_name("device-private.patchset").is_ok(),
        "device-private.patchset must be present under unsynced"
    );
}

/// The export's own refusal, which R62 left in place as the backstop.
///
/// Its only route is now a table created after open, since a schema carrying
/// an unkeyed table no longer opens at all.
#[test]
fn table_without_primary_key_is_refused_by_name() {
    let replica = Replica::in_memory();
    let mut conn = ConnettoConnection::<connetto_core::test_support::FakeTransport>::open(
        &replica,
        "CREATE TABLE keyed (id INTEGER PRIMARY KEY);",
        &ClientConfig::new("nopk-test".to_owned()),
        None,
    )
    .expect("open replica");
    diesel::connection::SimpleConnection::batch_execute(
        &mut conn,
        "CREATE TABLE nokey (name TEXT NOT NULL)",
    )
    .expect("create it mid-run");
    let err = conn
        .export_local_data(ExportScope::Everything)
        .expect_err("must refuse a table without a primary key");
    let msg = format!("{err}");
    assert!(
        msg.contains("nokey"),
        "error must name the refused table: {msg}"
    );
}

#[test]
fn policy_split_table_rows_travel_in_the_synced_patchset() {
    let ddl = "
CREATE TABLE orders_rls (id INTEGER PRIMARY KEY, owner_id TEXT NOT NULL, payload BLOB NOT NULL) STRICT;
CREATE VIEW orders AS SELECT id, owner_id, payload FROM orders_rls WHERE owner_id = connetto_user();
CREATE INDEX orders_rls_owner_idx ON orders_rls(owner_id);
";
    let config = ClientConfig::new("export-rls".to_owned())
        .with_sql_functions(connetto_client::SqlFunctions::default())
        .with_policy_tables(PolicyTables::from_translation(
            [("orders", "orders_rls")],
            ["orders"],
        ))
        .with_caller("connetto_user", "alice".to_owned());
    let replica = Replica::in_memory();
    let mut conn = ConnettoConnection::<connetto_core::test_support::FakeTransport>::open(
        &replica, ddl, &config, None,
    )
    .expect("open split replica");

    diesel::insert_into(orders_rls::table)
        .values((
            orders_rls::id.eq(1),
            orders_rls::owner_id.eq("alice"),
            orders_rls::payload.eq(vec![0xaau8, 0xbb]),
        ))
        .execute(conn.conn())
        .expect("seed order row");

    let bytes = conn
        .export_local_data(ExportScope::Everything)
        .expect("export local data");
    let mut archive = ZipArchive::new(Cursor::new(bytes)).expect("open zip");
    let raw = zip_entry(&mut archive, "synced.patchset");
    let decompressed = zstd::decode_all(raw.as_slice()).expect("decompress synced");
    let patchset = ParsedDiffSet::parse(&decompressed).expect("parse patchset");

    // Rows travel under the physical backing name, not the view name.
    let names = patchset_table_names(&patchset);
    assert!(
        names.contains(&"orders_rls".to_owned()),
        "physical backing table orders_rls must appear in the synced patchset"
    );
    assert!(
        !names.contains(&"orders".to_owned()),
        "view orders must not appear as a table in the synced patchset"
    );

    let rows: Vec<_> = patchset_inserts(&patchset)
        .into_iter()
        .filter(|(t, _)| t == "orders_rls")
        .map(|(_, v)| v)
        .collect();
    assert!(
        !rows.is_empty(),
        "orders_rls must have rows in the patchset"
    );
    assert!(
        rows.iter()
            .any(|row| row.contains(&Value::Text("alice".to_owned()))),
        "owner_id must survive in the patchset row"
    );
    assert!(
        rows.iter()
            .any(|row| row.contains(&Value::Blob(vec![0xaau8, 0xbb]))),
        "payload must survive in the patchset row"
    );
}

fn zip_entry(archive: &mut ZipArchive<Cursor<Vec<u8>>>, name: &str) -> Vec<u8> {
    let mut entry = archive.by_name(name).expect("zip entry");
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).expect("read zip entry");
    bytes
}

fn patchset_table_names(patchset: &ParsedDiffSet) -> Vec<String> {
    patchset
        .table_schemas()
        .into_iter()
        .map(|s| s.name().clone())
        .collect()
}

/// One insert a record carries: the table it names and its row values.
type Insert = (String, Vec<Value<String, Vec<u8>>>);

fn patchset_inserts(patchset: &ParsedDiffSet) -> Vec<Insert> {
    let mut ops = Vec::new();
    if let ParsedDiffSet::Patchset(ds) = patchset {
        for op in ds.iter() {
            if let PatchsetOp::Insert { table, values, .. } = op {
                ops.push((table.name().clone(), values.to_vec()));
            }
        }
    }
    ops
}
