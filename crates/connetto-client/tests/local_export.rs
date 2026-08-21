//! Local data export contract tests.

use connetto_client::{ClientConfig, ConnettoConnection, PolicyTables, Replica};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use std::io::{Cursor, Read};
use zip::ZipArchive;

const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
const SYNCED_DDL: &str = "
CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT NOT NULL, payload BLOB NOT NULL) STRICT;
CREATE INDEX items_label_idx ON items(label);
";
const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT NOT NULL) STRICT;";

#[derive(diesel::QueryableByName, Debug, PartialEq, Eq)]
struct ItemRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    id: i32,
    #[diesel(sql_type = diesel::sql_types::Text)]
    label: String,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    payload: Vec<u8>,
}

#[derive(diesel::QueryableByName, Debug, PartialEq, Eq)]
struct DraftRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    id: i32,
    #[diesel(sql_type = diesel::sql_types::Text)]
    body: String,
}

#[derive(diesel::QueryableByName)]
struct NameRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}

#[derive(diesel::QueryableByName)]
struct SchemaKindRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    kind: String,
}

#[test]
fn local_export_is_a_plain_zip_with_synced_and_device_private_databases() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let replica_path = dir.path().join("replica.sqlite");
    let tier_path = dir.path().join("tier.sqlite");
    let replica_path = replica_path.to_str().expect("utf-8 path").to_owned();
    let tier_path = tier_path.to_str().expect("utf-8 path").to_owned();
    let replica = Replica::encrypted_file(
        &replica_path,
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("replica key")
    .with_tier(&tier_path, TIER_DDL);
    let mut conn = ConnettoConnection::<connetto_core::test_support::FakeTransport>::open(
        &replica,
        SYNCED_DDL,
        &ClientConfig::new("export-test".to_owned()),
        None,
    )
    .expect("open replica");

    conn.conn()
        .batch_execute(
            "CREATE INDEX connetto_local.drafts_body_idx ON drafts(body);
             INSERT INTO items (id, label, payload) VALUES (1, 'alpha', X'0001ff');
             INSERT INTO drafts (id, body) VALUES (7, 'draft');",
        )
        .expect("seed local rows");
    diesel::sql_query("INSERT INTO items (id, label, payload) VALUES (?, ?, ?)")
        .bind::<diesel::sql_types::Integer, _>(2)
        .bind::<diesel::sql_types::Text, _>("nul\0text")
        .bind::<diesel::sql_types::Binary, _>(vec![2, 3])
        .execute(conn.conn())
        .expect("seed text with nul");
    diesel::sql_query("INSERT INTO drafts (id, body) VALUES (?, ?)")
        .bind::<diesel::sql_types::Integer, _>(8)
        .bind::<diesel::sql_types::Text, _>("draft\0body")
        .execute(conn.conn())
        .expect("seed private text with nul");

    let bytes = conn.export_local_data().expect("export local data");
    assert!(
        !std::fs::read(&replica_path)
            .expect("read encrypted replica")
            .starts_with(SQLITE_MAGIC)
    );
    assert!(
        !std::fs::read(&tier_path)
            .expect("read encrypted tier")
            .starts_with(SQLITE_MAGIC)
    );

    let mut archive = ZipArchive::new(Cursor::new(bytes)).expect("open export archive");
    let manifest = zip_entry(&mut archive, "manifest.json");
    let manifest: serde_json::Value = serde_json::from_slice(&manifest).expect("manifest json");
    assert_eq!(manifest["format"], "connetto-local-data");
    assert_eq!(manifest["version"], 1);
    assert_eq!(manifest["databases"][0]["tier"], "synced");
    assert_eq!(manifest["databases"][1]["tier"], "device_private");

    let synced = zip_entry(&mut archive, "synced.sqlite");
    let device_private = zip_entry(&mut archive, "device-private.sqlite");
    assert!(synced.starts_with(SQLITE_MAGIC));
    assert!(device_private.starts_with(SQLITE_MAGIC));

    let mut synced = open_exported(&synced);
    let items = diesel::sql_query("SELECT id, label, payload FROM items ORDER BY id")
        .load::<ItemRow>(&mut synced)
        .expect("read exported synced rows");
    assert_eq!(
        items,
        vec![
            ItemRow {
                id: 1,
                label: "alpha".to_owned(),
                payload: vec![0, 1, 255],
            },
            ItemRow {
                id: 2,
                label: "nul\0text".to_owned(),
                payload: vec![2, 3],
            },
        ]
    );
    assert!(index_names(&mut synced, "items").contains(&"items_label_idx".to_owned()));
    assert!(internal_names(&mut synced).is_empty());

    let mut device_private = open_exported(&device_private);
    let drafts = diesel::sql_query("SELECT id, body FROM drafts ORDER BY id")
        .load::<DraftRow>(&mut device_private)
        .expect("read exported device-private rows");
    assert_eq!(
        drafts,
        vec![
            DraftRow {
                id: 7,
                body: "draft".to_owned(),
            },
            DraftRow {
                id: 8,
                body: "draft\0body".to_owned(),
            },
        ]
    );
    assert!(index_names(&mut device_private, "drafts").contains(&"drafts_body_idx".to_owned()));
    assert!(internal_names(&mut device_private).is_empty());
}

#[test]
fn local_export_materializes_split_policy_tables_under_logical_names() {
    let ddl = "
CREATE TABLE orders_rls (id INTEGER PRIMARY KEY, owner_id TEXT NOT NULL, payload BLOB NOT NULL) STRICT;
CREATE VIEW orders AS SELECT id, owner_id, payload FROM orders_rls WHERE owner_id = connetto_user();
CREATE INDEX orders_rls_owner_idx ON orders_rls(owner_id);
INSERT INTO orders_rls (id, owner_id, payload) VALUES (1, 'alice', X'aabb');
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

    let bytes = conn.export_local_data().expect("export local data");
    let mut archive = ZipArchive::new(Cursor::new(bytes)).expect("open export archive");
    let synced = zip_entry(&mut archive, "synced.sqlite");
    let mut synced = open_exported(&synced);

    let objects = object_names(&mut synced);
    assert!(objects.contains(&"orders".to_owned()));
    assert!(!objects.contains(&"orders_rls".to_owned()));
    assert_eq!(object_kind(&mut synced, "orders"), "table");
    assert!(index_names(&mut synced, "orders").contains(&"orders_rls_owner_idx".to_owned()));
    let rows = diesel::sql_query("SELECT id, owner_id AS label, payload FROM orders ORDER BY id")
        .load::<ItemRow>(&mut synced)
        .expect("read exported logical table");
    assert_eq!(
        rows,
        vec![ItemRow {
            id: 1,
            label: "alice".to_owned(),
            payload: vec![170, 187],
        }]
    );
}

fn zip_entry(archive: &mut ZipArchive<Cursor<Vec<u8>>>, name: &str) -> Vec<u8> {
    let mut entry = archive.by_name(name).expect("zip entry");
    let mut bytes = Vec::new();
    entry.read_to_end(&mut bytes).expect("read zip entry");
    bytes
}

fn open_exported(bytes: &[u8]) -> diesel::SqliteConnection {
    let mut conn = diesel::SqliteConnection::establish(":memory:").expect("open sqlite");
    conn.deserialize_readonly_database_from_buffer(bytes)
        .expect("deserialize sqlite");
    conn
}

fn index_names(conn: &mut diesel::SqliteConnection, table: &str) -> Vec<String> {
    diesel::sql_query(format!("SELECT name FROM pragma_index_list('{table}')"))
        .load::<NameRow>(conn)
        .expect("read index list")
        .into_iter()
        .map(|row| row.name)
        .collect()
}

fn internal_names(conn: &mut diesel::SqliteConnection) -> Vec<String> {
    diesel::sql_query("SELECT name FROM sqlite_schema WHERE name GLOB '_connetto*'")
        .load::<NameRow>(conn)
        .expect("read internal names")
        .into_iter()
        .map(|row| row.name)
        .collect()
}

fn object_names(conn: &mut diesel::SqliteConnection) -> Vec<String> {
    diesel::sql_query("SELECT name FROM sqlite_schema")
        .load::<NameRow>(conn)
        .expect("read object names")
        .into_iter()
        .map(|row| row.name)
        .collect()
}

fn object_kind(conn: &mut diesel::SqliteConnection, name: &str) -> String {
    diesel::sql_query(format!(
        "SELECT type AS kind FROM sqlite_schema WHERE name = '{name}'"
    ))
    .load::<SchemaKindRow>(conn)
    .expect("read object kind")
    .into_iter()
    .next()
    .expect("object exists")
    .kind
}
