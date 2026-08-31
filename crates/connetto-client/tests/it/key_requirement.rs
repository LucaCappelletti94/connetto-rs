//! R62: connetto records nothing for a table whose only key is the implicit
//! `rowid`, so it refuses one unless the application accepted the loss.
//!
//! The first test here is the finding rather than the fix: it writes a row to
//! an unkeyed table the application accepted and shows the capture session
//! hands back nothing, which is why the refusals below exist. Before the fix
//! the same test ran without the acceptance and passed, because
//! `CREATE TABLE prefs (name TEXT, value TEXT)` is a keyed table by SQLite's
//! rules, so nothing warned the developer and the write was never uploaded.

use connetto_client::{ClientConfig, ClientError, ConnettoConnection, Replica, ReplicaKey};
use connetto_core::test_support::FakeTransport;
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use tempfile::tempdir;

/// A synced schema whose second table declares no key.
const MIXED_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT); \
     CREATE TABLE prefs (name TEXT, value TEXT)";

/// One keyed table, so a test can create its own tables afterwards.
const KEYED_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

fn config() -> ClientConfig {
    ClientConfig::new("r62")
}

fn key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x62; ReplicaKey::LEN])
}

/// One `count(*)` from the replica's own catalogue.
#[derive(diesel::QueryableByName)]
struct Counted {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    rows_found: i64,
}

/// The refused names, or a panic naming what came back instead. Takes the
/// whole result, since a connection is not `Debug` and `expect_err` needs it.
fn refused<T>(result: Result<T, ClientError>) -> Vec<String> {
    match result {
        Err(ClientError::WritesNotRecorded { tables }) => tables,
        Err(other) => panic!("expected a key-requirement refusal, got {other}"),
        Ok(_) => panic!("expected a refusal, got success"),
    }
}

/// The finding: a write to an unkeyed table is captured by nothing, so the
/// upload carries no trace of it, while the keyed table beside it travels.
///
/// This is the consented behaviour once the table is accepted, and it was the
/// silent one before this phase.
#[tokio::test]
async fn a_write_to_an_accepted_table_is_captured_by_nothing() {
    let mut conn = ConnettoConnection::<FakeTransport>::open(
        &Replica::in_memory(),
        MIXED_DDL,
        &config().with_unrecorded_tables(["prefs"]),
        None,
    )
    .expect("open the replica");

    conn.batch_execute("INSERT INTO prefs (name, value) VALUES ('theme', 'dark')")
        .expect("the write itself succeeds");
    assert_eq!(
        conn.push().await.expect("push"),
        None,
        "the session recorded nothing, so there is no mutation to send"
    );

    conn.batch_execute("INSERT INTO items (id, label) VALUES (1, 'kept')")
        .expect("write a keyed row");
    assert_eq!(
        conn.push().await.expect("push"),
        Some(0),
        "the keyed table records and uploads"
    );
}

/// The same schema without the acceptance never opens, and the refusal says
/// which table and what to write.
#[test]
fn a_rowid_only_table_is_refused_at_open() {
    let tables = refused(ConnettoConnection::<FakeTransport>::open(
        &Replica::in_memory(),
        MIXED_DDL,
        &config(),
        None,
    ));
    assert_eq!(tables.len(), 1, "only the unkeyed table: {tables:?}");
    let refusal = &tables[0];
    assert!(refusal.contains("prefs"), "names the table: {refusal}");
    assert!(refusal.contains("PRIMARY KEY"), "names the fix: {refusal}");
}

/// `UNIQUE(a, b)` satisfies a reader and not the recorder, so it is refused
/// too. This is the case a developer is most likely to think is covered.
#[test]
fn a_unique_constraint_without_a_primary_key_is_refused() {
    let tables = refused(ConnettoConnection::<FakeTransport>::open(
        &Replica::in_memory(),
        "CREATE TABLE pairs (a TEXT, b TEXT, UNIQUE(a, b))",
        &config(),
        None,
    ));
    assert!(
        tables.iter().any(|refusal| refusal.contains("pairs")),
        "names the table: {tables:?}"
    );
}

/// The capture session covers tables created after it exists, so a table
/// created mid-run is caught at the next write rather than at the next
/// restart, which is where the loss would otherwise be unbounded.
#[tokio::test]
async fn a_table_created_after_open_is_caught_at_the_next_write() {
    let mut conn = ConnettoConnection::<FakeTransport>::open(
        &Replica::in_memory(),
        KEYED_DDL,
        &config(),
        None,
    )
    .expect("open the replica");
    conn.batch_execute("CREATE TABLE later (body TEXT)")
        .expect("the application creates its own table");
    conn.batch_execute("INSERT INTO later (body) VALUES ('lost')")
        .expect("and writes to it");

    let tables = refused(conn.push().await);
    assert!(
        tables.iter().any(|refusal| refusal.contains("later")),
        "names the table created mid-run: {tables:?}"
    );
}

/// `ANALYZE` creates `sqlite_stat1`, which declares no primary key and moves
/// the schema cookie, so the write path meets it. It is SQLite's own table
/// rather than the application's, and skipping it is what keeps a replica
/// that was ever analysed writable.
#[tokio::test]
async fn sqlites_own_statistics_table_is_not_the_applications() {
    let mut conn = ConnettoConnection::<FakeTransport>::open(
        &Replica::in_memory(),
        "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT); \
         CREATE INDEX items_label ON items (label)",
        &config(),
        None,
    )
    .expect("open the replica");
    conn.batch_execute("INSERT INTO items (id, label) VALUES (1, 'kept'); ANALYZE")
        .expect("analyse the replica");
    let counted: Vec<Counted> = diesel::sql_query(
        "SELECT count(*) AS rows_found FROM sqlite_schema WHERE name = 'sqlite_stat1'",
    )
    .load(conn.conn())
    .expect("read the catalogue");
    assert_eq!(
        counted.first().map(|row| row.rows_found),
        Some(1),
        "ANALYZE really created the table"
    );

    assert_eq!(
        conn.push().await.expect("the statistics table is skipped"),
        Some(0),
        "the write travels"
    );
}

/// A write refused over a device-private table says so, because nothing in
/// that tier ever uploads and the message would otherwise read as an upload
/// failure (decision 4).
#[tokio::test]
async fn a_tier_table_created_after_open_is_caught_at_the_next_write() {
    let dir = tempdir().expect("temp dir");
    let replica_path = dir.path().join("replica.db");
    let tier_path = dir.path().join("tier.db");
    let replica = Replica::encrypted_file(replica_path.to_str().expect("utf-8"), Some(key()))
        .expect("replica")
        .with_tier(
            tier_path.to_str().expect("utf-8"),
            "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)",
        );
    let mut conn = ConnettoConnection::<FakeTransport>::open(&replica, KEYED_DDL, &config(), None)
        .expect("open the replica");
    conn.batch_execute("CREATE TABLE connetto_local.scratch (body TEXT)")
        .expect("the application creates a device-private table");

    let tables = refused(conn.push().await);
    assert_eq!(tables.len(), 1, "one refusal: {tables:?}");
    let refusal = &tables[0];
    assert!(refusal.contains("scratch"), "names the table: {refusal}");
    assert!(
        refusal.contains("device-private"),
        "says which database it is in: {refusal}"
    );
}

/// The tier is checked when connetto creates it, because a tab reads a tier
/// table through a session diff and an unkeyed one delivers nothing.
#[test]
fn an_unkeyed_tier_table_is_refused_on_the_create_path() {
    let tables = refused(ConnettoConnection::<FakeTransport>::open(
        &Replica::in_memory().with_tier("CREATE TABLE scratch (body TEXT)"),
        KEYED_DDL,
        &config(),
        None,
    ));
    assert!(
        tables.iter().any(|refusal| refusal.contains("scratch")),
        "names the tier table: {tables:?}"
    );
}

/// And when it attaches one a previous run created, which is every run after
/// the first.
#[test]
fn an_unkeyed_tier_table_is_refused_on_the_existing_path() {
    let dir = tempdir().expect("temp dir");
    let replica_path = dir.path().join("replica.db");
    let tier_path = dir.path().join("tier.db");
    let path = replica_path.to_str().expect("utf-8");
    let tier = tier_path.to_str().expect("utf-8");
    // The tier is created with the table accepted, which is the only way one
    // gets written at all, and then reopened without the acceptance.
    drop(
        ConnettoConnection::<FakeTransport>::open(
            &Replica::encrypted_file(path, Some(key()))
                .expect("replica")
                .with_tier(tier, "CREATE TABLE scratch (body TEXT)"),
            KEYED_DDL,
            &config().with_unrecorded_tables(["scratch"]),
            None,
        )
        .expect("the accepted tier opens"),
    );

    let tables = refused(ConnettoConnection::<FakeTransport>::open_existing(
        &Replica::encrypted_file(path, Some(key()))
            .expect("replica")
            .with_existing_tier(tier),
        &config(),
        None,
    ));
    assert!(
        tables.iter().any(|refusal| refusal.contains("scratch")),
        "names the tier table: {tables:?}"
    );
}

/// The acceptance means "this table is not recorded", so accepting one that
/// declares a key is a contradiction rather than a harmless extra name: the
/// table would sync while the application believed it did not.
#[test]
fn an_accepted_table_that_declares_a_key_is_refused() {
    let tables = refused(ConnettoConnection::<FakeTransport>::open(
        &Replica::in_memory(),
        KEYED_DDL,
        &config().with_unrecorded_tables(["items"]),
        None,
    ));
    assert_eq!(tables.len(), 1, "one refusal: {tables:?}");
    let refusal = &tables[0];
    assert!(refusal.contains("items"), "names the table: {refusal}");
    assert!(
        refusal.contains("declares a primary key"),
        "names the contradiction: {refusal}"
    );
}

/// A name that matches nothing is harmless, because the real table it was
/// meant to name is still refused, which is loud.
#[test]
fn an_acceptance_that_matches_nothing_is_harmless() {
    ConnettoConnection::<FakeTransport>::open(
        &Replica::in_memory(),
        KEYED_DDL,
        &config().with_unrecorded_tables(["prefrences"]),
        None,
    )
    .expect("a typo changes nothing about a keyed schema");
}

/// The export skips an accepted table rather than refusing it, since its rows
/// cannot travel and the application said so. The export's own refusal for an
/// unaccepted table is `local_export.rs`.
#[test]
fn the_export_skips_an_accepted_table() {
    let mut conn = ConnettoConnection::<FakeTransport>::open(
        &Replica::in_memory(),
        MIXED_DDL,
        &config().with_unrecorded_tables(["prefs"]),
        None,
    )
    .expect("open the replica");
    conn.batch_execute("INSERT INTO prefs (name, value) VALUES ('theme', 'dark')")
        .expect("write an accepted row");
    conn.export_local_data(connetto_client::ExportScope::Everything)
        .expect("the accepted table is skipped rather than refused");
}
