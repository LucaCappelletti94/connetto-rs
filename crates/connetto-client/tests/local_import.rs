//! Local data import contract tests (R56).
//!
//! The phase's promise in one line: a person whose device died restores the
//! archive onto its replacement and finds both the data that never syncs and
//! the work they did offline. What the server already has is not restored, so
//! an offline write's rows arrive as the write itself, back in the queue the
//! next connection drains.
//!
//! Every refusal is proven by name, because a refusal a person cannot act on
//! is worse than none: a different schema, a different account, a queue longer
//! than the replica holds, and a table this build does not have.

use connetto_client::{
    ClientConfig, ClientError, ConnettoConnection, ExportScope, ImportChoices, Keep, Replica,
};
use connetto_core::test_support::FakeTransport;
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use sqlite_diff_rs::{ChangesetOp, ParsedDiffSet};

const SYNCED_DDL: &str =
    "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT NOT NULL, payload BLOB) STRICT;";
/// A second column, so an archive from this schema is refused by a build
/// running `SYNCED_DDL`.
const WIDER_SYNCED_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT NOT NULL, payload BLOB, note TEXT) STRICT;";
const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT NOT NULL) STRICT;";
/// A tier whose rows have children that a delete would cascade to, which is
/// the one thing restoring a row must not do. The tier accepts `CREATE TABLE`
/// only, so a trigger cannot live here, and the cascade is the reachable half.
const KEPT_TIER_DDL: &str = "\
CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT NOT NULL) STRICT; \
CREATE TABLE notes (id INTEGER PRIMARY KEY, draft INTEGER NOT NULL REFERENCES drafts(id) ON DELETE CASCADE, body TEXT NOT NULL) STRICT;";
/// A tier carrying a table the plain build does not have.
const WIDER_TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT NOT NULL) STRICT; \
                              CREATE TABLE scratch (id INTEGER PRIMARY KEY, note TEXT) STRICT;";

#[derive(diesel::QueryableByName, Debug, PartialEq, Eq)]
struct DraftRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    id: i32,
    #[diesel(sql_type = diesel::sql_types::Text)]
    body: String,
}

#[derive(diesel::QueryableByName, Debug, PartialEq, Eq)]
struct ItemRow {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    id: i32,
    #[diesel(sql_type = diesel::sql_types::Text)]
    label: String,
}

#[derive(diesel::QueryableByName)]
struct PendingRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    seq: i64,
    #[diesel(sql_type = diesel::sql_types::Binary)]
    changeset: Vec<u8>,
}

/// One device: an encrypted replica with a device-private tier beside it, and
/// no transport, so a push persists its record and then fails to send, which is
/// exactly what an offline write is.
struct Device {
    conn: ConnettoConnection<FakeTransport>,
    _dir: tempfile::TempDir,
}

fn device(synced_ddl: &str, tier_ddl: &str, account: &str) -> Device {
    let dir = tempfile::tempdir().expect("temporary directory");
    let replica_path = dir
        .path()
        .join("replica.sqlite")
        .to_str()
        .expect("utf-8 path")
        .to_owned();
    let tier_path = dir
        .path()
        .join("tier.sqlite")
        .to_str()
        .expect("utf-8 path")
        .to_owned();
    let replica = Replica::encrypted_file(
        &replica_path,
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("replica key")
    .with_tier(&tier_path, tier_ddl);
    let conn = ConnettoConnection::<FakeTransport>::open(
        &replica,
        synced_ddl,
        &ClientConfig::new("import-test".to_owned()).with_caller("current_app_user", account),
        None,
    )
    .expect("open replica");
    Device { conn, _dir: dir }
}

/// Make one write and queue it without a server to send it to. That pair, the
/// row applied locally and the changeset in the queue, is an offline write.
async fn write_offline(device: &mut Device, sql: &str) {
    device.conn.conn().batch_execute(sql).expect("local write");
    device.conn.push().await.expect("queue the write");
}

fn drafts(conn: &mut ConnettoConnection<FakeTransport>) -> Vec<DraftRow> {
    diesel::sql_query("SELECT id, body FROM drafts ORDER BY id")
        .load(conn.conn())
        .expect("read drafts")
}

fn items(conn: &mut ConnettoConnection<FakeTransport>) -> Vec<ItemRow> {
    diesel::sql_query("SELECT id, label FROM items ORDER BY id")
        .load(conn.conn())
        .expect("read items")
}

fn queued(conn: &mut ConnettoConnection<FakeTransport>) -> Vec<PendingRow> {
    diesel::sql_query("SELECT seq, changeset FROM _connetto_pending ORDER BY seq")
        .load(conn.conn())
        .expect("read the queue")
}

/// The phase's whole contract: a replica exported, destroyed, and restored onto
/// a fresh one of the same account and build ends in the state it would have
/// been in.
#[tokio::test]
async fn a_restored_replica_holds_the_device_only_rows_and_the_unsent_writes() {
    let mut source = device(SYNCED_DDL, TIER_DDL, "alice");
    // The device-only tier is outside the capture session, so seeding it
    // queues nothing: those rows travel as rows.
    source
        .conn
        .conn()
        .batch_execute("INSERT INTO drafts (id, body) VALUES (1, 'first'), (2, 'second')")
        .expect("seed the tier");
    // Four writes the server never saw, one of each shape that matters plus
    // the one that survives them.
    write_offline(
        &mut source,
        "INSERT INTO items (id, label) VALUES (10, 'made offline')",
    )
    .await;
    write_offline(
        &mut source,
        "INSERT INTO items (id, label) VALUES (11, 'also offline')",
    )
    .await;
    write_offline(
        &mut source,
        "UPDATE items SET label = 'edited offline' WHERE id = 10",
    )
    .await;
    write_offline(&mut source, "DELETE FROM items WHERE id = 10").await;
    let archive = source
        .conn
        .export_local_data(ExportScope::Everything)
        .expect("export");

    // The replacement device: same build, same account, nothing on it.
    let mut fresh = device(SYNCED_DDL, TIER_DDL, "alice");
    let plan = fresh.conn.import_local_data(&archive).expect("plan");
    assert_eq!(plan.device_only_rows(), 2);
    assert_eq!(
        plan.queued_writes(),
        4,
        "four writes never reached a server"
    );
    assert!(plan.collisions().is_empty(), "nothing to overwrite yet");
    let outcome = fresh
        .conn
        .apply_import(&plan, &ImportChoices::keeping_the_file())
        .expect("apply");
    assert_eq!(outcome.rows_restored, 2);
    assert_eq!(outcome.writes_restored, 4);

    assert_eq!(
        drafts(&mut fresh.conn),
        vec![
            DraftRow {
                id: 1,
                body: "first".to_owned()
            },
            DraftRow {
                id: 2,
                body: "second".to_owned()
            },
        ],
        "the data that never syncs came back",
    );
    assert_eq!(
        items(&mut fresh.conn),
        vec![ItemRow {
            id: 11,
            label: "also offline".to_owned()
        }],
        "the offline writes replay locally in order, so the deleted row is gone and the other stands",
    );

    // The queue is back, in order, numbered above this replica's own, and the
    // offline delete is in it: that is the case a row-values format could not
    // express at all.
    let queue = queued(&mut fresh.conn);
    assert_eq!(queue.len(), 4);
    assert!(
        queue.windows(2).all(|pair| pair[0].seq < pair[1].seq),
        "the restored writes keep their order",
    );
    let deletes = queue
        .iter()
        .filter(|record| {
            let Ok(ParsedDiffSet::Changeset(set)) = ParsedDiffSet::parse(&record.changeset) else {
                return false;
            };
            set.iter()
                .any(|op| matches!(op, ChangesetOp::Delete { .. }))
        })
        .count();
    assert_eq!(deletes, 1, "the offline delete travelled as a delete");
}

/// The file wins, but never silently: the clash is in the plan before anything
/// is written, and the answer given is the one honoured.
#[tokio::test]
async fn a_clashing_row_is_reported_with_both_versions_and_the_answer_is_honoured() {
    let mut source = device(SYNCED_DDL, TIER_DDL, "alice");
    source
        .conn
        .conn()
        .batch_execute("INSERT INTO drafts (id, body) VALUES (7, 'the file version')")
        .expect("seed");
    let archive = source
        .conn
        .export_local_data(ExportScope::Unsynced)
        .expect("export");

    let mut mine = device(SYNCED_DDL, TIER_DDL, "alice");
    mine.conn
        .conn()
        .batch_execute("INSERT INTO drafts (id, body) VALUES (7, 'my version')")
        .expect("seed");

    let plan = mine.conn.import_local_data(&archive).expect("plan");
    let [clash] = plan.collisions() else {
        panic!(
            "expected exactly one clash, got {}",
            plan.collisions().len()
        );
    };
    assert_eq!(clash.table, "drafts");
    let differences = clash.differences();
    let [difference] = differences.as_slice() else {
        panic!("expected one differing column");
    };
    assert_eq!(difference.column, "body");
    assert_eq!(
        difference.mine,
        sqlite_diff_rs::Value::Text("my version".to_owned())
    );
    assert_eq!(
        difference.theirs,
        sqlite_diff_rs::Value::Text("the file version".to_owned())
    );

    // Keeping mine leaves the row alone.
    let outcome = mine
        .conn
        .apply_import(&plan, &ImportChoices::keeping_mine())
        .expect("apply");
    assert_eq!(outcome.rows_kept, 1);
    assert_eq!(outcome.rows_restored, 0);
    assert_eq!(drafts(&mut mine.conn)[0].body, "my version");

    // Answering the same clash the other way takes the file's.
    let plan = mine.conn.import_local_data(&archive).expect("plan again");
    let outcome = mine
        .conn
        .apply_import(&plan, &ImportChoices::keeping_mine().keep(0, Keep::TheFile))
        .expect("apply");
    assert_eq!(outcome.rows_restored, 1);
    assert_eq!(drafts(&mut mine.conn)[0].body, "the file version");
}

/// An archive made under another schema is refused, and the message says so.
#[tokio::test]
async fn a_mismatched_schema_is_refused_by_name() {
    let mut source = device(WIDER_SYNCED_DDL, TIER_DDL, "alice");
    let archive = source
        .conn
        .export_local_data(ExportScope::Everything)
        .expect("export");
    let mut target = device(SYNCED_DDL, TIER_DDL, "alice");
    match target.conn.import_local_data(&archive) {
        Err(ClientError::Import(message)) => assert!(
            message.contains("different schema"),
            "the refusal names the schema: {message}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// An archive belonging to another account is refused: an offline write carries
/// its writer's own owner value, so it could never be saved here anyway.
#[tokio::test]
async fn another_accounts_archive_is_refused_by_name() {
    let mut source = device(SYNCED_DDL, TIER_DDL, "alice");
    let archive = source
        .conn
        .export_local_data(ExportScope::Everything)
        .expect("export");
    let mut target = device(SYNCED_DDL, TIER_DDL, "bob");
    match target.conn.import_local_data(&archive) {
        Err(ClientError::Import(message)) => assert!(
            message.contains("another account"),
            "the refusal names the account: {message}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A tier carrying a table this build does not have is refused, and the schema
/// check is what catches it: a differing table set is a differing schema. The
/// table check behind it is proven in the crate's own tests, since no honest
/// export of this build can reach it.
#[tokio::test]
async fn a_tier_with_an_extra_table_is_refused() {
    let mut source = device(SYNCED_DDL, WIDER_TIER_DDL, "alice");
    source
        .conn
        .conn()
        .batch_execute("INSERT INTO scratch (id, note) VALUES (1, 'only here')")
        .expect("seed");
    let archive = source
        .conn
        .export_local_data(ExportScope::Unsynced)
        .expect("export");
    let mut target = device(SYNCED_DDL, TIER_DDL, "alice");
    match target.conn.import_local_data(&archive) {
        Err(ClientError::Import(message)) => assert!(
            message.contains("different schema"),
            "the refusal names the schema: {message}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The queue travels whole, and the cap is what bounds it at both ends: a
/// source device evicts its oldest record past the cap, so an honest archive
/// can never carry more than a replica holds. The refusal for one that does is
/// proven in the crate's own tests.
#[tokio::test]
async fn a_full_queue_travels_whole() {
    let mut source = device(SYNCED_DDL, TIER_DDL, "alice");
    for id in 0..8 {
        write_offline(
            &mut source,
            &format!("INSERT INTO items (id, label) VALUES ({id}, 'offline')"),
        )
        .await;
    }
    let archive = source
        .conn
        .export_local_data(ExportScope::Unsynced)
        .expect("export");
    let mut target = device(SYNCED_DDL, TIER_DDL, "alice");
    let plan = target.conn.import_local_data(&archive).expect("plan");
    assert_eq!(plan.queued_writes(), 8);
    let outcome = target
        .conn
        .apply_import(&plan, &ImportChoices::keeping_the_file())
        .expect("apply");
    assert_eq!(outcome.writes_restored, 8);
    assert_eq!(queued(&mut target.conn).len(), 8);
}

/// Restoring a clashing row updates it rather than replacing it.
///
/// `INSERT OR REPLACE` would delete the row first, which with foreign keys
/// enforced takes its children with it. A restore that destroys rows nobody
/// asked about is the shape this phase exists to avoid, so the write is an
/// upsert.
#[tokio::test]
async fn restoring_a_clashing_row_updates_it_rather_than_replacing_it() {
    let mut source = device(SYNCED_DDL, KEPT_TIER_DDL, "alice");
    source
        .conn
        .conn()
        .batch_execute("INSERT INTO drafts (id, body) VALUES (7, 'the file version')")
        .expect("seed the source");
    let archive = source
        .conn
        .export_local_data(ExportScope::Unsynced)
        .expect("export");

    let mut target = device(SYNCED_DDL, KEPT_TIER_DDL, "alice");
    target
        .conn
        .conn()
        .batch_execute(
            "PRAGMA foreign_keys = ON;
             INSERT INTO drafts (id, body) VALUES (7, 'my version');
             INSERT INTO notes (id, draft, body) VALUES (1, 7, 'a child of the draft');",
        )
        .expect("seed the target");

    let plan = target.conn.import_local_data(&archive).expect("plan");
    assert_eq!(plan.collisions().len(), 1);
    target
        .conn
        .apply_import(&plan, &ImportChoices::keeping_the_file())
        .expect("apply");

    assert_eq!(
        drafts(&mut target.conn)[0].body,
        "the file version",
        "the file's version won"
    );
    let children: Vec<Count> = diesel::sql_query("SELECT count(*) AS rows FROM notes")
        .load(target.conn.conn())
        .expect("count children");
    assert_eq!(children[0].rows, 1, "the child row survived the restore");
}

#[derive(diesel::QueryableByName)]
struct Count {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    rows: i64,
}
