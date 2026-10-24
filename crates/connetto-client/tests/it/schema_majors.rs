//! R31: a durable replica records the application schema major and bundle
//! hash it was built under, refuses a build it cannot serve, and rebuilds in
//! place when the build is a newer major, keeping the older major's unsent
//! writes in their writers' queues under the major they were captured in.
//!
//! Native and offline. Every case opens a real encrypted replica file twice,
//! once per build, because the property under test is what the second open
//! finds on disk.

use connetto_client::{
    ClientBuilder, ClientError, ConnettoConnection, DataDir, MemoryRefreshStore, SyncSchema,
    UnsyncedWrite,
};
use connetto_core::chain::{GENESIS, entry_hash};
use connetto_core::messages::WriterRef;
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_core::{MAJOR_DIRECTIVE, Major};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use sqlite_diff_rs::ParsedDiffSet;
use tempfile::{TempDir, tempdir};

const V1_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const V2_DDL: &str =
    "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT, rank INTEGER NOT NULL DEFAULT 0)";

diesel::table! {
    /// The synced table at major 1.
    items (id) {
        /// Item identifier, the primary key.
        id -> Integer,
        /// Optional item label.
        label -> Nullable<Text>,
    }
}

diesel::table! {
    /// The one-row record of the build a replica was made under.
    #[sql_name = "_connetto_build"]
    connetto_build (id) {
        /// Always 1.
        id -> Integer,
        /// The bundle hash.
        version -> Binary,
    }
}

diesel::table! {
    /// The client's pending queue, read by the assertions.
    #[sql_name = "_connetto_pending"]
    pending (writer, seq) {
        /// The writer the entry is queued under.
        writer -> Text,
        /// Its sequence in that writer's queue.
        seq -> BigInt,
        /// The stored changeset.
        changeset -> Binary,
        /// Its chain hash.
        entry_hash -> Binary,
        /// The major it was captured under.
        major -> Nullable<BigInt>,
    }
}

/// The split schema, whose view `t` writes through its backing table.
const SPLIT_DDL: &str = "CREATE TABLE physical_t (id INTEGER PRIMARY KEY); \
    CREATE VIEW t AS SELECT * FROM physical_t; \
    CREATE TRIGGER t_insert INSTEAD OF INSERT ON t \
    BEGIN INSERT INTO physical_t (id) VALUES (NEW.id); END;";

/// The split schema at `major`, the view `t` over `physical_t`.
fn split_schema(major: u32) -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            format!("{MAJOR_DIRECTIVE} {major}\n-- split"),
            "",
            format!("{SPLIT_DDL} {V1_DDL};"),
            vec![("t".to_owned(), "physical_t".to_owned())],
            vec!["t".to_owned()],
            None::<&str>,
        )
        .expect("the source declares its major"),
    )
}

/// One queued entry's stored bytes, chain hash and capture major.
#[derive(Queryable, Debug)]
struct QueuedRow {
    changeset: Vec<u8>,
    entry_hash: Vec<u8>,
    major: Option<i64>,
}

/// One `user_version` reading, which no `table!` can name.
#[derive(QueryableByName)]
struct UserVersion {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    user_version: i32,
}

/// One column name from `PRAGMA table_info`.
#[derive(QueryableByName)]
struct Column {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}

fn schema(major: u32, ddl: &str) -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            format!("{MAJOR_DIRECTIVE} {major}\n-- {ddl}"),
            "",
            ddl,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )
        .expect("the source declares its major"),
    )
}

async fn open(
    dir: &TempDir,
    schema: SyncSchema,
) -> Result<ConnettoConnection<FakeTransport>, ClientError> {
    let credential = super::support::held("tester");
    let store = super::support::key_store(&credential).await;
    ClientBuilder::new(
        schema,
        super::support::NeverDial::<FakeTransport>::default(),
    )
    .signed_in(credential)
    .durable(
        DataDir::new(dir.path().to_path_buf()),
        store,
        MemoryRefreshStore::default(),
    )
    .open_driven()
    .await
}

fn user_version(conn: &mut ConnettoConnection<FakeTransport>) -> i32 {
    // A vendor pragma, which the typed DSL cannot express.
    diesel::sql_query("PRAGMA main.user_version")
        .get_result::<UserVersion>(conn.conn())
        .expect("read user_version")
        .user_version
}

fn recorded_version(conn: &mut ConnettoConnection<FakeTransport>) -> Vec<u8> {
    connetto_build::table
        .select(connetto_build::version)
        .first(conn.conn())
        .expect("read the build record")
}

#[tokio::test]
async fn a_fresh_replica_records_the_build_major_and_hash() {
    let dir = tempdir().expect("temp dir");
    let built = schema(3, V1_DDL);
    let mut conn = open(&dir, built.clone()).await.expect("fresh open");
    assert_eq!(user_version(&mut conn), 3);
    assert_eq!(recorded_version(&mut conn), built.version().hash());
}

#[tokio::test]
async fn the_same_build_reopens_its_replica() {
    let dir = tempdir().expect("temp dir");
    drop(open(&dir, schema(1, V1_DDL)).await.expect("fresh open"));
    let mut conn = open(&dir, schema(1, V1_DDL)).await.expect("reopen");
    assert_eq!(user_version(&mut conn), 1);
}

#[tokio::test]
async fn the_same_major_from_another_schema_is_refused() {
    let dir = tempdir().expect("temp dir");
    let first = schema(1, V1_DDL);
    drop(open(&dir, first.clone()).await.expect("fresh open"));
    let changed = schema(1, V2_DDL);
    match open(&dir, changed.clone()).await {
        Err(ClientError::ReplicaSchemaChanged {
            major,
            recorded,
            build,
        }) => {
            assert_eq!(major, Major::new(1).expect("one is a major"));
            assert_eq!(recorded, first.version());
            assert_eq!(build, changed.version());
        }
        Err(other) => panic!("expected ReplicaSchemaChanged, got {other:?}"),
        Ok(_) => panic!("a changed schema at the same major opened the old replica"),
    }
}

#[tokio::test]
async fn an_older_build_refuses_a_newer_replica() {
    let dir = tempdir().expect("temp dir");
    drop(open(&dir, schema(2, V2_DDL)).await.expect("fresh open"));
    match open(&dir, schema(1, V1_DDL)).await {
        Err(ClientError::ReplicaNewer { recorded, build }) => {
            assert_eq!(recorded, Major::new(2).expect("two is a major"));
            assert_eq!(build, Major::new(1).expect("one is a major"));
        }
        Err(other) => panic!("expected ReplicaNewer, got {other:?}"),
        Ok(_) => panic!("an older build opened a newer replica"),
    }
}

#[tokio::test]
async fn a_replica_from_before_majors_is_stamped_with_the_build() {
    let dir = tempdir().expect("temp dir");
    let built = schema(1, V1_DDL);
    {
        let mut conn = open(&dir, built.clone()).await.expect("fresh open");
        conn.conn()
            .batch_execute("PRAGMA main.user_version = 0; DROP TABLE _connetto_build;")
            .expect("strip the record a pre-R31 replica never had");
    }
    let mut conn = open(&dir, built.clone()).await.expect("reopen");
    assert_eq!(user_version(&mut conn), 1);
    assert_eq!(recorded_version(&mut conn), built.version().hash());
}

#[tokio::test]
async fn a_recorded_major_without_its_build_hash_is_refused() {
    for remove in ["DROP TABLE _connetto_build", "DELETE FROM _connetto_build"] {
        let dir = tempdir().expect("temp dir");
        {
            let mut conn = open(&dir, schema(1, V1_DDL)).await.expect("fresh open");
            conn.conn().batch_execute(remove).expect("remove the hash");
        }
        match open(&dir, schema(1, V1_DDL)).await {
            Err(ClientError::ReplicaRecordMissing { recorded }) => {
                assert_eq!(recorded, Major::new(1).expect("one is a major"));
            }
            Err(other) => panic!("expected ReplicaRecordMissing, got {other:?}"),
            Ok(_) => panic!("a recorded major opened without its build hash"),
        }
    }
}

#[tokio::test]
async fn an_idle_replica_rebuilds_and_queues_writes_under_the_active_major() {
    let dir = tempdir().expect("temp dir");
    drop(open(&dir, schema(1, V1_DDL)).await.expect("fresh open"));
    let built = schema(2, V2_DDL);
    let mut conn = open(&dir, built.clone()).await.expect("rebuild");
    assert_eq!(user_version(&mut conn), 2);
    assert_eq!(recorded_version(&mut conn), built.version().hash());
    diesel::insert_into(items::table)
        .values((items::id.eq(1), items::label.eq("active")))
        .execute(conn.conn())
        .expect("write under the active major");
    assert_eq!(conn.push().await.expect("queue"), Some(1));
    assert_eq!(
        conn.unsynced(),
        vec![UnsyncedWrite {
            writer: WriterRef::Number(0),
            seq: 1,
            major: Major::new(2),
        }]
    );
}

#[tokio::test]
async fn a_replica_without_split_metadata_preserves_its_queued_wire_bytes() {
    let dir = tempdir().expect("temp dir");
    let expected: (Vec<u8>, Vec<u8>) = {
        let mut conn = open(&dir, schema(1, V1_DDL)).await.expect("fresh open");
        diesel::insert_into(items::table)
            .values((items::id.eq(1), items::label.eq("held")))
            .execute(conn.conn())
            .expect("write offline");
        assert_eq!(conn.push().await.expect("queue"), Some(1));
        conn.conn()
            .batch_execute("DROP TABLE _connetto_build_renames")
            .expect("remove split metadata");
        pending::table
            .select((pending::changeset, pending::entry_hash))
            .first(conn.conn())
            .expect("read the queued bytes")
    };
    let mut conn = open(&dir, schema(2, V2_DDL)).await.expect("rebuild");
    assert_eq!(user_version(&mut conn), 2);
    let actual: (Vec<u8>, Vec<u8>) = pending::table
        .select((pending::changeset, pending::entry_hash))
        .first(conn.conn())
        .expect("read the held bytes");
    assert_eq!(actual, expected);
    assert_eq!(
        conn.unsynced(),
        vec![UnsyncedWrite {
            writer: WriterRef::Number(0),
            seq: 1,
            major: Major::new(1),
        }]
    );
}

#[tokio::test]
async fn a_failed_rebuild_preserves_the_schema_record_rows_and_queue() {
    let dir = tempdir().expect("temp dir");
    let first = schema(1, V1_DDL);
    let expected: (Vec<u8>, Vec<u8>) = {
        let mut conn = open(&dir, first.clone()).await.expect("fresh open");
        diesel::insert_into(items::table)
            .values((items::id.eq(1), items::label.eq("retained")))
            .execute(conn.conn())
            .expect("write offline");
        assert_eq!(conn.push().await.expect("queue"), Some(1));
        pending::table
            .select((pending::changeset, pending::entry_hash))
            .first(conn.conn())
            .expect("read the queued bytes")
    };
    let broken = schema(2, &format!("{V2_DDL}; {V2_DDL}"));
    assert!(matches!(open(&dir, broken).await, Err(ClientError::Db(_))));
    let mut conn = open(&dir, first.clone())
        .await
        .expect("reopen the original build");
    assert_eq!(user_version(&mut conn), 1);
    assert_eq!(recorded_version(&mut conn), first.version().hash());
    assert_eq!(
        items::table
            .select(items::label)
            .first::<Option<String>>(conn.conn())
            .expect("read the retained row")
            .as_deref(),
        Some("retained")
    );
    let actual: (Vec<u8>, Vec<u8>) = pending::table
        .select((pending::changeset, pending::entry_hash))
        .first(conn.conn())
        .expect("read the retained queue");
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn a_newer_major_rebuilds_the_replica_in_place_and_keeps_unsent_writes_under_their_major() {
    let dir = tempdir().expect("temp dir");
    let first = schema(1, V1_DDL);
    let seq = {
        let mut conn = open(&dir, first.clone()).await.expect("fresh open");
        diesel::insert_into(items::table)
            .values((items::id.eq(1), items::label.eq("unsent")))
            .execute(conn.conn())
            .expect("write offline");
        conn.push().await.expect("queue").expect("a seq")
    };

    let second = schema(2, V2_DDL);
    let mut conn = open(&dir, second.clone())
        .await
        .expect("open the newer build");

    assert_eq!(user_version(&mut conn), 2);
    assert_eq!(recorded_version(&mut conn), second.version().hash());
    // A vendor pragma, which the typed DSL cannot express.
    let columns: Vec<Column> = diesel::sql_query("PRAGMA main.table_info(items)")
        .load(conn.conn())
        .expect("read the rebuilt table");
    assert_eq!(
        columns.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ["id", "label", "rank"],
        "the synced table now has the build's shape"
    );
    let rows: i64 = items::table
        .count()
        .get_result(conn.conn())
        .expect("count the rebuilt table");
    assert_eq!(
        rows, 0,
        "synced rows come back from the new major's snapshot"
    );
    assert_eq!(
        conn.unsynced(),
        vec![UnsyncedWrite {
            writer: WriterRef::Number(0),
            seq,
            major: Major::new(1),
        }],
        "the write stays queued under its writer and the major it was captured in"
    );
}

#[tokio::test]
async fn a_write_after_the_rebuild_chains_after_the_older_majors_entry() {
    let dir = tempdir().expect("temp dir");
    let first_seq = {
        let mut conn = open(&dir, schema(1, V1_DDL)).await.expect("fresh open");
        diesel::insert_into(items::table)
            .values((items::id.eq(1), items::label.eq("before")))
            .execute(conn.conn())
            .expect("write offline");
        conn.push().await.expect("queue").expect("a seq")
    };

    let mut conn = open(&dir, schema(2, V2_DDL))
        .await
        .expect("open the newer build");
    diesel::insert_into(items::table)
        .values((items::id.eq(2), items::label.eq("after")))
        .execute(conn.conn())
        .expect("write after the rebuild");
    let second_seq = conn.push().await.expect("queue").expect("a seq");
    assert_eq!(
        second_seq,
        first_seq + 1,
        "the writer's sequence continues across the rebuild"
    );

    let rows: Vec<QueuedRow> = pending::table
        .select((pending::changeset, pending::entry_hash, pending::major))
        .order(pending::seq)
        .load(conn.conn())
        .expect("read the queue");
    let [first, second] = rows.as_slice() else {
        panic!("expected two queued entries, found {rows:?}");
    };
    assert_eq!(
        (first.major, second.major),
        (Some(1), Some(2)),
        "each entry records the major it was captured under"
    );
    assert_eq!(
        first.entry_hash.as_slice(),
        entry_hash(&GENESIS, first_seq, &first.changeset),
        "the older entry keeps the hash it was queued with"
    );
    let head: [u8; 32] = first
        .entry_hash
        .as_slice()
        .try_into()
        .expect("a 32-byte hash");
    assert_eq!(
        second.entry_hash.as_slice(),
        entry_hash(&head, second_seq, &second.changeset),
        "the newer entry chains after the older one"
    );
}

#[tokio::test]
async fn a_rebuild_stores_a_split_tables_older_entry_under_its_wire_name() {
    let dir = tempdir().expect("temp dir");
    {
        let mut conn = open(&dir, split_schema(1)).await.expect("fresh open");
        conn.conn()
            .batch_execute(
                "INSERT INTO t (id) VALUES (1); INSERT INTO items (id, label) VALUES (2, 'plain')",
            )
            .expect("write through the view");
        conn.push().await.expect("queue").expect("a seq");
    }

    let mut conn = open(&dir, schema(2, V2_DDL))
        .await
        .expect("open the newer build, which no longer splits t");
    let (changeset, stored): (Vec<u8>, Vec<u8>) = pending::table
        .select((pending::changeset, pending::entry_hash))
        .first(conn.conn())
        .expect("read the older entry");
    let mut parsed = ParsedDiffSet::parse(&changeset).expect("parse the entry");
    let mut names = Vec::new();
    assert_eq!(
        parsed.rename_tables(|name| {
            names.push(name.to_owned());
            (name == "physical_t").then(|| "t".to_owned())
        }),
        0,
        "the entry names the table the older major's server reads"
    );
    names.sort();
    assert_eq!(names, ["items", "t"]);
    assert_eq!(
        stored.as_slice(),
        entry_hash(&GENESIS, 1, &changeset),
        "the stored bytes are the bytes the hash was taken over"
    );
}
