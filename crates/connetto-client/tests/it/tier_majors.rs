//! R31: the device-private tier migrates across application schema majors on
//! a connection of its own, one transaction per boundary, and refuses the
//! open when a boundary fails, when the result is not the build's shape, or
//! when the tier records a major the build cannot reach.
//!
//! Native and offline, on real encrypted files opened once per build.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use connetto_client::{
    ClientBuilder, ClientError, ConnettoConnection, DataDir, MemoryRefreshStore, SyncSchema,
    TierFailure, TierStepError,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::FakeTransport;
use connetto_core::{MAJOR_DIRECTIVE, Major, ShapeDifference, TierBoundary, TierHistory};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use tempfile::{TempDir, tempdir};

const REPLICA_DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const TIER_V1: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)";
const TIER_V2: &str =
    "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, pinned INTEGER NOT NULL DEFAULT 0)";
const ADD_PINNED: &str = "ALTER TABLE notes ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0";

diesel::table! {
    /// The device-private table at major 1, named bare as an application names it.
    notes (id) {
        /// Note identifier, the primary key.
        id -> Integer,
        /// Optional body.
        body -> Nullable<Text>,
    }
}

/// One pinned reading, read raw because the major 1 `table!` above has no
/// such column, which is the point of a migration.
#[derive(QueryableByName, Debug, PartialEq)]
struct Pinned {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    id: i32,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pinned: i32,
}

/// One `user_version` reading, which no `table!` can name.
#[derive(QueryableByName)]
struct UserVersion {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    user_version: i32,
}

/// One schema name from `PRAGMA database_list`.
#[derive(QueryableByName)]
struct Owner {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}

fn major(value: u32) -> Major {
    Major::new(value).expect("a test major is from 1 up")
}

/// A build at `at` whose tier is `tier`, carrying `history`.
fn build(at: u32, tier: Option<&str>, history: Option<TierHistory>) -> SyncSchema {
    let bundle = SchemaBundle::new(
        format!("{MAJOR_DIRECTIVE} {at}"),
        "",
        REPLICA_DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        tier,
    )
    .expect("the source declares its major");
    let bundle = match history {
        Some(history) => bundle
            .with_tier_history(history)
            .expect("the history reaches the build"),
        None => bundle,
    };
    SyncSchema::new(bundle)
}

/// The usual second build: major 2, the pinned column, its generated step.
fn build_two(generated: &str) -> SyncSchema {
    build(
        2,
        Some(TIER_V2),
        Some(TierHistory::new(
            major(1),
            Some(major(1)),
            vec![TierBoundary::new(major(1), generated)],
        )),
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

fn tier_major(conn: &mut ConnettoConnection<FakeTransport>) -> i32 {
    // A vendor pragma, which the typed DSL cannot express.
    diesel::sql_query("PRAGMA connetto_local.user_version")
        .get_result::<UserVersion>(conn.conn())
        .expect("read the tier's major")
        .user_version
}

fn pinned(conn: &mut ConnettoConnection<FakeTransport>) -> Vec<Pinned> {
    // The column exists only from major 2, past what the `table!` above names.
    diesel::sql_query("SELECT id, pinned FROM notes ORDER BY id")
        .load(conn.conn())
        .expect("read the migrated tier")
}

/// A tier at major 1 with one row, in `dir`.
async fn first_boot(dir: &TempDir) {
    let mut conn = open(dir, build(1, Some(TIER_V1), None))
        .await
        .expect("first boot");
    diesel::insert_into(notes::table)
        .values((notes::id.eq(7), notes::body.eq("kept")))
        .execute(conn.conn())
        .expect("write the tier");
    assert_eq!(
        tier_major(&mut conn),
        1,
        "a fresh tier records the build's major"
    );
}

#[tokio::test]
async fn a_tier_behind_the_build_migrates_and_keeps_its_rows() {
    let dir = tempdir().expect("temp dir");
    first_boot(&dir).await;

    let mut conn = open(&dir, build_two(ADD_PINNED))
        .await
        .expect("open the newer build");

    assert_eq!(tier_major(&mut conn), 2);
    assert_eq!(pinned(&mut conn), vec![Pinned { id: 7, pinned: 0 }]);
    let body: Vec<Option<String>> = notes::table
        .select(notes::body)
        .load(conn.conn())
        .expect("read the kept row");
    assert_eq!(body, vec![Some("kept".to_owned())]);
}

#[tokio::test]
async fn the_applications_step_runs_after_the_generated_one() {
    let dir = tempdir().expect("temp dir");
    first_boot(&dir).await;
    let ran = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&ran);
    let schema = build_two(ADD_PINNED)
        .with_tier_step(
            major(1),
            move |tier: &mut SqliteConnection| -> Result<(), TierStepError> {
                counted.fetch_add(1, Ordering::Relaxed);
                // Sees the column the generated step added.
                tier.batch_execute("UPDATE notes SET pinned = 1 WHERE body = 'kept'")?;
                Ok(())
            },
        )
        .expect("a step at the build's only boundary");

    let mut conn = open(&dir, schema.clone()).await.expect("open");
    assert_eq!(pinned(&mut conn), vec![Pinned { id: 7, pinned: 1 }]);
    drop(conn);
    drop(open(&dir, schema).await.expect("reopen"));
    assert_eq!(ran.load(Ordering::Relaxed), 1, "each boundary runs once");
}

#[tokio::test]
async fn a_failing_step_rolls_its_boundary_back_and_refuses_the_open() {
    let dir = tempdir().expect("temp dir");
    first_boot(&dir).await;
    let failing = build_two(ADD_PINNED)
        .with_tier_step(
            major(1),
            |_: &mut SqliteConnection| -> Result<(), TierStepError> {
                Err("the application cannot convert".into())
            },
        )
        .expect("a step at the build's only boundary");

    match open(&dir, failing).await {
        Err(ClientError::TierMigration {
            from,
            to,
            cause: TierFailure::Step(_),
        }) => {
            assert_eq!((from, to), (major(1), major(2)));
        }
        Err(other) => panic!("expected the step's failure, got {other:?}"),
        Ok(_) => panic!("a failed step opened the tier"),
    }

    // The generated ADD COLUMN rolled back with the step, so running it again
    // succeeds instead of finding the column already there.
    let mut conn = open(&dir, build_two(ADD_PINNED))
        .await
        .expect("the tier is still at major 1");
    assert_eq!(pinned(&mut conn), vec![Pinned { id: 7, pinned: 0 }]);
}

#[tokio::test]
async fn a_step_that_produces_the_wrong_shape_is_refused() {
    let dir = tempdir().expect("temp dir");
    first_boot(&dir).await;

    match open(&dir, build_two("ALTER TABLE notes ADD COLUMN pinned TEXT")).await {
        Err(ClientError::TierMigration {
            cause: TierFailure::Shape(differences),
            ..
        }) => assert!(
            matches!(
                differences.as_slice(),
                [ShapeDifference::ColumnsDiffer { table, .. }] if table == "notes"
            ),
            "the one difference is the column of the wrong type: {differences:?}"
        ),
        Err(other) => panic!("expected the shape refusal, got {other:?}"),
        Ok(_) => panic!("a tier of the wrong shape opened"),
    }
    let mut conn = open(&dir, build_two(ADD_PINNED))
        .await
        .expect("nothing of the wrong step committed");
    assert_eq!(tier_major(&mut conn), 2);
}

#[tokio::test]
async fn a_table_rebuild_stays_in_the_tier() {
    let dir = tempdir().expect("temp dir");
    first_boot(&dir).await;
    let rebuild = "CREATE TABLE new_notes (id INTEGER PRIMARY KEY, body TEXT, \
        pinned INTEGER NOT NULL DEFAULT 0); \
        INSERT INTO new_notes (id, body) SELECT id, body FROM notes; \
        DROP TABLE notes; \
        ALTER TABLE new_notes RENAME TO notes";

    let mut conn = open(&dir, build_two(rebuild)).await.expect("open");
    assert_eq!(pinned(&mut conn), vec![Pinned { id: 7, pinned: 0 }]);
    // A vendor pragma, which the typed DSL cannot express.
    let main_tables: Vec<Owner> =
        diesel::sql_query("SELECT name FROM main.sqlite_schema WHERE name LIKE '%notes%'")
            .load(conn.conn())
            .expect("read the replica's catalogue");
    assert!(
        main_tables.is_empty(),
        "the rebuilt table landed in the replica: {:?}",
        main_tables.iter().map(|t| &t.name).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_tier_ahead_of_the_build_is_refused() {
    let dir = tempdir().expect("temp dir");
    first_boot(&dir).await;
    {
        let mut conn = open(&dir, build(1, Some(TIER_V1), None))
            .await
            .expect("reopen");
        conn.conn()
            .batch_execute("PRAGMA connetto_local.user_version = 3")
            .expect("move the tier ahead");
    }
    match open(&dir, build(1, Some(TIER_V1), None)).await {
        Err(ClientError::TierNewer { recorded, build }) => {
            assert_eq!((recorded, build), (major(3), major(1)));
        }
        Err(other) => panic!("expected TierNewer, got {other:?}"),
        Ok(_) => panic!("a tier ahead of the build opened"),
    }
}

#[tokio::test]
async fn a_tier_older_than_the_oldest_export_is_refused() {
    let dir = tempdir().expect("temp dir");
    first_boot(&dir).await;
    let three = build(
        3,
        Some(TIER_V2),
        Some(TierHistory::new(
            major(2),
            Some(major(2)),
            vec![TierBoundary::new(major(2), "")],
        )),
    );
    match open(&dir, three).await {
        Err(ClientError::TierTooOld { recorded, oldest }) => {
            assert_eq!((recorded, oldest), (major(1), major(2)));
        }
        Err(other) => panic!("expected TierTooOld, got {other:?}"),
        Ok(_) => panic!("a tier no step reaches opened"),
    }
}

#[tokio::test]
async fn a_tier_a_later_major_introduces_is_created_on_an_existing_install() {
    let dir = tempdir().expect("temp dir");
    drop(
        open(&dir, build(1, None, None))
            .await
            .expect("first boot without a tier"),
    );
    let two = build(
        2,
        Some(TIER_V1),
        Some(TierHistory::new(major(2), Some(major(2)), Vec::new())),
    );

    let mut conn = open(&dir, two)
        .await
        .expect("open the build that adds a tier");
    diesel::insert_into(notes::table)
        .values((notes::id.eq(1), notes::body.eq("new")))
        .execute(conn.conn())
        .expect("write the new tier");
    assert_eq!(tier_major(&mut conn), 2);
}

#[tokio::test]
async fn a_lost_tier_still_fails_loudly() {
    let dir = tempdir().expect("temp dir");
    first_boot(&dir).await;
    let credential = super::support::held("tester");
    let tier = dir
        .path()
        .join(format!("{}-tier", credential.replica_name()));
    std::fs::remove_file(&tier).expect("lose the tier");

    assert!(
        open(&dir, build(1, Some(TIER_V1), None)).await.is_err(),
        "a tier this install already had is lost, never silently recreated"
    );
}
