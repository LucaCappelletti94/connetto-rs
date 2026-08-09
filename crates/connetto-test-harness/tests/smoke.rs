//! Phase B acceptance: the full in-process CDC loop over a real Postgres.
//!
//! A subscriber (client A) watches a table. A second client (B) applies a local
//! insert of a row it owns. The write goes through the production write target
//! under an RLS role (`app_writer`, `SET LOCAL app.user_id`), lands in Postgres,
//! and fans back out over a live logical replication stream to A as a live
//! patch. The row is then read back through the admin pool (RLS off) to confirm
//! it actually landed.
//!
//! `#[ignore]` by default: it needs a Postgres started with `wal_level=logical`.
//! Run under Docker with `DATABASE_URL` pointed at it and `-- --ignored`.

use std::time::Duration;

use connetto_core::messages::ControlMessage;
use connetto_server::{PgSnapshotSource, RlsAuth, RuntimeWritableCatalog};
use connetto_test_harness::{
    Fixture, HarnessAuth, ServerConfig, insert_changeset, pool_for, spawn_server, with_user,
};
use diesel::{QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::bb8::Pool;
use sqlite_diff_rs::Value;

const PG_DDL: &str =
    "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT, edited_at TEXT);";

diesel::table! {
    /// Test table for subscription and write integration
    notes (id) {
        /// Note identifier, the primary key
        id -> diesel::sql_types::Integer,
        /// Identity that owns the note
        owner -> diesel::sql_types::Text,
        /// Note content
        body -> diesel::sql_types::Text,
        /// Timestamp of the last edit
        edited_at -> diesel::sql_types::Text,
    }
}

#[derive(diesel::Queryable, diesel::Selectable, Debug, PartialEq)]
#[diesel(table_name = notes)]
#[diesel(check_for_backend(diesel::pg::Pg))]
struct NoteRow {
    id: i32,
    owner: String,
}

/// The `(id, owner)` rows in `notes`, read through the admin pool so RLS hides
/// none. Typed DSL against the `notes` `table!`, checked at compile time.
async fn notes(pool: &Pool<AsyncPgConnection>) -> Vec<(i32, String)> {
    let mut conn = pool.get().await.expect("admin connection");
    let rows: Vec<NoteRow> = notes::table
        .order(notes::id)
        .select(NoteRow::as_select())
        .load(&mut *conn)
        .await
        .expect("read notes");
    rows.into_iter().map(|row| (row.id, row.owner)).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker)"]
async fn write_lands_under_rls_and_fans_out_over_cdc() {
    let fixture = Fixture::acquire().await;
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS notes CASCADE",
            "DROP TABLE IF EXISTS _connetto_mutations",
            "DROP PUBLICATION IF EXISTS connetto_pub",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
             THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$",
            "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT, edited_at TEXT)",
            "ALTER TABLE notes REPLICA IDENTITY FULL",
            "ALTER TABLE notes ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY notes_p ON notes \
             USING (owner = current_setting('app.user_id', true)) \
             WITH CHECK (owner = current_setting('app.user_id', true))",
            "GRANT USAGE ON SCHEMA public TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO app_writer",
        ])
        .await;
    // The watermark table is provisioned by the admin, as a deployment would:
    // the restricted writer role cannot CREATE in schema public.
    connetto_test_harness::provision_watermark(fixture.admin()).await;
    fixture
        .exec("GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_writer")
        .await;
    fixture.start_replication(&["notes"]).await;

    let writer_pool = pool_for(&with_user(fixture.admin_url(), "app_writer", "app_writer")).await;
    let snapshot =
        PgSnapshotSource::from_ddl(writer_pool.clone(), PG_DDL).expect("snapshot source");
    let auth = HarnessAuth::rls(RlsAuth::from_ddl(writer_pool.clone(), PG_DDL).expect("rls auth"));
    let server = spawn_server(
        ServerConfig::new(PG_DDL, fixture.admin_url()).with_writable(
            RuntimeWritableCatalog::builder()
                .versioned("notes", "edited_at")
                .build(),
        ),
        snapshot,
        auth,
        writer_pool,
        fixture.admin().clone(),
    );

    // Client A subscribes to alice's notes and drains the initial snapshot of
    // the empty table (an empty snapshot may still carry an empty patch frame).
    let mut a = server.connect();
    a.handshake_with("client-a", "user:alice#reader").await;
    a.subscribe("notes", "SELECT * FROM notes WHERE owner = 'alice'")
        .await;
    let _ = a.expect_snapshot("notes").await;

    // Client B applies a local insert of a row it owns.
    let mut b = server.connect();
    b.handshake_with("client-b", "user:alice#writer").await;
    b.upload(
        1,
        insert_changeset(
            "notes",
            &["id", "owner", "body", "edited_at"],
            &[0],
            vec![
                Value::Integer(1),
                Value::Text("alice".to_owned()),
                Value::Text("mine".to_owned()),
                Value::Text("t1".to_owned()),
            ],
        ),
    )
    .await;
    match b.next_control().await {
        ControlMessage::MutationApplied(applied) => assert_eq!(applied.client_seq, 1),
        other => panic!("owned insert should apply under RLS, got {other:?}"),
    }
    match b.barrier(2).await {
        ControlMessage::Pong(_) => {}
        other => panic!("expected pong after the apply ack, got {other:?}"),
    }

    // The write fans back out over CDC to A's subscription as a live patch.
    let live = a.wait_for_live(Duration::from_secs(20)).await;
    assert_eq!(
        live.sub_id, "notes",
        "live patch for the right subscription"
    );
    assert!(
        !live.patchset_zstd.is_empty(),
        "the live patch carries the inserted row"
    );

    // Postgres holds the row, so the write really landed under RLS.
    assert_eq!(notes(fixture.admin()).await, vec![(1, "alice".to_owned())]);

    a.close().await;
    b.close().await;
    drop(server);
}
