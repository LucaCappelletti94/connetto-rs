//! Startup refuses a reconnect log table that lacks the `payload` column.
//!
//! A log table written before the compressed patch landed boots and then
//! fails every change it appends, which is a failure on the first change
//! rather than on the boot that could have named the column. The boot check
//! reads the catalogue and refuses the table, naming it and the absent
//! column.
//!
//! Needs Docker: the fixture starts its own Postgres.

use connetto_server::{Artifact, PreflightError, preflight};
use connetto_test_harness::Fixture;

/// This test's own log table, so it cannot disturb the shared one other
/// suites create.
const OPLOG: &str = "r91_oplog";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_refuses_a_log_table_without_the_payload_column() {
    let fixture = Fixture::acquire().await;
    fixture
        .setup(&[
            "DO $$ BEGIN CREATE TYPE r91_change_op AS ENUM ('insert', 'update', 'delete', 'truncate'); \
             EXCEPTION WHEN duplicate_object THEN NULL; END $$",
            "CREATE TABLE r91_oplog (
                 commit_lsn   BIGINT NOT NULL,
                 xid          BIGINT NOT NULL,
                 ordinal      BIGINT NOT NULL,
                 table_name   TEXT NOT NULL,
                 op           r91_change_op NOT NULL,
                 pk           BYTEA NOT NULL,
                 is_tombstone BOOLEAN NOT NULL,
                 event        BYTEA NOT NULL,
                 appended_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
                 PRIMARY KEY (commit_lsn, xid, ordinal)
             )",
        ])
        .await;

    let refused = preflight::require(
        fixture.admin(),
        &[Artifact::TableColumn {
            table: OPLOG,
            column: "payload",
        }],
    )
    .await
    .expect_err("a log table without the column must refuse startup");
    let PreflightError::MissingColumn { table, column } = &refused else {
        fixture.exec("DROP TABLE IF EXISTS r91_oplog").await;
        panic!("the refusal must name the missing column, got: {refused:?}");
    };
    assert_eq!(table, OPLOG, "the refusal names the table");
    assert_eq!(column, "payload", "the refusal names the column");
    assert!(
        refused.to_string().contains(OPLOG),
        "the message names the table: {refused}"
    );
    assert!(
        refused.to_string().contains("payload"),
        "the message names the column: {refused}"
    );

    // Fixed, and the same check passes.
    fixture
        .exec("ALTER TABLE r91_oplog ADD COLUMN payload BYTEA NOT NULL")
        .await;
    preflight::require(
        fixture.admin(),
        &[Artifact::TableColumn {
            table: OPLOG,
            column: "payload",
        }],
    )
    .await
    .expect("the log table now carries the column");

    fixture.exec("DROP TABLE IF EXISTS r91_oplog").await;
    fixture.exec("DROP TYPE IF EXISTS r91_change_op").await;
}
