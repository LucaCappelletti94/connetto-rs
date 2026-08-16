//! Startup refuses a replicated table that cannot report the row as it was
//! (R6).
//!
//! Postgres emits an update's or a delete's old image in full only under
//! `REPLICA IDENTITY FULL`. Without it the change path cannot tell a row that
//! left a caller's reach from one the caller was never allowed to see, so the
//! server refuses to start and names the tables to fix.
//!
//! **The scope is the second thing proved here, and it is the reason connetto
//! writes its own query instead of using the database-wide audit subql ships.**
//! connetto keeps its own bookkeeping tables in the same database and replicates
//! none of them, so the database-wide reading refuses a deployment that is
//! configured correctly.
//!
//! `#[ignore]` by default: it needs a running Postgres.

use connetto_server::{Artifact, PreflightError, preflight};
use connetto_test_harness::Fixture;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::Text;
use diesel_async::RunQueryDsl;

/// This test's own publication, so it cannot disturb the shared one other
/// suites create and drop.
const PUBLICATION: &str = "r6_preflight_pub";

#[derive(QueryableByName)]
struct Named {
    #[diesel(sql_type = Text)]
    name: String,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn startup_refuses_a_replicated_table_that_cannot_report_the_old_row() {
    let fixture = Fixture::acquire().await;
    fixture
        .setup(&[
            &format!("DROP PUBLICATION IF EXISTS {PUBLICATION}"),
            "DROP TABLE IF EXISTS r6_full, r6_default, r6_unpublished CASCADE",
            "CREATE TABLE r6_full (id INT PRIMARY KEY, owner TEXT)",
            "CREATE TABLE r6_default (id INT PRIMARY KEY, owner TEXT)",
            "CREATE TABLE r6_unpublished (id INT PRIMARY KEY, owner TEXT)",
            "ALTER TABLE r6_full REPLICA IDENTITY FULL",
            &format!("CREATE PUBLICATION {PUBLICATION} FOR TABLE r6_full, r6_default"),
        ])
        .await;

    let refused = preflight::require(
        fixture.admin(),
        &[Artifact::PreviousImages {
            publication: PUBLICATION,
        }],
    )
    .await
    .expect_err("a replicated table without the setting must refuse startup");
    let PreflightError::PreviousImage { tables, .. } = &refused else {
        panic!(
            "the wrong refusal, which would tell a deployment to provision a table that exists: {refused}"
        );
    };
    assert_eq!(
        tables, "r6_default",
        "the refusal names the table to fix and only that one"
    );
    assert!(
        !refused.to_string().contains("r6_unpublished"),
        "a table nobody replicates is not this check's business: {refused}"
    );

    // Fixed, and the same check passes.
    fixture
        .exec("ALTER TABLE r6_default REPLICA IDENTITY FULL")
        .await;
    preflight::require(
        fixture.admin(),
        &[Artifact::PreviousImages {
            publication: PUBLICATION,
        }],
    )
    .await
    .expect("both replicated tables now report the old row");

    fixture
        .exec(&format!("DROP PUBLICATION IF EXISTS {PUBLICATION}"))
        .await;
    fixture
        .exec("DROP TABLE IF EXISTS r6_full, r6_default, r6_unpublished CASCADE")
        .await;
}

/// The database-wide audit refuses a deployment this check passes.
///
/// Run rather than reasoned, because it is the whole argument for scoping the
/// check to the publication, and because the alternative was one line of subql's
/// that would have been cheaper to adopt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn the_database_wide_audit_would_refuse_a_correct_deployment() {
    let fixture = Fixture::acquire().await;
    fixture
        .setup(&[
            &format!("DROP PUBLICATION IF EXISTS {PUBLICATION}"),
            "DROP TABLE IF EXISTS r6_full CASCADE",
            "CREATE TABLE r6_full (id INT PRIMARY KEY, owner TEXT)",
            "ALTER TABLE r6_full REPLICA IDENTITY FULL",
            &format!("CREATE PUBLICATION {PUBLICATION} FOR TABLE r6_full"),
        ])
        .await;

    preflight::require(
        fixture.admin(),
        &[Artifact::PreviousImages {
            publication: PUBLICATION,
        }],
    )
    .await
    .expect("the only replicated table reports the old row");

    let mut conn = fixture.admin().get().await.expect("a connection");
    let flagged: Vec<Named> = sql_query(format!(
        "SELECT relname AS name FROM ({audit}) audit",
        audit = subql::REPLICA_IDENTITY_AUDIT_SQL
    ))
    .load(&mut *conn)
    .await
    .expect("the database-wide audit runs");
    let flagged: Vec<String> = flagged.into_iter().map(|row| row.name).collect();
    assert!(
        flagged.iter().any(|name| name == "_connetto_mutations"),
        "the database-wide reading reports connetto's own bookkeeping, which \
         nothing replicates and which no deployment can usefully change: {flagged:?}"
    );
    assert!(
        !flagged.iter().any(|name| name == "r6_full"),
        "and it agrees about the replicated table, so the two readings differ \
         only over tables outside the change stream: {flagged:?}"
    );

    fixture
        .exec(&format!("DROP PUBLICATION IF EXISTS {PUBLICATION}"))
        .await;
    fixture.exec("DROP TABLE IF EXISTS r6_full CASCADE").await;
}
