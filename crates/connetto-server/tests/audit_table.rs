//! Docker-gated test for the `auth_events` schema contract.
//!
//! Exercises the [`ConnettoAuditSchema`] default the `connetto_audit_table!`
//! macro generates: that a deployment can create the documented table, that
//! every `op` value survives a round trip through the Postgres enum, and that
//! the row a share mint names is preserved. `#[ignore]` by default because it
//! needs a running Postgres. Point `DATABASE_URL` at one and run with
//! `--ignored` after explicit approval.

use connetto_core::SessionId;
use connetto_server::audit::{AUTH_OP_TYPE, AuthEvent, AuthOp, ConnettoAuditSchema};
use connetto_server::connetto_audit_table;
use diesel::prelude::*;
use diesel::sql_query;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use subql::backend::Value;

/// Serializes these tests. Each drops and recreates the one `auth_events`
/// table and its enum type, so concurrent runs race on the DDL. Same treatment
/// `e2e.rs` gives the fixtures it shares.
static PG_SERIAL: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

// The reference default schema over `Id = String`, matching `authn_db.rs`.
connetto_audit_table!(
    String,
    diesel::sql_types::Text,
    uuid::Uuid,
    diesel::sql_types::Uuid,
);

/// Create the deployment-owned audit table. connetto emits no DDL, so the test
/// owns it, and the SQL mirrors `docs/architecture/08-authorization.md`.
async fn reset_audit_table(pool: &Pool<AsyncPgConnection>) {
    let mut conn = pool.get().await.expect("connection");
    for stmt in [
        "DROP TABLE IF EXISTS auth_events".to_owned(),
        format!("DROP TYPE IF EXISTS {AUTH_OP_TYPE}"),
        format!(
            "CREATE TYPE {AUTH_OP_TYPE} AS ENUM (\
                'logged_out', 'session_revoked', 'token_replayed', \
                'capability_minted', 'permission_change', 'model_change', \
                'banned', 'ban_lifted')"
        ),
        format!(
            "CREATE TABLE auth_events (\
                at TIMESTAMPTZ NOT NULL DEFAULT now(), \
                session UUID NOT NULL, \
                user_id TEXT, \
                op {AUTH_OP_TYPE} NOT NULL, \
                table_name TEXT, \
                pk UUID)"
        ),
    ] {
        sql_query(stmt).execute(&mut conn).await.expect("ddl");
    }
}

async fn pool() -> Pool<AsyncPgConnection> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    Pool::builder()
        .build(AsyncDieselConnectionManager::<AsyncPgConnection>::new(url))
        .await
        .expect("pool")
}

/// Every value the contract declares must survive Postgres.
///
/// The `op` column is a Postgres enum rather than text precisely so a value
/// outside the set is rejected by the database, which only holds if both ends
/// agree on every label. A Rust variant whose label the type does not declare
/// fails on write, and one Postgres accepts but Rust cannot decode fails on
/// read, so the round trip is the assertion that keeps the two in step.
#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn every_auth_op_round_trips_through_postgres() {
    let _serial = PG_SERIAL.lock().await;
    let pool = pool().await;
    reset_audit_table(&pool).await;
    let mut conn = pool.get().await.expect("connection");

    let all = [
        AuthOp::LoggedOut,
        AuthOp::SessionRevoked,
        AuthOp::TokenReplayed,
        AuthOp::CapabilityMinted,
        AuthOp::PermissionChange,
        AuthOp::ModelChange,
        AuthOp::Banned,
        AuthOp::BanLifted,
    ];
    for op in all {
        let session = SessionId::from_uuid(uuid::Uuid::new_v4());
        diesel_async::RunQueryDsl::execute(
            ConnettoAudit::audit_insert(AuthEvent::new(session, Some("alice".to_owned()), op)),
            &mut conn,
        )
        .await
        .unwrap_or_else(|err| panic!("insert {}: {err}", op.label()));

        let read: AuthOp = diesel_async::RunQueryDsl::get_result(
            auth_events::table
                .filter(auth_events::session.eq(session))
                .select(auth_events::op),
            &mut conn,
        )
        .await
        .unwrap_or_else(|err| panic!("read back {}: {err}", op.label()));
        assert_eq!(read, op, "{} did not round trip", op.label());
    }
}

/// A label Postgres does not declare must be refused rather than stored.
///
/// This is what the enum column buys over text, so it is asserted rather than
/// assumed.
#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn an_undeclared_op_label_is_refused() {
    let _serial = PG_SERIAL.lock().await;
    let pool = pool().await;
    reset_audit_table(&pool).await;
    let mut conn = pool.get().await.expect("connection");

    let refused = sql_query(format!(
        "INSERT INTO auth_events (session, op) VALUES ('{}', 'grant_rejected')",
        SessionId::from_uuid(uuid::Uuid::new_v4())
    ))
    .execute(&mut conn)
    .await;
    assert!(
        refused.is_err(),
        "a label outside the declared set must be refused by Postgres"
    );
}

/// A share mint names the row it shared, and nothing else does.
#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_mint_names_its_row_and_a_logout_does_not() {
    let _serial = PG_SERIAL.lock().await;
    let pool = pool().await;
    reset_audit_table(&pool).await;
    let mut conn = pool.get().await.expect("connection");

    let mint_session = SessionId::from_uuid(uuid::Uuid::new_v4());
    let shared_row = uuid::Uuid::new_v4();
    diesel_async::RunQueryDsl::execute(
        ConnettoAudit::audit_insert(
            AuthEvent::new(
                mint_session,
                Some("alice".to_owned()),
                AuthOp::CapabilityMinted,
            )
            .about_row("orders", vec![Value::Uuid(shared_row)]),
        ),
        &mut conn,
    )
    .await
    .expect("insert mint");

    let logout_session = SessionId::from_uuid(uuid::Uuid::new_v4());
    diesel_async::RunQueryDsl::execute(
        ConnettoAudit::audit_insert(AuthEvent::new(
            logout_session,
            Some("alice".to_owned()),
            AuthOp::LoggedOut,
        )),
        &mut conn,
    )
    .await
    .expect("insert logout");

    let (table_name, pk): (Option<String>, Option<uuid::Uuid>) =
        diesel_async::RunQueryDsl::get_result(
            auth_events::table
                .filter(auth_events::session.eq(mint_session))
                .select((auth_events::table_name, auth_events::pk)),
            &mut conn,
        )
        .await
        .expect("read mint");
    assert_eq!(table_name.as_deref(), Some("orders"));
    assert_eq!(
        pk,
        Some(shared_row),
        "the key is stored as the type the table declares"
    );

    let (table_name, pk): (Option<String>, Option<uuid::Uuid>) =
        diesel_async::RunQueryDsl::get_result(
            auth_events::table
                .filter(auth_events::session.eq(logout_session))
                .select((auth_events::table_name, auth_events::pk)),
            &mut conn,
        )
        .await
        .expect("read logout");
    assert_eq!(table_name, None, "a logout names no row");
    assert_eq!(pk, None, "a logout names no row");
}

/// The database clock stamps the row, not the emitting process.
#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn the_database_clock_stamps_the_row() {
    #[derive(QueryableByName)]
    struct Skew {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        secs: i64,
    }
    let _serial = PG_SERIAL.lock().await;
    let pool = pool().await;
    reset_audit_table(&pool).await;
    let mut conn = pool.get().await.expect("connection");

    let session = SessionId::from_uuid(uuid::Uuid::new_v4());
    diesel_async::RunQueryDsl::execute(
        ConnettoAudit::audit_insert(AuthEvent::new(session, None, AuthOp::LoggedOut)),
        &mut conn,
    )
    .await
    .expect("insert");

    let skew: Skew = sql_query(format!(
        "SELECT CAST(EXTRACT(EPOCH FROM (now() - at)) AS BIGINT) AS secs \
         FROM auth_events WHERE session = '{session}'"
    ))
    .get_result(&mut conn)
    .await
    .expect("read stamp");
    assert!(
        skew.secs.abs() < 5,
        "the row is stamped by the database clock, skew {}s",
        skew.secs
    );
}
