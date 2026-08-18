//! Docker-gated: the row-level-security policy answers the write question the
//! minting path asks (R50).
//!
//! A share must not hand on a verb the sharer does not hold itself, and the
//! minting path is the one caller that asks with no database write behind it, so
//! its answer is the only gate there is. `RlsAuth` used to allow every write
//! unconditionally, which made that gate a constant yes.
//!
//! The two verbs a share can certify both carry an existing row, so both are
//! answerable: Postgres applies a table's update rule to a locking read, which
//! is exactly the question. A delete is judged by its own rule when the schema
//! writes one separately, and a locking read cannot speak for that, so the
//! answerer refuses instead of borrowing the update verb's answer.
//!
//! `#[ignore]` by default because it needs a running Postgres. Point
//! `DATABASE_URL` at one and run with `--ignored` after explicit approval.
//!
//! A superuser and a table owner bypass row-level security, so the pool
//! connects as `app_minter`, which the fixture grants the same verbs a
//! deployment's `roles.sql` grants its reader role.

use std::sync::Arc;

use connetto_core::SessionId;
use connetto_core::auth::{AuthContext, Principal, Subject, VerifiedSession};
use connetto_server::{
    AuthConfig, CapabilityIssuer, PgSnapshotSource, RlsAuth, ShareError, ShareLevel, TokenAuthority,
};
use diesel::sql_query;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use subql::backend::{Postgres as PgValues, Value};
use subql::visibility::WriteOp;

/// Catalog DDL handed to the answerer and the row reader. Tables only, so it
/// parses: the policies below are applied to Postgres directly.
const CATALOG_DDL: &str = "\
CREATE TABLE journals (id INT PRIMARY KEY, owner TEXT, body TEXT);\
CREATE TABLE ledgers (id INT PRIMARY KEY, owner TEXT, body TEXT);";

fn admin_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned())
}

fn with_user(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("url has a scheme");
    let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    format!("{scheme}://{user}:{password}@{host}")
}

async fn pool_for(url: &str) -> Pool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.to_owned());
    Pool::builder().build(manager).await.expect("build pool")
}

fn caller(identity: &str) -> Principal {
    let mut principal: Principal = Principal::unidentified(SessionId::from_token_hash(identity));
    let _ = principal.accept(Subject::Identity(VerifiedSession {
        context: AuthContext::new(identity),
        session_id: SessionId::from_token_hash(identity),
    }));
    principal
}

/// Two tables that differ only in how their rules are written.
///
/// `journals` writes a rule per command, which is the shape that makes a read
/// answer the wrong question: everybody may read it, only the owner may change
/// or delete it. `ledgers` writes one rule for every command, which is what
/// connetto's own translation generates and what a locking read answers exactly.
async fn setup() -> Pool<AsyncPgConnection> {
    let admin = pool_for(&admin_url()).await;
    let mut conn = admin.get().await.expect("admin connection");
    for statement in [
        "DROP TABLE IF EXISTS journals, ledgers CASCADE",
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_minter') \
         THEN CREATE ROLE app_minter LOGIN PASSWORD 'app_minter'; END IF; END $$",
        "CREATE TABLE journals (id INT PRIMARY KEY, owner TEXT, body TEXT)",
        "CREATE TABLE ledgers (id INT PRIMARY KEY, owner TEXT, body TEXT)",
        "INSERT INTO journals VALUES (1, 'alice', 'a')",
        "INSERT INTO ledgers VALUES (1, 'alice', 'a')",
        "ALTER TABLE journals ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE ledgers ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY journals_read ON journals FOR SELECT USING (true)",
        "CREATE POLICY journals_update ON journals FOR UPDATE \
         USING (owner = current_setting('app.user_id', true))",
        "CREATE POLICY journals_delete ON journals FOR DELETE \
         USING (owner = current_setting('app.user_id', true))",
        "CREATE POLICY ledgers_all ON ledgers \
         USING (owner = current_setting('app.user_id', true))",
        "GRANT USAGE ON SCHEMA public TO app_minter",
        // What a deployment's roles.sql grants its reader role, because that
        // pool applies client mutations under row-level security too.
        "GRANT SELECT, INSERT, UPDATE, DELETE ON journals TO app_minter",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ledgers TO app_minter",
    ] {
        sql_query(statement)
            .execute(&mut *conn)
            .await
            .expect("setup statement");
    }
    drop(conn);
    pool_for(&with_user(&admin_url(), "app_minter", "app_minter")).await
}

type Issuer = CapabilityIssuer<RlsAuth, PgSnapshotSource, String>;

fn issuer(pool: &Pool<AsyncPgConnection>) -> Issuer {
    let auth = Arc::new(RlsAuth::from_ddl(pool.clone(), CATALOG_DDL).expect("build RlsAuth"));
    let rows = Arc::new(
        PgSnapshotSource::from_ddl(pool.clone(), CATALOG_DDL).expect("build snapshot source"),
    );
    let authority = Arc::new(TokenAuthority::generate(&AuthConfig::default()).expect("keypair"));
    CapabilityIssuer::new(authority, auth, rows, &AuthConfig::default())
}

/// A caller who may read a row but not change it may not certify a change.
#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_reader_may_not_mint_a_change_it_cannot_perform() {
    let pool = setup().await;
    let issuer = issuer(&pool);
    let row = [Value::<PgValues>::Int(1)];

    // Bob may read journal 1, which is what makes this the interesting case: the
    // read question says yes and the change question must say no.
    issuer
        .issue(&caller("bob"), "journals", &row, ShareLevel::read(), None)
        .await
        .expect("bob may read the row, so a read-level share is his to give");

    let refused = issuer
        .issue(
            &caller("bob"),
            "journals",
            &row,
            ShareLevel::read().with_update(),
            None,
        )
        .await
        .expect_err("bob may not change the row, so he may not hand that on");
    assert!(
        matches!(
            &refused,
            ShareError::NotWritable { op, .. } if *op == WriteOp::Update
        ),
        "the refusal names the verb the policy denied, got {refused:?}"
    );

    // The owner still may, so the answer discriminates rather than refusing
    // everything.
    issuer
        .issue(
            &caller("alice"),
            "journals",
            &row,
            ShareLevel::read().with_update(),
            None,
        )
        .await
        .expect("alice owns the row, so she may certify a change to it");
}

/// A delete rule written for its own command cannot be answered by a locking
/// read, so the answerer refuses rather than guessing, for the owner too.
#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_command_specific_delete_rule_is_refused_rather_than_guessed() {
    let pool = setup().await;
    let issuer = issuer(&pool);
    let row = [Value::<PgValues>::Int(1)];

    let refused = issuer
        .issue(
            &caller("alice"),
            "journals",
            &row,
            ShareLevel::read().with_delete(),
            None,
        )
        .await
        .expect_err("the delete rule is its own, so the answer is not available");
    assert!(
        matches!(
            &refused,
            ShareError::WriteUndecidable { op, .. } if *op == WriteOp::Delete
        ),
        "the refusal says it could not decide rather than that the row is unwritable, \
         got {refused:?}"
    );
}

/// One rule covering every command is what connetto's own translation writes,
/// and there the delete verb is answered from the database.
#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn one_rule_for_every_command_answers_the_delete_verb() {
    let pool = setup().await;
    let issuer = issuer(&pool);
    let row = [Value::<PgValues>::Int(1)];

    issuer
        .issue(
            &caller("alice"),
            "ledgers",
            &row,
            ShareLevel::read().with_delete().with_update(),
            None,
        )
        .await
        .expect("alice owns the ledger row, so both verbs are hers to give");

    let refused = issuer
        .issue(
            &caller("bob"),
            "ledgers",
            &row,
            ShareLevel::read().with_delete(),
            None,
        )
        .await
        .expect_err("bob cannot even read the ledger row");
    assert!(
        matches!(&refused, ShareError::Unauthorized { .. }),
        "the read question refuses first, got {refused:?}"
    );
}
