//! Docker-gated Row-Level Security read-filter test.
//!
//! Verifies that the row-level-security policy enforces a Postgres RLS policy
//! keyed on `current_setting('app.user_id')`. The check reads the key off the
//! row view, binds it typed and indexed as `col = $n`, and runs `EXISTS` under
//! the requesting identity, so the row's own primary-key index answers
//! visibility.
//! Covers a single integer key, a composite key, a uuid key, and the loud
//! failure raised for a key type the bind path does not cover yet.
//!
//! `#[ignore]` by default because it needs a running Postgres. Point
//! `DATABASE_URL` at one and run with `--ignored` after explicit approval.
//!
//! A superuser bypasses RLS entirely, so the check must connect as a
//! non-superuser role. The test creates `app_reader` for that and runs the
//! policy checks through it, doing privileged setup as the admin role.

#![allow(clippy::too_many_lines)]

use connetto_core::SessionId;
use connetto_core::auth::{AuthContext, Principal, Subject, VerifiedSession};
use connetto_server::{RlsAuth, RlsAuthError, ValuesRow};
use diesel::sql_query;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use std::sync::Arc;
use subql::backend::{Postgres, Value};
use subql::visibility::{Verdict, VisibilityPolicy};
use subql::{ParserDB, catalog_helpers};

/// Catalog DDL handed to [`RlsAuth`]. Only `CREATE TABLE`, so it parses cleanly;
/// the RLS wiring runs against Postgres separately.
const CATALOG_DDL: &str = "\
CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT, body TEXT);\
CREATE TABLE shares (doc_id INT, viewer TEXT, PRIMARY KEY (doc_id, viewer));\
CREATE TABLE assets (id UUID PRIMARY KEY, owner TEXT);\
CREATE TABLE events (occurred_at TIMESTAMP PRIMARY KEY, owner TEXT);";

fn admin_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned())
}

/// Rewrite a Postgres URL's user info, keeping host, port, and database.
fn with_user(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("url has a scheme");
    let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    format!("{scheme}://{user}:{password}@{host}")
}

async fn pool_for(url: &str) -> Pool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.to_owned());
    Pool::builder().build(manager).await.expect("build pool")
}

/// Ask the policy about one row, as the change path does.
///
/// `key` is the row's leading columns, which is all the filter reads: this
/// exercises the key path specifically, so the rest of the row is not supplied.
async fn ask(
    auth: &RlsAuth,
    user: &str,
    table: &str,
    key: &[Value<Postgres>],
) -> Result<bool, RlsAuthError> {
    let mut principal: Principal = Principal::unidentified(SessionId::from_token_hash(user));
    let _ = principal.accept(Subject::Identity(VerifiedSession {
        context: AuthContext::new(user),
        session_id: SessionId::from_token_hash(user),
    }));
    let catalog = ParserDB::parse::<sqlparser::dialect::PostgreSqlDialect>(CATALOG_DDL)
        .expect("the catalog parses");
    let table_id = catalog_helpers::table_id(&catalog, table).expect("the table is in the catalog");
    let row = ValuesRow::new(table_id, key);
    let watchers = [Arc::new(principal)];
    let mut verdicts = Vec::new();
    Verdict::reset(&mut verdicts, watchers.len());
    auth.may_see(&row, &watchers, &mut verdicts).await?;
    Ok(matches!(verdicts.as_slice(), [Verdict::Allow, ..]))
}

/// Whether `user` may read the row `key` names in `table`.
async fn visible(auth: &RlsAuth, user: &str, table: &str, key: &[Value<Postgres>]) -> bool {
    ask(auth, user, table, key)
        .await
        .expect("the visibility question")
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn rls_read_filter_enforces_visibility_per_user() {
    let alice_asset = uuid::Uuid::from_u128(0x0A11_CE00);
    let bob_asset = uuid::Uuid::from_u128(0x00B0_B000);

    let admin = pool_for(&admin_url()).await;
    let mut conn = admin.get().await.expect("admin connection");
    let setup: Vec<String> = vec![
        "DROP TABLE IF EXISTS docs, shares, assets, events CASCADE".to_owned(),
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') \
         THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; END $$"
            .to_owned(),
        "CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT, body TEXT)".to_owned(),
        "CREATE TABLE shares (doc_id INT, viewer TEXT, PRIMARY KEY (doc_id, viewer))".to_owned(),
        "CREATE TABLE assets (id UUID PRIMARY KEY, owner TEXT)".to_owned(),
        "CREATE TABLE events (occurred_at TIMESTAMP PRIMARY KEY, owner TEXT)".to_owned(),
        "INSERT INTO docs VALUES (1, 'alice', 'a'), (2, 'bob', 'b')".to_owned(),
        "INSERT INTO shares VALUES (1, 'alice'), (1, 'bob')".to_owned(),
        format!("INSERT INTO assets VALUES ('{alice_asset}', 'alice'), ('{bob_asset}', 'bob')"),
        "INSERT INTO events VALUES ('2024-01-01 12:00:00', 'alice')".to_owned(),
        "ALTER TABLE docs ENABLE ROW LEVEL SECURITY".to_owned(),
        "ALTER TABLE shares ENABLE ROW LEVEL SECURITY".to_owned(),
        "ALTER TABLE assets ENABLE ROW LEVEL SECURITY".to_owned(),
        "ALTER TABLE events ENABLE ROW LEVEL SECURITY".to_owned(),
        "CREATE POLICY docs_p ON docs USING (owner = current_setting('app.user_id', true))"
            .to_owned(),
        "CREATE POLICY shares_p ON shares USING (viewer = current_setting('app.user_id', true))"
            .to_owned(),
        "CREATE POLICY assets_p ON assets USING (owner = current_setting('app.user_id', true))"
            .to_owned(),
        "CREATE POLICY events_p ON events USING (owner = current_setting('app.user_id', true))"
            .to_owned(),
        "GRANT USAGE ON SCHEMA public TO app_reader".to_owned(),
        "GRANT SELECT ON docs, shares, assets, events TO app_reader".to_owned(),
    ];
    for stmt in setup {
        sql_query(stmt)
            .execute(&mut *conn)
            .await
            .expect("setup statement");
    }
    drop(conn);

    let reader = pool_for(&with_user(&admin_url(), "app_reader", "app_reader")).await;
    let auth = RlsAuth::from_ddl(reader, CATALOG_DDL).expect("build RlsAuth");

    // Single integer key: each user sees only their own row.
    assert!(visible(&auth, "alice", "docs", &[Value::Int(1)]).await);
    assert!(!visible(&auth, "alice", "docs", &[Value::Int(2)]).await);
    assert!(visible(&auth, "bob", "docs", &[Value::Int(2)]).await);
    assert!(!visible(&auth, "bob", "docs", &[Value::Int(1)]).await);

    // Composite key: the multi-column AND binds positionally and the policy
    // still hides the other user's row.
    let alice_share = [Value::Int(1), Value::String("alice".to_owned())];
    let bob_share = [Value::Int(1), Value::String("bob".to_owned())];
    assert!(visible(&auth, "alice", "shares", &alice_share).await);
    assert!(!visible(&auth, "bob", "shares", &alice_share).await);
    assert!(visible(&auth, "bob", "shares", &bob_share).await);

    // Uuid key: the uuid binds natively and visibility follows the owner.
    assert!(visible(&auth, "alice", "assets", &[Value::Uuid(alice_asset)]).await);
    assert!(!visible(&auth, "bob", "assets", &[Value::Uuid(alice_asset)]).await);
    assert!(visible(&auth, "bob", "assets", &[Value::Uuid(bob_asset)]).await);

    // A timestamp key is not bindable yet: the check fails loudly rather than
    // silently admitting or denying the row.
    let occurred_at = chrono::NaiveDate::from_ymd_opt(2024, 1, 1)
        .expect("date")
        .and_hms_opt(12, 0, 0)
        .expect("time");
    let err = ask(&auth, "alice", "events", &[Value::Timestamp(occurred_at)])
        .await
        .expect_err("timestamp key must fail loudly");
    assert!(
        matches!(err, RlsAuthError::UnsupportedKeyType { .. }),
        "expected UnsupportedKeyType, got {err:?}"
    );
}

/// A policy naming its own identity setting is honoured.
///
/// The share-key setting has been the application's choice since R4 and this
/// one was fixed in connetto's source until 2026-08-06. The assertion that
/// matters is the negative: with the default name the policy sees nothing,
/// because connetto would be binding a setting nobody reads.
#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn a_policy_may_name_its_own_identity_setting() {
    const OURS: &str = "myapp.current_user";

    let admin = pool_for(&admin_url()).await;
    let mut conn = admin.get().await.expect("admin connection");
    for stmt in [
        // The role is this test's own to provision: depending on the other test
        // having run first is an ordering dependency, and it bit once already.
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') \
         THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; END $$",
        "DROP TABLE IF EXISTS docs",
        "CREATE TABLE docs (id INT PRIMARY KEY, owner TEXT NOT NULL)",
        "INSERT INTO docs VALUES (1, 'alice'), (2, 'bob')",
        "ALTER TABLE docs ENABLE ROW LEVEL SECURITY",
        // The policy reads the application's own name, not connetto's default.
        "CREATE POLICY docs_p ON docs USING (owner = current_setting('myapp.current_user', true))",
        "GRANT USAGE ON SCHEMA public TO app_reader",
        "GRANT SELECT ON docs TO app_reader",
    ] {
        sql_query(stmt)
            .execute(&mut *conn)
            .await
            .expect("setup statement");
    }
    drop(conn);

    let reader = pool_for(&with_user(&admin_url(), "app_reader", "app_reader")).await;
    let renamed = RlsAuth::from_ddl(reader.clone(), CATALOG_DDL)
        .expect("build RlsAuth")
        .with_user_setting(OURS);
    assert!(visible(&renamed, "alice", "docs", &[Value::Int(1)]).await);
    assert!(!visible(&renamed, "alice", "docs", &[Value::Int(2)]).await);
    assert!(visible(&renamed, "bob", "docs", &[Value::Int(2)]).await);

    // Left at the default, connetto binds a setting this policy never reads, so
    // the owner comparison is NULL and every row is hidden. Without this the
    // test above would pass even if the rename did nothing.
    let defaulted = RlsAuth::from_ddl(reader, CATALOG_DDL).expect("build RlsAuth");
    assert!(!visible(&defaulted, "alice", "docs", &[Value::Int(1)]).await);
}
