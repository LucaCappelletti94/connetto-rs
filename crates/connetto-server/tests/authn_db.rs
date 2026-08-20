//! Needs Docker: the fixture starts its own Postgres.
//!
//! Exercises [`DbAuthStore`]: identity resolution through the resolver,
//! session creation and liveness, rotating refresh with reuse detection, and
//! revocation.

use std::time::SystemTime;

use connetto_server::{
    AuthConfig, AuthStore, AuthStoreError, DbAuthStore, DefaultUuidResolver, ResolvedIdentity,
    RetainedProviderToken, connetto_auth_tables,
};
use connetto_test_harness::Fixture;
use diesel::sql_query;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

// The reference default schema over `Id = String` (Text `user_id`): generates
// `ConnettoAuthSchema` plus the `connetto_sessions`/`connetto_provider_tokens`
// diesel tables the store queries against.
connetto_auth_tables!(String, diesel::sql_types::Text);

/// Reset the deployment-owned auth tables. connetto emits no DDL, so the test
/// owns the migration. `CREATE TABLE` and `DROP TABLE` are DDL the typed DSL
/// cannot express, the documented `sql_query` exception; the reference SQL
/// mirrors `docs/architecture/11-authentication.md`.
async fn reset_auth_tables(pool: &Pool<AsyncPgConnection>) {
    let mut conn = pool.get().await.expect("connection");
    for stmt in [
        "DROP TABLE IF EXISTS connetto_provider_tokens",
        "DROP TABLE IF EXISTS connetto_sessions",
        "CREATE TABLE connetto_sessions (\
            session_id UUID PRIMARY KEY, user_id TEXT NOT NULL, \
            current_refresh_hash BYTEA NOT NULL, idle_deadline TIMESTAMPTZ NOT NULL, \
            absolute_deadline TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE)",
        "CREATE TABLE connetto_provider_tokens (\
            session_id UUID PRIMARY KEY, issuer TEXT NOT NULL, access_token TEXT NOT NULL, \
            refresh_token TEXT, expires_at TIMESTAMPTZ)",
    ] {
        sql_query(stmt).execute(&mut conn).await.expect("ddl");
    }
}

/// Build the database store over the default schema, resolving identity to a
/// deterministic UUID v5 (the in-memory default resolver, run against Postgres).
fn build_store(pool: &Pool<AsyncPgConnection>) -> DbAuthStore<ConnettoAuthSchema> {
    DbAuthStore::new(
        pool.clone(),
        AuthConfig::default().refresh_lifetimes(),
        std::sync::Arc::new(DefaultUuidResolver),
    )
}

fn identity(subject: &str) -> ResolvedIdentity {
    ResolvedIdentity {
        issuer: "https://issuer.example".to_owned(),
        subject: subject.to_owned(),
        email: None,
        name: None,
        amr: Vec::new(),
        acr: None,
    }
}

// The two tests share one set of auth tables, so their `CREATE TABLE`s race on
// `pg_type_typname_nsp_index` when run concurrently. Serialize them.
static PG_SERIAL: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[tokio::test]
async fn db_store_creates_resolves_rotates_and_revokes() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    reset_auth_tables(fixture.admin()).await;
    let store = build_store(fixture.admin());
    let now = SystemTime::now();

    // Two logins for the same (issuer, subject) resolve to one deployment-owned
    // user id through the deterministic resolver, and each is its own live session.
    let first = store
        .create_session(&identity("frank"), now)
        .await
        .expect("first");
    let second = store
        .create_session(&identity("frank"), now)
        .await
        .expect("second");
    assert_eq!(
        first.context.user_id, second.context.user_id,
        "same identity resolves to one user id",
    );
    assert_ne!(first.session_id, second.session_id, "distinct sessions");
    assert!(
        store
            .session_is_live(first.session_id, now)
            .await
            .expect("live"),
        "fresh session is live",
    );

    // Rotation returns a new refresh token; the old one is now a rotated-out
    // token whose reuse is theft and revokes the session.
    let rotated = store
        .rotate_refresh(&first.refresh_token, now)
        .await
        .expect("rotate");
    assert_ne!(rotated.refresh_token, first.refresh_token, "token rotates");
    assert_eq!(rotated.context.user_id, first.context.user_id);

    let reuse = store.rotate_refresh(&first.refresh_token, now).await;
    assert!(
        matches!(reuse, Err(AuthStoreError::Reuse { session_id }) if session_id == first.session_id),
        "reused refresh token is theft naming its own session, got {reuse:?}",
    );
    assert!(
        !store
            .session_is_live(first.session_id, now)
            .await
            .expect("live"),
        "reuse revoked the session",
    );
    let after = store.rotate_refresh(&rotated.refresh_token, now).await;
    assert!(
        matches!(after, Err(AuthStoreError::NotFound)),
        "the rotated token is dead after reuse revoked the session, got {after:?}",
    );

    // Explicit revocation kills the still-live second session.
    assert!(
        store
            .session_is_live(second.session_id, now)
            .await
            .expect("live")
    );
    store
        .revoke_session(second.session_id)
        .await
        .expect("revoke");
    assert!(
        !store
            .session_is_live(second.session_id, now)
            .await
            .expect("live"),
        "revoked session is not live",
    );
}

#[tokio::test]
async fn db_store_retains_and_replaces_provider_tokens() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    reset_auth_tables(fixture.admin()).await;
    let store = build_store(fixture.admin());
    let now = SystemTime::now();
    let issued = store
        .create_session(&identity("grace"), now)
        .await
        .expect("create");

    // No retained token yet.
    assert!(
        store
            .retained_provider_token(issued.session_id)
            .await
            .expect("read")
            .is_none(),
    );

    // Store, then read back.
    let first = RetainedProviderToken {
        issuer: "https://issuer.example".to_owned(),
        access_token: "provider-access-1".to_owned(),
        refresh_token: Some("provider-refresh-1".to_owned()),
        expires_at: Some(now + std::time::Duration::from_secs(3600)),
    };
    store
        .set_retained_provider_token(issued.session_id, &first, now)
        .await
        .expect("store");
    let read = store
        .retained_provider_token(issued.session_id)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(read.access_token, "provider-access-1");
    assert_eq!(read.refresh_token.as_deref(), Some("provider-refresh-1"));
    assert_eq!(read.issuer, "https://issuer.example");

    // A second store upserts, replacing the row.
    let second = RetainedProviderToken {
        issuer: "https://issuer.example".to_owned(),
        access_token: "provider-access-2".to_owned(),
        refresh_token: None,
        expires_at: None,
    };
    store
        .set_retained_provider_token(issued.session_id, &second, now)
        .await
        .expect("store");
    let read = store
        .retained_provider_token(issued.session_id)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(read.access_token, "provider-access-2");
    assert_eq!(read.refresh_token, None);
    assert_eq!(read.expires_at, None);
}
