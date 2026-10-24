//! Needs Docker: the fixture starts its own Postgres.
//!
//! Exercises [`DbAuthStore`]: identity resolution through the resolver,
//! session creation and liveness, rotating refresh with reuse detection, and
//! revocation.

use std::time::Duration;

use connetto_server::{
    AuthConfig, AuthStore, AuthStoreError, DbAuthStore, DefaultUuidResolver, ResolvedIdentity,
    RetainedProviderToken,
};
use connetto_test_harness::Fixture;
use diesel::sql_query;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

// The default schema over `Id = String`, a Text `user_id`.
use connetto_server::defaults::ConnettoDefaults;

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
fn build_store(pool: &Pool<AsyncPgConnection>) -> DbAuthStore<ConnettoDefaults> {
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

    // Two logins for the same (issuer, subject) resolve to one deployment-owned
    // user id through the deterministic resolver, and each is its own live session.
    let first = store
        .create_session(&identity("frank"))
        .await
        .expect("first");
    let second = store
        .create_session(&identity("frank"))
        .await
        .expect("second");
    assert_eq!(
        first.context.user_id, second.context.user_id,
        "same identity resolves to one user id",
    );
    assert_ne!(first.session_id, second.session_id, "distinct sessions");
    assert!(
        store.session_is_live(first.session_id).await.expect("live"),
        "fresh session is live",
    );

    // Rotation returns a new refresh token; the old one is now a rotated-out
    // token whose reuse is theft and revokes the session.
    let rotated = store
        .rotate_refresh(&first.refresh_token)
        .await
        .expect("rotate");
    assert_ne!(rotated.refresh_token, first.refresh_token, "token rotates");
    assert_eq!(rotated.context.user_id, first.context.user_id);

    let reuse = store.rotate_refresh(&first.refresh_token).await;
    assert!(
        matches!(reuse, Err(AuthStoreError::Reuse { session_id }) if session_id == first.session_id),
        "reused refresh token is theft naming its own session, got {reuse:?}",
    );
    assert!(
        !store.session_is_live(first.session_id).await.expect("live"),
        "reuse revoked the session",
    );
    let after = store.rotate_refresh(&rotated.refresh_token).await;
    assert!(
        matches!(after, Err(AuthStoreError::NotFound)),
        "the rotated token is dead after reuse revoked the session, got {after:?}",
    );

    // Explicit revocation kills the still-live second session.
    assert!(
        store
            .session_is_live(second.session_id)
            .await
            .expect("live")
    );
    store
        .revoke_session(second.session_id)
        .await
        .expect("revoke");
    assert!(
        !store
            .session_is_live(second.session_id)
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
    let issued = store
        .create_session(&identity("grace"))
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

    // Store, then read back. An hour of lifetime outlives the store's
    // thirty-second margin, so the access token can still be used.
    let first = RetainedProviderToken {
        issuer: "https://issuer.example".to_owned(),
        access_token: "provider-access-1".to_owned(),
        refresh_token: Some("provider-refresh-1".to_owned()),
        expires_in: Some(Duration::from_secs(3600)),
    };
    store
        .set_retained_provider_token(issued.session_id, &first)
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
    assert!(read.still_valid, "an hour of lifetime outlives the margin");

    // A second store upserts, replacing the row.
    let second = RetainedProviderToken {
        issuer: "https://issuer.example".to_owned(),
        access_token: "provider-access-2".to_owned(),
        refresh_token: None,
        expires_in: None,
    };
    store
        .set_retained_provider_token(issued.session_id, &second)
        .await
        .expect("store");
    let read = store
        .retained_provider_token(issued.session_id)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(read.access_token, "provider-access-2");
    assert_eq!(read.refresh_token, None);
    assert!(read.still_valid, "no stated lifetime means no expiry");

    // A lifetime shorter than the margin is already spent as the database
    // reads it.
    let third = RetainedProviderToken {
        issuer: "https://issuer.example".to_owned(),
        access_token: "provider-access-3".to_owned(),
        refresh_token: None,
        expires_in: Some(Duration::from_secs(10)),
    };
    store
        .set_retained_provider_token(issued.session_id, &third)
        .await
        .expect("store");
    let read = store
        .retained_provider_token(issued.session_id)
        .await
        .expect("read")
        .expect("present");
    assert!(
        !read.still_valid,
        "ten seconds of lifetime is inside the margin"
    );
}

/// A deadline the database clock has passed is refused by the store, the
/// process clock out of the picture.
#[tokio::test]
async fn db_store_refuses_a_session_whose_deadline_lapsed_in_the_database() {
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    reset_auth_tables(fixture.admin()).await;
    let store = build_store(fixture.admin());
    let issued = store
        .create_session(&identity("harry"))
        .await
        .expect("create");

    // Backdate both deadlines a minute into the past, the way only the
    // database clock can. The clock expression is SQL the typed DSL cannot
    // express, the documented exception.
    let mut conn = fixture.admin().get().await.expect("connection");
    sql_query(
        "UPDATE connetto_sessions \
         SET idle_deadline = now() - interval '1 minute', \
             absolute_deadline = now() - interval '1 minute' \
         WHERE session_id = $1",
    )
    .bind::<diesel::sql_types::Uuid, _>(issued.session_id.as_uuid())
    .execute(&mut conn)
    .await
    .expect("backdate the deadlines");

    assert!(
        !store
            .session_is_live(issued.session_id)
            .await
            .expect("live"),
        "a lapsed absolute deadline is not live"
    );
    let refused = store.rotate_refresh(&issued.refresh_token).await;
    assert!(
        matches!(refused, Err(AuthStoreError::Expired)),
        "rotation refuses a session whose deadlines lapsed, got {refused:?}"
    );
}
