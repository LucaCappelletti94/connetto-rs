//! Docker-gated database auth store test.
//!
//! Exercises [`DbAuthStore`]: identity resolution through the linking table,
//! session creation and liveness, rotating refresh with reuse detection, and
//! revocation. `#[ignore]` by default because it needs a running Postgres.
//! Point `DATABASE_URL` at one and run with `--ignored` after explicit approval.
//!
//! The whole file compiles only under the `pg-async` feature.

#![cfg(feature = "pg-async")]

use std::collections::BTreeMap;
use std::time::SystemTime;

use connetto_server::{
    AuthConfig, AuthStore, AuthStoreError, DbAuthStore, ResolvedIdentity, RetainedProviderToken,
    provision_auth_tables,
};
use diesel::sql_query;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

fn identity(subject: &str) -> ResolvedIdentity {
    ResolvedIdentity {
        issuer: "https://issuer.example".to_owned(),
        subject: subject.to_owned(),
        tenant_id: Some("tenant-db".to_owned()),
        roles: vec!["member".to_owned()],
        claims: BTreeMap::new(),
    }
}

async fn pool() -> Pool<AsyncPgConnection> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned());
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url);
    Pool::builder().build(manager).await.expect("build pool")
}

// The two tests share one set of auth tables, so their `CREATE TABLE`s race on
// `pg_type_typname_nsp_index` when run concurrently. Serialize them.
static PG_SERIAL: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn db_store_creates_resolves_rotates_and_revokes() {
    let _serial = PG_SERIAL.lock().await;
    let pool = pool().await;
    {
        let mut conn = pool.get().await.expect("connection");
        sql_query("DROP TABLE IF EXISTS connetto_sessions")
            .execute(&mut conn)
            .await
            .expect("drop sessions");
        sql_query("DROP TABLE IF EXISTS connetto_identities")
            .execute(&mut conn)
            .await
            .expect("drop identities");
    }
    provision_auth_tables(&pool).await.expect("provision");

    let store = DbAuthStore::new(pool.clone(), AuthConfig::default().refresh_lifetimes());
    let now = SystemTime::now();

    // Two logins for the same (issuer, subject) resolve to one deployment-owned
    // user id through the linking table, and each is its own live session.
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
    assert_eq!(first.context.roles, vec!["member".to_owned()]);
    assert!(
        store
            .session_is_live(&first.session_id, now)
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
        matches!(reuse, Err(AuthStoreError::Reuse)),
        "reused refresh token is theft, got {reuse:?}",
    );
    assert!(
        !store
            .session_is_live(&first.session_id, now)
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
            .session_is_live(&second.session_id, now)
            .await
            .expect("live")
    );
    store
        .revoke_session(&second.session_id)
        .await
        .expect("revoke");
    assert!(
        !store
            .session_is_live(&second.session_id, now)
            .await
            .expect("live"),
        "revoked session is not live",
    );
}

#[tokio::test]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn db_store_retains_and_replaces_provider_tokens() {
    let _serial = PG_SERIAL.lock().await;
    let pool = pool().await;
    {
        let mut conn = pool.get().await.expect("connection");
        for stmt in [
            "DROP TABLE IF EXISTS connetto_provider_tokens",
            "DROP TABLE IF EXISTS connetto_sessions",
            "DROP TABLE IF EXISTS connetto_identities",
        ] {
            sql_query(stmt).execute(&mut conn).await.expect("drop");
        }
    }
    provision_auth_tables(&pool).await.expect("provision");

    let store = DbAuthStore::new(pool.clone(), AuthConfig::default().refresh_lifetimes());
    let now = SystemTime::now();
    let issued = store
        .create_session(&identity("grace"), now)
        .await
        .expect("create");

    // No retained token yet.
    assert!(
        store
            .retained_provider_token(&issued.session_id)
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
        .set_retained_provider_token(&issued.session_id, &first, now)
        .await
        .expect("store");
    let read = store
        .retained_provider_token(&issued.session_id)
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
        .set_retained_provider_token(&issued.session_id, &second, now)
        .await
        .expect("store");
    let read = store
        .retained_provider_token(&issued.session_id)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(read.access_token, "provider-access-2");
    assert_eq!(read.refresh_token, None);
    assert_eq!(read.expires_at, None);
}
