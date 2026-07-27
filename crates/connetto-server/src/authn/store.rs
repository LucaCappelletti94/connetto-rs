//! The pluggable auth store: identity mapping, connetto's sessions, and the
//! rotating refresh tokens.
//!
//! Two variants ship. [`InMemoryAuthStore`] holds everything in the process,
//! resolves identity deterministically from `(issuer, subject)`, and is
//! single-server and ephemeral. The database store (feature `pg-async`) holds
//! it in Postgres through typed diesel queries, resolves identity through a
//! linking table so one human may hold several logins, and is durable and
//! mesh-capable. See `docs/architecture/11-authentication.md`.
//!
//! The refresh token is `"<session_id>.<secret>"`. Only the SHA-256 of the
//! secret is stored, and every rotation replaces it. A presented secret whose
//! hash does not match the stored one, on a session that still exists, is
//! treated as reuse of a rotated-out token (theft) and revokes the session.

use std::collections::BTreeMap;
use std::time::SystemTime;

use connetto_core::auth::AuthContext;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::authn::token::RefreshLifetimes;

/// Namespace for the deterministic `(issuer, subject)` to `user_id` mapping in
/// the in-memory store. A fixed random UUID, per `OpenID Connect Core` 5.7 which
/// makes the issuer-and-subject pair the only guaranteed unique identifier.
const CONNETTO_ID_NAMESPACE: Uuid = Uuid::from_u128(0x1d3f_9c8a_4b62_4f1e_9a7d_2c5e_8b0f_6a41);

/// A caller identity resolved from a verified credential, ready to mint a
/// session for. Human-readable fields never appear here as identity, only the
/// issuer and subject do, per the identity-mapping rule.
#[derive(Debug, Clone)]
pub struct ResolvedIdentity {
    /// The `iss` claim of the credential the identity was verified from.
    pub issuer: String,
    /// The `sub` claim, locally unique within the issuer.
    pub subject: String,
    /// Optional tenant for multi-tenant deployments.
    pub tenant_id: Option<String>,
    /// Roles to attach to the session.
    pub roles: Vec<String>,
    /// Extra claims to carry into the session.
    pub claims: BTreeMap<String, String>,
}

impl ResolvedIdentity {
    /// Build the [`AuthContext`] this identity maps to under `user_id`.
    fn into_context(self, user_id: String) -> AuthContext {
        AuthContext {
            user_id,
            tenant_id: self.tenant_id,
            roles: self.roles,
            claims: self.claims,
        }
    }
}

/// A newly minted session: its id, the identity it carries, and the first
/// refresh token to hand the client.
#[derive(Debug, Clone)]
pub struct IssuedSession {
    /// The opaque session id, named by the access token's `sid`.
    pub session_id: String,
    /// The identity the session's access tokens carry.
    pub context: AuthContext,
    /// The refresh token to hand the client. Presented back to rotate.
    pub refresh_token: String,
    /// When this session stops being refreshable if never used again: the
    /// smaller of the idle deadline and the absolute ceiling. The client
    /// keeps it to warn before an offline session lapses with unsynced data.
    pub session_expires_at: SystemTime,
}

/// The result of a successful refresh: the rotated token plus the identity to
/// mint the new access token from.
#[derive(Debug, Clone)]
pub struct RefreshOutcome {
    /// The session that was refreshed.
    pub session_id: String,
    /// The identity to mint the new access token from.
    pub context: AuthContext,
    /// The rotated refresh token, replacing the presented one.
    pub refresh_token: String,
    /// When this session stops being refreshable if never used again, the
    /// smaller of the (freshly slid) idle deadline and the absolute ceiling.
    pub session_expires_at: SystemTime,
}

/// Failure surfaced by an [`AuthStore`].
#[derive(Debug, thiserror::Error)]
pub enum AuthStoreError {
    /// No session matched, or the presented token was malformed.
    #[error("no such session")]
    NotFound,
    /// The refresh token is past its idle window or absolute ceiling.
    #[error("refresh token expired")]
    Expired,
    /// A rotated-out refresh token was presented for a live session. The
    /// session was revoked as a theft response.
    #[error("refresh token reuse detected, session revoked")]
    Reuse,
    /// The backing store failed.
    #[error("auth store backend error: {0}")]
    Backend(String),
}

impl From<diesel::result::Error> for AuthStoreError {
    fn from(err: diesel::result::Error) -> Self {
        Self::Backend(err.to_string())
    }
}

/// The identity mapping, connetto's sessions, and the rotating refresh tokens.
///
/// Methods return `impl Future + Send` (not `async fn`) so a generic caller
/// (the session verifier boxed into a `Send` future, the async endpoints) stays
/// `Send` on the multi-threaded runtime. The concrete store is chosen at
/// startup, mirroring the `AuthPolicy` enum pattern in the server binary.
pub trait AuthStore: Send + Sync {
    /// Resolve `identity` to a `user_id`, create a session, and return it with
    /// its first refresh token. `now` seeds the refresh deadlines.
    fn create_session(
        &self,
        identity: &ResolvedIdentity,
        now: SystemTime,
    ) -> impl Future<Output = Result<IssuedSession, AuthStoreError>> + Send;

    /// Whether the session still exists, is not revoked, and is within its
    /// absolute ceiling. This is the handshake liveness check that makes
    /// revocation authoritative.
    fn session_is_live(
        &self,
        session_id: &str,
        now: SystemTime,
    ) -> impl Future<Output = Result<bool, AuthStoreError>> + Send;

    /// Validate the presented refresh token, rotate it, extend the idle window,
    /// and return the rotated token plus the identity to re-mint access from.
    fn rotate_refresh(
        &self,
        refresh_token: &str,
        now: SystemTime,
    ) -> impl Future<Output = Result<RefreshOutcome, AuthStoreError>> + Send;

    /// Revoke the session, refusing it on the next handshake even while its
    /// access token is still time-valid.
    fn revoke_session(
        &self,
        session_id: &str,
    ) -> impl Future<Output = Result<(), AuthStoreError>> + Send;

    /// Store the retained provider tokens for a session, replacing any existing.
    fn set_retained_provider_token(
        &self,
        session_id: &str,
        token: &crate::authn::provider::RetainedProviderToken,
        now: SystemTime,
    ) -> impl Future<Output = Result<(), AuthStoreError>> + Send;

    /// Read a session's retained provider tokens, if any were stored.
    fn retained_provider_token(
        &self,
        session_id: &str,
    ) -> impl Future<
        Output = Result<Option<crate::authn::provider::RetainedProviderToken>, AuthStoreError>,
    > + Send;
}

/// The deterministic `(issuer, subject)` to `user_id` mapping (UUID v5).
fn deterministic_user_id(issuer: &str, subject: &str) -> String {
    Uuid::new_v5(
        &CONNETTO_ID_NAMESPACE,
        format!("{issuer}|{subject}").as_bytes(),
    )
    .to_string()
}

/// A fresh 256-bit refresh secret as hex.
fn new_refresh_secret() -> String {
    format!(
        "{}{}",
        Uuid::new_v4().as_simple(),
        Uuid::new_v4().as_simple()
    )
}

/// SHA-256 of a refresh secret, the only form stored.
fn hash_secret(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.finalize().into()
}

/// Constant-time equality of two refresh-secret hashes, so the comparison
/// cannot leak how many leading bytes matched through timing.
fn hashes_match(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    a.ct_eq(b).into()
}

/// Assemble the wire refresh token from a session id and secret.
fn format_refresh(session_id: &str, secret: &str) -> String {
    format!("{session_id}.{secret}")
}

/// Split a wire refresh token into its session id and secret.
fn split_refresh(token: &str) -> Option<(&str, &str)> {
    token.split_once('.')
}

/// The in-memory auth store. Single-server and ephemeral: a restart drops every
/// session and forces re-login. Identity resolves deterministically, so no
/// lookup and no linking table.
pub struct InMemoryAuthStore {
    lifetimes: RefreshLifetimes,
    sessions: std::sync::Mutex<std::collections::HashMap<String, SessionRecord>>,
}

struct SessionRecord {
    context: AuthContext,
    current_refresh_hash: [u8; 32],
    idle_deadline: SystemTime,
    absolute_deadline: SystemTime,
    revoked: bool,
    retained: Option<crate::authn::provider::RetainedProviderToken>,
}

impl InMemoryAuthStore {
    /// Build an empty store enforcing `lifetimes`.
    #[must_use]
    pub fn new(lifetimes: RefreshLifetimes) -> Self {
        Self {
            lifetimes,
            sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl AuthStore for InMemoryAuthStore {
    #[allow(clippy::unused_async_trait_impl)]
    async fn create_session(
        &self,
        identity: &ResolvedIdentity,
        now: SystemTime,
    ) -> Result<IssuedSession, AuthStoreError> {
        let user_id = deterministic_user_id(&identity.issuer, &identity.subject);
        let context = identity.clone().into_context(user_id);
        let session_id = Uuid::new_v4().to_string();
        let secret = new_refresh_secret();
        let record = SessionRecord {
            context: context.clone(),
            current_refresh_hash: hash_secret(&secret),
            idle_deadline: now + self.lifetimes.idle_window,
            absolute_deadline: now + self.lifetimes.absolute_ceiling,
            revoked: false,
            retained: None,
        };
        self.sessions
            .lock()
            .expect("auth store lock")
            .insert(session_id.clone(), record);
        let refresh_token = format_refresh(&session_id, &secret);
        Ok(IssuedSession {
            session_id,
            context,
            refresh_token,
            session_expires_at: (now + self.lifetimes.idle_window)
                .min(now + self.lifetimes.absolute_ceiling),
        })
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn session_is_live(
        &self,
        session_id: &str,
        now: SystemTime,
    ) -> Result<bool, AuthStoreError> {
        let sessions = self.sessions.lock().expect("auth store lock");
        Ok(sessions
            .get(session_id)
            .is_some_and(|record| !record.revoked && now <= record.absolute_deadline))
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn rotate_refresh(
        &self,
        refresh_token: &str,
        now: SystemTime,
    ) -> Result<RefreshOutcome, AuthStoreError> {
        let (session_id, secret) = split_refresh(refresh_token).ok_or(AuthStoreError::NotFound)?;
        let mut sessions = self.sessions.lock().expect("auth store lock");
        let record = sessions
            .get_mut(session_id)
            .ok_or(AuthStoreError::NotFound)?;
        if record.revoked {
            return Err(AuthStoreError::NotFound);
        }
        if now > record.absolute_deadline || now > record.idle_deadline {
            return Err(AuthStoreError::Expired);
        }
        if !hashes_match(&hash_secret(secret), &record.current_refresh_hash) {
            // A rotated-out token for a live session: treat as theft.
            record.revoked = true;
            return Err(AuthStoreError::Reuse);
        }
        let new_secret = new_refresh_secret();
        record.current_refresh_hash = hash_secret(&new_secret);
        record.idle_deadline = (now + self.lifetimes.idle_window).min(record.absolute_deadline);
        Ok(RefreshOutcome {
            session_id: session_id.to_owned(),
            context: record.context.clone(),
            refresh_token: format_refresh(session_id, &new_secret),
            session_expires_at: record.idle_deadline,
        })
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn revoke_session(&self, session_id: &str) -> Result<(), AuthStoreError> {
        if let Some(record) = self
            .sessions
            .lock()
            .expect("auth store lock")
            .get_mut(session_id)
        {
            record.revoked = true;
        }
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn set_retained_provider_token(
        &self,
        session_id: &str,
        token: &crate::authn::provider::RetainedProviderToken,
        _now: SystemTime,
    ) -> Result<(), AuthStoreError> {
        if let Some(record) = self
            .sessions
            .lock()
            .expect("auth store lock")
            .get_mut(session_id)
        {
            record.retained = Some(token.clone());
        }
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn retained_provider_token(
        &self,
        session_id: &str,
    ) -> Result<Option<crate::authn::provider::RetainedProviderToken>, AuthStoreError> {
        Ok(self
            .sessions
            .lock()
            .expect("auth store lock")
            .get(session_id)
            .and_then(|record| record.retained.clone()))
    }
}

#[cfg(feature = "pg-async")]
pub use db::{DbAuthStore, provision_auth_tables};

#[cfg(feature = "pg-async")]
mod db {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use connetto_core::auth::AuthContext;
    use diesel::prelude::*;
    use diesel_async::pooled_connection::bb8::Pool;
    use diesel_async::scoped_futures::ScopedFutureExt;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
    use uuid::Uuid;

    use super::{
        AuthStore, AuthStoreError, IssuedSession, RefreshOutcome, ResolvedIdentity, format_refresh,
        hash_secret, hashes_match, new_refresh_secret, split_refresh,
    };
    use crate::authn::provider::RetainedProviderToken;
    use crate::authn::token::RefreshLifetimes;

    diesel::table! {
        connetto_identities (issuer, subject) {
            issuer -> Text,
            subject -> Text,
            user_id -> Text,
        }
    }

    diesel::table! {
        connetto_sessions (session_id) {
            session_id -> Text,
            user_id -> Text,
            context -> Jsonb,
            current_refresh_hash -> Binary,
            idle_deadline_ms -> BigInt,
            absolute_deadline_ms -> BigInt,
            revoked -> Bool,
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = connetto_identities)]
    struct NewIdentity<'a> {
        issuer: &'a str,
        subject: &'a str,
        user_id: &'a str,
    }

    #[derive(Insertable)]
    #[diesel(table_name = connetto_sessions)]
    struct NewSession {
        session_id: String,
        user_id: String,
        context: serde_json::Value,
        current_refresh_hash: Vec<u8>,
        idle_deadline_ms: i64,
        absolute_deadline_ms: i64,
        revoked: bool,
    }

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = connetto_sessions)]
    struct SessionRow {
        context: serde_json::Value,
        current_refresh_hash: Vec<u8>,
        idle_deadline_ms: i64,
        absolute_deadline_ms: i64,
        revoked: bool,
    }

    diesel::table! {
        connetto_provider_tokens (session_id) {
            session_id -> Text,
            issuer -> Text,
            access_token -> Text,
            refresh_token -> Nullable<Text>,
            expires_at_ms -> Nullable<BigInt>,
        }
    }

    #[derive(Insertable)]
    #[diesel(table_name = connetto_provider_tokens)]
    struct NewProviderToken {
        session_id: String,
        issuer: String,
        access_token: String,
        refresh_token: Option<String>,
        expires_at_ms: Option<i64>,
    }

    #[derive(Queryable, Selectable)]
    #[diesel(table_name = connetto_provider_tokens)]
    struct ProviderTokenRow {
        issuer: String,
        access_token: String,
        refresh_token: Option<String>,
        expires_at_ms: Option<i64>,
    }

    /// The Postgres auth store. Durable across restart and the only variant that
    /// backs a mesh, where its rows replicate like any other. Identity resolves
    /// through the `connetto_identities` linking table, so the deployment owns
    /// its ids and one human may link several logins.
    pub struct DbAuthStore {
        pool: Pool<AsyncPgConnection>,
        lifetimes: RefreshLifetimes,
    }

    impl DbAuthStore {
        /// Build over a connection pool enforcing `lifetimes`.
        #[must_use]
        pub fn new(pool: Pool<AsyncPgConnection>, lifetimes: RefreshLifetimes) -> Self {
            Self { pool, lifetimes }
        }
    }

    fn backend<E: core::fmt::Display>(err: E) -> AuthStoreError {
        AuthStoreError::Backend(err.to_string())
    }

    fn unix_ms(time: SystemTime) -> i64 {
        i64::try_from(
            time.duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_millis(),
        )
        .unwrap_or(i64::MAX)
    }

    fn time_from_ms(ms: i64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(u64::try_from(ms).unwrap_or(0))
    }

    fn context_to_json(context: &AuthContext) -> Result<serde_json::Value, AuthStoreError> {
        serde_json::to_value(context).map_err(backend)
    }

    fn context_from_json(value: serde_json::Value) -> Result<AuthContext, AuthStoreError> {
        serde_json::from_value(value).map_err(backend)
    }

    impl AuthStore for DbAuthStore {
        async fn create_session(
            &self,
            identity: &ResolvedIdentity,
            now: SystemTime,
        ) -> Result<IssuedSession, AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            let idle = unix_ms(now + self.lifetimes.idle_window);
            let absolute = unix_ms(now + self.lifetimes.absolute_ceiling);
            let secret = new_refresh_secret();
            let refresh_hash = hash_secret(&secret).to_vec();
            let session_id = Uuid::new_v4().to_string();
            let identity = identity.clone();
            let issued = conn
                .transaction::<_, AuthStoreError, _>(|conn| {
                    async move {
                        // Resolve or mint the deployment-owned user id.
                        let existing: Option<String> = connetto_identities::table
                            .filter(connetto_identities::issuer.eq(&identity.issuer))
                            .filter(connetto_identities::subject.eq(&identity.subject))
                            .select(connetto_identities::user_id)
                            .first(conn)
                            .await
                            .optional()
                            .map_err(backend)?;
                        let user_id = if let Some(user_id) = existing {
                            user_id
                        } else {
                            let user_id = Uuid::new_v4().to_string();
                            diesel::insert_into(connetto_identities::table)
                                .values(NewIdentity {
                                    issuer: &identity.issuer,
                                    subject: &identity.subject,
                                    user_id: &user_id,
                                })
                                .execute(conn)
                                .await
                                .map_err(backend)?;
                            user_id
                        };
                        let context = identity.into_context(user_id.clone());
                        diesel::insert_into(connetto_sessions::table)
                            .values(NewSession {
                                session_id: session_id.clone(),
                                user_id,
                                context: context_to_json(&context)?,
                                current_refresh_hash: refresh_hash,
                                idle_deadline_ms: idle,
                                absolute_deadline_ms: absolute,
                                revoked: false,
                            })
                            .execute(conn)
                            .await
                            .map_err(backend)?;
                        Ok(IssuedSession {
                            session_id: session_id.clone(),
                            context,
                            refresh_token: format_refresh(&session_id, &secret),
                            session_expires_at: time_from_ms(idle.min(absolute)),
                        })
                    }
                    .scope_boxed()
                })
                .await?;
            Ok(issued)
        }

        async fn session_is_live(
            &self,
            session_id: &str,
            now: SystemTime,
        ) -> Result<bool, AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            let now_ms = unix_ms(now);
            let live: Option<(bool, i64)> = connetto_sessions::table
                .filter(connetto_sessions::session_id.eq(session_id))
                .select((
                    connetto_sessions::revoked,
                    connetto_sessions::absolute_deadline_ms,
                ))
                .first(&mut conn)
                .await
                .optional()
                .map_err(backend)?;
            Ok(live.is_some_and(|(revoked, absolute)| !revoked && now_ms <= absolute))
        }

        async fn rotate_refresh(
            &self,
            refresh_token: &str,
            now: SystemTime,
        ) -> Result<RefreshOutcome, AuthStoreError> {
            let (session_id, secret) =
                split_refresh(refresh_token).ok_or(AuthStoreError::NotFound)?;
            let session_id = session_id.to_owned();
            let presented_hash = hash_secret(secret).to_vec();
            let now_ms = unix_ms(now);
            let idle = unix_ms(now + self.lifetimes.idle_window);
            let new_secret = new_refresh_secret();
            let new_hash = hash_secret(&new_secret).to_vec();
            let mut conn = self.pool.get().await.map_err(backend)?;
            let outcome = {
                let session_id = session_id.clone();
                conn.transaction::<_, AuthStoreError, _>(|conn| {
                    async move {
                        // Serialize concurrent refreshers on this row so two cannot
                        // double-rotate and trip the reuse defense.
                        let row: Option<SessionRow> = connetto_sessions::table
                            .filter(connetto_sessions::session_id.eq(&session_id))
                            .select(SessionRow::as_select())
                            .for_update()
                            .first(conn)
                            .await
                            .optional()
                            .map_err(backend)?;
                        let row = row.ok_or(AuthStoreError::NotFound)?;
                        if row.revoked {
                            return Err(AuthStoreError::NotFound);
                        }
                        if now_ms > row.absolute_deadline_ms || now_ms > row.idle_deadline_ms {
                            return Err(AuthStoreError::Expired);
                        }
                        if !hashes_match(&presented_hash, &row.current_refresh_hash) {
                            // Reuse of a rotated-out token. Signal theft, but do
                            // not revoke inside the transaction: returning an
                            // error rolls it back, so the revoke lands below in
                            // its own committed statement.
                            return Err(AuthStoreError::Reuse);
                        }
                        let capped_idle = idle.min(row.absolute_deadline_ms);
                        diesel::update(
                            connetto_sessions::table
                                .filter(connetto_sessions::session_id.eq(&session_id)),
                        )
                        .set((
                            connetto_sessions::current_refresh_hash.eq(&new_hash),
                            connetto_sessions::idle_deadline_ms.eq(capped_idle),
                        ))
                        .execute(conn)
                        .await
                        .map_err(backend)?;
                        let context = context_from_json(row.context)?;
                        Ok(RefreshOutcome {
                            session_id: session_id.clone(),
                            context,
                            refresh_token: format_refresh(&session_id, &new_secret),
                            session_expires_at: time_from_ms(capped_idle),
                        })
                    }
                    .scope_boxed()
                })
                .await
            };
            if matches!(outcome, Err(AuthStoreError::Reuse)) {
                diesel::update(
                    connetto_sessions::table.filter(connetto_sessions::session_id.eq(&session_id)),
                )
                .set(connetto_sessions::revoked.eq(true))
                .execute(&mut conn)
                .await
                .map_err(backend)?;
            }
            outcome
        }

        async fn revoke_session(&self, session_id: &str) -> Result<(), AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            diesel::update(
                connetto_sessions::table.filter(connetto_sessions::session_id.eq(session_id)),
            )
            .set(connetto_sessions::revoked.eq(true))
            .execute(&mut conn)
            .await
            .map_err(backend)?;
            Ok(())
        }

        async fn set_retained_provider_token(
            &self,
            session_id: &str,
            token: &RetainedProviderToken,
            _now: SystemTime,
        ) -> Result<(), AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            let expires_at_ms = token.expires_at.map(unix_ms);
            let row = NewProviderToken {
                session_id: session_id.to_owned(),
                issuer: token.issuer.clone(),
                access_token: token.access_token.clone(),
                refresh_token: token.refresh_token.clone(),
                expires_at_ms,
            };
            diesel::insert_into(connetto_provider_tokens::table)
                .values(&row)
                .on_conflict(connetto_provider_tokens::session_id)
                .do_update()
                .set((
                    connetto_provider_tokens::issuer.eq(&row.issuer),
                    connetto_provider_tokens::access_token.eq(&row.access_token),
                    connetto_provider_tokens::refresh_token.eq(&row.refresh_token),
                    connetto_provider_tokens::expires_at_ms.eq(expires_at_ms),
                ))
                .execute(&mut conn)
                .await
                .map_err(backend)?;
            Ok(())
        }

        async fn retained_provider_token(
            &self,
            session_id: &str,
        ) -> Result<Option<RetainedProviderToken>, AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            let row: Option<ProviderTokenRow> = connetto_provider_tokens::table
                .filter(connetto_provider_tokens::session_id.eq(session_id))
                .select(ProviderTokenRow::as_select())
                .first(&mut conn)
                .await
                .optional()
                .map_err(backend)?;
            Ok(row.map(|row| RetainedProviderToken {
                issuer: row.issuer,
                access_token: row.access_token,
                refresh_token: row.refresh_token,
                expires_at: row.expires_at_ms.map(time_from_ms),
            }))
        }
    }

    /// Provision the auth tables, run under a privileged role like any other
    /// DDL. The tables hold the identity linking map, the sessions with their
    /// rotating refresh hashes, and the retained provider tokens.
    ///
    /// # Errors
    ///
    /// [`AuthStoreError::Backend`] if the pool checkout or the DDL fails.
    pub async fn provision_auth_tables(
        pool: &Pool<AsyncPgConnection>,
    ) -> Result<(), AuthStoreError> {
        let mut conn = pool.get().await.map_err(backend)?;
        // Migration DDL, which the typed DSL does not express.
        diesel::sql_query(
            "CREATE TABLE IF NOT EXISTS connetto_identities \
             (issuer TEXT NOT NULL, subject TEXT NOT NULL, user_id TEXT NOT NULL, \
             PRIMARY KEY (issuer, subject))",
        )
        .execute(&mut conn)
        .await
        .map_err(backend)?;
        diesel::sql_query(
            "CREATE TABLE IF NOT EXISTS connetto_sessions \
             (session_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, context JSONB NOT NULL, \
             current_refresh_hash BYTEA NOT NULL, idle_deadline_ms BIGINT NOT NULL, \
             absolute_deadline_ms BIGINT NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE)",
        )
        .execute(&mut conn)
        .await
        .map_err(backend)?;
        diesel::sql_query(
            "CREATE TABLE IF NOT EXISTS connetto_provider_tokens \
             (session_id TEXT PRIMARY KEY, issuer TEXT NOT NULL, access_token TEXT NOT NULL, \
             refresh_token TEXT, expires_at_ms BIGINT)",
        )
        .execute(&mut conn)
        .await
        .map_err(backend)?;
        Ok(())
    }
}
