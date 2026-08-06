//! The pluggable auth store: identity mapping, connetto's sessions, and the
//! rotating refresh tokens.
//!
//! Two variants ship. [`InMemoryAuthStore`] holds everything in the process,
//! resolves identity deterministically from `(issuer, subject)`, and is
//! single-server and ephemeral. The database store holds
//! it in Postgres through typed diesel queries, resolves identity through a
//! linking table so one human may hold several logins, and is durable and
//! mesh-capable. See `docs/architecture/11-authentication.md`.
//!
//! The refresh token is `"<session_id>.<secret>"`. Only the SHA-256 of the
//! secret is stored, and every rotation replaces it. A presented secret whose
//! hash does not match the stored one, on a session that still exists, is
//! treated as reuse of a rotated-out token (theft) and revokes the session.

use std::time::SystemTime;

use connetto_core::SessionId;
use connetto_core::auth::AuthContext;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::authn::identity::{IdentityResolver, ResolveError, VerifiedClaims};
use crate::authn::token::RefreshLifetimes;

/// A caller identity resolved from a verified credential, ready to mint a
/// session for. Human-readable fields never serve as identity: only the
/// issuer and subject do, per the identity-mapping rule.
#[derive(Debug, Clone)]
pub struct ResolvedIdentity {
    /// The `iss` claim of the credential the identity was verified from.
    pub issuer: String,
    /// The `sub` claim, locally unique within the issuer.
    pub subject: String,
    /// The verified `email` claim, if the provider asserted one.
    pub email: Option<String>,
    /// The `name` claim, if present.
    pub name: Option<String>,
    /// The `amr` claim: the authentication methods used.
    pub amr: Vec<String>,
    /// The `acr` claim: the authentication context class reference.
    pub acr: Option<String>,
}

impl ResolvedIdentity {
    /// The verified provider claims to hand the [`IdentityResolver`].
    #[must_use]
    pub fn verified_claims(&self) -> VerifiedClaims {
        VerifiedClaims {
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            email: self.email.clone(),
            name: self.name.clone(),
            amr: self.amr.clone(),
            acr: self.acr.clone(),
        }
    }
}

/// A newly minted session: its id, the identity it carries, and the first
/// refresh token to hand the client.
#[derive(Debug, Clone)]
pub struct IssuedSession<Id = String> {
    /// The connetto-minted session id, named by the access token's `sid`.
    pub session_id: SessionId,
    /// The identity the session's access tokens carry.
    pub context: AuthContext<Id>,
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
pub struct RefreshOutcome<Id = String> {
    /// The session that was refreshed.
    pub session_id: SessionId,
    /// The identity to mint the new access token from.
    pub context: AuthContext<Id>,
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
    ///
    /// It names the session so the layer holding the revocation observer can
    /// close whatever connection that session still has open. Without the id
    /// the theft response could only refuse the next handshake, leaving the
    /// live socket streaming, which is the opposite of what a stolen
    /// credential warrants.
    #[error("refresh token reuse detected, session revoked")]
    Reuse {
        /// The session the replayed token named, now revoked.
        session_id: SessionId,
    },
    /// The identity resolver failed to map the verified claims to a user id.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
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
/// startup, the same way the server binary chooses its visibility policy.
pub trait AuthStore: Send + Sync {
    /// The developer-defined distributed user id this store resolves identities
    /// to and keys sessions on. connetto serializes it into the access-token
    /// claim (both ways), renders it to the RLS GUC through `Display`, and
    /// shares it across the runtime, so the full invariant lives here once.
    type Id: serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + core::fmt::Display
        + Send
        + Sync
        + 'static;

    /// Resolve `identity` to a `user_id`, create a session, and return it with
    /// its first refresh token. `now` seeds the refresh deadlines.
    fn create_session(
        &self,
        identity: &ResolvedIdentity,
        now: SystemTime,
    ) -> impl Future<Output = Result<IssuedSession<Self::Id>, AuthStoreError>> + Send;

    /// Whether the session still exists, is not revoked, and is within its
    /// absolute ceiling. This is the handshake liveness check that makes
    /// revocation authoritative.
    fn session_is_live(
        &self,
        session_id: SessionId,
        now: SystemTime,
    ) -> impl Future<Output = Result<bool, AuthStoreError>> + Send;

    /// Validate the presented refresh token, rotate it, extend the idle window,
    /// and return the rotated token plus the identity to re-mint access from.
    fn rotate_refresh(
        &self,
        refresh_token: &str,
        now: SystemTime,
    ) -> impl Future<Output = Result<RefreshOutcome<Self::Id>, AuthStoreError>> + Send;

    /// Revoke the session, refusing it on the next handshake even while its
    /// access token is still time-valid.
    fn revoke_session(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<(), AuthStoreError>> + Send;

    /// The session a presented refresh token names, once its secret is
    /// verified, or `None` when no live session matches.
    ///
    /// This is the authentication a logout needs: the caller holds the
    /// credential it wants torn down, and nothing else identifies the session
    /// to revoke. Unlike [`rotate_refresh`](Self::rotate_refresh) it does not
    /// rotate, and a mismatched secret is `None` rather than a theft signal,
    /// because an endpoint whose only effect is revocation must not become an
    /// oracle for guessed session ids.
    fn session_for_refresh(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<SessionId>, AuthStoreError>> + Send;

    /// Store the retained provider tokens for a session, replacing any existing.
    fn set_retained_provider_token(
        &self,
        session_id: SessionId,
        token: &crate::authn::provider::RetainedProviderToken,
        now: SystemTime,
    ) -> impl Future<Output = Result<(), AuthStoreError>> + Send;

    /// Read a session's retained provider tokens, if any were stored.
    fn retained_provider_token(
        &self,
        session_id: SessionId,
    ) -> impl Future<
        Output = Result<Option<crate::authn::provider::RetainedProviderToken>, AuthStoreError>,
    > + Send;
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

/// Mint a fresh session id. connetto-core carries no random number generator,
/// so the randomness belongs here, at the login that owns the session.
fn new_session_id() -> SessionId {
    SessionId::from_uuid(Uuid::new_v4())
}

/// Assemble the wire refresh token from a session id and secret.
///
/// One of the two sanctioned textual edges for a session id (the other is the
/// JWT `sid` claim). Everywhere else it moves as bytes.
fn format_refresh(session_id: SessionId, secret: &str) -> String {
    format!("{session_id}.{secret}")
}

/// Split a wire refresh token into its session id and secret.
///
/// A malformed id half is not found rather than an error shape of its own: a
/// caller may present anything here, and an unparseable id names no session.
pub(crate) fn split_refresh(token: &str) -> Option<(SessionId, &str)> {
    let (id, secret) = token.split_once('.')?;
    Some((id.parse().ok()?, secret))
}

/// The in-memory auth store. Single-server and ephemeral: a restart drops every
/// session and forces re-login. Identity resolves through a supplied resolver
/// (deterministic UUID v5 by default), so no lookup and no linking table.
pub struct InMemoryAuthStore<Id = String> {
    lifetimes: RefreshLifetimes,
    sessions: std::sync::Mutex<std::collections::HashMap<SessionId, SessionRecord<Id>>>,
    resolver: std::sync::Arc<dyn IdentityResolver<Id = Id>>,
}

struct SessionRecord<Id> {
    context: AuthContext<Id>,
    current_refresh_hash: [u8; 32],
    idle_deadline: SystemTime,
    absolute_deadline: SystemTime,
    revoked: bool,
    retained: Option<crate::authn::provider::RetainedProviderToken>,
}

impl InMemoryAuthStore<String> {
    /// Build an empty store enforcing `lifetimes`, resolving identity to a
    /// deterministic UUID v5 string over `(issuer, subject)`.
    #[must_use]
    pub fn new(lifetimes: RefreshLifetimes) -> Self {
        Self::with_resolver(
            lifetimes,
            std::sync::Arc::new(crate::authn::identity::DefaultUuidResolver),
        )
    }
}

impl<Id> InMemoryAuthStore<Id> {
    /// Build an empty store enforcing `lifetimes`, resolving each verified
    /// identity to a typed `Id` through `resolver`. This is the in-memory
    /// path for the developer's [`IdentityResolver`].
    #[must_use]
    pub fn with_resolver(
        lifetimes: RefreshLifetimes,
        resolver: std::sync::Arc<dyn IdentityResolver<Id = Id>>,
    ) -> Self {
        Self {
            lifetimes,
            sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
            resolver,
        }
    }
}

impl<
    Id: serde::Serialize
        + serde::de::DeserializeOwned
        + Clone
        + core::fmt::Display
        + Send
        + Sync
        + 'static,
> AuthStore for InMemoryAuthStore<Id>
{
    type Id = Id;

    async fn create_session(
        &self,
        identity: &ResolvedIdentity,
        now: SystemTime,
    ) -> Result<IssuedSession<Id>, AuthStoreError> {
        let user_id = self.resolver.resolve(&identity.verified_claims()).await?;
        let context = AuthContext { user_id };
        let session_id = new_session_id();
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
            .insert(session_id, record);
        let refresh_token = format_refresh(session_id, &secret);
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
        session_id: SessionId,
        now: SystemTime,
    ) -> Result<bool, AuthStoreError> {
        let sessions = self.sessions.lock().expect("auth store lock");
        Ok(sessions
            .get(&session_id)
            .is_some_and(|record| !record.revoked && now <= record.absolute_deadline))
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn rotate_refresh(
        &self,
        refresh_token: &str,
        now: SystemTime,
    ) -> Result<RefreshOutcome<Id>, AuthStoreError> {
        let (session_id, secret) = split_refresh(refresh_token).ok_or(AuthStoreError::NotFound)?;
        let mut sessions = self.sessions.lock().expect("auth store lock");
        let record = sessions
            .get_mut(&session_id)
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
            return Err(AuthStoreError::Reuse { session_id });
        }
        let new_secret = new_refresh_secret();
        record.current_refresh_hash = hash_secret(&new_secret);
        record.idle_deadline = (now + self.lifetimes.idle_window).min(record.absolute_deadline);
        Ok(RefreshOutcome {
            session_id,
            context: record.context.clone(),
            refresh_token: format_refresh(session_id, &new_secret),
            session_expires_at: record.idle_deadline,
        })
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn revoke_session(&self, session_id: SessionId) -> Result<(), AuthStoreError> {
        if let Some(record) = self
            .sessions
            .lock()
            .expect("auth store lock")
            .get_mut(&session_id)
        {
            record.revoked = true;
        }
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn session_for_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<Option<SessionId>, AuthStoreError> {
        let Some((session_id, secret)) = split_refresh(refresh_token) else {
            return Ok(None);
        };
        let sessions = self.sessions.lock().expect("auth store lock");
        let Some(record) = sessions.get(&session_id) else {
            return Ok(None);
        };
        if record.revoked || !hashes_match(&hash_secret(secret), &record.current_refresh_hash) {
            return Ok(None);
        }
        Ok(Some(session_id))
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn set_retained_provider_token(
        &self,
        session_id: SessionId,
        token: &crate::authn::provider::RetainedProviderToken,
        _now: SystemTime,
    ) -> Result<(), AuthStoreError> {
        if let Some(record) = self
            .sessions
            .lock()
            .expect("auth store lock")
            .get_mut(&session_id)
        {
            record.retained = Some(token.clone());
        }
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn retained_provider_token(
        &self,
        session_id: SessionId,
    ) -> Result<Option<crate::authn::provider::RetainedProviderToken>, AuthStoreError> {
        Ok(self
            .sessions
            .lock()
            .expect("auth store lock")
            .get(&session_id)
            .and_then(|record| record.retained.clone()))
    }
}

pub use db::DbAuthStore;

mod db {
    use std::sync::Arc;
    use std::time::SystemTime;

    use connetto_core::SessionId;
    use connetto_core::auth::AuthContext;
    use diesel::prelude::*;
    use diesel::query_dsl::methods::{FilterDsl, SelectDsl};
    use diesel_async::pooled_connection::bb8::Pool;
    use diesel_async::scoped_futures::ScopedFutureExt;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

    use super::{
        AuthStore, AuthStoreError, IssuedSession, RefreshOutcome, ResolvedIdentity, format_refresh,
        hash_secret, hashes_match, new_refresh_secret, new_session_id, split_refresh,
    };
    use crate::authn::identity::IdentityResolver;
    use crate::authn::provider::RetainedProviderToken;
    use crate::authn::schema::{ConnettoStoreSchema, Instant};
    use crate::authn::token::RefreshLifetimes;

    /// The rotation columns a `SELECT ... FOR UPDATE` loads: the typed
    /// `user_id`, the refresh hash, and the two deadlines plus the revoked
    /// flag.
    type SessionRow<S> = (
        <S as ConnettoStoreSchema>::Id,
        Vec<u8>,
        Instant,
        Instant,
        bool,
    );

    /// The Postgres auth store, generic over the deployment's schema. Durable
    /// across restart and the only variant that backs a mesh. Identity resolves
    /// through the deployment's [`IdentityResolver`], which owns the users table
    /// the `sessions.user_id` column foreign-keys, so connetto owns no schema.
    pub struct DbAuthStore<S: ConnettoStoreSchema> {
        pool: Pool<AsyncPgConnection>,
        lifetimes: RefreshLifetimes,
        resolver: Arc<dyn IdentityResolver<Id = S::Id>>,
    }

    impl<S: ConnettoStoreSchema> DbAuthStore<S> {
        /// Build over a connection pool, resolving identity through `resolver`.
        #[must_use]
        pub fn new(
            pool: Pool<AsyncPgConnection>,
            lifetimes: RefreshLifetimes,
            resolver: Arc<dyn IdentityResolver<Id = S::Id>>,
        ) -> Self {
            Self {
                pool,
                lifetimes,
                resolver,
            }
        }
    }

    fn backend<E: core::fmt::Display>(err: E) -> AuthStoreError {
        AuthStoreError::Backend(err.to_string())
    }

    /// The instant a `Timestamptz` column carries, from the `SystemTime` the
    /// [`AuthStore`] API speaks. Total and lossless in both directions, unlike
    /// the count of milliseconds these columns used to hold.
    fn to_instant(time: SystemTime) -> Instant {
        Instant::from(time)
    }

    fn from_instant(instant: Instant) -> SystemTime {
        instant.into()
    }

    impl<S: ConnettoStoreSchema> AuthStore for DbAuthStore<S> {
        type Id = S::Id;

        async fn create_session(
            &self,
            identity: &ResolvedIdentity,
            now: SystemTime,
        ) -> Result<IssuedSession<S::Id>, AuthStoreError> {
            let user_id = self.resolver.resolve(&identity.verified_claims()).await?;
            let idle = to_instant(now + self.lifetimes.idle_window);
            let absolute = to_instant(now + self.lifetimes.absolute_ceiling);
            let secret = new_refresh_secret();
            let refresh_hash = hash_secret(&secret).to_vec();
            let session_id = new_session_id();
            let row = S::new_session(
                session_id,
                user_id.clone(),
                refresh_hash,
                idle,
                absolute,
                false,
            );
            let mut conn = self.pool.get().await.map_err(backend)?;
            diesel::insert_into(S::Sessions::default())
                .values(row)
                .execute(&mut conn)
                .await
                .map_err(backend)?;
            let context = AuthContext { user_id };
            Ok(IssuedSession {
                session_id,
                context,
                refresh_token: format_refresh(session_id, &secret),
                session_expires_at: from_instant(idle.min(absolute)),
            })
        }

        async fn session_is_live(
            &self,
            session_id: SessionId,
            now: SystemTime,
        ) -> Result<bool, AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            let now = to_instant(now);
            let base = FilterDsl::filter(S::SessionsQuery::default(), S::session_pk(session_id));
            let query = SelectDsl::select(
                base,
                (S::Revoked::default(), S::AbsoluteDeadline::default()),
            );
            let live: Option<(bool, Instant)> =
                query.first(&mut conn).await.optional().map_err(backend)?;
            Ok(live.is_some_and(|(revoked, absolute)| !revoked && now <= absolute))
        }

        async fn rotate_refresh(
            &self,
            refresh_token: &str,
            now: SystemTime,
        ) -> Result<RefreshOutcome<S::Id>, AuthStoreError> {
            let (session_id, secret) =
                split_refresh(refresh_token).ok_or(AuthStoreError::NotFound)?;
            let presented_hash = hash_secret(secret).to_vec();
            let idle = to_instant(now + self.lifetimes.idle_window);
            let now = to_instant(now);
            let new_secret = new_refresh_secret();
            let new_hash = hash_secret(&new_secret).to_vec();
            let mut conn = self.pool.get().await.map_err(backend)?;
            let outcome = {
                conn.transaction::<_, AuthStoreError, _>(|conn| {
                    async move {
                        // Lock the row so two concurrent refreshers cannot both
                        // rotate and trip the reuse defense.
                        let row: Option<SessionRow<S>> = S::session_row_for_update(session_id)
                            .get_result(conn)
                            .await
                            .optional()
                            .map_err(backend)?;
                        let (user_id, current_hash, idle_deadline, absolute_deadline, revoked) =
                            row.ok_or(AuthStoreError::NotFound)?;
                        if revoked {
                            return Err(AuthStoreError::NotFound);
                        }
                        if now > absolute_deadline || now > idle_deadline {
                            return Err(AuthStoreError::Expired);
                        }
                        if !hashes_match(&presented_hash, &current_hash) {
                            // Reuse of a rotated-out token. Signal theft, but do
                            // not revoke inside the transaction: returning an
                            // error rolls it back, so the revoke lands below in
                            // its own committed statement.
                            return Err(AuthStoreError::Reuse { session_id });
                        }
                        let capped_idle = idle.min(absolute_deadline);
                        S::rotation_update(session_id, new_hash, capped_idle)
                            .execute(conn)
                            .await
                            .map_err(backend)?;
                        let context = AuthContext { user_id };
                        Ok(RefreshOutcome {
                            session_id,
                            context,
                            refresh_token: format_refresh(session_id, &new_secret),
                            session_expires_at: from_instant(capped_idle),
                        })
                    }
                    .scope_boxed()
                })
                .await
            };
            if matches!(outcome, Err(AuthStoreError::Reuse { .. })) {
                S::revoke_update(session_id)
                    .execute(&mut conn)
                    .await
                    .map_err(backend)?;
            }
            outcome
        }

        async fn revoke_session(&self, session_id: SessionId) -> Result<(), AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            S::revoke_update(session_id)
                .execute(&mut conn)
                .await
                .map_err(backend)?;
            Ok(())
        }

        async fn session_for_refresh(
            &self,
            refresh_token: &str,
        ) -> Result<Option<SessionId>, AuthStoreError> {
            let Some((session_id, secret)) = split_refresh(refresh_token) else {
                return Ok(None);
            };
            let presented_hash = hash_secret(secret).to_vec();
            let mut conn = self.pool.get().await.map_err(backend)?;
            // The rotation read is reused rather than adding a narrower one to
            // the schema trait: it already selects the refresh hash and the
            // revoked flag, and its row lock serializes a logout against a
            // refresh landing at the same moment.
            let row: Option<SessionRow<S>> = S::session_row_for_update(session_id)
                .get_result(&mut conn)
                .await
                .optional()
                .map_err(backend)?;
            let Some((_, current_hash, _, _, revoked)) = row else {
                return Ok(None);
            };
            if revoked || !hashes_match(&presented_hash, &current_hash) {
                return Ok(None);
            }
            Ok(Some(session_id))
        }

        async fn set_retained_provider_token(
            &self,
            session_id: SessionId,
            token: &RetainedProviderToken,
            _now: SystemTime,
        ) -> Result<(), AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            let expires_at = token.expires_at.map(to_instant);
            let row = S::new_provider_token(
                session_id,
                token.issuer.clone(),
                token.access_token.clone(),
                token.refresh_token.clone(),
                expires_at,
            );
            diesel::insert_into(S::ProviderTokens::default())
                .values(row)
                .on_conflict(S::PtSessionId::default())
                .do_update()
                .set((
                    S::PtIssuer::default().eq(token.issuer.clone()),
                    S::PtAccessToken::default().eq(token.access_token.clone()),
                    S::PtRefreshToken::default().eq(token.refresh_token.clone()),
                    S::PtExpiresAt::default().eq(expires_at),
                ))
                .execute(&mut conn)
                .await
                .map_err(backend)?;
            Ok(())
        }

        async fn retained_provider_token(
            &self,
            session_id: SessionId,
        ) -> Result<Option<RetainedProviderToken>, AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            let base = FilterDsl::filter(S::ProviderTokensQuery::default(), S::pt_pk(session_id));
            let query = SelectDsl::select(
                base,
                (
                    S::PtIssuer::default(),
                    S::PtAccessToken::default(),
                    S::PtRefreshToken::default(),
                    S::PtExpiresAt::default(),
                ),
            );
            let row: Option<(String, String, Option<String>, Option<Instant>)> =
                query.first(&mut conn).await.optional().map_err(backend)?;
            Ok(row.map(
                |(issuer, access_token, refresh_token, expires_at)| RetainedProviderToken {
                    issuer,
                    access_token,
                    refresh_token,
                    expires_at: expires_at.map(from_instant),
                },
            ))
        }
    }
}
