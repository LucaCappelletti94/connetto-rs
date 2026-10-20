//! The pluggable auth store: identity mapping, connetto's sessions, and the
//! rotating refresh tokens.
//!
//! Two variants ship. [`InMemoryAuthStore`] holds everything in the process,
//! resolves identity deterministically from `(issuer, subject)`, and is
//! single-server and ephemeral. The database store holds
//! it in Postgres through typed diesel queries, resolves identity through a
//! linking table so one human may hold several logins, and is durable. See `docs/architecture/11-authentication.md`.
//!
//! The refresh token is `"<session_id>.<secret>"`. Only the SHA-256 of the
//! secret is stored, and every rotation replaces it. A presented secret whose
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

    /// Resolve `identity` to a `user_id`, create a session, and return it
    /// with its first refresh token.
    fn create_session(
        &self,
        identity: &ResolvedIdentity,
    ) -> impl Future<Output = Result<IssuedSession<Self::Id>, AuthStoreError>> + Send;

    /// Whether the session still exists, is not revoked, and is within its
    /// absolute ceiling. This is the handshake liveness check that makes
    /// revocation authoritative.
    fn session_is_live(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<bool, AuthStoreError>> + Send;

    /// Validate the presented refresh token, rotate it, extend the idle
    /// window, and return the rotated token plus the identity to re-mint
    /// access from.
    fn rotate_refresh(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<RefreshOutcome<Self::Id>, AuthStoreError>> + Send;

    /// Revoke the session, refusing it on the next handshake even while its
    /// access token is still time-valid.
    fn revoke_session(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<(), AuthStoreError>> + Send;

    /// Revoke every session still live, returning how many were, the answer to a restore that revived rotated refresh tokens.
    fn revoke_every_session(&self) -> impl Future<Output = Result<u64, AuthStoreError>> + Send;

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

    /// Store the retained provider tokens for a session, replacing any
    /// existing.
    fn set_retained_provider_token(
        &self,
        session_id: SessionId,
        token: &crate::authn::provider::RetainedProviderToken,
    ) -> impl Future<Output = Result<(), AuthStoreError>> + Send;

    /// Read a session's retained provider tokens, if any were stored, with
    /// the store's verdict on the access token's lifetime.
    fn retained_provider_token(
        &self,
        session_id: SessionId,
    ) -> impl Future<
        Output = Result<Option<crate::authn::provider::StoredProviderToken>, AuthStoreError>,
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
///
/// It serves one process, so its deadlines live on the process clock, held
/// in a seam that defaults to `SystemTime::now` (chapter 21).
pub struct InMemoryAuthStore<Id = String> {
    lifetimes: RefreshLifetimes,
    sessions: std::sync::Mutex<std::collections::HashMap<SessionId, SessionRecord<Id>>>,
    resolver: std::sync::Arc<dyn IdentityResolver<Id = Id>>,
    clock: std::sync::Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

struct SessionRecord<Id> {
    context: AuthContext<Id>,
    current_refresh_hash: [u8; 32],
    idle_deadline: SystemTime,
    absolute_deadline: SystemTime,
    revoked: bool,
    retained: Option<RetainedRecord>,
}

/// The store's own copy of a session's retained provider tokens, stamped with
/// the expiry the process clock projects.
struct RetainedRecord {
    issuer: String,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<SystemTime>,
}

#[cfg(feature = "test-seams")]
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

#[cfg(feature = "test-seams")]
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
            clock: std::sync::Arc::new(SystemTime::now),
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
    ) -> Result<IssuedSession<Id>, AuthStoreError> {
        let now = (self.clock)();
        let user_id = self.resolver.resolve(&identity.verified_claims()).await?;
        let context = AuthContext { user_id };
        let session_id = new_session_id();
        let secret = new_refresh_secret();
        let record = SessionRecord {
            context: context.clone(),
            current_refresh_hash: hash_secret(&secret),
            idle_deadline: now + self.lifetimes.idle_window(),
            absolute_deadline: now + self.lifetimes.absolute_ceiling(),
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
            session_expires_at: (now + self.lifetimes.idle_window())
                .min(now + self.lifetimes.absolute_ceiling()),
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn session_is_live(&self, session_id: SessionId) -> Result<bool, AuthStoreError> {
        let now = (self.clock)();
        let sessions = self.sessions.lock().expect("auth store lock");
        Ok(sessions
            .get(&session_id)
            .is_some_and(|record| !record.revoked && now <= record.absolute_deadline))
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn rotate_refresh(
        &self,
        refresh_token: &str,
    ) -> Result<RefreshOutcome<Id>, AuthStoreError> {
        let now = (self.clock)();
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
        record.idle_deadline = (now + self.lifetimes.idle_window()).min(record.absolute_deadline);
        Ok(RefreshOutcome {
            session_id,
            context: record.context.clone(),
            refresh_token: format_refresh(session_id, &new_secret),
            session_expires_at: record.idle_deadline,
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
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

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn revoke_every_session(&self) -> Result<u64, AuthStoreError> {
        let mut revoked = 0;
        for record in self
            .sessions
            .lock()
            .expect("auth store lock")
            .values_mut()
            .filter(|record| !record.revoked)
        {
            record.revoked = true;
            revoked += 1;
        }
        Ok(revoked)
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
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

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn set_retained_provider_token(
        &self,
        session_id: SessionId,
        token: &crate::authn::provider::RetainedProviderToken,
    ) -> Result<(), AuthStoreError> {
        let now = (self.clock)();
        let expires_at = token.expires_in.map(|lifetime| now + lifetime);
        if let Some(record) = self
            .sessions
            .lock()
            .expect("auth store lock")
            .get_mut(&session_id)
        {
            record.retained = Some(RetainedRecord {
                issuer: token.issuer.clone(),
                access_token: token.access_token.clone(),
                refresh_token: token.refresh_token.clone(),
                expires_at,
            });
        }
        Ok(())
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn retained_provider_token(
        &self,
        session_id: SessionId,
    ) -> Result<Option<crate::authn::provider::StoredProviderToken>, AuthStoreError> {
        let now = (self.clock)();
        let sessions = self.sessions.lock().expect("auth store lock");
        let Some(record) = sessions.get(&session_id) else {
            return Ok(None);
        };
        Ok(record.retained.as_ref().map(|retained| {
            let still_valid = retained.expires_at.is_none_or(|deadline| {
                deadline > now + crate::authn::provider::PROVIDER_TOKEN_MARGIN
            });
            crate::authn::provider::StoredProviderToken {
                issuer: retained.issuer.clone(),
                access_token: retained.access_token.clone(),
                refresh_token: retained.refresh_token.clone(),
                still_valid,
            }
        }))
    }
}

pub use db::DbAuthStore;

mod db {
    use std::sync::Arc;

    use connetto_core::SessionId;
    use connetto_core::auth::AuthContext;
    use diesel_async::pooled_connection::bb8::Pool;
    use diesel_async::{AsyncConnection, AsyncPgConnection};

    use super::{
        AuthStore, AuthStoreError, IssuedSession, RefreshOutcome, ResolvedIdentity, format_refresh,
        hash_secret, hashes_match, new_refresh_secret, new_session_id, split_refresh,
    };
    use crate::authn::identity::IdentityResolver;
    use crate::authn::provider::RetainedProviderToken;
    use crate::authn::schema::{ConnettoStoreSchema, SessionRow};
    use crate::authn::token::RefreshLifetimes;
    use crate::schema::ConnettoSchema;

    /// The Postgres auth store, generic over the deployment's schema. Durable
    /// across restart and the only variant a promoted standby carries.
    pub struct DbAuthStore<D: ConnettoSchema> {
        pool: Pool<AsyncPgConnection>,
        lifetimes: RefreshLifetimes,
        resolver: Arc<dyn IdentityResolver<Id = <D::Auth as ConnettoStoreSchema>::Id>>,
    }

    impl<D: ConnettoSchema> DbAuthStore<D> {
        /// Build over a connection pool, resolving identity through `resolver`.
        #[must_use]
        pub fn new(
            pool: Pool<AsyncPgConnection>,
            lifetimes: RefreshLifetimes,
            resolver: Arc<dyn IdentityResolver<Id = <D::Auth as ConnettoStoreSchema>::Id>>,
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

    impl<D: ConnettoSchema> AuthStore for DbAuthStore<D> {
        type Id = <D::Auth as ConnettoStoreSchema>::Id;

        async fn create_session(
            &self,
            identity: &ResolvedIdentity,
        ) -> Result<IssuedSession<<D::Auth as ConnettoStoreSchema>::Id>, AuthStoreError> {
            let user_id = self.resolver.resolve(&identity.verified_claims()).await?;
            let secret = new_refresh_secret();
            let refresh_hash = hash_secret(&secret).to_vec();
            let session_id = new_session_id();
            let mut conn = self.pool.get().await.map_err(backend)?;
            // The deadlines are stamped by the database's clock, not this
            // process's (chapter 21).
            let (idle_deadline, absolute_deadline) = <D::Auth as ConnettoStoreSchema>::new_session(
                &mut conn,
                session_id,
                user_id.clone(),
                refresh_hash,
                self.lifetimes.idle_window(),
                self.lifetimes.absolute_ceiling(),
            )
            .await
            .map_err(backend)?;
            let context = AuthContext { user_id };
            Ok(IssuedSession {
                session_id,
                context,
                refresh_token: format_refresh(session_id, &secret),
                session_expires_at: idle_deadline.min(absolute_deadline).into(),
            })
        }

        async fn session_is_live(&self, session_id: SessionId) -> Result<bool, AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            let live = <D::Auth as ConnettoStoreSchema>::live_session(&mut conn, session_id)
                .await
                .map_err(backend)?;
            Ok(live.is_some_and(|revoked| !revoked))
        }

        async fn rotate_refresh(
            &self,
            refresh_token: &str,
        ) -> Result<RefreshOutcome<<D::Auth as ConnettoStoreSchema>::Id>, AuthStoreError> {
            let (session_id, secret) =
                split_refresh(refresh_token).ok_or(AuthStoreError::NotFound)?;
            let presented_hash = hash_secret(secret).to_vec();
            let new_secret = new_refresh_secret();
            let new_hash = hash_secret(&new_secret).to_vec();
            let mut conn = self.pool.get().await.map_err(backend)?;
            let outcome = {
                conn.transaction::<_, AuthStoreError, _>(async move |conn| {
                    // The lapsed verdict is the database's, judged in the
                    // statement (chapter 21).
                    let row: Option<SessionRow<<D::Auth as ConnettoStoreSchema>::Id>> =
                        <D::Auth as ConnettoStoreSchema>::session_row_for_update(conn, session_id)
                            .await
                            .map_err(backend)?;
                    let SessionRow {
                        user_id,
                        current_refresh_hash,
                        revoked,
                        idle_lapsed,
                        absolute_lapsed,
                    } = row.ok_or(AuthStoreError::NotFound)?;
                    if revoked {
                        return Err(AuthStoreError::NotFound);
                    }
                    if absolute_lapsed || idle_lapsed {
                        return Err(AuthStoreError::Expired);
                    }
                    if !hashes_match(&presented_hash, &current_refresh_hash) {
                        // Reuse of a rotated-out token signals theft, but the
                        // error rolls this transaction back, so the revoke
                        // lands below in its own committed statement.
                        return Err(AuthStoreError::Reuse { session_id });
                    }
                    let (idle_deadline, absolute_deadline) =
                        <D::Auth as ConnettoStoreSchema>::rotation_update(
                            conn,
                            session_id,
                            new_hash,
                            self.lifetimes.idle_window(),
                        )
                        .await
                        .map_err(backend)?;
                    let context = AuthContext { user_id };
                    Ok(RefreshOutcome {
                        session_id,
                        context,
                        refresh_token: format_refresh(session_id, &new_secret),
                        session_expires_at: idle_deadline.min(absolute_deadline).into(),
                    })
                })
                .await
            };
            if matches!(outcome, Err(AuthStoreError::Reuse { .. })) {
                <D::Auth as ConnettoStoreSchema>::revoke_update(&mut conn, session_id)
                    .await
                    .map_err(backend)?;
            }
            outcome
        }

        async fn revoke_session(&self, session_id: SessionId) -> Result<(), AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            <D::Auth as ConnettoStoreSchema>::revoke_update(&mut conn, session_id)
                .await
                .map_err(backend)?;
            Ok(())
        }

        async fn revoke_every_session(&self) -> Result<u64, AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            let revoked = <D::Auth as ConnettoStoreSchema>::revoke_every_update(&mut conn)
                .await
                .map_err(backend)?;
            Ok(u64::try_from(revoked).unwrap_or(u64::MAX))
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
            // The rotation read already selects the refresh hash and the
            // revoked flag, and its row lock serializes a logout against a
            // refresh landing at the same moment.
            let Some(SessionRow {
                current_refresh_hash,
                revoked,
                ..
            }) = <D::Auth as ConnettoStoreSchema>::session_row_for_update(&mut conn, session_id)
                .await
                .map_err(backend)?
            else {
                return Ok(None);
            };
            if revoked || !hashes_match(&presented_hash, &current_refresh_hash) {
                return Ok(None);
            }
            Ok(Some(session_id))
        }

        async fn set_retained_provider_token(
            &self,
            session_id: SessionId,
            token: &RetainedProviderToken,
        ) -> Result<(), AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            <D::Auth as ConnettoStoreSchema>::set_provider_token(
                &mut conn,
                session_id,
                token.issuer.clone(),
                token.access_token.clone(),
                token.refresh_token.clone(),
                token.expires_in,
            )
            .await
            .map_err(backend)?;
            Ok(())
        }

        async fn retained_provider_token(
            &self,
            session_id: SessionId,
        ) -> Result<Option<crate::authn::provider::StoredProviderToken>, AuthStoreError> {
            let mut conn = self.pool.get().await.map_err(backend)?;
            <D::Auth as ConnettoStoreSchema>::provider_token(&mut conn, session_id)
                .await
                .map_err(backend)
        }
    }
}
