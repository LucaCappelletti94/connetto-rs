//! The authentication service: login, refresh, revoke, and the handshake
//! authority.
//!
//! [`AuthService`] mints connetto tokens at login and rotates them at refresh
//! over an [`AuthStore`]. [`ConnettoHandshakeAuthority`] is the real
//! [`HandshakeAuthority`] the server injects: it checks each grant's signature
//! locally, confirms in the same store that a login grant's run is still live,
//! so a revoked run is refused on the next handshake even while its token is
//! time-valid, and it signs the resume blob a caller with no identity presents.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use connetto_core::SessionId;
use connetto_core::auth::Subject;
use connetto_core::messages::Grant;
use connetto_core::traits::{GrantCheckFuture, GrantRefused, HandleError, HandshakeAuthority};
use serde::de::DeserializeOwned;
use tokio::sync::Mutex as AsyncMutex;

use crate::authn::provider::{
    ProviderError, ProviderRegistry, RetainedProviderToken, VerifiedLogin,
};
use crate::authn::store::{AuthStore, AuthStoreError, ResolvedIdentity, split_refresh};
use crate::authn::token::{TokenAuthority, TokenError};
use crate::throttle::{AuthThrottle, ThrottleConfig};

/// The access token plus its rotating refresh token, returned by login and
/// refresh.
///
/// No key material rides this pair. The per-replica encryption key is minted on
/// the device that owns the replica, so the server never sees, stores, or
/// forwards one.
#[derive(Debug, Clone)]
pub struct TokenPair<Id> {
    /// The short-lived access token, presented as a grant on the handshake.
    pub access_token: String,
    /// The rotating refresh token, presented back to the refresh endpoint.
    pub refresh_token: String,
    /// The access token's lifetime in seconds, echoed as `expires_in`.
    pub expires_in_secs: u64,
    /// The typed `user_id` this session belongs to, carried to the client as
    /// the deployment's own id rather than as text. The client selects its
    /// replica file from it, so a re-authentication resolving to a different
    /// identity opens a different file instead of resuming this one's.
    pub user_id: Id,
    /// Unix-seconds instant the local session lapses if never refreshed again.
    /// The client warns before it passes with unsynced data queued.
    pub session_expires_at_secs: u64,
}

/// Unix seconds for a [`SystemTime`], clamped at the epoch.
fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Failure of a login or refresh.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The auth store rejected the operation.
    #[error(transparent)]
    Store(#[from] AuthStoreError),
    /// Minting the access token failed.
    #[error(transparent)]
    Token(#[from] TokenError),
    /// A provider operation (a retained-token refresh) failed.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// The caller's refresh quota is exhausted. Wait at least this long before retrying.
    #[error("rate limited")]
    RateLimited(Duration),
}

/// Mints and rotates connetto tokens over an [`AuthStore`].
///
/// Generic over the store so the concrete choice (in-memory or database) is
/// made once at startup, and every awaited store future stays `Send`.
pub struct AuthService<S: AuthStore> {
    authority: Arc<TokenAuthority>,
    store: Arc<S>,
    /// The provider registry, for the lazy retained-token refresh. `None`
    /// leaves retained tokens un-refreshable (returned as stored).
    registry: Option<Arc<ProviderRegistry>>,
    /// Per-session async locks serializing retained-token refreshes so two
    /// concurrent callers on one node cannot double-refresh and trip the
    /// provider's rotation-reuse defense.
    refresh_locks: Mutex<HashMap<SessionId, Arc<AsyncMutex<()>>>>,
    /// Observer fired after a session is revoked, set once at startup. The
    /// deployment points it at the session manager so revocation closes the
    /// session's live connection rather than only refusing its next handshake.
    revocation_hook: std::sync::OnceLock<SessionRevocationHook>,
    /// Sink for the durable record of access changes, set once at startup.
    /// `None` records nothing, which is what an in-memory deployment wants.
    audit_hook: std::sync::OnceLock<crate::audit::AuditHook<S::Id>>,
    /// Refresh-endpoint counters. Keyed by `String` (the `Display` rendering of
    /// `S::Id`) rather than by `S::Id` directly, because `Id` does not guarantee
    /// `Eq + Hash` and widening that public associated-type bound would impose on
    /// every application that owns the type.
    throttle: AuthThrottle<String>,
}

/// Observes a session revocation. Fired synchronously after the store revoke
/// succeeds, so an async close belongs on a spawned task inside the hook.
pub type SessionRevocationHook = Arc<dyn Fn(SessionId) + Send + Sync>;

impl<S: AuthStore> AuthService<S> {
    /// Build over a shared token authority and store, with no provider registry.
    #[must_use]
    pub fn new(authority: Arc<TokenAuthority>, store: Arc<S>) -> Self {
        Self {
            authority,
            store,
            registry: None,
            refresh_locks: Mutex::new(HashMap::new()),
            revocation_hook: std::sync::OnceLock::new(),
            audit_hook: std::sync::OnceLock::new(),
            throttle: AuthThrottle::new(ThrottleConfig::default()),
        }
    }

    /// Attach the provider registry that backs the lazy retained-token accessor.
    #[must_use]
    pub fn with_registry(mut self, registry: Arc<ProviderRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Replace the throttle built in [`Self::new`] with one for `config`.
    /// Supply tight limits in tests or in deployments that diverge from the
    /// default generous limits.
    #[must_use]
    pub fn with_throttle(mut self, config: ThrottleConfig) -> Self {
        self.throttle = AuthThrottle::new(config);
        self
    }

    /// Attach the revocation observer, once, after construction. A second call
    /// is ignored, which suits the one startup wiring point this exists for.
    pub fn set_revocation_hook(&self, hook: SessionRevocationHook) {
        let _ = self.revocation_hook.set(hook);
    }

    /// Attach the audit sink, once, after construction. A second call is
    /// ignored, matching the revocation observer beside it.
    ///
    /// Unset, connetto records nothing, which is the right default: the table
    /// is the deployment's and connetto emits no DDL, so a deployment that has
    /// not created it must not have writes attempted against it.
    pub fn set_audit_hook(&self, hook: crate::audit::AuditHook<S::Id>) {
        let _ = self.audit_hook.set(hook);
    }

    /// Record one access change, if a sink is attached.
    fn record(&self, event: crate::audit::AuthEvent<S::Id>) {
        if let Some(hook) = self.audit_hook.get() {
            hook(event);
        }
    }

    /// Create a session for a verified identity and mint its first token pair.
    ///
    /// # Errors
    ///
    /// [`AuthError`] if the store or the mint fails.
    pub async fn login(&self, identity: &ResolvedIdentity) -> Result<TokenPair<S::Id>, AuthError> {
        let now = SystemTime::now();
        let issued = self.store.create_session(identity, now).await?;
        let access_token = self
            .authority
            .mint_access(&issued.context, issued.session_id, now)?;
        tracing::info!(
            session = %issued.session_id,
            user = %issued.context.user_id,
            "login succeeded, session created"
        );
        self.throttle
            .learn_owner(issued.session_id, &issued.context.user_id.to_string());
        Ok(TokenPair {
            access_token,
            refresh_token: issued.refresh_token,
            expires_in_secs: self.authority.access_ttl().as_secs(),
            user_id: issued.context.user_id,
            session_expires_at_secs: unix_secs(issued.session_expires_at),
        })
    }

    /// Create a session for a verified login and retain its provider tokens.
    ///
    /// The phase-3 login callback uses this: the identity and the provider
    /// tokens both come from the provider's verified response.
    ///
    /// # Errors
    ///
    /// [`AuthError`] if the store or the mint fails.
    pub async fn login_with_provider(
        &self,
        login: &VerifiedLogin,
    ) -> Result<TokenPair<S::Id>, AuthError> {
        let now = SystemTime::now();
        let issued = self.store.create_session(&login.identity, now).await?;
        self.store
            .set_retained_provider_token(issued.session_id, &login.retained, now)
            .await?;
        let access_token = self
            .authority
            .mint_access(&issued.context, issued.session_id, now)?;
        tracing::info!(
            session = %issued.session_id,
            user = %issued.context.user_id,
            issuer = %login.retained.issuer,
            "login succeeded, session created with retained provider tokens"
        );
        self.throttle
            .learn_owner(issued.session_id, &issued.context.user_id.to_string());
        Ok(TokenPair {
            access_token,
            refresh_token: issued.refresh_token,
            expires_in_secs: self.authority.access_ttl().as_secs(),
            user_id: issued.context.user_id,
            session_expires_at_secs: unix_secs(issued.session_expires_at),
        })
    }

    /// A currently-valid provider access token for `session_id`, refreshing it
    /// inline against the provider when the stored one is about to expire and
    /// persisting the rotated refresh token.
    ///
    /// This is server-side only: it never emits a provider token to a client,
    /// which would break the Backend-For-Frontend boundary. Concurrent callers
    /// on one node are serialized per session. There is no background refresh.
    ///
    /// Returns `None` when the session retained no provider token. When no
    /// registry is attached or the issuer routes to no provider, the stored
    /// token is returned unrefreshed.
    ///
    /// # Errors
    ///
    /// [`AuthError`] if the store or the provider refresh fails.
    pub async fn provider_access_token(
        &self,
        session_id: SessionId,
    ) -> Result<Option<String>, AuthError> {
        let lock = {
            let mut locks = self.refresh_locks.lock().expect("refresh locks");
            Arc::clone(
                locks
                    .entry(session_id)
                    .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
            )
        };
        let _guard = lock.lock().await;

        let Some(retained) = self.store.retained_provider_token(session_id).await? else {
            return Ok(None);
        };
        let now = SystemTime::now();
        let still_valid = match retained.expires_at {
            Some(expires_at) => now + Duration::from_secs(30) < expires_at,
            None => true,
        };
        if still_valid {
            return Ok(Some(retained.access_token));
        }
        let (Some(refresh_token), Some(registry)) =
            (retained.refresh_token.as_deref(), self.registry.as_ref())
        else {
            return Ok(Some(retained.access_token));
        };
        let Some(provider) = registry.by_issuer(&retained.issuer) else {
            return Ok(Some(retained.access_token));
        };
        let refreshed = provider.refresh_provider_token(refresh_token).await?;
        // Preserve the tenant-specific issuer resolved at login.
        let refreshed = RetainedProviderToken {
            issuer: retained.issuer.clone(),
            ..refreshed
        };
        self.store
            .set_retained_provider_token(session_id, &refreshed, now)
            .await?;
        Ok(Some(refreshed.access_token))
    }

    /// Rotate the presented refresh token and mint a fresh access token.
    ///
    /// # Errors
    ///
    /// [`AuthError`] if the token is invalid, expired, reused, or the mint fails.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenPair<S::Id>, AuthError> {
        // Parse the session id before touching the store. A token that does not
        // parse names nothing, so skip all metering and let the store return its
        // own error unchanged.
        let named_session = split_refresh(refresh_token).map(|(sid, _)| sid);
        if let Some(session_id) = named_session
            && let Some(wait) = self.throttle.refresh_blocked(session_id)
        {
            return Err(AuthError::RateLimited(wait));
        }
        let now = SystemTime::now();
        let outcome = match self.store.rotate_refresh(refresh_token, now).await {
            Ok(outcome) => outcome,
            Err(err) => {
                // Only a credential failure counts. A store that is down fails
                // the honest attempts too, and charging those would turn an
                // outage into a lockout outliving it.
                if let Some(session_id) = named_session
                    && matches!(
                        err,
                        AuthStoreError::NotFound
                            | AuthStoreError::Expired
                            | AuthStoreError::Reuse { .. }
                    )
                {
                    let _ = self.throttle.refresh_failed(session_id);
                }
                // The store revokes on theft but cannot close anything: the
                // observer lives here. Without this the stolen-credential case
                // was the one case that left the socket streaming.
                if let AuthStoreError::Reuse { session_id } = &err {
                    tracing::warn!(
                        session = %session_id,
                        "refresh token reuse detected, session revoked as theft"
                    );
                    self.notify_revoked(*session_id);
                    // Not `revoke_as`: the store already revoked inside the
                    // rotation, so going back through it would write the row a
                    // second time.
                    self.record(crate::audit::AuthEvent::new(
                        *session_id,
                        None,
                        crate::audit::AuthOp::TokenReplayed,
                    ));
                }
                return Err(err.into());
            }
        };
        let access_token = self
            .authority
            .mint_access(&outcome.context, outcome.session_id, now)?;
        self.throttle
            .learn_owner(outcome.session_id, &outcome.context.user_id.to_string());
        tracing::info!(
            session = %outcome.session_id,
            user = %outcome.context.user_id,
            "refresh token rotated, access token reissued"
        );
        Ok(TokenPair {
            access_token,
            refresh_token: outcome.refresh_token,
            expires_in_secs: self.authority.access_ttl().as_secs(),
            user_id: outcome.context.user_id,
            session_expires_at_secs: unix_secs(outcome.session_expires_at),
        })
    }

    /// Revoke a session, refusing it on the next handshake.
    ///
    /// # Errors
    ///
    /// [`AuthError`] if the store fails.
    pub async fn revoke(&self, session_id: SessionId) -> Result<(), AuthError> {
        self.revoke_as(session_id, crate::audit::AuthOp::SessionRevoked)
            .await
    }

    /// Revoke, and record the cause. Three causes reach here and they are not
    /// interchangeable: an audit row saying only that a login ended cannot tell
    /// an ordinary logout from a stolen credential, which is the most valuable
    /// thing this table reports.
    ///
    /// The row names no user. Every producer here holds a session and not an
    /// identity, and `session` joins `connetto_sessions`, which has the user,
    /// so the alternative was a store round trip per revocation to denormalise
    /// a column the join already answers.
    async fn revoke_as(
        &self,
        session_id: SessionId,
        op: crate::audit::AuthOp,
    ) -> Result<(), AuthError> {
        self.store.revoke_session(session_id).await?;
        tracing::info!(session = %session_id, cause = op.label(), "session revoked");
        self.notify_revoked(session_id);
        self.record(crate::audit::AuthEvent::new(session_id, None, op));
        Ok(())
    }

    /// Tell the deployment's observer that a session died, so it can close the
    /// connection that session still holds. Every revocation path goes through
    /// here, which is what keeps the theft response and the logout equivalent.
    fn notify_revoked(&self, session_id: SessionId) {
        if let Some(hook) = self.revocation_hook.get() {
            hook(session_id);
        }
    }

    /// Log out the session the presented refresh token names: verify the token,
    /// then revoke.
    ///
    /// Returns whether a session was revoked. `false` means the token named no
    /// live session, which is indistinguishable to the caller from success on
    /// purpose: an endpoint whose only effect is revocation must not report
    /// whether a guessed credential existed.
    ///
    /// This is server-side liveness, not token expiry. The session is refused at
    /// the next handshake, and its refresh token stops rotating, while any access
    /// token already minted for it stays signature-valid until it expires. That
    /// bound is the access token's TTL and it is why the TTL is short.
    ///
    /// # Errors
    ///
    /// [`AuthError`] if the store fails.
    pub async fn logout(&self, refresh_token: &str) -> Result<bool, AuthError> {
        let Some(session_id) = self.store.session_for_refresh(refresh_token).await? else {
            return Ok(false);
        };
        self.revoke_as(session_id, crate::audit::AuthOp::LoggedOut)
            .await?;
        Ok(true)
    }

    /// Build the handshake authority sharing this service's token authority
    /// and store.
    #[must_use]
    pub fn handshake_authority(&self) -> ConnettoHandshakeAuthority<S> {
        ConnettoHandshakeAuthority {
            authority: Arc::clone(&self.authority),
            store: Arc::clone(&self.store),
        }
    }
}

/// The real [`HandshakeAuthority`]: check each grant against connetto's own
/// public key, confirm a login grant's run is still live in the store, and sign
/// the resume blob an unidentified run presents.
///
/// It closes the spoofing hole because a caller is only ever whoever a token
/// connetto signed says it is, and it closes the handle hole because a run with
/// no identity resumes only on a blob connetto signed.
pub struct ConnettoHandshakeAuthority<S: AuthStore> {
    authority: Arc<TokenAuthority>,
    store: Arc<S>,
}

impl<S: AuthStore> ConnettoHandshakeAuthority<S> {
    /// Build over a shared token authority and store.
    #[must_use]
    pub fn new(authority: Arc<TokenAuthority>, store: Arc<S>) -> Self {
        Self { authority, store }
    }
}

impl<S, Key> HandshakeAuthority<S::Id, Key> for ConnettoHandshakeAuthority<S>
where
    S: AuthStore + 'static,
    Key: DeserializeOwned + Send + 'static,
{
    fn check_grant<'a>(&'a self, grant: &'a Grant) -> GrantCheckFuture<'a, S::Id, Key> {
        Box::pin(async move {
            let subject = self
                .authority
                .check_grant::<S::Id, Key>(grant)
                .map_err(|err| GrantRefused::Invalid(err.to_string()))?;
            // Only a login has something to keep alive. A capability is
            // withdrawn by deleting the relation that grants it, which the
            // authorization model answers per question, so asking a store here
            // would invent a liveness concept the design deliberately has not.
            let session = match subject {
                Subject::Capability(subject) => return Ok(Subject::Capability(subject)),
                Subject::Identity(session) => session,
            };
            let live = self
                .store
                .session_is_live(session.session_id, SystemTime::now())
                .await
                .map_err(|err| GrantRefused::Invalid(err.to_string()))?;
            if !live {
                return Err(GrantRefused::Revoked);
            }
            Ok(Subject::Identity(session))
        })
    }

    fn mint_handle(&self, session_id: SessionId) -> Result<String, HandleError> {
        self.authority
            .mint_resume(session_id, SystemTime::now())
            .map_err(|err| HandleError(err.to_string()))
    }

    fn read_handle(&self, blob: &str) -> Result<SessionId, HandleError> {
        self.authority
            .verify_resume(blob)
            .map_err(|err| HandleError(err.to_string()))
    }
}
