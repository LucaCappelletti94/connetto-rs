//! The authentication service: login, refresh, revoke, and the handshake
//! session verifier.
//!
//! [`AuthService`] mints connetto tokens at login and rotates them at refresh
//! over an [`AuthStore`]. [`ConnettoSessionVerifier`] is the real
//! [`SessionVerifier`] the server injects: it verifies the access token
//! locally and checks session liveness in the same store, so a revoked session
//! is refused on the next handshake even while its access token is time-valid.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use connetto_core::traits::{SessionVerifier, SessionVerifyError, SessionVerifyFuture};
use tokio::sync::Mutex as AsyncMutex;

use crate::authn::provider::{
    ProviderError, ProviderRegistry, RetainedProviderToken, VerifiedLogin,
};
use crate::authn::store::{AuthStore, AuthStoreError, ResolvedIdentity};
use crate::authn::token::{TokenAuthority, TokenError};

/// The access token plus its rotating refresh token, returned by login and
/// refresh.
#[derive(Debug, Clone)]
pub struct TokenPair<Id> {
    /// The short-lived access token, carried in `Handshake.auth_token`.
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
}

/// Mints and rotates connetto tokens over an [`AuthStore`].
///
/// Generic over the store so the concrete choice (in-memory or database) is
/// made once at startup, mirroring the `AuthPolicy` enum pattern, and every
/// awaited store future stays `Send`.
pub struct AuthService<S: AuthStore> {
    authority: Arc<TokenAuthority>,
    store: Arc<S>,
    /// The provider registry, for the lazy retained-token refresh. `None`
    /// leaves retained tokens un-refreshable (returned as stored).
    registry: Option<Arc<ProviderRegistry>>,
    /// Per-session async locks serializing retained-token refreshes so two
    /// concurrent callers on one node cannot double-refresh and trip the
    /// provider's rotation-reuse defense.
    refresh_locks: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl<S: AuthStore> AuthService<S> {
    /// Build over a shared token authority and store, with no provider registry.
    #[must_use]
    pub fn new(authority: Arc<TokenAuthority>, store: Arc<S>) -> Self {
        Self {
            authority,
            store,
            registry: None,
            refresh_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Attach the provider registry that backs the lazy retained-token accessor.
    #[must_use]
    pub fn with_registry(mut self, registry: Arc<ProviderRegistry>) -> Self {
        self.registry = Some(registry);
        self
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
            .mint_access(&issued.context, &issued.session_id, now)?;
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
            .set_retained_provider_token(&issued.session_id, &login.retained, now)
            .await?;
        let access_token = self
            .authority
            .mint_access(&issued.context, &issued.session_id, now)?;
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
        session_id: &str,
    ) -> Result<Option<String>, AuthError> {
        let lock = {
            let mut locks = self.refresh_locks.lock().expect("refresh locks");
            Arc::clone(
                locks
                    .entry(session_id.to_owned())
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
        let now = SystemTime::now();
        let outcome = self.store.rotate_refresh(refresh_token, now).await?;
        let access_token =
            self.authority
                .mint_access(&outcome.context, &outcome.session_id, now)?;
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
    pub async fn revoke(&self, session_id: &str) -> Result<(), AuthError> {
        self.store.revoke_session(session_id).await?;
        Ok(())
    }

    /// Build the session verifier sharing this service's authority and store.
    #[must_use]
    pub fn verifier(&self) -> ConnettoSessionVerifier<S> {
        ConnettoSessionVerifier {
            authority: Arc::clone(&self.authority),
            store: Arc::clone(&self.store),
        }
    }
}

/// The real [`SessionVerifier`]: verify connetto's access token, then confirm
/// the session is still live in the store.
///
/// Injected into `SessionManager` through `with_session_verifier`. It closes
/// the spoofing hole because identity comes only from a token connetto signed.
pub struct ConnettoSessionVerifier<S: AuthStore> {
    authority: Arc<TokenAuthority>,
    store: Arc<S>,
}

impl<S: AuthStore> ConnettoSessionVerifier<S> {
    /// Build over a shared token authority and store.
    #[must_use]
    pub fn new(authority: Arc<TokenAuthority>, store: Arc<S>) -> Self {
        Self { authority, store }
    }
}

impl<S: AuthStore + 'static> SessionVerifier<S::Id> for ConnettoSessionVerifier<S> {
    fn verify_session<'a>(&'a self, auth_token: &'a str) -> SessionVerifyFuture<'a, S::Id> {
        Box::pin(async move {
            let verified = self
                .authority
                .verify_access::<S::Id>(auth_token)
                .map_err(|err| SessionVerifyError::Invalid(err.to_string()))?;
            let live = self
                .store
                .session_is_live(&verified.session_id, SystemTime::now())
                .await
                .map_err(|err| SessionVerifyError::Invalid(err.to_string()))?;
            if !live {
                return Err(SessionVerifyError::Revoked);
            }
            Ok(verified)
        })
    }
}
