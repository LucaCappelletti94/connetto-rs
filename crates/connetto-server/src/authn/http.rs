//! The login, callback, token, and refresh HTTP endpoints, served with axum.
//!
//! `GET /auth/login?provider=<name>` begins the Authorization Code plus PKCE
//! flow with the named provider, records the in-flight authorization keyed by
//! `state`, and redirects the user agent to the provider. A native loopback
//! client additionally passes `redirect_uri`, `code_challenge` (its own PKCE
//! S256 challenge), and `state`.
//!
//! `GET /auth/callback?code=&state=` completes the provider flow, verifies the
//! ID token, maps the claims, and connetto mints its own token pair. Without a
//! client `redirect_uri` it returns the pair as JSON (the programmatic and
//! browser-worker case). With one it mints a one-time connetto authorization
//! code and redirects the browser back to the loopback, and the client redeems
//! that code at `POST /auth/token` with its PKCE verifier. `POST /auth/refresh`
//! rotates a refresh token.
//!
//! The BFF boundary holds: provider tokens never reach the client, only
//! connetto's own tokens do, and the loopback exchange is PKCE-protected.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connetto_core::ReplicaKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authn::provider::{
    AuthCodes, IssuedAuthCode, PendingLogin, PendingLogins, ProviderError, ProviderRegistry,
};
use crate::authn::service::{AuthError, AuthService, TokenPair};
use crate::authn::store::AuthStore;

/// Which client redirect URIs the auth endpoints may deliver a minted
/// authorization code to.
///
/// Any RFC 8252 loopback redirect (`http` to `127.0.0.1`, `[::1]`, or
/// `localhost`, on any port and path) is accepted so a native client's
/// ephemeral loopback listener needs no registration. Every other redirect
/// must exactly match a deployment-configured entry, so a public browser
/// deployment permits only its own callback and an attacker cannot redirect a
/// victim's minted code off-origin.
#[derive(Debug, Clone, Default)]
pub struct RedirectPolicy {
    allowlist: Vec<String>,
}

impl RedirectPolicy {
    /// Build a policy whose `allowlist` holds the exact non-loopback redirect
    /// URIs the deployment permits. Loopback redirects are always permitted.
    #[must_use]
    pub fn new(allowlist: Vec<String>) -> Self {
        Self { allowlist }
    }

    /// Whether `redirect_uri` may receive a minted authorization code: a
    /// loopback address (any port and path) or an exact allowlist match.
    #[must_use]
    pub fn permits(&self, redirect_uri: &str) -> bool {
        self.allowlist.iter().any(|allowed| allowed == redirect_uri)
            || is_loopback_redirect(redirect_uri)
    }
}

/// Whether `redirect_uri` is an RFC 8252 loopback redirect: the `http` scheme
/// and a literal loopback host. Parsed rather than string-matched so a host
/// like `127.0.0.1.evil.example` or a `user@` authority trick cannot pass.
fn is_loopback_redirect(redirect_uri: &str) -> bool {
    let Ok(parsed) = url::Url::parse(redirect_uri) else {
        return false;
    };
    if parsed.scheme() != "http" {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// The `GET /auth/login` query: the provider, plus a native loopback client's
/// own redirect, PKCE challenge, and CSRF state when present.
#[derive(Debug, Deserialize)]
pub struct StartQuery {
    /// The configured provider name.
    pub provider: String,
    /// A native client's loopback redirect URL.
    #[serde(default)]
    pub redirect_uri: Option<String>,
    /// The client's PKCE S256 challenge.
    #[serde(default)]
    pub code_challenge: Option<String>,
    /// The client's CSRF state.
    #[serde(default)]
    pub state: Option<String>,
}

/// The `GET /auth/callback` query: the provider's authorization code and the
/// connetto CSRF state keying the in-flight authorization.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// The authorization code from the provider.
    pub code: String,
    /// The connetto CSRF state echoed back.
    pub state: String,
}

/// The `POST /auth/token` body: a one-time connetto code and the PKCE verifier.
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    /// The one-time connetto authorization code from the loopback redirect.
    pub code: String,
    /// The PKCE verifier whose S256 hash must match the challenge sent at login.
    pub code_verifier: String,
}

/// The `POST /auth/refresh` body.
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    /// The refresh token to rotate.
    pub refresh_token: String,
}

/// The token pair returned by the callback, the token exchange, and refresh.
#[derive(Debug, Serialize)]
pub struct TokenResponse<Id> {
    /// The short-lived access token for `Handshake.auth_token`.
    pub access_token: String,
    /// The rotating refresh token.
    pub refresh_token: String,
    /// The access token lifetime in seconds.
    pub expires_in: u64,
    /// The typed `user_id` this session belongs to, serialized as the
    /// deployment's own id so the client deserializes it back into that type
    /// and names its replica file from it, with no text on the identity path.
    pub user_id: Id,
    /// Unix-seconds instant the local session lapses without a further
    /// refresh, for the client's proactive unsynced-data warning.
    pub session_expires_at: u64,
    /// The per-replica encryption key, present only on login responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replica_key: Option<ReplicaKey>,
}

impl<Id> From<TokenPair<Id>> for TokenResponse<Id> {
    fn from(pair: TokenPair<Id>) -> Self {
        Self {
            access_token: pair.access_token,
            refresh_token: pair.refresh_token,
            expires_in: pair.expires_in_secs,
            user_id: pair.user_id,
            session_expires_at: pair.session_expires_at_secs,
            replica_key: pair.replica_key,
        }
    }
}

/// Shared state for the auth endpoints. Cloned per request (all fields are
/// `Arc`), so it is implemented by hand to avoid an `S: Clone` bound.
pub struct AuthState<S: AuthStore> {
    service: Arc<AuthService<S>>,
    registry: Arc<ProviderRegistry>,
    pending: Arc<PendingLogins>,
    codes: Arc<AuthCodes<S::Id>>,
    redirect_policy: RedirectPolicy,
}

impl<S: AuthStore> Clone for AuthState<S> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
            registry: Arc::clone(&self.registry),
            pending: Arc::clone(&self.pending),
            codes: Arc::clone(&self.codes),
            redirect_policy: self.redirect_policy.clone(),
        }
    }
}

/// A login, callback, token, or refresh failure, rendered without leaking
/// detail: a rejected credential is `401`, an unknown provider `404`, an unknown
/// or replayed state `400`, a bad or PKCE-mismatched grant `400`, a rejected
/// redirect `400`, an upstream provider fault `502`, and a store or mint fault
/// `500`.
enum AuthApiError {
    /// The service (store or token mint) failed.
    Service(AuthError),
    /// The provider exchange or verification failed.
    Provider(ProviderError),
    /// No provider matched the requested name.
    UnknownProvider,
    /// No in-flight authorization matched the callback state.
    UnknownState,
    /// The token exchange code was unknown, expired, or its PKCE verifier
    /// did not match the challenge.
    InvalidGrant,
    /// The client redirect URI was not a loopback address or an allowlisted
    /// entry, or a redirect and PKCE challenge were not supplied as a pair.
    InvalidRedirect,
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Service(
                AuthError::Store(crate::authn::store::AuthStoreError::Backend(_))
                | AuthError::Token(_)
                | AuthError::KeyGen,
            ) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Service(AuthError::Store(_)) => StatusCode::UNAUTHORIZED,
            Self::Service(AuthError::Provider(err)) | Self::Provider(err) => match err {
                ProviderError::Verification(_)
                | ProviderError::Assurance(_)
                | ProviderError::MissingIdToken => StatusCode::UNAUTHORIZED,
                ProviderError::Config(_)
                | ProviderError::Exchange(_)
                | ProviderError::Refresh(_) => StatusCode::BAD_GATEWAY,
            },
            Self::UnknownProvider => StatusCode::NOT_FOUND,
            Self::UnknownState | Self::InvalidGrant | Self::InvalidRedirect => {
                StatusCode::BAD_REQUEST
            }
        };
        (status, "authentication failed").into_response()
    }
}

/// Build the auth router over a shared service and provider registry.
pub fn auth_router<S: AuthStore + 'static>(
    service: Arc<AuthService<S>>,
    registry: Arc<ProviderRegistry>,
    redirect_policy: RedirectPolicy,
) -> Router {
    let state = AuthState {
        service,
        registry,
        redirect_policy,
        pending: Arc::new(PendingLogins::default()),
        codes: Arc::new(AuthCodes::default()),
    };
    Router::new()
        .route("/auth/login", get(login_start::<S>))
        .route("/auth/callback", get(callback::<S>))
        .route("/auth/token", post(token::<S>))
        .route("/auth/refresh", post(refresh::<S>))
        .with_state(state)
}

async fn login_start<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Query(query): Query<StartQuery>,
) -> Result<Redirect, AuthApiError> {
    // A client redirect and its PKCE challenge must come as a pair, and the
    // redirect must be a loopback or allowlisted URI, or connetto would deliver
    // a minted code (or fall through to returning tokens as JSON) off-origin.
    match (&query.redirect_uri, &query.code_challenge) {
        (Some(redirect_uri), Some(_)) if state.redirect_policy.permits(redirect_uri) => {}
        (None, None) => {}
        _ => return Err(AuthApiError::InvalidRedirect),
    }
    let provider = state
        .registry
        .by_name(&query.provider)
        .ok_or(AuthApiError::UnknownProvider)?;
    let redirect = provider.begin_login().map_err(AuthApiError::Provider)?;
    state.pending.insert(
        redirect.state.clone(),
        PendingLogin {
            provider: query.provider,
            pkce_verifier: redirect.pkce_verifier,
            nonce: redirect.nonce,
            client_redirect: query.redirect_uri,
            client_code_challenge: query.code_challenge,
            client_state: query.state,
        },
    );
    Ok(Redirect::temporary(&redirect.authorize_url))
}

async fn callback<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AuthApiError> {
    let pending = state
        .pending
        .take(&query.state)
        .ok_or(AuthApiError::UnknownState)?;
    let provider = state
        .registry
        .by_name(&pending.provider)
        .ok_or(AuthApiError::UnknownProvider)?;
    let verified = provider
        .complete_login(&query.code, &pending.pkce_verifier, &pending.nonce)
        .await
        .map_err(AuthApiError::Provider)?;
    let pair = state
        .service
        .login_with_provider(&verified)
        .await
        .map_err(AuthApiError::Service)?;

    // A client that supplied a redirect and PKCE challenge gets a one-time code
    // redirected to its listener. A caller that supplied neither gets the token
    // pair as JSON. login_start already rejected any other combination.
    match (pending.client_redirect, pending.client_code_challenge) {
        (Some(redirect_uri), Some(code_challenge)) => {
            if !state.redirect_policy.permits(&redirect_uri) {
                return Err(AuthApiError::InvalidRedirect);
            }
            let code = state.codes.issue(IssuedAuthCode {
                access_token: pair.access_token,
                refresh_token: pair.refresh_token,
                expires_in_secs: pair.expires_in_secs,
                user_id: pair.user_id,
                session_expires_at_secs: pair.session_expires_at_secs,
                replica_key: pair.replica_key,
                code_challenge,
            });
            let state_param = pending.client_state.unwrap_or_default();
            let separator = if redirect_uri.contains('?') { '&' } else { '?' };
            let location = format!(
                "{redirect_uri}{separator}code={}&state={}",
                urlencode(&code),
                urlencode(&state_param),
            );
            Ok(Redirect::temporary(&location).into_response())
        }
        (None, None) => Ok(Json(TokenResponse::from(pair)).into_response()),
        _ => Err(AuthApiError::InvalidRedirect),
    }
}

async fn token<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Json(request): Json<TokenExchangeRequest>,
) -> Result<Json<TokenResponse<S::Id>>, AuthApiError> {
    let issued = state
        .codes
        .redeem(&request.code)
        .ok_or(AuthApiError::InvalidGrant)?;
    if !verify_pkce_s256(&request.code_verifier, &issued.code_challenge) {
        return Err(AuthApiError::InvalidGrant);
    }
    Ok(Json(TokenResponse {
        access_token: issued.access_token,
        refresh_token: issued.refresh_token,
        expires_in: issued.expires_in_secs,
        user_id: issued.user_id,
        session_expires_at: issued.session_expires_at_secs,
        replica_key: issued.replica_key,
    }))
}

async fn refresh<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<TokenResponse<S::Id>>, AuthApiError> {
    let pair = state
        .service
        .refresh(&request.refresh_token)
        .await
        .map_err(AuthApiError::Service)?;
    Ok(Json(pair.into()))
}

/// Whether `verifier` hashes (S256) to `challenge`, compared in constant time
/// so a mismatch cannot be probed byte by byte through timing.
fn verify_pkce_s256(verifier: &str, challenge: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

/// Percent-encode a value for a query string. Codes and states are URL-safe
/// base64 or hex plus `-`, `_`, and `~`, none of which need escaping, but a
/// client-chosen state might, so escape the reserved set defensively.
fn urlencode(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}
