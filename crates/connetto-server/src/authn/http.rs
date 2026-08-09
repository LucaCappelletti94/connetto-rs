//! The login, callback, token, refresh, and logout HTTP endpoints, served with
//! axum.
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
//! rotates a refresh token, and `POST /auth/logout` revokes the session a
//! refresh token names, so a logged-out session is refused at the next
//! handshake rather than merely forgotten locally.
//!
//! The BFF boundary holds: provider tokens never reach the client, only
//! connetto's own tokens do, and the loopback exchange is PKCE-protected.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connetto_core::percent::percent_encode;
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
/// and a literal loopback host.
fn is_loopback_redirect(redirect_uri: &str) -> bool {
    let Ok(parsed) = url::Url::parse(redirect_uri) else {
        return false;
    };
    parsed.scheme() == "http" && is_loopback_host(&parsed)
}

/// Whether `parsed` names a literal loopback host: a `127.0.0.0/8` address,
/// `[::1]`, or `localhost` case-insensitively. Parsed rather than
/// string-matched, so `127.0.0.1.evil.example`, a trailing dot, or a `user@`
/// authority trick cannot pass.
///
/// The IPv4-mapped form `[::ffff:127.0.0.1]` is not loopback here, because
/// `Ipv6Addr::is_loopback` is false for it.
///
/// Two policies rest on this and each keeps its own extra condition at its own
/// site: [`RedirectPolicy`]'s loopback rule also pins the `http` scheme before
/// a minted authorization code may be delivered, and the CORS predicate in the
/// reference binary does not.
#[must_use]
pub fn is_loopback_host(parsed: &url::Url) -> bool {
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

/// The `POST /auth/logout` body.
#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    /// The refresh token whose session is to be revoked. It authenticates the
    /// request as well as naming the session, which is why no access token is
    /// needed: a device logging out holds the credential it is destroying, and
    /// its access token may already have expired.
    pub refresh_token: String,
}

/// The token pair returned by the callback, the token exchange, and refresh.
///
/// It carries no key material: the per-replica encryption key is minted on the
/// device that owns the replica.
#[derive(Debug, Serialize)]
pub struct TokenResponse<Id> {
    /// The short-lived access token, presented as one grant on the handshake.
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
}

impl<Id> From<TokenPair<Id>> for TokenResponse<Id> {
    fn from(pair: TokenPair<Id>) -> Self {
        Self {
            access_token: pair.access_token,
            refresh_token: pair.refresh_token,
            expires_in: pair.expires_in_secs,
            user_id: pair.user_id,
            session_expires_at: pair.session_expires_at_secs,
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

impl AuthApiError {
    /// Why the request failed. This never reaches the caller: the wire answer
    /// is the same on every path, so the log line is the only place a refusal
    /// says what it was.
    fn detail(&self) -> String {
        match self {
            Self::Service(err) => format!("service: {err}"),
            Self::Provider(err) => format!("provider: {err}"),
            Self::UnknownProvider => "no provider matched the requested name".to_owned(),
            Self::UnknownState => "no in-flight authorization matched the callback".to_owned(),
            Self::InvalidGrant => "unknown, expired, or PKCE-mismatched grant".to_owned(),
            Self::InvalidRedirect => "the client redirect uri was refused".to_owned(),
        }
    }
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let detail = self.detail();
        // Extract the Retry-After value before consuming self. Ceiling in whole
        // seconds, minimum 1, so the client always backs off at least a little.
        let retry_after = if let Self::Service(AuthError::RateLimited(wait)) = &self {
            Some(
                wait.as_secs()
                    .saturating_add(u64::from(wait.subsec_nanos() > 0))
                    .max(1),
            )
        } else {
            None
        };
        let status = match self {
            Self::Service(AuthError::RateLimited(_)) => StatusCode::TOO_MANY_REQUESTS,
            Self::Service(
                AuthError::Store(crate::authn::store::AuthStoreError::Backend(_))
                | AuthError::Token(_),
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
        tracing::warn!(status = status.as_u16(), detail = %detail, "authentication failed");
        if let Some(secs) = retry_after {
            (
                status,
                [(header::RETRY_AFTER, secs.to_string())],
                "authentication failed",
            )
                .into_response()
        } else {
            (status, "authentication failed").into_response()
        }
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
        .route("/auth/logout", post(logout::<S>))
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
                code_challenge,
            });
            let state_param = pending.client_state.unwrap_or_default();
            let separator = if redirect_uri.contains('?') { '&' } else { '?' };
            // Codes and states are URL-safe base64 or hex, none of which needs
            // escaping, but a client-chosen state might.
            let location = format!(
                "{redirect_uri}{separator}code={}&state={}",
                percent_encode(&code),
                percent_encode(&state_param),
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

/// Revoke the session the presented refresh token names.
///
/// Always `204`, whether or not a session was revoked, so the endpoint cannot be
/// used to probe whether a guessed refresh token names a live session. The
/// client's own local teardown does not depend on the answer either: it clears
/// its stored credential regardless, because a device with no connectivity must
/// still be able to log out.
async fn logout<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    Json(request): Json<LogoutRequest>,
) -> Result<StatusCode, AuthApiError> {
    state
        .service
        .logout(&request.refresh_token)
        .await
        .map_err(AuthApiError::Service)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Whether `verifier` hashes (S256) to `challenge`, compared in constant time
/// so a mismatch cannot be probed byte by byte through timing.
fn verify_pkce_s256(verifier: &str, challenge: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    let digest = Sha256::digest(verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(digest);
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::is_loopback_host;

    fn loopback(url: &str) -> bool {
        url::Url::parse(url).is_ok_and(|parsed| is_loopback_host(&parsed))
    }

    #[test]
    fn accepts_the_three_literal_loopback_forms() {
        assert!(loopback("http://127.0.0.1:8080/callback"));
        assert!(loopback("http://127.7.7.7/"));
        assert!(loopback("http://[::1]:0/"));
        assert!(loopback("http://localhost/"));
        assert!(loopback("http://LocalHost/"));
        assert!(loopback("https://127.0.0.1/"));
    }

    #[test]
    fn rejects_hosts_that_only_look_loopback() {
        assert!(!loopback("http://127.0.0.1.evil.example/"));
        assert!(!loopback("http://localhost.evil.example/"));
        assert!(!loopback("http://localhost./"));
        assert!(!loopback("http://example.com/"));
        assert!(!loopback("not a url"));
    }

    #[test]
    fn an_authority_trick_does_not_move_the_host() {
        // The host is what is matched, never the userinfo before the `@`.
        assert!(loopback("http://evil.example@127.0.0.1/"));
        assert!(!loopback("http://127.0.0.1@evil.example/"));
    }

    #[test]
    fn the_ipv4_mapped_form_is_not_loopback() {
        // `Ipv6Addr::is_loopback` is false for it. A gap both callers have
        // always shared, pinned here so a change to it is deliberate.
        assert!(!loopback("http://[::ffff:127.0.0.1]/"));
    }
}
