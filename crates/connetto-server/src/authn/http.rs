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
//!
//! R90 adds the browser contract on `/auth/token`, `/auth/refresh`, and
//! `/auth/logout`. A request marked with `X-Connetto-Client: browser` carries
//! its refresh credential in a per-account `HttpOnly` cookie named
//! `__Host-Http-connetto-refresh-` plus the base64url of the id's serde form,
//! and its JSON body never carries or receives the refresh token. The marker
//! is the CSRF latch RFC 10017 section 6.1.3.3.2 requires: a cookie-endpoint
//! request that omits it takes the native path and cannot authenticate with
//! the cookie, and a mixed or unknown marker is a `400`. Unmarked requests
//! keep the JSON-body contract and never see a `Set-Cookie`.
//! Refresh rotation under the marker binds account to credential: the body's
//! `user_id` selects the cookie by exact name, and a rotated pair naming a
//! different account revokes the presented session before the generic `401`.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite as JarSameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connetto_core::percent::percent_encode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authn::provider::{
    AuthCodes, IssuedAuthCode, PendingLogin, PendingLogins, ProviderError, ProviderRegistry,
};
use crate::authn::service::{AuthError, AuthService, TokenPair};
use crate::authn::store::{AuthStore, split_refresh};

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
///
/// The native contract fills `refresh_token`. The browser contract (a marked
/// request) fills `user_id` and must not fill `refresh_token`: its credential
/// rides the cookie named by that id.
#[derive(Debug, Deserialize)]
pub struct RefreshRequest<Id> {
    /// The refresh token to rotate. Native contract only.
    pub refresh_token: Option<String>,
    /// The account whose cookie carries the credential. Browser contract only.
    pub user_id: Option<Id>,
}

/// The `POST /auth/logout` body.
///
/// The native contract fills `refresh_token`. The browser contract fills
/// `user_id` and revokes through that account's cookie.
#[derive(Debug, Deserialize)]
pub struct LogoutRequest<Id> {
    /// The refresh token whose session is to be revoked. It authenticates the
    /// request as well as naming the session, which is why no access token is
    /// needed: a device logging out holds the credential it is destroying, and
    /// its access token may already have expired. Native contract only.
    pub refresh_token: Option<String>,
    /// The account whose cookie carries the credential to revoke. Browser
    /// contract only.
    pub user_id: Option<Id>,
}

/// The token pair returned by the callback, the token exchange, and refresh.
///
/// It carries no key material: the per-replica encryption key is minted on the
/// device that owns the replica.
#[derive(Debug, Serialize)]
pub struct TokenResponse<Id> {
    /// The short-lived access token, presented as one grant on the handshake.
    pub access_token: String,
    /// The rotating refresh token. Absent under the browser contract, where
    /// the credential rides the `Set-Cookie` instead and never enters script
    /// or a body the page can read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
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
            refresh_token: Some(pair.refresh_token),
            expires_in: pair.expires_in_secs,
            user_id: pair.user_id,
            session_expires_at: pair.session_expires_at_secs,
        }
    }
}

/// Shared state for the auth endpoints. Cloned per request (all fields are
/// `Arc`), so it is implemented by hand to avoid an `S: Clone` bound.
pub struct AuthState<S: AuthStore> {
    /// The `SameSite` attribute the refresh cookie renders with.
    pub cookie_same_site: CookieSameSite,
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
            cookie_same_site: self.cookie_same_site,
        }
    }
}

/// A login, callback, token, or refresh failure, rendered without leaking
/// detail: a rejected credential is `401`, an unknown provider `404`, an unknown
/// or replayed state `400`, a bad or PKCE-mismatched grant `400`, a rejected
/// redirect `400`, an upstream provider fault `502`, and a store or mint fault
/// `500`.
#[derive(Debug)]
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
    /// A request broke its contract: an unknown marker value, a marked
    /// request that also carries a body token or names no account, or an
    /// unmarked request with no body token.
    InvalidRequest,
    /// A marked request carried no cookie under the name its account derives,
    /// or the cookie's session turned out to name a different account. The
    /// answer is the generic `401` so the client falls through to an
    /// interactive login and nothing on the wire says which.
    InvalidCredential,
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
            Self::InvalidRequest => {
                "the request mixed or omitted its contract's credential".to_owned()
            }
            Self::InvalidCredential => "no credential rode the marked request".to_owned(),
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
            Self::Service(AuthError::Store(_)) | Self::InvalidCredential => {
                StatusCode::UNAUTHORIZED
            }
            Self::Service(AuthError::Provider(err)) | Self::Provider(err) => match err {
                ProviderError::Verification(_)
                | ProviderError::Assurance(_)
                | ProviderError::MissingIdToken => StatusCode::UNAUTHORIZED,
                ProviderError::Config(_)
                | ProviderError::Exchange(_)
                | ProviderError::Refresh(_) => StatusCode::BAD_GATEWAY,
            },
            Self::UnknownProvider => StatusCode::NOT_FOUND,
            Self::UnknownState
            | Self::InvalidGrant
            | Self::InvalidRedirect
            | Self::InvalidRequest => StatusCode::BAD_REQUEST,
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

/// The `SameSite` attribute the browser-contract refresh cookie renders
/// with. Exactly two settings, decided 2026-09-22: the cookie rides only the
/// three auth `POST`s, so `Lax` earns nothing over `Strict`, and `None` exists
/// only for deployments whose app origin is a different site than the auth
/// origin and whose browsers still accept third-party cookies. `None` earns
/// the cookie on top-level cross-site pages only. An app *embedded* in
/// another site needs CHIPS `Partitioned`, a distinct attribute rather than
/// a stricter `None`, and is out of scope here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CookieSameSite {
    /// The default. The cookie rides only same-site requests.
    #[default]
    Strict,
    /// Cross-site rides, which modern third-party-cookie blocking may drop.
    None,
}

impl CookieSameSite {
    /// Parse the deployment setting. Only the two lowercase names parse. Any
    /// other value is a configuration error the caller must refuse startup on.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "strict" => Some(Self::Strict),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    fn jar(self) -> JarSameSite {
        match self {
            Self::Strict => JarSameSite::Strict,
            Self::None => JarSameSite::None,
        }
    }
}

/// The request header whose value names the client contract. The marker is
/// the CSRF latch RFC 10017 section 6.1.3.3.2 requires on cookie-authenticated
/// `POST`s: a cross-origin request carrying it forces a preflight, and a form
/// submission cannot arrive with it.
pub const CLIENT_KIND_HEADER: &str = "x-connetto-client";

/// The one header value that selects the browser cookie contract.
pub const BROWSER_CLIENT: &str = "browser";

/// The prefix of the per-account refresh cookie. The `__Host-Http-` prefix
/// makes the browser itself reject any `Set-Cookie` that drops `Secure` or
/// `HttpOnly`, deviates from `Path=/`, or adds a `Domain`.
pub const REFRESH_COOKIE_PREFIX: &str = "__Host-Http-connetto-refresh-";

/// Whether this request carries the browser marker. An absent header is the
/// native contract. A present header with any other value is a refused
/// request, never a silent native fallthrough.
fn is_marked_request(headers: &HeaderMap) -> Result<bool, AuthApiError> {
    match headers.get(CLIENT_KIND_HEADER) {
        None => Ok(false),
        Some(value) if value == BROWSER_CLIENT => Ok(true),
        Some(_) => Err(AuthApiError::InvalidRequest),
    }
}

/// The cookie name for one account: the prefix plus the base64url (no pad) of
/// the id's serde JSON form. The serde encoding, not `Display`, is the
/// canonical byte source, matching the replica-name derivation, and base64url
/// keeps the name inside the RFC 6265 token characters whatever the id type
/// spells.
fn refresh_cookie_name<Id: Serialize>(user_id: &Id) -> Result<String, AuthApiError> {
    let encoded = serde_json::to_vec(user_id).map_err(|_| AuthApiError::InvalidRequest)?;
    Ok(format!(
        "{REFRESH_COOKIE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(encoded)
    ))
}

/// Build the refresh cookie with the full attribute set. The deletion path
/// passes the same builder so the removal `Set-Cookie` carries the attributes
/// the prefix rules demand on every header, a bare name-only removal being
/// rejected by the browser and leaving the account resumable after sign-out.
///
/// `Max-Age` is the time left until `lapses_at_secs`, the instant the session
/// lapses without a further refresh, so the cookie survives a browser restart
/// and never outlives what the server would accept. Every rotation sets it
/// again as the idle window slides.
fn refresh_cookie(
    name: String,
    value: String,
    same_site: CookieSameSite,
    lapses_at_secs: u64,
) -> Cookie<'static> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let remaining = i64::try_from(lapses_at_secs.saturating_sub(now)).unwrap_or(i64::MAX);
    Cookie::build((name, value))
        .http_only(true)
        .secure(true)
        .path("/")
        .same_site(same_site.jar())
        .max_age(time::Duration::seconds(remaining))
        .build()
}

/// Build the auth router over a shared service and provider registry.
pub fn auth_router<S: AuthStore + 'static>(
    service: Arc<AuthService<S>>,
    registry: Arc<ProviderRegistry>,
    redirect_policy: RedirectPolicy,
    cookie_same_site: CookieSameSite,
) -> Router {
    let state = AuthState {
        service,
        registry,
        redirect_policy,
        cookie_same_site,
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
    jar: CookieJar,
    headers: HeaderMap,
    Json(request): Json<TokenExchangeRequest>,
) -> Result<(CookieJar, Json<TokenResponse<S::Id>>), AuthApiError> {
    let marked = is_marked_request(&headers)?;
    let issued = state
        .codes
        .redeem(&request.code)
        .ok_or(AuthApiError::InvalidGrant)?;
    if !verify_pkce_s256(&request.code_verifier, &issued.code_challenge) {
        return Err(AuthApiError::InvalidGrant);
    }
    let (jar, refresh_token) = if marked {
        let name = refresh_cookie_name(&issued.user_id)?;
        let cookie = refresh_cookie(
            name,
            issued.refresh_token,
            state.cookie_same_site,
            issued.session_expires_at_secs,
        );
        (jar.add(cookie), None)
    } else {
        (jar, Some(issued.refresh_token))
    };
    Ok((
        jar,
        Json(TokenResponse {
            access_token: issued.access_token,
            refresh_token,
            expires_in: issued.expires_in_secs,
            user_id: issued.user_id,
            session_expires_at: issued.session_expires_at_secs,
        }),
    ))
}

async fn refresh<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(request): Json<RefreshRequest<S::Id>>,
) -> Result<(CookieJar, Json<TokenResponse<S::Id>>), AuthApiError> {
    let marked = is_marked_request(&headers)?;
    let presented = if marked {
        // The account names the cookie and the cookie carries the credential.
        // A body token on a marked request mixes the two contracts.
        let user_id = request
            .user_id
            .as_ref()
            .ok_or(AuthApiError::InvalidRequest)?;
        if request.refresh_token.is_some() {
            return Err(AuthApiError::InvalidRequest);
        }
        let name = refresh_cookie_name(user_id)?;
        let cookie = jar
            .get(&name)
            .ok_or(AuthApiError::InvalidCredential)?
            .value()
            .to_owned();
        Some((user_id, cookie))
    } else {
        // The native contract is unchanged: the body carries the credential.
        // A cookie riding an unmarked request authenticates nothing, which is
        // what keeps a cross-site form post out.
        None
    };
    let token = match &presented {
        Some((_, cookie)) => cookie.as_str(),
        None => request
            .refresh_token
            .as_deref()
            .ok_or(AuthApiError::InvalidRequest)?,
    };
    let pair = state
        .service
        .refresh(token)
        .await
        .map_err(AuthApiError::Service)?;
    if let Some((user_id, cookie)) = &presented {
        // The name derivation already ties this cookie to this account, so a
        // rotated pair naming somebody else means the stored session and its
        // name disagree. Revoke the presented session and answer the generic
        // `401`: the audit row and this log line are where an operator learns
        // what happened.
        let named = serde_json::to_vec(*user_id).map_err(|_| AuthApiError::InvalidRequest)?;
        let rotated =
            serde_json::to_vec(&pair.user_id).map_err(|_| AuthApiError::InvalidRequest)?;
        if named != rotated {
            tracing::error!(
                "refresh cookie named an account the session does not belong to, revoking the presented session"
            );
            if let Some((session_id, _)) = split_refresh(cookie) {
                state.service.revoke(session_id).await.ok();
            }
            return Err(AuthApiError::InvalidCredential);
        }
        let name = refresh_cookie_name(*user_id)?;
        let cookie = refresh_cookie(
            name,
            pair.refresh_token,
            state.cookie_same_site,
            pair.session_expires_at_secs,
        );
        return Ok((
            jar.add(cookie),
            Json(TokenResponse {
                access_token: pair.access_token,
                refresh_token: None,
                expires_in: pair.expires_in_secs,
                user_id: pair.user_id,
                session_expires_at: pair.session_expires_at_secs,
            }),
        ));
    }
    Ok((jar, Json(pair.into())))
}

/// Revoke the session the presented refresh token names.
///
/// Always `204`, whether or not a session was revoked, so the endpoint cannot be
/// used to probe whether a guessed refresh token names a live session. The
/// client's own local teardown does not depend on the answer either: it clears
/// its stored credential regardless, because a device with no connectivity must
/// still be able to log out.
/// The marked path answers `204` whether or not a cookie rode the request,
/// exactly as the native path answers it whether or not the token named a
/// live session, and the account's cookie is cleared in the same response.
async fn logout<S: AuthStore + 'static>(
    State(state): State<AuthState<S>>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(request): Json<LogoutRequest<S::Id>>,
) -> Result<Response, AuthApiError> {
    let marked = is_marked_request(&headers)?;
    if marked {
        let user_id = request
            .user_id
            .as_ref()
            .ok_or(AuthApiError::InvalidRequest)?;
        if request.refresh_token.is_some() {
            return Err(AuthApiError::InvalidRequest);
        }
        let name = refresh_cookie_name(user_id)?;
        let revoked = match jar.get(&name) {
            Some(cookie) => {
                let token = cookie.value().to_owned();
                state.service.logout(&token).await.map(drop)
            }
            None => Ok(()),
        };
        // The removal rides every outcome, a failed revoke included, because
        // the worker drops its index row whatever the answer. It carries the
        // full attribute set since the prefix rules apply to a deletion too.
        let jar = jar.remove(refresh_cookie(
            name,
            String::new(),
            state.cookie_same_site,
            0,
        ));
        return Ok(match revoked {
            Ok(()) => (jar, StatusCode::NO_CONTENT).into_response(),
            Err(err) => (jar, AuthApiError::Service(err)).into_response(),
        });
    }
    let token = request
        .refresh_token
        .as_deref()
        .ok_or(AuthApiError::InvalidRequest)?;
    state
        .service
        .logout(token)
        .await
        .map_err(AuthApiError::Service)?;
    Ok(StatusCode::NO_CONTENT.into_response())
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
    use super::{CookieSameSite, REFRESH_COOKIE_PREFIX, is_loopback_host, refresh_cookie_name};

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
    #[test]
    fn the_cookie_name_is_the_prefix_over_base64url_of_the_serde_form() {
        // The quotes are part of the serde JSON form of a String id, and the
        // encoding is base64url without padding, a valid cookie-name token.
        assert_eq!(
            refresh_cookie_name(&"erin".to_owned()).expect("serializable"),
            format!("{REFRESH_COOKIE_PREFIX}ImVyaW4i"),
        );
    }

    #[test]
    fn only_the_two_samesite_names_parse() {
        assert_eq!(
            CookieSameSite::parse("strict"),
            Some(CookieSameSite::Strict)
        );
        assert_eq!(CookieSameSite::parse("none"), Some(CookieSameSite::None));
        for rejected in ["Strict", "None", "lax", "", "no-samesite"] {
            assert_eq!(CookieSameSite::parse(rejected), None, "{rejected}");
        }
    }
}
