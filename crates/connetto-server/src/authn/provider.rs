//! Identity providers, the issuer-indexed registry, and MFA assurance.
//!
//! One [`IdentityProvider`] per configured provider runs the Authorization Code
//! plus PKCE flow against that provider, verifies its ID token, and maps the
//! claims to a [`ResolvedIdentity`]. The enabled providers live in a runtime
//! [`ProviderRegistry`] indexed by issuer, with a matcher fallback for a
//! provider that accepts a pattern of issuers (any-tenant Microsoft). Routing on
//! the unverified issuer only selects a provider, and nothing is trusted until
//! the selected provider has cryptographically verified the token. The registry
//! is a boxed trait object, not a static tuple: routing is a runtime match
//! either way and every provider yields the same identity. See
//! `docs/architecture/11-authentication.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use uuid::Uuid;

use crate::authn::store::ResolvedIdentity;

/// A boxed, `Send` future, for the object-safe async provider methods.
pub type BoxFuture<'a, T> = core::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Failure of a provider operation.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The provider configuration or discovery was rejected.
    #[error("provider configuration error: {0}")]
    Config(String),
    /// The authorization-code exchange failed.
    #[error("token exchange failed: {0}")]
    Exchange(String),
    /// The ID token failed verification (signature, issuer, audience, expiry, nonce).
    #[error("id token verification failed: {0}")]
    Verification(String),
    /// The login did not meet the configured assurance bar.
    #[error("assurance requirement not met: {0}")]
    Assurance(String),
    /// Refreshing a retained provider token failed.
    #[error("provider token refresh failed: {0}")]
    Refresh(String),
    /// The provider returned no ID token.
    #[error("the provider returned no id token")]
    MissingIdToken,
}

/// The authorize redirect plus the secrets a caller persists server-side keyed
/// by `state`, to complete the flow at the callback.
#[derive(Debug, Clone)]
pub struct LoginRedirect {
    /// The URL to send the user agent to.
    pub authorize_url: String,
    /// The opaque CSRF state, echoed back at the callback.
    pub state: String,
    /// The nonce bound into the ID token, checked at verification.
    pub nonce: String,
    /// The PKCE verifier, presented at the code exchange. A secret.
    pub pkce_verifier: String,
}

/// A completed login: the mapped identity plus the retained provider tokens.
#[derive(Debug, Clone)]
pub struct VerifiedLogin {
    /// The identity to mint a connetto session for.
    pub identity: ResolvedIdentity,
    /// The provider tokens to retain for the lazy accessor.
    pub retained: RetainedProviderToken,
}

/// Provider tokens retained after login, refreshed lazily when about to be used.
#[derive(Debug, Clone)]
pub struct RetainedProviderToken {
    /// The issuer these tokens belong to, so a refresh routes to its provider.
    pub issuer: String,
    /// The provider access token.
    pub access_token: String,
    /// The provider refresh token, when the provider issued one.
    pub refresh_token: Option<String>,
    /// When the access token expires, when the provider stated a lifetime.
    pub expires_at: Option<SystemTime>,
}

/// A multi-factor assurance bar and the request parameters that ask for it.
///
/// `acr_values` and `max_age` are sent on the authorize request. `acr_values`
/// and `required_amr` are then enforced against the verified ID token: if
/// `acr_values` is non-empty the token's `acr` must be one of them, and every
/// entry in `required_amr` must appear in the token's `amr`.
#[derive(Debug, Clone, Default)]
pub struct AssuranceRequirement {
    /// Acceptable `acr` values, requested and enforced. Empty means unenforced.
    pub acr_values: Vec<String>,
    /// Authentication methods that must all be present in the token's `amr`.
    pub required_amr: Vec<String>,
    /// The `max_age` request parameter, when set.
    pub max_age: Option<Duration>,
}

impl AssuranceRequirement {
    /// No assurance bar: accept any `acr`/`amr`. The default.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Whether an achieved `(acr, amr)` meets this bar.
    #[must_use]
    pub fn is_satisfied(&self, acr: Option<&str>, amr: &[&str]) -> bool {
        if !self.acr_values.is_empty()
            && !acr.is_some_and(|got| self.acr_values.iter().any(|want| want == got))
        {
            return false;
        }
        self.required_amr
            .iter()
            .all(|want| amr.iter().any(|got| got == want))
    }
}

/// One identity provider. Verification is off the hot path (once per login), so
/// the async methods are boxed trait-object futures.
pub trait IdentityProvider: Send + Sync {
    /// The provider's configured name, for the by-name lookup that starts a flow.
    fn name(&self) -> &str;

    /// The issuer used as the registry index key. For a pattern provider this is
    /// a representative string, and [`matches_issuer`](Self::matches_issuer) does
    /// the real check.
    fn issuer(&self) -> &str;

    /// Whether this provider verifies tokens from `issuer`. Default is exact.
    fn matches_issuer(&self, issuer: &str) -> bool {
        self.issuer() == issuer
    }

    /// Build the authorize redirect: PKCE, scopes, and the assurance request
    /// parameters. Synchronous, no network.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] if the authorize URL cannot be built.
    fn begin_login(&self) -> Result<LoginRedirect, ProviderError>;

    /// Exchange `code` for provider tokens, verify the ID token against `nonce`,
    /// enforce assurance, map the claims, and retain the tokens.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] on exchange, verification, or assurance failure.
    fn complete_login<'a>(
        &'a self,
        code: &'a str,
        pkce_verifier: &'a str,
        nonce: &'a str,
    ) -> BoxFuture<'a, Result<VerifiedLogin, ProviderError>>;

    /// Refresh a retained provider token against the provider.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Refresh`] on failure.
    fn refresh_provider_token<'a>(
        &'a self,
        refresh_token: &'a str,
    ) -> BoxFuture<'a, Result<RetainedProviderToken, ProviderError>>;
}

/// The enabled providers, indexed by issuer with a matcher fallback and a
/// by-name lookup for starting a flow. A deployment composes the set it enables,
/// with no blessed default.
#[derive(Default)]
pub struct ProviderRegistry {
    by_name: HashMap<String, Arc<dyn IdentityProvider>>,
    by_issuer: HashMap<String, Arc<dyn IdentityProvider>>,
    all: Vec<Arc<dyn IdentityProvider>>,
}

impl ProviderRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable a provider. A later registration under the same name or issuer
    /// replaces the earlier index entry.
    pub fn register(&mut self, provider: Arc<dyn IdentityProvider>) {
        self.by_name
            .insert(provider.name().to_owned(), Arc::clone(&provider));
        self.by_issuer
            .insert(provider.issuer().to_owned(), Arc::clone(&provider));
        self.all.push(provider);
    }

    /// The provider to start a flow with, by configured name.
    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&Arc<dyn IdentityProvider>> {
        self.by_name.get(name)
    }

    /// The provider that verifies tokens from `issuer`: the index first, then
    /// the matcher fallback for a pattern provider.
    #[must_use]
    pub fn by_issuer(&self, issuer: &str) -> Option<&Arc<dyn IdentityProvider>> {
        self.by_issuer.get(issuer).or_else(|| {
            self.all
                .iter()
                .find(|provider| provider.matches_issuer(issuer))
        })
    }

    /// The number of enabled providers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.all.len()
    }

    /// Whether no provider is enabled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.all.is_empty()
    }
}

/// A stand-in [`IdentityProvider`] that resolves to a configured identity with
/// no live provider, mirroring the permissive stand-ins elsewhere.
///
/// It performs no OAuth flow and verifies nothing, so it MUST NOT front a
/// production deployment. It lets tests and local loops exercise the login path.
pub struct PermissiveProvider {
    name: String,
    issuer: String,
    identity: ResolvedIdentity,
}

impl PermissiveProvider {
    /// Build a provider that always resolves to `identity`.
    #[must_use]
    pub fn new(name: impl Into<String>, identity: ResolvedIdentity) -> Self {
        let issuer = identity.issuer.clone();
        Self {
            name: name.into(),
            issuer,
            identity,
        }
    }

    fn retained(&self) -> RetainedProviderToken {
        RetainedProviderToken {
            issuer: self.issuer.clone(),
            access_token: "permissive-access-token".to_owned(),
            refresh_token: Some("permissive-refresh-token".to_owned()),
            expires_at: None,
        }
    }
}

impl IdentityProvider for PermissiveProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn issuer(&self) -> &str {
        &self.issuer
    }

    fn begin_login(&self) -> Result<LoginRedirect, ProviderError> {
        let state = Uuid::new_v4().to_string();
        Ok(LoginRedirect {
            // Echo the state in the URL the way a real provider does, so a
            // caller can carry it to the callback.
            authorize_url: format!("about:blank?state={state}"),
            state,
            nonce: Uuid::new_v4().to_string(),
            pkce_verifier: Uuid::new_v4().to_string(),
        })
    }

    fn complete_login<'a>(
        &'a self,
        _code: &'a str,
        _pkce_verifier: &'a str,
        _nonce: &'a str,
    ) -> BoxFuture<'a, Result<VerifiedLogin, ProviderError>> {
        Box::pin(async move {
            Ok(VerifiedLogin {
                identity: self.identity.clone(),
                retained: self.retained(),
            })
        })
    }

    fn refresh_provider_token<'a>(
        &'a self,
        _refresh_token: &'a str,
    ) -> BoxFuture<'a, Result<RetainedProviderToken, ProviderError>> {
        Box::pin(async move { Ok(self.retained()) })
    }
}

/// One in-flight authorization, held server-side between the login redirect and
/// the callback, keyed by the CSRF `state`.
#[derive(Debug, Clone)]
pub struct PendingLogin {
    /// The provider name the flow was started with.
    pub provider: String,
    /// The PKCE verifier to present at the code exchange with the provider. A secret.
    pub pkce_verifier: String,
    /// The nonce to check against the ID token.
    pub nonce: String,
    /// A native client's loopback redirect, when the flow is a loopback login.
    /// Its presence switches the callback from returning tokens as JSON to
    /// redirecting the browser back with a one-time connetto authorization code.
    pub client_redirect: Option<String>,
    /// The client's own PKCE S256 challenge, verified at the code exchange.
    pub client_code_challenge: Option<String>,
    /// The client's own CSRF state, echoed back to its redirect.
    pub client_state: Option<String>,
}

/// How long an in-flight authorization stays valid before the callback is
/// refused. The provider round-trip is interactive but bounded.
const PENDING_LOGIN_TTL: Duration = Duration::from_secs(600);
/// How long a one-time authorization code stays redeemable, short per RFC 6749
/// since the loopback or tab round-trip that redeems it is immediate.
const AUTH_CODE_TTL: Duration = Duration::from_secs(60);

/// Whether an entry stamped at `created_at` is past `ttl` as of `now`.
fn is_expired(created_at: Instant, now: Instant, ttl: Duration) -> bool {
    now.duration_since(created_at) > ttl
}

/// When `map` is at `cap`, drop expired entries first, then the oldest if still
/// full, so a bounded map evicts by age rather than by arbitrary hash order.
fn evict_if_full<V>(
    map: &mut HashMap<String, V>,
    cap: usize,
    now: Instant,
    ttl: Duration,
    created_at: impl Fn(&V) -> Instant,
) {
    if map.len() < cap {
        return;
    }
    map.retain(|_, value| !is_expired(created_at(value), now, ttl));
    if map.len() >= cap
        && let Some(oldest) = map
            .iter()
            .min_by_key(|(_, value)| created_at(value))
            .map(|(key, _)| key.clone())
    {
        map.remove(&oldest);
    }
}

/// A pending authorization with the instant it was recorded, for TTL expiry.
struct PendingEntry {
    login: PendingLogin,
    created_at: Instant,
}

/// The in-flight authorizations, keyed by `state`. Bounded and time-limited: an
/// entry past `PENDING_LOGIN_TTL` is refused at the callback and dropped, and
/// when the cap is reached expired entries go first, then the oldest.
pub struct PendingLogins {
    inner: std::sync::Mutex<HashMap<String, PendingEntry>>,
    cap: usize,
    ttl: Duration,
}

impl PendingLogins {
    /// A store holding at most `cap` in-flight authorizations, each valid for
    /// `ttl`.
    #[must_use]
    pub fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            inner: std::sync::Mutex::new(HashMap::new()),
            cap,
            ttl,
        }
    }

    /// Record an in-flight authorization under `state`.
    pub fn insert(&self, state: String, pending: PendingLogin) {
        let now = Instant::now();
        let mut map = self.inner.lock().expect("pending logins lock");
        if !map.contains_key(&state) {
            evict_if_full(&mut map, self.cap, now, self.ttl, |entry| entry.created_at);
        }
        map.insert(
            state,
            PendingEntry {
                login: pending,
                created_at: now,
            },
        );
    }

    /// Remove and return the authorization for `state`, consuming it so a
    /// callback cannot be replayed. An entry past its TTL is dropped and treated
    /// as absent.
    #[must_use]
    pub fn take(&self, state: &str) -> Option<PendingLogin> {
        let now = Instant::now();
        let entry = self
            .inner
            .lock()
            .expect("pending logins lock")
            .remove(state)?;
        (!is_expired(entry.created_at, now, self.ttl)).then_some(entry.login)
    }
}

impl Default for PendingLogins {
    fn default() -> Self {
        Self::new(4096, PENDING_LOGIN_TTL)
    }
}

/// A one-time connetto authorization code issued to a loopback client, holding
/// the minted token pair until the client redeems it at the token endpoint with
/// its PKCE verifier.
#[derive(Debug, Clone)]
pub struct IssuedAuthCode<Id> {
    /// The access token to hand back on redemption.
    pub access_token: String,
    /// The refresh token to hand back on redemption.
    pub refresh_token: String,
    /// The access token lifetime in seconds.
    pub expires_in_secs: u64,
    /// The typed `user_id` the redeemed pair belongs to.
    pub user_id: Id,
    /// Unix-seconds instant the local session lapses without a further refresh.
    pub session_expires_at_secs: u64,
    /// The client's PKCE S256 challenge that the redeeming verifier must match.
    pub code_challenge: String,
}

/// A one-time code with the instant it was issued, for TTL expiry.
struct CodeEntry<Id> {
    code: IssuedAuthCode<Id>,
    created_at: Instant,
}

/// The outstanding one-time authorization codes, keyed by the code. Bounded,
/// single-use, and time-limited: a code is removed the moment it is redeemed,
/// an entry past `AUTH_CODE_TTL` is refused and dropped, and when the cap is
/// reached expired codes go first, then the oldest.
pub struct AuthCodes<Id> {
    inner: std::sync::Mutex<HashMap<String, CodeEntry<Id>>>,
    cap: usize,
    ttl: Duration,
}

impl<Id> AuthCodes<Id> {
    /// A store holding at most `cap` outstanding codes, each valid for `ttl`.
    #[must_use]
    pub fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            inner: std::sync::Mutex::new(HashMap::new()),
            cap,
            ttl,
        }
    }

    /// Issue a code for `issued`, returning the opaque code string.
    pub fn issue(&self, issued: IssuedAuthCode<Id>) -> String {
        let now = Instant::now();
        let code = format!(
            "{}{}",
            uuid::Uuid::new_v4().as_simple(),
            uuid::Uuid::new_v4().as_simple()
        );
        let mut map = self.inner.lock().expect("auth codes lock");
        evict_if_full(&mut map, self.cap, now, self.ttl, |entry| entry.created_at);
        map.insert(
            code.clone(),
            CodeEntry {
                code: issued,
                created_at: now,
            },
        );
        code
    }

    /// Remove and return the code, consuming it so it cannot be redeemed twice.
    /// A code past its TTL is dropped and treated as absent.
    #[must_use]
    pub fn redeem(&self, code: &str) -> Option<IssuedAuthCode<Id>> {
        let now = Instant::now();
        let entry = self.inner.lock().expect("auth codes lock").remove(code)?;
        (!is_expired(entry.created_at, now, self.ttl)).then_some(entry.code)
    }
}

impl<Id> Default for AuthCodes<Id> {
    fn default() -> Self {
        Self::new(4096, AUTH_CODE_TTL)
    }
}

#[cfg(test)]
mod tests {
    // The stand-in providers return `&str` literals from trait methods whose
    // signature is fixed, so the lifetime-tightening lint does not apply.
    #![allow(clippy::unnecessary_literal_bound)]
    use super::*;
    use std::collections::BTreeMap;

    fn identity(issuer: &str, subject: &str) -> ResolvedIdentity {
        ResolvedIdentity {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            email: None,
            name: None,
            amr: Vec::new(),
            acr: None,
            tenant_id: None,
            roles: Vec::new(),
            claims: BTreeMap::new(),
        }
    }

    /// A provider whose issuer matches by prefix, standing in for a pattern
    /// provider to exercise the registry's matcher fallback.
    struct PatternProvider;

    impl IdentityProvider for PatternProvider {
        fn name(&self) -> &str {
            "pattern"
        }
        fn issuer(&self) -> &str {
            "pattern-index-key"
        }
        fn matches_issuer(&self, issuer: &str) -> bool {
            issuer.starts_with("https://login.microsoftonline.com/")
        }
        fn begin_login(&self) -> Result<LoginRedirect, ProviderError> {
            Err(ProviderError::Config("test".to_owned()))
        }
        fn complete_login<'a>(
            &'a self,
            _code: &'a str,
            _pkce_verifier: &'a str,
            _nonce: &'a str,
        ) -> BoxFuture<'a, Result<VerifiedLogin, ProviderError>> {
            Box::pin(async { Err(ProviderError::Config("test".to_owned())) })
        }
        fn refresh_provider_token<'a>(
            &'a self,
            _refresh_token: &'a str,
        ) -> BoxFuture<'a, Result<RetainedProviderToken, ProviderError>> {
            Box::pin(async { Err(ProviderError::Refresh("test".to_owned())) })
        }
    }

    #[test]
    fn registry_routes_by_name_issuer_and_matcher() {
        let mut registry = ProviderRegistry::new();
        registry.register(Arc::new(PermissiveProvider::new(
            "google",
            identity("https://accounts.google.com", "u"),
        )));
        registry.register(Arc::new(PatternProvider));

        assert_eq!(registry.len(), 2);
        assert!(registry.by_name("google").is_some());
        assert!(registry.by_name("absent").is_none());
        // Exact issuer index hit.
        assert_eq!(
            registry
                .by_issuer("https://accounts.google.com")
                .map(|p| p.name()),
            Some("google"),
        );
        // Index miss falls through to the pattern matcher.
        assert_eq!(
            registry
                .by_issuer("https://login.microsoftonline.com/tenant-1/v2.0")
                .map(|p| p.name()),
            Some("pattern"),
        );
        assert!(registry.by_issuer("https://unknown.example").is_none());
    }

    #[test]
    fn assurance_enforces_acr_allowlist_and_required_amr() {
        let bar = AssuranceRequirement {
            acr_values: vec!["high".to_owned()],
            required_amr: vec!["mfa".to_owned()],
            max_age: None,
        };
        assert!(bar.is_satisfied(Some("high"), &["mfa", "pwd"]));
        // acr not in the allowlist.
        assert!(!bar.is_satisfied(Some("low"), &["mfa"]));
        // acr absent when one is required.
        assert!(!bar.is_satisfied(None, &["mfa"]));
        // a required amr is missing.
        assert!(!bar.is_satisfied(Some("high"), &["pwd"]));
        // no bar accepts anything.
        assert!(AssuranceRequirement::none().is_satisfied(None, &[]));
    }

    #[tokio::test]
    async fn permissive_provider_resolves_its_configured_identity() {
        let provider = PermissiveProvider::new("dev", identity("https://dev", "alice"));
        let redirect = provider.begin_login().expect("begin");
        assert!(redirect.authorize_url.contains("state="));
        let login = provider
            .complete_login("code", &redirect.pkce_verifier, &redirect.nonce)
            .await
            .expect("complete");
        assert_eq!(login.identity.subject, "alice");
        assert_eq!(login.retained.issuer, "https://dev");
    }

    fn sample_pending() -> PendingLogin {
        PendingLogin {
            provider: "permissive".to_owned(),
            pkce_verifier: "verifier".to_owned(),
            nonce: "nonce".to_owned(),
            client_redirect: None,
            client_code_challenge: None,
            client_state: None,
        }
    }

    fn sample_code() -> IssuedAuthCode<String> {
        IssuedAuthCode {
            access_token: "access".to_owned(),
            refresh_token: "refresh".to_owned(),
            expires_in_secs: 900,
            user_id: "user".to_owned(),
            session_expires_at_secs: 0,
            code_challenge: "challenge".to_owned(),
        }
    }

    #[test]
    fn a_pending_login_past_its_ttl_is_refused() {
        let pending = PendingLogins::new(16, Duration::from_millis(5));
        pending.insert("state-1".to_owned(), sample_pending());
        std::thread::sleep(Duration::from_millis(25));
        assert!(
            pending.take("state-1").is_none(),
            "an expired pending login is dropped"
        );
    }

    #[test]
    fn pending_logins_evict_the_oldest_at_cap() {
        let pending = PendingLogins::new(2, Duration::from_secs(60));
        pending.insert("a".to_owned(), sample_pending());
        std::thread::sleep(Duration::from_millis(2));
        pending.insert("b".to_owned(), sample_pending());
        std::thread::sleep(Duration::from_millis(2));
        pending.insert("c".to_owned(), sample_pending());
        assert!(
            pending.take("a").is_none(),
            "the oldest entry is evicted at cap"
        );
        assert!(pending.take("b").is_some());
        assert!(pending.take("c").is_some());
    }

    #[test]
    fn an_auth_code_past_its_ttl_is_refused() {
        let codes = AuthCodes::new(16, Duration::from_millis(5));
        let code = codes.issue(sample_code());
        std::thread::sleep(Duration::from_millis(25));
        assert!(codes.redeem(&code).is_none(), "an expired code is refused");
    }

    #[test]
    fn an_auth_code_is_single_use() {
        let codes = AuthCodes::new(16, Duration::from_secs(60));
        let code = codes.issue(sample_code());
        assert!(codes.redeem(&code).is_some());
        assert!(
            codes.redeem(&code).is_none(),
            "a code cannot be redeemed twice"
        );
    }

    #[test]
    fn auth_codes_evict_the_oldest_at_cap() {
        let codes = AuthCodes::new(2, Duration::from_secs(60));
        let first = codes.issue(sample_code());
        std::thread::sleep(Duration::from_millis(2));
        let second = codes.issue(sample_code());
        std::thread::sleep(Duration::from_millis(2));
        let third = codes.issue(sample_code());
        assert!(
            codes.redeem(&first).is_none(),
            "the oldest code is evicted at cap"
        );
        assert!(codes.redeem(&second).is_some());
        assert!(codes.redeem(&third).is_some());
    }
}
