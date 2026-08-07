//! Phase E4.a: the shared OAuth spine, against a real identity provider.
//!
//! The dance is one implementation for both the native and the browser client:
//! the user agent navigates to `/auth/login`, connetto redirects it to the
//! provider's authorize endpoint, the provider redirects it back to
//! `/auth/callback`, connetto exchanges the code with the provider server to
//! server, and connetto redirects the user agent to the client's redirect URI
//! carrying connetto's own one-time code. Nothing in those steps is
//! native-specific or browser-specific, so proving them once proves them for
//! both.
//!
//! Before this test, none of it had ever run. Every other test either uses
//! the since-deleted permissive stand-in provider, which performed no I/O at
//! all, or `GenericOidcProvider::from_parts`, which `provider.rs` uses
//! precisely because it needs no network. So discovery, the token exchange, and
//! the JWKS fetch had never executed, and the provider's authorize endpoint had
//! never been requested by anything.
//!
//! Here `GenericOidcProvider` is pointed, unchanged, at `oauth2-test-server`: a
//! real OIDC implementation on a real loopback socket that serves a discovery
//! document, a JWKS endpoint, and RS256 ID tokens carrying the nonce, and that
//! auto-grants consent in its authorize handler so no human and no login form is
//! involved. Both servers run in this process, exactly as `authn_flow.rs` and
//! `native_auth.rs` already serve connetto's own router in-process, and every
//! request between them is real HTTP.
//!
//! What this deliberately does not cover is the user agent. An HTTP client walks
//! the redirect chain instead of a browser, so origin and navigation semantics
//! are absent, which is what the browser leg of E4 owes. Two defects already
//! found by reading live in that gap: the deleted permissive stand-in's
//! authorize URL, and the same-origin constraint on the worker's `fetch` calls.

use core::future::Future;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::HandshakeAuthority;
use connetto_core::messages::Grant;
use connetto_server::authn::identity::deterministic_uuid;
use connetto_server::{
    AbuseConfig, AssuranceRequirement, AuthConfig, AuthError, AuthService, AuthStore,
    AuthStoreError, GenericOidcProvider, InMemoryAuthStore, OidcProviderConfig, ProviderRegistry,
    RedirectPolicy, RequestGuard, ThrottleConfig, TokenAuthority, auth_router,
};
// The same path `provider_oidc.rs` uses: `reqwest` is not a direct dependency of
// this crate, it arrives through `openidconnect`, so the test client is built
// from the very client type the provider is handed.
use oauth2_test_server::{IssuerConfig, OAuthTestServer};
use openidconnect::reqwest;
use serde_json::json;

/// The provider name the login request selects by.
const PROVIDER: &str = "mock-idp";

/// The subject `oauth2-test-server` puts in every ID token it issues, from its
/// own `IssuerConfig::default`. The identity connetto resolves is derived from
/// it, so the test asserts against this rather than against a literal user id.
const IDP_SUBJECT: &str = "test-user-123";

/// A client redirect the login endpoint accepts without registration, because
/// [`RedirectPolicy`] treats any RFC 8252 loopback as allowed. Nothing listens
/// there: the test reads the code out of the redirect rather than following it,
/// which is what a native client's loopback listener would otherwise do.
const CLIENT_REDIRECT: &str = "http://127.0.0.1:1/callback";

/// One HTTP client for the whole test, with redirect following off so every hop
/// of the dance can be asserted rather than silently collapsed into its result.
fn user_agent() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build the user agent")
}

/// The `Location` of a response that must be a redirect.
fn location(response: &reqwest::Response) -> String {
    assert!(
        response.status().is_redirection(),
        "expected a redirect, got {}",
        response.status()
    );
    response
        .headers()
        .get("location")
        .expect("a redirect carries a location")
        .to_str()
        .expect("a utf-8 location")
        .to_owned()
}

/// One query parameter of `url`.
fn query_param(url: &str, key: &str) -> Option<String> {
    let parsed = url::Url::parse(url).expect("a parseable url");
    parsed
        .query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

/// connetto's auth endpoints on a real socket, in front of a real identity
/// provider on another, with the provider's client registered against connetto's
/// callback and the provider discovered over real HTTP.
struct Stack {
    connetto_base: String,
    idp_issuer: String,
    service: Arc<AuthService<InMemoryAuthStore>>,
    /// Held so the provider stays alive for the test's duration.
    _idp: OAuthTestServer,
}

impl Stack {
    async fn start() -> Self {
        // connetto's listener is bound first, because the callback URL it will
        // serve has to be registered with the provider as an exact redirect match
        // before the provider is discovered, and the router cannot be built until
        // the provider exists.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind connetto's auth endpoints");
        let connetto_base = format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("addr").port()
        );
        let connetto_callback = format!("{connetto_base}/auth/callback");

        // A real OIDC provider on its own loopback socket. Its host is pinned to
        // the address it is actually reachable at: `oauth2-test-server` defaults
        // to publishing `localhost` in its discovery document while binding
        // 127.0.0.1, and `openidconnect` correctly refuses a document whose
        // `issuer` does not equal the URL it was fetched from.
        let idp = OAuthTestServer::start_with_config(IssuerConfig {
            host: "127.0.0.1".into(),
            port: 0,
            ..IssuerConfig::default()
        })
        .await;
        let idp_issuer = idp.base_url.to_string().trim_end_matches('/').to_owned();
        let client = idp
            .register_client(json!({
                "redirect_uris": [connetto_callback.clone()],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": "openid",
            }))
            .await;
        assert!(
            client.client_secret.is_some(),
            "connetto is a confidential client, so the registration must issue a secret"
        );

        // Discovery is a real HTTP GET, and it is also what pins the issuer.
        let provider = GenericOidcProvider::discover(
            OidcProviderConfig {
                name: PROVIDER.to_owned(),
                client_id: client.client_id.clone(),
                client_secret: client.client_secret.clone(),
                issuer: idp_issuer.clone(),
                redirect_url: connetto_callback.clone(),
                scopes: Vec::new(),
                // The mock issues no `amr` or `acr`, and asking for assurance it
                // cannot express would test the bar rather than the spine. The
                // bar itself is covered by `provider.rs`.
                assurance: AssuranceRequirement::none(),
            },
            reqwest::Client::new(),
        )
        .await
        .expect("discover the provider over real HTTP");

        let config = AuthConfig::default();
        let authority = Arc::new(TokenAuthority::generate(&config).expect("keypair"));
        let store = Arc::new(InMemoryAuthStore::new(config.refresh_lifetimes()));
        let service = Arc::new(AuthService::new(
            authority,
            store,
            Arc::new(RequestGuard::default()),
        ));
        let mut registry = ProviderRegistry::new();
        registry.register(Arc::new(provider));
        let router = auth_router(
            Arc::clone(&service),
            Arc::new(registry),
            RedirectPolicy::default(),
        );
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve");
        });

        Self {
            connetto_base,
            idp_issuer,
            service,
            _idp: idp,
        }
    }

    /// connetto's callback URL, which is also the provider's registered redirect.
    fn callback(&self) -> String {
        format!("{}/auth/callback", self.connetto_base)
    }
}

/// The client's own PKCE pair, the one connetto's token endpoint checks. It is
/// distinct from the pair connetto mints for the provider: two PKCE exchanges are
/// layered here, the client's against connetto and connetto's against the
/// provider.
fn client_pkce() -> (&'static str, String) {
    use base64::Engine as _;
    use sha2::Digest as _;

    let verifier = "e4a-client-verifier-with-enough-entropy-for-s256";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// The whole spine in one pass, with every hop asserted: connetto's login
/// redirect lands on the provider, the provider's redirect lands back on
/// connetto's callback, connetto's callback hands the user agent a one-time code
/// at the client's redirect URI, and redeeming that code yields a connetto access
/// token whose session the real handshake verifier accepts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn the_oauth_spine_completes_against_a_real_identity_provider() {
    let stack = Stack::start().await;
    let base = &stack.connetto_base;
    let idp_issuer = &stack.idp_issuer;
    let connetto_callback = stack.callback();
    let agent = user_agent();

    // Step one. The user agent navigates to connetto's login endpoint, carrying
    // the client's own redirect, PKCE challenge, and state, which is what both
    // real clients send.
    let (client_verifier, client_challenge) = client_pkce();
    let login = agent
        .get(format!("{base}/auth/login"))
        .query(&[
            ("provider", PROVIDER),
            ("redirect_uri", CLIENT_REDIRECT),
            ("code_challenge", &client_challenge),
            ("state", "client-state-e4a"),
        ])
        .send()
        .await
        .expect("GET /auth/login");
    let authorize_url = location(&login);

    // Step two. That redirect points at the provider, not at connetto, and it
    // carries the provider-side PKCE challenge and nonce that connetto minted.
    assert!(
        authorize_url.starts_with(&format!("{idp_issuer}/authorize")),
        "the login redirect must land on the provider's authorize endpoint, got {authorize_url}"
    );
    assert_eq!(
        query_param(&authorize_url, "code_challenge_method").as_deref(),
        Some("S256"),
        "connetto must use PKCE S256 against the provider"
    );
    assert!(
        query_param(&authorize_url, "nonce").is_some(),
        "and must bind a nonce it will check in the ID token"
    );
    assert_eq!(
        query_param(&authorize_url, "redirect_uri").as_deref(),
        Some(connetto_callback.as_str()),
        "the provider redirects back to connetto, never to the client"
    );

    // Step three. The provider auto-grants consent and redirects back to
    // connetto's callback with its own authorization code.
    let authorized = agent
        .get(&authorize_url)
        .send()
        .await
        .expect("GET the provider's authorize endpoint");
    let callback_url = location(&authorized);
    assert!(
        callback_url.starts_with(&connetto_callback),
        "the provider must redirect back to connetto's callback, got {callback_url}"
    );
    assert!(
        query_param(&callback_url, "code").is_some(),
        "carrying a provider authorization code"
    );

    // Step four, which is where the work happens and where nothing is visible
    // from outside: connetto exchanges that code with the provider server to
    // server, fetches the JWKS, verifies the ID token's signature, issuer,
    // audience, and nonce, resolves an identity, and mints its own session. A
    // failure in any of it surfaces here as a non-redirect status.
    let completed = agent
        .get(&callback_url)
        .send()
        .await
        .expect("GET /auth/callback");
    let client_landing = location(&completed);

    // Step five. The user agent is sent to the client's own redirect URI with
    // connetto's one-time code and the client's state echoed back.
    assert!(
        client_landing.starts_with(CLIENT_REDIRECT),
        "connetto must deliver the code to the client's redirect, got {client_landing}"
    );
    assert_eq!(
        query_param(&client_landing, "state").as_deref(),
        Some("client-state-e4a"),
        "the client's own state is echoed, not the provider's"
    );
    let connetto_code = query_param(&client_landing, "code").expect("connetto's one-time code");

    // The client redeems that code with its PKCE verifier, which is the first
    // moment it holds a connetto token.
    let tokens: serde_json::Value = agent
        .post(format!("{base}/auth/token"))
        .json(&json!({ "code": connetto_code, "code_verifier": client_verifier }))
        .send()
        .await
        .expect("POST /auth/token")
        .json()
        .await
        .expect("a token response");
    let access_token = tokens["access_token"]
        .as_str()
        .expect("an access token")
        .to_owned();
    assert!(
        tokens["refresh_token"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "and a refresh token to resume with"
    );

    // The identity is the one the provider asserted, mapped through the store's
    // resolver. Deriving the expectation with the very function the resolver
    // calls makes this an assertion about the mapping rather than a restatement
    // of a constant that could drift from it.
    let expected_user_id = deterministic_uuid(idp_issuer, IDP_SUBJECT).to_string();
    assert_eq!(
        tokens["user_id"].as_str(),
        Some(expected_user_id.as_str()),
        "the session belongs to the identity the provider asserted"
    );

    // And the session is live: the real handshake verifier accepts the token
    // connetto minted from a provider login, which is the whole point of the
    // spine.
    let authority: &dyn HandshakeAuthority = &stack.service.handshake_authority();
    let verified = authority
        .check_grant(&Grant::new(&access_token))
        .await
        .expect("the minted session verifies at the handshake");
    let connetto_core::Subject::Identity(session) = verified else {
        panic!("expected identity subject from spine token");
    };
    assert_eq!(session.context.user_id, expected_user_id);
}

/// A provider code minted under one login cannot be redeemed against another
/// login's pending state, and this pins **which** guard stops it.
///
/// Both a PKCE verifier and a nonce are minted per login, and they fire in that
/// order: the token exchange presents the second login's verifier against a code
/// carrying the first login's challenge, so the provider refuses the exchange and
/// the ID token is never issued, which means the nonce check behind it is not
/// reachable from the HTTP surface at all. connetto renders a provider that
/// refuses an exchange as `502`, an upstream fault, rather than as a rejected
/// credential. The nonce check itself is covered directly by `provider.rs`, which
/// hands `verify_claims` a locally minted token with the wrong nonce.
///
/// Asserting the status rather than merely "not 200" is deliberate: if a later
/// change dropped the per-login PKCE binding, this would move to `401` or, worse,
/// succeed, and either would be visible here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_code_cannot_be_redeemed_against_another_logins_pending_state() {
    let stack = Stack::start().await;
    let base = &stack.connetto_base;
    let agent = user_agent();

    // Two logins are started, so two pending states exist, each with its own
    // PKCE verifier and nonce.
    let mut authorize_urls = Vec::new();
    for tag in ["first", "second"] {
        let login = agent
            .get(format!("{base}/auth/login"))
            .query(&[("provider", PROVIDER), ("state", tag)])
            .send()
            .await
            .expect("GET /auth/login");
        authorize_urls.push(location(&login));
    }
    // Both per-login secrets must actually differ, or this test proves nothing.
    let first_nonce = query_param(&authorize_urls[0], "nonce").expect("a nonce");
    let second_nonce = query_param(&authorize_urls[1], "nonce").expect("a nonce");
    assert_ne!(first_nonce, second_nonce, "each login mints its own nonce");
    let first_challenge = query_param(&authorize_urls[0], "code_challenge").expect("a challenge");
    let second_challenge = query_param(&authorize_urls[1], "code_challenge").expect("a challenge");
    assert_ne!(
        first_challenge, second_challenge,
        "and its own PKCE challenge, which is the guard that fires first"
    );

    // The first login is walked to the point of holding a provider code.
    let authorized = agent
        .get(&authorize_urls[0])
        .send()
        .await
        .expect("authorize the first login");
    let first_callback = location(&authorized);
    let first_code = query_param(&first_callback, "code").expect("a provider code");
    let second_state =
        query_param(&authorize_urls[1], "state").expect("connetto's state for the second login");

    // That code is presented against the SECOND login's state, so connetto
    // exchanges it with the second login's PKCE verifier. The provider refuses,
    // because the code was minted against the first login's challenge, and no ID
    // token is ever issued. Without the per-login PKCE binding this would reach
    // the nonce check instead, and without either it would mint a session.
    let crossed = agent
        .get(format!("{base}/auth/callback"))
        .query(&[
            ("code", first_code.as_str()),
            ("state", second_state.as_str()),
        ])
        .send()
        .await
        .expect("GET /auth/callback with a crossed code");
    assert_eq!(
        crossed.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "the provider refuses the exchange, which connetto renders as an upstream fault"
    );
}

/// A login that names no configured provider is a `404`, and one whose redirect
/// is neither a loopback nor allowlisted is a `400`. Both are cheap to assert on
/// the real router while it is up, and both are the guards that keep the spine
/// from delivering a minted code somewhere it should not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_login_endpoint_refuses_an_unknown_provider_and_an_offsite_redirect() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind connetto's auth endpoints");
    let connetto_base = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("addr").port()
    );

    let config = AuthConfig::default();
    let authority = Arc::new(TokenAuthority::generate(&config).expect("keypair"));
    let store = Arc::new(InMemoryAuthStore::new(config.refresh_lifetimes()));
    let service = Arc::new(AuthService::new(
        authority,
        store,
        Arc::new(RequestGuard::default()),
    ));
    let router = auth_router(
        service,
        Arc::new(ProviderRegistry::new()),
        RedirectPolicy::default(),
    );
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });

    let agent = user_agent();

    let unknown = agent
        .get(format!("{connetto_base}/auth/login"))
        .query(&[("provider", "no-such-provider")])
        .send()
        .await
        .expect("GET /auth/login");
    assert_eq!(unknown.status(), reqwest::StatusCode::NOT_FOUND);

    // An off-origin redirect with a well-formed PKCE pair: rejected on the
    // redirect alone, before any provider is consulted.
    let offsite = agent
        .get(format!("{connetto_base}/auth/login"))
        .query(&[
            ("provider", "no-such-provider"),
            ("redirect_uri", "https://attacker.example/steal"),
            ("code_challenge", "challenge"),
            ("state", "s"),
        ])
        .send()
        .await
        .expect("GET /auth/login");
    assert_eq!(
        offsite.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "an off-origin redirect is refused before the provider lookup"
    );
}

/// Guessing a refresh secret is answered with `429` and a `Retry-After` once
/// the session it names is out of allowance (R19).
///
/// The presented token is `<session>.<secret>`, so a caller guessing the secret
/// still says which session it is guessing at, and that name is the key. The
/// second attempt never reaches the store: a caller past its limit must not be
/// able to interleave guesses with valid attempts to keep going.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_guessed_refresh_token_is_rate_limited_after_its_session_runs_out() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind connetto's auth endpoints");
    let connetto_base = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().expect("addr").port()
    );

    let config = AuthConfig::default();
    let authority = Arc::new(TokenAuthority::generate(&config).expect("keypair"));
    let store = Arc::new(InMemoryAuthStore::new(config.refresh_lifetimes()));
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::new().refresh_failures_per_session(1, Duration::from_secs(300)),
        AbuseConfig::default(),
    ));
    let service = Arc::new(AuthService::new(authority, store, guard));
    let router = auth_router(
        service,
        Arc::new(ProviderRegistry::new()),
        RedirectPolicy::default(),
    );
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });

    let agent = user_agent();
    let target = uuid::Uuid::new_v4();
    let guess = |secret: &str| {
        agent
            .post(format!("{connetto_base}/auth/refresh"))
            .json(&serde_json::json!({ "refresh_token": format!("{target}.{secret}") }))
            .send()
    };

    let first = guess("wrong-once").await.expect("POST /auth/refresh");
    assert_eq!(
        first.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the first guess is answered like any other bad credential"
    );

    let second = guess("wrong-twice").await.expect("POST /auth/refresh");
    assert_eq!(
        second.status(),
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "the session named by the token is out of allowance"
    );
    let retry_after = second
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .expect("a 429 tells the caller how long to wait")
        .to_str()
        .expect("ascii header")
        .parse::<u64>()
        .expect("Retry-After is whole seconds");
    assert!(
        (1..=300).contains(&retry_after),
        "seconds, not milliseconds: {retry_after}"
    );

    // A different session is untouched by the first one's exhaustion.
    let other = agent
        .post(format!("{connetto_base}/auth/refresh"))
        .json(&serde_json::json!({
            "refresh_token": format!("{}.wrong", uuid::Uuid::new_v4())
        }))
        .send()
        .await
        .expect("POST /auth/refresh");
    assert_eq!(
        other.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the limit is per named session, not a shared bucket everyone can exhaust"
    );
}

/// A store whose rotation is broken the way a database outage breaks it, and
/// which behaves normally otherwise.
struct OutageStore(InMemoryAuthStore);

impl AuthStore for OutageStore {
    type Id = String;

    fn create_session(
        &self,
        identity: &connetto_server::ResolvedIdentity,
        now: std::time::SystemTime,
    ) -> impl Future<Output = Result<connetto_server::IssuedSession<Self::Id>, AuthStoreError>> + Send
    {
        self.0.create_session(identity, now)
    }

    fn session_is_live(
        &self,
        session_id: connetto_server::SessionId,
        now: std::time::SystemTime,
    ) -> impl Future<Output = Result<bool, AuthStoreError>> + Send {
        self.0.session_is_live(session_id, now)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn rotate_refresh(
        &self,
        _refresh_token: &str,
        _now: std::time::SystemTime,
    ) -> Result<connetto_server::RefreshOutcome<Self::Id>, AuthStoreError> {
        Err(AuthStoreError::Backend("connection refused".to_owned()))
    }

    fn revoke_session(
        &self,
        session_id: connetto_server::SessionId,
    ) -> impl Future<Output = Result<(), AuthStoreError>> + Send {
        self.0.revoke_session(session_id)
    }

    fn session_for_refresh(
        &self,
        refresh_token: &str,
    ) -> impl Future<Output = Result<Option<connetto_server::SessionId>, AuthStoreError>> + Send
    {
        self.0.session_for_refresh(refresh_token)
    }

    fn set_retained_provider_token(
        &self,
        session_id: connetto_server::SessionId,
        token: &connetto_server::RetainedProviderToken,
        now: std::time::SystemTime,
    ) -> impl Future<Output = Result<(), AuthStoreError>> + Send {
        self.0.set_retained_provider_token(session_id, token, now)
    }

    fn retained_provider_token(
        &self,
        session_id: connetto_server::SessionId,
    ) -> impl Future<Output = Result<Option<connetto_server::RetainedProviderToken>, AuthStoreError>>
    + Send {
        self.0.retained_provider_token(session_id)
    }
}

/// A store outage must not spend anybody's refresh allowance.
///
/// The counter exists to slow credential guessing. A database that is down
/// fails every attempt including the honest ones, so counting those would turn
/// an outage into a lockout that outlives it, refusing real users for the whole
/// window after the store comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_outage_does_not_spend_the_refresh_allowance() {
    let config = AuthConfig::default();
    let authority = Arc::new(TokenAuthority::generate(&config).expect("keypair"));
    let store = Arc::new(OutageStore(InMemoryAuthStore::new(
        config.refresh_lifetimes(),
    )));
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::new().refresh_failures_per_session(1, Duration::from_secs(300)),
        AbuseConfig::default(),
    ));
    let service = AuthService::new(authority, store, guard);

    let token = format!("{}.secret", uuid::Uuid::new_v4());
    for attempt in 0..4 {
        let err = service
            .refresh(&token)
            .await
            .expect_err("the store is down, so every attempt fails");
        assert!(
            !matches!(err, AuthError::RateLimited(_)),
            "attempt {attempt} was charged to the caller for the store's failure: {err:?}"
        );
    }
}
