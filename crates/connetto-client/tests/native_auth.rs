//! Phase 4 native acquisition test (Docker-free).
//!
//! Serves connetto-server's auth router on a real loopback port with a
//! permissive provider, then drives the full native flow: the authenticator
//! binds its own loopback listener and opens a browser, a fake browser walks the
//! provider round-trip and delivers the code to that listener, the authenticator
//! exchanges the code with its PKCE verifier, stores the refresh token, and
//! silently refreshes. No real browser, no live provider, no Postgres.

#![cfg(feature = "native-auth")]

use std::collections::BTreeMap;
use std::sync::Arc;

use connetto_client::{BrowserOpener, MemoryRefreshStore, NativeAuthenticator, RefreshTokenStore};
use connetto_server::{
    AuthConfig, AuthService, InMemoryAuthStore, PermissiveProvider, ProviderRegistry,
    RedirectPolicy, ResolvedIdentity, TokenAuthority, auth_router,
};

fn identity() -> ResolvedIdentity {
    ResolvedIdentity {
        issuer: "https://dev.example".to_owned(),
        subject: "native-user".to_owned(),
        email: None,
        name: None,
        amr: Vec::new(),
        acr: None,
        tenant_id: None,
        roles: Vec::new(),
        claims: BTreeMap::new(),
    }
}

/// Serve the auth router on an ephemeral port and return the base URL.
async fn spawn_auth_server() -> String {
    let config = AuthConfig::default();
    let authority = Arc::new(TokenAuthority::generate(&config).expect("keypair"));
    let store = Arc::new(InMemoryAuthStore::new(config.refresh_lifetimes()));
    let service = Arc::new(AuthService::new(authority, store));
    let mut registry = ProviderRegistry::new();
    registry.register(Arc::new(PermissiveProvider::new("permissive", identity())));
    let router = auth_router(service, Arc::new(registry), RedirectPolicy::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind auth server");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://127.0.0.1:{port}")
}

/// A fake browser: given connetto's login URL, walk the provider round-trip the
/// way a real browser plus provider would, then GET the loopback redirect to
/// hand the code to the authenticator's listener.
fn fake_browser(base: String) -> BrowserOpener {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");
    Arc::new(move |login_url: &str| {
        let http = http.clone();
        let base = base.clone();
        let login_url = login_url.to_owned();
        tokio::spawn(async move {
            // The login redirect carries connetto's CSRF state (the permissive
            // provider's authorize URL is about:blank?state=...).
            let authorize = http.get(login_url).send().await.expect("login");
            let location = authorize
                .headers()
                .get("location")
                .expect("login redirect")
                .to_str()
                .expect("utf8")
                .to_owned();
            let connetto_state = location
                .split("state=")
                .nth(1)
                .expect("state in login redirect")
                .to_owned();
            // The provider "redirects" back to connetto's callback, which
            // redirects to the loopback with the one-time code.
            let callback = http
                .get(format!(
                    "{base}/auth/callback?code=perm&state={connetto_state}"
                ))
                .send()
                .await
                .expect("callback");
            let loopback = callback
                .headers()
                .get("location")
                .expect("callback redirect")
                .to_str()
                .expect("utf8")
                .to_owned();
            // Deliver the code to the authenticator's loopback listener.
            let _ = http.get(loopback).send().await;
        });
        Ok(())
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_login_refreshes_and_silently_reacquires() {
    let base = spawn_auth_server().await;
    let store: Arc<dyn RefreshTokenStore> = Arc::new(MemoryRefreshStore::default());
    let authenticator = Arc::new(
        NativeAuthenticator::new(base.clone(), "permissive", Arc::clone(&store))
            .with_browser_opener(fake_browser(base.clone())),
    );

    // Interactive login over the loopback yields a session and stores a
    // refresh token.
    let login = authenticator.login().await.expect("login");
    assert!(!login.access_token.is_empty(), "access token acquired");
    assert!(!login.user_id.is_empty(), "login carries a user_id");
    assert!(
        login.session_expires_at > std::time::SystemTime::now(),
        "session expiry is in the future"
    );
    let first_refresh = store.load().expect("load").expect("refresh stored");

    // A silent refresh rotates the stored refresh token and keeps the identity.
    let refreshed = authenticator.refresh_access().await.expect("refresh");
    assert!(!refreshed.access_token.is_empty(), "refreshed access token");
    assert_eq!(refreshed.user_id, login.user_id, "identity is continuous");
    let second_refresh = store.load().expect("load").expect("refresh stored");
    assert_ne!(first_refresh, second_refresh, "refresh token rotated");

    // The token source refreshes without a browser, yielding the raw token.
    let via_source = authenticator.token_source().token().await.expect("source");
    assert!(
        !via_source.is_empty(),
        "token source yields an access token"
    );

    // A fresh authenticator sharing the store silently reacquires via refresh,
    // never opening the browser (the opener panics if called).
    let panicking: BrowserOpener =
        Arc::new(|_url: &str| panic!("browser opened during silent reacquire"));
    let silent = NativeAuthenticator::new(base, "permissive", Arc::clone(&store))
        .with_browser_opener(panicking);
    let session = silent.acquire().await.expect("silent acquire");
    assert!(
        !session.access_token.is_empty(),
        "silent acquire returns an access token"
    );
    assert_eq!(session.user_id, login.user_id, "same identity on reacquire");
}

#[test]
fn memory_refresh_store_round_trips() {
    let store = MemoryRefreshStore::default();
    assert!(store.load().unwrap().is_none(), "empty at first");
    store.store("refresh-abc").unwrap();
    assert_eq!(store.load().unwrap().as_deref(), Some("refresh-abc"));
    store.store("refresh-def").unwrap();
    assert_eq!(
        store.load().unwrap().as_deref(),
        Some("refresh-def"),
        "replaces"
    );
    store.clear().unwrap();
    assert!(store.load().unwrap().is_none(), "cleared");
}
