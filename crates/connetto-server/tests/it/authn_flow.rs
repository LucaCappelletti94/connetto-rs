//! Phase 2 authentication authority acceptance tests.
//!
//! These exercise the whole in-memory path: minting and verifying connetto's
//! own access token, the rotating refresh token with reuse detection, the
//! handshake liveness check that makes revocation authoritative, and the login
//! and refresh HTTP endpoints backed by a containerised OIDC provider.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use connetto_core::auth::AuthContext;
use connetto_core::messages::{ControlMessage, FatalErrorReason, Grant, Handshake};
use connetto_core::traits::{GrantRefused, HandshakeAuthority, IncomingFrame, Transport};
use connetto_core::{PROTOCOL_VERSION, Principal, Subject};
use connetto_server::{
    AuthConfig, AuthService, CookieSameSite, GenericOidcProvider, InMemoryAuthStore, Materializer,
    PageSpec, ProviderRegistry, RedirectPolicy, RequestGuard, ResolvedIdentity, SessionConfig,
    SessionManager, SnapshotEstimate, SnapshotPage, SnapshotSource, TokenAuthority, auth_router,
    loopback, pg_write_target,
};
use connetto_test_harness::{
    ConnettoWatermark, Fixture, MOCK_OAUTH_PROVIDER, MockOauth, RosterAuth, WITHHELD_ID,
};
use openidconnect::reqwest;
use serde_json::json;
use tower::ServiceExt;

const PG_DDL: &str = "CREATE TABLE items (id INT PRIMARY KEY, label TEXT);";

/// Records the identity the session presents to the snapshot read.
#[derive(Clone, Default)]
struct CapturingSnapshot {
    seen: Arc<Mutex<Option<AuthContext>>>,
}

impl SnapshotSource for CapturingSnapshot {
    type Error = std::convert::Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        Ok(SnapshotEstimate {
            rows: 0.0,
            width: 0,
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn snapshot_page(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        caller: &Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        *self.seen.lock().expect("capture lock") = caller.identity().cloned();
        Ok(SnapshotPage {
            patchset: Vec::new(),
            cursor: connetto_core::Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: 0,
            rows: 0,
            bytes: 0,
        })
    }
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

fn identity(subject: &str) -> ResolvedIdentity {
    ResolvedIdentity {
        issuer: "https://issuer.example".to_owned(),
        subject: subject.to_owned(),
        email: None,
        name: None,
        amr: Vec::new(),
        acr: None,
    }
}

fn service() -> (Arc<TokenAuthority>, Arc<AuthService<InMemoryAuthStore>>) {
    let config = AuthConfig::default();
    let authority = Arc::new(TokenAuthority::generate(&config).expect("generate keypair"));
    let store = Arc::new(InMemoryAuthStore::new(config.refresh_lifetimes()));
    let svc = Arc::new(AuthService::new(
        Arc::clone(&authority),
        store,
        Arc::new(RequestGuard::default()),
    ));
    (authority, svc)
}

fn manager_with(
    authority: Arc<dyn HandshakeAuthority>,
    snapshot: CapturingSnapshot,
    fixture: &Fixture,
) -> Arc<SessionManager<CapturingSnapshot, RosterAuth, ConnettoWatermark>> {
    // Rows come from a snapshot stub, not the change path. The policy is never consulted.
    SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        snapshot,
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        authority,
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_token_opens_a_handshake_then_revocation_refuses_it() {
    let fixture = Fixture::acquire().await;
    let (authority, svc) = service();
    let pair = svc.login(&identity("alice")).await.expect("login");

    // A login-minted access token opens the handshake, and the identity that
    // reaches the session is the token's, not the id the client claims.
    let snapshot = CapturingSnapshot::default();
    let seen = Arc::clone(&snapshot.seen);
    let manager = manager_with(Arc::new(svc.handshake_authority()), snapshot, &fixture);
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_transport));
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "spoofer").with_grant(Grant::new(&pair.access_token)),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };
    client
        .send_control(ControlMessage::Subscribe(
            connetto_core::messages::Subscribe {
                sub_id: "items".to_owned(),
                spec: connetto_core::messages::SubscriptionSpec::new("SELECT * FROM items"),
            },
        ))
        .await
        .expect("send subscribe");
    // Drain the empty snapshot.
    let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    let Some(IncomingFrame::Bulk(_)) = client.recv().await.expect("recv") else {
        panic!("expected snapshot patch");
    };
    let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };
    let captured = seen.lock().expect("capture lock").clone();
    let Subject::Identity(minted) = authority
        .check_grant::<String, String>(&Grant::new(&pair.access_token))
        .expect("verify")
    else {
        panic!("expected identity subject");
    };
    assert_eq!(
        captured.expect("the snapshot read saw an identity").user_id,
        minted.context.user_id,
        "the session must carry the token's identity, not the client's claim"
    );
    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");

    // Revoke the session. Its access token is still time-valid, but the grant
    // is now refused: the run continues unidentified rather than being rejected.
    let Subject::Identity(verified) = authority
        .check_grant::<String, String>(&Grant::new(&pair.access_token))
        .expect("verify")
    else {
        panic!("expected identity subject");
    };
    svc.revoke(verified.session_id).await.expect("revoke");

    let after_revoke = CapturingSnapshot::default();
    let seen2 = Arc::clone(&after_revoke.seen);
    let manager = manager_with(Arc::new(svc.handshake_authority()), after_revoke, &fixture);
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_transport));
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "alice").with_grant(Grant::new(&pair.access_token)),
        ))
        .await
        .expect("send handshake");
    // The revoked grant is refused but the connection stays open.
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack after revocation");
    };
    client
        .send_control(ControlMessage::Subscribe(
            connetto_core::messages::Subscribe {
                sub_id: "items".to_owned(),
                spec: connetto_core::messages::SubscriptionSpec::new("SELECT * FROM items"),
            },
        ))
        .await
        .expect("send subscribe");
    let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    let Some(IncomingFrame::Bulk(_)) = client.recv().await.expect("recv") else {
        panic!("expected snapshot patch");
    };
    let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };
    let captured2 = seen2.lock().expect("capture lock").clone();
    assert!(
        captured2.is_none(),
        "a revoked grant is refused and the run is unidentified",
    );
    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
}

/// R2: revoking a session closes its live connection rather than only refusing
/// the next handshake, and it does so through the real logout path.
///
/// The server binary wires `AuthService`'s revocation observer at the manager,
/// so a logout reaches the connection registry. Without the hook a revoked
/// caller keeps streaming until it happens to reconnect, which is the gap this
/// closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_closes_the_live_connection_it_revoked() {
    let fixture = Fixture::acquire().await;
    let (_authority, svc) = service();
    let pair = svc.login(&identity("dave")).await.expect("login");
    let manager = manager_with(
        Arc::new(svc.handshake_authority()),
        CapturingSnapshot::default(),
        &fixture,
    );

    // The binary's wiring: a revoke closes the session's live connection.
    {
        let revoke_manager = Arc::clone(&manager);
        svc.set_revocation_hook(Arc::new(move |session_id| {
            let manager = Arc::clone(&revoke_manager);
            tokio::spawn(async move {
                manager
                    .close_session(session_id, FatalErrorReason::SessionRevoked)
                    .await;
            });
        }));
    }

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(Arc::clone(&manager).serve(server_transport));
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "dave-device")
                .with_grant(Grant::new(&pair.access_token)),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    // The logout endpoint's own path: verify the refresh token, revoke, and
    // (through the hook) close whatever connection that session still holds.
    assert!(
        svc.logout(&pair.refresh_token).await.expect("logout"),
        "the refresh token names a live session"
    );

    // Thirty seconds, the delivery-class wait: the close travels through the
    // revocation hook, a spawned task, and a frame, and five seconds lost
    // that race on a saturated CI runner (2026-09-02). The contract is that
    // the connection closes, not that it closes fast.
    let closed = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let ControlMessage::FatalError(fatal) = next_control(&mut client).await {
                return fatal;
            }
        }
    })
    .await
    .expect("the revoked connection must be closed, not left streaming");
    assert_eq!(closed.reason, FatalErrorReason::SessionRevoked);
    let _ = server.await.expect("join");
}

/// The theft defence must close the live connection, exactly as a logout does.
///
/// A replayed refresh token means somebody holds a stolen credential, so it is
/// the case where leaving the socket open matters most. It went through the
/// store rather than through `AuthService::revoke`, so it never reached the
/// revocation observer and the caller kept streaming until it chose to
/// reconnect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_reuse_closes_the_live_connection_it_revoked() {
    let fixture = Fixture::acquire().await;
    let (_authority, svc) = service();
    let pair = svc.login(&identity("mallory")).await.expect("login");
    let manager = manager_with(
        Arc::new(svc.handshake_authority()),
        CapturingSnapshot::default(),
        &fixture,
    );
    {
        let revoke_manager = Arc::clone(&manager);
        svc.set_revocation_hook(Arc::new(move |session_id| {
            let manager = Arc::clone(&revoke_manager);
            tokio::spawn(async move {
                manager
                    .close_session(session_id, FatalErrorReason::SessionRevoked)
                    .await;
            });
        }));
    }

    let rotated = svc.refresh(&pair.refresh_token).await.expect("refresh");
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(Arc::clone(&manager).serve(server_transport));
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "mallory-device")
                .with_grant(Grant::new(&rotated.access_token)),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    // Replaying the rotated-out token is theft. It revokes the session, and
    // that must reach the connection the thief's victim still holds.
    assert!(
        svc.refresh(&pair.refresh_token).await.is_err(),
        "a replayed refresh token is refused"
    );

    // Thirty seconds for the same reason as the logout twin above.
    let closed = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let ControlMessage::FatalError(fatal) = next_control(&mut client).await {
                return fatal;
            }
        }
    })
    .await
    .expect("the theft response must close the connection, not leave it streaming");
    assert_eq!(closed.reason, FatalErrorReason::SessionRevoked);
    let _ = server.await.expect("join");
}

#[tokio::test]
async fn refresh_rotates_and_reusing_the_old_token_revokes_the_session() {
    let (authority, svc) = service();
    let pair = svc.login(&identity("bob")).await.expect("login");

    let rotated = svc.refresh(&pair.refresh_token).await.expect("refresh");
    assert_ne!(rotated.refresh_token, pair.refresh_token, "token rotates");
    // The rotated access token still verifies to the same session.
    let Subject::Identity(first) = authority
        .check_grant::<String, String>(&Grant::new(&pair.access_token))
        .expect("verify first")
    else {
        panic!("expected identity subject");
    };
    let Subject::Identity(second) = authority
        .check_grant::<String, String>(&Grant::new(&rotated.access_token))
        .expect("verify rotated")
    else {
        panic!("expected identity subject");
    };
    assert_eq!(first.session_id, second.session_id);

    // Reusing the original (rotated-out) refresh token is theft: it fails and
    // revokes the session, so the rotated token is now dead too.
    let reuse = svc.refresh(&pair.refresh_token).await;
    assert!(reuse.is_err(), "reused refresh token is rejected");
    let after = svc.refresh(&rotated.refresh_token).await;
    assert!(after.is_err(), "session revoked after reuse");

    // The authority now refuses the still-signed access token: session not live.
    let authority: &dyn connetto_core::traits::HandshakeAuthority = &svc.handshake_authority();
    let refused = authority
        .check_grant(&Grant::new(&rotated.access_token))
        .await;
    assert_eq!(refused, Err(GrantRefused::Revoked));
}

#[tokio::test]
async fn expired_access_token_is_refused() {
    let config = AuthConfig::default();
    let authority = Arc::new(TokenAuthority::generate(&config).expect("keypair"));
    let store = Arc::new(InMemoryAuthStore::new(config.refresh_lifetimes()));
    let svc = AuthService::new(
        Arc::clone(&authority),
        Arc::clone(&store),
        Arc::new(RequestGuard::default()),
    );
    let pair = svc.login(&identity("carol")).await.expect("login");
    let Subject::Identity(verified) = authority
        .check_grant::<String, String>(&Grant::new(&pair.access_token))
        .expect("verify")
    else {
        panic!("expected identity subject");
    };

    // Mint a token issued far enough in the past that it is already expired.
    let stale_issued = SystemTime::now() - (config.access_ttl() + Duration::from_secs(120));
    let stale = authority
        .mint_access(&verified.context, verified.session_id, stale_issued)
        .expect("mint stale");
    let authority: &dyn connetto_core::traits::HandshakeAuthority = &svc.handshake_authority();
    let refused = authority.check_grant(&Grant::new(&stale)).await;
    assert!(
        matches!(refused, Err(GrantRefused::Invalid(_))),
        "an expired access token is invalid, got {refused:?}",
    );
}

#[tokio::test]
async fn a_token_from_another_key_is_refused() {
    let config = AuthConfig::default();
    let store = Arc::new(InMemoryAuthStore::new(config.refresh_lifetimes()));
    let authority = Arc::new(TokenAuthority::generate(&config).expect("keypair a"));
    let svc = AuthService::new(
        Arc::clone(&authority),
        Arc::clone(&store),
        Arc::new(RequestGuard::default()),
    );
    // A different authority (different signing key) mints a token for the same
    // session id, simulating a forged credential.
    let other = TokenAuthority::generate(&config).expect("keypair b");
    let pair = svc.login(&identity("dave")).await.expect("login");
    let Subject::Identity(verified) = authority
        .check_grant::<String, String>(&Grant::new(&pair.access_token))
        .expect("verify")
    else {
        panic!("expected identity subject");
    };
    let forged = other
        .mint_access(&verified.context, verified.session_id, SystemTime::now())
        .expect("mint forged");

    let authority: &dyn connetto_core::traits::HandshakeAuthority = &svc.handshake_authority();
    let refused = authority.check_grant(&Grant::new(&forged)).await;
    assert!(
        matches!(refused, Err(GrantRefused::Invalid(_))),
        "a token signed by another key is refused, got {refused:?}",
    );
}

async fn post_json(
    router: axum::Router,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
        .expect("build request");
    let response = router.oneshot(request).await.expect("route");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, value)
}

async fn get_request(router: &axum::Router, uri: &str) -> axum::http::Response<Body> {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("build request");
    router.clone().oneshot(request).await.expect("route")
}

/// Start a real OIDC provider and return an Arc'd registry containing it.
async fn oidc_registry() -> (MockOauth, Arc<ProviderRegistry>) {
    const CALLBACK: &str = "http://127.0.0.1:1/auth/callback";
    let idp = MockOauth::start().await;
    let provider = GenericOidcProvider::discover(
        idp.oidc_config(MOCK_OAUTH_PROVIDER, CALLBACK),
        reqwest::Client::new(),
    )
    .await
    .expect("discover provider");
    let mut registry = ProviderRegistry::new();
    registry.register(Arc::new(provider));
    (idp, Arc::new(registry))
}

/// POST the username to the provider and read the redirected `code` and `state`.
async fn authorize_hop(authorize_url: &str, subject: &str) -> (String, String) {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build http client");
    let resp = client
        .post(authorize_url)
        .form(&[("username", subject)])
        .send()
        .await
        .expect("POST authorize");
    let location = resp
        .headers()
        .get("location")
        .expect("location header")
        .to_str()
        .expect("utf-8")
        .to_owned();
    let code = query_value(&location, "code");
    let state = query_value(&location, "state");
    (code, state)
}

#[tokio::test]
async fn http_oauth_flow_then_refresh_roundtrip() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );

    // Start: a redirect whose Location is the IDP authorize URL.
    let start = get_request(
        &router,
        &format!("/auth/login?provider={MOCK_OAUTH_PROVIDER}"),
    )
    .await;
    assert_eq!(start.status(), StatusCode::TEMPORARY_REDIRECT);
    let idp_authorize_url = start
        .headers()
        .get("location")
        .expect("location header")
        .to_str()
        .expect("utf8")
        .to_owned();
    let state = query_value(&idp_authorize_url, "state");

    // Authorize hop: POST the username to obtain the real code.
    let (code, _) = authorize_hop(&idp_authorize_url, "erin").await;

    // Callback: connetto exchanges the real code with the provider and mints its
    // own tokens. No provider token reaches the response.
    let callback = get_request(
        &router,
        &format!("/auth/callback?code={code}&state={state}"),
    )
    .await;
    assert_eq!(callback.status(), StatusCode::OK);
    let bytes = to_bytes(callback.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let refresh_token = body["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned();
    assert!(
        body["access_token"].as_str().is_some(),
        "access token present"
    );
    assert!(
        body.get("provider_access_token").is_none(),
        "no provider token leaks to the client",
    );
    let user_id = body["user_id"]
        .as_str()
        .expect("user_id present")
        .to_owned();
    assert!(!user_id.is_empty(), "user_id is non-empty");
    assert!(
        body["session_expires_at"].as_u64().is_some_and(|at| at > 0),
        "session expiry present",
    );

    // The state was consumed, so a replayed callback is refused.
    let replay = get_request(
        &router,
        &format!("/auth/callback?code=dummy-code&state={state}"),
    )
    .await;
    assert_eq!(
        replay.status(),
        StatusCode::BAD_REQUEST,
        "state cannot be replayed"
    );

    let (status, body) = post_json(
        router.clone(),
        "/auth/refresh",
        json!({ "refresh_token": refresh_token }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["access_token"].as_str().is_some(),
        "rotated access token"
    );
    assert_eq!(
        body["user_id"].as_str(),
        Some(user_id.as_str()),
        "refresh keeps the same identity",
    );
    assert!(
        body["session_expires_at"].as_u64().is_some_and(|at| at > 0),
        "refresh carries a session expiry",
    );

    let (status, _) = post_json(
        router,
        "/auth/refresh",
        json!({ "refresh_token": "nonexistent.deadbeef" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "bad refresh token is 401");
}

/// The PKCE verifier and its S256 challenge (`base64url(sha256(verifier))`,
/// computed offline), for the loopback token-exchange test.
const PKCE_VERIFIER: &str = "connetto-native-pkce-verifier-fixed-value-abc123";
const PKCE_CHALLENGE: &str = "Ast5dH2Rp4Ww-2yUBBcswbR_8wo5ha90LmXZhMEWx14";

fn query_value(location: &str, key: &str) -> String {
    location
        .split(['?', '&'])
        .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("no {key} in {location}"))
        .to_owned()
}

async fn location_of(router: &axum::Router, uri: &str) -> String {
    let response = get_request(router, uri).await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{uri}");
    response
        .headers()
        .get("location")
        .expect("location header")
        .to_str()
        .expect("utf8")
        .to_owned()
}

/// Drive the loopback halves and return the one-time connetto code.
async fn loopback_code(router: &axum::Router, subject: &str) -> String {
    let idp_authorize_url = location_of(
        router,
        &format!(
            "/auth/login?provider={MOCK_OAUTH_PROVIDER}&redirect_uri=http://127.0.0.1:9999/cb\
             &code_challenge={PKCE_CHALLENGE}&state=client-state-xyz"
        ),
    )
    .await;
    let connetto_state = query_value(&idp_authorize_url, "state");
    let (code, _) = authorize_hop(&idp_authorize_url, subject).await;
    let client_redirect = location_of(
        router,
        &format!("/auth/callback?code={code}&state={connetto_state}"),
    )
    .await;
    assert!(client_redirect.starts_with("http://127.0.0.1:9999/cb?"));
    assert_eq!(query_value(&client_redirect, "state"), "client-state-xyz");
    query_value(&client_redirect, "code")
}

#[tokio::test]
async fn loopback_code_exchange_with_pkce() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );

    let code = loopback_code(&router, "frank").await;
    let (status, body) = post_json(
        router.clone(),
        "/auth/token",
        json!({ "code": code, "code_verifier": PKCE_VERIFIER }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["access_token"].as_str().is_some(),
        "access token issued"
    );
    assert!(
        body["refresh_token"].as_str().is_some(),
        "refresh token issued"
    );
    assert!(
        body["user_id"].as_str().is_some_and(|id| !id.is_empty()),
        "loopback token carries the user_id"
    );
    assert!(
        body["session_expires_at"].as_u64().is_some_and(|at| at > 0),
        "loopback token carries a session expiry"
    );

    // The code is one-time: a second exchange fails.
    let (status, _) = post_json(
        router.clone(),
        "/auth/token",
        json!({ "code": code, "code_verifier": PKCE_VERIFIER }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "code cannot be reused");

    // A fresh code with the wrong PKCE verifier is refused.
    let fresh = loopback_code(&router, "frank").await;
    let (status, _) = post_json(
        router,
        "/auth/token",
        json!({ "code": fresh, "code_verifier": "wrong-verifier" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "pkce mismatch is refused");
}

#[tokio::test]
async fn redirect_policy_gates_the_client_redirect() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );

    // A non-loopback redirect with no allowlist entry is refused before any mint.
    let resp = get_request(
        &router,
        &format!("/auth/login?provider={MOCK_OAUTH_PROVIDER}&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&code_challenge=abc&state=s"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "off-origin redirect refused"
    );

    // A loopback redirect is accepted: a temporary redirect to the provider.
    let resp = get_request(
        &router,
        &format!("/auth/login?provider={MOCK_OAUTH_PROVIDER}&redirect_uri=http%3A%2F%2F127.0.0.1%3A9000%2Fcallback&code_challenge=abc&state=s"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "loopback accepted"
    );

    // A redirect without its PKCE challenge is refused as a partial pair.
    let resp = get_request(
        &router,
        &format!("/auth/login?provider={MOCK_OAUTH_PROVIDER}&redirect_uri=http%3A%2F%2F127.0.0.1%3A9000%2Fcallback"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "redirect without challenge refused"
    );
}

#[tokio::test]
async fn redirect_policy_admits_an_allowlisted_https_callback() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let policy = RedirectPolicy::new(vec!["https://app.example/cb".to_owned()]);
    let router = auth_router(svc, registry, policy, CookieSameSite::default());

    let resp = get_request(
        &router,
        &format!("/auth/login?provider={MOCK_OAUTH_PROVIDER}&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_challenge=abc&state=s"),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "allowlisted callback accepted"
    );
}

// R90: the browser cookie contract on the three auth endpoints.

/// POST a JSON body with arbitrary extra headers and return the raw response,
/// because the cookie contract lives in headers a parsed body cannot show.
async fn post_marked(
    router: axum::Router,
    path: &str,
    body: serde_json::Value,
    headers: &[(&str, &str)],
) -> axum::http::Response<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
        .expect("build request");
    router.oneshot(request).await.expect("route")
}

fn set_cookies(response: &axum::http::Response<Body>) -> Vec<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|value| value.to_str().expect("utf-8").to_owned())
        .collect()
}

const MARKED: [(&str, &str); 1] = [("x-connetto-client", "browser")];

/// Drive a marked loopback login and return the `name=value` pair the
/// `Set-Cookie` header carried together with the `user_id` the body returned,
/// because the cookie name derives from that id and a test cannot guess it.
async fn marked_login(router: &axum::Router, subject: &str) -> (String, String) {
    let code = loopback_code(router, subject).await;
    let response = post_marked(
        router.clone(),
        "/auth/token",
        json!({ "code": code, "code_verifier": PKCE_VERIFIER }),
        &MARKED,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "marked login succeeds");
    let cookies = set_cookies(&response);
    assert_eq!(cookies.len(), 1, "one cookie on a marked login");
    let cookie = cookies[0].split(';').next().expect("name=value").to_owned();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert!(body["access_token"].as_str().is_some(), "access token");
    assert!(
        body.get("refresh_token").is_none(),
        "the marked body carries no refresh token",
    );
    let user_id = body["user_id"].as_str().expect("user_id").to_owned();
    (cookie, user_id)
}

#[tokio::test]
async fn marked_login_sets_the_prefixed_cookie_and_hides_the_body_token() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );

    let code = loopback_code(&router, "erin").await;
    let response = post_marked(
        router.clone(),
        "/auth/token",
        json!({ "code": code, "code_verifier": PKCE_VERIFIER }),
        &MARKED,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert!(body["access_token"].as_str().is_some(), "access token");
    assert!(
        body.get("refresh_token").is_none(),
        "the marked body carries no refresh token",
    );

    let code2 = loopback_code(&router, "erin").await;
    let response = post_marked(
        router,
        "/auth/token",
        json!({ "code": code2, "code_verifier": PKCE_VERIFIER }),
        &MARKED,
    )
    .await;
    let cookie = set_cookies(&response).pop().expect("a set-cookie").clone();
    let (pair, rest) = cookie.split_once(';').expect("attributes");
    let (name, value) = pair.split_once('=').expect("name=value");
    assert!(
        name.starts_with("__Host-Http-connetto-refresh-"),
        "cookie carries the host prefix, got {name}",
    );
    assert!(!value.is_empty(), "the cookie carries a value");
    for attribute in ["HttpOnly", "Secure", "Path=/", "SameSite=Strict"] {
        assert!(rest.contains(attribute), "{attribute} present, got {rest}");
    }
    assert!(!rest.contains("Domain"), "no Domain attribute, got {rest}");
}

#[tokio::test]
async fn native_paths_never_see_a_set_cookie() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );

    let code = loopback_code(&router, "erin").await;
    let response = post_marked(
        router.clone(),
        "/auth/token",
        json!({ "code": code, "code_verifier": PKCE_VERIFIER }),
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        set_cookies(&response).is_empty(),
        "native login sets no cookie"
    );
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert!(
        body["refresh_token"].as_str().is_some(),
        "native login still carries the body token",
    );
}

#[tokio::test]
async fn marked_refresh_rotates_through_the_cookie() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );

    let (cookie, user_id) = marked_login(&router, "gina").await;
    let (name, first) = cookie.split_once('=').expect("name=value");

    let response = post_marked(
        router.clone(),
        "/auth/refresh",
        json!({ "user_id": user_id }),
        &[("x-connetto-client", "browser"), ("cookie", &cookie)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "marked refresh");
    let rotated = set_cookies(&response).pop().expect("rotated cookie");
    let (rotated_name, rotated_value) = rotated.split_once('=').expect("pair");
    assert_eq!(rotated_name, name, "rotation keeps the account's cookie");
    assert_ne!(rotated_value, first, "rotation changes the value");

    // The spent cookie value no longer refreshes: the jar updated server-side
    // and the old value is a replay.
    let replay = post_marked(
        router,
        "/auth/refresh",
        json!({ "user_id": user_id }),
        &[("x-connetto-client", "browser"), ("cookie", &cookie)],
    )
    .await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED, "replay refused");
}

#[tokio::test]
async fn marked_requests_without_the_cookie_are_401() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );

    let response = post_marked(
        router,
        "/auth/refresh",
        json!({ "user_id": "gina" }),
        &MARKED,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "a marked refresh with no cookie falls to interactive login",
    );
}

#[tokio::test]
async fn mixed_contracts_are_400() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );

    let (cookie, hugo) = marked_login(&router, "hugo").await;
    let cookie_headers = [
        ("x-connetto-client", "browser"),
        ("cookie", cookie.as_str()),
    ];

    // A marked refresh that also carries a body token mixes the two contracts.
    let response = post_marked(
        router.clone(),
        "/auth/refresh",
        json!({ "user_id": hugo, "refresh_token": "whatever.value" }),
        &cookie_headers,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "mixed refresh");

    // A marked refresh that names no account cannot select a cookie.
    let response = post_marked(router.clone(), "/auth/refresh", json!({}), &cookie_headers).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "no user_id");

    // The native path with no body token is the same refusal.
    let response = post_marked(router.clone(), "/auth/refresh", json!({}), &[]).await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "native no token"
    );

    // An unknown header value is not the browser contract either.
    let response = post_marked(
        router.clone(),
        "/auth/refresh",
        json!({ "user_id": hugo }),
        &[("x-connetto-client", "gecko"), ("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "unknown marker");

    // A cross-site form cannot set the marker, so its cookie rides a native
    // request that carries no body token and is refused before any rotation.
    let response = post_marked(
        router,
        "/auth/refresh",
        json!({ "user_id": hugo }),
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "a cookie alone never authenticates the native path",
    );
}

#[tokio::test]
async fn marked_logout_revokes_and_clears_only_that_cookie() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );

    let (hugo, hugo_id) = marked_login(&router, "hugo").await;
    let (anna, anna_id) = marked_login(&router, "anna").await;

    let response = post_marked(
        router.clone(),
        "/auth/logout",
        json!({ "user_id": hugo_id }),
        &[("x-connetto-client", "browser"), ("cookie", hugo.as_str())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT, "marked logout");
    let removal = set_cookies(&response).pop().expect("removal header");
    let (pair, rest) = removal.split_once(';').expect("attributes");
    let (_name, value) = pair.split_once('=').expect("name=value");
    assert_eq!(value, "", "the removal carries an empty value");
    for attribute in ["HttpOnly", "Secure", "Path=/", "SameSite=Strict"] {
        assert!(rest.contains(attribute), "removal {attribute}, got {rest}");
    }

    // The revoked session cannot refresh again even with the (stale) cookie.
    let response = post_marked(
        router.clone(),
        "/auth/refresh",
        json!({ "user_id": hugo_id }),
        &[("x-connetto-client", "browser"), ("cookie", hugo.as_str())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "revoked");

    // The other account's cookie is untouched.
    let response = post_marked(
        router,
        "/auth/refresh",
        json!({ "user_id": anna_id }),
        &[("x-connetto-client", "browser"), ("cookie", anna.as_str())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "the other account lives");
}

#[tokio::test]
async fn cookie_name_mismatch_revokes_the_borrowed_session() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );

    // erin logs in marked. frank logs in natively, so the test holds frank's
    // token as a string and can hand it under erin's cookie name.
    let (erin, erin_id) = marked_login(&router, "erin").await;
    let (erin_name, _) = erin.split_once('=').expect("erin cookie");
    let frank_code = loopback_code(&router, "frank").await;
    let (status, frank_body) = post_json(
        router.clone(),
        "/auth/token",
        json!({ "code": frank_code, "code_verifier": PKCE_VERIFIER }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let frank_token = frank_body["refresh_token"].as_str().expect("token");

    let borrowed = format!("{erin_name}={frank_token}");
    let response = post_marked(
        router.clone(),
        "/auth/refresh",
        json!({ "user_id": erin_id }),
        &[("x-connetto-client", "browser"), ("cookie", &borrowed)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "mismatch 401");

    // The borrowed session is gone: frank's own native refresh now fails.
    let (status, _) = post_json(
        router.clone(),
        "/auth/refresh",
        json!({ "refresh_token": frank_token }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "borrowed session revoked");

    // erin's own session was never touched.
    let response = post_marked(
        router,
        "/auth/refresh",
        json!({ "user_id": erin_id }),
        &[("x-connetto-client", "browser"), ("cookie", &erin)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "erin unaffected");
}

#[tokio::test]
async fn samesite_none_setting_renders_none() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::None,
    );

    let code = loopback_code(&router, "gina").await;
    let response = post_marked(
        router,
        "/auth/token",
        json!({ "code": code, "code_verifier": PKCE_VERIFIER }),
        &MARKED,
    )
    .await;
    let cookie = set_cookies(&response).pop().expect("cookie");
    assert!(cookie.contains("SameSite=None"), "got {cookie}");
    assert!(
        cookie.contains("Secure"),
        "None still carries Secure, got {cookie}"
    );
}

/// A store whose refresh lookup breaks mid-test, the way a database outage
/// breaks it after a login already landed.
struct LookupOutageStore {
    inner: InMemoryAuthStore,
    down: std::sync::atomic::AtomicBool,
}

impl connetto_server::AuthStore for LookupOutageStore {
    type Id = String;

    fn create_session(
        &self,
        identity: &ResolvedIdentity,
        now: SystemTime,
    ) -> impl Future<
        Output = Result<connetto_server::IssuedSession<Self::Id>, connetto_server::AuthStoreError>,
    > + Send {
        self.inner.create_session(identity, now)
    }

    fn session_is_live(
        &self,
        session_id: connetto_server::SessionId,
        now: SystemTime,
    ) -> impl Future<Output = Result<bool, connetto_server::AuthStoreError>> + Send {
        self.inner.session_is_live(session_id, now)
    }

    fn rotate_refresh(
        &self,
        refresh_token: &str,
        now: SystemTime,
    ) -> impl Future<
        Output = Result<connetto_server::RefreshOutcome<Self::Id>, connetto_server::AuthStoreError>,
    > + Send {
        self.inner.rotate_refresh(refresh_token, now)
    }

    fn revoke_session(
        &self,
        session_id: connetto_server::SessionId,
    ) -> impl Future<Output = Result<(), connetto_server::AuthStoreError>> + Send {
        self.inner.revoke_session(session_id)
    }

    fn revoke_every_session(
        &self,
    ) -> impl Future<Output = Result<u64, connetto_server::AuthStoreError>> + Send {
        self.inner.revoke_every_session()
    }

    fn session_for_refresh(
        &self,
        refresh_token: &str,
    ) -> impl Future<
        Output = Result<Option<connetto_server::SessionId>, connetto_server::AuthStoreError>,
    > + Send {
        let down = self.down.load(std::sync::atomic::Ordering::SeqCst);
        let lookup = self.inner.session_for_refresh(refresh_token);
        async move {
            if down {
                Err(connetto_server::AuthStoreError::Backend(
                    "connection refused".to_owned(),
                ))
            } else {
                lookup.await
            }
        }
    }

    fn set_retained_provider_token(
        &self,
        session_id: connetto_server::SessionId,
        token: &connetto_server::RetainedProviderToken,
        now: SystemTime,
    ) -> impl Future<Output = Result<(), connetto_server::AuthStoreError>> + Send {
        self.inner
            .set_retained_provider_token(session_id, token, now)
    }

    fn retained_provider_token(
        &self,
        session_id: connetto_server::SessionId,
    ) -> impl Future<
        Output = Result<
            Option<connetto_server::RetainedProviderToken>,
            connetto_server::AuthStoreError,
        >,
    > + Send {
        self.inner.retained_provider_token(session_id)
    }
}

/// A logout whose revoke fails still clears the cookie. The worker drops its
/// index row whatever the answer, so a cookie left behind would be a live
/// credential for an account the device believes it signed out of.
#[tokio::test]
async fn a_failed_marked_revoke_still_clears_the_cookie() {
    let config = AuthConfig::default();
    let authority = Arc::new(TokenAuthority::generate(&config).expect("generate keypair"));
    let store = Arc::new(LookupOutageStore {
        inner: InMemoryAuthStore::new(config.refresh_lifetimes()),
        down: std::sync::atomic::AtomicBool::new(false),
    });
    let svc = Arc::new(AuthService::new(
        authority,
        Arc::clone(&store),
        Arc::new(RequestGuard::default()),
    ));
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );
    let (cookie, user_id) = marked_login(&router, "ines").await;

    store.down.store(true, std::sync::atomic::Ordering::SeqCst);
    let response = post_marked(
        router,
        "/auth/logout",
        json!({ "user_id": user_id }),
        &[
            ("x-connetto-client", "browser"),
            ("cookie", cookie.as_str()),
        ],
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "the revoke failure is reported"
    );
    let removal = set_cookies(&response)
        .pop()
        .expect("the removal rides the error response");
    let (pair, rest) = removal.split_once(';').expect("attributes");
    let (name, value) = pair.split_once('=').expect("name=value");
    assert_eq!(
        name,
        cookie.split_once('=').expect("name=value").0,
        "the removal names the account's cookie"
    );
    assert_eq!(value, "", "the removal carries an empty value");
    for attribute in ["HttpOnly", "Secure", "Path=/", "SameSite=Strict"] {
        assert!(rest.contains(attribute), "removal {attribute}, got {rest}");
    }
}

/// The cookie pair, its `Max-Age`, and the body's lapse instant of one marked
/// response.
async fn cookie_lifetime(response: axum::http::Response<Body>) -> (String, u64, u64) {
    let cookie = set_cookies(&response).pop().expect("a refresh cookie");
    let max_age = cookie
        .split(';')
        .find_map(|attribute| attribute.trim().strip_prefix("Max-Age="))
        .unwrap_or_else(|| panic!("no Max-Age in {cookie}"))
        .parse::<u64>()
        .expect("numeric Max-Age");
    let pair = cookie.split(';').next().expect("name=value").to_owned();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    let lapses_at = body["session_expires_at"]
        .as_u64()
        .expect("session_expires_at");
    (pair, max_age, lapses_at)
}

fn assert_lives_until(max_age: u64, lapses_at: u64, what: &str) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    let remaining = lapses_at.saturating_sub(now);
    assert!(remaining > 0, "{what}: the session is live");
    assert!(
        max_age.abs_diff(remaining) <= 5,
        "{what}: Max-Age {max_age} tracks the {remaining}s the session has left"
    );
}

/// The refresh cookie outlives a browser restart and never outlives the
/// session: its `Max-Age` is the time left until the session lapses, set at
/// login and set again by every rotation as the idle window slides.
#[tokio::test]
async fn the_refresh_cookie_lives_until_the_session_lapses() {
    let (_authority, svc) = service();
    let (_idp, registry) = oidc_registry().await;
    let router = auth_router(
        svc,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::default(),
    );
    let code = loopback_code(&router, "jana").await;
    let login = post_marked(
        router.clone(),
        "/auth/token",
        json!({ "code": code, "code_verifier": PKCE_VERIFIER }),
        &MARKED,
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK, "marked login");
    let (cookie, max_age, lapses_at) = cookie_lifetime(login).await;
    assert_lives_until(max_age, lapses_at, "login");

    let user_id = {
        let (_, value) = cookie.split_once('=').expect("name=value");
        assert!(!value.is_empty(), "the login cookie carries a credential");
        let (_, encoded) = cookie
            .split_once("__Host-Http-connetto-refresh-")
            .expect("the prefixed name");
        let encoded = encoded.split_once('=').expect("name=value").0;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("base64url name");
        serde_json::from_slice::<serde_json::Value>(&raw).expect("serde id")
    };
    let rotated = post_marked(
        router,
        "/auth/refresh",
        json!({ "user_id": user_id }),
        &[
            ("x-connetto-client", "browser"),
            ("cookie", cookie.as_str()),
        ],
    )
    .await;
    assert_eq!(rotated.status(), StatusCode::OK, "marked refresh");
    let (_, max_age, lapses_at) = cookie_lifetime(rotated).await;
    assert_lives_until(max_age, lapses_at, "rotation");
}
