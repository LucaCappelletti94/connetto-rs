//! Phase 2 authentication authority acceptance tests (Docker-free).
//!
//! These exercise the whole in-memory path: minting and verifying connetto's
//! own access token, the rotating refresh token with reuse detection, the
//! handshake liveness check that makes revocation authoritative, and the login
//! and refresh HTTP endpoints. A login-minted token is proven to open a real
//! handshake and then to be refused once its session is revoked.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use connetto_core::auth::AuthContext;
use connetto_core::messages::{ControlMessage, FatalErrorReason, Grant, Handshake};
use connetto_core::traits::{GrantRefused, HandshakeAuthority, IncomingFrame, Transport};
use connetto_core::{PROTOCOL_VERSION, Principal, Subject};
use connetto_server::{
    AssuranceRequirement, AuthConfig, AuthService, GenericOidcProvider, InMemoryAuthStore,
    Materializer, OidcProviderConfig, PermissiveAuth, ProviderRegistry, RedirectPolicy,
    ResolvedIdentity, SessionConfig, SessionManager, Snapshot, SnapshotSource, TokenAuthority,
    auth_router, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture};
use oauth2_test_server::{IssuerConfig, OAuthTestServer};
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

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        caller: &Principal,
    ) -> Result<Snapshot, Self::Error> {
        *self.seen.lock().expect("capture lock") = caller.identity().cloned();
        Ok(Snapshot {
            patchset: Vec::new(),
            cursor: connetto_core::Cursor::new(Vec::new()),
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
    let svc = Arc::new(AuthService::new(Arc::clone(&authority), store));
    (authority, svc)
}

fn manager_with(
    authority: Arc<dyn HandshakeAuthority>,
    snapshot: CapturingSnapshot,
    fixture: &Fixture,
) -> Arc<SessionManager<CapturingSnapshot, PermissiveAuth, ConnettoWatermark>> {
    SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        snapshot,
        PermissiveAuth,
        authority,
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        SessionConfig::default(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
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
/// The deployment wires `AuthService`'s revocation observer at the manager,
/// exactly as the server binary does, so a logout reaches the connection
/// registry. Without the hook a revoked caller keeps streaming until it
/// happens to reconnect, which is the gap this closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
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

    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
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

    let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
    let svc = AuthService::new(Arc::clone(&authority), Arc::clone(&store));
    let pair = svc.login(&identity("carol")).await.expect("login");
    let Subject::Identity(verified) = authority
        .check_grant::<String, String>(&Grant::new(&pair.access_token))
        .expect("verify")
    else {
        panic!("expected identity subject");
    };

    // Mint a token issued far enough in the past that it is already expired.
    let stale_issued = SystemTime::now() - (config.access_ttl + Duration::from_secs(120));
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
    let svc = AuthService::new(Arc::clone(&authority), Arc::clone(&store));
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

/// Start a real OIDC provider with `subject` as the user id and return an Arc'd
/// registry containing the discovered "mock-idp" provider. Keep the returned
/// [`OAuthTestServer`] alive for the test's duration or the provider socket dies.
async fn oidc_registry(subject: &str) -> (OAuthTestServer, Arc<ProviderRegistry>) {
    const CALLBACK: &str = "http://127.0.0.1:1/auth/callback";
    let idp = OAuthTestServer::start_with_config(IssuerConfig {
        host: "127.0.0.1".into(),
        port: 0,
        default_user_id: subject.into(),
        ..IssuerConfig::default()
    })
    .await;
    let issuer = idp.base_url.to_string().trim_end_matches('/').to_owned();
    let client = idp
        .register_client(json!({
            "redirect_uris": [CALLBACK],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid",
        }))
        .await;
    let provider = GenericOidcProvider::discover(
        OidcProviderConfig {
            name: "mock-idp".to_owned(),
            client_id: client.client_id.clone(),
            client_secret: client.client_secret.clone(),
            issuer,
            redirect_url: CALLBACK.to_owned(),
            scopes: Vec::new(),
            assurance: AssuranceRequirement::none(),
        },
        reqwest::Client::new(),
    )
    .await
    .expect("discover provider");
    let mut registry = ProviderRegistry::new();
    registry.register(Arc::new(provider));
    (idp, Arc::new(registry))
}

/// GET the IDP's authorize URL with redirect following disabled and return the
/// `code` and `state` query values from the resulting redirect location.
async fn authorize_hop(authorize_url: &str) -> (String, String) {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build http client");
    let resp = client
        .get(authorize_url)
        .send()
        .await
        .expect("GET authorize");
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
    let (_idp, registry) = oidc_registry("erin").await;
    let router = auth_router(svc, registry, RedirectPolicy::default());

    // Start: a redirect whose Location is the IDP authorize URL.
    let start = get_request(&router, "/auth/login?provider=mock-idp").await;
    assert_eq!(start.status(), StatusCode::TEMPORARY_REDIRECT);
    let idp_authorize_url = start
        .headers()
        .get("location")
        .expect("location header")
        .to_str()
        .expect("utf8")
        .to_owned();
    let state = query_value(&idp_authorize_url, "state");

    // Authorize hop: GET the IDP's authorize URL to obtain the real code.
    let (code, _) = authorize_hop(&idp_authorize_url).await;

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

/// Drive the loopback halves (start then callback) and return the one-time
/// connetto code delivered to the client redirect.
async fn loopback_code(router: &axum::Router) -> String {
    let idp_authorize_url = location_of(
        router,
        &format!(
            "/auth/login?provider=mock-idp&redirect_uri=http://127.0.0.1:9999/cb\
             &code_challenge={PKCE_CHALLENGE}&state=client-state-xyz"
        ),
    )
    .await;
    let connetto_state = query_value(&idp_authorize_url, "state");
    let (code, _) = authorize_hop(&idp_authorize_url).await;
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
    let (_idp, registry) = oidc_registry("frank").await;
    let router = auth_router(svc, registry, RedirectPolicy::default());

    let code = loopback_code(&router).await;
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
    let fresh = loopback_code(&router).await;
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
    let (_idp, registry) = oidc_registry("grace").await;
    let router = auth_router(svc, registry, RedirectPolicy::default());

    // A non-loopback redirect with no allowlist entry is refused before any mint.
    let resp = get_request(
        &router,
        "/auth/login?provider=mock-idp&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&code_challenge=abc&state=s",
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
        "/auth/login?provider=mock-idp&redirect_uri=http%3A%2F%2F127.0.0.1%3A9000%2Fcallback&code_challenge=abc&state=s",
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
        "/auth/login?provider=mock-idp&redirect_uri=http%3A%2F%2F127.0.0.1%3A9000%2Fcallback",
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
    let (_idp, registry) = oidc_registry("heidi").await;
    let policy = RedirectPolicy::new(vec!["https://app.example/cb".to_owned()]);
    let router = auth_router(svc, registry, policy);

    let resp = get_request(
        &router,
        "/auth/login?provider=mock-idp&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&code_challenge=abc&state=s",
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::TEMPORARY_REDIRECT,
        "allowlisted callback accepted"
    );
}
