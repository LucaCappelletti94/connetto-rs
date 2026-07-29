//! Native acquisition (Docker-free).
//!
//! Serves connetto-server's auth router on a real loopback port with a
//! permissive provider, then drives the full native flow: the authenticator
//! binds its own loopback listener and opens a browser, a fake browser walks the
//! provider round-trip and delivers the code to that listener, the authenticator
//! exchanges the code with its PKCE verifier, stores the refresh token, and
//! silently refreshes. No real browser, no live provider, no Postgres.
//!
//! It also proves the typed `user_id` boundary: a deployment whose id is a
//! `rosetta_uuid::Uuid` gets that value back from the token endpoint as its own
//! type, with no `Display` or `FromStr` anywhere on the path, and the replica
//! file the client opens is named from it.

#![cfg(feature = "native-auth")]

use std::collections::BTreeMap;
use std::sync::Arc;

use connetto_client::{
    AcquiredSession, BrowserOpener, ClientError, MemoryKeyStore, MemoryRefreshStore,
    NativeAuthenticator, RefreshTokenStore, ReplicaKeyStore, provision_replica_key,
    replica_db_name,
};
use connetto_core::traits::{SessionVerifier, SessionVerifyError};
use connetto_server::{
    AuthConfig, AuthService, IdentityResolver, InMemoryAuthStore, PermissiveProvider,
    ProviderRegistry, RedirectPolicy, ResolveFuture, ResolvedIdentity, TokenAuthority,
    VerifiedClaims, auth_router,
};
use rosetta_uuid::Uuid;

/// A fixed namespace for the deterministic `(issuer, subject)` to `Uuid`
/// mapping, standing in for a deployment's own [`IdentityResolver`].
const NS: uuid::Uuid = uuid::Uuid::from_u128(0x2b7e_1516_28ae_d2a6_abf7_1588_09cf_4f3c);

/// The typed id the resolver below mints for `subject`.
fn typed_id(subject: &str) -> Uuid {
    uuid::Uuid::new_v5(&NS, format!("https://dev.example|{subject}").as_bytes()).into()
}

/// A deployment resolver mapping verified claims to its own typed id.
struct TypedResolver;

impl IdentityResolver for TypedResolver {
    type Id = Uuid;

    fn resolve<'a>(&'a self, claims: &'a VerifiedClaims) -> ResolveFuture<'a, Uuid> {
        let id: Uuid = uuid::Uuid::new_v5(
            &NS,
            format!("{}|{}", claims.issuer, claims.subject).as_bytes(),
        )
        .into();
        Box::pin(async move { Ok(id) })
    }
}

/// The permissive provider `name` logs in as, resolving to its own subject so
/// one server can mint two distinct identities.
fn identity_named(subject: &str) -> ResolvedIdentity {
    ResolvedIdentity {
        subject: subject.to_owned(),
        ..identity()
    }
}

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
    spawn_auth_server_with_service().await.0
}

/// As [`spawn_auth_server`], also handing back the service so a test can ask the
/// real handshake verifier what it makes of a token.
async fn spawn_auth_server_with_service() -> (String, Arc<AuthService<InMemoryAuthStore>>) {
    let config = AuthConfig::default();
    let authority = Arc::new(TokenAuthority::generate(&config).expect("keypair"));
    let store = Arc::new(InMemoryAuthStore::new(config.refresh_lifetimes()));
    let service = Arc::new(AuthService::new(authority, store));
    let mut registry = ProviderRegistry::new();
    registry.register(Arc::new(PermissiveProvider::new("permissive", identity())));
    let router = auth_router(
        Arc::clone(&service),
        Arc::new(registry),
        RedirectPolicy::default(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind auth server");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    (format!("http://127.0.0.1:{port}"), service)
}

/// Serve an auth router whose store resolves identity to a typed
/// `rosetta_uuid::Uuid`, with one permissive provider per identity so a single
/// server can mint two distinct users.
async fn spawn_typed_auth_server() -> String {
    let config = AuthConfig::default();
    let authority = Arc::new(TokenAuthority::generate(&config).expect("keypair"));
    let store = Arc::new(InMemoryAuthStore::<Uuid>::with_resolver(
        config.refresh_lifetimes(),
        Arc::new(TypedResolver),
    ));
    let service = Arc::new(AuthService::new(authority, store));
    let mut registry = ProviderRegistry::new();
    for subject in ["alice", "bob"] {
        registry.register(Arc::new(PermissiveProvider::new(
            subject,
            identity_named(subject),
        )));
    }
    let router = auth_router(service, Arc::new(registry), RedirectPolicy::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind typed auth server");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    format!("http://127.0.0.1:{port}")
}

/// Drive the full loopback login against `base` as the provider named
/// `subject`, yielding the session with its typed id.
async fn login_as(base: &str, subject: &str) -> AcquiredSession<Uuid> {
    let store: Arc<dyn RefreshTokenStore> = Arc::new(MemoryRefreshStore::default());
    NativeAuthenticator::new(base.to_owned(), subject, store)
        .with_browser_opener(fake_browser(base.to_owned()))
        .login::<Uuid>()
        .await
        .expect("typed login")
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
    let login = authenticator.login::<String>().await.expect("login");
    assert!(!login.access_token.is_empty(), "access token acquired");
    assert!(!login.user_id.is_empty(), "login carries a user_id");
    assert!(
        login.session_expires_at > std::time::SystemTime::now(),
        "session expiry is in the future"
    );
    let first_refresh = store.load().expect("load").expect("refresh stored");

    // A silent refresh rotates the stored refresh token and keeps the identity.
    let refreshed = authenticator
        .refresh_access::<String>()
        .await
        .expect("refresh");
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
    let session = silent.acquire::<String>().await.expect("silent acquire");
    assert!(
        !session.access_token.is_empty(),
        "silent acquire returns an access token"
    );
    assert_eq!(session.user_id, login.user_id, "same identity on reacquire");
}

/// A deployment whose `Id` is a typed uuid, not a string. The token endpoint
/// serializes that id and the client deserializes it straight back into the
/// same type, so nothing on the `user_id` path is text.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_typed_user_id_round_trips_and_names_the_replica() {
    let base = spawn_typed_auth_server().await;

    let alice = login_as(&base, "alice").await;
    let bob = login_as(&base, "bob").await;

    // The id arrives as the deployment's own type, carrying the exact value the
    // resolver minted rather than a re-parsed rendering of it.
    assert_eq!(alice.user_id, typed_id("alice"), "alice's typed id");
    assert_eq!(bob.user_id, typed_id("bob"), "bob's typed id");
    assert_ne!(alice.user_id, bob.user_id, "distinct identities");

    // That typed id, not a Display rendering of it, names the replica file.
    let alice_replica = replica_db_name("app.db", &alice.user_id).expect("alice replica");
    let bob_replica = replica_db_name("app.db", &bob.user_id).expect("bob replica");
    assert_ne!(
        alice_replica, bob_replica,
        "an account switch selects a different replica file",
    );
    assert_eq!(
        alice_replica,
        replica_db_name("app.db", &typed_id("alice")).expect("stable"),
        "one identity always returns to the same replica",
    );
}

/// Phase E1 acceptance on the native path, against the real auth router, as E3
/// re-shaped it: the key is minted on the device rather than carried by the
/// login response.
///
/// A first login mints a per-replica key and caches it, a later login resolving
/// the same identity keeps the cached key rather than minting another, a cold
/// start with no server in reach still resolves it, and two identities on one
/// device stay isolated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replica_key_is_provisioned_once_and_cached_per_identity() {
    let base = spawn_typed_auth_server().await;
    let keys = MemoryKeyStore::default();

    let alice = login_as(&base, "alice").await;
    let alice_replica = replica_db_name("app.db", &alice.user_id).expect("alice replica");

    // First sight of this replica: a key is minted locally and written through.
    let provisioned =
        provision_replica_key(&keys, &alice_replica).expect("a key is minted on first login");
    assert_eq!(
        keys.load(&alice_replica).expect("load"),
        Some(provisioned.clone()),
        "the minted key is cached for a later cold start",
    );

    // A second login for the same identity changes nothing about the key: the
    // server has no say in it, and provision-once means the cached key wins,
    // which is what stops a re-login from stranding the replica.
    let again = login_as(&base, "alice").await;
    assert_eq!(
        replica_db_name("app.db", &again.user_id).expect("replica"),
        alice_replica,
    );
    let effective = provision_replica_key(&keys, &alice_replica).expect("resolve");
    assert_eq!(
        effective, provisioned,
        "the cached key survives a second login",
    );

    // The offline property: nothing but the local store is consulted, so the
    // replica opens with no valid credential and no network.
    let offline = keys
        .load(&alice_replica)
        .expect("load")
        .expect("the cached key reads back");
    assert_eq!(offline, provisioned, "an offline cold start reads it back");

    // A second identity on the same device gets its own key and its own
    // record, so neither can read the other's replica.
    let bob = login_as(&base, "bob").await;
    let bob_replica = replica_db_name("app.db", &bob.user_id).expect("bob replica");
    let bob_key = provision_replica_key(&keys, &bob_replica).expect("bob is provisioned too");
    assert_ne!(bob_key, provisioned, "identities do not share a key");
    assert_eq!(
        keys.load(&alice_replica).expect("load"),
        Some(provisioned),
        "bob's login leaves alice's cached key untouched",
    );
}

/// Phase E3 acceptance, credential teardown against the real auth router.
///
/// A logout revokes the session server-side, which is the half a local clear
/// cannot give: the next handshake is refused even though the access token it was
/// minted with is still inside its own lifetime and still verifies by signature.
/// The stored refresh token is gone too, and a copy of it kept elsewhere is dead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_logout_revokes_the_session_and_clears_the_local_credential() {
    let (base, service) = spawn_auth_server_with_service().await;
    let store: Arc<dyn RefreshTokenStore> = Arc::new(MemoryRefreshStore::default());
    let authenticator = NativeAuthenticator::new(base.clone(), "permissive", Arc::clone(&store))
        .with_browser_opener(fake_browser(base.clone()));

    let login = authenticator.login::<String>().await.expect("login");
    let refresh = store
        .load()
        .expect("load")
        .expect("the refresh token is stored");

    // Before the logout the real handshake verifier accepts this token.
    let verifier = service.verifier();
    verifier
        .verify_session(&login.access_token)
        .await
        .expect("a live session verifies");

    authenticator.logout().await.expect("logout");

    // Local state is gone, so nothing on this device can silently reacquire.
    assert_eq!(
        store.load().expect("load"),
        None,
        "the refresh token is cleared",
    );

    // Server-side liveness is gone, which is what makes the logout mean
    // something: the access token is inside its 15 minute default TTL and its
    // signature still checks out, and the handshake refuses it anyway.
    match verifier.verify_session(&login.access_token).await {
        Err(SessionVerifyError::Revoked) => {}
        Err(other) => panic!("expected Revoked, got {other:?}"),
        Ok(_) => panic!("a logged-out session must be refused at the next handshake"),
    }

    // A copy of the refresh token kept anywhere else is dead too, so the session
    // cannot be resurrected into a fresh access token.
    let kept = MemoryRefreshStore::default();
    kept.store(&refresh).expect("seed the copy");
    let resurrect = NativeAuthenticator::new(base, "permissive", Arc::new(kept))
        .with_browser_opener(Arc::new(|_url: &str| {
            panic!("no browser during a refresh attempt")
        }));
    match resurrect.refresh_access::<String>().await {
        Err(ClientError::Auth(_)) => {}
        Err(other) => panic!("expected a rejected credential, got {other:?}"),
        Ok(_) => panic!("a revoked session must not rotate its refresh token"),
    }

    // Idempotent: with nothing stored there is nothing to revoke.
    authenticator
        .logout()
        .await
        .expect("a second logout is a no-op");
}

/// Offline logout, which decision three of phase E3 settles: the local clear
/// happens even when the revoke cannot be delivered, and the failure is reported
/// rather than swallowed, so the application knows the session stays live until it
/// expires on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_logout_still_clears_local_state_and_says_the_revoke_failed() {
    let store: Arc<dyn RefreshTokenStore> = Arc::new(MemoryRefreshStore::default());
    store.store("session-id.secret").expect("seed a credential");
    // Port 1 is reserved and nothing listens there, which is this test's stand-in
    // for a device with no connectivity.
    let authenticator =
        NativeAuthenticator::new("http://127.0.0.1:1", "permissive", Arc::clone(&store));

    match authenticator.logout().await {
        Err(ClientError::Transport(_)) => {}
        Err(other) => panic!("expected a transport failure, got {other:?}"),
        Ok(()) => panic!("an unreachable server must not report a successful revoke"),
    }
    assert_eq!(
        store.load().expect("load"),
        None,
        "the credential is cleared even when the revoke never landed",
    );
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
