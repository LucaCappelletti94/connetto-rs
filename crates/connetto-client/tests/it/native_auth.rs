//! Native acquisition.
//!
//! Serves connetto-server's auth router on a real loopback port with a
//! containerised OIDC provider, then drives the full native flow: the
//! authenticator binds its own loopback listener and opens a browser, a fake
//! browser walks the redirect chain and delivers the code to that listener, the
//! authenticator exchanges the code with its PKCE verifier, stores the refresh
//! token, and silently refreshes.
//!
//! It also proves the typed `user_id` boundary: a project whose id is a
//! `rosetta_uuid::Uuid` gets that value back from the token endpoint as its own
//! type, with no `Display` or `FromStr` anywhere on the path, and the replica
//! file the client opens is named from it.

use std::sync::Arc;

use connetto_client::{
    AcquiredSession, BrowserOpener, ClientError, Grant, MemoryKeyStore, MemoryRefreshStore,
    NativeAuthenticator, encode_identity, provision_replica_key, replica_db_name,
};
use connetto_core::traits::{GrantRefused, HandshakeAuthority, RefreshTokenStore, ReplicaKeyStore};
use connetto_server::{
    AuthConfig, AuthService, GenericOidcProvider, IdentityResolver, InMemoryAuthStore,
    ProviderRegistry, RedirectPolicy, RequestGuard, ResolveFuture, TokenAuthority, VerifiedClaims,
    auth_router,
};
use connetto_test_harness::{MOCK_OAUTH_PROVIDER, MockOauth};
use openidconnect::reqwest;
use rosetta_uuid::Uuid;

/// A fixed namespace for the deterministic `subject` to `Uuid` mapping,
/// standing in for an app's own [`IdentityResolver`].
const NS: uuid::Uuid = uuid::Uuid::from_u128(0x2b7e_1516_28ae_d2a6_abf7_1588_09cf_4f3c);

/// The typed id the resolver below mints for `subject`.
///
/// Keys on the subject alone because the test idp mints a fresh issuer per run.
fn typed_id(subject: &str) -> Uuid {
    uuid::Uuid::new_v5(&NS, subject.as_bytes()).into()
}

/// A resolver mapping verified claims to its own typed id.
struct TypedResolver;

impl IdentityResolver for TypedResolver {
    type Id = Uuid;

    fn resolve<'a>(&'a self, claims: &'a VerifiedClaims) -> ResolveFuture<'a, Uuid> {
        // Key on the subject alone: the test idp mints a fresh issuer per run.
        let id: Uuid = uuid::Uuid::new_v5(&NS, claims.subject.as_bytes()).into();
        Box::pin(async move { Ok(id) })
    }
}

/// Serve the auth router on an ephemeral port and return the base URL and idp
/// guard.
async fn spawn_auth_server() -> (String, MockOauth) {
    let (base, _service, idp) = spawn_auth_server_with_service().await;
    (base, idp)
}

/// As [`spawn_auth_server`], also handing back the service so a test can ask the
/// real handshake verifier what it makes of a token.
async fn spawn_auth_server_with_service() -> (String, Arc<AuthService<InMemoryAuthStore>>, MockOauth)
{
    // Bind connetto's listener first so the callback URL is known.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind auth server");
    let port = listener.local_addr().expect("addr").port();
    let base = format!("http://127.0.0.1:{port}");
    let callback = format!("{base}/auth/callback");

    let idp = MockOauth::start().await;
    let provider = GenericOidcProvider::discover(
        idp.oidc_config(MOCK_OAUTH_PROVIDER, callback),
        reqwest::Client::new(),
    )
    .await
    .expect("discover provider");

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
    (base, service, idp)
}

/// Serve an auth router whose store resolves identity to a typed
/// `rosetta_uuid::Uuid`, with one containerised provider.
async fn spawn_typed_auth_server() -> (String, MockOauth) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind typed auth server");
    let port = listener.local_addr().expect("addr").port();
    let base = format!("http://127.0.0.1:{port}");
    let callback = format!("{base}/auth/callback");

    let config = AuthConfig::default();
    let authority = Arc::new(TokenAuthority::generate(&config).expect("keypair"));
    let store = Arc::new(InMemoryAuthStore::<Uuid>::with_resolver(
        config.refresh_lifetimes(),
        Arc::new(TypedResolver),
    ));
    let service = Arc::new(AuthService::new(
        authority,
        store,
        Arc::new(RequestGuard::default()),
    ));
    let mut registry = ProviderRegistry::new();

    let idp = MockOauth::start().await;
    let provider = GenericOidcProvider::discover(
        idp.oidc_config(MOCK_OAUTH_PROVIDER, callback),
        reqwest::Client::new(),
    )
    .await
    .expect("discover provider");
    registry.register(Arc::new(provider));

    let router = auth_router(service, Arc::new(registry), RedirectPolicy::default());
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    (base, idp)
}

/// Drive the full loopback login against `base` as `subject`.
async fn login_as(base: &str, subject: &str) -> AcquiredSession<Uuid> {
    let store: SharedRefresh = Arc::new(MemoryRefreshStore::default());
    NativeAuthenticator::new(base.to_owned(), MOCK_OAUTH_PROVIDER, store, None)
        .with_browser_opener(fake_browser(subject))
        .login::<Uuid>()
        .await
        .expect("typed login")
}

/// The refresh store a [`NativeAuthenticator`] holds, spelled once.
type SharedRefresh = Arc<dyn RefreshTokenStore<Error = ClientError> + Send + Sync>;

/// A fake browser: given connetto's login URL, walk the real OIDC redirect
/// chain until the authenticator's loopback listener receives the code.
fn fake_browser(subject: &str) -> BrowserOpener {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");
    let subject = subject.to_owned();
    Arc::new(move |login_url: &str| {
        let http = http.clone();
        let subject = subject.clone();
        let login_url = login_url.to_owned();
        tokio::spawn(async move {
            let mut next_url = login_url;
            let mut submitted = false;
            for _ in 0..6 {
                let resp = http.get(&next_url).send().await.expect("hop");
                if !submitted && resp.url().path().ends_with("/authorize") {
                    let form_url = resp.url().to_string();
                    let posted = http
                        .post(form_url)
                        .form(&[("username", subject.as_str())])
                        .send()
                        .await
                        .expect("submit login form");
                    submitted = true;
                    let Some(loc) = posted.headers().get("location") else {
                        break;
                    };
                    loc.to_str()
                        .expect("utf8 location")
                        .clone_into(&mut next_url);
                    continue;
                }
                match resp.headers().get("location") {
                    Some(loc) => {
                        loc.to_str()
                            .expect("utf8 location")
                            .clone_into(&mut next_url);
                    }
                    None => break,
                }
            }
        });
        Ok(())
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_login_refreshes_and_silently_reacquires() {
    connetto_test_harness::isolated_session_keyring();
    let (base, _idp) = spawn_auth_server().await;
    let store: SharedRefresh = Arc::new(MemoryRefreshStore::default());

    // Interactive login: no account stored yet, so nothing to try silently.
    let login =
        NativeAuthenticator::new(base.clone(), MOCK_OAUTH_PROVIDER, Arc::clone(&store), None)
            .with_browser_opener(fake_browser("native-user"))
            .login::<String>()
            .await
            .expect("login");
    assert!(!login.access_token.is_empty(), "access token acquired");
    assert!(!login.user_id.is_empty(), "login carries a user_id");
    assert!(
        login.session_expires_at > std::time::SystemTime::now(),
        "session expiry is in the future"
    );

    // Login stores the credential under the encoded user id, not a literal.
    let encoded_account = encode_identity(&login.user_id).expect("encode account");
    let first_refresh = store
        .load(&encoded_account)
        .expect("load")
        .expect("refresh stored");

    // Subsequent operations know which account to address.
    let authenticator = Arc::new(
        NativeAuthenticator::new(
            base.clone(),
            MOCK_OAUTH_PROVIDER,
            Arc::clone(&store),
            Some(encoded_account.clone()),
        )
        .with_browser_opener(fake_browser("native-user")),
    );

    // A silent refresh rotates the stored refresh token and keeps the identity.
    let refreshed = authenticator
        .refresh_access::<String>()
        .await
        .expect("refresh");
    assert!(!refreshed.access_token.is_empty(), "refreshed access token");
    assert_eq!(refreshed.user_id, login.user_id, "identity is continuous");
    let second_refresh = store
        .load(&encoded_account)
        .expect("load")
        .expect("refresh stored");
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
    let silent = NativeAuthenticator::new(
        base,
        MOCK_OAUTH_PROVIDER,
        Arc::clone(&store),
        Some(encoded_account),
    )
    .with_browser_opener(panicking);
    let session = silent.acquire::<String>().await.expect("silent acquire");
    assert!(
        !session.access_token.is_empty(),
        "silent acquire returns an access token"
    );
    assert_eq!(session.user_id, login.user_id, "same identity on reacquire");
}

/// A project whose `Id` is a typed uuid, not a string. The token endpoint
/// serializes that id and the client deserializes it straight back into the
/// same type, so nothing on the `user_id` path is text.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_typed_user_id_round_trips_and_names_the_replica() {
    connetto_test_harness::isolated_session_keyring();
    let (base, _idp) = spawn_typed_auth_server().await;

    let alice = login_as(&base, "alice").await;
    let bob = login_as(&base, "bob").await;

    // The id arrives as the app's own type, carrying the exact value the
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
    connetto_test_harness::isolated_session_keyring();
    let (base, _idp) = spawn_typed_auth_server().await;
    let keys = MemoryKeyStore::default();

    let alice = login_as(&base, "alice").await;
    let alice_replica = replica_db_name("app.db", &alice.user_id).expect("alice replica");

    // First sight of this replica: a key is minted locally and written through.
    let provisioned = provision_replica_key(&keys, &alice_replica)
        .await
        .expect("a key is minted on first login");
    assert_eq!(
        keys.load(&alice_replica).await.expect("load"),
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
    let effective = provision_replica_key(&keys, &alice_replica)
        .await
        .expect("resolve");
    assert_eq!(
        effective, provisioned,
        "the cached key survives a second login",
    );

    // The offline property: nothing but the local store is consulted, so the
    // replica opens with no valid credential and no network.
    let offline = keys
        .load(&alice_replica)
        .await
        .expect("load")
        .expect("the cached key reads back");
    assert_eq!(offline, provisioned, "an offline cold start reads it back");

    // A second identity on the same device gets its own key and its own
    // record, so neither can read the other's replica.
    let bob = login_as(&base, "bob").await;
    let bob_replica = replica_db_name("app.db", &bob.user_id).expect("bob replica");
    let bob_key = provision_replica_key(&keys, &bob_replica)
        .await
        .expect("bob is provisioned too");
    assert_ne!(bob_key, provisioned, "identities do not share a key");
    assert_eq!(
        keys.load(&alice_replica).await.expect("load"),
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
    connetto_test_harness::isolated_session_keyring();
    let (base, service, _idp) = spawn_auth_server_with_service().await;
    let store: SharedRefresh = Arc::new(MemoryRefreshStore::default());

    let login =
        NativeAuthenticator::new(base.clone(), MOCK_OAUTH_PROVIDER, Arc::clone(&store), None)
            .with_browser_opener(fake_browser("native-user"))
            .login::<String>()
            .await
            .expect("login");

    // Login stores the credential under the encoded user id.
    let encoded_account = encode_identity(&login.user_id).expect("encode account");
    let refresh = store
        .load(&encoded_account)
        .expect("load")
        .expect("the refresh token is stored");

    // For logout and further operations, build an authenticator that knows the account.
    let authenticator = NativeAuthenticator::new(
        base.clone(),
        MOCK_OAUTH_PROVIDER,
        Arc::clone(&store),
        Some(encoded_account.clone()),
    )
    .with_browser_opener(fake_browser("native-user"));

    // Before the logout the real handshake verifier accepts this token.
    let concrete = service.handshake_authority();
    let authority: &dyn HandshakeAuthority = &concrete;
    authority
        .check_grant(&Grant::new(login.access_token.clone()))
        .await
        .expect("a live session verifies");

    authenticator.logout().await.expect("logout");

    // Local state is gone, so nothing on this device can silently reacquire.
    assert_eq!(
        store.load(&encoded_account).expect("load"),
        None,
        "the refresh token is cleared",
    );

    // Server-side liveness is gone, which is what makes the logout mean
    // something: the access token is inside its 15 minute default TTL and its
    // signature still checks out, and the handshake refuses it anyway.
    match authority
        .check_grant(&Grant::new(login.access_token.clone()))
        .await
    {
        Err(GrantRefused::Revoked) => {}
        Err(other) => panic!("expected Revoked, got {other:?}"),
        Ok(_) => panic!("a logged-out session must be refused at the next handshake"),
    }

    // A copy of the refresh token kept anywhere else is dead too, so the session
    // cannot be resurrected into a fresh access token.
    let kept = MemoryRefreshStore::default();
    kept.store(&encoded_account, &refresh)
        .expect("seed the copy");
    let resurrect = NativeAuthenticator::new(
        base,
        MOCK_OAUTH_PROVIDER,
        Arc::new(kept),
        Some(encoded_account),
    )
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
    connetto_test_harness::isolated_session_keyring();
    // The encoded form of the id the mock provider would return on a real login.
    let encoded_account = encode_identity("native-user").expect("encode offline account");
    let store: SharedRefresh = Arc::new(MemoryRefreshStore::default());
    store
        .store(&encoded_account, "session-id.secret")
        .expect("seed a credential");
    // Port 1 is reserved and nothing listens there, which is this test's stand-in
    // for a device with no connectivity.
    let authenticator = NativeAuthenticator::new(
        "http://127.0.0.1:1",
        MOCK_OAUTH_PROVIDER,
        Arc::clone(&store),
        Some(encoded_account.clone()),
    );

    match authenticator.logout().await {
        Err(ClientError::Transport(_)) => {}
        Err(other) => panic!("expected a transport failure, got {other:?}"),
        Ok(()) => panic!("an unreachable server must not report a successful revoke"),
    }
    assert_eq!(
        store.load(&encoded_account).expect("load"),
        None,
        "the credential is cleared even when the revoke never landed",
    );
}

#[test]
fn memory_refresh_store_round_trips() {
    let store = MemoryRefreshStore::default();
    assert!(store.load("any-key").unwrap().is_none(), "empty at first");
    store.store("any-key", "refresh-abc").unwrap();
    assert_eq!(
        store.load("any-key").unwrap().as_deref(),
        Some("refresh-abc")
    );
    store.store("any-key", "refresh-def").unwrap();
    assert_eq!(
        store.load("any-key").unwrap().as_deref(),
        Some("refresh-def"),
        "replaces"
    );
    store.clear("any-key").unwrap();
    assert!(store.load("any-key").unwrap().is_none(), "cleared");
}
