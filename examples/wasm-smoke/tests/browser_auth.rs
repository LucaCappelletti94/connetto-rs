//! Phase E4.b: the browser branch of authentication, against a real stack.
//!
//! Everything here is what the native leg structurally cannot reach. E4.a proved
//! the shared OAuth spine, meaning connetto's login and callback endpoints, the
//! provider round trip, and the token mint, all of which is one implementation for
//! both clients. What forks after that is browser-specific and had never run at
//! all: `BrowserAuthenticator` had never talked to a server, `web-sys` `fetch` had
//! never carried a token request, the refresh store had never held a credential
//! from a real login, and `BrowserAuthenticator::logout` had never been executed.
//!
//! Runs in a dedicated worker, which is where the real DB worker runs and the only
//! context with OPFS sync access handles, so the token custody path is the product
//! one: the refresh token lands in an OPFS database encrypted under this device's
//! own key.
//!
//! **Needs the auth stack up**, following the same convention as `opfs.rs` and
//! `smoke.rs`, which need the demo stack. This one needs only the auth stack and no
//! Postgres:
//!
//! ```text
//! mkdir -p target/devkeys
//! openssl genpkey -algorithm ed25519 -out target/devkeys/priv.pem
//! openssl pkey -in target/devkeys/priv.pem -pubout -out target/devkeys/pub.pem
//! CONNETTO_JWT_PRIVATE_KEY_FILE=target/devkeys/priv.pem \
//!   CONNETTO_JWT_PUBLIC_KEY_FILE=target/devkeys/pub.pem \
//!   cargo run --release --all-features -p connetto-server --example auth_stack
//! wasm-pack test --headless --chrome examples/wasm-smoke --test browser_auth
//! ```
//!
//! One thing this still stands in for: the tab. A worker cannot navigate, and a
//! test page that navigated away would end the test, so the login URL is walked
//! with a redirect-following `fetch` and the delivered code is read out of the
//! final URL. That is why the stack serves the client redirect on its own origin.
//! The hop this leaves unexercised is the `BroadcastChannel` handoff from a real
//! tab's callback route to the worker, which `deliver_login_code` and
//! `await_login_code` implement and which E4.c will drive from the demo.

#![cfg(target_arch = "wasm32")]

use connetto_client::replica_db_name;
use connetto_web::auth::{
    Acquired, BrowserAuthenticator, RefreshStore, ReplicaKeyStore, WorkerAuthConfig,
    provision_replica_key,
};
use connetto_web::storage::{ReplicaStorage, clear_device_key, device_key};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{Response, WorkerGlobalScope};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Where `cargo run --example auth_stack` listens by default.
const AUTH_BASE: &str = "http://127.0.0.1:18099";

/// The provider the stack registers, and the landing route it serves so the whole
/// redirect chain stays on one origin.
const PROVIDER: &str = "dev-idp";

/// The OPFS database holding the refresh token for this suite, distinct from the
/// other suites' so one origin's pool holds them all.
const REFRESH_DB: &str = "e4b-refresh.sqlite";

/// A second refresh store, used to present a credential the server has revoked.
const REVOKED_DB: &str = "e4b-revoked.sqlite";

/// The replica prefix this suite names its per-identity replica under.
const REPLICA_PREFIX: &str = "e4b-replica";

/// Stand in for the tab: walk the login URL with redirects followed and read the
/// delivered code and state out of the final URL.
///
/// A real tab navigates and its callback route posts the code to the worker over a
/// `BroadcastChannel`. A worker cannot navigate, and `fetch` cannot read a
/// `Location` header (a manual-redirect response is opaque), so following the
/// chain and reading `Response::url` is the only way to do this from here. It
/// works because the stack keeps every hop on one origin.
async fn walk_the_login(login_url: &str) -> (String, String) {
    let global: WorkerGlobalScope = js_sys::global()
        .dyn_into()
        .expect("this test runs in a worker");
    let response: Response = JsFuture::from(global.fetch_with_str(login_url))
        .await
        .expect("the auth stack must be running: see this file's header")
        .dyn_into()
        .expect("a fetch resolves to a Response");
    assert!(
        response.ok(),
        "the login chain ended at {} with status {}",
        response.url(),
        response.status()
    );
    let final_url = response.url();
    let parsed = web_sys::Url::new(&final_url).expect("a parseable final url");
    let params = parsed.search_params();
    let code = params
        .get("code")
        .unwrap_or_else(|| panic!("no code in the final url {final_url}"));
    let state = params
        .get("state")
        .unwrap_or_else(|| panic!("no state in the final url {final_url}"));
    (code, state)
}

fn config() -> WorkerAuthConfig {
    WorkerAuthConfig {
        auth_base_url: AUTH_BASE.to_owned(),
        // The stack serves the navigation and the fetch calls on one origin.
        login_base_url: None,
        provider: PROVIDER.to_owned(),
        redirect_uri: format!("{AUTH_BASE}/dev/landing"),
    }
}

/// The whole browser branch in one pass: acquire needs a login, the login
/// completes against a real provider, the token exchange goes out through
/// `web-sys` `fetch` from the worker, the refresh token lands encrypted in OPFS, a
/// second acquire refreshes silently rather than asking to log in again, the
/// identity names an encrypted replica that opens, and a logout clears local state
/// and revokes the session so the credential it held is dead.
#[wasm_bindgen_test]
async fn a_browser_login_and_logout_round_trip_against_a_real_stack() {
    let storage = ReplicaStorage::install().await;
    let keys = ReplicaKeyStore::open().await.expect("open the key store");

    // Start from nothing, so a rerun in the same origin is not resuming an earlier
    // session's credential.
    clear_device_key(&keys).await.expect("clear the device key");
    for db in [REFRESH_DB, REVOKED_DB] {
        storage.delete_db(db).expect("clear an earlier store");
    }
    let device = device_key(&keys).await.expect("mint the device key");

    let store =
        RefreshStore::open(&storage.db_url(REFRESH_DB), &device).expect("open the refresh store");
    let authenticator = BrowserAuthenticator::new(config());

    // Nothing is stored, so there is nothing to refresh from and the worker asks
    // for an interactive login.
    let pending = match authenticator
        .acquire::<String>(&store)
        .await
        .expect("acquire")
    {
        Acquired::NeedLogin(pending) => pending,
        Acquired::Access(_) => panic!("an empty refresh store cannot silently refresh"),
    };
    assert!(
        pending.login_url.starts_with(AUTH_BASE),
        "the login URL points at the configured auth base, got {}",
        pending.login_url
    );

    // The login completes for real: connetto redirects to the provider, the
    // provider auto-approves and redirects back, connetto exchanges the code
    // server to server and delivers its own one-time code to the client redirect.
    let (code, state) = walk_the_login(&pending.login_url).await;

    // The worker redeems that code over `web-sys` fetch, which is the first time
    // this path has ever carried a request, and persists the rotated refresh token
    // into the encrypted OPFS store.
    let session = authenticator
        .complete::<String>(&pending, &code, &state, &store)
        .await
        .expect("complete the login");
    assert!(
        !session.access_token.is_empty(),
        "the worker holds an access token"
    );
    assert!(
        !session.user_id.is_empty(),
        "and the identity the provider asserted"
    );
    let first_refresh = store
        .load()
        .expect("load")
        .expect("the refresh token is persisted");

    // A cold start or a leader failover refreshes silently: no interactive login,
    // the same identity, and a rotated token.
    let refreshed = match authenticator
        .acquire::<String>(&store)
        .await
        .expect("acquire again")
    {
        Acquired::Access(session) => session,
        Acquired::NeedLogin(_) => panic!("a stored refresh token must refresh silently"),
    };
    assert_eq!(
        refreshed.user_id, session.user_id,
        "the identity is continuous across a refresh"
    );
    let rotated = store.load().expect("load").expect("a refresh token");
    assert_ne!(rotated, first_refresh, "the refresh token rotated");

    // The identity names its own replica, and the key for it is minted on this
    // device. This is the join between the auth path and the encryption work: the
    // replica a real login opens is encrypted under a key the server never saw.
    let replica_name = replica_db_name(REPLICA_PREFIX, &session.user_id).expect("a replica name");
    storage
        .delete_db(&replica_name)
        .expect("clear an earlier replica");
    keys.clear(&replica_name).await.expect("clear its key");
    let replica_key = provision_replica_key(&keys, &replica_name)
        .await
        .expect("mint the replica key");
    {
        use diesel::Connection as _;
        use diesel::connection::SimpleConnection as _;

        let mut conn = diesel::SqliteConnection::establish(&storage.db_url(&replica_name))
            .expect("open the replica");
        connetto_client::cipher::unlock(&mut conn, &replica_key).expect("apply the key");
        conn.batch_execute("CREATE TABLE probe (id INTEGER PRIMARY KEY)")
            .expect("the encrypted replica accepts DDL");
    }
    assert!(
        storage.exists(&replica_name),
        "the identity's replica is in the pool"
    );

    // Keep a copy of the live credential, so the revoke can be observed rather
    // than inferred from the local clear.
    let live_refresh = store.load().expect("load").expect("a refresh token");
    let revoked_store =
        RefreshStore::open(&storage.db_url(REVOKED_DB), &device).expect("open the second store");
    revoked_store
        .save(&live_refresh)
        .expect("seed the copy before the logout");
    // Without this the revoke assertion below could pass for the wrong reason: an
    // empty store also yields `NeedLogin`, which would look like a refusal.
    assert_eq!(
        revoked_store.load().expect("load").as_deref(),
        Some(live_refresh.as_str()),
        "the copy really holds the credential that is about to be revoked"
    );

    // Credential teardown, for real, over `fetch` from the worker.
    authenticator
        .logout(&store)
        .await
        .expect("logout, including the server revoke");
    assert_eq!(
        store.load().expect("load"),
        None,
        "the local credential is cleared"
    );

    // And the copy is dead, which is what the revoke bought: without it this would
    // refresh happily and the logout would be local theatre.
    match authenticator
        .acquire::<String>(&revoked_store)
        .await
        .expect("acquire with the revoked credential")
    {
        Acquired::NeedLogin(_) => {}
        Acquired::Access(_) => {
            panic!("a revoked session must not refresh, even with the token in hand")
        }
    }

    // Data teardown is not part of a logout: the replica and its key survive, which
    // is what makes a returning user's resume fast.
    assert!(
        storage.exists(&replica_name),
        "a credential-only logout leaves the replica alone"
    );
    assert_eq!(
        keys.load(&replica_name).await.expect("load"),
        Some(replica_key),
        "and leaves its key alone"
    );
}
