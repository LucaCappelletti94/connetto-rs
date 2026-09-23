//! Phase E4.b: the browser branch of authentication, against a real stack.
//!
//! Everything here is what the native leg structurally cannot reach. E4.a proved
//! the shared OAuth spine, meaning connetto's login and callback endpoints, the
//! provider round trip, and the token mint, all of which is one implementation for
//! both clients. What forks after that is browser-specific: `BrowserAuthenticator`
//! talking to a server over `web-sys` `fetch`, the refresh credential living in
//! the `HttpOnly` cookie the browser carries, and `BrowserAuthenticator::logout`
//! revoking through that cookie.
//!
//! Runs in a dedicated worker, which is where the real DB worker runs and the
//! only context with OPFS sync access handles, so the account index beside the
//! cookie is the product one.
//!
//! One thing this still stands in for: the tab. A worker cannot navigate, and a
//! test page that navigated away would end the test, so the login URL is walked
//! with a redirect-following `fetch` and the delivered code is read out of the
//! final URL. That is why the stack serves the client redirect on its own origin.
//! The hop this leaves unexercised is the `BroadcastChannel` handoff from a real
//! tab's callback route to the worker, which `deliver_login_code` and
//! `await_login_code` implement and which E4.c will drive from the demo.

#![cfg(target_arch = "wasm32")]

use connetto_client::{encode_identity, replica_db_name};
use connetto_core::traits::ReplicaKeyStore;
use connetto_web::auth::{
    AccountStore, Acquired, BrowserAuthenticator, IdbKeyStore, WorkerAuthConfig,
    provision_replica_key,
};
use connetto_web::storage::ReplicaStorage;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
use web_sys::{Request, RequestInit, Response, WorkerGlobalScope};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Where the auth stack listens by default.
const AUTH_BASE: &str = "http://127.0.0.1:18099";

/// The provider the stack registers, and the landing route it serves so the
/// worker can read the delivered code from the final URL.
const PROVIDER: &str = "dev-idp";

/// A store of its own for the two-account exercise, so neither account's rows can
/// be confused with another test's.
const TWO_ACCOUNT_DB: &str = "r54-two-accounts.sqlite";

/// The OPFS account index for this suite, distinct from the other suites' so one
/// origin's pool holds them all.
const ACCOUNT_DB: &str = "e4b-accounts.sqlite";

/// A second index, for the stale-marker case, so its bogus marker cannot be
/// mistaken for the one above.
const STALE_DB: &str = "r42-stale-marker.sqlite";

/// The replica prefix this suite names its per-identity replica under.
const REPLICA_PREFIX: &str = "e4b-replica";

/// Stand in for the tab: walk the login URL, submit the selected subject to the
/// provider form, and read the delivered code and state out of the final URL.
///
/// A real tab navigates and its callback route posts the code to the worker over a
/// `BroadcastChannel`. A worker cannot navigate, and `fetch` cannot read a
/// `Location` header from a manual redirect response, so following the chain and
/// reading `Response::url` is the only way to do this from here.
async fn walk_the_login(login_url: &str, subject: &str) -> (String, String) {
    let global: WorkerGlobalScope = js_sys::global()
        .dyn_into()
        .expect("this test runs in a worker");
    let response: Response = JsFuture::from(global.fetch_with_str(login_url))
        .await
        .expect("the auth server must be running")
        .dyn_into()
        .expect("a fetch resolves to a Response");
    assert!(
        response.ok(),
        "the login form loaded at {} with status {}",
        response.url(),
        response.status()
    );
    let form_url = response.url();
    let init = RequestInit::new();
    init.set_method("POST");
    init.set_body(&format!("username={subject}").into());
    let request = Request::new_with_str_and_init(&form_url, &init).expect("build form request");
    request
        .headers()
        .set("content-type", "application/x-www-form-urlencoded")
        .expect("set form content type");
    let response: Response = JsFuture::from(global.fetch_with_request(&request))
        .await
        .expect("submit the login form")
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
    config_for(PROVIDER)
}

fn config_for(provider: &str) -> WorkerAuthConfig {
    // The stack serves connetto's navigation and fetch endpoints on one origin.
    WorkerAuthConfig::new(AUTH_BASE, provider, format!("{AUTH_BASE}/dev/landing"))
}

/// Log in for real against `provider` and return the session it resolved.
///
/// `account` is what the authenticator addresses on the way in, and it is `None`
/// for a first login and for adding somebody new: a stored account would be
/// silently refreshed instead, which is the whole difference between switching to
/// an account and adding one.
async fn login_as(
    subject: &str,
    account: Option<String>,
    store: &AccountStore,
) -> connetto_web::auth::BrowserSession<String> {
    let authenticator = BrowserAuthenticator::new(config_for(PROVIDER), account);
    let pending = match authenticator
        .acquire::<String>(store)
        .await
        .expect("acquire")
    {
        Acquired::NeedLogin(pending) => pending,
        Acquired::Access(_) => panic!("addressing no stored account cannot refresh silently"),
    };
    let (code, state) = walk_the_login(&pending.login_url, subject).await;
    authenticator
        .complete::<String>(&pending, &code, &state, store)
        .await
        .expect("complete the login")
}

/// The whole browser branch in one pass: acquire needs a login, the login
/// completes against a real provider, the token exchange goes out through
/// `web-sys` `fetch` from the worker, the browser takes the refresh cookie the
/// exchange set, a second acquire refreshes silently through that cookie rather
/// than asking to log in again, the identity names an encrypted replica that
/// opens, and a logout revokes the session and clears the cookie and the index
/// row.
#[wasm_bindgen_test]
async fn a_browser_login_and_logout_round_trip_against_a_real_stack() {
    let storage = ReplicaStorage::install().await;
    let keys = IdbKeyStore::open().await.expect("open the key store");

    // Start from nothing, so a rerun in the same origin is not resuming an
    // earlier session.
    storage
        .delete_db(ACCOUNT_DB)
        .expect("clear an earlier index");

    let store = AccountStore::open(&storage.db_url(ACCOUNT_DB)).expect("open the account index");
    // Nothing is stored, so pass None: this is a first run.
    let first_auth = BrowserAuthenticator::new(config(), None);

    let pending = match first_auth.acquire::<String>(&store).await.expect("acquire") {
        Acquired::NeedLogin(pending) => pending,
        Acquired::Access(_) => panic!("an empty account index cannot silently refresh"),
    };
    assert!(
        pending.login_url.starts_with(AUTH_BASE),
        "the login URL points at the configured auth base, got {}",
        pending.login_url
    );

    // The login completes for real: connetto redirects to the provider, the
    // chosen subject is submitted, connetto exchanges the code server to server,
    // and its own one-time code reaches the client redirect.
    let (code, state) = walk_the_login(&pending.login_url, "browser-user").await;

    // The worker redeems that code over `web-sys` fetch. The refresh token never
    // appears in the body: the same response set the `HttpOnly` cookie, which
    // this crate cannot read.
    let session = first_auth
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

    // The account lands in the index and owns the last-used marker.
    let account = encode_identity(&session.user_id).expect("encode the account key");
    assert!(
        store.accounts().expect("list").contains(&account),
        "the account is indexed"
    );
    assert_eq!(
        connetto_web::auth::remembered_account(&store)
            .expect("read the marker")
            .as_deref(),
        Some(account.as_str()),
        "and the marker names it"
    );

    // A cold start or a leader failover refreshes silently through the cookie:
    // no interactive login, the same identity. The authenticator for this knows
    // which account to try.
    let authenticator = BrowserAuthenticator::new(config(), Some(account.clone()));
    let refreshed = match authenticator
        .acquire::<String>(&store)
        .await
        .expect("acquire again")
    {
        Acquired::Access(session) => session,
        Acquired::NeedLogin(_) => panic!("the cookie the login set must refresh silently"),
    };
    assert_eq!(
        refreshed.user_id, session.user_id,
        "the identity is continuous across a refresh"
    );

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

    // Credential teardown, for real, over `fetch` from the worker: the marked
    // logout revokes the session and removes this account's cookie.
    authenticator
        .logout(&store)
        .await
        .expect("logout, including the server revoke");
    assert!(
        !store.accounts().expect("list").contains(&account),
        "the account leaves the index"
    );

    // The cookie is gone with the session: an acquire for the account can only
    // ask for an interactive login again. That the server-side session is dead
    // too, rather than merely un-carried, is pinned natively in
    // `authn_flow::marked_logout_revokes_and_clears_only_that_cookie`.
    match BrowserAuthenticator::new(config(), Some(account.clone()))
        .acquire::<String>(&store)
        .await
        .expect("acquire after logout")
    {
        Acquired::NeedLogin(_) => {}
        Acquired::Access(_) => panic!("a logged-out account must not refresh"),
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

/// R42 decision 4: a last-used marker naming an account whose credential is gone
/// asks for a login rather than signing the other stored account in.
///
/// **This is the half that a test with no server cannot carry.** Its sibling in
/// `crates/connetto-web/tests/account_boot.rs` proves the same outcome offline,
/// but offline a fallback that walked the remaining accounts would fail its
/// refresh too and reach the same answer, so nothing there tells the two designs
/// apart. Here the fallback's refresh would succeed, and the refusal to attempt
/// it is the observable difference.
///
/// Why the alternative is refused rather than merely unimplemented: it would open
/// one identity's data when the user expected another's, and there is no
/// meaningful order among stored accounts to choose from.
#[wasm_bindgen_test]
async fn a_marker_whose_credential_is_gone_never_signs_the_other_account_in() {
    let storage = ReplicaStorage::install().await;
    storage.delete_db(STALE_DB).expect("clear an earlier index");
    let store = AccountStore::open(&storage.db_url(STALE_DB)).expect("open the account index");

    // One real account, signed in for real, so its cookie genuinely refreshes.
    let pending = match BrowserAuthenticator::new(config(), None)
        .acquire::<String>(&store)
        .await
        .expect("acquire")
    {
        Acquired::NeedLogin(pending) => pending,
        Acquired::Access(_) => panic!("an empty index cannot refresh"),
    };
    let (code, state) = walk_the_login(&pending.login_url, "present-user").await;
    let session = BrowserAuthenticator::new(config(), None)
        .complete::<String>(&pending, &code, &state, &store)
        .await
        .expect("complete the login");
    let present = encode_identity(&session.user_id).expect("encode the account key");

    // A second account this device once held and has since signed out of. The
    // marker still names it, which is what a sign-out of the last-used account
    // leaves behind.
    let departed = encode_identity(&"departed-account").expect("encode the departed account");
    store
        .remember(&departed)
        .expect("point the marker at the departed account");
    store
        .forget(&departed)
        .expect("sign the departed account out, keeping the marker");

    let boot = connetto_web::auth::remembered_account(&store)
        .expect("read the marker")
        .expect("a marker is set");
    assert_eq!(boot, departed, "the boot reads the departed account");
    match BrowserAuthenticator::new(config(), Some(boot))
        .acquire::<String>(&store)
        .await
        .expect("an absent account is not an error")
    {
        Acquired::NeedLogin(_) => {}
        Acquired::Access(session) => panic!(
            "the boot signed in as {} instead of asking for a login",
            session.user_id
        ),
    }

    // The live account was never presented, and its cookie is exactly as alive as
    // it was: presenting it would have refreshed it, so this succeeding on a
    // second pass is what a fallback implementation would have done first.
    match BrowserAuthenticator::new(config(), Some(present.clone()))
        .acquire::<String>(&store)
        .await
        .expect("address the present account directly")
    {
        Acquired::Access(_) => {}
        Acquired::NeedLogin(_) => panic!("the present account's cookie should still refresh"),
    }
}

/// R54: two real logins leave two accounts signed in at once, and addressing
/// either one afterwards resolves that one.
///
/// This is the property R42 claims and could not previously demonstrate through
/// any application path. Its store-level half is covered by
/// `every_stored_account_is_listed`, and `account_boot.rs` covers the boot
/// decision. What only this can carry is that two genuine logins resolve two
/// genuine identities, that each account keeps its own working cookie, and that
/// the two name different replicas, which is what keeps one account's rows out
/// of the other's file.
///
/// The second identity comes from submitting a different subject to the same
/// provider.
#[wasm_bindgen_test]
async fn two_real_logins_leave_two_accounts_signed_in_at_once() {
    let storage = ReplicaStorage::install().await;
    storage
        .delete_db(TWO_ACCOUNT_DB)
        .expect("clear an earlier index");
    let store =
        AccountStore::open(&storage.db_url(TWO_ACCOUNT_DB)).expect("open the account index");

    // First person. Nothing is stored, so nothing is addressed.
    let first = login_as("alice", None, &store).await;
    let first_account = encode_identity(&first.user_id).expect("encode the first account");

    // Second person, added rather than switched to: no stored account is
    // addressed, so this reaches an interactive login instead of refreshing the
    // first person's cookie.
    let second = login_as("bob", None, &store).await;
    let second_account = encode_identity(&second.user_id).expect("encode the second account");

    assert_ne!(
        first.user_id, second.user_id,
        "the two subjects must resolve two different people, or this test proves nothing"
    );

    // Both signed in at once, which is the phase in one assertion.
    let listed = store.accounts().expect("list the accounts");
    assert!(
        listed.contains(&first_account) && listed.contains(&second_account),
        "both accounts are offered to a picker"
    );

    // The later login owns the cold-boot default.
    assert_eq!(
        connetto_web::auth::remembered_account(&store)
            .expect("read the marker")
            .as_deref(),
        Some(second_account.as_str()),
        "the last person to sign in is who a start with nobody named resumes"
    );

    // Each identity names its own replica, which is what keeps one account's rows
    // out of the other's file.
    let first_replica = replica_db_name(REPLICA_PREFIX, &first.user_id).expect("first replica");
    let second_replica = replica_db_name(REPLICA_PREFIX, &second.user_id).expect("second replica");
    assert_ne!(
        first_replica, second_replica,
        "two accounts cannot share one replica file"
    );

    // Switching back: addressing the first account refreshes it silently, with no
    // login and without becoming the other person. This is what a switch does once
    // the worker has been replaced, and it is the per-account cookie doing it:
    // adding the second person left the first one's cookie usable.
    let switched = match BrowserAuthenticator::new(config(), Some(first_account.clone()))
        .acquire::<String>(&store)
        .await
        .expect("acquire against the first account")
    {
        Acquired::Access(session) => session,
        Acquired::NeedLogin(_) => {
            panic!("a stored account must refresh silently, which is why a switch needs no login")
        }
    };
    assert_eq!(
        switched.user_id, first.user_id,
        "and it came back as the first person, not the last one to sign in"
    );
    assert_eq!(
        connetto_web::auth::remembered_account(&store)
            .expect("read the marker")
            .as_deref(),
        Some(first_account.as_str()),
        "so the marker now names the account that was switched to"
    );
}
