//! R42: which account a boot signs in as, and what it does when it cannot.
//!
//! The store-level property, that several accounts coexist and are listable, is
//! next door in `secret_stores.rs` through the shared exercise both targets run.
//! What this suite owes is the decision above it: the marker points at an index
//! row rather than merely naming a person, and a marker that no longer addresses
//! a resumable account asks for a login instead of signing somebody else in.
//!
//! No server is involved and none is needed. An acquisition with no index row to
//! address never reaches the network: it builds the login URL and returns
//! [`Acquired::NeedLogin`], which is exactly the path under test. The cookie
//! round trip is covered by `examples/wasm-smoke/tests/browser_auth.rs`.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_web::auth::{
    AccountStore, Acquired, BrowserAuthenticator, WorkerAuthConfig, remembered_account,
    remembered_identity,
};
use connetto_web::storage::ReplicaStorage;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The OPFS file this suite keeps its account index in, distinct from every
/// other suite's so a shared origin cannot cross them.
const ACCOUNT_DB: &str = "r42-account-boot.sqlite";

/// Unreachable on purpose. Nothing here may perform a request, so a test that
/// accidentally does fails on the connection rather than passing for the wrong
/// reason.
fn config() -> WorkerAuthConfig {
    WorkerAuthConfig::new(
        "http://127.0.0.1:1",
        "nobody",
        "http://127.0.0.1:1/callback",
    )
}

/// An account index of this suite's own, emptied first so a rerun in the same
/// origin is not reading an earlier one's rows.
async fn fresh_store() -> AccountStore {
    let storage = ReplicaStorage::install().await;
    storage
        .delete_db(ACCOUNT_DB)
        .expect("clear any earlier file");
    AccountStore::open(&storage.db_url(ACCOUNT_DB)).expect("open the account index")
}

/// What a login leaves behind, written the way the authenticator writes it: the
/// account listed, and the marker holding the same key.
fn sign_in(store: &AccountStore, user_id: &str) -> String {
    let account = connetto_client::encode_identity(&user_id).expect("encode the identity");
    store.remember(&account).expect("record the account");
    account
}

/// The marker addresses an index row, which is what makes a start with no
/// network possible: it is read before anything else and hands back a key that
/// addresses a resumable account.
#[wasm_bindgen_test]
async fn the_last_used_marker_addresses_the_account_it_names() {
    let store = fresh_store().await;
    let account = sign_in(&store, "alice");

    let remembered = remembered_account(&store)
        .expect("read the marker")
        .expect("a marker was written");
    assert_eq!(remembered, account, "the marker holds the account key");
    assert!(
        store.accounts().expect("list").contains(&account),
        "and the marker's key addresses a listed account, so a boot needs nothing else"
    );

    let typed: Option<String> = remembered_identity(&store).expect("decode the marker");
    assert_eq!(
        typed.as_deref(),
        Some("alice"),
        "the same record still reads back as the deployment's own id type"
    );
}

/// The last account to sign in wins the marker, which is the cold-boot default.
#[wasm_bindgen_test]
async fn the_marker_names_the_account_that_signed_in_last() {
    let store = fresh_store().await;
    let alice = sign_in(&store, "alice");
    let bob = sign_in(&store, "bob");

    assert_eq!(
        remembered_account(&store)
            .expect("read the marker")
            .as_deref(),
        Some(bob.as_str()),
        "the later sign-in is the one a start with nobody named resumes"
    );

    let listed = store.accounts().expect("list the accounts");
    assert!(
        listed.contains(&alice) && listed.contains(&bob),
        "both are offered to an application that wants to pick"
    );
}

/// Decision 4: a marker naming an account whose row is gone asks for a login,
/// and leaves the other stored account untouched.
///
/// **What this half does and does not settle.** With no server reachable, a
/// fallback that walked the remaining accounts would also end at
/// [`Acquired::NeedLogin`] offline, so this cannot tell the two apart on its
/// own. What it does pin is that the absent account is not an error, that no
/// request is attempted for it, and that nothing else in the index moves.
/// `examples/wasm-smoke/tests/browser_auth.rs` carries the half that excludes
/// the fallback, against a real auth stack where a fallback refresh would
/// succeed.
#[wasm_bindgen_test]
async fn a_marker_whose_account_is_gone_asks_for_a_login_and_adopts_nobody() {
    let store = fresh_store().await;
    let alice = sign_in(&store, "alice");
    let bob = sign_in(&store, "bob");

    // Bob signs out on this device. His row goes, the marker still names him,
    // and alice is still signed in and would be the tempting fallback.
    store.forget(&bob).expect("sign bob out");
    assert_eq!(
        remembered_account(&store)
            .expect("read the marker")
            .as_deref(),
        Some(bob.as_str()),
        "the marker is left naming him, which is the case under test"
    );

    let boot = remembered_account(&store).expect("read the marker");
    let acquired = BrowserAuthenticator::new(config(), boot)
        .acquire::<String>(&store)
        .await
        .expect("an absent account is not an error");
    assert!(
        matches!(acquired, Acquired::NeedLogin(_)),
        "a marker that addresses no index row asks for a login, without a request"
    );
    assert!(
        store.accounts().expect("list").contains(&alice),
        "and alice was neither signed in nor disturbed"
    );
}

/// A first run has no account to try, so it goes straight to a login rather
/// than addressing a literal that stands for nobody.
#[wasm_bindgen_test]
async fn a_first_run_names_no_account_and_asks_for_a_login() {
    let store = fresh_store().await;
    assert_eq!(
        remembered_account(&store).expect("read the marker"),
        None,
        "nothing was ever remembered"
    );
    assert!(
        store.accounts().expect("list the accounts").is_empty(),
        "and nothing is indexed, so a picker has nothing to offer"
    );

    let acquired = BrowserAuthenticator::new(config(), None)
        .acquire::<String>(&store)
        .await
        .expect("an empty index is not an error");
    assert!(
        matches!(acquired, Acquired::NeedLogin(_)),
        "a first run logs in"
    );
}

/// An index written by a build whose id type differs names an account this
/// build cannot decode. That is a login, not a boot failure: the row outlives
/// the boot, so an error here would refuse every start from then on.
#[wasm_bindgen_test]
async fn an_account_this_build_cannot_decode_asks_for_a_login() {
    let store = fresh_store().await;
    store.remember("42").expect("an integer-id build's account");

    match BrowserAuthenticator::new(config(), Some("42".to_owned()))
        .acquire::<String>(&store)
        .await
    {
        Ok(Acquired::NeedLogin(_)) => {}
        Ok(Acquired::Access(_)) => panic!("an undecodable account cannot resume"),
        Err(err) => panic!("an undecodable account must ask for a login, got {err}"),
    }
}
