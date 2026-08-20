//! R42: which account a boot signs in as, and what it does when it cannot.
//!
//! The store-level property, that several accounts coexist and are listable, is
//! next door in `secret_stores.rs` through the shared exercise both targets run.
//! What this suite owes is the decision above it: the marker points at a row
//! rather than merely naming a person, and a marker that no longer addresses a
//! credential asks for a login instead of signing somebody else in.
//!
//! No server is involved and none is needed. An acquisition with nothing to
//! present never reaches the network: it builds the login URL and returns
//! [`Acquired::NeedLogin`], which is exactly the path under test. A test that
//! seeded a usable credential would have to reach a real auth stack, and that
//! round trip is already covered by `examples/wasm-smoke/tests/browser_auth.rs`.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use connetto_core::traits::RefreshTokenStore;
use connetto_web::auth::{
    Acquired, BrowserAuthenticator, IdbKeyStore, RefreshStore, WorkerAuthConfig,
    remembered_account, remembered_identity,
};
use connetto_web::storage::{ReplicaStorage, device_key};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The OPFS file this suite keeps its refresh store in, distinct from every
/// other suite's so a shared origin cannot cross them.
const REFRESH_DB: &str = "r42-account-boot.sqlite";

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

/// A refresh store of this suite's own, emptied first so a rerun in the same
/// origin is not reading an earlier one's rows.
async fn fresh_store() -> RefreshStore {
    let storage = ReplicaStorage::install().await;
    let keys = IdbKeyStore::open().await.expect("open the key store");
    storage
        .delete_db(REFRESH_DB)
        .expect("clear any earlier file");
    let device = device_key(&keys).await.expect("mint the device key");
    RefreshStore::open(&storage.db_url(REFRESH_DB), &device).expect("open the refresh store")
}

/// What a login leaves behind, written the way the authenticator writes it: the
/// credential under the encoded identity, and the marker holding that same value.
fn sign_in(store: &RefreshStore, user_id: &str, token: &str) -> String {
    let account = connetto_client::encode_identity(&user_id).expect("encode the identity");
    store.store(&account, token).expect("store the credential");
    store
        .store(connetto_client::IDENTITY_RECORD, &account)
        .expect("write the marker");
    account
}

/// The marker addresses a row, which is what makes a start with no network
/// possible: it is read before anything else and hands back a key that reaches a
/// credential.
///
/// One value serving both jobs is the property here. If the marker held a display
/// name, or the row were keyed by the hashed replica name, this would still pass
/// its first assertion and fail its second.
#[wasm_bindgen_test]
async fn the_last_used_marker_addresses_the_credential_row_it_names() {
    let store = fresh_store().await;
    let account = sign_in(&store, "alice", "alice-refresh");

    let remembered = remembered_account(&store)
        .expect("read the marker")
        .expect("a marker was written");
    assert_eq!(remembered, account, "the marker holds the account key");
    assert_eq!(
        store
            .load(&remembered)
            .expect("load by the marker")
            .as_deref(),
        Some("alice-refresh"),
        "and that key reaches the credential, so a boot needs nothing else"
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
    let alice = sign_in(&store, "alice", "alice-refresh");
    let bob = sign_in(&store, "bob", "bob-refresh");

    assert_eq!(
        remembered_account(&store)
            .expect("read the marker")
            .as_deref(),
        Some(bob.as_str()),
        "the later sign-in is the one a start with nobody named resumes"
    );
    assert_eq!(
        store.load(&alice).expect("load alice").as_deref(),
        Some("alice-refresh"),
        "and the earlier account is still signed in, which is the whole point"
    );

    let listed = store.accounts().expect("list the accounts");
    assert!(
        listed.contains(&alice) && listed.contains(&bob),
        "both are offered to an application that wants to pick, got {listed:?}"
    );
}

/// Decision 4: a marker naming an account whose credential is gone asks for a
/// login, and leaves the other stored account untouched.
///
/// **What this half does and does not settle.** With no server reachable, a
/// fallback that walked the remaining accounts would also end at
/// [`Acquired::NeedLogin`], because its refresh could not succeed either, so this
/// cannot tell the two apart on its own. What it does pin is that the absent
/// credential is not an error and that nothing else in the store moves.
/// `examples/wasm-smoke/tests/browser_auth.rs` carries the half that excludes the
/// fallback, against a real auth stack where a fallback refresh would succeed and
/// rotate the other account's token.
#[wasm_bindgen_test]
async fn a_marker_whose_credential_is_gone_asks_for_a_login_and_adopts_nobody() {
    let store = fresh_store().await;
    let alice = sign_in(&store, "alice", "alice-refresh");
    let bob = sign_in(&store, "bob", "bob-refresh");

    // Bob signs out on this device. His row goes, the marker still names him, and
    // alice is still signed in and would be the tempting fallback.
    store.clear(&bob).expect("sign bob out");
    assert_eq!(
        remembered_account(&store)
            .expect("read the marker")
            .as_deref(),
        Some(bob.as_str()),
        "the marker is left naming him, which is the case under test"
    );

    let boot = remembered_account(&store).expect("read the marker");
    let acquired = BrowserAuthenticator::new(config(), boot)
        .acquire::<String, _>(&store)
        .await
        .expect("an absent credential is not an error");
    assert!(
        matches!(acquired, Acquired::NeedLogin(_)),
        "a marker that addresses nothing asks for a login"
    );
    assert_eq!(
        store.load(&alice).expect("load alice").as_deref(),
        Some("alice-refresh"),
        "and alice was neither signed in nor disturbed"
    );
}

/// A first run has no account to try, so it goes straight to a login rather than
/// addressing a literal that stands for nobody.
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
        "and nothing is stored, so a picker has nothing to offer"
    );

    let acquired = BrowserAuthenticator::new(config(), None)
        .acquire::<String, _>(&store)
        .await
        .expect("an empty store is not an error");
    assert!(
        matches!(acquired, Acquired::NeedLogin(_)),
        "a first run logs in"
    );
}
