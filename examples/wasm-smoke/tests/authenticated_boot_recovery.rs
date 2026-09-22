//! Phase E4.2: the startup path that resumes from nothing.
//!
//! The account index is a hint, not a credential. When the cookie behind its
//! marker is gone, cleared by the browser, revoked server-side, or never set on
//! this device, the startup treats the marker as spent rather than as a fatal
//! error: it logs in afresh and rewrites the index. Nothing in the worker can
//! tell a spent marker from a bogus one, so a planted marker exercises exactly
//! the case the recovery exists for.

#![cfg(target_arch = "wasm32")]

mod common;

use common::{ACCOUNT_DB, auth_config, play_the_tab, worker_config};
use connetto_web::auth::AccountStore;
use connetto_web::storage::ReplicaStorage;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// Account key used to plant the marker: JSON form of a `String` id with no
/// cookie anywhere near it.
const PLANTED: &str = "\"tester\"";

/// A marker whose cookie cannot refresh is replaced by a fresh login, not a
/// boot failure.
#[wasm_bindgen_test]
async fn a_marker_that_cannot_refresh_is_replaced_by_a_fresh_login() {
    let storage = ReplicaStorage::install().await;
    storage
        .delete_db(ACCOUNT_DB)
        .expect("clear an earlier account index");
    let db_url = storage.db_url(ACCOUNT_DB);

    // Plant an index whose marker names an account this browser holds no cookie
    // for. The silent refresh it addresses cannot succeed, which is the state
    // this recovery exists for.
    AccountStore::open(&db_url)
        .expect("open the account index")
        .remember(PLANTED)
        .expect("plant the marker");

    // The startup meets that marker and logs in through the tab.
    let logins_served = play_the_tab();
    connetto_web::workers::boot_db_worker::<String>(&worker_config(Some(auth_config())))
        .await
        .expect("the startup recovers from a marker with no cookie");
    assert_eq!(
        logins_served.get(),
        1,
        "the spent marker forced exactly one fresh login"
    );

    // The index the startup left behind names the account from that login, so
    // the next startup resumes it.
    let recovered = AccountStore::open(&db_url).expect("reopen the account index");
    let account = connetto_web::auth::remembered_account(&recovered)
        .expect("read account")
        .expect("the fresh login stored an account marker");
    assert_ne!(
        account, PLANTED,
        "the marker now names the account that actually logged in"
    );
    assert!(
        recovered.accounts().expect("list").contains(&account),
        "and the account is indexed"
    );
}
