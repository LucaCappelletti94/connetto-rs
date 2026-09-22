//! The browser store seams.
//!
//! The replica-key half runs the shared exercise from
//! `connetto_core::test_support`, the same one `connetto-client` runs against the
//! native keyring, so the trait seam is proven on both targets. The credential
//! half left with R90: the browser holds no credential store, only the plain
//! account index below, which is checked directly.

use connetto_client::cipher::{ReplicaKey, cipher_url, unlock};
use connetto_core::test_support::two_accounts_keep_their_own_key;
use connetto_web::auth::{AccountStore, AuthError, IdbKeyStore};
use connetto_web::storage::ReplicaStorage;
use diesel::Connection;
use diesel::SqliteConnection;
use diesel::connection::SimpleConnection;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_dedicated_worker);

/// The OPFS file the account-list exercise uses.
const ACCOUNTS_DB: &str = "r42-account-list.sqlite";

#[wasm_bindgen_test]
async fn the_browser_key_store_keeps_two_accounts_apart() {
    let store = IdbKeyStore::open().await.expect("open the key store");
    two_accounts_keep_their_own_key(&store, "r41-alice", "r41-bob").await;
}

/// R42: the account list an application's picker is built on, enumerated from
/// the index rows with the reserved marker excluded.
#[wasm_bindgen_test]
async fn the_account_index_lists_every_account_it_holds() {
    let storage = ReplicaStorage::install().await;
    storage
        .delete_db(ACCOUNTS_DB)
        .expect("clear any earlier file");
    let store = AccountStore::open(&storage.db_url(ACCOUNTS_DB)).expect("open the account index");

    let alice = connetto_client::encode_identity(&"r42-alice").expect("encode");
    let bob = connetto_client::encode_identity(&"r42-bob").expect("encode");
    store.remember(&alice).expect("list alice");
    store.remember(&bob).expect("list bob");

    let listed = store.accounts().expect("list the accounts");
    assert!(
        listed.contains(&alice) && listed.contains(&bob),
        "both accounts are offered to a picker"
    );
    assert!(
        !listed
            .iter()
            .any(|name| connetto_client::is_reserved_record(name)),
        "the last-used marker is never offered as somebody to sign in as"
    );

    store.forget(&bob).expect("sign bob out");
    let after = store.accounts().expect("list again");
    assert!(
        after.contains(&alice) && !after.contains(&bob),
        "signing one account out leaves the other listed"
    );
}

/// The OPFS file left in the pre-R90 encrypted shape.
const STALE_DB: &str = "r90-stale-encrypted.sqlite";

/// R90's recovery keys on the account-index open failing outright. SQLite
/// surfaces an unreadable file on the first page read rather than on
/// establish, so a keyed leftover must be refused by `open` itself and not
/// one call later, where nothing discards it.
#[wasm_bindgen_test]
async fn a_stale_encrypted_file_fails_where_the_recovery_lives() {
    let storage = ReplicaStorage::install().await;
    storage.delete_db(STALE_DB).expect("clear any earlier file");
    {
        let mut conn = SqliteConnection::establish(&cipher_url(STALE_DB, "opfs-sahpool"))
            .expect("open the stale store");
        unlock(&mut conn, &ReplicaKey::from_bytes([0x5a; ReplicaKey::LEN]))
            .expect("apply the old device key");
        conn.batch_execute(
            "CREATE TABLE connetto_refresh (token TEXT PRIMARY KEY NOT NULL, account TEXT NOT NULL)",
        )
        .expect("write the pre-R90 shape");
    }
    let outcome = AccountStore::open(&storage.db_url(STALE_DB));
    storage.delete_db(STALE_DB).expect("clean up");
    match outcome {
        Err(AuthError::Store(_)) => {}
        Err(other) => panic!("the boot recovery matches on Store, got {other:?}"),
        Ok(_) => panic!("a keyed file opened as the plain account index"),
    }
}
