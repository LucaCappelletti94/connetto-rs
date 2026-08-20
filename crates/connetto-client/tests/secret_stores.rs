//! R41: the native half of the two secret-store seams.
//!
//! What this buys over the per-store suites next to it is the caller. Both
//! exercises are written in `connetto_core::test_support` against the traits
//! alone and know nothing about a keyring, an `IndexedDB` database, or an
//! encrypted `SQLite` file. `connetto-web`'s `secret_stores.rs` runs the same
//! two functions against the browser stores, so the seam is proven by one
//! caller working on both targets rather than by the rename.
#![cfg(feature = "native-auth")]

use connetto_client::{IDENTITY_RECORD, MemoryKeyStore, MemoryRefreshStore};
use connetto_core::test_support::{
    every_stored_account_is_listed, two_accounts_keep_their_own_key,
    two_accounts_keep_their_own_token,
};

#[test]
fn the_in_memory_refresh_store_keeps_two_accounts_apart() {
    two_accounts_keep_their_own_token(&MemoryRefreshStore::default(), "alice", "bob");
}

/// R42: the account list the picker is built on, against the enumerable store.
#[test]
fn the_in_memory_refresh_store_lists_every_account_it_holds() {
    every_stored_account_is_listed(
        &MemoryRefreshStore::default(),
        "alice",
        "bob",
        IDENTITY_RECORD,
    );
}

#[tokio::test]
async fn the_in_memory_key_store_keeps_two_accounts_apart() {
    two_accounts_keep_their_own_key(&MemoryKeyStore::default(), "alice", "bob").await;
}

/// The production stores use names unique to this process, so reruns do not collide.
#[test]
fn the_keyring_refresh_store_keeps_two_accounts_apart() {
    use connetto_client::KeyringStore;

    let service = format!("connetto-r41-refresh-{}", std::process::id());
    two_accounts_keep_their_own_token(&KeyringStore::new(service), "alice", "bob");
}

/// R42: the same property against the store that cannot be enumerated.
#[test]
fn the_keyring_refresh_store_lists_every_account_it_holds() {
    use connetto_client::KeyringStore;

    let service = format!("connetto-r42-refresh-{}", std::process::id());
    every_stored_account_is_listed(&KeyringStore::new(service), "alice", "bob", IDENTITY_RECORD);
}

#[tokio::test]
async fn the_keyring_key_store_keeps_two_accounts_apart() {
    use connetto_client::KeyringKeyStore;

    let service = format!("connetto-r41-keys-{}", std::process::id());
    two_accounts_keep_their_own_key(&KeyringKeyStore::new(service), "alice", "bob").await;
}
