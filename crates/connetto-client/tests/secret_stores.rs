//! R41: the native half of the two secret-store seams.
//!
//! What this buys over the per-store suites next to it is the caller. Both
//! exercises are written in `connetto_core::test_support` against the traits
//! alone and know nothing about a keyring, an `IndexedDB` database, or an
//! encrypted `SQLite` file. `connetto-web`'s `secret_stores.rs` runs the same
//! two functions against the browser stores, so the seam is proven by one
//! caller working on both targets rather than by the rename.
#![cfg(feature = "native-auth")]

use connetto_client::{MemoryKeyStore, MemoryRefreshStore};
use connetto_core::test_support::{
    two_accounts_keep_their_own_key, two_accounts_keep_their_own_token,
};

#[test]
fn the_in_memory_refresh_store_keeps_two_accounts_apart() {
    two_accounts_keep_their_own_token(&MemoryRefreshStore::default(), "alice", "bob");
}

#[tokio::test]
async fn the_in_memory_key_store_keeps_two_accounts_apart() {
    two_accounts_keep_their_own_key(&MemoryKeyStore::default(), "alice", "bob").await;
}

/// The production stores, against the real OS keyring rather than a fake.
///
/// One service, one record per account, and the record names are unique to this
/// test so a rerun neither collides with a developer's own entries nor with a
/// concurrent run of the suite. Ignored by default because it writes to the
/// machine's secure storage, which a headless or locked session may refuse.
#[test]
#[ignore = "writes to the OS keyring; run explicitly"]
fn the_keyring_refresh_store_keeps_two_accounts_apart() {
    use connetto_client::KeyringStore;

    let service = format!("connetto-r41-refresh-{}", std::process::id());
    two_accounts_keep_their_own_token(&KeyringStore::new(service), "alice", "bob");
}

#[tokio::test]
#[ignore = "writes to the OS keyring; run explicitly"]
async fn the_keyring_key_store_keeps_two_accounts_apart() {
    use connetto_client::KeyringKeyStore;

    let service = format!("connetto-r41-keys-{}", std::process::id());
    two_accounts_keep_their_own_key(&KeyringKeyStore::new(service), "alice", "bob").await;
}
