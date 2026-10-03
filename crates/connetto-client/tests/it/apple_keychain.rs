//! R51 on a real Apple keychain, from a bare test binary.
//!
//! A test binary carries no `keychain-access-groups` entitlement, so the data
//! protection keychain refuses it. The secrets then stay ungated in the macOS
//! login keychain, and the custody says the gate is unsupported rather than
//! claiming one. The gate itself is proven on a device, where a person
//! approves the sheet.
//!
//! The login keychain is locked outside a desktop session, over SSH or on a
//! headless runner, so the test runs on request from a desktop terminal:
//! `cargo test -p connetto-client --features native-auth --test it apple_keychain -- --ignored`.

use connetto_client::{Custody, KeyringKeyStore, KeyringStore, NoGate};
use connetto_core::traits::{RefreshTokenStore as _, ReplicaKeyStore as _};

/// A service no other run shares, so a crashed run leaves nothing a later one reads.
fn service() -> String {
    format!("dev.connetto.test.r51.{}", std::process::id())
}

#[tokio::test]
#[ignore = "needs the login keychain a desktop session unlocks"]
async fn a_build_without_the_entitlement_keeps_its_secrets_and_reports_no_gate() {
    let service = service();
    let tokens = KeyringStore::new(service.clone());
    let keys = KeyringKeyStore::new(service);
    let key = connetto_core::test_support::replica_key();

    tokens
        .store("\"alice\"", "refresh")
        .await
        .expect("the token is kept");
    keys.store("replica", &key).await.expect("the key is kept");
    assert_eq!(
        tokens.load("\"alice\"").await.expect("read").as_deref(),
        Some("refresh")
    );
    assert_eq!(keys.load("replica").await.expect("read"), Some(key));
    assert_eq!(
        tokens.protection(),
        Custody::Unverified(NoGate::Unsupported)
    );
    assert_eq!(keys.protection(), Custody::Unverified(NoGate::Unsupported));

    tokens.clear("\"alice\"").await.expect("clear the token");
    keys.clear("replica").await.expect("clear the key");
    assert_eq!(tokens.load("\"alice\"").await.expect("read"), None);
    assert_eq!(keys.load("replica").await.expect("read"), None);
}
