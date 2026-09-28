//! R41: the native half of the two secret-store seams.
//!
//! What this buys over the per-store suites next to it is the caller. Both
//! exercises are written in `connetto_core::test_support` against the traits
//! alone and know nothing about a keyring.

use connetto_client::{IDENTITY_RECORD, MemoryKeyStore, MemoryRefreshStore};
use connetto_core::test_support::{
    every_stored_account_is_listed, two_accounts_keep_their_own_key,
    two_accounts_keep_their_own_token,
};

#[tokio::test]
async fn the_in_memory_refresh_store_keeps_two_accounts_apart() {
    two_accounts_keep_their_own_token(&MemoryRefreshStore::default(), "alice", "bob").await;
}

/// R42: the account list the picker is built on, against the enumerable store.
#[tokio::test]
async fn the_in_memory_refresh_store_lists_every_account_it_holds() {
    every_stored_account_is_listed(
        &MemoryRefreshStore::default(),
        "alice",
        "bob",
        IDENTITY_RECORD,
    )
    .await;
}

#[tokio::test]
async fn the_remembered_account_is_the_identity_record() {
    use connetto_client::auth::remembered_account;
    use connetto_core::traits::RefreshTokenStore as _;
    let store = MemoryRefreshStore::default();
    assert_eq!(remembered_account(&store).await.expect("read"), None);
    store
        .store(IDENTITY_RECORD, "\"alice\"")
        .await
        .expect("remember alice");
    assert_eq!(
        remembered_account(&store).await.expect("read").as_deref(),
        Some("\"alice\"")
    );
}

#[tokio::test]
async fn the_in_memory_key_store_keeps_two_accounts_apart() {
    two_accounts_keep_their_own_key(&MemoryKeyStore::default(), "alice", "bob").await;
}

/// The Linux keyring stores, each named explicitly so no test writes into the
/// desktop's own keyring (R71 decision 7).
#[cfg(target_os = "linux")]
mod linux {
    use connetto_client::{
        Backend, IDENTITY_RECORD, KeyFile, KeyringKeyStore, KeyringStore, LinuxStore,
    };
    use connetto_core::test_support::{
        every_stored_account_is_listed, two_accounts_keep_their_own_key,
        two_accounts_keep_their_own_token,
    };

    /// Every durable store and keyutils, each under a service unique to this process.
    fn stores(dir: &std::path::Path) -> Vec<(&'static str, LinuxStore)> {
        let key = dir.join("wrap.key");
        std::fs::write(&key, [3_u8; 32]).expect("write a wrap key");
        vec![
            ("keyutils", LinuxStore::Keyutils),
            (
                "key-file",
                LinuxStore::KeyFile(KeyFile::new(key, dir.join("state"))),
            ),
        ]
    }

    #[tokio::test]
    async fn every_store_keeps_two_accounts_apart_and_lists_them() {
        let _keyring = connetto_test_harness::isolated_session_keyring();
        let dir = tempfile::tempdir().expect("tempdir");
        for (label, store) in stores(dir.path()) {
            let service = format!("connetto-r71-{label}-{}", std::process::id());
            let tokens = KeyringStore::with_linux_store(&service, store.clone());
            two_accounts_keep_their_own_token(&tokens, "alice", "bob").await;
            every_stored_account_is_listed(&tokens, "alice", "bob", IDENTITY_RECORD).await;
            let keys = KeyringKeyStore::with_linux_store(&service, store);
            two_accounts_keep_their_own_key(&keys, "alice", "bob").await;
        }
    }

    #[tokio::test]
    async fn the_report_names_the_store_and_whether_it_survives_a_reboot() {
        let _keyring = connetto_test_harness::isolated_session_keyring();
        let dir = tempfile::tempdir().expect("tempdir");
        let mut reports = Vec::new();
        for (label, store) in stores(dir.path()) {
            let tokens = KeyringStore::with_linux_store(
                format!("connetto-r71-report-{label}"),
                store.clone(),
            );
            let report = tokens.backend().await.expect("the store opens");
            let keys =
                KeyringKeyStore::with_linux_store(format!("connetto-r71-report-{label}"), store);
            assert_eq!(
                keys.backend().await.expect("the key store opens"),
                report,
                "both stores report alike"
            );
            reports.push(report);
        }
        assert_eq!(
            reports,
            [
                Backend::Keyutils,
                Backend::KeyFile {
                    previous_key_needed: false
                }
            ]
        );
        assert!(
            !reports[0].survives_reboot(),
            "keyutils says it is lost at reboot"
        );
        assert!(reports[1].survives_reboot());
    }

    #[tokio::test]
    async fn a_named_key_file_of_the_wrong_length_refuses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = dir.path().join("short.key");
        std::fs::write(&key, [3_u8; 16]).expect("write a short key");
        let tokens = KeyringStore::with_linux_store(
            "connetto-r71-short",
            LinuxStore::KeyFile(KeyFile::new(key, dir.path().join("state"))),
        );
        let err = tokens.backend().await.expect_err("a 16-byte key refuses");
        assert!(
            matches!(
                err,
                connetto_client::ClientError::SecretStore(
                    connetto_client::SecretStoreError::WrapKeyLength { len: 16, .. }
                )
            ),
            "got {err}"
        );
    }
}
