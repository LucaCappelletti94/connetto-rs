//! Writes, then in a later run reads back, a replica key and a refresh token
//! through a named wrap-key file, for R71's container custody test.
//!
//! Usage: `secret_store_probe write|read KEY_FILE STATE_DIR`.

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    use anyhow::{Context as _, bail, ensure};
    use connetto_client::{
        KeyFile, KeyringKeyStore, KeyringStore, LinuxStore, provision_replica_key,
    };
    use connetto_core::traits::{RefreshTokenStore as _, ReplicaKeyStore as _};

    const SERVICE: &str = "connetto-r71-container";
    const ACCOUNT: &str = "\"alice\"";
    const TOKEN: &str = "alice-refresh";

    let args: Vec<String> = std::env::args().collect();
    let [_, phase, key, state] = args.as_slice() else {
        bail!("usage: secret_store_probe write|read KEY_FILE STATE_DIR");
    };
    let store = LinuxStore::KeyFile(KeyFile::new(key, state));
    let tokens = KeyringStore::with_linux_store(SERVICE, store.clone());
    let keys = KeyringKeyStore::with_linux_store(SERVICE, store);
    match phase.as_str() {
        "write" => {
            provision_replica_key(&keys, "replica")
                .await
                .context("provisioning the key")?;
            tokens
                .store(ACCOUNT, TOKEN)
                .await
                .context("storing the token")?;
        }
        "read" => {
            let backend = tokens.backend().await.context("opening the store")?;
            ensure!(
                backend.survives_reboot(),
                "{backend:?} does not survive a reboot"
            );
            ensure!(
                keys.load("replica")
                    .await
                    .context("loading the key")?
                    .is_some(),
                "the replica key is gone"
            );
            let token = tokens.load(ACCOUNT).await.context("loading the token")?;
            ensure!(
                token.as_deref() == Some(TOKEN),
                "the token read back as {token:?}"
            );
        }
        other => bail!("unknown phase {other}"),
    }
    println!("{phase} ok");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
