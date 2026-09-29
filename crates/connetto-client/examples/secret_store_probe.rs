//! Writes, then in a later run reads back, a replica key and a refresh token
//! through one Linux store, for R71's container and desktop custody runs.
//!
//! Usage: `secret_store_probe write|read key-file KEY_FILE STATE_DIR`,
//! `secret_store_probe write|read secret-service`, or
//! `secret_store_probe write|read detected`.

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    use anyhow::{Context as _, bail, ensure};
    use connetto_client::{
        KeyFile, KeyringKeyStore, KeyringStore, LinuxStore, provision_replica_key,
    };
    use connetto_core::traits::{RefreshTokenStore as _, ReplicaKeyStore as _};

    const SERVICE: &str = "connetto-r71-probe";
    const ACCOUNT: &str = "\"alice\"";
    const TOKEN: &str = "alice-refresh";

    let args: Vec<String> = std::env::args().collect();
    let (phase, store) = match args.as_slice() {
        [_, phase, kind, key, state] if kind == "key-file" => {
            (phase, Some(LinuxStore::KeyFile(KeyFile::new(key, state))))
        }
        [_, phase, kind] if kind == "secret-service" => (phase, Some(LinuxStore::SecretService)),
        [_, phase, kind] if kind == "detected" => (phase, None),
        _ => bail!(
            "usage: secret_store_probe write|read key-file KEY_FILE STATE_DIR | secret-service | detected"
        ),
    };
    let (tokens, keys) = match store {
        Some(store) => (
            KeyringStore::with_linux_store(SERVICE, store.clone()),
            KeyringKeyStore::with_linux_store(SERVICE, store),
        ),
        None => (KeyringStore::new(SERVICE), KeyringKeyStore::new(SERVICE)),
    };
    let backend = tokens.backend().await.context("opening the store")?;
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
    println!("{phase} ok through {backend:?}");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {}
