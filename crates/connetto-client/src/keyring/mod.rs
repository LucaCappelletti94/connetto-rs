//! The OS secret store behind [`KeyringStore`](crate::KeyringStore) and
//! [`KeyringKeyStore`](crate::KeyringKeyStore).

#[cfg(target_os = "linux")]
mod linux;

use std::path::PathBuf;
use std::time::Duration;

#[cfg(target_os = "linux")]
pub use linux::{Backend, KeyFile, LinuxStore};

use crate::ClientError;

/// Why an OS secret store refused.
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    /// No durable store was reachable, and the application named none.
    #[error("no durable secret store is reachable, probed {probed}")]
    NoStore {
        /// Every store detection tried, in order.
        probed: &'static str,
    },
    /// The desktop's unlock or create dialog was dismissed, or could not be shown.
    #[error("the desktop keyring stayed locked: the dialog was dismissed or could not be shown")]
    Dismissed,
    /// Nobody answered the desktop's dialog, or the Secret portal, within the bound.
    #[error("the secret store did not answer within {0:?}")]
    TimedOut(Duration),
    /// A wrap key does not hold exactly 32 bytes.
    #[error("the wrap key {path} holds {len} bytes, not 32")]
    WrapKeyLength {
        /// Where the key was read from.
        path: PathBuf,
        /// How many bytes it held.
        len: usize,
    },
    /// A sealed record opens under no wrap key the store holds.
    #[error("the sealed record {record} opens under no wrap key this store holds")]
    Unsealable {
        /// The record's file name.
        record: String,
    },
    /// A stored secret is not the base64 text connetto writes.
    #[error("a stored secret is not base64 text")]
    Encoding,
    /// The backing store failed.
    #[error("{0}")]
    Backend(String),
}

impl From<SecretStoreError> for ClientError {
    fn from(err: SecretStoreError) -> Self {
        Self::SecretStore(err)
    }
}

/// One service's entries in the OS secret store, one per name.
pub(crate) struct Keyring {
    service: String,
    #[cfg(target_os = "linux")]
    store: linux::Store,
}

impl Keyring {
    /// The detected store.
    pub(crate) fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            #[cfg(target_os = "linux")]
            store: linux::Store::detect(),
        }
    }

    /// The store the application named.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_linux_store(service: impl Into<String>, store: LinuxStore) -> Self {
        Self {
            service: service.into(),
            store: linux::Store::named(store),
        }
    }

    /// Which Linux store holds these secrets.
    #[cfg(target_os = "linux")]
    pub(crate) async fn backend(&self) -> Result<Backend, ClientError> {
        self.store.backend().await
    }

    /// The secret stored under `name`, or `None` when none was stored.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(clippy::unused_async, reason = "only the Linux stores await")
    )]
    pub(crate) async fn read(&self, name: &str) -> Result<Option<String>, ClientError> {
        #[cfg(target_os = "linux")]
        {
            self.store.read(&self.service, name).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            platform::read(&self.service, name)
        }
    }

    /// Persist `secret` under `name`, replacing any prior one.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(clippy::unused_async, reason = "only the Linux stores await")
    )]
    pub(crate) async fn write(&self, name: &str, secret: &str) -> Result<(), ClientError> {
        #[cfg(target_os = "linux")]
        {
            self.store.write(&self.service, name, secret).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            platform::write(&self.service, name, secret)
        }
    }

    /// Remove the entry stored under `name`, if any.
    #[cfg_attr(
        not(target_os = "linux"),
        expect(clippy::unused_async, reason = "only the Linux stores await")
    )]
    pub(crate) async fn clear(&self, name: &str) -> Result<(), ClientError> {
        #[cfg(target_os = "linux")]
        {
            self.store.clear(&self.service, name).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            platform::clear(&self.service, name)
        }
    }
}

/// `keyring-core` entries through the process-wide platform store.
#[cfg(not(target_os = "linux"))]
mod platform {
    use std::sync::{Arc, LazyLock};

    use crate::ClientError;

    static STORE: LazyLock<Result<(), Arc<str>>> =
        LazyLock::new(|| install_store().map_err(|err| Arc::<str>::from(err.to_string())));

    fn ensure_store() -> Result<(), ClientError> {
        STORE
            .as_ref()
            .copied()
            .map_err(|err| ClientError::Auth(format!("keyring setup: {err}")))
    }

    #[cfg(target_os = "macos")]
    fn install_store() -> keyring_core::Result<()> {
        keyring_core::set_default_store(apple_native_keyring_store::keychain::Store::new()?);
        Ok(())
    }

    #[cfg(target_os = "ios")]
    fn install_store() -> keyring_core::Result<()> {
        keyring_core::set_default_store(apple_native_keyring_store::protected::Store::new()?);
        Ok(())
    }

    #[cfg(target_os = "android")]
    fn install_store() -> keyring_core::Result<()> {
        keyring_core::set_default_store(android_native_keyring_store::Store::new()?);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn install_store() -> keyring_core::Result<()> {
        keyring_core::set_default_store(windows_native_keyring_store::Store::new()?);
        Ok(())
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "macos",
        target_os = "windows"
    )))]
    fn install_store() -> keyring_core::Result<()> {
        Err(keyring_core::Error::Invalid(
            "platform".to_owned(),
            "native auth has no keyring store for this platform".to_owned(),
        ))
    }

    fn entry(service: &str, name: &str) -> Result<keyring_core::Entry, ClientError> {
        ensure_store()?;
        keyring_core::Entry::new(service, name)
            .map_err(|err| ClientError::Auth(format!("keyring open: {err}")))
    }

    pub(super) fn read(service: &str, name: &str) -> Result<Option<String>, ClientError> {
        match entry(service, name)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(err) => Err(ClientError::Auth(format!("keyring load: {err}"))),
        }
    }

    pub(super) fn write(service: &str, name: &str, secret: &str) -> Result<(), ClientError> {
        entry(service, name)?
            .set_password(secret)
            .map_err(|err| ClientError::Auth(format!("keyring store: {err}")))
    }

    pub(super) fn clear(service: &str, name: &str) -> Result<(), ClientError> {
        match entry(service, name)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => Err(ClientError::Auth(format!("keyring clear: {err}"))),
        }
    }
}
