//! The OS secret store behind [`KeyringStore`](crate::KeyringStore) and
//! [`KeyringKeyStore`](crate::KeyringKeyStore).

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use android::KeystorePrompt;
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;
#[cfg(any(
    test,
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "windows"
))]
mod gate;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::{HelloCancellation, HelloOwner, HelloWindow};

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
    /// The platform's biometric or passcode prompt over the gated secrets was
    /// dismissed or did not verify the user.
    #[error("the unlock prompt was dismissed")]
    PromptDismissed,
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

    /// The custody the secrets under this service carry.
    #[cfg_attr(
        not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        )),
        expect(
            clippy::unused_self,
            reason = "only the gated platforms read their service's gate"
        )
    )]
    pub(crate) fn protection(&self) -> connetto_core::custody::Custody {
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        ))]
        {
            gated::protection(&self.service)
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        )))]
        {
            connetto_core::custody::Custody::Unverified(connetto_core::custody::NoGate::Unsupported)
        }
    }

    /// Whether the platform started the gated store over since the last call,
    /// because the key sealing it was lost. Android and Windows lose one.
    #[cfg_attr(
        not(any(target_os = "android", target_os = "windows")),
        expect(
            clippy::unused_self,
            reason = "only Android and Windows lose a gated store's key"
        )
    )]
    pub(crate) fn take_lost(&self) -> bool {
        #[cfg(any(target_os = "android", target_os = "windows"))]
        {
            gated::take_lost(&self.service)
        }
        #[cfg(not(any(target_os = "android", target_os = "windows")))]
        {
            false
        }
    }

    /// The secret stored under `name`, or `None` when none was stored.
    #[cfg_attr(
        not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        )),
        expect(clippy::unused_async, reason = "only the Linux and gated stores await")
    )]
    pub(crate) async fn read(&self, name: &str) -> Result<Option<String>, ClientError> {
        #[cfg(target_os = "linux")]
        {
            self.store.read(&self.service, name).await
        }
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        ))]
        {
            let name = name.to_owned();
            gated::blocking(&self.service, move |gate| gate.read(&name)).await
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        )))]
        {
            platform::read(&self.service, name)
        }
    }

    /// Persist `secret` under `name`, replacing any prior one.
    #[cfg_attr(
        not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        )),
        expect(clippy::unused_async, reason = "only the Linux and gated stores await")
    )]
    pub(crate) async fn write(&self, name: &str, secret: &str) -> Result<(), ClientError> {
        #[cfg(target_os = "linux")]
        {
            self.store.write(&self.service, name, secret).await
        }
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        ))]
        {
            let (name, secret) = (name.to_owned(), secret.to_owned());
            gated::blocking(&self.service, move |gate| gate.write(&name, &secret)).await
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        )))]
        {
            platform::write(&self.service, name, secret)
        }
    }

    /// Remove the entry stored under `name`, if any.
    #[cfg_attr(
        not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        )),
        expect(clippy::unused_async, reason = "only the Linux and gated stores await")
    )]
    pub(crate) async fn clear(&self, name: &str) -> Result<(), ClientError> {
        #[cfg(target_os = "linux")]
        {
            self.store.clear(&self.service, name).await
        }
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        ))]
        {
            let name = name.to_owned();
            gated::blocking(&self.service, move |gate| gate.clear(&name)).await
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "windows"
        )))]
        {
            platform::clear(&self.service, name)
        }
    }
}

/// `keyring-core` entries through the process-wide platform store.
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "windows"
)))]
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

/// The process-wide gates over the platform keyring, one per service, since
/// the platform store is process-wide.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "windows"
))]
mod gated {
    use std::collections::HashMap;
    use std::sync::{Arc, LazyLock, Mutex, PoisonError};

    use connetto_core::custody::{Custody, NoGate};

    #[cfg(target_os = "android")]
    use super::android::AndroidBackend as Platform;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    use super::apple::AppleBackend as Platform;
    use super::gate::{KeyringMechanism, SecretGate};
    #[cfg(target_os = "windows")]
    use super::windows::WindowsBackend as Platform;
    use crate::ClientError;
    use crate::away::GateMechanism;

    type Gate = SecretGate<Platform>;

    static GATES: LazyLock<Mutex<HashMap<String, Arc<Gate>>>> = LazyLock::new(Mutex::default);

    fn gate(service: &str) -> Result<Arc<Gate>, ClientError> {
        let mut gates = GATES.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(gate) = gates.get(service) {
            return Ok(Arc::clone(gate));
        }
        let gate = Arc::new(SecretGate::new(service, Platform::new()?, true));
        gates.insert(service.to_owned(), Arc::clone(&gate));
        Ok(gate)
    }

    /// Run `op` on the service's gate off the async runtime, since a gated
    /// keychain call blocks while its sheet is up.
    pub(super) async fn blocking<R, F>(service: &str, op: F) -> Result<R, ClientError>
    where
        R: Send + 'static,
        F: FnOnce(&Gate) -> Result<R, ClientError> + Send + 'static,
    {
        let gate = gate(service)?;
        tokio::task::spawn_blocking(move || op(&gate))
            .await
            .map_err(|err| ClientError::Auth(format!("keychain task: {err}")))?
    }

    /// Give the service's gated store the prompt it opens through.
    #[cfg(target_os = "android")]
    pub(crate) fn set_prompt(
        service: &str,
        prompt: Arc<dyn super::KeystorePrompt>,
    ) -> Result<(), ClientError> {
        gate(service)?.backend().set_prompt(prompt);
        Ok(())
    }

    /// Give the service's gated store the window its prompt opens over.
    #[cfg(target_os = "windows")]
    pub(crate) fn set_owner(
        service: &str,
        owner: Arc<dyn super::HelloOwner>,
    ) -> Result<(), ClientError> {
        gate(service)?.backend().set_owner(owner);
        Ok(())
    }

    /// Whether the service's gated store was started over after its key was
    /// lost, reported once.
    #[cfg(any(target_os = "android", target_os = "windows"))]
    pub(crate) fn take_lost(service: &str) -> bool {
        gate(service).is_ok_and(|gate| gate.backend().take_lost())
    }

    /// The custody of the service's secrets.
    pub(super) fn protection(service: &str) -> Custody {
        gate(service).map_or(Custody::Unverified(NoGate::Unsupported), |gate| {
            gate.protection()
        })
    }

    /// Apply the application's gate setting and hand back the mechanism the
    /// client's re-check drives, when the secrets are gated.
    pub(crate) fn arm(
        service: &str,
        on: bool,
    ) -> Result<Option<Arc<dyn GateMechanism>>, ClientError> {
        let gate = gate(service)?;
        gate.configure(on);
        Ok(gate
            .is_gated()
            .then(|| Arc::new(KeyringMechanism::new(gate)) as Arc<dyn GateMechanism>))
    }
}

/// Apply the application's gate setting to `service`'s secrets and hand back
/// the mechanism the client's re-check drives, `None` where the platform has
/// no gate or the secrets are not gated.
///
/// # Errors
///
/// [`ClientError`] when the platform store cannot be opened.
#[cfg_attr(
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows"
    )),
    expect(
        clippy::unnecessary_wraps,
        reason = "only the gated platforms can fail to open the store"
    )
)]
pub(crate) fn arm_gate(
    service: &str,
    on: bool,
) -> Result<Option<std::sync::Arc<dyn crate::away::GateMechanism>>, ClientError> {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows"
    ))]
    {
        gated::arm(service, on)
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        target_os = "windows"
    )))]
    {
        let _ = (service, on);
        Ok(None)
    }
}

/// Give `service`'s Keystore-gated secrets the prompt they unlock through.
///
/// # Errors
///
/// [`ClientError`] when the platform store cannot be opened.
#[cfg(target_os = "android")]
pub(crate) fn set_keystore_prompt(
    service: &str,
    prompt: std::sync::Arc<dyn KeystorePrompt>,
) -> Result<(), ClientError> {
    gated::set_prompt(service, prompt)
}

/// Give `service`'s Hello-gated secrets the window their prompt opens over.
///
/// # Errors
///
/// [`ClientError`] when the platform store cannot be opened.
#[cfg(target_os = "windows")]
pub(crate) fn set_hello_owner(
    service: &str,
    owner: std::sync::Arc<dyn HelloOwner>,
) -> Result<(), ClientError> {
    gated::set_owner(service, owner)
}
