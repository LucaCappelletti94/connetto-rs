//! The Linux secret stores (R71): the Secret Service, libsecret's sandbox
//! keyring, sealed files under a systemd credential or a named key file, and
//! keyutils.

mod sandbox;
mod sealed;
mod secret_service;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use keyring_core::api::CredentialStoreApi as _;
use zeroize::Zeroizing;

use super::SecretStoreError;
use crate::ClientError;

/// The systemd credential holding the current wrap key.
const CREDENTIAL: &str = "connetto.wrap-key";
/// The systemd credential holding the wrap key being rotated out.
const PREVIOUS_CREDENTIAL: &str = "connetto.wrap-key.previous";
/// The directory under a state directory that holds the sealed records.
const SEALED_DIR: &str = "connetto-secrets";
/// What detection tries, in order.
const PROBED: &str =
    "the sandbox keyring, the connetto.wrap-key systemd credential and the Secret Service";

/// A Linux secret store an application names instead of detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxStore {
    /// The desktop session's Secret Service, in its default collection.
    SecretService,
    /// libsecret's sandbox keyring, opened with the Secret portal's secret.
    SandboxKeyring,
    /// Files sealed under the unit's `connetto.wrap-key` systemd credential.
    SystemdCredential,
    /// Files sealed under a wrap key the application names.
    KeyFile(KeyFile),
    /// The kernel session keyring, which a reboot empties.
    Keyutils,
}

/// A wrap-key file and the state directory its sealed records live in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFile {
    key: PathBuf,
    previous: Option<PathBuf>,
    state: PathBuf,
}

impl KeyFile {
    /// Records under `state`, sealed with the 32-byte key in the file `key`.
    #[must_use]
    pub fn new(key: impl Into<PathBuf>, state: impl Into<PathBuf>) -> Self {
        Self {
            key: key.into(),
            previous: None,
            state: state.into(),
        }
    }

    /// Reseal every record still under the key in the file `previous`.
    #[must_use]
    pub fn with_previous(mut self, previous: impl Into<PathBuf>) -> Self {
        self.previous = Some(previous.into());
        self
    }
}

/// Which Linux store holds a store's secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// The Secret Service's default collection.
    SecretService,
    /// libsecret's sandbox keyring.
    SandboxKeyring,
    /// Sealed files under the `connetto.wrap-key` systemd credential.
    SystemdCredential {
        /// Whether a record still opens only under the previous wrap key.
        previous_key_needed: bool,
    },
    /// Sealed files under an application-named key file.
    KeyFile {
        /// Whether a record still opens only under the previous wrap key.
        previous_key_needed: bool,
    },
    /// The kernel session keyring.
    Keyutils,
}

impl Backend {
    /// Whether the secrets survive a reboot.
    #[must_use]
    pub const fn survives_reboot(self) -> bool {
        !matches!(self, Self::Keyutils)
    }
}

/// The process facts detection reads.
struct Environment {
    sandboxed: bool,
    credentials: Option<PathBuf>,
    state: Option<PathBuf>,
}

impl Environment {
    fn of_process() -> Self {
        Self {
            sandboxed: oo7::ashpd::is_sandboxed(),
            credentials: std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from),
            // systemd joins several state directories with ':' and the first is the unit's own.
            state: std::env::var_os("STATE_DIRECTORY").and_then(|dirs| {
                dirs.to_str()
                    .and_then(|dirs| dirs.split(':').next())
                    .map(PathBuf::from)
            }),
        }
    }
}

/// A store resolved at first use, since reaching one awaits.
pub(crate) struct Store {
    named: Option<LinuxStore>,
    opened: tokio::sync::OnceCell<Opened>,
}

enum Opened {
    SecretService(secret_service::SecretService),
    Sandbox(sandbox::Sandbox),
    Sealed {
        files: sealed::Sealed,
        credential: bool,
    },
    Keyutils(Arc<linux_keyutils_keyring_store::Store>),
}

impl Store {
    pub(crate) fn detect() -> Self {
        Self {
            named: None,
            opened: tokio::sync::OnceCell::new(),
        }
    }

    pub(crate) fn named(store: LinuxStore) -> Self {
        Self {
            named: Some(store),
            opened: tokio::sync::OnceCell::new(),
        }
    }

    async fn opened(&self) -> Result<&Opened, ClientError> {
        self.opened
            .get_or_try_init(|| async {
                let env = Environment::of_process();
                match &self.named {
                    Some(store) => open_named(store, &env).await,
                    None => detect(&env, secret_service::session_bus().await).await,
                }
            })
            .await
    }

    pub(crate) async fn backend(&self) -> Result<Backend, ClientError> {
        Ok(match self.opened().await? {
            Opened::SecretService(_) => Backend::SecretService,
            Opened::Sandbox(_) => Backend::SandboxKeyring,
            Opened::Sealed {
                files,
                credential: true,
            } => Backend::SystemdCredential {
                previous_key_needed: files.previous_key_needed(),
            },
            Opened::Sealed {
                files,
                credential: false,
            } => Backend::KeyFile {
                previous_key_needed: files.previous_key_needed(),
            },
            Opened::Keyutils(_) => Backend::Keyutils,
        })
    }

    pub(crate) async fn read(
        &self,
        service: &str,
        name: &str,
    ) -> Result<Option<String>, ClientError> {
        match self.opened().await? {
            Opened::SecretService(store) => store.read(service, name).await,
            Opened::Sandbox(store) => store.read(service, name).await,
            Opened::Sealed { files, .. } => files
                .read(service, name)?
                .map(|mut bytes| utf8(core::mem::take(&mut *bytes)))
                .transpose(),
            Opened::Keyutils(store) => match keyutils_entry(store, service, name)?.get_password() {
                Ok(secret) => Ok(Some(secret)),
                Err(keyring_core::Error::NoEntry) => Ok(None),
                Err(err) => Err(backend_error("keyutils load", err)),
            },
        }
    }

    pub(crate) async fn write(
        &self,
        service: &str,
        name: &str,
        secret: &str,
    ) -> Result<(), ClientError> {
        match self.opened().await? {
            Opened::SecretService(store) => store.write(service, name, secret).await,
            Opened::Sandbox(store) => store.write(service, name, secret).await,
            Opened::Sealed { files, .. } => files.write(service, name, secret.as_bytes()),
            Opened::Keyutils(store) => keyutils_entry(store, service, name)?
                .set_password(secret)
                .map_err(|err| backend_error("keyutils store", err)),
        }
    }

    pub(crate) async fn clear(&self, service: &str, name: &str) -> Result<(), ClientError> {
        match self.opened().await? {
            Opened::SecretService(store) => store.clear(service, name).await,
            Opened::Sandbox(store) => store.clear(service, name).await,
            Opened::Sealed { files, .. } => files.clear(service, name),
            Opened::Keyutils(store) => {
                match keyutils_entry(store, service, name)?.delete_credential() {
                    Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
                    Err(err) => Err(backend_error("keyutils clear", err)),
                }
            }
        }
    }
}

/// What detection settles on.
enum Detected<'a> {
    Sandbox,
    Credential(&'a Path),
    SecretService(zbus::Connection),
}

/// Decision 5's order: the sandbox, then a credential, then the Secret Service.
fn choose(
    env: &Environment,
    bus: Option<zbus::Connection>,
) -> Result<Detected<'_>, SecretStoreError> {
    if env.sandboxed {
        return Ok(Detected::Sandbox);
    }
    if let Some(credentials) = env.credentials.as_deref()
        && credentials.join(CREDENTIAL).exists()
    {
        return Ok(Detected::Credential(credentials));
    }
    bus.map(Detected::SecretService)
        .ok_or(SecretStoreError::NoStore { probed: PROBED })
}

async fn detect(env: &Environment, bus: Option<zbus::Connection>) -> Result<Opened, ClientError> {
    match choose(env, bus)? {
        Detected::Sandbox => Ok(Opened::Sandbox(sandbox::Sandbox::open().await?)),
        Detected::Credential(credentials) => open_credential(credentials, env.state.as_deref()),
        Detected::SecretService(bus) => Ok(Opened::SecretService(
            secret_service::SecretService::open(bus, secret_service::PROMPT_BOUND).await?,
        )),
    }
}

async fn open_named(store: &LinuxStore, env: &Environment) -> Result<Opened, ClientError> {
    match store {
        LinuxStore::SecretService => {
            let bus = secret_service::session_bus()
                .await
                .ok_or(SecretStoreError::NoStore {
                    probed: "the Secret Service",
                })?;
            Ok(Opened::SecretService(
                secret_service::SecretService::open(bus, secret_service::PROMPT_BOUND).await?,
            ))
        }
        LinuxStore::SandboxKeyring => Ok(Opened::Sandbox(sandbox::Sandbox::open().await?)),
        LinuxStore::SystemdCredential => {
            let credentials = env
                .credentials
                .as_deref()
                .ok_or(SecretStoreError::NoStore {
                    probed: "the connetto.wrap-key systemd credential",
                })?;
            open_credential(credentials, env.state.as_deref())
        }
        LinuxStore::KeyFile(file) => Ok(Opened::Sealed {
            files: sealed::Sealed::open(
                file.state.join(SEALED_DIR),
                &*sealed::read_wrap_key(&file.key)?,
                file.previous
                    .as_deref()
                    .map(sealed::read_wrap_key)
                    .transpose()?
                    .as_deref(),
            )?,
            credential: false,
        }),
        LinuxStore::Keyutils => Ok(Opened::Keyutils(
            linux_keyutils_keyring_store::Store::new()
                .map_err(|err| backend_error("keyutils open", err))?,
        )),
    }
}

fn open_credential(credentials: &Path, state: Option<&Path>) -> Result<Opened, ClientError> {
    let state = state.ok_or_else(|| {
        SecretStoreError::Backend(
            "the unit has a connetto.wrap-key credential and no StateDirectory=".to_owned(),
        )
    })?;
    let previous = credentials.join(PREVIOUS_CREDENTIAL);
    let previous = previous
        .exists()
        .then(|| sealed::read_wrap_key(&previous))
        .transpose()?;
    Ok(Opened::Sealed {
        files: sealed::Sealed::open(
            state.join(SEALED_DIR),
            &*sealed::read_wrap_key(&credentials.join(CREDENTIAL))?,
            previous.as_deref(),
        )?,
        credential: true,
    })
}

fn keyutils_entry(
    store: &linux_keyutils_keyring_store::Store,
    service: &str,
    name: &str,
) -> Result<keyring_core::Entry, ClientError> {
    store
        .build(service, name, None)
        .map_err(|err| backend_error("keyutils open", err))
}

/// The attributes a keyring item is found by.
fn attributes<'a>(service: &'a str, name: &'a str) -> [(&'static str, &'a str); 2] {
    [("service", service), ("record", name)]
}

/// The secret as the base64 text a keyring item holds (decision 6).
fn encode(secret: &str) -> Zeroizing<String> {
    Zeroizing::new(STANDARD.encode(secret))
}

/// The secret a keyring item's base64 text holds.
fn decode(text: &[u8]) -> Result<String, ClientError> {
    let bytes = STANDARD
        .decode(text)
        .map_err(|_| SecretStoreError::Encoding)?;
    utf8(bytes)
}

fn utf8(bytes: Vec<u8>) -> Result<String, ClientError> {
    String::from_utf8(bytes).map_err(|err| {
        drop(Zeroizing::new(err.into_bytes()));
        SecretStoreError::Encoding.into()
    })
}

fn backend_error(what: &str, err: impl std::fmt::Display) -> ClientError {
    SecretStoreError::Backend(format!("{what}: {err}")).into()
}

#[cfg(test)]
mod tests;
