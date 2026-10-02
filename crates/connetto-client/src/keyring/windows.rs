//! Windows Hello behind the gate (R53).
//!
//! The reserved records live in the ordinary Credential Manager store,
//! readable before any prompt. The secrets live in one `HelloStore` per
//! service, sealed under a key derived from a Windows Hello passkey, which
//! the first unlock enrolls and every later unlock asserts. The prompt needs
//! a live window, which the application lends through [`HelloOwner`].

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use keyring_core::Entry;
use keyring_core::api::CredentialStoreApi;
use windows_native_keyring_store::hello::HelloError;
pub use windows_native_keyring_store::hello::{HelloCancellation, HelloWindow};
use windows_native_keyring_store::{HelloStore, Store};

use super::gate::{Backend, Refusal, Storage};
use crate::ClientError;

/// The named store holding one app's gated secrets.
const GATED_STORE: &str = "connetto-gated";
/// How long a Windows Hello prompt may stay up.
const UNLOCK_WINDOW: Duration = Duration::from_secs(120);
/// How long discarding a lost store may wait for in-flight Hello work.
const DISCARD_WINDOW: Duration = Duration::from_secs(30);

/// The window a Windows Hello prompt opens over.
///
/// `connetto-dioxus` implements it over the desktop window. An application
/// hands one to its keyring sign-in with
/// [`KeyringAuth::with_hello_owner`](crate::KeyringAuth::with_hello_owner).
/// A build without one keeps its secrets ungated and reports the gate
/// unsupported.
pub trait HelloOwner: Send + Sync {
    /// A hold on the live window one prompt opens over, `None` while no
    /// window can host it. Connetto keeps the hold until Windows returns, and
    /// `cancel` cancels that prompt, for a window asked to close meanwhile.
    fn lease(&self, cancel: HelloCancellation) -> Option<Arc<dyn HelloWindow>>;
}

/// The two stores one app's secrets live in.
pub(crate) struct WindowsBackend {
    plain: Arc<Store>,
    gated: Mutex<Option<Arc<HelloStore>>>,
    owner: Mutex<Option<Arc<dyn HelloOwner>>>,
    /// Set once the gated store was discarded after its Hello credential was lost.
    lost: Mutex<bool>,
}

impl WindowsBackend {
    /// The ordinary store, the gated one opened on first use.
    pub(crate) fn new() -> Result<Self, ClientError> {
        Ok(Self {
            plain: Store::new().map_err(|err| setup(&err))?,
            gated: Mutex::new(None),
            owner: Mutex::new(None),
            lost: Mutex::new(false),
        })
    }

    /// The window the gated store's prompt opens over.
    pub(crate) fn set_owner(&self, owner: Arc<dyn HelloOwner>) {
        *self.owner.lock().unwrap_or_else(PoisonError::into_inner) = Some(owner);
    }

    /// Whether the gated store was discarded because its Hello credential was
    /// lost, which the next replica key read reports once.
    pub(crate) fn take_lost(&self) -> bool {
        std::mem::take(&mut *self.lost.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn owner(&self) -> Option<Arc<dyn HelloOwner>> {
        self.owner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The gated store, created on first use. Creating it never prompts.
    fn hello_store(&self, service: &str) -> Result<Arc<HelloStore>, ClientError> {
        let mut gated = self.gated.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(store) = gated.as_ref() {
            return Ok(Arc::clone(store));
        }
        let store = HelloStore::new(service, GATED_STORE).map_err(|err| setup(&err))?;
        *gated = Some(Arc::clone(&store));
        Ok(store)
    }

    /// The gated store, where this build and machine can gate at all.
    fn gated_store(&self, service: &str) -> Result<Arc<HelloStore>, Refusal> {
        if self.owner().is_none() {
            return Err(Refusal::NoEntitlement);
        }
        HelloStore::capability().map_err(|err| refusal_of(&err))?;
        self.hello_store(service).map_err(Refusal::Other)
    }

    /// One Windows Hello prompt over the owner's window.
    fn unlock(&self, store: &HelloStore) -> Result<(), HelloError> {
        let owner = self.owner().ok_or(HelloError::MissingOwner)?;
        let cancellation = HelloCancellation::new();
        let window = owner
            .lease(cancellation.clone())
            .ok_or(HelloError::MissingOwner)?;
        store.unlock(window, &cancellation, UNLOCK_WINDOW)
    }

    /// Discard a store whose Hello credential is gone, with every secret it
    /// sealed, and start a fresh one. The loss is reported once.
    fn start_over(&self, service: &str, store: &HelloStore) -> Result<Arc<HelloStore>, Refusal> {
        tracing::warn!("the gated store's Windows Hello credential is gone, starting it over");
        store
            .discard(DISCARD_WINDOW)
            .map_err(|err| Refusal::Other(hello(&err)))?;
        let fresh = HelloStore::new(service, GATED_STORE).map_err(|err| other(&err))?;
        *self.gated.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&fresh));
        *self.lost.lock().unwrap_or_else(PoisonError::into_inner) = true;
        Ok(fresh)
    }

    fn entry(&self, service: &str, name: &str, storage: Storage) -> Result<Entry, ClientError> {
        match storage {
            Storage::Gated => self.hello_store(service)?.build(service, name, None),
            Storage::Ungated(_) => self.plain.build(service, name, None),
        }
        .map_err(|err| ClientError::Auth(format!("keyring open: {err}")))
    }
}

impl Backend for WindowsBackend {
    fn read(&self, service: &str, name: &str, storage: Storage) -> Result<Option<String>, Refusal> {
        match self
            .entry(service, name, storage)
            .map_err(Refusal::Other)?
            .get_password()
        {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(err) => Err(refusal(&err)),
        }
    }

    fn write(
        &self,
        service: &str,
        name: &str,
        secret: &str,
        storage: Storage,
    ) -> Result<(), Refusal> {
        self.entry(service, name, storage)
            .map_err(Refusal::Other)?
            .set_password(secret)
            .map_err(|err| refusal(&err))
    }

    fn clear(&self, service: &str, name: &str, storage: Storage) -> Result<(), ClientError> {
        match self.entry(service, name, storage)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => Err(refusal(&err).into()),
        }
    }

    fn open(&self, service: &str, _probe: Option<&str>) -> Result<(), Refusal> {
        let store = self.gated_store(service)?;
        match self.unlock(&store) {
            Err(HelloError::KeyLost | HelloError::Corrupt(_) | HelloError::Discarding) => {
                let fresh = self.start_over(service, &store)?;
                self.unlock(&fresh).map_err(|err| refusal_of(&err))
            }
            unlocked => unlocked.map_err(|err| refusal_of(&err)),
        }
    }

    fn close(&self, _service: &str) {
        if let Some(store) = self
            .gated
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            store.lock();
        }
    }

    fn opens_explicitly(&self) -> bool {
        true
    }
}

/// A Hello refusal as the gate sees it.
fn refusal_of(err: &HelloError) -> Refusal {
    match err {
        HelloError::Cancelled | HelloError::TimedOut | HelloError::MissingOwner => {
            Refusal::Dismissed
        }
        HelloError::Unsupported(_) => Refusal::NoEntitlement,
        HelloError::Locked => Refusal::Other(ClientError::Locked),
        other_err => Refusal::Other(hello(other_err)),
    }
}

/// A store refusal as the gate sees it. A locked store answers
/// `NoStorageAccess`, which the gate never reaches unopened, so it reads as
/// the gate's own lock.
fn refusal(err: &keyring_core::Error) -> Refusal {
    match err {
        keyring_core::Error::NoStorageAccess(_) => Refusal::Other(ClientError::Locked),
        other_err => other(other_err),
    }
}

fn other(err: &keyring_core::Error) -> Refusal {
    Refusal::Other(ClientError::Auth(format!("windows hello store: {err}")))
}

fn hello(err: &HelloError) -> ClientError {
    ClientError::Auth(format!("windows hello: {err}"))
}

fn setup(err: &keyring_core::Error) -> ClientError {
    ClientError::Auth(format!("keyring setup: {err}"))
}
