//! The Android Keystore behind the gate (R52).
//!
//! The reserved records live in `android-native-keyring-store`'s default
//! store, readable before any prompt. The secrets live in a named store
//! configured `user-auth-required` with a timeout of `0`, which stays locked
//! until the app approves the `Cipher` from [`Store::begin_unlock`] in a
//! biometric or device-credential prompt and passes it to
//! [`Store::finish_unlock`], and locks again on [`Store::lock`]. The prompt is
//! the application's, through [`KeystorePrompt`], since the crate is pure JNI
//! and cannot host the prompt's callback.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use android_native_keyring_store::Store;
use keyring_core::Entry;
use keyring_core::api::CredentialStoreApi;

use super::gate::{Backend, Refusal, Storage};
use crate::ClientError;

/// The named store holding the gated secrets, one per app.
const GATED_STORE: [(&str, &str); 3] = [
    ("name", "connetto-gated"),
    ("user-auth-required", "true"),
    ("user-auth-timeout", "0"),
];

/// The API level a per-use Keystore key accepting the device credential needs.
const ANDROID_11: u32 = 30;

/// This device's API level, read as `0` when the property cannot be read.
fn api_level() -> u32 {
    android_system_properties::AndroidSystemProperties::new()
        .get("ro.build.version.sdk")
        .and_then(|level| level.parse().ok())
        .unwrap_or(0)
}

/// The platform prompt an Android build unlocks its gated secrets through.
///
/// `connetto-auth-session` implements both halves in Kotlin. An application
/// hands one to its keyring sign-in with
/// [`KeyringAuth::with_keystore_prompt`](crate::KeyringAuth::with_keystore_prompt).
/// A build without one keeps its secrets ungated and reports the gate
/// unsupported.
pub trait KeystorePrompt: Send + Sync {
    /// Whether the device has a secure lock screen, without which Android holds
    /// no key behind the user's verification.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the platform cannot be asked.
    fn device_secure(&self) -> Result<bool, ClientError>;

    /// Show the biometric or device-credential prompt over `cipher`, a
    /// `javax.crypto.Cipher` the store hands out as the prompt's
    /// `CryptoObject`, and answer whether the user approved it. Blocks until
    /// the prompt closes.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the prompt cannot be shown.
    fn approve(&self, cipher: &jni::objects::GlobalRef) -> Result<bool, ClientError>;
}

/// The two stores one app's secrets live in.
pub(crate) struct AndroidBackend {
    plain: Arc<Store>,
    gated: Mutex<Option<Arc<Store>>>,
    prompt: Mutex<Option<Arc<dyn KeystorePrompt>>>,
    /// Set once the gated store was recreated after its Keystore key was lost.
    lost: Mutex<bool>,
}

impl AndroidBackend {
    /// The default store, the gated one opened on first use.
    pub(crate) fn new() -> Result<Self, ClientError> {
        Ok(Self {
            plain: Store::new().map_err(|err| setup(&err))?,
            gated: Mutex::new(None),
            prompt: Mutex::new(None),
            lost: Mutex::new(false),
        })
    }

    /// The prompt the gated store opens through.
    pub(crate) fn set_prompt(&self, prompt: Arc<dyn KeystorePrompt>) {
        *self.prompt.lock().unwrap_or_else(PoisonError::into_inner) = Some(prompt);
    }

    /// Whether the gated store was recreated because its key was lost, which
    /// the next replica key read reports once.
    pub(crate) fn take_lost(&self) -> bool {
        std::mem::take(&mut *self.lost.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn prompt(&self) -> Option<Arc<dyn KeystorePrompt>> {
        self.prompt
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The gated store, created on first use. A device before Android 11 or
    /// with no secure lock screen, or a build with no prompt, cannot have one.
    fn gated_store(&self) -> Result<Arc<Store>, Refusal> {
        let mut gated = self.gated.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(store) = gated.as_ref() {
            return Ok(Arc::clone(store));
        }
        if api_level() < ANDROID_11 {
            return Err(Refusal::Unsupported);
        }
        let Some(prompt) = self.prompt() else {
            return Err(Refusal::Unsupported);
        };
        if !prompt.device_secure().map_err(Refusal::Other)? {
            return Err(Refusal::NoDeviceLock);
        }
        if let Some(store) = self.existing(&mut gated)? {
            return Ok(store);
        }
        let store = Store::new_with_configuration(&HashMap::from(GATED_STORE))
            .map_err(|err| other(&err))?;
        *gated = Some(Arc::clone(&store));
        Ok(store)
    }

    /// The gated store when one exists, never creating one.
    fn existing_gated(&self) -> Result<Option<Arc<Store>>, Refusal> {
        self.existing(&mut self.gated.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// The gated store behind `gated` when one exists, deleting a store whose
    /// key went with the screen lock and reporting that loss once.
    fn existing(&self, gated: &mut Option<Arc<Store>>) -> Result<Option<Arc<Store>>, Refusal> {
        if let Some(store) = gated.as_ref() {
            return Ok(Some(Arc::clone(store)));
        }
        let config = HashMap::from(GATED_STORE);
        if api_level() < ANDROID_11 || !Store::exists(&config).map_err(|err| other(&err))? {
            return Ok(None);
        }
        match Store::new_with_configuration(&config) {
            Ok(store) => {
                *gated = Some(Arc::clone(&store));
                Ok(Some(store))
            }
            Err(keyring_core::Error::BadStoreFormat(reason)) => {
                tracing::warn!(%reason, "the gated store's Keystore key is gone, discarding it");
                Store::delete(&config).map_err(|err| other(&err))?;
                *self.lost.lock().unwrap_or_else(PoisonError::into_inner) = true;
                Ok(None)
            }
            Err(err) => Err(other(&err)),
        }
    }

    fn entry(&self, service: &str, name: &str, storage: Storage) -> Result<Entry, Refusal> {
        match storage {
            Storage::Gated => self.gated_store()?.build(service, name, None),
            Storage::Ungated(_) => self.plain.build(service, name, None),
        }
        .map_err(|err| other(&err))
    }
}

impl Backend for AndroidBackend {
    fn read(&self, service: &str, name: &str, storage: Storage) -> Result<Option<String>, Refusal> {
        match self.entry(service, name, storage)?.get_password() {
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
        self.entry(service, name, storage)?
            .set_password(secret)
            .map_err(|err| refusal(&err))
    }

    fn clear(&self, service: &str, name: &str, storage: Storage) -> Result<(), ClientError> {
        let entry = match storage {
            Storage::Gated => match self.existing_gated()? {
                Some(store) => store.build(service, name, None),
                None => return Ok(()),
            },
            Storage::Ungated(_) => self.plain.build(service, name, None),
        }
        .map_err(|err| ClientError::from(other(&err)))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => Err(refusal(&err).into()),
        }
    }

    fn read_stranded(&self, service: &str, name: &str) -> Result<Option<String>, Refusal> {
        let Some(store) = self.existing_gated()? else {
            return Ok(None);
        };
        let entry = store
            .build(service, name, None)
            .map_err(|err| other(&err))?;
        match entry.get_credential() {
            Ok(_) => {}
            Err(keyring_core::Error::NoEntry) => return Ok(None),
            Err(err) => return Err(refusal(&err)),
        }
        if let Err(keyring_core::Error::NoStorageAccess(_)) = entry.get_password() {
            self.open(service, None)?;
        }
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(err) => Err(refusal(&err)),
        }
    }

    fn open(&self, _service: &str, _probe: Option<&str>) -> Result<(), Refusal> {
        let store = self.gated_store()?;
        let prompt = self.prompt().ok_or(Refusal::Unsupported)?;
        let cipher = store.begin_unlock().map_err(|err| other(&err))?;
        if !prompt.approve(&cipher).map_err(Refusal::Other)? {
            return Err(Refusal::Dismissed);
        }
        store
            .finish_unlock(cipher.as_obj())
            .map_err(|err| other(&err))
    }

    fn close(&self, _service: &str) {
        let gated = self.gated.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(store) = gated.as_ref()
            && let Err(err) = store.lock()
        {
            tracing::warn!(%err, "locking the gated store failed");
        }
    }

    fn opens_explicitly(&self) -> bool {
        true
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
    Refusal::Other(ClientError::Auth(format!("keystore: {err}")))
}

fn setup(err: &keyring_core::Error) -> ClientError {
    ClientError::Auth(format!("keystore setup: {err}"))
}
