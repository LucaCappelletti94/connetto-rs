//! The Apple keychain behind the gate (R51).
//!
//! Every Apple target keeps its secrets in the data protection keychain
//! through `apple-native-keyring-store`'s protected store, configured with
//! `shared-authentication` so one approval opens every gated item until
//! [`reset_authentication`](protected::Store::reset_authentication). A gated
//! secret carries `require-user-presence`, a biometric or the device passcode,
//! and sits under its service with `.gated` appended, apart from any ungated
//! copy.
//! The data protection keychain needs the `keychain-access-groups`
//! entitlement, which a bare signed binary lacks, and macOS then keeps its
//! secrets in the login keychain instead, ungated.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use apple_native_keyring_store::protected;
use keyring_core::Entry;
use keyring_core::api::CredentialStoreApi;

use super::gate::{Backend, Refusal, Storage};
use crate::ClientError;

/// `errSecUserCanceled`, a dismissed sheet.
const USER_CANCELED: i32 = -128;
/// `errSecAuthFailed`, a verification that did not pass, or a gated create
/// on a device with no passcode.
const AUTH_FAILED: i32 = -25293;
/// `errSecMissingEntitlement`, a build without `keychain-access-groups`.
const MISSING_ENTITLEMENT: i32 = -34018;
/// Appended to the service of a gated item, so a gated and an ungated copy of
/// one secret are two items rather than one whose protection is fixed.
const GATED_SERVICE: &str = ".gated";

/// The keychain stores one service's secrets live in.
pub(crate) struct AppleBackend {
    protected: Arc<protected::Store>,
    /// The login keychain, where a macOS build without the entitlement keeps
    /// its secrets.
    #[cfg(target_os = "macos")]
    login: Arc<apple_native_keyring_store::keychain::Store>,
    /// Set once the data protection keychain refused for a missing
    /// entitlement.
    unentitled: AtomicBool,
}

impl AppleBackend {
    /// The stores, the protected one sharing one authentication.
    pub(crate) fn new() -> Result<Self, ClientError> {
        let config = HashMap::from([("shared-authentication", "true")]);
        Ok(Self {
            protected: protected::Store::new_with_configuration(&config)
                .map_err(|err| setup(&err))?,
            #[cfg(target_os = "macos")]
            login: apple_native_keyring_store::keychain::Store::new().map_err(|err| setup(&err))?,
            unentitled: AtomicBool::new(false),
        })
    }

    fn entry(&self, service: &str, name: &str, storage: Storage) -> Result<Entry, Refusal> {
        let gated_service;
        let service = if storage == Storage::Gated {
            gated_service = format!("{service}{GATED_SERVICE}");
            gated_service.as_str()
        } else {
            service
        };
        #[cfg(target_os = "macos")]
        if self.unentitled.load(Ordering::Relaxed) {
            return self
                .login
                .build(service, name, None)
                .map_err(|err| other(&err));
        }
        let gated = HashMap::from([("access-policy", "require-user-presence")]);
        let modifiers = (storage == Storage::Gated).then_some(&gated);
        self.protected
            .build(service, name, modifiers)
            .map_err(|err| other(&err))
    }

    /// Classify a keychain refusal, remembering a missing entitlement.
    fn refusal(&self, err: &keyring_core::Error, creating: bool) -> Refusal {
        match status(err) {
            Some(MISSING_ENTITLEMENT) => {
                self.unentitled.store(true, Ordering::Relaxed);
                Refusal::Unsupported
            }
            Some(AUTH_FAILED) if creating => Refusal::NoDeviceLock,
            Some(USER_CANCELED | AUTH_FAILED) => Refusal::Dismissed,
            _ => other(err),
        }
    }
}

/// Whether to retry an ungated operation in the login keychain once the
/// protected one refused for a missing entitlement, which only macOS has.
fn retry_ungated(refusal: &Refusal, storage: Storage) -> bool {
    cfg!(target_os = "macos")
        && matches!(refusal, Refusal::Unsupported)
        && matches!(storage, Storage::Ungated(_))
}

impl Backend for AppleBackend {
    fn read(&self, service: &str, name: &str, storage: Storage) -> Result<Option<String>, Refusal> {
        match self.entry(service, name, storage)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(err) => {
                let refusal = self.refusal(&err, false);
                if retry_ungated(&refusal, storage) {
                    return self.read(service, name, storage);
                }
                Err(refusal)
            }
        }
    }

    fn write(
        &self,
        service: &str,
        name: &str,
        secret: &str,
        storage: Storage,
    ) -> Result<(), Refusal> {
        match self.entry(service, name, storage)?.set_password(secret) {
            Ok(()) => Ok(()),
            Err(err) => {
                let refusal = self.refusal(&err, true);
                if retry_ungated(&refusal, storage) {
                    return self.write(service, name, secret, storage);
                }
                Err(refusal)
            }
        }
    }

    fn clear(&self, service: &str, name: &str, storage: Storage) -> Result<(), ClientError> {
        let entry = self
            .entry(service, name, storage)
            .map_err(ClientError::from)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => match self.refusal(&err, false) {
                refusal if retry_ungated(&refusal, storage) => self.clear(service, name, storage),
                // A build without the entitlement holds no gated item.
                Refusal::Unsupported => Ok(()),
                refusal => Err(refusal.into()),
            },
        }
    }

    fn read_stranded(&self, service: &str, name: &str) -> Result<Option<String>, Refusal> {
        match self.read(service, name, Storage::Gated) {
            Err(Refusal::Unsupported) => Ok(None),
            read => read,
        }
    }

    fn open(&self, service: &str, probe: Option<&str>) -> Result<(), Refusal> {
        match probe {
            Some(name) => self.read(service, name, Storage::Gated).map(drop),
            None => Ok(()),
        }
    }

    fn close(&self, _service: &str) {
        self.protected.reset_authentication();
    }

    fn opens_explicitly(&self) -> bool {
        false
    }
}

/// The keychain status code behind a store error, when there is one.
fn status(err: &keyring_core::Error) -> Option<i32> {
    match err {
        keyring_core::Error::PlatformFailure(inner)
        | keyring_core::Error::NoStorageAccess(inner) => inner
            .downcast_ref::<security_framework::base::Error>()
            .map(|status| status.code()),
        _ => None,
    }
}

fn other(err: &keyring_core::Error) -> Refusal {
    Refusal::Other(ClientError::Auth(format!("keychain: {err}")))
}

fn setup(err: &keyring_core::Error) -> ClientError {
    ClientError::Auth(format!("keychain setup: {err}"))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::{AUTH_FAILED, AppleBackend, MISSING_ENTITLEMENT, USER_CANCELED, retry_ungated};
    use crate::keyring::gate::{Refusal, Storage};
    use connetto_core::custody::NoGate;

    fn refused(status: i32) -> keyring_core::Error {
        keyring_core::Error::PlatformFailure(Box::new(security_framework::base::Error::from_code(
            status,
        )))
    }

    #[test]
    fn the_keychain_statuses_map_to_what_the_gate_acts_on() {
        let backend = AppleBackend::new().expect("the stores open without touching the keychain");
        assert!(matches!(
            backend.refusal(&refused(USER_CANCELED), false),
            Refusal::Dismissed
        ));
        assert!(matches!(
            backend.refusal(&refused(AUTH_FAILED), false),
            Refusal::Dismissed
        ));
        assert!(matches!(
            backend.refusal(&refused(AUTH_FAILED), true),
            Refusal::NoDeviceLock
        ));
        assert!(matches!(
            backend.refusal(&refused(-25299), true),
            Refusal::Other(_)
        ));
        assert!(!backend.unentitled.load(Ordering::Relaxed));
        assert!(matches!(
            backend.refusal(&refused(MISSING_ENTITLEMENT), false),
            Refusal::Unsupported
        ));
        assert!(
            backend.unentitled.load(Ordering::Relaxed),
            "a missing entitlement is remembered"
        );
    }

    #[test]
    fn only_macos_retries_an_ungated_secret_in_the_login_keychain() {
        let ungated = Storage::Ungated(NoGate::Unsupported);
        assert_eq!(
            retry_ungated(&Refusal::Unsupported, ungated),
            cfg!(target_os = "macos")
        );
        assert!(!retry_ungated(&Refusal::Unsupported, Storage::Gated));
        assert!(!retry_ungated(&Refusal::Dismissed, ungated));
    }
}
