//! The device key in the TPM, through the Microsoft Platform Crypto Provider
//! (R74 decision 6).

use connetto_core::device_cert::{DeviceKey, DeviceKeyError, KeyHome};
use ring::digest::{SHA256, digest};
use windows_native_keyring_store::tpm_key::{TpmKeyError, TpmSigningKey};

use super::{ChipError, ChipKeys, der_signature};

/// The TPM, holding user-scoped keys that never leave it.
pub(crate) struct Tpm;

/// A P-256 key the TPM holds and never releases.
pub struct TpmKey(TpmSigningKey);

impl DeviceKey for TpmKey {
    fn public_point(&self) -> [u8; 65] {
        self.0.public_point()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
        let hashed: [u8; 32] = digest(&SHA256, message)
            .as_ref()
            .try_into()
            .map_err(|_| DeviceKeyError::Unavailable)?;
        self.0
            .sign_digest(&hashed)
            .map(|fixed| der_signature(&fixed))
            .map_err(|err| DeviceKeyError::Platform(Box::new(err)))
    }

    fn home(&self) -> KeyHome {
        KeyHome::Tpm
    }
}

/// A TPM refusal as the open order reads it. A machine without a usable
/// TPM keeps a software key (decision 16).
fn chip_error(err: TpmKeyError) -> ChipError {
    match err {
        TpmKeyError::Unavailable(_) => ChipError::Unavailable(err.to_string()),
        other => ChipError::Failed(Box::new(other)),
    }
}

impl ChipKeys for Tpm {
    type Key = TpmKey;

    fn find(&self, label: &str) -> Result<Option<TpmKey>, ChipError> {
        match TpmSigningKey::open(label) {
            Ok(key) => Ok(key.map(TpmKey)),
            // No usable TPM holds no key, and the open order then falls back.
            Err(TpmKeyError::Unavailable(_)) => Ok(None),
            Err(err) => Err(chip_error(err)),
        }
    }

    fn create(&self, label: &str) -> Result<TpmKey, ChipError> {
        TpmSigningKey::create(label).map(TpmKey).map_err(chip_error)
    }

    fn delete(&self, label: &str) -> Result<(), ChipError> {
        match TpmSigningKey::open(label) {
            Ok(Some(key)) => key.delete().map_err(|refused| chip_error(refused.error)),
            Ok(None) | Err(TpmKeyError::Unavailable(_)) => Ok(()),
            Err(err) => Err(chip_error(err)),
        }
    }
}
