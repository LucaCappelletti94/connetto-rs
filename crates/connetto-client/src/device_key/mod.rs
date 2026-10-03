//! A device's identity key on this platform (R74): held in the security chip,
//! or a software key kept in the plain secret store where no chip is usable
//! (decision 16).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use connetto_core::device_cert::{DeviceKey, DeviceKeyError, KeyHome};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use zeroize::Zeroizing;

use crate::ClientError;

/// Why no device key could be made.
#[derive(Debug, thiserror::Error)]
pub enum DeviceKeyStoreError {
    /// The platform's random source refused.
    #[error("the platform could not generate a device key")]
    Generate(#[source] ring::error::Unspecified),
    /// A freshly generated key did not read back.
    #[error("a freshly generated device key does not read back")]
    Unreadable,
}

/// Where an account's device key record is read and written, the platform
/// secret store in a client and a map in tests.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "R74 step 3's enrolment opens the key")
)]
pub(crate) trait KeyRecords: Send + Sync {
    /// The secret stored under `name`, `None` when none was.
    fn read(&self, name: &str) -> impl Future<Output = Result<Option<String>, ClientError>> + Send;
    /// Store `secret` under `name`, replacing any prior one.
    fn write(
        &self,
        name: &str,
        secret: &str,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;
}

impl KeyRecords for crate::keyring::Keyring {
    async fn read(&self, name: &str) -> Result<Option<String>, ClientError> {
        crate::keyring::Keyring::read(self, name).await
    }

    async fn write(&self, name: &str, secret: &str) -> Result<(), ClientError> {
        crate::keyring::Keyring::write(self, name, secret).await
    }
}

/// A P-256 device key held in software.
pub struct SoftwareKey {
    pair: EcdsaKeyPair,
    point: [u8; 65],
    rng: SystemRandom,
}

/// A device key and whether it was made by this open.
pub struct OpenedKey<K> {
    /// The key.
    pub key: K,
    /// Whether no usable key was stored, so a fresh one replaced it and the
    /// device must enrol again.
    pub created: bool,
}

impl SoftwareKey {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "R74 step 3's enrolment opens the key")
    )]
    fn from_pkcs8(rng: SystemRandom, der: &[u8]) -> Option<Self> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, der, &rng).ok()?;
        let point = pair.public_key().as_ref().try_into().ok()?;
        Some(Self { pair, point, rng })
    }
}

impl DeviceKey for SoftwareKey {
    fn public_point(&self) -> [u8; 65] {
        self.point
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
        self.pair
            .sign(&self.rng, message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|err| DeviceKeyError::Platform(Box::new(err)))
    }

    fn home(&self) -> KeyHome {
        KeyHome::Software
    }
}

/// Open `account`'s software key from `records`, creating and storing a fresh
/// one when none is stored or the stored one cannot be read.
///
/// # Errors
///
/// The store's error, or [`ClientError::DeviceKey`] when no key could be made.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "R74 step 3's enrolment opens the key")
)]
pub(crate) async fn open_software_key(
    records: &impl KeyRecords,
    account: &str,
) -> Result<OpenedKey<SoftwareKey>, ClientError> {
    let name = crate::device_key_record(account);
    let rng = SystemRandom::new();
    if let Some(stored) = records.read(&name).await? {
        let der = Zeroizing::new(STANDARD.decode(stored.as_bytes()).unwrap_or_default());
        if let Some(key) = SoftwareKey::from_pkcs8(rng.clone(), &der) {
            return Ok(OpenedKey {
                key,
                created: false,
            });
        }
    }
    let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(DeviceKeyStoreError::Generate)?;
    let der = Zeroizing::new(der.as_ref().to_vec());
    let encoded = Zeroizing::new(STANDARD.encode(der.as_slice()));
    records.write(&name, &encoded).await?;
    let key = SoftwareKey::from_pkcs8(rng, &der).ok_or(DeviceKeyStoreError::Unreadable)?;
    Ok(OpenedKey { key, created: true })
}

#[cfg(test)]
mod tests;
