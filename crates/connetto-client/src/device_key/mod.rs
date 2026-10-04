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

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub(crate) use android::AndroidKeystore;
#[cfg(target_os = "android")]
pub use android::{JavaAccess, KeystoreKey};
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use apple::EnclaveKey;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use apple::SecureEnclave;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub(crate) use windows::Tpm;
#[cfg(target_os = "windows")]
pub use windows::TpmKey;

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
pub(crate) trait KeyRecords: Send + Sync {
    /// The secret stored under `name`, `None` when none was.
    fn read(&self, name: &str) -> impl Future<Output = Result<Option<String>, ClientError>> + Send;
    /// Store `secret` under `name`, replacing any prior one.
    fn write(
        &self,
        name: &str,
        secret: &str,
    ) -> impl Future<Output = Result<(), ClientError>> + Send;
    /// Remove whatever is stored under `name`.
    fn delete(&self, name: &str) -> impl Future<Output = Result<(), ClientError>> + Send;
}

impl KeyRecords for crate::keyring::Keyring {
    async fn read(&self, name: &str) -> Result<Option<String>, ClientError> {
        crate::keyring::Keyring::read(self, name).await
    }

    async fn write(&self, name: &str, secret: &str) -> Result<(), ClientError> {
        crate::keyring::Keyring::write(self, name, secret).await
    }

    async fn delete(&self, name: &str) -> Result<(), ClientError> {
        crate::keyring::Keyring::clear(self, name).await
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

/// One platform's security chip, as the open order drives it.
pub(crate) trait ChipKeys: Send + Sync {
    /// The key the chip holds.
    type Key: DeviceKey + 'static;
    /// The key stored under `label`, `None` when the chip holds none.
    ///
    /// # Errors
    ///
    /// [`ChipError`] when the chip cannot be asked.
    fn find(&self, label: &str) -> Result<Option<Self::Key>, ChipError>;
    /// Create a key under `label`, usable once the device was unlocked since
    /// its restart (decision 11).
    ///
    /// # Errors
    ///
    /// [`ChipError::Unavailable`] when this device has no usable chip.
    fn create(&self, label: &str) -> Result<Self::Key, ChipError>;
    /// Delete every key stored under `label`, succeeding when there is none.
    ///
    /// # Errors
    ///
    /// [`ChipError`] when the chip cannot be asked.
    fn delete(&self, label: &str) -> Result<(), ChipError>;
}

/// A platform without a key chip connetto reaches, so every device key there
/// is a software key (decision 16).
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "windows"
)))]
pub(crate) struct NoChip;

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "windows"
)))]
impl ChipKeys for NoChip {
    type Key = SoftwareKey;

    fn find(&self, _label: &str) -> Result<Option<SoftwareKey>, ChipError> {
        Ok(None)
    }

    fn create(&self, _label: &str) -> Result<SoftwareKey, ChipError> {
        Err(ChipError::Unavailable(
            "this platform has no key chip connetto reaches".into(),
        ))
    }

    fn delete(&self, _label: &str) -> Result<(), ChipError> {
        Ok(())
    }
}

/// Why a chip could not hold a device key.
#[derive(Debug, thiserror::Error)]
pub enum ChipError {
    /// No usable chip, so the device keeps a software key (decision 16).
    #[error("no usable key chip: {0}")]
    Unavailable(String),
    /// The chip failed for another reason.
    #[error("the key chip failed")]
    Failed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// The label a chip stores `account`'s key under for the app `service`.
fn chip_label(service: &str, account: &str) -> String {
    format!("connetto-device-key:{service}:{account}")
}

/// Open `account`'s device key, preferring the chip.
///
/// The chip's key wins when it holds one. Otherwise a stored software key
/// wins, so a device that fell back once keeps its identity. Otherwise the
/// chip makes a key, and a device without a usable chip makes a software key
/// in `records` instead.
///
/// # Errors
///
/// The chip's failure other than [`ChipError::Unavailable`], or the store's.
pub(crate) async fn open_device_key<C: ChipKeys + 'static>(
    chip: std::sync::Arc<C>,
    records: &impl KeyRecords,
    service: &str,
    account: &str,
) -> Result<OpenedKey<Box<dyn DeviceKey>>, ClientError> {
    let label = chip_label(service, account);
    let found = {
        let (chip, label) = (std::sync::Arc::clone(&chip), label.clone());
        blocking(move || chip.find(&label)).await?
    };
    if let Some(key) = found {
        return Ok(OpenedKey {
            key: Box::new(key),
            created: false,
        });
    }
    let name = crate::device_key_record(account);
    if records.read(&name).await?.is_some() {
        let opened = open_software_key(records, account).await?;
        return Ok(boxed(opened));
    }
    match blocking(move || chip.create(&label)).await {
        Ok(key) => Ok(OpenedKey {
            key: Box::new(key),
            created: true,
        }),
        Err(ClientError::DeviceChip(ChipError::Unavailable(reason))) => {
            tracing::warn!(%reason, "no usable key chip, keeping a software device key");
            Ok(boxed(open_software_key(records, account).await?))
        }
        Err(err) => Err(err),
    }
}

/// Delete `account`'s device key wherever it is held, the chip and the store.
///
/// # Errors
///
/// The chip's failure, or the store's.
pub(crate) async fn delete_device_key<C: ChipKeys + 'static>(
    chip: std::sync::Arc<C>,
    records: &impl KeyRecords,
    service: &str,
    account: &str,
) -> Result<(), ClientError> {
    let label = chip_label(service, account);
    blocking(move || chip.delete(&label)).await?;
    records.delete(&crate::device_key_record(account)).await
}

fn boxed(opened: OpenedKey<SoftwareKey>) -> OpenedKey<Box<dyn DeviceKey>> {
    OpenedKey {
        key: Box::new(opened.key),
        created: opened.created,
    }
}

/// The DER `ECDSA-Sig-Value` of a signature given as fixed-width `r || s`.
#[cfg(any(target_os = "windows", test))]
fn der_signature(fixed: &[u8; 64]) -> Vec<u8> {
    fn integer(out: &mut Vec<u8>, value: &[u8]) {
        let start = value
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(value.len() - 1);
        let value = &value[start..];
        let pad = value[0] & 0x80 != 0;
        out.push(0x02);
        out.push(u8::try_from(value.len() + usize::from(pad)).unwrap_or(u8::MAX));
        if pad {
            out.push(0);
        }
        out.extend_from_slice(value);
    }
    let mut body = Vec::with_capacity(70);
    integer(&mut body, &fixed[..32]);
    integer(&mut body, &fixed[32..]);
    let mut der = Vec::with_capacity(body.len() + 2);
    der.push(0x30);
    der.push(u8::try_from(body.len()).unwrap_or(u8::MAX));
    der.extend_from_slice(&body);
    der
}

/// Run a chip call off the async runtime, since a TPM takes hundreds of
/// milliseconds to sign.
async fn blocking<T: Send + 'static>(
    call: impl FnOnce() -> Result<T, ChipError> + Send + 'static,
) -> Result<T, ClientError> {
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|err| ClientError::DeviceChip(ChipError::Failed(Box::new(err))))?
        .map_err(ClientError::DeviceChip)
}

#[cfg(test)]
mod tests;
