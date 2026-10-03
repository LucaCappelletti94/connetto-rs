use rcgen::{PKCS_ECDSA_P256_SHA256, PublicKeyData, SignatureAlgorithm, SigningKey};

use super::identity::KeyId;

/// The DER prefix of a P-256 `SubjectPublicKeyInfo` ahead of its 65-byte point.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// A device's P-256 identity key, held in its security chip or in software.
pub trait DeviceKey: Send + Sync {
    /// The uncompressed public point, `0x04` then the coordinates.
    fn public_point(&self) -> [u8; 65];

    /// An ECDSA P-256 SHA-256 signature over `message`, DER encoded.
    ///
    /// # Errors
    ///
    /// [`DeviceKeyError`] when the chip or the store refuses.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DeviceKeyError>;

    /// Where the key lives.
    fn home(&self) -> KeyHome;
}

/// Where a device key lives (R74 decisions 6 and 16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyHome {
    /// Apple's Secure Enclave.
    SecureEnclave,
    /// The Android Keystore, in `StrongBox` or the trusted environment.
    AndroidKeystore {
        /// Whether the key sits in a `StrongBox` chip.
        strongbox: bool,
    },
    /// A Windows TPM through the Platform Crypto Provider.
    Tpm,
    /// Software, in the device's secret store.
    Software,
}

/// Why a device key could not sign.
#[derive(Debug, thiserror::Error)]
pub enum DeviceKeyError {
    /// The key is gone or its store is unreachable.
    #[error("the device key is unavailable")]
    Unavailable,
    /// The platform refused, with its own error.
    #[error("the platform refused to sign")]
    Platform(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// The DER `SubjectPublicKeyInfo` of `key`.
#[must_use]
pub fn public_key_info(key: &dyn DeviceKey) -> Vec<u8> {
    let mut spki = Vec::with_capacity(P256_SPKI_PREFIX.len() + 65);
    spki.extend_from_slice(&P256_SPKI_PREFIX);
    spki.extend_from_slice(&key.public_point());
    spki
}

/// The id certificates name `key` by.
#[must_use]
pub fn key_id(key: &dyn DeviceKey) -> KeyId {
    KeyId::of_public_key(&public_key_info(key))
}

/// A device key as the signer of its own certificate request.
pub struct CertificateSigner<'a> {
    key: &'a dyn DeviceKey,
    point: [u8; 65],
}

impl<'a> CertificateSigner<'a> {
    /// Sign requests with `key`.
    #[must_use]
    pub fn new(key: &'a dyn DeviceKey) -> Self {
        Self {
            point: key.public_point(),
            key,
        }
    }
}

impl PublicKeyData for CertificateSigner<'_> {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for CertificateSigner<'_> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.key
            .sign(message)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}
