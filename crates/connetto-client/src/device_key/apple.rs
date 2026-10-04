//! The device key in Apple's Secure Enclave (R74 decision 6).

use connetto_core::device_cert::{DeviceKey, DeviceKeyError, KeyHome};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Limit, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework::passwords_options::AccessControlOptions;

use super::{ChipError, ChipKeys};

/// `errSecItemNotFound`.
const ITEM_NOT_FOUND: i32 = -25_300;
/// `errSecMissingEntitlement`, a build without the keychain access group.
const MISSING_ENTITLEMENT: i32 = -34_018;

/// A refusal from the Security framework, kept as its code and description.
#[derive(Debug, thiserror::Error)]
#[error("Security framework error {code}: {message}")]
pub struct EnclaveFailure {
    /// The `OSStatus` the framework reported.
    pub code: isize,
    /// The framework's description.
    pub message: String,
}

impl From<core_foundation::error::CFError> for EnclaveFailure {
    fn from(err: core_foundation::error::CFError) -> Self {
        Self {
            code: err.code(),
            message: err.description().to_string(),
        }
    }
}

/// The Secure Enclave, through the data protection keychain.
pub(crate) struct SecureEnclave;

/// A P-256 key the Secure Enclave holds and never releases.
pub struct EnclaveKey {
    key: SecKey,
    point: [u8; 65],
}

impl EnclaveKey {
    fn new(key: SecKey) -> Result<Self, ChipError> {
        let point = key
            .public_key()
            .and_then(|public| public.external_representation())
            .and_then(|data| <[u8; 65]>::try_from(data.bytes()).ok())
            .ok_or_else(|| {
                ChipError::Unavailable("the enclave key has no P-256 public point".into())
            })?;
        Ok(Self { key, point })
    }
}

impl DeviceKey for EnclaveKey {
    fn public_point(&self) -> [u8; 65] {
        self.point
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
        self.key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message)
            .map_err(|err| DeviceKeyError::Platform(Box::new(EnclaveFailure::from(err))))
    }

    fn home(&self) -> KeyHome {
        KeyHome::SecureEnclave
    }
}

impl ChipKeys for SecureEnclave {
    type Key = EnclaveKey;

    fn find(&self, label: &str) -> Result<Option<EnclaveKey>, ChipError> {
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .label(label)
            .load_refs(true)
            .limit(Limit::Max(1));
        // iOS has only the data protection keychain, macOS has to be told.
        #[cfg(target_os = "macos")]
        search.ignore_legacy_keychains();
        let found = search.search();
        match found {
            Ok(results) => results
                .into_iter()
                .find_map(|result| match result {
                    SearchResult::Ref(Reference::Key(key)) => Some(key),
                    _ => None,
                })
                .map(EnclaveKey::new)
                .transpose(),
            // An unentitled build cannot reach the data protection keychain, so
            // it holds no enclave key and falls back when it tries to make one.
            Err(err) if matches!(err.code(), ITEM_NOT_FOUND | MISSING_ENTITLEMENT) => Ok(None),
            Err(err) => Err(ChipError::Failed(Box::new(err))),
        }
    }

    fn create(&self, label: &str) -> Result<EnclaveKey, ChipError> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            AccessControlOptions::PRIVATE_KEY_USAGE.bits(),
        )
        .map_err(|err| ChipError::Failed(Box::new(err)))?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_location(Location::DataProtectionKeychain)
            .set_label(label)
            .set_access_control(access);
        // No enclave, or a build without the keychain entitlement, both refuse here.
        let key = SecKey::new(&options)
            .map_err(|err| ChipError::Unavailable(EnclaveFailure::from(err).to_string()))?;
        EnclaveKey::new(key)
    }

    fn delete(&self, label: &str) -> Result<(), ChipError> {
        let mut search = ItemSearchOptions::new();
        search.class(ItemClass::key()).label(label);
        #[cfg(target_os = "macos")]
        search.ignore_legacy_keychains();
        match search.delete() {
            Ok(()) => Ok(()),
            Err(err) if matches!(err.code(), ITEM_NOT_FOUND | MISSING_ENTITLEMENT) => Ok(()),
            Err(err) => Err(ChipError::Failed(Box::new(err))),
        }
    }
}
