#![doc = include_str!("../README.md")]

use std::time::Duration;

/// How long [`attest`] waits for each of Apple's answers. Generating a key is
/// local, and attesting it asks Apple's servers.
pub const ANSWER_WITHIN: Duration = Duration::from_secs(60);

/// What App Attest vouched for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppAttestation {
    /// The App Attest key's identifier, the SHA-256 of its public key.
    pub key_id: Vec<u8>,
    /// The CBOR attestation object Apple signed.
    pub attestation: Vec<u8>,
}

/// Why App Attest produced no attestation on a device that supports it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppAttestError {
    /// The framework reported an error.
    #[error("App Attest failed with {domain} {code}: {description}")]
    Apple {
        /// The error domain.
        domain: String,
        /// The error code within the domain.
        code: isize,
        /// The framework's description of the error.
        description: String,
    },
    /// The framework did not answer within [`ANSWER_WITHIN`].
    #[error("App Attest did not answer within {0:?}")]
    TimedOut(Duration),
    /// The framework answered with neither a result nor an error, or with a
    /// key identifier that is not base64.
    #[error("App Attest answered without a usable result")]
    NoResult,
}

/// Attest a fresh App Attest key over `client_data_hash`.
///
/// Blocks until Apple answers, at most [`ANSWER_WITHIN`] per step, so call
/// it off an async runtime. A fresh key is generated each time and dropped
/// after, since a device attests once per device key.
///
/// # Errors
///
/// [`AppAttestError`] when a supported device's framework fails or does not
/// answer in time. A device without App Attest answers `Ok(None)`.
pub fn attest(client_data_hash: &[u8; 32]) -> Result<Option<AppAttestation>, AppAttestError> {
    platform::attest(client_data_hash)
}

#[cfg(not(target_os = "ios"))]
mod platform {
    use super::{AppAttestError, AppAttestation};

    #[expect(
        clippy::unnecessary_wraps,
        reason = "one signature on every target, and only iOS can fail"
    )]
    pub(super) fn attest(
        _client_data_hash: &[u8; 32],
    ) -> Result<Option<AppAttestation>, AppAttestError> {
        Ok(None)
    }
}

#[cfg(target_os = "ios")]
#[expect(
    unsafe_code,
    reason = "the DeviceCheck calls objc2 marks unsafe, each sound under the module's lock"
)]
#[path = "ios.rs"]
mod platform;
