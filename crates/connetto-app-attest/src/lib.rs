//! Apple App Attest for connetto's device enrolment (R74 decision 35).
//!
//! [`attest`] asks Apple to vouch that a genuine copy of the app, signed under
//! its App ID, made a request whose SHA-256 is the client data hash. It is the
//! workspace's one crate allowed `unsafe` code.
//!
//! `DCAppAttestService`'s instance methods lazily build a private controller
//! on the shared service without a lock, so two concurrent first calls can
//! release it under each other (objc2 #869). Every call here runs while one
//! process-wide lock is held, from `isSupported` to the attestation's
//! completion, so no two calls overlap. Other code in the same process that
//! calls App Attest outside this crate is not covered by that lock and must
//! not run while [`attest`] does.
//!
//! On every target but iOS and iPadOS [`attest`] answers `Ok(None)`. A Mac
//! answers the same, since App Attest is unsupported on every Mac.

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
mod platform {
    use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};

    use base64::Engine as _;
    use block2::RcBlock;
    use objc2_device_check::{DCAppAttestService, DCError, DCErrorDomain};
    use objc2_foundation::{NSData, NSError, NSString};
    use parking_lot::Mutex;

    use super::{ANSWER_WITHIN, AppAttestError, AppAttestation};

    /// Held for the whole of every App Attest exchange in this process.
    static SERIAL: Mutex<()> = Mutex::new(());

    /// What one completion handler hands back.
    type Answer<T> = Result<Option<T>, AppAttestError>;

    /// An error a completion handler reported.
    enum Reported {
        /// The device does not support App Attest.
        Unsupported,
        /// Any other failure.
        Failed(AppAttestError),
    }

    pub(super) fn attest(
        client_data_hash: &[u8; 32],
    ) -> Result<Option<AppAttestation>, AppAttestError> {
        let _serial = SERIAL.lock();
        // SAFETY: `sharedService` takes no arguments and returns the
        // process-wide singleton. objc2 #869 marks it safe on its main branch.
        let service = unsafe { DCAppAttestService::sharedService() };
        // SAFETY: `SERIAL` is held, so no other call on the shared service
        // runs while its controller may be created here.
        let supported = unsafe { service.isSupported() };
        if !supported {
            return Ok(None);
        }

        let (send, receive) = sync_channel::<Answer<String>>(1);
        let handler = RcBlock::new(move |key_id: *mut NSString, error: *mut NSError| {
            // SAFETY: the framework passes either null or a valid string it
            // owns for the duration of this call, and the string is copied
            // before the call returns.
            let key_id = unsafe { key_id.as_ref() }.map(ToString::to_string);
            // SAFETY: as above, for the error.
            let error = unsafe { error.as_ref() }.map(classify);
            answer(&send, key_id, error);
        });
        // SAFETY: `SERIAL` is held for the whole exchange. The handler is a
        // `'static` block the framework copies, so dropping ours after the
        // call is sound.
        unsafe { service.generateKeyWithCompletionHandler(&handler) };
        let Some(key_id) = wait(&receive)? else {
            return Ok(None);
        };

        let (send, receive) = sync_channel::<Answer<Vec<u8>>>(1);
        let handler = RcBlock::new(move |attestation: *mut NSData, error: *mut NSError| {
            // SAFETY: the framework passes either null or valid data it owns
            // for the duration of this call, and the bytes are copied before
            // the call returns.
            let attestation = unsafe { attestation.as_ref() }.map(NSData::to_vec);
            // SAFETY: as above, for the error.
            let error = unsafe { error.as_ref() }.map(classify);
            answer(&send, attestation, error);
        });
        let hash = NSData::with_bytes(client_data_hash);
        let key = NSString::from_str(&key_id);
        // SAFETY: `SERIAL` is held for the whole exchange, `key` names the key
        // just generated, and the handler is a `'static` block the framework
        // copies.
        unsafe { service.attestKey_clientDataHash_completionHandler(&key, &hash, &handler) };
        let Some(attestation) = wait(&receive)? else {
            return Ok(None);
        };

        let key_id = base64::engine::general_purpose::STANDARD
            .decode(key_id)
            .map_err(|_| AppAttestError::NoResult)?;
        Ok(Some(AppAttestation {
            key_id,
            attestation,
        }))
    }

    /// What an error App Attest reported means.
    fn classify(error: &NSError) -> Reported {
        let domain = error.domain();
        // SAFETY: `DCErrorDomain` is an immutable framework constant.
        let device_check = unsafe { DCErrorDomain };
        if *domain == *device_check && error.code() == DCError::FeatureUnsupported.0 {
            return Reported::Unsupported;
        }
        Reported::Failed(AppAttestError::Apple {
            domain: domain.to_string(),
            code: error.code(),
            description: error.localizedDescription().to_string(),
        })
    }

    /// Send a handler's outcome, which the waiting side may have stopped
    /// waiting for.
    fn answer<T>(send: &SyncSender<Answer<T>>, value: Option<T>, error: Option<Reported>) {
        let outcome = match (value, error) {
            (_, Some(Reported::Failed(error))) => Err(error),
            (_, Some(Reported::Unsupported)) => Ok(None),
            (Some(value), None) => Ok(Some(value)),
            (None, None) => Err(AppAttestError::NoResult),
        };
        let _ = send.try_send(outcome);
    }

    /// The next handler outcome, waited for at most [`ANSWER_WITHIN`].
    fn wait<T>(receive: &std::sync::mpsc::Receiver<Answer<T>>) -> Answer<T> {
        match receive.recv_timeout(ANSWER_WITHIN) {
            Ok(outcome) => outcome,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                Err(AppAttestError::TimedOut(ANSWER_WITHIN))
            }
        }
    }
}
