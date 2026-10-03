//! Enrolling a signed-in device's key (R74 step 3).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use connetto_core::SessionId;
use connetto_core::device_cert::{CertificateRequest, IssueError, KeyId};
use connetto_core::messages::{EnrolGrant, EnrolRefusal, EnrolRequest};
use ring::rand::{SecureRandom as _, SystemRandom};
use tokio::time::Instant;

use super::DeviceCertConfig;

/// The largest descriptor accepted, in bytes.
const DESCRIPTOR_LIMIT: usize = 4096;

/// One certificate the server issued, recorded before it is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolment<Id> {
    /// The account the certificate names.
    pub user: Id,
    /// The enrolled device key.
    pub key: KeyId,
    /// The certificate's serial.
    pub serial: [u8; 16],
    /// When the certificate expires.
    pub expires_at: SystemTime,
    /// The session that asked for it.
    pub session: SessionId,
    /// The application's device descriptor, as sent.
    pub descriptor: Vec<u8>,
}

/// What recording an enrolment found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    /// Recorded, so the certificate may be sent.
    Granted,
    /// The key's enrolment is revoked, so nothing was recorded.
    Revoked,
}

/// The enrolment table could not be reached.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct EnrolmentError(String);

impl EnrolmentError {
    /// Name a failure.
    #[must_use]
    pub fn new(detail: impl core::fmt::Display) -> Self {
        Self(detail.to_string())
    }
}

/// The answer to one enrolment-table operation.
pub type EnrolmentFuture<'a, T> =
    core::pin::Pin<Box<dyn Future<Output = Result<T, EnrolmentError>> + Send + 'a>>;

/// Records the certificates the server issues.
///
/// A trait object for the reason [`crate::ban::BanStore`] is one.
pub trait EnrolmentStore<Id>: Send + Sync + 'static {
    /// Record `enrolment` unless its key's enrolment is revoked, deciding both in one step.
    fn record(&self, enrolment: Enrolment<Id>) -> EnrolmentFuture<'_, Recorded>;
}

/// An [`EnrolmentStore`] in memory, for tests and single-process runs.
#[derive(Debug)]
pub struct MemoryEnrolments<Id> {
    state: parking_lot::Mutex<(Vec<Enrolment<Id>>, HashSet<KeyId>)>,
}

impl<Id> Default for MemoryEnrolments<Id> {
    fn default() -> Self {
        Self {
            state: parking_lot::Mutex::new((Vec::new(), HashSet::new())),
        }
    }
}

impl<Id: Clone> MemoryEnrolments<Id> {
    /// Every enrolment recorded, oldest first.
    #[must_use]
    pub fn records(&self) -> Vec<Enrolment<Id>> {
        self.state.lock().0.clone()
    }

    /// Revoke `key`, so every later enrolment of it is refused.
    pub fn revoke(&self, key: KeyId) {
        self.state.lock().1.insert(key);
    }
}

impl<Id: Send + 'static> EnrolmentStore<Id> for MemoryEnrolments<Id> {
    fn record(&self, enrolment: Enrolment<Id>) -> EnrolmentFuture<'_, Recorded> {
        let mut state = self.state.lock();
        let recorded = if state.1.contains(&enrolment.key) {
            Recorded::Revoked
        } else {
            state.0.push(enrolment);
            Recorded::Granted
        };
        Box::pin(core::future::ready(Ok(recorded)))
    }
}

/// A nonce handed to a session, spent by the next enrolment request whatever its outcome.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PendingChallenge {
    nonce: [u8; 32],
    expires: Instant,
}

/// The issuer settings and the table enrolments are recorded in.
pub struct DeviceEnrolment<Id> {
    config: DeviceCertConfig,
    store: Arc<dyn EnrolmentStore<Id>>,
    random: SystemRandom,
}

impl<Id: Clone + core::fmt::Display + 'static> DeviceEnrolment<Id> {
    /// Issue under `config`, recording into `store`.
    #[must_use]
    pub fn new(config: DeviceCertConfig, store: Arc<dyn EnrolmentStore<Id>>) -> Self {
        Self {
            config,
            store,
            random: SystemRandom::new(),
        }
    }

    /// A fresh nonce, replacing any the session held, and how long it stays valid.
    pub(crate) fn challenge(
        &self,
        pending: &mut Option<PendingChallenge>,
    ) -> Result<([u8; 32], Duration), EnrolRefusal> {
        let mut nonce = [0; 32];
        self.random
            .fill(&mut nonce)
            .map_err(|_| EnrolRefusal::IssuerUnavailable)?;
        let window = self.config.challenge_window();
        *pending = Some(PendingChallenge {
            nonce,
            expires: Instant::now() + window,
        });
        Ok((nonce, window))
    }

    /// Issue and record the certificate `request` asks for on behalf of `user`.
    pub(crate) async fn enrol(
        &self,
        user: &Id,
        session: SessionId,
        pending: &mut Option<PendingChallenge>,
        request: EnrolRequest,
    ) -> Result<EnrolGrant, EnrolRefusal> {
        let challenge = pending.take();
        if request.descriptor.len() > DESCRIPTOR_LIMIT {
            return Err(EnrolRefusal::InvalidRequest);
        }
        let csr =
            CertificateRequest::parse(&request.csr).map_err(|_| EnrolRefusal::InvalidRequest)?;
        let live = challenge.filter(|challenge| {
            Instant::now() < challenge.expires && &challenge.nonce == csr.challenge()
        });
        if live.is_none() {
            return Err(EnrolRefusal::ChallengeExpired);
        }
        let lifetime = self
            .config
            .lifetime_for(request.lifetime_secs.map(Duration::from_secs))
            .map_err(|refused| EnrolRefusal::OverCeiling {
                ceiling_secs: refused.ceiling.as_secs(),
            })?;
        let mut serial = [0; 16];
        self.random
            .fill(&mut serial)
            .map_err(|_| EnrolRefusal::IssuerUnavailable)?;
        let not_before = SystemTime::now();
        let issuer = self.config.issuer();
        let leaf = issuer
            .issue(&csr, &user.to_string(), not_before, lifetime, serial)
            .map_err(|err| match err {
                IssueError::Identity(_) => EnrolRefusal::Unidentified,
                IssueError::OutlivesIssuer | IssueError::Validity | IssueError::Sign(_) => {
                    tracing::warn!(error = %err, "device certificate not issued");
                    EnrolRefusal::IssuerUnavailable
                }
            })?;
        let enrolment = Enrolment {
            user: user.clone(),
            key: KeyId::of_public_key(csr.public_key()),
            serial,
            expires_at: not_before + lifetime,
            session,
            descriptor: request.descriptor,
        };
        match self.store.record(enrolment).await {
            Ok(Recorded::Granted) => Ok(EnrolGrant {
                request_id: request.request_id,
                chain: vec![leaf.into(), issuer.certificate().to_vec().into()],
                revocation_lists: Vec::new(),
            }),
            Ok(Recorded::Revoked) => Err(EnrolRefusal::Revoked),
            Err(err) => {
                tracing::warn!(error = %err, "the enrolment table refused a record");
                Err(EnrolRefusal::IssuerUnavailable)
            }
        }
    }
}
