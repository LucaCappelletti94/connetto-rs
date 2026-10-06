//! Enrolling a signed-in device's key (R74 step 3), revoking it and publishing
//! the lists that say so (step 5).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use connetto_core::SessionId;
use connetto_core::device_cert::{
    AttestationLevel, CertificateRequest, IssueError, KeyId, ListError, Revoked,
};
use connetto_core::messages::{DeviceSummary, EnrolGrant, EnrolRefusal, EnrolRequest, SignedList};
use ring::rand::{SecureRandom as _, SystemRandom};
use tokio::time::Instant;

use super::{DeviceCertConfig, LifetimeError, StatusList, verify};

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
    /// The issuer that signed it, whose list names it once its key is revoked.
    pub issuer: KeyId,
    /// When the certificate starts, which is when the key was last seen.
    pub issued_at: SystemTime,
    /// When the certificate expires.
    pub expires_at: SystemTime,
    /// The session that asked for it.
    pub session: SessionId,
    /// The application's device descriptor, as sent.
    pub descriptor: Vec<u8>,
    /// The attestation level the first enrolment recorded, which renewals keep.
    pub attestation: AttestationLevel,
}

/// What recording an enrolment found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recorded {
    /// Recorded, so the certificate may be sent.
    Granted,
    /// The key's enrolment is revoked, so nothing was recorded.
    Revoked,
    /// The key is enrolled under another account, so nothing was recorded.
    HeldElsewhere,
    /// The descriptor does not decode into the deployment's descriptor type,
    /// so nothing was recorded.
    UnreadableDescriptor,
}

/// One enrolled device of an account, as the device list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The device key.
    pub key: KeyId,
    /// When the key first enrolled.
    pub enrolled_at: SystemTime,
    /// When the key last enrolled or renewed.
    pub last_seen: SystemTime,
    /// When the key was revoked.
    pub revoked_at: Option<SystemTime>,
    /// The descriptor the device last sent.
    pub descriptor: Vec<u8>,
}

/// What revoking a key found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// Revoked now, naming the session that last enrolled or renewed it.
    Revoked {
        /// The auth-store session the enrolment records.
        session: SessionId,
    },
    /// Revoked before, naming the session the enrolment recorded, so the
    /// revocation can be repeated against it.
    AlreadyRevoked {
        /// The auth-store session the enrolment records.
        session: SessionId,
    },
    /// No enrolment of that key, for that account when one is named.
    NotFound,
}

/// The enrolment table or the issuer it signs for could not be reached.
#[derive(Debug, thiserror::Error)]
pub enum EnrolmentError {
    /// The connection pool could not hand out a connection.
    #[error("the enrolment pool is unreachable")]
    Pool(#[source] diesel_async::pooled_connection::bb8::RunError),
    /// A statement against the enrolment tables failed.
    #[error("the enrolment tables refused a statement")]
    Query(#[source] diesel::result::Error),
    /// The descriptor would not encode into the tables' columns.
    #[error("the descriptor could not be encoded")]
    Descriptor(#[source] rmp_serde::encode::Error),
    /// A revocation list would not be signed under its issuer.
    #[error(transparent)]
    Signing(#[from] ListError),
    /// An issuer's list number does not fit a CRL Number.
    #[error("a list number does not fit a CRL Number")]
    ListNumber(#[source] std::num::TryFromIntError),
    /// The stored attestation level is not one the server records.
    #[error("the stored attestation level is not a level")]
    StoredLevel,
}

/// The answer to one enrolment-table operation.
pub type EnrolmentFuture<'a, T> =
    core::pin::Pin<Box<dyn Future<Output = Result<T, EnrolmentError>> + Send + 'a>>;

/// Records the certificates the server issues and the keys it revokes.
///
/// A trait object for the reason [`crate::ban::BanStore`] is one.
pub trait EnrolmentStore<Id>: Send + Sync + 'static {
    /// Record `enrolment` unless its key's enrolment is revoked or belongs to
    /// another account, deciding in one step.
    fn record(&self, enrolment: Enrolment<Id>) -> EnrolmentFuture<'_, Recorded>;

    /// `user`'s devices, revoked ones included.
    fn devices<'a>(&'a self, user: &'a Id) -> EnrolmentFuture<'a, Vec<Device>>;

    /// Revoke `key` at `at`, only when it is `user`'s when a user is named.
    fn revoke<'a>(
        &'a self,
        user: Option<&'a Id>,
        key: KeyId,
        at: SystemTime,
    ) -> EnrolmentFuture<'a, Revocation>;

    /// Every serial `issuer` signed for a revoked key, whose certificate has
    /// not expired at `now`.
    fn revoked_serials(&self, issuer: KeyId, now: SystemTime) -> EnrolmentFuture<'_, Vec<Revoked>>;

    /// The next CRL Number of the issuer `issuer`, above every number handed
    /// out before, across restarts.
    fn next_list_number(&self, issuer: KeyId) -> EnrolmentFuture<'_, u64>;

    /// The level the key's first enrolment under `user` recorded, `None`
    /// when the key has no enrolment under `user`.
    fn stored_attestation<'a>(
        &'a self,
        user: &'a Id,
        key: KeyId,
    ) -> EnrolmentFuture<'a, Option<AttestationLevel>>;
}

#[derive(Debug)]
struct Row<Id> {
    user: Id,
    enrolled_at: SystemTime,
    last_seen: SystemTime,
    revoked_at: Option<SystemTime>,
    session: SessionId,
    descriptor: Vec<u8>,
    attestation: AttestationLevel,
}

#[derive(Debug)]
struct Memory<Id> {
    grants: Vec<Enrolment<Id>>,
    rows: HashMap<KeyId, Row<Id>>,
    numbers: HashMap<KeyId, u64>,
}

/// An [`EnrolmentStore`] in memory, for tests and single-process runs.
#[derive(Debug)]
pub struct MemoryEnrolments<Id> {
    state: parking_lot::Mutex<Memory<Id>>,
}

impl<Id> Default for MemoryEnrolments<Id> {
    fn default() -> Self {
        Self {
            state: parking_lot::Mutex::new(Memory {
                grants: Vec::new(),
                rows: HashMap::new(),
                numbers: HashMap::new(),
            }),
        }
    }
}

impl<Id: Clone> MemoryEnrolments<Id> {
    /// Every certificate recorded, oldest first.
    #[must_use]
    pub fn records(&self) -> Vec<Enrolment<Id>> {
        self.state.lock().grants.clone()
    }
}

impl<Id: Clone + PartialEq + Send + 'static> MemoryEnrolments<Id> {
    /// Revoke `key` whoever it belongs to, as an operator would, without
    /// publishing a list.
    pub fn revoke_key(&self, key: KeyId) {
        let _ = self.revoke_now(None, key, SystemTime::now());
    }
}

impl<Id: Clone + PartialEq + Send + 'static> MemoryEnrolments<Id> {
    fn record_now(&self, enrolment: Enrolment<Id>) -> Recorded {
        let mut state = self.state.lock();
        if let Some(row) = state.rows.get_mut(&enrolment.key) {
            if row.revoked_at.is_some() {
                return Recorded::Revoked;
            }
            if row.user != enrolment.user {
                return Recorded::HeldElsewhere;
            }
            row.last_seen = enrolment.issued_at;
            row.session = enrolment.session;
            row.descriptor.clone_from(&enrolment.descriptor);
        } else {
            state.rows.insert(
                enrolment.key,
                Row {
                    user: enrolment.user.clone(),
                    enrolled_at: enrolment.issued_at,
                    last_seen: enrolment.issued_at,
                    revoked_at: None,
                    session: enrolment.session,
                    descriptor: enrolment.descriptor.clone(),
                    attestation: enrolment.attestation,
                },
            );
        }
        state.grants.push(enrolment);
        Recorded::Granted
    }

    fn revoke_now(&self, user: Option<&Id>, key: KeyId, at: SystemTime) -> Revocation {
        let mut state = self.state.lock();
        match state.rows.get_mut(&key) {
            Some(row) if user.is_none_or(|user| *user == row.user) => {
                if row.revoked_at.is_some() {
                    Revocation::AlreadyRevoked {
                        session: row.session,
                    }
                } else {
                    row.revoked_at = Some(at);
                    Revocation::Revoked {
                        session: row.session,
                    }
                }
            }
            _ => Revocation::NotFound,
        }
    }
}

impl<Id: Clone + PartialEq + Send + Sync + 'static> EnrolmentStore<Id> for MemoryEnrolments<Id> {
    fn record(&self, enrolment: Enrolment<Id>) -> EnrolmentFuture<'_, Recorded> {
        Box::pin(core::future::ready(Ok(self.record_now(enrolment))))
    }

    fn devices<'a>(&'a self, user: &'a Id) -> EnrolmentFuture<'a, Vec<Device>> {
        let devices = self
            .state
            .lock()
            .rows
            .iter()
            .filter(|(_, row)| row.user == *user)
            .map(|(key, row)| Device {
                key: *key,
                enrolled_at: row.enrolled_at,
                last_seen: row.last_seen,
                revoked_at: row.revoked_at,
                descriptor: row.descriptor.clone(),
            })
            .collect();
        Box::pin(core::future::ready(Ok(devices)))
    }

    fn revoke<'a>(
        &'a self,
        user: Option<&'a Id>,
        key: KeyId,
        at: SystemTime,
    ) -> EnrolmentFuture<'a, Revocation> {
        Box::pin(core::future::ready(Ok(self.revoke_now(user, key, at))))
    }

    fn revoked_serials(&self, issuer: KeyId, now: SystemTime) -> EnrolmentFuture<'_, Vec<Revoked>> {
        let state = self.state.lock();
        let serials = state
            .grants
            .iter()
            .filter(|grant| grant.issuer == issuer && grant.expires_at > now)
            .filter_map(|grant| {
                let at = state.rows.get(&grant.key)?.revoked_at?;
                Some(Revoked {
                    serial: grant.serial.to_vec(),
                    at,
                })
            })
            .collect();
        Box::pin(core::future::ready(Ok(serials)))
    }

    fn next_list_number(&self, issuer: KeyId) -> EnrolmentFuture<'_, u64> {
        let mut state = self.state.lock();
        let number = state.numbers.entry(issuer).or_insert(0);
        *number += 1;
        let number = *number;
        Box::pin(core::future::ready(Ok(number)))
    }

    fn stored_attestation<'a>(
        &'a self,
        user: &'a Id,
        key: KeyId,
    ) -> EnrolmentFuture<'a, Option<AttestationLevel>> {
        let stored = self
            .state
            .lock()
            .rows
            .get(&key)
            .filter(|row| row.user == *user)
            .map(|row| row.attestation);
        Box::pin(core::future::ready(Ok(stored)))
    }
}

/// A nonce handed to a session, spent by the next enrolment request whatever its outcome.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PendingChallenge {
    nonce: [u8; 32],
    expires: Instant,
}

/// Revokes an auth-store session, which the deployment points at its auth service.
pub type SessionRevoker =
    Arc<dyn Fn(SessionId) -> core::pin::Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Why a device could not be revoked.
#[derive(Debug, thiserror::Error)]
pub enum RevokeError {
    /// No enrolment of that key, for the caller's account.
    #[error("no such device")]
    NotFound,
    /// No device enrolment is installed on the server.
    #[error("no device enrolment is installed")]
    NotInstalled,
    /// The enrolment table or the issuer failed.
    #[error("the device could not be revoked")]
    Unavailable(#[source] EnrolmentError),
}

/// The issuer settings, the table enrolments are recorded in, and the
/// revocation lists last published.
pub struct DeviceEnrolment<Id> {
    config: DeviceCertConfig,
    store: Arc<dyn EnrolmentStore<Id>>,
    random: SystemRandom,
    lists: tokio::sync::Mutex<Option<Vec<SignedList>>>,
    revoker: Option<SessionRevoker>,
    /// The attestation status list an Android chain's serials are checked against.
    status: Option<StatusList>,
    /// The time a certificate is issued at.
    clock: fn() -> SystemTime,
}

/// Seconds since the Unix epoch, zero before it.
fn secs(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

impl<Id: Clone + core::fmt::Display + 'static> DeviceEnrolment<Id> {
    /// Issue under `config`, recording into `store`.
    #[must_use]
    pub fn new(config: DeviceCertConfig, store: Arc<dyn EnrolmentStore<Id>>) -> Self {
        Self {
            config,
            store,
            random: SystemRandom::new(),
            lists: tokio::sync::Mutex::new(None),
            revoker: None,
            clock: SystemTime::now,
            status: None,
        }
    }

    /// Issue at the time `clock` reads, so a test stands in for a device
    /// whose clock differs from the server's.
    #[cfg(feature = "test-seams")]
    #[must_use]
    pub fn with_issue_clock(mut self, clock: fn() -> SystemTime) -> Self {
        self.clock = clock;
        self
    }

    /// Revoke the auth-store session a revoked device last enrolled with
    /// through `revoker`, so a stolen device still signed in cannot enrol a
    /// fresh key and undo the report.
    #[must_use]
    pub fn with_session_revoker(mut self, revoker: SessionRevoker) -> Self {
        self.revoker = Some(revoker);
        self
    }

    /// The attestation status list an Android chain's serials are checked
    /// against, fetched by the task the builder starts.
    #[must_use]
    pub fn with_status_list(mut self, list: StatusList) -> Self {
        self.status = Some(list);
        self
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
        let key = KeyId::of_public_key(csr.public_key());
        // The level the first enrolment recorded stands, whatever a renewal sends.
        let level = match self.store.stored_attestation(user, key).await {
            Ok(Some(stored)) => stored,
            Ok(None) => verify(
                &self.config,
                self.status.as_ref(),
                request.attestation.as_ref(),
                &request.csr,
                csr.public_key(),
            )
            .map_err(|_| EnrolRefusal::InvalidRequest)?,
            Err(err) => {
                tracing::warn!(error = %err, "the enrolment table refused the stored level");
                return Err(EnrolRefusal::IssuerUnavailable);
            }
        };
        if !self.config.accepted_attestation().contains(&level) {
            return Err(EnrolRefusal::AttestationRequired);
        }
        let lifetime = self
            .config
            .lifetime_for(request.lifetime_secs.map(Duration::from_secs))
            .map_err(|refused| match refused {
                LifetimeError::OverCeiling { ceiling } => EnrolRefusal::OverCeiling {
                    ceiling_secs: ceiling.as_secs(),
                },
            })?;
        let mut serial = [0; 16];
        self.random
            .fill(&mut serial)
            .map_err(|_| EnrolRefusal::IssuerUnavailable)?;
        let not_before = (self.clock)();
        let issuer = self.config.issuer();
        let leaf = issuer
            .issue(&csr, &user.to_string(), not_before, lifetime, serial, level)
            .map_err(|err| match err {
                IssueError::Identity(_) => EnrolRefusal::Unidentified,
                IssueError::OutlivesIssuer | IssueError::Validity | IssueError::Sign(_) => {
                    tracing::warn!(error = %err, "device certificate not issued");
                    EnrolRefusal::IssuerUnavailable
                }
            })?;
        let enrolment = Enrolment {
            user: user.clone(),
            key,
            serial,
            issuer: issuer.key_id(),
            issued_at: not_before,
            expires_at: not_before + lifetime,
            session,
            descriptor: request.descriptor,
            attestation: level,
        };
        match self.store.record(enrolment).await {
            Ok(Recorded::Granted) => Ok(EnrolGrant {
                request_id: request.request_id,
                chain: vec![leaf.into(), issuer.certificate().to_vec().into()],
                revocation_lists: self.lists().await.unwrap_or_default(),
            }),
            Ok(Recorded::Revoked) => Err(EnrolRefusal::Revoked),
            Ok(Recorded::HeldElsewhere | Recorded::UnreadableDescriptor) => {
                Err(EnrolRefusal::InvalidRequest)
            }
            Err(err) => {
                tracing::warn!(error = %err, "the enrolment table refused a record");
                Err(EnrolRefusal::IssuerUnavailable)
            }
        }
    }

    /// `user`'s devices, as the device list shows them.
    pub(crate) async fn devices(&self, user: &Id) -> Result<Vec<DeviceSummary>, EnrolmentError> {
        Ok(self
            .store
            .devices(user)
            .await?
            .into_iter()
            .map(|device| DeviceSummary {
                key_id: *device.key.as_bytes(),
                enrolled_at_secs: secs(device.enrolled_at),
                last_seen_secs: secs(device.last_seen),
                revoked_at_secs: device.revoked_at.map(secs),
                descriptor: device.descriptor,
            })
            .collect())
    }

    /// The lists last published, built on first use.
    ///
    /// # Errors
    ///
    /// [`EnrolmentError`] when the table or the issuer fails.
    pub async fn lists(&self) -> Result<Vec<SignedList>, EnrolmentError> {
        let mut lists = self.lists.lock().await;
        if let Some(lists) = lists.as_ref() {
            return Ok(lists.clone());
        }
        let built = self.build_lists().await?;
        *lists = Some(built.clone());
        Ok(built)
    }

    /// Sign a fresh list naming every unexpired serial of every revoked key,
    /// under the next number, and keep it as the published one.
    async fn publish(&self) -> Result<Vec<SignedList>, EnrolmentError> {
        let mut lists = self.lists.lock().await;
        let built = self.build_lists().await?;
        *lists = Some(built.clone());
        Ok(built)
    }

    /// One list per issuer still signing, the current one and every retired
    /// one not yet expired, then the root's lists as given.
    async fn build_lists(&self) -> Result<Vec<SignedList>, EnrolmentError> {
        let now = SystemTime::now();
        let mut lists = Vec::new();
        for issuer in self.config.signing_issuers(now) {
            let revoked = self.store.revoked_serials(issuer.key_id(), now).await?;
            let number = self.store.next_list_number(issuer.key_id()).await?;
            // No list promises a next one later than the longest certificate
            // it could name stays valid.
            let list = issuer.sign_list(number, &revoked, now, now + self.config.ceiling())?;
            lists.push(SignedList {
                list,
                signer: issuer.certificate().to_vec(),
            });
        }
        lists.extend_from_slice(self.config.root_lists());
        Ok(lists)
    }

    /// Revoke `key`, `user`'s when one is named, and publish the list that
    /// says so, repeating the publish when the key is already revoked.
    /// Answers whether the revocation is new, the session the key last
    /// enrolled with, and the lists, for the caller to close and push.
    ///
    /// # Errors
    ///
    /// [`RevokeError::NotFound`] for a key not enrolled, or not `user`'s, and
    /// [`RevokeError::Unavailable`] when the table or the issuer fails, the
    /// cached lists dropped so the next handshake or grant rebuilds them.
    pub(crate) async fn revoke(
        &self,
        user: Option<&Id>,
        key: KeyId,
    ) -> Result<(bool, SessionId, Vec<SignedList>), RevokeError> {
        let outcome = self
            .store
            .revoke(user, key, SystemTime::now())
            .await
            .map_err(RevokeError::Unavailable)?;
        let (fresh, session) = match outcome {
            Revocation::NotFound => return Err(RevokeError::NotFound),
            Revocation::AlreadyRevoked { session } => (false, session),
            Revocation::Revoked { session } => (true, session),
        };
        match self.publish().await {
            Ok(lists) => Ok((fresh, session, lists)),
            Err(err) => {
                *self.lists.lock().await = None;
                Err(RevokeError::Unavailable(err))
            }
        }
    }

    /// Revoke the auth-store session `session`, when a revoker is set.
    pub(crate) async fn revoke_session(&self, session: SessionId) {
        if let Some(revoker) = &self.revoker {
            revoker(session).await;
        }
    }
}
