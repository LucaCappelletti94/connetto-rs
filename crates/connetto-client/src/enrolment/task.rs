//! The task beside the pump that enrols, renews and reissues (decision 18),
//! one line of R74's lifecycle table per branch.

use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::time::SystemTime;

use std::collections::HashMap;

use connetto_core::device_cert::{
    CertificateRequest, CertificateSigner, DeviceCertificate, DeviceDescriptor, DeviceKey, KeyHome,
    KeyId, RevocationList, certificate_key_id, certificate_serial, key_id, verify_chain,
};
use connetto_core::messages::{
    ControlMessage, DeviceSummary, DevicesRequest, EnrolChallengeRequest, EnrolRefusal,
    EnrolRequest, FatalErrorReason, RevokeDeviceRequest, SignedList, SyncStatus,
};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use super::{Answer, Held, KeptList, Standing, half_life};
use crate::device_key::{ChipError, ChipKeys, KeyRecords, OpenedKey};
use crate::{ClientError, ClientEvent};

/// How long one answer is waited for.
const ANSWER_WAIT: Duration = Duration::from_secs(30);
/// The longest sleep between two looks at the certificate, so a renewal that
/// failed is tried again and a wall clock that jumped is noticed.
const RECHECK: Duration = Duration::from_hours(1);

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why a certificate was not issued.
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    /// No server is reachable, or it did not answer in time.
    #[error("the server is not reachable")]
    Offline,
    /// The lifetime is over the server's ceiling, refused and never shortened.
    #[error("the lifetime is over the server's ceiling of {} s", .ceiling.as_secs())]
    OverCeiling {
        /// The longest lifetime the server grants.
        ceiling: Duration,
    },
    /// This device's key was revoked, so it and its certificate are deleted.
    #[error("this device's key was revoked")]
    Revoked,
    /// The server refused for another reason.
    #[error("the server refused the certificate: {0:?}")]
    Refused(EnrolRefusal),
    /// This build has no device identity (decision 21).
    #[error("this build has no device identity")]
    NoIdentity,
    /// The device key or the replica failed.
    #[error(transparent)]
    Device(ClientError),
}

/// Where a device's key is opened and deleted.
pub(crate) trait DeviceKeys: Send + Sync {
    /// Open the key, creating one when none is held.
    fn open(&self) -> BoxFuture<'_, Result<OpenedKey<Box<dyn DeviceKey>>, ClientError>>;
    /// Delete the key wherever it is held.
    fn delete(&self) -> BoxFuture<'_, Result<(), ClientError>>;
}

/// An account's key on this platform's chip, else in its secret store.
pub(crate) struct PlatformKeys<C, R> {
    pub(crate) chip: Arc<C>,
    pub(crate) records: R,
    pub(crate) service: String,
    pub(crate) account: String,
}

impl<C, R> DeviceKeys for PlatformKeys<C, R>
where
    C: ChipKeys + 'static,
    R: KeyRecords,
{
    fn open(&self) -> BoxFuture<'_, Result<OpenedKey<Box<dyn DeviceKey>>, ClientError>> {
        Box::pin(crate::device_key::open_device_key(
            Arc::clone(&self.chip),
            &self.records,
            &self.service,
            &self.account,
        ))
    }

    fn delete(&self) -> BoxFuture<'_, Result<(), ClientError>> {
        Box::pin(crate::device_key::delete_device_key(
            Arc::clone(&self.chip),
            &self.records,
            &self.service,
            &self.account,
        ))
    }
}

/// What the task needs of the running client.
pub(crate) trait Link: Send + Sync + 'static {
    /// Whether any handle on the client remains.
    fn alive(&self) -> bool;
    /// The client's event stream.
    fn events(&self) -> broadcast::Receiver<ClientEvent>;
    /// Emit `event` to the application.
    fn emit(&self, event: ClientEvent);
    /// Resolves once the pump has ended.
    fn ended(&self) -> impl Future<Output = ()> + Send;
    /// Whether a transport is attached.
    fn connected(&self) -> impl Future<Output = bool> + Send;
    /// Send `msg`, answered quoting `request_id`.
    fn ask(
        &self,
        request_id: String,
        msg: ControlMessage,
    ) -> impl Future<Output = Result<oneshot::Receiver<Answer>, ClientError>> + Send;
    /// Replace the certificate the replica holds.
    fn store(&self, held: Held) -> impl Future<Output = Result<(), ClientError>> + Send;
    /// Forget the certificate the replica holds.
    fn forget(&self) -> impl Future<Output = Result<(), ClientError>> + Send;
    /// Keep `kept` as its signer's list.
    fn store_list(&self, kept: KeptList) -> impl Future<Output = Result<(), ClientError>> + Send;
}

/// One enrolled device of the account, as the lost-device list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEntry<D> {
    /// The device key, which its certificate's identity names.
    pub key: KeyId,
    /// When the key first enrolled.
    pub enrolled_at: SystemTime,
    /// When the key last enrolled or renewed.
    pub last_seen: SystemTime,
    /// When the key was reported lost.
    pub revoked_at: Option<SystemTime>,
    /// What the device described itself as, `None` when it sent nothing this
    /// build's descriptor type reads.
    pub descriptor: Option<D>,
}

impl<D: DeviceDescriptor> DeviceEntry<D> {
    fn of(summary: &DeviceSummary) -> Self {
        let at = |secs: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        Self {
            key: KeyId::from_bytes(summary.key_id),
            enrolled_at: at(summary.enrolled_at_secs),
            last_seen: at(summary.last_seen_secs),
            revoked_at: summary.revoked_at_secs.map(at),
            descriptor: rmp_serde::from_slice(&summary.descriptor).ok(),
        }
    }
}

enum Command {
    Reissue {
        lifetime: Duration,
        reply: oneshot::Sender<Result<(), CertificateError>>,
    },
    Devices {
        reply: oneshot::Sender<Result<Vec<DeviceSummary>, CertificateError>>,
    },
    Revoke {
        key: KeyId,
        reply: oneshot::Sender<Result<(), CertificateError>>,
    },
}

/// The task's half the builder hands to the client.
pub(crate) struct Enroller {
    keys: Arc<dyn DeviceKeys>,
    held: Option<Held>,
    roots: Vec<Vec<u8>>,
    kept: Vec<KeptList>,
    lists: super::ListInbox,
    lifetime: Option<Duration>,
    descriptor: Vec<u8>,
    commands: mpsc::UnboundedReceiver<Command>,
    published: watch::Sender<Option<DeviceCertificate>>,
    home: watch::Sender<Option<KeyHome>>,
}

/// The application's half, held by the native client.
pub(crate) struct EnrolHandle {
    keys: Arc<dyn DeviceKeys>,
    commands: mpsc::UnboundedSender<Command>,
    published: watch::Receiver<Option<DeviceCertificate>>,
    home: watch::Receiver<Option<KeyHome>>,
}

impl Enroller {
    /// A task enrolling `keys` at `lifetime`, the server's default when
    /// `None`, sending `descriptor`, verifying against `roots`, starting
    /// from the certificate `held` and the lists `kept` the replica holds and
    /// taking pushed `lists`, and the handle that steers it.
    pub(crate) fn new(
        keys: Arc<dyn DeviceKeys>,
        lifetime: Option<Duration>,
        descriptor: Vec<u8>,
        roots: Vec<Vec<u8>>,
        held: Option<Held>,
        kept: Vec<KeptList>,
        lists: super::ListInbox,
    ) -> (Self, EnrolHandle) {
        let (sender, commands) = mpsc::unbounded_channel();
        let (published, observed) = watch::channel(held.as_ref().map(|held| held.leaf.clone()));
        let (home, homed) = watch::channel(None);
        (
            Self {
                keys: Arc::clone(&keys),
                held,
                roots,
                kept,
                lists,
                lifetime,
                descriptor,
                commands,
                published,
                home,
            },
            EnrolHandle {
                keys,
                commands: sender,
                published: observed,
                home: homed,
            },
        )
    }
}

impl EnrolHandle {
    /// Ask for a certificate at `lifetime` now.
    pub(crate) async fn reissue(&self, lifetime: Duration) -> Result<(), CertificateError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Reissue { lifetime, reply })
            .map_err(|_| CertificateError::Offline)?;
        answer.await.unwrap_or(Err(CertificateError::Offline))
    }

    /// The account's devices.
    pub(crate) async fn devices<D: DeviceDescriptor>(
        &self,
    ) -> Result<Vec<DeviceEntry<D>>, CertificateError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Devices { reply })
            .map_err(|_| CertificateError::Offline)?;
        let summaries = answer.await.unwrap_or(Err(CertificateError::Offline))?;
        Ok(summaries.iter().map(DeviceEntry::of).collect())
    }

    /// Report the device holding `key` lost.
    pub(crate) async fn revoke(&self, key: KeyId) -> Result<(), CertificateError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Revoke { key, reply })
            .map_err(|_| CertificateError::Offline)?;
        answer.await.unwrap_or(Err(CertificateError::Offline))
    }

    /// The certificate this device holds.
    pub(crate) fn certificate(&self) -> Option<DeviceCertificate> {
        self.published.borrow().clone()
    }

    /// Where the device key lives, once it is open.
    pub(crate) fn key_home(&self) -> Option<KeyHome> {
        *self.home.borrow()
    }

    /// Delete the device key wherever it is held.
    pub(crate) async fn delete_key(&self) -> Result<(), ClientError> {
        self.keys.delete().await
    }
}

/// How long to sleep before looking at `held` again.
pub(super) fn next_look(held: Option<&Held>, now: SystemTime) -> Duration {
    match (Standing::of(held, now), held) {
        (Standing::Fresh, Some(held)) => half_life(held)
            .duration_since(now)
            .unwrap_or_default()
            .min(RECHECK),
        _ => RECHECK,
    }
}

fn request_id() -> String {
    format!("enrol-{}", NEXT_REQUEST.fetch_add(1, Ordering::Relaxed))
}

/// Why one exchange produced no certificate.
enum Failed {
    Offline,
    Refused(EnrolRefusal),
    Device(ClientError),
}

impl From<Failed> for CertificateError {
    fn from(failed: Failed) -> Self {
        match failed {
            Failed::Offline => Self::Offline,
            Failed::Refused(EnrolRefusal::OverCeiling { ceiling_secs }) => Self::OverCeiling {
                ceiling: Duration::from_secs(ceiling_secs),
            },
            Failed::Refused(EnrolRefusal::Revoked) => Self::Revoked,
            Failed::Refused(reason) => Self::Refused(reason),
            Failed::Device(err) => Self::Device(err),
        }
    }
}

fn sent(err: ClientError) -> Failed {
    match err {
        ClientError::NotConnected | ClientError::Transport(_) => Failed::Offline,
        other => Failed::Device(other),
    }
}

async fn answer(receiver: oneshot::Receiver<Answer>) -> Result<Answer, Failed> {
    match tokio::time::timeout(ANSWER_WAIT, receiver).await {
        Ok(Ok(Answer::Refused(reason))) => Err(Failed::Refused(reason)),
        Ok(Ok(answer)) => Ok(answer),
        Ok(Err(_)) | Err(_) => Err(Failed::Offline),
    }
}

fn unexpected() -> Failed {
    Failed::Device(ClientError::Protocol(
        "an enrolment answer of the wrong kind".into(),
    ))
}

/// The task's state across its loop.
struct Run<L> {
    link: L,
    enroller: Enroller,
    held: Option<Held>,
    key: Option<Arc<dyn DeviceKey>>,
    kept: HashMap<Vec<u8>, KeptList>,
    /// A certificate the root withdrew, whose key enrols again.
    withdrawn: Option<Withdrawn>,
    /// Whether the local clock puts the held certificate outside its window
    /// (decision 29).
    clock_off: bool,
}

/// A certificate withdrawn because the root revoked its issuer.
struct Withdrawn {
    /// Its lifetime, which the re-enrolment asks for again.
    lifetime: Option<Duration>,
}

/// What the intake makes of a verified list against the one kept from the same signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Intake {
    /// Higher-numbered, or the first from its signer, so it replaces the kept one.
    Newer,
    /// The kept list itself, or an older one.
    Stale,
    /// The kept number with other content, which only a faulty or hostile
    /// signer produces, so it is logged and ignored.
    Conflicting,
}

pub(super) fn intake(kept: Option<&KeptList>, list: &RevocationList) -> Intake {
    match kept {
        None => Intake::Newer,
        Some(kept) if list.number() > kept.number => Intake::Newer,
        Some(kept) if list.number() == kept.number && list.der() != kept.list.as_slice() => {
            Intake::Conflicting
        }
        Some(_) => Intake::Stale,
    }
}

impl<L: Link> Run<L> {
    fn publish(&self) {
        self.enroller
            .published
            .send_replace(self.held.as_ref().map(|held| held.leaf.clone()));
    }

    /// The device key, opened on first use. A key made by this open replaces
    /// a lost one, so the certificate of the lost one goes (lifecycle row
    /// "Custody record missing at open").
    async fn key(&mut self) -> Result<Arc<dyn DeviceKey>, ClientError> {
        if let Some(key) = &self.key {
            return Ok(Arc::clone(key));
        }
        let opened = self.enroller.keys.open().await?;
        if opened.created && self.held.is_some() {
            self.link.forget().await?;
            self.held = None;
            self.publish();
        }
        let key: Arc<dyn DeviceKey> = Arc::from(opened.key);
        self.enroller.home.send_replace(Some(key.home()));
        self.key = Some(Arc::clone(&key));
        Ok(key)
    }

    /// One challenge and one request, returning the granted chain.
    async fn exchange(
        &mut self,
        lifetime: Option<Duration>,
    ) -> Result<(Arc<dyn DeviceKey>, Vec<Vec<u8>>, Vec<SignedList>), Failed> {
        let key = self.key().await.map_err(Failed::Device)?;
        let id = request_id();
        let asked = self
            .link
            .ask(
                id.clone(),
                ControlMessage::EnrolChallengeRequest(EnrolChallengeRequest { request_id: id }),
            )
            .await
            .map_err(sent)?;
        let Answer::Challenge(nonce) = answer(asked).await? else {
            return Err(unexpected());
        };
        let signer = Arc::clone(&key);
        let csr = tokio::task::spawn_blocking(move || {
            CertificateRequest::build(&CertificateSigner::new(&*signer), &nonce)
        })
        .await
        .map_err(|err| ClientError::DeviceChip(ChipError::Failed(Box::new(err))))
        .and_then(|built| {
            built.map_err(|err| ClientError::DeviceChip(ChipError::Failed(Box::new(err))))
        })
        .map_err(Failed::Device)?;
        let id = request_id();
        let asked = self
            .link
            .ask(
                id.clone(),
                ControlMessage::EnrolRequest(EnrolRequest {
                    request_id: id,
                    csr,
                    lifetime_secs: lifetime.map(|lifetime| lifetime.as_secs()),
                    descriptor: self.enroller.descriptor.clone(),
                }),
            )
            .await
            .map_err(sent)?;
        let Answer::Grant(chain, lists) = answer(asked).await? else {
            return Err(unexpected());
        };
        Ok((key, chain, lists))
    }

    /// Ask for a certificate at `lifetime` and keep what is granted. A
    /// renewal, unlike a caller's request, retries over a lowered ceiling at
    /// the ceiling (lifecycle row "Refused over ceiling").
    async fn request(
        &mut self,
        lifetime: Option<Duration>,
        renewal: bool,
    ) -> Result<(), CertificateError> {
        let mut lifetime = lifetime;
        let outcome = match self.exchange(lifetime).await {
            Err(Failed::Refused(EnrolRefusal::OverCeiling { ceiling_secs })) if renewal => {
                let ceiling = Duration::from_secs(ceiling_secs);
                self.link.emit(ClientEvent::CertificateLifetimeCapped {
                    requested: lifetime.unwrap_or_default(),
                    ceiling,
                });
                lifetime = Some(ceiling);
                self.exchange(lifetime).await
            }
            other => other,
        };
        match outcome {
            Ok((key, chain, lists)) => {
                self.keep(&*key, chain, lifetime).await?;
                self.take_lists(lists).await;
                Ok(())
            }
            Err(Failed::Refused(EnrolRefusal::Revoked)) => {
                self.revoked().await;
                Err(CertificateError::Revoked)
            }
            Err(failed) => Err(failed.into()),
        }
    }

    /// Store the granted chain, after checking it certifies this device's key
    /// (lifecycle row "Grant received").
    async fn keep(
        &mut self,
        key: &dyn DeviceKey,
        mut chain: Vec<Vec<u8>>,
        lifetime: Option<Duration>,
    ) -> Result<(), CertificateError> {
        let protocol = |detail: &str| {
            CertificateError::Device(ClientError::Protocol(format!(
                "the granted certificate {detail}"
            )))
        };
        if chain.len() < 2 {
            return Err(protocol("comes without its issuer"));
        }
        let issuer = chain.swap_remove(1);
        let certificate = chain.swap_remove(0);
        verify_chain(&certificate, &issuer, &self.enroller.roots)
            .map_err(|_| protocol("does not chain to a deployment root"))?;
        let leaf = DeviceCertificate::parse(&certificate)
            .map_err(|_| protocol("is not a device certificate"))?;
        if leaf.identity().key() != key_id(key) {
            return Err(protocol("names another key"));
        }
        let held = Held {
            leaf,
            certificate,
            issuer,
            lifetime,
        };
        self.link
            .store(held.clone())
            .await
            .map_err(CertificateError::Device)?;
        let standing = Standing::of(Some(&held), SystemTime::now());
        self.held = Some(held);
        self.publish();
        // The server just issued it, so a window that does not hold it now
        // says the local clock is off (lifecycle row "Grant received").
        match standing {
            Standing::ClockOff => self.clock_outside(false),
            Standing::Expired => self.clock_outside(true),
            _ => self.clock_off = false,
        }
        Ok(())
    }

    /// Delete a certificate whose issuer the root revoked, keep the key, and
    /// say so, the key enrolling again when connected (decision 24).
    async fn withdraw(&mut self) {
        let lifetime = self.held.as_ref().and_then(|held| held.lifetime);
        if let Err(err) = self.link.forget().await {
            tracing::warn!(error = %err, "the withdrawn certificate could not be deleted");
        }
        self.held = None;
        self.withdrawn = Some(Withdrawn { lifetime });
        self.publish();
        self.link.emit(ClientEvent::CertificateWithdrawn);
    }

    /// Delete the key and certificate of a revoked device and say so
    /// (lifecycle row "Refused as revoked").
    async fn revoked(&mut self) {
        if let Err(err) = self.enroller.keys.delete().await {
            tracing::warn!(error = %err, "the revoked device key could not be deleted");
        }
        if let Err(err) = self.link.forget().await {
            tracing::warn!(error = %err, "the revoked certificate could not be deleted");
        }
        self.key = None;
        self.enroller.home.send_replace(None);
        self.held = None;
        self.publish();
        self.link.emit(ClientEvent::DeviceRevoked);
    }

    /// Keep each verified list newer than the one kept from its signer, and
    /// take this device's own listed certificate as its revocation (lifecycle
    /// row "Newer list from server or peer", decision 22).
    async fn take_lists(&mut self, lists: Vec<SignedList>) {
        for signed in lists {
            let list =
                match RevocationList::verify(&signed.list, &signed.signer, &self.enroller.roots) {
                    Ok(list) => list,
                    Err(err) => {
                        tracing::warn!(error = %err, "a revocation list was refused");
                        continue;
                    }
                };
            let signer_key = list.issuer().as_bytes().to_vec();
            let from_root = self
                .enroller
                .roots
                .iter()
                .any(|root| root.as_slice() == signed.signer.as_slice());
            match intake(self.kept.get(&signer_key), &list) {
                Intake::Stale => continue,
                Intake::Conflicting => {
                    tracing::warn!(
                        number = list.number(),
                        "a revocation list repeats a kept number with other content"
                    );
                    continue;
                }
                Intake::Newer => {}
            }
            let kept = KeptList {
                signer_key: signer_key.clone(),
                number: list.number(),
                list: signed.list,
                signer: signed.signer,
            };
            if let Err(err) = self.link.store_list(kept.clone()).await {
                tracing::warn!(error = %err, "a revocation list could not be kept");
                continue;
            }
            self.kept.insert(signer_key, kept);
            let own = self.held.as_ref().is_some_and(|held| {
                certificate_key_id(&held.issuer).is_ok_and(|issuer| issuer == list.issuer())
                    && list.revokes(held.leaf.serial())
            });
            let issuer_revoked = from_root
                && self.held.as_ref().is_some_and(|held| {
                    certificate_serial(&held.issuer).is_ok_and(|serial| list.revokes(&serial))
                });
            if own {
                self.revoked().await;
            } else if issuer_revoked {
                self.withdraw().await;
            }
        }
    }

    /// One request and its one answer, for the device list and reports.
    async fn ask_once(&self, msg: impl FnOnce(String) -> ControlMessage) -> Result<Answer, Failed> {
        let id = request_id();
        let asked = self.link.ask(id.clone(), msg(id)).await.map_err(sent)?;
        answer(asked).await
    }

    async fn devices(&self) -> Result<Vec<DeviceSummary>, CertificateError> {
        match self
            .ask_once(|request_id| ControlMessage::DevicesRequest(DevicesRequest { request_id }))
            .await?
        {
            Answer::Devices(devices) => Ok(devices),
            _ => Err(unexpected().into()),
        }
    }

    async fn revoke(&self, key: KeyId) -> Result<(), CertificateError> {
        match self
            .ask_once(|request_id| {
                ControlMessage::RevokeDeviceRequest(RevokeDeviceRequest {
                    request_id,
                    key_id: *key.as_bytes(),
                })
            })
            .await?
        {
            Answer::Revoked => Ok(()),
            _ => Err(unexpected().into()),
        }
    }

    /// Where the held certificate stands, re-evaluating the window: a
    /// certificate not yet valid enters `ClockOff`, one the window holds
    /// leaves it, and one expired by a clock already known to run ahead stays
    /// in it (lifecycle row "Wall clock changes, or the hourly look").
    fn standing(&mut self, now: SystemTime) -> Standing {
        match Standing::of(self.held.as_ref(), now) {
            Standing::ClockOff => {
                self.clock_outside(false);
                Standing::ClockOff
            }
            Standing::Expired if self.clock_off => Standing::ClockOff,
            standing => {
                self.clock_off = false;
                standing
            }
        }
    }

    /// Enter `ClockOff`, raising `ClockOutsideWindow` once (decision 29).
    fn clock_outside(&mut self, ahead: bool) {
        if !self.clock_off {
            self.clock_off = true;
            self.link.emit(ClientEvent::ClockOutsideWindow { ahead });
        }
    }

    /// Act on a live connection as the certificate's standing says
    /// (lifecycle rows "Connected and signed in", "Half-life crossed" and
    /// "Wall clock changes, or the hourly look"). The hourly look never
    /// renews a certificate the local clock puts outside its window.
    async fn on_connected(&mut self, by_look: bool) {
        let outcome = match self.standing(SystemTime::now()) {
            Standing::Fresh => return,
            Standing::ClockOff if by_look => return,
            Standing::NoKey => {
                let lifetime = self
                    .withdrawn
                    .take()
                    .map_or(self.enroller.lifetime, |withdrawn| withdrawn.lifetime);
                self.request(lifetime, true).await
            }
            Standing::Aging | Standing::Expired | Standing::ClockOff => {
                let lifetime = self.held.as_ref().and_then(|held| held.lifetime);
                self.request(lifetime, true).await
            }
        };
        if let Err(err) = outcome {
            tracing::warn!(error = %err, "the device certificate was not issued");
        }
    }
}

/// Run the enrolment task until the client ends.
pub(crate) async fn run<L: Link>(link: L, mut enroller: Enroller) {
    let mut events = link.events();
    let held = enroller.held.take();
    let kept = core::mem::take(&mut enroller.kept)
        .into_iter()
        .map(|kept| (kept.signer_key.clone(), kept))
        .collect();
    let mut run = Run {
        link,
        enroller,
        held,
        key: None,
        kept,
        withdrawn: None,
        clock_off: false,
    };
    // Opened at once, so a lost key is noticed before any connection.
    if let Err(err) = run.key().await {
        tracing::warn!(error = %err, "the device key could not be opened");
    }
    // Lifecycle row "Opened with the replica".
    run.standing(SystemTime::now());
    let mut due = run.link.connected().await;
    let mut by_look = false;
    let mut steering = true;
    loop {
        if !run.link.alive() {
            return;
        }
        if due {
            due = false;
            run.on_connected(by_look).await;
        }
        by_look = false;
        let look = next_look(run.held.as_ref(), SystemTime::now());
        tokio::select! {
            () = run.link.ended() => return,
            event = events.recv() => match event {
                Ok(ClientEvent::SyncStatus(SyncStatus::Connected)) | Err(RecvError::Lagged(_)) => {
                    due = true;
                }
                Ok(ClientEvent::ServerClosed { reason: FatalErrorReason::DeviceRevoked }) => {
                    run.revoked().await;
                }
                Ok(_) => {}
                Err(RecvError::Closed) => return,
            },
            command = run.enroller.commands.recv(), if steering => match command {
                Some(Command::Reissue { lifetime, reply }) => {
                    let outcome = if run.link.connected().await {
                        run.request(Some(lifetime), false).await
                    } else {
                        Err(CertificateError::Offline)
                    };
                    let _ = reply.send(outcome);
                }
                Some(Command::Devices { reply }) => {
                    let _ = reply.send(run.devices().await);
                }
                Some(Command::Revoke { key, reply }) => {
                    let _ = reply.send(run.revoke(key).await);
                }
                None => steering = false,
            },
            Some(lists) = run.enroller.lists.recv() => {
                run.take_lists(lists).await;
                if run.withdrawn.is_some() {
                    due = run.link.connected().await;
                }
            }
            () = tokio::time::sleep(look) => {
                due = run.link.connected().await;
                by_look = true;
            }
        }
    }
}
