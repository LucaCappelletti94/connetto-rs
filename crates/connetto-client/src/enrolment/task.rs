//! The task beside the pump that enrols, renews and reissues (decision 18),
//! one line of R74's lifecycle table per branch.

use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::time::SystemTime;

use connetto_core::device_cert::{
    CertificateRequest, CertificateSigner, DeviceCertificate, DeviceKey, key_id,
};
use connetto_core::messages::{
    ControlMessage, EnrolChallengeRequest, EnrolRefusal, EnrolRequest, SyncStatus,
};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use super::{Answer, Held, Standing, half_life};
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
}

enum Command {
    Reissue {
        lifetime: Duration,
        reply: oneshot::Sender<Result<(), CertificateError>>,
    },
}

/// The task's half the builder hands to the client.
pub(crate) struct Enroller {
    keys: Arc<dyn DeviceKeys>,
    held: Option<Held>,
    lifetime: Option<Duration>,
    descriptor: Vec<u8>,
    commands: mpsc::UnboundedReceiver<Command>,
    published: watch::Sender<Option<DeviceCertificate>>,
}

/// The application's half, held by the native client.
pub(crate) struct EnrolHandle {
    keys: Arc<dyn DeviceKeys>,
    commands: mpsc::UnboundedSender<Command>,
    published: watch::Receiver<Option<DeviceCertificate>>,
}

impl Enroller {
    /// A task enrolling `keys` at `lifetime`, the server's default when
    /// `None`, sending `descriptor`, starting from the certificate `held`
    /// the replica holds, and the handle that steers it.
    pub(crate) fn new(
        keys: Arc<dyn DeviceKeys>,
        lifetime: Option<Duration>,
        descriptor: Vec<u8>,
        held: Option<Held>,
    ) -> (Self, EnrolHandle) {
        let (sender, commands) = mpsc::unbounded_channel();
        let (published, observed) = watch::channel(held.as_ref().map(|held| held.leaf.clone()));
        (
            Self {
                keys: Arc::clone(&keys),
                held,
                lifetime,
                descriptor,
                commands,
                published,
            },
            EnrolHandle {
                keys,
                commands: sender,
                published: observed,
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

    /// The certificate this device holds.
    pub(crate) fn certificate(&self) -> Option<DeviceCertificate> {
        self.published.borrow().clone()
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
        self.key = Some(Arc::clone(&key));
        Ok(key)
    }

    /// One challenge and one request, returning the granted chain.
    async fn exchange(
        &mut self,
        lifetime: Option<Duration>,
    ) -> Result<(Arc<dyn DeviceKey>, Vec<Vec<u8>>), Failed> {
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
        let Answer::Grant(chain) = answer(asked).await? else {
            return Err(unexpected());
        };
        Ok((key, chain))
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
            Ok((key, chain)) => self.keep(&*key, chain, lifetime).await,
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
        self.held = Some(held);
        self.publish();
        Ok(())
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
        self.held = None;
        self.publish();
        self.link.emit(ClientEvent::DeviceRevoked);
    }

    /// Act on a live connection as the certificate's standing says
    /// (lifecycle rows "Connected and signed in" and "Half-life crossed").
    async fn on_connected(&mut self) {
        let outcome = match Standing::of(self.held.as_ref(), SystemTime::now()) {
            Standing::Fresh => return,
            Standing::NoKey => self.request(self.enroller.lifetime, true).await,
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
    let mut run = Run {
        link,
        enroller,
        held,
        key: None,
    };
    // Opened at once, so a lost key is noticed before any connection.
    if let Err(err) = run.key().await {
        tracing::warn!(error = %err, "the device key could not be opened");
    }
    let mut due = run.link.connected().await;
    let mut steering = true;
    loop {
        if !run.link.alive() {
            return;
        }
        if due {
            due = false;
            run.on_connected().await;
        }
        let look = next_look(run.held.as_ref(), SystemTime::now());
        tokio::select! {
            () = run.link.ended() => return,
            event = events.recv() => match event {
                Ok(ClientEvent::SyncStatus(SyncStatus::Connected)) | Err(RecvError::Lagged(_)) => {
                    due = true;
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
                None => steering = false,
            },
            () = tokio::time::sleep(look) => due = run.link.connected().await,
        }
    }
}
