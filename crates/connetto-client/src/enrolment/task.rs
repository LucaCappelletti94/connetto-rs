//! The task beside the pump that enrols, renews and reissues (decision 18),
//! one line of R74's lifecycle table per branch.

use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::time::SystemTime;

use std::collections::HashMap;

#[cfg(feature = "peer")]
use std::net::SocketAddr;

#[cfg(feature = "peer")]
use connetto_core::device_cert::DeviceIdentity;
use connetto_core::device_cert::{
    CertificateRequest, CertificateSigner, DeviceCertificate, DeviceDescriptor, DeviceKey, KeyHome,
    KeyId, RevocationList, certificate_key_id, certificate_serial, key_id, verify_chain,
};
use connetto_core::messages::{
    ControlMessage, DeviceSummary, DevicesRequest, EnrolChallengeRequest, EnrolRefusal,
    EnrolRequest, FatalErrorReason, RevokeDeviceRequest, SignedList, SyncStatus,
};
#[cfg(feature = "peer")]
use connetto_peer::{CloseReason, DiscoveryEvent, EXCHANGE_BOUND, LinkError, PeerEvent};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use super::{Answer, Held, KeptList, Standing, TOLERANCE, half_life};
#[cfg(feature = "peer")]
use crate::PeerError;
#[cfg(feature = "peer")]
use crate::bluetooth::{BluetoothError, HostId, JoinNearbyError, PROMPT_BOUND};
use crate::device_key::{ChipError, ChipKeys, KeyRecords, OpenedKey};
#[cfg(feature = "peer")]
use crate::hotspot::{HOST_BOUND, HotspotError, HotspotOffer, JOIN_BOUND, JoinError, MARGIN};
#[cfg(all(feature = "peer", target_os = "android"))]
use crate::multicast::MulticastLock;
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
    /// `link_peer` refused as expired, so the task raises the event (R76).
    #[cfg(feature = "peer")]
    CertificateExpired,
}

/// The peer node the task drives, the listener address it binds and the
/// node's link events (R76).
#[cfg(feature = "peer")]
pub(crate) struct Peer {
    /// The node presenting this device's identity.
    pub(crate) node: connetto_peer::Node,
    /// The discovery driver, browsing and dialing what it finds (R76).
    pub(crate) discovery: connetto_peer::Discovery,
    /// The address the listener binds.
    pub(crate) listen: SocketAddr,
    /// The node's link events, until the task reads them.
    pub(crate) events: mpsc::UnboundedReceiver<PeerEvent>,
    /// Discovery's events, until the task reads them.
    pub(crate) discovery_events: mpsc::UnboundedReceiver<connetto_peer::DiscoveryEvent>,
    /// The application's JNI access, for the multicast lock the browse holds
    /// (R76).
    #[cfg(all(feature = "peer", target_os = "android"))]
    pub(crate) java: Option<Arc<dyn crate::device_key::JavaAccess>>,
}

/// The next peer-link event, or nothing when the build has no peer link (R76).
#[cfg(feature = "peer")]
type NextPeerEvent = Option<connetto_peer::PeerEvent>;
#[cfg(not(feature = "peer"))]
type NextPeerEvent = core::convert::Infallible;

/// The peer link's event receiver, empty when the build has no peer link
/// (R76).
struct PeerEvents {
    #[cfg(feature = "peer")]
    rx: mpsc::UnboundedReceiver<connetto_peer::PeerEvent>,
}

impl PeerEvents {
    /// The next event, or a future that never resolves without the peer link.
    async fn next(&mut self) -> NextPeerEvent {
        #[cfg(feature = "peer")]
        {
            self.rx.recv().await
        }
        #[cfg(not(feature = "peer"))]
        {
            core::future::pending().await
        }
    }
}

/// The next discovery event, or nothing when the build has no peer link
/// (R76).
#[cfg(feature = "peer")]
type NextDiscoveryEvent = Option<connetto_peer::DiscoveryEvent>;
#[cfg(not(feature = "peer"))]
type NextDiscoveryEvent = core::convert::Infallible;

/// Discovery's event receiver, empty when the build has no peer link (R76).
struct DiscoveryEvents {
    #[cfg(feature = "peer")]
    rx: mpsc::UnboundedReceiver<connetto_peer::DiscoveryEvent>,
}

impl DiscoveryEvents {
    /// The next event, or a future that never resolves without the peer link.
    async fn next(&mut self) -> NextDiscoveryEvent {
        #[cfg(feature = "peer")]
        {
            self.rx.recv().await
        }
        #[cfg(not(feature = "peer"))]
        {
            core::future::pending().await
        }
    }
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
    /// Whether the local clock puts the held certificate outside its window
    /// (decision 29), shared with the handle so a dial reads the standing the
    /// task does (R76).
    clock_off: Arc<AtomicBool>,
    #[cfg(feature = "peer")]
    /// The fingerprint the device serves, its standing the peer node
    /// reports (R76).
    peer_serving: watch::Sender<Option<connetto_peer::Fingerprint>>,
    #[cfg(feature = "peer")]
    peer: Option<Peer>,
}

/// The application's half, held by the native client.
#[derive(Clone)]
pub(crate) struct EnrolHandle {
    keys: Arc<dyn DeviceKeys>,
    commands: mpsc::UnboundedSender<Command>,
    published: watch::Receiver<Option<DeviceCertificate>>,
    home: watch::Receiver<Option<KeyHome>>,
    #[cfg(feature = "peer")]
    /// The task's clock-off latch, its dials refusing by the window while it
    /// is set (R76).
    clock_off: Arc<AtomicBool>,
    #[cfg(feature = "peer")]
    peer: connetto_peer::Node,
    #[cfg(feature = "peer")]
    /// The hotspot machine's commands, until it ends with the client (R76).
    hotspot: mpsc::UnboundedSender<crate::hotspot::Command>,
    #[cfg(feature = "peer")]
    /// The Bluetooth machine's commands, until it ends with the client (R76).
    bluetooth: mpsc::UnboundedSender<crate::bluetooth::Command>,
    #[cfg(feature = "peer")]
    /// The fingerprint the device serves, once it serves (R76).
    peer_serving: watch::Receiver<Option<connetto_peer::Fingerprint>>,
}

impl Enroller {
    /// A task enrolling `keys` at `lifetime`, the server's default when
    /// `None`, sending `descriptor`, verifying against `roots`, starting
    /// from the certificate `held` and the lists `kept` the replica holds and
    /// taking pushed `lists`, steering the peer node `peer` (R76), and the
    /// handle that steers it.
    #[cfg_attr(
        feature = "peer",
        expect(
            clippy::too_many_arguments,
            reason = "the peer node and its hotspot and Bluetooth channels join the seven enrolment inputs and a config struct would hide the same arity behind another type"
        )
    )]
    pub(crate) fn new(
        keys: Arc<dyn DeviceKeys>,
        lifetime: Option<Duration>,
        descriptor: Vec<u8>,
        roots: Vec<Vec<u8>>,
        held: Option<Held>,
        kept: Vec<KeptList>,
        lists: super::ListInbox,
        #[cfg(feature = "peer")] peer: Peer,
        #[cfg(feature = "peer")] hotspot: mpsc::UnboundedSender<crate::hotspot::Command>,
        #[cfg(feature = "peer")] bluetooth: mpsc::UnboundedSender<crate::bluetooth::Command>,
    ) -> (Self, EnrolHandle) {
        let (sender, commands) = mpsc::unbounded_channel();
        let (published, observed) = watch::channel(held.as_ref().map(|held| held.leaf.clone()));
        let (home, homed) = watch::channel(None);
        let clock_off = Arc::new(AtomicBool::new(false));
        #[cfg(feature = "peer")]
        let peer_node = peer.node.clone();
        #[cfg(feature = "peer")]
        let (peer_serving, peer_serving_rx) = watch::channel(None);
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
                clock_off: Arc::clone(&clock_off),
                #[cfg(feature = "peer")]
                peer_serving,
                #[cfg(feature = "peer")]
                peer: Some(peer),
            },
            EnrolHandle {
                keys,
                commands: sender,
                published: observed,
                home: homed,
                #[cfg(feature = "peer")]
                clock_off,
                #[cfg(feature = "peer")]
                peer: peer_node,
                #[cfg(feature = "peer")]
                hotspot,
                #[cfg(feature = "peer")]
                bluetooth,
                #[cfg(feature = "peer")]
                peer_serving: peer_serving_rx,
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

    /// Where the device's peer listener binds, once the task serves (R76).
    #[cfg(feature = "peer")]
    pub(crate) fn peer_address(&self) -> Option<SocketAddr> {
        self.peer.local_addr()
    }

    /// Dial `addr`, refusing by the device's standing before any socket
    /// opens and handing back the peer's identity once the link is live
    /// (R76).
    #[cfg(feature = "peer")]
    pub(crate) async fn link_peer(&self, addr: SocketAddr) -> Result<DeviceIdentity, PeerError> {
        // A copy, so no watch guard is held across the dial.
        let held = self.published.borrow().clone();
        match Standing::of_leaf(held.as_ref(), SystemTime::now()) {
            Standing::NoKey => Err(PeerError::NoIdentity),
            Standing::Expired if self.clock_off.load(Ordering::Acquire) => {
                Err(PeerError::ClockOutsideWindow)
            }
            Standing::Expired => {
                let _ = self.commands.send(Command::CertificateExpired);
                Err(PeerError::CertificateExpired)
            }
            Standing::ClockOff => Err(PeerError::ClockOutsideWindow),
            Standing::Fresh | Standing::Aging => match self.peer.link(addr).await {
                Ok(peer) => Ok(peer),
                Err(LinkError::NotServing) => Err(PeerError::NoIdentity),
                Err(err) => Err(PeerError::Link(err)),
            },
        }
    }

    /// Host this device's hotspot, its beacon's outcome beside the offer,
    /// within the machines' bounds (R76).
    #[cfg(feature = "peer")]
    pub(crate) async fn host_hotspot(&self) -> Result<crate::bluetooth::Hosted, HotspotError> {
        let (reply, answer) = oneshot::channel();
        self.bluetooth
            .send(crate::bluetooth::Command::Host(reply))
            .map_err(|_| HotspotError::Failed)?;
        match tokio::time::timeout(HOST_BOUND + PROMPT_BOUND + MARGIN, answer).await {
            Ok(Ok(hosted)) => hosted,
            Ok(Err(_)) => Err(HotspotError::Failed),
            Err(_) => Err(HotspotError::TimedOut),
        }
    }

    /// Stop hosting, or cancel the pending request (R76).
    #[cfg(feature = "peer")]
    pub(crate) fn stop_hotspot(&self) {
        let _ = self.hotspot.send(crate::hotspot::Command::StopHost);
    }

    /// Join `offer`'s network, answered with its gateway, within the
    /// machine's bound (R76).
    #[cfg(feature = "peer")]
    pub(crate) async fn join_hotspot(
        &self,
        offer: &HotspotOffer,
    ) -> Result<std::net::IpAddr, JoinError> {
        let (reply, answer) = oneshot::channel();
        self.hotspot
            .send(crate::hotspot::Command::Join {
                offer: offer.clone(),
                reply,
            })
            .map_err(|_| JoinError::Failed)?;
        match tokio::time::timeout(JOIN_BOUND + MARGIN, answer).await {
            Ok(Ok(gateway)) => gateway,
            Ok(Err(_)) => Err(JoinError::Failed),
            Err(_) => Err(JoinError::TimedOut),
        }
    }

    /// Leave the joined network, or cancel the pending request (R76).
    #[cfg(feature = "peer")]
    pub(crate) fn leave_hotspot(&self) {
        let _ = self.hotspot.send(crate::hotspot::Command::Leave);
    }

    /// Enable Bluetooth, the platform's action inside the call, within the
    /// machine's bound (R76 decision 21).
    #[cfg(feature = "peer")]
    pub(crate) async fn enable_bluetooth(&self) -> Result<(), BluetoothError> {
        let (reply, answer) = oneshot::channel();
        self.bluetooth
            .send(crate::bluetooth::Command::Enable(reply))
            .map_err(|_| BluetoothError::Failed("the client is gone".into()))?;
        match tokio::time::timeout(PROMPT_BOUND + MARGIN, answer).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => Err(BluetoothError::Failed("the client is gone".into())),
            Err(_) => Err(BluetoothError::TimedOut),
        }
    }

    /// Join the nearby host's hotspot through the exchange, within the
    /// machines' bounds (R76 decision 19).
    #[cfg(feature = "peer")]
    pub(crate) async fn join_nearby(
        &self,
        host: &HostId,
    ) -> Result<std::net::IpAddr, JoinNearbyError> {
        let (reply, answer) = oneshot::channel();
        self.bluetooth
            .send(crate::bluetooth::Command::JoinNearby { host: *host, reply })
            .map_err(|_| JoinNearbyError::Join(JoinError::Failed))?;
        // A Bluetooth not yet ready runs its action first, within its own
        // bound, before the exchange and the join.
        match tokio::time::timeout(PROMPT_BOUND + EXCHANGE_BOUND + JOIN_BOUND + MARGIN, answer)
            .await
        {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => Err(JoinNearbyError::Join(JoinError::Failed)),
            Err(_) => Err(JoinNearbyError::Join(JoinError::TimedOut)),
        }
    }

    /// Fetch the nearby host's offer through the exchange, within the
    /// machine's bound (R76 decision 19).
    #[cfg(feature = "peer")]
    pub(crate) async fn fetch_offer(&self, host: &HostId) -> Result<HotspotOffer, BluetoothError> {
        let (reply, answer) = oneshot::channel();
        self.bluetooth
            .send(crate::bluetooth::Command::Fetch { host: *host, reply })
            .map_err(|_| BluetoothError::Failed("the client is gone".into()))?;
        // A Bluetooth not yet ready runs its action first, within its own
        // bound, before the exchange.
        match tokio::time::timeout(PROMPT_BOUND + EXCHANGE_BOUND + MARGIN, answer).await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) => Err(BluetoothError::Failed("the client is gone".into())),
            Err(_) => Err(BluetoothError::TimedOut),
        }
    }

    /// The scan's standing, at run time (R76 decision 19).
    #[cfg(feature = "peer")]
    pub(crate) fn set_hotspot_scan(&self, scan: bool) {
        let _ = self
            .bluetooth
            .send(crate::bluetooth::Command::SetScan(scan));
    }

    /// The autojoin's standing, at run time, implying the scan (R76 decision
    /// 19).
    #[cfg(feature = "peer")]
    pub(crate) fn set_hotspot_autojoin(&self, autojoin: bool) {
        let _ = self
            .bluetooth
            .send(crate::bluetooth::Command::SetAutojoin(autojoin));
    }

    /// The prompt's standing, at run time (R76 decision 21).
    #[cfg(feature = "peer")]
    pub(crate) fn set_bluetooth_prompt(&self, prompt: bool) {
        let _ = self
            .bluetooth
            .send(crate::bluetooth::Command::SetPrompt(prompt));
    }

    /// The fingerprint the device serves, once it serves (R76).
    #[cfg(feature = "peer")]
    pub(crate) fn peer_serving_fingerprint(&self) -> Option<connetto_peer::Fingerprint> {
        *self.peer_serving.borrow()
    }
}

/// How long to sleep before looking at `held` again.
pub(super) fn next_look(held: Option<&Held>, now: SystemTime) -> Duration {
    let Some(held) = held else {
        return RECHECK;
    };
    let (start, end) = (held.leaf.not_before(), held.leaf.not_after());
    match Standing::of(Some(held), now) {
        Standing::Fresh => half_life(held)
            .duration_since(now)
            .unwrap_or_default()
            .min(RECHECK),
        // The expiry wake reaches the exact moment, so a link never outlives
        // the window by the look's slack (R76 decision 9), and the hourly look
        // still retries a renewal and catches a jumped clock.
        Standing::Aging => (end + TOLERANCE)
            .duration_since(now)
            .unwrap_or_default()
            .min(RECHECK),
        Standing::ClockOff => (start - TOLERANCE)
            .duration_since(now)
            .unwrap_or_default()
            .min(RECHECK),
        Standing::Expired | Standing::NoKey => RECHECK,
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
    /// Whether the deployment refused the device's attestation level, so it
    /// asks again only on its next connection (decision 33).
    attestation_refused: bool,
    /// The peer node the task drives, its listener address and the standing
    /// it last acted on (R76).
    #[cfg(feature = "peer")]
    peer: connetto_peer::Node,
    #[cfg(feature = "peer")]
    peer_listen: SocketAddr,
    #[cfg(feature = "peer")]
    peer_standing: Standing,
    /// The peer link's events, until the task ends them (R76).
    peer_events: PeerEvents,
    /// The discovery driver, behind the peer link (R76).
    #[cfg(feature = "peer")]
    discovery: connetto_peer::Discovery,
    /// Discovery's events, until the task ends them (R76).
    discovery_events: DiscoveryEvents,
    /// The application's JNI access, for the multicast lock the browse holds
    /// (R76).
    #[cfg(all(feature = "peer", target_os = "android"))]
    java: Option<Arc<dyn crate::device_key::JavaAccess>>,
    /// The multicast lock the browse holds, until the standing leaves (R76).
    #[cfg(all(feature = "peer", target_os = "android"))]
    multicast: Option<MulticastLock>,
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
        // The evidence is sent only while the device holds no certificate
        // (decision 13), computed off the async runtime as the CSR is.
        let attestation = if self.held.is_some() {
            None
        } else {
            let key = Arc::clone(&key);
            let csr = csr.clone();
            tokio::task::spawn_blocking(move || match key.attestation(&csr)? {
                Some(own) => Ok(Some(own)),
                None => crate::device_key::app_attestation(&csr),
            })
            .await
            .map_err(|err| ClientError::DeviceChip(ChipError::Failed(Box::new(err))))
            .and_then(|attested| {
                attested.map_err(|err| ClientError::DeviceChip(ChipError::Failed(Box::new(err))))
            })
            .map_err(Failed::Device)?
        };
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
                    attestation,
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
            Err(Failed::Refused(EnrolRefusal::AttestationRequired)) if renewal => {
                // The level cannot change, so the device asks again only on
                // its next connection, keeping any certificate it holds
                // (lifecycle row "Refused as attestation required").
                self.attestation_refused = true;
                self.link.emit(ClientEvent::AttestationRequired);
                Err(CertificateError::Refused(EnrolRefusal::AttestationRequired))
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
            _ => self.enroller.clock_off.store(false, Ordering::Release),
        }
        #[cfg(feature = "peer")]
        self.peer_transition(standing).await;
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
        #[cfg(feature = "peer")]
        self.peer_stop(CloseReason::Withdrawn);
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
        #[cfg(feature = "peer")]
        self.peer_stop(CloseReason::Revoked);
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
            #[cfg(feature = "peer")]
            self.peer.keep_list(kept.list.clone(), kept.signer.clone());
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
            Standing::Expired if self.enroller.clock_off.load(Ordering::Acquire) => {
                Standing::ClockOff
            }
            standing => {
                self.enroller.clock_off.store(false, Ordering::Release);
                standing
            }
        }
    }

    /// Enter `ClockOff`, raising `ClockOutsideWindow` once (decision 29).
    fn clock_outside(&mut self, ahead: bool) {
        if !self.enroller.clock_off.swap(true, Ordering::Release) {
            self.link.emit(ClientEvent::ClockOutsideWindow { ahead });
        }
    }

    /// Re-evaluate the standing of the held certificate and let the peer link
    /// cross the row the standing crossed (R76).
    #[cfg(feature = "peer")]
    async fn stand_by(&mut self) -> Standing {
        let standing = self.standing(SystemTime::now());
        self.peer_transition(standing).await;
        standing
    }

    /// Re-evaluate the standing of the held certificate, in a build without
    /// the peer link.
    #[cfg(not(feature = "peer"))]
    fn stand_by(&mut self) -> std::future::Ready<Standing> {
        std::future::ready(self.standing(SystemTime::now()))
    }

    /// Serve or stop the peer listener as the standing the task crossed says
    /// (R76).
    #[cfg(feature = "peer")]
    async fn peer_transition(&mut self, after: Standing) {
        let before = self.peer_standing;
        self.peer_standing = after;
        match (before, after) {
            (_, Standing::Fresh | Standing::Aging) => self.peer_serve().await,
            (Standing::Fresh | Standing::Aging, Standing::Expired) => {
                self.peer_stop(CloseReason::CertificateExpired);
            }
            (Standing::Fresh | Standing::Aging, Standing::ClockOff) => {
                self.peer_stop(CloseReason::ClockOutsideWindow);
            }
            _ => {}
        }
    }

    /// Bind the peer listener and present the held identity, keeping the port
    /// and the live links when the identity changes (R76).
    #[cfg(feature = "peer")]
    async fn peer_serve(&mut self) {
        let (certificate, issuer) = match &self.held {
            Some(held) => (held.certificate.clone(), held.issuer.clone()),
            None => return,
        };
        let key = match self.key().await {
            Ok(key) => key,
            Err(err) => {
                tracing::warn!(error = %err, "the device key could not be opened, so the peer link waits");
                self.enroller.peer_serving.send_replace(None);
                return;
            }
        };
        let fingerprint = connetto_peer::Fingerprint::of(&certificate);
        let identity = connetto_peer::Identity {
            certificate,
            issuer,
            key,
        };
        match self.peer.serve(self.peer_listen, identity) {
            Ok(bound) => {
                #[cfg(all(feature = "peer", target_os = "android"))]
                if let Some(java) = self.java.clone() {
                    match MulticastLock::acquire(java) {
                        Ok(lock) => self.multicast = Some(lock),
                        Err(err) => tracing::warn!(
                            error = %err,
                            "the multicast lock will not hold, so the browse holds none"
                        ),
                    }
                }
                self.enroller.peer_serving.send_replace(Some(fingerprint));
                self.discovery.serve(bound.port(), fingerprint);
            }
            Err(err) => {
                tracing::warn!(error = %err, "the peer listener could not bind");
                self.enroller.peer_serving.send_replace(None);
                self.link.emit(ClientEvent::PeerListenFailed {
                    address: self.peer_listen,
                    error: err.to_string(),
                });
            }
        }
    }

    /// Close every peer link with `reason` and take the listener, which is a
    /// no-op when the node serves nothing (R76).
    #[cfg(feature = "peer")]
    fn peer_stop(&mut self, reason: CloseReason) {
        self.peer_standing = Standing::NoKey;
        self.enroller.peer_serving.send_replace(None);
        #[cfg(all(feature = "peer", target_os = "android"))]
        {
            self.multicast = None;
        }
        self.discovery.stop();
        self.peer.stop(reason);
    }

    /// Act on a live connection as the certificate's standing says
    /// (lifecycle rows "Connected and signed in", "Half-life crossed" and
    /// "Wall clock changes, or the hourly look"). The hourly look never
    /// renews a certificate the local clock puts outside its window.
    async fn on_connected(&mut self, by_look: bool) {
        // A refused level cannot change, so a refused device asks again only
        // on its next connection, never on the hourly look (lifecycle row
        // "Refused as attestation required").
        if self.attestation_refused {
            return;
        }
        let outcome = match self.stand_by().await {
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
#[expect(
    clippy::too_many_lines,
    reason = "the select's arms are the whole loop and splitting them would scatter the task's lifecycle"
)]
pub(crate) async fn run<L: Link>(link: L, mut enroller: Enroller) {
    let mut events = link.events();
    let held = enroller.held.take();
    #[cfg(feature = "peer")]
    let peer = enroller
        .peer
        .take()
        .expect("a peer build hands the task its node");
    let kept: HashMap<Vec<u8>, KeptList> = core::mem::take(&mut enroller.kept)
        .into_iter()
        .map(|kept| (kept.signer_key.clone(), kept))
        .collect();
    // The lists the replica keeps at open, for the node's handshakes (R76).
    #[cfg(feature = "peer")]
    for kept in kept.values() {
        peer.node.keep_list(kept.list.clone(), kept.signer.clone());
    }
    let mut run = Run {
        link,
        enroller,
        held,
        key: None,
        kept,
        withdrawn: None,
        attestation_refused: false,
        #[cfg(feature = "peer")]
        peer: peer.node,
        #[cfg(feature = "peer")]
        peer_listen: peer.listen,
        #[cfg(feature = "peer")]
        peer_standing: Standing::NoKey,
        #[cfg(feature = "peer")]
        peer_events: PeerEvents { rx: peer.events },
        #[cfg(feature = "peer")]
        discovery: peer.discovery,
        #[cfg(feature = "peer")]
        discovery_events: DiscoveryEvents {
            rx: peer.discovery_events,
        },
        #[cfg(all(feature = "peer", target_os = "android"))]
        java: peer.java,
        #[cfg(all(feature = "peer", target_os = "android"))]
        multicast: None,
        #[cfg(not(feature = "peer"))]
        peer_events: PeerEvents {},
        #[cfg(not(feature = "peer"))]
        discovery_events: DiscoveryEvents {},
    };
    // Opened at once, so a lost key is noticed before any connection.
    if let Err(err) = run.key().await {
        tracing::warn!(error = %err, "the device key could not be opened");
    }
    // Lifecycle row "Opened with the replica".
    let _ = run.stand_by().await;
    let mut due = run.link.connected().await;
    let mut by_look = false;
    let mut steering = true;
    loop {
        if !run.link.alive() {
            break;
        }
        if due {
            due = false;
            run.on_connected(by_look).await;
        }
        by_look = false;
        let look = next_look(run.held.as_ref(), SystemTime::now());
        tokio::select! {
            () = run.link.ended() => break,
            event = events.recv() => match event {
                Ok(ClientEvent::SyncStatus(SyncStatus::Connected)) | Err(RecvError::Lagged(_)) => {
                    run.attestation_refused = false;
                    due = true;
                }
                Ok(ClientEvent::ServerClosed { reason: FatalErrorReason::DeviceRevoked }) => {
                    run.revoked().await;
                }
                Ok(_) => {}
                Err(RecvError::Closed) => break,
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
                #[cfg(feature = "peer")]
                Some(Command::CertificateExpired) => {
                    run.link.emit(ClientEvent::CertificateExpired);
                }
                None => steering = false,
            },
            Some(lists) = run.enroller.lists.recv() => {
                run.take_lists(lists).await;
                if run.withdrawn.is_some() {
                    due = run.link.connected().await;
                }
            }
            peer = run.peer_events.next() => {
                #[cfg(feature = "peer")]
                if let Some(event) = peer {
                    run.discovery.on_node_event(&event);
                    match event {
                        PeerEvent::Linked { peer } => {
                            run.link.emit(ClientEvent::PeerLinked { peer });
                        }
                        PeerEvent::Unlinked { peer, reason } => {
                            run.link.emit(ClientEvent::PeerUnlinked { peer, reason });
                        }
                        PeerEvent::ListReceived { list, signer } => {
                            run.take_lists(vec![SignedList { list, signer }]).await;
                            if run.withdrawn.is_some() {
                                due = run.link.connected().await;
                            }
                        }
                    }
                }
                #[cfg(not(feature = "peer"))]
                match peer {}
            },
            discovery = run.discovery_events.next() => {
                #[cfg(feature = "peer")]
                if let Some(event) = discovery {
                    match event {
                        DiscoveryEvent::Found { address, fingerprint } => {
                            run.link
                                .emit(ClientEvent::PeerFound { address, fingerprint });
                        }
                        DiscoveryEvent::Gone { fingerprint } => {
                            run.link.emit(ClientEvent::PeerGone { fingerprint });
                        }
                    }
                }
                #[cfg(not(feature = "peer"))]
                match discovery {}
            },
            () = tokio::time::sleep(look) => {
                let _ = run.stand_by().await;
                due = run.link.connected().await;
                by_look = true;
            }
        }
    }
    // The task is done, so the peer link ends with it (R76).
    #[cfg(feature = "peer")]
    run.peer_stop(CloseReason::Closed);
}
