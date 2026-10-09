//! The Bluetooth beacon and the exchange over it (R76).
//!
//! The machine is a small loop beside the hotspot machine's. An API method
//! sends a command, the machine looks at its backends on a tick, and applies
//! the beacon and joiner tables to the answers, the events and the seams the
//! client gave it. The proofs drive the tables through fake backends, and the
//! Android backend reaches the bundled plugin through the application's JNI
//! access.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::device_cert::DeviceIdentity;
use connetto_peer::{
    Beacon, ChunkStream, EXCHANGE_BOUND, ExchangeError, Fingerprint, Node, OfferFrame,
};
use tokio::sync::{mpsc, oneshot, watch};

use crate::ClientEvent;
use crate::hotspot::{
    HotspotError, HotspotOffer, HotspotSecurity, JOIN_BOUND, JoinError, MARGIN, Reply, TICK,
};

#[cfg(target_os = "android")]
mod android;

#[cfg(target_os = "android")]
pub(crate) use android::AndroidBluetoothBackend;

/// The pace of the machine's look while an exchange runs.
const FAST_TICK: Duration = Duration::from_millis(20);
/// The time a prompt action gets (R76 decision 21).
pub(crate) const PROMPT_BOUND: Duration = Duration::from_secs(60);
/// The time a host's beacon goes unseen before it is reported gone.
const GONE_AFTER: Duration = Duration::from_secs(30);
/// The exchanges a host runs at once, the fifth connection refused (R76).
const MAX_EXCHANGES: usize = 4;
/// The GATT header the negotiated packet size leaves to the chunks.
const CHUNK_OVERHEAD: usize = 3;
/// The longest attribute value GATT allows, which a notification or a write
/// cannot pass however large the packet.
const MAX_ATTRIBUTE_VALUE: usize = 512;

/// The device of a nearby host, the key the platform's Bluetooth stands on.
pub type HostId = u64;

/// The platform's Bluetooth, as the client reads it (R76 decision 21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BluetoothState {
    /// The radio is on and the permissions are granted.
    Ready,
    /// The radio is off.
    Off,
    /// A permission is not granted.
    NotPermitted,
    /// This system has no Bluetooth.
    Unsupported,
}

impl std::fmt::Display for BluetoothState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Ready => "ready",
            Self::Off => "off",
            Self::NotPermitted => "not permitted",
            Self::Unsupported => "unsupported",
        };
        f.write_str(text)
    }
}

/// The platform's prompt action, once it finishes (R76 decision 21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptOutcome {
    /// No action ran, the standing was already the call's.
    NotAsked,
    /// The user declined it.
    Declined,
    /// The system showed the settings pane instead.
    SentToSettings,
    /// The action could not be shown.
    Blocked,
}

/// The reasons a Bluetooth call will not go (R76).
#[derive(Debug, thiserror::Error)]
pub enum BluetoothError {
    /// Bluetooth is off, with the prompt's outcome.
    #[error("Bluetooth is off, the prompt {0}")]
    Off(PromptOutcome),
    /// The Bluetooth permissions are not granted, with the prompt's outcome.
    #[error("the Bluetooth permissions are not granted {missing:?}, the prompt {outcome}")]
    NotPermitted {
        /// The missing permissions' names.
        missing: Vec<String>,
        /// The prompt's outcome.
        outcome: PromptOutcome,
    },
    /// This system has no Bluetooth.
    #[error("this system has no Bluetooth")]
    Unsupported,
    /// An exchange is already running.
    #[error("an exchange is already running")]
    Busy,
    /// The exchange failed, with the link's reason.
    #[error(transparent)]
    Exchange(#[from] ExchangeError),
    /// The exchange did not finish within its bound.
    #[error("the exchange did not finish within its bound")]
    TimedOut,
    /// The platform's Bluetooth failed.
    #[error("the platform's Bluetooth failed: {0}")]
    Failed(String),
}

impl std::fmt::Display for PromptOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NotAsked => "not asked",
            Self::Declined => "declined",
            Self::SentToSettings => "sent to settings",
            Self::Blocked => "blocked",
        };
        f.write_str(text)
    }
}

/// The reasons a nearby join will not go (R76).
#[derive(Debug, thiserror::Error)]
pub enum JoinNearbyError {
    /// Bluetooth will not go, with the reason.
    #[error(transparent)]
    Bluetooth(#[from] BluetoothError),
    /// The exchange's offer could not be joined, with the hotspot's reason.
    #[error(transparent)]
    Join(#[from] JoinError),
}

/// The answer a `host_hotspot` call gets (R76).
#[derive(Debug)]
pub struct Hosted {
    /// The hotspot's details.
    pub offer: HotspotOffer,
    /// The beacon's outcome, the refusal beside a still-unavailable radio.
    pub beacon: Result<(), BluetoothError>,
}

/// The host's beacon standing, for the application's panel (R76).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeaconState {
    /// Advertising, under the beacon's prefix.
    Advertising {
        /// The first 8 bytes of the presented leaf's fingerprint.
        prefix: [u8; 8],
    },
    /// Off, with the reason.
    Off {
        /// Why the beacon is not advertising.
        reason: &'static str,
    },
}

/// An event the host's GATT service reports (R76).
#[cfg_attr(
    not(target_os = "android"),
    expect(
        dead_code,
        reason = "the platform backends construct these events, a non-Android build reads them through the tables only"
    )
)]
#[derive(Clone, Debug)]
pub enum PeripheralEvent {
    /// A joiner connected, with the negotiated packet size.
    Connected {
        /// The device's key.
        device: u64,
        /// The negotiated packet size.
        mtu: u16,
    },
    /// A chunk the joiner wrote.
    Chunk {
        /// The device's key.
        device: u64,
        /// The chunk's bytes.
        bytes: Vec<u8>,
    },
    /// A joiner disconnected.
    Disconnected {
        /// The device's key.
        device: u64,
    },
    /// The platform's Bluetooth failed.
    Failed(String),
}

/// An event the joiner's central reports (R76).
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the central's backend arrives with btleplug (R76 decision 20), so only the proofs construct these events"
    )
)]
#[derive(Clone, Debug)]
pub enum CentralEvent {
    /// A beacon was seen, with its service data and signal.
    Seen {
        /// The host's key.
        host: HostId,
        /// The beacon's service data.
        service_data: Vec<u8>,
        /// The signal's strength.
        rssi: i16,
    },
    /// The host connected, with the negotiated packet size.
    Connected {
        /// The host's key.
        host: HostId,
        /// The negotiated packet size.
        mtu: u16,
    },
    /// A chunk the host notified.
    Chunk {
        /// The host's key.
        host: HostId,
        /// The chunk's bytes.
        bytes: Vec<u8>,
    },
    /// The host disconnected.
    Disconnected {
        /// The host's key.
        host: HostId,
    },
}

/// The platform's Bluetooth readiness, polled by the machine (R76 decision 21).
pub trait ReadinessBackend: Send + Sync {
    /// The platform's standing.
    fn state(&self) -> BluetoothState;
    /// The permissions not granted, by name.
    fn missing_permissions(&self) -> Vec<String>;
    /// Start the platform's action the waiting call wants.
    fn prompt(&self) -> Result<(), BluetoothError>;
    /// The finished action's outcome, `None` while it runs.
    fn prompt_outcome(&self) -> Option<PromptOutcome>;
}

/// The host's GATT service and advertisement, polled by the machine (R76).
pub trait PeripheralBackend: Send + Sync {
    /// Start the advertisement and the service under `beacon`.
    fn start(&self, beacon: [u8; 9]) -> Result<(), BluetoothError>;
    /// Stop the advertisement and close the service.
    fn stop(&self);
    /// The service's events, drained.
    fn poll(&self) -> Vec<PeripheralEvent>;
    /// Write a chunk to the device's characteristic.
    fn notify(&self, device: u64, bytes: &[u8]) -> Result<(), BluetoothError>;
    /// End the device's connection.
    fn disconnect(&self, device: u64);
}

/// The joiner's central, polled by the machine (R76).
pub trait CentralBackend: Send + Sync {
    /// Start scanning for the beacon.
    fn start_scan(&self);
    /// Stop scanning.
    fn stop_scan(&self);
    /// The central's events, drained.
    fn poll(&self) -> Vec<CentralEvent>;
    /// Connect to the host.
    fn connect(&self, host: HostId);
    /// Write a chunk to the host's characteristic.
    fn write(&self, host: HostId, bytes: &[u8]) -> Result<(), BluetoothError>;
    /// End the host's connection.
    fn disconnect(&self, host: HostId);
}

/// The backends on a system with no Bluetooth.
pub struct UnsupportedBackend;

impl ReadinessBackend for UnsupportedBackend {
    fn state(&self) -> BluetoothState {
        BluetoothState::Unsupported
    }

    fn missing_permissions(&self) -> Vec<String> {
        Vec::new()
    }

    fn prompt(&self) -> Result<(), BluetoothError> {
        Err(BluetoothError::Unsupported)
    }

    fn prompt_outcome(&self) -> Option<PromptOutcome> {
        Some(PromptOutcome::NotAsked)
    }
}

impl PeripheralBackend for UnsupportedBackend {
    fn start(&self, _beacon: [u8; 9]) -> Result<(), BluetoothError> {
        Err(BluetoothError::Unsupported)
    }

    fn stop(&self) {}

    fn poll(&self) -> Vec<PeripheralEvent> {
        Vec::new()
    }

    fn notify(&self, _device: u64, _bytes: &[u8]) -> Result<(), BluetoothError> {
        Err(BluetoothError::Unsupported)
    }

    fn disconnect(&self, _device: u64) {}
}

/// A system's readiness, its peripheral, and its central where it runs one.
pub(crate) type Backends = (
    Arc<dyn ReadinessBackend>,
    Arc<dyn PeripheralBackend>,
    Option<Arc<dyn CentralBackend>>,
);

/// The backends on a system with no Bluetooth, which runs no central.
pub(crate) fn unsupported_backends() -> Backends {
    (
        Arc::new(UnsupportedBackend) as Arc<dyn ReadinessBackend>,
        Arc::new(UnsupportedBackend) as Arc<dyn PeripheralBackend>,
        None,
    )
}

/// The bytes one chunk carries over a connection of `mtu`, within both the
/// packet and the longest attribute value GATT allows.
fn chunk_size(mtu: u16) -> usize {
    usize::from(mtu)
        .saturating_sub(CHUNK_OVERHEAD)
        .clamp(1, MAX_ATTRIBUTE_VALUE)
}

/// The offer the machine hands the exchange, from the hotspot's.
fn offer_frame(offer: &HotspotOffer) -> OfferFrame {
    let security = match offer.security {
        HotspotSecurity::Wpa2 => 0,
        HotspotSecurity::Wpa3 => 1,
    };
    OfferFrame::new(
        offer.ssid.clone(),
        offer.passphrase.clone(),
        security,
        offer.port,
    )
}

/// The hotspot's offer, from the exchange's.
fn hotspot_offer(frame: &OfferFrame) -> HotspotOffer {
    let security = match frame.security {
        0 => HotspotSecurity::Wpa2,
        // A code the platform does not name keeps the stronger security.
        _ => HotspotSecurity::Wpa3,
    };
    HotspotOffer::new(
        frame.ssid.clone(),
        frame.passphrase().to_owned(),
        security,
        frame.port,
    )
}

/// A stream error the machine names when its own channel fails.
fn channel_error(text: &'static str) -> ExchangeError {
    ExchangeError::Io(io::Error::new(io::ErrorKind::BrokenPipe, text))
}

/// The host side's exchanges (R76).
struct HostExchange {
    /// The stream's reader, the joiner's chunks in order.
    inbound: mpsc::Sender<Vec<u8>>,
    /// The stream's writer, the host's chunks out of order.
    outbound: mpsc::Receiver<Vec<u8>>,
    /// The exchange's answer, once it ends.
    reply: oneshot::Receiver<Result<DeviceIdentity, ExchangeError>>,
    /// The bound the exchange gets.
    deadline: tokio::time::Instant,
}

/// The host's beacon standing (R76).
enum HostBtState {
    /// Not advertising.
    Off,
    /// Advertising under `prefix`, with the running exchanges.
    Advertising {
        /// The beacon's prefix the advertisement carries.
        prefix: [u8; 8],
        /// The exchanges running beneath the cap.
        exchanges: HashMap<u64, HostExchange>,
    },
}

/// The manual exchange's answer, by its kind.
enum ManualReply {
    /// The offer the fetch answers.
    Fetch(Reply<Result<HotspotOffer, BluetoothError>>),
    /// The gateway the join answers.
    Join(Reply<Result<IpAddr, JoinNearbyError>>),
}

/// The exchange's kind, what its offer goes to (R76).
enum Kind {
    /// The fetch's, answered to the caller.
    Fetch,
    /// The join's, handed to `join_hotspot`.
    Join,
}

/// The joiner's standing (R76).
enum JoinerState {
    /// Not scanning, nothing running.
    Idle,
    /// Scanning for the beacon.
    Scanning,
    /// The exchange with `host` running, with its answer and its bound.
    Exchanging {
        /// The host the exchange runs with.
        host: HostId,
        /// What the exchange's offer goes to.
        kind: Kind,
        /// The manual exchange's answer, `None` for autojoin.
        reply: Option<ManualReply>,
        /// The bound the exchange gets.
        deadline: tokio::time::Instant,
        /// The stream's reader, the host's chunks in order, once connected.
        inbound: Option<mpsc::Sender<Vec<u8>>>,
        /// The stream's writer, the joiner's chunks out of order, once
        /// connected.
        outbound: Option<mpsc::Receiver<Vec<u8>>>,
        /// The exchange's answer, once it ends.
        task_reply: Option<oneshot::Receiver<Result<(DeviceIdentity, OfferFrame), ExchangeError>>>,
    },
}

/// A seen host, for the panel and the tried rule (R76).
struct HostRecord {
    /// The beacon's prefix last seen.
    prefix: [u8; 8],
    /// When the beacon was last seen, on the monotonic clock.
    last_seen: tokio::time::Instant,
    /// The signal last seen.
    rssi: Option<i16>,
    /// Whether the join's been tried, until the beacon changes.
    tried: bool,
}

/// A prompt action's waiting call (R76 decision 21).
enum PromptPending {
    /// The enable's answer.
    Enable {
        /// The answer, once the action finishes.
        reply: Reply<Result<(), BluetoothError>>,
    },
    /// The fetch's answer.
    Fetch {
        /// The host the fetch runs with.
        host: HostId,
        /// The answer, once the action finishes.
        reply: Reply<Result<HotspotOffer, BluetoothError>>,
    },
    /// The join's answer.
    Join {
        /// The host the join runs with.
        host: HostId,
        /// The answer, once the action finishes.
        reply: Reply<Result<IpAddr, JoinNearbyError>>,
    },
}

/// The platform's one prompt action in flight, with its waiters (R76
/// decision 21).
struct PromptBatch {
    /// The calls waiting on the action.
    pending: Vec<PromptPending>,
    /// The bound the action gets.
    deadline: tokio::time::Instant,
}

/// The hosted answers in flight, beside the beacon's outcome (R76).
struct HostedPending {
    /// The hotspot offers' answers, from the hotspot machine.
    offers: Vec<oneshot::Receiver<Result<HotspotOffer, HotspotError>>>,
    /// The callers' answers.
    replies: Vec<Reply<Result<Hosted, HotspotError>>>,
    /// The beacon's outcome, once the standing decides it.
    beacon: Option<BeaconResolution>,
}

/// The beacon's outcome, standing beside the hosted's answers (R76).
#[derive(Clone, Copy, Debug)]
enum BeaconResolution {
    /// The beacon advertises, so the call's answer stands on the offer.
    Ok,
    /// The standing's refusal, re-derived for each caller's answer.
    Refusal {
        /// The standing the refusal stands on.
        state: BluetoothState,
        /// The prompt's outcome, `None` where the bound ran.
        outcome: Option<PromptOutcome>,
    },
}

/// A joined answer in flight, from the join machine (R76).
struct JoinPending {
    /// The host the join runs with.
    host: HostId,
    /// The join machine's answer, once the network is up.
    reply: oneshot::Receiver<Result<IpAddr, JoinError>>,
    /// The caller's answer, for the manual join.
    caller: Option<Reply<Result<IpAddr, JoinNearbyError>>>,
    /// The bound the join gets.
    deadline: tokio::time::Instant,
}

/// The beacon's outcome decision, computed outside the hosted's borrow.
enum BeaconDecision {
    /// Resolve the beacon with the outcome.
    Resolve(BeaconResolution),
    /// Start the platform's action, which decides the beacon.
    StartAction,
    /// Wait, the standing does not decide yet.
    Wait,
}

/// The seam handing an exchange's offer to the hotspot's join.
pub(crate) type JoinSeam =
    Arc<dyn Fn(HotspotOffer, Reply<Result<IpAddr, JoinError>>) + Send + Sync>;

/// The machine, one per client (R76).
pub(crate) struct Machine {
    readiness: Arc<dyn ReadinessBackend>,
    peripheral: Arc<dyn PeripheralBackend>,
    central: Option<Arc<dyn CentralBackend>>,
    node: Node,
    /// The fingerprint the device serves, `None` where it does not.
    serving: Arc<dyn Fn() -> Option<Fingerprint> + Send + Sync>,
    /// Hand the exchange's offer to the hotspot's join.
    join: JoinSeam,
    /// Emit an event to the application.
    emit: Arc<dyn Fn(ClientEvent) + Send + Sync>,
    /// Whether the scan runs, on by default (R76 decision 19).
    scan: bool,
    /// Whether autojoin joins the strongest host, off by default (R76
    /// decision 19).
    autojoin: bool,
    /// Whether the call-driven prompts run, on by default (R76 decision 21).
    prompt: bool,
    /// The readiness last reported, for the change event.
    readiness_state: BluetoothState,
    host: HostBtState,
    joiner: JoinerState,
    hosts: HashMap<HostId, HostRecord>,
    hosted: Option<HostedPending>,
    pending_join: Vec<JoinPending>,
    prompting: Option<PromptBatch>,
    /// The calls waiting for the platform's action to start.
    action_waiters: Vec<PromptPending>,
    beacon: watch::Sender<BeaconState>,
}

impl Machine {
    /// The machine over the backends, the peer node, the scan and autojoin
    /// standings, the prompt standing, and the serving, join and event
    /// seams. The receiver stands the host's beacon for the panel.
    #[expect(
        clippy::too_many_arguments,
        reason = "the three backends and the three seams join the node and its three standings, and a config struct would hide the same arity behind another type"
    )]
    pub(crate) fn new(
        readiness: Arc<dyn ReadinessBackend>,
        peripheral: Arc<dyn PeripheralBackend>,
        central: Option<Arc<dyn CentralBackend>>,
        node: Node,
        scan: bool,
        autojoin: bool,
        prompt: bool,
        serving: Arc<dyn Fn() -> Option<Fingerprint> + Send + Sync>,
        join: JoinSeam,
        emit: Arc<dyn Fn(ClientEvent) + Send + Sync>,
    ) -> (Self, watch::Receiver<BeaconState>) {
        let serving_present = (serving)().is_some();
        let (beacon, beacon_rx) = watch::channel(BeaconState::Off {
            reason: Self::beacon_reason(readiness.state(), false, serving_present),
        });
        (
            Self {
                readiness,
                peripheral,
                central,
                node,
                serving,
                join,
                emit,
                scan,
                autojoin,
                prompt,
                readiness_state: BluetoothState::Unsupported,
                host: HostBtState::Off,
                joiner: JoinerState::Idle,
                hosts: HashMap::new(),
                hosted: None,
                pending_join: Vec::new(),
                prompting: None,
                action_waiters: Vec::new(),
                beacon,
            },
            beacon_rx,
        )
    }

    /// The reason the beacon is off, for the panel (R76).
    fn beacon_reason(state: BluetoothState, hosting: bool, serving: bool) -> &'static str {
        match state {
            BluetoothState::Unsupported => "no bluetooth on this system",
            BluetoothState::NotPermitted => "the bluetooth permissions are not granted",
            BluetoothState::Off => "bluetooth is off",
            BluetoothState::Ready if !hosting => "the device does not host a hotspot",
            BluetoothState::Ready if !serving => "the device does not serve its peer",
            BluetoothState::Ready => "the beacon is not started",
        }
    }

    /// The host's hosted answer, linked by the runner from the hotspot
    /// machine's (R76).
    pub(crate) fn hosted(
        &mut self,
        offer: oneshot::Receiver<Result<HotspotOffer, HotspotError>>,
        reply: Reply<Result<Hosted, HotspotError>>,
    ) {
        let Some(hosted) = self.hosted.as_mut() else {
            self.hosted = Some(HostedPending {
                offers: vec![offer],
                replies: vec![reply],
                beacon: None,
            });
            return;
        };
        hosted.offers.push(offer);
        hosted.replies.push(reply);
    }

    /// Take `command` and steer the tables to their rows.
    pub(crate) fn handle(&mut self, command: Command) {
        match command {
            Command::Enable(reply) => match self.readiness.state() {
                BluetoothState::Ready => {
                    let _ = reply.send(Ok(()));
                }
                BluetoothState::Unsupported => {
                    let _ = reply.send(Err(BluetoothError::Unsupported));
                }
                // The enable always runs the platform's action, the prompt's
                // standing beside it (R76 decision 21).
                _ => self.prompt_for(PromptPending::Enable { reply }, true),
            },
            // The runner links the host's answer to the hotspot machine's,
            // so the machine does not take it on its own.
            Command::Host(_) => {}
            Command::JoinNearby { host, reply } => {
                self.begin_manual(host, Kind::Join, ManualReply::Join(reply));
            }
            Command::Fetch { host, reply } => {
                self.begin_manual(host, Kind::Fetch, ManualReply::Fetch(reply));
            }
            Command::SetScan(on) => self.scan = on,
            Command::SetAutojoin(on) => {
                self.autojoin = on;
                if on {
                    self.scan = true;
                }
            }
            Command::SetPrompt(on) => self.prompt = on,
        }
    }

    /// A manual exchange from the call's rows (R76 joiner table).
    fn begin_manual(&mut self, host: HostId, kind: Kind, reply: ManualReply) {
        if self.central.is_none() {
            // The system runs no central, so the call has nothing to join
            // with.
            Self::answer_manual(reply, BluetoothError::Unsupported);
            return;
        }
        if matches!(self.joiner, JoinerState::Exchanging { .. }) {
            // An exchange is running, so the call answers Busy.
            Self::answer_manual(reply, BluetoothError::Busy);
            return;
        }
        match self.readiness.state() {
            BluetoothState::Ready => self.begin_join_exchange(host, kind, Some(reply)),
            BluetoothState::Unsupported => {
                Self::answer_manual(reply, BluetoothError::Unsupported);
            }
            // Decision 21's action runs once, unless the prompt is switched
            // off, then the rows go on (R76 joiner table).
            _ => match reply {
                ManualReply::Fetch(reply) => {
                    self.prompt_for(PromptPending::Fetch { host, reply }, false);
                }
                ManualReply::Join(reply) => {
                    self.prompt_for(PromptPending::Join { host, reply }, false);
                }
            },
        }
    }

    /// The manual exchange's answer, on its error rows.
    fn answer_manual(reply: ManualReply, err: BluetoothError) {
        match reply {
            ManualReply::Fetch(reply) => {
                let _ = reply.send(Err(err));
            }
            ManualReply::Join(reply) => {
                let _ = reply.send(Err(JoinNearbyError::Bluetooth(err)));
            }
        }
    }

    /// The prompt action's waiting call, started once (R76 decision 21).
    fn prompt_for(&mut self, pending: PromptPending, from_enable: bool) {
        if !from_enable && !self.prompt {
            let err = self.state_error(self.readiness.state());
            Self::answer_pending(pending, err);
            return;
        }
        self.action_waiters.push(pending);
        if self.prompting.is_none() {
            self.start_prompt_action();
        }
    }

    /// The platform's one action, started for the waiting calls.
    fn start_prompt_action(&mut self) {
        let waiters = core::mem::take(&mut self.action_waiters);
        if let Err(failure) = self.readiness.prompt() {
            // The action will not start, so the waiters answer with the
            // standing's reason.
            for pending in waiters {
                let err = match self.readiness.state() {
                    state @ (BluetoothState::Off | BluetoothState::NotPermitted) => {
                        self.state_error_with(state, PromptOutcome::Blocked)
                    }
                    state => self.state_error(state),
                };
                Self::answer_pending(pending, err);
            }
            let _ = failure;
            return;
        }
        self.prompting = Some(PromptBatch {
            pending: waiters,
            deadline: tokio::time::Instant::now() + PROMPT_BOUND,
        });
    }

    /// The standing's error, with no action asked.
    fn state_error(&self, state: BluetoothState) -> BluetoothError {
        match state {
            BluetoothState::Ready => {
                BluetoothError::Failed("the Bluetooth standing stands Ready".into())
            }
            BluetoothState::Off => BluetoothError::Off(PromptOutcome::NotAsked),
            BluetoothState::NotPermitted => BluetoothError::NotPermitted {
                missing: self.readiness.missing_permissions(),
                outcome: PromptOutcome::NotAsked,
            },
            BluetoothState::Unsupported => BluetoothError::Unsupported,
        }
    }

    /// The standing's error, with the action's outcome.
    fn state_error_with(&self, state: BluetoothState, outcome: PromptOutcome) -> BluetoothError {
        match state {
            BluetoothState::Off => BluetoothError::Off(outcome),
            BluetoothState::NotPermitted => BluetoothError::NotPermitted {
                missing: self.readiness.missing_permissions(),
                outcome,
            },
            state => self.state_error(state),
        }
    }

    /// A waiting call's answer, on its error rows.
    fn answer_pending(pending: PromptPending, err: BluetoothError) {
        match pending {
            PromptPending::Enable { reply } => {
                let _ = reply.send(Err(err));
            }
            PromptPending::Fetch { reply, .. } => {
                let _ = reply.send(Err(err));
            }
            PromptPending::Join { reply, .. } => {
                let _ = reply.send(Err(JoinNearbyError::Bluetooth(err)));
            }
        }
    }

    /// The action's outcome, once the platform reports it or its bound runs
    /// (R76 decision 21).
    fn apply_prompt(
        &mut self,
        state: BluetoothState,
        outcome: Option<PromptOutcome>,
        batch: PromptBatch,
    ) {
        for pending in batch.pending {
            match (state, outcome) {
                // The bound with no outcome answers its own.
                (_, None) => Self::answer_pending(pending, BluetoothError::TimedOut),
                (BluetoothState::Ready, Some(_)) => match pending {
                    PromptPending::Enable { reply } => {
                        let _ = reply.send(Ok(()));
                    }
                    PromptPending::Fetch { host, reply } => {
                        self.begin_join_exchange(
                            host,
                            Kind::Fetch,
                            Some(ManualReply::Fetch(reply)),
                        );
                    }
                    PromptPending::Join { host, reply } => {
                        self.begin_join_exchange(host, Kind::Join, Some(ManualReply::Join(reply)));
                    }
                },
                (BluetoothState::Unsupported, Some(_)) => {
                    Self::answer_pending(pending, BluetoothError::Unsupported);
                }
                (state @ (BluetoothState::Off | BluetoothState::NotPermitted), Some(outcome)) => {
                    Self::answer_pending(pending, self.state_error_with(state, outcome));
                }
            }
        }
        // The beacon's outcome, for the host's answer, decided outside the
        // hosted's borrow.
        let resolution = match (state, outcome) {
            (BluetoothState::Ready, Some(_)) => BeaconResolution::Ok,
            _ => BeaconResolution::Refusal { state, outcome },
        };
        if let Some(hosted) = self.hosted.as_mut()
            && hosted.beacon.is_none()
        {
            hosted.beacon = Some(resolution);
        }
    }

    /// Look at the backends' outcomes and apply the tables' transitions.
    pub(crate) fn tick(&mut self, hosting: Option<&HotspotOffer>, joined: bool) {
        let now = tokio::time::Instant::now();
        let state = self.readiness.state();
        let serving = (self.serving)();

        // The readiness's change, reported once.
        if state != self.readiness_state {
            self.readiness_state = state;
            (self.emit)(ClientEvent::BluetoothChanged { state });
        }

        // The prompt action's outcome, once the platform reports it or its
        // bound runs.
        if let Some(deadline) = self.prompting.as_ref().map(|batch| batch.deadline) {
            let outcome = self.readiness.prompt_outcome();
            if (outcome.is_some() || now >= deadline)
                && let Some(batch) = self.prompting.take()
            {
                self.apply_prompt(state, outcome, batch);
            }
        }

        self.tick_host(state, hosting, serving.as_ref());
        self.tick_joiner(state, joined, serving.is_some(), now);
        self.answer_hosted(state);
        self.answer_joined(now);
        self.update_beacon(state, hosting.is_some(), serving.is_some());
    }

    /// The host's beacon rows (R76 host table).
    fn tick_host(
        &mut self,
        state: BluetoothState,
        hosting: Option<&HotspotOffer>,
        serving: Option<&Fingerprint>,
    ) {
        match &mut self.host {
            // The device hosts a hotspot and serves, so the beacon starts.
            HostBtState::Off if state == BluetoothState::Ready => {
                if let (Some(_), Some(fingerprint)) = (hosting, serving) {
                    let beacon = Beacon::of(fingerprint);
                    if self.peripheral.start(beacon.to_service_data()).is_ok() {
                        self.host = HostBtState::Advertising {
                            prefix: beacon.prefix,
                            exchanges: HashMap::new(),
                        };
                    } else {
                        // The platform will not advertise, so the standing
                        // retries on its next look.
                        tracing::warn!(
                            "the beacon could not start, so it retries on the next look"
                        );
                    }
                }
            }
            HostBtState::Advertising { prefix, exchanges } => {
                // The hotspot stops, the device stops serving, or Bluetooth
                // leaves Ready, so the beacon stops with its exchanges.
                if state != BluetoothState::Ready || hosting.is_none() || serving.is_none() {
                    self.peripheral.stop();
                    self.host = HostBtState::Off;
                    return;
                }
                if let Some(fingerprint) = serving {
                    // A renewal changes the leaf, so the beacon advertises
                    // again under the new prefix.
                    if fingerprint.prefix() != *prefix {
                        let beacon = Beacon::of(fingerprint);
                        if self.peripheral.start(beacon.to_service_data()).is_ok() {
                            *prefix = beacon.prefix;
                        }
                    }
                }
                // The exchanges' rows, the outbound, the outcome, the bound.
                let ended = tick_host_exchanges(&self.peripheral, exchanges);
                for (device, _outcome) in ended {
                    self.peripheral.disconnect(device);
                }
            }
            HostBtState::Off => {}
        }
        // The service's events.
        for event in self.peripheral.poll() {
            match event {
                PeripheralEvent::Connected { device, mtu } => {
                    let HostBtState::Advertising { exchanges, .. } = &mut self.host else {
                        self.peripheral.disconnect(device);
                        continue;
                    };
                    if exchanges.len() >= MAX_EXCHANGES || exchanges.contains_key(&device) {
                        // A joiner connects while four exchanges run, so it
                        // is disconnected at once.
                        self.peripheral.disconnect(device);
                        continue;
                    }
                    if let Some(offer) = hosting.cloned() {
                        // A joiner connects while fewer than four exchanges
                        // run, so it runs its exchange.
                        start_host_exchange(&self.node, exchanges, device, mtu, offer);
                    } else {
                        self.peripheral.disconnect(device);
                    }
                }
                PeripheralEvent::Chunk { device, bytes } => {
                    if let HostBtState::Advertising { exchanges, .. } = &mut self.host {
                        let reader_gone = match exchanges.get_mut(&device) {
                            Some(exchange) => exchange.inbound.try_send(bytes).is_err(),
                            None => false,
                        };
                        // The stream's reader is gone, so the exchange ends.
                        if reader_gone && end_host_exchange(exchanges, device) {
                            self.peripheral.disconnect(device);
                        }
                    }
                }
                PeripheralEvent::Disconnected { device } => {
                    if let HostBtState::Advertising { exchanges, .. } = &mut self.host
                        && end_host_exchange(exchanges, device)
                    {
                        self.peripheral.disconnect(device);
                    }
                }
                // The platform's failure stands logged, the exchanges end by
                // their own bound.
                PeripheralEvent::Failed(reason) => {
                    tracing::warn!(%reason, "the platform's Bluetooth failed");
                }
            }
        }
    }
}
/// The host's exchange rows, its outbound, outcome and bound (R76 host
/// table).
fn tick_host_exchanges(
    peripheral: &Arc<dyn PeripheralBackend>,
    exchanges: &mut HashMap<u64, HostExchange>,
) -> Vec<(u64, Result<DeviceIdentity, ExchangeError>)> {
    let now = tokio::time::Instant::now();
    let mut ended: Vec<(u64, Result<DeviceIdentity, ExchangeError>)> = Vec::new();
    for (device, exchange) in exchanges.iter_mut() {
        // The exchange's outbound, to the device's notification.
        while let Ok(chunk) = exchange.outbound.try_recv() {
            if peripheral.notify(*device, &chunk).is_err() {
                ended.push((
                    *device,
                    Err(channel_error("the notification will not send")),
                ));
                break;
            }
        }
        let outcome = match exchange.reply.try_recv() {
            Ok(outcome) => Some(outcome),
            Err(oneshot::error::TryRecvError::Closed) => {
                Some(Err(channel_error("the exchange's task ended")))
            }
            // 30 seconds pass in one exchange, so it ends with no offer.
            Err(oneshot::error::TryRecvError::Empty) if now >= exchange.deadline => {
                Some(Err(ExchangeError::Timeout))
            }
            Err(oneshot::error::TryRecvError::Empty) => None,
        };
        if let Some(outcome) = outcome {
            ended.push((*device, outcome));
        }
    }
    for (device, outcome) in &ended {
        if exchanges.remove(device).is_some() {
            // The chain is refused, the handshake completes, or the bound
            // runs, so the exchange ends, with or without its offer.
            match outcome {
                Ok(identity) => tracing::debug!(?identity, "the exchange handed its offer"),
                Err(err) => tracing::debug!(%err, "the exchange ended without its offer"),
            }
        }
    }
    ended
}

/// End the device's exchange, its stream's reader gone.
fn end_host_exchange(exchanges: &mut HashMap<u64, HostExchange>, device: u64) -> bool {
    exchanges.remove(&device).is_some()
}

/// One exchange, over the joiner's GATT connection (R76).
fn start_host_exchange(
    node: &Node,
    exchanges: &mut HashMap<u64, HostExchange>,
    device: u64,
    mtu: u16,
    offer: HotspotOffer,
) {
    // The MTU is a platform packet-size count, so the widening stands
    // lossless.
    let chunk_size = chunk_size(mtu);
    let (inbound_tx, inbound_rx) = mpsc::channel(64);
    let (outbound_tx, outbound_rx) = mpsc::channel(64);
    let node = node.clone();
    let (reply_tx, reply_rx) = oneshot::channel();
    tokio::spawn(async move {
        let io = ChunkStream::new(inbound_rx, outbound_tx, chunk_size);
        let outcome = node.offer_over(io, offer_frame(&offer)).await;
        let _ = reply_tx.send(outcome);
    });
    exchanges.insert(
        device,
        HostExchange {
            inbound: inbound_tx,
            outbound: outbound_rx,
            reply: reply_rx,
            deadline: tokio::time::Instant::now() + EXCHANGE_BOUND,
        },
    );
}

impl Machine {
    /// The joiner's scan and exchange rows (R76 joiner table).
    #[expect(
        clippy::too_many_lines,
        reason = "one tick walks the joiner table's rows in order"
    )]
    fn tick_joiner(
        &mut self,
        state: BluetoothState,
        joined: bool,
        serving: bool,
        now: tokio::time::Instant,
    ) {
        // The scan's condition, decision 19, on a system whose central runs
        // and whose Bluetooth stands Ready.
        let should_scan = self.scan
            && serving
            && !joined
            && state == BluetoothState::Ready
            && self.central.is_some();

        match self.joiner {
            // Scan or autojoin turned on while the device serves with no
            // joined hotspot.
            JoinerState::Idle if should_scan => {
                if let Some(central) = &self.central {
                    central.start_scan();
                }
                self.joiner = JoinerState::Scanning;
            }
            // Scan turned off, the device stops serving, a hotspot is
            // joined, or Bluetooth leaves Ready.
            JoinerState::Scanning if !should_scan => {
                if let Some(central) = &self.central {
                    central.stop_scan();
                }
                self.report_hosts_gone();
                self.joiner = JoinerState::Idle;
            }
            _ => {}
        }

        // Bluetooth leaves Ready, so the exchange fails with BluetoothOff.
        if state != BluetoothState::Ready && matches!(self.joiner, JoinerState::Exchanging { .. }) {
            self.end_join_exchange(
                Err(ExchangeError::Io(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Bluetooth left Ready",
                ))),
                now,
            );
        }

        // A host's beacon is unseen for 30 seconds, so it is reported gone.
        let mut gone = Vec::new();
        for (host, record) in &self.hosts {
            if now >= record.last_seen + GONE_AFTER {
                gone.push(*host);
            }
        }
        for host in gone {
            self.hosts.remove(&host);
            (self.emit)(ClientEvent::HostGone { host });
        }

        // The central's events.
        let events = self
            .central
            .as_ref()
            .map(|central| central.poll())
            .unwrap_or_default();
        for event in events {
            let mut end = None;
            match event {
                // A beacon with connetto's UUID is seen.
                CentralEvent::Seen {
                    host,
                    service_data,
                    rssi,
                } => {
                    if let Some(beacon) = Beacon::from_service_data(&service_data) {
                        match self.hosts.get_mut(&host) {
                            None => {
                                self.hosts.insert(
                                    host,
                                    HostRecord {
                                        prefix: beacon.prefix,
                                        last_seen: now,
                                        rssi: Some(rssi),
                                        tried: false,
                                    },
                                );
                                (self.emit)(ClientEvent::HostNearby {
                                    host,
                                    prefix: beacon.prefix,
                                    rssi: Some(rssi),
                                });
                            }
                            // A known prefix refreshes its signal.
                            Some(record) if record.prefix == beacon.prefix => {
                                record.last_seen = now;
                                record.rssi = Some(rssi);
                            }
                            // A new prefix is a new host, untried again.
                            Some(record) => {
                                record.prefix = beacon.prefix;
                                record.last_seen = now;
                                record.rssi = Some(rssi);
                                record.tried = false;
                                (self.emit)(ClientEvent::HostNearby {
                                    host,
                                    prefix: beacon.prefix,
                                    rssi: Some(rssi),
                                });
                            }
                        }
                    }
                }
                // The host connected, the exchange's stream goes live.
                CentralEvent::Connected { host, mtu } => {
                    if matches!(&self.joiner, JoinerState::Exchanging { host: h, .. } if *h == host)
                    {
                        self.begin_join_task(mtu);
                    } else if let Some(central) = &self.central {
                        central.disconnect(host);
                    }
                }
                // A chunk the host notified, to the exchange's stream.
                CentralEvent::Chunk { host, bytes } => {
                    if matches!(&self.joiner, JoinerState::Exchanging { host: h, .. } if *h == host)
                        && !self.send_join_chunk(host, bytes)
                    {
                        end = Some(channel_error("the stream's reader is gone"));
                    }
                }
                // The host disconnected, so the exchange's stream ends by its
                // EOF.
                CentralEvent::Disconnected { host } => {
                    if let JoinerState::Exchanging {
                        host: exchanging,
                        task_reply,
                        ..
                    } = &self.joiner
                        && *exchanging == host
                    {
                        if task_reply.is_none() {
                            // The stream never ran, so the exchange ends here.
                            end = Some(ExchangeError::Io(io::Error::new(
                                io::ErrorKind::NotConnected,
                                "the host disconnected",
                            )));
                        } else {
                            // The stream ends, so the running exchange fails.
                            self.drop_join_inbound();
                        }
                    }
                }
            }
            if let Some(err) = end {
                self.end_join_exchange(Err(err), now);
            }
        }

        // Autojoin is on and a host not yet tried is seen.
        if self.autojoin
            && should_scan
            && matches!(self.joiner, JoinerState::Scanning)
            && let Some(host) = self.strongest_untried_host()
        {
            self.begin_join_exchange(host, Kind::Join, None);
        }

        // The exchange's rows, the outbound, the outcome, the bound.
        let write_failed = {
            let mut failed = false;
            if let JoinerState::Exchanging { host, outbound, .. } = &mut self.joiner
                && let Some(outbound) = outbound.as_mut()
            {
                while let Ok(chunk) = outbound.try_recv() {
                    let written = self
                        .central
                        .as_ref()
                        .map(|central| central.write(*host, &chunk));
                    if !matches!(written, Some(Ok(()))) {
                        failed = true;
                        break;
                    }
                }
            }
            failed
        };
        let outcome = if write_failed {
            Some(Err(channel_error("the central's write will not go")))
        } else {
            match &mut self.joiner {
                JoinerState::Exchanging {
                    deadline,
                    task_reply,
                    ..
                } => {
                    match task_reply.as_mut() {
                        // The exchange yields its answer, or its bound runs.
                        Some(reply) => match reply.try_recv() {
                            Ok(outcome) => Some(outcome),
                            Err(oneshot::error::TryRecvError::Closed) => {
                                Some(Err(channel_error("the exchange's task ended")))
                            }
                            Err(oneshot::error::TryRecvError::Empty) if now >= *deadline => {
                                Some(Err(ExchangeError::Timeout))
                            }
                            Err(oneshot::error::TryRecvError::Empty) => None,
                        },
                        None => None,
                    }
                }
                _ => None,
            }
        };
        if let Some(outcome) = outcome {
            self.end_join_exchange(outcome, now);
        }
    }

    /// The strongest host not yet tried, for autojoin (R76 decision 19).
    fn strongest_untried_host(&self) -> Option<HostId> {
        self.hosts
            .iter()
            .filter(|(_, record)| !record.tried)
            .max_by_key(|(_, record)| record.rssi.unwrap_or(i16::MIN))
            .map(|(host, _)| *host)
    }

    /// Report every seen host gone and forget it.
    fn report_hosts_gone(&mut self) {
        for host in self.hosts.keys() {
            (self.emit)(ClientEvent::HostGone { host: *host });
        }
        self.hosts.clear();
    }

    /// The join's exchange, from the scan or the call (R76).
    fn begin_join_exchange(&mut self, host: HostId, kind: Kind, reply: Option<ManualReply>) {
        if matches!(self.joiner, JoinerState::Scanning)
            && let Some(central) = &self.central
        {
            central.stop_scan();
        }
        self.joiner = JoinerState::Exchanging {
            host,
            kind,
            reply,
            deadline: tokio::time::Instant::now() + EXCHANGE_BOUND,
            inbound: None,
            outbound: None,
            task_reply: None,
        };
        if let Some(central) = &self.central {
            central.connect(host);
        }
    }

    /// The join's exchange, its stream live over the connected GATT (R76).
    fn begin_join_task(&mut self, mtu: u16) {
        let chunk_size = chunk_size(mtu);
        let (inbound_tx, inbound_rx) = mpsc::channel(64);
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        let node = self.node.clone();
        let (reply_tx, reply_rx) = oneshot::channel();
        tokio::spawn(async move {
            let io = ChunkStream::new(inbound_rx, outbound_tx, chunk_size);
            let outcome = node.fetch_over(io).await;
            let _ = reply_tx.send(outcome);
        });
        if let JoinerState::Exchanging {
            inbound,
            outbound,
            task_reply,
            ..
        } = &mut self.joiner
        {
            *inbound = Some(inbound_tx);
            *outbound = Some(outbound_rx);
            *task_reply = Some(reply_rx);
        }
    }

    /// A chunk to the exchange's stream, `false` where its reader is gone.
    fn send_join_chunk(&mut self, host: HostId, bytes: Vec<u8>) -> bool {
        let JoinerState::Exchanging {
            host: target,
            inbound,
            ..
        } = &mut self.joiner
        else {
            return true;
        };
        if *target != host {
            return true;
        }
        match inbound {
            Some(sender) => sender.try_send(bytes).is_ok(),
            None => false,
        }
    }

    /// The exchange's stream's reader, gone with the host's connection.
    fn drop_join_inbound(&mut self) {
        if let JoinerState::Exchanging { inbound, .. } = &mut self.joiner {
            *inbound = None;
        }
    }

    /// The exchange's end, its rows applied (R76 joiner table).
    fn end_join_exchange(
        &mut self,
        outcome: Result<(DeviceIdentity, OfferFrame), ExchangeError>,
        now: tokio::time::Instant,
    ) {
        let JoinerState::Exchanging {
            host, kind, reply, ..
        } = core::mem::replace(&mut self.joiner, JoinerState::Idle)
        else {
            return;
        };
        if let Some(central) = &self.central {
            central.disconnect(host);
        }
        match outcome {
            // The exchange yields the offer, so it goes to its kind.
            Ok((_identity, frame)) => match kind {
                Kind::Fetch => {
                    if let Some(ManualReply::Fetch(reply)) = reply {
                        let _ = reply.send(Ok(hotspot_offer(&frame)));
                    }
                }
                Kind::Join => {
                    let offer = hotspot_offer(&frame);
                    let (join_tx, join_rx) = oneshot::channel();
                    (self.join)(offer.clone(), join_tx);
                    let caller = reply.and_then(|reply| match reply {
                        ManualReply::Join(reply) => Some(reply),
                        ManualReply::Fetch(_) => None,
                    });
                    self.pending_join.push(JoinPending {
                        host,
                        reply: join_rx,
                        caller,
                        deadline: now + JOIN_BOUND + MARGIN,
                    });
                }
            },
            // The host's chain is refused, the exchange times out, or
            // Bluetooth fails, so the host is marked tried.
            Err(err) => {
                if let Some(record) = self.hosts.get_mut(&host) {
                    record.tried = true;
                }
                match reply {
                    Some(ManualReply::Fetch(reply)) => {
                        let _ = reply.send(Err(BluetoothError::Exchange(err)));
                    }
                    Some(ManualReply::Join(reply)) => {
                        let _ = reply.send(Err(JoinNearbyError::Bluetooth(
                            BluetoothError::Exchange(err),
                        )));
                    }
                    None => {
                        tracing::debug!(
                            %err,
                            "the autojoin's exchange ended without its offer"
                        );
                    }
                }
            }
        }
    }

    /// The hosted answers, once the offer and the beacon stand (R76 host
    /// table).
    fn answer_hosted(&mut self, state: BluetoothState) {
        // The beacon's outcome, decided outside the hosted's borrow. It
        // stands on the state and the host's look, not on the offer, so it
        // is decided as soon as the standing allows and the answers below
        // wait for the offer on its own channel.
        let decision = self.hosted.as_ref().and_then(|hosted| {
            if hosted.beacon.is_none() {
                Some(match state {
                    BluetoothState::Ready
                        if matches!(self.host, HostBtState::Advertising { .. }) =>
                    {
                        BeaconDecision::Resolve(BeaconResolution::Ok)
                    }
                    // The host's look starts the beacon, which the look
                    // answers.
                    BluetoothState::Ready => BeaconDecision::Wait,
                    // The standing decides the refusal, which each caller's
                    // answer re-derives.
                    // The hotspot's answer is in hand, so decision 21's
                    // action runs once, unless the prompt is switched off.
                    BluetoothState::Off | BluetoothState::NotPermitted if self.prompt => {
                        BeaconDecision::StartAction
                    }
                    BluetoothState::Unsupported
                    | BluetoothState::Off
                    | BluetoothState::NotPermitted => {
                        BeaconDecision::Resolve(BeaconResolution::Refusal {
                            state,
                            outcome: Some(PromptOutcome::NotAsked),
                        })
                    }
                })
            } else {
                None
            }
        });
        match decision {
            Some(BeaconDecision::Resolve(resolution)) => {
                if let Some(hosted) = self.hosted.as_mut() {
                    hosted.beacon = Some(resolution);
                }
            }
            Some(BeaconDecision::StartAction) if self.prompting.is_none() => {
                self.start_prompt_action();
            }
            _ => {}
        }
        // The answers, once the offer and the beacon stand, the refusal
        // re-derived for each caller.
        let (offers, replies, resolution) = {
            let Some(hosted) = self.hosted.as_mut() else {
                return;
            };
            let Some(resolution) = hosted.beacon else {
                return;
            };
            (
                core::mem::take(&mut hosted.offers),
                core::mem::take(&mut hosted.replies),
                resolution,
            )
        };
        let mut kept_offers = Vec::new();
        let mut kept_replies = Vec::new();
        for (mut offer, reply) in offers.into_iter().zip(replies) {
            match offer.try_recv() {
                Ok(answer) => {
                    let beacon = match resolution {
                        BeaconResolution::Ok => Ok(()),
                        BeaconResolution::Refusal { state, outcome } => {
                            Err(self.beacon_refusal(state, outcome))
                        }
                    };
                    let _ = reply.send(match answer {
                        Ok(offer) => Ok(Hosted { offer, beacon }),
                        Err(err) => Err(err),
                    });
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    kept_offers.push(offer);
                    kept_replies.push(reply);
                }
                // The caller is gone, so the answer stands without it.
                Err(oneshot::error::TryRecvError::Closed) => {}
            }
        }
        if kept_offers.is_empty() {
            self.hosted = None;
        } else {
            let Some(hosted) = self.hosted.as_mut() else {
                return;
            };
            hosted.offers = kept_offers;
            hosted.replies = kept_replies;
        }
    }

    /// The beacon's refusal, re-derived for each caller's answer (R76).
    fn beacon_refusal(
        &self,
        state: BluetoothState,
        outcome: Option<PromptOutcome>,
    ) -> BluetoothError {
        match (state, outcome) {
            (BluetoothState::Unsupported, _) => BluetoothError::Unsupported,
            (BluetoothState::Off, Some(outcome)) => BluetoothError::Off(outcome),
            (BluetoothState::NotPermitted, Some(outcome)) => BluetoothError::NotPermitted {
                missing: self.readiness.missing_permissions(),
                outcome,
            },
            // The Ready standing is never a refusal, so that defensive row
            // stands on the bound's own reason.
            (_, _) => BluetoothError::TimedOut,
        }
    }

    /// The joined answers, once the join machine answers them (R76 joiner
    /// table).
    fn answer_joined(&mut self, now: tokio::time::Instant) {
        let mut done: Vec<(usize, Result<IpAddr, JoinError>)> = Vec::new();
        for (index, pending) in self.pending_join.iter_mut().enumerate() {
            let answer = match pending.reply.try_recv() {
                Ok(answer) => Some(answer),
                Err(oneshot::error::TryRecvError::Closed) => Some(Err(JoinError::Failed)),
                Err(oneshot::error::TryRecvError::Empty) if now >= pending.deadline => {
                    Some(Err(JoinError::TimedOut))
                }
                Err(oneshot::error::TryRecvError::Empty) => None,
            };
            if let Some(answer) = answer {
                done.push((index, answer));
            }
        }
        for (index, answer) in done {
            let pending = self.pending_join.remove(index);
            // The join is declined or times out, so the host is marked tried.
            if let Err(err) = &answer
                && matches!(err, JoinError::Declined | JoinError::TimedOut)
                && let Some(record) = self.hosts.get_mut(&pending.host)
            {
                record.tried = true;
            }
            if let Some(caller) = pending.caller {
                let _ = caller.send(match answer {
                    Ok(gateway) => Ok(gateway),
                    Err(err) => Err(JoinNearbyError::Join(err)),
                });
            }
        }
    }

    /// The beacon's standing, for the panel (R76).
    fn update_beacon(&mut self, state: BluetoothState, hosting: bool, serving: bool) {
        let beacon = match &self.host {
            HostBtState::Advertising { prefix, .. } => BeaconState::Advertising { prefix: *prefix },
            HostBtState::Off => BeaconState::Off {
                reason: Self::beacon_reason(state, hosting, serving),
            },
        };
        if *self.beacon.borrow() != beacon {
            self.beacon.send_replace(beacon);
        }
    }

    /// Apply the "Client closed" rows, for the loop's end and a dropped
    /// client (R76).
    pub(crate) fn close(&mut self) {
        // The host's service stops, the joiner's scan and exchange cancel.
        self.peripheral.stop();
        if matches!(self.joiner, JoinerState::Scanning)
            && let Some(central) = &self.central
        {
            central.stop_scan();
        }
        self.host = HostBtState::Off;
        self.joiner = JoinerState::Idle;
        self.hosts.clear();
        self.hosted = None;
        self.pending_join.clear();
        self.prompting = None;
        self.action_waiters.clear();
        // The beacon's standing settles, for the panel.
        let state = self.readiness.state();
        self.update_beacon(state, false, (self.serving)().is_some());
    }

    /// Whether an exchange runs, so the loop's pace tightens.
    pub(crate) fn exchange_running(&self) -> bool {
        matches!(self.joiner, JoinerState::Exchanging { .. })
            || matches!(
                self.host,
                HostBtState::Advertising { ref exchanges, .. } if !exchanges.is_empty()
            )
    }
}

/// The machine's commands, from the client's API (R76).
pub(crate) enum Command {
    /// Enable Bluetooth, the platform's action inside the call (R76 decision
    /// 21).
    Enable(Reply<Result<(), BluetoothError>>),
    /// Host the hotspot, the runner linking the hotspot machine's answer.
    Host(Reply<Result<Hosted, HotspotError>>),
    /// Join the nearby host's hotspot through the exchange (R76 decision
    /// 19).
    JoinNearby {
        /// The host to join.
        host: HostId,
        /// The answer, once the network is up.
        reply: Reply<Result<IpAddr, JoinNearbyError>>,
    },
    /// Fetch the nearby host's offer through the exchange, without joining
    /// (R76 decision 19).
    Fetch {
        /// The host to fetch.
        host: HostId,
        /// The answer, once the exchange yields the offer.
        reply: Reply<Result<HotspotOffer, BluetoothError>>,
    },
    /// The scan's standing, at run time (R76 decision 19).
    SetScan(bool),
    /// The autojoin's standing, at run time, implying the scan (R76 decision
    /// 19).
    SetAutojoin(bool),
    /// The prompt's standing, at run time (R76 decision 21).
    SetPrompt(bool),
}

/// The one inbound the loop looks at, from either machine's channel or its
/// own pace.
enum Next {
    Hotspot(Option<crate::hotspot::Command>),
    Bluetooth(Option<Command>),
    Tick,
}

/// The machines' loop beside the client's pump, ending with it (R76).
pub(crate) struct Runner {
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
    hotspot: Arc<dyn crate::hotspot::HotspotBackend>,
    peripheral: Arc<dyn PeripheralBackend>,
    central: Option<Arc<dyn CentralBackend>>,
}

impl Future for Runner {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        self.future.as_mut().poll(cx)
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        // A dropped client leaves the machines unpollable, so the tables'
        // "Client closed" rows apply here, where they are no-ops on the
        // backends' own standing.
        self.hotspot.stop_host();
        self.hotspot.leave_join();
        self.peripheral.stop();
        if let Some(central) = &self.central {
            central.stop_scan();
        }
    }
}

/// The machines beside the client's pump, the backends' stop and leave
/// applying to a dropped client (R76).
pub(crate) fn run(
    mut hotspot: crate::hotspot::Machine,
    mut hotspot_commands: mpsc::UnboundedReceiver<crate::hotspot::Command>,
    mut bluetooth: Machine,
    mut bluetooth_commands: mpsc::UnboundedReceiver<Command>,
) -> Runner {
    let hotspot_backend = Arc::clone(&hotspot.backend);
    let peripheral = Arc::clone(&bluetooth.peripheral);
    let central = bluetooth.central.clone();
    Runner {
        future: Box::pin(async move {
            let mut hotspot_closed = false;
            let mut bluetooth_closed = false;
            loop {
                let pace = if bluetooth.exchange_running() {
                    FAST_TICK
                } else {
                    TICK
                };
                let next = tokio::select! {
                    command = hotspot_commands.recv() => Next::Hotspot(command),
                    command = bluetooth_commands.recv() => Next::Bluetooth(command),
                    () = tokio::time::sleep(pace) => Next::Tick,
                };
                match next {
                    Next::Hotspot(Some(command)) => hotspot.handle(command),
                    Next::Hotspot(None) => hotspot_closed = true,
                    Next::Bluetooth(Some(command)) => match command {
                        // The caller's answer stands linked to the beacon's,
                        // beside the hotspot machine's offer.
                        Command::Host(caller) => {
                            let (offer_tx, offer_rx) = oneshot::channel();
                            hotspot.handle(crate::hotspot::Command::Host(offer_tx));
                            bluetooth.hosted(offer_rx, caller);
                        }
                        command => bluetooth.handle(command),
                    },
                    Next::Bluetooth(None) => bluetooth_closed = true,
                    Next::Tick => {
                        // The hotspot's standing, read before either tick, so
                        // the beacon's rows stand on the hotspot's own look.
                        let hosting = hotspot.hosting_offer();
                        let joined = hotspot.joined();
                        hotspot.tick();
                        bluetooth.tick(hosting.as_ref(), joined);
                    }
                }
                // A closed channel ends the loop, both of them.
                if hotspot_closed && bluetooth_closed {
                    hotspot.close();
                    bluetooth.close();
                    break;
                }
            }
        }),
        hotspot: hotspot_backend,
        peripheral,
        central,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::time::{SystemTime, UNIX_EPOCH};

    use connetto_core::device_cert::{
        AttestationLevel, CertificateRequest, CertificateSigner, DeploymentId, DeviceCertificate,
        DeviceIssuer, DeviceKey, DeviceKeyError, KeyHome, RootCa, public_key_info,
    };
    use connetto_peer::{Identity, PeerEvent, SystemClock, Trust};
    use parking_lot::Mutex;
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, SigningKey};

    /// The offers the join seam received, with their replies.
    type Joins = Arc<Mutex<Vec<(HotspotOffer, oneshot::Sender<Result<IpAddr, JoinError>>)>>>;

    const DAY: Duration = Duration::from_hours(24);

    fn whole_second() -> SystemTime {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs();
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn all_levels() -> Vec<AttestationLevel> {
        AttestationLevel::ALL.into_iter().collect()
    }

    /// A device key held in memory, standing in for a chip.
    struct MemKey(Arc<KeyPair>);

    impl DeviceKey for MemKey {
        fn public_point(&self) -> [u8; 65] {
            self.0
                .public_key_raw()
                .try_into()
                .expect("an uncompressed P-256 point")
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
            self.0
                .sign(message)
                .map_err(|err| DeviceKeyError::Platform(Box::new(err)))
        }

        fn home(&self) -> KeyHome {
            KeyHome::Software
        }
    }

    /// A root and the two device identities it signs, under one issuer.
    struct Deployment {
        root: Vec<u8>,
        host_leaf: Vec<u8>,
        host_identity: Identity,
        joiner_leaf: Vec<u8>,
        joiner_identity: Identity,
    }

    impl Deployment {
        fn new() -> Self {
            let now = whole_second();
            let root = RootCa::create(
                DeploymentId::from_uuid(uuid::Uuid::from_u128(1)),
                now - 10 * DAY,
                3650 * DAY,
            )
            .expect("the root mints");
            let root_der = root.certificate().to_vec();
            let issuer_key: Arc<KeyPair> =
                Arc::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("the issuer key"));
            let issuer_holder = MemKey(Arc::clone(&issuer_key));
            let spki = public_key_info(&issuer_holder);
            let issuer_cert = root
                .sign_issuer(&spki, now - 10 * DAY, 366 * DAY, [1; 16])
                .expect("the issuer signs");
            let issuer_pair = KeyPair::from_pkcs8_der_and_sign_algo(
                &rustls::pki_types::PrivatePkcs8KeyDer::from(issuer_key.serialize_der()),
                &PKCS_ECDSA_P256_SHA256,
            )
            .expect("the issuer key round-trips");
            let signer = DeviceIssuer::new(issuer_cert.clone(), issuer_pair, &root_der)
                .expect("the issuer loads");
            let (host_leaf, host_identity) =
                Self::device(&signer, &issuer_cert, "host", now, [1; 16]);
            let (joiner_leaf, joiner_identity) =
                Self::device(&signer, &issuer_cert, "joiner", now, [2; 16]);
            Self {
                root: root_der,
                host_leaf,
                host_identity,
                joiner_leaf,
                joiner_identity,
            }
        }

        fn device(
            signer: &DeviceIssuer,
            issuer_cert: &[u8],
            account: &str,
            now: SystemTime,
            serial: [u8; 16],
        ) -> (Vec<u8>, Identity) {
            let key = MemKey(Arc::new(
                KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("the device key"),
            ));
            let csr = CertificateRequest::build(&CertificateSigner::new(&key), &[1; 32])
                .expect("the csr");
            let request = CertificateRequest::parse(&csr).expect("the request parses");
            let leaf = signer
                .issue(
                    &request,
                    account,
                    now,
                    DAY,
                    serial,
                    AttestationLevel::Unproven,
                )
                .expect("the certificate issues");
            DeviceCertificate::parse(&leaf).expect("the profile holds");
            let identity = Identity {
                certificate: leaf.clone(),
                issuer: issuer_cert.to_vec(),
                key: Arc::new(key),
            };
            (leaf, identity)
        }
    }

    /// A node that trusts `root_der` and serves `identity` on loopback.
    fn serving_node(root_der: Vec<u8>, identity: Identity) -> Node {
        let (tx, _rx) = mpsc::unbounded_channel::<PeerEvent>();
        let node = Node::new(
            Trust {
                roots: vec![root_der],
                accepted: all_levels(),
            },
            Arc::new(SystemClock),
            tx,
        )
        .expect("the roots hold keys");
        node.serve(SocketAddr::from(([127, 0, 0, 1], 0)), identity)
            .expect("the listener binds");
        node
    }

    /// A node with no identity, so its exchanges answer `NotServing`.
    fn quiet_node() -> Node {
        let (tx, _rx) = mpsc::unbounded_channel::<PeerEvent>();
        Node::new(
            Trust {
                roots: Vec::new(),
                accepted: Vec::new(),
            },
            Arc::new(SystemClock),
            tx,
        )
        .expect("a node with no roots")
    }

    /// A readiness the test steers, recording its prompt.
    struct FakeReadiness {
        state: Mutex<BluetoothState>,
        missing: Mutex<Vec<String>>,
        prompt_calls: Mutex<usize>,
        outcome: Mutex<Option<PromptOutcome>>,
    }

    impl FakeReadiness {
        fn new(state: BluetoothState) -> Self {
            Self {
                state: Mutex::new(state),
                missing: Mutex::new(Vec::new()),
                prompt_calls: Mutex::new(0),
                outcome: Mutex::new(None),
            }
        }
    }

    impl ReadinessBackend for FakeReadiness {
        fn state(&self) -> BluetoothState {
            *self.state.lock()
        }

        fn missing_permissions(&self) -> Vec<String> {
            self.missing.lock().clone()
        }

        fn prompt(&self) -> Result<(), BluetoothError> {
            *self.prompt_calls.lock() += 1;
            Ok(())
        }

        fn prompt_outcome(&self) -> Option<PromptOutcome> {
            *self.outcome.lock()
        }
    }

    /// The wire the host's notifications and the joiner's writes cross.
    struct Wire {
        to_joiner: Mutex<VecDeque<(u64, Vec<u8>)>>,
        to_host: Mutex<VecDeque<(u64, Vec<u8>)>>,
    }

    impl Wire {
        fn new() -> Self {
            Self {
                to_joiner: Mutex::new(VecDeque::new()),
                to_host: Mutex::new(VecDeque::new()),
            }
        }
    }

    /// A GATT service the test steers, bridging its notifications to the wire.
    struct FakePeripheral {
        wire: Arc<Wire>,
        started: Mutex<Vec<[u8; 9]>>,
        stopped: Mutex<usize>,
        disconnects: Mutex<Vec<u64>>,
        notifies: Mutex<Vec<(u64, usize)>>,
        queue: Mutex<VecDeque<PeripheralEvent>>,
    }

    impl FakePeripheral {
        fn new(wire: Arc<Wire>) -> Self {
            Self {
                wire,
                started: Mutex::new(Vec::new()),
                stopped: Mutex::new(0),
                disconnects: Mutex::new(Vec::new()),
                notifies: Mutex::new(Vec::new()),
                queue: Mutex::new(VecDeque::new()),
            }
        }

        fn push(&self, event: PeripheralEvent) {
            self.queue.lock().push_back(event);
        }
    }

    impl PeripheralBackend for FakePeripheral {
        fn start(&self, beacon: [u8; 9]) -> Result<(), BluetoothError> {
            self.started.lock().push(beacon);
            Ok(())
        }

        fn stop(&self) {
            *self.stopped.lock() += 1;
        }

        fn poll(&self) -> Vec<PeripheralEvent> {
            let mut out: Vec<PeripheralEvent> = self.queue.lock().drain(..).collect();
            for (device, bytes) in self.wire.to_host.lock().drain(..) {
                out.push(PeripheralEvent::Chunk { device, bytes });
            }
            out
        }

        fn notify(&self, device: u64, bytes: &[u8]) -> Result<(), BluetoothError> {
            self.notifies.lock().push((device, bytes.len()));
            self.wire
                .to_joiner
                .lock()
                .push_back((device, bytes.to_vec()));
            Ok(())
        }

        fn disconnect(&self, device: u64) {
            self.disconnects.lock().push(device);
        }
    }

    /// A central the test steers, bridging its writes to the wire.
    struct FakeCentral {
        wire: Arc<Wire>,
        scans: Mutex<i32>,
        /// Every scan start, so a flapping scan shows.
        starts: Mutex<u32>,
        connects: Mutex<Vec<u64>>,
        disconnects: Mutex<Vec<u64>>,
        queue: Mutex<VecDeque<CentralEvent>>,
    }

    impl FakeCentral {
        fn new(wire: Arc<Wire>) -> Self {
            Self {
                wire,
                scans: Mutex::new(0),
                starts: Mutex::new(0),
                connects: Mutex::new(Vec::new()),
                disconnects: Mutex::new(Vec::new()),
                queue: Mutex::new(VecDeque::new()),
            }
        }

        fn push(&self, event: CentralEvent) {
            self.queue.lock().push_back(event);
        }

        fn started(&self) -> bool {
            *self.scans.lock() > 0
        }
    }

    impl CentralBackend for FakeCentral {
        fn start_scan(&self) {
            *self.scans.lock() += 1;
            *self.starts.lock() += 1;
        }

        fn stop_scan(&self) {
            *self.scans.lock() -= 1;
        }

        fn poll(&self) -> Vec<CentralEvent> {
            let mut out: Vec<CentralEvent> = self.queue.lock().drain(..).collect();
            for (host, bytes) in self.wire.to_joiner.lock().drain(..) {
                out.push(CentralEvent::Chunk { host, bytes });
            }
            out
        }

        fn connect(&self, host: HostId) {
            self.connects.lock().push(host);
        }

        fn write(&self, host: HostId, bytes: &[u8]) -> Result<(), BluetoothError> {
            self.wire.to_host.lock().push_back((host, bytes.to_vec()));
            Ok(())
        }

        fn disconnect(&self, host: HostId) {
            self.disconnects.lock().push(host);
        }
    }

    /// The machine over the fakes, with its seams' records.
    struct Harness {
        machine: Machine,
        readiness: Arc<FakeReadiness>,
        peripheral: Arc<FakePeripheral>,
        central: Arc<FakeCentral>,
        serving: Arc<Mutex<Option<Fingerprint>>>,
        events: Arc<Mutex<Vec<ClientEvent>>>,
        beacon: watch::Receiver<BeaconState>,
    }

    fn fp(seed: u8) -> Fingerprint {
        Fingerprint::of(&[seed; 32])
    }

    fn offer() -> HotspotOffer {
        HotspotOffer::new("hotspot", "secret", HotspotSecurity::Wpa2, Some(54321))
    }

    impl Harness {
        fn new(state: BluetoothState) -> Self {
            Self::with(state, quiet_node(), true, false, true, Some(fp(1)))
        }

        fn with(
            state: BluetoothState,
            node: Node,
            scan: bool,
            autojoin: bool,
            prompt: bool,
            serving: Option<Fingerprint>,
        ) -> Self {
            let wire = Arc::new(Wire::new());
            let readiness = Arc::new(FakeReadiness::new(state));
            let peripheral = Arc::new(FakePeripheral::new(wire.clone()));
            let central = Arc::new(FakeCentral::new(wire));
            let serving = Arc::new(Mutex::new(serving));
            let scan = Arc::new(Mutex::new(scan));
            let autojoin = Arc::new(Mutex::new(autojoin));
            let prompt = Arc::new(Mutex::new(prompt));
            let joins: Joins = Arc::new(Mutex::new(Vec::new()));
            let events: Arc<Mutex<Vec<ClientEvent>>> = Arc::new(Mutex::new(Vec::new()));
            let (machine, beacon) = Machine::new(
                Arc::clone(&readiness) as Arc<dyn ReadinessBackend>,
                Arc::clone(&peripheral) as Arc<dyn PeripheralBackend>,
                Some(Arc::clone(&central) as Arc<dyn CentralBackend>),
                node,
                *scan.lock(),
                *autojoin.lock(),
                *prompt.lock(),
                Arc::new({
                    let serving = Arc::clone(&serving);
                    move || *serving.lock()
                }),
                Arc::new({
                    let joins = Arc::clone(&joins);
                    move |offer, reply| joins.lock().push((offer, reply))
                }),
                Arc::new({
                    let events = Arc::clone(&events);
                    move |event| events.lock().push(event)
                }),
            );
            Self {
                machine,
                readiness,
                peripheral,
                central,
                serving,
                events,
                beacon,
            }
        }

        fn beacon_state(&self) -> BeaconState {
            self.beacon.borrow().clone()
        }

        fn tick(&mut self, hosting: Option<&HotspotOffer>) {
            self.machine.tick(hosting, false);
        }

        fn host_seen(&self, host: HostId, host_fp: &Fingerprint, rssi: i16) {
            self.central.push(CentralEvent::Seen {
                host,
                service_data: Beacon::of(host_fp).to_service_data().to_vec(),
                rssi,
            });
        }

        fn host_nearby(&self) -> Vec<(HostId, [u8; 8])> {
            self.events
                .lock()
                .iter()
                .filter_map(|event| match event {
                    ClientEvent::HostNearby { host, prefix, .. } => Some((*host, *prefix)),
                    _ => None,
                })
                .collect()
        }

        fn host_gone(&self) -> Vec<HostId> {
            self.events
                .lock()
                .iter()
                .filter_map(|event| match event {
                    ClientEvent::HostGone { host } => Some(*host),
                    _ => None,
                })
                .collect()
        }
    }

    type JoinReply = oneshot::Sender<Result<IpAddr, JoinError>>;

    impl Harness {
        fn strongest_untried(&self) -> Option<HostId> {
            self.machine.strongest_untried_host()
        }
    }

    /// The host and joiner machines over one wire, each with a serving node.
    struct ExchangePair {
        host: Machine,
        host_peripheral: Arc<FakePeripheral>,
        joiner: Machine,
        joiner_central: Arc<FakeCentral>,
        joins: Arc<Mutex<Vec<(HotspotOffer, JoinReply)>>>,
        host_fp: Fingerprint,
    }

    impl ExchangePair {
        fn new() -> Self {
            let d = Deployment::new();
            let wire = Arc::new(Wire::new());
            // The host plays no joiner and the joiner plays no host, so their
            // unused roles drain a wire nothing writes to, never the live one.
            let dead_wire = Arc::new(Wire::new());
            let host_fp = Fingerprint::of(&d.host_leaf);
            let host_node = serving_node(d.root.clone(), d.host_identity);
            let joiner_node = serving_node(d.root.clone(), d.joiner_identity);
            let h_readiness = Arc::new(FakeReadiness::new(BluetoothState::Ready));
            let h_peripheral = Arc::new(FakePeripheral::new(wire.clone()));
            let h_central = Arc::new(FakeCentral::new(dead_wire.clone()));
            let h_serving = Arc::new(Mutex::new(Some(host_fp)));
            let h_events: Arc<Mutex<Vec<ClientEvent>>> = Arc::new(Mutex::new(Vec::new()));
            let (host, _h_beacon) = Machine::new(
                h_readiness,
                h_peripheral.clone(),
                Some(h_central as Arc<dyn CentralBackend>),
                host_node,
                false,
                false,
                true,
                Arc::new({
                    let serving = Arc::clone(&h_serving);
                    move || *serving.lock()
                }),
                Arc::new(move |_offer, _reply| {}),
                Arc::new({
                    let events = Arc::clone(&h_events);
                    move |event| events.lock().push(event)
                }),
            );
            let j_readiness = Arc::new(FakeReadiness::new(BluetoothState::Ready));
            let j_peripheral = Arc::new(FakePeripheral::new(dead_wire.clone()));
            let j_central = Arc::new(FakeCentral::new(wire.clone()));
            let j_serving = Arc::new(Mutex::new(Some(Fingerprint::of(&d.joiner_leaf))));
            let joins: Arc<Mutex<Vec<(HotspotOffer, JoinReply)>>> =
                Arc::new(Mutex::new(Vec::new()));
            let j_events: Arc<Mutex<Vec<ClientEvent>>> = Arc::new(Mutex::new(Vec::new()));
            let (joiner, _j_beacon) = Machine::new(
                j_readiness,
                j_peripheral,
                Some(j_central.clone() as Arc<dyn CentralBackend>),
                joiner_node,
                true,
                false,
                true,
                Arc::new({
                    let serving = Arc::clone(&j_serving);
                    move || *serving.lock()
                }),
                Arc::new({
                    let joins = Arc::clone(&joins);
                    move |offer, reply| joins.lock().push((offer, reply))
                }),
                Arc::new({
                    let events = Arc::clone(&j_events);
                    move |event| events.lock().push(event)
                }),
            );
            Self {
                host,
                host_peripheral: h_peripheral,
                joiner,
                joiner_central: j_central,
                joins,
                host_fp,
            }
        }

        /// Advertise the host's beacon and pump until `done` stands.
        async fn pump_until(&mut self, mut done: impl FnMut() -> bool) {
            let mut p = 0;
            self.host.tick(Some(&offer()), false);
            loop {
                if done() {
                    break;
                }
                p += 1;
                assert!(p < 2000, "the exchange did not complete in time");
                self.host.tick(Some(&offer()), false);
                self.joiner.tick(None, false);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    // --- The host's beacon table ---

    #[test]
    fn a_chunk_fits_both_the_packet_and_the_longest_attribute() {
        assert_eq!(chunk_size(23), 20);
        assert_eq!(chunk_size(185), 182);
        assert_eq!(chunk_size(517), 512);
        assert_eq!(chunk_size(0), 1);
    }

    #[tokio::test]
    async fn a_hosting_serving_device_starts_its_beacon() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.tick(Some(&offer()));
        assert_eq!(h.peripheral.started.lock().len(), 1);
        let prefix = fp(1).prefix();
        assert_eq!(h.beacon_state(), BeaconState::Advertising { prefix });
    }

    #[tokio::test]
    async fn a_stopped_hotspot_stops_the_beacon() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.tick(Some(&offer()));
        assert_eq!(h.peripheral.started.lock().len(), 1);
        // The hotspot stops, so the beacon stops with it.
        h.tick(None);
        assert_eq!(*h.peripheral.stopped.lock(), 1);
        assert!(matches!(h.beacon_state(), BeaconState::Off { .. }));
    }

    #[tokio::test]
    async fn a_renewal_readvertises_under_its_new_prefix() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.tick(Some(&offer()));
        assert_eq!(h.peripheral.started.lock().len(), 1);
        // A renewal changes the presented leaf, so the beacon re-advertises.
        *h.serving.lock() = Some(fp(2));
        h.tick(Some(&offer()));
        assert_eq!(h.peripheral.started.lock().len(), 2);
        let prefix = fp(2).prefix();
        assert_eq!(h.beacon_state(), BeaconState::Advertising { prefix });
    }

    #[tokio::test]
    async fn a_joiner_connecting_beneath_the_cap_runs_its_exchange() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.tick(Some(&offer()));
        h.peripheral.push(PeripheralEvent::Connected {
            device: 7,
            mtu: 517,
        });
        h.tick(Some(&offer()));
        // The exchange runs, so the platform is left connected.
        assert!(h.peripheral.disconnects.lock().is_empty());
        // Its NotServing outcome ends it on the next look.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        h.tick(Some(&offer()));
        assert_eq!(*h.peripheral.disconnects.lock(), vec![7]);
    }

    #[tokio::test]
    async fn a_fifth_connection_is_disconnected_at_once() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.tick(Some(&offer()));
        for device in 1..=4 {
            h.peripheral
                .push(PeripheralEvent::Connected { device, mtu: 517 });
        }
        h.tick(Some(&offer()));
        // Four exchanges run, so the fifth is disconnected at once.
        h.peripheral.push(PeripheralEvent::Connected {
            device: 5,
            mtu: 517,
        });
        h.tick(Some(&offer()));
        assert_eq!(*h.peripheral.disconnects.lock(), vec![5]);
    }

    #[tokio::test]
    async fn a_refused_chain_ends_its_exchange_without_an_offer() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.tick(Some(&offer()));
        h.peripheral.push(PeripheralEvent::Connected {
            device: 7,
            mtu: 517,
        });
        h.tick(Some(&offer()));
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        h.tick(Some(&offer()));
        // The exchange ends, and no offer was sent.
        assert_eq!(*h.peripheral.disconnects.lock(), vec![7]);
        assert!(h.peripheral.notifies.lock().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_exchange_ends_at_its_bound() {
        let d = Deployment::new();
        let node = serving_node(d.root.clone(), d.host_identity);
        let mut h = Harness::with(BluetoothState::Ready, node, true, false, true, Some(fp(1)));
        h.tick(Some(&offer()));
        h.peripheral.push(PeripheralEvent::Connected {
            device: 7,
            mtu: 517,
        });
        h.tick(Some(&offer()));
        // No joiner answers, so the exchange runs out its bound.
        tokio::time::sleep(EXCHANGE_BOUND + Duration::from_secs(1)).await;
        h.tick(Some(&offer()));
        assert_eq!(*h.peripheral.disconnects.lock(), vec![7]);
    }

    #[tokio::test]
    async fn bluetooth_leaving_ready_stops_the_beacon() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.tick(Some(&offer()));
        assert_eq!(h.peripheral.started.lock().len(), 1);
        *h.readiness.state.lock() = BluetoothState::Off;
        h.tick(Some(&offer()));
        assert_eq!(*h.peripheral.stopped.lock(), 1);
        assert!(matches!(h.beacon_state(), BeaconState::Off { .. }));
    }

    #[tokio::test]
    async fn bluetooth_becoming_ready_starts_the_beacon() {
        let mut h = Harness::new(BluetoothState::Off);
        h.tick(Some(&offer()));
        assert!(h.peripheral.started.lock().is_empty());
        *h.readiness.state.lock() = BluetoothState::Ready;
        h.tick(Some(&offer()));
        assert_eq!(h.peripheral.started.lock().len(), 1);
    }

    #[tokio::test]
    async fn a_host_hotspot_without_ready_bluetooth_answers_its_beacon_outcome() {
        let mut h = Harness::new(BluetoothState::Off);
        let (offer_tx, offer_rx) = oneshot::channel();
        let (reply_tx, mut reply_rx) = oneshot::channel();
        h.machine.hosted(offer_rx, reply_tx);
        h.tick(Some(&offer()));
        // Decision 21's action ran once, and the hotspot's answer went in.
        assert_eq!(*h.readiness.prompt_calls.lock(), 1);
        let _ = offer_tx.send(Ok(offer()));
        // The user declined, so the beacon's outcome is a refusal.
        *h.readiness.outcome.lock() = Some(PromptOutcome::Declined);
        h.tick(Some(&offer()));
        let hosted = reply_rx.try_recv().expect("the caller is answered");
        let Hosted { offer, beacon } = hosted.expect("the hotspot started");
        assert_eq!(offer.ssid, "hotspot");
        assert!(matches!(
            beacon,
            Err(BluetoothError::Off(PromptOutcome::Declined))
        ));
    }

    #[tokio::test]
    async fn a_closed_client_stops_the_beacon() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.tick(Some(&offer()));
        assert_eq!(h.peripheral.started.lock().len(), 1);
        h.machine.close();
        assert_eq!(*h.peripheral.stopped.lock(), 1);
        assert!(matches!(h.beacon_state(), BeaconState::Off { .. }));
    }

    // --- The joiner's scan and exchange table ---

    #[tokio::test]
    async fn scan_on_while_serving_starts_scanning() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.tick(None);
        assert!(h.central.started());
    }

    #[tokio::test]
    async fn scan_off_stops_scanning_and_reports_its_hosts_gone() {
        let mut h = Harness::new(BluetoothState::Ready);
        let host_fp = fp(9);
        h.tick(None);
        h.host_seen(1, &host_fp, -50);
        h.tick(None);
        assert_eq!(h.host_nearby(), vec![(1, host_fp.prefix())]);
        h.machine.handle(Command::SetScan(false));
        h.tick(None);
        assert!(!h.central.started());
        assert_eq!(h.host_gone(), vec![1]);
    }

    #[tokio::test]
    async fn a_new_beacon_reports_host_nearby_and_a_known_one_refreshes() {
        let mut h = Harness::new(BluetoothState::Ready);
        let host_fp = fp(9);
        h.tick(None);
        h.host_seen(1, &host_fp, -50);
        h.tick(None);
        assert_eq!(h.host_nearby(), vec![(1, host_fp.prefix())]);
        // A known prefix refreshes its signal, with no new event.
        h.host_seen(1, &host_fp, -60);
        h.tick(None);
        assert_eq!(h.host_nearby(), vec![(1, host_fp.prefix())]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_unseen_beacon_is_reported_gone_after_its_bound() {
        let mut h = Harness::new(BluetoothState::Ready);
        let host_fp = fp(9);
        h.tick(None);
        h.host_seen(1, &host_fp, -50);
        h.tick(None);
        assert_eq!(h.host_gone(), Vec::<HostId>::new());
        tokio::time::sleep(GONE_AFTER + Duration::from_secs(1)).await;
        h.tick(None);
        assert_eq!(h.host_gone(), vec![1]);
    }

    #[tokio::test]
    async fn autojoin_picks_the_strongest_untried_host() {
        let mut h = Harness::with(
            BluetoothState::Ready,
            quiet_node(),
            true,
            true,
            true,
            Some(fp(1)),
        );
        let weak = fp(10);
        let strong = fp(11);
        h.tick(None);
        h.host_seen(1, &weak, -80);
        h.host_seen(2, &strong, -40);
        h.tick(None);
        assert_eq!(*h.central.connects.lock(), vec![2]);
    }

    #[tokio::test]
    async fn a_join_without_ready_bluetooth_runs_its_action_once() {
        let mut h = Harness::new(BluetoothState::Off);
        let (reply_tx, _reply_rx) = oneshot::channel();
        h.machine.handle(Command::Fetch {
            host: 1,
            reply: reply_tx,
        });
        h.tick(None);
        assert_eq!(*h.readiness.prompt_calls.lock(), 1);
        // The user approves, so the radio stands Ready and the exchange goes.
        *h.readiness.state.lock() = BluetoothState::Ready;
        *h.readiness.outcome.lock() = Some(PromptOutcome::NotAsked);
        h.tick(None);
        assert_eq!(*h.readiness.prompt_calls.lock(), 1);
        assert_eq!(*h.central.connects.lock(), vec![1]);
    }

    #[tokio::test]
    async fn a_system_without_a_central_neither_scans_nor_joins() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.machine.central = None;
        h.tick(None);
        h.tick(None);
        assert_eq!(*h.central.starts.lock(), 0);
        let (reply_tx, mut reply_rx) = oneshot::channel();
        h.machine.handle(Command::Fetch {
            host: 1,
            reply: reply_tx,
        });
        assert!(matches!(
            reply_rx.try_recv(),
            Ok(Err(BluetoothError::Unsupported))
        ));
        assert_eq!(*h.readiness.prompt_calls.lock(), 0);
    }

    #[tokio::test]
    async fn a_manual_join_runs_its_exchange_from_its_state() {
        let mut h = Harness::new(BluetoothState::Ready);
        let (first_tx, _first_rx) = oneshot::channel();
        h.machine.handle(Command::Fetch {
            host: 1,
            reply: first_tx,
        });
        h.tick(None);
        assert_eq!(*h.central.connects.lock(), vec![1]);
        // An exchange runs, so a second call answers Busy.
        let (busy_tx, mut busy_rx) = oneshot::channel();
        h.machine.handle(Command::Fetch {
            host: 2,
            reply: busy_tx,
        });
        h.tick(None);
        let answer = busy_rx.try_recv().expect("the caller is answered");
        assert!(matches!(answer, Err(BluetoothError::Busy)));
    }

    #[tokio::test]
    async fn a_refused_or_failed_exchange_marks_its_host_tried() {
        let mut h = Harness::new(BluetoothState::Ready);
        let host_fp = fp(9);
        h.tick(None);
        h.host_seen(1, &host_fp, -50);
        h.tick(None);
        // A manual fetch, whose NotServing exchange ends refused.
        let (reply_tx, _reply_rx) = oneshot::channel();
        h.machine.handle(Command::Fetch {
            host: 1,
            reply: reply_tx,
        });
        h.tick(None);
        h.central
            .push(CentralEvent::Connected { host: 1, mtu: 517 });
        h.tick(None);
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        h.tick(None);
        // The host is marked tried, so it is no longer picked.
        assert!(h.strongest_untried().is_none());
    }

    #[tokio::test]
    async fn a_host_that_disconnects_ends_its_exchange_at_once() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.tick(None);
        h.host_seen(1, &fp(9), -50);
        h.tick(None);
        let (reply_tx, mut reply_rx) = oneshot::channel();
        h.machine.handle(Command::Fetch {
            host: 1,
            reply: reply_tx,
        });
        h.tick(None);
        assert_eq!(*h.central.connects.lock(), vec![1]);
        // The host drops the connection before it settles.
        h.central.push(CentralEvent::Disconnected { host: 1 });
        h.tick(None);
        tokio::task::yield_now().await;
        h.tick(None);
        assert!(matches!(reply_rx.try_recv(), Ok(Err(_))));
        assert!(h.strongest_untried().is_none());
    }

    #[tokio::test]
    async fn a_declined_join_marks_its_host_tried() {
        let mut pair = ExchangePair::new();
        let device: HostId = 1;
        // The host's beacon is seen, so it is tracked and untried.
        pair.joiner_central.push(CentralEvent::Seen {
            host: device,
            service_data: Beacon::of(&pair.host_fp).to_service_data().to_vec(),
            rssi: -40,
        });
        pair.joiner.tick(None, false);
        let (join_tx, mut join_rx) = oneshot::channel();
        pair.joiner.handle(Command::JoinNearby {
            host: device,
            reply: join_tx,
        });
        pair.joiner_central.push(CentralEvent::Connected {
            host: device,
            mtu: 517,
        });
        pair.host_peripheral
            .push(PeripheralEvent::Connected { device, mtu: 517 });
        let joins = Arc::clone(&pair.joins);
        pair.pump_until(|| !joins.lock().is_empty()).await;
        let (_offer, join_seam) = joins.lock().remove(0);
        // The user declines the join, so the host is marked tried.
        let _ = join_seam.send(Err(JoinError::Declined));
        pair.joiner.tick(None, false);
        let answer = join_rx.try_recv().expect("the caller is answered");
        assert!(matches!(
            answer,
            Err(JoinNearbyError::Join(JoinError::Declined))
        ));
        assert!(pair.joiner.strongest_untried_host().is_none());
    }

    #[tokio::test]
    async fn bluetooth_leaving_ready_fails_its_exchange() {
        let mut h = Harness::new(BluetoothState::Ready);
        let (reply_tx, mut reply_rx) = oneshot::channel();
        h.machine.handle(Command::Fetch {
            host: 1,
            reply: reply_tx,
        });
        h.tick(None);
        // The exchange's stream goes live.
        h.central
            .push(CentralEvent::Connected { host: 1, mtu: 517 });
        h.tick(None);
        // Bluetooth leaves Ready, so the exchange fails with BluetoothOff.
        *h.readiness.state.lock() = BluetoothState::Off;
        h.tick(None);
        let answer = reply_rx.try_recv().expect("the caller is answered");
        assert!(matches!(
            answer,
            Err(BluetoothError::Exchange(ExchangeError::Io(_)))
        ));
    }

    #[tokio::test]
    async fn bluetooth_becoming_ready_starts_its_scan() {
        let mut h = Harness::new(BluetoothState::Off);
        h.tick(None);
        h.tick(None);
        // The scan does not start while the radio stands Off.
        assert_eq!(*h.central.starts.lock(), 0);
        *h.readiness.state.lock() = BluetoothState::Ready;
        h.tick(None);
        assert!(h.central.started());
    }

    #[tokio::test]
    async fn a_closed_client_stops_its_scan_and_exchange() {
        let mut h = Harness::new(BluetoothState::Ready);
        h.tick(None);
        assert!(h.central.started());
        // An exchange runs beneath the scan.
        let (reply_tx, mut reply_rx) = oneshot::channel();
        h.machine.handle(Command::Fetch {
            host: 1,
            reply: reply_tx,
        });
        h.tick(None);
        assert_eq!(*h.central.connects.lock(), vec![1]);
        // The client closes, so the scan stops and the exchange cancels.
        h.machine.close();
        assert!(!h.central.started());
        // The cancelled exchange's answer is dropped with it.
        assert!(reply_rx.try_recv().is_err());
    }

    // --- The exchange's offer, over the machines ---

    #[tokio::test]
    async fn a_completed_exchange_sends_its_offer_and_ends() {
        let mut pair = ExchangePair::new();
        let device: HostId = 1;
        let (fetch_tx, _fetch_rx) = oneshot::channel();
        pair.joiner.handle(Command::Fetch {
            host: device,
            reply: fetch_tx,
        });
        pair.joiner_central.push(CentralEvent::Connected {
            host: device,
            mtu: 517,
        });
        pair.host_peripheral
            .push(PeripheralEvent::Connected { device, mtu: 517 });
        let host_peripheral = Arc::clone(&pair.host_peripheral);
        pair.pump_until(|| host_peripheral.disconnects.lock().contains(&device))
            .await;
        // The host sent its offer over the link, then ended the exchange.
        assert!(!pair.host_peripheral.notifies.lock().is_empty());
        assert!(pair.host_peripheral.disconnects.lock().contains(&device));
    }

    #[tokio::test]
    async fn an_exchanged_offer_reaches_its_caller_and_the_join() {
        let mut pair = ExchangePair::new();
        let device: HostId = 1;
        let (join_tx, mut join_rx) = oneshot::channel();
        pair.joiner.handle(Command::JoinNearby {
            host: device,
            reply: join_tx,
        });
        pair.joiner_central.push(CentralEvent::Connected {
            host: device,
            mtu: 517,
        });
        pair.host_peripheral
            .push(PeripheralEvent::Connected { device, mtu: 517 });
        let joins = Arc::clone(&pair.joins);
        pair.pump_until(|| !joins.lock().is_empty()).await;
        // The offer reached the join's seam.
        let (offer, join_seam) = pair.joins.lock().remove(0);
        assert_eq!(offer.ssid, "hotspot");
        assert_eq!(offer.passphrase, "secret");
        // The join answers its gateway, so the caller gets it.
        let _ = join_seam.send(Ok("192.168.43.1".parse().unwrap()));
        pair.joiner.tick(None, false);
        let gateway: IpAddr = "192.168.43.1".parse().unwrap();
        let answer = join_rx.try_recv();
        let Ok(Ok(answered)) = answer else {
            panic!("the join answers its gateway, got {answer:?}")
        };
        assert_eq!(answered, gateway);
    }

    // --- The unified runner ---

    /// A hotspot backend whose host stands Started, so the runner's host
    /// row answers its offer.
    struct FakeHotspotBackend {
        host_status: Mutex<crate::hotspot::HostStatus>,
    }

    impl FakeHotspotBackend {
        fn new() -> Self {
            Self {
                host_status: Mutex::new(crate::hotspot::HostStatus::Started {
                    ssid: "hotspot".into(),
                    passphrase: "secret".into(),
                    security: HotspotSecurity::Wpa2,
                }),
            }
        }
    }

    impl crate::hotspot::HotspotBackend for FakeHotspotBackend {
        fn request_host(&self) -> Result<(), HotspotError> {
            Ok(())
        }

        fn stop_host(&self) {}

        fn host_status(&self) -> crate::hotspot::HostStatus {
            self.host_status.lock().clone()
        }

        fn request_join(&self, _offer: &HotspotOffer) -> Result<(), JoinError> {
            Ok(())
        }

        fn leave_join(&self) {}

        fn join_status(&self) -> crate::hotspot::JoinStatus {
            crate::hotspot::JoinStatus::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_runner_answers_a_host_and_ends_with_its_channel() {
        let wire = Arc::new(Wire::new());
        let h_readiness = Arc::new(FakeReadiness::new(BluetoothState::Ready));
        let h_peripheral = Arc::new(FakePeripheral::new(wire.clone()));
        let h_central = Arc::new(FakeCentral::new(wire));
        let h_serving = Arc::new(Mutex::new(Some(fp(1))));
        let h_events: Arc<Mutex<Vec<ClientEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let (bt_machine, _bt_beacon) = Machine::new(
            h_readiness,
            h_peripheral,
            Some(h_central as Arc<dyn CentralBackend>),
            quiet_node(),
            false,
            false,
            true,
            Arc::new({
                let serving = Arc::clone(&h_serving);
                move || *serving.lock()
            }),
            Arc::new(move |_offer, _reply| {}),
            Arc::new({
                let events = Arc::clone(&h_events);
                move |event| events.lock().push(event)
            }),
        );
        let hotspot_backend: Arc<FakeHotspotBackend> = Arc::new(FakeHotspotBackend::new());
        let hotspot_events: Arc<Mutex<Vec<ClientEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let hotspot_machine = crate::hotspot::Machine::new(
            Arc::clone(&hotspot_backend) as Arc<dyn crate::hotspot::HotspotBackend>,
            false,
            Arc::new(|| Some(54321)),
            Arc::new(|_subnet| {}),
            Arc::new(|_addr| {}),
            Arc::new({
                let events = Arc::clone(&hotspot_events);
                move |event| events.lock().push(event)
            }),
        );
        let (hotspot_tx, hotspot_rx) = mpsc::unbounded_channel();
        let (bt_tx, bt_rx) = mpsc::unbounded_channel();
        let runner = run(hotspot_machine, hotspot_rx, bt_machine, bt_rx);
        let runner = tokio::spawn(async move {
            tokio::pin!(runner);
            runner.await;
        });
        let (host_tx, host_rx) = oneshot::channel();
        bt_tx
            .send(Command::Host(host_tx))
            .expect("the channel is open");
        let hosted = tokio::time::timeout(Duration::from_secs(5), host_rx)
            .await
            .expect("the host's answer arrives")
            .expect("the channel stays open");
        let hosted = hosted.expect("the hotspot starts");
        assert_eq!(hosted.offer.ssid, "hotspot");
        assert!(hosted.beacon.is_ok());
        // Both channels close, so the runner ends with them.
        drop(hotspot_tx);
        drop(bt_tx);
        tokio::time::timeout(Duration::from_secs(5), runner)
            .await
            .expect("the runner ends")
            .expect("the runner task is sound");
    }
}
