//! The hosted and joined hotspots, behind the two tables that steer them
//! (R76).
//!
//! The machine is a small loop. An API method sends a command, the machine
//! asks the backend, looks at its outcome on a tick, and applies the table's
//! transitions to the answer, the events and the seams the client gave it.
//! The proofs drive the tables through a fake backend, and the Android
//! backend reaches the bundled plugin through the application's JNI access.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use parking_lot::Mutex;
use tokio::sync::oneshot;
use zeroize::Zeroize;

use crate::ClientEvent;

#[cfg(target_os = "android")]
pub(crate) mod android;

#[cfg(target_os = "android")]
pub(crate) use android::{AndroidHotspotBackend, JoinedBind};

/// The time a hosted hotspot gets to start.
pub(crate) const HOST_BOUND: Duration = Duration::from_secs(30);
/// The time a join gets, approval included.
pub(crate) const JOIN_BOUND: Duration = Duration::from_secs(60);
/// The margin the API methods give the machine past its bound.
pub(crate) const MARGIN: Duration = Duration::from_secs(5);
/// The pace of the machine's look at the backend's outcome.
pub(crate) const TICK: Duration = Duration::from_millis(250);

/// The security a hotspot's Wi-Fi carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotspotSecurity {
    /// WPA2 personal, a passphrase.
    Wpa2,
    /// WPA3 personal, a passphrase.
    Wpa3,
}

/// The details a hosted hotspot hands to its joiners.
#[derive(Clone, PartialEq, Eq)]
pub struct HotspotOffer {
    /// The network name.
    pub ssid: String,
    /// The passphrase, redacted in the debug form and zeroed on drop.
    pub passphrase: String,
    /// The security the network carries.
    pub security: HotspotSecurity,
    /// The peer port the host serves, while the device serves it.
    pub port: Option<u16>,
}

impl HotspotOffer {
    /// An offer with its details.
    #[must_use]
    pub fn new(
        ssid: impl Into<String>,
        passphrase: impl Into<String>,
        security: HotspotSecurity,
        port: Option<u16>,
    ) -> Self {
        Self {
            ssid: ssid.into(),
            passphrase: passphrase.into(),
            security,
            port,
        }
    }
}

impl fmt::Debug for HotspotOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HotspotOffer")
            .field("ssid", &self.ssid)
            .field("passphrase", &"<redacted>")
            .field("security", &self.security)
            .field("port", &self.port)
            .finish()
    }
}

impl Drop for HotspotOffer {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

/// The reasons a hotspot will not host (R76).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HotspotError {
    /// This system cannot host a hotspot.
    #[error("this system cannot host a hotspot")]
    Unsupported,
    /// The permission `name` is not granted.
    #[error("the permission {0} is not granted")]
    MissingPermission(String),
    /// The device cannot host a hotspot in its current mode.
    #[error("the device cannot host a hotspot in its current mode")]
    Incompatible,
    /// No channel is available for the hotspot.
    #[error("no channel is available for the hotspot")]
    NoChannel,
    /// Tethering is disallowed.
    #[error("tethering is disallowed")]
    Disallowed,
    /// The hotspot did not start within its bound.
    #[error("the hotspot did not start within its bound")]
    TimedOut,
    /// The hotspot failed to start.
    #[error("the hotspot failed to start")]
    Failed,
}

/// The reasons a hotspot will not join (R76).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JoinError {
    /// This system cannot join a hotspot.
    #[error("this system cannot join a hotspot")]
    Unsupported,
    /// The permission `name` is not granted.
    #[error("the permission {0} is not granted")]
    MissingPermission(String),
    /// The network is not available to this device.
    #[error("the network is not available to this device")]
    Declined,
    /// The network did not answer within its bound.
    #[error("the network did not answer within its bound")]
    TimedOut,
    /// The join failed.
    #[error("the join failed")]
    Failed,
}

/// The host side's outcome, as the backend stands it (R76).
#[cfg_attr(
    not(any(target_os = "android", test)),
    expect(
        dead_code,
        reason = "the Android backend and the proofs construct these standings, a non-Android build reads them through the tables only"
    )
)]
#[derive(Clone)]
pub(crate) enum HostStatus {
    /// Nothing requested, or the request in flight.
    Pending,
    /// The hotspot is up, with its credentials.
    Started {
        /// The network name.
        ssid: String,
        /// The passphrase.
        passphrase: String,
        /// The security the network carries.
        security: HotspotSecurity,
    },
    /// The hotspot failed, with the mapped reason.
    Failed(HotspotError),
    /// The system or the user stopped it.
    Stopped,
}

/// The join side's outcome, as the backend stands it (R76).
#[cfg_attr(
    not(any(target_os = "android", test)),
    expect(
        dead_code,
        reason = "the Android backend and the proofs construct these standings, a non-Android build reads them through the tables only"
    )
)]
#[derive(Clone)]
pub(crate) enum JoinStatus {
    /// Nothing requested, or the request in flight.
    Pending,
    /// The network is up, with its subnet and gateway.
    Available {
        /// The device's address on the network.
        address: Ipv4Addr,
        /// The subnet's prefix length.
        prefix: u8,
        /// The network's gateway.
        gateway: IpAddr,
    },
    /// The system will not give the network.
    Unavailable,
    /// The joined network is gone.
    Lost,
}

/// The backend's side of the hotspot tables, one per system (R76).
pub(crate) trait HotspotBackend: Send + Sync {
    /// Request the hotspot, answering a missing permission or `Unsupported`
    /// at once.
    fn request_host(&self) -> Result<(), HotspotError>;
    /// Stop hosting, or cancel the pending request.
    fn stop_host(&self);
    /// What the host side stands, for the machine's look.
    fn host_status(&self) -> HostStatus;
    /// Request the offer's network, answering a missing permission or
    /// `Unsupported` at once.
    fn request_join(&self, offer: &HotspotOffer) -> Result<(), JoinError>;
    /// Leave the joined network, or cancel the pending request.
    fn leave_join(&self);
    /// What the join side stands, for the machine's look.
    fn join_status(&self) -> JoinStatus;
}

/// The backend for a system without a hotspot (R76).
pub(crate) struct UnsupportedBackend;

impl HotspotBackend for UnsupportedBackend {
    fn request_host(&self) -> Result<(), HotspotError> {
        Err(HotspotError::Unsupported)
    }

    fn stop_host(&self) {}

    fn host_status(&self) -> HostStatus {
        HostStatus::Pending
    }

    fn request_join(&self, _offer: &HotspotOffer) -> Result<(), JoinError> {
        Err(JoinError::Unsupported)
    }

    fn leave_join(&self) {}

    fn join_status(&self) -> JoinStatus {
        JoinStatus::Pending
    }
}

/// The one-shot answer the machine sends, the API methods awaiting it under
/// their bound (R76).
pub(crate) type Reply<T> = oneshot::Sender<T>;

/// The host side's standing (R76).
enum HostState {
    /// Not hosting, nothing requested.
    Off,
    /// The request in flight, with its answers and its bound.
    Starting {
        replies: Vec<Reply<Result<HotspotOffer, HotspotError>>>,
        deadline: tokio::time::Instant,
    },
    /// Hosting, with the details the answers hand out.
    Hosting { offer: HotspotOffer },
}

/// The join side's standing (R76).
enum JoinState {
    /// Not joined, nothing requested.
    Idle,
    /// The request in flight, with its answer, the offer and its bound.
    Requesting {
        offer: HotspotOffer,
        reply: Reply<Result<IpAddr, JoinError>>,
        deadline: tokio::time::Instant,
    },
    /// Joined.
    Joined,
}

/// The hotspot machine's commands, from the client's API (R76).
pub(crate) enum Command {
    /// Host the hotspot, answered with its details or the reason it will not.
    Host(Reply<Result<HotspotOffer, HotspotError>>),
    /// Stop hosting.
    StopHost,
    /// Join the offer's network, answered with its gateway.
    Join {
        /// The network to join.
        offer: HotspotOffer,
        /// The answer, once the network is up.
        reply: Reply<Result<IpAddr, JoinError>>,
    },
    /// Leave the joined network.
    Leave,
}

/// Bind the dials' sockets to a joined subnet, or stop binding (R76).
type SubnetBind = Arc<dyn Fn(Option<(Ipv4Addr, u8)>) + Send + Sync>;

/// The hotspot machine, one per client (R76).
pub(crate) struct Machine {
    pub(crate) backend: Arc<dyn HotspotBackend>,
    autolink: bool,
    /// The peer port the device serves, from its listener's standing.
    peer_port: Arc<dyn Fn() -> Option<u16> + Send + Sync>,
    /// Bind the dials' sockets to `subnet`, or stop binding with `None`.
    bind: SubnetBind,
    /// Dial one peer address, fire and forget.
    dial: Arc<dyn Fn(SocketAddr) + Send + Sync>,
    /// Emit an event to the application.
    emit: Arc<dyn Fn(ClientEvent) + Send + Sync>,
    host: HostState,
    join: JoinState,
}

impl Machine {
    /// The machine over `backend`, the peer port, subnet bind, dial and
    /// event seams and the device's autolink standing.
    pub(crate) fn new(
        backend: Arc<dyn HotspotBackend>,
        autolink: bool,
        peer_port: Arc<dyn Fn() -> Option<u16> + Send + Sync>,
        bind: SubnetBind,
        dial: Arc<dyn Fn(SocketAddr) + Send + Sync>,
        emit: Arc<dyn Fn(ClientEvent) + Send + Sync>,
    ) -> Self {
        Self {
            backend,
            autolink,
            peer_port,
            bind,
            dial,
            emit,
            host: HostState::Off,
            join: JoinState::Idle,
        }
    }

    /// The offer the host side holds, while it hosts.
    pub(crate) fn hosting_offer(&self) -> Option<HotspotOffer> {
        match &self.host {
            HostState::Hosting { offer } => Some(offer.clone()),
            _ => None,
        }
    }

    /// Whether the join side stands Joined.
    pub(crate) fn joined(&self) -> bool {
        matches!(self.join, JoinState::Joined)
    }

    /// Take `command` and steer the tables to their rows.
    pub(crate) fn handle(&mut self, command: Command) {
        match command {
            Command::Host(reply) => {
                if matches!(self.host, HostState::Off) {
                    match self.backend.request_host() {
                        Err(err) => {
                            let _ = reply.send(Err(err));
                        }
                        Ok(()) => {
                            self.host = HostState::Starting {
                                replies: vec![reply],
                                deadline: tokio::time::Instant::now() + HOST_BOUND,
                            };
                        }
                    }
                } else if let HostState::Starting { replies, .. } = &mut self.host {
                    replies.push(reply);
                } else if let HostState::Hosting { offer } = &mut self.host {
                    let mut answer = offer.clone();
                    answer.port = (self.peer_port)();
                    let _ = reply.send(Ok(answer));
                }
            }
            Command::StopHost => match core::mem::replace(&mut self.host, HostState::Off) {
                HostState::Off => {}
                HostState::Starting { replies, .. } => {
                    self.backend.stop_host();
                    for reply in replies {
                        let _ = reply.send(Err(HotspotError::Failed));
                    }
                }
                HostState::Hosting { .. } => self.backend.stop_host(),
            },
            Command::Join { offer, reply } => {
                // The earlier request cancelled, the joined network
                // released and its bind stopped, before the new request
                // goes to the tables.
                match core::mem::replace(&mut self.join, JoinState::Idle) {
                    JoinState::Idle => {}
                    JoinState::Requesting { reply: old, .. } => {
                        self.backend.leave_join();
                        let _ = old.send(Err(JoinError::Declined));
                    }
                    JoinState::Joined => {
                        self.backend.leave_join();
                        (self.bind)(None);
                    }
                }
                if let Err(err) = self.backend.request_join(&offer) {
                    let _ = reply.send(Err(err));
                } else {
                    self.join = JoinState::Requesting {
                        offer,
                        reply,
                        deadline: tokio::time::Instant::now() + JOIN_BOUND,
                    };
                }
            }
            Command::Leave => match core::mem::replace(&mut self.join, JoinState::Idle) {
                JoinState::Idle => {}
                JoinState::Requesting { reply, .. } => {
                    self.backend.leave_join();
                    let _ = reply.send(Err(JoinError::Declined));
                }
                JoinState::Joined => {
                    self.backend.leave_join();
                    (self.bind)(None);
                }
            },
        }
    }

    /// Look at the backends' outcomes and apply the tables' transitions.
    #[expect(
        clippy::too_many_lines,
        reason = "one tick walks the host and join tables' rows in order"
    )]
    pub(crate) fn tick(&mut self) {
        if matches!(self.host, HostState::Starting { .. }) {
            match self.backend.host_status() {
                HostStatus::Started {
                    ssid,
                    passphrase,
                    security,
                } => {
                    let HostState::Starting { replies, .. } =
                        core::mem::replace(&mut self.host, HostState::Off)
                    else {
                        unreachable!("the host side left Starting between the look and the take");
                    };
                    let offer = HotspotOffer::new(ssid, passphrase, security, (self.peer_port)());
                    self.host = HostState::Hosting {
                        offer: offer.clone(),
                    };
                    for reply in replies {
                        let _ = reply.send(Ok(offer.clone()));
                    }
                }
                HostStatus::Failed(err) => {
                    let HostState::Starting { replies, .. } =
                        core::mem::replace(&mut self.host, HostState::Off)
                    else {
                        unreachable!("the host side left Starting between the look and the take");
                    };
                    for reply in replies {
                        let _ = reply.send(Err(err.clone()));
                    }
                }
                HostStatus::Stopped => {
                    let HostState::Starting { replies, .. } =
                        core::mem::replace(&mut self.host, HostState::Off)
                    else {
                        unreachable!("the host side left Starting between the look and the take");
                    };
                    for reply in replies {
                        let _ = reply.send(Err(HotspotError::Failed));
                    }
                }
                HostStatus::Pending => {}
            }
            if let HostState::Starting { deadline, .. } = &self.host {
                // A real answer beats the bound, so the look comes first.
                if tokio::time::Instant::now() >= *deadline {
                    let HostState::Starting { replies, .. } =
                        core::mem::replace(&mut self.host, HostState::Off)
                    else {
                        unreachable!("the host side left Starting between the look and the take");
                    };
                    self.backend.stop_host();
                    for reply in replies {
                        let _ = reply.send(Err(HotspotError::TimedOut));
                    }
                }
            }
        } else if matches!(self.host, HostState::Hosting { .. })
            && matches!(self.backend.host_status(), HostStatus::Stopped)
        {
            self.host = HostState::Off;
            (self.emit)(ClientEvent::HotspotStopped);
        }

        if matches!(self.join, JoinState::Requesting { .. }) {
            match self.backend.join_status() {
                JoinStatus::Available {
                    address,
                    prefix,
                    gateway,
                } => {
                    let JoinState::Requesting { offer, reply, .. } =
                        core::mem::replace(&mut self.join, JoinState::Idle)
                    else {
                        unreachable!("the join side left Requesting between the look and the take");
                    };
                    (self.bind)(Some((address, prefix)));
                    let port = offer.port.filter(|_| self.autolink);
                    if let Some(port) = port {
                        (self.dial)(SocketAddr::new(gateway, port));
                    }
                    self.join = JoinState::Joined;
                    let _ = reply.send(Ok(gateway));
                }
                JoinStatus::Unavailable | JoinStatus::Lost => {
                    let JoinState::Requesting { reply, .. } =
                        core::mem::replace(&mut self.join, JoinState::Idle)
                    else {
                        unreachable!("the join side left Requesting between the look and the take");
                    };
                    let _ = reply.send(Err(JoinError::Declined));
                }
                JoinStatus::Pending => {}
            }
            let due = matches!(
                &self.join,
                JoinState::Requesting { deadline, .. } if *deadline <= tokio::time::Instant::now()
            );
            if due {
                let JoinState::Requesting { reply, .. } =
                    core::mem::replace(&mut self.join, JoinState::Idle)
                else {
                    unreachable!("the join side left Requesting between the look and the take");
                };
                self.backend.leave_join();
                let _ = reply.send(Err(JoinError::TimedOut));
            }
        } else if matches!(self.join, JoinState::Joined)
            && matches!(self.backend.join_status(), JoinStatus::Lost)
        {
            self.join = JoinState::Idle;
            (self.bind)(None);
            (self.emit)(ClientEvent::HotspotLeft);
        }
    }

    /// Apply the "Client closed" rows, for the loop's end and a dropped
    /// client.
    pub(crate) fn close(&mut self) {
        if matches!(
            self.host,
            HostState::Starting { .. } | HostState::Hosting { .. }
        ) {
            self.backend.stop_host();
        }
        if matches!(self.join, JoinState::Requesting { .. } | JoinState::Joined) {
            self.backend.leave_join();
            if matches!(self.join, JoinState::Joined) {
                (self.bind)(None);
            }
        }
        self.host = HostState::Off;
        self.join = JoinState::Idle;
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// A backend whose outcome the test steers, recording its calls.
    struct FakeBackend {
        host_request: Mutex<Result<(), HotspotError>>,
        join_request: Mutex<Result<(), JoinError>>,
        host_status: Mutex<HostStatus>,
        join_status: Mutex<JoinStatus>,
        calls: Mutex<Vec<&'static str>>,
    }

    impl FakeBackend {
        fn new() -> Self {
            Self {
                host_request: Mutex::new(Ok(())),
                join_request: Mutex::new(Ok(())),
                host_status: Mutex::new(HostStatus::Pending),
                join_status: Mutex::new(JoinStatus::Pending),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn started(&self, security: HotspotSecurity) {
            *self.host_status.lock() = HostStatus::Started {
                ssid: "hotspot".into(),
                passphrase: "secret".into(),
                security,
            };
        }

        fn available(&self) {
            *self.join_status.lock() = JoinStatus::Available {
                address: "192.168.43.1".parse().unwrap(),
                prefix: 24,
                gateway: "192.168.43.1".parse().unwrap(),
            };
        }

        fn counted(&self, call: &'static str) -> usize {
            self.calls
                .lock()
                .iter()
                .filter(|recorded| **recorded == call)
                .count()
        }
    }

    impl HotspotBackend for FakeBackend {
        fn request_host(&self) -> Result<(), HotspotError> {
            self.calls.lock().push("request_host");
            self.host_request.lock().clone()
        }

        fn stop_host(&self) {
            self.calls.lock().push("stop_host");
        }

        fn host_status(&self) -> HostStatus {
            self.host_status.lock().clone()
        }

        fn request_join(&self, _offer: &HotspotOffer) -> Result<(), JoinError> {
            self.calls.lock().push("request_join");
            self.join_request.lock().clone()
        }

        fn leave_join(&self) {
            self.calls.lock().push("leave_join");
        }

        fn join_status(&self) -> JoinStatus {
            self.join_status.lock().clone()
        }
    }

    /// The machine over a fresh fake backend, with its seams' records.
    /// A recorded subnet bind, the join's gateway and its prefix.
    type Subnets = Arc<Mutex<Vec<Option<(Ipv4Addr, u8)>>>>;

    struct Harness {
        machine: Machine,
        backend: Arc<FakeBackend>,
        port: Arc<Mutex<Option<u16>>>,
        binds: Subnets,
        dials: Arc<Mutex<Vec<SocketAddr>>>,
        events: Arc<Mutex<Vec<ClientEvent>>>,
    }

    impl Harness {
        fn new(autolink: bool) -> Self {
            let backend: Arc<FakeBackend> = Arc::new(FakeBackend::new());
            let port: Arc<Mutex<Option<u16>>> = Arc::new(Mutex::new(Some(54321)));
            let binds: Subnets = Arc::new(Mutex::new(Vec::new()));
            let dials: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));
            let events: Arc<Mutex<Vec<ClientEvent>>> = Arc::new(Mutex::new(Vec::new()));
            let machine = Machine::new(
                Arc::clone(&backend) as Arc<dyn HotspotBackend>,
                autolink,
                Arc::new({
                    let port = Arc::clone(&port);
                    move || *port.lock()
                }),
                Arc::new({
                    let binds = Arc::clone(&binds);
                    move |subnet| binds.lock().push(subnet)
                }),
                Arc::new({
                    let dials = Arc::clone(&dials);
                    move |addr| dials.lock().push(addr)
                }),
                Arc::new({
                    let events = Arc::clone(&events);
                    move |event| events.lock().push(event)
                }),
            );
            Self {
                machine,
                backend,
                port,
                binds,
                dials,
                events,
            }
        }

        fn offer(security: HotspotSecurity, port: Option<u16>) -> HotspotOffer {
            HotspotOffer::new("hotspot", "secret", security, port)
        }

        /// Host through the started row, so the tables stand at Hosting.
        fn hosting(&mut self) {
            let (reply, mut answer) = oneshot::channel();
            self.machine.handle(Command::Host(reply));
            self.backend.started(HotspotSecurity::Wpa2);
            self.machine.tick();
            assert_eq!(
                answer.try_recv().unwrap(),
                Ok(Self::offer(HotspotSecurity::Wpa2, Some(54321)))
            );
        }

        /// Join through the available row, so the tables stand at Joined.
        fn joined(&mut self) {
            let (reply, mut answer) = oneshot::channel();
            self.machine.handle(Command::Join {
                offer: Self::offer(HotspotSecurity::Wpa2, Some(54321)),
                reply,
            });
            self.backend.available();
            self.machine.tick();
            let gateway: IpAddr = "192.168.43.1".parse().unwrap();
            assert_eq!(answer.try_recv().unwrap(), Ok(gateway));
        }
    }

    /// The host row `host_hotspot | Off | a missing permission answers
    /// MissingPermission`, and the next request still goes.
    #[test]
    fn a_missing_permission_answers_the_host_request() {
        let mut h = Harness::new(true);
        *h.backend.host_request.lock() = Err(HotspotError::MissingPermission(
            "NEARBY_WIFI_DEVICES".into(),
        ));
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Host(reply));
        assert_eq!(
            answer.try_recv().unwrap(),
            Err(HotspotError::MissingPermission(
                "NEARBY_WIFI_DEVICES".into()
            ))
        );
        *h.backend.host_request.lock() = Ok(());
        let (fresh, mut fresh_answer) = oneshot::channel();
        h.machine.handle(Command::Host(fresh));
        assert_eq!(h.backend.counted("request_host"), 2);
        assert!(fresh_answer.try_recv().is_err());
    }

    /// The host rows `host_hotspot | Off | request the network` and
    /// `host_hotspot | Starting | wait on the same request`.
    #[test]
    fn a_host_request_waits_on_its_start() {
        let mut h = Harness::new(true);
        let (first, mut first_answer) = oneshot::channel();
        h.machine.handle(Command::Host(first));
        let (second, mut second_answer) = oneshot::channel();
        h.machine.handle(Command::Host(second));
        assert_eq!(h.backend.counted("request_host"), 1);
        h.backend.started(HotspotSecurity::Wpa3);
        h.machine.tick();
        let offer = Harness::offer(HotspotSecurity::Wpa3, Some(54321));
        assert_eq!(first_answer.try_recv().unwrap(), Ok(offer.clone()));
        assert_eq!(second_answer.try_recv().unwrap(), Ok(offer));
    }

    /// The host rows `Hotspot started | Starting | become Hosting` and the
    /// port present while the device serves.
    #[test]
    fn a_started_hotspot_hosts_with_its_offer() {
        let mut h = Harness::new(true);
        h.hosting();
        assert!(h.events.lock().is_empty());
        assert!(h.binds.lock().is_empty());
    }

    /// The host row `host_hotspot | Hosting | answer the current offer`,
    /// with the port as the standing has it.
    #[test]
    fn a_hosting_host_answers_the_current_offer() {
        let mut h = Harness::new(true);
        h.hosting();
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Host(reply));
        assert_eq!(
            answer.try_recv().unwrap(),
            Ok(Harness::offer(HotspotSecurity::Wpa2, Some(54321)))
        );
        // The standing loses the listener, and the port follows it.
        *h.port.lock() = None;
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Host(reply));
        assert_eq!(
            answer.try_recv().unwrap(),
            Ok(Harness::offer(HotspotSecurity::Wpa2, None))
        );
    }

    /// The host row `Hotspot failed | Starting | Off, answer the mapped
    /// error`, and the next request still goes.
    #[test]
    fn a_failed_hotspot_answers_its_mapped_error() {
        let mut h = Harness::new(true);
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Host(reply));
        *h.backend.host_status.lock() = HostStatus::Failed(HotspotError::NoChannel);
        h.machine.tick();
        assert_eq!(answer.try_recv().unwrap(), Err(HotspotError::NoChannel));
        let (fresh, mut fresh_answer) = oneshot::channel();
        h.machine.handle(Command::Host(fresh));
        assert_eq!(h.backend.counted("request_host"), 2);
        assert!(fresh_answer.try_recv().is_err());
    }

    /// The host row `30 s without an answer | Starting | cancel, Off,
    /// answer TimedOut`.
    #[tokio::test]
    async fn the_host_bound_cancels_a_request_without_an_answer() {
        tokio::time::pause();
        let mut h = Harness::new(true);
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Host(reply));
        tokio::time::advance(HOST_BOUND).await;
        h.machine.tick();
        assert_eq!(answer.try_recv().unwrap(), Err(HotspotError::TimedOut));
        assert_eq!(h.backend.counted("stop_host"), 1);
    }

    /// The host row `System or user stops it | Starting | Off, answer
    /// Failed`, the backend already stopped, so nothing cancels.
    #[test]
    fn a_system_stop_cancels_a_starting_host() {
        let mut h = Harness::new(true);
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Host(reply));
        *h.backend.host_status.lock() = HostStatus::Stopped;
        h.machine.tick();
        assert_eq!(answer.try_recv().unwrap(), Err(HotspotError::Failed));
        assert_eq!(h.backend.counted("stop_host"), 0);
    }

    /// The host rows `System or user stops it | Hosting | Off, raise
    /// HotspotStopped` and `stop_hotspot | Hosting | stop the reservation`,
    /// with no event for the user's stop.
    #[test]
    fn a_stopped_hotspot_leaves_its_host_with_its_event() {
        let mut h = Harness::new(true);
        h.hosting();
        *h.backend.host_status.lock() = HostStatus::Stopped;
        h.machine.tick();
        assert_eq!(h.events.lock().as_slice(), &[ClientEvent::HotspotStopped]);
        assert_eq!(h.backend.counted("stop_host"), 0);
    }

    #[test]
    fn a_user_stop_closes_a_hosting_host_without_its_event() {
        let mut h = Harness::new(true);
        h.hosting();
        h.machine.handle(Command::StopHost);
        assert_eq!(h.backend.counted("stop_host"), 1);
        assert!(h.events.lock().is_empty());
    }

    /// The host rows `stop_hotspot | Starting | cancel, answer the pending
    /// call Failed` and `stop_hotspot | Off | nothing`.
    #[test]
    fn a_user_stop_cancels_a_starting_host() {
        let mut h = Harness::new(true);
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Host(reply));
        h.machine.handle(Command::StopHost);
        assert_eq!(h.backend.counted("stop_host"), 1);
        assert_eq!(answer.try_recv().unwrap(), Err(HotspotError::Failed));
        h.machine.handle(Command::StopHost);
        assert_eq!(h.backend.counted("stop_host"), 1);
    }

    /// The host rows `Client closed`, across the three standings.
    #[test]
    fn a_closed_client_applies_its_host_rows() {
        let mut h = Harness::new(true);
        h.machine.close();
        assert_eq!(h.backend.counted("stop_host"), 0);

        let (reply, _answer) = oneshot::channel();
        h.machine.handle(Command::Host(reply));
        h.machine.close();
        assert_eq!(h.backend.counted("stop_host"), 1);

        let (reply, _answer) = oneshot::channel();
        h.machine.handle(Command::Host(reply));
        h.backend.started(HotspotSecurity::Wpa2);
        h.machine.tick();
        h.machine.close();
        assert_eq!(h.backend.counted("stop_host"), 2);
    }

    /// The join row `join_hotspot | Idle | a missing permission answers
    /// MissingPermission`, and the next request still goes.
    #[test]
    fn a_missing_permission_answers_the_join_request() {
        let mut h = Harness::new(true);
        *h.backend.join_request.lock() =
            Err(JoinError::MissingPermission("NEARBY_WIFI_DEVICES".into()));
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply,
        });
        assert_eq!(
            answer.try_recv().unwrap(),
            Err(JoinError::MissingPermission("NEARBY_WIFI_DEVICES".into()))
        );
        *h.backend.join_request.lock() = Ok(());
        let (fresh, mut fresh_answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply: fresh,
        });
        assert_eq!(h.backend.counted("request_join"), 2);
        assert!(fresh_answer.try_recv().is_err());
    }

    /// The join row `join_hotspot | Requesting | cancel the earlier request,
    /// request this one`, the earlier release standing before the new
    /// request.
    #[test]
    fn a_join_cancels_the_earlier_request() {
        let mut h = Harness::new(true);
        let (first, mut first_answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply: first,
        });
        let (second, mut second_answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply: second,
        });
        assert_eq!(
            h.backend.calls.lock().as_slice(),
            &["request_join", "leave_join", "request_join"],
            "the earlier request stands released before the new one goes"
        );
        assert_eq!(first_answer.try_recv().unwrap(), Err(JoinError::Declined));
        assert!(second_answer.try_recv().is_err());
    }

    /// The join row `Network available | Requesting | become Joined`, with
    /// the bind, the gateway answer and the autolink dial.
    #[test]
    fn an_available_network_joins_binds_and_answers() {
        let mut h = Harness::new(true);
        h.joined();
        let gateway: IpAddr = "192.168.43.1".parse().unwrap();
        assert_eq!(
            h.binds.lock().as_slice(),
            &[Some(("192.168.43.1".parse().unwrap(), 24))]
        );
        assert_eq!(
            h.dials.lock().as_slice(),
            &[SocketAddr::new(gateway, 54321)]
        );
    }

    /// The autolink dial, with the autolink off and with the offer's port
    /// absent.
    #[test]
    fn the_autolink_dial_follows_its_rows() {
        let mut h = Harness::new(false);
        h.joined();
        assert!(h.dials.lock().is_empty());

        let mut h = Harness::new(true);
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, None),
            reply,
        });
        h.backend.available();
        h.machine.tick();
        assert!(answer.try_recv().unwrap().is_ok());
        assert!(h.dials.lock().is_empty());
    }

    /// The join row `Network unavailable | Requesting | Idle, answer
    /// Declined`.
    #[test]
    fn an_unavailable_network_declines() {
        let mut h = Harness::new(true);
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply,
        });
        *h.backend.join_status.lock() = JoinStatus::Unavailable;
        h.machine.tick();
        assert_eq!(answer.try_recv().unwrap(), Err(JoinError::Declined));
    }

    /// The join row `60 s without an answer | Requesting | cancel, Idle,
    /// answer TimedOut`.
    #[tokio::test]
    async fn the_join_bound_cancels_a_request_without_an_answer() {
        tokio::time::pause();
        let mut h = Harness::new(true);
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply,
        });
        tokio::time::advance(JOIN_BOUND).await;
        h.machine.tick();
        assert_eq!(answer.try_recv().unwrap(), Err(JoinError::TimedOut));
        assert_eq!(h.backend.counted("leave_join"), 1);
    }

    /// The join row `Network lost | Joined | stop binding, Idle, raise
    /// HotspotLeft`.
    #[test]
    fn a_lost_network_leaves_its_join_with_its_event() {
        let mut h = Harness::new(true);
        h.joined();
        *h.backend.join_status.lock() = JoinStatus::Lost;
        h.machine.tick();
        assert_eq!(h.events.lock().as_slice(), &[ClientEvent::HotspotLeft]);
        assert_eq!(*h.binds.lock().last().unwrap(), None);
        assert_eq!(h.backend.counted("leave_join"), 0);
    }

    /// The join rows `leave_hotspot | Idle | nothing` and `| Requesting |
    /// cancel, answer the pending call Declined`.
    #[test]
    fn a_user_leave_cancels_a_requesting_join() {
        let mut h = Harness::new(true);
        h.machine.handle(Command::Leave);
        assert!(h.backend.calls.lock().is_empty());

        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply,
        });
        h.machine.handle(Command::Leave);
        assert_eq!(h.backend.counted("leave_join"), 1);
        assert_eq!(answer.try_recv().unwrap(), Err(JoinError::Declined));
    }

    /// The join row `leave_hotspot | Joined | release the network, stop
    /// binding`, with no event.
    #[test]
    fn a_user_leave_releases_a_joined_join_without_its_event() {
        let mut h = Harness::new(true);
        h.joined();
        h.machine.handle(Command::Leave);
        assert_eq!(h.backend.counted("leave_join"), 1);
        assert_eq!(*h.binds.lock().last().unwrap(), None);
        assert!(h.events.lock().is_empty());
    }

    /// The join rows `Client closed`, across the three standings.
    #[test]
    fn a_closed_client_applies_its_join_rows() {
        let mut h = Harness::new(true);
        h.machine.close();
        assert!(h.backend.calls.lock().is_empty());

        let (reply, _answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply,
        });
        h.machine.close();
        assert_eq!(h.backend.counted("leave_join"), 1);

        let (reply, _answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply,
        });
        h.backend.available();
        h.machine.tick();
        h.machine.close();
        assert_eq!(h.backend.counted("leave_join"), 2);
        assert_eq!(*h.binds.lock().last().unwrap(), None);
    }

    /// The join row `join_hotspot | Joined | release the joined network,
    /// request this one`.
    #[test]
    fn a_join_during_joined_releases_the_earlier_network() {
        let mut h = Harness::new(true);
        h.joined();
        let (reply, mut answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply,
        });
        assert_eq!(
            h.backend.calls.lock().as_slice(),
            &["request_join", "leave_join", "request_join"],
            "the network stands released before the new request goes"
        );
        assert_eq!(*h.binds.lock().last().unwrap(), None);
        assert!(answer.try_recv().is_err());
    }

    /// The join row `join_hotspot | Requesting | cancel the earlier request,
    /// request this one`, with a request that refuses at once. The earlier
    /// release still stands before it, the error answers, and the side
    /// stands idle.
    #[test]
    fn a_refused_join_request_leaves_the_side_idle() {
        let mut h = Harness::new(true);
        let (first, mut first_answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply: first,
        });
        *h.backend.join_request.lock() =
            Err(JoinError::MissingPermission("NEARBY_WIFI_DEVICES".into()));
        let (second, mut second_answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply: second,
        });
        assert_eq!(
            h.backend.calls.lock().as_slice(),
            &["request_join", "leave_join", "request_join"],
            "the earlier request stands released before the refused one"
        );
        assert_eq!(first_answer.try_recv().unwrap(), Err(JoinError::Declined));
        assert_eq!(
            second_answer.try_recv().unwrap(),
            Err(JoinError::MissingPermission("NEARBY_WIFI_DEVICES".into()))
        );
        // The side stands idle, so a good request still goes to the tables.
        *h.backend.join_request.lock() = Ok(());
        let (third, mut third_answer) = oneshot::channel();
        h.machine.handle(Command::Join {
            offer: Harness::offer(HotspotSecurity::Wpa2, Some(54321)),
            reply: third,
        });
        assert!(
            third_answer.try_recv().is_err(),
            "the good request is in flight"
        );
    }

    /// The offer's debug form hides its passphrase.
    #[test]
    fn the_offer_hides_its_passphrase_in_its_debug_form() {
        let offer = HotspotOffer::new("net", "hunter2", HotspotSecurity::Wpa3, Some(443));
        let text = format!("{offer:?}");
        assert!(!text.contains("hunter2"));
        assert!(text.contains("net"));
        assert!(text.contains("<redacted>"));
    }
}
