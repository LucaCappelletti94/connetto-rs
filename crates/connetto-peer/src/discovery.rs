//! The discovery driver, the discovery table's advertisement, browse and
//! dials behind the crate's `discovery` feature.

use mdns_sd::{
    DaemonEvent, IfKind, MDNS_PORT, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo,
};
use parking_lot::Mutex;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::warn;

use connetto_core::device_cert::DeviceIdentity;

use crate::CloseReason;
use crate::LinkError;
use crate::Node;
use crate::PeerEvent;
use crate::fingerprint::Fingerprint;
use crate::frame::PROTOCOL_VERSION;
use crate::policy::{Action, DialOutcome, Policy};

/// The service type discovery announces under.
const SERVICE_TYPE: &str = "_connetto-peer._tcp.local.";
/// The TXT key the frame version rides under.
const TXT_VERSION: &str = "v";
/// The TXT key the leaf fingerprint rides under.
const TXT_FINGERPRINT: &str = "fp";

/// What discovery tells the device about the instances it sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    /// An instance was found or resolved.
    Found {
        /// The resolved address to dial.
        address: SocketAddr,
        /// The instance's leaf fingerprint.
        fingerprint: Fingerprint,
    },
    /// An instance was removed.
    Gone {
        /// The instance's leaf fingerprint.
        fingerprint: Fingerprint,
    },
}

/// The discovery driver, one device's side of the browse.
pub struct Discovery {
    /// The node the found instances dial.
    node: Node,
    /// Whether the device dials what it finds.
    autolink: bool,
    /// The commands the driver obeys.
    tx: mpsc::UnboundedSender<Command>,
    /// The runner's command intake, until the first serve takes it.
    rx: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
    /// What the runner tells the device.
    events: mpsc::UnboundedSender<DiscoveryEvent>,
    /// The driver, once the first serve has spawned the runner.
    running: AtomicBool,
    /// The mDNS port the daemon binds.
    mdns_port: u16,
    /// The daemon restricted to the loopback, where the proofs run.
    loopback_only: bool,
}

impl std::fmt::Debug for Discovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discovery").finish_non_exhaustive()
    }
}

/// A command for the discovery's runner.
enum Command {
    /// The standing serves at `port` under `own`, or a renewal moved either.
    Serve { port: u16, own: Fingerprint },
    /// The standing left serving, so the driver stops and forgets.
    Stop,
    /// A node link event, mapped to an instance by the peer's leaf.
    NodeEvent {
        /// The peer the link reached or fell from.
        peer: DeviceIdentity,
        /// The close reason, the link fell, else the link reached.
        reason: Option<CloseReason>,
    },
    /// A dial the runner started ended.
    DialOutcome {
        /// The dialled instance.
        fp: Fingerprint,
        /// How the dial ended.
        outcome: DialOutcome,
    },
    /// A retry timer woke, so the due instances dial.
    RetryDue,
}

impl Discovery {
    /// Drive discovery for `node`, dialing what it finds when `autolink`,
    /// telling `events` what it learns.
    pub fn new(node: Node, autolink: bool, events: mpsc::UnboundedSender<DiscoveryEvent>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            node,
            autolink,
            tx,
            rx: Mutex::new(Some(rx)),
            events,
            running: AtomicBool::new(false),
            mdns_port: MDNS_PORT,
            loopback_only: false,
        }
    }

    /// The mDNS port the daemon binds, to clear the system daemon's in the
    /// proofs.
    #[must_use]
    pub fn with_mdns_port(mut self, port: u16) -> Self {
        self.mdns_port = port;
        self
    }

    /// Restrict the daemon to the loopback interface, where the proofs run.
    #[must_use]
    pub fn loopback_only(mut self) -> Self {
        self.loopback_only = true;
        self
    }

    /// Start the advertisement and the browse at the node's bound `port`
    /// under `own`, or re-register when a renewal moved either.
    pub fn serve(&self, port: u16, own: Fingerprint) {
        let started = self.running.fetch_or(true, Ordering::AcqRel);
        if !started {
            let rx = self.rx.lock().take();
            match (rx, tokio::runtime::Handle::try_current()) {
                (Some(rx), Ok(handle)) => {
                    handle.spawn(run(
                        self.node.clone(),
                        self.autolink,
                        self.mdns_port,
                        self.loopback_only,
                        rx,
                        self.tx.downgrade(),
                        self.events.clone(),
                    ));
                }
                (Some(rx), Err(_)) => {
                    self.running.store(false, Ordering::Release);
                    *self.rx.lock() = Some(rx);
                    warn!("no runtime drives the discovery, so it waits");
                    return;
                }
                (None, _) => return,
            }
        }
        let _ = self.tx.send(Command::Serve { port, own });
    }

    /// Stop the advertisement and the browse and forget every instance.
    pub fn stop(&self) {
        let _ = self.tx.send(Command::Stop);
    }

    /// Hand a node link event to the policy, which maps it by the peer's
    /// leaf.
    pub fn on_node_event(&self, event: &PeerEvent) {
        let command = match event {
            PeerEvent::Linked { peer } => Command::NodeEvent {
                peer: peer.clone(),
                reason: None,
            },
            PeerEvent::Unlinked { peer, reason } => Command::NodeEvent {
                peer: peer.clone(),
                reason: Some(*reason),
            },
            PeerEvent::ListReceived { .. } => return,
        };
        let _ = self.tx.send(command);
    }
}

/// The driver until the standing leaves, the one policy per standing.
///
/// The policy outlives a local address change, which re-browses under the
/// same standing, and is dropped when the standing leaves. The commands are
/// held weak, so the runner ends when the last driver reference is gone.
async fn run(
    node: Node,
    autolink: bool,
    mdns_port: u16,
    loopback_only: bool,
    mut commands: mpsc::UnboundedReceiver<Command>,
    commands_tx: mpsc::WeakUnboundedSender<Command>,
    events: mpsc::UnboundedSender<DiscoveryEvent>,
) {
    loop {
        let (port, own) = match commands.recv().await {
            Some(Command::Serve { port, own }) => (port, own),
            // Nothing serves, so the events nothing serves wait.
            Some(Command::NodeEvent { .. } | Command::DialOutcome { .. } | Command::RetryDue) => {
                continue;
            }
            // A stop while idle is the standing's own, and the driver waits
            // for its next serve.
            Some(Command::Stop) => continue,
            // The last driver reference is gone, so the runner ends with it.
            None => return,
        };
        // A new standing, a new policy, until the standing leaves.
        let mut policy = Policy::new(own, autolink);
        let mut current = (port, own);
        loop {
            let re_browse = serve_round(
                &node,
                mdns_port,
                loopback_only,
                &mut commands,
                &commands_tx,
                &events,
                &mut policy,
                &mut current,
            )
            .await;
            if !re_browse {
                break;
            }
            // The local addresses changed, so the same standing and the same
            // policy browse again.
        }
    }
}

/// One round of the browse, until the standing leaves or a re-browse is due.
///
/// Answers `true` when the standing holds and a re-browse is due.
#[expect(
    clippy::too_many_arguments,
    reason = "each input is a distinct channel or config"
)]
#[expect(clippy::too_many_lines, reason = "the select! loop is one unit")]
async fn serve_round(
    node: &Node,
    mdns_port: u16,
    loopback_only: bool,
    commands: &mut mpsc::UnboundedReceiver<Command>,
    commands_tx: &mpsc::WeakUnboundedSender<Command>,
    events: &mpsc::UnboundedSender<DiscoveryEvent>,
    policy: &mut Policy,
    current: &mut (u16, Fingerprint),
) -> bool {
    let (port, own) = *current;
    let daemon = match ServiceDaemon::new_with_port(mdns_port) {
        Ok(daemon) => daemon,
        Err(err) => {
            warn!(%err, "the mDNS daemon will not start, so discovery waits");
            return false;
        }
    };
    if loopback_only {
        let loopback = (|| {
            daemon.disable_interface(IfKind::All)?;
            daemon.enable_interface(IfKind::LoopbackV4)
        })();
        if let Err(err) = loopback {
            warn!(%err, "the loopback will not select, so discovery waits");
            return false;
        }
    }
    let browse = match daemon.browse(SERVICE_TYPE) {
        Ok(browse) => browse,
        Err(err) => {
            warn!(%err, "the browse will not start, so discovery waits");
            return false;
        }
    };
    let monitor = match daemon.monitor() {
        Ok(monitor) => monitor,
        Err(err) => {
            warn!(%err, "the monitor will not start, so discovery waits");
            return false;
        }
    };
    let mut names: HashMap<String, Fingerprint> = HashMap::new();
    let mut registered: Option<String> = None;
    if let Some(fullname) = register(&daemon, own, port) {
        registered = Some(fullname);
    } else {
        warn!("the advertisement will not register, so the browse alone serves");
    }
    // The round's retry timers, one per fingerprint, ending with it.
    let mut retry_timers: HashMap<Fingerprint, tokio::task::JoinHandle<()>> = HashMap::new();
    let re_browse = {
        loop {
            tokio::select! {
                command = commands.recv() => {
                    let Some(command) = command else {
                        break false;
                    };
                    match command {
                        Command::Serve { port, own } => {
                            // A renewal re-registers under a new name and
                            // fingerprint, and the advertisement follows the
                            // port.
                            if (port, own) != *current {
                                re_register(&daemon, &mut registered, policy, port, own);
                                *current = (port, own);
                            }
                        }
                        Command::Stop => break false,
                        Command::NodeEvent { peer, reason } => {
                            let Some(fp) = node.peer_fingerprint(&peer) else {
                                continue;
                            };
                            match reason {
                                None => policy.linked(fp),
                                Some(reason) => policy.unlinked(Instant::now(), fp, reason),
                            };
                            arm_retry(&mut retry_timers, commands_tx, policy, fp);
                        }
                        // The dial's truth is the link's, so a late outcome
                        // lands on the state the machine holds.
                        Command::DialOutcome { fp, outcome } => {
                            let now = Instant::now();
                            policy.dial_result(now, fp, outcome);
                            arm_retry(&mut retry_timers, commands_tx, policy, fp);
                            // The ended dial frees its place, and the due
                            // dials take their turn.
                            for queued in policy.due(now) {
                                spawn_dial(node, commands_tx, queued, policy.addresses(&queued));
                            }
                        }
                        Command::RetryDue => {
                            let now = Instant::now();
                            for fp in policy.due(now) {
                                spawn_dial(node, commands_tx, fp, policy.addresses(&fp));
                            }
                        }
                    }
                }
                event = browse.recv_async() => {
                    let Ok(event) = event else {
                        warn!("the browse channel closed, so the browse ends");
                        break false;
                    };
                    match event {
                        ServiceEvent::ServiceResolved(resolved) => {
                            let Some(fp) = fingerprint_of(&resolved) else {
                                continue;
                            };
                            let name = resolved.fullname.clone();
                            names.insert(name.clone(), fp);
                            let addresses: Vec<SocketAddr> = resolved
                                .addresses
                                .iter()
                                .map(|ip| SocketAddr::new(ip.to_ip_addr(), resolved.port))
                                .collect();
                            let actions = policy.found(&name, fp, &addresses);
                            apply(&actions, fp, node, commands_tx, events, policy);
                        }
                        ServiceEvent::ServiceRemoved(_service_type, fullname) => {
                            let Some(fp) = names.remove(&fullname) else {
                                continue;
                            };
                            // The peer may have re-advertised under a fresh
                            // name before this goodbye, so only the last
                            // name's removal reports the peer gone.
                            let last_name = !names.values().any(|still| *still == fp);
                            let actions = if last_name {
                                policy.removed(fp)
                            } else {
                                Vec::new()
                            };
                            apply(&actions, fp, node, commands_tx, events, policy);
                        }
                        // The search's own bookkeeping, which the browse owns.
                        _ => {}
                    }
                }
                event = monitor.recv_async() => {
                    match event {
                        // The host's addresses moved, so the same standing
                        // browses again, the policy holding.
                        Ok(DaemonEvent::IpAdd(_) | DaemonEvent::IpDel(_)) => {
                            policy.addresses_changed();
                            break true;
                        }
                        Ok(DaemonEvent::Error(err)) => {
                            warn!(%err, "the mDNS daemon met an error");
                        }
                        Ok(_) => {}
                        Err(_) => {
                            warn!("the monitor channel closed, so the browse ends");
                            break false;
                        }
                    }
                }
            }
        }
    };
    // The round ends, so its timers go with it.
    for (_, timer) in retry_timers.drain() {
        timer.abort();
    }
    if let Some(fullname) = registered {
        let _ = daemon.unregister(&fullname);
    }
    let _ = daemon.shutdown();
    re_browse
}

/// Register the advertisement under a fresh name at `port` carrying `own`.
fn register(daemon: &ServiceDaemon, own: Fingerprint, port: u16) -> Option<String> {
    let name = random_name();
    // The SRV target is the instance's own hostname, the one name
    // `mdns-sd` accepts for a `.local.` host.
    let host = format!("{name}.local.");
    let version = PROTOCOL_VERSION.to_string();
    let fingerprint = own.to_string();
    let props = [
        (TXT_VERSION, version.as_str()),
        (TXT_FINGERPRINT, fingerprint.as_str()),
    ];
    let info = ServiceInfo::new(SERVICE_TYPE, &name, &host, (), port, &props[..])
        .expect("the service names hold")
        .enable_addr_auto();
    let fullname = info.get_fullname().to_string();
    daemon.register(info).ok().map(|()| fullname)
}

/// Drop the old registration and register the renewal, moving the policy's
/// own fingerprint with it.
fn re_register(
    daemon: &ServiceDaemon,
    registered: &mut Option<String>,
    policy: &mut Policy,
    port: u16,
    own: Fingerprint,
) {
    if let Some(fullname) = registered.take() {
        let _ = daemon.unregister(fullname.as_str());
    }
    policy.set_own(own);
    if let Some(fullname) = register(daemon, own, port) {
        *registered = Some(fullname);
    } else {
        warn!("the renewed advertisement will not register");
    }
}

/// The actions a policy move left, told to the device and dialled.
fn apply(
    actions: &[Action],
    fp: Fingerprint,
    node: &Node,
    commands_tx: &mpsc::WeakUnboundedSender<Command>,
    events: &mpsc::UnboundedSender<DiscoveryEvent>,
    policy: &Policy,
) {
    for action in actions {
        match action {
            Action::Found(address) => {
                let _ = events.send(DiscoveryEvent::Found {
                    address: *address,
                    fingerprint: fp,
                });
            }
            Action::Gone => {
                let _ = events.send(DiscoveryEvent::Gone { fingerprint: fp });
            }
            Action::Dial => {
                spawn_dial(node, commands_tx, fp, policy.addresses(&fp));
            }
            // The browse owns its own restart, the monitor's branch.
            Action::Browse => {}
        }
    }
}

/// The retry timer one outcome arms, one per fingerprint and owned by the
/// round. A replacement deadline aborts the earlier timer, the drop of the
/// retry aborts it, and the round's end aborts the rest.
fn arm_retry(
    timers: &mut HashMap<Fingerprint, tokio::task::JoinHandle<()>>,
    commands_tx: &mpsc::WeakUnboundedSender<Command>,
    policy: &Policy,
    fp: Fingerprint,
) {
    match policy.retry_at(&fp) {
        Some(at) => {
            if let Some(earlier) = timers.remove(&fp) {
                earlier.abort();
            }
            let commands_tx = commands_tx.clone();
            let at = tokio::time::Instant::from_std(at);
            timers.insert(
                fp,
                tokio::spawn(async move {
                    tokio::time::sleep_until(at).await;
                    // The driver is gone, so the timer it served is done.
                    let Some(commands_tx) = commands_tx.upgrade() else {
                        return;
                    };
                    let _ = commands_tx.send(Command::RetryDue);
                }),
            );
        }
        // The retry dropped, so the timer that served it goes with it.
        None => {
            if let Some(earlier) = timers.remove(&fp) {
                earlier.abort();
            }
        }
    }
}

/// A dial the policy started, over the instance's addresses `IPv4` first.
fn spawn_dial(
    node: &Node,
    commands_tx: &mpsc::WeakUnboundedSender<Command>,
    fp: Fingerprint,
    addresses: Vec<SocketAddr>,
) {
    let node = node.clone();
    let commands_tx = commands_tx.clone();
    tokio::spawn(async move {
        let outcome = dial(&node, addresses).await;
        // The driver is gone, so its dial's result lands nowhere.
        let Some(commands_tx) = commands_tx.upgrade() else {
            return;
        };
        let _ = commands_tx.send(Command::DialOutcome { fp, outcome });
    });
}

/// Dial the instance's addresses, `IPv4` first, until one answers.
async fn dial(node: &Node, addresses: Vec<SocketAddr>) -> DialOutcome {
    let mut ordered: Vec<SocketAddr> = Vec::new();
    let mut rest: Vec<SocketAddr> = Vec::new();
    for address in &addresses {
        if address.is_ipv4() {
            ordered.push(*address);
        } else {
            rest.push(*address);
        }
    }
    ordered.extend(rest);
    for address in ordered {
        let linked = match node.link(address).await {
            Ok(_) => true,
            Err(LinkError::Unreachable(_) | LinkError::Timeout | LinkError::NotServing) => false,
            Err(_) => return DialOutcome::Refused,
        };
        if linked {
            return DialOutcome::Linked;
        }
    }
    DialOutcome::Unreachable
}

/// The random instance name a registration announces under.
fn random_name() -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let random = SystemRandom::new();
    let mut bytes = [0u8; 8];
    random.fill(&mut bytes).expect("the system random fills");
    bytes
        .iter()
        .fold(String::with_capacity(16), |mut name, byte| {
            name.push(char::from(HEX[usize::from(*byte >> 4)]));
            name.push(char::from(HEX[usize::from(*byte & 0xf)]));
            name
        })
}

/// The fingerprint a hex TXT value carries, when it carries one.
fn fingerprint_text(text: &str) -> Option<Fingerprint> {
    // A fingerprint is exactly 64 hex characters, and a shorter value is a
    // different record, not a truncated one.
    if text.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(Fingerprint::new(bytes))
}

/// The fingerprint a resolved instance carries, when it carries one.
fn fingerprint_of(resolved: &ResolvedService) -> Option<Fingerprint> {
    let value = resolved
        .txt_properties
        .get_property_val(TXT_FINGERPRINT)
        .and_then(|value| value)?;
    let text = std::str::from_utf8(value).ok()?;
    fingerprint_text(text)
}

#[cfg(test)]
mod tests {
    use super::fingerprint_text;
    use crate::fingerprint::Fingerprint;

    /// The TXT fingerprint is exactly 64 hex characters, or nothing.
    #[test]
    fn a_fingerprint_is_exactly_sixty_four_hex_characters() {
        let fingerprint = Fingerprint::new([0xab; 32]);
        let hex = fingerprint.to_string();
        assert_eq!(
            fingerprint_text(&hex),
            Some(fingerprint),
            "the full value holds"
        );
        assert_eq!(
            fingerprint_text(&hex[..62]),
            None,
            "a short value is refused"
        );
        assert_eq!(
            fingerprint_text(&hex[..63]),
            None,
            "an odd length is refused"
        );
        assert_eq!(
            fingerprint_text(&format!("zz{}", &hex[2..])),
            None,
            "a non-hex value is refused"
        );
    }

    /// The retry timer stands one per fingerprint. A replacement deadline
    /// aborts the earlier timer, and the round's end aborts the rest.
    #[tokio::test]
    async fn a_replaced_retry_timer_aborts_its_predecessor() {
        use super::{Command, arm_retry};
        use crate::policy::{DialOutcome, FIRST_WAIT, Policy};
        use std::collections::HashMap;
        use std::time::{Duration, Instant};
        use tokio::sync::mpsc;

        tokio::time::pause();
        let (tx, mut rx) = mpsc::unbounded_channel::<Command>();
        let weak = tx.downgrade();
        let fp = Fingerprint::new([1; 32]);
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 443));
        let mut policy = Policy::new(Fingerprint::new([0; 32]), true);
        policy.found("n", fp, &[addr]);
        // The dial ends unreachable, so the first retry is due after the
        // first wait, and the next outcome moves the deadline.
        policy.dial_result(Instant::now(), fp, DialOutcome::Unreachable);
        let mut timers: HashMap<Fingerprint, tokio::task::JoinHandle<()>> = HashMap::new();
        arm_retry(&mut timers, &weak, &policy, fp);
        assert_eq!(timers.len(), 1, "one timer stands for the instance");
        policy.dial_result(Instant::now(), fp, DialOutcome::Unreachable);
        arm_retry(&mut timers, &weak, &policy, fp);
        assert_eq!(timers.len(), 1, "the replacement stands alone");
        // The earlier deadline passes, and its aborted timer wakes nothing.
        tokio::time::advance(FIRST_WAIT + Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
        assert!(rx.try_recv().is_err(), "the aborted timer woke late");
        // The replacement deadline passes, and its timer wakes once.
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert!(
            matches!(rx.try_recv().ok(), Some(Command::RetryDue)),
            "the replacement wakes its dial"
        );
        assert!(rx.try_recv().is_err(), "one wake per timer");
    }
}
