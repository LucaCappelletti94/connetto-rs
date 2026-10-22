//! The discovery driver, the discovery table's advertisement, browse and
//! dials behind the crate's `discovery` feature.

use mdns_sd::{DaemonEvent, IfKind, MDNS_PORT, ServiceDaemon, ServiceEvent, ServiceInfo};
use parking_lot::Mutex;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
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

/// The DNS-SD service type discovery advertises and browses, without its domain.
pub const DNS_SD_SERVICE: &str = "_connetto-peer._tcp";
/// The service type in the `local.` domain, as `mdns-sd` names it.
const SERVICE_TYPE: &str = "_connetto-peer._tcp.local.";
/// The TXT key the frame version rides under.
const TXT_VERSION: &str = "v";
/// The TXT key the leaf fingerprint rides under.
const TXT_FINGERPRINT: &str = "fp";

/// What a DNS-SD session reports about the service type it browses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsSdEvent {
    /// The instance `name` stands at `addresses` with its TXT pairs, the full set replacing any earlier one.
    Resolved {
        /// The instance's name, as the session reports it.
        name: String,
        /// The instance's TXT pairs, a key without a value carrying none.
        txt: Vec<(String, Option<Vec<u8>>)>,
        /// Every address the instance answers at, with its port.
        addresses: Vec<SocketAddr>,
    },
    /// The instance `name` left.
    Removed {
        /// The instance's name, as the session reports it.
        name: String,
    },
    /// The session can no longer serve, so the round opens a fresh one.
    Restart,
    /// A fault the session survives, for the log.
    Fault(String),
}

/// Where a DNS-SD session reports its events.
pub type DnsSdSink = Box<dyn FnMut(DnsSdEvent) + Send>;

/// A platform's DNS-SD service, browsing [`DNS_SD_SERVICE`] and advertising under it.
pub trait DnsSd: Send + Sync {
    /// Open a session that browses the service type and reports to `events`.
    ///
    /// # Errors
    ///
    /// When the platform's service will not start.
    fn open(&self, events: DnsSdSink) -> io::Result<Box<dyn DnsSdSession>>;
}

/// One browse and its advertisements, all ended when the session drops.
pub trait DnsSdSession: Send {
    /// Advertise the instance `name` at `port` with the TXT pairs `txt`.
    ///
    /// # Errors
    ///
    /// When the session no longer runs or refuses the advertisement.
    fn register(&mut self, name: &str, port: u16, txt: &[(&str, &str)]) -> io::Result<()>;

    /// End the advertisement `name`.
    fn unregister(&mut self, name: &str);
}

/// The `mdns-sd` daemon in the process, the default DNS-SD service.
#[derive(Debug, Clone, Copy)]
struct MdnsSd {
    /// The mDNS port the daemon binds.
    port: u16,
    /// The daemon restricted to the loopback, where the proofs run.
    loopback_only: bool,
}

/// One `mdns-sd` daemon, its browse forwarded by a task.
struct MdnsSdSession {
    daemon: ServiceDaemon,
    /// The full names the advertisements went out under, by instance name.
    registered: HashMap<String, String>,
    forward: tokio::task::JoinHandle<()>,
}

impl DnsSd for MdnsSd {
    fn open(&self, mut events: DnsSdSink) -> io::Result<Box<dyn DnsSdSession>> {
        let daemon = ServiceDaemon::new_with_port(self.port).map_err(io::Error::other)?;
        let started = (|| {
            if self.loopback_only {
                daemon.disable_interface(IfKind::All)?;
                daemon.enable_interface(IfKind::LoopbackV4)?;
            }
            Ok::<_, mdns_sd::Error>((daemon.browse(SERVICE_TYPE)?, daemon.monitor()?))
        })();
        let (browse, monitor) = match started {
            Ok(channels) => channels,
            Err(err) => {
                let _ = daemon.shutdown();
                return Err(io::Error::other(err));
            }
        };
        let forward = tokio::spawn(async move {
            loop {
                let event = tokio::select! {
                    event = browse.recv_async() => {
                        let Ok(event) = event else { return };
                        match event {
                            ServiceEvent::ServiceResolved(resolved) => DnsSdEvent::Resolved {
                                txt: resolved
                                    .txt_properties
                                    .iter()
                                    .map(|pair| (pair.key().to_owned(), pair.val().map(<[u8]>::to_vec)))
                                    .collect(),
                                addresses: resolved
                                    .addresses
                                    .iter()
                                    .map(|ip| SocketAddr::new(ip.to_ip_addr(), resolved.port))
                                    .collect(),
                                name: resolved.fullname,
                            },
                            ServiceEvent::ServiceRemoved(_service_type, fullname) => {
                                DnsSdEvent::Removed { name: fullname }
                            }
                            // The search's own bookkeeping, which the browse owns.
                            _ => continue,
                        }
                    }
                    event = monitor.recv_async() => {
                        let Ok(event) = event else { return };
                        match event {
                            // The host's addresses moved, so the round browses again.
                            DaemonEvent::IpAdd(_) | DaemonEvent::IpDel(_) => DnsSdEvent::Restart,
                            DaemonEvent::Error(err) => DnsSdEvent::Fault(err.to_string()),
                            _ => continue,
                        }
                    }
                };
                events(event);
            }
        });
        Ok(Box::new(MdnsSdSession {
            daemon,
            registered: HashMap::new(),
            forward,
        }))
    }
}

impl DnsSdSession for MdnsSdSession {
    fn register(&mut self, name: &str, port: u16, txt: &[(&str, &str)]) -> io::Result<()> {
        // The SRV target is the instance's own hostname, the one name
        // `mdns-sd` accepts for a `.local.` host.
        let host = format!("{name}.local.");
        let info = ServiceInfo::new(SERVICE_TYPE, name, &host, (), port, txt)
            .map_err(io::Error::other)?
            .enable_addr_auto();
        let fullname = info.get_fullname().to_owned();
        self.daemon.register(info).map_err(io::Error::other)?;
        self.registered.insert(name.to_owned(), fullname);
        Ok(())
    }

    fn unregister(&mut self, name: &str) {
        if let Some(fullname) = self.registered.remove(name) {
            let _ = self.daemon.unregister(&fullname);
        }
    }
}

impl Drop for MdnsSdSession {
    fn drop(&mut self) {
        for (_, fullname) in self.registered.drain() {
            let _ = self.daemon.unregister(&fullname);
        }
        let _ = self.daemon.shutdown();
        self.forward.abort();
    }
}

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
    /// The default `mdns-sd` service's settings.
    mdns: MdnsSd,
    /// The platform's DNS-SD service, in place of `mdns-sd`.
    platform: Option<Arc<dyn DnsSd>>,
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
            mdns: MdnsSd {
                port: MDNS_PORT,
                loopback_only: false,
            },
            platform: None,
        }
    }

    /// The mDNS port the daemon binds, to clear the system daemon's in the
    /// proofs.
    #[must_use]
    pub fn with_mdns_port(mut self, port: u16) -> Self {
        self.mdns.port = port;
        self
    }

    /// Restrict the daemon to the loopback interface, where the proofs run.
    #[must_use]
    pub fn loopback_only(mut self) -> Self {
        self.mdns.loopback_only = true;
        self
    }

    /// Advertise and browse through the platform's DNS-SD service in place of `mdns-sd`.
    #[must_use]
    pub fn with_dns_sd(mut self, dns_sd: Arc<dyn DnsSd>) -> Self {
        self.platform = Some(dns_sd);
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
                        self.platform.clone().unwrap_or_else(|| Arc::new(self.mdns)),
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
    dns_sd: Arc<dyn DnsSd>,
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
                dns_sd.as_ref(),
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
#[expect(clippy::too_many_lines, reason = "the select! loop is one unit")]
async fn serve_round(
    node: &Node,
    dns_sd: &dyn DnsSd,
    commands: &mut mpsc::UnboundedReceiver<Command>,
    commands_tx: &mpsc::WeakUnboundedSender<Command>,
    events: &mpsc::UnboundedSender<DiscoveryEvent>,
    policy: &mut Policy,
    current: &mut (u16, Fingerprint),
) -> bool {
    let (port, own) = *current;
    let (found_tx, mut found) = mpsc::unbounded_channel();
    let sink: DnsSdSink = Box::new(move |event| {
        let _ = found_tx.send(event);
    });
    let mut session = match dns_sd.open(sink) {
        Ok(session) => session,
        Err(err) => {
            warn!(%err, "the DNS-SD service will not start, so discovery waits");
            return false;
        }
    };
    let mut names: HashMap<String, Fingerprint> = HashMap::new();
    let mut registered = register(session.as_mut(), own, port);
    if registered.is_none() {
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
                                re_register(session.as_mut(), &mut registered, policy, port, own);
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
                event = found.recv() => {
                    let Some(event) = event else {
                        warn!("the DNS-SD session ended, so the browse ends");
                        break false;
                    };
                    match event {
                        DnsSdEvent::Resolved { name, txt, addresses } => {
                            let Some(fp) = fingerprint_of(&txt) else {
                                continue;
                            };
                            names.insert(name.clone(), fp);
                            let actions = policy.found(&name, fp, &addresses);
                            apply(&actions, fp, node, commands_tx, events, policy);
                        }
                        DnsSdEvent::Removed { name } => {
                            let Some(fp) = names.remove(&name) else {
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
                        // The same standing browses again, the policy holding.
                        DnsSdEvent::Restart => {
                            policy.addresses_changed();
                            break true;
                        }
                        DnsSdEvent::Fault(fault) => {
                            warn!(%fault, "the DNS-SD service met a fault");
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
    if let Some(name) = registered {
        session.unregister(&name);
    }
    re_browse
}

/// Register the advertisement under a fresh name at `port` carrying `own`.
fn register(session: &mut dyn DnsSdSession, own: Fingerprint, port: u16) -> Option<String> {
    let name = random_name();
    let version = PROTOCOL_VERSION.to_string();
    let fingerprint = own.to_string();
    let props = [
        (TXT_VERSION, version.as_str()),
        (TXT_FINGERPRINT, fingerprint.as_str()),
    ];
    match session.register(&name, port, &props) {
        Ok(()) => Some(name),
        Err(err) => {
            warn!(%err, "the advertisement was refused");
            None
        }
    }
}

/// Drop the old registration and register the renewal, moving the policy's
/// own fingerprint with it.
fn re_register(
    session: &mut dyn DnsSdSession,
    registered: &mut Option<String>,
    policy: &mut Policy,
    port: u16,
    own: Fingerprint,
) {
    if let Some(name) = registered.take() {
        session.unregister(&name);
    }
    policy.set_own(own);
    *registered = register(session, own, port);
    if registered.is_none() {
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

/// The fingerprint a resolved instance's TXT pairs carry, when they carry one.
fn fingerprint_of(txt: &[(String, Option<Vec<u8>>)]) -> Option<Fingerprint> {
    let value = txt
        .iter()
        .find(|(key, _)| key == TXT_FINGERPRINT)
        .and_then(|(_, value)| value.as_deref())?;
    let hex = std::str::from_utf8(value).ok()?;
    fingerprint_text(hex)
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
