//! The node: the served identity, the dials, the kept lists, and the links.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use connetto_core::device_cert::{
    DeviceCertificate, DeviceIdentity, KeyId, RevocationList, certificate_key_id,
    certificate_serial, key_id,
};
use parking_lot::{Mutex, RwLock};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ServerConfig, version};
use serde_bytes::ByteBuf;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, warn};

use crate::error::{CloseReason, LinkError, Refusal, TrustError};
use crate::event::PeerEvent;
use crate::frame::{FrameError, PROTOCOL_VERSION, PeerFrame, read_frame, write_frame};
use crate::identity::{Clock, Identity, Trust};
use crate::signer::{IdentityClientCert, IdentityServerCert};
use crate::verify::{Crl, KeptList, PeerVerifier};

/// The time a dial gives its connect.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The time a dial gives the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// The time a dial gives the hello exchange.
pub(crate) const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// The time a frame write gets before the peer is taken to have stalled.
pub(crate) const WRITE_BOUND: Duration = Duration::from_secs(10);
/// The pace of the liveness pings.
pub(crate) const PING_EVERY: Duration = Duration::from_secs(15);
/// The silence that takes a link down.
pub(crate) const SILENCE_LIMIT: Duration = Duration::from_secs(45);
const DIAL_NAME: &str = "connetto-peer";

/// The links' liveness bounds, the ping pace and the silence that takes a
/// link down.
#[derive(Clone, Copy, Debug)]
pub struct Liveness {
    /// The pace of the liveness pings.
    pub ping_every: Duration,
    /// The silence that takes a link down.
    pub silence_limit: Duration,
}

impl Default for Liveness {
    fn default() -> Self {
        Self {
            ping_every: PING_EVERY,
            silence_limit: SILENCE_LIMIT,
        }
    }
}

/// The node's shared state, behind an `Arc` for its tasks.
pub(crate) struct NodeState {
    trust: Trust,
    root_key_ids: Vec<KeyId>,
    pub(crate) verifier: PeerVerifier,
    own_key: Arc<RwLock<Option<KeyId>>>,
    identity: RwLock<Option<Identity>>,
    lists: Arc<RwLock<Vec<KeptList>>>,
    /// The kept CRLs, a snapshot swapped by `keep_list`.
    crls: Arc<RwLock<Arc<[Crl]>>>,
    /// The live links and the peers awaiting their keeper, under one lock so
    /// a close and a registration never race.
    pub(crate) links: Mutex<HashMap<KeyId, SlotState>>,
    listener: RwLock<Option<ListenerSlot>>,
    /// Whether the node still serves, checked under the links lock.
    pub(crate) serving: AtomicBool,
    /// The monotonic dial counter a `Hello` carries.
    pub(crate) dial_count: Mutex<u64>,
    /// The registration order, to tell a replaced slot apart.
    next_seq: Mutex<u64>,
    pub(crate) events: mpsc::UnboundedSender<PeerEvent>,
    pub(crate) ping_every: Duration,
    pub(crate) silence_limit: Duration,
}

/// One entry per peer, under the node's single links lock.
pub(crate) enum SlotState {
    /// A live link to the peer.
    Live(LinkSlot),
    /// A link to the peer that just closed with `Duplicate`, waiting for the
    /// kept link to register.
    AwaitingKeeper(DeviceIdentity),
}

impl fmt::Debug for NodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeState").finish_non_exhaustive()
    }
}

/// A live link to a peer, beside what a close or a forward needs.
pub(crate) struct LinkSlot {
    /// What the certificate names.
    pub(crate) peer: DeviceIdentity,
    /// The peer's leaf, DER.
    pub(crate) leaf: Vec<u8>,
    /// The peer's issuer, DER.
    pub(crate) issuer: Vec<u8>,
    /// The revocation list numbers the peer has, by issuer key id.
    pub(crate) numbers: BTreeMap<[u8; 32], u64>,
    /// The key id of the side that dialed this connection.
    dialer: KeyId,
    /// The dial counter the dialer's `Hello` carried, for the duplicate rule.
    dial: u64,
    /// The registration order, to tell a replaced slot apart.
    pub(crate) seq: u64,
    /// The commands the frame task obeys, unbounded so a revocation is never
    /// dropped.
    command: mpsc::UnboundedSender<LinkCommand>,
    /// The frame task, once spawned.
    task: Option<tokio::task::JoinHandle<()>>,
}

/// A command for a link's frame task.
pub(crate) enum LinkCommand {
    /// Close the link with a reason.
    Close(CloseReason),
    /// Deliver a revocation list the peer lacks.
    List {
        /// The list, DER.
        list: Vec<u8>,
        /// The signer's certificate, DER.
        signer: Vec<u8>,
        /// The list's issuer key id.
        issuer: KeyId,
        /// The list's number.
        number: u64,
    },
    /// Hand the renewed chain to the link still holding the old one.
    Certificate {
        /// The renewed leaf, DER.
        leaf: Vec<u8>,
        /// The renewed leaf's issuer, DER.
        issuer: Vec<u8>,
    },
}

/// The served listener, beside what stops it.
struct ListenerSlot {
    /// The bound address.
    addr: SocketAddr,
    /// The stop flag.
    stop: watch::Sender<bool>,
}

/// The peer link's node, one device's side of the loopback.
#[derive(Clone)]
pub struct Node {
    state: Arc<NodeState>,
    /// Shared by every handle, so its drop runs once, with the last one.
    _lifetime: Arc<Lifetime>,
}

/// Closes the listener and every link when the last `Node` handle drops.
struct Lifetime(Arc<NodeState>);

impl Drop for Lifetime {
    fn drop(&mut self) {
        stop_state(&self.0, CloseReason::Closed);
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.state.fmt(f)
    }
}

impl Node {
    /// Build the node on a trust, behind `clock`, telling `events` what it
    /// learns about its links.
    ///
    /// # Errors
    ///
    /// [`TrustError`] when a deployment root holds no key.
    pub fn new(
        trust: Trust,
        clock: Arc<dyn Clock>,
        events: mpsc::UnboundedSender<PeerEvent>,
    ) -> Result<Self, TrustError> {
        Self::with_liveness(trust, clock, events, Liveness::default())
    }

    /// Build the node with its links' liveness bounds, `liveness`'s ping
    /// pace and silence limit.
    ///
    /// # Errors
    ///
    /// [`TrustError`] when a deployment root holds no key.
    pub fn with_liveness(
        trust: Trust,
        clock: Arc<dyn Clock>,
        events: mpsc::UnboundedSender<PeerEvent>,
        liveness: Liveness,
    ) -> Result<Self, TrustError> {
        let root_key_ids = trust
            .roots
            .iter()
            .enumerate()
            .map(|(index, root)| {
                certificate_key_id(root).map_err(|source| TrustError::Root { index, source })
            })
            .collect::<Result<_, _>>()?;
        let own_key = Arc::new(RwLock::new(None));
        let lists = Arc::new(RwLock::new(Vec::new()));
        let crls = Arc::new(RwLock::new(Arc::from(Vec::<Crl>::new().into_boxed_slice())));
        let verifier = PeerVerifier::new(&trust, clock, Arc::clone(&own_key), Arc::clone(&crls));
        let state = Arc::new(NodeState {
            trust,
            root_key_ids,
            verifier,
            own_key,
            identity: RwLock::new(None),
            lists,
            crls,
            links: Mutex::new(HashMap::new()),
            listener: RwLock::new(None),
            serving: AtomicBool::new(false),
            dial_count: Mutex::new(0),
            next_seq: Mutex::new(0),
            events,
            ping_every: liveness.ping_every,
            silence_limit: liveness.silence_limit,
        });
        Ok(Self {
            _lifetime: Arc::new(Lifetime(Arc::clone(&state))),
            state,
        })
    }

    /// Present `identity` on `listen`, keeping the port and the live links
    /// when the node already serves.
    ///
    /// # Errors
    ///
    /// [`io::Error`] when the port will not bind or the runtime cannot
    /// drive the acceptor.
    pub fn serve(&self, listen: SocketAddr, identity: Identity) -> io::Result<SocketAddr> {
        *self.state.own_key.write() = Some(key_id(&*identity.key));
        let renewed = {
            let mut identity_slot = self.state.identity.write();
            let renewed = identity_slot
                .as_ref()
                .is_none_or(|held| held.certificate != identity.certificate);
            *identity_slot = Some(identity);
            renewed
        };
        if let Some(slot) = self.state.listener.read().as_ref() {
            // The port and the live links stay, and a changed presented
            // chain reaches them.
            if renewed {
                self.renew_links();
            }
            return Ok(slot.addr);
        }
        let std_listener = std::net::TcpListener::bind(listen)?;
        std_listener.set_nonblocking(true)?;
        let addr = std_listener.local_addr()?;
        let (stop_tx, stop_rx) = watch::channel(false);
        let listener = TcpListener::from_std(std_listener)?;
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("no tokio runtime drives the acceptor"))?;
        let state = Arc::clone(&self.state);
        handle.spawn(accept_loop(state, listener, stop_rx));
        *self.state.listener.write() = Some(ListenerSlot {
            addr,
            stop: stop_tx,
        });
        self.state.serving.store(true, Ordering::Release);
        Ok(addr)
    }

    /// Hand the node's current chain to the live links, which verify it as at
    /// a handshake and move their expiry deadline.
    fn renew_links(&self) {
        let identity_slot = self.state.identity.read();
        let held = identity_slot.as_ref().expect("serving holds an identity");
        let links = self.state.links.lock();
        for slot_state in links.values() {
            if let SlotState::Live(slot) = slot_state {
                let _ = slot.command.send(LinkCommand::Certificate {
                    leaf: held.certificate.clone(),
                    issuer: held.issuer.clone(),
                });
            }
        }
    }

    /// Close every link with `reason` and drop the listener.
    pub fn stop(&self, reason: CloseReason) {
        stop_state(&self.state, reason);
    }

    /// The bound address, while the node serves.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.state.listener.read().as_ref().map(|slot| slot.addr)
    }

    /// Dial `addr`, answering the peer's identity once the link is live.
    ///
    /// # Errors
    ///
    /// [`LinkError`] naming the failed phase or the refusal.
    ///
    /// # Panics
    ///
    /// When the peer's presented chain cannot be parsed as device
    /// certificates.
    pub async fn link(&self, addr: SocketAddr) -> Result<DeviceIdentity, LinkError> {
        let identity = self
            .state
            .identity
            .read()
            .clone()
            .ok_or(LinkError::NotServing)?;
        let dial = {
            let mut dial_count = self.state.dial_count.lock();
            *dial_count += 1;
            *dial_count
        };
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| LinkError::Timeout)?
            .map_err(LinkError::Unreachable)?;
        let config = client_config_for(
            &self.state.trust,
            self.state.verifier.clock(),
            *self.state.own_key.read(),
            Arc::clone(&self.state.crls),
            &identity,
        );
        let connector = TlsConnector::from(config);
        let domain = ServerName::try_from(DIAL_NAME).expect("a valid dial name");
        let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(domain, tcp))
            .await
            .map_err(|_| LinkError::Timeout)?
            .map_err(map_tls)?;
        let (leaf, issuer) = {
            let certs = tls
                .get_ref()
                .1
                .peer_certificates()
                .expect("the client auth is mandatory");
            let (Some(leaf), Some(issuer)) = (certs.first(), certs.get(1)) else {
                return Err(LinkError::Protocol(
                    "the peer presented no issuer certificate".into(),
                ));
            };
            (leaf.to_vec(), issuer.to_vec())
        };
        let peer = DeviceCertificate::parse(&leaf)
            .expect("the profile was verified at the handshake")
            .identity()
            .clone();
        let mut tls = tls;
        let (peer_numbers, _peer_dial) = exchange_hello(&mut tls, &self.state, dial).await?;
        register_link(
            &self.state,
            Handshaken {
                peer: peer.clone(),
                leaf,
                issuer,
                numbers: peer_numbers,
                dialer: key_id(&*identity.key),
                dial,
            },
            tls,
        )?;
        Ok(peer)
    }

    /// Keep `list`, signed by `signer`, and forward it to the links that
    /// lack it.
    ///
    /// The caller's intake already accepted the list as newer.
    pub fn keep_list(&self, list: Vec<u8>, signer: Vec<u8>) {
        let issuer = match certificate_key_id(&signer) {
            Ok(issuer) => issuer,
            Err(err) => {
                warn!(%err, "a kept list names no usable issuer");
                return;
            }
        };
        let parsed = match RevocationList::verify(&list, &signer, &self.state.trust.roots) {
            Ok(parsed) => parsed,
            Err(err) => {
                warn!(%err, "a kept list failed verification");
                return;
            }
        };
        let number = parsed.number();
        let crl = webpki::OwnedCertRevocationList::from_der(&list).ok();
        let kept = KeptList {
            issuer,
            number,
            der: list,
            signer,
            parsed,
            crl,
        };
        {
            let mut lists = self.state.lists.write();
            if let Some(existing) = lists.iter().find(|l| l.issuer == issuer)
                && existing.number >= kept.number
            {
                return;
            }
            lists.retain(|l| l.issuer != issuer);
            lists.push(kept.clone());
            // Rebuild the CRL snapshot, so a handshake sees the new list.
            let crls: Vec<Crl> = lists
                .iter()
                .filter_map(|kept| kept.crl.as_ref().map(|crl| Crl::Owned(crl.clone())))
                .collect();
            *self.state.crls.write() = Arc::from(crls.into_boxed_slice());
        }
        // Forward the list to the links that lack it, then close the links
        // the list revokes. A link the list revokes receives it first, so
        // the peer's intake can react to its own revocation, and the command
        // channel is unbounded, so a revocation is never dropped.
        let links = self.state.links.lock();
        for slot_state in links.values() {
            let SlotState::Live(slot) = slot_state else {
                continue;
            };
            let lacks = slot
                .numbers
                .get(&issuer.as_bytes()[..])
                .is_none_or(|had| kept.number > *had);
            if lacks {
                let _ = slot.command.send(LinkCommand::List {
                    list: kept.der.clone(),
                    signer: kept.signer.clone(),
                    issuer,
                    number: kept.number,
                });
            }
            if chain_revoked(&self.state, &slot.leaf, &slot.issuer) {
                let _ = slot
                    .command
                    .send(LinkCommand::Close(CloseReason::PeerRevoked));
            }
        }
    }
}

/// Close every link with `reason` and drop the listener.
fn stop_state(state: &NodeState, reason: CloseReason) {
    // A stopped node presents nothing, so it dials nobody until it serves again.
    *state.identity.write() = None;
    *state.own_key.write() = None;
    if let Some(slot) = state.listener.write().take() {
        let _ = slot.stop.send(true);
    }
    let drained: Vec<SlotState> = {
        let mut links = state.links.lock();
        state.serving.store(false, Ordering::Release);
        links.drain().map(|(_, slot_state)| slot_state).collect()
    };
    for slot_state in drained {
        match slot_state {
            SlotState::Live(slot) => {
                let _ = slot.command.send(LinkCommand::Close(reason));
                if let Some(task) = slot.task {
                    task.abort();
                }
                state
                    .events
                    .send(PeerEvent::Unlinked {
                        peer: slot.peer,
                        reason,
                    })
                    .ok();
            }
            SlotState::AwaitingKeeper(peer) => {
                state.events.send(PeerEvent::Unlinked { peer, reason }).ok();
            }
        }
    }
}

/// Whether a kept list revokes the peer's chain, the leaf under its issuer
/// or the issuer under a shipped root.
fn chain_revoked(state: &NodeState, leaf: &[u8], issuer: &[u8]) -> bool {
    let (Some(leaf_serial), Some(issuer_serial), Some(issuer_key)) = (
        certificate_serial(leaf).ok(),
        certificate_serial(issuer).ok(),
        certificate_key_id(issuer).ok(),
    ) else {
        return false;
    };
    state.lists.read().iter().any(|kept| {
        (kept.issuer == issuer_key && kept.parsed.revokes(&leaf_serial))
            || (state.root_key_ids.contains(&kept.issuer) && kept.parsed.revokes(&issuer_serial))
    })
}

/// The dialer's TLS config, for `identity` on a standalone trust and CRLs.
pub(crate) fn client_config_for(
    trust: &Trust,
    clock: Arc<dyn Clock>,
    own_key: Option<KeyId>,
    crls: Arc<RwLock<Arc<[Crl]>>>,
    identity: &Identity,
) -> Arc<ClientConfig> {
    let verifier = verifier_for(trust, clock, own_key, crls);
    Arc::new(
        ClientConfig::builder_with_provider(ring_provider())
            .with_protocol_versions(&[&version::TLS13])
            .expect("ring speaks TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_cert_resolver(Arc::new(IdentityClientCert::new(
                presented(identity),
                Arc::clone(&identity.key),
            ))),
    )
}

/// The listener's TLS config, for `identity` on a standalone trust and
/// CRLs.
pub(crate) fn server_config_for(
    trust: &Trust,
    clock: Arc<dyn Clock>,
    own_key: Option<KeyId>,
    crls: Arc<RwLock<Arc<[Crl]>>>,
    identity: &Identity,
) -> Arc<ServerConfig> {
    let verifier = verifier_for(trust, clock, own_key, crls);
    Arc::new(
        ServerConfig::builder_with_provider(ring_provider())
            .with_protocol_versions(&[&version::TLS13])
            .expect("ring speaks TLS 1.3")
            .with_client_cert_verifier(Arc::new(verifier))
            .with_cert_resolver(Arc::new(IdentityServerCert::new(
                presented(identity),
                Arc::clone(&identity.key),
            ))),
    )
}

/// The ring provider, named outright so a build that also enables another
/// rustls provider never leaves the choice to the process default.
fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The verifier a standalone config carries, on its own key and CRL lock.
fn verifier_for(
    trust: &Trust,
    clock: Arc<dyn Clock>,
    own_key: Option<KeyId>,
    crls: Arc<RwLock<Arc<[Crl]>>>,
) -> PeerVerifier {
    PeerVerifier::new(trust, clock, Arc::new(RwLock::new(own_key)), crls)
}

/// The presented certificates, the leaf ahead of its issuer.
fn presented(identity: &Identity) -> Vec<CertificateDer<'static>> {
    vec![
        CertificateDer::from(identity.certificate.clone()),
        CertificateDer::from(identity.issuer.clone()),
    ]
}

/// A rustls failure as the dial's typed error, the peer's alert first and
/// the own verifier's typed refusal second.
fn map_rustls(err: rustls::Error) -> LinkError {
    if let rustls::Error::AlertReceived(alert) = err {
        return LinkError::RefusedByPeer(alert);
    }
    if let rustls::Error::InvalidCertificate(rustls::CertificateError::Other(inner)) = &err
        && let Some(refusal) = inner.0.downcast_ref::<crate::error::Refusal>()
    {
        return LinkError::Refused(*refusal);
    }
    LinkError::Tls(err)
}

/// A connect or handshake failure as the dial's typed error, a plain I/O
/// failure as `Unreachable`.
fn map_tls(err: io::Error) -> LinkError {
    match err.downcast::<rustls::Error>() {
        Ok(err) => map_rustls(err),
        Err(err) => LinkError::Unreachable(err),
    }
}

/// A frame failure as the dial's typed error, surfacing the peer's TLS
/// alert when it reaches the dial on the first read.
fn map_frame(err: FrameError) -> LinkError {
    let message = err.to_string();
    match err {
        FrameError::Io(io_err) => {
            if let Ok(rustls_err) = io_err.downcast::<rustls::Error>() {
                return map_rustls(rustls_err);
            }
            LinkError::Protocol(message)
        }
        _ => LinkError::Protocol(message),
    }
}

/// The accept loop, until stopped.
async fn accept_loop(
    state: Arc<NodeState>,
    listener: TcpListener,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            accepted = listener.accept() => {
                let (tcp, _peer_addr) = match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        debug!(%err, "the accept failed");
                        continue;
                    }
                };
                let identity = state.identity.read().clone();
                let Some(identity) = identity else {
                    drop(tcp);
                    continue;
                };
                let state = Arc::clone(&state);
                tokio::spawn(inbound(state, tcp, identity));
            }
        }
    }
}

/// The listener's side of a handshake, until the link registers or the
/// peer is refused.
async fn inbound(state: Arc<NodeState>, tcp: TcpStream, identity: Identity) {
    let config = server_config_for(
        &state.trust,
        state.verifier.clock(),
        *state.own_key.read(),
        Arc::clone(&state.crls),
        &identity,
    );
    let acceptor = TlsAcceptor::from(config);
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(err)) => {
            debug!(%err, "an inbound handshake was refused");
            return;
        }
        Err(_) => {
            debug!("an inbound handshake timed out");
            return;
        }
    };
    let (leaf, issuer) = {
        let certs = tls
            .get_ref()
            .1
            .peer_certificates()
            .expect("the client auth is mandatory");
        let (Some(leaf), Some(issuer)) = (certs.first(), certs.get(1)) else {
            debug!("the peer presented no issuer certificate");
            return;
        };
        (leaf.to_vec(), issuer.to_vec())
    };
    let peer = match DeviceCertificate::parse(&leaf) {
        Ok(certificate) => certificate.identity().clone(),
        Err(err) => {
            warn!(%err, "the peer's certificate failed the profile");
            return;
        }
    };
    let mut tls = tls;
    let (peer_numbers, dial) = match exchange_hello(&mut tls, &state, 0).await {
        Ok(pair) => pair,
        Err(err) => {
            debug!(%err, "the inbound hello failed");
            return;
        }
    };
    let dialer = peer.key();
    // An inbound link a stop or a fresh list dropped needs no answer, the
    // dialer sees the close.
    let _ = register_link(
        &state,
        Handshaken {
            peer,
            leaf,
            issuer,
            numbers: peer_numbers,
            dialer,
            dial,
        },
        tls,
    );
}

/// Exchange hellos over the live stream and write the lists the peer lacks.
///
/// # Errors
///
/// [`LinkError`] for a timeout, a broken frame, or a different version.
async fn exchange_hello<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    state: &NodeState,
    dial: u64,
) -> Result<(BTreeMap<[u8; 32], u64>, u64), LinkError> {
    let numbers = state
        .lists
        .read()
        .iter()
        .map(|kept| (ByteBuf::from(kept.issuer.as_bytes().to_vec()), kept.number))
        .collect();
    let hello = PeerFrame::Hello {
        version: PROTOCOL_VERSION,
        dial,
        numbers,
    };
    tokio::time::timeout(HELLO_TIMEOUT, write_frame(io, &hello))
        .await
        .map_err(|_| LinkError::Timeout)?
        .map_err(map_frame)?;
    let frame = tokio::time::timeout(HELLO_TIMEOUT, read_frame(io))
        .await
        .map_err(|_| LinkError::Timeout)?
        .map_err(map_frame)?;
    let Some(PeerFrame::Hello {
        version,
        dial: peer_dial,
        numbers,
    }) = frame
    else {
        return Err(LinkError::Protocol(
            "the peer's first frame is not a hello".into(),
        ));
    };
    if version != PROTOCOL_VERSION {
        return Err(LinkError::UnsupportedVersion { their: version });
    }
    let mut peer_numbers = BTreeMap::new();
    for (id, number) in numbers {
        let key: [u8; 32] = id
            .into_vec()
            .try_into()
            .map_err(|_| LinkError::Protocol("a hello number names no key id".into()))?;
        peer_numbers.insert(key, number);
    }
    let to_send: Vec<PeerFrame> = {
        let lists = state.lists.read();
        lists
            .iter()
            .filter(|kept| {
                peer_numbers
                    .get(&kept.issuer.as_bytes()[..])
                    .is_none_or(|had| kept.number > *had)
            })
            .map(|kept| PeerFrame::List {
                list: ByteBuf::from(kept.der.clone()),
                signer: ByteBuf::from(kept.signer.clone()),
            })
            .collect()
    };
    for frame in &to_send {
        tokio::time::timeout(HELLO_TIMEOUT, write_frame(io, frame))
            .await
            .map_err(|_| LinkError::Timeout)?
            .map_err(map_frame)?;
    }
    Ok((peer_numbers, peer_dial))
}

/// What a completed handshake and hello learned about the peer.
struct Handshaken {
    /// What the peer's certificate names.
    peer: DeviceIdentity,
    /// The peer's leaf, DER.
    leaf: Vec<u8>,
    /// The peer's issuer, DER.
    issuer: Vec<u8>,
    /// The revocation list numbers the peer has, by issuer key id.
    numbers: BTreeMap<[u8; 32], u64>,
    /// The key id of the side that dialed.
    dialer: KeyId,
    /// The dialer's dial counter.
    dial: u64,
}

/// Register a completed link under the duplicate rule, spawning its frame
/// task on a kept link and dropping a losing one without an event.
///
/// # Errors
///
/// [`LinkError::NotServing`] when the node stopped before the link could
/// register, and [`LinkError::Refused`] when a list kept since the handshake
/// revokes the peer's chain.
fn register_link<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    state: &Arc<NodeState>,
    handshaken: Handshaken,
    tls: S,
) -> Result<(), LinkError> {
    let Handshaken {
        peer,
        leaf,
        issuer,
        numbers,
        dialer,
        dial,
    } = handshaken;
    let peer = &peer;
    let peer_key = peer.key();
    let seq = {
        let mut next_seq = state.next_seq.lock();
        *next_seq += 1;
        *next_seq
    };
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    // The keep decision, the serving check and the insert, atomic under the
    // one links lock so a stop and a duplicate close cannot race a
    // registration.
    let keep_new = {
        let mut links = state.links.lock();
        // A stop may have landed between the dial and the registration.
        if !state.serving.load(Ordering::Acquire) {
            return Err(LinkError::NotServing);
        }
        // A list kept between the handshake and this registration revokes
        // the chain here, under the same lock `keep_list` sweeps the links in.
        if chain_revoked(state, &leaf, &issuer) {
            return Err(LinkError::Refused(Refusal::Revoked));
        }
        let fresh = links.get(&peer_key).is_none();
        let keep_new = match links.get(&peer_key) {
            None | Some(SlotState::AwaitingKeeper(_)) => true,
            Some(SlotState::Live(existing)) => {
                if existing.dialer == dialer {
                    dial > existing.dial
                } else {
                    dialer.as_bytes() < existing.dialer.as_bytes()
                }
            }
        };
        if keep_new {
            // Close the losing link, if the new one keeps the slot. Its frame
            // task sends the `Close` frame and exits on the command.
            if let Some(SlotState::Live(existing)) = links.get(&peer_key) {
                let _ = existing
                    .command
                    .send(LinkCommand::Close(CloseReason::Duplicate));
            }
            let slot = LinkSlot {
                peer: (*peer).clone(),
                leaf,
                issuer,
                numbers,
                dialer,
                dial,
                seq,
                command: cmd_tx,
                task: None,
            };
            links.insert(peer_key, SlotState::Live(slot));
            if fresh {
                state
                    .events
                    .send(PeerEvent::Linked {
                        peer: (*peer).clone(),
                    })
                    .ok();
            }
        }
        keep_new
    };
    if keep_new {
        let task = tokio::spawn(crate::link::run(
            Arc::clone(state),
            tls,
            cmd_rx,
            peer_key,
            seq,
        ));
        let mut links = state.links.lock();
        if let Some(SlotState::Live(slot)) = links.get_mut(&peer_key)
            && slot.seq == seq
        {
            slot.task = Some(task);
        }
    } else {
        // The peer learns the close is a duplicate, so it waits for the kept
        // link instead of reporting the peer gone.
        tokio::spawn(async move {
            let mut tls = tls;
            let close = PeerFrame::Close {
                reason: CloseReason::Duplicate,
            };
            let _ = tokio::time::timeout(WRITE_BOUND, write_frame(&mut tls, &close)).await;
        });
    }
    Ok(())
}
