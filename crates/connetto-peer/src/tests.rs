//! The R76 slice 1 proofs, on loopback, with every certificate minted here.
//!
//! Each proof drives the public surface alone, except the silent-peer case,
//! which also completes a raw TLS peer through the crate's own client config
//! so it can stop reading and sending after the handshake.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use connetto_core::device_cert::{
    AttestationLevel, CertificateRequest, CertificateSigner, DeploymentId, DeviceCertificate,
    DeviceIdentity, DeviceIssuer, DeviceKey, DeviceKeyError, KeyHome, Revoked, RootCa, key_id,
    public_key_info,
};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, SigningKey as RcgenSigningKey};
use tokio::sync::mpsc;
use tokio::time;

use crate::frame::{PeerFrame, read_frame, write_frame};
use crate::node::client_config_for;
use crate::{
    CloseReason, Identity, LinkError, Liveness, Node, PeerEvent, Refusal, SystemClock, Trust,
};

const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_hours(24);

/// A device key held in memory, standing in for a chip.
struct Device(Arc<KeyPair>);

impl Clone for Device {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl DeviceKey for Device {
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

/// An issuer beside the certificate and key it signs with.
struct Issuer {
    /// The issuer certificate, DER.
    certificate: Vec<u8>,
    /// The signing key, for the lists it signs.
    signer: DeviceIssuer,
    /// The serial the root used when signing the issuer.
    serial: [u8; 16],
}

/// A deployment a test mints: one root and the issuers and devices it
/// signs.
struct Deployment {
    root: RootCa,
}

impl Deployment {
    /// Mint a root for deployment `id`, valid around `now`.
    fn new(id: u128, now: SystemTime) -> Self {
        let root = RootCa::create(
            DeploymentId::from_uuid(uuid::Uuid::from_u128(id)),
            now - 10 * DAY,
            3650 * DAY,
        )
        .expect("the root mints");
        Self { root }
    }

    /// The root's DER, what a device is built with.
    fn root_der(&self) -> Vec<u8> {
        self.root.certificate().to_vec()
    }

    /// Sign one more issuer, valid around `now`.
    fn add_issuer(&self, now: SystemTime, serial: [u8; 16]) -> Issuer {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("the issuer key");
        let holder = Device(Arc::new(key));
        let stored = rustls_pki_types::PrivatePkcs8KeyDer::from(holder.0.serialize_der());
        let key = KeyPair::from_pkcs8_der_and_sign_algo(&stored, &PKCS_ECDSA_P256_SHA256)
            .expect("the key round-trips");
        let certificate = self
            .root
            .sign_issuer(&public_key_info(&holder), now - 10 * DAY, 366 * DAY, serial)
            .expect("the issuer signs");
        let signer = DeviceIssuer::new(certificate.clone(), key, self.root.certificate())
            .expect("the issuer loads");
        Issuer {
            certificate,
            signer,
            serial,
        }
    }

    /// A device certificate under `issuer`, valid from `not_before` for `lifetime`.
    #[expect(clippy::unused_self, reason = "the issuer carries its own signer")]
    fn device(
        &self,
        issuer: &Issuer,
        account: &str,
        not_before: SystemTime,
        lifetime: Duration,
        serial: [u8; 16],
        level: AttestationLevel,
    ) -> Peer {
        let key = Device(Arc::new(
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("the device key"),
        ));
        let csr =
            CertificateRequest::build(&CertificateSigner::new(&key), &[1; 32]).expect("the csr");
        let request = CertificateRequest::parse(&csr).expect("the request parses");
        let leaf = issuer
            .signer
            .issue(&request, account, not_before, lifetime, serial, level)
            .expect("the certificate issues");
        let parsed = DeviceCertificate::parse(&leaf).expect("the profile holds");
        Peer {
            key,
            identity: parsed.identity().clone(),
            serial: parsed.serial().to_vec(),
            level,
            leaf,
            issuer: issuer.certificate.clone(),
        }
    }

    /// Reissue the device `peer` under `issuer`, a new serial and window.
    #[expect(clippy::unused_self, reason = "the issuer carries its own signer")]
    fn reissue(
        &self,
        issuer: &Issuer,
        peer: &Peer,
        not_before: SystemTime,
        lifetime: Duration,
        serial: [u8; 16],
    ) -> Peer {
        let key = peer.key.clone();
        let csr =
            CertificateRequest::build(&CertificateSigner::new(&key), &[1; 32]).expect("the csr");
        let request = CertificateRequest::parse(&csr).expect("the request parses");
        let leaf = issuer
            .signer
            .issue(
                &request,
                peer.identity.account(),
                not_before,
                lifetime,
                serial,
                peer.level,
            )
            .expect("the reissue grants");
        let parsed = DeviceCertificate::parse(&leaf).expect("the profile holds");
        Peer {
            key,
            identity: parsed.identity().clone(),
            serial: parsed.serial().to_vec(),
            level: peer.level,
            leaf,
            issuer: issuer.certificate.clone(),
        }
    }

    /// An issuer-signed list `number` revoking `revoked`, dated at `now`.
    #[expect(clippy::unused_self, reason = "the issuer carries its own signer")]
    fn issuer_list(
        &self,
        issuer: &Issuer,
        number: u64,
        revoked: &[Revoked],
        now: SystemTime,
    ) -> (Vec<u8>, Vec<u8>) {
        let list = issuer
            .signer
            .sign_list(number, revoked, now, now + 7 * DAY)
            .expect("the list signs");
        (list, issuer.certificate.clone())
    }

    /// A root-signed list `number` revoking `revoked`, dated at `now`.
    fn root_list(&self, number: u64, revoked: &[Revoked], now: SystemTime) -> (Vec<u8>, Vec<u8>) {
        let list = self
            .root
            .sign_list(number, revoked, now, now + 7 * DAY)
            .expect("the list signs");
        (list, self.root_der())
    }
}

/// A device certificate beside the key that signs for it.
struct Peer {
    /// The key, held in memory.
    key: Device,
    /// What the certificate names.
    identity: DeviceIdentity,
    /// The serial a list names the leaf by.
    serial: Vec<u8>,
    /// The attestation level the leaf records.
    level: AttestationLevel,
    /// The leaf, DER.
    leaf: Vec<u8>,
    /// The issuer certificate, DER.
    issuer: Vec<u8>,
}

impl Peer {
    /// The presented identity the node serves and dials with.
    fn identity(&self) -> Identity {
        Identity {
            certificate: self.leaf.clone(),
            issuer: self.issuer.clone(),
            key: Arc::new(self.key.clone()),
        }
    }

    /// The key id, what the duplicate rule compares.
    fn key_id(&self) -> connetto_core::device_cert::KeyId {
        key_id(&self.key)
    }
}

/// Every attestation level, the deployment default.
fn all_levels() -> Vec<AttestationLevel> {
    AttestationLevel::ALL.into_iter().collect()
}

/// A trust over one deployment root accepting every level.
fn trust_root(root_der: Vec<u8>) -> Trust {
    Trust {
        roots: vec![root_der],
        accepted: all_levels(),
    }
}

/// A wall clock shifted by a fixed offset, for the clock proofs.
#[derive(Debug)]
struct ShiftedClock {
    /// The offset from the real wall clock.
    offset: Duration,
}

impl crate::Clock for ShiftedClock {
    fn now(&self) -> SystemTime {
        SystemTime::now() + self.offset
    }
}

/// A trust over `roots` accepting `accepted`, behind `clock`.
fn node_on(
    roots: Vec<Vec<u8>>,
    accepted: Vec<AttestationLevel>,
    clock: Arc<dyn crate::Clock>,
    events: mpsc::UnboundedSender<PeerEvent>,
) -> Node {
    Node::new(Trust { roots, accepted }, clock, events)
}

/// A node on one deployment root and the system clock.
fn node(root_der: Vec<u8>, events: mpsc::UnboundedSender<PeerEvent>) -> Node {
    node_on(vec![root_der], all_levels(), Arc::new(SystemClock), events)
}

/// A node on one deployment root and the system clock, with its links'
/// liveness bounds set.
fn node_liveness(
    root_der: Vec<u8>,
    events: mpsc::UnboundedSender<PeerEvent>,
    liveness: Liveness,
) -> Node {
    Node::with_liveness(
        Trust {
            roots: vec![root_der],
            accepted: all_levels(),
        },
        Arc::new(SystemClock),
        events,
        liveness,
    )
}

/// An event channel pair.
fn events() -> (
    mpsc::UnboundedSender<PeerEvent>,
    mpsc::UnboundedReceiver<PeerEvent>,
) {
    mpsc::unbounded_channel()
}

/// The whole second the wall clock stands on, as X.509 carries time.
fn whole_second() -> SystemTime {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// Serve `peer` on loopback, answering the bound address.
fn serve(node: &Node, peer: &Peer) -> SocketAddr {
    node.serve(SocketAddr::from(([127, 0, 0, 1], 0)), peer.identity())
        .expect("the listener binds")
}

/// Collect `count` events, failing if ten seconds run out.
async fn next_events(rx: &mut mpsc::UnboundedReceiver<PeerEvent>, count: usize) -> Vec<PeerEvent> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(
            time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .expect("the event arrives")
                .expect("the channel stays open"),
        );
    }
    out
}

/// Wait for one event matching `keep`, draining the ones that do not.
async fn await_event(
    rx: &mut mpsc::UnboundedReceiver<PeerEvent>,
    bound: Duration,
    mut keep: impl FnMut(&PeerEvent) -> bool,
) -> PeerEvent {
    let deadline = time::sleep(bound);
    tokio::pin!(deadline);
    loop {
        let event = tokio::select! {
            event = rx.recv() => event.expect("the channel stays open"),
            () = &mut deadline => panic!("the expected event never arrived"),
        };
        if keep(&event) {
            return event;
        }
    }
}

/// Assert that no event arrives within `bound`.
async fn no_events(rx: &mut mpsc::UnboundedReceiver<PeerEvent>, bound: Duration) {
    assert!(
        time::timeout(bound, rx.recv()).await.is_err(),
        "an event arrived that nothing expected"
    );
}

/// A raw TLS peer over loopback, through the crate's own client config, so
/// the test can stop reading and sending after the handshake.
async fn raw_peer_connect(
    root_der: Vec<u8>,
    peer: &Peer,
    addr: SocketAddr,
) -> tokio_rustls::TlsStream<tokio::net::TcpStream> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("the loopback connects");
    let crls = Arc::new(parking_lot::RwLock::new(Arc::from(
        Vec::<crate::verify::Crl>::new().into_boxed_slice(),
    )));
    let config = client_config_for(
        &trust_root(root_der),
        Arc::new(SystemClock),
        Some(peer.key_id()),
        crls,
        &peer.identity(),
    );
    let connector = tokio_rustls::TlsConnector::from(config);
    let domain =
        rustls::pki_types::ServerName::try_from("connetto-peer").expect("a valid dial name");
    connector
        .connect(domain, tcp)
        .await
        .expect("the handshake completes")
        .into()
}

// --- Proof 1 ---

#[tokio::test]
async fn two_nodes_link_and_a_kept_list_reaches_the_other() {
    let now = whole_second();
    let deployment = Deployment::new(1, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let alice = deployment.device(
        &issuer,
        "alice",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let bob = deployment.device(
        &issuer,
        "bob",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    let (a_tx, mut a_rx) = events();
    let (b_tx, mut b_rx) = events();
    let a = node(deployment.root_der(), a_tx);
    let b = node(deployment.root_der(), b_tx);

    // Bob keeps a list Alice's Hello will lack.
    let (list, signer) = deployment.issuer_list(&issuer, 1, &[], now);
    b.keep_list(list.clone(), signer.clone());

    let addr = serve(&b, &bob);
    let _ = serve(&a, &alice);
    let peer = a.link(addr).await.expect("the link completes");
    assert_eq!(peer, bob.identity);

    assert_eq!(
        next_events(&mut a_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: bob.identity.clone()
        }]
    );
    assert_eq!(
        next_events(&mut b_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: alice.identity.clone()
        }]
    );

    // Bob's kept list reaches Alice as the raw ListReceived event.
    assert_eq!(
        next_events(&mut a_rx, 1).await,
        vec![PeerEvent::ListReceived { list, signer }]
    );

    a.stop(CloseReason::Closed);
    b.stop(CloseReason::Closed);
}

// --- Proof 2 ---

#[tokio::test]
async fn a_foreign_root_is_refused_both_directions() {
    let now = whole_second();
    let home = Deployment::new(2, now);
    let foreign = Deployment::new(3, now);
    let home_issuer = home.add_issuer(now, [1; 16]);
    let foreign_issuer = foreign.add_issuer(now, [1; 16]);

    let host = home.device(
        &home_issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let stranger = foreign.device(
        &foreign_issuer,
        "stranger",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );

    let (h_tx, mut h_rx) = events();
    let (f_tx, mut f_rx) = events();
    let home_node = node(home.root_der(), h_tx);
    let foreign_node = node(foreign.root_der(), f_tx);

    let addr = serve(&home_node, &host);
    serve(&foreign_node, &stranger);

    // The foreign device dials home, and its own verifier refuses the home
    // chain, which reaches a root it does not ship.
    let err = foreign_node.link(addr).await.expect_err("refused");
    assert!(
        matches!(err, LinkError::Refused(Refusal::Untrusted)),
        "the dialer answers its own typed refusal, got {err:?}"
    );

    // The refused inbound handshake raises nothing on either side.
    no_events(&mut h_rx, Duration::from_secs(1)).await;
    no_events(&mut f_rx, Duration::from_secs(1)).await;

    // A dialer that trusts home but presents a foreign-rooted certificate
    // meets home's refusal as the peer's alert.
    let (d_tx, mut d_rx) = events();
    let dialer = node(home.root_der(), d_tx);
    serve(&dialer, &stranger);
    let err = dialer.link(addr).await.expect_err("refused");
    assert!(
        matches!(err, LinkError::RefusedByPeer(_)),
        "the peer's alert reaches the dialer, got {err:?}"
    );

    // The refused dial raises nothing on the dialer either.
    no_events(&mut d_rx, Duration::from_secs(1)).await;

    home_node.stop(CloseReason::Closed);
    foreign_node.stop(CloseReason::Closed);
    dialer.stop(CloseReason::Closed);
}

// --- Proof 3, R74 proof 4 ---

#[tokio::test]
async fn a_root_list_revoking_an_issuer_closes_and_refuses() {
    let now = whole_second();
    let deployment = Deployment::new(4, now);
    let issuer_one = deployment.add_issuer(now, [1; 16]);
    let issuer_two = deployment.add_issuer(now, [2; 16]);

    // One device under each issuer.
    let under_one = deployment.device(
        &issuer_one,
        "under-one",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let under_two = deployment.device(
        &issuer_two,
        "under-two",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    let (a_tx, mut a_rx) = events();
    let (b_tx, mut b_rx) = events();
    let a = node(deployment.root_der(), a_tx);
    let b = node(deployment.root_der(), b_tx);

    let a_addr = serve(&a, &under_one);
    let b_addr = serve(&b, &under_two);

    // The two link both ways, and the duplicate rule keeps one link each.
    let (a_to_b, b_to_a) = tokio::join!(a.link(b_addr), b.link(a_addr));
    assert_eq!(a_to_b.as_ref().ok(), Some(&under_two.identity));
    assert_eq!(b_to_a.as_ref().ok(), Some(&under_one.identity));
    assert_eq!(
        next_events(&mut a_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: under_two.identity.clone()
        }]
    );
    assert_eq!(
        next_events(&mut b_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: under_one.identity.clone()
        }]
    );

    // The root signs a list revoking issuer one, and both nodes keep it.
    let (list, signer) = deployment.root_list(
        1,
        &[Revoked {
            serial: issuer_one.serial.to_vec(),
            at: now,
        }],
        now,
    );
    a.keep_list(list.clone(), signer.clone());
    b.keep_list(list, signer);

    // B's peer, under one, is now revoked, so b closes the live link with
    // PeerRevoked, and a sees the close as its peer's.
    let event = await_event(&mut b_rx, Duration::from_secs(10), |event| {
        matches!(
            event,
            PeerEvent::Unlinked {
                reason: CloseReason::PeerRevoked,
                ..
            }
        )
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::Unlinked {
            peer: under_one.identity.clone(),
            reason: CloseReason::PeerRevoked
        }
    );
    let event = await_event(&mut a_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::Unlinked { .. })
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::Unlinked {
            peer: under_two.identity.clone(),
            reason: CloseReason::Closed
        }
    );

    // A new link from b to a is refused by b's verifier, which now reads
    // the revoked issuer out of a's chain.
    let err = b.link(a_addr).await.expect_err("refused");
    assert!(matches!(err, LinkError::Refused(Refusal::Revoked)));

    // A new link from a to b passes a's verifier and meets b's alert.
    let err = a.link(b_addr).await.expect_err("refused");
    assert!(
        matches!(err, LinkError::RefusedByPeer(_)),
        "the peer's alert reaches the dialer, got {err:?}"
    );

    a.stop(CloseReason::Closed);
    b.stop(CloseReason::Closed);
}

// --- Proof 4 ---

#[tokio::test]
async fn a_leaf_list_closes_its_link_and_forwards_to_a_third() {
    let now = whole_second();
    let deployment = Deployment::new(5, now);
    let issuer = deployment.add_issuer(now, [1; 16]);

    let alpha = deployment.device(
        &issuer,
        "alpha",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let beta = deployment.device(
        &issuer,
        "beta",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );
    let gamma = deployment.device(
        &issuer,
        "gamma",
        now,
        DAY,
        [3; 16],
        AttestationLevel::Unproven,
    );

    let (a_tx, mut a_rx) = events();
    let (b_tx, mut b_rx) = events();
    let (c_tx, mut c_rx) = events();
    let a = node(deployment.root_der(), a_tx);
    let b = node(deployment.root_der(), b_tx);
    let c = node(deployment.root_der(), c_tx);

    serve(&a, &alpha);
    let b_addr = serve(&b, &beta);
    let c_addr = serve(&c, &gamma);

    // A full mesh, one link per pair.
    let (a_to_b, a_to_c, b_to_c) = tokio::join!(a.link(b_addr), a.link(c_addr), b.link(c_addr));
    assert_eq!(a_to_b.as_ref().ok(), Some(&beta.identity));
    assert_eq!(a_to_c.as_ref().ok(), Some(&gamma.identity));
    assert_eq!(b_to_c.as_ref().ok(), Some(&gamma.identity));

    // Alpha keeps a list revoking beta's leaf. It does not name gamma.
    let (list, signer) = deployment.issuer_list(
        &issuer,
        1,
        &[Revoked {
            serial: beta.serial.clone(),
            at: now,
        }],
        now,
    );
    a.keep_list(list.clone(), signer.clone());

    // Alpha's link to beta closes with PeerRevoked.
    let event = await_event(&mut a_rx, Duration::from_secs(10), |event| {
        matches!(
            event,
            PeerEvent::Unlinked {
                peer,
                reason: CloseReason::PeerRevoked
            } if *peer == beta.identity
        )
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::Unlinked {
            peer: beta.identity.clone(),
            reason: CloseReason::PeerRevoked
        }
    );

    // Beta sees the close as its peer's.
    let event = await_event(&mut b_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::Unlinked { .. })
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::Unlinked {
            peer: alpha.identity.clone(),
            reason: CloseReason::Closed
        }
    );

    // Gamma, linked to alpha and lacking the list, receives it raw.
    let event = await_event(&mut c_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::ListReceived { .. })
    })
    .await;
    assert_eq!(event, PeerEvent::ListReceived { list, signer });

    a.stop(CloseReason::Closed);
    b.stop(CloseReason::Closed);
    c.stop(CloseReason::Closed);
}

// --- Proof 5, R74 proof 6 ---

#[tokio::test]
async fn a_clock_outside_the_window_refuses_and_a_small_skew_links() {
    let now = whole_second();
    let deployment = Deployment::new(6, now);
    let issuer = deployment.add_issuer(now, [1; 16]);

    let honest = deployment.device(
        &issuer,
        "honest",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let skewed = deployment.device(
        &issuer,
        "skewed",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );
    let tolerant = deployment.device(
        &issuer,
        "tolerant",
        now,
        DAY,
        [3; 16],
        AttestationLevel::Unproven,
    );

    let (o_tx, mut o_rx) = events();
    let (s_tx, mut s_rx) = events();
    let honest_node = node(deployment.root_der(), o_tx);
    // The skewed node's clock stands two days ahead.
    let skewed_node = node_on(
        vec![deployment.root_der()],
        all_levels(),
        Arc::new(ShiftedClock { offset: 2 * DAY }),
        s_tx,
    );

    let honest_addr = serve(&honest_node, &honest);
    let skewed_addr = serve(&skewed_node, &skewed);

    // The skewed node dials, and its own clock refuses every peer.
    let err = skewed_node
        .link(honest_addr)
        .await
        .expect_err("refused by the skewed clock");
    assert!(
        matches!(err, LinkError::Refused(Refusal::Expired)),
        "got {err:?}"
    );

    // The honest node dials the skewed one and meets the refusal as the
    // peer's alert.
    let err = honest_node
        .link(skewed_addr)
        .await
        .expect_err("refused by the peer");
    assert!(matches!(err, LinkError::RefusedByPeer(_)), "got {err:?}");

    // No events on either side for the refused handshakes.
    no_events(&mut o_rx, Duration::from_secs(1)).await;
    no_events(&mut s_rx, Duration::from_secs(1)).await;

    // A four-minute skew still links, inside the five-minute tolerance.
    let (t_tx, mut t_rx) = events();
    let tolerant_node = node_on(
        vec![deployment.root_der()],
        all_levels(),
        Arc::new(ShiftedClock {
            offset: 4 * 60 * Duration::from_secs(1),
        }),
        t_tx,
    );
    serve(&tolerant_node, &tolerant);
    let peer = tolerant_node
        .link(honest_addr)
        .await
        .expect("the tolerance covers four minutes");
    assert_eq!(peer, honest.identity);
    assert_eq!(
        next_events(&mut t_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: honest.identity.clone()
        }]
    );

    honest_node.stop(CloseReason::Closed);
    skewed_node.stop(CloseReason::Closed);
    tolerant_node.stop(CloseReason::Closed);
}

// --- Proof 6 ---

#[tokio::test]
async fn an_unaccepted_attestation_level_is_refused() {
    let now = whole_second();
    let deployment = Deployment::new(7, now);
    let issuer = deployment.add_issuer(now, [1; 16]);

    let unproven = deployment.device(
        &issuer,
        "unproven",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let proven_a = deployment.device(
        &issuer,
        "proven-a",
        now,
        DAY,
        [2; 16],
        AttestationLevel::ChipProven,
    );
    let proven_b = deployment.device(
        &issuer,
        "proven-b",
        now,
        DAY,
        [3; 16],
        AttestationLevel::ChipProven,
    );

    let (o_tx, mut o_rx) = events();
    let (a_tx, mut a_rx) = events();
    let (b_tx, mut b_rx) = events();
    // The open node accepts every level and presents the unproven device.
    let open = node(deployment.root_der(), o_tx);
    // The strict nodes accept only chip-proven and present chip-proven devices.
    let strict_a = node_on(
        vec![deployment.root_der()],
        vec![AttestationLevel::ChipProven],
        Arc::new(SystemClock),
        a_tx,
    );
    let strict_b = node_on(
        vec![deployment.root_der()],
        vec![AttestationLevel::ChipProven],
        Arc::new(SystemClock),
        b_tx,
    );

    let open_addr = serve(&open, &unproven);
    let _a_addr = serve(&strict_a, &proven_a);
    let b_addr = serve(&strict_b, &proven_b);

    // A node that does not accept the unproven level refuses that dial, and
    // neither side records the link.
    let err = strict_a.link(open_addr).await.expect_err("refused");
    assert!(
        matches!(
            err,
            LinkError::Refused(Refusal::AttestationRefused(AttestationLevel::Unproven))
        ),
        "got {err:?}"
    );
    no_events(&mut o_rx, Duration::from_secs(1)).await;
    no_events(&mut a_rx, Duration::from_secs(1)).await;

    // Two nodes that both accept the chip-proven level link, and each learns
    // of the other.
    let peer = strict_a
        .link(b_addr)
        .await
        .expect("both accept chip-proven");
    assert_eq!(peer, proven_b.identity);
    assert_eq!(
        next_events(&mut a_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: proven_b.identity.clone()
        }]
    );
    assert_eq!(
        next_events(&mut b_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: proven_a.identity.clone()
        }]
    );

    open.stop(CloseReason::Closed);
    strict_a.stop(CloseReason::Closed);
    strict_b.stop(CloseReason::Closed);
}

// --- Proof 7 ---

#[tokio::test]
async fn a_silent_peer_closes_with_peer_lost_and_pings_keep_a_link() {
    let now = whole_second();
    let deployment = Deployment::new(8, now);
    let issuer = deployment.add_issuer(now, [1; 16]);

    let host = deployment.device(
        &issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let silent = deployment.device(
        &issuer,
        "silent",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );
    let bob = deployment.device(
        &issuer,
        "bob",
        now,
        DAY,
        [3; 16],
        AttestationLevel::Unproven,
    );

    let (h_tx, mut h_rx) = events();
    let host_node = node(deployment.root_der(), h_tx);
    let host_addr = serve(&host_node, &host);

    // A peer that completes the handshake and then stops reading and
    // sending, holding the socket open.
    let mut raw = raw_peer_connect(deployment.root_der(), &silent, host_addr).await;
    let hello = PeerFrame::Hello {
        version: 1,
        dial: 1,
        numbers: Vec::new(),
    };
    write_frame(&mut raw, &hello)
        .await
        .expect("the hello writes");
    let hello = tokio::time::timeout(crate::node::HELLO_TIMEOUT, read_frame(&mut raw))
        .await
        .expect("the host answers within the bound")
        .expect("a frame arrives")
        .expect("the host sends a hello");
    assert!(matches!(hello, PeerFrame::Hello { version: 1, .. }));
    time::pause();

    // The link is live on the host side, and then the silence bound closes
    // it with PeerLost while the host's pings go unanswered.
    let event = await_event(&mut h_rx, Duration::from_secs(120), |event| {
        matches!(
            event,
            PeerEvent::Unlinked {
                reason: CloseReason::PeerLost,
                ..
            }
        )
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::Unlinked {
            peer: silent.identity.clone(),
            reason: CloseReason::PeerLost
        }
    );
    drop(raw);
    time::resume();

    // A healthy peer answers the pings, and the link lives past its silence
    // bound. A short liveness bound keeps the wait real.
    let (b_tx, mut b_rx) = events();
    let bob_node = node_liveness(
        deployment.root_der(),
        b_tx,
        Liveness {
            ping_every: Duration::from_millis(200),
            silence_limit: Duration::from_secs(2),
        },
    );
    let bob_addr = serve(&bob_node, &bob);
    let peer = host_node.link(bob_addr).await.expect("the link completes");
    assert_eq!(peer, bob.identity);
    assert_eq!(
        next_events(&mut h_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: bob.identity.clone()
        }]
    );
    assert_eq!(
        next_events(&mut b_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: host.identity.clone()
        }]
    );

    // Past the silence bound, a kept list still crosses the link.
    let (list, signer) = deployment.issuer_list(&issuer, 1, &[], now);
    time::sleep(3 * Duration::from_secs(1)).await;
    host_node.keep_list(list.clone(), signer.clone());
    let event = await_event(&mut b_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::ListReceived { .. })
    })
    .await;
    assert_eq!(event, PeerEvent::ListReceived { list, signer });

    host_node.stop(CloseReason::Closed);
    bob_node.stop(CloseReason::Closed);
}

// --- Proof 8 ---

#[tokio::test]
async fn two_devices_dialing_each_other_keep_one_link_each() {
    let now = whole_second();
    let deployment = Deployment::new(9, now);
    let issuer = deployment.add_issuer(now, [1; 16]);

    let alpha = deployment.device(
        &issuer,
        "alpha",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let beta = deployment.device(
        &issuer,
        "beta",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    let (a_tx, mut a_rx) = events();
    let (b_tx, mut b_rx) = events();
    let a = node(deployment.root_der(), a_tx);
    let b = node(deployment.root_der(), b_tx);

    let a_addr = serve(&a, &alpha);
    let b_addr = serve(&b, &beta);

    // Both dial at once.
    let (a_to_b, b_to_a) = tokio::join!(a.link(b_addr), b.link(a_addr));
    assert_eq!(a_to_b.as_ref().ok(), Some(&beta.identity));
    assert_eq!(b_to_a.as_ref().ok(), Some(&alpha.identity));

    // Exactly one link per side, and the duplicate rule raises nothing.
    assert_eq!(
        next_events(&mut a_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: beta.identity.clone()
        }]
    );
    assert_eq!(
        next_events(&mut b_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: alpha.identity.clone()
        }]
    );
    no_events(&mut a_rx, Duration::from_secs(1)).await;
    no_events(&mut b_rx, Duration::from_secs(1)).await;

    // The kept link is the same on both ends, so traffic crosses it both
    // ways, while a disagreeing pair would have closed both.
    let (list_a, signer_a) = deployment.issuer_list(&issuer, 1, &[], now);
    let (list_b, signer_b) = deployment.issuer_list(&issuer, 2, &[], now);
    a.keep_list(list_a.clone(), signer_a.clone());
    b.keep_list(list_b.clone(), signer_b.clone());
    let event = await_event(&mut b_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::ListReceived { .. })
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::ListReceived {
            list: list_a,
            signer: signer_a
        }
    );
    let event = await_event(&mut a_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::ListReceived { .. })
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::ListReceived {
            list: list_b,
            signer: signer_b
        }
    );

    a.stop(CloseReason::Closed);
    b.stop(CloseReason::Closed);
}

// --- Proof 9 ---

#[tokio::test]
async fn serving_again_with_a_new_certificate_keeps_port_and_link() {
    let now = whole_second();
    let deployment = Deployment::new(10, now);
    let issuer = deployment.add_issuer(now, [1; 16]);

    let alice = deployment.device(
        &issuer,
        "alice",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let bob = deployment.device(
        &issuer,
        "bob",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );

    let (a_tx, mut a_rx) = events();
    let (b_tx, mut b_rx) = events();
    let a = node(deployment.root_der(), a_tx);
    let b = node(deployment.root_der(), b_tx);

    let addr = serve(&a, &alice);
    let _ = serve(&b, &bob);
    let peer = b.link(addr).await.expect("the link completes");
    assert_eq!(peer, alice.identity);
    assert_eq!(
        next_events(&mut b_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: alice.identity.clone()
        }]
    );
    assert_eq!(
        next_events(&mut a_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: bob.identity.clone()
        }]
    );

    // Alice renews, a new serial and window on the same key, and serves
    // again. The port and the live link stay.
    let renewed = deployment.reissue(&issuer, &alice, now + HOUR, DAY, [17; 16]);
    let served = a
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)), renewed.identity())
        .expect("the re-serve keeps the listener");
    assert_eq!(served, addr);
    assert_eq!(a.local_addr(), Some(addr));

    // The link still carries frames under the swapped certificate.
    let (list, signer) = deployment.issuer_list(&issuer, 1, &[], now);
    a.keep_list(list.clone(), signer.clone());
    let event = await_event(&mut b_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::ListReceived { .. })
    })
    .await;
    assert_eq!(event, PeerEvent::ListReceived { list, signer });

    a.stop(CloseReason::Closed);
    b.stop(CloseReason::Closed);
}

#[tokio::test]
async fn a_second_dial_from_the_same_node_keeps_the_same_link() {
    let now = whole_second();
    let deployment = Deployment::new(9, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let alpha = deployment.device(
        &issuer,
        "alpha",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let beta = deployment.device(
        &issuer,
        "beta",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );
    let (a_tx, mut a_rx) = events();
    let (b_tx, mut b_rx) = events();
    let a = node(deployment.root_der(), a_tx);
    let b = node(deployment.root_der(), b_tx);
    let _a_addr = serve(&a, &alpha);
    let b_addr = serve(&b, &beta);

    // The first dial links both ends.
    let first = a.link(b_addr).await;
    assert_eq!(first.as_ref().ok(), Some(&beta.identity));
    assert_eq!(
        next_events(&mut a_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: beta.identity.clone()
        }]
    );
    assert_eq!(
        next_events(&mut b_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: alpha.identity.clone()
        }]
    );

    // A dials the same peer again while the first link is live. The dial
    // counter decides, and the higher dial keeps the slot on both ends.
    let second = a.link(b_addr).await;
    assert_eq!(second.as_ref().ok(), Some(&beta.identity));

    // The kept link is the same on both ends, so neither side reports the
    // peer as unlinked and the duplicate close is silent on both.
    no_events(&mut a_rx, Duration::from_secs(2)).await;
    no_events(&mut b_rx, Duration::from_secs(2)).await;

    // The surviving link still carries traffic.
    let (list, signer) = deployment.issuer_list(&issuer, 1, &[], now);
    a.keep_list(list.clone(), signer.clone());
    let event = await_event(&mut b_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::ListReceived { .. })
    })
    .await;
    assert_eq!(event, PeerEvent::ListReceived { list, signer });

    a.stop(CloseReason::Closed);
    b.stop(CloseReason::Closed);
}

#[tokio::test]
async fn dropping_the_last_node_closes_the_listener_and_links() {
    let now = whole_second();
    let deployment = Deployment::new(9, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let alpha = deployment.device(
        &issuer,
        "alpha",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let beta = deployment.device(
        &issuer,
        "beta",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );
    let (a_tx, _a_rx) = events();
    let (b_tx, mut b_rx) = events();
    let a = node(deployment.root_der(), a_tx);
    let b = node(deployment.root_der(), b_tx);
    let a_addr = serve(&a, &alpha);
    let b_addr = serve(&b, &beta);
    let a_to_b = a.link(b_addr).await;
    assert_eq!(a_to_b.as_ref().ok(), Some(&beta.identity));
    assert_eq!(
        next_events(&mut b_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: alpha.identity.clone()
        }]
    );

    // Drop the last handle of a. The stop teardown closes the links and the
    // listener.
    drop(a);

    // b sees the link close with the stop reason.
    let event = await_event(&mut b_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::Unlinked { .. })
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::Unlinked {
            peer: alpha.identity,
            reason: CloseReason::Closed
        }
    );

    // A fresh connect to a's old address is refused once the accept loop
    // stops.
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(a_addr).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        tokio::net::TcpStream::connect(a_addr).await.is_err(),
        "the listener should be closed after the node drops"
    );
}

/// A raw peer that completed the handshake and its `Hello` with the node at
/// `addr`.
async fn raw_linked(
    root_der: Vec<u8>,
    peer: &Peer,
    addr: SocketAddr,
) -> tokio_rustls::TlsStream<tokio::net::TcpStream> {
    let mut raw = raw_peer_connect(root_der, peer, addr).await;
    let hello = PeerFrame::Hello {
        version: 1,
        dial: 1,
        numbers: Vec::new(),
    };
    write_frame(&mut raw, &hello)
        .await
        .expect("the hello writes");
    let answer = time::timeout(crate::node::HELLO_TIMEOUT, read_frame(&mut raw))
        .await
        .expect("the node answers within the bound")
        .expect("a frame arrives");
    assert!(matches!(answer, Some(PeerFrame::Hello { .. })));
    raw
}

#[tokio::test]
async fn an_oversized_or_misplaced_frame_closes_with_protocol() {
    use tokio::io::AsyncWriteExt;

    let now = whole_second();
    let deployment = Deployment::new(10, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let host = deployment.device(
        &issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let large = deployment.device(
        &issuer,
        "large",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );
    let again = deployment.device(
        &issuer,
        "again",
        now,
        DAY,
        [3; 16],
        AttestationLevel::Unproven,
    );
    let (h_tx, mut h_rx) = events();
    let host_node = node(deployment.root_der(), h_tx);
    let host_addr = serve(&host_node, &host);

    // A length past the ceiling closes before any body is read.
    let mut raw = raw_linked(deployment.root_der(), &large, host_addr).await;
    raw.write_all(&(crate::frame::MAX_FRAME_LEN + 1).to_be_bytes())
        .await
        .expect("the length writes");
    raw.flush().await.expect("the length flushes");
    let event = await_event(&mut h_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::Unlinked { .. })
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::Unlinked {
            peer: large.identity.clone(),
            reason: CloseReason::Protocol
        }
    );

    // A second `Hello` on a live link breaks the protocol too.
    let mut raw = raw_linked(deployment.root_der(), &again, host_addr).await;
    let hello = PeerFrame::Hello {
        version: 1,
        dial: 2,
        numbers: Vec::new(),
    };
    write_frame(&mut raw, &hello)
        .await
        .expect("the hello writes");
    let event = await_event(&mut h_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::Unlinked { .. })
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::Unlinked {
            peer: again.identity.clone(),
            reason: CloseReason::Protocol
        }
    );
}

#[tokio::test]
async fn a_duplicate_close_holds_the_peer_until_the_bound_or_a_stop() {
    let now = whole_second();
    let deployment = Deployment::new(11, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let host = deployment.device(
        &issuer,
        "host",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let gone = deployment.device(
        &issuer,
        "gone",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );
    let held = deployment.device(
        &issuer,
        "held",
        now,
        DAY,
        [3; 16],
        AttestationLevel::Unproven,
    );
    let (h_tx, mut h_rx) = events();
    let host_node = node(deployment.root_der(), h_tx);
    let host_addr = serve(&host_node, &host);

    // A peer announcing a duplicate close whose kept link never arrives is
    // reported gone only once the hello bound runs out.
    let mut raw = raw_linked(deployment.root_der(), &gone, host_addr).await;
    assert_eq!(
        next_events(&mut h_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: gone.identity.clone()
        }]
    );
    let close = PeerFrame::Close {
        reason: CloseReason::Duplicate,
    };
    write_frame(&mut raw, &close)
        .await
        .expect("the close writes");
    drop(raw);
    time::pause();
    let started = time::Instant::now();
    let event = await_event(&mut h_rx, Duration::from_secs(60), |event| {
        matches!(event, PeerEvent::Unlinked { .. })
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::Unlinked {
            peer: gone.identity.clone(),
            reason: CloseReason::Duplicate
        }
    );
    assert!(
        started.elapsed() >= crate::node::HELLO_TIMEOUT,
        "the peer stays reported linked for the hello bound"
    );
    time::resume();

    // A stop during the wait reports the held peer with the stop's reason.
    let mut raw = raw_linked(deployment.root_der(), &held, host_addr).await;
    assert_eq!(
        next_events(&mut h_rx, 1).await,
        vec![PeerEvent::Linked {
            peer: held.identity.clone()
        }]
    );
    write_frame(&mut raw, &close)
        .await
        .expect("the close writes");
    drop(raw);
    no_events(&mut h_rx, Duration::from_millis(500)).await;
    host_node.stop(CloseReason::Withdrawn);
    assert_eq!(
        next_events(&mut h_rx, 1).await,
        vec![PeerEvent::Unlinked {
            peer: held.identity.clone(),
            reason: CloseReason::Withdrawn
        }]
    );
}

#[tokio::test]
async fn a_stale_or_unverified_list_is_neither_kept_nor_forwarded() {
    let now = whole_second();
    let deployment = Deployment::new(12, now);
    let foreign = Deployment::new(13, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let foreign_issuer = foreign.add_issuer(now, [1; 16]);
    let alpha = deployment.device(
        &issuer,
        "alpha",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let beta = deployment.device(
        &issuer,
        "beta",
        now,
        DAY,
        [2; 16],
        AttestationLevel::Unproven,
    );
    let gamma = deployment.device(
        &issuer,
        "gamma",
        now,
        DAY,
        [3; 16],
        AttestationLevel::Unproven,
    );
    let (a_tx, _a_rx) = events();
    let (b_tx, mut b_rx) = events();
    let a = node(deployment.root_der(), a_tx);
    let b = node(deployment.root_der(), b_tx);
    let a_addr = serve(&a, &alpha);
    let b_addr = serve(&b, &beta);
    a.link(b_addr).await.expect("the link opens");
    assert!(matches!(
        next_events(&mut b_rx, 1).await.as_slice(),
        [PeerEvent::Linked { .. }]
    ));

    let (newer, signer) = deployment.issuer_list(&issuer, 2, &[], now);
    a.keep_list(newer.clone(), signer.clone());
    assert_eq!(
        next_events(&mut b_rx, 1).await,
        vec![PeerEvent::ListReceived {
            list: newer.clone(),
            signer: signer.clone()
        }]
    );

    // A lower number, a list under a foreign root, and bytes that are no
    // list at all reach nobody.
    let (older, _) = deployment.issuer_list(&issuer, 1, &[], now);
    a.keep_list(older, signer.clone());
    let (forged, forged_signer) = foreign.issuer_list(&foreign_issuer, 9, &[], now);
    a.keep_list(forged, forged_signer);
    a.keep_list(vec![0x30, 0x00], signer.clone());
    no_events(&mut b_rx, Duration::from_millis(500)).await;

    // A peer linking afterwards learns the newer list, the one alpha kept.
    let (c_tx, mut c_rx) = events();
    let c = node(deployment.root_der(), c_tx);
    serve(&c, &gamma);
    c.link(a_addr).await.expect("the link opens");
    let event = await_event(&mut c_rx, Duration::from_secs(10), |event| {
        matches!(event, PeerEvent::ListReceived { .. })
    })
    .await;
    assert_eq!(
        event,
        PeerEvent::ListReceived {
            list: newer,
            signer
        }
    );
}

#[tokio::test]
async fn a_dial_nobody_answers_or_without_an_identity_fails_typed() {
    let now = whole_second();
    let deployment = Deployment::new(14, now);
    let issuer = deployment.add_issuer(now, [1; 16]);
    let alpha = deployment.device(
        &issuer,
        "alpha",
        now,
        DAY,
        [1; 16],
        AttestationLevel::Unproven,
    );
    let (a_tx, _a_rx) = events();
    let a = node(deployment.root_der(), a_tx);
    let closed = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
        probe.local_addr().expect("its address")
    };

    assert!(matches!(a.link(closed).await, Err(LinkError::NotServing)));
    serve(&a, &alpha);
    assert!(matches!(
        a.link(closed).await,
        Err(LinkError::Unreachable(_))
    ));
}
