//! The R76 slice 3 loopback proofs, every advertisement and browse running
//! on the loopback.
//!
//! Each proof first probes that loopback multicast works, and skips itself
//! when it does not, so a host without loopback multicast never reads as a
//! discovery failure.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

use connetto_core::device_cert::{AttestationLevel, DeviceIdentity};
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::sync::mpsc;
use tokio::time;

use crate::Discovery;
use crate::DiscoveryEvent;
use crate::Fingerprint;
use crate::PeerEvent;
use crate::tests::{Deployment, Peer, events, node, serve, whole_second};

/// A loopback port the proof's mDNS daemons bind, clear of the system
/// daemon's and of every other proof's.
fn fresh_mdns_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("the loopback binds")
        .local_addr()
        .expect("the bound address")
        .port()
}
const DAY: Duration = Duration::from_hours(24);
const WAIT: Duration = Duration::from_secs(30);

/// A loopback multicast round-trip, answered when the host lets it through.
///
/// Binds a datagram socket to the loopback, joins the mDNS group there, and
/// asks a second socket, pointed at the loopback, to multicast to it.
fn loopback_multicast() -> bool {
    let works = probe_loopback_multicast();
    assert!(
        works || std::env::var_os("CONNETTO_REQUIRE_MULTICAST").is_none(),
        "CONNETTO_REQUIRE_MULTICAST is set and the loopback multicast probe failed"
    );
    works
}

/// Whether a datagram sent to the mDNS group over the loopback comes back.
fn probe_loopback_multicast() -> bool {
    let group = Ipv4Addr::new(224, 0, 0, 251);
    let lo = Ipv4Addr::LOCALHOST;
    let receiver = match Socket::new(Domain::IPV4, Type::DGRAM, None) {
        Ok(socket) => socket,
        Err(err) => {
            eprintln!("the mDNS probe will not open a socket: {err}");
            return false;
        }
    };
    // Bound to every address, since a socket bound to the loopback's unicast
    // address never receives a datagram sent to the group.
    let bind = SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    if let Err(err) = receiver.bind(&bind) {
        eprintln!("the mDNS probe will not bind the loopback: {err}");
        return false;
    }
    let Some(addr) = receiver
        .local_addr()
        .ok()
        .and_then(|addr| addr.as_socket_ipv4())
    else {
        eprintln!("the mDNS probe will not read its bound address");
        return false;
    };
    let port = addr.port();
    if let Err(err) = receiver.join_multicast_v4(&group, &lo) {
        eprintln!("the mDNS probe will not join the group on the loopback: {err}");
        return false;
    }
    let _ = receiver.set_read_timeout(Some(Duration::from_secs(3)));
    let sender = match Socket::new(Domain::IPV4, Type::DGRAM, None) {
        Ok(socket) => socket,
        Err(err) => {
            eprintln!("the mDNS probe will not open a sender: {err}");
            return false;
        }
    };
    if let Err(err) = sender.set_multicast_if_v4(&lo) {
        eprintln!("the mDNS probe will not point the sender at the loopback: {err}");
        return false;
    }
    let target = SockAddr::from(SocketAddrV4::new(group, port));
    if let Err(err) = sender.send_to(b"connetto", &target) {
        eprintln!("the mDNS probe will not multicast to the loopback: {err}");
        return false;
    }
    let mut buf = vec![std::mem::MaybeUninit::uninit(); 32];
    match receiver.recv(buf.as_mut_slice()) {
        Ok(n) if n > 0 => true,
        Ok(_) => {
            eprintln!("the mDNS probe multicast no datagram to the loopback");
            false
        }
        Err(err) => {
            eprintln!("the mDNS probe heard nothing on the loopback: {err}");
            false
        }
    }
}

/// The node's link events handed to the discovery and teed to `out`, until
/// the node's channel ends.
async fn forward(
    discovery: Arc<Discovery>,
    mut node_events: mpsc::UnboundedReceiver<PeerEvent>,
    out: mpsc::UnboundedSender<PeerEvent>,
) {
    while let Some(event) = node_events.recv().await {
        discovery.on_node_event(&event);
        let _ = out.send(event);
    }
}

/// Wait for the instance `fingerprint` to be found, answering its address.
async fn await_found(
    rx: &mut mpsc::UnboundedReceiver<DiscoveryEvent>,
    fingerprint: Fingerprint,
) -> SocketAddr {
    loop {
        let event = time::timeout(WAIT, rx.recv())
            .await
            .expect("discovery reports within the bound")
            .expect("the channel stays open");
        match event {
            DiscoveryEvent::Found {
                address,
                fingerprint: found,
            } if found == fingerprint => {
                return address;
            }
            _ => {}
        }
    }
}

/// Wait for the link to `peer` to land.
async fn await_linked(rx: &mut mpsc::UnboundedReceiver<PeerEvent>, peer: &DeviceIdentity) {
    loop {
        let event = time::timeout(WAIT, rx.recv())
            .await
            .expect("the link lands within the bound")
            .expect("the channel stays open");
        match event {
            PeerEvent::Linked { peer: linked } if &linked == peer => return,
            _ => {}
        }
    }
}

/// Mint one deployment, one issuer, and the two devices a proof links.
fn pair(now: std::time::SystemTime) -> (Deployment, Peer, Peer) {
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
    (deployment, alice, bob)
}

/// A node and its discovery, served on loopback, the events teed out.
fn standing(
    deployment: &Deployment,
    peer: &crate::tests::Peer,
    autolink: bool,
    port: u16,
) -> (
    crate::Node,
    Arc<Discovery>,
    SocketAddr,
    mpsc::UnboundedReceiver<DiscoveryEvent>,
    mpsc::UnboundedReceiver<PeerEvent>,
) {
    let (tx, rx) = events();
    let node = node(deployment.root_der(), tx);
    let (discovery_tx, discovery_rx) = mpsc::unbounded_channel();
    let discovery = Arc::new(
        Discovery::new(node.clone(), autolink, discovery_tx)
            .with_mdns_port(port)
            .loopback_only(),
    );
    let addr = serve(&node, peer);
    let (tee_tx, tee_rx) = mpsc::unbounded_channel();
    let forwarder = discovery.clone();
    tokio::spawn(forward(forwarder, rx, tee_tx));
    (node, discovery, addr, discovery_rx, tee_rx)
}

/// Proof 1.
#[tokio::test]
async fn two_nodes_discover_each_other_and_autolink() {
    if !loopback_multicast() {
        eprintln!("the loopback multicast probe failed, so the proof skips");
        return;
    }
    eprintln!("R76-PROOF-RAN two_nodes_discover_each_other_and_autolink");
    let (deployment, alice, bob) = pair(whole_second());
    let port = fresh_mdns_port();
    let (alice_node, da, a_addr, mut da_rx, mut a_events) =
        standing(&deployment, &alice, true, port);
    let (bob_node, db, b_addr, mut db_rx, mut b_events) = standing(&deployment, &bob, true, port);

    let alice_fp = Fingerprint::of(&alice.leaf);
    let bob_fp = Fingerprint::of(&bob.leaf);
    da.serve(a_addr.port(), alice_fp);
    db.serve(b_addr.port(), bob_fp);

    // Each side reports the other at its bound address, and the dial lands.
    assert_eq!(await_found(&mut da_rx, bob_fp).await, b_addr);
    assert_eq!(await_found(&mut db_rx, alice_fp).await, a_addr);
    await_linked(&mut a_events, &bob.identity).await;
    await_linked(&mut b_events, &alice.identity).await;

    // The node maps the live link to the instance's fingerprint.
    assert_eq!(alice_node.peer_fingerprint(&bob.identity), Some(bob_fp));
    assert_eq!(bob_node.peer_fingerprint(&alice.identity), Some(alice_fp));

    da.stop();
    db.stop();
}

/// Proof 3.
#[tokio::test]
async fn a_renewal_re_registers_under_a_new_fingerprint() {
    if !loopback_multicast() {
        eprintln!("the loopback multicast probe failed, so the proof skips");
        return;
    }
    eprintln!("R76-PROOF-RAN a_renewal_re_registers_under_a_new_fingerprint");
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
    let renewed = deployment.reissue(&issuer, &alice, now, DAY, [3; 16]);

    let port = fresh_mdns_port();
    let (alice_node, da, a_addr, mut da_rx, mut a_events) =
        standing(&deployment, &alice, true, port);
    let (bob_node, db, b_addr, mut db_rx, mut b_events) = standing(&deployment, &bob, true, port);

    let alice_fp = Fingerprint::of(&alice.leaf);
    let bob_fp = Fingerprint::of(&bob.leaf);
    let renewed_fp = Fingerprint::of(&renewed.leaf);
    da.serve(a_addr.port(), alice_fp);
    db.serve(b_addr.port(), bob_fp);

    // They find each other and link under the old fingerprint.
    await_found(&mut da_rx, bob_fp).await;
    await_found(&mut db_rx, alice_fp).await;
    await_linked(&mut a_events, &bob.identity).await;
    await_linked(&mut b_events, &alice.identity).await;

    // The renewal keeps the port and the link, and the advertisement moves
    // to the new fingerprint.
    alice_node
        .serve(a_addr, renewed.identity())
        .expect("the renewal serves");
    da.serve(a_addr.port(), renewed_fp);

    // Bob's browse sees the old instance gone and the new one found, in
    // either order, and the link's renewal reaches his node.
    let mut gone = false;
    let mut found = None;
    while !gone || found.is_none() {
        let event = time::timeout(WAIT, db_rx.recv())
            .await
            .expect("discovery reports within the bound")
            .expect("the channel stays open");
        match event {
            DiscoveryEvent::Gone { fingerprint: g } if g == alice_fp => gone = true,
            DiscoveryEvent::Found {
                address,
                fingerprint: f,
            } if f == renewed_fp => found = Some(address),
            _ => {}
        }
    }
    assert_eq!(found, Some(a_addr));
    let deadline = Instant::now() + WAIT;
    loop {
        if bob_node.peer_fingerprint(&alice.identity) == Some(renewed_fp) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the renewal reaches the link within the bound"
        );
        time::sleep(Duration::from_millis(50)).await;
    }

    da.stop();
    db.stop();
}

/// Proof 5.
#[tokio::test]
async fn dropping_the_driver_ends_its_runner() {
    let (deployment, alice, _bob) = pair(whole_second());
    let (alice_events, _) = events();
    let alice_node = node(deployment.root_der(), alice_events);
    let a_addr = serve(&alice_node, &alice);
    let (da_tx, mut da_rx) = mpsc::unbounded_channel();
    let da = Discovery::new(alice_node, false, da_tx)
        .with_mdns_port(fresh_mdns_port())
        .loopback_only();
    let fp = Fingerprint::of(&alice.leaf);
    da.serve(a_addr.port(), fp);
    // Dropping the driver ends its runner, and the event channel closes with
    // it.
    drop(da);
    let closed = time::timeout(Duration::from_secs(5), da_rx.recv()).await;
    assert!(
        matches!(closed, Ok(None)),
        "dropping the driver ends its runner"
    );
}

/// Proof 6.
#[tokio::test]
async fn a_stopped_discovery_serves_again() {
    if !loopback_multicast() {
        eprintln!("the loopback multicast probe failed, so the proof skips");
        return;
    }
    eprintln!("R76-PROOF-RAN a_stopped_discovery_serves_again");
    let (deployment, alice, bob) = pair(whole_second());
    let port = fresh_mdns_port();

    // The advertiser, without the tee, so the proof can drop it.
    let (alice_events, _) = events();
    let alice_node = node(deployment.root_der(), alice_events);
    let a_addr = serve(&alice_node, &alice);
    let (da_tx, _da_rx) = mpsc::unbounded_channel();
    let da = Discovery::new(alice_node.clone(), false, da_tx)
        .with_mdns_port(port)
        .loopback_only();

    // The browser.
    let (bob_events, _) = events();
    let bob_node = node(deployment.root_der(), bob_events);
    let b_addr = serve(&bob_node, &bob);
    let (db_tx, mut db_rx) = mpsc::unbounded_channel();
    let db = Discovery::new(bob_node.clone(), false, db_tx)
        .with_mdns_port(port)
        .loopback_only();

    let alice_fp = Fingerprint::of(&alice.leaf);
    let bob_fp = Fingerprint::of(&bob.leaf);
    da.serve(a_addr.port(), alice_fp);
    db.serve(b_addr.port(), bob_fp);
    await_found(&mut db_rx, alice_fp).await;
    da.stop();

    // A serve after a stop advertises again, under a fresh name.
    da.serve(a_addr.port(), alice_fp);
    await_found(&mut db_rx, alice_fp).await;

    da.stop();
    db.stop();
}
