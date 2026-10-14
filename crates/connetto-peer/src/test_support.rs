//! The loopback multicast probe the discovery proofs run before they trust
//! the interface, here and in `connetto-client`'s suite (R76 slice 3).
//!
//! A proof whose probe fails skips itself, so a host without loopback
//! multicast never reads as a discovery failure. Setting
//! `CONNETTO_REQUIRE_MULTICAST` turns a failed probe into a panic, which CI
//! sets so a broken probe never hides every proof behind a skip.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use socket2::{Domain, SockAddr, Socket, Type};

/// A loopback multicast round-trip, answered when the host lets it through.
///
/// Binds a datagram socket to every address, joins the mDNS group on the
/// loopback, and asks a second socket, pointed at the loopback, to multicast
/// to it.
///
/// # Panics
///
/// When the probe fails while `CONNETTO_REQUIRE_MULTICAST` is set.
#[must_use]
pub fn loopback_multicast() -> bool {
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
