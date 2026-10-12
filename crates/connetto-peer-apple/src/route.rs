//! The default gateway read from the kernel's routing table dump, the bytes
//! `sysctl` answers for `CTL_NET`, `PF_ROUTE`, `NET_RT_FLAGS` and
//! `RTF_GATEWAY` on Apple systems (R76).

use std::net::Ipv4Addr;

/// The length of Apple's `rt_msghdr`, the header before each route's
/// addresses.
pub(crate) const HEADER: usize = 92;
/// The route is up.
const RTF_UP: u32 = 0x1;
/// The route goes through a gateway.
const RTF_GATEWAY: u32 = 0x2;
/// The route's destination address follows the header.
const RTA_DST: u32 = 0x1;
/// The route's gateway address follows the destination.
const RTA_GATEWAY: u32 = 0x2;
/// The address family of IP version 4.
const AF_INET: u8 = 2;

/// The gateway of the up default route over IP version 4 on the interface `index` in
/// `dump`, `None` when the dump carries none or does not parse.
pub(crate) fn default_gateway(dump: &[u8], index: u16) -> Option<Ipv4Addr> {
    let mut rest = dump;
    while rest.len() >= HEADER {
        let length = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        if length < HEADER || length > rest.len() {
            return None;
        }
        let (message, next) = rest.split_at(length);
        rest = next;
        let route_index = u16::from_ne_bytes([message[4], message[5]]);
        let flags = u32::from_ne_bytes(message[8..12].try_into().ok()?);
        let addresses = u32::from_ne_bytes(message[12..16].try_into().ok()?);
        if route_index != index
            || flags & (RTF_UP | RTF_GATEWAY) != RTF_UP | RTF_GATEWAY
            || addresses & (RTA_DST | RTA_GATEWAY) != RTA_DST | RTA_GATEWAY
        {
            continue;
        }
        let body = &message[HEADER..];
        let (destination, body) = sockaddr(body)?;
        let (gateway, _) = sockaddr(body)?;
        if inet(destination).unwrap_or(Ipv4Addr::UNSPECIFIED) != Ipv4Addr::UNSPECIFIED {
            continue;
        }
        if let Some(gateway) = inet(gateway) {
            return Some(gateway);
        }
    }
    None
}

/// The next address in a route message and the bytes after it, its length
/// rounded up to four bytes and an empty one taking four.
fn sockaddr(body: &[u8]) -> Option<(&[u8], &[u8])> {
    let length = usize::from(*body.first()?);
    let taken = length.max(1).div_ceil(4) * 4;
    if body.len() < taken {
        return None;
    }
    Some((&body[..length], &body[taken..]))
}

/// The version 4 address of `sockaddr`, `None` for another family or a short
/// one.
fn inet(sockaddr: &[u8]) -> Option<Ipv4Addr> {
    if sockaddr.len() < 8 || sockaddr[1] != AF_INET {
        return None;
    }
    Some(Ipv4Addr::new(
        sockaddr[4],
        sockaddr[5],
        sockaddr[6],
        sockaddr[7],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One route message, Apple's header then the destination and gateway
    /// addresses, each padded to four bytes.
    fn message(index: u16, flags: u32, destination: &[u8], gateway: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        for address in [destination, gateway] {
            body.extend_from_slice(address);
            let padded = address.len().max(1).div_ceil(4) * 4;
            body.resize(body.len() + padded - address.len(), 0);
        }
        let mut header = vec![0u8; HEADER];
        let length = u16::try_from(HEADER + body.len()).unwrap();
        header[0..2].copy_from_slice(&length.to_ne_bytes());
        header[2] = 5;
        header[3] = 4;
        header[4..6].copy_from_slice(&index.to_ne_bytes());
        header[8..12].copy_from_slice(&flags.to_ne_bytes());
        header[12..16].copy_from_slice(&(RTA_DST | RTA_GATEWAY).to_ne_bytes());
        header.extend_from_slice(&body);
        header
    }

    fn inet(address: [u8; 4]) -> Vec<u8> {
        let mut sockaddr = vec![16, AF_INET, 0, 0];
        sockaddr.extend_from_slice(&address);
        sockaddr.resize(16, 0);
        sockaddr
    }

    #[test]
    fn the_default_route_on_the_interface_answers_its_gateway() {
        let mut dump = message(
            3,
            RTF_UP | RTF_GATEWAY,
            &inet([10, 0, 0, 0]),
            &inet([10, 0, 0, 9]),
        );
        dump.extend(message(
            4,
            RTF_UP | RTF_GATEWAY,
            &inet([0, 0, 0, 0]),
            &inet([172, 20, 10, 1]),
        ));
        assert_eq!(
            default_gateway(&dump, 4),
            Some(Ipv4Addr::new(172, 20, 10, 1))
        );
    }

    #[test]
    fn a_default_route_with_an_empty_destination_counts() {
        let dump = message(4, RTF_UP | RTF_GATEWAY, &[0], &inet([192, 168, 43, 1]));
        assert_eq!(
            default_gateway(&dump, 4),
            Some(Ipv4Addr::new(192, 168, 43, 1))
        );
    }

    #[test]
    fn another_interface_or_a_down_route_answers_none() {
        let mut dump = message(
            7,
            RTF_UP | RTF_GATEWAY,
            &inet([0, 0, 0, 0]),
            &inet([10, 9, 0, 1]),
        );
        dump.extend(message(
            4,
            RTF_GATEWAY,
            &inet([0, 0, 0, 0]),
            &inet([172, 20, 10, 1]),
        ));
        assert_eq!(default_gateway(&dump, 4), None);
    }

    #[test]
    fn a_truncated_dump_answers_none() {
        let dump = message(
            4,
            RTF_UP | RTF_GATEWAY,
            &inet([0, 0, 0, 0]),
            &inet([172, 20, 10, 1]),
        );
        assert_eq!(default_gateway(&dump[..HEADER + 10], 4), None);
        assert_eq!(default_gateway(&dump[..40], 4), None);
    }
}
