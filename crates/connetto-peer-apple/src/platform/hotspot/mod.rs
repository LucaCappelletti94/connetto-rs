//! The system's join, and the read of the joined network (R76).

#[cfg(target_os = "ios")]
mod ios;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "ios")]
pub(crate) use ios::{completion, join, leave, wifi_name};
#[cfg(target_os = "macos")]
pub(crate) use macos::{completion, join, leave, wifi_name};

use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr};

use crate::hotspot::Joined;

/// What a joined network stands at, read on the Wi-Fi interface alone.
pub(crate) fn joined() -> Option<Joined> {
    let wifi = wifi_name()?;
    let (address, prefix) = ipv4_on(if_addrs::get_if_addrs().ok()?, &wifi)?;
    Some(Joined {
        address,
        prefix,
        gateway: default_route_gateway(&wifi),
    })
}

/// The first `IPv4` address and prefix on the interface named `name`.
fn ipv4_on(
    interfaces: impl IntoIterator<Item = if_addrs::Interface>,
    name: &str,
) -> Option<(Ipv4Addr, u8)> {
    interfaces.into_iter().find_map(|interface| {
        if interface.name != name {
            return None;
        }
        match interface.addr {
            if_addrs::IfAddr::V4(v4) => Some((v4.ip, v4.prefixlen)),
            if_addrs::IfAddr::V6(_) => None,
        }
    })
}

/// The routing table dump's header, as the route parser reads it.
const _: () = assert!(std::mem::size_of::<libc::rt_msghdr>() == crate::route::HEADER);

/// The gateway of the default route on the interface named `wifi`, read
/// from the kernel's routing table, once the system reports one.
pub(crate) fn default_route_gateway(wifi: &str) -> Option<IpAddr> {
    let wifi = CString::new(wifi).ok()?;
    // SAFETY: the name is a valid string the call only reads.
    let index = unsafe { libc::if_nametoindex(wifi.as_ptr()) };
    let index = u16::try_from(index).ok().filter(|index| *index != 0)?;
    let mut name = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        libc::NET_RT_FLAGS,
        libc::RTF_GATEWAY,
    ];
    let depth = libc::c_uint::try_from(name.len()).ok()?;
    let mut length: libc::size_t = 0;
    // SAFETY: the name holds `depth` entries, and a null buffer asks only
    // for the dump's length, which the call writes to `length`.
    let asked = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            depth,
            std::ptr::null_mut(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if asked != 0 {
        return None;
    }
    let mut dump = vec![0u8; length];
    // SAFETY: the buffer holds `length` bytes, the call writes at most that
    // many and answers the count it wrote in `length`.
    let read = unsafe {
        libc::sysctl(
            name.as_mut_ptr(),
            depth,
            dump.as_mut_ptr().cast(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 {
        return None;
    }
    dump.truncate(length);
    crate::route::default_gateway(&dump, index).map(IpAddr::V4)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use if_addrs::{IfAddr, IfOperStatus, Ifv4Addr, Ifv6Addr, Interface};

    use super::ipv4_on;

    fn v4(name: &str, ip: [u8; 4], prefixlen: u8) -> Interface {
        Interface {
            name: name.to_owned(),
            addr: IfAddr::V4(Ifv4Addr {
                ip: Ipv4Addr::from(ip),
                netmask: Ipv4Addr::UNSPECIFIED,
                prefixlen,
                broadcast: None,
            }),
            index: None,
            oper_status: IfOperStatus::Up,
            is_p2p: false,
        }
    }

    /// The address is the Wi-Fi interface's, an Ethernet `en0` beside a
    /// Wi-Fi `en1` never standing in for it.
    #[test]
    fn the_address_is_read_on_the_wifi_interface_alone() {
        let interfaces = vec![
            v4("en0", [192, 168, 1, 20], 24),
            Interface {
                name: "en1".to_owned(),
                addr: IfAddr::V6(Ifv6Addr {
                    ip: std::net::Ipv6Addr::LOCALHOST,
                    netmask: std::net::Ipv6Addr::UNSPECIFIED,
                    prefixlen: 64,
                    broadcast: None,
                }),
                index: None,
                oper_status: IfOperStatus::Up,
                is_p2p: false,
            },
            v4("en1", [172, 20, 10, 2], 28),
        ];
        assert_eq!(
            ipv4_on(interfaces.clone(), "en1"),
            Some((Ipv4Addr::new(172, 20, 10, 2), 28))
        );
        assert_eq!(
            ipv4_on(interfaces, "en0"),
            Some((Ipv4Addr::new(192, 168, 1, 20), 24))
        );
        assert_eq!(ipv4_on(vec![v4("en0", [192, 168, 1, 20], 24)], "en1"), None);
    }
}
