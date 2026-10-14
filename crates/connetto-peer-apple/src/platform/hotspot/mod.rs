//! The system's join, and the read of the joined network (R76).

#[cfg(target_os = "ios")]
mod ios;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "ios")]
pub(crate) use ios::{completion, join, leave};
#[cfg(target_os = "macos")]
pub(crate) use macos::{completion, join, leave};

use std::net::IpAddr;

use crate::hotspot::Joined;

/// What a joined network stands at.
pub(crate) fn joined() -> Option<Joined> {
    let (address, prefix) = if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find_map(|interface| {
            (interface.name == "en0")
                .then_some(interface.addr)
                .and_then(|addr| match addr {
                    if_addrs::IfAddr::V4(v4) => Some((v4.ip, v4.prefixlen)),
                    if_addrs::IfAddr::V6(_) => None,
                })
        })?;
    Some(Joined {
        address,
        prefix,
        gateway: default_route_gateway(),
    })
}

/// The routing table dump's header, as the route parser reads it.
const _: () = assert!(std::mem::size_of::<libc::rt_msghdr>() == crate::route::HEADER);

/// The joined network's interface.
const WIFI: &std::ffi::CStr = c"en0";

/// The gateway of the default route on the Wi-Fi interface, read from the
/// kernel's routing table, once the system reports one.
pub(crate) fn default_route_gateway() -> Option<IpAddr> {
    // SAFETY: the name is a valid string the call only reads.
    let index = unsafe { libc::if_nametoindex(WIFI.as_ptr()) };
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
