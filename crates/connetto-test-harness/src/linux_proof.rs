//! The pure standing of the linux leg proof (R76 slice 9b), beside the
//! leg's child process in `linux_leg`. The leg's scan, its beacon's prefix
//! and the phone's network standing the walk reads, and the helpers that
//! name them.

use std::fmt::Write;
use std::net::IpAddr;
use std::time::Duration;

use connetto_client::BluetoothState;
use serde::{Deserialize, Serialize};

/// How long the adapter gets to report itself off after a power off.
pub const ADAPTER_OFF_BOUND: Duration = Duration::from_secs(30);

/// One nearby host the leg's scan stands on, as its standing.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NearbyHost {
    /// The host's device, the key the scan stands on.
    pub host: u64,
    /// The beacon's prefix as 16 hex digits, where the beacon carries one.
    pub prefix: Option<String>,
    /// The signal the beacon carried.
    pub rssi: Option<i16>,
}

/// The offer a linux host stands on, as the leg's `host` answer shows it.
#[derive(Clone, Debug, Deserialize)]
pub struct LegOffer {
    /// The hotspot's ssid.
    pub ssid: String,
    /// The hotspot's passphrase.
    pub passphrase: String,
    /// The host's peer port, while its listener serves.
    pub port: Option<u16>,
    /// The offer as one `WIFI:` payload.
    pub payload: String,
    /// Why the beacon is down beside the offer, and none while it
    /// advertises.
    pub beacon_off: Option<String>,
}

/// The connection a connected Wi-Fi device holds in an `nmcli dev status`
/// listing, absent while no connected Wi-Fi line names one.
pub fn parse_station_name(status: &str) -> Option<String> {
    status.lines().find_map(|line| {
        // The tokens come off one by one, the rest trimmed after each.
        let (_, rest) = line.trim_start().split_once(char::is_whitespace)?;
        let (kind, rest) = rest.trim_start().split_once(char::is_whitespace)?;
        let (state, rest) = rest.trim_start().split_once(char::is_whitespace)?;
        // The connection name may hold spaces, so it is the whole rest.
        let name = rest.trim_start();
        (kind == "wifi" && state == "connected" && !name.is_empty()).then(|| name.to_owned())
    })
}

/// The first three octets of the hotspot's shared subnet, which
/// `NetworkManager`'s `ipv4.method shared` always brings up at `10.42.0.1/24`.
pub const HOTSPOT_SUBNET_OCTETS: [u8; 3] = [10, 42, 0];

/// Whether `remote` stands inside the shared hotspot subnet.
pub fn in_hotspot_subnet(remote: IpAddr) -> bool {
    matches!(remote, IpAddr::V4(v4) if v4.octets()[..3] == HOTSPOT_SUBNET_OCTETS)
}

/// The remote endpoint of one `ss -tnH state established` line, absent
/// while the line names no endpoint or no address.
pub fn ss_remote_address(line: &str) -> Option<IpAddr> {
    // The endpoint is the line's last field: an address, a port, and
    // brackets while the address is IPv6.
    let peer = line.split_whitespace().next_back()?;
    let address = if let Some(close) = peer.find(']')
        && peer.starts_with('[')
    {
        &peer[1..close]
    } else {
        peer.rsplit_once(':')?.0
    };
    let ip: IpAddr = address.parse().ok()?;
    if let IpAddr::V6(v6) = ip {
        let seg = v6.segments();
        // An IPv4 endpoint can stand mapped into an IPv6 address, its
        // five zero groups, the all-ones group and two address groups.
        if seg[0..6] == [0, 0, 0, 0, 0, 0xffff] {
            let high = seg[6].to_be_bytes();
            let low = seg[7].to_be_bytes();
            return Some(IpAddr::from([high[0], high[1], low[0], low[1]]));
        }
    }
    Some(ip)
}

/// The host to join, where exactly one host stands in sight and its beacon
/// carries `prefix`, and none while another host stands or the prefix does
/// not show.
pub fn single_nearby(hosts: &[NearbyHost], prefix: &str) -> Option<u64> {
    match hosts {
        [host] if host.prefix.as_deref() == Some(prefix) => Some(host.host),
        _ => None,
    }
}

/// The beacon's prefix as the pages show it, 16 lowercase hex digits.
pub fn hex_prefix(prefix: [u8; 8]) -> String {
    let mut out = String::with_capacity(16);
    for byte in prefix {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The Bluetooth standing a leg's `bluetooth` answer names.
pub fn bluetooth_state(text: &str) -> BluetoothState {
    match text {
        "ready" => BluetoothState::Ready,
        "off" => BluetoothState::Off,
        "not permitted" => BluetoothState::NotPermitted,
        _ => BluetoothState::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn station_name_reads_a_connected_wifi_line() {
        let status = "\
DEVICE           TYPE    STATE                  CONNECTION
wlp39s0          wifi      connected              iliadbox-107795 1
p2p-dev-wlp39s0  wifi-p2p  disconnected           --
";
        assert_eq!(
            parse_station_name(status).as_deref(),
            Some("iliadbox-107795 1")
        );
    }

    #[test]
    fn station_name_ignores_every_line_but_a_connected_wifi() {
        let status = "\
enp37s0f0        ethernet  connected              iliadbox-wired
wlp39s0          wifi      disconnected           --
";
        assert_eq!(parse_station_name(status), None);
    }

    #[test]
    fn station_name_reads_a_hosting_ap() {
        let status = "wlp39s0          wifi      connected              connetto-1a2b\n";
        assert_eq!(parse_station_name(status).as_deref(), Some("connetto-1a2b"));
    }

    #[test]
    fn station_name_refuses_an_empty_name() {
        let status = "wlp39s0          wifi      connected              \n";
        assert_eq!(parse_station_name(status), None);
    }

    #[test]
    fn single_host_carries_the_prefix() {
        let hosts = vec![NearbyHost {
            host: 7,
            prefix: Some("a1b2c3d4e5f6a7b8".to_owned()),
            rssi: Some(-40),
        }];
        assert_eq!(single_nearby(&hosts, "a1b2c3d4e5f6a7b8"), Some(7));
    }

    #[test]
    fn single_host_refuses_a_wrong_prefix() {
        let hosts = vec![NearbyHost {
            host: 7,
            prefix: Some("a1b2c3d4e5f6a7b8".to_owned()),
            rssi: None,
        }];
        assert_eq!(single_nearby(&hosts, "ffffffffffffffff"), None);
        assert_eq!(single_nearby(&[], "a1b2c3d4e5f6a7b8"), None);
    }

    #[test]
    fn single_host_refuses_a_second_host() {
        let hosts = vec![
            NearbyHost {
                host: 7,
                prefix: Some("a1b2c3d4e5f6a7b8".to_owned()),
                rssi: None,
            },
            NearbyHost {
                host: 8,
                prefix: None,
                rssi: None,
            },
        ];
        assert_eq!(single_nearby(&hosts, "a1b2c3d4e5f6a7b8"), None);
    }

    #[test]
    fn beacon_prefix_renders_sixteen_hex_digits() {
        assert_eq!(
            hex_prefix([0, 1, 16, 127, 255, 0, 9, 42]),
            "0001107fff00092a"
        );
    }

    #[test]
    fn bluetooth_answers_map_to_the_client_states() {
        assert_eq!(bluetooth_state("ready"), BluetoothState::Ready);
        assert_eq!(bluetooth_state("off"), BluetoothState::Off);
        assert_eq!(
            bluetooth_state("not permitted"),
            BluetoothState::NotPermitted
        );
        assert_eq!(bluetooth_state("unsupported"), BluetoothState::Unsupported);
        assert_eq!(
            bluetooth_state("something else"),
            BluetoothState::Unsupported
        );
    }

    #[test]
    fn ss_remote_reads_an_ipv4_endpoint() {
        let line = "tcp   ESTAB  0      0      192.168.1.145:51234  10.42.0.2:37105";
        assert_eq!(ss_remote_address(line), Some(IpAddr::from([10, 42, 0, 2])));
    }

    #[test]
    fn ss_remote_reads_an_ipv4_mapped_endpoint() {
        let line = "tcp   ESTAB  0      0      [::1]:4242         ::ffff:10.42.0.2:37105";
        assert_eq!(ss_remote_address(line), Some(IpAddr::from([10, 42, 0, 2])));
    }

    #[test]
    fn ss_remote_reads_a_bracketed_ipv6_endpoint() {
        let line = "tcp   ESTAB  0      0      [::1]:4242         [fd00::1]:37105";
        assert_eq!(
            ss_remote_address(line),
            Some(IpAddr::V6("fd00::1".parse().unwrap()))
        );
    }

    #[test]
    fn ss_remote_refuses_a_line_without_an_endpoint() {
        assert_eq!(ss_remote_address(""), None);
        assert_eq!(ss_remote_address("tcp   ESTAB  0      0"), None);
        assert_eq!(ss_remote_address("u_str ESTAB  0      0      u_str"), None);
    }

    #[test]
    fn ss_remote_refuses_an_unparseable_endpoint() {
        let line = "tcp   ESTAB  0      0      192.168.1.145:51234  999.999.0.2:37105";
        assert_eq!(ss_remote_address(line), None);
        assert_eq!(
            ss_remote_address("tcp   ESTAB  0      0      [::1]:4242  [not-an-address]:37105"),
            None
        );
    }

    #[test]
    fn the_shared_subnet_holds_the_hotspot_endpoints() {
        assert!(in_hotspot_subnet(IpAddr::from([10, 42, 0, 2])));
        assert!(!in_hotspot_subnet(IpAddr::from([192, 168, 1, 2])));
        assert!(!in_hotspot_subnet(IpAddr::from([10, 42, 1, 2])));
    }
}
