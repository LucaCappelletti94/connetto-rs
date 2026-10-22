//! The peer and hotspot panel (R76): the device's peer listener, its linked
//! peers, the hotspot it hosts with the offer shown as plain lines, and the
//! forms that join a hotspot another device hosted.
//!
//! The panel is native only, since a browser has no Bluetooth or hotspot
//! control, and sits behind the `peer` feature like the link itself.

use dioxus::prelude::*;

use crate::platform::native::SessionParts;
use connetto_client::ClientEvent;

fn linked_line(
    peer: &connetto_core::device_cert::DeviceIdentity,
    remote: Option<std::net::SocketAddr>,
) -> String {
    match remote {
        Some(remote) => format!("linked: {} via {remote}", short_identity(peer)),
        None => format!("linked: {}", short_identity(peer)),
    }
}

/// A device identity as `account/key prefix`, what the panel names devices
/// by, its own included.
#[cfg(feature = "peer")]
fn short_identity(identity: &connetto_core::device_cert::DeviceIdentity) -> String {
    let key = identity.key().to_string();
    let prefix = key.get(..8).unwrap_or_default();
    format!("{}/{prefix}", identity.account())
}

/// The offer's port line, `none` while the device does not serve its peer.
#[cfg(feature = "peer")]
fn port_line(port: Option<u16>) -> String {
    port.map_or_else(|| "none".to_owned(), |port| port.to_string())
}

/// The offer this device hosts, as the lines the panel shows it, the
/// passphrase copied out of the offer before it zeroizes its.
#[cfg(feature = "peer")]
#[derive(Clone, Debug)]
struct OfferLines {
    /// The hotspot's ssid.
    ssid: String,
    /// The hotspot's passphrase.
    passphrase: String,
    /// The device's peer port, present while it serves it.
    port: Option<u16>,
    /// The offer as one `WIFI:` payload, which the panel also draws as a QR
    /// code (R76 decision 23).
    payload: String,
}

/// The payload as an SVG QR code, `None` where it does not fit one.
#[cfg(feature = "peer")]
fn payload_qr(payload: &str) -> Option<String> {
    let code = qrcode::QrCode::new(payload.as_bytes()).ok()?;
    Some(
        code.render::<qrcode::render::svg::Color<'_>>()
            .min_dimensions(200, 200)
            .build(),
    )
}

/// The host's beacon standing as the panel's line.
#[cfg(feature = "peer")]
fn format_beacon(state: connetto_client::BeaconState) -> String {
    match state {
        connetto_client::BeaconState::Advertising { prefix } => {
            let mut line = String::from("beacon: advertising ");
            for byte in prefix {
                use std::fmt::Write as _;
                let _ = write!(line, "{byte:02x}");
            }
            line
        }
        connetto_client::BeaconState::Off { reason } => format!("beacon: off ({reason})"),
    }
}

/// The permission a refused nearby join misses, which the panel asks for.
#[cfg(feature = "peer")]
fn nearby_permission(err: &connetto_client::JoinNearbyError) -> Option<&str> {
    match err {
        connetto_client::JoinNearbyError::Join(connetto_client::JoinError::MissingPermission(
            name,
        )) => Some(name),
        _ => None,
    }
}
/// The peer and hotspot panel (R76 slice 4): the device's peer listener, its
/// linked peers, the hotspot it hosts with the offer shown as plain lines,
/// and the form that joins a hotspot another device hosted.
#[cfg(feature = "peer")]
#[component]
pub(crate) fn PeerPanel(parts: SessionParts) -> Element {
    use connetto_client::{HotspotError, HotspotOffer, HotspotSecurity, JoinError};
    use dioxus_free_icons::Icon;
    use dioxus_free_icons::icons::fa_solid_icons::{
        FaCircleInfo, FaPowerOff, FaQrcode, FaRightFromBracket, FaSatelliteDish, FaStop,
        FaTowerBroadcast, FaWifi,
    };

    // The listener's port, read again every second, since the listener opens
    // beside the pump the way enrolment does.
    let mut peer_port: Signal<Option<u16>> = use_signal(|| None);
    // One line per linked peer, read off the node on the same pace, so a
    // replaced link never leaves its old address on the page.
    let mut peers: Signal<Vec<String>> = use_signal(Vec::new);
    // The Bluetooth standing and the host's beacon, read on the same pace.
    let mut bluetooth_line: Signal<String> = use_signal(|| "bluetooth: unsupported".to_owned());
    let mut beacon_line: Signal<String> =
        use_signal(|| "beacon: off (no bluetooth on this system)".to_owned());
    {
        let parts = parts.clone();
        use_hook(move || {
            spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let port = parts.0.native.peer_address().map(|address| address.port());
                    if *peer_port.peek() != port {
                        peer_port.set(port);
                    }
                    let state = format!("bluetooth: {}", parts.0.native.bluetooth_state());
                    if *bluetooth_line.peek() != state {
                        bluetooth_line.set(state);
                    }
                    let line = format_beacon(parts.0.native.beacon_state());
                    if *beacon_line.peek() != line {
                        beacon_line.set(line);
                    }
                    let mut lines: Vec<String> = parts
                        .0
                        .native
                        .linked_peers()
                        .iter()
                        .map(|link| linked_line(&link.peer, link.remote))
                        .collect();
                    lines.sort();
                    if *peers.peek() != lines {
                        peers.set(lines);
                    }
                }
            })
        });
    }

    // The offer this device hosts, as its plain lines, until the hotspot
    // stops.
    let offer: Signal<Option<OfferLines>> = use_signal(|| None);
    // The last hotspot or join outcome, `idle` before the first.
    let outcome: Signal<String> = use_signal(|| "idle".to_owned());
    // Whether this device stands joined to a host's hotspot, which hides the
    // joins and the hosting until it leaves.
    let joined: Signal<bool> = use_signal(|| false);
    // Whether a VPN refused the joined hotspot's dial, shown on its own line
    // so a join's outcome landing later never hides it.
    let vpn_blocked: Signal<bool> = use_signal(|| false);
    // A permission a host or join named as missing, which the panel asks for
    // on the UI thread, where the platform's prompt wants to be asked from.
    let missing: Signal<Option<String>> = use_signal(|| None);
    // The hosts whose beacons this device sees, with their prefixes and
    // signals, as the scan reports them.
    let nearby: Signal<Vec<NearbyHost>> = use_signal(Vec::new);
    // The join form, the host's offer read off its lines or typed over.
    let mut join_ssid: Signal<String> = use_signal(String::new);
    let mut join_passphrase: Signal<String> = use_signal(String::new);
    let mut join_port: Signal<String> = use_signal(String::new);
    // A pasted or scanned `WIFI:` payload (R76 decision 24).
    let mut join_payload: Signal<String> = use_signal(String::new);
    // The personal hotspot's form, the network name pre-filled from the
    // device's user-set name where the platform answers one (R76 decision 26).
    let mut personal_ssid: Signal<String> =
        use_signal(|| parts.0.native.personal_hotspot_name().unwrap_or_default());
    let mut personal_passphrase: Signal<String> = use_signal(String::new);

    // The link's and the hotspot's events, which the panel owns.
    let client = parts.0.client.clone();
    let event_rx = client.events();
    {
        let mut offer = offer;
        let mut outcome = outcome;
        let mut nearby = nearby;
        let mut joined = joined;
        let mut vpn_blocked = vpn_blocked;
        use_hook(move || {
            spawn(async move {
                let mut rx = event_rx;
                while let Ok(event) = rx.recv().await {
                    match event {
                        ClientEvent::HotspotStopped => {
                            offer.set(None);
                            outcome.set("stopped by the system or the user".to_owned());
                        }
                        ClientEvent::HotspotLeft => {
                            joined.set(false);
                            vpn_blocked.set(false);
                            outcome.set("the joined network was lost".to_owned());
                        }
                        ClientEvent::HostNearby { host, prefix, rssi } => {
                            let mut held = nearby.peek().clone();
                            held.retain(|known| known.host != host);
                            held.push(NearbyHost { host, prefix, rssi });
                            nearby.set(held);
                        }
                        ClientEvent::HostGone { host } => {
                            let mut held = nearby.peek().clone();
                            held.retain(|known| known.host != host);
                            nearby.set(held);
                        }
                        ClientEvent::HotspotUnreached => {
                            outcome.set("unreached".to_owned());
                        }
                        ClientEvent::JoinedNetworkBlockedByVpn => {
                            vpn_blocked.set(true);
                        }
                        _ => {}
                    }
                }
            })
        });
    }

    // The platform's permission prompt wants the UI thread, so the panel
    // fires it there when a host or join named a missing permission.
    let mut missing_effect = missing;
    use_effect(move || {
        if missing_effect().is_some() {
            #[cfg(target_os = "android")]
            connetto_peer_android::request_peer_permissions();
            #[cfg(target_os = "macos")]
            connetto_peer_apple::hotspot::request_location_access();
            missing_effect.set(None);
        }
    });

    let host_parts = parts.clone();
    let host_offer = offer;
    let host_outcome = outcome;
    let host_missing = missing;
    let stop_parts = parts.clone();
    let stop_offer = offer;
    let stop_outcome = outcome;
    let join_parts = parts.clone();
    let mut join_outcome = outcome;
    let join_missing = missing;
    let leave_parts = parts.clone();
    let payload_parts = parts.clone();
    let payload_outcome = outcome;
    let payload_missing = missing;
    let nearby_missing = missing;
    let leave_outcome = outcome;
    let bt_parts = parts.clone();
    let bt_outcome = outcome;
    let nearby_parts = parts.clone();
    let nearby_outcome = outcome;
    let nearby_hosts = nearby;
    let personal_parts = parts.clone();
    let personal_offer = offer;
    let mut personal_outcome = outcome;
    let join_joined = joined;
    let payload_joined = joined;
    let nearby_joined = joined;
    let leave_joined = joined;
    let leave_vpn_blocked = vpn_blocked;

    let me = parts
        .0
        .native
        .device_certificate()
        .map(|certificate| short_identity(certificate.identity()));
    let peer_line = match (peer_port(), me) {
        (Some(port), Some(me)) => format!("peer: listening on {port} as {me}"),
        _ => "peer: not serving".to_owned(),
    };
    let peers = peers();
    let nearby_lines: Vec<String> = nearby().iter().map(NearbyHost::line).collect();
    let offer = offer();
    let outcome = outcome();
    let hosting = offer.is_some();
    let joined_now = joined();
    let vpn_line = (joined() && vpn_blocked()).then_some(
        "link: a VPN on this device blocks its own connections over the joined hotspot, only peers that connect to it can link",
    );
    #[cfg(target_os = "ios")]
    let personal_note: Option<&str> = Some("connetto cannot see whether Personal Hotspot is on");
    #[cfg(not(target_os = "ios"))]
    let personal_note: Option<&str> = None;

    rsx! {
        div {
            class: "peer",
            style: "font-family: monospace; font-size: 0.85em; color: #333; border: 1px solid #ccc; border-radius: 4px; padding: 8px 12px; margin-bottom: 12px; line-height: 1.5;",
            style {
                ".peer section + section {{ border-top: 1px solid #ddd; }}
                .peer section {{ padding: 6px 0; }}
                .peer h4 {{ display: flex; align-items: center; gap: 6px; margin: 4px 0; font-size: 1em; }}
                .peer p {{ margin: 2px 0; }}
                .peer input {{ display: block; width: 100%; max-width: 28em; box-sizing: border-box; margin: 4px 0; padding: 4px 6px; font-family: monospace; }}
                .peer .row {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 6px 0; }}
                .peer button {{ display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; }}"
            }
            section {
                h4 {
                    Icon { icon: FaCircleInfo, width: 14, height: 14 }
                    "Status"
                }
                p { {peer_line} }
                p { {bluetooth_line()} }
                p { {beacon_line()} }
                for line in peers.iter().cloned() {
                    p { {line} }
                }
                if let Some(note) = personal_note {
                    p { {note} }
                }
                for line in nearby_lines {
                    p { {line} }
                }
                if let Some(offer) = offer {
                    p {
                        "hotspot ssid: "
                        {offer.ssid.clone()}
                    }
                    p {
                        "hotspot passphrase: "
                        {offer.passphrase.clone()}
                    }
                    p {
                        "hotspot port: "
                        {port_line(offer.port)}
                    }
                    p {
                        "hotspot payload: "
                        {offer.payload.clone()}
                    }
                    if let Some(svg) = payload_qr(&offer.payload) {
                        div { dangerous_inner_html: svg }
                    }
                }
                p {
                    "hotspot: "
                    {outcome}
                }
                if let Some(line) = vpn_line {
                    p { {line} }
                }
                div { class: "row",
                    button {
                        onclick: move |_| {
                            let parts = bt_parts.clone();
                            let mut outcome = bt_outcome;
                            spawn(async move {
                                outcome.set("turning on bluetooth".to_owned());
                                match parts.0.native.enable_bluetooth().await {
                                    Ok(()) => outcome.set("bluetooth is on".to_owned()),
                                    Err(err) => outcome.set(err.to_string()),
                                }
                            });
                        },
                        Icon { icon: FaPowerOff, width: 14, height: 14 }
                        "Turn on Bluetooth"
                    }
                }
            }
            if !cfg!(target_os = "macos") && !joined_now {
                section {
                    h4 {
                        Icon { icon: FaTowerBroadcast, width: 14, height: 14 }
                        "Host"
                    }
                    div { class: "row",
                        if !hosting {
                            button {
                                onclick: move |_| {
                                    let parts = host_parts.clone();
                                    let mut offer = host_offer;
                                    let mut outcome = host_outcome;
                                    let mut missing = host_missing;
                                    spawn(async move {
                                        outcome.set("asking for the hotspot".to_owned());
                                        let result = parts.0.native.host_hotspot().await;
                                        match result {
                                            Ok(hosted) => {
                                                offer
                                                    .set(
                                                        Some(OfferLines {
                                                            ssid: hosted.offer.ssid.clone(),
                                                            passphrase: hosted.offer.passphrase.clone(),
                                                            port: hosted.offer.port,
                                                            payload: hosted.offer.to_wifi_payload().to_string(),
                                                        }),
                                                    );
                                                outcome
                                                    .set(
                                                        match hosted.beacon {
                                                            Ok(()) => "hosting".to_owned(),
                                                            Err(err) => format!("hosting, the beacon is off: {err}"),
                                                        },
                                                    );
                                            }
                                            Err(err) => {
                                                if let HotspotError::MissingPermission(name) = &err {
                                                    missing.set(Some(name.clone()));
                                                }
                                                outcome.set(err.to_string());
                                            }
                                        }
                                    });
                                },
                                Icon {
                                    icon: FaTowerBroadcast,
                                    width: 14,
                                    height: 14,
                                }
                                "Host a hotspot"
                            }
                        }
                        if hosting {
                            button {
                                onclick: move |_| {
                                    let parts = stop_parts.clone();
                                    let mut offer = stop_offer;
                                    let mut outcome = stop_outcome;
                                    spawn(async move {
                                        parts.0.native.stop_hotspot().await;
                                        offer.set(None);
                                        outcome.set("stopped".to_owned());
                                    });
                                },
                                Icon { icon: FaStop, width: 14, height: 14 }
                                "Stop the hotspot"
                            }
                        }
                    }
                    if cfg!(target_os = "ios") && !hosting {
                        input {
                            r#type: "text",
                            name: "personal-ssid",
                            placeholder: "the personal hotspot's network name",
                            value: "{personal_ssid}",
                            oninput: move |event| personal_ssid.set(event.value()),
                            style: "font-family: monospace;",
                        }
                        input {
                            r#type: "text",
                            name: "personal-passphrase",
                            placeholder: "the personal hotspot's passphrase",
                            value: "{personal_passphrase}",
                            oninput: move |event| personal_passphrase.set(event.value()),
                            style: "font-family: monospace;",
                        }
                        button {
                            onclick: move |_| {
                                let ssid = personal_ssid.peek().trim().to_owned();
                                let passphrase = personal_passphrase.peek().clone();
                                if ssid.is_empty() || passphrase.is_empty() {
                                    personal_outcome
                                        .set("the network name and the passphrase need filling".to_owned());
                                    return;
                                }
                                let parts = personal_parts.clone();
                                let mut offer = personal_offer;
                                let mut outcome = personal_outcome;
                                spawn(async move {
                                    outcome.set("asking for the personal hotspot".to_owned());
                                    let result =
                                        parts.0.native.host_personal_hotspot(&ssid, &passphrase).await;
                                    match result {
                                        Ok(hosted) => {
                                            offer
                                                .set(
                                                    Some(OfferLines {
                                                        ssid: hosted.offer.ssid.clone(),
                                                        passphrase: hosted.offer.passphrase.clone(),
                                                        port: hosted.offer.port,
                                                        payload: hosted.offer.to_wifi_payload().to_string(),
                                                    }),
                                                );
                                            outcome
                                                .set(
                                                    match hosted.beacon {
                                                        Ok(()) => "hosting".to_owned(),
                                                        Err(err) => format!("hosting, the beacon is off: {err}"),
                                                    },
                                                );
                                        }
                                        Err(err) => outcome.set(err.to_string()),
                                    }
                                });
                            },
                            Icon {
                                icon: FaTowerBroadcast,
                                width: 14,
                                height: 14,
                            }
                            "Host my Personal Hotspot"
                        }
                    }
                }
            }
            if !hosting && !joined_now {
                section {
                    h4 {
                        Icon { icon: FaWifi, width: 14, height: 14 }
                        "Join by the offer"
                    }
                    input {
                        r#type: "text",
                        name: "ssid",
                        placeholder: "the offer's ssid",
                        value: "{join_ssid}",
                        oninput: move |event| join_ssid.set(event.value()),
                        style: "font-family: monospace;",
                    }
                    input {
                        r#type: "text",
                        name: "passphrase",
                        placeholder: "the offer's passphrase",
                        value: "{join_passphrase}",
                        oninput: move |event| join_passphrase.set(event.value()),
                        style: "font-family: monospace;",
                    }
                    input {
                        r#type: "text",
                        name: "port",
                        placeholder: "the offer's port",
                        value: "{join_port}",
                        oninput: move |event| join_port.set(event.value()),
                        style: "font-family: monospace;",
                    }
                    button {
                        onclick: move |_| {
                            let ssid = join_ssid.peek().trim().to_owned();
                            let passphrase = join_passphrase.peek().clone();
                            let port_text = join_port.peek().trim().to_owned();
                            if ssid.is_empty() || passphrase.is_empty() {
                                join_outcome.set("the ssid and the passphrase need filling".to_owned());
                                return;
                            }
                            let port = match port_text.as_str() {
                                "" => None,
                                text => {
                                    match text.parse::<u16>() {
                                        Ok(port) => Some(port),
                                        Err(_) => {
                                            join_outcome.set("the port is not a number".to_owned());
                                            return;
                                        }
                                    }
                                }
                            };
                            let offer = HotspotOffer::new(ssid, passphrase, HotspotSecurity::Wpa2, port);
                            let parts = join_parts.clone();
                            let mut outcome = join_outcome;
                            let mut joined = join_joined;
                            let mut missing = join_missing;
                            spawn(async move {
                                outcome.set("joining the hotspot".to_owned());
                                let gateway = parts.0.native.join_hotspot(&offer).await;
                                match gateway {
                                    Ok(gateway) => {
                                        joined.set(true);
                                        outcome.set(format!("joined through the gateway {gateway}"));
                                    }
                                    Err(err) => {
                                        if let JoinError::MissingPermission(name) = &err {
                                            missing.set(Some(name.clone()));
                                        }
                                        outcome.set(err.to_string());
                                    }
                                }
                            });
                        },
                        Icon { icon: FaWifi, width: 14, height: 14 }
                        "Join the hotspot"
                    }
                }
                section {
                    h4 {
                        Icon { icon: FaQrcode, width: 14, height: 14 }
                        "Join by the payload"
                    }
                    input {
                        name: "payload",
                        placeholder: "WIFI: payload",
                        value: "{join_payload}",
                        oninput: move |event| join_payload.set(event.value()),
                        style: "font-family: monospace;",
                    }
                    button {
                        onclick: move |_| {
                            let mut outcome = payload_outcome;
                            let mut joined = payload_joined;
                            let offer = match HotspotOffer::from_wifi_payload(join_payload.peek().trim()) {
                                Ok(offer) => offer,
                                Err(err) => {
                                    outcome.set(err.to_string());
                                    return;
                                }
                            };
                            let parts = payload_parts.clone();
                            let mut missing = payload_missing;
                            spawn(async move {
                                outcome.set("joining the hotspot".to_owned());
                                match parts.0.native.join_hotspot(&offer).await {
                                    Ok(gateway) => {
                                        joined.set(true);
                                        outcome.set(format!("joined through the gateway {gateway}"));
                                    }
                                    Err(err) => {
                                        if let JoinError::MissingPermission(name) = &err {
                                            missing.set(Some(name.clone()));
                                        }
                                        outcome.set(err.to_string());
                                    }
                                }
                            });
                        },
                        Icon { icon: FaQrcode, width: 14, height: 14 }
                        "Join from the payload"
                    }
                }
            }
            if !hosting {
                section {
                    h4 {
                        Icon { icon: FaSatelliteDish, width: 14, height: 14 }
                        "Join nearby, or leave"
                    }
                    div { class: "row",
                        if joined_now {
                            button {
                                onclick: move |_| {
                                    let parts = leave_parts.clone();
                                    let mut outcome = leave_outcome;
                                    let mut joined = leave_joined;
                                    let mut vpn_blocked = leave_vpn_blocked;
                                    spawn(async move {
                                        parts.0.native.leave_hotspot().await;
                                        joined.set(false);
                                        vpn_blocked.set(false);
                                        outcome.set("left".to_owned());
                                    });
                                },
                                Icon {
                                    icon: FaRightFromBracket,
                                    width: 14,
                                    height: 14,
                                }
                                "Leave the hotspot"
                            }
                        }
                        if !joined_now {
                            button {
                                onclick: move |_| {
                                    let strongest = nearby_hosts
                                        .peek()
                                        .iter()
                                        .max_by_key(|known| (known.rssi.unwrap_or(i16::MIN), known.host))
                                        .map(|known| known.host);
                                    let mut outcome = nearby_outcome;
                                    let mut joined = nearby_joined;
                                    // One nearby join at a time, so its outcome is the one shown.
                                    if *outcome.peek() == "joining the nearby host" {
                                        return;
                                    }
                                    let Some(host) = strongest else {
                                        outcome.set("no host is nearby".to_owned());
                                        return;
                                    };
                                    let parts = nearby_parts.clone();
                                    let mut missing = nearby_missing;
                                    spawn(async move {
                                        outcome.set("joining the nearby host".to_owned());
                                        match parts.0.native.join_nearby(&host).await {
                                            Ok((identity, gateway)) => {
                                                joined.set(true);
                                                outcome
                                                    .set(
                                                        format!(
                                                            "joined through the gateway {gateway} as {}",
                                                            short_identity(&identity),
                                                        ),
                                                    );
                                            }
                                            Err(err) => {
                                                if let Some(name) = nearby_permission(&err) {
                                                    missing.set(Some(name.to_owned()));
                                                }
                                                outcome.set(err.to_string());
                                            }
                                        }
                                    });
                                },
                                Icon {
                                    icon: FaSatelliteDish,
                                    width: 14,
                                    height: 14,
                                }
                                "Join the nearby host"
                            }
                        }
                    }
                }
            }
        }
    }
}
/// A host whose beacon this device sees (R76).
#[cfg(feature = "peer")]
#[derive(Clone, PartialEq)]
struct NearbyHost {
    host: connetto_client::HostId,
    /// The beacon's prefix, where the beacon carries one (R76 decision 25).
    prefix: Option<[u8; 8]>,
    rssi: Option<i16>,
}

#[cfg(feature = "peer")]
impl NearbyHost {
    /// The panel's line, `nearby: <prefix>` or `nearby: no beacon prefix`
    /// where the beacon carries none, with the signal where known.
    fn line(&self) -> String {
        use std::fmt::Write as _;
        let mut line = String::from("nearby: ");
        match self.prefix {
            Some(prefix) => {
                for byte in prefix {
                    let _ = write!(line, "{byte:02x}");
                }
            }
            None => line.push_str("no beacon prefix"),
        }
        if let Some(rssi) = self.rssi {
            let _ = write!(line, " at {rssi} dBm");
        }
        line
    }
}

#[cfg(test)]
mod tests {
    /// A nearby join refused for a missing permission names it, so the
    /// panel asks for it as the typed and payload joins do.
    #[test]
    fn a_nearby_join_names_the_permission_it_misses() {
        use super::nearby_permission;
        use connetto_client::{BluetoothError, JoinError, JoinNearbyError};
        let missing =
            JoinNearbyError::Join(JoinError::MissingPermission("Location Services".to_owned()));
        assert_eq!(nearby_permission(&missing), Some("Location Services"));
        let unsupported = JoinNearbyError::Bluetooth(BluetoothError::Unsupported);
        assert_eq!(nearby_permission(&unsupported), None);
    }
}
