#![doc = include_str!("../README.md")]

use std::time::Duration;

/// The bound one hop onto the platform's owning queues gets (R76).
pub const HOP_WITHIN: Duration = Duration::from_secs(10);

/// Why the platform's frameworks could not do what was asked (R76).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A framework reported an error.
    #[error("the {domain} framework reported {code}: {description}")]
    Apple {
        /// The error domain.
        domain: String,
        /// The error code within the domain.
        code: isize,
        /// The framework's description of the error.
        description: String,
    },
    /// A platform facility is absent at run time.
    #[error("the platform facility {0} is absent at run time")]
    Missing(String),
    /// The platform did not answer within [`HOP_WITHIN`].
    #[error("the platform did not answer within {0:?}")]
    TimedOut(Duration),
    /// This target has no such facility.
    #[error("this target has no such facility")]
    Unsupported,
}

/// The device's role in the system's interface families (R76).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Idiom {
    /// A phone.
    Phone,
    /// A pad.
    Pad,
    /// Neither, including every non-Apple target.
    Other,
}

/// The device's user-set name, or `None` for the platform's generic answer.
///
/// iOS answers the user's name only under the
/// `com.apple.developer.device-information.user-selected-name` entitlement,
/// and answers its generic model name without it, which this reads as `None`
/// (R76 decision 17).
pub fn device_name() -> Option<String> {
    crate::platform::device::device_name()
}

/// The device's interface idiom.
///
/// A Wi-Fi pad's Personal Hotspot cannot be turned on from an app, so the
/// client's hotspot backend reads this to answer a typed refusal for a
/// personal host on anything but a phone (R76 decision 27).
pub fn device_idiom() -> Idiom {
    crate::platform::device::device_idiom()
}

/// The names the platform answers for a device it does not name.
#[cfg_attr(
    not(any(target_os = "ios", test)),
    expect(
        dead_code,
        reason = "the iOS platform and the tests read these, a host build without tests uses neither"
    )
)]
const GENERIC_NAMES: [&str; 3] = ["iPhone", "iPad", "iPod"];

/// The domain the system's join answers in.
#[cfg_attr(
    not(any(target_os = "ios", test)),
    expect(
        dead_code,
        reason = "the iOS platform and the tests read this, a host build without tests uses neither"
    )
)]
pub(crate) const HOTSPOT_JOIN_DOMAIN: &str = "NEHotspotConfigurationErrorDomain";

/// The code that domain answers for a network the device already stands on.
#[cfg_attr(
    not(any(target_os = "ios", test)),
    expect(
        dead_code,
        reason = "the iOS platform and the tests read this, a host build without tests uses neither"
    )
)]
pub(crate) const HOTSPOT_ALREADY_ASSOCIATED: isize = 7;

/// Whether the platform's name answer stands generic, so [`device_name`]
/// reads `None` (R76 decision 17).
#[cfg_attr(
    not(any(target_os = "ios", test)),
    expect(
        dead_code,
        reason = "the iOS platform and the tests call this, a host build without tests uses neither"
    )
)]
pub(crate) fn is_generic_name(name: &str) -> bool {
    GENERIC_NAMES.contains(&name)
}

/// Whether the system's join error stands for a network the device already
/// stands on, so the join's goal stands reached (R76).
#[cfg_attr(
    not(any(target_os = "ios", test)),
    expect(
        dead_code,
        reason = "the iOS platform and the tests call this, a host build without tests uses neither"
    )
)]
pub(crate) fn join_already_associated(domain: &str, code: isize) -> bool {
    domain == HOTSPOT_JOIN_DOMAIN && code == HOTSPOT_ALREADY_ASSOCIATED
}

/// One hex digit's value, sixteen standing for invalid.
#[cfg_attr(
    not(any(target_os = "ios", test)),
    expect(
        dead_code,
        reason = "the iOS platform and the tests call this, a host build without tests uses neither"
    )
)]
pub(crate) fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 16,
    }
}

/// The first eight bytes of a canonical UUID text, big-endian, the device
/// key the exchange stands on (R76).
#[cfg_attr(
    not(any(target_os = "ios", test)),
    expect(
        dead_code,
        reason = "the iOS platform and the tests call this, a host build without tests uses neither"
    )
)]
pub(crate) fn key_from_uuid_text(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
    {
        return None;
    }
    let starts = [0, 2, 4, 6, 9, 11, 14, 16];
    let mut out = [0u8; 8];
    for (pair, position) in out.iter_mut().zip(starts) {
        let hi = nibble(bytes[position]);
        let lo = nibble(bytes[position + 1]);
        if hi == 16 || lo == 16 {
            return None;
        }
        *pair = hi * 16 + lo;
    }
    Some(u64::from_be_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::{
        HOTSPOT_JOIN_DOMAIN, is_generic_name, join_already_associated, key_from_uuid_text,
    };

    #[test]
    fn the_device_key_takes_the_uuids_first_half_big_endian() {
        let text = "a9952637-85d5-4071-9ed8-c28bd7ba670c";
        assert_eq!(key_from_uuid_text(text), Some(0xa995_2637_85d5_4071));
    }

    #[test]
    fn the_device_key_rejects_short_and_non_hex_text() {
        assert_eq!(key_from_uuid_text("a995"), None);
        assert_eq!(
            key_from_uuid_text("z9952637-85d5-4071-9ed8-c28bd7ba670c"),
            None
        );
    }

    #[test]
    fn the_platforms_generic_names_stand_generic() {
        assert!(is_generic_name("iPhone"));
        assert!(is_generic_name("iPad"));
        assert!(!is_generic_name("Luca's iPhone"));
        assert!(!is_generic_name(""));
    }

    #[test]
    fn the_join_domain_stands_already_associated_only_there() {
        assert!(join_already_associated(HOTSPOT_JOIN_DOMAIN, 7));
        assert!(!join_already_associated(HOTSPOT_JOIN_DOMAIN, 6));
        assert!(!join_already_associated("OtherDomain", 7));
    }
}

/// The host's Bluetooth, the GATT service the peer exchange runs over and
/// the beacon advertisement that points to it (R76).
pub mod bluetooth {
    /// The radio's standing, as the platform reports it (R76 decision 21).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum State {
        /// The radio is on and the app may use it.
        Ready,
        /// The radio is off, or its standing is not settled yet.
        Off,
        /// The app may not use the radio.
        NotPermitted,
        /// The platform has no such radio.
        Unsupported,
    }

    /// How a prompt action ended, once it settled.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PromptOutcome {
        /// The standing was already the call's, so nothing was asked.
        NotAsked,
        /// The platform asked, and the user declined.
        Declined,
    }

    /// An event the host's GATT service reports (R76).
    #[derive(Clone, Debug)]
    pub enum Event {
        /// A central subscribed to the outbox, `mtu` its frame length.
        Connected {
            /// The central's key, the first eight bytes of its identifier.
            device: u64,
            /// The central's frame length.
            mtu: u16,
        },
        /// A central wrote to the inbox.
        Chunk {
            /// The central's key.
            device: u64,
            /// What the central wrote.
            bytes: Vec<u8>,
        },
        /// A central's subscription ended.
        Disconnected {
            /// The central's key.
            device: u64,
        },
        /// The platform's frameworks failed at the service's work.
        Failed(String),
    }

    /// The radio's standing (R76 decision 21).
    ///
    /// Before a manager exists the app's Bluetooth authorization answers,
    /// `NotPermitted` until the user allowed the app, since creating the
    /// manager is the platform's strongest action and asks for that access.
    /// An app already allowed creates its manager without the power alert
    /// and reads `Off` until the radio's standing arrives.
    pub fn state() -> State {
        crate::platform::peripheral::state()
    }

    /// Run the platform's strongest action once (R76 decision 21).
    ///
    /// On Apple the action creates the manager with its power alert where
    /// that stands to show, and recreates the manager when the radio is off
    /// to show it again.
    ///
    /// # Errors
    ///
    /// A framework error where the platform answers one.
    pub fn prompt() -> Result<(), crate::Error> {
        crate::platform::peripheral::prompt()
    }

    /// The last [`prompt`]'s outcome, once it settles.
    ///
    /// It answers `Some` once the standing is terminal for the prompt, and
    /// `None` while the platform's alert may still be on screen, since the
    /// platform reports no decline for its power alert and the caller's
    /// bound ends a prompt that never settles.
    pub fn prompt_outcome() -> Option<PromptOutcome> {
        crate::platform::peripheral::prompt_outcome()
    }

    /// Open the GATT service and begin its beacon advertisement (R76).
    ///
    /// The advertisement carries the service's UUID alone (R76 decision 25),
    /// and the service's add and the advertisement's start settle on the
    /// platform's own queue, so this answer may stand before the
    /// advertisement is live.
    ///
    /// # Errors
    ///
    /// A framework error where the platform answers one, or its queue not
    /// answering within its bound.
    pub fn start() -> Result<(), crate::Error> {
        crate::platform::peripheral::start()
    }

    /// Stop the advertisement and close the service (R76).
    ///
    /// # Errors
    ///
    /// A framework error where the platform answers one, or its queue not
    /// answering within its bound.
    pub fn stop() -> Result<(), crate::Error> {
        crate::platform::peripheral::stop()
    }

    /// Take the events the service has reported since the last call.
    pub fn poll() -> Vec<Event> {
        crate::platform::peripheral::poll()
    }

    /// Send one outbox notification to a subscribed central.
    ///
    /// A frame the platform cannot take yet is held, and sent when the
    /// platform says it is ready, so back-pressure drops no frame.
    ///
    /// # Errors
    ///
    /// A framework error where the platform answers one, or its queue not
    /// answering within its bound.
    pub fn notify(device: u64, bytes: &[u8]) -> Result<(), crate::Error> {
        crate::platform::peripheral::notify(device, bytes)
    }

    /// Close the central's connection.
    ///
    /// The platform's peripheral role cannot cancel a central's connection
    /// (R76), so this stands ready and records nothing.
    pub fn disconnect(device: u64) {
        crate::platform::peripheral::disconnect(device);
    }
}

/// The joiner's hotspot, the network join asked of the system and the read
/// of the network the device joined (R76).
pub mod hotspot {
    use std::net::{IpAddr, Ipv4Addr};

    /// The network's security, as the platform's join API knows it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Security {
        /// WPA2 personal.
        Wpa2,
        /// WPA3 personal.
        Wpa3,
    }

    /// How the system answered a join it took.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Joining {
        /// The system joined the network.
        Joined,
        /// The device already stood on the network.
        AlreadyThere,
    }

    /// What a joined network stands at, once it stands.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Joined {
        /// The network's address on the device's interface.
        pub address: Ipv4Addr,
        /// The address's prefix length, in bits.
        pub prefix: u8,
        /// The network's gateway, once the system reports a default route.
        pub gateway: Option<IpAddr>,
    }

    /// Ask the system to join a network (R76).
    ///
    /// The system answers with its completion, which this module records.
    /// Read it with [`completion`]. A user's decline of the system's join
    /// dialog answers there as an error, not here.
    ///
    /// # Errors
    ///
    /// A framework error where the platform answers one, and its WPA3
    /// selector standing absent.
    pub fn join(ssid: &str, passphrase: &str, security: Security) -> Result<(), crate::Error> {
        crate::platform::hotspot::join(ssid, passphrase, security)
    }

    /// The system's answer to the last [`join`], once it answers.
    pub fn completion() -> Option<Result<Joining, crate::Error>> {
        crate::platform::hotspot::completion()
    }

    /// Release the system's standing for a network (R76).
    ///
    /// # Errors
    ///
    /// A framework error where the platform answers one.
    pub fn leave(ssid: &str) -> Result<(), crate::Error> {
        crate::platform::hotspot::leave(ssid)
    }

    /// What a joined network stands at (R76 decision 26).
    ///
    /// It answers `Some` once the device's interface carries the joined
    /// network's address, and its gateway is `None` while the system reports
    /// no default route.
    pub fn joined() -> Option<Joined> {
        crate::platform::hotspot::joined()
    }
}

#[cfg(any(target_os = "ios", test))]
mod route;

#[cfg(not(target_os = "ios"))]
#[path = "unsupported.rs"]
mod platform;

#[cfg(target_os = "ios")]
mod platform;
