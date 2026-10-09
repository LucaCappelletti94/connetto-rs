//! The beacon the host advertises over Bluetooth while it hosts a hotspot
//! and serves its peer link (R76 decision 18).

use crate::fingerprint::Fingerprint;
use crate::frame::PROTOCOL_VERSION;

// The frame version must fit the beacon's one version byte, and a value that
// no longer fits stops the crate compiling.
const _: () = assert!(
    // Widening, so the bound compares losslessly in a const context.
    PROTOCOL_VERSION <= u8::MAX as u16,
    "the beacon's version byte fits the frame version"
);

/// The frame version the beacon's service data carries.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the assertion above bounds the version to a byte"
)]
const VERSION: u8 = PROTOCOL_VERSION as u8;

/// The GATT service the beacon advertises and the exchange runs under,
/// `a9952637-85d5-4071-9ed8-c28bd7ba670c`.
pub const SERVICE_UUID: [u8; 16] = [
    0xa9, 0x95, 0x26, 0x37, 0x85, 0xd5, 0x40, 0x71, 0x9e, 0xd8, 0xc2, 0x8b, 0xd7, 0xba, 0x67, 0x0c,
];
/// The characteristic the joiner writes its chunks to,
/// `bdd3f20f-a8d0-4003-82db-4f941b4c375b`.
pub const INBOX_UUID: [u8; 16] = [
    0xbd, 0xd3, 0xf2, 0x0f, 0xa8, 0xd0, 0x40, 0x03, 0x82, 0xdb, 0x4f, 0x94, 0x1b, 0x4c, 0x37, 0x5b,
];
/// The characteristic the joiner reads its chunks from,
/// `62ba3a58-c377-47f5-93e1-cd6790bc2e53`.
pub const OUTBOX_UUID: [u8; 16] = [
    0x62, 0xba, 0x3a, 0x58, 0xc3, 0x77, 0x47, 0xf5, 0x93, 0xe1, 0xcd, 0x67, 0x90, 0xbc, 0x2e, 0x53,
];

/// The advertised beacon, the frame version beside the first 8 bytes of the
/// presented leaf's fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Beacon {
    /// The frame version the host speaks.
    pub version: u8,
    /// The first 8 bytes of the presented leaf's fingerprint.
    pub prefix: [u8; 8],
}

impl Beacon {
    /// The beacon of the presented leaf's `fingerprint`.
    #[must_use]
    pub fn of(fingerprint: &Fingerprint) -> Self {
        Self {
            version: VERSION,
            prefix: fingerprint.prefix(),
        }
    }

    /// The 9 service-data bytes, the version ahead of the prefix.
    #[must_use]
    pub fn to_service_data(&self) -> [u8; 9] {
        let mut data = [0u8; 9];
        data[0] = self.version;
        data[1..].copy_from_slice(&self.prefix);
        data
    }

    /// Decode the 9 service-data bytes a scan of this service carries,
    /// `None` when the slice is short.
    #[must_use]
    pub fn from_service_data(data: &[u8]) -> Option<Self> {
        let version = *data.first()?;
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(data.get(1..9)?);
        Some(Self { version, prefix })
    }

    /// Whether the beacon is `fingerprint`'s, the prefix the only thing a
    /// scan carries of it.
    #[must_use]
    pub fn matches(&self, fingerprint: &Fingerprint) -> bool {
        self.prefix == fingerprint.prefix()
    }
}

/// The whole legacy advertisement, the flags beside the one service-data AD
/// under [`SERVICE_UUID`], test-only.
#[cfg(test)]
pub(crate) fn legacy_advert_bytes(beacon: &Beacon) -> [u8; 30] {
    let mut bytes = [0u8; 30];
    // The flags take the three reserved bytes, broadcast, limited
    // discoverable.
    bytes[0..3].copy_from_slice(&[0x01, 0x02, 0x06]);
    // The service-data AD, its length counting the type, the 16 UUID bytes
    // and the 9 data bytes.
    bytes[3] = 26;
    bytes[4] = 0x21;
    bytes[5..21].copy_from_slice(&SERVICE_UUID);
    bytes[21..30].copy_from_slice(&beacon.to_service_data());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_data_round_trips_and_names_the_prefix() {
        let fingerprint = Fingerprint::of(b"the presented leaf");
        let beacon = Beacon::of(&fingerprint);
        assert_eq!(beacon.version, 1);
        assert_eq!(beacon.prefix, fingerprint.prefix());

        let data = beacon.to_service_data();
        assert_eq!(data.len(), 9);
        assert_eq!(data[0], beacon.version);
        assert_eq!(&data[1..], &fingerprint.prefix());

        let decoded = Beacon::from_service_data(&data).expect("the service data decodes");
        assert_eq!(decoded, beacon);
        assert!(decoded.matches(&fingerprint));
        let other = Fingerprint::of(b"another leaf");
        assert!(!decoded.matches(&other));

        assert!(Beacon::from_service_data(&data[..8]).is_none());
        assert!(Beacon::from_service_data(&[]).is_none());
    }

    #[test]
    fn the_legacy_advert_fits_its_31_bytes() {
        let beacon = Beacon::of(&Fingerprint::of(b"the presented leaf"));
        let advert = legacy_advert_bytes(&beacon);
        // A legacy advertisement is 31 bytes including the three reserved,
        // and the flags plus the one service-data AD use 30.
        assert!(advert.len() <= 31);
        assert_eq!(&advert[0..3], &[0x01, 0x02, 0x06]);
        assert_eq!(&advert[3..5], &[26, 0x21]);
        assert_eq!(&advert[5..21], &SERVICE_UUID);
        assert_eq!(&advert[21..30], &beacon.to_service_data());
    }
}
