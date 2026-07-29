//! The per-replica key that encrypts a local replica's pages at rest.
//!
//! One replica file, one key. It is scoped per device rather than per session,
//! so it outlives logout and lets a returning user resume their replica
//! instead of re-syncing, and it is destroyed only by an explicit data wipe,
//! which crypto-shreds the replica by making its ciphertext inert.
//!
//! Do not confuse it with [`SessionId`](crate::SessionId), which turns over
//! with every session. Two keys, two lifetimes, and nothing derives one from
//! the other.
//!
//! The server mints it once, at login, and never retains a copy. The client
//! caches it and prefers its cached copy forever after, which is what makes it
//! per replica: two devices of one identity cache different keys, and neither
//! can read the other's file. The consequence is deliberate and worth stating
//! plainly: losing the cached key loses the replica. Synced tables recover by
//! re-syncing from the server, device-local tables do not recover at all.
//!
//! The core carries no entropy source, exactly as it carries none for
//! `SessionId`, so there is no `ReplicaKey::generate` here. Minting belongs to
//! the server that owns the login, which already has a CSPRNG.
//!
//! Serialization is lowercase hex, because the value rides a JSON token
//! response. The bytes are wiped when the key is dropped, and neither
//! [`Debug`](core::fmt::Debug) nor [`Display`](core::fmt::Display) will print
//! them.

use core::fmt;
use core::str::FromStr;

use zeroize::Zeroize;

/// The raw key that encrypts one replica's pages.
///
/// Obtain one from the token response at login, or from the client's key
/// store on a later boot. Treat [`ReplicaKey::as_bytes`] as the only way the
/// material leaves this type, and keep it out of logs.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplicaKey([u8; Self::LEN]);

impl ReplicaKey {
    /// Length of the raw key in bytes, fixed by the AES-256 page cipher.
    pub const LEN: usize = 32;

    /// Take ownership of raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The raw key material.
    ///
    /// The only accessor, so a `grep` for it finds every place the bytes
    /// escape.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl Drop for ReplicaKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Redacted: a key must never reach a log through a derived `Debug`.
impl fmt::Debug for ReplicaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReplicaKey(<redacted>)")
    }
}

/// Redacted, for the same reason as [`Debug`].
impl fmt::Display for ReplicaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A string that is not a valid replica key.
///
/// Implemented by hand rather than through `thiserror`, which is an optional
/// dependency here, so the key costs the core no new mandatory crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaKeyParseError;

impl fmt::Display for ReplicaKeyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a replica key is {} lowercase hex characters",
            ReplicaKey::LEN * 2
        )
    }
}

impl std::error::Error for ReplicaKeyParseError {}

/// Parse the lowercase hex form. Uppercase is accepted too, since a hand-typed
/// key in a test fixture is not worth rejecting over case.
impl FromStr for ReplicaKey {
    type Err = ReplicaKeyParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.len() != Self::LEN * 2 {
            return Err(ReplicaKeyParseError);
        }
        let mut bytes = [0u8; Self::LEN];
        for (slot, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
            let hi = hex_digit(pair[0]).ok_or(ReplicaKeyParseError)?;
            let lo = hex_digit(pair[1]).ok_or(ReplicaKeyParseError)?;
            *slot = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

/// The value of one hex digit, or `None` when the byte is not one.
const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl serde::Serialize for ReplicaKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut hex = String::with_capacity(Self::LEN * 2);
        for byte in self.0 {
            use fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        let result = serializer.serialize_str(&hex);
        hex.zeroize();
        result
    }
}

impl<'de> serde::Deserialize<'de> for ReplicaKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let parsed = text.parse().map_err(serde::de::Error::custom);
        // The transient hex is key material too, so it does not outlive the parse.
        let mut text = text;
        text.zeroize();
        parsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let key = ReplicaKey::from_bytes([0xab; ReplicaKey::LEN]);
        let json = serde_json::to_string(&key).expect("serialize");
        assert_eq!(json, format!("\"{}\"", "ab".repeat(ReplicaKey::LEN)));
        let back: ReplicaKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, key);
    }

    #[test]
    fn every_byte_survives_the_round_trip() {
        let mut bytes = [0u8; ReplicaKey::LEN];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::try_from(index * 7 % 256).expect("below 256");
        }
        let key = ReplicaKey::from_bytes(bytes);
        let json = serde_json::to_string(&key).expect("serialize");
        let back: ReplicaKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.as_bytes(), &bytes);
    }

    #[test]
    fn a_wrong_length_is_refused() {
        assert!("ab".parse::<ReplicaKey>().is_err());
        assert!(
            "ab".repeat(ReplicaKey::LEN + 1)
                .parse::<ReplicaKey>()
                .is_err()
        );
    }

    #[test]
    fn a_non_hex_character_is_refused() {
        let mut text = "ab".repeat(ReplicaKey::LEN);
        text.replace_range(0..1, "z");
        assert!(text.parse::<ReplicaKey>().is_err());
    }

    #[test]
    fn uppercase_hex_parses_to_the_same_key() {
        let lower: ReplicaKey = "ab".repeat(ReplicaKey::LEN).parse().expect("lowercase");
        let upper: ReplicaKey = "AB".repeat(ReplicaKey::LEN).parse().expect("uppercase");
        assert_eq!(lower, upper);
    }

    #[test]
    fn neither_debug_nor_display_leaks_the_bytes() {
        let key = ReplicaKey::from_bytes([0xcd; ReplicaKey::LEN]);
        assert!(!format!("{key:?}").contains("cd"));
        assert!(!format!("{key}").contains("cd"));
    }
}
