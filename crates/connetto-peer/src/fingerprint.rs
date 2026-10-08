//! The leaf fingerprint the discovery TXT record and events carry.

use std::fmt;

/// The SHA-256 of a presented leaf, the only thing discovery names about a
/// device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Wrap `bytes`.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Hash `leaf_der`, the presented leaf.
    ///
    /// # Panics
    ///
    /// Never, a SHA-256 digest is 32 bytes.
    pub fn of(leaf_der: &[u8]) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, leaf_der);
        Self(
            digest
                .as_ref()
                .try_into()
                .expect("a sha-256 digest is 32 bytes"),
        )
    }

    /// The 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Fingerprint;

    #[test]
    fn the_hash_of_a_leaf_is_its_lower_hex_display() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let fingerprint = Fingerprint::of(b"the leaf");
        let hex = fingerprint
            .as_bytes()
            .iter()
            .fold(String::new(), |mut out, byte| {
                out.push(char::from(HEX[usize::from(*byte >> 4)]));
                out.push(char::from(HEX[usize::from(*byte & 0xf)]));
                out
            });
        assert_eq!(fingerprint.to_string(), hex);
    }
}
