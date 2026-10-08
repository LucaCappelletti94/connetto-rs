/// The X.509 serial of a certificate the deployment signs.
///
/// Sixteen octets whose first is `0x01` through `0x7F`, so the DER
/// `INTEGER` of it is positive and minimal, the form RFC 5280 4.1.2.2
/// and the DER encoding rules ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateSerial([u8; 16]);

impl CertificateSerial {
    /// The serial over `bytes`, when its first octet is `0x01` through `0x7F`.
    ///
    /// `None` when the first octet is `0x00`, which a minimal `INTEGER`
    /// drops, or `0x80` or higher, which would read as negative.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Option<Self> {
        match bytes[0] {
            0x01..=0x7F => Some(Self(bytes)),
            _ => None,
        }
    }

    /// A fresh serial, drawn from `fill` until its first octet is positive
    /// and minimal, so the redraw keeps the draw unbiased.
    ///
    /// # Errors
    ///
    /// The error `fill` reports when it refuses a draw.
    pub fn random<F, E>(mut fill: F) -> Result<Self, E>
    where
        F: FnMut(&mut [u8]) -> Result<(), E>,
    {
        loop {
            let mut bytes = [0_u8; 16];
            fill(&mut bytes)?;
            if let Some(serial) = Self::new(bytes) {
                return Ok(serial);
            }
        }
    }

    /// The octets, as the record and the certificate carry them.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}
