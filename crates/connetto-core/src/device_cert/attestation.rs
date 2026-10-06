//! What a device proved about itself at enrolment, carried in its certificate
//! (R74 decisions 7, 10 and 13).

/// The certificate extension carrying the attestation level, non-critical,
/// whose value is the DER `UTF8String` of [`AttestationLevel::as_str`].
///
/// It stands under RFC 5612's documentation enterprise number 32473 until
/// IANA assigns connetto's own, which replaces it before any real deployment
/// (decision 10).
pub const ATTESTATION_EXTENSION: &[u64] = &[1, 3, 6, 1, 4, 1, 32473, 1];

/// Whether [`ATTESTATION_EXTENSION`] still stands under the documentation
/// number rather than connetto's assigned one.
pub const ATTESTATION_OID_IS_STAND_IN: bool = true;

/// The fixed attestation challenge the Android device key is created with
/// (R74 decision 31), which the server checks its attestation chain for.
pub const ANDROID_ATTESTATION_CHALLENGE: &[u8] = b"connetto device key";

/// What the server verified about a device key at its first enrolment.
/// Renewals keep it and never attest again (decision 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationLevel {
    /// Android attested the key at the `TrustedEnvironment` or `StrongBox`
    /// level, so it lives in the phone's chip.
    ChipProven,
    /// Apple's App Attest signed over the certificate request, so a genuine
    /// copy of the deployment's app on an iPhone, iPad or Mac asked. It says
    /// nothing about where the key lives.
    AppAttested,
    /// Nothing was proven.
    Unproven,
}

impl AttestationLevel {
    /// Every level.
    pub const ALL: [Self; 3] = [Self::ChipProven, Self::AppAttested, Self::Unproven];

    /// The level's name, `chip-proven`, `app-attested` or `unproven`, as the
    /// extension, the enrolment table and the server's settings spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChipProven => "chip-proven",
            Self::AppAttested => "app-attested",
            Self::Unproven => "unproven",
        }
    }

    /// The level `name` spells, the inverse of [`as_str`](Self::as_str).
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|level| level.as_str() == name)
    }

    /// The extension value, a DER `UTF8String` of the level's name.
    #[must_use]
    pub fn extension_value(self) -> Vec<u8> {
        let name = self.as_str().as_bytes();
        let mut der = Vec::with_capacity(name.len() + 2);
        der.push(0x0c);
        der.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
        der.extend_from_slice(name);
        der
    }

    /// The level an extension value names, `None` for anything else.
    #[must_use]
    pub fn from_extension_value(der: &[u8]) -> Option<Self> {
        let [0x0c, len, name @ ..] = der else {
            return None;
        };
        if usize::from(*len) != name.len() {
            return None;
        }
        Self::parse(core::str::from_utf8(name).ok()?)
    }
}

impl core::fmt::Display for AttestationLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
