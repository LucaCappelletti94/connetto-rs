use core::fmt;

use sha2::{Digest, Sha256};

const SCHEME: &str = "connetto://";

/// The deployment a device belongs to, the UUID its root names (R74 decision 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeploymentId(uuid::Uuid);

impl DeploymentId {
    /// Wrap the UUID a root was created with.
    #[must_use]
    pub const fn from_uuid(id: uuid::Uuid) -> Self {
        Self(id)
    }

    /// The underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &uuid::Uuid {
        &self.0
    }

    /// Parse the canonical lowercase hyphenated form, refusing every other spelling.
    pub(crate) fn from_canonical(text: &str) -> Option<Self> {
        let id = uuid::Uuid::try_parse(text).ok()?;
        (id.hyphenated().to_string() == text).then_some(Self(id))
    }
}

impl fmt::Display for DeploymentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

/// The SHA-256 of a device key's `SubjectPublicKeyInfo`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId([u8; 32]);

impl KeyId {
    /// The id of the key whose DER `SubjectPublicKeyInfo` is `spki`.
    #[must_use]
    pub fn of_public_key(spki: &[u8]) -> Self {
        Self(Sha256::digest(spki).into())
    }

    /// Wrap a digest already computed.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_hex(text: &str) -> Option<Self> {
        decode_lower_hex(text).map(Self)
    }
}

/// 32 bytes from exactly 64 lowercase hex digits.
pub(super) fn decode_lower_hex(text: &str) -> Option<[u8; 32]> {
    let (pairs, []) = text.as_bytes().as_chunks::<2>() else {
        return None;
    };
    if pairs.len() != 32 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (byte, &[high, low]) in bytes.iter_mut().zip(pairs) {
        *byte = (lower_hex_value(high)? << 4) | lower_hex_value(low)?;
    }
    Some(bytes)
}

fn lower_hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({self})")
    }
}

/// The deployment, account and device key a certificate names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceIdentity {
    deployment: DeploymentId,
    account: String,
    key: KeyId,
}

/// Why a device identity or its URI was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The account is empty, `.` or `..`, or holds a character outside SPIFFE's path set.
    #[error("the account {0:?} cannot be a URI path segment")]
    Account(String),
    /// The text is not `connetto://<deployment>/account/<account>/device/<key>`.
    #[error("{0:?} is not a device identity URI")]
    Uri(String),
}

impl DeviceIdentity {
    /// Name the device holding `key` for `account` in `deployment`.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Account`] when the account is empty, `.` or `..`, or
    /// holds a character outside SPIFFE's letters, digits, dots, dashes and
    /// underscores.
    pub fn new(
        deployment: DeploymentId,
        account: impl Into<String>,
        key: KeyId,
    ) -> Result<Self, IdentityError> {
        let account = account.into();
        if !is_path_segment(&account) {
            return Err(IdentityError::Account(account));
        }
        Ok(Self {
            deployment,
            account,
            key,
        })
    }

    /// Parse the URI a certificate carries.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Uri`] for anything but the exact canonical form.
    pub fn from_uri(uri: &str) -> Result<Self, IdentityError> {
        let refused = || IdentityError::Uri(uri.to_owned());
        let rest = uri.strip_prefix(SCHEME).ok_or_else(refused)?;
        let mut parts = rest.split('/');
        let (Some(deployment), Some("account"), Some(account), Some("device"), Some(key), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(refused());
        };
        let deployment = DeploymentId::from_canonical(deployment).ok_or_else(refused)?;
        let key = KeyId::from_hex(key).ok_or_else(refused)?;
        Self::new(deployment, account, key).map_err(|_| refused())
    }

    /// The URI form, which round-trips through [`Self::from_uri`].
    #[must_use]
    pub fn uri(&self) -> String {
        format!(
            "{SCHEME}{}/account/{}/device/{}",
            self.deployment, self.account, self.key
        )
    }

    /// The deployment.
    #[must_use]
    pub const fn deployment(&self) -> DeploymentId {
        self.deployment
    }

    /// The account.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The device key's id.
    #[must_use]
    pub const fn key(&self) -> KeyId {
        self.key
    }
}

fn is_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}
