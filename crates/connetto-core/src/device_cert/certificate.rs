use std::time::{Duration, SystemTime, UNIX_EPOCH};

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY};
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;

use super::attestation::{ATTESTATION_EXTENSION, AttestationLevel};
use super::identity::{DeviceIdentity, IdentityError, KeyId};

/// A device certificate whose profile has been checked.
///
/// Parsing checks the profile only. The chain, validity window and revocation
/// are the verifier's to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificate {
    identity: DeviceIdentity,
    not_before: SystemTime,
    not_after: SystemTime,
    serial: Vec<u8>,
    attestation: AttestationLevel,
}

/// How a certificate departs from the device profile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// Not a DER X.509 certificate.
    #[error("not a certificate")]
    Malformed,
    /// The subject is not empty.
    #[error("the subject is not empty")]
    Subject,
    /// The certificate is a CA.
    #[error("the certificate is a CA")]
    CertificateAuthority,
    /// Key usage is absent, not critical, or more than `digitalSignature`.
    #[error("key usage is not exactly digitalSignature, marked critical")]
    KeyUsage,
    /// Extended key usage is not exactly `serverAuth` and `clientAuth`.
    #[error("extended key usage is not exactly serverAuth and clientAuth")]
    ExtendedKeyUsage,
    /// The subject alternative names are not one critical URI.
    #[error("the subject alternative names are not exactly one critical URI")]
    SubjectAltName,
    /// The URI is not a device identity.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// The key is not an ECDSA P-256 key.
    #[error("the key is not P-256")]
    NotP256,
    /// The URI names a different key from the one the certificate holds.
    #[error("the identity names a different key")]
    KeyMismatch,
    /// A critical extension outside the profile.
    #[error("a critical extension outside the profile")]
    UnknownCriticalExtension,
    /// The attestation extension is critical or names no level.
    #[error("the attestation extension is critical or names no level")]
    Attestation,
}

impl DeviceCertificate {
    /// Parse `der` and check it against the device profile.
    ///
    /// # Errors
    ///
    /// [`ProfileError`] naming the first departure from the profile.
    pub fn parse(der: &[u8]) -> Result<Self, ProfileError> {
        let (rest, cert) = X509Certificate::from_der(der).map_err(|_| ProfileError::Malformed)?;
        if !rest.is_empty() {
            return Err(ProfileError::Malformed);
        }
        if cert.subject().iter().next().is_some() {
            return Err(ProfileError::Subject);
        }
        let spki = cert.public_key();
        if !is_p256(spki) {
            return Err(ProfileError::NotP256);
        }

        let mut identity = None;
        let mut attestation = AttestationLevel::Unproven;
        let (mut key_usage, mut extended_key_usage) = (false, false);
        for extension in cert.extensions() {
            if extension
                .oid
                .iter()
                .is_some_and(|arcs| arcs.eq(ATTESTATION_EXTENSION.iter().copied()))
            {
                if extension.critical {
                    return Err(ProfileError::Attestation);
                }
                attestation = AttestationLevel::from_extension_value(extension.value)
                    .ok_or(ProfileError::Attestation)?;
                continue;
            }
            match extension.parsed_extension() {
                ParsedExtension::BasicConstraints(constraints) => {
                    if constraints.ca {
                        return Err(ProfileError::CertificateAuthority);
                    }
                }
                ParsedExtension::KeyUsage(usage) => {
                    let only_signature = usage.digital_signature() && usage.flags.is_power_of_two();
                    if !extension.critical || !only_signature {
                        return Err(ProfileError::KeyUsage);
                    }
                    key_usage = true;
                }
                ParsedExtension::ExtendedKeyUsage(usage) => {
                    let exact = usage.server_auth
                        && usage.client_auth
                        && !usage.any
                        && !usage.code_signing
                        && !usage.email_protection
                        && !usage.time_stamping
                        && !usage.ocsp_signing
                        && usage.other.is_empty();
                    if !exact {
                        return Err(ProfileError::ExtendedKeyUsage);
                    }
                    extended_key_usage = true;
                }
                ParsedExtension::SubjectAlternativeName(names) => {
                    let [GeneralName::URI(uri)] = names.general_names.as_slice() else {
                        return Err(ProfileError::SubjectAltName);
                    };
                    if !extension.critical {
                        return Err(ProfileError::SubjectAltName);
                    }
                    identity = Some(DeviceIdentity::from_uri(uri)?);
                }
                _ if extension.critical => return Err(ProfileError::UnknownCriticalExtension),
                _ => {}
            }
        }
        if !key_usage {
            return Err(ProfileError::KeyUsage);
        }
        if !extended_key_usage {
            return Err(ProfileError::ExtendedKeyUsage);
        }
        let identity = identity.ok_or(ProfileError::SubjectAltName)?;
        if identity.key() != KeyId::of_public_key(spki.raw) {
            return Err(ProfileError::KeyMismatch);
        }

        let validity = cert.validity();
        let serial = cert.raw_serial();
        let serial = serial.strip_prefix(&[0]).unwrap_or(serial).to_vec();
        Ok(Self {
            identity,
            not_before: from_timestamp(validity.not_before.timestamp())?,
            not_after: from_timestamp(validity.not_after.timestamp())?,
            serial,
            attestation,
        })
    }

    /// What the device proved at its first enrolment, `Unproven` for a
    /// certificate without the attestation extension.
    #[must_use]
    pub const fn attestation(&self) -> AttestationLevel {
        self.attestation
    }

    /// The device the certificate names.
    #[must_use]
    pub const fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// The start of the validity window.
    #[must_use]
    pub const fn not_before(&self) -> SystemTime {
        self.not_before
    }

    /// The end of the validity window.
    #[must_use]
    pub const fn not_after(&self) -> SystemTime {
        self.not_after
    }

    /// The serial number, without the sign octet DER adds to a high first byte.
    #[must_use]
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }
}

fn from_timestamp(secs: i64) -> Result<SystemTime, ProfileError> {
    u64::try_from(secs)
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
        .map_err(|_| ProfileError::Malformed)
}

/// Whether `spki` holds an ECDSA key on P-256, the one curve every device chip holds.
pub(super) fn is_p256(spki: &SubjectPublicKeyInfo<'_>) -> bool {
    spki.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY
        && spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|params| params.as_oid().ok())
            .is_some_and(|curve| curve == OID_EC_P256)
}
