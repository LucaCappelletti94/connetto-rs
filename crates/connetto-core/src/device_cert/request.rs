use rcgen::{Attribute, CertificateParams, SigningKey};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::cri_attributes::ParsedCriAttribute;
use x509_parser::oid_registry::OID_PKCS9_CHALLENGE_PASSWORD;
use x509_parser::prelude::FromDer;

use super::certificate::is_p256;
use super::identity::decode_lower_hex;

/// PKCS #9 `challengePassword`, which carries the server's enrolment nonce.
const CHALLENGE_PASSWORD: &[u64] = &[1, 2, 840, 113_549, 1, 9, 7];

/// A device's certificate request, its signature checked and its key P-256.
///
/// Only the key and the server's challenge are taken from it. Every field the
/// request asks for (subject, names, usages, constraints) is ignored, since the
/// issuer writes the whole profile itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    spki: Vec<u8>,
    challenge: [u8; 32],
}

/// Why a certificate request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// Not a DER PKCS #10 request.
    #[error("not a certificate request")]
    Malformed,
    /// The request's signature does not verify under its own key.
    #[error("the request's signature does not verify")]
    BadSignature,
    /// The key is not an ECDSA P-256 key.
    #[error("the request's key is not P-256")]
    NotP256,
    /// No `challengePassword` holding a 32-byte nonce in lowercase hex.
    #[error("the request carries no server challenge")]
    NoChallenge,
}

impl CertificateRequest {
    /// Parse and check a DER request.
    ///
    /// # Errors
    ///
    /// [`RequestError`] naming the first check that failed.
    pub fn parse(der: &[u8]) -> Result<Self, RequestError> {
        let (rest, request) =
            X509CertificationRequest::from_der(der).map_err(|_| RequestError::Malformed)?;
        if !rest.is_empty() {
            return Err(RequestError::Malformed);
        }
        let info = &request.certification_request_info;
        let spki = &info.subject_pki;
        if !is_p256(spki) {
            return Err(RequestError::NotP256);
        }
        request
            .verify_signature()
            .map_err(|_| RequestError::BadSignature)?;
        let challenge = info
            .iter_attributes()
            .filter(|attribute| attribute.oid == OID_PKCS9_CHALLENGE_PASSWORD)
            .find_map(|attribute| match attribute.parsed_attribute() {
                ParsedCriAttribute::ChallengePassword(password) => decode_lower_hex(&password.0),
                _ => None,
            })
            .ok_or(RequestError::NoChallenge)?;
        Ok(Self {
            spki: spki.raw.to_vec(),
            challenge,
        })
    }

    /// Build the request a device sends, signed by `key` and carrying `challenge`.
    ///
    /// # Errors
    ///
    /// The signing key's error, such as a chip refusing to sign.
    pub fn build(key: &impl SigningKey, challenge: &[u8; 32]) -> Result<Vec<u8>, rcgen::Error> {
        let request = CertificateParams::default()
            .serialize_request_with_attributes(key, vec![challenge_attribute(challenge)])?;
        Ok(request.der().to_vec())
    }

    /// The DER `SubjectPublicKeyInfo` of the requesting key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.spki
    }

    /// The nonce the server issued for this enrolment.
    #[must_use]
    pub const fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }
}

/// The `challengePassword` attribute holding `nonce` as a 64-character
/// lowercase hex `PrintableString`.
pub(crate) fn challenge_attribute(nonce: &[u8; 32]) -> Attribute {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut values = Vec::with_capacity(68);
    // SET { PrintableString (64 octets) }
    values.extend_from_slice(&[0x31, 66, 0x13, 64]);
    for byte in nonce {
        values.push(HEX[usize::from(byte >> 4)]);
        values.push(HEX[usize::from(byte & 0x0f)]);
    }
    Attribute {
        oid: CHALLENGE_PASSWORD,
        values,
    }
}
