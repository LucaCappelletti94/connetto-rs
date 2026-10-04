//! Revocation lists (R74 step 5): X.509 CRLs an issuer signs, numbered per
//! issuer, and the chain checks a device runs against the roots it ships.

use std::time::SystemTime;

use rcgen::{
    CertificateRevocationListParams, Issuer, KeyIdMethod, RevokedCertParams, SerialNumber,
};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;

use super::authority::{DeviceIssuer, to_time};
use super::identity::KeyId;

/// One certificate a list revokes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    /// The certificate's serial.
    pub serial: Vec<u8>,
    /// When it was revoked.
    pub at: SystemTime,
}

/// A list whose signature chains to a deployment root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationList {
    issuer: KeyId,
    number: u64,
    serials: Vec<Vec<u8>>,
    der: Vec<u8>,
}

/// Why a list or a chain was refused, or a list not signed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListError {
    /// A list or certificate does not parse.
    #[error("not a revocation list or certificate")]
    Malformed,
    /// The list carries no CRL Number, or one over 64 bits.
    #[error("the list carries no usable CRL Number")]
    NoNumber,
    /// The signature does not verify under the named signer's key.
    #[error("the signature does not verify")]
    BadSignature,
    /// The signer is not a root the device ships and does not chain to one.
    #[error("the signer does not chain to a deployment root")]
    Untrusted,
    /// The times do not fit an X.509 time.
    #[error("the times are outside what a list can carry")]
    Validity,
    /// The certificate library refused the parameters.
    #[error("the list could not be signed")]
    Sign(#[from] rcgen::Error),
}

impl DeviceIssuer {
    /// Sign list number `number`, revoking `revoked`, issued at `this_update`
    /// and promising the next by `next_update`.
    ///
    /// # Errors
    ///
    /// [`ListError::Validity`] for times outside X.509, [`ListError::Sign`]
    /// when signing fails.
    pub fn sign_list(
        &self,
        number: u64,
        revoked: &[Revoked],
        this_update: SystemTime,
        next_update: SystemTime,
    ) -> Result<Vec<u8>, ListError> {
        let revoked_certs = revoked
            .iter()
            .map(|entry| {
                Ok(RevokedCertParams {
                    serial_number: SerialNumber::from_slice(&entry.serial),
                    revocation_time: to_time(entry.at).ok_or(ListError::Validity)?,
                    reason_code: None,
                    invalidity_date: None,
                })
            })
            .collect::<Result<Vec<_>, ListError>>()?;
        let params = CertificateRevocationListParams {
            this_update: to_time(this_update).ok_or(ListError::Validity)?,
            next_update: to_time(next_update).ok_or(ListError::Validity)?,
            crl_number: SerialNumber::from_slice(&number.to_be_bytes()),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let signer = Issuer::from_ca_cert_der(&self.certificate().into(), self.key())?;
        Ok(params.signed_by(&signer)?.der().to_vec())
    }
}

/// The key identifier of the certificate `der`, the SHA-256 of its public key,
/// which is what a list from that signer is kept under.
///
/// # Errors
///
/// [`ListError::Malformed`] when `der` is not a certificate.
pub fn certificate_key_id(der: &[u8]) -> Result<KeyId, ListError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| ListError::Malformed)?;
    Ok(KeyId::of_public_key(cert.public_key().raw))
}

/// Check that the CA certificate `signer` is one of `roots`, or is signed by one.
///
/// # Errors
///
/// [`ListError::Malformed`] when a certificate does not parse,
/// [`ListError::Untrusted`] when no root vouches for `signer`.
pub fn verify_signer(signer: &[u8], roots: &[Vec<u8>]) -> Result<(), ListError> {
    let (_, cert) = X509Certificate::from_der(signer).map_err(|_| ListError::Malformed)?;
    if roots.iter().any(|root| root.as_slice() == signer) {
        return Ok(());
    }
    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|constraints| constraints.value.ca);
    if !is_ca {
        return Err(ListError::Untrusted);
    }
    let vouched = roots.iter().any(|root| {
        X509Certificate::from_der(root)
            .is_ok_and(|(_, root)| cert.verify_signature(Some(root.public_key())).is_ok())
    });
    if vouched {
        Ok(())
    } else {
        Err(ListError::Untrusted)
    }
}

/// Check that `leaf` is signed by `issuer` and `issuer` by one of `roots`.
///
/// # Errors
///
/// As [`verify_signer`], and [`ListError::BadSignature`] when `issuer` did
/// not sign `leaf`.
pub fn verify_chain(leaf: &[u8], issuer: &[u8], roots: &[Vec<u8>]) -> Result<(), ListError> {
    verify_signer(issuer, roots)?;
    let (_, issuer) = X509Certificate::from_der(issuer).map_err(|_| ListError::Malformed)?;
    let (_, leaf) = X509Certificate::from_der(leaf).map_err(|_| ListError::Malformed)?;
    leaf.verify_signature(Some(issuer.public_key()))
        .map_err(|_| ListError::BadSignature)
}

impl RevocationList {
    /// Verify `list` as signed by the certificate `signer`, itself one of
    /// `roots` or signed by one. A root signs the lists that revoke issuers.
    ///
    /// # Errors
    ///
    /// [`ListError`] naming the first check that failed.
    pub fn verify(list: &[u8], signer: &[u8], roots: &[Vec<u8>]) -> Result<Self, ListError> {
        verify_signer(signer, roots)?;
        let (_, signer_cert) =
            X509Certificate::from_der(signer).map_err(|_| ListError::Malformed)?;
        let (rest, crl) =
            CertificateRevocationList::from_der(list).map_err(|_| ListError::Malformed)?;
        if !rest.is_empty() {
            return Err(ListError::Malformed);
        }
        crl.verify_signature(signer_cert.public_key())
            .map_err(|_| ListError::BadSignature)?;
        let digits = crl.crl_number().ok_or(ListError::NoNumber)?.to_u64_digits();
        let number = match digits.as_slice() {
            [] => 0,
            [number] => *number,
            _ => return Err(ListError::NoNumber),
        };
        let serials = crl
            .iter_revoked_certificates()
            .map(|revoked| revoked.raw_serial().to_vec())
            .collect();
        Ok(Self {
            issuer: KeyId::of_public_key(signer_cert.public_key().raw),
            number,
            serials,
            der: list.to_vec(),
        })
    }

    /// The key identifier of the list's signer.
    #[must_use]
    pub const fn issuer(&self) -> KeyId {
        self.issuer
    }

    /// The CRL Number, increasing per issuer.
    #[must_use]
    pub const fn number(&self) -> u64 {
        self.number
    }

    /// Whether the list revokes the certificate whose serial is `serial`.
    #[must_use]
    pub fn revokes(&self, serial: &[u8]) -> bool {
        self.serials
            .iter()
            .any(|listed| trim(listed) == trim(serial))
    }

    /// The list as signed.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }
}

/// A serial without the leading zero DER adds to keep a high bit positive.
fn trim(serial: &[u8]) -> &[u8] {
    let start = serial
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(serial.len());
    &serial[start..]
}
