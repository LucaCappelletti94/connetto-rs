use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    SanType, SerialNumber, SubjectPublicKeyInfo,
};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use super::attestation::{ATTESTATION_EXTENSION, AttestationLevel};
use super::identity::{DeploymentId, DeviceIdentity, KeyId};
use super::request::CertificateRequest;

/// X.520 `serialNumber` (2.5.4.5), which keeps sibling issuers' subjects apart, since
/// revocation lists are matched to a certificate by its issuer's name.
const SERIAL_NUMBER_ATTRIBUTE: [u64; 4] = [2, 5, 4, 5];

/// The deployment's root, kept offline and used only by `connetto-ca`.
pub struct RootCa {
    certificate: Vec<u8>,
    key: KeyPair,
}

/// Why a root could not be created or read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootError {
    /// The certificate does not parse.
    #[error("the root certificate does not parse")]
    Malformed,
    /// The subject's common name is not one canonical deployment UUID.
    #[error("the root does not name its deployment")]
    NoDeployment,
    /// The validity does not fit an X.509 time.
    #[error("the validity is outside what a certificate can carry")]
    Validity,
    /// The private key is not the key the root certificate certifies.
    #[error("the key does not match the root certificate")]
    KeyMismatch,
    /// The certificate library refused the key or the parameters.
    #[error("the certificate could not be signed")]
    Sign(#[from] rcgen::Error),
}

impl RootCa {
    /// Create a root for `deployment`, valid from `not_before` for `valid_for`.
    ///
    /// # Errors
    ///
    /// [`RootError`] when the times do not fit a certificate or signing fails.
    pub fn create(
        deployment: DeploymentId,
        not_before: SystemTime,
        valid_for: Duration,
    ) -> Result<Self, RootError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, deployment.to_string());
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = to_time(not_before).ok_or(RootError::Validity)?;
        params.not_after = to_time(not_before + valid_for).ok_or(RootError::Validity)?;
        let certificate = params.self_signed(&key)?.der().to_vec();
        Ok(Self { certificate, key })
    }

    /// Reload a root `connetto-ca` stored, checking it names a deployment and
    /// that `key` is its key.
    ///
    /// # Errors
    ///
    /// [`RootError::Malformed`], [`RootError::NoDeployment`] or
    /// [`RootError::KeyMismatch`].
    pub fn from_parts(certificate: Vec<u8>, key: KeyPair) -> Result<Self, RootError> {
        deployment_of_root(&certificate)?;
        let (_, cert) =
            X509Certificate::from_der(&certificate).map_err(|_| RootError::Malformed)?;
        if cert.public_key().raw != rcgen::PublicKeyData::subject_public_key_info(&key) {
            return Err(RootError::KeyMismatch);
        }
        Ok(Self { certificate, key })
    }

    /// The root's DER certificate, the one applications are built with.
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// The root's signing key.
    pub(super) const fn key(&self) -> &KeyPair {
        &self.key
    }

    /// The root's private key as PKCS #8 DER, for `connetto-ca` to encrypt and store.
    #[must_use]
    pub fn private_key_der(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(self.key.serialize_der())
    }

    /// Sign an issuer for the key whose DER `SubjectPublicKeyInfo` is `issuer_key`.
    ///
    /// # Errors
    ///
    /// [`RootError`] when the key or the times do not fit, or signing fails.
    pub fn sign_issuer(
        &self,
        issuer_key: &[u8],
        not_before: SystemTime,
        valid_for: Duration,
        serial: [u8; 16],
    ) -> Result<Vec<u8>, RootError> {
        let public = SubjectPublicKeyInfo::from_der(issuer_key)?;
        let signer = Issuer::from_ca_cert_der(&self.certificate.as_slice().into(), &self.key)?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "connetto device issuer");
        let mut serial_hex = String::with_capacity(serial.len() * 2);
        for byte in serial {
            use std::fmt::Write as _;
            let _ = write!(serial_hex, "{byte:02x}");
        }
        params.distinguished_name.push(
            DnType::CustomDnType(SERIAL_NUMBER_ATTRIBUTE.to_vec()),
            DnValue::PrintableString(serial_hex.as_str().try_into()?),
        );
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = to_time(not_before).ok_or(RootError::Validity)?;
        params.not_after = to_time(not_before + valid_for).ok_or(RootError::Validity)?;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        Ok(params.signed_by(&public, &signer)?.der().to_vec())
    }
}

/// The deployment a root certificate names in its subject's common name.
///
/// # Errors
///
/// [`RootError::Malformed`] or [`RootError::NoDeployment`].
pub fn deployment_of_root(root: &[u8]) -> Result<DeploymentId, RootError> {
    let (_, cert) = X509Certificate::from_der(root).map_err(|_| RootError::Malformed)?;
    let mut names = cert.subject().iter_common_name();
    let (Some(name), None) = (names.next(), names.next()) else {
        return Err(RootError::NoDeployment);
    };
    name.as_str()
        .ok()
        .and_then(DeploymentId::from_canonical)
        .ok_or(RootError::NoDeployment)
}

/// The server's issuer, which signs device certificates.
pub struct DeviceIssuer {
    certificate: Vec<u8>,
    key: KeyPair,
    key_id: KeyId,
    deployment: DeploymentId,
    not_after: SystemTime,
}

/// Why an issuer could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssuerError {
    /// The root is unreadable or names no deployment.
    #[error(transparent)]
    Root(#[from] RootError),
    /// The issuer certificate does not parse.
    #[error("the issuer certificate does not parse")]
    Malformed,
    /// The issuer certificate's signature does not verify under the root's key.
    #[error("the root did not sign this issuer")]
    NotSignedByRoot,
    /// The issuer certificate is not a CA certificate allowed to sign certificates.
    #[error("the issuer certificate may not sign certificates")]
    NotAnIssuer,
    /// The private key is not the key the issuer certificate certifies.
    #[error("the key does not match the issuer certificate")]
    KeyMismatch,
    /// The stored key is not a P-256 PKCS #8 key.
    #[error("the issuer key is not a P-256 PKCS #8 key")]
    Key(#[source] rcgen::Error),
}

/// Why a device certificate was not issued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssueError {
    /// The account cannot appear in the identity URI.
    #[error(transparent)]
    Identity(#[from] super::identity::IdentityError),
    /// The certificate would expire after the issuer, so its chain would stop verifying first.
    #[error("the certificate would outlive its issuer")]
    OutlivesIssuer,
    /// The validity does not fit an X.509 time.
    #[error("the validity is outside what a certificate can carry")]
    Validity,
    /// The certificate library refused the key or the parameters.
    #[error("the certificate could not be signed")]
    Sign(#[from] rcgen::Error),
}

impl DeviceIssuer {
    /// Load an issuer, checking that `root` signed it and that `key` is its key.
    ///
    /// # Errors
    ///
    /// [`IssuerError`] naming the first check that failed.
    pub fn new(certificate: Vec<u8>, key: KeyPair, root: &[u8]) -> Result<Self, IssuerError> {
        let deployment = deployment_of_root(root)?;
        let (_, root_cert) = X509Certificate::from_der(root).map_err(|_| RootError::Malformed)?;
        let (_, cert) =
            X509Certificate::from_der(&certificate).map_err(|_| IssuerError::Malformed)?;
        cert.verify_signature(Some(root_cert.public_key()))
            .map_err(|_| IssuerError::NotSignedByRoot)?;
        let may_issue = cert
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|constraints| constraints.value.ca)
            && cert
                .key_usage()
                .ok()
                .flatten()
                .is_some_and(|usage| usage.value.key_cert_sign());
        if !may_issue {
            return Err(IssuerError::NotAnIssuer);
        }
        if cert.public_key().raw != rcgen::PublicKeyData::subject_public_key_info(&key) {
            return Err(IssuerError::KeyMismatch);
        }
        let not_after = UNIX_EPOCH
            + Duration::from_secs(
                u64::try_from(cert.validity().not_after.timestamp())
                    .map_err(|_| IssuerError::Malformed)?,
            );
        let key_id = KeyId::of_public_key(cert.public_key().raw);
        Ok(Self {
            certificate,
            key,
            key_id,
            deployment,
            not_after,
        })
    }

    /// Load an issuer whose key is stored as PKCS #8 DER, with the checks of [`Self::new`].
    ///
    /// # Errors
    ///
    /// [`IssuerError::Key`] when `key` is not a P-256 PKCS #8 key, else as [`Self::new`].
    pub fn from_pkcs8(certificate: Vec<u8>, key: &[u8], root: &[u8]) -> Result<Self, IssuerError> {
        let key = KeyPair::try_from(key).map_err(IssuerError::Key)?;
        Self::new(certificate, key, root)
    }

    /// The issuer's DER certificate, sent with every grant as the chain's middle link.
    #[must_use]
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// The key identifier its lists are kept under, the SHA-256 of its key.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The issuer's signing key.
    pub(super) const fn key(&self) -> &KeyPair {
        &self.key
    }

    /// The deployment the issuer's root names.
    #[must_use]
    pub const fn deployment(&self) -> DeploymentId {
        self.deployment
    }

    /// When the issuer's own certificate expires, after which it issues nothing.
    #[must_use]
    pub const fn not_after(&self) -> SystemTime {
        self.not_after
    }

    /// Issue the device certificate for `request`, naming `account`, valid from
    /// `not_before` for `lifetime`, recording `attestation`.
    ///
    /// # Errors
    ///
    /// [`IssueError`] when the account cannot be named, the certificate would
    /// outlive the issuer, or signing fails.
    pub fn issue(
        &self,
        request: &CertificateRequest,
        account: &str,
        not_before: SystemTime,
        lifetime: Duration,
        serial: [u8; 16],
        attestation: AttestationLevel,
    ) -> Result<Vec<u8>, IssueError> {
        let identity = DeviceIdentity::new(
            self.deployment,
            account,
            KeyId::of_public_key(request.public_key()),
        )?;
        let not_after = not_before + lifetime;
        if not_after > self.not_after {
            return Err(IssueError::OutlivesIssuer);
        }
        let public = SubjectPublicKeyInfo::from_der(request.public_key())?;
        let signer = Issuer::from_ca_cert_der(&self.certificate.as_slice().into(), &self.key)?;
        let uri = identity.uri().try_into()?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.subject_alt_names = vec![SanType::URI(uri)];
        params.not_before = to_time(not_before).ok_or(IssueError::Validity)?;
        params.not_after = to_time(not_after).ok_or(IssueError::Validity)?;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        params.custom_extensions = vec![CustomExtension::from_oid_content(
            ATTESTATION_EXTENSION,
            attestation.extension_value(),
        )];
        Ok(params.signed_by(&public, &signer)?.der().to_vec())
    }
}

/// `at` truncated to whole seconds, the precision X.509 times carry.
pub(super) fn to_time(at: SystemTime) -> Option<OffsetDateTime> {
    let secs = at.duration_since(UNIX_EPOCH).ok()?.as_secs();
    OffsetDateTime::from_unix_timestamp(i64::try_from(secs).ok()?).ok()
}
