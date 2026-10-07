//! The chain verifier for both ends of the link, behind the wall clock.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::device_cert::{AttestationLevel, DeviceCertificate, KeyId};
use parking_lot::RwLock;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use rustls::server::danger::ClientCertVerified;
use rustls::{DistinguishedName, Error, SignatureScheme};

use crate::error::Refusal;
use crate::identity::{Clock, Trust};

/// A kept CRL, owned, so a snapshot is a cheap `Arc` clone.
pub(crate) type Crl = webpki::CertRevocationList<'static>;
/// The tolerance a wall clock gets against the certificate windows, five
/// minutes either way.
const TOLERANCE: Duration = Duration::from_secs(300);

/// A kept revocation list, beside what a verifier and a forward need.
#[derive(Clone)]
pub(crate) struct KeptList {
    /// The issuer the list signs for.
    pub(crate) issuer: KeyId,
    /// The list's number.
    pub(crate) number: u64,
    /// The list, DER.
    pub(crate) der: Vec<u8>,
    /// The signer's certificate, DER.
    pub(crate) signer: Vec<u8>,
    /// The list's verified content.
    pub(crate) parsed: connetto_core::device_cert::RevocationList,
    /// The list as a CRL, for the verifier.
    pub(crate) crl: Option<webpki::OwnedCertRevocationList>,
}

/// The verifier for the server's chain and the client's chain alike.
#[derive(Clone)]
pub(crate) struct PeerVerifier {
    accepted: Vec<AttestationLevel>,
    clock: Arc<dyn Clock>,
    algs: WebPkiSupportedAlgorithms,
    /// The trust anchors, owned, built once and shared by a cheap clone.
    anchors: Vec<TrustAnchor<'static>>,
    own_key: Arc<RwLock<Option<KeyId>>>,
    /// The parsed CRLs, a snapshot swapped by `keep_list` so a handshake
    /// clones an `Arc` and borrows.
    crls: Arc<RwLock<Arc<[Crl]>>>,
}

impl fmt::Debug for PeerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerVerifier").finish_non_exhaustive()
    }
}

impl PeerVerifier {
    /// Build the verifier for `trust`, behind `clock`, with its key, list
    /// and CRL state shared through the locks the node updates.
    pub(crate) fn new(
        trust: &Trust,
        clock: Arc<dyn Clock>,
        own_key: Arc<RwLock<Option<KeyId>>>,
        crls: Arc<RwLock<Arc<[Crl]>>>,
    ) -> Self {
        let anchors: Vec<TrustAnchor<'static>> = trust
            .roots
            .iter()
            .filter_map(|root| {
                let der = CertificateDer::from(root.clone());
                webpki::anchor_from_trusted_cert(&der)
                    .ok()
                    .map(|anchor| anchor.to_owned())
            })
            .collect();
        Self {
            anchors,
            accepted: trust.accepted.clone(),
            clock,
            algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
            own_key,
            crls,
        }
    }

    /// The clock the verifier reads, for the configs the node builds.
    pub(crate) fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// Verify `end_entity` through `intermediates` to a shipped root, at the
    /// clock's time inside the tolerance, against the kept lists, the
    /// accepted levels, and this node's own key.
    pub(crate) fn verify_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        usage: webpki::KeyUsage,
    ) -> Result<DeviceCertificate, Refusal> {
        let Ok(leaf) = webpki::EndEntityCert::try_from(end_entity) else {
            return Err(Refusal::Profile);
        };
        let anchors = &self.anchors;
        // A cheap `Arc` clone of the kept CRLs, borrowed rather than cloned.
        let crls = self.crls.read().clone();
        let refs: Vec<&Crl> = crls.iter().collect();
        let revocation: Option<webpki::RevocationOptions<'_>> = if refs.is_empty() {
            None
        } else {
            Some(
                webpki::RevocationOptionsBuilder::new(&refs)
                    .expect("at least one list is present")
                    .with_depth(webpki::RevocationCheckDepth::Chain)
                    .with_status_policy(webpki::UnknownStatusPolicy::Allow)
                    .with_expiration_policy(webpki::ExpirationPolicy::Ignore)
                    .build(),
            )
        };

        // The wall clock first, then the window's edges, so a small skew
        // links while a real expiry refuses.
        let now = self.clock.now();
        let attempts = [now, now - TOLERANCE, now + TOLERANCE];
        let mut first: Option<webpki::Error> = None;
        let mut fatal: Option<webpki::Error> = None;
        for attempt in attempts {
            let time = UnixTime::since_unix_epoch(
                attempt
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .expect("the clock stands after the epoch"),
            );
            match leaf.verify_for_usage(
                self.algs.all,
                anchors,
                intermediates,
                time,
                usage,
                revocation,
                None,
            ) {
                Ok(_path) => {
                    let Ok(certificate) = DeviceCertificate::parse(end_entity.as_ref()) else {
                        return Err(Refusal::Profile);
                    };
                    if !self.accepted.contains(&certificate.attestation()) {
                        return Err(Refusal::AttestationRefused(certificate.attestation()));
                    }
                    let own = self.own_key.read();
                    if own
                        .as_ref()
                        .is_some_and(|key| *key == certificate.identity().key())
                    {
                        return Err(Refusal::OwnKey);
                    }
                    return Ok(certificate);
                }
                Err(err) => {
                    let validity_only = matches!(
                        err,
                        webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. }
                    );
                    if first.is_none() {
                        first = Some(err.clone());
                    }
                    if !validity_only {
                        fatal = Some(err);
                        break;
                    }
                }
            }
        }
        Err(classify(
            &fatal.or(first).expect("every attempt records its error"),
        ))
    }
}

/// A webpki failure as the typed refusal it names.
fn classify(err: &webpki::Error) -> Refusal {
    match err {
        webpki::Error::UnknownIssuer => Refusal::Untrusted,
        webpki::Error::CertRevoked => Refusal::Revoked,
        webpki::Error::CertExpired { .. } => Refusal::Expired,
        webpki::Error::CertNotValidYet { .. } => Refusal::NotYetValid,
        _ => Refusal::Profile,
    }
}

/// A verifier failure as the TLS error the peer's alert or the dialer's
/// downcast carries.
pub(crate) fn refusal_error(refusal: Refusal) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
        Arc::new(refusal),
    )))
}

impl rustls::client::danger::ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.verify_chain(end_entity, intermediates, webpki::KeyUsage::server_auth())
            .map(|_| ServerCertVerified::assertion())
            .map_err(refusal_error)
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(rustls::Error::General(
            "the link speaks only TLS 1.3".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

impl rustls::server::danger::ClientCertVerifier for PeerVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verify_chain(end_entity, intermediates, webpki::KeyUsage::client_auth())
            .map(|_| ClientCertVerified::assertion())
            .map_err(refusal_error)
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(rustls::Error::General(
            "the link speaks only TLS 1.3".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}
