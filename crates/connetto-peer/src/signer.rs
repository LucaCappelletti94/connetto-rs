//! The device key behind rustls's signer, for the handshake signatures.

use std::fmt;
use std::sync::Arc;

use connetto_core::device_cert::{DeviceKey, DeviceKeyError};
use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer};
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

/// The DER prefix of a P-256 `SubjectPublicKeyInfo` ahead of its 65-byte
/// point, the same prefix the core spells.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// A device key behind rustls's `SigningKey`.
pub(crate) struct DeviceSigner {
    key: Arc<dyn DeviceKey>,
}

impl DeviceSigner {
    /// Wrap the key a node presents or dials with.
    pub(crate) fn new(key: Arc<dyn DeviceKey>) -> Self {
        Self { key }
    }
}

impl fmt::Debug for DeviceSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceSigner").finish_non_exhaustive()
    }
}

impl SigningKey for DeviceSigner {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| {
                Box::new(DeviceKeySigner {
                    key: Arc::clone(&self.key),
                }) as Box<dyn Signer>
            })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        let mut spki = Vec::with_capacity(P256_SPKI_PREFIX.len() + self.key.public_point().len());
        spki.extend_from_slice(&P256_SPKI_PREFIX);
        spki.extend_from_slice(&self.key.public_point());
        Some(SubjectPublicKeyInfoDer::from(spki))
    }
}

/// One signature from the device key.
struct DeviceKeySigner {
    key: Arc<dyn DeviceKey>,
}

impl fmt::Debug for DeviceKeySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKeySigner").finish_non_exhaustive()
    }
}

impl Signer for DeviceKeySigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        // A chip sign may block, so a worker thread of a multi-threaded
        // runtime parks while it waits and cannot starve the runtime.
        let key = Arc::clone(&self.key);
        let sign = || key.sign(message).map_err(|err| sign_refused(&err));
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(sign)
            }
            _ => sign(),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// A `DeviceKeyError` as a TLS failure, the signing path has no finer error.
fn sign_refused(err: &DeviceKeyError) -> rustls::Error {
    rustls::Error::General(format!("the device key refused to sign, {err}"))
}

/// The identity a dial presents, resolved when the peer's schemes hold P-256.
pub(crate) struct IdentityClientCert {
    cert: Vec<CertificateDer<'static>>,
    key: Arc<dyn DeviceKey>,
}

impl IdentityClientCert {
    /// The certificates and the key they were signed with.
    pub(crate) fn new(cert: Vec<CertificateDer<'static>>, key: Arc<dyn DeviceKey>) -> Self {
        Self { cert, key }
    }
}

impl fmt::Debug for IdentityClientCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityClientCert").finish_non_exhaustive()
    }
}

impl rustls::client::ResolvesClientCert for IdentityClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if sigschemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256) {
            Some(Arc::new(rustls::sign::CertifiedKey::new(
                self.cert.clone(),
                Arc::new(DeviceSigner::new(Arc::clone(&self.key))),
            )))
        } else {
            None
        }
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The identity a node serves, resolved when the dialer's schemes hold P-256.
pub(crate) struct IdentityServerCert {
    cert: Vec<CertificateDer<'static>>,
    key: Arc<dyn DeviceKey>,
}

impl IdentityServerCert {
    /// The certificates and the key they were signed with.
    pub(crate) fn new(cert: Vec<CertificateDer<'static>>, key: Arc<dyn DeviceKey>) -> Self {
        Self { cert, key }
    }
}

impl fmt::Debug for IdentityServerCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityServerCert").finish_non_exhaustive()
    }
}

impl rustls::server::ResolvesServerCert for IdentityServerCert {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        client_hello
            .signature_schemes()
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| {
                Arc::new(rustls::sign::CertifiedKey::new(
                    self.cert.clone(),
                    Arc::new(DeviceSigner::new(Arc::clone(&self.key))),
                ))
            })
    }
}
