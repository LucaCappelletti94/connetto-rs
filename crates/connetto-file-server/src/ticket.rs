//! Upload and download tickets: Ed25519-signed compact tokens.
//!
//! Token format: `{payload_b64}.{sig_b64}` where both components are
//! URL-safe base64 (no padding) and `payload_b64` is a postcard-serialized
//! [`TicketPayload`].

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use postcard;
use ring::{
    rand::SystemRandom,
    signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// What the ticket authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verb {
    /// Read (download) the named file.
    Read,
    /// Write (upload) the named file, up to `ceiling` bytes.
    Write,
}

/// The signed, compact payload carried by every ticket token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketPayload {
    /// 32-byte BLAKE3 identity of the file this ticket authorizes.
    pub file_id: [u8; 32],
    /// Authorized operation.
    pub verb: Verb,
    /// Bytes one response may serve under [`Verb::Read`], per response rather than per ticket.
    pub ceiling: u64,
    /// Unix timestamp (seconds) after which the ticket is expired.
    pub expiry: i64,
    /// Caller identity carried for attribution.
    pub caller: String,
}

/// Error produced by ticket operations.
#[derive(Debug, Error)]
pub enum TicketError {
    /// Postcard serialization or deserialization failed.
    #[error("payload serialization: {0}")]
    Postcard(#[from] postcard::Error),
    /// Base64 decoding failed.
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// Malformed token string (missing dot separator).
    #[error("malformed token")]
    Malformed,
    /// Ed25519 signature did not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// Token has passed its expiry time.
    #[error("ticket expired")]
    Expired,
    /// Token authorizes a different verb than requested.
    #[error("wrong verb")]
    WrongVerb,
    /// Ring key-generation error.
    #[error("key generation: {0}")]
    Ring(String),
}

/// Holds the Ed25519 private key and mints ticket tokens.
pub struct TicketSigner {
    key_pair: Ed25519KeyPair,
}

impl TicketSigner {
    /// Generates a fresh keypair.  Returns the signer plus the raw public-key
    /// bytes needed to construct the matching [`TicketVerifier`].
    pub fn generate() -> Result<(Self, Vec<u8>), TicketError> {
        let rng = SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| TicketError::Ring(format!("{e:?}")))?;
        let kp = Ed25519KeyPair::from_pkcs8(doc.as_ref())
            .map_err(|e| TicketError::Ring(format!("{e:?}")))?;
        let public = kp.public_key().as_ref().to_vec();
        Ok((Self { key_pair: kp }, public))
    }

    /// Loads from a PKCS8 DER document.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, TicketError> {
        let kp =
            Ed25519KeyPair::from_pkcs8(der).map_err(|e| TicketError::Ring(format!("{e:?}")))?;
        Ok(Self { key_pair: kp })
    }

    /// Returns the raw public-key bytes for constructing a [`TicketVerifier`].
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Mints a signed token for `payload`.
    pub fn mint(&self, payload: &TicketPayload) -> Result<String, TicketError> {
        let payload_bytes = postcard::to_allocvec(payload)?;
        let sig = self.key_pair.sign(&payload_bytes);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
        Ok(format!("{payload_b64}.{sig_b64}"))
    }
}

/// Holds the Ed25519 public key and verifies ticket tokens.
#[derive(Clone)]
pub struct TicketVerifier {
    public_key: Vec<u8>,
}

impl TicketVerifier {
    /// Constructs from raw public-key bytes produced by [`TicketSigner::generate`]
    /// or [`TicketSigner::public_key_bytes`].
    pub fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }

    /// Verifies `token` and returns the payload if the signature is valid and
    /// the token is not expired.
    pub fn verify(&self, token: &str) -> Result<TicketPayload, TicketError> {
        let dot = token.rfind('.').ok_or(TicketError::Malformed)?;
        let payload_b64 = &token[..dot];
        let sig_b64 = &token[dot + 1..];
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64)?;
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)?;
        UnparsedPublicKey::new(&ED25519, &self.public_key)
            .verify(&payload_bytes, &sig_bytes)
            .map_err(|_| TicketError::InvalidSignature)?;
        let payload: TicketPayload = postcard::from_bytes(&payload_bytes)?;
        let now = chrono::Utc::now().timestamp();
        if payload.expiry < now {
            return Err(TicketError::Expired);
        }
        Ok(payload)
    }

    /// Verifies the token and additionally asserts it authorizes `expected_verb`.
    /// Returns the payload on success.
    pub fn verify_verb(
        &self,
        token: &str,
        expected_verb: Verb,
    ) -> Result<TicketPayload, TicketError> {
        let payload = self.verify(token)?;
        if payload.verb != expected_verb {
            return Err(TicketError::WrongVerb);
        }
        Ok(payload)
    }
}
