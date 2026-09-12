//! Upload and download tickets: Ed25519-signed compact tokens.
//!
//! Token format: `{payload_b64}.{sig_b64}` where both components are
//! URL-safe base64 (no padding) and `payload_b64` is a postcard-serialized
//! [`TicketPayload`].

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connetto_core::messages::ContentVerb;
use connetto_core::traits::ContentTicketSigner;
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
    /// The base URL is neither HTTPS nor plain HTTP on a loopback host.
    ///
    /// Accepted schemes and hosts: `https` with any host, or `http` with
    /// `localhost`, `127.0.0.1`, or `[::1]`.
    #[error("base URL is not HTTPS or loopback: {base}")]
    InsecureBase {
        /// The rejected base URL.
        base: String,
    },
}

/// Holds the Ed25519 private key and mints ticket tokens.
///
/// `base_url` is the scheme-and-authority prefix the file server answers on,
/// without a trailing slash (for example `https://files.example.com`). It is
/// embedded in every URL returned by [`ContentTicketSigner::mint`].
///
/// `read_ceiling` is the byte cap placed on every read ticket minted through
/// the trait. The file server refuses a response whose byte count exceeds the
/// ticket's ceiling, so this value bounds what one read ticket can serve.
/// Deployments set it to the largest single-response download they permit.
pub struct TicketSigner {
    key_pair: Ed25519KeyPair,
    base_url: String,
    ticket_ttl: Duration,
    read_ceiling: u64,
}

/// Returns `Ok(())` when `base_url` is safe to mint tickets against.
///
/// # Errors
///
/// Returns `TicketError::InsecureBase` when the scheme is `http` and the host
/// is not `localhost`, `127.0.0.1`, or `[::1]`.
fn validate_base(base_url: &str) -> Result<(), TicketError> {
    let after_scheme = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"));
    let is_http = base_url.starts_with("http://");
    let loopback = match after_scheme {
        Some(rest) => {
            let authority = rest.split('/').next().unwrap_or(rest);
            let host = match authority.strip_prefix('[') {
                // A bracketed IPv6 host holds colons of its own, so the port is whatever
                // follows the closing bracket.
                Some(inside) => inside.split(']').next().unwrap_or(inside),
                None => authority.split(':').next().unwrap_or(authority),
            };
            matches!(host, "localhost" | "127.0.0.1" | "::1")
        }
        None => false,
    };
    if after_scheme.is_some() && (!is_http || loopback) {
        Ok(())
    } else {
        Err(TicketError::InsecureBase {
            base: base_url.to_owned(),
        })
    }
}

impl TicketSigner {
    /// Generates a fresh keypair.
    ///
    /// Returns the signer plus the raw public-key bytes needed to construct the
    /// matching [`TicketVerifier`].  `base_url` is the file server's base address
    /// without a trailing slash; `ticket_ttl` is how long each minted ticket
    /// remains valid; `read_ceiling` is the byte cap on every read ticket.
    ///
    /// # Errors
    ///
    /// Returns `TicketError::InsecureBase` if `base_url` is not HTTPS or loopback HTTP.
    /// Returns `TicketError::Ring` if key generation fails or if the ring library rejects the generated PKCS8 document.
    pub fn generate(
        base_url: String,
        ticket_ttl: Duration,
        read_ceiling: u64,
    ) -> Result<(Self, Vec<u8>), TicketError> {
        validate_base(&base_url)?;
        let rng = SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| TicketError::Ring(format!("{e:?}")))?;
        let kp = Ed25519KeyPair::from_pkcs8(doc.as_ref())
            .map_err(|e| TicketError::Ring(format!("{e:?}")))?;
        let public = kp.public_key().as_ref().to_vec();
        Ok((
            Self {
                key_pair: kp,
                base_url,
                ticket_ttl,
                read_ceiling,
            },
            public,
        ))
    }

    /// Loads from a PKCS8 DER document.
    ///
    /// `base_url`, `ticket_ttl`, and `read_ceiling` carry the same meaning as
    /// in [`Self::generate`].
    ///
    /// # Errors
    ///
    /// Returns `TicketError::InsecureBase` if `base_url` is not HTTPS or loopback HTTP.
    /// Returns `TicketError::Ring` if `der` is not a valid PKCS8 document for an Ed25519 key pair.
    pub fn from_pkcs8_der(
        der: &[u8],
        base_url: String,
        ticket_ttl: Duration,
        read_ceiling: u64,
    ) -> Result<Self, TicketError> {
        validate_base(&base_url)?;
        let kp =
            Ed25519KeyPair::from_pkcs8(der).map_err(|e| TicketError::Ring(format!("{e:?}")))?;
        Ok(Self {
            key_pair: kp,
            base_url,
            ticket_ttl,
            read_ceiling,
        })
    }

    /// Returns the raw public-key bytes for constructing a [`TicketVerifier`].
    pub fn public_key_bytes(&self) -> &[u8] {
        self.key_pair.public_key().as_ref()
    }

    /// Mints a signed token for `payload`.
    ///
    /// # Errors
    ///
    /// Returns `TicketError::Postcard` if the payload cannot be serialized.
    pub fn mint(&self, payload: &TicketPayload) -> Result<String, TicketError> {
        let payload_bytes = postcard::to_allocvec(payload)?;
        let sig = self.key_pair.sign(&payload_bytes);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
        Ok(format!("{payload_b64}.{sig_b64}"))
    }
}

impl ContentTicketSigner for TicketSigner {
    type Error = TicketError;

    fn mint(
        &self,
        caller: &str,
        file_id: [u8; 32],
        verb: ContentVerb,
    ) -> impl core::future::Future<Output = Result<String, Self::Error>> + Send {
        let result: Result<String, TicketError> = (|| {
            let ttl_secs = i64::try_from(self.ticket_ttl.as_secs())
                .map_err(|_| TicketError::Ring("ticket TTL exceeds i64 seconds".into()))?;
            let expiry = chrono::Utc::now()
                .timestamp()
                .checked_add(ttl_secs)
                .ok_or_else(|| TicketError::Ring("ticket expiry overflow".into()))?;
            let (local_verb, ceiling) = match verb {
                ContentVerb::Read => (Verb::Read, self.read_ceiling),
                ContentVerb::Write { declared_len } => (Verb::Write, declared_len),
            };
            let payload = TicketPayload {
                file_id,
                verb: local_verb,
                ceiling,
                expiry,
                caller: caller.into(),
            };
            let token = TicketSigner::mint(self, &payload)?;
            let hex_id = crate::hex_32(&file_id);
            let url = match verb {
                ContentVerb::Read => {
                    format!("{}/files/{}?t={}", self.base_url, hex_id, token)
                }
                ContentVerb::Write { .. } => {
                    format!("{}/files/{}/intent?t={}", self.base_url, hex_id, token)
                }
            };
            Ok(url)
        })();
        core::future::ready(result)
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
    ///
    /// # Errors
    ///
    /// Returns `TicketError::Malformed` if `token` does not contain a dot separator.
    /// Returns `TicketError::Base64` if the payload or signature segment is not valid URL-safe base64.
    /// Returns `TicketError::InvalidSignature` if the Ed25519 signature does not verify against the stored public key.
    /// Returns `TicketError::Postcard` if the payload bytes cannot be deserialized.
    /// Returns `TicketError::Expired` if the token's expiry timestamp is in the past.
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
    ///
    /// # Errors
    ///
    /// Returns all errors from [`Self::verify`].
    /// Returns `TicketError::WrongVerb` if the token's verb does not match `expected_verb`.
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
