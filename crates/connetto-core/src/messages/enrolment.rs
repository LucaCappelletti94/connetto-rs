//! Device enrolment (R74): a signed-in native device asks for a nonce, then
//! sends a certificate request carrying it and receives its certificate.

use serde::{Deserialize, Serialize};

/// Client asks for a single-use nonce to put in its certificate request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolChallengeRequest {
    /// Client-chosen correlation token, echoed by the answer.
    pub request_id: String,
}

/// Server hands back a nonce bound to this session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolChallenge {
    /// Correlation token from the request this answers.
    pub request_id: String,
    /// The nonce the request must carry, usable once.
    pub nonce: [u8; 32],
    /// How long the nonce stays valid, relative so no clock has to agree.
    pub expires_in_ms: u64,
}

/// Client asks for a certificate, at first enrolment, on renewal, or to
/// reissue at another lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolRequest {
    /// Client-chosen correlation token, echoed by the answer.
    pub request_id: String,
    /// The DER PKCS #10 request the device key signed, carrying the nonce.
    #[serde(with = "serde_bytes")]
    pub csr: Vec<u8>,
    /// The lifetime the application asks for, the server's default when `None`.
    pub lifetime_secs: Option<u64>,
    /// The application's device descriptor, `MessagePack`, at most 4 KiB.
    #[serde(with = "serde_bytes")]
    pub descriptor: Vec<u8>,
}

/// Server hands back the device's certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolGrant {
    /// Correlation token from the request this answers.
    pub request_id: String,
    /// The DER chain, the device's certificate first, then its issuer.
    pub chain: Vec<serde_bytes::ByteBuf>,
    /// The DER revocation lists the device should hold.
    pub revocation_lists: Vec<serde_bytes::ByteBuf>,
}

/// Server refuses a challenge or an enrolment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolRefused {
    /// Correlation token from the request this answers.
    pub request_id: String,
    /// Why.
    pub reason: EnrolRefusal,
}

/// Why an enrolment was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrolRefusal {
    /// The session names no signed-in account.
    Unidentified,
    /// The server holds no device certificate issuer.
    IssuerUnavailable,
    /// No unused, unexpired nonce matches the request.
    ChallengeExpired,
    /// The request is malformed, its key is not P-256, or its descriptor is too large.
    InvalidRequest,
    /// The requested lifetime is over the server's ceiling, never shortened.
    OverCeiling {
        /// The longest lifetime the server grants.
        ceiling_secs: u64,
    },
    /// The device key's enrolment was revoked.
    Revoked,
}
