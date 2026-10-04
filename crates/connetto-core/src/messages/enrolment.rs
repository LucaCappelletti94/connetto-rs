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
    /// The application's device descriptor, `MessagePack`, at most 4096 bytes.
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
    /// The revocation lists the device should hold.
    pub revocation_lists: Vec<SignedList>,
}

/// A revocation list and the certificate that signed it, a device issuer or,
/// for a list revoking issuers, the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedList {
    /// The DER list.
    #[serde(with = "serde_bytes")]
    pub list: Vec<u8>,
    /// The DER certificate of its signer.
    #[serde(with = "serde_bytes")]
    pub signer: Vec<u8>,
}

/// Server hands a device the current revocation lists, after every
/// handshake and whenever a list changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationUpdate {
    /// One list per issuer.
    pub lists: Vec<SignedList>,
}

/// Client asks for its account's devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicesRequest {
    /// Client-chosen correlation token, echoed by the answer.
    pub request_id: String,
}

/// One enrolled device of the caller's account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSummary {
    /// The device key's identifier, the SHA-256 of its public key.
    pub key_id: [u8; 32],
    /// When the key first enrolled, in seconds since the Unix epoch.
    pub enrolled_at_secs: u64,
    /// When the key last enrolled or renewed, in seconds since the Unix epoch.
    pub last_seen_secs: u64,
    /// When the key was revoked, in seconds since the Unix epoch.
    pub revoked_at_secs: Option<u64>,
    /// The application's descriptor as the device last sent it, `MessagePack`.
    #[serde(with = "serde_bytes")]
    pub descriptor: Vec<u8>,
}

/// Server answers with the caller's devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicesList {
    /// Correlation token from the request this answers.
    pub request_id: String,
    /// The account's devices, revoked ones included until they are purged.
    pub devices: Vec<DeviceSummary>,
}

/// Client reports one of its account's devices lost.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeDeviceRequest {
    /// Client-chosen correlation token, echoed by the answer.
    pub request_id: String,
    /// The device key to revoke.
    pub key_id: [u8; 32],
}

/// Server confirms a device is revoked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRevokedAck {
    /// Correlation token from the request this answers.
    pub request_id: String,
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
