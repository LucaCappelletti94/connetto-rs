//! Why a link closed, why a chain was refused, why a dial failed.

use connetto_core::device_cert::AttestationLevel;
use rustls::AlertDescription;
use serde::{Deserialize, Serialize};

/// Why a link closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseReason {
    /// The peer or this node closed the link.
    Closed,
    /// A frame broke the protocol.
    Protocol,
    /// The peer went silent past the bound.
    PeerLost,
    /// The duplicate rule closed the later of two links to one peer.
    Duplicate,
    /// A kept list revoked the peer's chain.
    PeerRevoked,
    /// The peer's certificate passed its expiry plus the tolerance.
    PeerExpired,
    /// The peer speaks a different frame version.
    UnsupportedVersion,
    /// The peer's chain is outside its validity window.
    CertificateExpired,
    /// The node's clock stands outside the window its peer allows.
    ClockOutsideWindow,
    /// The node withdrew the certificate from service.
    Withdrawn,
    /// The node's key or certificate was revoked.
    Revoked,
}

/// A typed refusal of a peer's chain, carried over the TLS alert as its own
/// error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The chain reaches a root this node does not trust.
    #[error("the peer's chain reaches an untrusted root")]
    Untrusted,
    /// A kept list revokes the chain.
    #[error("the peer's chain is revoked")]
    Revoked,
    /// The chain is past its validity window.
    #[error("the peer's chain is expired")]
    Expired,
    /// The chain is not yet inside its validity window.
    #[error("the peer's chain is not yet valid")]
    NotYetValid,
    /// The certificate does not fit the device profile.
    #[error("the peer's certificate does not fit the device profile")]
    Profile,
    /// The peer's attestation level is not in the accepted set.
    #[error("the peer's attestation level is not accepted")]
    AttestationRefused(AttestationLevel),
    /// The peer presents this node's own key.
    #[error("the peer presents this node's own key")]
    OwnKey,
}

/// Why a dial failed.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// The node holds no identity to present.
    #[error("the node holds no identity to present")]
    NotServing,
    /// The loopback connect failed.
    #[error("the peer is unreachable")]
    Unreachable(#[source] std::io::Error),
    /// A connect, handshake, or hello ran out of its bound.
    #[error("the peer took too long to answer")]
    Timeout,
    /// The node's own verifier refused the peer's chain, with the reason.
    #[error("the verifier refused the peer")]
    Refused(Refusal),
    /// The peer's TLS alert refused the dial.
    #[error("the peer refused the dial")]
    RefusedByPeer(AlertDescription),
    /// The peer speaks a different frame version.
    #[error("the peer speaks protocol version {their}")]
    UnsupportedVersion {
        /// The version the peer offered.
        their: u16,
    },
    /// A frame broke the protocol.
    #[error("the peer broke the frame protocol")]
    Protocol(String),
    /// A TLS failure without a typed reason.
    #[error("tls failed")]
    Tls(#[source] rustls::Error),
}
