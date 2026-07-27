//! Non-fatal and fatal server error frames.
//!
//! Non-fatal errors are correlated with a specific client request via
//! `related_to`. The session keeps running. Fatal errors terminate the session
//! immediately after being sent. The client must reconnect (fresh handshake).

use serde::{Deserialize, Serialize};

/// Non-fatal error attached to a specific client request.
///
/// The server keeps the session alive after sending this. Typical uses:
/// rejecting a `Subscribe` for a malformed query, reporting a transient auth
/// outage that resolved before delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonFatalError {
    /// Identifier of the request or subscription this error refers to. May be
    /// the `sub_id` from a `Subscribe`, a mutation `client_seq` rendered as a
    /// string, or any other client-chosen correlation token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_to: Option<String>,
    /// Human-readable detail.
    pub detail: String,
}

/// Reason the server is closing the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FatalErrorReason {
    /// Wire protocol mismatch. `expected` is the server's `PROTOCOL_VERSION`.
    /// `got` is what the client declared in its handshake.
    ProtocolVersionMismatch {
        /// Server's supported version.
        expected: u32,
        /// Version declared by the client.
        got: u32,
    },
    /// Authentication failed at the handshake: the presented `auth_token` was
    /// absent, failed verification, or names a session that is no longer live.
    /// The client routes to re-login rather than a generic reconnect.
    AuthenticationFailed,
    /// Session was administratively revoked mid-connection.
    SessionRevoked,
    /// Client sent a control frame the server could not parse.
    ProtocolViolation {
        /// Human-readable detail.
        detail: String,
    },
    /// Server is shutting down and cannot service the session.
    ServerShuttingDown,
    /// Everything else. Prefer a specific variant when possible.
    Other {
        /// Human-readable detail.
        detail: String,
    },
}

/// Session-terminating error frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatalError {
    /// Why the session is being closed.
    pub reason: FatalErrorReason,
}

impl FatalError {
    /// Build a fatal error with a specific reason.
    pub fn new(reason: FatalErrorReason) -> Self {
        Self { reason }
    }
}
