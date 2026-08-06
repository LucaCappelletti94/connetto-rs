//! Non-fatal, rate-limit and fatal server error frames.
//!
//! Non-fatal errors and rate-limit refusals are correlated with a specific
//! client request via `related_to`. The session keeps running. Fatal errors
//! terminate the session immediately after being sent. The client must
//! reconnect (fresh handshake).

use serde::{Deserialize, Serialize};

/// The one detail text a refused subscription carries.
///
/// Every refusal on the subscribe path reads exactly like this, whatever the
/// cause. A detail that varied would tell the caller which stage refused, and
/// so whether the table or column it guessed exists. The cause goes to the
/// structured log instead.
pub const SUBSCRIPTION_REFUSED: &str = "subscription refused";

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

/// The caller asked for something too often, and this one is refused.
///
/// Distinct from [`NonFatalError`] on purpose, and typed rather than a detail
/// string a client would parse. A caller that is over a limit must be able to
/// tell "retry later" from "this will never work", because a client reconnects
/// by re-declaring every subscription at once and can trip a limit while
/// perfectly well behaved. Saying so discloses nothing: a caller already knows
/// how fast it was asking.
///
/// This is not a refusal of what was named, so it never merges with
/// [`SUBSCRIPTION_REFUSED`], which stays byte-identical across causes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimited {
    /// Identifier of the request this refusal refers to, the `sub_id` of a
    /// refused `Subscribe`. Absent when the refusal belongs to no single
    /// request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_to: Option<String>,
    /// How long until the limit's window rolls over, so a client waits once
    /// rather than probing for the answer.
    pub retry_after_ms: u64,
}

/// Reason the server is closing the session.
///
/// Every variant names a specific close the server performs. There is no
/// catch-all: a reason no code path can produce is a branch a client writes
/// and never reaches.
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
    /// Session was administratively revoked mid-connection.
    SessionRevoked,
    /// A newer connection presented this session's durable handle, so this
    /// older connection is closed. One live connection per session handle,
    /// because the handle keys the per-subscription cursors and the pending
    /// buffer, and two readers would each consume the other's changes.
    ConnectionSuperseded,
    /// Client sent a control frame the server could not parse.
    ProtocolViolation {
        /// Human-readable detail.
        detail: String,
    },
    /// Server is shutting down and cannot service the session.
    ServerShuttingDown,
    /// The caller opened connections or presented credentials faster than the
    /// configured limit, so this one is closed rather than served.
    RateLimited {
        /// How long until the limit's window rolls over.
        retry_after_ms: u64,
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
