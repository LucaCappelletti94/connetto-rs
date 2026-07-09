//! Keepalive and flow-control primitives.
//!
//! `Ping` and `Pong` carry a client-chosen nonce so responses can be matched
//! against outstanding probes. `AckCredits` replenishes the server's delivery
//! window per §02 "Flow Control".

use serde::{Deserialize, Serialize};

/// Client heartbeat probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ping {
    /// Client-chosen nonce echoed by the server in the corresponding `Pong`.
    pub nonce: u64,
}

/// Server heartbeat reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Pong {
    /// Echoed from the originating `Ping`.
    pub nonce: u64,
}

/// Client hands the server more delivery credits.
///
/// A single delivered frame (control or bulk) consumes one credit. Credits are
/// additive on top of whatever the server currently has, capped by the server's
/// per-session ceiling. That ceiling is a server-side concern and does not
/// appear on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AckCredits {
    /// Credits to add to the server's outstanding window.
    pub credits: u32,
}
