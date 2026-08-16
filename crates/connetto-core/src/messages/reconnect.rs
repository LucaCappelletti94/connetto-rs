//! Full-resync signal (Q6.2).
//!
//! Sent by the server when a subscription's rows have to be replaced rather
//! than updated: the client's cursor fell outside the retention window, or a
//! permission changed with no row event to carry the consequence. The client
//! clears local data for the affected subscription and applies the follow-up
//! snapshot as a replacement, not a merge.

use serde::{Deserialize, Serialize};

/// Why the rows a subscription holds must be replaced rather than updated.
///
/// A reason no code path can produce is a branch an application writes and
/// never reaches, so each variant names its producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FullResyncReason {
    /// Client's cursor is older than the oldest oplog entry the server retains.
    CursorOutsideRetention,
    /// A grant reaching this subscription's table moved, so what the caller may
    /// see changed with no row event to hang the consequence on (R7).
    AuthorizationChange,
}

/// Server tells the client "throw away local state for this subscription and
/// wait for a fresh snapshot".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullResyncRequired {
    /// Which subscription must be resynced from scratch.
    pub sub_id: String,
    /// Why the incremental path could not be used.
    pub reason: FullResyncReason,
}
