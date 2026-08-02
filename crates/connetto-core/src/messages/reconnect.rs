//! Full-resync signal (Q6.2).
//!
//! Sent by the server when a subscription cannot resume incrementally, because
//! the client's cursor fell outside the retention window. The client clears
//! local data for the affected subscription and applies the follow-up snapshot
//! as a replacement, not a merge.

use serde::{Deserialize, Serialize};

/// Why an incremental resume is impossible.
///
/// One variant, because one thing sends this. A reason no code path can
/// produce is a branch an application writes and never reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FullResyncReason {
    /// Client's cursor is older than the oldest oplog entry the server retains.
    CursorOutsideRetention,
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
