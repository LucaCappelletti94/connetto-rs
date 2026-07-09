//! Full-resync signal (Q6.2).
//!
//! Sent by the server when a subscription cannot resume incrementally, typically
//! because the client's cursor fell outside the retention window, the session
//! expired, or the schema is incompatible with the oplog span. The client clears
//! local data for the affected subscription and applies the follow-up snapshot
//! as a replacement, not a merge.

use serde::{Deserialize, Serialize};

/// Why an incremental resume is impossible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FullResyncReason {
    /// Client's cursor is older than the oldest oplog entry the server retains.
    CursorOutsideRetention,
    /// Server-side session state (subscriptions, cursors, pending `PatchSet`)
    /// was garbage-collected before the client reconnected.
    SessionExpired,
    /// Schema changed in a way that invalidates cached local rows for this
    /// subscription (e.g. column dropped, primary key redefined).
    SchemaIncompatible,
    /// Everything else. Prefer a specific variant when a cause is clear.
    Other {
        /// Human-readable detail.
        detail: String,
    },
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
