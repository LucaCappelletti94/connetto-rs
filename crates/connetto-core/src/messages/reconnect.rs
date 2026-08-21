//! Full-resync signal (Q6.2).
//!
//! Sent by the server when a subscription's rows have to be replaced rather
//! than updated: the client's cursor fell outside the retention window, a
//! permission changed with no row event to carry the consequence, or a table
//! was emptied and no patchset can say so. The client clears local data for the
//! affected subscription and applies the follow-up snapshot as a replacement,
//! not a merge.

use serde::{Deserialize, Serialize};

/// Why the rows a subscription holds must be replaced rather than updated.
///
/// A reason no code path can produce is a branch an application writes and
/// never reaches, so each variant names its producer.
///
/// Not `Copy`, because one variant names the table it concerns. Reading that
/// name off the reason is what lets the client tell an emptied table from a
/// subscription-wide replacement, which it has to, since only the first is
/// entitled to ignore what a sibling subscription still claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FullResyncReason {
    /// Client's cursor is older than the oldest oplog entry the server retains.
    CursorOutsideRetention,
    /// A grant reaching this subscription's table moved, so what the caller may
    /// see changed with no row event to hang the consequence on (R7).
    AuthorizationChange,
    /// The named table was emptied, which a patchset cannot express: it carries
    /// insert, update and delete operations only, so the payload folded for a
    /// truncate has none and applying it leaves every row in place (R48).
    TableTruncated {
        /// The emptied table, as the catalog names it. Every row of it is stale
        /// whatever a subscription's filter says, so the client deletes the
        /// whole of this one rather than sparing what siblings still claim.
        table: String,
    },
    /// An initial read arriving in pages failed part way through, so what the
    /// client holds is part of a set (R58). The replacement is read afresh
    /// before this notice goes out, so nothing is discarded on a promise.
    SnapshotInterrupted,
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
