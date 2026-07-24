//! Mutation header, acknowledgement, and mutation error responses.
//!
//! The client uploads writes as `SQLite` patchsets tagged with a monotonically
//! increasing `client_seq` (Q2.2). The header travels on the control channel.
//! The patchset itself rides on the bulk channel as
//! [`crate::messages::bulk::BulkMessage::MutationPatch`]. The data flows back
//! via the CDC path per Q3.5, but a durable apply is additionally confirmed
//! with a [`MutationApplied`] acknowledgement, so the client can retire the
//! pending record it would otherwise replay on reconnect, and so application
//! flows can await the server verdict. The server deduplicates replays with a
//! durable per-client watermark, which makes the upload path exactly-once.

use serde::{Deserialize, Serialize};

/// Control-plane header announcing a mutation upload.
///
/// The matching `BulkMessage::MutationPatch { client_seq, .. }` carries the
/// patchset bytes. The pair travels as two frames in a defined order: control
/// first, bulk immediately after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationHeader {
    /// Per-client monotonically increasing sequence number. Survives
    /// reconnects and process restarts: replayed uploads reuse the original
    /// number, and the server's watermark makes the replay idempotent.
    pub client_seq: u64,
    /// Number of ops packaged into the corresponding bulk patchset.
    ///
    /// Advisory: lets the server pre-size buffers and reject implausible
    /// headers. The authoritative op count is what the patchset parser sees.
    pub op_count: u32,
}

impl MutationHeader {
    /// Build a header from a sequence number and op count.
    pub fn new(client_seq: u64, op_count: u32) -> Self {
        Self {
            client_seq,
            op_count,
        }
    }
}

/// Server confirms a mutation is durably applied (or was already applied by
/// an earlier delivery of the same sequence).
///
/// This is the retire signal for the client's pending record: an unretired
/// mutation is replayed on the next resume, and the server's watermark
/// swallows any duplicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MutationApplied {
    /// Sequence number of the applied mutation.
    pub client_seq: u64,
}

/// Reason the server rejected a mutation before applying it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationRejectReason {
    /// Session's `AuthContext` is not permitted to perform this operation.
    Unauthorized,
    /// Patchset targets columns or tables outside the current schema.
    SchemaMismatch,
    /// `PostgreSQL` constraint violation (unique, FK, check, not-null).
    ///
    /// Human-readable detail passed straight from the driver so app UIs can
    /// surface the exact cause without a server round-trip.
    Constraint {
        /// Human-readable message from the underlying driver.
        detail: String,
    },
    /// Bulk patchset failed to parse. `detail` names the parser error.
    Malformed {
        /// Human-readable parse error.
        detail: String,
    },
    /// Everything else. Prefer more specific variants when possible.
    Other {
        /// Human-readable detail.
        detail: String,
    },
}

/// Server rejects a mutation without applying it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationReject {
    /// Sequence number of the rejected mutation.
    pub client_seq: u64,
    /// Why the mutation was rejected.
    pub reason: MutationRejectReason,
}

/// Server detects that the client's optimistic write was based on a stale row.
///
/// Conflict detection uses `WHERE id = ? AND updated_at = ?` per Q3.2. When the
/// row is now newer than the client saw, the server sends the current
/// `updated_at` plus a JSON snapshot of the current row so the app can run its
/// configured conflict-resolution strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationConflict {
    /// Sequence number of the conflicting mutation.
    pub client_seq: u64,
    /// Table name for the conflicting row. Informational: the patchset already
    /// names it, but the client may not have the patchset in hand any more.
    pub table: String,
    /// Server's current `updated_at` value for the row, in RFC 3339 form.
    pub server_updated_at: String,
    /// Server's current row snapshot as a JSON object.
    ///
    /// JSON is the wire format here (not `MessagePack`) because the row shape is
    /// only known at runtime. Q2.1 reserves JSON for shape-unknown-at-compile
    /// data. The client deserialises into its `Diesel` row type.
    pub server_row_json: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_builds_from_parts() {
        let h = MutationHeader::new(42, 3);
        assert_eq!(h.client_seq, 42);
        assert_eq!(h.op_count, 3);
    }

    #[test]
    fn reject_reason_variants_are_distinguishable() {
        let a = MutationRejectReason::Unauthorized;
        let b = MutationRejectReason::SchemaMismatch;
        let c = MutationRejectReason::Constraint {
            detail: "unique_violation".into(),
        };
        assert_ne!(a, b);
        assert_ne!(b, c);
    }
}
