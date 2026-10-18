//! Mutation header, acknowledgement, and mutation error responses.
//!
//! The client uploads writes as `SQLite` patchsets tagged with the sequence
//! its writer's pending queue gave them (R75), `client_seq` on the wire. The
//! header travels on the control channel. The patchset itself rides on the
//! bulk channel as [`crate::messages::bulk::BulkMessage::MutationPatch`]. The
//! data flows back via the CDC path per Q3.5, but a settled write is
//! additionally confirmed with a [`MutationApplied`] or a [`MutationReject`],
//! so the client can retire the pending record it would otherwise replay on
//! reconnect, and so application flows can await the server verdict. The
//! server settles each `(writer, sequence)` once, in order, and answers any
//! later delivery of it from that record, which makes every path exactly-once.

use serde::{Deserialize, Serialize};

use super::writer::{Provenance, WriterRef};
use crate::schema::Major;

/// Control-plane header announcing a mutation upload.
///
/// The matching `BulkMessage::MutationPatch { client_seq, .. }` carries the
/// patchset bytes. The pair travels as two frames in a defined order: control
/// first, bulk immediately after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationHeader {
    /// The sequence the writer's pending queue gave this write, one past the
    /// last the server settled for the writer. A replay reuses the original
    /// number, and the server answers it from the settled record.
    pub client_seq: u64,
    /// Number of ops packaged into the corresponding bulk patchset.
    ///
    /// Advisory: lets the server pre-size buffers and reject implausible
    /// headers. The authoritative op count is what the patchset parser sees.
    pub op_count: u32,
    /// The writer and sequence this entry was first written under, for an
    /// entry an import restored or a retired writer's device carried forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
}

impl MutationHeader {
    /// Build a header from a sequence number and op count.
    pub fn new(client_seq: u64, op_count: u32) -> Self {
        Self {
            client_seq,
            op_count,
            provenance: None,
        }
    }

    /// Name where this entry was first written.
    #[must_use]
    pub fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Some(provenance);
        self
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
    /// The server could not settle this write, because the authorization
    /// service was unreachable when it checked whether this caller may write
    /// or the database could not take the write within the server's retry
    /// budget.
    ///
    /// Reusing `Unauthorized` here would be a data-loss bug: a client that
    /// receives `Unauthorized` stops retrying and may discard the mutation,
    /// turning a transient outage into permanent loss. A client that receives
    /// `Indeterminate` MUST retry rather than retire its pending record. Every
    /// later write on the same connection is answered `Indeterminate` too until
    /// this one is settled, so none applies ahead of it.
    Indeterminate,
    /// The server already settled a different entry at this writer and
    /// sequence, which stands, so this one never applies.
    Forked,
}

/// Formats the refusal and any driver detail for display.
impl core::fmt::Display for MutationRejectReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("unauthorized"),
            Self::SchemaMismatch => f.write_str("schema mismatch"),
            Self::Constraint { detail } => write!(f, "constraint violation: {detail}"),
            Self::Malformed { detail } => write!(f, "malformed patchset: {detail}"),
            Self::Other { detail } => f.write_str(detail),
            Self::Indeterminate => f.write_str("cannot tell yet, retrying"),
            Self::Forked => f.write_str("another write already settled at this sequence"),
        }
    }
}

/// Server rejects a mutation without applying it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationReject {
    /// Sequence number of the rejected mutation.
    pub client_seq: u64,
    /// Why the mutation was rejected.
    pub reason: MutationRejectReason,
}

/// The server's copy of a row a client's optimistic write collided with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictRow {
    /// The row's current version value, in the column its table versions on.
    pub updated_at: String,
    /// The row as a JSON object.
    ///
    /// JSON is the wire format here (not `MessagePack`) because the row shape is
    /// only known at runtime. Q2.1 reserves JSON for shape-unknown-at-compile
    /// data. The client deserialises into its `Diesel` row type.
    pub row_json: String,
}

/// Server detects that the client's optimistic write was based on a stale row.
///
/// Conflict detection uses `WHERE id = ? AND updated_at = ?` per Q3.2. When the
/// row is now newer than the client saw, the server sends its current copy so
/// the app can run its configured conflict-resolution strategy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationConflict {
    /// Sequence number of the conflicting mutation.
    pub client_seq: u64,
    /// Table name for the conflicting row. Informational: the patchset already
    /// names it, but the client may not have the patchset in hand any more.
    pub table: String,
    /// The server's copy of the row, absent when the row is gone: a write
    /// against a row somebody else deleted conflicts with nothing to send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_row: Option<ConflictRow>,
}

/// One write an older application schema major captured, named by its writer
/// and the sequence it is the writer's (R31).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldWrite {
    /// The writer the write is queued under.
    pub writer: WriterRef,
    /// Its sequence in that writer's queue.
    pub seq: u64,
}

/// How work an older application schema major captured settled while it
/// drained to that major's server (R31).
///
/// A native client reports it as an event. A browser relay hub, whose worker
/// owns the drain, tells every tab through
/// [`ControlMessage::HeldWork`](crate::messages::ControlMessage::HeldWork),
/// so the application reads it wherever it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeldWork {
    /// A held write was applied by its major's server.
    Applied {
        /// The major it was captured under.
        major: Major,
        /// The write.
        write: HeldWrite,
    },
    /// A held write was refused by its major's server. Nothing is rolled
    /// back, because the rebuild already replaced the rows it touched with the
    /// newer major's snapshot.
    Rejected {
        /// The major it was captured under.
        major: Major,
        /// The write.
        write: HeldWrite,
        /// Why the server refused it, `None` when it collided with a newer
        /// version of a row instead.
        reason: Option<MutationRejectReason>,
    },
    /// The held work of a major can never be applied, because that major's
    /// server is gone or serves another schema, so it was dropped and every
    /// writer it was queued under retired.
    Lost {
        /// The major it was captured under.
        major: Major,
        /// The writes dropped.
        writes: Vec<HeldWrite>,
        /// How many unsent files were dropped.
        files: u64,
    },
    /// Every write and file held from a major is settled.
    Drained {
        /// The major whose held work is done.
        major: Major,
    },
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

    /// An application shows the reason's message, so no two reasons may read
    /// alike and the driver's detail must reach the reader.
    #[test]
    fn every_reject_reason_displays_its_own_message_with_its_detail() {
        let detail = "duplicate key value violates unique constraint";
        let reasons = [
            MutationRejectReason::Unauthorized,
            MutationRejectReason::SchemaMismatch,
            MutationRejectReason::Constraint {
                detail: detail.into(),
            },
            MutationRejectReason::Malformed {
                detail: detail.into(),
            },
            MutationRejectReason::Other {
                detail: "a server-side failure".into(),
            },
            MutationRejectReason::Indeterminate,
            MutationRejectReason::Forked,
        ];
        let messages: Vec<String> = reasons.iter().map(ToString::to_string).collect();
        for (i, message) in messages.iter().enumerate() {
            assert!(!message.is_empty(), "{:?} displays nothing", reasons[i]);
            for other in &messages[i + 1..] {
                assert_ne!(message, other, "two reasons read alike");
            }
        }
        for (reason, message) in reasons.iter().zip(&messages) {
            match reason {
                MutationRejectReason::Constraint { detail }
                | MutationRejectReason::Malformed { detail }
                | MutationRejectReason::Other { detail } => {
                    assert!(
                        message.contains(detail.as_str()),
                        "{message} drops {detail}"
                    );
                }
                _ => {}
            }
        }
    }
}
