//! Bulk-plane wire enum.
//!
//! Every message carrying a large opaque byte payload (a `SQLite` patchset, a
//! schema blob) rides here. Bulk payloads are pre-compressed with `Zstd` at the
//! application layer per Q2.5. The `*_zstd` fields hold the already-compressed
//! bytes so the transport layer never re-compresses. Decompression is the
//! consumer's responsibility.

use serde::{Deserialize, Serialize};

use crate::{cursor::Cursor, schema::SchemaVersion};

/// Bulk-plane frames.
///
/// Each variant carries a `Zstd`-compressed byte payload plus the minimal
/// routing header the receiver needs to place it (subscription id, resume
/// cursor, mutation sequence, or schema version).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BulkMessage {
    /// Piece of an initial snapshot for a subscription.
    SnapshotPatch(SnapshotPatch),
    /// A live CDC update for a subscription.
    LivePatch(LivePatch),
    /// A client-uploaded mutation patchset. Paired one-to-one with the
    /// [`crate::messages::mutation::MutationHeader`] control frame that
    /// immediately preceded it.
    MutationPatch(MutationPatch),
    /// Schema payload accompanying a [`crate::messages::schema::SchemaUpdate`].
    SchemaBlob(SchemaBlob),
}

/// Snapshot chunk for a subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotPatch {
    /// Subscription this patch belongs to.
    pub sub_id: String,
    /// `Zstd`-compressed `SQLite` patchset bytes.
    #[serde(with = "serde_bytes")]
    pub patchset_zstd: Vec<u8>,
}

impl SnapshotPatch {
    /// Build a snapshot patch from a subscription id and already-compressed bytes.
    pub fn new(sub_id: impl Into<String>, patchset_zstd: impl Into<Vec<u8>>) -> Self {
        Self {
            sub_id: sub_id.into(),
            patchset_zstd: patchset_zstd.into(),
        }
    }

    /// Access the compressed patchset payload.
    #[inline]
    pub fn patchset_zstd(&self) -> &[u8] {
        &self.patchset_zstd
    }
}

/// Live CDC update for a subscription. Cursor advances the client's resume point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LivePatch {
    /// Subscription this patch belongs to.
    pub sub_id: String,
    /// New resume cursor to persist after applying this patch.
    pub cursor: Cursor,
    /// `Zstd`-compressed `SQLite` patchset bytes.
    #[serde(with = "serde_bytes")]
    pub patchset_zstd: Vec<u8>,
}

impl LivePatch {
    /// Build a live patch from its parts.
    pub fn new(
        sub_id: impl Into<String>,
        cursor: Cursor,
        patchset_zstd: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            sub_id: sub_id.into(),
            cursor,
            patchset_zstd: patchset_zstd.into(),
        }
    }
}

/// Client-uploaded mutation patchset.
///
/// Paired one-to-one with the [`crate::messages::mutation::MutationHeader`]
/// that immediately preceded it on the control channel. `client_seq` is
/// duplicated here so the server can validate the pairing without cross-channel
/// state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationPatch {
    /// Sequence number that must match the immediately preceding header.
    pub client_seq: u64,
    /// `Zstd`-compressed `SQLite` patchset bytes.
    #[serde(with = "serde_bytes")]
    pub patchset_zstd: Vec<u8>,
}

impl MutationPatch {
    /// Build a mutation patch from its parts.
    pub fn new(client_seq: u64, patchset_zstd: impl Into<Vec<u8>>) -> Self {
        Self {
            client_seq,
            patchset_zstd: patchset_zstd.into(),
        }
    }
}

/// Schema payload for the client to install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaBlob {
    /// Which schema version this payload realises.
    pub version: SchemaVersion,
    /// `Zstd`-compressed serialized schema payload. Encoding of the inner bytes
    /// is a higher-layer concern (the server crate emits it, the client crate
    /// consumes it). `connetto-core` just moves the bytes.
    #[serde(with = "serde_bytes")]
    pub blob_zstd: Vec<u8>,
}

impl SchemaBlob {
    /// Build a schema blob from a version and already-compressed bytes.
    pub fn new(version: SchemaVersion, blob_zstd: impl Into<Vec<u8>>) -> Self {
        Self {
            version,
            blob_zstd: blob_zstd.into(),
        }
    }
}
