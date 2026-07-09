//! Schema version envelope shared between client and server.
//!
//! The client persists the last accepted [`SchemaVersion`] and compares it against
//! the one it receives in `HandshakeAck` and `SchemaUpdate` to decide whether to
//! run a local migration. The `hash` field is a content hash of the underlying
//! schema description (columns, PKs, filtered by RLS visibility) so version
//! comparison never depends on wall-clock strings alone.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Identifier plus content hash for a schema payload.
///
/// The identifier is any monotonically increasing tag the server chooses
/// (git SHA, deploy id, incrementing counter). The hash is the authoritative
/// equality signal: two schemas with identical hashes are byte-for-byte
/// interchangeable regardless of their identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaVersion {
    /// Server-chosen tag. Human-readable but not authoritative for equality.
    pub id: String,
    /// Content hash of the schema payload. Authoritative equality signal.
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

impl SchemaVersion {
    /// Build a schema version from an id string and a content hash.
    pub fn new(id: impl Into<String>, hash: impl Into<Vec<u8>>) -> Self {
        Self {
            id: id.into(),
            hash: hash.into(),
        }
    }

    /// Content hash bytes.
    #[inline]
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }
}

impl From<(String, ByteBuf)> for SchemaVersion {
    fn from((id, hash): (String, ByteBuf)) -> Self {
        Self {
            id,
            hash: hash.into_vec(),
        }
    }
}
