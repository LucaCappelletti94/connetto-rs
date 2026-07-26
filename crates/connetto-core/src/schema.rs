//! Schema version shared between client and server.
//!
//! The client compares the [`SchemaVersion`] it was built against with the one
//! the server advertises in `HandshakeAck`. connetto does not migrate schemas at
//! runtime (the client never runs DDL), so a mismatch means this app build is
//! stale and must reload, not that a migration should run. A version is a
//! content hash of the schema source: two schemas are interchangeable iff their
//! hashes match.
//!
//! A [`SchemaVersion`] always holds a real content hash. The absence of a
//! declared version is modeled out of band, as `Option<SchemaVersion>` on the
//! config and ack boundaries, never as an empty hash. There is deliberately no
//! `Default`: a fabricated empty hash is not a hash, and an in-band sentinel is
//! exactly what let a stale-check bug slip through. Staleness is checked only
//! when both sides declare a version (both `Some`).
//!
//! [`HandshakeAck`]: crate::messages::HandshakeAck

use core::fmt;

use serde::{Deserialize, Serialize};

/// Content hash identifying a schema, the authoritative equality signal shared
/// between client and server. Two schemas are interchangeable iff their hashes
/// match. It renders as a short hex prefix for humans, since the hash itself is
/// the identity. Absence of a version is `Option::None` at the boundaries, not
/// a value of this type.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SchemaVersion(#[serde(with = "serde_bytes")] Vec<u8>);

impl SchemaVersion {
    /// Build a schema version from a precomputed content hash.
    pub fn from_hash(hash: impl Into<Vec<u8>>) -> Self {
        Self(hash.into())
    }

    /// Build a schema version by hashing a schema source document with
    /// [`schema_hash`], the shared canonical fingerprint both the server and an
    /// app build compute from the same source.
    pub fn from_source(source: &str) -> Self {
        Self(schema_hash(source))
    }

    /// The content hash bytes.
    #[inline]
    pub fn hash(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for SchemaVersion {
    /// A short hex prefix, enough to identify a build in a log or error.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("none");
        }
        for byte in self.0.iter().take(6) {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SchemaVersion({self})")
    }
}

/// Deterministic content hash of a schema source document, shared by the server
/// (over its Postgres DDL) and an app build (over the same source), so two
/// builds of one schema agree bit-for-bit. Line endings are normalized so a
/// CRLF vs LF checkout difference does not force a spurious reload. Nothing else
/// is normalized, so any real edit changes the hash.
#[must_use]
pub fn schema_hash(source: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let normalized = source.replace("\r\n", "\n");
    Sha256::digest(normalized.as_bytes()).to_vec()
}
