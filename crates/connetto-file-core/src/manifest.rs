//! File manifests: ordered per-chunk records mapping byte ranges to hashes.

use crate::identity::{ChunkHash, FileId};

/// Per-chunk record carrying the content hash and plaintext byte length.
///
/// The length maps a byte range to its chunk without fetching any bytes,
/// enabling range requests to skip ahead in the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkMeta {
    /// Plaintext content hash. Used as the store key and the encryption AAD.
    pub hash: ChunkHash,
    /// Byte length of the plaintext chunk.
    pub len: u64,
}

/// Ordered list of chunk records for one file.
///
/// Transport and dedup metadata only: the file identity is computed from the
/// raw bytes (chunking-independent), and the chunk hashes are the store keys.
/// Lengths are present because they map a byte range to a specific chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    file_id: FileId,
    chunks: Vec<ChunkMeta>,
}

impl Manifest {
    /// Constructs a manifest from a file identity and an ordered chunk list.
    #[must_use]
    pub fn new(file_id: FileId, chunks: Vec<ChunkMeta>) -> Self {
        Self { file_id, chunks }
    }

    /// Returns the file identity hash.
    #[must_use]
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    /// Returns the ordered chunk records.
    #[must_use]
    pub fn chunks(&self) -> &[ChunkMeta] {
        &self.chunks
    }
}
