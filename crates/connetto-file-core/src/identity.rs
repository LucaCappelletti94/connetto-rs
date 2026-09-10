//! Content-hash newtypes for files and their chunks.

use core::fmt;

/// Content identity of a file: BLAKE3 hash of its raw bytes.
///
/// The identity is chunking-independent by design: re-tuning chunk parameters
/// never re-identifies a file, and verified range streaming (bao) is a free
/// future upgrade because BLAKE3 is internally a Merkle tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId([u8; 32]);

/// Content hash of a single plaintext chunk: BLAKE3 of the chunk bytes.
///
/// Serves as the store key and as the authenticated associated data for
/// encryption, binding each stored ciphertext to its position in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkHash([u8; 32]);

/// Incremental computation of a file identity.
#[derive(Debug, Default)]
pub struct FileIdHasher(blake3::Hasher);

impl FileIdHasher {
    /// Starts an empty file identity.
    #[must_use]
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }

    /// Adds the next bytes in file order.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Finishes the identity.
    #[must_use]
    pub fn finalize(self) -> FileId {
        FileId(*self.0.finalize().as_bytes())
    }
}

impl FileId {
    /// Wraps raw bytes as a `FileId`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes a file identity from ordered byte slices without joining them.
    #[must_use]
    pub fn from_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut hasher = FileIdHasher::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        hasher.finalize()
    }
}

impl ChunkHash {
    /// Wraps raw bytes as a `ChunkHash`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes the identity of one plaintext chunk.
    #[must_use]
    pub fn from_data(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Display for ChunkHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
