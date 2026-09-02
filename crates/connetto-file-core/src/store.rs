//! The `ChunkStore` trait: content-addressed chunk storage.

use crate::identity::ChunkHash;

/// Content-addressed storage for file chunks.
///
/// The key is always the plaintext chunk hash, regardless of what bytes the
/// implementation actually persists (encrypted, compressed, or plain). The
/// [`crate::EncryptingStore`] decorator makes this transparent: callers of
/// [`crate::process_file`] and [`crate::reassemble`] always speak plaintext.
pub trait ChunkStore {
    /// The error type returned by storage operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Stores a chunk at its content hash.
    ///
    /// Overwrites silently when the hash is already present. Content-addressed
    /// dedup is guaranteed by the hash.
    fn write_chunk(&self, hash: &ChunkHash, data: &[u8]) -> Result<(), Self::Error>;

    /// Retrieves the bytes stored at `hash`.
    fn read_chunk(&self, hash: &ChunkHash) -> Result<Vec<u8>, Self::Error>;

    /// Reports whether a chunk for `hash` is already present.
    fn has_chunk(&self, hash: &ChunkHash) -> Result<bool, Self::Error>;
}
