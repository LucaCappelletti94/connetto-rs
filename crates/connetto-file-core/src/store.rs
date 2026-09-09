//! The `ChunkStore` trait: content-addressed chunk storage.

use crate::identity::ChunkHash;
use crate::maybe_send::MaybeSend;

/// Content-addressed async storage for file chunks.
///
/// The key is always the plaintext chunk hash, regardless of what bytes the
/// implementation actually persists (encrypted, compressed, or plain). The
/// [`crate::EncryptingStore`] decorator makes this transparent: callers of
/// [`crate::process_file`] and [`crate::reassemble`] always speak plaintext.
///
/// Methods return `impl Future + MaybeSend` so a caller on a multi-threaded
/// native runtime can hold futures across spawn boundaries. On wasm the bound
/// is vacuous and single-threaded stores implement the trait directly without
/// any `Send` constraint. Implementations write plain `async fn` bodies.
pub trait ChunkStore {
    /// The error type returned by storage operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Stores a chunk at its content hash.
    ///
    /// Overwrites silently when the hash is already present.
    fn write_chunk(
        &self,
        hash: &ChunkHash,
        data: &[u8],
    ) -> impl core::future::Future<Output = Result<(), Self::Error>> + MaybeSend;

    /// Retrieves the bytes stored at `hash`.
    fn read_chunk(
        &self,
        hash: &ChunkHash,
    ) -> impl core::future::Future<Output = Result<Vec<u8>, Self::Error>> + MaybeSend;

    /// Reports whether a chunk for `hash` is already present.
    fn has_chunk(
        &self,
        hash: &ChunkHash,
    ) -> impl core::future::Future<Output = Result<bool, Self::Error>> + MaybeSend;

    /// Removes the chunk stored at `hash`.
    ///
    /// Removing a hash the store does not hold succeeds: the caller wanted
    /// the chunk gone and it is, and a sweep re-running over a list it
    /// already collected is the ordinary case rather than an error.
    ///
    /// A store never decides on its own that a chunk is unreferenced. That
    /// judgement belongs to whoever holds the manifests, because two of them
    /// can name the same chunk.
    fn delete_chunk(
        &self,
        hash: &ChunkHash,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>> + MaybeSend;
}
