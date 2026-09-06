//! Chunk storage backends for the file server.
//!
//! `AnyStore` dispatches between the two production backends (`Fs`, `Object`)
//! and a `Custom` variant that accepts any implementation of the `CustomStore`
//! trait.  The `Custom` variant is the extension point used by integration
//! tests to inject faults; no test-only machinery lives in the library.

pub mod fs;
pub mod object;

pub use fs::FsStore;
pub use object::ObjectStoreBackend;

use std::io;
use std::pin::Pin;

use bytes::Bytes;
use connetto_file_core::ChunkHash;
use thiserror::Error;

/// Error returned by any chunk store operation.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Filesystem I/O failure.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// Object store failure.
    #[error("object store: {0}")]
    Object(object_store::Error),
}

impl From<object_store::Error> for StoreError {
    fn from(e: object_store::Error) -> Self {
        Self::Object(e)
    }
}

/// Dynamic store backend for custom implementations.
///
/// Implement this trait in test code to inject any behaviour (faults, latency,
/// gating) into a router without touching the production enum.
pub trait CustomStore: Send + Sync + 'static {
    /// Store `data` at `hash`.
    fn write<'a>(
        &'a self,
        hash: &'a ChunkHash,
        data: Bytes,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), StoreError>> + Send + 'a>>;

    /// Return the bytes stored at `hash`.
    fn read<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Bytes, StoreError>> + Send + 'a>>;

    /// Return `true` when `hash` is already present.
    fn exists<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<bool, StoreError>> + Send + 'a>>;

    /// Delete the chunk at `hash`.  A missing chunk is not an error.
    fn delete<'a>(
        &'a self,
        hash: &'a ChunkHash,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), StoreError>> + Send + 'a>>;
}

/// Either storage backend, chosen at construction time.
pub enum AnyStore {
    /// Local filesystem directory store.
    Fs(FsStore),
    /// Any `object_store`-compatible backend (S3, `MinIO`, local filesystem).
    Object(ObjectStoreBackend),
    /// Dynamic backend for integration tests and custom deployments.
    Custom(Box<dyn CustomStore>),
}

impl AnyStore {
    /// Stores `data` at `hash`.  Overwrites silently when already present.
    pub async fn write(&self, hash: &ChunkHash, data: Bytes) -> Result<(), StoreError> {
        match self {
            Self::Fs(s) => {
                use connetto_file_core::ChunkStore;
                s.write_chunk(hash, &data).await
            }
            Self::Object(s) => {
                use connetto_file_core::ChunkStore;
                s.write_chunk(hash, &data).await
            }
            Self::Custom(s) => s.write(hash, data).await,
        }
    }

    /// Reads the bytes stored at `hash`.
    pub async fn read(&self, hash: &ChunkHash) -> Result<Bytes, StoreError> {
        let vec = match self {
            Self::Fs(s) => {
                use connetto_file_core::ChunkStore;
                s.read_chunk(hash).await?
            }
            Self::Object(s) => {
                use connetto_file_core::ChunkStore;
                s.read_chunk(hash).await?
            }
            Self::Custom(s) => return s.read(hash).await,
        };
        Ok(Bytes::from(vec))
    }

    /// Returns `true` when a chunk for `hash` is already present.
    pub async fn exists(&self, hash: &ChunkHash) -> Result<bool, StoreError> {
        match self {
            Self::Fs(s) => {
                use connetto_file_core::ChunkStore;
                s.has_chunk(hash).await
            }
            Self::Object(s) => {
                use connetto_file_core::ChunkStore;
                s.has_chunk(hash).await
            }
            Self::Custom(s) => s.exists(hash).await,
        }
    }

    /// Deletes the chunk at `hash`.  A missing chunk is not an error.
    pub async fn delete(&self, hash: &ChunkHash) -> Result<(), StoreError> {
        match self {
            Self::Fs(s) => fs::delete_chunk(s, hash).await,
            Self::Object(s) => object::delete_chunk(s, hash).await,
            Self::Custom(s) => s.delete(hash).await,
        }
    }
}
