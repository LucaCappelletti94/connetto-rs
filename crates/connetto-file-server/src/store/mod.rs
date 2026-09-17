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
    ///
    /// # Errors
    ///
    /// Returns `StoreError::Io` when the `Fs` backend cannot write or rename the chunk file.
    /// Returns `StoreError::Object` when the `Object` backend reports an object store error.
    /// Propagates whatever `StoreError` the `Custom` backend returns.
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
    ///
    /// # Errors
    ///
    /// Returns `StoreError::Io` when the `Fs` backend cannot read the chunk file.
    /// Returns `StoreError::Object` when the `Object` backend reports an object store error.
    /// Propagates whatever `StoreError` the `Custom` backend returns.
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
    ///
    /// # Errors
    ///
    /// Returns `StoreError::Object` when the `Object` backend reports an object store error.
    /// Propagates whatever `StoreError` the `Custom` backend returns.
    /// The `Fs` backend never returns an error from this method because `Path::exists` silently converts filesystem errors to `false`.
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
    ///
    /// # Errors
    ///
    /// Returns `StoreError::Io` when the `Fs` backend fails to remove the chunk file for a reason other than the file being absent.
    /// Returns `StoreError::Object` when the `Object` backend reports an object store error.
    /// Propagates whatever `StoreError` the `Custom` backend returns.
    pub async fn delete(&self, hash: &ChunkHash) -> Result<(), StoreError> {
        match self {
            Self::Fs(s) => {
                use connetto_file_core::ChunkStore;
                s.delete_chunk(hash).await
            }
            Self::Object(s) => {
                use connetto_file_core::ChunkStore;
                s.delete_chunk(hash).await
            }
            Self::Custom(s) => s.delete(hash).await,
        }
    }

    /// Opens the `Object` backend named by an `object_store` URL.
    ///
    /// The URL's own path becomes a prefix inside the backend, so
    /// `s3://bucket/tenant` stores its chunks under `tenant/chunks/...`.
    ///
    /// # Errors
    ///
    /// Returns `StoreError::Object` when the scheme is unknown or the
    /// backend cannot be built from the URL.
    pub fn from_url(url: &url::Url) -> Result<Self, StoreError> {
        let (store, prefix) = object_store::parse_url(url)?;
        let store: std::sync::Arc<dyn object_store::ObjectStore> = std::sync::Arc::from(store);
        let store = if prefix.as_ref().is_empty() {
            store
        } else {
            std::sync::Arc::new(object_store::prefix::PrefixStore::new(store, prefix))
        };
        Ok(Self::Object(ObjectStoreBackend::new(store)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn two_urls_sharing_a_root_store_under_their_own_prefixes() {
        // The URL prefix is what lets two deployments share one bucket or
        // directory, so a chunk written through one URL must be invisible to
        // another URL that addresses a sibling location.
        let root = tempfile::tempdir().expect("a temporary root");
        let hash = connetto_file_core::ChunkHash::from_bytes([3u8; 32]);
        let a = AnyStore::from_url(
            &url::Url::from_file_path(root.path().join("tenant-a")).expect("a file url"),
        )
        .expect("a file url opens");
        let b = AnyStore::from_url(
            &url::Url::from_file_path(root.path().join("tenant-b")).expect("a file url"),
        )
        .expect("a file url opens");
        a.write(&hash, bytes::Bytes::from_static(b"tenant a bytes"))
            .await
            .expect("write through the first url");
        assert!(a.exists(&hash).await.expect("read back the first"));
        assert!(
            !b.exists(&hash).await.expect("read back the second"),
            "the prefix must separate sibling locations"
        );
    }

    #[tokio::test]
    async fn an_empty_prefix_url_stores_at_the_backend_root() {
        // A file url naming the filesystem root carries no prefix, the shape
        // that takes the no-prefix branch of `from_url`.  Nothing is written,
        // the root is the real filesystem, so only the open and one absent
        // lookup are proven.
        let root = url::Url::from_file_path(std::path::Path::new("/")).expect("a root url");
        let store = AnyStore::from_url(&root).expect("the filesystem root opens");
        let hash = connetto_file_core::ChunkHash::from_bytes([4u8; 32]);
        assert!(
            !store.exists(&hash).await.is_ok_and(|found| found),
            "a fresh hash is absent from the backend root"
        );
    }
}
