//! Object-store chunk backend (S3, `MinIO`, local filesystem, and any other
//! `object_store`-compatible target).

use super::StoreError;
use connetto_file_core::{ChunkHash, ChunkStore};
use object_store::{ObjectStore, PutPayload, path::Path};
use std::sync::Arc;

/// Content-addressed chunk store backed by any [`ObjectStore`] implementation.
///
/// Chunks are stored at `chunks/{h[0..2]}/{h[2..4]}/{h}` where `h` is the
/// lower-hex hash.
pub struct ObjectStoreBackend {
    store: Arc<dyn ObjectStore>,
}

impl ObjectStoreBackend {
    /// Wraps `store` in a content-addressed chunk backend.
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    fn chunk_path(hash: &ChunkHash) -> Path {
        let h = crate::hex_32(hash.as_bytes());
        Path::from(format!("chunks/{}/{}/{}", &h[..2], &h[2..4], h))
    }
}

// ObjectStore is Send + Sync, so the impl is Sync automatically.
impl ChunkStore for ObjectStoreBackend {
    type Error = StoreError;

    async fn write_chunk(&self, hash: &ChunkHash, data: &[u8]) -> Result<(), StoreError> {
        let path = Self::chunk_path(hash);
        let payload = PutPayload::from(bytes::Bytes::copy_from_slice(data));
        self.store
            .put(&path, payload)
            .await
            .map(|_| ())
            .map_err(StoreError::from)
    }

    async fn read_chunk(&self, hash: &ChunkHash) -> Result<Vec<u8>, StoreError> {
        let path = Self::chunk_path(hash);
        let result = self.store.get(&path).await?;
        let bytes = result.bytes().await?;
        Ok(bytes.to_vec())
    }

    async fn has_chunk(&self, hash: &ChunkHash) -> Result<bool, StoreError> {
        let path = Self::chunk_path(hash);
        match self.store.head(&path).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(StoreError::from(e)),
        }
    }

    async fn delete_chunk(&self, hash: &ChunkHash) -> Result<(), StoreError> {
        let path = Self::chunk_path(hash);
        match self.store.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(StoreError::from(e)),
        }
    }
}
