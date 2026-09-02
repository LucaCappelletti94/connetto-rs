//! In-memory chunk store backed by a mutex-held hash map.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Mutex;

use crate::identity::ChunkHash;
use crate::store::ChunkStore;

/// In-memory chunk store.
///
/// Thread-safe via interior `Mutex`. Suitable for tests and for short-lived
/// in-process pipelines. All stored bytes are lost when the store is dropped.
#[derive(Debug, Default)]
pub struct MemStore {
    chunks: Mutex<HashMap<ChunkHash, Vec<u8>>>,
}

impl MemStore {
    /// Creates an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ChunkStore for MemStore {
    type Error = Infallible;

    fn write_chunk(&self, hash: &ChunkHash, data: &[u8]) -> Result<(), Infallible> {
        self.chunks
            .lock()
            .expect("MemStore lock is not poisoned")
            .insert(*hash, data.to_vec());
        Ok(())
    }

    fn read_chunk(&self, hash: &ChunkHash) -> Result<Vec<u8>, Infallible> {
        Ok(self
            .chunks
            .lock()
            .expect("MemStore lock is not poisoned")
            .get(hash)
            .cloned()
            .unwrap_or_default())
    }

    fn has_chunk(&self, hash: &ChunkHash) -> Result<bool, Infallible> {
        Ok(self
            .chunks
            .lock()
            .expect("MemStore lock is not poisoned")
            .contains_key(hash))
    }
}
