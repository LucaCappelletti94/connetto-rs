//! In-memory chunk store backed by a mutex-held hash map.

use core::future::{self, Future};
use std::collections::HashMap;
use std::sync::Mutex;

use thiserror::Error;

use crate::identity::ChunkHash;
use crate::store::{ChunkInventory, ChunkStore};

/// The one thing an in-memory store can fail at.
#[derive(Debug, Error)]
pub enum MemStoreError {
    /// A read named a chunk the store does not hold.
    ///
    /// Reporting it is the whole reason this error type exists rather than
    /// `Infallible`: a store that answers an absent chunk with empty bytes
    /// makes [`reassemble`](crate::reassemble) return the wrong file and call
    /// it success.
    #[error("no chunk stored at {hash}")]
    Absent {
        /// The hash that is not there.
        hash: ChunkHash,
    },
}

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
    type Error = MemStoreError;

    fn write_chunk(
        &self,
        hash: &ChunkHash,
        data: &[u8],
    ) -> impl Future<Output = Result<(), MemStoreError>> + Send {
        self.chunks
            .lock()
            .expect("MemStore lock is not poisoned")
            .insert(*hash, data.to_vec());
        future::ready(Ok(()))
    }

    fn read_chunk(
        &self,
        hash: &ChunkHash,
    ) -> impl Future<Output = Result<Vec<u8>, MemStoreError>> + Send {
        let val = self
            .chunks
            .lock()
            .expect("MemStore lock is not poisoned")
            .get(hash)
            .cloned()
            .ok_or(MemStoreError::Absent { hash: *hash });
        future::ready(val)
    }

    fn has_chunk(
        &self,
        hash: &ChunkHash,
    ) -> impl Future<Output = Result<bool, MemStoreError>> + Send {
        let present = self
            .chunks
            .lock()
            .expect("MemStore lock is not poisoned")
            .contains_key(hash);
        future::ready(Ok(present))
    }

    fn delete_chunk(
        &self,
        hash: &ChunkHash,
    ) -> impl Future<Output = Result<(), MemStoreError>> + Send {
        self.chunks
            .lock()
            .expect("MemStore lock is not poisoned")
            .remove(hash);
        future::ready(Ok(()))
    }
}

impl ChunkInventory for MemStore {
    fn stored_hashes(&self) -> impl Future<Output = Result<Vec<ChunkHash>, MemStoreError>> + Send {
        let hashes = self
            .chunks
            .lock()
            .expect("MemStore lock is not poisoned")
            .keys()
            .copied()
            .collect();
        future::ready(Ok(hashes))
    }
}
