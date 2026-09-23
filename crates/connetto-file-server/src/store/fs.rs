//! Filesystem chunk store.

use super::{StoreError, StoredChunk};
use connetto_file_core::{ChunkHash, ChunkStore};
use core::future::{self, Future};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Content-addressed chunk store backed by a local filesystem directory.
///
/// Each chunk lives at `{root}/{h[0..2]}/{h[2..4]}/{h}` where `h` is the
/// 64-character lower-hex hash string.  Writes are atomic: bytes are written
/// to a per-write unique sibling temp file then renamed, so a concurrent
/// reader never sees a partial write and two concurrent writes of the same
/// hash both succeed without corruption.
pub struct FsStore {
    root: PathBuf,
}

impl FsStore {
    /// Opens (or creates) a store rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns `StoreError::Io` if `create_dir_all` fails to create the store root directory.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn chunk_path(&self, hash: &ChunkHash) -> PathBuf {
        let h = crate::hex_32(hash.as_bytes());
        self.root.join(&h[..2]).join(&h[2..4]).join(&h)
    }

    /// Every chunk under the root, skipping names that are not a hash, such as temp files.
    ///
    /// # Errors
    ///
    /// Returns `StoreError::Io` when a directory or a file's metadata cannot be read.
    pub async fn list(&self) -> Result<Vec<StoredChunk>, StoreError> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || list_blocking(&root))
            .await
            .map_err(|err| StoreError::Io(std::io::Error::other(err)))?
    }
}

fn list_blocking(root: &Path) -> Result<Vec<StoredChunk>, StoreError> {
    let mut found = Vec::new();
    for first in std::fs::read_dir(root)? {
        let first = first?;
        if !first.file_type()?.is_dir() {
            continue;
        }
        for second in std::fs::read_dir(first.path())? {
            let second = second?;
            if !second.file_type()?.is_dir() {
                continue;
            }
            for entry in std::fs::read_dir(second.path())? {
                let entry = entry?;
                let Some(bytes) = entry
                    .file_name()
                    .to_str()
                    .and_then(crate::upload::parse_hex_32)
                else {
                    continue;
                };
                found.push(StoredChunk {
                    hash: ChunkHash::from_bytes(bytes),
                    modified: entry.metadata()?.modified()?,
                });
            }
        }
    }
    Ok(found)
}

impl ChunkStore for FsStore {
    type Error = StoreError;

    async fn write_chunk(&self, hash: &ChunkHash, data: &[u8]) -> Result<(), StoreError> {
        let target = self.chunk_path(hash);
        // Content-addressed: an existing final file already holds the same
        // bytes, so we can skip the write entirely.
        if target.exists() {
            return Ok(());
        }
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        // Unique suffix prevents concurrent same-chunk writes from clobbering
        // each other's temp files.  Rename is POSIX-atomic; the winner lands
        // the final file first and all subsequent renames overwrite with
        // identical bytes, which is harmless for a content-addressed store.
        let tmp = unique_tmp_path(&target);
        tokio::fs::write(&tmp, data).await?;
        tokio::fs::rename(&tmp, &target).await?;
        Ok(())
    }

    async fn read_chunk(&self, hash: &ChunkHash) -> Result<Vec<u8>, StoreError> {
        Ok(tokio::fs::read(self.chunk_path(hash)).await?)
    }

    fn has_chunk(&self, hash: &ChunkHash) -> impl Future<Output = Result<bool, StoreError>> + Send {
        future::ready(Ok(self.chunk_path(hash).exists()))
    }

    async fn delete_chunk(&self, hash: &ChunkHash) -> Result<(), StoreError> {
        let path = self.chunk_path(hash);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }
}

/// Generates a unique temp path by combining the process ID and a
/// monotonically increasing per-process counter.  Uniqueness across
/// concurrent tasks within a process is guaranteed by the atomic fetch-add.
fn unique_tmp_path(target: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = target
        .file_name()
        .expect("chunk path always has filename")
        .to_string_lossy();
    target
        .parent()
        .expect("path always has parent")
        .join(format!("{name}.{pid}.{n}.tmp"))
}
