//! The `std::fs` chunk store: one file per chunk, named by content hash.

use core::sync::atomic::{AtomicU64, Ordering};
use std::io;
use std::path::{Path, PathBuf};

use connetto_file_core::{ChunkHash, ChunkStore};
use thiserror::Error;
use tokio::io::AsyncWriteExt;

/// Errors produced by [`FsStore`].
#[derive(Debug, Error)]
pub enum FsStoreError {
    /// A filesystem operation failed, naming the path it was on.
    #[error("chunk file {path}: {source}")]
    Io {
        /// The path the operation was on.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
}

/// Chunk storage in a directory tree, one file per chunk.
///
/// A chunk lives at `<root>/<first two hex characters>/<full hex>`, so a store
/// holding a million chunks spreads them over 256 directories rather than one.
/// The bytes written are whatever the caller hands over, which through
/// [`EncryptingStore`](connetto_file_core::EncryptingStore) is ciphertext.
///
/// A write lands through a temporary file and a rename, so a crash mid-write
/// leaves a temporary file that no read can reach rather than a truncated
/// chunk that [`has_chunk`](ChunkStore::has_chunk) would accept. The temporary
/// name is unique within this store, which assumes one store per directory:
/// two processes over one directory is not a supported topology, for the same
/// reason R26 gives for OPFS.
#[derive(Clone)]
pub struct FsStore {
    inner: std::sync::Arc<FsInner>,
}

/// The state one store directory owns, shared by every clone.
struct FsInner {
    root: PathBuf,
    next_temp: AtomicU64,
}

impl FsStore {
    /// Opens a store rooted at `root`. Directories are created on first write,
    /// so this touches the filesystem not at all.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            inner: std::sync::Arc::new(FsInner {
                root: root.into(),
                next_temp: AtomicU64::new(0),
            }),
        }
    }

    /// The directory this store writes into.
    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    /// The path a chunk with this hash occupies.
    fn path_of(&self, hash: &ChunkHash) -> PathBuf {
        let hex = hash.to_string();
        let mut path = self.inner.root.clone();
        path.push(&hex[..2]);
        path.push(&hex);
        path
    }
}

/// Attaches the path to an I/O failure.
fn at(path: &Path) -> impl FnOnce(io::Error) -> FsStoreError + '_ {
    move |source| FsStoreError::Io {
        path: path.to_owned(),
        source,
    }
}

impl ChunkStore for FsStore {
    type Error = FsStoreError;

    async fn write_chunk(&self, hash: &ChunkHash, data: &[u8]) -> Result<(), Self::Error> {
        let final_path = self.path_of(hash);
        let dir = final_path
            .parent()
            .expect("a chunk path always has a fan-out directory");
        tokio::fs::create_dir_all(dir).await.map_err(at(dir))?;
        let ticket = self.inner.next_temp.fetch_add(1, Ordering::Relaxed);
        let temp_path = dir.join(format!("{hash}.{ticket}.tmp"));
        // Written, flushed to stable storage, and only then renamed, because
        // this call returning is what lets a manifest naming the chunk commit.
        // Without the flush a host crash can recover the row, the manifest and
        // the outbox entry beside a chunk file that is absent or short, which
        // is exactly the loss the same-transaction rule exists to prevent, and
        // the bytes are the half that cannot be fetched again.
        {
            let mut file = tokio::fs::File::create(&temp_path)
                .await
                .map_err(at(&temp_path))?;
            file.write_all(data).await.map_err(at(&temp_path))?;
            file.sync_all().await.map_err(at(&temp_path))?;
        }
        tokio::fs::rename(&temp_path, &final_path)
            .await
            .map_err(at(&final_path))?;
        // The rename itself is a directory change, so the entry needs its own
        // flush: a synced file under an unsynced directory entry is still a
        // chunk a reader cannot find.
        tokio::fs::File::open(dir)
            .await
            .map_err(at(dir))?
            .sync_all()
            .await
            .map_err(at(dir))
    }

    async fn read_chunk(&self, hash: &ChunkHash) -> Result<Vec<u8>, Self::Error> {
        let path = self.path_of(hash);
        tokio::fs::read(&path).await.map_err(at(&path))
    }

    async fn has_chunk(&self, hash: &ChunkHash) -> Result<bool, Self::Error> {
        let path = self.path_of(hash);
        match tokio::fs::metadata(&path).await {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(at(&path)(err)),
        }
    }

    async fn delete_chunk(&self, hash: &ChunkHash) -> Result<(), Self::Error> {
        let path = self.path_of(hash);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            // A hash the store never held, or one a previous sweep already
            // collected. The caller wanted it gone, and it is.
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(at(&path)(err)),
        }
    }
}
