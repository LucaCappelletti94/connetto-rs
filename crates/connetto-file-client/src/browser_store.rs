//! Browser chunk storage backed by worker-owned OPFS or session memory.

use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use connetto_file_core::{ChunkHash, ChunkInventory, ChunkStore, MemStore, MemStoreError};
use js_sys::{Reflect, Uint8Array};
use thiserror::Error;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    DedicatedWorkerGlobalScope, File, FileSystemDirectoryHandle, FileSystemFileHandle,
    FileSystemRemoveOptions,
};

mod opfs_api;

use opfs_api::{
    browser_error, directory_handle, file_handle, is_not_found, move_file, next_key, type_error,
    write_file,
};

const ROOT: &str = "connetto-content";

/// A browser chunk storage failure.
#[derive(Debug, Error)]
pub enum BrowserStoreError {
    /// The requested store namespace cannot name one OPFS directory.
    #[error("invalid browser chunk store namespace {namespace:?}")]
    InvalidNamespace {
        /// The rejected namespace.
        namespace: String,
    },
    /// A chunk read named bytes the store does not hold.
    #[error("no chunk stored at {hash}")]
    Absent {
        /// The missing chunk hash.
        hash: ChunkHash,
    },
    /// A browser filesystem operation failed.
    #[error("browser filesystem {operation}: {message}")]
    Browser {
        /// The operation that failed.
        operation: &'static str,
        /// The browser exception text.
        message: String,
    },
    /// A browser filesystem API returned a value of the wrong type.
    #[error("browser filesystem {operation} returned an unexpected value: {message}")]
    UnexpectedType {
        /// The operation whose result had the wrong type.
        operation: &'static str,
        /// The unexpected value's diagnostic text.
        message: String,
    },
    /// The in-memory fallback failed.
    #[error(transparent)]
    Memory(#[from] MemStoreError),
}

/// An OPFS store that reacquires the worker root and atomically exposes each closed replacement.
#[derive(Clone, Debug)]
pub(crate) struct OpfsStore {
    inner: Arc<OpfsInner>,
}

#[derive(Debug)]
struct OpfsInner {
    namespace: String,
    next_temp: AtomicU64,
}

struct PendingChunk {
    directory: FileSystemDirectoryHandle,
    handle: FileSystemFileHandle,
    temp_name: String,
    final_name: String,
}

impl OpfsStore {
    /// Opens or creates the namespace in the current dedicated worker.
    pub(crate) async fn open(
        _worker: &DedicatedWorkerGlobalScope,
        namespace: impl Into<String>,
    ) -> Result<Self, BrowserStoreError> {
        let namespace = namespace.into();
        validate_namespace(&namespace)?;
        let store = Self {
            inner: Arc::new(OpfsInner {
                namespace,
                next_temp: AtomicU64::new(0),
            }),
        };
        let directory = store.directory(true).await?;
        let probe_name = ".move-probe";
        let probe = file_handle(&directory, probe_name, true)
            .await?
            .expect("create=true always returns a file");
        let move_supported = Reflect::get(probe.as_ref(), &JsValue::from_str("move"))
            .is_ok_and(|value| value.is_function());
        let _ = JsFuture::from(directory.remove_entry(probe_name)).await;
        remove_temporary_entries(&directory).await?;
        if !move_supported {
            return Err(BrowserStoreError::Browser {
                operation: "install OPFS store",
                message: "atomic file moves are unavailable".to_owned(),
            });
        }
        Ok(store)
    }

    async fn directory(
        &self,
        create: bool,
    ) -> Result<FileSystemDirectoryHandle, BrowserStoreError> {
        let scope: DedicatedWorkerGlobalScope = js_sys::global()
            .dyn_into()
            .map_err(|value| type_error("decode worker scope", &value.into()))?;
        let root = JsFuture::from(scope.navigator().storage().get_directory())
            .await
            .map_err(|value| browser_error("open OPFS root", &value))?
            .dyn_into::<FileSystemDirectoryHandle>()
            .map_err(|value| type_error("decode OPFS root", &value))?;
        let app = directory_handle(&root, ROOT, true)
            .await?
            .expect("create=true always returns a directory");
        directory_handle(&app, &self.inner.namespace, create)
            .await?
            .ok_or_else(|| BrowserStoreError::Browser {
                operation: "open store namespace",
                message: "namespace is absent".to_owned(),
            })
    }

    async fn fanout(
        &self,
        hash: &ChunkHash,
        create: bool,
    ) -> Result<Option<FileSystemDirectoryHandle>, BrowserStoreError> {
        let root = self.directory(false).await?;
        directory_handle(&root, &hash.to_string()[..2], create).await
    }

    async fn file(
        &self,
        hash: &ChunkHash,
        create: bool,
    ) -> Result<Option<FileSystemFileHandle>, BrowserStoreError> {
        let Some(dir) = self.fanout(hash, create).await? else {
            return Ok(None);
        };
        file_handle(&dir, &hash.to_string(), create).await
    }

    async fn stage_chunk(
        &self,
        hash: &ChunkHash,
        data: &[u8],
    ) -> Result<PendingChunk, BrowserStoreError> {
        let directory = self
            .fanout(hash, true)
            .await?
            .expect("create=true always returns a directory");
        let final_name = hash.to_string();
        let ticket = self.inner.next_temp.fetch_add(1, Ordering::Relaxed);
        let temp_name = format!(".{hash}.{ticket}.tmp");
        let handle = file_handle(&directory, &temp_name, true)
            .await?
            .expect("create=true always returns a file");
        if let Err(error) = write_file(&handle, data).await {
            let _ = JsFuture::from(directory.remove_entry(&temp_name)).await;
            return Err(error);
        }
        Ok(PendingChunk {
            directory,
            handle,
            temp_name,
            final_name,
        })
    }

    async fn land_chunk(&self, pending: PendingChunk) -> Result<(), BrowserStoreError> {
        if let Err(error) =
            move_file(&pending.handle, &pending.directory, &pending.final_name).await
        {
            let landed_elsewhere = file_handle(&pending.directory, &pending.final_name, false)
                .await?
                .is_some();
            let _ = JsFuture::from(pending.directory.remove_entry(&pending.temp_name)).await;
            if landed_elsewhere {
                return Ok(());
            }
            return Err(error);
        }
        Ok(())
    }
}

impl ChunkStore for OpfsStore {
    type Error = BrowserStoreError;

    async fn write_chunk(&self, hash: &ChunkHash, data: &[u8]) -> Result<(), Self::Error> {
        self.directory(true).await?;
        // `createWritable` keeps changes in a swap file until `close`, preserving the old chunk on interruption.
        if let Some(handle) = self.file(hash, false).await? {
            return write_file(&handle, data).await;
        }
        let pending = self.stage_chunk(hash, data).await?;
        self.land_chunk(pending).await
    }

    async fn read_chunk(&self, hash: &ChunkHash) -> Result<Vec<u8>, Self::Error> {
        let handle = self
            .file(hash, false)
            .await?
            .ok_or(BrowserStoreError::Absent { hash: *hash })?;
        let file = JsFuture::from(handle.get_file())
            .await
            .map_err(|value| browser_error("open chunk file", &value))?
            .dyn_into::<File>()
            .map_err(|value| type_error("decode chunk file", &value))?;
        let buffer = JsFuture::from(file.array_buffer())
            .await
            .map_err(|value| browser_error("read chunk file", &value))?;
        Ok(Uint8Array::new(&buffer).to_vec())
    }

    async fn has_chunk(&self, hash: &ChunkHash) -> Result<bool, Self::Error> {
        Ok(self.file(hash, false).await?.is_some())
    }

    async fn delete_chunk(&self, hash: &ChunkHash) -> Result<(), Self::Error> {
        let Some(dir) = self.fanout(hash, false).await? else {
            return Ok(());
        };
        match JsFuture::from(dir.remove_entry(&hash.to_string())).await {
            Ok(_) => Ok(()),
            Err(value) if is_not_found(&value) => Ok(()),
            Err(value) => Err(browser_error("delete chunk", &value)),
        }
    }
}

impl ChunkInventory for OpfsStore {
    async fn stored_hashes(&self) -> Result<Vec<ChunkHash>, Self::Error> {
        let root = self.directory(false).await?;
        let fanouts = root.keys();
        let mut hashes = Vec::new();
        while let Some(name) = next_key(&fanouts).await? {
            if valid_fanout(&name) {
                collect_hashes(&root, &name, &mut hashes).await?;
            }
        }
        Ok(hashes)
    }
}

fn valid_fanout(name: &str) -> bool {
    name.len() == 2 && name.bytes().all(is_lower_hex)
}

async fn collect_hashes(
    root: &FileSystemDirectoryHandle,
    fanout: &str,
    hashes: &mut Vec<ChunkHash>,
) -> Result<(), BrowserStoreError> {
    let Some(dir) = directory_handle(root, fanout, false).await? else {
        return Ok(());
    };
    let chunks = dir.keys();
    while let Some(chunk) = next_key(&chunks).await? {
        if let Some(hash) = parse_hash(&chunk) {
            hashes.push(hash);
        }
    }
    Ok(())
}

async fn remove_temporary_entries(
    root: &FileSystemDirectoryHandle,
) -> Result<(), BrowserStoreError> {
    let fanouts = root.keys();
    while let Some(name) = next_key(&fanouts).await? {
        if !valid_fanout(&name) {
            continue;
        }
        let Some(directory) = directory_handle(root, &name, false).await? else {
            continue;
        };
        let entries = directory.keys();
        while let Some(entry) = next_key(&entries).await? {
            if temporary_name(&entry) {
                remove_temporary_entry(&directory, &entry).await?;
            }
        }
    }
    Ok(())
}

async fn remove_temporary_entry(
    directory: &FileSystemDirectoryHandle,
    name: &str,
) -> Result<(), BrowserStoreError> {
    match JsFuture::from(directory.remove_entry(name)).await {
        Ok(_) => Ok(()),
        Err(value) if is_not_found(&value) => Ok(()),
        Err(value) => Err(browser_error("remove temporary chunk", &value)),
    }
}

fn temporary_name(name: &str) -> bool {
    let Some((hash, ticket)) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
        .and_then(|name| name.split_once('.'))
    else {
        return false;
    };
    parse_hash(hash).is_some() && ticket.parse::<u64>().is_ok()
}

/// Browser chunk storage with an ephemeral fallback when OPFS is unavailable.
#[derive(Clone, Debug)]
pub struct BrowserStore {
    inner: BrowserStoreInner,
    fallback_memory: bool,
}

#[derive(Clone, Debug)]
enum BrowserStoreInner {
    Opfs(OpfsStore),
    Memory(Arc<MemStore>),
}

impl BrowserStore {
    /// Installs OPFS for `worker` and otherwise creates a fresh memory store.
    ///
    /// # Errors
    ///
    /// [`BrowserStoreError::InvalidNamespace`] when `namespace` cannot name one directory.
    pub async fn install(
        worker: &DedicatedWorkerGlobalScope,
        namespace: impl Into<String>,
    ) -> Result<Self, BrowserStoreError> {
        let namespace = namespace.into();
        validate_namespace(&namespace)?;
        let (inner, fallback_memory) = match OpfsStore::open(worker, namespace).await {
            Ok(store) => (BrowserStoreInner::Opfs(store), false),
            Err(_) => (BrowserStoreInner::Memory(Arc::new(MemStore::new())), true),
        };
        Ok(Self {
            inner,
            fallback_memory,
        })
    }

    /// Removes one persistent namespace and all of its chunks.
    ///
    /// # Errors
    ///
    /// [`BrowserStoreError`] when the namespace is invalid or OPFS removal fails.
    pub async fn remove(
        worker: &DedicatedWorkerGlobalScope,
        namespace: &str,
    ) -> Result<(), BrowserStoreError> {
        validate_namespace(namespace)?;
        remove_namespace(worker, namespace).await
    }

    /// Creates a worker-lifetime memory store.
    #[must_use]
    pub fn ephemeral() -> Self {
        Self {
            inner: BrowserStoreInner::Memory(Arc::new(MemStore::new())),
            fallback_memory: false,
        }
    }

    /// Whether this store survives the worker lifetime.
    #[must_use]
    pub fn is_persistent(&self) -> bool {
        matches!(self.inner, BrowserStoreInner::Opfs(_))
    }
}

impl ChunkStore for BrowserStore {
    type Error = BrowserStoreError;

    fn read_failure_is_ambiguous(&self, error: &Self::Error) -> bool {
        matches!(error, BrowserStoreError::Browser { .. })
            || (self.fallback_memory
                && matches!(
                    error,
                    BrowserStoreError::Memory(MemStoreError::Absent { .. })
                ))
    }

    async fn write_chunk(&self, hash: &ChunkHash, data: &[u8]) -> Result<(), Self::Error> {
        match &self.inner {
            BrowserStoreInner::Opfs(store) => store.write_chunk(hash, data).await,
            BrowserStoreInner::Memory(store) => {
                store.write_chunk(hash, data).await.map_err(Into::into)
            }
        }
    }

    async fn read_chunk(&self, hash: &ChunkHash) -> Result<Vec<u8>, Self::Error> {
        match &self.inner {
            BrowserStoreInner::Opfs(store) => store.read_chunk(hash).await,
            BrowserStoreInner::Memory(store) => store.read_chunk(hash).await.map_err(Into::into),
        }
    }

    async fn has_chunk(&self, hash: &ChunkHash) -> Result<bool, Self::Error> {
        match &self.inner {
            BrowserStoreInner::Opfs(store) => store.has_chunk(hash).await,
            BrowserStoreInner::Memory(store) => store.has_chunk(hash).await.map_err(Into::into),
        }
    }

    async fn delete_chunk(&self, hash: &ChunkHash) -> Result<(), Self::Error> {
        match &self.inner {
            BrowserStoreInner::Opfs(store) => store.delete_chunk(hash).await,
            BrowserStoreInner::Memory(store) => store.delete_chunk(hash).await.map_err(Into::into),
        }
    }
}

impl ChunkInventory for BrowserStore {
    async fn stored_hashes(&self) -> Result<Vec<ChunkHash>, Self::Error> {
        match &self.inner {
            BrowserStoreInner::Opfs(store) => store.stored_hashes().await,
            BrowserStoreInner::Memory(store) => store.stored_hashes().await.map_err(Into::into),
        }
    }
}

async fn remove_namespace(
    worker: &DedicatedWorkerGlobalScope,
    namespace: &str,
) -> Result<(), BrowserStoreError> {
    let root = JsFuture::from(worker.navigator().storage().get_directory())
        .await
        .map_err(|value| browser_error("open OPFS root", &value))?
        .dyn_into::<FileSystemDirectoryHandle>()
        .map_err(|value| type_error("decode OPFS root", &value))?;
    let Some(app) = directory_handle(&root, ROOT, false).await? else {
        return Ok(());
    };
    let options = FileSystemRemoveOptions::new();
    options.set_recursive(true);
    match JsFuture::from(app.remove_entry_with_options(namespace, &options)).await {
        Ok(_) => Ok(()),
        Err(value) if is_not_found(&value) => Ok(()),
        Err(value) => Err(browser_error("remove store namespace", &value)),
    }
}

fn validate_namespace(namespace: &str) -> Result<(), BrowserStoreError> {
    if namespace.is_empty()
        || namespace == "."
        || namespace == ".."
        || namespace.contains(['/', '\\'])
    {
        return Err(BrowserStoreError::InvalidNamespace {
            namespace: namespace.to_owned(),
        });
    }
    Ok(())
}

fn parse_hash(name: &str) -> Option<ChunkHash> {
    let digits = name.as_bytes();
    if digits.len() != 64 || !digits.iter().copied().all(is_lower_hex) {
        return None;
    }
    let (pairs, _) = digits.as_chunks::<2>();
    let mut bytes = [0u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(pairs) {
        *byte = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(ChunkHash::from_bytes(bytes))
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

#[cfg(test)]
mod tests;
