//! The content resolver and the local sources it asks.
//!
//! Display is not sync (chapter 18): the common case answers a short-lived
//! signed URL and never touches the chunk store. Local bytes are the answer in
//! two of the three cases that chapter names, unsent content and pinned
//! content, and the third, a locally processed input, is a direct
//! [`bytes`](crate::ContentClient::bytes) call rather than a display decision.

use core::pin::Pin;

use connetto_file_core::{ChunkStore, Manifest, reassemble};

use crate::error::ContentError;

/// A boxed future from a local source, `Send` wherever the platform has
/// threads, exactly as `connetto-file-core` treats its own futures.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub type SourceFuture<'a, O> = Pin<Box<dyn Future<Output = O> + Send + 'a>>;

/// A boxed future from a local source.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub type SourceFuture<'a, O> = Pin<Box<dyn Future<Output = O> + 'a>>;

/// A local source the resolver owns, `Send` and `Sync` wherever the platform
/// has threads: the resolver holds one across every await while it asks.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub type BoxedSource = Box<dyn LocalContentSource + Send + Sync>;

/// A local source the resolver owns.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub type BoxedSource = Box<dyn LocalContentSource>;

/// A place this device can read a file's bytes from without a server.
///
/// The resolver holds an ordered list and asks each in turn, so a further
/// source is registered rather than folded into the resolver's own decisions.
/// R25's design names the two that follow: chunks fetched from a peer, and a
/// pull from a peer that is present right now (R79).
pub trait LocalContentSource {
    /// A short name for this source, carried on the answer so a caller can
    /// tell where bytes came from.
    fn name(&self) -> &'static str;

    /// Serves the bytes `manifest` describes.
    ///
    /// `Ok(None)` means this source does not hold them, which is ordinary and
    /// moves the resolver to the next source. An error means it should have
    /// and could not.
    fn bytes<'a>(
        &'a self,
        manifest: &'a Manifest,
    ) -> SourceFuture<'a, Result<Option<Vec<u8>>, ContentError>>;
}

/// The local chunk store as a content source.
///
/// Every chunk is probed before any is read, so a partially present manifest
/// answers "not here" rather than failing halfway through a reassembly.
pub struct ChunkStoreSource<S: ChunkStore> {
    store: S,
}

impl<S: ChunkStore> ChunkStoreSource<S> {
    /// Wraps a chunk store as a source.
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S: ChunkStore + Sync> LocalContentSource for ChunkStoreSource<S> {
    fn name(&self) -> &'static str {
        "chunk store"
    }

    fn bytes<'a>(
        &'a self,
        manifest: &'a Manifest,
    ) -> SourceFuture<'a, Result<Option<Vec<u8>>, ContentError>> {
        Box::pin(async move {
            for chunk in manifest.chunks() {
                let held = self
                    .store
                    .has_chunk(&chunk.hash)
                    .await
                    .map_err(|err| ContentError::Store(err.to_string()))?;
                if !held {
                    return Ok(None);
                }
            }
            reassemble(manifest, &self.store)
                .await
                .map(Some)
                .map_err(|err| ContentError::Store(err.to_string()))
        })
    }
}

/// Where a file's bytes are to be had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// Bytes are here now, and which source served them.
    Local {
        /// The source that answered.
        source: &'static str,
        /// The file's bytes.
        bytes: Vec<u8>,
    },
    /// A short-lived signed URL. The ticket is inside it, so an `img` tag or a
    /// media element can fetch it directly, with `Range` and caching working
    /// as they do for any other URL.
    Remote {
        /// The granted address.
        url: String,
    },
    /// Nothing local holds the bytes and no server can be asked for them.
    ///
    /// The metadata row's own `content_state` is the other half of this
    /// answer, and the half that says whether the bytes exist anywhere yet.
    /// This resolver never reads that column: it lives on the application's
    /// table, whose shape the client does not know and which the file server
    /// reaches only through `connetto_set_content_state`.
    Unavailable,
}
