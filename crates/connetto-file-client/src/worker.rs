//! Worker-owned content archiving, outbox management and upload.

use core::fmt::Display;
use std::collections::HashSet;

use connetto_client::{ClientEvent, ConnettoConnection, ExportScope, ImportChoices, ImportOutcome};
use connetto_core::messages::ContentVerb;
use connetto_core::traits::Transport;
use connetto_file_core::{
    ChunkStore, EncryptStoreError, EncryptingStore, FileId, Manifest, MaybeSend,
};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;

use crate::db;
use crate::error::ContentError;
use crate::http::ContentHttp;
use crate::import::{apply_content_import, prepare_content_import, write_import_chunks};
use crate::{ticket, upload};

/// Result of one worker-owned outbox attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentFlush {
    /// One outbox entry was uploaded or permanently retired.
    Progressed,
    /// The entry remains queued for a later retry.
    Deferred,
    /// No entry was queued.
    Empty,
    /// The ticket wait yielded so the worker can serve local work.
    Interrupted,
}

/// Resumable state for worker-owned outbox attempts.
#[derive(Default)]
pub struct ContentFlushState {
    pending_ticket: Option<ticket::PendingTicket>,
    last_attempted: Option<FileId>,
}

impl ContentFlushState {
    /// Whether an interrupted ticket request still awaits its answer.
    #[must_use]
    pub fn is_waiting(&self) -> bool {
        self.pending_ticket.is_some()
    }
}

/// Coupled mutable state for one raw-connection outbox walk.
pub struct FlushCursor<'a, T: Transport> {
    /// The live sync connection.
    pub connection: &'a mut ConnettoConnection<T>,
    /// Ongoing attempt state.
    pub state: &'a mut ContentFlushState,
}

/// The entry to attempt next: one past `last`, wrapping.
///
/// An entry whose ticket keeps being refused stays queued, so always taking
/// the first one would leave every later file waiting on it forever.
fn next_after(waiting: &[FileId], last: Option<FileId>) -> Option<FileId> {
    if waiting.is_empty() {
        return None;
    }
    let next = last
        .and_then(|last| waiting.iter().position(|file| *file == last))
        .map_or(0, |index| (index + 1) % waiting.len());
    waiting.get(next).copied()
}

/// Takes one file out of the outbox and records its loss, in one transaction.
///
/// Split apart, an entry could leave the outbox with nothing recording that
/// this device ever declared the file while an application row still names it.
pub(crate) fn retire(
    conn: &mut diesel::SqliteConnection,
    file_id: FileId,
) -> Result<(), ContentError> {
    conn.transaction(|conn| {
        db::dequeue(conn, file_id)?;
        db::record_retired(conn, file_id)
    })
    .map_err(ContentError::from)
}

/// A worker-owned outbox attempt after its cancel-safe ticket wait.
pub enum ContentFlushStart<B> {
    /// The attempt finished without an HTTP transfer.
    Complete(ContentFlush),
    /// A granted upload can run while the connection owner serves local work.
    Upload(ContentUpload<B>),
}

/// One granted content upload that no longer borrows the sync connection.
pub struct ContentUpload<B> {
    file_id: FileId,
    upload_url: String,
    manifest: Manifest,
    store: B,
    root_key: [u8; 32],
}

enum ManifestStart {
    Ready(Manifest),
    Complete(ContentFlush),
}

impl<B> ContentUpload<B>
where
    B: ChunkStore + Clone + Sync + MaybeSend + 'static,
{
    /// Transfers the granted content over HTTP.
    ///
    /// # Errors
    ///
    /// [`ContentError`] when reading a chunk or completing the HTTP upload fails.
    pub async fn transfer<H: ContentHttp>(&self, http: &H) -> Result<(), ContentError> {
        let store = EncryptingStore::new(self.store.clone(), &self.root_key);
        upload::upload(http, &self.upload_url, &self.manifest, &store).await
    }
}

/// Content archive policy for an owner of a raw sync connection.
pub struct ContentArchive<B> {
    store: B,
    root_key: [u8; 32],
}

impl<B> ContentArchive<B>
where
    B: ChunkStore + Clone + Sync + MaybeSend + 'static,
{
    /// Creates archive policy over one encrypted chunk store.
    #[must_use]
    pub const fn new(store: B, root_key: [u8; 32]) -> Self {
        Self { store, root_key }
    }

    /// Installs content bookkeeping.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the bookkeeping schema cannot be applied.
    pub fn install<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<(), ContentError> {
        connection
            .conn()
            .batch_execute(db::CONTENT_DDL)
            .map_err(Into::into)
    }

    /// Counts content files that have not reached the server.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the outbox cannot be read.
    pub fn pending_files<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<u64, ContentError> {
        db::outbox_count(connection.conn())
    }

    /// Retires outbox entries whose bytes are conclusively unreadable, keeping
    /// each identity in the replica until the application acknowledges it.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when reading the outbox or a manifest fails, or when the dequeue write fails.
    pub async fn verify_unsent<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<Vec<FileId>, ContentError> {
        let waiting = db::outbox(connection.conn())?;
        let mut lost = Vec::new();
        for file_id in waiting {
            let unreadable = match db::load_manifest(connection.conn(), file_id)? {
                Some(manifest) => {
                    unreadable_chunk_count(&self.store, &self.root_key, &manifest).await
                }
                None => Some(0),
            };
            if unreadable.is_some() {
                retire(connection.conn(), file_id)?;
                lost.push(file_id);
            }
        }
        Ok(lost)
    }

    /// Files whose unsent bytes were lost and whose loss is unacknowledged.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the record cannot be read.
    pub fn retired_content<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<Vec<FileId>, ContentError> {
        db::retired(connection.conn())
    }

    /// Drops the losses the application has dealt with.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the record cannot be written.
    pub fn forget_retired_content<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        files: &[FileId],
    ) -> Result<(), ContentError> {
        for file_id in files {
            db::forget_retired(connection.conn(), *file_id)?;
        }
        Ok(())
    }

    /// Attempts one raw-connection outbox entry.
    ///
    /// `cancel` interrupts only the cancel-safe ticket wait. Once an HTTP
    /// upload starts, the attempt and its local dequeue bookkeeping finish
    /// together.
    pub async fn flush_next_or<T, H, C>(
        &self,
        cursor: &mut FlushCursor<'_, T>,
        http: &H,
        cancel: C,
    ) -> (Result<ContentFlush, ContentError>, Vec<ClientEvent>)
    where
        T: Transport,
        T::Error: Display,
        H: ContentHttp,
        C: core::future::Future<Output = ()>,
    {
        let (start, observed) = self
            .begin_flush_next_or(cursor.connection, cursor.state, cancel)
            .await;
        let result = match start {
            Ok(ContentFlushStart::Complete(flush)) => Ok(flush),
            Ok(ContentFlushStart::Upload(upload)) => {
                let result = upload.transfer(http).await;
                self.finish_upload(cursor.connection, &upload, result)
            }
            Err(error) => Err(error),
        };
        (result, observed)
    }

    /// Waits for one upload ticket without retaining the sync connection for the HTTP transfer.
    ///
    /// # Errors
    ///
    /// [`ContentError`] when the outbox, manifest, ticket exchange, or dequeue write fails.
    pub async fn begin_flush_next_or<T, C>(
        &self,
        connection: &mut ConnettoConnection<T>,
        state: &mut ContentFlushState,
        cancel: C,
    ) -> (Result<ContentFlushStart<B>, ContentError>, Vec<ClientEvent>)
    where
        T: Transport,
        T::Error: Display,
        C: core::future::Future<Output = ()>,
    {
        let mut observed = Vec::new();
        let result = self
            .begin_attempt(connection, &mut observed, state, cancel)
            .await;
        (result, observed)
    }

    async fn begin_attempt<T, C>(
        &self,
        connection: &mut ConnettoConnection<T>,
        observed: &mut Vec<ClientEvent>,
        state: &mut ContentFlushState,
        cancel: C,
    ) -> Result<ContentFlushStart<B>, ContentError>
    where
        T: Transport,
        T::Error: Display,
        C: core::future::Future<Output = ()>,
    {
        let Some(file_id) = Self::next_outbox_file(connection, state)? else {
            return Ok(ContentFlushStart::Complete(ContentFlush::Empty));
        };
        let manifest = match Self::load_outbox_manifest(connection, file_id)? {
            ManifestStart::Ready(manifest) => manifest,
            ManifestStart::Complete(flush) => return Ok(ContentFlushStart::Complete(flush)),
        };
        let declared_len = manifest.chunks().iter().map(|chunk| chunk.len).sum();
        let upload_url = match ticket::request_connection_or(
            connection,
            file_id,
            ContentVerb::Write { declared_len },
            observed,
            cancel,
            &mut state.pending_ticket,
        )
        .await
        {
            Ok(Some(url)) => url,
            Ok(None) => return Ok(ContentFlushStart::Complete(ContentFlush::Interrupted)),
            Err(error) => {
                return Self::finish_attempt(connection, file_id, Err(error))
                    .map(ContentFlushStart::Complete);
            }
        };
        Ok(ContentFlushStart::Upload(ContentUpload {
            file_id,
            upload_url,
            manifest,
            store: self.store.clone(),
            root_key: self.root_key,
        }))
    }

    fn next_outbox_file<T: Transport>(
        connection: &mut ConnettoConnection<T>,
        state: &mut ContentFlushState,
    ) -> Result<Option<FileId>, ContentError> {
        let waiting = db::outbox(connection.conn())?;
        if let Some(file_id) = state.pending_ticket.as_ref().map(|ticket| ticket.file_id)
            && waiting.contains(&file_id)
        {
            return Ok(Some(file_id));
        }
        state.pending_ticket = None;
        state.last_attempted = next_after(&waiting, state.last_attempted);
        Ok(state.last_attempted)
    }

    fn load_outbox_manifest<T: Transport>(
        connection: &mut ConnettoConnection<T>,
        file_id: FileId,
    ) -> Result<ManifestStart, ContentError> {
        match db::load_manifest(connection.conn(), file_id) {
            Ok(Some(manifest)) => Ok(ManifestStart::Ready(manifest)),
            Ok(None) => Self::finish_attempt(
                connection,
                file_id,
                Err(ContentError::NoManifest { file_id }),
            )
            .map(ManifestStart::Complete),
            Err(error) => {
                Self::finish_attempt(connection, file_id, Err(error)).map(ManifestStart::Complete)
            }
        }
    }

    /// Finishes local bookkeeping for an HTTP transfer.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the outbox entry cannot be removed.
    pub fn finish_upload<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        upload: &ContentUpload<B>,
        result: Result<(), ContentError>,
    ) -> Result<ContentFlush, ContentError> {
        Self::finish_attempt(connection, upload.file_id, result)
    }

    fn finish_attempt<T: Transport>(
        connection: &mut ConnettoConnection<T>,
        file_id: FileId,
        result: Result<(), ContentError>,
    ) -> Result<ContentFlush, ContentError> {
        match result {
            Err(error) if error.is_retryable() => Ok(ContentFlush::Deferred),
            Ok(()) | Err(_) => {
                db::dequeue(connection.conn(), file_id)?;
                Ok(ContentFlush::Progressed)
            }
        }
    }

    /// Exports unsent content and replica data.
    ///
    /// # Errors
    ///
    /// [`ContentError`] when the outbox, chunk store, or replica export fails.
    pub async fn export_local_data<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        scope: ExportScope,
    ) -> Result<Vec<u8>, ContentError> {
        let manifests = outbox_manifests(connection)?;
        let attachments = content_attachments(&self.store, &self.root_key, &manifests).await?;
        connection
            .export_local_data_with_attachments(scope, &attachments)
            .map_err(Into::into)
    }

    /// Validates and applies content under this device key.
    ///
    /// # Errors
    ///
    /// [`ContentError`] when validation, chunk storage, or replica import fails.
    pub async fn import_local_data<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        bytes: &[u8],
    ) -> Result<(ImportOutcome, usize), ContentError> {
        let plan = prepare_content_import(connection, bytes)?;
        let collisions = plan.replica_plan().collisions().len();
        write_import_chunks(&self.store, &self.root_key, &plan).await?;
        let outcome = apply_content_import(connection, &plan, &ImportChoices::keeping_the_file())?;
        connection.replay_pending().await?;
        Ok((outcome, collisions))
    }
}

pub(crate) fn outbox_manifests<T: Transport>(
    connection: &mut ConnettoConnection<T>,
) -> Result<Vec<Manifest>, ContentError> {
    db::outbox(connection.conn())?
        .into_iter()
        .map(|file_id| {
            db::load_manifest(connection.conn(), file_id)?
                .ok_or(ContentError::NoManifest { file_id })
        })
        .collect()
}

pub(crate) async fn content_attachments<B>(
    store: &B,
    root_key: &[u8; 32],
    manifests: &[Manifest],
) -> Result<Vec<connetto_client::ArchiveAttachment>, ContentError>
where
    B: ChunkStore + Clone + Sync + MaybeSend + 'static,
{
    let store = EncryptingStore::new(store.clone(), root_key);
    let mut seen = HashSet::new();
    let mut chunks = Vec::new();
    for manifest in manifests {
        for chunk in manifest.chunks() {
            if !seen.insert(chunk.hash) {
                continue;
            }
            let bytes = store
                .read_chunk(&chunk.hash)
                .await
                .map_err(|error| ContentError::Store(error.to_string()))?;
            chunks.push((chunk.hash, bytes));
        }
    }
    crate::archive::encode(manifests, chunks)
}

pub(crate) async fn unreadable_chunk_count<B>(
    store: &B,
    root_key: &[u8; 32],
    manifest: &Manifest,
) -> Option<usize>
where
    B: ChunkStore + Clone + Sync + MaybeSend + 'static,
{
    let encrypted = EncryptingStore::new(store.clone(), root_key);
    let mut count = 0;
    let mut ambiguous = false;
    for chunk in manifest.chunks() {
        match encrypted.read_chunk(&chunk.hash).await {
            Ok(_) => {}
            Err(EncryptStoreError::Inner(err)) if store.read_failure_is_ambiguous(&err) => {
                ambiguous = true;
            }
            Err(_) => count += 1,
        }
    }
    (!ambiguous && count > 0).then_some(count)
}

#[cfg(test)]
mod tests {
    use super::{FileId, next_after};

    fn file(byte: u8) -> FileId {
        FileId::from_bytes([byte; 32])
    }

    /// A file that defers on every attempt must not hold up the rest.
    #[test]
    fn a_deferred_entry_hands_the_next_attempt_to_the_next_file() {
        let waiting = [file(1), file(2), file(3)];

        let first = next_after(&waiting, None);
        let second = next_after(&waiting, first);
        let third = next_after(&waiting, second);

        assert_eq!(first, Some(file(1)));
        assert_eq!(second, Some(file(2)));
        assert_eq!(third, Some(file(3)));
        assert_eq!(
            next_after(&waiting, third),
            Some(file(1)),
            "the walk wraps rather than ending"
        );
    }

    /// The uploaded file leaves the outbox, so the cursor no longer names a row.
    #[test]
    fn a_cursor_past_a_dequeued_file_restarts_the_walk() {
        assert_eq!(
            next_after(&[file(2), file(3)], Some(file(1))),
            Some(file(2))
        );
        assert_eq!(next_after(&[], Some(file(1))), None);
    }
}
