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

/// Resumable position of an integrity scan over one file's chunks.
///
/// A scan is bound to the file and the chunk list it was taken over, so a cursor offered
/// for another file, or for a manifest that has since been replaced, starts again.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChunkScan {
    file: Option<FileId>,
    chunks: u64,
    next: usize,
    missing: Option<usize>,
    ambiguous: bool,
}

impl ChunkScan {
    /// Whether this scan has yet to read a chunk.
    #[must_use]
    pub const fn is_fresh(&self) -> bool {
        self.next == 0
    }
}

/// What one budgeted integrity scan concluded.
#[derive(Debug, Clone, Copy)]
pub enum ScanStep {
    /// Chunks remain, to be scanned from this position.
    More(ChunkScan),
    /// Every chunk read, so the entry stays queued.
    Intact,
    /// Bytes are conclusively gone, so the entry was retired.
    Retired,
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

    /// Lists the files waiting in the outbox, in queue order.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the outbox cannot be read.
    pub fn unsent_files<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<Vec<FileId>, ContentError> {
        db::outbox(connection.conn())
    }

    /// Sums the distinct bytes the unsent files name, which is what an export of them carries.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the outbox or a manifest cannot be read, and
    /// [`ContentError::NoManifest`] when an outbox entry names no manifest.
    pub fn unsent_content_bytes<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<u64, ContentError> {
        let mut seen = HashSet::new();
        let mut total = 0;
        for manifest in outbox_manifests(connection)? {
            for chunk in manifest.chunks() {
                if seen.insert(chunk.hash) {
                    total += chunk.len;
                }
            }
        }
        Ok(total)
    }

    /// Checks up to `budget` of one outbox entry's chunks, resuming from `scan`.
    ///
    /// A caller drives this with a small budget so a file naming many chunks cannot hold
    /// its turn: the decision waits until every chunk has been read, because an ambiguous
    /// read anywhere keeps the entry.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when reading the manifest fails, or when the dequeue write fails.
    pub async fn scan_unsent_file<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        file_id: FileId,
        scan: ChunkScan,
        budget: usize,
    ) -> Result<ScanStep, ContentError> {
        let Some(manifest) = db::load_manifest(connection.conn(), file_id)? else {
            retire(connection.conn(), file_id)?;
            return Ok(ScanStep::Retired);
        };
        let chunks = manifest.chunks();
        // A replacement manifest can name other chunks under the same file identity, so the
        // cursor is bound to the list it was taken over rather than to its length.
        let fingerprint = chunk_fingerprint(chunks);
        let mut scan = if scan.file == Some(file_id) && scan.chunks == fingerprint {
            scan
        } else {
            ChunkScan {
                file: Some(file_id),
                chunks: fingerprint,
                ..ChunkScan::default()
            }
        };
        let encrypted = EncryptingStore::new(self.store.clone(), &self.root_key);
        let stop = scan.next.saturating_add(budget.max(1)).min(chunks.len());
        while scan.next < stop {
            match encrypted.read_chunk(&chunks[scan.next].hash).await {
                Ok(_) => {}
                Err(EncryptStoreError::Inner(err))
                    if self.store.read_failure_is_ambiguous(&err) =>
                {
                    scan.ambiguous = true;
                }
                Err(_) => scan.missing = scan.missing.or(Some(scan.next)),
            }
            scan.next += 1;
        }
        if scan.next < chunks.len() {
            return Ok(ScanStep::More(scan));
        }
        let (false, Some(missing)) = (scan.ambiguous, scan.missing) else {
            return Ok(ScanStep::Intact);
        };
        // A restore can land between slices, so the decision rests on a fresh read rather
        // than on what an earlier slice saw.
        if encrypted.read_chunk(&chunks[missing].hash).await.is_ok() {
            return Ok(ScanStep::More(ChunkScan {
                file: Some(file_id),
                chunks: fingerprint,
                ..ChunkScan::default()
            }));
        }
        retire(connection.conn(), file_id)?;
        Ok(ScanStep::Retired)
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
        let mut lost = Vec::new();
        for file_id in self.unsent_files(connection)? {
            let mut scan = ChunkScan::default();
            loop {
                match self
                    .scan_unsent_file(connection, file_id, scan, usize::MAX)
                    .await?
                {
                    ScanStep::More(next) => scan = next,
                    ScanStep::Retired => {
                        lost.push(file_id);
                        break;
                    }
                    ScanStep::Intact => break,
                }
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
        let mut cursor = FlushCursor { connection, state };
        let result = self.begin_attempt(&mut cursor, &mut observed, cancel).await;
        (result, observed)
    }

    async fn begin_attempt<T, C>(
        &self,
        cursor: &mut FlushCursor<'_, T>,
        observed: &mut Vec<ClientEvent>,
        cancel: C,
    ) -> Result<ContentFlushStart<B>, ContentError>
    where
        T: Transport,
        T::Error: Display,
        C: core::future::Future<Output = ()>,
    {
        let Some(file_id) = Self::next_outbox_file(cursor.connection, cursor.state)? else {
            return Ok(ContentFlushStart::Complete(ContentFlush::Empty));
        };
        let manifest = match Self::load_outbox_manifest(cursor.connection, file_id)? {
            ManifestStart::Ready(manifest) => manifest,
            ManifestStart::Complete(flush) => return Ok(ContentFlushStart::Complete(flush)),
        };
        let declared_len = manifest.chunks().iter().map(|chunk| chunk.len).sum();
        let upload_url = match ticket::request_connection_or(
            cursor.connection,
            file_id,
            ContentVerb::Write { declared_len },
            observed,
            cancel,
            &mut cursor.state.pending_ticket,
        )
        .await
        {
            Ok(Some(url)) => url,
            Ok(None) => return Ok(ContentFlushStart::Complete(ContentFlush::Interrupted)),
            Err(error) => {
                return Self::finish_attempt(cursor.connection, file_id, Err(error))
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
        // The import is committed, so a failed replay is left to the outbox driver.
        let _ = connection.replay_pending().await;
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

/// Fingerprints the ordered chunk list, so a replaced manifest is never resumed into.
///
/// `FNV-1a` over each chunk hash and length, which needs to separate lists rather than
/// resist an adversary.
fn chunk_fingerprint(chunks: &[connetto_file_core::ChunkMeta]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |byte: u8| {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    };
    for chunk in chunks {
        for byte in chunk.hash.as_bytes() {
            mix(*byte);
        }
        for byte in chunk.len.to_le_bytes() {
            mix(byte);
        }
    }
    hash
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

    /// A manifest replaced under the same identity is scanned from the start, even when the
    /// replacement names the same number of chunks.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_replaced_manifest_restarts_the_scan() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{ChunkStore, EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("replace"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        let present = process_file(&vec![4u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the readable file chunks");
        let replacement = process_file(&vec![5u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the replacement chunks");
        encrypted
            .delete_chunk(&replacement.chunks()[0].hash)
            .await
            .expect("drop the replacement chunk");
        assert_eq!(
            present.chunks().len(),
            replacement.chunks().len(),
            "the replacement must be the same length to exercise the fingerprint"
        );

        db::put_manifest(connection.conn(), &present).expect("record the manifest");
        db::enqueue(connection.conn(), present.file_id()).expect("queue the file");
        let past_the_chunk = match archive
            .scan_unsent_file(
                &mut connection,
                present.file_id(),
                super::ChunkScan::default(),
                8,
            )
            .await
            .expect("the readable file scans")
        {
            super::ScanStep::Intact => super::ChunkScan {
                file: Some(present.file_id()),
                chunks: super::chunk_fingerprint(present.chunks()),
                next: present.chunks().len(),
                missing: None,
                ambiguous: false,
            },
            other => panic!("a readable file stays queued, got {other:?}"),
        };

        // The same identity now names other chunks, one of which is gone.
        db::drop_manifest(connection.conn(), present.file_id()).expect("drop the manifest");
        let swapped =
            connetto_file_core::Manifest::new(present.file_id(), replacement.chunks().to_vec());
        db::put_manifest(connection.conn(), &swapped).expect("record the replacement");

        let step = archive
            .scan_unsent_file(&mut connection, present.file_id(), past_the_chunk, 8)
            .await
            .expect("the replacement scans");
        assert!(
            matches!(step, super::ScanStep::Retired),
            "a cursor from the old chunk list must not skip the new one, got {step:?}"
        );
    }

    /// A restore landing between slices keeps the entry, because an import can put back
    /// the very chunk an earlier slice found missing.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_chunk_restored_mid_scan_keeps_the_entry() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{ChunkStore, EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("restore"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        let bytes = vec![7u8; 33 * 1024 * 1024];
        let manifest = process_file(&bytes, MimeClass::Jpeg, &encrypted)
            .await
            .expect("the bytes chunk");
        let first_hash = manifest.chunks()[0].hash;
        let chunk = encrypted
            .read_chunk(&first_hash)
            .await
            .expect("read the first chunk");
        encrypted
            .delete_chunk(&first_hash)
            .await
            .expect("drop the first chunk");
        db::put_manifest(connection.conn(), &manifest).expect("record the manifest");
        db::enqueue(connection.conn(), manifest.file_id()).expect("queue the file");

        let mut scan = super::ChunkScan::default();
        for _ in 0..manifest.chunks().len() - 1 {
            match archive
                .scan_unsent_file(&mut connection, manifest.file_id(), scan, 1)
                .await
                .expect("each slice scans")
            {
                super::ScanStep::More(next) => scan = next,
                other => panic!("the scan cannot conclude before its last chunk: {other:?}"),
            }
        }
        // The import lands between slices, putting the missing bytes back.
        encrypted
            .write_chunk(&first_hash, &chunk)
            .await
            .expect("restore the first chunk");

        let mut step = archive
            .scan_unsent_file(&mut connection, manifest.file_id(), scan, 1)
            .await
            .expect("the last slice scans");
        while let super::ScanStep::More(next) = step {
            step = archive
                .scan_unsent_file(&mut connection, manifest.file_id(), next, 8)
                .await
                .expect("the restarted scan runs");
        }
        assert!(
            matches!(step, super::ScanStep::Intact),
            "restored bytes must keep the entry, got {step:?}"
        );
        assert_eq!(
            db::outbox(connection.conn()).expect("read the outbox"),
            vec![manifest.file_id()],
            "and the file is still queued to upload"
        );
    }

    /// A cursor belongs to the file it was taken over, so one offered for another file
    /// reads that file's chunks from the start rather than skipping them.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_cursor_from_another_file_does_not_skip_chunks() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{ChunkStore, EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("cursor"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        let elsewhere = process_file(&vec![1u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the other file chunks");
        let manifest = process_file(&vec![2u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("this file chunks");
        encrypted
            .delete_chunk(&manifest.chunks()[0].hash)
            .await
            .expect("drop the only chunk");
        db::put_manifest(connection.conn(), &manifest).expect("record the manifest");
        db::enqueue(connection.conn(), manifest.file_id()).expect("queue the file");

        let foreign = match archive
            .scan_unsent_file(
                &mut connection,
                elsewhere.file_id(),
                super::ChunkScan::default(),
                8,
            )
            .await
            .expect("the other file scans")
        {
            super::ScanStep::More(scan) => scan,
            _ => super::ChunkScan {
                file: Some(elsewhere.file_id()),
                chunks: super::chunk_fingerprint(elsewhere.chunks()),
                next: elsewhere.chunks().len(),
                missing: None,
                ambiguous: false,
            },
        };

        let step = archive
            .scan_unsent_file(&mut connection, manifest.file_id(), foreign, 8)
            .await
            .expect("this file scans");
        assert!(
            matches!(step, super::ScanStep::Retired),
            "a foreign cursor must not pass an unreadable chunk off as read, got {step:?}"
        );
    }

    /// An export of the unsent files carries their distinct chunk bytes, which is the
    /// total the browser buffering guard compares against.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn the_unsent_total_counts_each_chunk_once() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("total"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");
        assert_eq!(
            archive
                .unsent_content_bytes(&mut connection)
                .expect("an empty outbox sums to nothing"),
            0
        );

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        let bytes = vec![3u8; 1024];
        let manifest = process_file(&bytes, MimeClass::Jpeg, &encrypted)
            .await
            .expect("the bytes chunk");
        db::put_manifest(connection.conn(), &manifest).expect("record the manifest");
        db::enqueue(connection.conn(), manifest.file_id()).expect("queue the file");
        // The same bytes chunk to the same hashes, so a second entry adds nothing.
        db::enqueue(connection.conn(), manifest.file_id()).expect("queue it again");

        assert_eq!(
            archive
                .unsent_content_bytes(&mut connection)
                .expect("the outbox sums"),
            u64::try_from(bytes.len()).expect("a small length"),
            "each distinct chunk counts once"
        );
    }

    /// A chunk lost in a later slice still retires the entry, so the accumulation a
    /// budgeted scan carries across turns has to survive the resume.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_resumed_scan_retires_a_file_whose_last_chunk_is_gone() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{ChunkStore, EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("scan"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        // Fixed 16 MiB slabs, so the chunk count is exactly three rather than content defined.
        let bytes = vec![7u8; 33 * 1024 * 1024];
        let manifest = process_file(&bytes, MimeClass::Jpeg, &encrypted)
            .await
            .expect("the bytes chunk");
        assert_eq!(
            manifest.chunks().len(),
            3,
            "the test needs more chunks than one slice"
        );
        let last = manifest.chunks().last().expect("a chunk").hash;
        encrypted
            .delete_chunk(&last)
            .await
            .expect("drop the last chunk");
        db::put_manifest(connection.conn(), &manifest).expect("record the manifest");
        db::enqueue(connection.conn(), manifest.file_id()).expect("queue the file");

        let mut scan = super::ChunkScan::default();
        let step = archive
            .scan_unsent_file(&mut connection, manifest.file_id(), scan, 1)
            .await
            .expect("the first slice scans");
        let super::ScanStep::More(next) = step else {
            panic!("a multi-chunk file cannot conclude in one slice of one chunk");
        };
        scan = next;

        loop {
            match archive
                .scan_unsent_file(&mut connection, manifest.file_id(), scan, 1)
                .await
                .expect("each slice scans")
            {
                super::ScanStep::More(next) => scan = next,
                super::ScanStep::Retired => break,
                super::ScanStep::Intact => panic!("the missing last chunk must retire the entry"),
            }
        }
        assert!(
            db::outbox(connection.conn())
                .expect("read the outbox")
                .is_empty(),
            "a retired entry leaves the outbox"
        );
    }
}
