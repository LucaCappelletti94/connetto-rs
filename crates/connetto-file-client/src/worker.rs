//! Worker-owned content archiving, outbox management and upload.

use core::fmt::Display;
use std::collections::HashSet;
use std::io::Read;

use connetto_client::{ClientEvent, ConnettoConnection, ExportScope, ImportChoices, ImportOutcome};
use connetto_core::messages::ContentVerb;
use connetto_core::traits::Transport;
use connetto_file_core::{
    ChunkHash, ChunkStore, EncryptStoreError, EncryptingStore, FileId, Manifest, MaybeSend,
    MimeClass, process_file_from_reader,
};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;

use crate::db;
use crate::error::{AttemptOutcome, ContentError, StageCommitError};
use crate::http::ContentHttp;
use crate::import::{apply_content_import, prepare_content_import, write_import_chunks};
use crate::resolve::{ChunkStoreSource, LocalContentSource, Resolved};
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
/// A heal entry leaves quietly, since a cache copy lost is no authored data lost.
pub(crate) fn retire(
    conn: &mut diesel::SqliteConnection,
    file_id: FileId,
) -> Result<(), ContentError> {
    conn.transaction(|conn| {
        let heal = db::is_heal(conn, file_id)?;
        db::dequeue(conn, file_id)?;
        if heal {
            return Ok(());
        }
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

/// The decision of a [`ContentArchive::start_resolve_connection`] at the
/// moment it was asked.
pub enum ResolveStart {
    /// The answer is already in hand: the local store had the bytes, or the
    /// connection cannot ask the server.
    Answered(Resolved),
    /// The read-ticket request is in flight; pumped events settle it through
    /// [`PendingConnectionResolve::route`].
    Waiting(PendingConnectionResolve),
}

/// A connection resolve whose ticket request is in flight.
///
/// Opaque: the caller keeps it beside its own request bookkeeping until
/// routing an event settles the wait.
pub struct PendingConnectionResolve {
    ticket: ticket::PendingTicket,
}

impl PendingConnectionResolve {
    /// What one pumped upstream event has to say about this waiting resolve.
    ///
    /// `Settled` ends the wait; `Err` means answer
    /// [`Resolved::Unavailable`]. `Other` leaves the event to the caller's
    /// own handling, the same events [`resolve_connection`](ContentArchive::resolve_connection)
    /// returns as observed.
    pub fn route(&self, event: &ClientEvent) -> ResolveRoute {
        match ticket::route_connection_event(&self.ticket, event) {
            ticket::RouteAnswer::Settled(result) => ResolveRoute::Settled(result),
            ticket::RouteAnswer::Other => ResolveRoute::Other,
        }
    }
}

/// What routing one pumped event did to a waiting resolve.
pub enum ResolveRoute {
    /// The wait ends. `Ok(url)` is the granted read; `Err` means answer
    /// [`Resolved::Unavailable`] and log.
    Settled(Result<String, ContentError>),
    /// The event belongs to something else; the caller still owns it.
    Other,
}

/// Content archive policy for an owner of a raw sync connection.
pub struct ContentArchive<B> {
    store: B,
    root_key: [u8; 32],
    heal_queries: Vec<(String, String)>,
}

impl<B> ContentArchive<B>
where
    B: ChunkStore + Clone + Sync + MaybeSend + 'static,
{
    /// Creates archive policy over one encrypted chunk store.
    #[must_use]
    pub const fn new(store: B, root_key: [u8; 32]) -> Self {
        Self {
            store,
            root_key,
            heal_queries: Vec::new(),
        }
    }

    /// Adds a query naming, in `file_id_column`, files the server marked lost, as
    /// [`ContentClient::heal_lost`](crate::ContentClient::heal_lost) does natively.
    #[must_use]
    pub fn with_heal_lost(mut self, query: &str, file_id_column: &str) -> Self {
        self.heal_queries
            .push((query.to_owned(), file_id_column.to_owned()));
        self
    }

    /// Whether any heal query is registered, so a row change is worth a [`queue_lost`](Self::queue_lost).
    #[must_use]
    pub fn heals_lost(&self) -> bool {
        !self.heal_queries.is_empty()
    }

    /// Installs content bookkeeping and checks every heal query answers its column.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the bookkeeping schema cannot be applied, and
    /// [`ContentError::HealColumnMissing`] when a heal query does not return its column.
    pub fn install<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<(), ContentError> {
        let conn = connection.conn();
        conn.batch_execute(db::CONTENT_DDL)?;
        db::add_outbox_columns(conn)?;
        for (query, column) in &self.heal_queries {
            if !crate::retain::answers_column(conn, query, column) {
                return Err(ContentError::HealColumnMissing {
                    query: query.clone(),
                    column: column.clone(),
                });
            }
        }
        Ok(())
    }

    /// Puts back in the outbox every file a heal query names that this device holds.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when a query or the bookkeeping cannot be read or written.
    pub fn queue_lost<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<Vec<FileId>, ContentError> {
        crate::retain::queue_lost(connection.conn(), &self.heal_queries)
    }

    /// Keeps the files `query` names in `file_id_column` on this device under `name`, as
    /// [`ContentClient::pin_content`](crate::ContentClient::pin_content) does natively.
    ///
    /// # Errors
    ///
    /// [`ContentError::PinColumnMissing`] when the query does not return the named column,
    /// and [`ContentError::Replica`] when the record cannot be written.
    pub fn pin_content<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        name: &str,
        query: &str,
        file_id_column: &str,
    ) -> Result<(), ContentError> {
        if !crate::retain::answers_column(connection.conn(), query, file_id_column) {
            return Err(ContentError::PinColumnMissing {
                name: name.to_owned(),
                column: file_id_column.to_owned(),
            });
        }
        connection
            .transact_with_bookkeeping(
                |c| db::put_pin(c, name, query, file_id_column).map_err(ContentError::Replica),
                |_| Ok::<(), ContentError>(()),
            )
            .map(|_| ())
    }

    /// Ends the pin under `name`. Unknown names are a no-op.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the record cannot be removed.
    pub fn unpin_content<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        name: &str,
    ) -> Result<(), ContentError> {
        connection
            .transact_with_bookkeeping(
                |c| db::drop_pin(c, name),
                |_| Ok::<(), diesel::result::Error>(()),
            )
            .map(|_| ())
            .map_err(ContentError::Replica)
    }

    /// Every content pin, as name, query and file-id column, in name order.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the records cannot be read.
    pub fn content_pins<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<Vec<(String, String, String)>, ContentError> {
        db::pins(connection.conn()).map_err(ContentError::Replica)
    }

    /// Chunks one file into the encrypted store without touching the replica.
    ///
    /// The slow half of staging a file, so a hub can keep serving local work
    /// while a large file is split. [`commit_staged`](Self::commit_staged)
    /// closes the pair in one transaction. The identity inside the returned
    /// manifest is what the bytes hash to, and it is the only identity the
    /// chunks can ever be served under.
    ///
    /// # Errors
    ///
    /// [`ContentError::Store`] when reading the bytes or writing a chunk fails.
    pub async fn chunk_file<R>(&self, reader: R, mime: MimeClass) -> Result<Manifest, ContentError>
    where
        R: Read + MaybeSend,
    {
        let store = EncryptingStore::new_with(
            self.store.clone(),
            &self.root_key,
            mime.params().skip_compression,
        );
        process_file_from_reader(reader, mime, &store)
            .await
            .map_err(|err| ContentError::Store(err.to_string()))
    }

    /// Commits staged content and the row that names it as one transaction.
    ///
    /// The raw-connection shape of [`ContentClient::stage`](crate::ContentClient::stage):
    /// the manifest and its outbox entry are recorded with capture suspended,
    /// and `row` then runs with capture live, so the row syncs as part of the
    /// same mutation and the upload leg sees the queued entry. `row` receives
    /// the identity the chunked bytes hash to; a caller told an identity
    /// elsewhere compares it here, because bytes that hash to something else
    /// can never be served under the declared one.
    ///
    /// # Errors
    ///
    /// Anything `row` returns, or [`StageCommitError::Bookkeeping`] when the
    /// manifest or outbox write fails. Either way nothing committed, and the
    /// chunks stand until the next orphan sweep.
    pub fn commit_staged<T, F, O>(
        &self,
        connection: &mut ConnettoConnection<T>,
        manifest: &Manifest,
        row: F,
    ) -> Result<O, StageCommitError>
    where
        T: Transport,
        F: FnOnce(&mut SqliteConnection, FileId) -> Result<O, StageCommitError>,
    {
        let file_id = manifest.file_id();
        connection
            .transact_with_bookkeeping(
                |conn| {
                    db::put_manifest(conn, manifest)?;
                    db::enqueue(conn, file_id)?;
                    Ok(())
                },
                |conn| row(conn, file_id),
            )
            .map(|((), outcome)| outcome)
    }

    /// The answer about this file's bytes this device can give on its own.
    ///
    /// The shape of [`ContentClient`](crate::ContentClient)'s own local
    /// answer: unsent content answers from the chunk store or nowhere, pinned
    /// content prefers what the pin paid to keep, and anything else answers
    /// `None`, which means only a server knows.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] on a bookkeeping read failure.
    pub async fn resolve_local<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        file_id: FileId,
    ) -> Result<Option<Resolved>, ContentError> {
        let Some(manifest) = db::load_manifest(connection.conn(), file_id)? else {
            return Ok(None);
        };
        let source =
            ChunkStoreSource::new(EncryptingStore::new(self.store.clone(), &self.root_key));
        if db::is_unsent(connection.conn(), file_id)? {
            return Ok(Some(match source.bytes(&manifest).await? {
                Some(bytes) => Resolved::Local {
                    source: source.name(),
                    bytes,
                },
                None => Resolved::Unavailable,
            }));
        }
        if !crate::retain::pinned_ids(connection.conn())?.contains(&file_id) {
            return Ok(None);
        }
        Ok(source.bytes(&manifest).await?.map(|bytes| Resolved::Local {
            source: source.name(),
            bytes,
        }))
    }

    /// Where this file's bytes are to be had, answering the way the owning
    /// client would, for a hub that serves resolution questions for others.
    ///
    /// [`resolve_local`](Self::resolve_local) first, then the server for
    /// anything local sources cannot answer, exactly as
    /// [`ContentClient::resolve`](crate::ContentClient::resolve) does. A
    /// `cancel` that fires, a server refusal and an offline connection all
    /// answer [`Resolved::Unavailable`], because the question deserves an
    /// answer rather than a wait. Events pumped while the ticket round trip
    /// runs come back in the returned vector for the caller to re-apply; a
    /// cancelled wait re-applies them without an answer.
    ///
    /// There is no error to handle. A bookkeeping failure, a server refusal,
    /// a transport failure and a cancelled wait all answer
    /// [`Resolved::Unavailable`], the only answer better than no answer.
    pub async fn resolve_connection<T, C>(
        &self,
        connection: &mut ConnettoConnection<T>,
        file_id: FileId,
        cancel: C,
    ) -> (Resolved, Vec<ClientEvent>)
    where
        T: Transport,
        T::Error: Display,
        C: core::future::Future<Output = ()>,
    {
        let mut observed = Vec::new();
        match self
            .answer_connection(connection, file_id, cancel, &mut observed)
            .await
        {
            Ok(answer) => (answer, observed),
            Err(_) => (Resolved::Unavailable, observed),
        }
    }

    /// Starts a connection resolve without waiting for the server.
    ///
    /// [`resolve_local`](Self::resolve_local) answers first and
    /// `Answered(Resolved::Unavailable)` follows when the connection cannot
    /// ask; otherwise the read-ticket request goes out and the handle comes
    /// back in `Waiting`, to be settled event by event with
    /// [`route`](PendingConnectionResolve::route). This is the shape
    /// a hub that must keep serving its queue uses instead of
    /// [`resolve_connection`](Self::resolve_connection), which holds a task
    /// parked until the answer or the cancel.
    ///
    /// # Errors
    ///
    /// A replica read failure or a transport failure on the way to sending
    /// the ticket request is returned. Nothing else is an error: a refusal
    /// and a closed link both answer through the routed events.
    ///
    /// # Panics
    ///
    /// Never. A request that reports success always leaves its handle
    /// behind, and the handle is what the returned waiting state carries.
    pub async fn start_resolve_connection<T>(
        &self,
        connection: &mut ConnettoConnection<T>,
        file_id: FileId,
    ) -> Result<ResolveStart, ContentError>
    where
        T: Transport,
        T::Error: Display,
    {
        if let Some(answer) = self.resolve_local(connection, file_id).await? {
            return Ok(ResolveStart::Answered(answer));
        }
        if !connection.is_connected() {
            return Ok(ResolveStart::Answered(Resolved::Unavailable));
        }
        let mut pending = None;
        ticket::ensure_pending_request(connection, file_id, ContentVerb::Read, &mut pending)
            .await?;
        let ticket = pending.expect("a sent request leaves its handle behind");
        Ok(ResolveStart::Waiting(PendingConnectionResolve { ticket }))
    }

    async fn answer_connection<T, C>(
        &self,
        connection: &mut ConnettoConnection<T>,
        file_id: FileId,
        cancel: C,
        observed: &mut Vec<ClientEvent>,
    ) -> Result<Resolved, ContentError>
    where
        T: Transport,
        T::Error: Display,
        C: core::future::Future<Output = ()>,
    {
        if let Some(answer) = self.resolve_local(connection, file_id).await? {
            return Ok(answer);
        }
        if !connection.is_connected() {
            return Ok(Resolved::Unavailable);
        }
        let mut pending = None;
        let url = ticket::request_connection_or(
            connection,
            file_id,
            ContentVerb::Read,
            observed,
            cancel,
            &mut pending,
        )
        .await?;
        Ok(match url {
            Some(url) => Resolved::Remote { url },
            None => Resolved::Unavailable,
        })
    }

    /// Counts files authored here that have not reached the server.
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

    /// Counts content files that are sendable: in the outbox and not permanently refused.
    ///
    /// The outbox driver schedules walks from this count rather than from
    /// [`pending_files`](Self::pending_files), so a refused entry never triggers a walk,
    /// and a queued heal entry does.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the outbox cannot be read.
    pub fn sendable_files<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<u64, ContentError> {
        db::sendable_count(connection.conn())
    }

    /// Lists the files authored here that wait in the outbox, in queue order.
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

    /// Drops every manifest no pin covers and whose file is no longer unsent, answering
    /// how many went.
    ///
    /// The chunks follow through the orphan sweep, because a dropped manifest is what
    /// makes them unreferenced. This is the policy the page-side tidy pass applies, and
    /// the worker needs it too: without it a device keeps every file it ever uploaded.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when a pin, a pin query or a manifest cannot be read, or
    /// when the eviction write fails.
    pub fn evict_uncovered<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<usize, ContentError> {
        let pinned = crate::retain::pinned_ids(connection.conn())?;
        crate::retain::evict_uncovered(connection.conn(), &pinned)
    }

    /// Lists the chunks the store holds that no manifest references.
    ///
    /// An import or a stage lands chunks before the transaction that records their
    /// manifest, so a failure in between leaves bytes nothing will ever name. Asking the
    /// replica what is referenced rather than what was released is what sees those.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the referenced set cannot be read, and
    /// [`ContentError::Store`] when the store cannot be listed.
    pub async fn orphan_chunks<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<Vec<ChunkHash>, ContentError>
    where
        B: connetto_file_core::ChunkInventory,
    {
        let referenced = db::referenced_hashes(connection.conn())?;
        let held = self
            .store
            .stored_hashes()
            .await
            .map_err(|error| ContentError::Store(error.to_string()))?;
        Ok(held
            .into_iter()
            .filter(|hash| !referenced.contains(hash))
            .collect())
    }

    /// Deletes one listed orphan, unless a manifest has come to name it since.
    ///
    /// A caller holding a long orphan list deletes a few per turn, so a crowded store
    /// cannot hold the turn, and an import landing in between can reference a listed
    /// chunk, so the reference is checked here rather than trusted from the list.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the reference cannot be read, and
    /// [`ContentError::Store`] when the delete fails.
    pub async fn discard_chunk<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        hash: &ChunkHash,
    ) -> Result<(), ContentError> {
        if db::hash_is_referenced(connection.conn(), hash)? {
            return Ok(());
        }
        self.store
            .delete_chunk(hash)
            .await
            .map_err(|error| ContentError::Store(error.to_string()))
    }

    /// Deletes every chunk no manifest references, answering how many went.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the referenced set cannot be read, and
    /// [`ContentError::Store`] when the store cannot be listed or a delete fails.
    pub async fn reclaim_orphans<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<usize, ContentError>
    where
        B: connetto_file_core::ChunkInventory,
    {
        let orphans = self.orphan_chunks(connection).await?;
        for hash in &orphans {
            self.discard_chunk(connection, hash).await?;
        }
        Ok(orphans.len())
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
        match encrypted.read_chunk(&chunks[missing].hash).await {
            Ok(_) => {
                return Ok(ScanStep::More(ChunkScan {
                    file: Some(file_id),
                    chunks: fingerprint,
                    ..ChunkScan::default()
                }));
            }
            Err(EncryptStoreError::Inner(err)) if self.store.read_failure_is_ambiguous(&err) => {
                // An unavailable store is not an absence, so the entry keeps its bytes.
                return Ok(ScanStep::Intact);
            }
            Err(_) => {}
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

    /// Every refused outbox entry with its permanent refusal detail.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the record cannot be read.
    pub fn refused_content<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
    ) -> Result<Vec<(FileId, String)>, ContentError> {
        db::refusals(connection.conn())
    }

    /// Clears the refusal mark on one outbox entry so the next walk attempts it.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the record cannot be written.
    pub fn retry_refused<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        file_id: FileId,
    ) -> Result<(), ContentError> {
        db::clear_refusal(connection.conn(), file_id).map_err(ContentError::from)
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
        connection
            .conn()
            .transaction(|conn| {
                for file_id in files {
                    db::forget_retired(conn, *file_id)?;
                }
                Ok::<(), diesel::result::Error>(())
            })
            .map_err(ContentError::from)
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
                self.finish_upload(cursor.connection, &upload, result).await
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
        let waiting = db::sendable(connection.conn())?;
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
    /// A loss is confirmed against the current manifest, since a concurrent import can
    /// replace it or restore its bytes during the transfer, and only the one chunk that
    /// manifest still names is read, so a large lost file never holds the worker.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the manifest cannot be read or the entry removed.
    pub async fn finish_upload<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        upload: &ContentUpload<B>,
        result: Result<(), ContentError>,
    ) -> Result<ContentFlush, ContentError> {
        match &result {
            Err(error) if error.outcome() == AttemptOutcome::Lost => {
                if self
                    .loss_is_confirmed(connection, upload.file_id, error)
                    .await?
                {
                    retire(connection.conn(), upload.file_id)?;
                    Ok(ContentFlush::Progressed)
                } else {
                    Ok(ContentFlush::Deferred)
                }
            }
            _ => Self::finish_attempt(connection, upload.file_id, result),
        }
    }

    /// Whether the reported loss still holds against the manifest this device holds now.
    ///
    /// A manifest an import replaced under the same identity can name other chunks, so a
    /// reported chunk the current manifest no longer names is stale and keeps the entry.
    async fn loss_is_confirmed<T: Transport>(
        &self,
        connection: &mut ConnettoConnection<T>,
        file_id: FileId,
        error: &ContentError,
    ) -> Result<bool, ContentError> {
        let Some(manifest) = db::load_manifest(connection.conn(), file_id)? else {
            return Ok(true);
        };
        let ContentError::LostChunk { hash, .. } = error else {
            return Ok(false);
        };
        if !manifest.chunks().iter().any(|chunk| chunk.hash == *hash) {
            return Ok(false);
        }
        let store = EncryptingStore::new(self.store.clone(), &self.root_key);
        Ok(match store.read_chunk(hash).await {
            Ok(_) => false,
            Err(err) => !store.read_failure_is_ambiguous(&err),
        })
    }

    fn finish_attempt<T: Transport>(
        connection: &mut ConnettoConnection<T>,
        file_id: FileId,
        result: Result<(), ContentError>,
    ) -> Result<ContentFlush, ContentError> {
        match result {
            Ok(()) => {
                db::dequeue(connection.conn(), file_id)?;
                Ok(ContentFlush::Progressed)
            }
            Err(error) => match error.outcome() {
                AttemptOutcome::Retry => Ok(ContentFlush::Deferred),
                AttemptOutcome::Refused => {
                    db::refuse(connection.conn(), file_id, &error.to_string())?;
                    Ok(ContentFlush::Progressed)
                }
                // A device loss retires the entry the way the integrity scan does.
                AttemptOutcome::Lost => {
                    retire(connection.conn(), file_id)?;
                    Ok(ContentFlush::Progressed)
                }
            },
        }
    }

    /// Exports unsent content and replica data to `sink`.
    ///
    /// The sink is written through as each chunk is read from the store, so
    /// one chunk is in memory at a time. Returns the sink once the archive is
    /// complete.
    ///
    /// # Errors
    ///
    /// [`ContentError`] when the outbox, chunk store, or replica export fails.
    pub async fn export_local_data<T: Transport, W: std::io::Write>(
        &self,
        connection: &mut ConnettoConnection<T>,
        scope: ExportScope,
        sink: W,
    ) -> Result<W, ContentError> {
        let manifests = outbox_manifests(connection)?;
        let declaration = crate::archive::declare_content(&manifests)?;
        let export =
            connection.export_local_data_with_attachments(scope, &declaration.attachments, sink)?;
        write_content_entries(&self.store, &self.root_key, &declaration, export).await
    }

    /// Validates and applies content under this device key.
    ///
    /// # Errors
    ///
    /// [`ContentError`] when validation, chunk storage, or replica import fails.
    pub async fn import_local_data<T: Transport, R: std::io::Read + std::io::Seek>(
        &self,
        connection: &mut ConnettoConnection<T>,
        source: R,
    ) -> Result<(ImportOutcome, usize), ContentError> {
        let mut plan = prepare_content_import(connection, source)?;
        let collisions = plan.replica_plan().collisions().len();
        write_import_chunks(&self.store, &self.root_key, &mut plan).await?;
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

/// Writes the content index entry and then one entry per distinct chunk.
///
/// Each chunk is read from the store immediately before its own entry is
/// written, so the export holds one chunk at a time whatever the archive
/// weighs, and both export paths get that from the same place.
pub(crate) async fn write_content_entries<B, W>(
    store: &B,
    root_key: &[u8; 32],
    declaration: &crate::archive::ContentDeclaration,
    mut export: connetto_client::LocalDataExport<W>,
) -> Result<W, ContentError>
where
    B: ChunkStore + Clone + Sync + MaybeSend + 'static,
    W: std::io::Write,
{
    export.write_attachment(crate::archive::MANIFESTS_PATH, &declaration.manifest_bytes)?;
    let store = EncryptingStore::new(store.clone(), root_key);
    for hash in &declaration.chunk_hashes {
        let bytes = store
            .read_chunk(hash)
            .await
            .map_err(|error| ContentError::Store(error.to_string()))?;
        export.write_attachment(&format!("{}{hash}", crate::archive::CHUNK_PREFIX), &bytes)?;
    }
    Ok(export.finish()?)
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
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    use core::sync::atomic::{AtomicUsize, Ordering};

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

    /// A chunk a manifest has come to name since it was listed survives the sweep, which
    /// is the race an import between the listing and the deletion opens.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_relisted_chunk_survives_the_sweep() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{ChunkStore, EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("relisted"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        let manifest = process_file(&vec![3u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the bytes chunk");
        let hash = manifest.chunks()[0].hash;
        let listed = archive
            .orphan_chunks(&mut connection)
            .await
            .expect("the listing runs");
        assert_eq!(listed, vec![hash], "nothing names the chunk yet");

        // The import lands between the listing and the deletion.
        db::put_manifest(connection.conn(), &manifest).expect("record the manifest");

        archive
            .discard_chunk(&mut connection, &hash)
            .await
            .expect("the discard runs");
        assert!(
            encrypted.read_chunk(&hash).await.is_ok(),
            "a chunk a manifest names must survive a stale orphan listing"
        );
    }

    /// A heal query queues a held file once, and never a file queued already, lost here
    /// too, or held nowhere on this device.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_heal_query_queues_only_files_this_device_can_send() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{EncryptingStore, MimeClass, process_file};
        use diesel::connection::SimpleConnection;

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY, content_id BLOB, content_state TEXT)",
            &ClientConfig::new("heal"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]).with_heal_lost(
            "SELECT content_id FROM photos WHERE content_state = 'lost'",
            "content_id",
        );
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        let mut files = Vec::new();
        for byte in 1..=4u8 {
            let manifest = process_file(&vec![byte; 1024], MimeClass::Jpeg, &encrypted)
                .await
                .expect("the bytes chunk");
            files.push(manifest);
        }
        let [held, queued, retired, absent] = [&files[0], &files[1], &files[2], &files[3]];
        for manifest in [held, queued, retired] {
            db::put_manifest(connection.conn(), manifest).expect("record the manifest");
        }
        db::enqueue(connection.conn(), queued.file_id()).expect("queue one");
        db::record_retired(connection.conn(), retired.file_id()).expect("retire one");
        for (id, manifest) in files.iter().enumerate() {
            connection
                .conn()
                .batch_execute(&format!(
                    "INSERT INTO photos VALUES ({id}, x'{}', 'lost')",
                    manifest.file_id()
                ))
                .expect("a lost row");
        }

        assert_eq!(
            archive.queue_lost(&mut connection).expect("the pass runs"),
            vec![held.file_id()]
        );
        assert!(db::is_unsent(connection.conn(), held.file_id()).expect("read"));
        assert!(!db::is_unsent(connection.conn(), absent.file_id()).expect("read"));
        assert_eq!(
            archive
                .queue_lost(&mut connection)
                .expect("the pass runs again"),
            Vec::new(),
            "a queued file is not queued twice"
        );

        // A heal entry is sent like any entry and is not this device's authorship.
        assert_eq!(archive.sendable_files(&mut connection).expect("count"), 2);
        assert_eq!(archive.pending_files(&mut connection).expect("count"), 1);
        assert_eq!(
            archive.unsent_files(&mut connection).expect("list"),
            vec![queued.file_id()]
        );
        assert_eq!(
            super::outbox_manifests(&mut connection)
                .expect("the export set")
                .iter()
                .map(connetto_file_core::Manifest::file_id)
                .collect::<Vec<_>>(),
            vec![queued.file_id()],
            "a heal entry is never exported as authored content"
        );

        // Another device healed the file, so this one must not upload it too.
        connection
            .conn()
            .batch_execute("UPDATE photos SET content_state = 'available'")
            .expect("the heal arrives");
        assert_eq!(
            archive.queue_lost(&mut connection).expect("the pass runs"),
            Vec::new()
        );
        assert!(!db::is_unsent(connection.conn(), held.file_id()).expect("read"));
        assert!(
            db::is_unsent(connection.conn(), queued.file_id()).expect("read"),
            "an authored entry stays whatever the query says"
        );
    }

    /// A heal entry whose local bytes are gone leaves the outbox quietly, since a cache
    /// copy lost is no authored data lost.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[test]
    fn an_unreadable_heal_entry_is_dropped_without_a_loss_record() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;

        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("heal-lost"),
            None,
        )
        .expect("the replica opens offline");
        let archive =
            super::ContentArchive::new(crate::store::FsStore::new(dir.path().join("c")), [1; 32]);
        archive.install(&mut connection).expect("content tables");
        let healing = file(0x4E);
        db::enqueue_heal(connection.conn(), healing).expect("queue a heal");

        super::ContentArchive::<crate::store::FsStore>::finish_attempt(
            &mut connection,
            healing,
            Err(crate::error::ContentError::NoManifest { file_id: healing }),
        )
        .expect("the attempt settles");
        assert!(!db::is_unsent(connection.conn(), healing).expect("read"));
        assert_eq!(
            db::retired(connection.conn()).expect("read retired"),
            Vec::<FileId>::new()
        );
    }

    /// An uploaded file no pin covers is released, while an unsent one is kept, so a
    /// device that uploads does not keep every file it ever sent.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn an_uploaded_file_no_pin_covers_is_released() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("evict"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        let uploaded = process_file(&vec![1u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the uploaded file chunks");
        let unsent = process_file(&vec![2u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the unsent file chunks");
        db::put_manifest(connection.conn(), &uploaded).expect("record the uploaded manifest");
        db::put_manifest(connection.conn(), &unsent).expect("record the unsent manifest");
        db::enqueue(connection.conn(), unsent.file_id()).expect("queue the unsent file");

        assert_eq!(
            archive
                .evict_uncovered(&mut connection)
                .expect("the eviction runs"),
            1,
            "only the uploaded file is released"
        );
        assert_eq!(
            db::all_manifests(connection.conn()).expect("read the manifests"),
            vec![unsent.file_id()],
            "the unsent file keeps its manifest"
        );
        assert_eq!(
            archive
                .reclaim_orphans(&mut connection)
                .await
                .expect("the sweep runs"),
            uploaded.chunks().len(),
            "and the released chunks are reclaimed"
        );
    }

    /// Chunks an interrupted import left behind are reclaimed, and the ones a manifest
    /// names are kept.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn an_interrupted_import_leaves_no_chunks_behind() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{ChunkStore, EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("sweep"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        let kept = process_file(&vec![8u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the recorded file chunks");
        // The import that wrote these bytes failed before its manifest could commit.
        let abandoned = process_file(&vec![9u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the abandoned file chunks");
        db::put_manifest(connection.conn(), &kept).expect("record the manifest");

        assert_eq!(
            archive
                .reclaim_orphans(&mut connection)
                .await
                .expect("the sweep runs"),
            abandoned.chunks().len(),
            "every chunk no manifest names is reclaimed"
        );
        assert!(
            encrypted.read_chunk(&kept.chunks()[0].hash).await.is_ok(),
            "a referenced chunk survives the sweep"
        );
        assert!(
            encrypted
                .read_chunk(&abandoned.chunks()[0].hash)
                .await
                .is_err(),
            "and the abandoned bytes are gone"
        );
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

    /// An unavailable store is not an absence, so the confirmation read keeps the entry
    /// rather than retiring it.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn an_ambiguous_confirmation_read_keeps_the_entry() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{ChunkStore, EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("ambiguous"),
            None,
        )
        .expect("the replica opens offline");

        let classifications = std::sync::Arc::new(AtomicUsize::new(0));
        let unavailable = super::ContentArchive::new(
            Unavailable(store.clone(), std::sync::Arc::clone(&classifications)),
            [1; 32],
        );
        unavailable
            .install(&mut connection)
            .expect("content tables");

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        let manifest = process_file(&vec![6u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the bytes chunk");
        encrypted
            .delete_chunk(&manifest.chunks()[0].hash)
            .await
            .expect("drop the only chunk");
        db::put_manifest(connection.conn(), &manifest).expect("record the manifest");
        db::enqueue(connection.conn(), manifest.file_id()).expect("queue the file");

        let step = unavailable
            .scan_unsent_file(
                &mut connection,
                manifest.file_id(),
                super::ChunkScan::default(),
                8,
            )
            .await
            .expect("the scan runs");
        assert!(
            matches!(step, super::ScanStep::Intact),
            "an unavailable store must keep the entry, got {step:?}"
        );
        assert_eq!(
            db::outbox(connection.conn()).expect("read the outbox"),
            vec![manifest.file_id()],
            "and the file stays queued"
        );
        assert_eq!(
            classifications.load(Ordering::Relaxed),
            2,
            "the verdict must come from the confirmation read, not from the slice"
        );
    }

    /// A store that reads a first failure as an absence and every later one as a store
    /// that may be unavailable, which is what puts the ambiguity on the confirmation read.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[derive(Clone)]
    struct Unavailable(crate::store::FsStore, std::sync::Arc<AtomicUsize>);

    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    impl connetto_file_core::ChunkStore for Unavailable {
        type Error = crate::store::FsStoreError;

        fn read_failure_is_ambiguous(&self, _error: &Self::Error) -> bool {
            self.1.fetch_add(1, Ordering::Relaxed) > 0
        }

        async fn write_chunk(
            &self,
            hash: &connetto_file_core::ChunkHash,
            bytes: &[u8],
        ) -> Result<(), Self::Error> {
            connetto_file_core::ChunkStore::write_chunk(&self.0, hash, bytes).await
        }

        async fn read_chunk(
            &self,
            hash: &connetto_file_core::ChunkHash,
        ) -> Result<Vec<u8>, Self::Error> {
            connetto_file_core::ChunkStore::read_chunk(&self.0, hash).await
        }

        async fn has_chunk(
            &self,
            hash: &connetto_file_core::ChunkHash,
        ) -> Result<bool, Self::Error> {
            connetto_file_core::ChunkStore::has_chunk(&self.0, hash).await
        }

        async fn delete_chunk(
            &self,
            hash: &connetto_file_core::ChunkHash,
        ) -> Result<(), Self::Error> {
            connetto_file_core::ChunkStore::delete_chunk(&self.0, hash).await
        }
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

    /// A missing manifest is a device loss, so the upload walk retires the entry
    /// into the retired record exactly as the integrity scan does for the same fact.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_missing_manifest_is_a_loss_on_the_walk_and_the_scan() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("missing-manifest"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store, [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let walked = file(0x5A);
        db::enqueue(connection.conn(), walked).expect("queue the walked file");
        super::ContentArchive::<crate::store::FsStore>::finish_attempt(
            &mut connection,
            walked,
            Err(crate::error::ContentError::NoManifest { file_id: walked }),
        )
        .expect("finish_attempt runs");
        assert!(
            db::outbox(connection.conn())
                .expect("read the outbox")
                .is_empty(),
            "a lost file leaves the outbox"
        );
        assert!(
            db::refusals(connection.conn())
                .expect("read refusals")
                .is_empty(),
            "a loss is not a refusal"
        );

        let scanned = file(0x5B);
        db::enqueue(connection.conn(), scanned).expect("queue the scanned file");
        let step = archive
            .scan_unsent_file(&mut connection, scanned, super::ChunkScan::default(), 8)
            .await
            .expect("the scan runs");
        assert!(
            matches!(step, super::ScanStep::Retired),
            "the scan retires the same fact, got {step:?}"
        );

        assert_eq!(
            db::retired(connection.conn()).expect("read retired"),
            vec![walked, scanned],
            "both passes retire the file with the missing manifest"
        );
    }

    /// A loss reported by the transfer is confirmed against the store before retiring, so a
    /// chunk a concurrent import restored during the transfer keeps the entry.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn finish_upload_confirms_the_loss_before_retiring() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{ChunkStore, EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("confirm-loss"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store.clone(), &[1; 32]);
        let manifest = process_file(&vec![7u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the bytes chunk");
        let file_id = manifest.file_id();
        db::put_manifest(connection.conn(), &manifest).expect("record the manifest");
        db::enqueue(connection.conn(), file_id).expect("queue the file");

        let upload = super::ContentUpload {
            file_id,
            upload_url: String::new(),
            manifest: manifest.clone(),
            store: store.clone(),
            root_key: [1; 32],
        };
        let hash = manifest.chunks()[0].hash;
        let lost = || crate::error::ContentError::LostChunk {
            file_id,
            hash,
            detail: "chunk gone".to_owned(),
        };

        let flush = archive
            .finish_upload(&mut connection, &upload, Err(lost()))
            .await
            .expect("finish_upload runs");
        assert_eq!(
            flush,
            super::ContentFlush::Deferred,
            "a chunk still present keeps the entry"
        );
        assert!(
            db::retired(connection.conn())
                .expect("read retired")
                .is_empty(),
            "nothing is retired while the bytes are present"
        );
        assert_eq!(
            db::outbox(connection.conn()).expect("read the outbox"),
            vec![file_id],
            "the entry stays queued for another walk"
        );

        encrypted
            .delete_chunk(&manifest.chunks()[0].hash)
            .await
            .expect("drop the only chunk");
        let flush = archive
            .finish_upload(&mut connection, &upload, Err(lost()))
            .await
            .expect("finish_upload runs");
        assert_eq!(
            flush,
            super::ContentFlush::Progressed,
            "a confirmed loss settles the entry"
        );
        assert_eq!(
            db::retired(connection.conn()).expect("read retired"),
            vec![file_id],
            "a confirmed loss is retired"
        );
        assert!(
            db::outbox(connection.conn())
                .expect("read the outbox")
                .is_empty(),
            "a retired entry leaves the outbox"
        );
    }

    /// Counts `read_chunk` calls, to prove a loss is confirmed against one chunk.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[derive(Clone)]
    struct CountingStore {
        inner: crate::store::FsStore,
        reads: std::sync::Arc<core::sync::atomic::AtomicUsize>,
    }

    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    impl connetto_file_core::ChunkStore for CountingStore {
        type Error = crate::store::FsStoreError;

        async fn write_chunk(
            &self,
            hash: &connetto_file_core::ChunkHash,
            data: &[u8],
        ) -> Result<(), Self::Error> {
            self.inner.write_chunk(hash, data).await
        }

        async fn read_chunk(
            &self,
            hash: &connetto_file_core::ChunkHash,
        ) -> Result<Vec<u8>, Self::Error> {
            self.reads
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            self.inner.read_chunk(hash).await
        }

        async fn has_chunk(
            &self,
            hash: &connetto_file_core::ChunkHash,
        ) -> Result<bool, Self::Error> {
            self.inner.has_chunk(hash).await
        }

        async fn delete_chunk(
            &self,
            hash: &connetto_file_core::ChunkHash,
        ) -> Result<(), Self::Error> {
            self.inner.delete_chunk(hash).await
        }
    }

    /// Confirming a loss reads only the chunk the transfer named, never the whole file, so a
    /// large lost upload cannot hold the worker while every other chunk is decrypted.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn finish_upload_reads_only_the_reported_chunk() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{EncryptingStore, MimeClass, process_file};
        use core::sync::atomic::Ordering;

        let dir = tempfile::tempdir().expect("a temporary directory");
        let reads = std::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let store = CountingStore {
            inner: crate::store::FsStore::new(dir.path().join("chunks")),
            reads: reads.clone(),
        };
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("targeted-loss"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store.clone(), &[1; 32]);
        // Jpeg chunks in fixed 16 MiB slabs, so 33 MiB is three chunks.
        let manifest = process_file(&vec![7u8; 33 * 1024 * 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("chunk the file");
        assert!(
            manifest.chunks().len() > 1,
            "the file must have several chunks to tell a targeted read apart"
        );
        let file_id = manifest.file_id();
        db::put_manifest(connection.conn(), &manifest).expect("record the manifest");
        db::enqueue(connection.conn(), file_id).expect("queue the file");

        let upload = super::ContentUpload {
            file_id,
            upload_url: String::new(),
            manifest: manifest.clone(),
            store: store.clone(),
            root_key: [1; 32],
        };
        let error = crate::error::ContentError::LostChunk {
            file_id,
            hash: manifest.chunks()[1].hash,
            detail: "chunk gone".to_owned(),
        };

        reads.store(0, Ordering::Relaxed);
        let flush = archive
            .finish_upload(&mut connection, &upload, Err(error))
            .await
            .expect("finish_upload runs");
        assert_eq!(
            flush,
            super::ContentFlush::Deferred,
            "the named chunk is present, so the entry is kept"
        );
        assert_eq!(
            reads.load(Ordering::Relaxed),
            1,
            "confirming the loss reads only the one named chunk"
        );
    }

    /// A manifest an import replaced under the same identity keeps the entry, because the
    /// chunk the transfer reported lost is no longer the file this device holds.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn finish_upload_keeps_a_file_whose_manifest_was_replaced() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{
            ChunkHash, ChunkMeta, ChunkStore, EncryptingStore, Manifest, MimeClass, process_file,
        };

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("replaced-manifest"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store.clone(), &[1; 32]);
        let original = process_file(&vec![7u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("chunk the file");
        let file_id = original.file_id();
        let lost_hash = original.chunks()[0].hash;
        // The chunk the transfer named is gone from the store.
        encrypted
            .delete_chunk(&lost_hash)
            .await
            .expect("drop the reported chunk");

        // An import replaced the manifest under the same identity with different chunking,
        // and its bytes are present.
        let replacement_bytes = b"the same file chunked another way".to_vec();
        let replacement_hash = ChunkHash::from_bytes([0xBB; 32]);
        assert_ne!(
            replacement_hash, lost_hash,
            "the replacement names another chunk"
        );
        encrypted
            .write_chunk(&replacement_hash, &replacement_bytes)
            .await
            .expect("store the replacement chunk");
        let replacement = Manifest::new(
            file_id,
            vec![ChunkMeta {
                hash: replacement_hash,
                len: u64::try_from(replacement_bytes.len()).expect("length fits u64"),
            }],
        );
        db::put_manifest(connection.conn(), &replacement).expect("record the replacement manifest");
        db::enqueue(connection.conn(), file_id).expect("queue the file");

        let upload = super::ContentUpload {
            file_id,
            upload_url: String::new(),
            manifest: original.clone(),
            store: store.clone(),
            root_key: [1; 32],
        };
        let error = crate::error::ContentError::LostChunk {
            file_id,
            hash: lost_hash,
            detail: "chunk gone".to_owned(),
        };

        let flush = archive
            .finish_upload(&mut connection, &upload, Err(error))
            .await
            .expect("finish_upload runs");
        assert_eq!(
            flush,
            super::ContentFlush::Deferred,
            "a replaced manifest that no longer names the reported chunk keeps the entry"
        );
        assert!(
            db::retired(connection.conn())
                .expect("read retired")
                .is_empty(),
            "the replacement is not retired"
        );
        assert_eq!(
            db::outbox(connection.conn()).expect("read the outbox"),
            vec![file_id],
            "the entry stays queued for another walk"
        );
    }

    /// A permanent upload error marks the entry as refused rather than removing it, so the
    /// file stays in the outbox with its detail, the retired table stays empty, and the
    /// pending-work count stays at one.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_permanent_refusal_stays_in_the_outbox() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("refuse-stays"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        let manifest = process_file(&vec![1u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the bytes chunk");
        db::put_manifest(connection.conn(), &manifest).expect("record the manifest");
        db::enqueue(connection.conn(), manifest.file_id()).expect("queue the file");

        // HTTP 413 is a permanent ceiling rejection.
        let permanent = crate::error::ContentError::Http {
            status: 413,
            stage: "commit",
        };
        super::ContentArchive::<crate::store::FsStore>::finish_attempt(
            &mut connection,
            manifest.file_id(),
            Err(permanent),
        )
        .expect("finish_attempt runs");

        assert_eq!(
            db::outbox(connection.conn()).expect("read the outbox"),
            vec![manifest.file_id()],
            "a refused file must stay in the outbox"
        );
        assert_eq!(
            db::outbox_count(connection.conn()).expect("count the outbox"),
            1,
            "the pending-work count must stay at one"
        );
        assert!(
            db::retired(connection.conn())
                .expect("read retired")
                .is_empty(),
            "the retired table must be empty"
        );
        let refusals = db::refusals(connection.conn()).expect("read refusals");
        assert_eq!(refusals.len(), 1, "one refusal record must appear");
        assert_eq!(
            refusals[0].0,
            manifest.file_id(),
            "the refusal must name the refused file"
        );
    }

    /// A refused outbox entry is not offered to the upload driver, while an unmarked entry
    /// in the same outbox is still sendable.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_refused_entry_is_skipped_while_an_unmarked_entry_is_sendable() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;

        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("sendable"),
            None,
        )
        .expect("the replica opens offline");
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let archive = super::ContentArchive::new(store, [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let refused = file(0xAA);
        let sendable = file(0xBB);
        db::enqueue(connection.conn(), refused).expect("queue the refused file");
        db::enqueue(connection.conn(), sendable).expect("queue the sendable file");
        db::refuse(connection.conn(), refused, "over the ceiling").expect("mark as refused");

        assert_eq!(
            db::outbox(connection.conn()).expect("read outbox"),
            vec![refused, sendable],
            "outbox returns every entry regardless of refusal"
        );
        assert_eq!(
            db::sendable(connection.conn()).expect("read sendable"),
            vec![sendable],
            "sendable returns only unmarked entries"
        );
    }

    /// Clearing the refusal mark through `retry_refused` makes the entry sendable again, so
    /// the next walk can attempt it.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn retry_refused_clears_the_mark_and_the_entry_becomes_sendable() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;

        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("retry-refused"),
            None,
        )
        .expect("the replica opens offline");
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let archive = super::ContentArchive::new(store, [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let file_id = file(0xCC);
        db::enqueue(connection.conn(), file_id).expect("queue the file");
        db::refuse(connection.conn(), file_id, "too large").expect("mark as refused");
        assert!(
            db::sendable(connection.conn())
                .expect("read sendable before retry")
                .is_empty(),
            "the refused entry must not be sendable before retry"
        );

        archive
            .retry_refused(&mut connection, file_id)
            .expect("retry_refused runs");

        assert_eq!(
            db::sendable(connection.conn()).expect("read sendable after retry"),
            vec![file_id],
            "the entry must be sendable after the refusal is cleared"
        );
    }

    /// A file queued to heal and then staged or imported here is authored, so it counts as pending and is never retired quietly.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_heal_entry_whose_file_is_then_authored_here_becomes_authored() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;

        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("heal-then-author"),
            None,
        )
        .expect("the replica opens offline");
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let archive = super::ContentArchive::new(store, [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let file_id = file(0xDD);
        db::enqueue_heal(connection.conn(), file_id).expect("queue a heal");
        db::refuse(connection.conn(), file_id, "over the quota").expect("refuse the heal");
        db::enqueue(connection.conn(), file_id).expect("author the same file");

        assert!(!db::is_heal(connection.conn(), file_id).expect("read the kind"));
        assert_eq!(db::outbox_count(connection.conn()).expect("count"), 1);
        assert!(
            db::sendable(connection.conn())
                .expect("sendable")
                .is_empty(),
            "the refusal stays until an explicit retry, as for any authored entry"
        );
    }

    /// The integrity walk retires a refused entry whose bytes are conclusively gone, so a
    /// refusal does not make a loss invisible.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn the_integrity_walk_retires_a_refused_entry_with_missing_bytes() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_core::{ChunkStore, EncryptingStore, MimeClass, process_file};

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("retire-refused"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store.clone(), [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let encrypted = EncryptingStore::new(store, &[1; 32]);
        let manifest = process_file(&vec![2u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the bytes chunk");
        encrypted
            .delete_chunk(&manifest.chunks()[0].hash)
            .await
            .expect("drop the only chunk");
        db::put_manifest(connection.conn(), &manifest).expect("record the manifest");
        db::enqueue(connection.conn(), manifest.file_id()).expect("queue the file");
        db::refuse(connection.conn(), manifest.file_id(), "too large").expect("mark as refused");

        let step = archive
            .scan_unsent_file(
                &mut connection,
                manifest.file_id(),
                super::ChunkScan::default(),
                8,
            )
            .await
            .expect("the scan runs");
        assert!(
            matches!(step, super::ScanStep::Retired),
            "a refused entry with missing bytes must be retired, got {step:?}"
        );
        assert!(
            db::outbox(connection.conn())
                .expect("read the outbox")
                .is_empty(),
            "a retired refused entry leaves the outbox"
        );
    }

    /// `sendable_files` counts only unmarked entries while `pending_files` counts both,
    /// keeping the two meanings apart: pending work is the full outbox, sendable work
    /// is what the driver actually attempts.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn sendable_files_excludes_refused_while_pending_files_counts_both() {
        use crate::db;
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY)",
            &ClientConfig::new("sendable-count"),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store, [1; 32]);
        archive.install(&mut connection).expect("content tables");

        let refused = file(0x01);
        let sendable = file(0x02);
        db::enqueue(connection.conn(), refused).expect("queue the refused file");
        db::enqueue(connection.conn(), sendable).expect("queue the sendable file");
        db::refuse(connection.conn(), refused, "over the ceiling").expect("mark as refused");

        assert_eq!(
            archive
                .pending_files(&mut connection)
                .expect("pending count"),
            2,
            "pending_files counts every authored outbox row including refused ones"
        );
        assert_eq!(
            archive
                .sendable_files(&mut connection)
                .expect("sendable count"),
            1,
            "sendable_files counts only unmarked entries"
        );
    }

    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        n: i64,
    }

    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    fn count(connection: &mut diesel::SqliteConnection, sql: &str) -> i64 {
        use diesel::RunQueryDsl;
        diesel::sql_query(sql)
            .get_result::<Count>(connection)
            .expect("the count reads")
            .n
    }

    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    fn staged_fixture(
        name: &str,
    ) -> (
        tempfile::TempDir,
        super::ContentArchive<crate::store::FsStore>,
        connetto_client::ConnettoConnection<connetto_core::test_support::FakeTransport>,
    ) {
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;

        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = crate::store::FsStore::new(dir.path().join("chunks"));
        let mut connection = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            "CREATE TABLE photos (id INTEGER PRIMARY KEY, content_id BLOB NOT NULL)",
            &ClientConfig::new(name),
            None,
        )
        .expect("the replica opens offline");
        let archive = super::ContentArchive::new(store, [1; 32]);
        archive.install(&mut connection).expect("content tables");
        (dir, archive, connection)
    }

    /// The manifest, the outbox entry and the naming row commit together, and
    /// the identity they carry is the one the bytes hash to.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_staged_file_and_its_row_commit_together() {
        use crate::db;
        use connetto_file_core::MimeClass;
        use diesel::RunQueryDsl;

        let (_dir, archive, mut connection) = staged_fixture("stage-commit");
        let bytes = vec![7u8; 1024];
        let manifest = archive
            .chunk_file(&bytes[..], MimeClass::Jpeg)
            .await
            .expect("the bytes chunk");
        let expected = manifest.file_id();

        let written = archive
            .commit_staged(&mut connection, &manifest, |conn, id| {
                diesel::sql_query("INSERT INTO photos (id, content_id) VALUES (1, ?)")
                    .bind::<diesel::sql_types::Binary, _>(id.as_bytes().to_vec())
                    .execute(conn)?;
                Ok(id)
            })
            .expect("the staged commit lands");

        assert_eq!(written, expected, "the row is told the computed identity");
        assert!(
            db::load_manifest(connection.conn(), expected)
                .expect("the manifest reads")
                .is_some(),
            "the manifest committed with the row"
        );
        assert_eq!(
            db::outbox(connection.conn()).expect("the outbox reads"),
            vec![expected],
            "the upload was queued with the row"
        );
        assert_eq!(
            count(connection.conn(), "SELECT COUNT(*) AS n FROM photos"),
            1,
            "the row committed"
        );
    }

    /// A row closure that refuses the computed identity rolls back the
    /// manifest and the outbox entry with it, leaving nothing staged behind.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_row_that_refuses_the_computed_id_rolls_the_manifest_back() {
        use crate::db;
        use crate::error::StageCommitError;
        use connetto_file_core::MimeClass;
        use diesel::RunQueryDsl;

        let (_dir, archive, mut connection) = staged_fixture("stage-mismatch");
        let bytes = vec![8u8; 1024];
        let manifest = archive
            .chunk_file(&bytes[..], MimeClass::Jpeg)
            .await
            .expect("the bytes chunk");
        let declared = FileId::from_bytes([9; 32]);

        let error = archive
            .commit_staged(&mut connection, &manifest, |conn, id| {
                if id != declared {
                    return Err(StageCommitError::Row(format!(
                        "declared {declared}, the bytes hash to {id}"
                    )));
                }
                diesel::sql_query("INSERT INTO photos (id, content_id) VALUES (1, ?)")
                    .bind::<diesel::sql_types::Binary, _>(id.as_bytes().to_vec())
                    .execute(conn)?;
                Ok(id)
            })
            .expect_err("a mismatched identity must refuse");
        assert!(matches!(error, StageCommitError::Row(_)));

        assert!(
            db::load_manifest(connection.conn(), manifest.file_id())
                .expect("the manifest reads")
                .is_none(),
            "a refused row leaves no manifest behind"
        );
        assert!(
            db::outbox(connection.conn())
                .expect("the outbox reads")
                .is_empty(),
            "a refused row queues no upload"
        );
        assert_eq!(
            count(connection.conn(), "SELECT COUNT(*) AS n FROM photos"),
            0,
            "nothing wrote to the application table"
        );
    }

    /// Content the worker just staged answers locally before any upload, and
    /// answers with the exact bytes.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn unsent_staged_content_resolves_from_the_chunk_store() {
        use crate::resolve::Resolved;
        use connetto_file_core::MimeClass;

        let (_dir, archive, mut connection) = staged_fixture("stage-resolve");
        let bytes = vec![5u8; 2048];
        let manifest = archive
            .chunk_file(&bytes[..], MimeClass::Jpeg)
            .await
            .expect("the bytes chunk");
        archive
            .commit_staged(&mut connection, &manifest, |_conn, id| Ok(id))
            .expect("the staged commit lands");

        let (answer, observed) = archive
            .resolve_connection(
                &mut connection,
                manifest.file_id(),
                core::future::pending::<()>(),
            )
            .await;
        match answer {
            Resolved::Local { bytes: served, .. } => assert_eq!(served, bytes),
            other => panic!("unsent content must resolve locally, got {other:?}"),
        }
        assert!(observed.is_empty(), "no round trip ran");
    }

    /// Content the worker cannot produce answers `Unavailable`: a file with no
    /// manifest, and an uploaded file no pin covers, both with no server
    /// online.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn content_the_worker_cannot_produce_resolves_unavailable_offline() {
        use crate::db;
        use crate::resolve::Resolved;
        use connetto_file_core::{EncryptingStore, MimeClass, process_file};

        let (dir, archive, mut connection) = staged_fixture("stage-unavailable");
        let (answer, _) = archive
            .resolve_connection(
                &mut connection,
                FileId::from_bytes([3; 32]),
                core::future::pending::<()>(),
            )
            .await;
        assert!(
            matches!(answer, Resolved::Unavailable),
            "an unknown file must resolve Unavailable, got {answer:?}"
        );

        let encrypted = EncryptingStore::new(
            crate::store::FsStore::new(dir.path().join("chunks")),
            &[1; 32],
        );
        let uploaded = process_file(&vec![4u8; 1024], MimeClass::Jpeg, &encrypted)
            .await
            .expect("the file chunks");
        db::put_manifest(connection.conn(), &uploaded).expect("record the manifest");
        let (answer, _) = archive
            .resolve_connection(
                &mut connection,
                uploaded.file_id(),
                core::future::pending::<()>(),
            )
            .await;
        assert!(
            matches!(answer, Resolved::Unavailable),
            "an uploaded unpinned file offline must resolve Unavailable, got {answer:?}"
        );
    }
}
