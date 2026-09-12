//! The content client: staging, uploading, resolving and pinning.

use core::fmt::Display;
use std::collections::HashSet;
use std::io::Read;

use connetto_client::live::ConnettoClient;
use connetto_client::reconnect::{ReconnectPolicy, Sleeper};
use connetto_client::{ClientEvent, ExportScope, ImportChoices, ImportOutcome, SyncStatus};
use connetto_core::messages::ContentVerb;
use connetto_core::traits::Transport;
use connetto_file_core::{
    ChunkInventory, ChunkStore, EncryptingStore, FileId, Manifest, MaybeSend, MimeClass,
    process_file_from_reader,
};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use tokio::sync::broadcast;

use crate::db;
use crate::error::ContentError;
use crate::http::ContentHttp;
use crate::import::{
    ContentImportPlan, apply_content_import, prepare_content_import, write_import_chunks,
};
use crate::resolve::{BoxedSource, ChunkStoreSource, Resolved};
use crate::worker::{content_attachments, outbox_manifests, retire, unreadable_chunk_count};
use crate::{ticket, upload};

/// How many content events are held for a slow observer.
const EVENT_CAPACITY: usize = 64;

/// The chunking class for content fetched from the server.
///
/// Fetched content is cache: refetchable by construction, never exported. Its
/// chunk parameters therefore affect only local dedup, so one class serves
/// every fetch. Unsent content, where dedup against the server does matter, is
/// chunked with the class the application named when it staged the file.
const FETCHED_CLASS: MimeClass = MimeClass::Generic;

/// Something the content client did that the application may want to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentEvent {
    /// An outbox entry uploaded and committed. The server has flipped
    /// `content_state`, so the metadata row's own update is on its way.
    Uploaded {
        /// The file that landed.
        file_id: FileId,
    },
    /// An upload attempt failed in a way a later attempt may not. The entry
    /// stays in the outbox.
    UploadDeferred {
        /// The file still waiting.
        file_id: FileId,
        /// What went wrong.
        detail: String,
    },
    /// An upload attempt failed in a way no later attempt changes. The entry
    /// is out of the outbox and will not be retried.
    UploadRefused {
        /// The file that will not upload.
        file_id: FileId,
        /// What went wrong.
        detail: String,
    },
    /// The boot integrity pass found an unsent file whose chunks are gone or
    /// unreadable. Its outbox entry is dropped, because unsent content cannot
    /// be refetched, and its manifest is kept as the record that this device
    /// declared the file. The application's row still names it, so this is the
    /// signal to delete that row or ask the user for the file again.
    BytesLost {
        /// The file whose bytes are gone.
        file_id: FileId,
        /// How many of its chunks could not be read.
        unreadable: usize,
    },
    /// A pinned file's bytes arrived and are now local.
    Fetched {
        /// The file now held locally.
        file_id: FileId,
    },
    /// The boot integrity pass could not run, so no unsent file was checked
    /// this time. The walk went ahead: a pass that cannot read the outbox
    /// says nothing about the bytes, so refusing to upload on its word would
    /// hold back content that is very likely fine.
    IntegrityPassFailed {
        /// What went wrong.
        detail: String,
    },
}

/// Files, on top of a running [`ConnettoClient`].
///
/// Metadata travels as ordinary synced rows and content travels here. The
/// application stages a file with [`stage`](Self::stage), which writes the
/// bytes and commits the manifest with the row that names it, and displays it
/// with [`resolve`](Self::resolve), which answers a signed URL in the common
/// case and never touches the chunk store.
pub struct ContentClient<T: Transport, B: ChunkStore + Clone, H: ContentHttp> {
    client: ConnettoClient<T>,
    store: B,
    root_key: [u8; 32],
    http: H,
    sources: Vec<BoxedSource>,
    events: broadcast::Sender<ContentEvent>,
    /// Held across every pairing of a chunk-file write with the manifest
    /// commit that references it, and across the sweep's mirror of that pair.
    ///
    /// Without it the sweep and a staging call interleave: the sweep decides a
    /// hash is unreferenced, commits, and then deletes the file a staging call
    /// wrote and committed a manifest for in between, so an outbox entry loses
    /// bytes it had. One store belongs to one process, the same assumption the
    /// store's temporary names rest on, so one mutex closes it.
    content_writes: tokio::sync::Mutex<()>,
}

impl<T, B, H> ContentClient<T, B, H>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    B: ChunkStore + Clone + Sync + MaybeSend + 'static,
    H: ContentHttp,
{
    /// Attaches file handling to a running client.
    ///
    /// `store` holds the ciphertext and knows nothing of keys: the encrypting
    /// decorator is applied here, per operation, so each file's chunks are
    /// compressed or not according to the class the caller names. `root_key`
    /// is the same custody the replica's key comes from, so the R23 unlock
    /// gate and crypto-shred-on-wipe cover content exactly as they cover rows.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the bookkeeping schema cannot be
    /// applied.
    pub async fn attach(
        client: ConnettoClient<T>,
        store: B,
        root_key: [u8; 32],
        http: H,
    ) -> Result<Self, ContentError> {
        client
            .with_conn(|conn| conn.batch_execute(db::CONTENT_DDL))
            .await?;
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        let local = ChunkStoreSource::new(EncryptingStore::new(store.clone(), &root_key));
        Ok(Self {
            client,
            store,
            root_key,
            http,
            sources: vec![Box::new(local)],
            events,
            content_writes: tokio::sync::Mutex::new(()),
        })
    }

    /// Exports unsent content and replica data.
    ///
    /// # Errors
    ///
    /// [`ContentError`] when the outbox, chunk store, or replica export fails.
    pub async fn export_local_data(&self, scope: ExportScope) -> Result<Vec<u8>, ContentError> {
        let _writing = self.content_writes.lock().await;
        let manifests = self.client.with_conn(outbox_manifests).await?;
        let attachments = content_attachments(&self.store, &self.root_key, &manifests).await?;
        self.client
            .with_conn(|conn| conn.export_local_data_with_attachments(scope, &attachments))
            .await
            .map_err(ContentError::Client)
    }

    /// Verifies replica data and content identities without mutation.
    ///
    /// # Errors
    ///
    /// [`ContentError`] when the archive or its content does not validate.
    pub async fn prepare_local_data_import(
        &self,
        bytes: &[u8],
    ) -> Result<ContentImportPlan, ContentError> {
        self.client
            .with_conn(|connection| prepare_content_import(connection, bytes))
            .await
    }

    /// Restores content under this device key.
    ///
    /// # Errors
    ///
    /// [`ContentError`] when chunk storage or replica import fails.
    pub async fn apply_local_data_import(
        &self,
        plan: &ContentImportPlan,
        choices: &ImportChoices,
    ) -> Result<ImportOutcome, ContentError> {
        let _writing = self.content_writes.lock().await;
        write_import_chunks(&self.store, &self.root_key, plan).await?;
        let outcome = self
            .client
            .with_conn(|connection| apply_content_import(connection, plan, choices))
            .await?;
        // The import is committed, so a failed replay is left to the outbox driver.
        let _ = self.client.replay_pending().await;
        Ok(outcome)
    }

    /// Registers a further local source, asked after the ones already there.
    #[must_use]
    pub fn with_source(mut self, source: BoxedSource) -> Self {
        self.sources.push(source);
        self
    }

    /// Observe what the content client does. Lagging receivers drop the oldest
    /// events.
    #[must_use]
    pub fn events(&self) -> broadcast::Receiver<ContentEvent> {
        self.events.subscribe()
    }

    /// The encrypting view of the chunk store for one content class.
    fn store_for(&self, mime: MimeClass) -> EncryptingStore<B> {
        EncryptingStore::new_with(
            self.store.clone(),
            &self.root_key,
            mime.params().skip_compression,
        )
    }

    /// Writes a file's bytes and commits its manifest with the row that names
    /// it, as one transaction.
    ///
    /// The bytes are chunked and stored first, so a crash before the commit
    /// orphans chunk files, which the sweep collects, and leaves no row
    /// pointing at content nothing describes. Then one transaction records the
    /// manifest and the outbox entry with capture suspended, and runs `row`
    /// with capture live, so the application's insert uploads as an ordinary
    /// mutation and the bookkeeping never does.
    ///
    /// `row` receives the file identity, which is what it stores on its own
    /// column, and returns whatever the caller wants out of the write.
    ///
    /// # Errors
    ///
    /// [`ContentError::Store`] when the bytes cannot be read or written, and
    /// [`ContentError::Replica`] when the transaction fails, including when
    /// `row` itself fails, in which case nothing at all is committed.
    pub async fn stage<R, F, O>(
        &self,
        reader: R,
        mime: MimeClass,
        row: F,
    ) -> Result<(FileId, O), ContentError>
    where
        R: Read + MaybeSend,
        F: FnOnce(&mut SqliteConnection, FileId) -> Result<O, diesel::result::Error>,
    {
        let _writing = self.content_writes.lock().await;
        let store = self.store_for(mime);
        let manifest = process_file_from_reader(reader, mime, &store)
            .await
            .map_err(|err| ContentError::Store(err.to_string()))?;
        let file_id = manifest.file_id();
        let out = self
            .client
            .with_conn(|conn| {
                conn.transact_with_bookkeeping(
                    |c| {
                        db::put_manifest(c, &manifest)?;
                        db::enqueue(c, file_id)
                    },
                    |c| row(c, file_id),
                )
                .map(|((), out)| out)
            })
            .await?;
        Ok((file_id, out))
    }

    /// Reads every unsent file's chunks and retires the entries whose bytes
    /// are gone, returning the files that lost them.
    ///
    /// Reading rather than probing is the point: a chunk file that exists but
    /// does not authenticate is as lost as one that is absent, and this is the
    /// only set of content on the device that cannot be fetched again, so
    /// proving it readable is proportionate. Each loss emits
    /// [`ContentEvent::BytesLost`].
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the outbox or a manifest cannot be read.
    pub async fn verify_unsent(&self) -> Result<Vec<FileId>, ContentError> {
        let waiting = self
            .client
            .with_conn(|conn| db::outbox(conn.conn()))
            .await?;
        let mut lost = Vec::new();
        for file_id in waiting {
            let Some(unreadable) = self.unreadable_chunks(file_id).await? else {
                continue;
            };
            self.client
                .with_conn(|conn| retire(conn.conn(), file_id))
                .await?;
            lost.push(file_id);
            let _ = self.events.send(ContentEvent::BytesLost {
                file_id,
                unreadable,
            });
        }
        Ok(lost)
    }

    /// Files whose unsent bytes were lost and whose loss is unacknowledged.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the record cannot be read.
    pub async fn retired_content(&self) -> Result<Vec<FileId>, ContentError> {
        self.client.with_conn(|conn| db::retired(conn.conn())).await
    }

    /// Drops the losses the application has dealt with.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the record cannot be written.
    pub async fn forget_retired_content(&self, files: &[FileId]) -> Result<(), ContentError> {
        for file_id in files {
            let file_id = *file_id;
            self.client
                .with_conn(move |conn| db::forget_retired(conn.conn(), file_id))
                .await?;
        }
        Ok(())
    }

    /// How many of one unsent file's chunks cannot be read, or `None` when all
    /// of them can.
    ///
    /// An outbox entry with no manifest at all counts as lost with a count of
    /// zero: nothing here can name its chunks, so nothing can upload it.
    async fn unreadable_chunks(&self, file_id: FileId) -> Result<Option<usize>, ContentError> {
        let manifest = self
            .client
            .with_conn(|conn| db::load_manifest(conn.conn(), file_id))
            .await?;
        let Some(manifest) = manifest else {
            return Ok(Some(0));
        };
        Ok(unreadable_chunk_count(&self.store, &self.root_key, &manifest).await)
    }

    /// Uploads every file waiting in the outbox, returning how many landed.
    ///
    /// Each file takes a fresh write ticket, because a ticket names one file
    /// and one declared size. A failure the error calls retryable keeps the
    /// entry for the next walk; anything else retires it, because keeping an
    /// entry no attempt can satisfy is a walk that never finishes.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the outbox cannot be read. A failure on
    /// one file is reported as an event and does not stop the walk.
    pub async fn flush_outbox(&self) -> Result<usize, ContentError> {
        let waiting = self
            .client
            .with_conn(|conn| db::outbox(conn.conn()))
            .await?;
        let mut sent = 0;
        for file_id in waiting {
            match self.upload_one(file_id).await {
                Ok(()) => {
                    self.client
                        .with_conn(|conn| db::dequeue(conn.conn(), file_id))
                        .await?;
                    sent += 1;
                    let _ = self.events.send(ContentEvent::Uploaded { file_id });
                }
                Err(err) if err.is_retryable() => {
                    let _ = self.events.send(ContentEvent::UploadDeferred {
                        file_id,
                        detail: err.to_string(),
                    });
                }
                Err(err) => {
                    self.client
                        .with_conn(|conn| db::dequeue(conn.conn(), file_id))
                        .await?;
                    let _ = self.events.send(ContentEvent::UploadRefused {
                        file_id,
                        detail: err.to_string(),
                    });
                }
            }
        }
        Ok(sent)
    }

    /// One file: a write ticket, then the whole negotiation under it.
    async fn upload_one(&self, file_id: FileId) -> Result<(), ContentError> {
        let manifest = self
            .client
            .with_conn(|conn| db::load_manifest(conn.conn(), file_id))
            .await?
            .ok_or(ContentError::NoManifest { file_id })?;
        let declared_len: u64 = manifest.chunks().iter().map(|chunk| chunk.len).sum();
        let url =
            ticket::request(&self.client, file_id, ContentVerb::Write { declared_len }).await?;
        let store = self.store_for(FETCHED_CLASS);
        upload::upload(&self.http, &url, &manifest, &store).await
    }

    /// The outbox driver: the boot integrity pass, then a walk whenever one
    /// could get further than the last.
    ///
    /// Returned as a future rather than spawned, the same shape
    /// [`ConnettoClient::with_pump`] uses, so the caller decides which
    /// executor drives it. It ends when the client's event stream ends, which
    /// is when the last client clone drops.
    ///
    /// A reconnect is not the only thing that unblocks a walk, and treating it
    /// as the only one leaves offline content pending forever. The ordinary
    /// case says so: a write ticket is refused for a file the deployment
    /// cannot see yet, and what makes it visible is the entry row landing, on
    /// a connection that never dropped. A saturated upload window clears the
    /// same way. So while anything is still queued this backs off and walks
    /// again under `sleeper`, and while the outbox is empty it costs nothing,
    /// waiting on the event stream instead.
    pub async fn drive_outbox<S: Sleeper>(&self, mut sleeper: S) {
        let policy = ReconnectPolicy::default();
        let mut events = self.client.events();
        if let Err(err) = self.verify_unsent().await {
            let _ = self.events.send(ContentEvent::IntegrityPassFailed {
                detail: err.to_string(),
            });
        }
        let mut attempt: u32 = 0;
        loop {
            let _ = self.flush_outbox().await;
            let queued = self
                .client
                .with_conn(|conn| db::outbox(conn.conn()))
                .await
                .is_ok_and(|waiting| !waiting.is_empty());
            if queued {
                attempt = attempt.saturating_add(1);
                sleeper.sleep(policy.backoff(attempt)).await;
                continue;
            }
            attempt = 0;
            loop {
                match events.recv().await {
                    Ok(
                        ClientEvent::Reconnected
                        | ClientEvent::SyncStatus(SyncStatus::Connected)
                        | ClientEvent::MutationApplied { .. },
                    ) => break,
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }

    /// Where this file's bytes are to be had, for display.
    ///
    /// Unsent content answers from the chunk store or not at all: the server
    /// has never held it, so there is no URL to grant. Pinned content prefers
    /// local bytes, which is what the pin bought. Everything else answers a
    /// signed URL, and answers [`Resolved::Unavailable`] when there is no
    /// server to ask.
    ///
    /// # Errors
    ///
    /// [`ContentError::TicketRefused`] when the server will not grant a read,
    /// and [`ContentError::Replica`] on a bookkeeping read failure.
    pub async fn resolve(&self, file_id: FileId) -> Result<Resolved, ContentError> {
        if let Some(answer) = self.local_answer(file_id).await? {
            return Ok(answer);
        }
        if !self.client.with_conn(|conn| conn.is_connected()).await {
            return Ok(Resolved::Unavailable);
        }
        let url = ticket::request(&self.client, file_id, ContentVerb::Read).await?;
        Ok(Resolved::Remote { url })
    }

    /// The answer the device can give on its own, or `None` to ask a server.
    ///
    /// Unsent content answers here or nowhere, because the server has never
    /// held it. Pinned content prefers what the pin paid to keep. Anything
    /// else falls through, which is the common case chapter 18 describes as
    /// never touching the chunk store at all.
    async fn local_answer(&self, file_id: FileId) -> Result<Option<Resolved>, ContentError> {
        let Some(manifest) = self
            .client
            .with_conn(|conn| db::load_manifest(conn.conn(), file_id))
            .await?
        else {
            return Ok(None);
        };
        if self
            .client
            .with_conn(|conn| db::is_unsent(conn.conn(), file_id))
            .await?
        {
            return Ok(Some(
                self.local_bytes(&manifest)
                    .await?
                    .unwrap_or(Resolved::Unavailable),
            ));
        }
        if !self.pinned().await?.contains(&file_id) {
            return Ok(None);
        }
        self.local_bytes(&manifest).await
    }

    /// This file's bytes, from a local source or from the server.
    ///
    /// The direct read for the case chapter 18 calls a locally processed
    /// input: a caller that needs the bytes themselves rather than somewhere
    /// to point a renderer. `None` means neither this device nor the server
    /// can produce them right now.
    ///
    /// # Errors
    ///
    /// As [`resolve`](Self::resolve), plus [`ContentError::Transport`] when a
    /// download fails.
    pub async fn bytes(&self, file_id: FileId) -> Result<Option<Vec<u8>>, ContentError> {
        match self.resolve(file_id).await? {
            Resolved::Local { bytes, .. } => Ok(Some(bytes)),
            Resolved::Remote { url } => upload::download(&self.http, &url).await.map(Some),
            Resolved::Unavailable => Ok(None),
        }
    }

    /// Asks each local source in turn for the bytes this manifest describes.
    async fn local_bytes(&self, manifest: &Manifest) -> Result<Option<Resolved>, ContentError> {
        for source in &self.sources {
            if let Some(bytes) = source.bytes(manifest).await? {
                return Ok(Some(Resolved::Local {
                    source: source.name(),
                    bytes,
                }));
            }
        }
        Ok(None)
    }

    /// Keeps a query's files' bytes on this device until
    /// [`unpin_content`](Self::unpin_content).
    ///
    /// The byte-level mirror of R15's row pins, and query-shaped for the same
    /// reason: a pin over a set that changes should not need re-declaring
    /// every time it does. `file_id_column` names the result column carrying
    /// the identity, which is the one thing a row pin does not need to know.
    ///
    /// The query is validated here, so a pin that names a column its query
    /// does not return is refused now rather than failing on every later
    /// evaluation.
    ///
    /// # Errors
    ///
    /// [`ContentError::PinColumnMissing`] when the query does not return the
    /// named column, and [`ContentError::Replica`] when the record cannot be
    /// written.
    pub async fn pin_content(
        &self,
        name: &str,
        query: &str,
        file_id_column: &str,
    ) -> Result<(), ContentError> {
        if file_id_column.contains(['[', ']']) {
            return Err(ContentError::PinColumnMissing {
                name: name.to_owned(),
                column: file_id_column.to_owned(),
            });
        }
        let probe = pin_sql(query, file_id_column);
        let name = name.to_owned();
        let query = query.to_owned();
        let column = file_id_column.to_owned();
        self.client
            .with_conn(move |conn| {
                if diesel::sql_query(format!("{probe} LIMIT 0"))
                    .execute(conn.conn())
                    .is_err()
                {
                    return Err(ContentError::PinColumnMissing { name, column });
                }
                conn.transact_with_bookkeeping(
                    |c| db::put_pin(c, &name, &query, &column).map_err(ContentError::Replica),
                    |_| Ok::<(), ContentError>(()),
                )
                .map(|_| ())
            })
            .await
    }

    /// Ends the pin under `name`. Unknown names are a no-op.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the record cannot be removed.
    pub async fn unpin_content(&self, name: &str) -> Result<(), ContentError> {
        let name = name.to_owned();
        self.client
            .with_conn(move |conn| {
                conn.transact_with_bookkeeping(
                    |c| db::drop_pin(c, &name),
                    |_| Ok::<(), diesel::result::Error>(()),
                )
                .map(|_| ())
            })
            .await
            .map_err(ContentError::Replica)
    }

    /// Every content pin, as name, query and file-id column, in name order.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when the records cannot be read.
    pub async fn content_pins(&self) -> Result<Vec<(String, String, String)>, ContentError> {
        self.client
            .with_conn(|conn| db::pins(conn.conn()))
            .await
            .map_err(ContentError::Replica)
    }

    /// The files every pin currently names.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] when a pin's query cannot be evaluated.
    pub async fn pinned(&self) -> Result<HashSet<FileId>, ContentError> {
        self.client
            .with_conn(|conn| {
                let c = conn.conn();
                let mut wanted = HashSet::new();
                for (_, query, column) in db::pins(c)? {
                    let rows: Vec<PinnedId> =
                        diesel::sql_query(pin_sql(&query, &column)).load(c)?;
                    for row in rows {
                        if let Ok(bytes) = <[u8; 32]>::try_from(row.file_id.as_slice()) {
                            wanted.insert(FileId::from_bytes(bytes));
                        }
                    }
                }
                Ok(wanted)
            })
            .await
    }

    /// Fetches every pinned file this device does not hold, returning the ones
    /// that arrived.
    ///
    /// A pinned file's bytes come down whole and are re-chunked locally: the
    /// identity is BLAKE3 over the whole file, so the download proves itself,
    /// and chunking is deterministic, so the chunk keys come out the same as
    /// anywhere else. A ranged fetch by chunk is not available, because a
    /// device that has never seen the file holds no manifest to drive one and
    /// the file server serves assembled bytes rather than chunks.
    ///
    /// # Errors
    ///
    /// [`ContentError::IdentityMismatch`] when downloaded bytes are not the
    /// file that was asked for, plus the ticket and transport failures
    /// [`resolve`](Self::resolve) reports.
    pub async fn fetch_pinned(&self) -> Result<Vec<FileId>, ContentError> {
        let mut arrived = Vec::new();
        for file_id in self.pinned().await? {
            if self.already_local(file_id).await?
                || !self.client.with_conn(|conn| conn.is_connected()).await
            {
                continue;
            }
            self.fetch_one(file_id).await?;
            arrived.push(file_id);
            let _ = self.events.send(ContentEvent::Fetched { file_id });
        }
        Ok(arrived)
    }

    /// Whether a local source already serves this file's bytes.
    async fn already_local(&self, file_id: FileId) -> Result<bool, ContentError> {
        let Some(manifest) = self
            .client
            .with_conn(|conn| db::load_manifest(conn.conn(), file_id))
            .await?
        else {
            return Ok(false);
        };
        Ok(self.local_bytes(&manifest).await?.is_some())
    }

    /// Downloads one file whole, proves it is the file that was asked for, and
    /// re-chunks it into the store under its own manifest.
    async fn fetch_one(&self, file_id: FileId) -> Result<(), ContentError> {
        let url = ticket::request(&self.client, file_id, ContentVerb::Read).await?;
        let bytes = upload::download(&self.http, &url).await?;
        let _writing = self.content_writes.lock().await;
        let store = self.store_for(FETCHED_CLASS);
        let manifest = process_file_from_reader(bytes.as_slice(), FETCHED_CLASS, &store)
            .await
            .map_err(|err| ContentError::Store(err.to_string()))?;
        if manifest.file_id() != file_id {
            return Err(ContentError::IdentityMismatch {
                expected: file_id,
                actual: manifest.file_id(),
            });
        }
        self.client
            .with_conn(|conn| {
                conn.transact_with_bookkeeping(
                    |c| db::put_manifest(c, &manifest),
                    |_| Ok::<(), diesel::result::Error>(()),
                )
            })
            .await
            .map_err(ContentError::Replica)
            .map(|_| ())
    }
}

impl<T, B, H> ContentClient<T, B, H>
where
    T: Transport + MaybeSend + 'static,
    T::Error: Display,
    B: ChunkInventory + Clone + Sync + MaybeSend + 'static,
    H: ContentHttp,
{
    /// Reclaims the disk every byte nothing wants is holding.
    ///
    /// The byte-level mirror of R15's `tidy`, and application-callable for the
    /// same reason: only the application knows why it holds data. A manifest
    /// survives when the file is unsent, because those bytes cannot be fetched
    /// again, or when a pin names it. Everything else is cache and goes.
    ///
    /// Then every chunk file the store holds that no surviving manifest names
    /// is deleted. Enumerating the store rather than the hashes an eviction
    /// released is what makes the second half possible: a staging call whose
    /// transaction failed leaves chunk files no manifest ever mentioned, and
    /// nothing derived from manifests could ever name them. Two manifests may
    /// share a chunk, so a chunk goes only when the whole surviving set is
    /// silent about it.
    ///
    /// The order is what makes a crash safe. The manifest rows go first and
    /// commit, then the files, so an interruption leaves chunk files nothing
    /// points at, which the next pass collects, rather than a manifest
    /// pointing at bytes that are gone. This pass is why that is safe.
    ///
    /// Returns how many files were evicted, which counts manifests rather than
    /// chunk files: an orphan that never had a manifest was never a file this
    /// device could name.
    ///
    /// # Errors
    ///
    /// [`ContentError::Replica`] on a bookkeeping failure and
    /// [`ContentError::Store`] when the store cannot be listed or a chunk file
    /// cannot be removed.
    pub async fn tidy_content(&self) -> Result<usize, ContentError> {
        let pinned = self.pinned().await?;
        let _writing = self.content_writes.lock().await;
        let (evicted, referenced) = self
            .client
            .with_conn(|conn| {
                conn.transact_with_bookkeeping(
                    |c| {
                        let evicted = evict_uncovered(c, &pinned)?;
                        Ok((evicted, db::referenced_hashes(c)?))
                    },
                    |_| Ok::<(), ContentError>(()),
                )
                // The application half writes nothing here: eviction is
                // entirely connetto's own bookkeeping, and using the same
                // primitive keeps one transaction shape for every content
                // write.
                .map(|(counted, ())| counted)
            })
            .await?;
        self.delete_unreferenced(&referenced).await?;
        Ok(evicted)
    }

    /// Deletes every chunk the store holds that `referenced` does not name.
    async fn delete_unreferenced(
        &self,
        referenced: &HashSet<connetto_file_core::ChunkHash>,
    ) -> Result<(), ContentError> {
        let store = self.store_for(FETCHED_CLASS);
        let held = store
            .stored_hashes()
            .await
            .map_err(|err| ContentError::Store(err.to_string()))?;
        for hash in held {
            if referenced.contains(&hash) {
                continue;
            }
            store
                .delete_chunk(&hash)
                .await
                .map_err(|err| ContentError::Store(err.to_string()))?;
        }
        Ok(())
    }
}

/// One file identity out of a pin query.
#[derive(diesel::QueryableByName)]
struct PinnedId {
    /// The identity bytes the pin's named column carried.
    #[diesel(sql_type = diesel::sql_types::Binary)]
    file_id: Vec<u8>,
}

/// Drops every manifest nothing covers and answers how many went.
///
/// The chunk files are not touched here. The rows have to commit before any
/// file goes, because the reverse order leaves a manifest pointing at bytes
/// that are gone.
fn evict_uncovered(
    conn: &mut SqliteConnection,
    pinned: &HashSet<FileId>,
) -> Result<usize, ContentError> {
    let mut evicted = 0;
    for file_id in db::all_manifests(conn)? {
        if evictable(conn, pinned, file_id)?.is_none() {
            continue;
        }
        db::drop_manifest(conn, file_id)?;
        evicted += 1;
    }
    Ok(evicted)
}

/// The manifest to evict, or `None` when something still wants this file.
fn evictable(
    conn: &mut SqliteConnection,
    pinned: &HashSet<FileId>,
    file_id: FileId,
) -> Result<Option<Manifest>, ContentError> {
    if pinned.contains(&file_id) || db::is_unsent(conn, file_id)? {
        return Ok(None);
    }
    db::load_manifest(conn, file_id)
}

/// Wraps a pin's query so one fixed column name comes back.
///
/// The wrap costs nothing: SQLite flattens a bare subselect, which R58
/// measured on the server side of the same pattern.
///
/// The column is bracket-quoted rather than double-quoted, and the difference
/// is load-bearing. SQLite resolves a double-quoted identifier that names no
/// column as a string literal instead of refusing it, so a pin naming a
/// column its query does not return would be accepted and would then answer
/// the text of its own column name for every row, as a file identity. Bracket
/// quoting has no such fallback and reports `no such column`.
fn pin_sql(query: &str, column: &str) -> String {
    format!("SELECT [{column}] AS file_id FROM ({query}) AS _connetto_pin")
}
