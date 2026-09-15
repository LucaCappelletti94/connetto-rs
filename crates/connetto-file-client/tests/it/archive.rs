//! Device archive contracts for unsent content.

use connetto_client::live::ConnettoClient;
use connetto_client::{ArchiveAttachment, ExportScope, ImportChoices};
use connetto_file_client::{
    ContentClient, ContentError, ContentEvent, FsStore, FsStoreError, Resolved,
};
use connetto_file_core::{ChunkHash, ChunkStore, FileId, MimeClass};
use core::fmt::Write as FmtWrite;
use core::sync::atomic::{AtomicUsize, Ordering};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;
use tokio::sync::broadcast;

use crate::support::{
    RecordingHttp, Scripted, attach_content, connected_client, connected_content_bulk_failing,
    insert_row_and_pin_album, learn_file_id, offline_client, offline_content, photos, stage_photo,
};

const PHOTO: &[u8] = b"an offline photograph that must survive a device replacement";
const CACHE: &[u8] = b"a fetched photograph the server can provide again";

#[tokio::test]
async fn unsent_content_restores_under_the_receiving_key_with_its_row_and_outbox() {
    let source_dir = tempdir().expect("source directory");
    let (archive, file_id, source_ciphertext) = export_source(source_dir.path()).await;

    let target_dir = tempdir().expect("target directory");
    let (target, target_client) = import_target(target_dir.path(), archive).await;
    assert_restored(&target, &target_client, file_id).await;

    let target_ciphertext = only_chunk(&target_dir.path().join("chunks"));
    assert_ne!(target_ciphertext, source_ciphertext);
    assert_ne!(target_ciphertext, PHOTO);
}

async fn export_source(base: &std::path::Path) -> (Vec<u8>, FileId, Vec<u8>) {
    let client = offline_client(&base.join("replica.sqlite"));
    let chunks = base.join("chunks");
    let content = ContentClient::attach(
        client,
        FsStore::new(&chunks),
        [1; 32],
        RecordingHttp::default(),
    )
    .await
    .expect("attach source content");
    let file_id = stage_photo(&content, 1, PHOTO, MimeClass::Jpeg).await;
    let archive = content
        .export_local_data(ExportScope::Unsynced, Vec::new())
        .await
        .expect("export unsent content");
    (archive, file_id, only_chunk(&chunks))
}

async fn import_target(
    base: &std::path::Path,
    archive: Vec<u8>,
) -> (
    ContentClient<Scripted, FsStore, RecordingHttp>,
    ConnettoClient<Scripted>,
) {
    let client = offline_client(&base.join("replica.sqlite"));
    let content = ContentClient::attach(
        client.clone(),
        FsStore::new(base.join("chunks")),
        [2; 32],
        RecordingHttp::default(),
    )
    .await
    .expect("attach target content");
    let mut plan = content
        .prepare_local_data_import(std::io::Cursor::new(archive))
        .await
        .expect("verify archive");
    assert_eq!(plan.content_files(), 1);
    content
        .apply_local_data_import(&mut plan, &ImportChoices::keeping_the_file())
        .await
        .expect("restore archive");
    (content, client)
}

async fn assert_restored(
    content: &ContentClient<Scripted, FsStore, RecordingHttp>,
    client: &ConnettoClient<Scripted>,
    file_id: FileId,
) {
    let Resolved::Local { bytes, .. } = content.resolve(file_id).await.expect("resolve restored")
    else {
        panic!("restored unsent content must resolve locally");
    };
    assert_eq!(bytes, PHOTO);
    let row_id: Vec<u8> = client
        .with_conn(|conn| {
            photos::table
                .filter(photos::id.eq(1))
                .select(photos::content_id)
                .first(conn.conn())
        })
        .await
        .expect("read restored row");
    assert_eq!(row_id, file_id.as_bytes());
    assert_eq!(
        content
            .verify_unsent()
            .await
            .expect("verify restored outbox"),
        Vec::<FileId>::new()
    );
}

#[tokio::test]
async fn fetched_cache_is_absent_from_the_archive() {
    let source_dir = tempdir().expect("source directory");
    let file_id = learn_file_id(CACHE).await;
    let client = connected_client(
        &source_dir.path().join("replica.sqlite"),
        Scripted::granting("https://content.invalid/read"),
    )
    .await;
    let content = attach_content(
        client.clone(),
        &source_dir.path().join("chunks"),
        RecordingHttp::new([(200, CACHE.to_vec())]),
    )
    .await;
    insert_row_and_pin_album(&client, &content, file_id).await;
    assert_eq!(
        content.fetch_pinned().await.expect("fetch cache"),
        vec![file_id]
    );

    let archive = content
        .export_local_data(ExportScope::Unsynced, Vec::new())
        .await
        .expect("export");
    let target_dir = tempdir().expect("target directory");
    let target = attach_content(
        offline_client(&target_dir.path().join("replica.sqlite")),
        &target_dir.path().join("chunks"),
        RecordingHttp::default(),
    )
    .await;
    let plan = target
        .prepare_local_data_import(std::io::Cursor::new(archive))
        .await
        .expect("verify archive");
    assert_eq!(plan.content_files(), 0, "refetchable cache does not travel");
}

#[tokio::test]
async fn independently_pending_content_restores_without_replica_rows_or_writes() {
    let source_dir = tempdir().expect("source directory");
    let source_client = offline_client(&source_dir.path().join("replica.sqlite"));
    let file_id = FileId::from_chunks([PHOTO]);
    let archive = raw_archive(
        &source_client,
        content_attachments(file_id, ChunkHash::from_data(PHOTO), PHOTO.len(), PHOTO),
    )
    .await;

    let target_dir = tempdir().expect("target directory");
    let target = attach_content(
        offline_client(&target_dir.path().join("replica.sqlite")),
        &target_dir.path().join("chunks"),
        RecordingHttp::default(),
    )
    .await;
    let mut plan = target
        .prepare_local_data_import(std::io::Cursor::new(&archive[..]))
        .await
        .expect("prepare import");
    assert_eq!(plan.replica_plan().device_only_rows(), 0);
    assert_eq!(plan.replica_plan().queued_writes(), 0);
    target
        .apply_local_data_import(&mut plan, &ImportChoices::keeping_the_file())
        .await
        .expect("restore pending content");

    let exported = target
        .export_local_data(ExportScope::Unsynced, Vec::new())
        .await
        .expect("re-export restored outbox");
    let exported_plan = target
        .prepare_local_data_import(std::io::Cursor::new(exported))
        .await
        .expect("verify re-export");
    assert_eq!(exported_plan.content_files(), 1);
}

#[tokio::test]
async fn corrupt_lengths_hashes_and_file_identities_are_refused_before_apply() {
    let dir = tempdir().expect("directory");
    let client = offline_client(&dir.path().join("replica.sqlite"));
    let content = attach_content(
        client.clone(),
        &dir.path().join("chunks"),
        RecordingHttp::default(),
    )
    .await;
    let hash = ChunkHash::from_data(PHOTO);
    let file_id = FileId::from_chunks([PHOTO]);

    let wrong_length = raw_archive(
        &client,
        content_attachments(file_id, hash, PHOTO.len() + 1, PHOTO),
    )
    .await;
    assert_archive_error(&content, &wrong_length, "has length").await;

    let mut tampered = PHOTO.to_vec();
    *tampered.first_mut().expect("photo is nonempty") ^= 1;
    let wrong_hash = raw_archive(
        &client,
        content_attachments(file_id, hash, PHOTO.len(), &tampered),
    )
    .await;
    assert_archive_error(&content, &wrong_hash, "has hash").await;

    let wrong_identity = raw_archive(
        &client,
        content_attachments(FileId::from_bytes([0; 32]), hash, PHOTO.len(), PHOTO),
    )
    .await;
    assert_archive_error(&content, &wrong_identity, "reconstructs as").await;
}

#[tokio::test]
async fn attachments_owned_by_another_layer_are_refused() {
    let dir = tempdir().expect("directory");
    let client = offline_client(&dir.path().join("replica.sqlite"));
    let content = attach_content(
        client.clone(),
        &dir.path().join("chunks"),
        RecordingHttp::default(),
    )
    .await;
    let mut entries = content_attachments(
        FileId::from_chunks([PHOTO]),
        ChunkHash::from_data(PHOTO),
        PHOTO.len(),
        PHOTO,
    );
    entries.push((
        ArchiveAttachment::new("search/index.json", 2).expect("foreign attachment decl"),
        b"{}".to_vec(),
    ));
    let archive = raw_archive(&client, entries).await;

    assert_archive_error(&content, &archive, "search/index.json is not handled").await;
}

/// Returns `(declaration, bytes)` pairs for the index and one chunk, with
/// `len` going into the manifest JSON (may differ from `bytes.len()` in
/// error-path tests).
fn content_attachments(
    file_id: FileId,
    hash: ChunkHash,
    len: usize,
    bytes: &[u8],
) -> Vec<(ArchiveAttachment, Vec<u8>)> {
    let index = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "files": [{
            "file_id": file_id.to_string(),
            "chunks": [{"hash": hash.to_string(), "len": len}],
        }],
    }))
    .expect("encode test index");
    let index_len = u64::try_from(index.len()).expect("index len fits u64");
    let chunk_len = u64::try_from(bytes.len()).expect("chunk len fits u64");
    vec![
        (
            ArchiveAttachment::new("content/manifests.json", index_len).expect("manifest decl"),
            index,
        ),
        (
            ArchiveAttachment::new(format!("content/chunks/{hash}"), chunk_len)
                .expect("chunk decl"),
            bytes.to_vec(),
        ),
    ]
}

async fn raw_archive(
    client: &ConnettoClient<Scripted>,
    entries: Vec<(ArchiveAttachment, Vec<u8>)>,
) -> Vec<u8> {
    client
        .with_conn(move |conn| {
            let decls: Vec<_> = entries.iter().map(|(d, _)| d.clone()).collect();
            let mut export =
                conn.export_local_data_with_attachments(ExportScope::Unsynced, &decls, Vec::new())?;
            for (decl, body) in &entries {
                export.write_attachment(decl.path(), body)?;
            }
            export.finish()
        })
        .await
        .expect("build test archive")
}

async fn assert_archive_error(
    content: &ContentClient<Scripted, FsStore, RecordingHttp>,
    bytes: &[u8],
    expected: &str,
) {
    let error = content
        .prepare_local_data_import(std::io::Cursor::new(bytes))
        .await
        .expect_err("corrupt content must be refused");
    assert!(
        matches!(error, ContentError::Archive(_)) && error.to_string().contains(expected),
        "expected {expected:?} in {error}"
    );
}

fn only_chunk(root: &std::path::Path) -> Vec<u8> {
    let directory = std::fs::read_dir(root)
        .expect("read chunk root")
        .next()
        .expect("hash prefix directory")
        .expect("read prefix entry")
        .path();
    let chunk = std::fs::read_dir(directory)
        .expect("read hash prefix")
        .next()
        .expect("chunk file")
        .expect("read chunk entry")
        .path();
    std::fs::read(chunk).expect("read ciphertext")
}

/// A replay failure after the import commits must not surface as an import
/// error: the rows, chunks and outbox entry are durable, and the outbox
/// driver retries later.
///
/// Before the fix, the `?` on `replay_pending` propagates the transport error
/// and the caller's `.expect(...)` panics here.
#[tokio::test]
async fn import_succeeds_when_replay_fails_after_commit() {
    let source_dir = tempdir().expect("source directory");
    let (archive, file_id, _) = export_source(source_dir.path()).await;

    let target_dir = tempdir().expect("target directory");
    let target = connected_content_bulk_failing(target_dir.path()).await;

    let mut plan = target
        .prepare_local_data_import(std::io::Cursor::new(archive))
        .await
        .expect("verify archive");
    // Assertion that fails before the fix: the transport error from
    // `replay_pending` propagates and panics here.
    target
        .apply_local_data_import(&mut plan, &ImportChoices::keeping_the_file())
        .await
        .expect("import must succeed even when replay fails after commit");

    // Chunks and manifest must be accessible under the target key.
    let Resolved::Local { bytes, .. } = target.resolve(file_id).await.expect("resolve restored")
    else {
        panic!("restored content must resolve locally after replay failure");
    };
    assert_eq!(bytes, PHOTO);
}

/// A content-only import wakes the outbox driver without any replica mutation.
#[tokio::test]
async fn content_only_import_wakes_outbox_driver() {
    const INTENT: &str = "https://files.test/files/\
        0000000000000000000000000000000000000000000000000000000000000000/intent?t=TOKEN";
    let source_dir = tempdir().expect("source dir");
    let source = offline_client(&source_dir.path().join("replica.sqlite"));
    let file_id = FileId::from_chunks([PHOTO]);
    let archive = raw_archive(
        &source,
        content_attachments(file_id, ChunkHash::from_data(PHOTO), PHOTO.len(), PHOTO),
    )
    .await;
    let target_dir = tempdir().expect("target dir");
    let http = RecordingHttp::new([(200_u16, br#"{"needed":[]}"#.to_vec()), (200_u16, vec![])]);
    let target = attach_content(
        connected_client(
            &target_dir.path().join("replica.sqlite"),
            Scripted::granting(INTENT),
        )
        .await,
        &target_dir.path().join("chunks"),
        http,
    )
    .await;
    let mut plan = target
        .prepare_local_data_import(std::io::Cursor::new(archive))
        .await
        .expect("prepare");
    let mut events = target.events();
    // The driver parks after the boot pass. The import signals import_notify,
    // waking the driver, which uploads the file and emits Uploaded.
    tokio::select! {
        () = target.drive_outbox(|_: core::time::Duration| core::future::ready(())) => {
            panic!("drive_outbox must not return while the test runs");
        }
        result = tokio::time::timeout(
            core::time::Duration::from_secs(5),
            async {
                tokio::time::sleep(core::time::Duration::from_millis(50)).await;
                target
                    .apply_local_data_import(&mut plan, &ImportChoices::keeping_the_file())
                    .await
                    .expect("import");
                loop {
                    match events.recv().await {
                        Ok(ContentEvent::Uploaded { .. }) => break,
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => {
                            panic!("event stream closed before Uploaded arrived");
                        }
                    }
                }
            },
        ) => {
            result.expect("Uploaded event must arrive within five seconds of the import");
        }
    }
}

/// `forget_retired_content` wraps the whole list in one transaction.
#[tokio::test]
async fn forget_retired_content_is_all_or_nothing() {
    let dir = tempdir().expect("temp dir");
    let (client, content) = offline_content(dir.path()).await;
    let file_a = FileId::from_chunks([b"file alpha" as &[u8]]);
    let file_b = FileId::from_chunks([b"file beta" as &[u8]]);
    let (mut hex_a, mut hex_b) = (String::with_capacity(64), String::with_capacity(64));
    for b in file_a.as_bytes() {
        write!(hex_a, "{b:02x}").expect("write to String infallible");
    }
    for b in file_b.as_bytes() {
        write!(hex_b, "{b:02x}").expect("write to String infallible");
    }
    // Insert both and install a trigger that aborts any delete when one row remains.
    client
        .with_conn(|conn| {
            conn.conn().batch_execute(&format!(
                "INSERT OR IGNORE INTO _connetto_content_retired (file_id) VALUES (x'{hex_a}'); \
                 INSERT OR IGNORE INTO _connetto_content_retired (file_id) VALUES (x'{hex_b}'); \
                 CREATE TRIGGER test_abort_second_forget \
                 BEFORE DELETE ON _connetto_content_retired \
                 WHEN (SELECT COUNT(*) FROM _connetto_content_retired) = 1 \
                 BEGIN SELECT RAISE(ABORT, 'test-induced failure'); END",
            ))
        })
        .await
        .expect("insert retired records and trigger");
    let result = content.forget_retired_content(&[file_a, file_b]).await;
    assert!(
        result.is_err(),
        "second delete must fail due to the trigger"
    );
    let still_retired = content.retired_content().await.expect("read retired");
    let present: std::collections::HashSet<_> = still_retired.into_iter().collect();
    assert!(
        present.contains(&file_a),
        "file_a must remain after transaction rollback"
    );
    assert!(
        present.contains(&file_b),
        "file_b must remain after transaction rollback"
    );
}

/// A refused import leaves the chunk store exactly as it was before the attempt.
///
/// Validation is a read-only first pass. Nothing is written to the store
/// until the entire archive checks out. This case fails if validation and
/// writing are reordered so that any chunk is written before the failure.
#[tokio::test]
async fn refused_import_leaves_chunk_store_empty() {
    const CHUNK_A: &[u8] = b"first chunk of content for file A";
    const CHUNK_B: &[u8] = b"second chunk of content for file B";
    let dir = tempdir().expect("temp dir");
    let client = offline_client(&dir.path().join("replica.sqlite"));
    let content = attach_content(
        client.clone(),
        &dir.path().join("chunks"),
        RecordingHttp::default(),
    )
    .await;

    let hash_a = ChunkHash::from_data(CHUNK_A);
    let hash_b = ChunkHash::from_data(CHUNK_B);
    let file_id_a = FileId::from_chunks([CHUNK_A]);
    // File B declares a wrong identity so validation fails after reading both chunks.
    let bad_id = FileId::from_bytes([0xff; 32]);

    let index = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "files": [
            {
                "file_id": file_id_a.to_string(),
                "chunks": [{"hash": hash_a.to_string(), "len": CHUNK_A.len()}],
            },
            {
                "file_id": bad_id.to_string(),
                "chunks": [{"hash": hash_b.to_string(), "len": CHUNK_B.len()}],
            },
        ],
    }))
    .expect("encode test index");
    let index_len = u64::try_from(index.len()).expect("index len fits u64");
    let len_a = u64::try_from(CHUNK_A.len()).expect("len_a fits u64");
    let len_b = u64::try_from(CHUNK_B.len()).expect("len_b fits u64");
    let archive = raw_archive(
        &client,
        vec![
            (
                ArchiveAttachment::new("content/manifests.json", index_len).expect("index decl"),
                index,
            ),
            (
                ArchiveAttachment::new(format!("content/chunks/{hash_a}"), len_a)
                    .expect("chunk a decl"),
                CHUNK_A.to_vec(),
            ),
            (
                ArchiveAttachment::new(format!("content/chunks/{hash_b}"), len_b)
                    .expect("chunk b decl"),
                CHUNK_B.to_vec(),
            ),
        ],
    )
    .await;

    let error = content
        .prepare_local_data_import(std::io::Cursor::new(archive.as_slice()))
        .await
        .expect_err("tampered file identity must be refused");
    assert!(
        matches!(error, ContentError::Archive(_)) && error.to_string().contains("reconstructs as"),
        "expected 'reconstructs as' in {error}"
    );

    let store = FsStore::new(dir.path().join("chunks"));
    assert!(
        !store.has_chunk(&hash_a).await.expect("probe chunk a"),
        "chunk a must not be in the store after a refused import"
    );
    assert!(
        !store.has_chunk(&hash_b).await.expect("probe chunk b"),
        "chunk b must not be in the store after a refused import"
    );
}

/// A sink that reports how many bytes the archive has taken so far.
struct CountingSink {
    inner: Vec<u8>,
    written: Arc<AtomicUsize>,
}

impl std::io::Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.written.fetch_add(written, Ordering::Relaxed);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// A store that records what the sink had taken at each chunk read.
#[derive(Clone)]
struct SpyStore {
    inner: FsStore,
    written_at_read: Arc<Mutex<Vec<usize>>>,
    written: Arc<AtomicUsize>,
}

impl ChunkStore for SpyStore {
    type Error = FsStoreError;

    async fn write_chunk(&self, hash: &ChunkHash, data: &[u8]) -> Result<(), FsStoreError> {
        self.inner.write_chunk(hash, data).await
    }

    async fn read_chunk(&self, hash: &ChunkHash) -> Result<Vec<u8>, FsStoreError> {
        let bytes = self.inner.read_chunk(hash).await?;
        let taken = self.written.load(Ordering::Relaxed);
        self.written_at_read
            .lock()
            .expect("the recorder is not poisoned")
            .push(taken);
        Ok(bytes)
    }

    async fn has_chunk(&self, hash: &ChunkHash) -> Result<bool, FsStoreError> {
        self.inner.has_chunk(hash).await
    }

    async fn delete_chunk(&self, hash: &ChunkHash) -> Result<(), FsStoreError> {
        self.inner.delete_chunk(hash).await
    }
}

/// An export reads one chunk and writes its entry before it reads the next,
/// so the bytes it holds are one chunk's worth whatever the archive weighs.
///
/// The recorded counts grow between consecutive reads only when the previous
/// chunk left for the archive before the next one arrived.
#[tokio::test]
async fn export_reads_one_chunk_at_a_time() {
    const FILE_A: &[u8] = b"export interleave test: file alpha";
    const FILE_B: &[u8] = b"export interleave test: file beta";

    let dir = tempdir().expect("temp dir");
    let written = Arc::new(AtomicUsize::new(0));
    let written_at_read: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let spy = SpyStore {
        inner: FsStore::new(dir.path().join("chunks")),
        written_at_read: Arc::clone(&written_at_read),
        written: Arc::clone(&written),
    };
    let client = offline_client(&dir.path().join("replica.sqlite"));
    let content = ContentClient::attach(client, spy, [1; 32], RecordingHttp::default())
        .await
        .expect("attach content");

    // Stage two files with distinct content to produce two distinct chunks.
    content
        .stage(FILE_A, MimeClass::Generic, |conn, file_id| {
            diesel::insert_into(photos::table)
                .values((
                    photos::id.eq(1i32),
                    photos::content_id.eq(file_id.as_bytes().to_vec()),
                ))
                .execute(conn)
                .map(|_| ())
        })
        .await
        .expect("stage file A");
    content
        .stage(FILE_B, MimeClass::Generic, |conn, file_id| {
            diesel::insert_into(photos::table)
                .values((
                    photos::id.eq(2i32),
                    photos::content_id.eq(file_id.as_bytes().to_vec()),
                ))
                .execute(conn)
                .map(|_| ())
        })
        .await
        .expect("stage file B");

    let sink = CountingSink {
        inner: Vec::new(),
        written: Arc::clone(&written),
    };
    content
        .export_local_data(ExportScope::Unsynced, sink)
        .await
        .expect("export");

    let reads = written_at_read
        .lock()
        .expect("the recorder is not poisoned")
        .clone();
    assert_eq!(
        reads.len(),
        2,
        "two distinct chunks produce two store reads"
    );
    assert!(
        reads[0] < reads[1],
        "chunk 1 read before chunk 0 was written (reads[0]={}, reads[1]={})",
        reads[0],
        reads[1],
    );
}
