//! Device archive contracts for unsent content.

use connetto_client::live::ConnettoClient;
use connetto_client::{ArchiveAttachment, ExportScope, ImportChoices};
use connetto_file_client::{ContentClient, ContentError, FsStore, Resolved};
use connetto_file_core::{ChunkHash, FileId, MimeClass};
use diesel::prelude::*;
use tempfile::tempdir;

use crate::support::{
    RecordingHttp, Scripted, attach_content, connected_client, insert_row_and_pin_album,
    learn_file_id, offline_client, photos, stage_photo,
};

const PHOTO: &[u8] = b"an offline photograph that must survive a device replacement";
const CACHE: &[u8] = b"a fetched photograph the server can provide again";

#[tokio::test]
async fn unsent_content_restores_under_the_receiving_key_with_its_row_and_outbox() {
    let source_dir = tempdir().expect("source directory");
    let (archive, file_id, source_ciphertext) = export_source(source_dir.path()).await;

    let target_dir = tempdir().expect("target directory");
    let (target, target_client) = import_target(target_dir.path(), &archive).await;
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
        .export_local_data(ExportScope::Unsynced)
        .await
        .expect("export unsent content");
    (archive, file_id, only_chunk(&chunks))
}

async fn import_target(
    base: &std::path::Path,
    archive: &[u8],
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
    let plan = content
        .prepare_local_data_import(archive)
        .await
        .expect("verify archive");
    assert_eq!(plan.content_files(), 1);
    content
        .apply_local_data_import(&plan, &ImportChoices::keeping_the_file())
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
        .export_local_data(ExportScope::Unsynced)
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
        .prepare_local_data_import(&archive)
        .await
        .expect("verify archive");
    assert_eq!(plan.content_files(), 0, "refetchable cache does not travel");
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
    let mut attachments = content_attachments(
        FileId::from_chunks([PHOTO]),
        ChunkHash::from_data(PHOTO),
        PHOTO.len(),
        PHOTO,
    );
    attachments.push(
        ArchiveAttachment::new("search/index.json", b"{}".to_vec()).expect("foreign attachment"),
    );
    let archive = raw_archive(&client, attachments).await;

    assert_archive_error(&content, &archive, "search/index.json is not handled").await;
}

fn content_attachments(
    file_id: FileId,
    hash: ChunkHash,
    len: usize,
    bytes: &[u8],
) -> Vec<ArchiveAttachment> {
    let index = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "files": [{
            "file_id": file_id.to_string(),
            "chunks": [{"hash": hash.to_string(), "len": len}],
        }],
    }))
    .expect("encode test index");
    vec![
        ArchiveAttachment::new("content/manifests.json", index).expect("manifest attachment"),
        ArchiveAttachment::new(format!("content/chunks/{hash}"), bytes.to_vec())
            .expect("chunk attachment"),
    ]
}

async fn raw_archive(
    client: &ConnettoClient<Scripted>,
    attachments: Vec<ArchiveAttachment>,
) -> Vec<u8> {
    client
        .with_conn(|conn| {
            conn.export_local_data_with_attachments(ExportScope::Unsynced, &attachments)
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
        .prepare_local_data_import(bytes)
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
