//! Plaintext content attachments in the device archive.

use std::collections::{HashMap, HashSet};

use connetto_client::ArchiveAttachment;
use connetto_file_core::{ChunkHash, ChunkMeta, FileId, FileIdHasher, Manifest};
use serde::{Deserialize, Serialize};

use crate::ContentError;

pub(crate) const MANIFESTS_PATH: &str = "content/manifests.json";
const CHUNK_PREFIX: &str = "content/chunks/";
const VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentIndex {
    version: u32,
    files: Vec<FileRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    file_id: String,
    chunks: Vec<ChunkRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkRecord {
    hash: String,
    len: u64,
}

pub(crate) struct DecodedContent {
    pub(crate) manifests: Vec<Manifest>,
    pub(crate) chunks: Vec<(ChunkHash, Vec<u8>)>,
}

pub(crate) fn encode(
    manifests: &[Manifest],
    mut chunks: Vec<(ChunkHash, Vec<u8>)>,
) -> Result<Vec<ArchiveAttachment>, ContentError> {
    let files = manifests
        .iter()
        .map(|manifest| FileRecord {
            file_id: manifest.file_id().to_string(),
            chunks: manifest
                .chunks()
                .iter()
                .map(|chunk| ChunkRecord {
                    hash: chunk.hash.to_string(),
                    len: chunk.len,
                })
                .collect(),
        })
        .collect();
    let index = serde_json::to_vec_pretty(&ContentIndex {
        version: VERSION,
        files,
    })
    .map_err(|error| archive_error(format!("encode content manifests: {error}")))?;
    let mut attachments = Vec::with_capacity(chunks.len() + 1);
    attachments.push(ArchiveAttachment::new(MANIFESTS_PATH, index)?);
    chunks.sort_unstable_by_key(|(hash, _)| hash.to_string());
    for (hash, bytes) in chunks {
        attachments.push(ArchiveAttachment::new(
            format!("{CHUNK_PREFIX}{hash}"),
            bytes,
        )?);
    }
    Ok(attachments)
}

pub(crate) fn decode(attachments: &[ArchiveAttachment]) -> Result<DecodedContent, ContentError> {
    let content: Vec<_> = attachments
        .iter()
        .filter(|attachment| attachment.path().starts_with("content/"))
        .collect();
    if content.is_empty() {
        return Ok(DecodedContent {
            manifests: Vec::new(),
            chunks: Vec::new(),
        });
    }
    let index = decode_index(&content)?;
    let chunks = decode_chunks(&content)?;
    let manifests = decode_manifests(&index.files, &chunks)?;
    Ok(DecodedContent {
        manifests,
        chunks: chunks.into_iter().collect(),
    })
}

fn decode_index(content: &[&ArchiveAttachment]) -> Result<ContentIndex, ContentError> {
    let indices: Vec<_> = content
        .iter()
        .filter(|attachment| attachment.path() == MANIFESTS_PATH)
        .collect();
    let [index] = indices.as_slice() else {
        return Err(archive_error(
            "content attachments require exactly one content/manifests.json".to_owned(),
        ));
    };
    let index: ContentIndex = serde_json::from_slice(index.bytes())
        .map_err(|error| archive_error(format!("decode content manifests: {error}")))?;
    if index.version != VERSION {
        return Err(archive_error(format!(
            "content manifests version {} is not supported",
            index.version
        )));
    }
    Ok(index)
}

fn decode_chunks(
    content: &[&ArchiveAttachment],
) -> Result<HashMap<ChunkHash, Vec<u8>>, ContentError> {
    let mut chunks = HashMap::new();
    for attachment in content {
        if attachment.path() == MANIFESTS_PATH {
            continue;
        }
        let Some(name) = attachment.path().strip_prefix(CHUNK_PREFIX) else {
            return Err(archive_error(format!(
                "unknown content attachment {}",
                attachment.path()
            )));
        };
        let hash = ChunkHash::from_bytes(decode_hash(name)?);
        if chunks.insert(hash, attachment.bytes().to_vec()).is_some() {
            return Err(archive_error(format!("content chunk {name} is repeated")));
        }
    }
    Ok(chunks)
}

fn decode_manifests(
    files: &[FileRecord],
    chunks: &HashMap<ChunkHash, Vec<u8>>,
) -> Result<Vec<Manifest>, ContentError> {
    let mut file_ids = HashSet::new();
    let mut referenced = HashSet::new();
    let mut manifests = Vec::with_capacity(files.len());
    for file in files {
        let manifest = decode_manifest(file, chunks, &mut referenced)?;
        if !file_ids.insert(manifest.file_id()) {
            return Err(archive_error(format!(
                "content file {} is repeated",
                manifest.file_id()
            )));
        }
        manifests.push(manifest);
    }
    if let Some(extra) = chunks.keys().find(|hash| !referenced.contains(hash)) {
        return Err(archive_error(format!(
            "content chunk {extra} is not named by a manifest"
        )));
    }
    Ok(manifests)
}

fn decode_manifest(
    file: &FileRecord,
    chunks: &HashMap<ChunkHash, Vec<u8>>,
    referenced: &mut HashSet<ChunkHash>,
) -> Result<Manifest, ContentError> {
    let file_id = FileId::from_bytes(decode_hash(&file.file_id)?);
    if file.chunks.is_empty() {
        return Err(archive_error(format!(
            "content file {file_id} has no chunks"
        )));
    }
    let mut hasher = FileIdHasher::new();
    let mut metas = Vec::with_capacity(file.chunks.len());
    for chunk in &file.chunks {
        metas.push(decode_chunk(chunk, chunks, referenced, &mut hasher)?);
    }
    let actual = hasher.finalize();
    if actual != file_id {
        return Err(archive_error(format!(
            "content file {file_id} reconstructs as {actual}"
        )));
    }
    Ok(Manifest::new(file_id, metas))
}

fn decode_chunk(
    chunk: &ChunkRecord,
    chunks: &HashMap<ChunkHash, Vec<u8>>,
    referenced: &mut HashSet<ChunkHash>,
    hasher: &mut FileIdHasher,
) -> Result<ChunkMeta, ContentError> {
    let hash = ChunkHash::from_bytes(decode_hash(&chunk.hash)?);
    let bytes = chunks
        .get(&hash)
        .ok_or_else(|| archive_error(format!("content chunk {hash} is absent")))?;
    if u64::try_from(bytes.len()).ok() != Some(chunk.len) {
        return Err(archive_error(format!(
            "content chunk {hash} has length {}, expected {}",
            bytes.len(),
            chunk.len
        )));
    }
    let actual = ChunkHash::from_data(bytes);
    if actual != hash {
        return Err(archive_error(format!(
            "content chunk {hash} has hash {actual}"
        )));
    }
    hasher.update(bytes);
    referenced.insert(hash);
    Ok(ChunkMeta {
        hash,
        len: chunk.len,
    })
}

fn decode_hash(value: &str) -> Result<[u8; 32], ContentError> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return Err(archive_error(format!(
            "content hash {value:?} is not 64 lowercase hexadecimal characters"
        )));
    }
    let mut decoded = [0u8; 32];
    for (at, pair) in bytes.chunks(2).enumerate() {
        decoded[at] = (nibble(pair[0]).ok_or_else(|| invalid_hash(value))? << 4)
            | nibble(pair[1]).ok_or_else(|| invalid_hash(value))?;
    }
    Ok(decoded)
}

const fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn invalid_hash(value: &str) -> ContentError {
    archive_error(format!(
        "content hash {value:?} is not 64 lowercase hexadecimal characters"
    ))
}

fn archive_error(message: String) -> ContentError {
    ContentError::Archive(message)
}
