//! Plaintext content attachments in the device archive.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};

use connetto_client::{ArchiveAttachment, ImportPlan};
use connetto_file_core::{ChunkHash, ChunkMeta, FileId, FileIdHasher, Manifest};
use serde::{Deserialize, Serialize};

use crate::ContentError;

pub(crate) const MANIFESTS_PATH: &str = "content/manifests.json";
pub(crate) const CHUNK_PREFIX: &str = "content/chunks/";
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

/// Everything an export needs before it writes one byte of content.
pub(crate) struct ContentDeclaration {
    /// The serialized `content/manifests.json` bytes.
    pub(crate) manifest_bytes: Vec<u8>,
    /// Every attachment declaration, the index first and then the chunks in
    /// hash order.
    pub(crate) attachments: Vec<ArchiveAttachment>,
    /// The distinct chunk hashes, in the order their entries are written.
    pub(crate) chunk_hashes: Vec<ChunkHash>,
}

/// Declares the content entries of one export.
///
/// Every length comes from the manifests, so no chunk is read here.
pub(crate) fn declare_content(manifests: &[Manifest]) -> Result<ContentDeclaration, ContentError> {
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
    let manifest_bytes = serde_json::to_vec_pretty(&ContentIndex {
        version: VERSION,
        files,
    })
    .map_err(|error| archive_error(format!("encode content manifests: {error}")))?;

    let index_len = u64::try_from(manifest_bytes.len())
        .map_err(|_| archive_error("manifest index overflows u64".to_owned()))?;
    let index_decl = ArchiveAttachment::new(MANIFESTS_PATH, index_len)?;

    // Hex is monotonic in the bytes it spells, so the byte order is the order
    // the entry names sort in, without a string per comparison.
    let mut seen: HashMap<ChunkHash, u64> = HashMap::new();
    for manifest in manifests {
        for chunk in manifest.chunks() {
            seen.entry(chunk.hash).or_insert(chunk.len);
        }
    }
    let mut distinct: Vec<(ChunkHash, u64)> = seen.into_iter().collect();
    distinct.sort_unstable_by_key(|(hash, _)| *hash.as_bytes());

    let mut attachments = Vec::with_capacity(distinct.len() + 1);
    attachments.push(index_decl);
    let mut chunk_hashes = Vec::with_capacity(distinct.len());
    for (hash, len) in distinct {
        attachments.push(ArchiveAttachment::new(
            format!("{CHUNK_PREFIX}{hash}"),
            len,
        )?);
        chunk_hashes.push(hash);
    }

    Ok(ContentDeclaration {
        manifest_bytes,
        attachments,
        chunk_hashes,
    })
}

/// Validates every content attachment the plan names and writes nothing.
///
/// Returns the manifests and the distinct chunk hashes in the order
/// [`declare_content`] writes them.
pub(crate) fn validate_import<R: Read + Seek>(
    plan: &mut ImportPlan<R>,
) -> Result<(Vec<Manifest>, Vec<ChunkHash>), ContentError> {
    let attachments = plan.attachments();

    if let Some(bad) = attachments
        .iter()
        .find(|a| !a.path().starts_with("content/"))
    {
        return Err(archive_error(format!(
            "archive attachment {} is not handled by the content importer",
            bad.path()
        )));
    }

    if attachments.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut chunk_decls: HashMap<ChunkHash, u64> = HashMap::new();
    for attachment in attachments {
        let path = attachment.path();
        if path == MANIFESTS_PATH {
            continue;
        }
        let Some(name) = path.strip_prefix(CHUNK_PREFIX) else {
            return Err(archive_error(format!("unknown content attachment {path}")));
        };
        let hash = ChunkHash::from_bytes(decode_hash(name)?);
        if chunk_decls.insert(hash, attachment.byte_len()).is_some() {
            return Err(archive_error(format!("content chunk {name} is repeated")));
        }
    }

    let mut buf = Vec::new();
    plan.read_attachment(MANIFESTS_PATH, &mut buf)?;
    let index: ContentIndex = serde_json::from_slice(&buf)
        .map_err(|error| archive_error(format!("decode content manifests: {error}")))?;
    if index.version != VERSION {
        return Err(archive_error(format!(
            "content manifests version {} is not supported",
            index.version
        )));
    }

    // The identity hashes the bytes in manifest order, not in entry order.
    let mut file_ids = HashSet::new();
    let mut referenced = HashSet::new();
    let mut manifests = Vec::with_capacity(index.files.len());

    for file in &index.files {
        let manifest = validate_file_record(file, &chunk_decls, plan, &mut buf, &mut referenced)?;
        if !file_ids.insert(manifest.file_id()) {
            return Err(archive_error(format!(
                "content file {} is repeated",
                manifest.file_id()
            )));
        }
        manifests.push(manifest);
    }

    if let Some(extra) = chunk_decls.keys().find(|hash| !referenced.contains(*hash)) {
        return Err(archive_error(format!(
            "content chunk {extra} is not named by a manifest"
        )));
    }

    let mut distinct: Vec<ChunkHash> = referenced.into_iter().collect();
    distinct.sort_unstable_by_key(|hash| *hash.as_bytes());

    Ok((manifests, distinct))
}

/// Validates one file record against the entries the archive declares and the
/// bytes they hold.
fn validate_file_record<R: Read + Seek>(
    file: &FileRecord,
    chunk_decls: &HashMap<ChunkHash, u64>,
    plan: &mut ImportPlan<R>,
    buf: &mut Vec<u8>,
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
        let hash = ChunkHash::from_bytes(decode_hash(&chunk.hash)?);
        let chunk_path = format!("{CHUNK_PREFIX}{hash}");

        let &declared_len = chunk_decls
            .get(&hash)
            .ok_or_else(|| archive_error(format!("content chunk {hash} is absent")))?;
        if declared_len != chunk.len {
            return Err(archive_error(format!(
                "content chunk {hash} has length {declared_len}, expected {}",
                chunk.len
            )));
        }

        plan.read_attachment(&chunk_path, buf)?;

        let actual = ChunkHash::from_data(buf);
        if actual != hash {
            return Err(archive_error(format!(
                "content chunk {hash} has hash {actual}"
            )));
        }

        hasher.update(buf);
        referenced.insert(hash);
        metas.push(ChunkMeta {
            hash,
            len: chunk.len,
        });
    }

    let actual_id = hasher.finalize();
    if actual_id != file_id {
        return Err(archive_error(format!(
            "content file {file_id} reconstructs as {actual_id}"
        )));
    }

    Ok(Manifest::new(file_id, metas))
}

pub(crate) fn decode_hash(value: &str) -> Result<[u8; 32], ContentError> {
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
