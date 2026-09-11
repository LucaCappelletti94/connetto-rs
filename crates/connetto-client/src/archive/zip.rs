use std::collections::HashSet;
use std::io::{Read, Write};

use crate::ClientError;

use super::{
    Archive, ArchiveAttachment, ExportScope, FORMAT, Incoming, LOCAL_ROWS, MANIFEST,
    MAX_ATTACHMENT_BYTES, MAX_ATTACHMENTS_BYTES, NOTE, PENDING, SYNCED_ROWS, VERSION, read_error,
    zip_error,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    version: u32,
    scope: String,
    schema_fingerprint: String,
    #[serde(default)]
    account: Option<String>,
    compression: String,
    note: String,
    entries: Vec<Entry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    kind: String,
    path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
}

/// Writes one archive with per-entry encodings.
pub(crate) fn write(archive: &Archive<'_>) -> Result<Vec<u8>, ClientError> {
    validate_export_attachments(archive.attachments)?;
    let manifest = encode_manifest(archive)?;
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    // Readers validate the manifest before decompressing payloads.
    zip.start_file(MANIFEST, options).map_err(zip_error)?;
    zip.write_all(&manifest).map_err(zip_error)?;
    write_payloads(&mut zip, archive, options)?;
    write_attachments(&mut zip, archive.attachments, options)?;
    zip.finish()
        .map(std::io::Cursor::into_inner)
        .map_err(zip_error)
}

fn encode_manifest(archive: &Archive<'_>) -> Result<Vec<u8>, ClientError> {
    serde_json::to_vec_pretty(&Manifest {
        format: FORMAT.to_owned(),
        version: VERSION,
        scope: archive.scope.as_str().to_owned(),
        schema_fingerprint: archive.fingerprint.clone(),
        account: archive.account.clone(),
        compression: "per-entry".to_owned(),
        note: NOTE.to_owned(),
        entries: manifest_entries(archive),
    })
    .map_err(|err| ClientError::Export(format!("encoding the manifest: {err}")))
}

fn manifest_entries(archive: &Archive<'_>) -> Vec<Entry> {
    let mut entries = Vec::new();
    if archive.synced_rows.is_some() {
        entries.push(encoded_entry("rows", SYNCED_ROWS, "zstd"));
    }
    if archive.local_rows.is_some() {
        entries.push(encoded_entry("rows", LOCAL_ROWS, "zstd"));
    }
    if !archive.pending.is_empty() {
        entries.push(encoded_entry("pending", PENDING, "zstd"));
    }
    entries.extend(
        archive
            .attachments
            .iter()
            .map(|attachment| encoded_entry("attachment", attachment.path(), "identity")),
    );
    entries
}

fn encoded_entry(kind: &str, path: &str, encoding: &str) -> Entry {
    Entry {
        kind: kind.to_owned(),
        path: path.to_owned(),
        encoding: Some(encoding.to_owned()),
    }
}

fn write_payloads(
    zip: &mut zip::ZipWriter<std::io::Cursor<Vec<u8>>>,
    archive: &Archive<'_>,
    options: zip::write::SimpleFileOptions,
) -> Result<(), ClientError> {
    if let Some(rows) = &archive.synced_rows {
        write_entry(zip, SYNCED_ROWS, rows, options)?;
    }
    if let Some(rows) = &archive.local_rows {
        write_entry(zip, LOCAL_ROWS, rows, options)?;
    }
    if !archive.pending.is_empty() {
        write_entry(zip, PENDING, &encode_pending(&archive.pending), options)?;
    }
    Ok(())
}

fn validate_export_attachments(attachments: &[ArchiveAttachment]) -> Result<(), ClientError> {
    let mut paths = HashSet::new();
    let mut total = 0_u64;
    for attachment in attachments {
        validate_attachment_path(attachment.path(), ClientError::Export)?;
        if !paths.insert(attachment.path()) {
            return Err(ClientError::Export(format!(
                "the archive attachment path {} is repeated",
                attachment.path()
            )));
        }
        let size = u64::try_from(attachment.bytes().len()).map_err(|_| {
            ClientError::Export(format!(
                "archive attachment {} does not fit archive size accounting",
                attachment.path()
            ))
        })?;
        total = checked_attachment_total(attachment.path(), size, total, ClientError::Export)?;
    }
    Ok(())
}

fn write_attachments(
    zip: &mut zip::ZipWriter<std::io::Cursor<Vec<u8>>>,
    attachments: &[ArchiveAttachment],
    options: zip::write::SimpleFileOptions,
) -> Result<(), ClientError> {
    for attachment in attachments {
        zip.start_file(attachment.path(), options)
            .map_err(zip_error)?;
        zip.write_all(attachment.bytes()).map_err(zip_error)?;
    }
    Ok(())
}

fn write_entry(
    zip: &mut zip::ZipWriter<std::io::Cursor<Vec<u8>>>,
    path: &str,
    payload: &[u8],
    options: zip::write::SimpleFileOptions,
) -> Result<(), ClientError> {
    zip.start_file(path, options).map_err(zip_error)?;
    zip.write_all(&zstd::encode_all(payload, 3)?)
        .map_err(zip_error)
}

/// Read an archive back, refusing a format or version this build does not
/// know before any entry is decompressed.
pub(crate) fn read(bytes: &[u8]) -> Result<Incoming, ClientError> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(read_error)?;
    let manifest: Manifest = {
        let mut entry = zip.by_name(MANIFEST).map_err(|_| {
            ClientError::Import(
                "the archive carries no manifest, so it is not a connetto export".to_owned(),
            )
        })?;
        let mut text = String::new();
        entry.read_to_string(&mut text).map_err(read_error)?;
        serde_json::from_str(&text)
            .map_err(|err| ClientError::Import(format!("the manifest does not parse: {err}")))?
    };
    if manifest.format != FORMAT {
        return Err(ClientError::Import(format!(
            "the archive is a {} file, not a connetto export",
            manifest.format
        )));
    }
    if manifest.version != VERSION {
        return Err(ClientError::Import(format!(
            "the archive is version {}, and this build reads version {VERSION}",
            manifest.version
        )));
    }
    let scope = match manifest.scope.as_str() {
        "everything" => ExportScope::Everything,
        "unsynced" => ExportScope::Unsynced,
        other => {
            return Err(ClientError::Import(format!(
                "the archive names an unknown scope {other}"
            )));
        }
    };
    let declared = validate_archive_layout(&mut zip, &manifest, scope)?;
    let synced_present = declared.contains(SYNCED_ROWS);
    let local_rows = read_entry(&mut zip, LOCAL_ROWS)?;
    let pending = match read_entry(&mut zip, PENDING)? {
        Some(bytes) => decode_pending(&bytes)?,
        None => Vec::new(),
    };
    let attachments = read_attachments(&mut zip, &manifest.entries)?;
    Ok(Incoming {
        scope,
        fingerprint: manifest.schema_fingerprint,
        account: manifest.account,
        synced_present,
        local_rows,
        pending,
        attachments,
    })
}

fn validate_archive_layout(
    zip: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
    manifest: &Manifest,
    scope: ExportScope,
) -> Result<HashSet<String>, ClientError> {
    if manifest.compression != "per-entry" {
        return Err(ClientError::Import(format!(
            "the archive names unsupported compression {}",
            manifest.compression
        )));
    }
    let declared = declared_paths(&manifest.entries)?;
    validate_physical_layout(stored_paths(zip)?, &declared)?;
    validate_scope(&declared, scope)?;
    Ok(declared)
}

fn declared_paths(entries: &[Entry]) -> Result<HashSet<String>, ClientError> {
    let mut declared = HashSet::new();
    for entry in entries {
        validate_entry_declaration(entry)?;
        if !declared.insert(entry.path.clone()) {
            return Err(ClientError::Import(format!(
                "the archive manifest repeats {}",
                entry.path
            )));
        }
    }
    Ok(declared)
}

fn stored_paths(
    zip: &zip::ZipArchive<std::io::Cursor<&[u8]>>,
) -> Result<HashSet<String>, ClientError> {
    let mut stored = HashSet::new();
    for name in zip.file_names() {
        let path = name.to_owned();
        if !stored.insert(path.clone()) {
            return Err(ClientError::Import(format!(
                "the archive repeats entry {path}"
            )));
        }
    }
    Ok(stored)
}

fn validate_physical_layout(
    mut stored: HashSet<String>,
    declared: &HashSet<String>,
) -> Result<(), ClientError> {
    if !stored.remove(MANIFEST) {
        return Err(ClientError::Import(
            "the archive carries no manifest".to_owned(),
        ));
    }
    for path in declared {
        if !stored.remove(path) {
            return Err(ClientError::Import(format!(
                "the archive manifest names {path}, but the entry is absent"
            )));
        }
    }
    if let Some(path) = stored.into_iter().next() {
        return Err(ClientError::Import(format!(
            "the archive entry {path} is not declared by its manifest"
        )));
    }
    Ok(())
}

fn validate_scope(declared: &HashSet<String>, scope: ExportScope) -> Result<(), ClientError> {
    if declared.contains(SYNCED_ROWS) != matches!(scope, ExportScope::Everything) {
        return Err(ClientError::Import(
            "the archive scope contradicts its synced rows entry".to_owned(),
        ));
    }
    Ok(())
}

fn validate_entry_declaration(entry: &Entry) -> Result<(), ClientError> {
    match entry.kind.as_str() {
        "rows" if matches!(entry.path.as_str(), SYNCED_ROWS | LOCAL_ROWS) => {
            require_encoding(entry, "zstd")
        }
        "pending" if entry.path == PENDING => require_encoding(entry, "zstd"),
        "attachment" => {
            validate_attachment_path(&entry.path, ClientError::Import)?;
            require_encoding(entry, "identity")
        }
        "rows" | "pending" => Err(ClientError::Import(format!(
            "archive entry {} contradicts kind {}",
            entry.path, entry.kind
        ))),
        kind => Err(ClientError::Import(format!(
            "unknown archive entry kind {kind}"
        ))),
    }
}

fn require_encoding(entry: &Entry, expected: &str) -> Result<(), ClientError> {
    if entry.encoding.as_deref() == Some(expected) {
        Ok(())
    } else {
        Err(ClientError::Import(format!(
            "archive entry {} must use {expected} encoding",
            entry.path
        )))
    }
}

fn read_entry(
    zip: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
    path: &str,
) -> Result<Option<Vec<u8>>, ClientError> {
    let Ok(mut entry) = zip.by_name(path) else {
        return Ok(None);
    };
    let mut packed = Vec::new();
    entry.read_to_end(&mut packed).map_err(read_error)?;
    Ok(Some(zstd::decode_all(packed.as_slice())?))
}

fn read_attachments(
    zip: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
    entries: &[Entry],
) -> Result<Vec<ArchiveAttachment>, ClientError> {
    let mut attachments = Vec::new();
    let mut total = 0_u64;
    for entry in entries.iter().filter(|entry| entry.kind == "attachment") {
        let mut file = zip.by_name(&entry.path).map_err(read_error)?;
        if file.compression() != zip::CompressionMethod::Stored {
            return Err(ClientError::Import(format!(
                "archive attachment {} must use ZIP Stored compression",
                entry.path
            )));
        }
        let size = file.size();
        total = checked_attachment_total(&entry.path, size, total, ClientError::Import)?;
        let capacity = usize::try_from(size).map_err(|_| {
            ClientError::Import(format!(
                "archive attachment {} does not fit this platform",
                entry.path
            ))
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes).map_err(read_error)?;
        attachments.push(ArchiveAttachment::from_raw(entry.path.clone(), bytes));
    }
    Ok(attachments)
}

fn checked_attachment_total(
    path: &str,
    size: u64,
    total: u64,
    error: fn(String) -> ClientError,
) -> Result<u64, ClientError> {
    if size > MAX_ATTACHMENT_BYTES {
        return Err(error(format!(
            "archive attachment {path} is {size} bytes, above the {MAX_ATTACHMENT_BYTES}-byte limit"
        )));
    }
    total
        .checked_add(size)
        .filter(|total| *total <= MAX_ATTACHMENTS_BYTES)
        .ok_or_else(|| {
            error(format!(
                "archive attachments exceed the {MAX_ATTACHMENTS_BYTES}-byte aggregate limit"
            ))
        })
}

/// Validate that `path` is a safe relative archive path and not a reserved name.
pub(super) fn validate_attachment_path(
    path: &str,
    error: fn(String) -> ClientError,
) -> Result<(), ClientError> {
    let reserved = [MANIFEST, SYNCED_ROWS, LOCAL_ROWS, PENDING];
    let valid = !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !reserved.contains(&path)
        && path
            .split('/')
            .all(|component| !matches!(component, "" | "." | ".."));
    if valid {
        Ok(())
    } else {
        Err(error(format!(
            "the archive attachment path {path:?} is not a safe relative path"
        )))
    }
}

/// The queue as one entry: a count, then each changeset behind its length.
///
/// Its own framing rather than one entry per write, because a queue of a
/// hundred writes is a hundred zip entries otherwise, and the order is the
/// only thing about them that matters.
fn encode_pending(records: &[Vec<u8>]) -> Vec<u8> {
    let total: usize = records.iter().map(|record| record.len() + 8).sum();
    let mut out = Vec::with_capacity(total + 8);
    // usize fits u64 on every supported Rust target
    let count = u64::try_from(records.len()).expect("slice length exceeds u64");
    out.extend_from_slice(&count.to_be_bytes());
    for record in records {
        let len = u64::try_from(record.len()).expect("slice length exceeds u64");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(record);
    }
    out
}

fn decode_pending(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ClientError> {
    let malformed = || ClientError::Import("the queue entry is malformed".to_owned());
    let count = u64::from_be_bytes(
        bytes
            .get(..8)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?,
    );
    let mut at = 8;
    let mut records = Vec::new();
    for _ in 0..count {
        let len = usize::try_from(u64::from_be_bytes(
            bytes
                .get(at..at + 8)
                .ok_or_else(malformed)?
                .try_into()
                .map_err(|_| malformed())?,
        ))
        .map_err(|_| malformed())?;
        at += 8;
        records.push(bytes.get(at..at + len).ok_or_else(malformed)?.to_vec());
        at += len;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use serde_json::json;

    use super::super::{Archive, ExportScope, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENTS_BYTES};
    use super::{checked_attachment_total, decode_pending, encode_pending, read, write};
    use crate::ClientError;

    /// The queue's framing carries every record, in order, whatever the bytes
    /// inside one look like.
    #[test]
    fn the_queue_framing_round_trips() {
        let records = vec![vec![0u8, 1, 2], Vec::new(), vec![255u8; 300]];
        let encoded = encode_pending(&records);
        assert_eq!(decode_pending(&encoded).expect("decode"), records);
    }

    #[test]
    fn compressed_attachments_are_refused_before_their_body_is_read() {
        let manifest = json!({
            "format": "connetto-local-data",
            "version": 3,
            "scope": "unsynced",
            "schema_fingerprint": "abc123",
            "account": null,
            "compression": "per-entry",
            "note": "test",
            "entries": [
                {"kind": "attachment", "path": "content/chunks/abc", "encoding": "identity"}
            ],
        });
        let cursor = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(cursor);
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("manifest.json", stored)
            .expect("start manifest");
        zip.write_all(&serde_json::to_vec(&manifest).expect("encode manifest"))
            .expect("write manifest");
        zip.start_file("content/chunks/abc", stored)
            .expect("start attachment");
        zip.write_all(&vec![0_u8; 64 * 1024])
            .expect("write attachment");
        let mut bytes = zip.finish().expect("finish archive").into_inner();
        set_zip_compression(&mut bytes, b"content/chunks/abc", 8);

        let error = read(&bytes).expect_err("compressed attachment");
        assert!(
            error
                .to_string()
                .contains("Compression method not supported")
        );
    }

    #[test]
    fn attachment_size_limits_apply_to_export_and_import() {
        let oversized = checked_attachment_total(
            "content/chunks/oversized",
            MAX_ATTACHMENT_BYTES + 1,
            0,
            ClientError::Export,
        )
        .expect_err("oversized export attachment");
        assert!(oversized.to_string().contains("above"));

        let aggregate = checked_attachment_total(
            "content/chunks/last",
            1,
            MAX_ATTACHMENTS_BYTES,
            ClientError::Import,
        )
        .expect_err("oversized import aggregate");
        assert!(aggregate.to_string().contains("aggregate"));
    }

    fn set_zip_compression(bytes: &mut [u8], path: &[u8], method: u16) {
        let method = method.to_le_bytes();
        let positions: Vec<_> = bytes
            .windows(path.len())
            .enumerate()
            .filter_map(|(at, value)| (value == path).then_some(at))
            .collect();
        for at in positions {
            if at >= 30 && &bytes[at - 30..at - 26] == b"PK\x03\x04" {
                bytes[at - 22..at - 20].copy_from_slice(&method);
            } else if at >= 46 && &bytes[at - 46..at - 42] == b"PK\x01\x02" {
                bytes[at - 36..at - 34].copy_from_slice(&method);
            }
        }
    }

    /// A truncated queue entry is refused rather than read as a shorter one.
    #[test]
    fn a_truncated_queue_entry_is_refused() {
        let encoded = encode_pending(&[vec![1u8, 2, 3]]);
        assert!(decode_pending(&encoded[..encoded.len() - 1]).is_err());
    }

    /// What an export writes, an import reads back unchanged.
    #[test]
    fn an_archive_round_trips() {
        let archive = Archive {
            scope: ExportScope::Unsynced,
            fingerprint: "abc123".to_owned(),
            account: Some("\"alice\"".to_owned()),
            synced_rows: None,
            local_rows: Some(vec![7u8; 64]),
            pending: vec![vec![9u8; 16]],
            attachments: &[],
        };
        let bytes = write(&archive).expect("write");
        let read_back = read(&bytes).expect("read");
        assert_eq!(read_back.scope, ExportScope::Unsynced);
        assert_eq!(read_back.fingerprint, "abc123");
        assert_eq!(read_back.account.as_deref(), Some("\"alice\""));
        assert!(!read_back.synced_present);
        assert_eq!(read_back.local_rows, Some(vec![7u8; 64]));
        assert_eq!(read_back.pending, vec![vec![9u8; 16]]);
    }

    /// Entry declarations must exactly describe the archive payload.
    #[test]
    fn malformed_entry_declarations_are_refused() {
        assert_invalid_entries(
            &json!([{"kind": "unknown", "path": "mystery", "encoding": "identity"}]),
            &[("mystery", b"")],
            "unknown archive entry kind",
        );
        assert_invalid_entries(
            &json!([{"kind": "pending", "path": "pending.changesets", "encoding": "identity"}]),
            &[("pending.changesets", b"")],
            "must use zstd",
        );
        assert_invalid_entries(&json!([]), &[("undeclared", b"")], "not declared");
    }

    fn assert_invalid_entries(
        entries: &serde_json::Value,
        files: &[(&str, &[u8])],
        expected: &str,
    ) {
        let manifest = json!({
            "format": "connetto-local-data",
            "version": 3,
            "scope": "unsynced",
            "schema_fingerprint": "abc123",
            "account": null,
            "compression": "per-entry",
            "note": "test",
            "entries": entries,
        });
        let cursor = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("manifest.json", options)
            .expect("start manifest");
        zip.write_all(&serde_json::to_vec(&manifest).expect("encode manifest"))
            .expect("write manifest");
        for (path, bytes) in files {
            zip.start_file(path, options).expect("start entry");
            zip.write_all(bytes).expect("write entry");
        }
        let bytes = zip.finish().expect("finish archive").into_inner();
        let error = read(&bytes).expect_err("malformed entries must be refused");
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?} in {error}"
        );
    }

    /// A file that is not one of ours is refused by name rather than parsed.
    #[test]
    fn a_foreign_file_is_refused() {
        assert!(read(b"not a zip at all").is_err());
    }
}
