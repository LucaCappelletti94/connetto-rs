use std::collections::HashSet;
use std::io::Read;

use crate::ClientError;

use super::super::{
    ArchiveAttachment, ExportScope, FORMAT, Incoming, LOCAL_ROWS, MANIFEST, MAX_ATTACHMENTS_BYTES,
    PENDING, SYNCED_ROWS, VERSION, read_error,
};
use super::{Entry, Manifest, checked_attachment_total, validate_attachment_path};

/// Read an archive back, refusing a format or version this build does not
/// know before any entry is decompressed.
pub(crate) fn read(bytes: &[u8]) -> Result<Incoming, ClientError> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(read_error)?;
    let manifest = read_manifest(&mut zip)?;
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
    let scope = parse_scope(&manifest.scope)?;
    let declared = validate_archive_layout(&mut zip, &manifest, scope)?;
    let synced_present = declared.contains(SYNCED_ROWS);
    let local_rows = read_entry(&mut zip, LOCAL_ROWS)?;
    let pending = read_pending_queue(&mut zip)?;
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

fn read_manifest(
    zip: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
) -> Result<Manifest, ClientError> {
    let mut entry = zip.by_name(MANIFEST).map_err(|_| {
        ClientError::Import(
            "the archive carries no manifest, so it is not a connetto export".to_owned(),
        )
    })?;
    let mut text = String::new();
    entry.read_to_string(&mut text).map_err(read_error)?;
    serde_json::from_str(&text)
        .map_err(|err| ClientError::Import(format!("the manifest does not parse: {err}")))
}

fn parse_scope(scope: &str) -> Result<ExportScope, ClientError> {
    match scope {
        "everything" => Ok(ExportScope::Everything),
        "unsynced" => Ok(ExportScope::Unsynced),
        other => Err(ClientError::Import(format!(
            "the archive names an unknown scope {other}"
        ))),
    }
}

fn read_pending_queue(
    zip: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
) -> Result<Vec<Vec<u8>>, ClientError> {
    match read_entry(zip, PENDING)? {
        Some(bytes) => decode_pending(&bytes),
        None => Ok(Vec::new()),
    }
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
    read_entry_bounded(zip, path, MAX_ATTACHMENTS_BYTES)
}

/// Reads one compressed entry, refusing output above `limit`.
///
/// The limit is a parameter so a test proves the boundary over kilobytes rather than over
/// the gigabytes the shipped ceiling names.
fn read_entry_bounded(
    zip: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>,
    path: &str,
    limit: u64,
) -> Result<Option<Vec<u8>>, ClientError> {
    let Ok(entry) = zip.by_name(path) else {
        return Ok(None);
    };
    // The ZIP entry streams into the decoder rather than through a buffer of its own,
    // because its own compression expands unboundedly before any ceiling could apply.
    let decoder = zstd::stream::read::Decoder::new(entry)?;
    let ceiling =
        usize::try_from(limit).expect("the decompression limit fits usize on supported targets");
    let mut decompressed = Vec::new();
    // One byte past the ceiling, so an entry of exactly the ceiling is accepted and the
    // one that follows is refused.
    decoder
        .take(limit.saturating_add(1))
        .read_to_end(&mut decompressed)?;
    if decompressed.len() > ceiling {
        return Err(ClientError::Import(format!(
            "archive entry {path} exceeds the decompression limit"
        )));
    }
    Ok(Some(decompressed))
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

pub(super) fn decode_pending(bytes: &[u8]) -> Result<Vec<Vec<u8>>, ClientError> {
    let malformed = || ClientError::Import("the queue entry is malformed".to_owned());
    let count = u64::from_be_bytes(
        bytes
            .get(..8)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?,
    );
    // Every record costs at least its eight length bytes, so a count above what the entry
    // can hold is refused before one vector per record is allocated.
    let capacity = u64::try_from(bytes.len().saturating_sub(8) / 8).unwrap_or(u64::MAX);
    if count > capacity {
        return Err(malformed());
    }
    let mut at: usize = 8;
    let mut records = Vec::new();
    for _ in 0..count {
        let len = usize::try_from(u64::from_be_bytes(
            bytes
                .get(at..at.checked_add(8).ok_or_else(malformed)?)
                .ok_or_else(malformed)?
                .try_into()
                .map_err(|_| malformed())?,
        ))
        .map_err(|_| malformed())?;
        at += 8;
        records.push(
            bytes
                .get(at..at.checked_add(len).ok_or_else(malformed)?)
                .ok_or_else(malformed)?
                .to_vec(),
        );
        at = at.checked_add(len).ok_or_else(malformed)?;
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use serde_json::json;

    use super::super::super::{Archive, ExportScope};
    use super::decode_pending;
    use super::read;

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
        let bytes = super::super::write::write(&archive).expect("write");
        let read_back = read(&bytes).expect("read");
        assert_eq!(read_back.scope, ExportScope::Unsynced);
        assert_eq!(read_back.fingerprint, "abc123");
        assert_eq!(read_back.account.as_deref(), Some("\"alice\""));
        assert!(!read_back.synced_present);
        assert_eq!(read_back.local_rows, Some(vec![7u8; 64]));
        assert_eq!(read_back.pending, vec![vec![9u8; 16]]);
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

    /// A file that is not one of ours is refused by name rather than parsed.
    #[test]
    fn a_foreign_file_is_refused() {
        assert!(read(b"not a zip at all").is_err());
    }

    /// An entry whose output passes the ceiling is refused, naming the entry, while an
    /// entry of exactly the ceiling is read.
    #[test]
    fn the_decompression_ceiling_is_the_boundary() {
        let limit: u64 = 64 * 1024;
        let exact = usize::try_from(limit).expect("limit fits usize");
        for (len, expected) in [(exact, None), (exact + 1, Some("decompression limit"))] {
            let bytes =
                zip_with_entry(&zstd::encode_all(vec![0u8; len].as_slice(), 1).expect("zstd"));
            let mut zip =
                zip::ZipArchive::new(std::io::Cursor::new(bytes.as_slice())).expect("zip");
            let outcome = super::read_entry_bounded(&mut zip, "device-private.patchset", limit);
            match (expected, outcome) {
                (None, Ok(Some(entry))) => {
                    assert_eq!(entry.len(), exact, "the exact ceiling reads");
                }
                (Some(needle), Err(error)) => {
                    let text = error.to_string();
                    assert!(text.contains(needle), "expected {needle} in error: {text}");
                    assert!(
                        text.contains("device-private.patchset"),
                        "expected the entry name in error: {text}"
                    );
                }
                (_, outcome) => panic!("unexpected outcome for {len} bytes: {outcome:?}"),
            }
        }
    }

    /// One archive holding a manifest and one zstd row entry, for the reader tests.
    fn zip_with_entry(entry: &[u8]) -> Vec<u8> {
        let manifest = json!({
            "format": "connetto-local-data",
            "version": 3,
            "scope": "unsynced",
            "schema_fingerprint": "abc123",
            "account": null,
            "compression": "per-entry",
            "note": "test",
            "entries": [{"kind": "rows", "path": "device-private.patchset", "encoding": "zstd"}],
        });
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("manifest.json", options)
            .expect("start manifest");
        zip.write_all(&serde_json::to_vec(&manifest).expect("manifest json"))
            .expect("write manifest");
        zip.start_file("device-private.patchset", options)
            .expect("start entry");
        zip.write_all(entry).expect("write entry");
        zip.finish().expect("finish archive").into_inner()
    }

    /// A queue entry with a length field of `u64::MAX` is refused rather than panicking.
    #[test]
    fn oversized_queue_entry_is_refused() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&u64::MAX.to_be_bytes());
        let error = decode_pending(&bytes).expect_err("overflowing queue entry must be refused");
        assert!(
            error.to_string().contains("malformed"),
            "expected 'malformed' in error: {error}"
        );
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
}
