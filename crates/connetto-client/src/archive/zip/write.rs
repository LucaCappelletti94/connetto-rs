use std::collections::HashSet;
use std::io::Write;

use crate::ClientError;

use super::super::{
    Archive, ArchiveAttachment, FORMAT, LOCAL_ROWS, MANIFEST, NOTE, PENDING, SYNCED_ROWS, VERSION,
    zip_error,
};
use super::{Entry, Manifest, checked_attachment_total, validate_attachment_path};

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

/// The queue as one entry: a count, then each changeset behind its length.
///
/// Its own framing rather than one entry per write, because a queue of a
/// hundred writes is a hundred zip entries otherwise, and the order is the
/// only thing about them that matters.
pub(super) fn encode_pending(records: &[Vec<u8>]) -> Vec<u8> {
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
