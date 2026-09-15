use std::collections::{HashMap, HashSet};
use std::io::Write;

use crate::ClientError;

use super::super::{
    Archive, ArchiveAttachment, FORMAT, LOCAL_ROWS, MANIFEST, NOTE, PENDING, SYNCED_ROWS, VERSION,
    zip_error,
};
use super::{Entry, Manifest, checked_attachment_total, validate_attachment_path};

/// An archive whose declared entries are written and whose attachment bodies are not.
///
/// The sink is written through as each entry arrives, so the caller holds one
/// attachment at a time and never the archive. [`finish`](Self::finish)
/// returns the sink, which is the only handle on the archive once it is
/// complete.
#[must_use = "an export is incomplete until finish writes the central directory"]
pub struct LocalDataExport<W: Write> {
    zip: zip::ZipWriter<zip::write::StreamWriter<W>>,
    /// Every declared attachment not yet written, by path, with its declared length.
    owed: HashMap<String, u64>,
}

/// Writes the manifest and the row entries, leaving the declared attachments owed.
pub(crate) fn start<W: Write>(
    sink: W,
    archive: &Archive<'_>,
) -> Result<LocalDataExport<W>, ClientError> {
    validate_export_attachments(archive.attachments)?;
    let manifest = encode_manifest(archive)?;
    // A stream writer describes each entry after its body rather than seeking
    // back to patch the header, which is what lets the sink be a file or a
    // browser blob rather than a buffer.
    let mut zip = zip::ZipWriter::new_stream(sink);
    // Readers validate the manifest before decompressing payloads.
    zip.start_file(MANIFEST, stored()).map_err(zip_error)?;
    zip.write_all(&manifest).map_err(zip_error)?;
    write_payloads(&mut zip, archive)?;
    Ok(LocalDataExport {
        zip,
        owed: archive
            .attachments
            .iter()
            .map(|attachment| (attachment.path().to_owned(), attachment.byte_len()))
            .collect(),
    })
}

impl<W: Write> LocalDataExport<W> {
    /// Writes one declared attachment's body.
    ///
    /// # Errors
    ///
    /// [`ClientError::Export`] when `path` was not declared, was already
    /// written, or `bytes` is not the length its declaration named.
    pub fn write_attachment(&mut self, path: &str, bytes: &[u8]) -> Result<(), ClientError> {
        let declared = self.owed.remove(path).ok_or_else(|| {
            ClientError::Export(format!(
                "the archive declares no unwritten attachment at {path}"
            ))
        })?;
        let len = u64::try_from(bytes.len()).map_err(|_| {
            ClientError::Export(format!(
                "archive attachment {path} does not fit archive size accounting"
            ))
        })?;
        if len != declared {
            return Err(ClientError::Export(format!(
                "archive attachment {path} declares {declared} bytes and carries {len}"
            )));
        }
        self.zip.start_file(path, stored()).map_err(zip_error)?;
        self.zip.write_all(bytes).map_err(zip_error)
    }

    /// Closes the archive and returns the sink.
    ///
    /// # Errors
    ///
    /// [`ClientError::Export`] when a declared attachment was never written,
    /// which would leave the manifest naming an absent entry, or when the sink
    /// refuses the central directory.
    pub fn finish(self) -> Result<W, ClientError> {
        if let Some(path) = self.owed.keys().min() {
            return Err(ClientError::Export(format!(
                "the archive declares attachment {path}, which was never written"
            )));
        }
        self.zip
            .finish()
            .map(zip::write::StreamWriter::into_inner)
            .map_err(zip_error)
    }
}

fn stored() -> zip::write::SimpleFileOptions {
    zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored)
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

fn write_payloads<W: Write>(
    zip: &mut zip::ZipWriter<zip::write::StreamWriter<W>>,
    archive: &Archive<'_>,
) -> Result<(), ClientError> {
    if let Some(rows) = &archive.synced_rows {
        write_entry(zip, SYNCED_ROWS, rows)?;
    }
    if let Some(rows) = &archive.local_rows {
        write_entry(zip, LOCAL_ROWS, rows)?;
    }
    if !archive.pending.is_empty() {
        write_entry(zip, PENDING, &encode_pending(&archive.pending))?;
    }
    Ok(())
}

/// Checks the declarations before the manifest names them, since a declared
/// attachment is what the reader will insist on finding.
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
        total = checked_attachment_total(
            attachment.path(),
            attachment.byte_len(),
            total,
            ClientError::Export,
        )?;
    }
    Ok(())
}

fn write_entry<W: Write>(
    zip: &mut zip::ZipWriter<zip::write::StreamWriter<W>>,
    path: &str,
    payload: &[u8],
) -> Result<(), ClientError> {
    zip.start_file(path, stored()).map_err(zip_error)?;
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
