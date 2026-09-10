//! Device archives carry zstd-compressed SQLite change records plus optional opaque attachments.
//!
//! The archive is unencrypted and must be protected like the data itself.

use std::collections::HashSet;
use std::io::{Read, Write};

use diesel::SqliteConnection;
use diesel::prelude::*;
use sha2::{Digest, Sha256};
use sqlite_diff_rs::{DynTable, PatchsetOp};

use crate::ClientError;
use crate::quote_ident;

/// How much of the device an export carries.
///
/// An import restores only what the server does not have, so the two values
/// differ in whether the cache of server rows rides along (R56 decision 11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExportScope {
    /// Every row the device holds: the synced replica and the device-private
    /// tier. The default, so an export stays a copy of the device.
    #[default]
    Everything,
    /// Only what an import restores: the device-private tier and the writes
    /// that never reached the server. As small as the thing it is for.
    Unsynced,
}

impl ExportScope {
    /// The manifest spelling.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Everything => "everything",
            Self::Unsynced => "unsynced",
        }
    }
}

/// The archive format name.
const FORMAT: &str = "connetto-local-data";
/// Version 3 requires attachment-aware readers.
const VERSION: u32 = 3;
const MANIFEST: &str = "manifest.json";
const SYNCED_ROWS: &str = "synced.patchset";
const LOCAL_ROWS: &str = "device-private.patchset";
const PENDING: &str = "pending.changesets";
/// Human-readable description of the entry encodings.
const NOTE: &str = "rows are zstd SQLite change records. Attachments declare their encoding";
const MAX_ATTACHMENT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ATTACHMENTS_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// An opaque file another client layer carries in the device archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveAttachment {
    path: String,
    bytes: Vec<u8>,
}

impl ArchiveAttachment {
    /// Creates a safe raw archive entry.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when `path` is unsafe or reserved by the archive format.
    pub fn new(path: impl Into<String>, bytes: Vec<u8>) -> Result<Self, ClientError> {
        let path = path.into();
        validate_attachment_path(&path, ClientError::Export)?;
        Ok(Self { path, bytes })
    }

    /// The entry's relative archive path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The raw entry bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// One archive about to be written.
#[derive(Debug)]
pub(crate) struct Archive<'a> {
    /// How much of the device it carries.
    pub(crate) scope: ExportScope,
    /// The schema it was made under.
    pub(crate) fingerprint: String,
    /// The account it was made under, absent when the deployment names no
    /// caller.
    pub(crate) account: Option<String>,
    /// The synced replica's rows, absent under [`ExportScope::Unsynced`].
    pub(crate) synced_rows: Option<Vec<u8>>,
    /// The device-private tier's rows, absent when no tier is attached.
    pub(crate) local_rows: Option<Vec<u8>>,
    /// The writes that never reached the server, in the order they were made.
    ///
    /// Their sequence numbers are deliberately not carried: a number means
    /// something only inside one durable session handle, and an archive is
    /// restored under a different one, so an import stacks them above the
    /// receiving replica's own (R56 decision 12).
    pub(crate) pending: Vec<Vec<u8>>,
    /// Opaque files supplied by an optional client layer.
    pub(crate) attachments: &'a [ArchiveAttachment],
}

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

fn zip_error(error: impl core::fmt::Display) -> ClientError {
    ClientError::Export(format!("writing the zip archive: {error}"))
}

fn read_error(error: impl core::fmt::Display) -> ClientError {
    ClientError::Import(format!("reading the archive: {error}"))
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
            .map(|attachment| encoded_entry("attachment", &attachment.path, "identity")),
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
        validate_attachment_path(&attachment.path, ClientError::Export)?;
        if !paths.insert(attachment.path.as_str()) {
            return Err(ClientError::Export(format!(
                "the archive attachment path {} is repeated",
                attachment.path
            )));
        }
        let size = u64::try_from(attachment.bytes.len()).map_err(|_| {
            ClientError::Export(format!(
                "archive attachment {} does not fit archive size accounting",
                attachment.path
            ))
        })?;
        total = checked_attachment_total(&attachment.path, size, total, ClientError::Export)?;
    }
    Ok(())
}

fn write_attachments(
    zip: &mut zip::ZipWriter<std::io::Cursor<Vec<u8>>>,
    attachments: &[ArchiveAttachment],
    options: zip::write::SimpleFileOptions,
) -> Result<(), ClientError> {
    for attachment in attachments {
        zip.start_file(&attachment.path, options)
            .map_err(zip_error)?;
        zip.write_all(&attachment.bytes).map_err(zip_error)?;
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

/// What an import reads out of an archive.
///
/// The synced replica's rows are named rather than carried: an import never
/// restores the server's own copy (R56 decision 1), so decompressing the
/// largest entry in the file to discard it would be the one avoidable cost on
/// this path.
#[derive(Debug)]
pub(crate) struct Incoming {
    /// How much of the device the file carries.
    pub(crate) scope: ExportScope,
    /// The schema it was made under.
    pub(crate) fingerprint: String,
    /// The account it was made under.
    pub(crate) account: Option<String>,
    /// Whether it carries the synced replica's rows at all.
    pub(crate) synced_present: bool,
    /// The device-private tier's rows.
    pub(crate) local_rows: Option<Vec<u8>>,
    /// The writes that never reached the server, in order.
    pub(crate) pending: Vec<Vec<u8>>,
    /// Opaque files supplied by optional client layers.
    pub(crate) attachments: Vec<ArchiveAttachment>,
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
        attachments.push(ArchiveAttachment {
            path: entry.path.clone(),
            bytes,
        });
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

fn validate_attachment_path(
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
    out.extend_from_slice(&(records.len() as u64).to_be_bytes());
    for record in records {
        out.extend_from_slice(&(record.len() as u64).to_be_bytes());
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

#[derive(diesel::QueryableByName)]
struct SchemaRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    sql: String,
}

/// One value of a row.
///
/// Typed, never a text rendering of the value: a blob or a string holding a
/// `NUL` cannot survive one, which is the mistake `R26` made and had to undo.
pub type Cell = sqlite_diff_rs::Value<String, Vec<u8>>;

/// One row an import would overwrite: the key it is keyed by, this device's
/// version and the file's.
#[derive(Debug, Clone, PartialEq)]
pub struct Collision {
    /// The table it belongs to.
    pub table: String,
    /// Its primary-key values, in key order.
    pub key: Vec<Cell>,
    /// The column names, in table order, for both versions below.
    pub columns: Vec<String>,
    /// The version on this device.
    pub mine: Vec<Cell>,
    /// The version in the file.
    pub theirs: Vec<Cell>,
}

/// One column whose value differs between the two versions of a row.
#[derive(Debug, Clone, PartialEq)]
pub struct Difference {
    /// The column's name.
    pub column: String,
    /// This device's value.
    pub mine: Cell,
    /// The file's value.
    pub theirs: Cell,
}

impl Collision {
    /// The columns whose values differ, so an application has something to
    /// show without writing a comparison of its own.
    ///
    /// A convenience rather than the answer: an application that wants to
    /// present the pair its own way reads `mine` and `theirs` directly.
    #[must_use]
    pub fn differences(&self) -> Vec<Difference> {
        self.columns
            .iter()
            .enumerate()
            .filter_map(|(at, column)| {
                let mine = self.mine.get(at)?;
                let theirs = self.theirs.get(at)?;
                (mine != theirs).then(|| Difference {
                    column: column.clone(),
                    mine: mine.clone(),
                    theirs: theirs.clone(),
                })
            })
            .collect()
    }
}

/// Which version of a clashing row an import keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    /// What this device already holds.
    Mine,
    /// What the file carries. The default, because an import exists to bring
    /// data back.
    TheFile,
}

/// The answers an application gives to a plan's collisions.
///
/// A blanket rule with per-row exceptions, so a person facing hundreds of
/// clashes is not asked hundreds of questions and one who cares about a
/// particular row still decides it (R56 decision 3b).
pub struct ImportChoices {
    blanket: Keep,
    per_row: std::collections::HashMap<usize, Keep>,
}

impl ImportChoices {
    /// Take the file's version of every clashing row.
    #[must_use]
    pub fn keeping_the_file() -> Self {
        Self {
            blanket: Keep::TheFile,
            per_row: std::collections::HashMap::new(),
        }
    }

    /// Keep this device's version of every clashing row.
    #[must_use]
    pub fn keeping_mine() -> Self {
        Self {
            blanket: Keep::Mine,
            per_row: std::collections::HashMap::new(),
        }
    }

    /// Answer one clash by its index in [`ImportPlan::collisions`], overriding
    /// the blanket rule.
    #[must_use]
    pub fn keep(mut self, collision: usize, keep: Keep) -> Self {
        self.per_row.insert(collision, keep);
        self
    }

    /// The answer for one planned row.
    pub(crate) fn answer(&self, collision: Option<usize>) -> Keep {
        match collision {
            None => Keep::TheFile,
            Some(at) => self.per_row.get(&at).copied().unwrap_or(self.blanket),
        }
    }
}

/// One device-only row the file carries, and the clash it would cause.
#[derive(Debug)]
pub(crate) struct PlannedRow {
    pub(crate) table: String,
    pub(crate) columns: Vec<String>,
    pub(crate) key_columns: Vec<String>,
    pub(crate) values: Vec<Cell>,
    pub(crate) collision: Option<usize>,
}

/// A read and checked archive, and what applying it would overwrite.
///
/// Nothing has been written when this exists: every refusal happened while it
/// was built, and the collisions are reported before anything is overwritten,
/// which is the shape the logout protocol already has (R56 decision 3).
#[must_use = "pass this plan and an ImportChoices to apply_import. Dropping it leaves the import incomplete"]
#[derive(Debug)]
pub struct ImportPlan {
    pub(crate) archive: Incoming,
    pub(crate) rows: Vec<PlannedRow>,
    pub(crate) collisions: Vec<Collision>,
}

impl ImportPlan {
    /// The rows this import would overwrite, each with both versions.
    #[must_use]
    pub fn collisions(&self) -> &[Collision] {
        &self.collisions
    }

    /// How many device-only rows the file carries.
    #[must_use]
    pub fn device_only_rows(&self) -> usize {
        self.rows.len()
    }

    /// How many writes that never reached the server the file carries.
    #[must_use]
    pub fn queued_writes(&self) -> usize {
        self.archive.pending.len()
    }

    /// Opaque files supplied by optional client layers.
    #[must_use]
    pub fn attachments(&self) -> &[ArchiveAttachment] {
        &self.archive.attachments
    }

    /// How much of the device the file was written with.
    #[must_use]
    pub const fn scope(&self) -> ExportScope {
        self.archive.scope
    }

    /// Whether the file also carries the cache of rows the server holds, which
    /// an import never restores: the server sends those again, and writing them
    /// back would have them deleted without warning at the next refresh.
    ///
    /// Worth saying to a person who exported everything and is told that two
    /// rows came back.
    #[must_use]
    pub const fn carries_the_server_cache(&self) -> bool {
        self.archive.synced_present
    }
}

/// What an import did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImportOutcome {
    /// Device-only rows written.
    pub rows_restored: usize,
    /// Clashing rows left as this device had them.
    pub rows_kept: usize,
    /// Writes put back in the queue, each also applied locally.
    pub writes_restored: usize,
}

/// One row a record carries.
pub(crate) struct IncomingRow {
    /// The table it belongs to.
    pub(crate) table: String,
    /// That table's columns, in table order.
    pub(crate) columns: Vec<String>,
    /// The primary-key columns, in key order.
    pub(crate) key_columns: Vec<String>,
    /// The primary-key values, in key order.
    pub(crate) key: Vec<Cell>,
    /// Every value, in table order.
    pub(crate) values: Vec<Cell>,
}

/// Index one schema's current rows by table and primary key, read through the
/// same session mechanism the export uses so both sides of a comparison are
/// typed the same way.
type RowIndex = std::collections::HashMap<(String, Vec<Cell>), Vec<Cell>>;

/// Read the ops of a row record, refusing a table this build does not have or
/// one whose column count differs.
///
/// The table set is checked because the session extension **skips** a table
/// absent from the target rather than reporting it, which is the same
/// silent-loss shape `R40` and `R26` were both bitten by (R56 decision 6).
pub(crate) fn read_rows(
    patchset: &[u8],
    known: &std::collections::HashMap<String, Vec<String>>,
) -> Result<Vec<IncomingRow>, ClientError> {
    if patchset.is_empty() {
        return Ok(Vec::new());
    }
    let parsed = sqlite_diff_rs::ParsedDiffSet::parse(patchset)
        .map_err(|err| ClientError::Import(format!("the row record does not parse: {err}")))?;
    let sqlite_diff_rs::ParsedDiffSet::Patchset(set) = parsed else {
        return Err(ClientError::Import(
            "a tier's rows must travel as a patchset".to_owned(),
        ));
    };
    let mut rows = Vec::new();
    for op in set.iter() {
        let PatchsetOp::Insert { table, values, .. } = op else {
            return Err(ClientError::Import(
                "a tier's rows must be inserts only".to_owned(),
            ));
        };
        let name = table.name().to_owned();
        let Some(columns) = known.get(&name.to_lowercase()) else {
            return Err(ClientError::Import(format!(
                "the archive carries table {name}, which this build does not have"
            )));
        };
        if columns.len() != values.len() {
            return Err(ClientError::Import(format!(
                "the archive's table {name} has {} columns and this build's has {}",
                values.len(),
                columns.len()
            )));
        }
        let mut flags = vec![0u8; table.number_of_columns()];
        table.write_pk_flags(&mut flags);
        // The flag is the column's 1-based position in the key, so sorting by
        // it puts a composite key in key order rather than table order.
        let mut key: Vec<(u8, String, Cell)> = flags
            .iter()
            .zip(columns.iter().zip(values.iter()))
            .filter(|(flag, _)| **flag > 0)
            .map(|(flag, (column, value))| (*flag, column.clone(), value.clone()))
            .collect();
        key.sort_by_key(|(flag, _, _)| *flag);
        rows.push(IncomingRow {
            table: name,
            columns: columns.clone(),
            key_columns: key.iter().map(|(_, column, _)| column.clone()).collect(),
            key: key.into_iter().map(|(_, _, value)| value).collect(),
            values: values.to_vec(),
        });
    }
    Ok(rows)
}

/// Index the rows a record carries, for comparing the two sides of a clash.
pub(crate) fn index_rows(
    patchset: &[u8],
    known: &std::collections::HashMap<String, Vec<String>>,
) -> Result<RowIndex, ClientError> {
    Ok(read_rows(patchset, known)?
        .into_iter()
        .map(|row| ((row.table, row.key), row.values))
        .collect())
}

/// The columns of every table of one schema, keyed by lowercased name.
pub(crate) fn schema_columns(
    db: &mut SqliteConnection,
    schema: &str,
    include: Option<&HashSet<String>>,
    hidden: &HashSet<String>,
) -> Result<std::collections::HashMap<String, Vec<String>>, ClientError> {
    #[derive(diesel::QueryableByName)]
    struct NameRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
    }
    let tables: Vec<NameRow> = diesel::sql_query(format!(
        "SELECT name FROM {}.sqlite_schema WHERE type = 'table' ORDER BY name",
        quote_ident(schema)
    ))
    .load(db)?;
    let mut out = std::collections::HashMap::new();
    for table in tables {
        if !crate::export_table_allowed(&table.name, include, hidden) {
            continue;
        }
        let columns: Vec<NameRow> = diesel::sql_query(format!(
            "SELECT name FROM {}.pragma_table_info(?) ORDER BY cid",
            quote_ident(schema)
        ))
        .bind::<diesel::sql_types::Text, _>(&table.name)
        .load(db)?;
        out.insert(
            table.name.to_lowercase(),
            columns.into_iter().map(|column| column.name).collect(),
        );
    }
    Ok(out)
}

/// Write one row into `schema`, updating the row already there.
///
/// An upsert rather than `INSERT OR REPLACE`, which deletes the row it
/// replaces: that fires the table's delete triggers and takes any
/// `ON DELETE CASCADE` children with it, so restoring a row would destroy rows
/// nobody asked about.
///
/// Values bind by their own storage class, so a blob stays a blob and text
/// holding a `NUL` survives.
pub(crate) fn write_row(
    db: &mut SqliteConnection,
    schema: &str,
    table: &str,
    columns: &[String],
    key_columns: &[String],
    values: &[Cell],
) -> Result<(), ClientError> {
    use diesel::sql_types::{Binary, Double, Nullable, Text};
    let names = columns
        .iter()
        .map(|column| quote_ident(column))
        .collect::<Vec<_>>()
        .join(", ");
    let places = vec!["?"; columns.len()].join(", ");
    let key = key_columns
        .iter()
        .map(|column| quote_ident(column))
        .collect::<Vec<_>>()
        .join(", ");
    let updates = columns
        .iter()
        .filter(|column| !key_columns.iter().any(|key| key == *column))
        .map(|column| {
            let column = quote_ident(column);
            format!("{column} = excluded.{column}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    // A table whose every column is in the key has nothing to update, and its
    // row is already exactly what the file carries.
    let resolution = if updates.is_empty() {
        "NOTHING".to_owned()
    } else {
        format!("UPDATE SET {updates}")
    };
    let sql = format!(
        "INSERT INTO {}.{} ({names}) VALUES ({places}) \
         ON CONFLICT ({key}) DO {resolution}",
        quote_ident(schema),
        quote_ident(table)
    );
    let mut query = diesel::sql_query(sql).into_boxed::<diesel::sqlite::Sqlite>();
    for value in values {
        query = match value {
            sqlite_diff_rs::Value::Null => query.bind::<Nullable<Text>, _>(None::<String>),
            sqlite_diff_rs::Value::Integer(number) => {
                query.bind::<diesel::sql_types::BigInt, _>(*number)
            }
            sqlite_diff_rs::Value::Real(number) => query.bind::<Double, _>(*number),
            sqlite_diff_rs::Value::Text(text) => query.bind::<Text, _>(text.clone()),
            sqlite_diff_rs::Value::Blob(bytes) => query.bind::<Binary, _>(bytes.clone()),
        };
    }
    query.execute(db)?;
    Ok(())
}

/// A fingerprint of the schema an archive was made under, over both the
/// replica and the device-private tier.
///
/// Structural rather than declared: an import has to refuse any schema that
/// differs, and a deployment's declared version can stay the same across a
/// changed table (R56 decision 4). The stored `CREATE TABLE` text is what
/// SQLite kept verbatim, so two devices of one build hash the same and a
/// changed column changes the digest.
pub(crate) fn fingerprint(
    db: &mut SqliteConnection,
    schemas: &[(&str, Option<&HashSet<String>>)],
    hidden: &HashSet<String>,
) -> Result<String, ClientError> {
    let mut digest = Sha256::new();
    for (schema, include) in schemas {
        let rows: Vec<SchemaRow> = diesel::sql_query(format!(
            "SELECT name, sql FROM {}.sqlite_schema \
             WHERE type = 'table' AND sql IS NOT NULL ORDER BY name",
            quote_ident(schema)
        ))
        .load(db)?;
        digest.update(schema.as_bytes());
        for row in rows {
            if !crate::export_table_allowed(&row.name, *include, hidden) {
                continue;
            }
            digest.update(row.name.as_bytes());
            digest.update([0]);
            digest.update(row.sql.as_bytes());
            digest.update([0]);
        }
    }
    Ok(digest
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            use core::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        }))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::{
        Archive, ExportScope, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENTS_BYTES,
        checked_attachment_total, decode_pending, encode_pending, read, write,
    };
    use crate::ClientError;
    use serde_json::json;

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
