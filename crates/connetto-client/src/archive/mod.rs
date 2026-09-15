//! Device archives carry zstd-compressed SQLite change records plus optional opaque attachments.
//!
//! The archive is unencrypted and must be protected like the data itself.

pub(crate) mod rows;
pub(crate) mod zip;

use crate::ClientError;

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
/// The most one attachment may ask a device to hold on disk, and in memory
/// while its own entry is written or read.
const MAX_ATTACHMENT_BYTES: u64 = 256 * 1024 * 1024;
/// The most every attachment together may ask a device to hold on disk.
const MAX_ATTACHMENTS_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// An opaque file another client layer carries in the device archive, named
/// and sized rather than held.
///
/// The bytes travel through the archive one entry at a time, so an attachment
/// is a declaration on the way out, written with
/// [`LocalDataExport::write_attachment`](crate::LocalDataExport::write_attachment),
/// and a name on the way in, read with
/// [`ImportPlan::read_attachment`](crate::ImportPlan::read_attachment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveAttachment {
    path: String,
    byte_len: u64,
}

impl ArchiveAttachment {
    /// Declares a safe raw archive entry of `byte_len` bytes.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when `path` is unsafe or reserved by the archive format.
    pub fn new(path: impl Into<String>, byte_len: u64) -> Result<Self, ClientError> {
        let path = path.into();
        zip::validate_attachment_path(&path, ClientError::Export)?;
        Ok(Self { path, byte_len })
    }

    /// The entry's relative archive path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// How many bytes the entry carries.
    #[must_use]
    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    /// Constructs a pre-validated declaration directly, for use by the zip reader.
    const fn from_raw(path: String, byte_len: u64) -> Self {
        Self { path, byte_len }
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

/// A checked archive, still open, and what applying it would overwrite.
///
/// Nothing has been written when this exists, because every refusal the rows
/// and the manifest can raise happened while it was built, and the collisions
/// are reported before anything is overwritten, which is the shape the logout
/// protocol already has (R56 decision 3).
///
/// The plan holds the source open, because the attachments it names are read
/// from it one at a time rather than carried.
#[must_use = "pass this plan and an ImportChoices to apply_import. Dropping it leaves the import incomplete"]
pub struct ImportPlan<R> {
    pub(crate) archive: Incoming,
    pub(crate) rows: Vec<PlannedRow>,
    pub(crate) collisions: Vec<Collision>,
    pub(crate) reader: zip::read::ArchiveReader<R>,
}

impl<R> core::fmt::Debug for ImportPlan<R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ImportPlan")
            .field("archive", &self.archive)
            .field("rows", &self.rows)
            .field("collisions", &self.collisions)
            .finish_non_exhaustive()
    }
}

impl<R> ImportPlan<R> {
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

    /// The opaque files optional client layers supplied, each named and sized.
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

impl<R: std::io::Read + std::io::Seek> ImportPlan<R> {
    /// Reads one attachment the plan names into `into`, replacing its contents.
    ///
    /// The caller owns the buffer, so a walk over every attachment holds one
    /// of them at a time.
    ///
    /// # Errors
    ///
    /// [`ClientError::Import`] when the archive carries no attachment at
    /// `path`, or when the entry does not read back at its declared length.
    pub fn read_attachment(&mut self, path: &str, into: &mut Vec<u8>) -> Result<(), ClientError> {
        self.reader.read_attachment(path, into)
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

fn zip_error(error: impl core::fmt::Display) -> ClientError {
    ClientError::Export(format!("writing the zip archive: {error}"))
}

fn read_error(error: impl core::fmt::Display) -> ClientError {
    ClientError::Import(format!("reading the archive: {error}"))
}

pub(crate) use rows::{fingerprint, index_rows, read_rows, schema_columns, write_row};
pub(crate) use zip::read::open;
pub use zip::write::LocalDataExport;
pub(crate) use zip::write::start;
