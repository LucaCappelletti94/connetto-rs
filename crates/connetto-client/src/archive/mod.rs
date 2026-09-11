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
        zip::validate_attachment_path(&path, ClientError::Export)?;
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

    /// Constructs a pre-validated entry directly, for use by the zip reader.
    fn from_raw(path: String, bytes: Vec<u8>) -> Self {
        Self { path, bytes }
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

fn zip_error(error: impl core::fmt::Display) -> ClientError {
    ClientError::Export(format!("writing the zip archive: {error}"))
}

fn read_error(error: impl core::fmt::Display) -> ClientError {
    ClientError::Import(format!("reading the archive: {error}"))
}

pub(crate) use rows::{fingerprint, index_rows, read_rows, schema_columns, write_row};
pub(crate) use zip::{read, write};
