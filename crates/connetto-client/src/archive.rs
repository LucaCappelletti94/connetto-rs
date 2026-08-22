//! The device archive: what an export writes and an import reads.
//!
//! Every entry is connetto's own binary format, a SQLite change record rather
//! than a database (R56 decision 10). The rows of a tier travel as the session
//! patchset the export already had to build, so nothing is replayed into a
//! second database and serialized back out, and an import is the exact inverse
//! of an export. That costs the readability the first format promised, which
//! only ever paid when connetto was absent: handing a person their data is
//! `R61`'s job and reads from queries the application supplies.
//!
//! The manifest carries what an import has to check before it applies anything:
//! the schema the archive was made under, the account it belongs to, and which
//! entries are present.
//!
//! **The file is not encrypted.** It holds every row the device can read, in
//! the clear, so it is a bearer document. That is a decision rather than an
//! oversight (`R26`), and the method that writes it says so where the person
//! chooses to write one.

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

/// The archive format's own name, unchanged from `R26` so an older file is
/// recognised and refused by version rather than mistaken for something else.
const FORMAT: &str = "connetto-local-data";
/// Raised by `R56`: version 1 was a zip of plain SQLite databases.
const VERSION: u32 = 2;
const MANIFEST: &str = "manifest.json";
const SYNCED_ROWS: &str = "synced.patchset";
const LOCAL_ROWS: &str = "device-private.patchset";
const PENDING: &str = "pending.changesets";
/// What the manifest says about its own entries, so a person opening the file
/// is not left guessing why SQLite will not open one.
const NOTE: &str =
    "every entry is a SQLite change record, connetto's own binary format, not a database";

/// One archive about to be written.
#[derive(Debug)]
pub(crate) struct Archive {
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
}

#[derive(serde::Serialize, serde::Deserialize)]
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
struct Entry {
    kind: String,
    path: String,
}

fn zip_error(error: impl core::fmt::Display) -> ClientError {
    ClientError::Export(format!("writing the zip archive: {error}"))
}

fn read_error(error: impl core::fmt::Display) -> ClientError {
    ClientError::Import(format!("reading the archive: {error}"))
}

/// Write `archive` as a zip of compressed change records.
///
/// Entries are compressed (`R26`'s leftover): `zstd` is an unconditional
/// dependency of this crate on every target, and the whole wire protocol
/// already compresses with it.
pub(crate) fn write(archive: &Archive) -> Result<Vec<u8>, ClientError> {
    let mut entries = Vec::new();
    if archive.synced_rows.is_some() {
        entries.push(Entry {
            kind: "rows".to_owned(),
            path: SYNCED_ROWS.to_owned(),
        });
    }
    if archive.local_rows.is_some() {
        entries.push(Entry {
            kind: "rows".to_owned(),
            path: LOCAL_ROWS.to_owned(),
        });
    }
    if !archive.pending.is_empty() {
        entries.push(Entry {
            kind: "pending".to_owned(),
            path: PENDING.to_owned(),
        });
    }
    let manifest = serde_json::to_vec_pretty(&Manifest {
        format: FORMAT.to_owned(),
        version: VERSION,
        scope: archive.scope.as_str().to_owned(),
        schema_fingerprint: archive.fingerprint.clone(),
        account: archive.account.clone(),
        compression: "zstd".to_owned(),
        note: NOTE.to_owned(),
        entries,
    })
    .map_err(|err| ClientError::Export(format!("encoding the manifest: {err}")))?;

    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    // The manifest stays uncompressed: it is small, and a reader deciding
    // whether to accept the file at all should not have to decompress first.
    zip.start_file(MANIFEST, options).map_err(zip_error)?;
    zip.write_all(&manifest).map_err(zip_error)?;
    if let Some(rows) = &archive.synced_rows {
        write_entry(&mut zip, SYNCED_ROWS, rows, options)?;
    }
    if let Some(rows) = &archive.local_rows {
        write_entry(&mut zip, LOCAL_ROWS, rows, options)?;
    }
    if !archive.pending.is_empty() {
        write_entry(
            &mut zip,
            PENDING,
            &encode_pending(&archive.pending),
            options,
        )?;
    }
    zip.finish()
        .map(std::io::Cursor::into_inner)
        .map_err(zip_error)
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
    let synced_present = zip.by_name(SYNCED_ROWS).is_ok();
    let local_rows = read_entry(&mut zip, LOCAL_ROWS)?;
    let pending = match read_entry(&mut zip, PENDING)? {
        Some(bytes) => decode_pending(&bytes)?,
        None => Vec::new(),
    };
    Ok(Incoming {
        scope,
        fingerprint: manifest.schema_fingerprint,
        account: manifest.account,
        synced_present,
        local_rows,
        pending,
    })
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
    use super::{Archive, ExportScope, decode_pending, encode_pending, read, write};

    /// The queue's framing carries every record, in order, whatever the bytes
    /// inside one look like.
    #[test]
    fn the_queue_framing_round_trips() {
        let records = vec![vec![0u8, 1, 2], Vec::new(), vec![255u8; 300]];
        let encoded = encode_pending(&records);
        assert_eq!(decode_pending(&encoded).expect("decode"), records);
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

    /// A file that is not one of ours is refused by name rather than parsed.
    #[test]
    fn a_foreign_file_is_refused() {
        assert!(read(b"not a zip at all").is_err());
    }
}
