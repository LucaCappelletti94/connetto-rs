//! The content bookkeeping in the replica: manifests, the upload outbox and
//! the content pins.
//!
//! These tables live in the replica rather than in the device-private tier,
//! and the reason is load-bearing. The invariant is that a manifest and the
//! application row that names its file commit together, and the replica is
//! opened `journal_mode=WAL` before the tier is attached, so the two are
//! separate files and SQLite's cross-file atomic commit does not apply: a
//! transaction over both commits with no error while a host crash may update
//! one file and not the other. The `_connetto_` prefix is what keeps these
//! tables out of capture, out of the tier's application-table listing and off
//! the wire, exactly as it does for `_connetto_pending`.

use std::collections::HashSet;

use connetto_file_core::{ChunkHash, ChunkMeta, FileId, Manifest};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;

use crate::error::ContentError;

diesel::table! {
    /// One row per chunk of one manifest, ordered by `ordinal`.
    ///
    /// There is no manifest header table beside this one, because there is
    /// nothing for it to hold: a file's identity is its key here, its total
    /// length is the sum of these lengths, and file-core emits one chunk even
    /// for an empty file, so a manifest with no chunk row cannot exist.
    _connetto_content_chunks (file_id, ordinal) {
        /// BLAKE3 identity of the file this chunk belongs to.
        file_id -> Binary,
        /// Position of this chunk in the file, from zero.
        ordinal -> Integer,
        /// BLAKE3 hash of the chunk's plaintext, its key in the chunk store.
        hash -> Binary,
        /// Plaintext byte length of the chunk.
        len -> BigInt,
    }
}

diesel::table! {
    /// One row per file this device must upload, authored here or healing a file the server lost, and `outbox` and `outbox_count` read only the authored rows.
    _connetto_content_outbox (file_id) {
        /// BLAKE3 identity of the file awaiting upload.
        file_id -> Binary,
        /// Permanent refusal detail, set when no later attempt can succeed.
        refused -> Nullable<Text>,
        /// Whether the entry heals a file the server lost rather than sending one this device authored.
        heal -> Bool,
    }
}

diesel::table! {
    /// One row per file whose unsent bytes were found unreadable.
    ///
    /// Retiring an outbox entry destroys the only record that this device ever
    /// declared the file, and the application's own row still names it, so the
    /// identity is kept here until the application says it has dealt with it.
    _connetto_content_retired (file_id) {
        /// BLAKE3 identity of the file whose bytes are gone.
        file_id -> Binary,
    }
}

diesel::table! {
    /// One row per content pin, under the application's chosen name.
    _connetto_content_pins (name) {
        /// The application-chosen pin name, its identity for replace and end.
        name -> Text,
        /// The SQLite query whose result names the pinned files.
        query -> Text,
        /// The result column of `query` that carries the file identity.
        file_id_column -> Text,
    }
}

/// The bookkeeping schema, applied on every open so a new replica gains all
/// tables, the same way `_connetto_meta` arrives.
pub(crate) const CONTENT_DDL: &str = "\
    CREATE TABLE IF NOT EXISTS _connetto_content_chunks \
    (file_id BLOB NOT NULL, ordinal INTEGER NOT NULL, hash BLOB NOT NULL, \
     len BIGINT NOT NULL, PRIMARY KEY (file_id, ordinal)); \
    CREATE TABLE IF NOT EXISTS _connetto_content_outbox \
    (file_id BLOB NOT NULL PRIMARY KEY, refused TEXT, heal BOOLEAN NOT NULL DEFAULT FALSE); \
    CREATE TABLE IF NOT EXISTS _connetto_content_retired \
    (file_id BLOB NOT NULL PRIMARY KEY); \
    CREATE TABLE IF NOT EXISTS _connetto_content_pins \
    (name TEXT NOT NULL PRIMARY KEY, query TEXT NOT NULL, file_id_column TEXT NOT NULL)";

/// Adds the `refused` and `heal` columns to an existing outbox table that predates them.
///
/// Run as separate statements after `CONTENT_DDL` because `batch_execute`
/// aborts the whole batch on the first error, and each statement is expected
/// to fail with a duplicate-column error on replicas that already have it.
///
/// # Errors
///
/// [`diesel::result::Error`] for any error other than a duplicate-column name.
pub(crate) fn add_outbox_columns(conn: &mut SqliteConnection) -> Result<(), diesel::result::Error> {
    add_column(
        conn,
        "ALTER TABLE _connetto_content_outbox ADD COLUMN refused TEXT",
    )?;
    add_column(
        conn,
        "ALTER TABLE _connetto_content_outbox ADD COLUMN heal BOOLEAN NOT NULL DEFAULT FALSE",
    )
}

fn add_column(conn: &mut SqliteConnection, statement: &str) -> Result<(), diesel::result::Error> {
    match conn.batch_execute(statement) {
        Ok(()) => Ok(()),
        Err(diesel::result::Error::DatabaseError(_, ref info))
            if info.message().contains("duplicate column name") =>
        {
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Writes a manifest's chunk rows, replacing any the same file already had.
///
/// Replacing rather than failing is what makes a re-stage of the same bytes
/// idempotent: the identity is the bytes, so a second stage of the same file
/// describes the same chunks in the same order.
pub(crate) fn put_manifest(
    conn: &mut SqliteConnection,
    manifest: &Manifest,
) -> Result<(), diesel::result::Error> {
    let id = manifest.file_id().as_bytes().to_vec();
    diesel::delete(_connetto_content_chunks::table)
        .filter(_connetto_content_chunks::file_id.eq(&id))
        .execute(conn)?;
    for (ordinal, chunk) in manifest.chunks().iter().enumerate() {
        let ordinal = i32::try_from(ordinal).map_err(|_| {
            diesel::result::Error::SerializationError(
                "a manifest with more than two billion chunks cannot be recorded".into(),
            )
        })?;
        let len = i64::try_from(chunk.len).map_err(|_| {
            diesel::result::Error::SerializationError(
                "a chunk longer than i64::MAX cannot be recorded".into(),
            )
        })?;
        diesel::insert_into(_connetto_content_chunks::table)
            .values((
                _connetto_content_chunks::file_id.eq(&id),
                _connetto_content_chunks::ordinal.eq(ordinal),
                _connetto_content_chunks::hash.eq(chunk.hash.as_bytes().to_vec()),
                _connetto_content_chunks::len.eq(len),
            ))
            .execute(conn)?;
    }
    Ok(())
}

/// Reads back a manifest, or `None` when this device holds none for the file.
pub(crate) fn load_manifest(
    conn: &mut SqliteConnection,
    file_id: FileId,
) -> Result<Option<Manifest>, ContentError> {
    let rows: Vec<(Vec<u8>, i64)> = _connetto_content_chunks::table
        .filter(_connetto_content_chunks::file_id.eq(file_id.as_bytes().to_vec()))
        .order(_connetto_content_chunks::ordinal.asc())
        .select((
            _connetto_content_chunks::hash,
            _connetto_content_chunks::len,
        ))
        .load(conn)?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut chunks = Vec::with_capacity(rows.len());
    for (hash, len) in rows {
        chunks.push(ChunkMeta {
            hash: ChunkHash::from_bytes(exactly_32(&hash)?),
            len: u64::try_from(len).map_err(|_| ContentError::Replica(negative_length()))?,
        });
    }
    Ok(Some(Manifest::new(file_id, chunks)))
}

/// Deletes a manifest's chunk rows.
pub(crate) fn drop_manifest(
    conn: &mut SqliteConnection,
    file_id: FileId,
) -> Result<(), diesel::result::Error> {
    diesel::delete(_connetto_content_chunks::table)
        .filter(_connetto_content_chunks::file_id.eq(file_id.as_bytes().to_vec()))
        .execute(conn)
        .map(|_| ())
}

/// Every file this device holds a manifest for.
pub(crate) fn all_manifests(conn: &mut SqliteConnection) -> Result<Vec<FileId>, ContentError> {
    let rows: Vec<Vec<u8>> = _connetto_content_chunks::table
        .select(_connetto_content_chunks::file_id)
        .distinct()
        .load(conn)?;
    rows.into_iter()
        .map(|id| Ok(FileId::from_bytes(exactly_32(&id)?)))
        .collect()
}

/// Every chunk hash some manifest still names.
///
/// The set a sweep keeps. Asking the replica what is referenced, rather than
/// asking which of a candidate list is not, is what lets the sweep also see
/// chunks no manifest ever named: a staging call whose transaction failed
/// leaves files on disk that no released-hash list would ever mention.
pub(crate) fn referenced_hashes(
    conn: &mut SqliteConnection,
) -> Result<HashSet<ChunkHash>, ContentError> {
    let rows: Vec<Vec<u8>> = _connetto_content_chunks::table
        .select(_connetto_content_chunks::hash)
        .distinct()
        .load(conn)?;
    rows.into_iter()
        .map(|hash| Ok(ChunkHash::from_bytes(exactly_32(&hash)?)))
        .collect()
}

/// Records that this device holds a file the server lost and should upload it again.
pub(crate) fn enqueue_heal(
    conn: &mut SqliteConnection,
    file_id: FileId,
) -> Result<(), diesel::result::Error> {
    diesel::insert_or_ignore_into(_connetto_content_outbox::table)
        .values((
            _connetto_content_outbox::file_id.eq(file_id.as_bytes().to_vec()),
            _connetto_content_outbox::heal.eq(true),
        ))
        .execute(conn)
        .map(|_| ())
}

/// Every heal entry in the outbox.
pub(crate) fn heal_entries(conn: &mut SqliteConnection) -> Result<Vec<FileId>, ContentError> {
    let rows: Vec<Vec<u8>> = _connetto_content_outbox::table
        .filter(_connetto_content_outbox::heal.eq(true))
        .select(_connetto_content_outbox::file_id)
        .load(conn)?;
    rows.into_iter()
        .map(|id| Ok(FileId::from_bytes(exactly_32(&id)?)))
        .collect()
}

/// Whether this file's outbox entry is a heal.
pub(crate) fn is_heal(
    conn: &mut SqliteConnection,
    file_id: FileId,
) -> Result<bool, diesel::result::Error> {
    _connetto_content_outbox::table
        .filter(_connetto_content_outbox::file_id.eq(file_id.as_bytes().to_vec()))
        .filter(_connetto_content_outbox::heal.eq(true))
        .count()
        .get_result::<i64>(conn)
        .map(|n| n > 0)
}

/// Records that a file is authored here and not yet uploaded, turning a queued heal of it authored.
pub(crate) fn enqueue(
    conn: &mut SqliteConnection,
    file_id: FileId,
) -> Result<(), diesel::result::Error> {
    diesel::insert_into(_connetto_content_outbox::table)
        .values(_connetto_content_outbox::file_id.eq(file_id.as_bytes().to_vec()))
        .on_conflict(_connetto_content_outbox::file_id)
        .do_update()
        .set(_connetto_content_outbox::heal.eq(false))
        .execute(conn)
        .map(|_| ())
}

/// Retires an outbox entry, whether the upload succeeded or gave up.
pub(crate) fn dequeue(
    conn: &mut SqliteConnection,
    file_id: FileId,
) -> Result<(), diesel::result::Error> {
    diesel::delete(_connetto_content_outbox::table)
        .filter(_connetto_content_outbox::file_id.eq(file_id.as_bytes().to_vec()))
        .execute(conn)
        .map(|_| ())
}

/// Records that a file's unsent bytes were unreadable, so the loss survives a restart.
pub(crate) fn record_retired(
    conn: &mut SqliteConnection,
    file_id: FileId,
) -> Result<(), diesel::result::Error> {
    diesel::insert_or_ignore_into(_connetto_content_retired::table)
        .values(_connetto_content_retired::file_id.eq(file_id.as_bytes().to_vec()))
        .execute(conn)
        .map(|_| ())
}

/// Every file whose loss the application has not acknowledged.
pub(crate) fn retired(conn: &mut SqliteConnection) -> Result<Vec<FileId>, ContentError> {
    let rows: Vec<Vec<u8>> = _connetto_content_retired::table
        .order(_connetto_content_retired::file_id.asc())
        .select(_connetto_content_retired::file_id)
        .load(conn)?;
    rows.into_iter()
        .map(|id| Ok(FileId::from_bytes(exactly_32(&id)?)))
        .collect()
}

/// Drops one acknowledged loss.
pub(crate) fn forget_retired(
    conn: &mut SqliteConnection,
    file_id: FileId,
) -> Result<(), diesel::result::Error> {
    diesel::delete(_connetto_content_retired::table)
        .filter(_connetto_content_retired::file_id.eq(file_id.as_bytes().to_vec()))
        .execute(conn)
        .map(|_| ())
}

/// Every authored file awaiting upload, oldest identity first for a stable walk order.
pub(crate) fn outbox(conn: &mut SqliteConnection) -> Result<Vec<FileId>, ContentError> {
    let rows: Vec<Vec<u8>> = _connetto_content_outbox::table
        .filter(_connetto_content_outbox::heal.eq(false))
        .order(_connetto_content_outbox::file_id.asc())
        .select(_connetto_content_outbox::file_id)
        .load(conn)?;
    rows.into_iter()
        .map(|id| Ok(FileId::from_bytes(exactly_32(&id)?)))
        .collect()
}

/// Number of authored files waiting for upload.
pub(crate) fn outbox_count(conn: &mut SqliteConnection) -> Result<u64, ContentError> {
    let count = _connetto_content_outbox::table
        .filter(_connetto_content_outbox::heal.eq(false))
        .count()
        .get_result::<i64>(conn)?;
    Ok(u64::try_from(count).expect("SQLite COUNT is non-negative"))
}

/// Number of files waiting for upload that have not been marked as permanently refused.
pub(crate) fn sendable_count(conn: &mut SqliteConnection) -> Result<u64, ContentError> {
    let count = _connetto_content_outbox::table
        .count()
        .filter(_connetto_content_outbox::refused.is_null())
        .get_result::<i64>(conn)?;
    Ok(u64::try_from(count).expect("SQLite COUNT is non-negative"))
}

/// Marks an outbox entry as permanently refused, recording the detail.
///
/// The entry stays in the outbox and is counted by `outbox` and
/// `outbox_count`, but `sendable` excludes it until `clear_refusal` clears
/// the mark.
///
/// # Errors
///
/// [`diesel::result::Error`] when the update cannot be written.
pub(crate) fn refuse(
    conn: &mut SqliteConnection,
    file_id: FileId,
    detail: &str,
) -> Result<(), diesel::result::Error> {
    diesel::update(_connetto_content_outbox::table)
        .filter(_connetto_content_outbox::file_id.eq(file_id.as_bytes().to_vec()))
        .set(_connetto_content_outbox::refused.eq(detail))
        .execute(conn)
        .map(|_| ())
}

/// Clears the refusal mark on one outbox entry so the next walk attempts it.
///
/// # Errors
///
/// [`diesel::result::Error`] when the update cannot be written.
pub(crate) fn clear_refusal(
    conn: &mut SqliteConnection,
    file_id: FileId,
) -> Result<(), diesel::result::Error> {
    diesel::update(_connetto_content_outbox::table)
        .filter(_connetto_content_outbox::file_id.eq(file_id.as_bytes().to_vec()))
        .set(_connetto_content_outbox::refused.eq::<Option<String>>(None))
        .execute(conn)
        .map(|_| ())
}

/// Outbox entries that have not been marked as permanently refused, in
/// identity order.
///
/// This is the candidate list the upload driver walks: refused entries wait
/// for an explicit retry and are never re-attempted on their own.
///
/// # Errors
///
/// [`ContentError::Replica`] when the outbox cannot be read.
pub(crate) fn sendable(conn: &mut SqliteConnection) -> Result<Vec<FileId>, ContentError> {
    let rows: Vec<Vec<u8>> = _connetto_content_outbox::table
        .order(_connetto_content_outbox::file_id.asc())
        .filter(_connetto_content_outbox::refused.is_null())
        .select(_connetto_content_outbox::file_id)
        .load(conn)?;
    rows.into_iter()
        .map(|id| Ok(FileId::from_bytes(exactly_32(&id)?)))
        .collect()
}

/// Every refused outbox entry with its permanent refusal detail, in identity order.
///
/// # Errors
///
/// [`ContentError::Replica`] when the outbox cannot be read.
pub(crate) fn refusals(conn: &mut SqliteConnection) -> Result<Vec<(FileId, String)>, ContentError> {
    let rows: Vec<(Vec<u8>, Option<String>)> = _connetto_content_outbox::table
        .order(_connetto_content_outbox::file_id.asc())
        .filter(_connetto_content_outbox::refused.is_not_null())
        .select((
            _connetto_content_outbox::file_id,
            _connetto_content_outbox::refused,
        ))
        .load(conn)?;
    rows.into_iter()
        .map(|(id, detail)| {
            let file_id = FileId::from_bytes(exactly_32(&id)?);
            let detail = detail.ok_or_else(|| {
                diesel::result::Error::DeserializationError(
                    "refused column was null after IS NOT NULL filter".into(),
                )
            })?;
            Ok((file_id, detail))
        })
        .collect()
}

/// Whether this file is still awaiting upload.
pub(crate) fn is_unsent(
    conn: &mut SqliteConnection,
    file_id: FileId,
) -> Result<bool, diesel::result::Error> {
    _connetto_content_outbox::table
        .filter(_connetto_content_outbox::file_id.eq(file_id.as_bytes().to_vec()))
        .count()
        .get_result::<i64>(conn)
        .map(|n| n > 0)
}

/// Whether any manifest still names this chunk.
pub(crate) fn hash_is_referenced(
    conn: &mut SqliteConnection,
    hash: &ChunkHash,
) -> Result<bool, diesel::result::Error> {
    _connetto_content_chunks::table
        .filter(_connetto_content_chunks::hash.eq(hash.as_bytes().to_vec()))
        .count()
        .get_result::<i64>(conn)
        .map(|n| n > 0)
}

/// Creates or replaces a pin under `name`.
pub(crate) fn put_pin(
    conn: &mut SqliteConnection,
    name: &str,
    query: &str,
    file_id_column: &str,
) -> Result<(), diesel::result::Error> {
    diesel::replace_into(_connetto_content_pins::table)
        .values((
            _connetto_content_pins::name.eq(name),
            _connetto_content_pins::query.eq(query),
            _connetto_content_pins::file_id_column.eq(file_id_column),
        ))
        .execute(conn)
        .map(|_| ())
}

/// Ends the pin under `name`. Unknown names are a no-op.
pub(crate) fn drop_pin(
    conn: &mut SqliteConnection,
    name: &str,
) -> Result<(), diesel::result::Error> {
    diesel::delete(_connetto_content_pins::table)
        .filter(_connetto_content_pins::name.eq(name))
        .execute(conn)
        .map(|_| ())
}

/// Every pin as name, query and file-id column, in name order.
pub(crate) fn pins(
    conn: &mut SqliteConnection,
) -> Result<Vec<(String, String, String)>, diesel::result::Error> {
    _connetto_content_pins::table
        .order(_connetto_content_pins::name.asc())
        .select((
            _connetto_content_pins::name,
            _connetto_content_pins::query,
            _connetto_content_pins::file_id_column,
        ))
        .load(conn)
}

/// Rejects a hash column that is not 32 bytes wide.
fn exactly_32(bytes: &[u8]) -> Result<[u8; 32], ContentError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        ContentError::Replica(diesel::result::Error::DeserializationError(
            format!("a content hash column holds {} bytes, not 32", bytes.len()).into(),
        ))
    })
}

/// The error a negative stored chunk length produces.
fn negative_length() -> diesel::result::Error {
    diesel::result::Error::DeserializationError("a chunk length column is negative".into())
}
