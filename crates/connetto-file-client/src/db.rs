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
    /// One row per file this device authored and has not yet uploaded.
    ///
    /// Presence here is what makes content unsent rather than cached, which
    /// is the distinction chapter 18 draws: unsent content is data and cannot
    /// be refetched, fetched content is cache.
    _connetto_content_outbox (file_id) {
        /// BLAKE3 identity of the file awaiting upload.
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

/// The bookkeeping schema, applied on every open so an existing replica gains
/// it without a migration, the same way `_connetto_meta` arrives.
pub(crate) const CONTENT_DDL: &str = "\
    CREATE TABLE IF NOT EXISTS _connetto_content_chunks \
    (file_id BLOB NOT NULL, ordinal INTEGER NOT NULL, hash BLOB NOT NULL, \
     len BIGINT NOT NULL, PRIMARY KEY (file_id, ordinal)); \
    CREATE TABLE IF NOT EXISTS _connetto_content_outbox \
    (file_id BLOB NOT NULL PRIMARY KEY); \
    CREATE TABLE IF NOT EXISTS _connetto_content_pins \
    (name TEXT NOT NULL PRIMARY KEY, query TEXT NOT NULL, file_id_column TEXT NOT NULL)";

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

/// Records that a file is authored here and not yet uploaded.
pub(crate) fn enqueue(
    conn: &mut SqliteConnection,
    file_id: FileId,
) -> Result<(), diesel::result::Error> {
    diesel::insert_or_ignore_into(_connetto_content_outbox::table)
        .values(_connetto_content_outbox::file_id.eq(file_id.as_bytes().to_vec()))
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

/// Every file awaiting upload, oldest identity first for a stable walk order.
pub(crate) fn outbox(conn: &mut SqliteConnection) -> Result<Vec<FileId>, ContentError> {
    let rows: Vec<Vec<u8>> = _connetto_content_outbox::table
        .order(_connetto_content_outbox::file_id.asc())
        .select(_connetto_content_outbox::file_id)
        .load(conn)?;
    rows.into_iter()
        .map(|id| Ok(FileId::from_bytes(exactly_32(&id)?)))
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
