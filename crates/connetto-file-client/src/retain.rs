//! Which content a device keeps: the pin coverage and the manifest eviction it drives.
//!
//! Shared by the page-side client's tidy pass and the worker-owned archive, because the
//! policy is the same in both: a file is kept while a pin covers it or it is still unsent.

use std::collections::HashSet;

use connetto_file_core::{FileId, Manifest};
use diesel::prelude::*;

use crate::db;
use crate::error::ContentError;

/// Every file identity the replica's pins currently cover.
///
/// # Errors
///
/// [`ContentError::Replica`] when a pin row or a pin query cannot be read.
pub(crate) fn pinned_ids(conn: &mut SqliteConnection) -> Result<HashSet<FileId>, ContentError> {
    let mut wanted = HashSet::new();
    for (_, query, column) in db::pins(conn)? {
        let rows: Vec<PinnedId> = diesel::sql_query(pin_sql(&query, &column)).load(conn)?;
        for row in rows {
            if let Ok(bytes) = <[u8; 32]>::try_from(row.file_id.as_slice()) {
                wanted.insert(FileId::from_bytes(bytes));
            }
        }
    }
    Ok(wanted)
}

/// One file identity out of a pin query.
#[derive(diesel::QueryableByName)]
pub(crate) struct PinnedId {
    /// The identity bytes the pin's named column carried.
    #[diesel(sql_type = diesel::sql_types::Binary)]
    file_id: Vec<u8>,
}

/// Drops every manifest nothing covers and answers how many went.
///
/// The chunk files are not touched here. The rows have to commit before any
/// file goes, because the reverse order leaves a manifest pointing at bytes
/// that are gone.
pub(crate) fn evict_uncovered(
    conn: &mut SqliteConnection,
    pinned: &HashSet<FileId>,
) -> Result<usize, ContentError> {
    let mut evicted = 0;
    for file_id in db::all_manifests(conn)? {
        if evictable(conn, pinned, file_id)?.is_none() {
            continue;
        }
        db::drop_manifest(conn, file_id)?;
        evicted += 1;
    }
    Ok(evicted)
}

/// The manifest to evict, or `None` when something still wants this file.
fn evictable(
    conn: &mut SqliteConnection,
    pinned: &HashSet<FileId>,
    file_id: FileId,
) -> Result<Option<Manifest>, ContentError> {
    if pinned.contains(&file_id) || db::is_unsent(conn, file_id)? {
        return Ok(None);
    }
    db::load_manifest(conn, file_id)
}

/// Wraps a pin's query so one fixed column name comes back.
///
/// The wrap costs nothing: SQLite flattens a bare subselect, which R58
/// measured on the server side of the same pattern.
///
/// The column is bracket-quoted rather than double-quoted, and the difference
/// is load-bearing. SQLite resolves a double-quoted identifier that names no
/// column as a string literal instead of refusing it, so a pin naming a
/// column its query does not return would be accepted and would then answer
/// the text of its own column name for every row, as a file identity. Bracket
/// quoting has no such fallback and reports `no such column`.
pub(crate) fn pin_sql(query: &str, column: &str) -> String {
    format!("SELECT [{column}] AS file_id FROM ({query}) AS _connetto_pin")
}
