//! Needed-hashes computation for the intent answer.
//!
//! All four steps run inside one transaction so `set_config` with `is_local =
//! true` stays in scope for the full query: a transaction-scoped setting
//! evaporates after its statement's autocommit without a wrapping transaction.
//! The `connetto_visible_files` function applies its own RLS after `set_config`
//! threads the caller identity in, so caller B cannot learn whether any of
//! caller A's committed file ids share the declared chunk bytes.
//!
//! Both helper queries use `sql_query`: the typed DSL cannot express a generic
//! `INNER JOIN` over two laundered query sources, and `eq_any` with a generic
//! column type is not covered by the trait's where clauses.

use std::collections::HashSet;

use connetto_core::auth::ContentCaller;
use connetto_file_core::{ChunkHash, ChunkMeta};
use diesel::prelude::*;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

use crate::caller::{CallerSettings, bind_caller};
use crate::functions;
use crate::schema::ConnettoFileSchema;

/// Returns the chunk hashes from `chunks` that `caller` must upload.
///
/// Two sets are excluded from the answer. Chunks already present in committed
/// files visible to `caller` (through `connetto_visible_files`) need no
/// transfer, and chunks this same manifest (`own_file_id`, `own_key`) already
/// has stored need no transfer either: a retry whose commit was refused
/// re-PUTs nothing, which is what keeps a refused upload from re-billing its
/// bytes to the deployment's bandwidth window on every attempt. The
/// own-manifest rows are keyed by the verified caller's storage key, so the
/// answer never speaks of another caller's uploads.
pub(crate) async fn needed_hashes<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    settings: &CallerSettings,
    caller: &ContentCaller,
    chunks: &[ChunkMeta],
    own_file_id: &[u8],
    own_key: &str,
) -> Result<Vec<ChunkHash>, diesel::result::Error> {
    if chunks.is_empty() {
        return Ok(Vec::new());
    }
    let declared: Vec<Vec<u8>> = chunks.iter().map(|m| m.hash.as_bytes().to_vec()).collect();
    let caller = caller.clone();
    let settings = settings.clone();
    let chunks_snap: Vec<ChunkMeta> = chunks.to_vec();
    let own_id = own_file_id.to_vec();
    let own_key = own_key.to_string();
    conn.transaction::<Vec<ChunkHash>, diesel::result::Error, _>(async move |c| {
        // Step 1: bind the caller so RLS fires inside connetto_visible_files.
        bind_caller(c, &settings, &caller).await?;

        // Step 2: chunks this exact manifest has already stored. No
        // visibility function is needed for them: the rows carry the
        // caller's own storage key, derived from the verified ticket.
        let own_stored = own_stored_hashes::<S>(c, &own_id, &own_key).await?;

        // Step 3: the declared hashes that committed manifests visible to
        // the caller already carry.
        let present = visible_committed_hashes_in::<S>(c, &declared).await?;

        let needed = chunks_snap
            .iter()
            .filter(|m| {
                !present.contains(m.hash.as_bytes()) && !own_stored.contains(m.hash.as_bytes())
            })
            .map(|m| m.hash)
            .collect();
        Ok(needed)
    })
    .await
}

/// The declared bytes a commit adds to the deployment's storage total: the
/// distinct hashes of `pairs` no committed manifest visible to `caller`
/// carries, each counted once because the total itself sums distinct
/// `(hash, len)` pairs. Visibility is the very function the intent answer
/// uses, so a ceiling decision cannot reveal more than that answer
/// legitimately does, and a committed duplicate the caller cannot see is
/// charged whole, the same conservative direction the per-identity quota
/// takes.
pub(crate) async fn new_declared_bytes<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    settings: &CallerSettings,
    caller: &ContentCaller,
    pairs: &[(Vec<u8>, i64)],
) -> Result<u64, diesel::result::Error> {
    if pairs.is_empty() {
        return Ok(0);
    }
    let declared: Vec<Vec<u8>> = pairs.iter().map(|p| p.0.clone()).collect();
    let caller = caller.clone();
    let settings = settings.clone();
    let lens = pairs.to_vec();
    conn.transaction::<u64, diesel::result::Error, _>(async move |c| {
        bind_caller(c, &settings, &caller).await?;
        let present = visible_committed_hashes_in::<S>(c, &declared).await?;
        // Each hash counts once. The stored total sums distinct
        // (hash, len) pairs, so a manifest repeating a chunk slab may
        // charge it at most once.
        let mut counted: HashSet<&[u8]> = HashSet::new();
        Ok(lens
            .iter()
            .filter(|(hash, _)| !present.contains(hash.as_slice()))
            .filter(|(hash, _)| counted.insert(hash.as_slice()))
            .map(|(_, len)| u64::try_from(*len).unwrap_or(0))
            .sum())
    })
    .await
}

/// The declared hashes carried by committed manifests the bound caller may
/// see. Runs inside the caller's already-open transaction, after
/// [`bind_caller`], so `connetto_visible_files` applies RLS.
async fn visible_committed_hashes_in<S: ConnettoFileSchema>(
    c: &mut AsyncPgConnection,
    declared: &[Vec<u8>],
) -> Result<HashSet<[u8; 32]>, diesel::result::Error> {
    let candidate_ids = committed_file_ids_for::<S>(c, declared).await?;
    if candidate_ids.is_empty() {
        return Ok(HashSet::new());
    }
    let visible_ids: Vec<Vec<u8>> =
        diesel::select(functions::connetto_visible_files(candidate_ids))
            .get_result(c)
            .await?;
    if visible_ids.is_empty() {
        return Ok(HashSet::new());
    }
    present_chunk_hashes::<S>(c, &visible_ids, declared).await
}

/// The hashes this manifest's own rows have stored, whether or not the file
/// is committed. `stored` flips when the chunk's PUT passes its verification.
async fn own_stored_hashes<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    own_file_id: &[u8],
    own_key: &str,
) -> Result<HashSet<[u8; 32]>, diesel::result::Error> {
    #[derive(QueryableByName)]
    struct OwnHashRow {
        #[diesel(sql_type = diesel::sql_types::Bytea)]
        chunk_hash: Vec<u8>,
    }
    let rows: Vec<OwnHashRow> = diesel::sql_query(format!(
        "SELECT mc.chunk_hash FROM {chunks} mc WHERE mc.file_id = $1 AND mc.uploaded_by = $2 \
         AND mc.stored",
        chunks = S::MANIFEST_CHUNKS_SQL,
    ))
    .bind::<diesel::sql_types::Bytea, _>(own_file_id)
    .bind::<diesel::sql_types::Text, _>(own_key)
    .load(conn)
    .await?;
    let mut set = HashSet::with_capacity(rows.len());
    for row in rows {
        let hash: [u8; 32] = row.chunk_hash.try_into().map_err(|_| {
            diesel::result::Error::DeserializationError("chunk_hash not 32 bytes".into())
        })?;
        set.insert(hash);
    }
    Ok(set)
}

/// Queries the committed manifest tables for file ids that contain at least
/// one of the declared chunk hashes.
///
/// Uses `sql_query` because a generic `INNER JOIN` over two laundered table
/// types is not expressible through the trait's where clauses.
///
/// The JOIN uses both columns of the composite FK so only `manifest_chunks` rows
/// belonging to committed manifests are considered.
pub(crate) async fn committed_file_ids_for<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    declared_hashes: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, diesel::result::Error> {
    #[derive(QueryableByName)]
    struct FileIdRow {
        #[diesel(sql_type = diesel::sql_types::Bytea)]
        file_id: Vec<u8>,
    }
    let rows: Vec<FileIdRow> = diesel::sql_query(format!(
        "SELECT DISTINCT m.file_id \
         FROM {manifests} m \
         JOIN {chunks} mc ON mc.file_id = m.file_id AND mc.uploaded_by = m.uploaded_by \
         WHERE m.committed = TRUE \
         AND mc.chunk_hash = ANY($1)",
        manifests = S::MANIFESTS_SQL,
        chunks = S::MANIFEST_CHUNKS_SQL,
    ))
    .bind::<diesel::sql_types::Array<diesel::sql_types::Bytea>, _>(declared_hashes)
    .load(conn)
    .await?;
    Ok(rows.into_iter().map(|r| r.file_id).collect())
}

/// Queries chunk hashes from the visible committed manifests that overlap with
/// the declared set.
///
/// Uses `sql_query` because `eq_any` over a generic laundered column type is
/// not covered by the trait's where clauses.
///
/// The JOIN uses both columns of the composite FK to restrict to committed
/// manifests only, preventing uncommitted chunk rows from satisfying the dedup
/// check.
pub(crate) async fn present_chunk_hashes<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    visible_file_ids: &[Vec<u8>],
    declared_hashes: &[Vec<u8>],
) -> Result<HashSet<[u8; 32]>, diesel::result::Error> {
    #[derive(QueryableByName)]
    struct HashRow {
        #[diesel(sql_type = diesel::sql_types::Bytea)]
        chunk_hash: Vec<u8>,
    }
    let rows: Vec<HashRow> = diesel::sql_query(format!(
        "SELECT DISTINCT mc.chunk_hash \
         FROM {chunks} mc \
         JOIN {manifests} m ON m.file_id = mc.file_id AND m.uploaded_by = mc.uploaded_by \
         WHERE m.file_id = ANY($1) \
         AND mc.chunk_hash = ANY($2) \
         AND m.committed = TRUE",
        chunks = S::MANIFEST_CHUNKS_SQL,
        manifests = S::MANIFESTS_SQL,
    ))
    .bind::<diesel::sql_types::Array<diesel::sql_types::Bytea>, _>(visible_file_ids)
    .bind::<diesel::sql_types::Array<diesel::sql_types::Bytea>, _>(declared_hashes)
    .load(conn)
    .await?;

    let mut set = HashSet::with_capacity(rows.len());
    for row in rows {
        let arr: [u8; 32] = row.chunk_hash.try_into().map_err(|_| {
            diesel::result::Error::DeserializationError("chunk_hash not 32 bytes".into())
        })?;
        set.insert(arr);
    }
    Ok(set)
}
