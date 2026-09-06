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

use connetto_file_core::{ChunkHash, ChunkMeta};
use diesel::prelude::*;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

use crate::functions;
use crate::schema::ConnettoFileSchema;

/// Returns the chunk hashes from `chunks` that `caller` must upload.
///
/// Chunks already present in committed files visible to `caller` (through
/// `connetto_visible_files`) are excluded from the answer.
pub(crate) async fn needed_hashes<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    caller: &str,
    chunks: &[ChunkMeta],
) -> Result<Vec<ChunkHash>, diesel::result::Error> {
    if chunks.is_empty() {
        return Ok(Vec::new());
    }
    let declared: Vec<Vec<u8>> = chunks.iter().map(|m| m.hash.as_bytes().to_vec()).collect();
    let caller = caller.to_owned();
    let chunks_snap: Vec<ChunkMeta> = chunks.to_vec();
    conn.transaction::<Vec<ChunkHash>, diesel::result::Error, _>(|c| {
        async move {
            // Step 1: set caller identity so RLS fires inside connetto_visible_files.
            diesel::select(functions::set_config("app.user_id", &caller, true))
                .get_result::<String>(c)
                .await?;

            // Step 2: map declared chunk hashes to committed file ids.
            let candidate_ids = committed_file_ids_for::<S>(c, &declared).await?;
            if candidate_ids.is_empty() {
                return Ok(chunks_snap.iter().map(|m| m.hash).collect());
            }

            // Step 3: ask the deployment which of those file ids the caller may see.
            let visible_ids: Vec<Vec<u8>> =
                diesel::select(functions::connetto_visible_files(candidate_ids))
                    .get_result(c)
                    .await?;
            if visible_ids.is_empty() {
                return Ok(chunks_snap.iter().map(|m| m.hash).collect());
            }

            // Step 4: collect chunk hashes from visible committed manifests that
            // overlap with the declared set.
            let present = present_chunk_hashes::<S>(c, &visible_ids, &declared).await?;
            let needed = chunks_snap
                .iter()
                .filter(|m| !present.contains(m.hash.as_bytes()))
                .map(|m| m.hash)
                .collect();
            Ok(needed)
        }
        .scope_boxed()
    })
    .await
}

/// Queries the committed manifest tables for file ids that contain at least
/// one of the declared chunk hashes.
///
/// Uses `sql_query` because a generic `INNER JOIN` over two laundered table
/// types is not expressible through the trait's where clauses.
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
         JOIN {chunks} mc ON mc.file_id = m.file_id \
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
        "SELECT DISTINCT chunk_hash \
         FROM {chunks} \
         WHERE file_id = ANY($1) \
         AND chunk_hash = ANY($2)",
        chunks = S::MANIFEST_CHUNKS_SQL,
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
