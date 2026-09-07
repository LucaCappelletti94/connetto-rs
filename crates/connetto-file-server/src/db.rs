//! Database operations generic over [`ConnettoFileSchema`].
//!
//! All typed diesel operations use the schema trait's factory methods and
//! laundered query sources so the table names remain deployment-controlled.
//! Every function uses the typed DSL.

use chrono::{DateTime, Utc};

use connetto_file_core::{ChunkHash, ChunkMeta, FileId, Manifest};
use diesel::query_dsl::methods::{FilterDsl, LimitDsl, SelectDsl};
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncConnectionCore, AsyncPgConnection, RunQueryDsl};

use crate::functions;
use crate::needed;
use crate::schema::ConnettoFileSchema;

// ---------------------------------------------------------------------------
// Public outcome types
// ---------------------------------------------------------------------------

/// Outcome of [`try_account_chunk_put`].
pub(crate) enum ChunkPutResult {
    /// Chunk newly accounted for; stored flag set, tally incremented, registry advanced to `stored`.
    Accepted,
    /// Chunk was already stored for this manifest; re-PUT is idempotent.
    AlreadyStored,
    /// Adding this chunk would push `accepted_bytes` past the ticket ceiling.
    WouldExceedCeiling,
}

/// Outcome of [`insert_manifest`].
pub(crate) enum InsertManifestOutcome {
    /// New manifest declared; chunk rows inserted.
    Inserted,
    /// Manifest already exists and the re-declaration matches it exactly.
    AlreadyPresent,
    /// Manifest already exists but the re-declaration differs from it.
    ManifestConflict,
    /// A declared chunk hash is in `deleting` state; the intent must be retried.
    RegistryConflict,
}

/// Outcome of [`commit_manifest_atomic`].
pub(crate) enum CommitOutcome {
    /// Manifest newly committed and setter called.
    Committed,
    /// Another concurrent or prior commit already committed this manifest.
    /// The setter was NOT called again; treat as idempotent success.
    AlreadyCommitted,
}

/// Manifest existence and committed state, returned by [`load_manifest_locked`].
pub(crate) enum ManifestState {
    /// The manifest exists and has been committed; no further action needed.
    Committed,
    /// The manifest exists but has not yet been committed.
    Uncommitted(Manifest, String),
}

// ---------------------------------------------------------------------------
// Internal transaction error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
enum CommitTxError {
    #[error(transparent)]
    Db(#[from] diesel::result::Error),
    #[error("setter: {0}")]
    Setter(diesel::result::Error),
}

// ---------------------------------------------------------------------------
// Intent operations
// ---------------------------------------------------------------------------

/// Inserts registry rows, locks them, then inserts the manifest and chunk references atomically.
///
/// Returns [`InsertManifestOutcome::RegistryConflict`] when a hash is in `deleting` state,
/// [`InsertManifestOutcome::ManifestConflict`] when the file id already has a different manifest,
/// [`InsertManifestOutcome::AlreadyPresent`] when the re-declaration matches exactly, and
/// [`InsertManifestOutcome::Inserted`] on success.
///
/// Registry and chunk inserts are batched into one SQL statement each so intent for
/// a large manifest does not issue O(n) sequential round trips.
pub(crate) async fn insert_manifest<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    file_id: &FileId,
    total_len: i64,
    caller: &str,
    chunks: &[ChunkMeta],
) -> Result<InsertManifestOutcome, diesel::result::Error> {
    let file_id_bytes = file_id.as_bytes().to_vec();
    let caller_owned = caller.to_owned();
    let chunks_owned: Vec<ChunkMeta> = chunks.to_vec();
    let now = Utc::now();

    conn.transaction::<InsertManifestOutcome, diesel::result::Error, _>(move |c| {
        async move {
            // Collect unique hashes in sorted order for deterministic locking.
            let mut unique_hashes: Vec<Vec<u8>> = chunks_owned
                .iter()
                .map(|ch| ch.hash.as_bytes().to_vec())
                .collect();
            unique_hashes.sort_unstable();
            unique_hashes.dedup();

            // Batch-insert registry rows; clone the hashes because INSERT and the subsequent
            // lock both consume an owned Vec and the INSERT must run first.
            if !unique_hashes.is_empty() {
                c.execute_returning_count(S::insert_registry_pending_batch_stmt(
                    unique_hashes.clone(),
                ))
                .await?;
            }

            // Lock registry rows in hash order to prevent deadlocks with other uploads.
            let locked: Vec<(Vec<u8>, String)> =
                S::lock_registry_rows_stmt(unique_hashes).load(c).await?;
            if locked.iter().any(|(_, state)| state == "deleting") {
                return Err(diesel::result::Error::RollbackTransaction);
            }

            // Try to insert the manifest header.
            let inserted = c
                .execute_returning_count(S::insert_manifest_stmt(
                    file_id_bytes.clone(),
                    total_len,
                    caller_owned,
                    now,
                ))
                .await?;

            if inserted == 0 {
                // Manifest already exists; compare with stored chunk rows.
                let existing = load_chunk_rows::<S>(c, file_id_bytes).await?;
                return Ok(
                    if declared_matches_stored(&chunks_owned, existing.chunks()) {
                        InsertManifestOutcome::AlreadyPresent
                    } else {
                        InsertManifestOutcome::ManifestConflict
                    },
                );
            }

            // Batch-insert chunk rows (one SQL statement, not one per chunk).
            if !chunks_owned.is_empty() {
                let rows: Vec<(i32, Vec<u8>, i64)> = chunks_owned
                    .iter()
                    .enumerate()
                    .map(|(i, ch)| {
                        let pos = i32::try_from(i).map_err(|_| {
                            diesel::result::Error::DeserializationError(
                                "chunk count overflows i32".into(),
                            )
                        })?;
                        let len = i64::try_from(ch.len).map_err(|_| {
                            diesel::result::Error::DeserializationError(
                                "chunk len overflows i64".into(),
                            )
                        })?;
                        Ok((pos, ch.hash.as_bytes().to_vec(), len))
                    })
                    .collect::<Result<Vec<_>, diesel::result::Error>>()?;
                c.execute_returning_count(S::insert_chunk_rows_batch_stmt(file_id_bytes, rows))
                    .await?;
            }

            Ok(InsertManifestOutcome::Inserted)
        }
        .scope_boxed()
    })
    .await
    .or_else(|e| match e {
        diesel::result::Error::RollbackTransaction => Ok(InsertManifestOutcome::RegistryConflict),
        other => Err(other),
    })
}

// ---------------------------------------------------------------------------
// Load helpers
// ---------------------------------------------------------------------------

/// Returns the manifest for `file_id` only if it is committed.
pub(crate) async fn load_committed_manifest<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    file_id: &FileId,
) -> Result<Option<Manifest>, diesel::result::Error> {
    let filtered = FilterDsl::filter(
        S::ManifestsQuery::default(),
        S::manifest_pk_eq(file_id.as_bytes().to_vec()),
    );
    let query = SelectDsl::select(
        filtered,
        (S::MColFileId::default(), S::MColCommitted::default()),
    );
    let mut rows: Vec<(Vec<u8>, bool)> = LimitDsl::limit(query, 1).load(conn).await?;
    match rows.pop() {
        Some((fid, true)) => load_chunk_rows::<S>(conn, fid).await.map(Some),
        _ => Ok(None),
    }
}

/// Locks and returns the manifest for `file_id` in any state.
pub(crate) async fn load_manifest_locked<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    file_id: &FileId,
) -> Result<Option<ManifestState>, diesel::result::Error> {
    let mut rows: Vec<(Vec<u8>, bool, String)> =
        S::lock_manifest_row_stmt(file_id.as_bytes().to_vec())
            .load(conn)
            .await?;
    let Some((file_id, committed, uploaded_by)) = rows.pop() else {
        return Ok(None);
    };
    if committed {
        return Ok(Some(ManifestState::Committed));
    }
    let manifest = load_chunk_rows::<S>(conn, file_id).await?;
    Ok(Some(ManifestState::Uncommitted(manifest, uploaded_by)))
}

/// Returns the declared chunk length for `chunk_hash` in this upload, or
/// `None` if the hash is not in the manifest.
pub(crate) async fn declared_chunk_len<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    file_id: &FileId,
    chunk_hash: &ChunkHash,
) -> Result<Option<u64>, diesel::result::Error> {
    let filtered1 = FilterDsl::filter(
        S::ManifestChunksQuery::default(),
        S::mc_file_id_eq(file_id.as_bytes().to_vec()),
    );
    let filtered2 = FilterDsl::filter(
        filtered1,
        S::mc_chunk_hash_eq(chunk_hash.as_bytes().to_vec()),
    );
    let query = SelectDsl::select(filtered2, S::MCColChunkLen::default());
    let mut rows: Vec<i64> = LimitDsl::limit(query, 1).load(conn).await?;
    rows.pop()
        .map(|l| {
            u64::try_from(l).map_err(|_| {
                diesel::result::Error::DeserializationError("negative chunk_len".into())
            })
        })
        .transpose()
}

// ---------------------------------------------------------------------------
// PUT operations
// ---------------------------------------------------------------------------

/// Accounts one durably written chunk inside the caller's registry-lock transaction.
pub(crate) async fn account_chunk_put<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    file_id: &FileId,
    chunk_hash: &ChunkHash,
    chunk_len: u64,
    ceiling: u64,
) -> Result<ChunkPutResult, diesel::result::Error> {
    let file_id_bytes = file_id.as_bytes().to_vec();
    let hash_bytes = chunk_hash.as_bytes().to_vec();
    let chunk_len_i64 = i64::try_from(chunk_len).map_err(|_| {
        diesel::result::Error::DeserializationError("chunk_len overflows i64".into())
    })?;
    let ceiling_i64 = i64::try_from(ceiling)
        .map_err(|_| diesel::result::Error::DeserializationError("ceiling overflows i64".into()))?;
    let allowed = ceiling_i64.checked_sub(chunk_len_i64).unwrap_or(-1);

    let mark_stored =
        S::mark_chunk_stored_stmt(file_id_bytes.clone(), hash_bytes.clone(), chunk_len_i64);
    if conn.execute_returning_count(mark_stored).await? == 0 {
        return Ok(ChunkPutResult::AlreadyStored);
    }

    let tally = S::tally_bytes_stmt(file_id_bytes, chunk_len_i64, allowed);
    if conn.execute_returning_count(tally).await? == 0 {
        return Ok(ChunkPutResult::WouldExceedCeiling);
    }

    conn.execute_returning_count(S::mark_registry_stored_stmt(hash_bytes))
        .await?;
    Ok(ChunkPutResult::Accepted)
}

// ---------------------------------------------------------------------------
// Commit operations
// ---------------------------------------------------------------------------

/// Returns `true` when every chunk for `file_id` is either stored through this
/// manifest OR is present in a committed manifest visible to `caller`.
///
/// Runs on the reader connection so the deployment's row-level security applies
/// inside `connetto_visible_files`.  The admin role owns the tables and bypasses
/// RLS, so evaluating this on the admin connection silently allows a SECURITY
/// INVOKER function that relies on RLS alone to return every candidate file and
/// accept invisible dedup targets, reopening the original critical hole.
pub(crate) async fn all_chunks_satisfied<S: ConnettoFileSchema>(
    reader_conn: &mut AsyncPgConnection,
    file_id: &FileId,
    caller: &str,
) -> Result<bool, diesel::result::Error> {
    let caller = caller.to_owned();
    let file_id_bytes = file_id.as_bytes().to_vec();
    reader_conn
        .transaction::<bool, diesel::result::Error, _>(|conn| {
            async move {
                // Step 1: collect hashes of chunk rows with stored = FALSE.
                let unstored: Vec<Vec<u8>> = S::all_unstored_chunk_hashes_stmt(file_id_bytes)
                    .load(conn)
                    .await?;
                if unstored.is_empty() {
                    return Ok(true);
                }

                // Step 2: thread caller identity so RLS fires for this transaction.
                diesel::select(functions::set_config("app.user_id", &caller, true))
                    .get_result::<String>(conn)
                    .await?;

                // Steps 3-5: reuse needed.rs's three-step visibility machinery.
                let candidate_ids = needed::committed_file_ids_for::<S>(conn, &unstored).await?;
                if candidate_ids.is_empty() {
                    return Ok(false);
                }
                let visible_ids: Vec<Vec<u8>> =
                    diesel::select(functions::connetto_visible_files(candidate_ids))
                        .get_result(conn)
                        .await?;
                if visible_ids.is_empty() {
                    return Ok(false);
                }
                let present =
                    needed::present_chunk_hashes::<S>(conn, &visible_ids, &unstored).await?;

                // Every unstored hash must be covered by a visible committed manifest.
                for h in &unstored {
                    let arr: [u8; 32] = h.as_slice().try_into().map_err(|_| {
                        diesel::result::Error::DeserializationError(
                            "unstored hash not 32 bytes".into(),
                        )
                    })?;
                    if !present.contains(&arr) {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            .scope_boxed()
        })
        .await
}

/// Locks the registry row for `hash` and returns its state.
pub(crate) async fn lock_registry_state<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    hash: &ChunkHash,
) -> Result<Option<String>, diesel::result::Error> {
    let mut rows: Vec<(Vec<u8>, String)> =
        S::lock_registry_rows_stmt(vec![hash.as_bytes().to_vec()])
            .load(conn)
            .await?;
    Ok(rows.pop().map(|(_, state)| state))
}

/// Atomically marks the manifest committed and calls the deployment setter,
/// all inside one Postgres transaction.
///
/// When the manifest is already committed (zero rows from the guarded UPDATE),
/// returns [`CommitOutcome::AlreadyCommitted`] without re-calling the setter.
///
/// Commit no longer touches the chunk registry: liveness is derived from
/// `manifest_chunks` references and no counter needs incrementing.
pub(crate) async fn commit_manifest_atomic<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    file_id: &FileId,
) -> Result<CommitOutcome, diesel::result::Error> {
    let file_id_bytes = file_id.as_bytes().to_vec();
    // Pre-build the commit statement; the setter argument is a separate
    // owned copy since both are consumed inside the transaction body.
    let commit_stmt = S::mark_manifest_committed_stmt(file_id_bytes.clone());
    let setter_arg = file_id_bytes;

    conn.transaction::<CommitOutcome, CommitTxError, _>(move |c| {
        async move {
            let rows = c.execute_returning_count(commit_stmt).await?;

            if rows == 0 {
                return Ok(CommitOutcome::AlreadyCommitted);
            }

            // Call the deployment setter inside the transaction.  A raise rolls
            // back the committed flag so the client can retry.
            diesel::select(crate::functions::connetto_set_content_state(
                setter_arg.as_slice(),
                "available",
            ))
            .get_result::<Option<Vec<u8>>>(c)
            .await
            .map_err(CommitTxError::Setter)?;

            Ok(CommitOutcome::Committed)
        }
        .scope_boxed()
    })
    .await
    .map_err(|e| match e {
        CommitTxError::Db(e) | CommitTxError::Setter(e) => e,
    })
}

// ---------------------------------------------------------------------------
// Sweep operations
// ---------------------------------------------------------------------------

/// Locks the sweep set, deletes stale manifests, then marks still-unreferenced hashes.
pub(crate) async fn prepare_sweep<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    cutoff: DateTime<Utc>,
) -> Result<usize, diesel::result::Error> {
    conn.transaction::<usize, diesel::result::Error, _>(move |c| {
        async move {
            let candidates = S::lock_sweep_rows_stmt(cutoff).load(c).await?;
            let orphan_ids = S::delete_orphaned_stmt(cutoff).load(c).await?;
            if !candidates.is_empty() {
                S::mark_unreferenced_deleting_stmt(candidates)
                    .load(c)
                    .await?;
            }
            Ok(orphan_ids.len())
        }
        .scope_boxed()
    })
    .await
}

/// Returns all chunk hashes currently in `deleting` state.
///
/// Used by the sweep to resume stranded deletions after a server crash.
pub(crate) async fn list_deleting_hashes<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
) -> Result<Vec<Vec<u8>>, diesel::result::Error> {
    let filtered = FilterDsl::filter(S::ChunkRegistryQuery::default(), S::cr_state_eq_deleting());
    let query = SelectDsl::select(filtered, S::CRColChunkHash::default());
    query.load(conn).await
}

/// Deletes a single registry row after its store object has been removed.
///
/// Call only after the store deletion succeeds.  Leaving the row in place on a
/// store failure is intentional: the next sweep retries.
pub(crate) async fn delete_registry_row<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    hash: &ChunkHash,
) -> Result<(), diesel::result::Error> {
    conn.execute_returning_count(S::delete_registry_row_stmt(hash.as_bytes().to_vec()))
        .await
        .map(|_| ())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Loads chunk rows for `file_id_bytes` ordered by position, then builds a
/// [`Manifest`].
async fn load_chunk_rows<S: ConnettoFileSchema>(
    conn: &mut AsyncPgConnection,
    file_id_bytes: Vec<u8>,
) -> Result<Manifest, diesel::result::Error> {
    use diesel::query_dsl::methods::OrderDsl;
    let filtered = FilterDsl::filter(
        S::ManifestChunksQuery::default(),
        S::mc_file_id_eq(file_id_bytes.clone()),
    );
    let ordered = OrderDsl::order(filtered, S::MCColPosition::default());
    let query = SelectDsl::select(
        ordered,
        (S::MCColChunkHash::default(), S::MCColChunkLen::default()),
    );
    let rows: Vec<(Vec<u8>, i64)> = query.load(conn).await?;
    manifest_from_rows(&file_id_bytes, &rows)
}

fn manifest_from_rows(
    file_id_bytes: &[u8],
    chunks: &[(Vec<u8>, i64)],
) -> Result<Manifest, diesel::result::Error> {
    let file_id_arr: [u8; 32] = file_id_bytes
        .try_into()
        .map_err(|_| diesel::result::Error::DeserializationError("bad file_id length".into()))?;
    let file_id = FileId::from_bytes(file_id_arr);
    let metas: Result<Vec<ChunkMeta>, diesel::result::Error> = chunks
        .iter()
        .map(|(hash_bytes, chunk_len)| {
            let hash_arr: [u8; 32] = hash_bytes.as_slice().try_into().map_err(|_| {
                diesel::result::Error::DeserializationError("bad chunk_hash length".into())
            })?;
            let len = u64::try_from(*chunk_len).map_err(|_| {
                diesel::result::Error::DeserializationError("negative chunk_len".into())
            })?;
            Ok(ChunkMeta {
                hash: ChunkHash::from_bytes(hash_arr),
                len,
            })
        })
        .collect();
    Ok(Manifest::new(file_id, metas?))
}

/// Returns `true` when the declared chunks match the stored manifest exactly.
///
/// Checks count, hash, and length at each position in order.
fn declared_matches_stored(declared: &[ChunkMeta], stored: &[ChunkMeta]) -> bool {
    declared.len() == stored.len()
        && declared
            .iter()
            .zip(stored.iter())
            .all(|(d, s)| d.hash == s.hash && d.len == s.len)
}
