//! Upload handlers: intent declaration, chunk PUT, and commit.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use bytes::Bytes;
use chrono::Utc;
use connetto_file_core::{ChunkHash, ChunkMeta, FileId};
use diesel_async::{AsyncConnection, RunQueryDsl};
use serde::{Deserialize, Serialize};

use crate::{
    caller::{attributions, manifest_key},
    db,
    error::ServerError,
    needed,
    quotas::{self, bandwidth_retry_after_secs},
    router::AppState,
    schema::ConnettoFileSchema,
    store::AnyStore,
    ticket::Verb,
};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Query parameter carrying the signed ticket on every upload endpoint.
#[derive(Deserialize)]
pub(crate) struct TicketQuery {
    /// The signed ticket token.
    pub t: String,
}

/// Body for `POST /files/{id}/intent`.
#[derive(Deserialize)]
pub(crate) struct IntentRequest {
    /// Total byte count; must equal the sum of declared chunk lengths.
    pub total_len: u64,
    /// Ordered list of chunks the upload will provide.
    pub chunks: Vec<ChunkMetaJson>,
}

/// JSON representation of a single chunk in the intent body.
#[derive(Deserialize)]
pub(crate) struct ChunkMetaJson {
    /// Lower-hex BLAKE3 hash of the chunk bytes (64 characters).
    pub hash: String,
    /// Declared byte length of the chunk.
    pub len: u64,
}

/// Response body from `POST /files/{id}/intent`.
#[derive(Serialize)]
pub(crate) struct IntentResponse {
    /// Hex-encoded chunk hashes the caller must upload before committing.
    pub needed: Vec<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Declares the manifest for a new upload and answers which chunks are needed.
///
/// Refuses when:
/// - any declared chunk hash is in `deleting` state (503 retry later)
/// - the chunk count exceeds the ceiling-derived cap (413)
///
/// A re-declaration for the same (`file_id`, `caller`) pair returns 200 with
/// needed hashes computed from the declared chunks.
pub(crate) async fn post_intent<S: ConnettoFileSchema>(
    State(state): State<AppState<S>>,
    Path(id): Path<String>,
    Query(q): Query<TicketQuery>,
    Json(body): Json<IntentRequest>,
) -> Result<(StatusCode, Json<IntentResponse>), ServerError> {
    let ticket = state.verifier.verify_verb(&q.t, Verb::Write)?;
    let file_id = parse_file_id(&id)?;
    check_ids_match(&file_id, &ticket.file_id)?;
    // Cap chunk count to prevent the zero-length-chunk DoS under a zero ceiling.
    // Any ceiling allows at most ceiling+1 chunks (one per byte plus one for empty files).
    // The absolute cap is MEDIA_PARAMS.max / 256 = 65536, matching the 2 MiB body budget.
    // ceiling=0 gives max 1 chunk, preventing 25k zero-length-chunk declarations.
    let max_chunk_count: usize = ticket
        .ceiling
        .saturating_add(1)
        .min(u64::from(connetto_file_core::MEDIA_PARAMS.max) / 256)
        .try_into()
        .map_err(|_| ServerError::BadParam("chunk count cap overflows usize".into()))?;
    if body.chunks.len() > max_chunk_count {
        return Err(ServerError::TooManyChunks);
    }
    let chunks = parse_chunk_metas(&body.chunks)?;
    // Declared chunk lengths must sum to total_len with no overflow.
    let declared_sum: u64 = chunks
        .iter()
        .try_fold(0u64, |acc, c| acc.checked_add(c.len))
        .ok_or_else(|| ServerError::BadParam("chunk length sum overflows u64".into()))?;
    if declared_sum != body.total_len {
        return Err(ServerError::BadParam(
            "total_len must equal sum of declared chunk lengths".into(),
        ));
    }
    // The whole manifest must fit within the signed ceiling.
    if declared_sum > ticket.ceiling {
        return Err(ServerError::CeilingExceeded);
    }
    let total_len = i64::try_from(body.total_len)
        .map_err(|_| ServerError::BadParam("total_len overflows i64".into()))?;
    let key = manifest_key(&state.caller_settings, &ticket.caller)?;
    let mut admin_conn = state.pools.admin.get().await?;
    match db::insert_manifest::<S>(&mut admin_conn, &file_id, total_len, &key, &chunks).await? {
        db::InsertManifestOutcome::RegistryConflict => return Err(ServerError::RegistryConflict),
        db::InsertManifestOutcome::Inserted | db::InsertManifestOutcome::AlreadyPresent => {}
    }
    let mut reader_conn = state.pools.reader.get().await?;
    let needed_hashes = needed::needed_hashes::<S>(
        &mut reader_conn,
        &state.caller_settings,
        &ticket.caller,
        &chunks,
        file_id.as_bytes(),
        &key,
    )
    .await?;
    let needed: Vec<String> = needed_hashes.iter().map(hex_hash).collect();
    Ok((StatusCode::OK, Json(IntentResponse { needed })))
}

/// Stores and accounts one verified chunk while holding its registry row lock.
pub(crate) async fn put_chunk<S: ConnettoFileSchema>(
    State(state): State<AppState<S>>,
    Path(hash_hex): Path<String>,
    Query(q): Query<TicketQuery>,
    body: Bytes,
) -> Result<StatusCode, ServerError> {
    let ticket = state.verifier.verify_verb(&q.t, Verb::Write)?;
    let chunk_hash = parse_chunk_hash(&hash_hex)?;
    let file_id = FileId::from_bytes(ticket.file_id);
    let caller = manifest_key(&state.caller_settings, &ticket.caller)?;
    let body_len = u64::try_from(body.len())
        .map_err(|_| ServerError::BadParam("body length overflows u64".into()))?;
    // A ceiling above i64::MAX cannot be exceeded by any real upload; clamp once
    // here so the database layer receives an i64 and no conversion fails at PUT time.
    let ceiling_i64: i64 = i64::try_from(ticket.ceiling).unwrap_or(i64::MAX);
    verify_blake3(&body, &chunk_hash)?;
    let store = &state.store;
    let mut admin_conn = state.pools.admin.get().await?;

    admin_conn
        .transaction::<StatusCode, ServerError, _>(async move |conn| {
            let registry_state = db::lock_registry_state::<S>(conn, &chunk_hash)
                .await?
                .ok_or(ServerError::NotFound)?;
            if registry_state == "deleting" {
                return Err(ServerError::RegistryConflict);
            }

            let declared_len = db::declared_chunk_len::<S>(conn, &file_id, &caller, &chunk_hash)
                .await?
                .ok_or(ServerError::NotFound)?;
            if body_len != declared_len {
                return Err(ServerError::HashMismatch);
            }

            store.write(&chunk_hash, body).await?;
            match db::account_chunk_put::<S>(
                conn,
                &file_id,
                &caller,
                &chunk_hash,
                declared_len,
                ceiling_i64,
            )
            .await?
            {
                db::ChunkPutResult::WouldExceedCeiling => Err(ServerError::CeilingExceeded),
                db::ChunkPutResult::Accepted | db::ChunkPutResult::AlreadyStored => {
                    // The wire bytes were accepted either way: a retry of a
                    // chunk this upload already stored still moved them.
                    quotas::ledger_add::<S>(conn, 0, body_len).await?;
                    Ok(StatusCode::NO_CONTENT)
                }
            }
        })
        .await
}

/// Verifies declared chunks were supplied by this upload, checks file identity,
/// marks the manifest committed, and calls the state setter atomically.
///
/// Four outcomes by manifest state:
/// - Absent (`file_id`, manifest key) row: 404.
/// - Already committed (sequential retry after a lost response, or a second
///   session staging bytes identical to a file a previous session committed):
///   idempotent 200, with the state setter re-run so metadata rows inserted
///   since the first commit are still flipped.
/// - Uncommitted: verify all chunks are satisfied (stored through this upload OR deduped
///   from a committed manifest visible to the caller), then verify identity, then commit.
///   The caller must have declared the manifest (ownership is implicit in the composite key).
///   A concurrent commit races inside the transaction; the loser returns 200.
pub(crate) async fn post_commit<S: ConnettoFileSchema>(
    State(state): State<AppState<S>>,
    Path(id): Path<String>,
    Query(q): Query<TicketQuery>,
) -> Result<StatusCode, ServerError> {
    let ticket = state.verifier.verify_verb(&q.t, Verb::Write)?;
    let file_id = parse_file_id(&id)?;
    check_ids_match(&file_id, &ticket.file_id)?;
    let key = manifest_key(&state.caller_settings, &ticket.caller)?;
    let attributions: Vec<String> = attributions(&ticket.caller)?
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let store = &state.store;
    let settings = state.caller_settings.clone();
    let ceilings = state.ceilings.clone();
    let quota_settings = state.quotas.clone();
    // Ordering: acquire reader before admin so a saturated reader pool never
    // blocks a holder of the manifest FOR UPDATE lock.
    let mut reader_conn = state.pools.reader.get().await?;
    // Evaluate chunk satisfaction as the reader role so RLS applies inside
    // connetto_visible_files.  The admin role owns the tables and bypasses RLS,
    // so calling this on the admin connection would silently pass for files the
    // caller cannot see when the function relies on RLS rather than an explicit
    // current_setting predicate.
    //
    // The check runs before the manifest lock is taken.  A concurrent visibility
    // change between the check and the commit is acceptable: the same window
    // already exists between the intent answer and this call, and a committed
    // manifest referenced by any chunk row cannot be collected by the sweep
    // while that reference exists, so the deduped bytes are stable.
    if !db::all_chunks_satisfied::<S>(
        &mut reader_conn,
        &state.caller_settings,
        &file_id,
        &ticket.caller,
        &key,
    )
    .await?
    {
        return Err(ServerError::CommitRefused);
    }
    let mut admin_conn = state.pools.admin.get().await?;
    // What this commit would actually add to the deployment's stored
    // bytes: the distinct declared chunks that no committed manifest
    // visible to this caller already carries. The ceiling judges this
    // margin rather than the declared size, so a commit whose bulk
    // deduplicates against committed content still settles whenever its
    // new bytes fit the headroom. The measurement runs on the reader
    // connection because the visibility predicate is the caller's. It
    // can only over-count, a chunk can become committed between this
    // read and the flip but never un-committed, the same conservative
    // direction as the refresh staleness of the cached total it joins.
    // Zero cost when no ceiling is configured.
    let storage_new_bytes: u64 = if quota_settings.storage_ceiling > 0 {
        let pairs = db::manifest_chunk_pairs::<S>(&mut admin_conn, &file_id, &key).await?;
        needed::new_declared_bytes::<S>(
            &mut reader_conn,
            &state.caller_settings,
            &ticket.caller,
            &pairs,
        )
        .await?
    } else {
        0
    };
    admin_conn
        .transaction::<StatusCode, ServerError, _>(async move |conn| {
            let (manifest, declared) =
                match db::load_manifest_locked::<S>(conn, &file_id, &key).await? {
                    // A heal for others deletes the healer's manifest, so its retry finds only the committed file.
                    None if db::file_committed::<S>(conn, &file_id).await? => {
                        return Ok(StatusCode::OK);
                    }
                    None => return Err(ServerError::NotFound),
                    Some(db::ManifestState::Committed) => {
                        // Already committed from a previous call or session: re-run the
                        // setter so metadata rows inserted since the first commit are
                        // updated. The setter is UPDATE ... WHERE content_id = $1 and
                        // is idempotent for rows already at the target state.
                        for attribution in &attributions {
                            diesel::select(crate::functions::connetto_set_content_state(
                                file_id.as_bytes().to_vec().as_slice(),
                                "available",
                                attribution.as_str(),
                            ))
                            .get_result::<Option<Vec<u8>>>(conn)
                            .await?;
                        }
                        return Ok(StatusCode::OK);
                    }
                    Some(db::ManifestState::Uncommitted(manifest)) => {
                        // R87's checks guard new bytes only: an already-committed
                        // manifest made its bytes true earlier and re-committing
                        // it must stay idempotent even if a ceiling or the
                        // uploader's quota filled since.  The deployment numbers
                        // are the cached in-memory totals, so the overshoot they
                        // allow is bounded by the refresh cadence times the
                        // deployment's throughput.
                        let declared: u64 = manifest
                            .chunks()
                            .iter()
                            .fold(0u64, |acc, c| acc.saturating_add(c.len));
                        // A heal is checked too, because the store no longer holds a lost file's bytes.
                        {
                            let totals = ceilings.read().await;
                            check_deployment_ceilings(&totals, &quota_settings, storage_new_bytes)?;
                        }
                        (manifest, declared)
                    }
                };
            verify_file_identity(store, &manifest).await?;
            // The uploader's own quota check takes its advisory lock last,
            // after the store reads above, so verifying a large file never
            // makes that uploader's other commits queue behind disk or
            // object-store latency. The guarantee is unchanged: every
            // committer takes this lock before flipping its manifest, the
            // verification mutates nothing in the database, so the SUM under
            // the lock still sees every flip that happened before it.
            // A healer that is not an original uploader is charged nothing and owns nothing.
            let lost = db::lost_manifest_callers::<S>(conn, &file_id).await?;
            let heals_for_others = !lost.is_empty() && !lost.contains(&key);
            if quota_settings.identity_quota > 0 && !heals_for_others {
                quotas::serialize_uploader(conn, &key).await?;
                let used = quotas::uploader_committed_bytes::<S>(conn, &key).await?;
                if used.saturating_add(declared) > quota_settings.identity_quota {
                    return Err(ServerError::QuotaExceeded);
                }
            }
            let attributions: Vec<&str> = attributions.iter().map(String::as_str).collect();
            db::commit_manifest_atomic::<S>(
                conn,
                &settings,
                &file_id,
                &key,
                &attributions,
                lost,
                manifest.chunks(),
            )
            .await?;
            Ok(StatusCode::OK)
        })
        .await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The metered commit check, taken under the manifest lock. The deployment
/// numbers are the cached totals shared by every replica, so the overshoot
/// they allow is bounded by the refresh cadence times the deployment's
/// throughput.
fn check_deployment_ceilings(
    totals: &crate::quotas::CeilingTotals,
    settings: &crate::quotas::QuotaSettings,
    new_bytes: u64,
) -> Result<(), ServerError> {
    // The storage ceiling projects this file's NEW bytes, so one commit
    // cannot overshoot the ceiling by its whole size while chunks committed
    // by visible files still cost nothing. Committed duplicates the caller
    // cannot see are charged whole, the same conservative direction the
    // per-identity quota takes.
    if settings.storage_ceiling > 0
        && totals.stored_bytes.saturating_add(new_bytes) > settings.storage_ceiling
    {
        // A storage refusal is not self-healing the way the window is. The
        // interval only waits out a refresh and any concurrent deletes, and
        // a deployment full until an operator or a sweeper frees bytes
        // keeps refusing.
        return Err(ServerError::StorageCeiling {
            retry_after_secs: settings.refresh.as_secs().saturating_mul(6).max(1),
        });
    }
    // The bandwidth window needs no projection. Every chunk PUT of this
    // upload already billed its bytes today, so the cached window contains
    // this file.
    if settings.bandwidth_ceiling > 0 && totals.window_bytes >= settings.bandwidth_ceiling {
        return Err(ServerError::BandwidthCeiling {
            retry_after_secs: bandwidth_retry_after_secs(
                totals.oldest_day,
                settings.window_days,
                Utc::now(),
            ),
        });
    }
    Ok(())
}

async fn verify_file_identity(
    store: &AnyStore,
    manifest: &connetto_file_core::Manifest,
) -> Result<(), ServerError> {
    let mut hasher = blake3::Hasher::new();
    for chunk in manifest.chunks() {
        let data = store.read(&chunk.hash).await?;
        let actual_len = u64::try_from(data.len()).map_err(|_| ServerError::CommitRefused)?;
        if actual_len != chunk.len {
            return Err(ServerError::CommitRefused);
        }
        hasher.update(&data);
    }
    let computed: [u8; 32] = *hasher.finalize().as_bytes();
    if computed != *manifest.file_id().as_bytes() {
        return Err(ServerError::CommitRefused);
    }
    Ok(())
}

fn verify_blake3(data: &[u8], expected: &ChunkHash) -> Result<(), ServerError> {
    let computed: [u8; 32] = *blake3::hash(data).as_bytes();
    if computed != *expected.as_bytes() {
        return Err(ServerError::HashMismatch);
    }
    Ok(())
}

fn parse_chunk_metas(items: &[ChunkMetaJson]) -> Result<Vec<ChunkMeta>, ServerError> {
    use std::collections::HashMap;
    let mut seen: HashMap<[u8; 32], u64> = HashMap::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let hash = parse_chunk_hash(&item.hash)?;
        if i64::try_from(item.len).is_err() {
            return Err(ServerError::BadParam(format!(
                "chunk {} length {} overflows i64 (DB column limit)",
                item.hash, item.len
            )));
        }
        match seen.get(hash.as_bytes()) {
            Some(&prev) if prev != item.len => {
                return Err(ServerError::BadParam(format!(
                    "chunk {} declared with conflicting lengths {} and {}",
                    item.hash, prev, item.len
                )));
            }
            Some(_) => {}
            None => {
                seen.insert(*hash.as_bytes(), item.len);
            }
        }
        out.push(ChunkMeta {
            hash,
            len: item.len,
        });
    }
    Ok(out)
}

pub(crate) fn parse_file_id(s: &str) -> Result<FileId, ServerError> {
    let bytes = parse_hex_32(s).ok_or_else(|| ServerError::BadParam("invalid file id".into()))?;
    Ok(FileId::from_bytes(bytes))
}

pub(crate) fn parse_chunk_hash(s: &str) -> Result<ChunkHash, ServerError> {
    let bytes =
        parse_hex_32(s).ok_or_else(|| ServerError::BadParam("invalid chunk hash".into()))?;
    Ok(ChunkHash::from_bytes(bytes))
}

pub(crate) fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn check_ids_match(url_id: &FileId, ticket_id: &[u8; 32]) -> Result<(), ServerError> {
    if url_id.as_bytes() != ticket_id {
        return Err(ServerError::NotFound);
    }
    Ok(())
}

/// Encodes a [`ChunkHash`] as a 64-character lowercase hex string.
pub(crate) fn hex_hash(h: &ChunkHash) -> String {
    crate::hex_32(h.as_bytes())
}

#[cfg(test)]
mod ceiling_tests {
    use super::check_deployment_ceilings;
    use crate::error::ServerError;
    use crate::quotas::{CeilingTotals, QuotaSettings};

    #[test]
    fn the_storage_ceiling_judges_new_bytes_not_declared_bytes() {
        let settings = QuotaSettings {
            storage_ceiling: 12_288,
            ..Default::default()
        };
        let totals = CeilingTotals {
            stored_bytes: 8_192,
            ..Default::default()
        };
        // New bytes exactly filling the headroom pass, one byte more
        // refuses. A commit declared far above the headroom but mostly
        // deduplicated lives or dies on this margin.
        assert!(check_deployment_ceilings(&totals, &settings, 4_096).is_ok());
        assert!(matches!(
            check_deployment_ceilings(&totals, &settings, 4_097),
            Err(ServerError::StorageCeiling { .. })
        ));
    }

    #[test]
    fn the_bandwidth_window_refuses_at_its_ceiling_without_projection() {
        let settings = QuotaSettings {
            bandwidth_ceiling: 8_192,
            ..Default::default()
        };
        let totals = CeilingTotals {
            window_bytes: 8_192,
            ..Default::default()
        };
        // The window needs no projection, this upload's PUTs already
        // billed themselves, so even zero new bytes refuse at the cap.
        assert!(matches!(
            check_deployment_ceilings(&totals, &settings, 0),
            Err(ServerError::BandwidthCeiling { .. })
        ));
    }
}
