//! Upload handlers: intent declaration, chunk PUT, and commit.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use bytes::Bytes;
use connetto_file_core::{ChunkHash, ChunkMeta, FileId};
use diesel_async::{AsyncConnection, scoped_futures::ScopedFutureExt};
use serde::{Deserialize, Serialize};

use crate::{
    db, error::ServerError, needed, router::AppState, schema::ConnettoFileSchema, store::AnyStore,
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
/// - any declared chunk hash is in `deleting` state (509 retry later)
/// - a re-declaration for the same file id does not match the stored manifest (409)
/// - the chunk count exceeds the ceiling-derived cap (413)
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
    let mut admin_conn = state.pools.admin.get().await?;
    match db::insert_manifest::<S>(
        &mut admin_conn,
        &file_id,
        total_len,
        &ticket.caller,
        &chunks,
    )
    .await?
    {
        db::InsertManifestOutcome::RegistryConflict => return Err(ServerError::RegistryConflict),
        db::InsertManifestOutcome::ManifestConflict => return Err(ServerError::ManifestConflict),
        db::InsertManifestOutcome::Inserted | db::InsertManifestOutcome::AlreadyPresent => {}
    }
    let mut reader_conn = state.pools.reader.get().await?;
    let needed_hashes =
        needed::needed_hashes::<S>(&mut reader_conn, &ticket.caller, &chunks).await?;
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
    let body_len = u64::try_from(body.len())
        .map_err(|_| ServerError::BadParam("body length overflows u64".into()))?;
    verify_blake3(&body, &chunk_hash)?;
    let store = &state.store;
    let mut admin_conn = state.pools.admin.get().await?;

    admin_conn
        .transaction::<StatusCode, ServerError, _>(move |conn| {
            async move {
                let registry_state = db::lock_registry_state::<S>(conn, &chunk_hash)
                    .await?
                    .ok_or(ServerError::NotFound)?;
                if registry_state == "deleting" {
                    return Err(ServerError::RegistryConflict);
                }

                let declared_len = db::declared_chunk_len::<S>(conn, &file_id, &chunk_hash)
                    .await?
                    .ok_or(ServerError::NotFound)?;
                if body_len != declared_len {
                    return Err(ServerError::HashMismatch);
                }

                store.write(&chunk_hash, body).await?;
                match db::account_chunk_put::<S>(
                    conn,
                    &file_id,
                    &chunk_hash,
                    declared_len,
                    ticket.ceiling,
                )
                .await?
                {
                    db::ChunkPutResult::WouldExceedCeiling => Err(ServerError::CeilingExceeded),
                    db::ChunkPutResult::Accepted | db::ChunkPutResult::AlreadyStored => {
                        Ok(StatusCode::NO_CONTENT)
                    }
                }
            }
            .scope_boxed()
        })
        .await
}

/// Verifies declared chunks were supplied by this upload, checks file identity,
/// marks the manifest committed, and calls the state setter atomically.
///
/// Three outcomes by manifest state:
/// - Absent file id: 404.
/// - Already committed (sequential retry after a lost response): idempotent 200.
/// - Uncommitted: verify all chunks are satisfied (stored through this upload OR deduped
///   from a committed manifest visible to the caller), verify identity, commit, return 200.
///   A concurrent commit races inside the transaction; the loser returns 200.
pub(crate) async fn post_commit<S: ConnettoFileSchema>(
    State(state): State<AppState<S>>,
    Path(id): Path<String>,
    Query(q): Query<TicketQuery>,
) -> Result<StatusCode, ServerError> {
    let ticket = state.verifier.verify_verb(&q.t, Verb::Write)?;
    let file_id = parse_file_id(&id)?;
    check_ids_match(&file_id, &ticket.file_id)?;
    if state.content_state_fn != "connetto_set_content_state" {
        return Err(ServerError::BadParam(format!(
            "content_state_fn must be 'connetto_set_content_state', got '{}'",
            state.content_state_fn
        )));
    }
    let caller = ticket.caller;
    let store = &state.store;
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
    if !db::all_chunks_satisfied::<S>(&mut reader_conn, &file_id, &caller).await? {
        return Err(ServerError::CommitRefused);
    }
    let mut admin_conn = state.pools.admin.get().await?;
    admin_conn
        .transaction::<StatusCode, ServerError, _>(move |conn| {
            async move {
                let manifest = match db::load_manifest_locked::<S>(conn, &file_id).await? {
                    None => return Err(ServerError::NotFound),
                    Some(db::ManifestState::Committed) => return Ok(StatusCode::OK),
                    Some(db::ManifestState::Uncommitted(manifest)) => manifest,
                };
                verify_file_identity(store, &manifest).await?;
                db::commit_manifest_atomic::<S>(conn, &file_id).await?;
                Ok(StatusCode::OK)
            }
            .scope_boxed()
        })
        .await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn verify_file_identity(
    store: &AnyStore,
    manifest: &connetto_file_core::Manifest,
) -> Result<(), ServerError> {
    let mut hasher = blake3::Hasher::new();
    for chunk in manifest.chunks() {
        let data = store.read(&chunk.hash).await?;
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

fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
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

pub(crate) fn hex_hash(h: &ChunkHash) -> String {
    h.as_bytes()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}
