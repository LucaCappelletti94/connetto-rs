//! File download handler.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use bytes::Bytes;
use futures_util::stream;
use thiserror::Error;

use crate::router::AppState;
use crate::schema::ConnettoFileSchema;
use crate::upload::TicketQuery;
use crate::{db, error::ServerError, ticket::Verb, upload::parse_file_id};

/// Downloads a file under a read ticket, with optional `Range` support.
///
/// Response codes:
/// - 200 full fetch
/// - 206 ranged fetch
/// - 404 absent, uncommitted, wrong verb, bad ticket, or response too large
/// - 416 range outside the file
///
/// Every response carries `Content-Length: <bytes_to_serve>` and
/// `Accept-Ranges: bytes`.  For zero-byte files both values are 0 and `bytes`
/// respectively, and no store reads are issued.
///
/// The response body is streamed: headers are sent immediately and chunks are
/// read from the store one at a time as the client drains the body.  A
/// mid-stream store error closes the connection; the client sees an abrupt
/// close without a trailer.
///
/// Per-request ceiling: `ticket.ceiling` must be at least as large as the
/// bytes this specific response will serve.
///
/// Manifest selection: only the committed manifest row for `(file_id,
/// ticket.caller)` is loaded.  Every committed manifest for the same file id
/// carries identical content (BLAKE3 identity is verified at commit), so the
/// caller's own row yields the correct bytes.  The admin connection bypasses
/// RLS, but the `uploaded_by` filter is applied explicitly, so no cross-caller
/// manifest is ever reachable.
pub(crate) async fn get_file<S: ConnettoFileSchema>(
    State(state): State<AppState<S>>,
    Path(id): Path<String>,
    Query(q): Query<TicketQuery>,
    headers: HeaderMap,
) -> Result<Response, ServerError> {
    let ticket = state.verifier.verify_verb(&q.t, Verb::Read)?;
    let file_id = parse_file_id(&id)?;
    if file_id.as_bytes() != &ticket.file_id {
        return Err(ServerError::NotFound);
    }
    let mut admin_conn = state.pools.admin.get().await?;
    let manifest = db::load_committed_manifest::<S>(&mut admin_conn, &file_id, &ticket.caller)
        .await?
        .ok_or(ServerError::NotFound)?;
    let etag = etag_value(&file_id);
    let total: u64 = manifest.chunks().iter().map(|c| c.len).sum();
    let range = parse_range(headers.get(header::RANGE), total)?;
    let bytes_to_serve: u64 = match range {
        None => total,
        Some((lo, hi)) => hi - lo + 1,
    };
    if bytes_to_serve > ticket.ceiling {
        return Err(ServerError::NotFound);
    }

    let status = if range.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };

    // Content-Length and Accept-Ranges are required on every response,
    // including zero-byte files and range responses.
    let mut builder = Response::builder()
        .status(status)
        .header(header::ETAG, &etag)
        .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, bytes_to_serve)
        .header(header::ACCEPT_RANGES, "bytes");
    if let Some((lo, hi)) = range {
        builder = builder.header(header::CONTENT_RANGE, format!("bytes {lo}-{hi}/{total}"));
    }

    // Empty file: body is empty; no store reads needed.
    if total == 0 {
        return builder
            .body(axum::body::Body::empty())
            .map_err(|_| ServerError::NotFound);
    }

    // Non-empty: determine the inclusive byte range and build a streaming body.
    let (lo, hi) = range.unwrap_or((0, total - 1)); // safe: total > 0 checked above
    let chunks: Vec<connetto_file_core::ChunkMeta> = manifest.chunks().to_vec();
    let body_stream = serving_stream(state.clone(), chunks, lo, hi);
    builder
        .body(axum::body::Body::from_stream(body_stream))
        .map_err(|_| ServerError::NotFound)
}

// ---------------------------------------------------------------------------
// Streaming body
// ---------------------------------------------------------------------------

/// Error produced mid-stream while reading a chunk from the store.
#[derive(Debug, Error)]
enum StreamError {
    /// Store read error.
    #[error("store: {0}")]
    Store(#[from] crate::store::StoreError),
}

/// State threaded through the `unfold` stream.
struct ChunkStreamState<S: ConnettoFileSchema> {
    state: AppState<S>,
    chunks: Vec<connetto_file_core::ChunkMeta>,
    lo: u64,
    hi: u64,
    /// Byte offset of the start of `chunks[idx]` within the whole file.
    cursor: u64,
    idx: usize,
}

/// Returns a stream that yields one `Bytes` slice per overlapping chunk.
///
/// Zero-length chunks are skipped.  A store read error terminates the stream.
fn serving_stream<S: ConnettoFileSchema>(
    state: AppState<S>,
    chunks: Vec<connetto_file_core::ChunkMeta>,
    lo: u64,
    hi: u64,
) -> impl stream::Stream<Item = Result<Bytes, StreamError>> + Send + 'static {
    stream::unfold(
        ChunkStreamState {
            state,
            chunks,
            lo,
            hi,
            cursor: 0,
            idx: 0,
        },
        |mut s| async move {
            // Advance past zero-length or pre-range chunks.
            loop {
                if s.idx >= s.chunks.len() {
                    return None;
                }
                let c = &s.chunks[s.idx];
                if c.len == 0 {
                    s.idx += 1;
                    continue;
                }
                // Chunk covers [cursor, cursor + len - 1]; safe because len > 0.
                let chunk_end = s.cursor + c.len - 1;
                if chunk_end < s.lo {
                    s.cursor += c.len;
                    s.idx += 1;
                    continue;
                }
                if s.cursor > s.hi {
                    return None;
                }
                break;
            }

            let chunk = s.chunks[s.idx].clone();
            let chunk_start = s.cursor;
            s.cursor += chunk.len;
            s.idx += 1;

            let data = match s.state.store.read(&chunk.hash).await {
                Ok(d) => d,
                Err(e) => return Some((Err(StreamError::Store(e)), s)),
            };

            // Defence against a truncated object or a third-party backend under-delivering.
            let fetched = u64::try_from(data.len()).unwrap_or(u64::MAX);
            if fetched != chunk.len {
                let e = std::io::Error::other("store returned wrong byte count for chunk");
                return Some((Err(StreamError::Store(crate::store::StoreError::Io(e))), s));
            }

            // Compute the slice within this chunk that falls inside [lo, hi].
            let slice_lo = s.lo.saturating_sub(chunk_start);
            // hi >= chunk_start is guaranteed by the loop above.
            let slice_hi = (s.hi - chunk_start).min(chunk.len - 1);

            // slice_lo and slice_hi are bounded by chunk.len which equals data.len().
            let lo_usize = usize::try_from(slice_lo).unwrap_or(0);
            let hi_usize = usize::try_from(slice_hi).unwrap_or(data.len().saturating_sub(1));

            Some((Ok(data.slice(lo_usize..=hi_usize)), s))
        },
    )
}

// ---------------------------------------------------------------------------
// Range helpers
// ---------------------------------------------------------------------------

/// An inclusive byte range, or `None` for the full file.
type ByteRange = Option<(u64, u64)>;

fn parse_range(
    hdr: Option<&axum::http::HeaderValue>,
    total: u64,
) -> Result<ByteRange, ServerError> {
    let Some(val) = hdr else { return Ok(None) };
    let s = val.to_str().unwrap_or("");
    let s = s.strip_prefix("bytes=").unwrap_or("");
    let (lo_s, hi_s) = s.split_once('-').ok_or(ServerError::RangeNotSatisfiable)?;
    if lo_s.trim().is_empty() {
        // Suffix range bytes=-N: the last N bytes of the representation.
        let n: u64 = hi_s
            .trim()
            .parse()
            .map_err(|_| ServerError::RangeNotSatisfiable)?;
        if total == 0 || n == 0 {
            return Err(ServerError::RangeNotSatisfiable);
        }
        return Ok(Some((total.saturating_sub(n), total - 1)));
    }
    let lo: u64 = lo_s
        .trim()
        .parse()
        .map_err(|_| ServerError::RangeNotSatisfiable)?;
    // Empty file: any range is unsatisfiable.
    if total == 0 || lo >= total {
        return Err(ServerError::RangeNotSatisfiable);
    }
    // RFC 7233 s2.1: clip the stated end rather than refusing when it exceeds the file.
    let hi: u64 = if hi_s.trim().is_empty() {
        total - 1
    } else {
        hi_s.trim()
            .parse::<u64>()
            .map_err(|_| ServerError::RangeNotSatisfiable)?
            .min(total - 1)
    };
    if lo > hi {
        return Err(ServerError::RangeNotSatisfiable);
    }
    Ok(Some((lo, hi)))
}

fn etag_value(file_id: &connetto_file_core::FileId) -> String {
    let hex: String = file_id
        .as_bytes()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        });
    format!("\"{hex}\"")
}
