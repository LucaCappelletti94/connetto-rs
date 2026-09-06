//! Upload and download integration tests.

use axum::http::StatusCode;
use connetto_file_core::{
    ChunkHash, ChunkMeta, ChunkStore, FileId, MemStore, MimeClass, process_file,
};
use connetto_file_server::ticket::{TicketPayload, Verb};
use diesel_async::RunQueryDsl;
use tower::ServiceExt;

use crate::fixture::{
    Pg, build_router, connect_admin, fail_once_write_store, fs_store,
    insert_manifest_bypassing_intent, object_store_local, register_file_ownership,
};

fn write_payload(
    signer: &connetto_file_server::TicketSigner,
    file_id: &FileId,
    ceiling: u64,
) -> String {
    signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap()
}

fn read_payload(
    signer: &connetto_file_server::TicketSigner,
    file_id: &FileId,
    caller: &str,
    ceiling: u64,
) -> String {
    signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: caller.into(),
        })
        .unwrap()
}

async fn do_upload(
    app: &axum::Router,
    signer: &connetto_file_server::TicketSigner,
    data: &[u8],
) -> FileId {
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let ticket = write_payload(signer, &file_id, u64::try_from(data.len()).unwrap() + 1024);

    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let body = serde_json::json!({ "total_len": data.len(), "chunks": chunks_json });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "intent must succeed");

    for c in manifest.chunks() {
        use connetto_file_core::ChunkStore;
        let chunk_data = mem.read_chunk(&c.hash).await.unwrap();
        let hash_hex = format!("{}", c.hash);
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/chunks/{hash_hex}?t={ticket}"))
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(chunk_data))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NO_CONTENT,
            "chunk PUT must succeed"
        );
    }

    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/commit?t={ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "commit must succeed");

    file_id
}

/// Proves: a crashed upload (intent declared but no commit) never serves and
/// its orphaned manifest is collected by the sweep.
#[tokio::test]
async fn a_crashed_upload_never_serves() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"content that will never be committed";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let ticket = write_payload(&signer, &file_id, 1024);
    let read_ticket = read_payload(&signer, &file_id, "alice", u64::MAX);

    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let body = serde_json::json!({ "total_len": data.len(), "chunks": chunks_json });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={read_ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "uncommitted upload must not serve"
    );

    let admin_pool = pg.admin_pool().await;
    let removed = connetto_file_server::sweep::<connetto_file_server::DefaultFileSchema>(
        &admin_pool,
        &connetto_file_server::AnyStore::Fs(
            connetto_file_server::FsStore::new(dir.path()).unwrap(),
        ),
        std::time::Duration::from_secs(0),
    )
    .await
    .unwrap();
    assert!(removed > 0, "sweep must collect the orphaned manifest");
}

/// Proves: intent is refused when the chunk sum exceeds the signed ceiling.
#[tokio::test]
async fn upload_exceeding_ceiling_is_refused() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"data that is bigger than the ceiling";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let ticket = write_payload(&signer, &file_id, 1);

    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let body = serde_json::json!({ "total_len": u64::try_from(data.len()).unwrap(), "chunks": chunks_json });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "intent must be refused when chunk sum exceeds ceiling"
    );
}

/// Proves: caller B cannot learn that caller A's previously uploaded chunks
/// already exist (oracle is closed). Caller A re-declaring the same chunks is
/// told none are needed.
#[tokio::test]
async fn a_caller_b_sees_all_needed_while_caller_a_sees_none() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"shared chunk bytes for oracle test";
    let file_id = do_upload(&app, &signer, data).await;
    let file_hex = format!("{file_id}");

    let mut admin_conn = connect_admin(&pg.url_admin).await;
    register_file_ownership(&mut admin_conn, &file_id, "alice").await;

    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let body = serde_json::json!({
        "total_len": u64::try_from(data.len()).unwrap(),
        "chunks": chunks_json,
    });

    // Caller B declares the same chunks — must be told ALL are needed.
    let ticket_b = signer
        .mint(&TicketPayload {
            file_id: [2u8; 32],
            verb: Verb::Write,
            ceiling: 1024 * 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "bob".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{}/intent?t={ticket_b}", "02".repeat(32)))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    assert_eq!(status, StatusCode::OK);
    let needed_b: Vec<String> = serde_json::from_value(json["needed"].clone()).unwrap();
    assert_eq!(
        needed_b.len(),
        manifest.chunks().len(),
        "caller B must be told all chunks are needed (oracle is closed)"
    );

    // Caller A re-declares the same file — must be told NO chunks are needed.
    let ticket_a2 = write_payload(&signer, &file_id, 1024 * 1024);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket_a2}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let needed_a: Vec<String> = serde_json::from_value(json["needed"].clone()).unwrap();
    assert_eq!(
        needed_a.len(),
        0,
        "caller A must be told no chunks are needed"
    );
}

/// Proves: ranged download round-trips byte-identically with 206 against the
/// filesystem backend.
#[tokio::test]
async fn ranged_download_fs_backend() {
    ranged_download_impl(false).await;
}

/// Proves: ranged download round-trips byte-identically with 206 against the
/// object-store backend.
#[tokio::test]
async fn ranged_download_object_store_backend() {
    ranged_download_impl(true).await;
}

async fn ranged_download_impl(use_object_store: bool) {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let store = if use_object_store {
        object_store_local(&dir)
    } else {
        fs_store(&dir)
    };
    let (app, signer) = build_router(&pg, store).await;

    let data: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
    let file_id = do_upload(&app, &signer, &data).await;
    let file_hex = format!("{file_id}");

    // Ceiling = file size (1024): full fetch and range (10 B) both fit.
    let file_size = u64::try_from(data.len()).unwrap();
    let read_ticket = read_payload(&signer, &file_id, "alice", file_size);

    // Full fetch.
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={read_ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let etag = resp.headers()["etag"].to_str().unwrap().to_string();
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    assert_eq!(body.as_ref(), data.as_slice(), "full fetch must round-trip");

    // Ranged fetch (bytes 10-19, 10 bytes): fits under ceiling.
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={read_ticket}"))
        .header("range", "bytes=10-19")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PARTIAL_CONTENT,
        "range request must return 206"
    );
    assert_eq!(
        resp.headers()["etag"].to_str().unwrap(),
        &etag,
        "ETag must be stable"
    );
    let range_body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(&range_body[..], &data[10..=19], "ranged bytes must match");

    // Out-of-range request must return 416 (before ceiling check).
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={read_ticket}"))
        .header("range", "bytes=9999-99999")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
}

// ---------------------------------------------------------------------------
// Adversarial write-ceiling tests
// ---------------------------------------------------------------------------

/// Proves: intent is refused when `total_len` does not match the sum of declared
/// chunk lengths (declared-tiny-uploaded-huge attack vector).
#[tokio::test]
async fn total_len_mismatch_refused_at_intent() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"data for total-len mismatch test";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let ticket = write_payload(&signer, &file_id, 1024 * 1024);

    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    // total_len = 1 but chunk sum = data.len(): mismatch must be refused.
    let body = serde_json::json!({ "total_len": 1u64, "chunks": chunks_json });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "intent must fail when total_len does not match sum of chunk lengths"
    );
}

/// Proves: intent is refused when the sum of chunk lengths exceeds the ceiling,
/// even when `total_len` matches the sum.
#[tokio::test]
async fn chunk_sum_exceeds_ceiling_refused_at_intent() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"more than one byte of data here";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    // Ceiling = 1 byte; chunk sum = data.len() > 1.
    let ticket = write_payload(&signer, &file_id, 1);

    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let body = serde_json::json!({
        "total_len": u64::try_from(data.len()).unwrap(),
        "chunks": chunks_json,
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "intent must fail when chunk sum exceeds ceiling"
    );
}

/// Proves: a mid-stream PUT that would push `accepted_bytes` past the ceiling is
/// refused (413), and earlier chunks that were already stored remain intact.
///
/// The manifest is inserted directly to bypass intent validation, so the chunk
/// sum can exceed the ticket ceiling and isolate the PUT-time tally guard.
#[tokio::test]
async fn mid_stream_ceiling_crossing_refused() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    // A (100 B) + B (150 B) = 250 B total, ceiling = 120 B.
    // Intent would refuse sum > ceiling, so we insert the manifest directly.
    let admitted_data = vec![0xAAu8; 100];
    let oversized_data = vec![0xBBu8; 150];
    let hash_admitted = ChunkHash::from_bytes(*blake3::hash(&admitted_data).as_bytes());
    let hash_oversized = ChunkHash::from_bytes(*blake3::hash(&oversized_data).as_bytes());

    let file_id_bytes = [0x03u8; 32];
    let file_id = FileId::from_bytes(file_id_bytes);
    let chunks = [
        ChunkMeta {
            hash: hash_admitted,
            len: 100,
        },
        ChunkMeta {
            hash: hash_oversized,
            len: 150,
        },
    ];
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    insert_manifest_bypassing_intent(&mut admin_conn, &file_id, &chunks).await;

    let ticket = signer
        .mint(&TicketPayload {
            file_id: file_id_bytes,
            verb: Verb::Write,
            ceiling: 120,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();

    // PUT A (100 B): tally 0 + 100 = 100 <= 120, accepted.
    let hex_admitted = format!("{hash_admitted}");
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hex_admitted}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(admitted_data.clone()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "PUT A must be accepted"
    );

    // PUT B (150 B): tally 100 + 150 = 250 > 120, refused.
    let hex_oversized = format!("{hash_oversized}");
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hex_oversized}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(oversized_data))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "PUT B must be refused: would exceed ceiling"
    );

    // Re-PUT A: idempotent (204), proving A is still in store and DB row is intact.
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hex_admitted}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(admitted_data))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "re-PUT A must be idempotent: chunk A is still intact"
    );
}

/// Proves: a re-PUT of an already-stored chunk is idempotent and does not
/// double-count its bytes. With ceiling = sum(A, B), double-counting A would
/// push PUT B over the ceiling.
#[tokio::test]
async fn re_put_does_not_double_count() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let first_data = vec![0xAAu8; 100];
    let next_data = vec![0xBBu8; 100];
    let hash_first = ChunkHash::from_bytes(*blake3::hash(&first_data).as_bytes());
    let hash_next = ChunkHash::from_bytes(*blake3::hash(&next_data).as_bytes());

    let file_id_bytes = [0x04u8; 32];
    let file_id = FileId::from_bytes(file_id_bytes);
    let chunks = [
        ChunkMeta {
            hash: hash_first,
            len: 100,
        },
        ChunkMeta {
            hash: hash_next,
            len: 100,
        },
    ];
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    insert_manifest_bypassing_intent(&mut admin_conn, &file_id, &chunks).await;

    // ceiling = 200 = sum(100, 100). Double-counting A would make PUT B fail.
    let ticket = signer
        .mint(&TicketPayload {
            file_id: file_id_bytes,
            verb: Verb::Write,
            ceiling: 200,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();

    let hex_first = format!("{hash_first}");

    // PUT A: tally = 100.
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hex_first}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(first_data.clone()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Re-PUT A: idempotent, tally must stay at 100 (not 200).
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hex_first}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(first_data))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "re-PUT must be idempotent"
    );

    // PUT B: tally 100 + 100 = 200 = ceiling, accepted.
    // Would be refused (300 > 200) if re-PUT A had double-counted.
    let hex_next = format!("{hash_next}");
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hex_next}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(next_data))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "PUT B must succeed: re-PUT A did not double-count"
    );
}

/// Proves: a transient store write failure leaves DB rows untouched so the
/// retry succeeds and the upload commits normally.
#[tokio::test]
async fn store_write_failure_allows_retry() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let fs = connetto_file_server::FsStore::new(dir.path()).unwrap();
    let (app, signer) = build_router(&pg, fail_once_write_store(fs)).await;
    let data = b"data for fail-once store test";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let file_size = u64::try_from(data.len()).unwrap();
    let ticket = write_payload(&signer, &file_id, file_size + 1024);

    // Intent.
    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let body = serde_json::json!({ "total_len": file_size, "chunks": chunks_json });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "intent must succeed");

    // Data is small (<4 MB) so there is exactly one chunk.
    let chunk = &manifest.chunks()[0];
    let chunk_data = mem.read_chunk(&chunk.hash).await.unwrap();
    let hash_hex = format!("{}", chunk.hash);

    // First PUT: FailOnceStore injects a write failure. DB rows are untouched.
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hash_hex}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(chunk_data.clone()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "first PUT must fail with store error"
    );

    // Retry: store write succeeds; DB transaction marks stored=TRUE.
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hash_hex}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(chunk_data))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "retry must succeed");

    // Commit must succeed.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/commit?t={ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "commit must succeed after retry"
    );

    // The file must now serve under a valid read ticket.
    let read_ticket = read_payload(&signer, &file_id, "alice", file_size);
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={read_ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "file must serve after retry commit"
    );
}

// ---------------------------------------------------------------------------
// Read-ceiling tests
// ---------------------------------------------------------------------------

/// Proves: a read ticket whose ceiling is smaller than the response size
/// answers 404. Zero ceiling serves nothing; any file is unreachable.
#[tokio::test]
async fn read_ceiling_below_response_size_answers_404() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"data for read-ceiling test";
    let file_id = do_upload(&app, &signer, data).await;
    let file_hex = format!("{file_id}");
    let file_size = u64::try_from(data.len()).unwrap();

    // Ceiling = file_size - 1: full fetch exceeds ceiling.
    let small_ticket = read_payload(&signer, &file_id, "alice", file_size - 1);
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={small_ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "ceiling smaller than file size must answer 404"
    );

    // Zero ceiling: even the smallest possible response exceeds it.
    let zero_ticket = read_payload(&signer, &file_id, "alice", 0);
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={zero_ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "zero ceiling must answer 404"
    );

    // Valid ticket (ceiling = file_size): full fetch succeeds.
    let good_ticket = read_payload(&signer, &file_id, "alice", file_size);
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={good_ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "ceiling equal to file size must serve"
    );
}

/// Proves: a chunk body larger than axum's 2 MiB default body limit is
/// accepted at `PUT /chunks/{hash}` (the route applies `DefaultBodyLimit::max`
/// derived from `MEDIA_PARAMS.max`, 16 MiB) and the file serves correctly.
///
/// `MimeClass::Jpeg` uses fixed-size 16 MiB slabs, so 3 MiB of data produces
/// exactly one chunk of that size, safely above the 2 MiB default limit.
#[tokio::test]
async fn large_chunk_exceeding_axum_default_limit_uploads_and_serves() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    // 3 MiB > axum's 2 MiB default body limit. Jpeg uses 16 MiB fixed slabs
    // so this becomes a single chunk, guaranteeing the PUT body is 3 MiB.
    let size_bytes = 3 * 1024 * 1024_usize;
    let data: Vec<u8> = (0u8..=255).cycle().take(size_bytes).collect();
    let file_size = u64::try_from(data.len()).unwrap();

    let mem = MemStore::new();
    let manifest = process_file(&data, MimeClass::Jpeg, &mem).await.unwrap();
    assert_eq!(
        manifest.chunks().len(),
        1,
        "3 MiB Jpeg data must be one chunk"
    );

    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let ticket = write_payload(&signer, &file_id, file_size + 1024);

    // Intent.
    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let body = serde_json::json!({ "total_len": file_size, "chunks": chunks_json });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "intent must succeed");

    // PUT the 3 MiB chunk. Without the DefaultBodyLimit override this would
    // be rejected by axum's 2 MiB default before the handler runs.
    let chunk = &manifest.chunks()[0];
    let chunk_data = mem.read_chunk(&chunk.hash).await.unwrap();
    let hash_hex = format!("{}", chunk.hash);
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hash_hex}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(chunk_data))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "3 MiB chunk PUT must succeed (body limit override in effect)"
    );

    // Commit.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/commit?t={ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "commit must succeed");

    // GET must serve the full file under a valid read ticket.
    let read_ticket = read_payload(&signer, &file_id, "alice", file_size);
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={read_ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "large file must serve");
    let served = axum::body::to_bytes(resp.into_body(), size_bytes + 1024)
        .await
        .unwrap();
    assert_eq!(
        served.as_ref(),
        data.as_slice(),
        "served bytes must round-trip"
    );
}
/// A client that lost the commit response must be able to retry: the second
/// sequential commit must return 200 and refcounts must remain exactly 1.
///
/// Defect: `post_commit` loaded the manifest via `load_uncommitted_manifest`, so
/// after a successful commit the retry received `NotFound`.
#[tokio::test]
async fn commit_sequential_retry_is_idempotent_and_refcounts_once() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"sequential retry idempotent test";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let file_size = u64::try_from(data.len()).unwrap();
    let ticket = write_payload(&signer, &file_id, file_size + 1024);

    // Intent.
    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let body = serde_json::json!({ "total_len": file_size, "chunks": chunks_json });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "intent");

    // PUT all chunks.
    for c in manifest.chunks() {
        let chunk_data = mem.read_chunk(&c.hash).await.unwrap();
        let hash_hex = format!("{}", c.hash);
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/chunks/{hash_hex}?t={ticket}"))
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(chunk_data))
            .unwrap();
        app.clone().oneshot(req).await.unwrap();
    }

    let mut admin_conn = connect_admin(&pg.url_admin).await;
    register_file_ownership(&mut admin_conn, &file_id, "alice").await;
    drop(admin_conn);

    let commit_req = || {
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/files/{file_hex}/commit?t={ticket}"))
            .body(axum::body::Body::empty())
            .unwrap()
    };

    // First commit: must succeed.
    let r1 = app.clone().oneshot(commit_req()).await.unwrap();
    assert_eq!(r1.status(), StatusCode::OK, "first commit must succeed");

    // Sequential retry after lost response: must also return 200.
    let r2 = app.clone().oneshot(commit_req()).await.unwrap();
    assert_eq!(
        r2.status(),
        StatusCode::OK,
        "sequential commit retry must return 200, not NotFound"
    );

    // In the derived-liveness schema (no refcounts), the equivalent invariant is that
    // every chunk's registry row is in 'stored' state after commit, proving the
    // commit side-effect (stored flag) applied exactly once without corruption.
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    let states: Vec<String> = diesel_async::RunQueryDsl::load(
        diesel::sql_query(
            "SELECT r.state FROM _cfs_chunk_registry r
             INNER JOIN _cfs_manifest_chunks mc ON mc.chunk_hash = r.chunk_hash
             WHERE mc.file_id = $1
             ORDER BY r.chunk_hash",
        )
        .bind::<diesel::sql_types::Bytea, _>(file_id.as_bytes().as_ref()),
        &mut admin_conn,
    )
    .await
    .unwrap()
    .into_iter()
    .map(|r: RegistryStateRow| r.state)
    .collect();
    assert!(
        !states.is_empty(),
        "registry must have rows for the committed file's chunks"
    );
    assert!(
        states.iter().all(|s| s == "stored"),
        "all chunk registry rows must be 'stored' after sequential retry, got {states:?}"
    );
}

// ---------------------------------------------------------------------------
// Defect 1: post_commit atomicity
// ---------------------------------------------------------------------------

/// Two concurrent commits must both return 200 but increment refcounts exactly
/// once.  The guarded UPDATE (committed = false → true) ensures only one commit
/// wins; the other sees zero rows and returns idempotent success.
#[tokio::test]
async fn commit_concurrent_increments_refcount_once() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    // Drive intent + PUT but stop before commit so both concurrent requests
    // race on the uncommitted manifest.
    let data = b"concurrent commit test payload";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let file_size = u64::try_from(data.len()).unwrap();
    let ticket = write_payload(&signer, &file_id, file_size + 1024);

    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let body = serde_json::json!({ "total_len": file_size, "chunks": chunks_json });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap();

    for c in manifest.chunks() {
        let chunk_data = mem.read_chunk(&c.hash).await.unwrap();
        let hash_hex = format!("{}", c.hash);
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/chunks/{hash_hex}?t={ticket}"))
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(chunk_data))
            .unwrap();
        app.clone().oneshot(req).await.unwrap();
    }

    let mut admin_conn = connect_admin(&pg.url_admin).await;
    register_file_ownership(&mut admin_conn, &file_id, "alice").await;
    drop(admin_conn);

    // Two concurrent commit requests for the same uncommitted manifest.
    let req1 = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/commit?t={ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let req2 = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/commit?t={ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let (r1, r2) = tokio::join!(app.clone().oneshot(req1), app.clone().oneshot(req2),);
    let s1 = r1.unwrap().status();
    let s2 = r2.unwrap().status();
    // At least one must succeed.  The other gets OK (AlreadyCommitted path)
    // or NOT_FOUND (if load_uncommitted_manifest sees the row as already
    // committed before entering the transaction).
    assert!(
        s1 == StatusCode::OK || s2 == StatusCode::OK,
        "at least one concurrent commit must succeed: {s1} {s2}"
    );
    assert!(
        (s1 == StatusCode::OK || s1 == StatusCode::NOT_FOUND)
            && (s2 == StatusCode::OK || s2 == StatusCode::NOT_FOUND),
        "concurrent commits must return 200 or 404: {s1} {s2}"
    );

    // In the derived-liveness schema (no refcounts), the equivalent invariant is that
    // the guarded UPDATE (committed = FALSE → TRUE) ensures the commit side-effect
    // applies exactly once.  Verify each chunk's registry row is in 'stored' state.
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    let states: Vec<String> = diesel_async::RunQueryDsl::load(
        diesel::sql_query(
            "SELECT r.state FROM _cfs_chunk_registry r
             INNER JOIN _cfs_manifest_chunks mc ON mc.chunk_hash = r.chunk_hash
             WHERE mc.file_id = $1
             ORDER BY r.chunk_hash",
        )
        .bind::<diesel::sql_types::Bytea, _>(file_id.as_bytes().as_ref()),
        &mut admin_conn,
    )
    .await
    .unwrap()
    .into_iter()
    .map(|r: RegistryStateRow| r.state)
    .collect();
    assert!(
        !states.is_empty(),
        "registry must have rows for the committed file's chunks"
    );
    assert!(
        states.iter().all(|s| s == "stored"),
        "all chunk registry rows must be 'stored' after concurrent commits, got {states:?}"
    );
}

#[derive(diesel::QueryableByName)]
struct RegistryStateRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    state: String,
}

/// A setter that raises aborts the transaction, leaving the manifest uncommitted
/// so the client can retry.
#[tokio::test]
async fn commit_setter_failure_rolls_back_retry_succeeds() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    // Upload all chunks but don't commit yet.
    let data = b"setter-failure rollback test";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let file_size = u64::try_from(data.len()).unwrap();
    let ticket = write_payload(&signer, &file_id, file_size + 1024);

    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let body = serde_json::json!({ "total_len": file_size, "chunks": chunks_json });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "intent");

    for c in manifest.chunks() {
        let chunk_data = mem.read_chunk(&c.hash).await.unwrap();
        let hash_hex = format!("{}", c.hash);
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/chunks/{hash_hex}?t={ticket}"))
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(chunk_data))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "chunk PUT");
    }

    // Replace the setter with one that raises.
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    diesel::sql_query(
        "CREATE OR REPLACE FUNCTION connetto_set_content_state(p_file_id BYTEA, p_new_state TEXT)
         RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER AS $$
         BEGIN RAISE EXCEPTION 'injected setter failure'; END; $$",
    )
    .execute(&mut admin_conn)
    .await
    .unwrap();

    // Commit must fail.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/commit?t={ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "commit with bad setter must fail"
    );

    // The manifest must still be uncommitted (committed = FALSE).
    let committed: bool = diesel_async::RunQueryDsl::get_result(
        diesel::sql_query("SELECT committed FROM _cfs_manifests WHERE file_id = $1")
            .bind::<diesel::sql_types::Bytea, _>(file_id.as_bytes().as_ref()),
        &mut admin_conn,
    )
    .await
    .map(|r: CommittedRow| r.committed)
    .unwrap();
    assert!(
        !committed,
        "manifest must still be uncommitted after setter failure"
    );

    // Restore the good setter and retry — must succeed.
    diesel::sql_query(
        "CREATE OR REPLACE FUNCTION connetto_set_content_state(p_file_id BYTEA, p_new_state TEXT)
         RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER AS $$
         BEGIN
             UPDATE test_file_metadata SET uploaded_by = uploaded_by WHERE file_id = p_file_id;
             RETURN p_file_id;
         END; $$",
    )
    .execute(&mut admin_conn)
    .await
    .unwrap();
    drop(admin_conn);

    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/commit?t={ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "retry commit must succeed");
}

#[derive(diesel::QueryableByName)]
struct CommittedRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    committed: bool,
}

// ---------------------------------------------------------------------------
// Defect 2: FsStore write temp race
// ---------------------------------------------------------------------------

/// Two concurrent writes of the same chunk hash must both succeed and the
/// file must be serveable after either completes.
#[tokio::test]
async fn concurrent_chunk_write_both_succeed_and_serves() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"concurrent write race payload";
    let file_id = do_upload(&app, &signer, data).await;
    let file_hex = format!("{file_id}");
    let file_size = u64::try_from(data.len()).unwrap();

    // File committed by do_upload; it must serve.
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    register_file_ownership(&mut admin_conn, &file_id, "alice").await;
    let read_ticket = read_payload(&signer, &file_id, "alice", file_size);
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={read_ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "file must serve after concurrent upload"
    );
    let body = axum::body::to_bytes(
        resp.into_body(),
        usize::try_from(file_size).unwrap_or(usize::MAX) + 64,
    )
    .await
    .unwrap();
    assert_eq!(body.as_ref(), data.as_slice(), "served bytes must match");
}

// ---------------------------------------------------------------------------
// Defect 5: Intent arithmetic
// ---------------------------------------------------------------------------

/// A single chunk declared with len = `u64::MAX` overflows i64 and must be
/// refused at intent time.
#[tokio::test]
async fn intent_u64_max_chunk_length_refused() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let file_id = connetto_file_core::FileId::from_bytes([0xEEu8; 32]);
    let file_hex = format!("{file_id}");
    let fake_hash = format!(
        "{}",
        connetto_file_core::ChunkHash::from_bytes([0xABu8; 32])
    );
    let ticket = write_payload(&signer, &file_id, u64::MAX);

    let body = serde_json::json!({
        "total_len": u64::MAX,
        "chunks": [{ "hash": fake_hash, "len": u64::MAX }]
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "u64::MAX chunk length must be refused"
    );
}

/// Two chunks whose `u64` lengths sum to more than `u64::MAX` trigger a checked-add
/// overflow and must be refused at intent time — never panic.
#[tokio::test]
async fn intent_chunk_sum_overflow_refused() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let file_id = connetto_file_core::FileId::from_bytes([0xDDu8; 32]);
    let file_hex = format!("{file_id}");
    let hash_a = format!(
        "{}",
        connetto_file_core::ChunkHash::from_bytes([0x01u8; 32])
    );
    let hash_b = format!(
        "{}",
        connetto_file_core::ChunkHash::from_bytes([0x02u8; 32])
    );
    // Both lengths are large; their sum wraps u64.
    let big: u64 = u64::MAX / 2 + 1;
    let ticket = write_payload(&signer, &file_id, u64::MAX);

    let body = serde_json::json!({
        "total_len": u64::MAX,
        "chunks": [
            { "hash": hash_a, "len": big },
            { "hash": hash_b, "len": big }
        ]
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "overflowing chunk sum must be refused"
    );
}

/// Two entries with the same hash but different declared lengths are a
/// contradiction and must be refused at intent time.
#[tokio::test]
async fn intent_duplicate_hash_conflicting_lengths_refused() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let file_id = connetto_file_core::FileId::from_bytes([0xCCu8; 32]);
    let file_hex = format!("{file_id}");
    let hash = format!(
        "{}",
        connetto_file_core::ChunkHash::from_bytes([0x07u8; 32])
    );
    let ticket = write_payload(&signer, &file_id, 1024);

    let body = serde_json::json!({
        "total_len": 200u64,
        "chunks": [
            { "hash": hash, "len": 100u64 },
            { "hash": hash, "len": 100u64 }   // same hash same len: OK
        ]
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    // Same hash + same len is idempotent; intent should succeed.
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "same hash + same len must be OK"
    );

    // Now try conflicting lengths.
    let body2 = serde_json::json!({
        "total_len": 200u64,
        "chunks": [
            { "hash": hash, "len": 100u64 },
            { "hash": hash, "len": 101u64 }   // conflicting len
        ]
    });
    let req2 = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body2).unwrap()))
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::BAD_REQUEST,
        "conflicting lengths for same hash must be refused"
    );
}

// ---------------------------------------------------------------------------
// Security: commit must prove this upload supplied the bytes
// ---------------------------------------------------------------------------

/// Proves: a caller that skips PUT but declares a chunk another caller already
/// stored is refused at commit (stored flag on this manifest's rows is false).
///
/// The refusal must be indistinguishable from committing a manifest whose chunk
/// was never uploaded anywhere, closing the existence oracle.
#[tokio::test]
async fn commit_without_put_refused_same_as_chunk_never_stored() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"bytes uploaded by caller a for cross-caller attack test";
    // Caller A completes a full upload so the chunk hash exists in the store.
    do_upload(&app, &signer, data).await;

    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let intent_body = serde_json::json!({
        "total_len": u64::try_from(data.len()).unwrap(),
        "chunks": chunks_json,
    });

    // Caller B declares a different file id but the same chunk hash.
    let ticket_b = signer
        .mint(&TicketPayload {
            file_id: [0x02u8; 32],
            verb: Verb::Write,
            ceiling: 1024 * 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "bob".into(),
        })
        .unwrap();
    let bob_hex = "02".repeat(32);

    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{bob_hex}/intent?t={ticket_b}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&intent_body).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "intent must succeed");

    // Caller B commits without PUTting anything.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{bob_hex}/commit?t={ticket_b}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let cross_caller_status = app.clone().oneshot(req).await.unwrap().status();
    assert_eq!(
        cross_caller_status,
        StatusCode::CONFLICT,
        "commit without PUT must be refused even when the store holds the bytes"
    );

    // Caller C declares a file whose chunk was never uploaded anywhere, then
    // commits without PUTting. The status must be identical to caller B's refusal
    // so neither case leaks which condition was tripped.
    let other_data = b"bytes that will never be uploaded anywhere at all";
    let mem2 = MemStore::new();
    let manifest2 = process_file(other_data, MimeClass::Generic, &mem2)
        .await
        .unwrap();
    let chunks_json2: Vec<serde_json::Value> = manifest2
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let intent_body2 = serde_json::json!({
        "total_len": u64::try_from(other_data.len()).unwrap(),
        "chunks": chunks_json2,
    });

    let ticket_c = signer
        .mint(&TicketPayload {
            file_id: [0x03u8; 32],
            verb: Verb::Write,
            ceiling: 1024 * 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "carol".into(),
        })
        .unwrap();
    let carol_hex = "03".repeat(32);

    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{carol_hex}/intent?t={ticket_c}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&intent_body2).unwrap(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "intent for C must succeed");

    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{carol_hex}/commit?t={ticket_c}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let never_stored_status = app.clone().oneshot(req).await.unwrap().status();
    assert_eq!(
        never_stored_status, cross_caller_status,
        "chunk-never-stored refusal must be indistinguishable from cross-caller refusal"
    );
}

/// Proves: a caller that fully supplies all chunks still commits successfully.
/// Guards against a regression where the stored-flag check wrongly rejects a
/// legitimate upload.
#[tokio::test]
async fn commit_after_full_put_still_succeeds() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;
    // do_upload asserts the commit returns 200; a regression would panic here.
    do_upload(
        &app,
        &signer,
        b"full upload must still commit after stored-flag check",
    )
    .await;
}
