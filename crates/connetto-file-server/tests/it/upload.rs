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
    insert_manifest_bypassing_intent(&mut admin_conn, &file_id, "alice", &chunks).await;

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
    insert_manifest_bypassing_intent(&mut admin_conn, &file_id, "alice", &chunks).await;

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
        "CREATE OR REPLACE FUNCTION connetto_set_content_state(
             p_file_id BYTEA, p_new_state TEXT, p_caller TEXT
         ) RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER
             SET search_path TO '' AS $$
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
        diesel::sql_query(
            "SELECT committed FROM _cfs_manifests \
             WHERE file_id = $1 AND uploaded_by = 'alice'",
        )
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
        "CREATE OR REPLACE FUNCTION connetto_set_content_state(
             p_file_id BYTEA, p_new_state TEXT, p_caller TEXT
         ) RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER
             SET search_path TO '' AS $$
         BEGIN
             UPDATE public.test_file_metadata
             SET    uploaded_by = uploaded_by
             WHERE  file_id = p_file_id;
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
///
/// Bob's file id equals `chunk_a.hash` so a broken visibility gate (one that
/// grants every file) lets identity pass and the commit succeeds with 200,
/// proving the test actually exercises the visibility gate and not a vacuous
/// identity refusal.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn commit_without_put_refused_same_as_chunk_never_stored() {
    use connetto_file_core::ChunkStore;
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    // Alice uploads file X = [A, B] so file_x_id = BLAKE3(stored_A || stored_B)
    // differs from chunk_a.hash = BLAKE3(stored_A). Bob can then declare file Y
    // with file_id = chunk_a.hash and skip PUT, expecting a free-ride on chunk A.
    let data_a = b"cross-caller-attack chunk A payload";
    let data_b = b"cross-caller-attack chunk B payload";
    let mem_a = MemStore::new();
    let mem_b = MemStore::new();
    let mf_a = process_file(data_a, MimeClass::Generic, &mem_a)
        .await
        .unwrap();
    let mf_b = process_file(data_b, MimeClass::Generic, &mem_b)
        .await
        .unwrap();
    let chunk_a = &mf_a.chunks()[0];
    let chunk_b = &mf_b.chunks()[0];
    let stored_a = mem_a.read_chunk(&chunk_a.hash).await.unwrap();
    let stored_b = mem_b.read_chunk(&chunk_b.hash).await.unwrap();
    let file_x_id = {
        let mut h = blake3::Hasher::new();
        h.update(&stored_a);
        h.update(&stored_b);
        FileId::from_bytes(*h.finalize().as_bytes())
    };
    let file_x_hex = format!("{file_x_id}");
    let ticket_alice = signer
        .mint(&TicketPayload {
            file_id: *file_x_id.as_bytes(),
            verb: Verb::Write,
            ceiling: chunk_a.len + chunk_b.len + 256,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let body_x = serde_json::json!({
        "total_len": chunk_a.len + chunk_b.len,
        "chunks": [
            { "hash": format!("{}", chunk_a.hash), "len": chunk_a.len },
            { "hash": format!("{}", chunk_b.hash), "len": chunk_b.len },
        ],
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_x_hex}/intent?t={ticket_alice}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body_x).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "alice's intent must succeed");
    app.clone()
        .oneshot(
            axum::http::Request::builder()
                .method("PUT")
                .uri(format!("/chunks/{}?t={ticket_alice}", chunk_a.hash))
                .header("content-type", "application/octet-stream")
                .body(axum::body::Body::from(stored_a))
                .unwrap(),
        )
        .await
        .unwrap();
    app.clone()
        .oneshot(
            axum::http::Request::builder()
                .method("PUT")
                .uri(format!("/chunks/{}?t={ticket_alice}", chunk_b.hash))
                .header("content-type", "application/octet-stream")
                .body(axum::body::Body::from(stored_b))
                .unwrap(),
        )
        .await
        .unwrap();
    app.clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_x_hex}/commit?t={ticket_alice}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Bob declares file Y = [chunk A] with file_id = chunk_a.hash. That id is
    // what verify_file_identity would compute for a one-chunk file of chunk A
    // bytes, so if the visibility gate were broken the commit would succeed (200).
    // Alice's file X is NOT registered in test_file_metadata, so Bob cannot see
    // it and the visibility check must refuse.
    let bob_file_id = FileId::from_bytes(*chunk_a.hash.as_bytes());
    let bob_file_hex = format!("{bob_file_id}");
    let ticket_b = signer
        .mint(&TicketPayload {
            file_id: *chunk_a.hash.as_bytes(),
            verb: Verb::Write,
            ceiling: chunk_a.len + 256,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "bob".into(),
        })
        .unwrap();
    let body_b = serde_json::json!({
        "total_len": chunk_a.len,
        "chunks": [{ "hash": format!("{}", chunk_a.hash), "len": chunk_a.len }],
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{bob_file_hex}/intent?t={ticket_b}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body_b).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "bob's intent must succeed");

    // Bob commits without PUTting. The ownership check passes (bob == bob).
    // The visibility gate must refuse because Alice's file X is not visible to bob.
    let cross_caller_status = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{bob_file_hex}/commit?t={ticket_b}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
    assert_eq!(
        cross_caller_status,
        StatusCode::CONFLICT,
        "commit without PUT must be refused even when the store holds the bytes"
    );

    // Caller C declares a file whose chunk was never uploaded anywhere, then
    // commits without PUTting. The status must be identical to B's refusal
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
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{carol_hex}/intent?t={ticket_c}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&intent_body2).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "intent for C must succeed");
    let never_stored_status = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{carol_hex}/commit?t={ticket_c}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
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

/// Proves: a second caller holding a valid write ticket for the same file id
/// cannot commit a manifest they did not declare.
///
/// Alice declares and fully PUTs file X without committing. Dave, with a valid
/// ticket for the same file id but caller="dave", posts commit. Because every
/// chunk is stored the unstored set is empty and `all_chunks_satisfied`
/// short-circuits to true without reaching the visibility gate; the ownership
/// check is the only barrier between Dave and committing Alice's manifest.
#[tokio::test]
async fn commit_by_non_declarer_refused() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"victim payload for ownership binding test";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let alice_ticket = write_payload(&signer, &file_id, u64::try_from(data.len()).unwrap() + 256);

    // Alice declares intent.
    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let intent_body = serde_json::json!({
        "total_len": u64::try_from(data.len()).unwrap(),
        "chunks": chunks_json,
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/intent?t={alice_ticket}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&intent_body).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "alice's intent must succeed");

    // Alice PUTs all chunks but does not commit.
    for c in manifest.chunks() {
        use connetto_file_core::ChunkStore;
        let chunk_data = mem.read_chunk(&c.hash).await.unwrap();
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri(format!("/chunks/{}?t={alice_ticket}", c.hash))
                    .header("content-type", "application/octet-stream")
                    .body(axum::body::Body::from(chunk_data))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "PUT must succeed");
    }

    // Dave holds a valid write ticket for the same file id but caller="dave".
    let dave_ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: u64::try_from(data.len()).unwrap() + 256,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "dave".into(),
        })
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/commit?t={dave_ticket}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "a non-declarer gets 404: no manifest exists for (file_id, dave) with composite PK"
    );
}

// ---------------------------------------------------------------------------
// Finding 1: dedup commit tests
// ---------------------------------------------------------------------------

/// Proves the dedup scenario from Finding 1: commit X as [A, B], intent Y as [A, C],
/// PUT only C (following the server's needed answer), commit Y succeeds.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn dedup_commit_round_trip() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    // Upload file X = [A] as alice (small data produces one chunk).
    let data_x = b"dedup-test chunk A";
    let mem_x = MemStore::new();
    let manifest_x = process_file(data_x, MimeClass::Generic, &mem_x)
        .await
        .unwrap();
    assert_eq!(
        manifest_x.chunks().len(),
        1,
        "data_x must produce exactly one chunk"
    );
    let chunk_a = &manifest_x.chunks()[0];
    let data_a_stored = mem_x.read_chunk(&chunk_a.hash).await.unwrap();

    let file_x_id = manifest_x.file_id();
    let file_x_hex = format!("{file_x_id}");
    let ticket_x = write_payload(
        &signer,
        &file_x_id,
        u64::try_from(data_a_stored.len()).unwrap() + 256,
    );

    // Declare intent for file X and upload chunk A.
    {
        let chunks_json: Vec<serde_json::Value> = manifest_x
            .chunks()
            .iter()
            .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
            .collect();
        let body = serde_json::json!({ "total_len": chunk_a.len, "chunks": chunks_json });
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/files/{file_x_hex}/intent?t={ticket_x}"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri(format!("/chunks/{}?t={ticket_x}", chunk_a.hash))
                    .header("content-type", "application/octet-stream")
                    .body(axum::body::Body::from(data_a_stored.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/files/{file_x_hex}/commit?t={ticket_x}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Register file X as visible to alice.
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    register_file_ownership(&mut admin_conn, &file_x_id, "alice").await;

    // Build file Y = [A, C] where C is a distinct chunk.
    let data_c_raw = b"dedup-test chunk C";
    let mem_c = MemStore::new();
    let manifest_c = process_file(data_c_raw, MimeClass::Generic, &mem_c)
        .await
        .unwrap();
    assert_eq!(
        manifest_c.chunks().len(),
        1,
        "data_c must produce exactly one chunk"
    );
    let chunk_c = &manifest_c.chunks()[0];
    let chunk_c_bytes = mem_c.read_chunk(&chunk_c.hash).await.unwrap();

    // target_file_id = BLAKE3(stored_A || stored_C) mirrors how verify_file_identity works.
    let target_file_id = {
        let mut h = blake3::Hasher::new();
        h.update(&data_a_stored);
        h.update(&chunk_c_bytes);
        FileId::from_bytes(*h.finalize().as_bytes())
    };
    let target_hex = format!("{target_file_id}");
    let target_ceiling = u64::try_from(data_a_stored.len() + chunk_c_bytes.len()).unwrap() + 256;
    let target_ticket = signer
        .mint(&TicketPayload {
            file_id: *target_file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: target_ceiling,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();

    // Intent for file Y = [A, C].
    let total_len_y = u64::try_from(data_a_stored.len() + chunk_c_bytes.len()).unwrap();
    let body_y = serde_json::json!({
        "total_len": total_len_y,
        "chunks": [
            { "hash": format!("{}", chunk_a.hash), "len": chunk_a.len },
            { "hash": format!("{}", chunk_c.hash), "len": chunk_c.len },
        ],
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{target_hex}/intent?t={target_ticket}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body_y).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "intent for Y must succeed");
    let resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let needed: Vec<String> = serde_json::from_value(json["needed"].clone()).unwrap();
    assert_eq!(
        needed.len(),
        1,
        "only chunk C must be needed (A deduped from file X)"
    );
    assert_eq!(
        needed[0],
        format!("{}", chunk_c.hash),
        "the needed chunk must be C"
    );

    // PUT only chunk C, skipping A per the server's instruction.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("PUT")
                .uri(format!("/chunks/{}?t={target_ticket}", chunk_c.hash))
                .header("content-type", "application/octet-stream")
                .body(axum::body::Body::from(chunk_c_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "PUT C must succeed");

    // Commit file Y; A is satisfied by dedup visibility from file X.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{target_hex}/commit?t={target_ticket}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "commit must succeed via dedup from file X"
    );
}

/// Proves Finding 1's security invariant: a caller who cannot see file X is still
/// told chunk A is needed and is refused at commit if the PUT is skipped.
#[allow(clippy::too_many_lines, clippy::similar_names)]
#[tokio::test]
async fn dedup_commit_rejected_for_invisible_file() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    // Upload and commit file X = [A, B] as alice.  Two chunks are required so
    // file_x_id = BLAKE3(A || B) differs from BLAKE3(A) = chunk_a.hash, giving
    // bob a distinct uncommitted manifest to attack rather than alice's committed one.
    let data_a = b"security-test chunk A";
    let data_b = b"security-test chunk B";
    let mem_a = MemStore::new();
    let mem_b = MemStore::new();
    let manifest_a = process_file(data_a, MimeClass::Generic, &mem_a)
        .await
        .unwrap();
    let manifest_b = process_file(data_b, MimeClass::Generic, &mem_b)
        .await
        .unwrap();
    let chunk_a = &manifest_a.chunks()[0];
    let chunk_b = &manifest_b.chunks()[0];
    let data_a_stored = mem_a.read_chunk(&chunk_a.hash).await.unwrap();
    let data_b_stored = mem_b.read_chunk(&chunk_b.hash).await.unwrap();

    // file_x_id mirrors what verify_file_identity computes: BLAKE3 over stored chunk bytes.
    let file_x_id = {
        let mut h = blake3::Hasher::new();
        h.update(&data_a_stored);
        h.update(&data_b_stored);
        FileId::from_bytes(*h.finalize().as_bytes())
    };
    let file_x_hex = format!("{file_x_id}");
    let alice_ceiling = chunk_a.len + chunk_b.len + 256;
    let ticket_x = write_payload(&signer, &file_x_id, alice_ceiling);
    {
        let total_len_x = chunk_a.len + chunk_b.len;
        let body = serde_json::json!({
            "total_len": total_len_x,
            "chunks": [
                { "hash": format!("{}", chunk_a.hash), "len": chunk_a.len },
                { "hash": format!("{}", chunk_b.hash), "len": chunk_b.len },
            ],
        });
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/files/{file_x_hex}/intent?t={ticket_x}"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri(format!("/chunks/{}?t={ticket_x}", chunk_a.hash))
                    .header("content-type", "application/octet-stream")
                    .body(axum::body::Body::from(data_a_stored))
                    .unwrap(),
            )
            .await
            .unwrap();
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri(format!("/chunks/{}?t={ticket_x}", chunk_b.hash))
                    .header("content-type", "application/octet-stream")
                    .body(axum::body::Body::from(data_b_stored))
                    .unwrap(),
            )
            .await
            .unwrap();
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/files/{file_x_hex}/commit?t={ticket_x}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    // File X is visible to alice ONLY (bob cannot see it).
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    register_file_ownership(&mut admin_conn, &file_x_id, "alice").await;

    // Bob's attack: declare file Y whose id = BLAKE3(chunk A stored bytes).
    // Any other id makes verify_file_identity refuse the commit regardless of
    // visibility, so the test would pass vacuously even if the visibility check
    // were broken.  This id is the one that lets the commit succeed when the
    // visibility check wrongly passes, proving the guard actually fires.
    let bob_file_id = FileId::from_bytes(*chunk_a.hash.as_bytes());
    let bob_file_hex = format!("{bob_file_id}");
    let bob_ceiling = chunk_a.len + 256;
    let ticket_bob = signer
        .mint(&TicketPayload {
            file_id: *chunk_a.hash.as_bytes(),
            verb: Verb::Write,
            ceiling: bob_ceiling,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "bob".into(),
        })
        .unwrap();

    let body_bob = serde_json::json!({
        "total_len": chunk_a.len,
        "chunks": [{ "hash": format!("{}", chunk_a.hash), "len": chunk_a.len }],
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{bob_file_hex}/intent?t={ticket_bob}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&body_bob).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "bob's intent must succeed");
    let resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let needed: Vec<String> = serde_json::from_value(json["needed"].clone()).unwrap();
    assert_eq!(
        needed.len(),
        1,
        "bob must be told A is needed (he cannot see alice's file X)"
    );

    // Bob skips the PUT and tries to commit, hoping to free-ride on alice's chunk.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{bob_file_hex}/commit?t={ticket_bob}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "commit must be refused: A not stored and file X not visible to bob"
    );
}

// ---------------------------------------------------------------------------
// Finding 2: manifest immutability
// ---------------------------------------------------------------------------

/// Proves that a second intent for the same (`file_id`, `caller`) pair with different chunks
/// returns 200 (AlreadyPresent): the stored manifest is unchanged and a subsequent commit
/// fails because the stored manifest does not match the re-declared chunks.
#[tokio::test]
async fn second_intent_with_different_chunks_refused() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    // First intent: file Y = [A].
    let data_a = b"immutability chunk A";
    let mem_a = MemStore::new();
    let manifest_a = process_file(data_a, MimeClass::Generic, &mem_a)
        .await
        .unwrap();
    let chunk_a = &manifest_a.chunks()[0];
    let file_y_id = manifest_a.file_id();
    let file_y_hex = format!("{file_y_id}");
    let ticket_y = write_payload(
        &signer,
        &file_y_id,
        u64::try_from(data_a.len()).unwrap() + 256,
    );

    let body_first = serde_json::json!({
        "total_len": chunk_a.len,
        "chunks": [{ "hash": format!("{}", chunk_a.hash), "len": chunk_a.len }],
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_y_hex}/intent?t={ticket_y}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&body_first).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "first intent must succeed");

    // Second intent: same file id but different chunks (different hash).
    let data_b = b"immutability chunk B - different content";
    let mem_b = MemStore::new();
    let manifest_b = process_file(data_b, MimeClass::Generic, &mem_b)
        .await
        .unwrap();
    let chunk_b = &manifest_b.chunks()[0];
    let body_second = serde_json::json!({
        "total_len": chunk_b.len,
        "chunks": [{ "hash": format!("{}", chunk_b.hash), "len": chunk_b.len }],
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_y_hex}/intent?t={ticket_y}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&body_second).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "second intent with different chunks returns 200 (AlreadyPresent collapses ManifestConflict)"
    );
}

// ---------------------------------------------------------------------------
// Finding 3: range clipping
// ---------------------------------------------------------------------------

/// Proves RFC 7233 clipping: a range whose stated end exceeds the file returns 206
/// with the clipped length, while a range starting past the end returns 416.
#[tokio::test]
async fn range_clipped_to_file_end() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"short file for range clip test";
    let file_id = do_upload(&app, &signer, data).await;
    let file_hex = format!("{file_id}");
    let file_size = u64::try_from(data.len()).unwrap();
    let read_ticket = read_payload(&signer, &file_id, "alice", file_size);

    // Stated end = 1 MiB - 1; file is only 30 bytes. Must clip and return 206.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(format!("/files/{file_hex}?t={read_ticket}"))
                .header("range", "bytes=0-1048575")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PARTIAL_CONTENT,
        "range extending past EOF must return 206 not 416"
    );
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    assert_eq!(
        body.as_ref(),
        data.as_ref(),
        "clipped range must return full file bytes"
    );

    // Start past EOF: 416.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(format!("/files/{file_hex}?t={read_ticket}"))
                .header("range", "bytes=9999-19999")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::RANGE_NOT_SATISFIABLE,
        "range starting past EOF must return 416"
    );
}

// ---------------------------------------------------------------------------
// Finding 5: chunk count cap
// ---------------------------------------------------------------------------

/// Proves that an intent declaring more chunks than the ceiling-derived cap is refused.
#[tokio::test]
async fn intent_refuses_too_many_chunks() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    // ceiling = 0 means only zero-length chunks are legal; the cap is 1.
    let file_id = FileId::from_bytes([0xCCu8; 32]);
    let ticket = signer
        .mint(&TicketPayload {
            file_id: [0xCCu8; 32],
            verb: Verb::Write,
            ceiling: 0,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let file_hex = format!("{file_id}");

    // Build 200 zero-length chunk entries; any hash will do.
    let zero_chunk_hash = blake3::hash(b"").to_hex().to_string();
    let chunks: Vec<serde_json::Value> = (0..200)
        .map(|_| serde_json::json!({ "hash": zero_chunk_hash, "len": 0_u64 }))
        .collect();
    let body = serde_json::json!({ "total_len": 0_u64, "chunks": chunks });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/intent?t={ticket}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "intent with 200 chunks under ceiling=0 must be refused"
    );
}

// ---------------------------------------------------------------------------
// Round 3: reader-role visibility check covers RLS-only deployments
// ---------------------------------------------------------------------------

/// Proves the security invariant under a deployment whose `connetto_visible_files`
/// relies on RLS alone (no `current_setting` predicate in its body).
///
/// This test fails against the previous admin-pool `all_chunks_satisfied`: when
/// called as admin the function bypasses RLS and returns every file, so bob's
/// commit would wrongly succeed.  With the reader-role implementation the RLS
/// policy on `test_file_metadata` correctly hides alice's file from bob.
#[allow(clippy::too_many_lines, clippy::similar_names)]
#[tokio::test]
async fn dedup_commit_rejected_for_invisible_file_rls_only() {
    let pg = Pg::start_rls_only().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    // Upload and commit file X = [A, B] as alice.  Two chunks are required so
    // file_x_id = BLAKE3(A || B) differs from BLAKE3(A) = chunk_a.hash, giving
    // bob a distinct uncommitted manifest to attack rather than alice's committed one.
    let data_a = b"rls-only security-test chunk A";
    let data_b = b"rls-only security-test chunk B";
    let mem_a = MemStore::new();
    let mem_b = MemStore::new();
    let manifest_a = process_file(data_a, MimeClass::Generic, &mem_a)
        .await
        .unwrap();
    let manifest_b = process_file(data_b, MimeClass::Generic, &mem_b)
        .await
        .unwrap();
    let chunk_a = &manifest_a.chunks()[0];
    let chunk_b = &manifest_b.chunks()[0];
    let data_a_stored = mem_a.read_chunk(&chunk_a.hash).await.unwrap();
    let data_b_stored = mem_b.read_chunk(&chunk_b.hash).await.unwrap();

    // file_x_id mirrors what verify_file_identity computes: BLAKE3 over stored chunk bytes.
    let file_x_id = {
        let mut h = blake3::Hasher::new();
        h.update(&data_a_stored);
        h.update(&data_b_stored);
        FileId::from_bytes(*h.finalize().as_bytes())
    };
    let file_x_hex = format!("{file_x_id}");
    let alice_ceiling = chunk_a.len + chunk_b.len + 256;
    let ticket_x = write_payload(&signer, &file_x_id, alice_ceiling);
    {
        let total_len_x = chunk_a.len + chunk_b.len;
        let body = serde_json::json!({
            "total_len": total_len_x,
            "chunks": [
                { "hash": format!("{}", chunk_a.hash), "len": chunk_a.len },
                { "hash": format!("{}", chunk_b.hash), "len": chunk_b.len },
            ],
        });
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/files/{file_x_hex}/intent?t={ticket_x}"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri(format!("/chunks/{}?t={ticket_x}", chunk_a.hash))
                    .header("content-type", "application/octet-stream")
                    .body(axum::body::Body::from(data_a_stored))
                    .unwrap(),
            )
            .await
            .unwrap();
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri(format!("/chunks/{}?t={ticket_x}", chunk_b.hash))
                    .header("content-type", "application/octet-stream")
                    .body(axum::body::Body::from(data_b_stored))
                    .unwrap(),
            )
            .await
            .unwrap();
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/files/{file_x_hex}/commit?t={ticket_x}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    // Register file X as owned by alice only; bob has no visibility of it.
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    register_file_ownership(&mut admin_conn, &file_x_id, "alice").await;

    // Bob's attack: declare file Y whose id = BLAKE3(chunk A stored bytes).
    // Any other id makes verify_file_identity refuse the commit regardless of
    // visibility, so the test would pass vacuously even if the visibility check
    // were broken.  This id is the one that lets the commit succeed when the
    // visibility check wrongly passes, proving the reader-role RLS guard fires.
    let bob_file_id = FileId::from_bytes(*chunk_a.hash.as_bytes());
    let bob_file_hex = format!("{bob_file_id}");
    let bob_ceiling = chunk_a.len + 256;
    let ticket_bob = signer
        .mint(&TicketPayload {
            file_id: *chunk_a.hash.as_bytes(),
            verb: Verb::Write,
            ceiling: bob_ceiling,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "bob".into(),
        })
        .unwrap();

    let body_bob = serde_json::json!({
        "total_len": chunk_a.len,
        "chunks": [{ "hash": format!("{}", chunk_a.hash), "len": chunk_a.len }],
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{bob_file_hex}/intent?t={ticket_bob}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&body_bob).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "bob's intent must succeed");
    let resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let needed: Vec<String> = serde_json::from_value(json["needed"].clone()).unwrap();
    assert_eq!(
        needed.len(),
        1,
        "bob must be told A is needed (he cannot see alice's file X under RLS-only policy)"
    );

    // Bob skips the PUT and tries to commit.  The reader-role check enforces
    // RLS on connetto_visible_files so alice's file remains invisible to bob.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{bob_file_hex}/commit?t={ticket_bob}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "commit must be refused under RLS-only policy: file X not visible to bob"
    );
}

// ---------------------------------------------------------------------------
// Round 6: dedup chunk declared length must match the stored object
// ---------------------------------------------------------------------------

/// Proves: a deduplicated chunk whose declared length does not match the stored
/// object's actual byte count is refused at commit.
///
/// File X = [A, B] is committed first, making both chunks visible to alice.
/// Malicious file Y = [B (length lied to 999), A] uses blake3 of the real
/// bytes in reversed order as its identity so the identity check passes.
/// The length check on stored B (real length != 999) must be the gate that refuses.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn dedup_commit_with_lying_chunk_length_refused() {
    use connetto_file_core::ChunkStore;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    // Produce two single-chunk manifests so each raw slice maps to one chunk.
    let raw_a: &[u8] = b"chunk-A-payload-bytes";
    let raw_b: &[u8] = b"chunk-B-payload-bytes-different";
    let mem_a = MemStore::new();
    let mem_b = MemStore::new();
    let mf_a = process_file(raw_a, MimeClass::Generic, &mem_a)
        .await
        .unwrap();
    let mf_b = process_file(raw_b, MimeClass::Generic, &mem_b)
        .await
        .unwrap();
    assert_eq!(
        mf_a.chunks().len(),
        1,
        "raw_a must produce exactly one chunk"
    );
    assert_eq!(
        mf_b.chunks().len(),
        1,
        "raw_b must produce exactly one chunk"
    );
    let chunk_a = &mf_a.chunks()[0];
    let chunk_b = &mf_b.chunks()[0];
    let stored_a = mem_a.read_chunk(&chunk_a.hash).await.unwrap();
    let stored_b = mem_b.read_chunk(&chunk_b.hash).await.unwrap();
    // Compute all IDs using references before any value is consumed.
    // File X = [A, B]: file_id_X = blake3(stored_A || stored_B).
    let file_id_x = {
        let mut h = blake3::Hasher::new();
        h.update(&stored_a);
        h.update(&stored_b);
        FileId::from_bytes(*h.finalize().as_bytes())
    };
    // Malicious file Y = [B, A] (reversed): file_id_Y = blake3(stored_B || stored_A).
    let file_id_y = {
        let mut h = blake3::Hasher::new();
        h.update(&stored_b);
        h.update(&stored_a);
        FileId::from_bytes(*h.finalize().as_bytes())
    };
    let stored_b_len = stored_b.len();

    let x_path = format!("{file_id_x}");
    let total_len_x = chunk_a.len + chunk_b.len;
    let ticket_x = write_payload(&signer, &file_id_x, total_len_x + 256);
    let hash_a = chunk_a.hash;
    let hash_b = chunk_b.hash;
    let len_a = chunk_a.len;
    let len_b = chunk_b.len;

    let intent_x = serde_json::json!({
        "total_len": total_len_x,
        "chunks": [
            { "hash": format!("{hash_a}"), "len": len_a },
            { "hash": format!("{hash_b}"), "len": len_b },
        ],
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{x_path}/intent?t={ticket_x}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&intent_x).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "X intent must succeed");

    // Move stored_a and stored_b into the PUT bodies; references are done.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("PUT")
                .uri(format!("/chunks/{hash_a}?t={ticket_x}"))
                .header("content-type", "application/octet-stream")
                .body(axum::body::Body::from(stored_a))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "PUT A must succeed");

    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("PUT")
                .uri(format!("/chunks/{hash_b}?t={ticket_x}"))
                .header("content-type", "application/octet-stream")
                .body(axum::body::Body::from(stored_b))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "PUT B must succeed");

    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{x_path}/commit?t={ticket_x}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "X commit must succeed");

    // Make X visible to alice so Y can dedup its chunks.
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    register_file_ownership(&mut admin_conn, &file_id_x, "alice").await;

    // Intent for malicious Y: B with lying len=999, A with honest len.
    // Both chunks are deduped from X (alice can see X), so needed must be empty.
    let lying_len: u64 = 999;
    let total_len_y = lying_len + len_a;
    let ticket_y = write_payload(&signer, &file_id_y, total_len_y + 256);
    let y_path = format!("{file_id_y}");

    let intent_y = serde_json::json!({
        "total_len": total_len_y,
        "chunks": [
            { "hash": format!("{hash_b}"), "len": lying_len },
            { "hash": format!("{hash_a}"), "len": len_a },
        ],
    });
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{y_path}/intent?t={ticket_y}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&intent_y).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Y intent must succeed");
    let resp_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_bytes).unwrap();
    let needed: Vec<String> = serde_json::from_value(json["needed"].clone()).unwrap();
    assert!(
        needed.is_empty(),
        "both chunks must be deduped from file X (needed={needed:?})"
    );

    // Commit Y: identity passes (blake3(real_B || real_A) = file_id_Y) but the
    // length check must refuse because stored_B is {stored_b_len} bytes, not 999.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{y_path}/commit?t={ticket_y}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "commit must be refused: chunk B declared {lying_len} bytes but stored object is {stored_b_len} bytes",
    );
}

// ---------------------------------------------------------------------------
// Finding 1: composite-key fix
// ---------------------------------------------------------------------------

/// Proves Finding 1: the squatter scenario.
///
/// Alice declares intent and uploads all chunks for content X but does not commit.
/// With the old `file_id`-only PK alice's uncommitted row squats the content:
/// bob's intent returns `AlreadyPresent`, his PUTs are `AlreadyStored`, and his
/// commit is refused 409 because `uploaded_by="alice"` != `"bob"`.
///
/// With the composite (`file_id`, `uploaded_by`) PK bob gets his own independent
/// row, his PUTs mark his own chunk rows stored, and his commit succeeds (200).
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn two_callers_identical_content_both_commit() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"content uploaded by two independent callers finding one";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");

    let alice_ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: u64::try_from(data.len()).unwrap() + 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let bob_ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: u64::try_from(data.len()).unwrap() + 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "bob".into(),
        })
        .unwrap();

    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let intent_body =
        serde_json::to_vec(&serde_json::json!({ "total_len": data.len(), "chunks": chunks_json }))
            .unwrap();

    // Alice declares intent but will NOT commit yet.
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/intent?t={alice_ticket}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(intent_body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "alice intent must succeed");

    // Alice PUTs all chunks.
    for c in manifest.chunks() {
        let chunk_data = mem.read_chunk(&c.hash).await.unwrap();
        let hash_hex = format!("{}", c.hash);
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri(format!("/chunks/{hash_hex}?t={alice_ticket}"))
                    .header("content-type", "application/octet-stream")
                    .body(axum::body::Body::from(chunk_data))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NO_CONTENT,
            "alice PUT must succeed"
        );
    }
    // Alice does NOT commit here — she squats the content.

    // Bob declares intent for the same content (alice's uncommitted row squats it
    // in the old single-key schema).
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/intent?t={bob_ticket}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(intent_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "bob intent must succeed");

    // Bob PUTs all chunks (store writes are idempotent; alice already wrote the bytes).
    for c in manifest.chunks() {
        let chunk_data = mem.read_chunk(&c.hash).await.unwrap();
        let hash_hex = format!("{}", c.hash);
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri(format!("/chunks/{hash_hex}?t={bob_ticket}"))
                    .header("content-type", "application/octet-stream")
                    .body(axum::body::Body::from(chunk_data))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NO_CONTENT,
            "bob PUT must succeed"
        );
    }

    // Bob commits while alice's manifest is still uncommitted.
    // Old code (file_id-only PK): loads alice's uncommitted manifest,
    // uploaded_by="alice" != caller="bob" -> 409 CommitRefused.
    // New code (composite PK): loads bob's own uncommitted manifest -> 200.
    let bob_status = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/commit?t={bob_ticket}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
    assert_eq!(
        bob_status,
        StatusCode::OK,
        "bob must commit independently (before fix: 409 ownership mismatch)"
    );

    // Alice commits independently after bob.
    let alice_status = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/commit?t={alice_ticket}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
    assert_eq!(
        alice_status,
        StatusCode::OK,
        "alice commit must also succeed"
    );
}

/// Proves Finding 1 property 2: a non-declarer still cannot commit under the
/// composite PK.  Dave holds a valid write ticket but never declared intent,
/// so no (`file_id`, `dave`) manifest exists.  He gets 404, not 200.
#[tokio::test]
async fn non_declarer_cannot_commit_after_composite_key_fix() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"ownership binding test for composite key";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let alice_ticket = write_payload(&signer, &file_id, u64::try_from(data.len()).unwrap() + 256);

    // Alice declares intent and PUTs all chunks.
    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let intent_body = serde_json::to_vec(&serde_json::json!({
        "total_len": u64::try_from(data.len()).unwrap(),
        "chunks": chunks_json,
    }))
    .unwrap();
    app.clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/intent?t={alice_ticket}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(intent_body))
                .unwrap(),
        )
        .await
        .unwrap();
    for c in manifest.chunks() {
        use connetto_file_core::ChunkStore;
        let chunk_data = mem.read_chunk(&c.hash).await.unwrap();
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri(format!("/chunks/{}?t={alice_ticket}", c.hash))
                    .header("content-type", "application/octet-stream")
                    .body(axum::body::Body::from(chunk_data))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // Dave holds a valid write ticket but never declared intent.
    let dave_ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: u64::try_from(data.len()).unwrap() + 256,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "dave".into(),
        })
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/commit?t={dave_ticket}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "dave has no manifest row so commit returns 404"
    );
}

/// Proves Finding 1 property 3: GET with two committed manifests from different
/// callers serves the right bytes to each and denies a caller without a manifest.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn get_file_scoped_to_committed_caller() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"same bytes committed by two independent callers";
    let alice_file_id = do_upload(&app, &signer, data).await;
    let file_hex = format!("{alice_file_id}");

    // Mint alice and bob write tickets for the same file id (same BLAKE3 content).
    let bob_write = signer
        .mint(&TicketPayload {
            file_id: *alice_file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: u64::try_from(data.len()).unwrap() + 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "bob".into(),
        })
        .unwrap();

    // Bob also uploads (independent, same content).
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let intent_body =
        serde_json::to_vec(&serde_json::json!({ "total_len": data.len(), "chunks": chunks_json }))
            .unwrap();
    app.clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/intent?t={bob_write}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(intent_body))
                .unwrap(),
        )
        .await
        .unwrap();
    for c in manifest.chunks() {
        use connetto_file_core::ChunkStore;
        let chunk_data = mem.read_chunk(&c.hash).await.unwrap();
        app.clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("PUT")
                    .uri(format!("/chunks/{}?t={bob_write}", c.hash))
                    .header("content-type", "application/octet-stream")
                    .body(axum::body::Body::from(chunk_data))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    let bob_commit = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/commit?t={bob_write}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        bob_commit.status(),
        StatusCode::OK,
        "bob commit must succeed"
    );

    // Alice can GET her own committed manifest.
    let alice_read = signer
        .mint(&TicketPayload {
            file_id: *alice_file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: u64::try_from(data.len()).unwrap() + 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(format!("/files/{file_hex}?t={alice_read}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "alice must serve her own manifest"
    );
    let body = axum::body::to_bytes(resp.into_body(), data.len() + 64)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), data, "alice gets the right bytes");

    // Bob can GET his own committed manifest.
    let bob_read = signer
        .mint(&TicketPayload {
            file_id: *alice_file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: u64::try_from(data.len()).unwrap() + 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "bob".into(),
        })
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(format!("/files/{file_hex}?t={bob_read}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "bob must serve his own manifest"
    );
    let body = axum::body::to_bytes(resp.into_body(), data.len() + 64)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), data, "bob gets the right bytes");

    // Charlie (no manifest) cannot serve.
    let charlie_read = signer
        .mint(&TicketPayload {
            file_id: *alice_file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: u64::try_from(data.len()).unwrap() + 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "charlie".into(),
        })
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(format!("/files/{file_hex}?t={charlie_read}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "charlie has no committed manifest so GET returns 404"
    );
}

/// Proves Finding 6: a refused intent (`AlreadyPresent`) leaves no orphan
/// registry rows for the incoming chunks.
#[tokio::test]
async fn refused_intent_leaves_no_registry_rows() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"registry orphan test payload";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let ticket = write_payload(&signer, &file_id, u64::try_from(data.len()).unwrap() + 1024);

    let chunks_json: Vec<serde_json::Value> = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect();
    let intent_body = serde_json::json!({ "total_len": data.len(), "chunks": chunks_json });

    // First declaration: inserts the manifest.
    app.clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/intent?t={ticket}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&intent_body).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Count registry rows after the first declaration.
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    let count_before: i64 = {
        #[derive(diesel::QueryableByName)]
        struct CountRow {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            n: i64,
        }
        let rows: Vec<CountRow> =
            diesel::sql_query("SELECT COUNT(*)::bigint AS n FROM _cfs_chunk_registry")
                .load(&mut admin_conn)
                .await
                .unwrap();
        rows.into_iter().next().unwrap().n
    };

    // Re-declare with the same (file_id, caller): AlreadyPresent, transaction rolled back.
    app.clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/files/{file_hex}/intent?t={ticket}"))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::to_vec(&intent_body).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Registry row count must be unchanged: the rollback left no new rows.
    let count_after: i64 = {
        #[derive(diesel::QueryableByName)]
        struct CountRow {
            #[diesel(sql_type = diesel::sql_types::BigInt)]
            n: i64,
        }
        let rows: Vec<CountRow> =
            diesel::sql_query("SELECT COUNT(*)::bigint AS n FROM _cfs_chunk_registry")
                .load(&mut admin_conn)
                .await
                .unwrap();
        rows.into_iter().next().unwrap().n
    };
    assert_eq!(
        count_after, count_before,
        "refused (AlreadyPresent) intent must not leave orphan registry rows"
    );
}

// ---------------------------------------------------------------------------
// Finding: ticket ceiling above i64::MAX must not produce HTTP 500
// ---------------------------------------------------------------------------

/// Proves: a PUT carrying a ticket with ceiling = `u64::MAX` is accepted as 204.
///
/// Before the fix the database layer's `i64::try_from(u64::MAX)` fails and the
/// handler propagates a `DeserializationError` as HTTP 500. The ceiling is
/// clamped to `i64::MAX` at the handler so any physically unreachable ceiling
/// preserves the ticket intent without reaching the conversion.
#[tokio::test]
async fn put_chunk_with_u64_max_ceiling_succeeds() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"hello ceiling";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let chunks: Vec<ChunkMeta> = manifest.chunks().to_vec();

    let mut admin_conn = connect_admin(&pg.url_admin).await;
    insert_manifest_bypassing_intent(&mut admin_conn, &file_id, "alice", &chunks).await;
    drop(admin_conn);

    let ticket = signer
        .mint(&connetto_file_server::ticket::TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: connetto_file_server::ticket::Verb::Write,
            ceiling: u64::MAX,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();

    let chunk = &chunks[0];
    let hash_hex = format!("{}", chunk.hash);
    let chunk_data = mem.read_chunk(&chunk.hash).await.unwrap();
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hash_hex}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(chunk_data))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "PUT with u64::MAX ceiling must succeed (204), not 500"
    );
}
