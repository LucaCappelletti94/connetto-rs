//! Serve tests: absent / uncommitted files answer 404, headers are correct.

use axum::http::StatusCode;
use connetto_file_server::ticket::{TicketPayload, Verb};
use tower::ServiceExt;

use crate::fixture::{Pg, build_router, fs_store, make_signer};

#[tokio::test]
async fn absent_file_answers_404() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let file_id = [9u8; 32];
    let token = signer
        .mint(&TicketPayload {
            file_id,
            verb: Verb::Read,
            ceiling: 0,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let id_hex = connetto_file_server::hex_32(&file_id);
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{id_hex}?t={token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn bad_ticket_answers_404() {
    use crate::fixture::{connect_admin, insert_committed_manifest};
    use connetto_file_core::FileId;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;
    let (other_signer, _) = make_signer();

    let file_id_bytes = [5u8; 32];
    let file_id = FileId::from_bytes(file_id_bytes);
    let id_hex = connetto_file_server::hex_32(&file_id_bytes);
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    insert_committed_manifest(&mut admin_conn, &file_id, "alice", &[]).await;

    // A valid read ticket for the committed file must serve 200, proving that
    // the manifest lookup succeeds and only the signature check can cause 404.
    let valid_token = signer
        .mint(&TicketPayload {
            file_id: file_id_bytes,
            verb: Verb::Read,
            ceiling: 0,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{id_hex}?t={valid_token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "valid ticket on committed file must answer 200"
    );

    // A token signed by a different key must be refused regardless of the manifest.
    let bad_token = other_signer
        .mint(&TicketPayload {
            file_id: file_id_bytes,
            verb: Verb::Read,
            ceiling: 0,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{id_hex}?t={bad_token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NOT_FOUND,
        "bad ticket (wrong signing key) must answer 404"
    );
}

#[tokio::test]
async fn expired_ticket_answers_404() {
    use crate::fixture::{connect_admin, insert_committed_manifest};
    use connetto_file_core::FileId;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let file_id_bytes = [3u8; 32];
    let file_id = FileId::from_bytes(file_id_bytes);
    let id_hex = connetto_file_server::hex_32(&file_id_bytes);
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    insert_committed_manifest(&mut admin_conn, &file_id, "alice", &[]).await;

    // A valid (non-expired) read ticket for the committed file must serve 200,
    // proving that the manifest lookup succeeds and only expiry can cause 404.
    let valid_token = signer
        .mint(&TicketPayload {
            file_id: file_id_bytes,
            verb: Verb::Read,
            ceiling: 0,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{id_hex}?t={valid_token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "valid ticket on committed file must answer 200"
    );

    // An expired ticket must be refused regardless of the manifest.
    let expired_token = signer
        .mint(&TicketPayload {
            file_id: file_id_bytes,
            verb: Verb::Read,
            ceiling: 0,
            expiry: chrono::Utc::now().timestamp() - 1,
            caller: "alice".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{id_hex}?t={expired_token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NOT_FOUND,
        "expired ticket must answer 404"
    );
}

#[tokio::test]
async fn write_ticket_on_read_endpoint_answers_404() {
    use crate::fixture::{connect_admin, insert_committed_manifest};
    use connetto_file_core::FileId;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let file_id_bytes = [4u8; 32];
    let file_id = FileId::from_bytes(file_id_bytes);
    let id_hex = connetto_file_server::hex_32(&file_id_bytes);
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    insert_committed_manifest(&mut admin_conn, &file_id, "alice", &[]).await;

    // A read ticket for the committed file must serve 200, proving that the
    // manifest lookup succeeds and only the wrong verb can cause 404.
    let read_token = signer
        .mint(&TicketPayload {
            file_id: file_id_bytes,
            verb: Verb::Read,
            ceiling: 0,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{id_hex}?t={read_token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "read ticket on committed file must answer 200"
    );

    // A write ticket presented at the read endpoint must be refused.
    let write_token = signer
        .mint(&TicketPayload {
            file_id: file_id_bytes,
            verb: Verb::Write,
            ceiling: 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{id_hex}?t={write_token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NOT_FOUND,
        "write ticket on read endpoint must answer 404"
    );
}

// ---------------------------------------------------------------------------
// Defect 6: empty files
// ---------------------------------------------------------------------------

/// An empty committed file must serve with 200 and an empty body.
#[tokio::test]
async fn empty_file_serves_200_with_empty_body() {
    use crate::fixture::{Pg, build_router, connect_admin, fs_store, insert_committed_manifest};
    use connetto_file_core::{ChunkStore, MemStore, MimeClass, process_file};

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let mem = MemStore::new();
    let manifest = process_file(&[], MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = connetto_file_server::hex_32(file_id.as_bytes());

    {
        use connetto_file_server::FsStore;
        let fs = FsStore::new(dir.path()).unwrap();
        for c in manifest.chunks() {
            let data = mem.read_chunk(&c.hash).await.unwrap();
            fs.write_chunk(&c.hash, &data).await.unwrap();
        }
    }

    let mut admin_conn = connect_admin(&pg.url_admin).await;
    insert_committed_manifest(&mut admin_conn, &file_id, "alice", manifest.chunks()).await;

    let token = signer
        .mint(&connetto_file_server::ticket::TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: 0,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "empty file must answer 200");
    let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
    assert!(body.is_empty(), "empty file body must be empty");
}

/// A range request on an empty committed file must return 416.
#[tokio::test]
async fn empty_file_range_request_answers_416() {
    use crate::fixture::{Pg, build_router, connect_admin, fs_store, insert_committed_manifest};
    use connetto_file_core::{ChunkStore, MemStore, MimeClass, process_file};

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let mem = MemStore::new();
    let manifest = process_file(&[], MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = connetto_file_server::hex_32(file_id.as_bytes());

    {
        use connetto_file_server::FsStore;
        let fs = FsStore::new(dir.path()).unwrap();
        for c in manifest.chunks() {
            let data = mem.read_chunk(&c.hash).await.unwrap();
            fs.write_chunk(&c.hash, &data).await.unwrap();
        }
    }

    let mut admin_conn = connect_admin(&pg.url_admin).await;
    insert_committed_manifest(&mut admin_conn, &file_id, "alice", manifest.chunks()).await;

    let token = signer
        .mint(&connetto_file_server::ticket::TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={token}"))
        .header("range", "bytes=0-0")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::RANGE_NOT_SATISFIABLE,
        "range on empty file must be 416"
    );
}

// ---------------------------------------------------------------------------
// Defect 7: streaming serve
// ---------------------------------------------------------------------------

/// Headers and the first chunk must arrive before the store releases the second
/// chunk read.  This proves the response is genuinely streamed.
#[tokio::test]
async fn streaming_serve_first_chunk_arrives_before_second_read_released() {
    use crate::fixture::{
        Pg, connect_admin, gated_read_store, insert_committed_manifest, make_signer,
    };
    use connetto_file_core::{ChunkHash, ChunkMeta, ChunkStore, FileId};
    use connetto_file_server::{AppPools, Config, DefaultFileSchema, FsStore, serve};
    use http_body_util::BodyExt;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();

    let chunk1_data = vec![0xAAu8; 64];
    let chunk2_data = vec![0xBBu8; 64];
    let hash1 = ChunkHash::from_bytes(*blake3::hash(&chunk1_data).as_bytes());
    let hash2 = ChunkHash::from_bytes(*blake3::hash(&chunk2_data).as_bytes());

    // Write chunks to the backing fs store.
    {
        let fs = FsStore::new(dir.path()).unwrap();
        fs.write_chunk(&hash1, &chunk1_data).await.unwrap();
        fs.write_chunk(&hash2, &chunk2_data).await.unwrap();
    }

    // Gated store blocks the 2nd read until gate.notify_one().
    let (store, _entered, gate) = gated_read_store(FsStore::new(dir.path()).unwrap(), 2);

    let (signer, verifier) = make_signer();
    // Pg::start() already applied DEPLOYMENT_DDL and FIXTURE_STMTS, so
    // serve() preflight passes without extra setup.
    let app = serve::<DefaultFileSchema>(Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: pg.reader_pool().await,
        },
        store,
        verifier,
        content_state_fn: "connetto_set_content_state".into(),
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    })
    .await
    .expect("preflight passed in streaming test");

    let file_id = FileId::from_bytes([0xFEu8; 32]);
    let chunks = vec![
        ChunkMeta {
            hash: hash1,
            len: 64,
        },
        ChunkMeta {
            hash: hash2,
            len: 64,
        },
    ];
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    insert_committed_manifest(&mut admin_conn, &file_id, "alice", &chunks).await;
    drop(admin_conn);

    let file_hex = connetto_file_server::hex_32(file_id.as_bytes());
    let token = signer
        .mint(&connetto_file_server::ticket::TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: 128,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();

    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={token}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Headers arrive before any store read: the response is streamed.
    assert!(
        resp.headers().contains_key("etag"),
        "etag must be present in headers"
    );

    let mut body = resp.into_body();

    // First chunk arrives without releasing the gate.
    let frame1 = tokio::time::timeout(std::time::Duration::from_secs(5), body.frame())
        .await
        .expect("first chunk timed out")
        .expect("stream error on first chunk")
        .expect("no frame");
    let data1 = frame1.into_data().expect("first frame must be data");
    assert_eq!(&data1[..], &chunk1_data[..], "first chunk must match");

    // Release the gate; second chunk must then arrive.
    gate.notify_one();

    let frame2 = tokio::time::timeout(std::time::Duration::from_secs(5), body.frame())
        .await
        .expect("second chunk timed out after gate")
        .expect("stream error on second chunk")
        .expect("no second frame");
    let data2 = frame2.into_data().expect("second frame must be data");
    assert_eq!(&data2[..], &chunk2_data[..], "second chunk must match");
}
// ---------------------------------------------------------------------------
// Item 4: Content-Length and Accept-Ranges headers
// ---------------------------------------------------------------------------

/// Proves: a full GET response carries `Content-Length: file_size` and
/// `Accept-Ranges: bytes` on a non-empty committed file.
#[tokio::test]
async fn content_length_present_on_full_response() {
    use crate::fixture::{Pg, build_router, connect_admin, fs_store, insert_committed_manifest};
    use connetto_file_core::{ChunkStore, MemStore, MimeClass, process_file};
    use connetto_file_server::FsStore;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"header test payload for full response";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let total: u64 = manifest.chunks().iter().map(|c| c.len).sum();

    let fs = FsStore::new(dir.path()).unwrap();
    for c in manifest.chunks() {
        let bytes = mem.read_chunk(&c.hash).await.unwrap();
        fs.write_chunk(&c.hash, &bytes).await.unwrap();
    }
    let mut conn = connect_admin(&pg.url_admin).await;
    insert_committed_manifest(&mut conn, &file_id, "alice", manifest.chunks()).await;

    let token = signer
        .mint(&connetto_file_server::ticket::TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: total + 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!(
            "/files/{}?t={token}",
            connetto_file_server::hex_32(file_id.as_bytes())
        ))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "full response must be 200");
    let cl = resp
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .expect("Content-Length must be present and numeric");
    assert_eq!(cl, total, "Content-Length must equal file size");
    let ar = resp
        .headers()
        .get(axum::http::header::ACCEPT_RANGES)
        .and_then(|v| v.to_str().ok())
        .expect("Accept-Ranges must be present");
    assert_eq!(ar, "bytes", "Accept-Ranges must be 'bytes'");
}

/// Proves: a partial (ranged) GET response carries `Content-Length: range_size`
/// and `Accept-Ranges: bytes`.
#[tokio::test]
async fn content_length_present_on_partial_response() {
    use crate::fixture::{Pg, build_router, connect_admin, fs_store, insert_committed_manifest};
    use connetto_file_core::{ChunkStore, MemStore, MimeClass, process_file};
    use connetto_file_server::FsStore;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"partial response header test payload needs some bytes";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let total: u64 = manifest.chunks().iter().map(|c| c.len).sum();
    assert!(total >= 10, "test data must be at least 10 bytes");

    let fs = FsStore::new(dir.path()).unwrap();
    for c in manifest.chunks() {
        let bytes = mem.read_chunk(&c.hash).await.unwrap();
        fs.write_chunk(&c.hash, &bytes).await.unwrap();
    }
    let mut conn = connect_admin(&pg.url_admin).await;
    insert_committed_manifest(&mut conn, &file_id, "alice", manifest.chunks()).await;

    let token = signer
        .mint(&connetto_file_server::ticket::TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: total + 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    // Request bytes 0-4 (5 bytes).
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!(
            "/files/{}?t={token}",
            connetto_file_server::hex_32(file_id.as_bytes())
        ))
        .header("range", "bytes=0-4")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PARTIAL_CONTENT,
        "ranged response must be 206"
    );
    let cl = resp
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .expect("Content-Length must be present and numeric on partial response");
    assert_eq!(
        cl, 5,
        "Content-Length must equal range size (bytes 0-4 = 5 bytes)"
    );
    let ar = resp
        .headers()
        .get(axum::http::header::ACCEPT_RANGES)
        .and_then(|v| v.to_str().ok())
        .expect("Accept-Ranges must be present on partial response");
    assert_eq!(
        ar, "bytes",
        "Accept-Ranges must be 'bytes' on partial response"
    );
}

/// Proves: an empty committed file GET response carries `Content-Length: 0`
/// and `Accept-Ranges: bytes`.
#[tokio::test]
async fn content_length_present_on_empty_file_response() {
    use crate::fixture::{Pg, build_router, connect_admin, fs_store, insert_committed_manifest};
    use connetto_file_core::{ChunkStore, MemStore, MimeClass, process_file};
    use connetto_file_server::FsStore;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let mem = MemStore::new();
    let manifest = process_file(&[], MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();

    let fs = FsStore::new(dir.path()).unwrap();
    for c in manifest.chunks() {
        let bytes = mem.read_chunk(&c.hash).await.unwrap();
        fs.write_chunk(&c.hash, &bytes).await.unwrap();
    }
    let mut conn = connect_admin(&pg.url_admin).await;
    insert_committed_manifest(&mut conn, &file_id, "alice", manifest.chunks()).await;

    let token = signer
        .mint(&connetto_file_server::ticket::TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: 0,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!(
            "/files/{}?t={token}",
            connetto_file_server::hex_32(file_id.as_bytes())
        ))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "empty file must answer 200");
    let cl = resp
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .expect("Content-Length must be present on empty file response");
    assert_eq!(cl, 0, "Content-Length must be 0 for empty file");
    let ar = resp
        .headers()
        .get(axum::http::header::ACCEPT_RANGES)
        .and_then(|v| v.to_str().ok())
        .expect("Accept-Ranges must be present on empty file response");
    assert_eq!(
        ar, "bytes",
        "Accept-Ranges must be 'bytes' on empty file response"
    );
}

// ---------------------------------------------------------------------------
// Finding 1: suffix byte ranges
// ---------------------------------------------------------------------------

/// A suffix range bytes=-N delivers the last N bytes with 206.
#[tokio::test]
async fn suffix_byte_range_serves_206() {
    use crate::fixture::{Pg, build_router, connect_admin, fs_store, insert_committed_manifest};
    use connetto_file_core::{ChunkStore, MemStore, MimeClass, process_file};
    use connetto_file_server::FsStore;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let (app, signer) = build_router(&pg, fs_store(&dir)).await;

    let data = b"0123456789abcdef";
    let mem = MemStore::new();
    let manifest = process_file(data.as_ref(), MimeClass::Generic, &mem)
        .await
        .unwrap();
    let file_id = manifest.file_id();
    let total: u64 = manifest.chunks().iter().map(|c| c.len).sum();

    let fs = FsStore::new(dir.path()).unwrap();
    for c in manifest.chunks() {
        let bytes = mem.read_chunk(&c.hash).await.unwrap();
        fs.write_chunk(&c.hash, &bytes).await.unwrap();
    }
    let mut conn = connect_admin(&pg.url_admin).await;
    insert_committed_manifest(&mut conn, &file_id, "alice", manifest.chunks()).await;

    let token = signer
        .mint(&connetto_file_server::ticket::TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: total,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    // Request the last 4 bytes via suffix range.
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!(
            "/files/{}?t={token}",
            connetto_file_server::hex_32(file_id.as_bytes())
        ))
        .header("range", "bytes=-4")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PARTIAL_CONTENT,
        "suffix range must answer 206"
    );
    let body = axum::body::to_bytes(resp.into_body(), 16).await.unwrap();
    assert_eq!(
        &body[..],
        &data[data.len() - 4..],
        "suffix range must deliver the last 4 bytes"
    );
}

// ---------------------------------------------------------------------------
// Finding 2: short store read
// ---------------------------------------------------------------------------

/// A store that under-delivers terminates the stream with an error, not a panic.
#[tokio::test]
async fn short_store_read_terminates_stream_with_error() {
    use crate::fixture::{
        Pg, connect_admin, insert_committed_manifest, make_signer, short_read_store,
    };
    use connetto_file_core::{ChunkHash, ChunkMeta, ChunkStore, FileId};
    use connetto_file_server::{AppPools, Config, DefaultFileSchema, FsStore, serve};

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();

    let chunk_data = vec![0xCCu8; 64];
    let hash = ChunkHash::from_bytes(*blake3::hash(&chunk_data).as_bytes());

    {
        let fs = FsStore::new(dir.path()).unwrap();
        fs.write_chunk(&hash, &chunk_data).await.unwrap();
    }

    // Store returns only 32 bytes but the manifest declares 64.
    let store = short_read_store(FsStore::new(dir.path()).unwrap(), 32);

    let (signer, verifier) = make_signer();
    let app = serve::<DefaultFileSchema>(Config {
        pools: AppPools {
            admin: pg.admin_pool().await,
            reader: pg.reader_pool().await,
        },
        store,
        verifier,
        content_state_fn: "connetto_set_content_state".into(),
        grace: std::time::Duration::from_secs(3600),
        _schema: std::marker::PhantomData,
    })
    .await
    .expect("preflight passed");

    let file_id = FileId::from_bytes([0xEEu8; 32]);
    let chunks = vec![ChunkMeta { hash, len: 64 }];
    let mut admin_conn = connect_admin(&pg.url_admin).await;
    insert_committed_manifest(&mut admin_conn, &file_id, "alice", &chunks).await;
    drop(admin_conn);

    let token = signer
        .mint(&connetto_file_server::ticket::TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: 64,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!(
            "/files/{}?t={token}",
            connetto_file_server::hex_32(file_id.as_bytes())
        ))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "status is decided before store reads"
    );
    // Body collection must fail, not panic: the stream returns a store error.
    let result = axum::body::to_bytes(resp.into_body(), 128).await;
    assert!(result.is_err(), "body must fail on short store read");
}
