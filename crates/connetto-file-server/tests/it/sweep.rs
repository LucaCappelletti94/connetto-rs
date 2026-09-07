//! Sweep tests: orphaned uncommitted uploads and zero-refcount chunks are collected.

use axum::http::StatusCode;
use connetto_file_core::{ChunkStore, MemStore, MimeClass, process_file};
use connetto_file_server::ticket::{TicketPayload, Verb};
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use tower::ServiceExt;

use crate::fixture::{Pg, build_router};

mod race_schema {
    use diesel::prelude::*;

    connetto_file_server::connetto_file_tables!();
}

#[tokio::test]
async fn sweep_removes_orphaned_upload_and_its_chunks() {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let store_path = dir.path().to_path_buf();
    let (app, signer) = build_router(
        &pg,
        connetto_file_server::AnyStore::Fs(
            connetto_file_server::FsStore::new(&store_path).unwrap(),
        ),
    )
    .await;

    let data = b"orphaned content for sweep test";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "sweeptest".into(),
        })
        .unwrap();

    // Intent only — upload starts but never commits.
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
    assert_eq!(resp.status(), StatusCode::OK);

    // PUT one chunk.
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
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Sweep with zero grace: orphaned manifest + its PUT chunk must be collected.
    let admin_pool = pg.admin_pool().await;
    let store = connetto_file_server::AnyStore::Fs(
        connetto_file_server::FsStore::new(&store_path).unwrap(),
    );
    let removed = connetto_file_server::sweep::<connetto_file_server::DefaultFileSchema>(
        &admin_pool,
        &store,
        std::time::Duration::from_secs(0),
    )
    .await
    .unwrap();
    assert!(
        removed > 0,
        "sweep must remove the orphaned manifest and its chunks"
    );

    // The file must still not serve (the intent was never committed, and now
    // the manifest row is gone too).
    let read_ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: 0,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "sweeptest".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={read_ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "swept file must not serve"
    );
}

/// Defect 3: drain-order fix.
///
/// With a store that fails the first delete, the sweep must keep the DB record
/// intact (so the next sweep can retry) and report an error.  The second sweep
/// with a healthy store deletes both the store object and the DB record.
#[tokio::test]
async fn sweep_fail_once_delete_keeps_candidate_retry_succeeds() {
    use crate::fixture::fail_once_delete_store;
    use connetto_file_server::FsStore;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let store_path = dir.path().to_path_buf();

    let (app, signer) = build_router(
        &pg,
        fail_once_delete_store(FsStore::new(&store_path).unwrap()),
    )
    .await;

    // Upload a file that will be orphaned (intent + PUT, no commit).
    let data = b"sweep-retry orphaned content";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "sweepretry".into(),
        })
        .unwrap();

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
    assert_eq!(resp.status(), StatusCode::OK);

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
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // First sweep: the orphaned manifest is removed, but the chunk delete fails
    // (fail-once store).  The DB record must be preserved for retry.
    let admin_pool = pg.admin_pool().await;
    let fail_store = fail_once_delete_store(FsStore::new(&store_path).unwrap());
    let sweep1 = connetto_file_server::sweep::<connetto_file_server::DefaultFileSchema>(
        &admin_pool,
        &fail_store,
        std::time::Duration::from_secs(0),
    )
    .await;
    assert!(
        sweep1.is_err(),
        "first sweep must error when store delete fails"
    );

    // Second sweep with a healthy store clears the store object and the DB record.
    let healthy = connetto_file_server::AnyStore::Fs(FsStore::new(&store_path).unwrap());
    let removed = connetto_file_server::sweep::<connetto_file_server::DefaultFileSchema>(
        &admin_pool,
        &healthy,
        std::time::Duration::from_secs(0),
    )
    .await
    .expect("second sweep must succeed");
    assert!(
        removed > 0,
        "second sweep must remove the retained chunk candidate"
    );
}
// ---------------------------------------------------------------------------
// Item 1: Race tests
// ---------------------------------------------------------------------------

/// Proves (race: sweep vs commit): sweep does not collect a manifest that was
/// committed before the sweep ran, even with zero grace.
#[tokio::test]
async fn sweep_does_not_collect_committed_manifest() {
    use connetto_file_server::DefaultFileSchema;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let store_path = dir.path().to_path_buf();
    let (app, signer) = build_router(
        &pg,
        connetto_file_server::AnyStore::Fs(
            connetto_file_server::FsStore::new(&store_path).unwrap(),
        ),
    )
    .await;

    // Upload and commit a file.
    let data = b"sweep vs commit race test content";
    let mem = connetto_file_core::MemStore::new();
    let manifest = connetto_file_core::process_file(data, MimeClass::Generic, &mem)
        .await
        .unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "committer".into(),
        })
        .unwrap();

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
    app.clone().oneshot(req).await.unwrap();

    for chunk in manifest.chunks() {
        let chunk_data = mem.read_chunk(&chunk.hash).await.unwrap();
        let hash_hex = format!("{}", chunk.hash);
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/chunks/{hash_hex}?t={ticket}"))
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(chunk_data))
            .unwrap();
        app.clone().oneshot(req).await.unwrap();
    }

    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex}/commit?t={ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "commit must succeed");

    // Sweep with zero grace: committed manifest must survive.
    let admin_pool = pg.admin_pool().await;
    let store = connetto_file_server::AnyStore::Fs(
        connetto_file_server::FsStore::new(&store_path).unwrap(),
    );
    let removed = connetto_file_server::sweep::<DefaultFileSchema>(
        &admin_pool,
        &store,
        std::time::Duration::from_secs(0),
    )
    .await
    .expect("sweep must not error");
    assert_eq!(
        removed, 0,
        "committed manifest must not be collected by sweep"
    );

    // Committed file must still serve.
    let read_ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling: 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "committer".into(),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!("/files/{file_hex}?t={read_ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "committed file must serve after sweep"
    );
}

/// Proves (race: sweep vs intent): a new intent for a hash in `deleting` state
/// is refused with 503.  Uploads may not reclaim a hash the sweep has marked
/// for deletion until the registry row is fully removed.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn deleting_hash_blocks_new_intent_with_503() {
    use connetto_file_core::ChunkStore;
    use connetto_file_server::{DefaultFileSchema, FsStore};

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let store_path = dir.path().to_path_buf();
    let (app, signer) = build_router(
        &pg,
        connetto_file_server::AnyStore::Fs(FsStore::new(&store_path).unwrap()),
    )
    .await;

    // Upload and orphan a file (intent + PUT, no commit).
    let data = b"intent race test content for deleting state";
    let mem = connetto_file_core::MemStore::new();
    let manifest = connetto_file_core::process_file(data, MimeClass::Generic, &mem)
        .await
        .unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let chunk = &manifest.chunks()[0];
    let chunk_hash = chunk.hash;
    let ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "racer".into(),
        })
        .unwrap();

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
    assert_eq!(resp.status(), StatusCode::OK, "intent must succeed");

    let chunk_data = mem.read_chunk(&chunk_hash).await.unwrap();
    let hash_hex = format!("{chunk_hash}");
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hash_hex}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(chunk_data))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "PUT must succeed");

    // Sweep: manifest is orphaned (uncommitted, zero grace), hash enters deleting.
    let admin_pool = pg.admin_pool().await;
    let store = connetto_file_server::AnyStore::Fs(FsStore::new(&store_path).unwrap());
    connetto_file_server::sweep::<DefaultFileSchema>(
        &admin_pool,
        &store,
        std::time::Duration::from_secs(0),
    )
    .await
    .expect("sweep must not error");

    // Verify: registry row is gone (sweep fully cleaned up the hash).
    let mut admin_conn = crate::fixture::connect_admin(&pg.url_admin).await;
    let count = crate::fixture::registry_row_count(&mut admin_conn, &chunk_hash).await;
    assert_eq!(count, 0, "registry row must be gone after sweep");

    // We test the blocked-by-deleting scenario by directly inserting a deleting row.
    // The library schema is private; sql_query is the only path from integration-test code.
    diesel::sql_query(
        "INSERT INTO _cfs_chunk_registry (chunk_hash, state) VALUES ($1, 'deleting')
         ON CONFLICT (chunk_hash) DO UPDATE SET state = 'deleting'",
    )
    .bind::<diesel::sql_types::Bytea, _>(chunk_hash.as_bytes().as_ref())
    .execute(&mut admin_conn)
    .await
    .expect("force registry row to deleting");

    let file_id2 = connetto_file_core::FileId::from_bytes([0xABu8; 32]);
    let file_hex2 = format!("{file_id2}");
    let ticket2 = signer
        .mint(&TicketPayload {
            file_id: *file_id2.as_bytes(),
            verb: Verb::Write,
            ceiling: 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "racer".into(),
        })
        .unwrap();
    let chunks_json2 = manifest
        .chunks()
        .iter()
        .map(|c| serde_json::json!({ "hash": format!("{}", c.hash), "len": c.len }))
        .collect::<Vec<_>>();
    let body2 = serde_json::json!({ "total_len": u64::try_from(data.len()).unwrap(), "chunks": chunks_json2 });
    let req2 = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_hex2}/intent?t={ticket2}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body2).unwrap()))
        .unwrap();
    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "intent for a deleting hash must return 503"
    );
}

/// Proves (race: sweep vs PUT): a PUT for a hash in `deleting` state is refused
/// with 503, even when a valid manifest row references that hash.
#[tokio::test]
async fn deleting_hash_blocks_put_with_503() {
    use crate::fixture::insert_manifest_bypassing_intent;
    use connetto_file_core::{ChunkMeta, ChunkStore, MemStore, MimeClass, process_file};

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let store_path = dir.path().to_path_buf();

    // Build manifest metadata.
    let data = b"put race test content for deleting state check";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let chunk = &manifest.chunks()[0];
    let chunk_hash = chunk.hash;

    // Directly insert a registry row with state='deleting', simulating a sweep
    // that has marked H for deletion but not yet completed the store delete.
    // This is the race window where a PUT for H must be refused.
    // The library schema is private; sql_query is the only path from integration-test code.
    let mut admin_conn = crate::fixture::connect_admin(&pg.url_admin).await;
    diesel::sql_query(
        "INSERT INTO _cfs_chunk_registry (chunk_hash, state) VALUES ($1, 'deleting')
         ON CONFLICT (chunk_hash) DO UPDATE SET state = 'deleting'",
    )
    .bind::<diesel::sql_types::Bytea, _>(chunk_hash.as_bytes().as_ref())
    .execute(&mut admin_conn)
    .await
    .expect("insert registry deleting");

    // Create manifest M2 with hash H bypassing intent (which would have refused
    // a deleting hash).  This gives a valid manifest_chunks row so put_chunk
    // can find the declared chunk length before reaching the registry check.
    let file_id2 = connetto_file_core::FileId::from_bytes([0x22u8; 32]);
    insert_manifest_bypassing_intent(
        &mut admin_conn,
        &file_id2,
        &[ChunkMeta {
            hash: chunk_hash,
            len: chunk.len,
        }],
    )
    .await;
    drop(admin_conn);

    // Build the app and try to PUT the deleting hash.
    let (app, signer) = build_router(
        &pg,
        connetto_file_server::AnyStore::Fs(
            connetto_file_server::FsStore::new(&store_path).unwrap(),
        ),
    )
    .await;
    let ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id2.as_bytes(),
            verb: Verb::Write,
            ceiling: 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "putter".into(),
        })
        .unwrap();
    let chunk_data = mem.read_chunk(&chunk_hash).await.unwrap();
    let hash_hex = format!("{chunk_hash}");
    let req = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{hash_hex}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(chunk_data))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "PUT for a deleting hash must return 503"
    );
}

// ---------------------------------------------------------------------------
// Item 2: Crash-point tests
// ---------------------------------------------------------------------------

/// Proves (crash window 1: after intent, before store write): a manifest with
/// chunk rows and pending registry entries but no store object is fully cleaned
/// up by the next sweep.  No permanently invisible orphan survives.
#[tokio::test]
async fn crash_window_1_intent_no_store_write_sweep_cleans_registry() {
    use crate::fixture::{insert_manifest_bypassing_intent, registry_row_count};
    use connetto_file_core::{ChunkMeta, MemStore, MimeClass, process_file};
    use connetto_file_server::{DefaultFileSchema, FsStore};

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let store_path = dir.path().to_path_buf();

    // Build a single-chunk manifest.
    let data = b"crash window 1 payload";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let chunk = &manifest.chunks()[0];
    let chunk_hash = chunk.hash;
    let file_id = connetto_file_core::FileId::from_bytes([0x33u8; 32]);

    let mut admin_conn = crate::fixture::connect_admin(&pg.url_admin).await;
    // Create manifest + manifest_chunks rows (simulates intent having run).
    insert_manifest_bypassing_intent(
        &mut admin_conn,
        &file_id,
        &[ChunkMeta {
            hash: chunk_hash,
            len: chunk.len,
        }],
    )
    .await;
    // Insert registry row with state=pending (intent creates this transactionally).
    // The library schema is private; sql_query is the only path from integration-test code.
    diesel::sql_query(
        "INSERT INTO _cfs_chunk_registry (chunk_hash, state) VALUES ($1, 'pending')
         ON CONFLICT (chunk_hash) DO NOTHING",
    )
    .bind::<diesel::sql_types::Bytea, _>(chunk_hash.as_bytes().as_ref())
    .execute(&mut admin_conn)
    .await
    .expect("insert registry pending for crash window 1");

    // Verify the registry row exists before sweep.
    let before = registry_row_count(&mut admin_conn, &chunk_hash).await;
    assert_eq!(before, 1, "registry row must exist before sweep");

    // Sweep (zero grace): manifest is old and uncommitted.  No store object to
    // delete; the sweep must still remove the registry row cleanly.
    let admin_pool = pg.admin_pool().await;
    let store = connetto_file_server::AnyStore::Fs(FsStore::new(&store_path).unwrap());
    connetto_file_server::sweep::<DefaultFileSchema>(
        &admin_pool,
        &store,
        std::time::Duration::from_secs(0),
    )
    .await
    .expect("sweep must succeed for crash window 1");

    // Registry row must be gone: no permanently invisible orphan survives.
    let mut admin_conn2 = crate::fixture::connect_admin(&pg.url_admin).await;
    let after = registry_row_count(&mut admin_conn2, &chunk_hash).await;
    assert_eq!(
        after, 0,
        "registry row must be gone after sweep (crash window 1)"
    );
}

/// Proves (crash window 2: after store write, before registry stored): a chunk
/// written to the object store but whose registry row is still `pending` (the
/// DB mark crashed) is fully cleaned up by the next sweep.  No orphaned store
/// object or registry row survives.
#[tokio::test]
async fn crash_window_2_store_written_registry_pending_sweep_cleans_up() {
    use crate::fixture::{insert_manifest_bypassing_intent, registry_row_count};
    use connetto_file_core::{ChunkMeta, ChunkStore, MemStore, MimeClass, process_file};
    use connetto_file_server::{DefaultFileSchema, FsStore};

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let store_path = dir.path().to_path_buf();

    // Build manifest metadata.
    let data = b"crash window 2 payload after store write";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let chunk = &manifest.chunks()[0];
    let chunk_hash = chunk.hash;
    let file_id = connetto_file_core::FileId::from_bytes([0x44u8; 32]);

    let mut admin_conn = crate::fixture::connect_admin(&pg.url_admin).await;
    // Create manifest + manifest_chunks rows.
    insert_manifest_bypassing_intent(
        &mut admin_conn,
        &file_id,
        &[ChunkMeta {
            hash: chunk_hash,
            len: chunk.len,
        }],
    )
    .await;
    // Insert registry row with state=pending.
    // The library schema is private; sql_query is the only path from integration-test code.
    diesel::sql_query(
        "INSERT INTO _cfs_chunk_registry (chunk_hash, state) VALUES ($1, 'pending')
         ON CONFLICT (chunk_hash) DO NOTHING",
    )
    .bind::<diesel::sql_types::Bytea, _>(chunk_hash.as_bytes().as_ref())
    .execute(&mut admin_conn)
    .await
    .expect("insert registry pending for crash window 2");

    // Write the chunk to the store DIRECTLY, simulating the store write that
    // succeeded before the crash, without running try_account_chunk_put (which
    // would have marked the registry row stored).
    let fs = FsStore::new(&store_path).unwrap();
    let chunk_bytes = mem.read_chunk(&chunk_hash).await.unwrap();
    fs.write_chunk(&chunk_hash, &chunk_bytes).await.unwrap();

    // Sweep (zero grace): old uncommitted manifest is deleted, cascade removes
    // manifest_chunks, H becomes unreferenced (pending), sweep marks it
    // deleting, deletes from store, removes registry row.
    let admin_pool = pg.admin_pool().await;
    let store = connetto_file_server::AnyStore::Fs(FsStore::new(&store_path).unwrap());
    connetto_file_server::sweep::<DefaultFileSchema>(
        &admin_pool,
        &store,
        std::time::Duration::from_secs(0),
    )
    .await
    .expect("sweep must succeed for crash window 2");

    // Both the store object and the registry row must be gone.
    let mut admin_conn2 = crate::fixture::connect_admin(&pg.url_admin).await;
    let after = registry_row_count(&mut admin_conn2, &chunk_hash).await;
    assert_eq!(
        after, 0,
        "registry row must be gone after sweep (crash window 2)"
    );
    // Store object must also be gone: attempting to read it returns not-found.
    let read_store = FsStore::new(&store_path).unwrap();
    let read_result = read_store.read_chunk(&chunk_hash).await;
    assert!(
        read_result.is_err(),
        "store object must be deleted after sweep (crash window 2)"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sweep_waits_for_overlapping_intent_before_marking_deleting() {
    use connetto_file_core::{ChunkStore, MemStore};
    use connetto_file_server::{AnyStore, DefaultFileSchema, FsStore};
    use diesel::{ExpressionMethods, QueryDsl};
    use diesel_async::AsyncPgConnection;
    use diesel_async::pooled_connection::{AsyncDieselConnectionManager, bb8::Pool};
    use race_schema::_cfs_chunk_registry as registry;

    #[derive(diesel::QueryableByName)]
    struct WaitingRow {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        waiting: bool,
    }

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let data = b"overlapping intent payload";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let chunk = &manifest.chunks()[0];
    let hash = chunk.hash;
    let fs = FsStore::new(dir.path()).unwrap();
    fs.write_chunk(&hash, &mem.read_chunk(&hash).await.unwrap())
        .await
        .unwrap();

    let mut admin_conn = crate::fixture::connect_admin(&pg.url_admin).await;
    diesel::insert_into(registry::table)
        .values((
            registry::chunk_hash.eq(hash.as_bytes().as_ref()),
            registry::state.eq("stored"),
        ))
        .execute(&mut admin_conn)
        .await
        .unwrap();
    admin_conn
        .batch_execute(
            "CREATE FUNCTION cfs_block_intent() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
                 PERFORM pg_advisory_xact_lock(65001);
                 RETURN NEW;
             END
             $$;
             CREATE TRIGGER cfs_block_intent
             BEFORE INSERT ON _cfs_manifest_chunks
             FOR EACH ROW EXECUTE FUNCTION cfs_block_intent();
             SELECT pg_advisory_lock(65001);",
        )
        .await
        .unwrap();

    let (app, signer) = build_router(&pg, AnyStore::Fs(FsStore::new(dir.path()).unwrap())).await;
    let ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: u64::try_from(data.len()).unwrap(),
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let intent = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_id}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&serde_json::json!({
                "total_len": data.len(),
                "chunks": [{
                    "hash": format!("{}", chunk.hash),
                    "len": chunk.len,
                }],
            }))
            .unwrap(),
        ))
        .unwrap();
    let intent_task = tokio::spawn(app.oneshot(intent));

    let mut intent_waiting = false;
    for _ in 0..200 {
        let rows: Vec<WaitingRow> = diesel::sql_query(
            "SELECT EXISTS (
                SELECT 1 FROM pg_stat_activity
                WHERE pid <> pg_backend_pid()
                  AND wait_event_type = 'Lock'
                  AND wait_event = 'advisory'
            ) AS waiting",
        )
        .load(&mut admin_conn)
        .await
        .unwrap();
        intent_waiting = rows.as_slice().first().is_some_and(|row| row.waiting);
        if intent_waiting {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(intent_waiting, "intent must reach the trigger barrier");

    let sweep_url = format!("{}?application_name=cfs_sweep_overlap", pg.url_admin);
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(sweep_url);
    let sweep_pool = Pool::builder().max_size(1).build(manager).await.unwrap();
    let store_path = dir.path().to_path_buf();
    let sweep_task = tokio::spawn(async move {
        let store = AnyStore::Fs(FsStore::new(store_path).unwrap());
        connetto_file_server::sweep::<DefaultFileSchema>(
            &sweep_pool,
            &store,
            std::time::Duration::from_secs(3600),
        )
        .await
    });

    let mut sweep_waiting = false;
    for _ in 0..200 {
        let rows: Vec<WaitingRow> = diesel::sql_query(
            "SELECT EXISTS (
                SELECT 1 FROM pg_stat_activity
                WHERE application_name = 'cfs_sweep_overlap'
                  AND state = 'active'
                  AND wait_event_type = 'Lock'
            ) AS waiting",
        )
        .load(&mut admin_conn)
        .await
        .unwrap();
        sweep_waiting = rows.as_slice().first().is_some_and(|row| row.waiting);
        if sweep_waiting {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(sweep_waiting, "sweep must wait for the intent row lock");

    admin_conn
        .batch_execute("SELECT pg_advisory_unlock(65001)")
        .await
        .unwrap();
    assert_eq!(intent_task.await.unwrap().unwrap().status(), StatusCode::OK);
    assert_eq!(sweep_task.await.unwrap().unwrap(), 0);

    let state: String = registry::table
        .filter(registry::chunk_hash.eq(hash.as_bytes().as_ref()))
        .select(registry::state)
        .first(&mut admin_conn)
        .await
        .unwrap();
    assert_eq!(state, "stored");
    assert_eq!(
        FsStore::new(dir.path())
            .unwrap()
            .read_chunk(&hash)
            .await
            .unwrap(),
        data
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sweep_waits_for_overlapping_put_before_deleting_bytes() {
    use connetto_file_core::{ChunkStore, MemStore};
    use connetto_file_server::{AnyStore, DefaultFileSchema, FsStore};
    use diesel_async::AsyncPgConnection;
    use diesel_async::pooled_connection::{AsyncDieselConnectionManager, bb8::Pool};

    #[derive(diesel::QueryableByName)]
    struct WaitingRow {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        waiting: bool,
    }

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let data = b"overlapping PUT payload";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let chunk = &manifest.chunks()[0];
    let chunk_hash = chunk.hash;
    let (store, write_entered, release_write) =
        crate::fixture::gated_write_store(FsStore::new(dir.path()).unwrap());
    let (app, signer) = build_router(&pg, store).await;
    let ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: u64::try_from(data.len()).unwrap(),
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let chunks_json = vec![serde_json::json!({
        "hash": format!("{}", chunk.hash),
        "len": chunk.len,
    })];
    let intent = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_id}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&serde_json::json!({
                "total_len": data.len(),
                "chunks": chunks_json,
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(intent).await.unwrap().status(),
        StatusCode::OK
    );

    let put = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{chunk_hash}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(data.as_slice()))
        .unwrap();
    let put_task = tokio::spawn(app.clone().oneshot(put));
    write_entered.notified().await;

    let sweep_url = format!("{}?application_name=cfs_put_sweep_overlap", pg.url_admin);
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(sweep_url);
    let sweep_pool = Pool::builder().max_size(1).build(manager).await.unwrap();
    let store_path = dir.path().to_path_buf();
    let sweep_task = tokio::spawn(async move {
        let store = AnyStore::Fs(FsStore::new(store_path).unwrap());
        connetto_file_server::sweep::<DefaultFileSchema>(
            &sweep_pool,
            &store,
            std::time::Duration::ZERO,
        )
        .await
    });

    let mut check_conn = crate::fixture::connect_admin(&pg.url_admin).await;
    let mut waiting = false;
    for _ in 0..200 {
        let rows: Vec<WaitingRow> = diesel::sql_query(
            "SELECT EXISTS (
                SELECT 1 FROM pg_stat_activity
                WHERE application_name = 'cfs_put_sweep_overlap'
                  AND state = 'active'
                  AND wait_event_type = 'Lock'
            ) AS waiting",
        )
        .load(&mut check_conn)
        .await
        .unwrap();
        waiting = rows.as_slice().first().is_some_and(|row| row.waiting);
        if waiting {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(waiting, "sweep must wait for the PUT row lock");

    release_write.notify_one();
    assert_eq!(
        put_task.await.unwrap().unwrap().status(),
        StatusCode::NO_CONTENT
    );
    sweep_task.await.unwrap().unwrap();

    assert!(
        FsStore::new(dir.path())
            .unwrap()
            .read_chunk(&chunk_hash)
            .await
            .is_err()
    );
    assert_eq!(
        crate::fixture::registry_row_count(&mut check_conn, &chunk_hash).await,
        0
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sweep_waits_for_overlapping_commit_verification() {
    use connetto_file_core::{ChunkStore, MemStore};
    use connetto_file_server::{AnyStore, DefaultFileSchema, FsStore};
    use diesel_async::AsyncPgConnection;
    use diesel_async::pooled_connection::{AsyncDieselConnectionManager, bb8::Pool};

    #[derive(diesel::QueryableByName)]
    struct WaitingRow {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        waiting: bool,
    }

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let data = b"overlapping commit payload";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let chunk = &manifest.chunks()[0];
    let chunk_hash = chunk.hash;
    let (store, read_entered, release_read) =
        crate::fixture::gated_read_store(FsStore::new(dir.path()).unwrap(), 1);
    let (app, signer) = build_router(&pg, store).await;
    let ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: u64::try_from(data.len()).unwrap(),
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let chunks_json = vec![serde_json::json!({
        "hash": format!("{}", chunk.hash),
        "len": chunk.len,
    })];
    let intent = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_id}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&serde_json::json!({
                "total_len": data.len(),
                "chunks": chunks_json,
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(intent).await.unwrap().status(),
        StatusCode::OK
    );
    let put = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{chunk_hash}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(data.as_slice()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(put).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    let commit = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_id}/commit?t={ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let commit_task = tokio::spawn(app.clone().oneshot(commit));
    read_entered.notified().await;

    let sweep_url = format!("{}?application_name=cfs_commit_sweep_overlap", pg.url_admin);
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(sweep_url);
    let sweep_pool = Pool::builder().max_size(1).build(manager).await.unwrap();
    let store_path = dir.path().to_path_buf();
    let sweep_task = tokio::spawn(async move {
        let store = AnyStore::Fs(FsStore::new(store_path).unwrap());
        connetto_file_server::sweep::<DefaultFileSchema>(
            &sweep_pool,
            &store,
            std::time::Duration::ZERO,
        )
        .await
    });

    let mut check_conn = crate::fixture::connect_admin(&pg.url_admin).await;
    let mut waiting = false;
    for _ in 0..200 {
        let rows: Vec<WaitingRow> = diesel::sql_query(
            "SELECT EXISTS (
                SELECT 1 FROM pg_stat_activity
                WHERE application_name = 'cfs_commit_sweep_overlap'
                  AND state = 'active'
                  AND wait_event_type = 'Lock'
            ) AS waiting",
        )
        .load(&mut check_conn)
        .await
        .unwrap();
        waiting = rows.as_slice().first().is_some_and(|row| row.waiting);
        if waiting {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(waiting, "sweep must wait for the manifest row lock");

    release_read.notify_one();
    assert_eq!(commit_task.await.unwrap().unwrap().status(), StatusCode::OK);
    assert_eq!(sweep_task.await.unwrap().unwrap(), 0);
    assert_eq!(
        FsStore::new(dir.path())
            .unwrap()
            .read_chunk(&chunk_hash)
            .await
            .unwrap(),
        data
    );
}

/// A sweep must not lock live content: it completes while a PUT for a fresh
/// manifest still holds that hash's registry row.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn sweep_does_not_lock_live_content_held_by_an_active_put() {
    use connetto_file_core::MemStore;
    use connetto_file_server::{AnyStore, DefaultFileSchema, FsStore};
    use diesel_async::AsyncPgConnection;
    use diesel_async::pooled_connection::{AsyncDieselConnectionManager, bb8::Pool};

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let data = b"live content held by an active PUT";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let chunk = &manifest.chunks()[0];
    let chunk_hash = chunk.hash;
    let (store, write_entered, release_write) =
        crate::fixture::gated_write_store(FsStore::new(dir.path()).unwrap());
    let (app, signer) = build_router(&pg, store).await;
    let ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: u64::try_from(data.len()).unwrap(),
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: "alice".into(),
        })
        .unwrap();
    let intent = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{file_id}/intent?t={ticket}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&serde_json::json!({
                "total_len": data.len(),
                "chunks": [{ "hash": format!("{}", chunk.hash), "len": chunk.len }],
            }))
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(intent).await.unwrap().status(),
        StatusCode::OK
    );

    let put = axum::http::Request::builder()
        .method("PUT")
        .uri(format!("/chunks/{chunk_hash}?t={ticket}"))
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(data.as_slice()))
        .unwrap();
    let put_task = tokio::spawn(app.clone().oneshot(put));
    write_entered.notified().await;

    // The PUT now holds this hash's registry row.  A sweep whose lock set is
    // bounded to doomed hashes must still finish; a table-wide lock would hang.
    let sweep_url = format!("{}?application_name=cfs_live_lock_probe", pg.url_admin);
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(sweep_url);
    let sweep_pool = Pool::builder().max_size(1).build(manager).await.unwrap();
    let store_path = dir.path().to_path_buf();
    let swept = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::spawn(async move {
            let store = AnyStore::Fs(FsStore::new(store_path).unwrap());
            connetto_file_server::sweep::<DefaultFileSchema>(
                &sweep_pool,
                &store,
                std::time::Duration::from_secs(3600),
            )
            .await
        }),
    )
    .await
    .expect("sweep must not block on live content")
    .unwrap()
    .expect("sweep must succeed");
    assert_eq!(swept, 0, "nothing is collectable while the upload is fresh");

    release_write.notify_one();
    assert_eq!(
        put_task.await.unwrap().unwrap().status(),
        StatusCode::NO_CONTENT
    );
}

/// A sweep must not wait on a live row that is not a candidate: it completes
/// while another session holds the registry row of a committed, referenced hash.
///
/// The overlap tests only prove candidates ARE locked, so without this a return
/// to table-wide locking would pass the suite.
#[tokio::test]
async fn sweep_ignores_a_held_lock_on_a_committed_hash() {
    use connetto_file_core::{ChunkMeta, MemStore};
    use connetto_file_server::{AnyStore, DefaultFileSchema, FsStore};
    use diesel::{ExpressionMethods, QueryDsl};
    use diesel_async::AsyncPgConnection;
    use diesel_async::pooled_connection::{AsyncDieselConnectionManager, bb8::Pool};
    use race_schema::_cfs_chunk_registry as registry;

    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let data = b"committed content whose row is held elsewhere";
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let chunk = &manifest.chunks()[0];
    let live_hash = chunk.hash;

    let fs = FsStore::new(dir.path()).unwrap();
    fs.write_chunk(&live_hash, &mem.read_chunk(&live_hash).await.unwrap())
        .await
        .unwrap();

    // A committed manifest keeps this hash live, so it is never a candidate.
    let mut holder = crate::fixture::connect_admin(&pg.url_admin).await;
    crate::fixture::insert_committed_manifest(
        &mut holder,
        &file_id,
        &[ChunkMeta {
            hash: live_hash,
            len: chunk.len,
        }],
    )
    .await;

    // Genuine garbage for the sweep to collect, so the pass is not a no-op.
    let doomed = connetto_file_core::ChunkHash::from_bytes([0x7Cu8; 32]);
    diesel::insert_into(registry::table)
        .values((
            registry::chunk_hash.eq(doomed.as_bytes().as_ref()),
            registry::state.eq("stored"),
        ))
        .execute(&mut holder)
        .await
        .unwrap();

    // Hold the live hash's registry row in an open transaction.
    holder.batch_execute("BEGIN").await.unwrap();
    let _: (Vec<u8>, String) = registry::table
        .filter(registry::chunk_hash.eq(live_hash.as_bytes().as_ref()))
        .for_update()
        .select((registry::chunk_hash, registry::state))
        .first(&mut holder)
        .await
        .unwrap();

    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(pg.url_admin.clone());
    let sweep_pool = Pool::builder().max_size(1).build(manager).await.unwrap();
    let store_path = dir.path().to_path_buf();
    let swept = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::spawn(async move {
            let store = AnyStore::Fs(FsStore::new(store_path).unwrap());
            connetto_file_server::sweep::<DefaultFileSchema>(
                &sweep_pool,
                &store,
                std::time::Duration::ZERO,
            )
            .await
        }),
    )
    .await
    .expect("sweep must not wait on a non-candidate row")
    .unwrap()
    .expect("sweep must succeed");
    assert_eq!(swept, 1, "the doomed hash is collected");

    holder.batch_execute("COMMIT").await.unwrap();
    let live_state: String = registry::table
        .filter(registry::chunk_hash.eq(live_hash.as_bytes().as_ref()))
        .select(registry::state)
        .first(&mut holder)
        .await
        .unwrap();
    assert_eq!(live_state, "stored", "the committed hash is untouched");
    assert_eq!(
        FsStore::new(dir.path())
            .unwrap()
            .read_chunk(&live_hash)
            .await
            .unwrap(),
        data
    );
}

// ---------------------------------------------------------------------------
// Round 6: out-of-range grace period must propagate as an error
// ---------------------------------------------------------------------------

/// Proves: sweep returns `SweepError::GracePeriodOutOfRange` rather than silently
/// substituting a one-hour cutoff when the grace Duration overflows chrono's range.
/// The grace conversion fires before `pool.get()`, so no database connection is needed.
#[tokio::test]
async fn sweep_out_of_range_grace_period_returns_error() {
    use connetto_file_server::{AnyStore, DefaultFileSchema, FsStore, SweepError};
    use diesel_async::AsyncPgConnection;
    use diesel_async::pooled_connection::{AsyncDieselConnectionManager, bb8::Pool};

    let dir = tempfile::TempDir::new().unwrap();
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(
        "postgresql://unused:unused@127.0.0.1:1/unused",
    );
    let pool = Pool::builder().max_size(1).build_unchecked(manager);
    let store = AnyStore::Fs(FsStore::new(dir.path()).unwrap());

    let result =
        connetto_file_server::sweep::<DefaultFileSchema>(&pool, &store, std::time::Duration::MAX)
            .await;

    assert!(
        matches!(result, Err(SweepError::GracePeriodOutOfRange)),
        "expected GracePeriodOutOfRange, got {result:?}",
    );
}
