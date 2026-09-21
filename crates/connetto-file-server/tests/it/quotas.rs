//! R87 quotas, deployment ceilings, the traffic ledger, and the per-uploader
//! commit serialization.

use std::time::Duration;

use axum::http::StatusCode;
use connetto_file_core::{ChunkStore, FileId, MemStore, MimeClass, process_file};
use connetto_file_server::ticket::{TicketPayload, Verb};
use connetto_file_server::{CeilingCache, QuotaSettings};

use diesel::sql_types::{Bytea, Text};
use diesel_async::RunQueryDsl;
use tower::ServiceExt;

use crate::fixture::{Pg, build_router_with_quotas, connect_admin, fs_store, identified};

struct Fixture {
    pg: Pg,
    app: axum::Router,
    signer: connetto_file_server::TicketSigner,
    _dir: tempfile::TempDir,
}

async fn fixture(settings: QuotaSettings) -> Fixture {
    let pg = Pg::start().await;
    let dir = tempfile::TempDir::new().unwrap();
    let ceilings = CeilingCache::default();
    let (app, signer) = build_router_with_quotas(
        &pg,
        fs_store(&dir),
        settings,
        ceilings,
        connetto_file_server::CallerSettings::default(),
    )
    .await;
    Fixture {
        pg,
        app,
        signer,
        _dir: dir,
    }
}

/// Stages a file through intent and the chunk PUTs, returning everything the
/// commit step needs.  Split so a test can hold a file staged while it
/// arranges the ceiling state around the commit.
struct Staged {
    file_id: FileId,
    file_hex: String,
    ticket: String,
}

async fn stage(
    app: &axum::Router,
    signer: &connetto_file_server::TicketSigner,
    data: &[u8],
) -> Staged {
    let mem = MemStore::new();
    let manifest = process_file(data, MimeClass::Generic, &mem).await.unwrap();
    let file_id = manifest.file_id();
    let file_hex = format!("{file_id}");
    let file_size = u64::try_from(data.len()).unwrap();
    let ticket = signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Write,
            ceiling: file_size + 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: identified("alice"),
        })
        .unwrap();
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
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "intent"
    );
    for c in manifest.chunks() {
        let chunk_data = mem.read_chunk(&c.hash).await.unwrap();
        let hash_hex = format!("{}", c.hash);
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/chunks/{hash_hex}?t={ticket}"))
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(chunk_data))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::NO_CONTENT,
            "chunk PUT"
        );
    }
    Staged {
        file_id,
        file_hex,
        ticket,
    }
}

async fn commit(app: &axum::Router, staged: &Staged) -> axum::response::Response {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!(
            "/files/{}/commit?t={}",
            staged.file_hex, staged.ticket
        ))
        .body(axum::body::Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap()
}

async fn upload(app: &axum::Router, signer: &connetto_file_server::TicketSigner, data: &[u8]) {
    let staged = stage(app, signer, data).await;
    let resp = commit(app, &staged).await;
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "upload commit, body was {body:?}");
}

fn read_ticket(
    signer: &connetto_file_server::TicketSigner,
    file_id: &FileId,
    ceiling: u64,
) -> String {
    signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb: Verb::Read,
            ceiling,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: identified("alice"),
        })
        .unwrap()
}

#[derive(diesel::QueryableByName)]
struct TrafficRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    served_bytes: i64,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    accepted_bytes: i64,
}

/// Polls today's ledger row until the served and accepted totals reach the
/// expected values, so a test asserts the real refresh-and-ledger path
/// instead of a hand-seeded cache.
async fn await_traffic(pg: &Pg, served: i64, accepted: i64) -> TrafficRow {
    let mut conn = connect_admin(&pg.url_admin).await;
    for _ in 0..100 {
        let rows: Vec<TrafficRow> = diesel::sql_query(
            "SELECT served_bytes, accepted_bytes FROM _cfs_traffic WHERE day = CURRENT_DATE",
        )
        .load(&mut conn)
        .await
        .unwrap();
        if let Some(row) = rows.into_iter().next()
            && row.served_bytes >= served
            && row.accepted_bytes >= accepted
        {
            return row;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("ledger never reached served={served} accepted={accepted}");
}

/// `n` blocks of 4096 bytes of content distinct to `tag`.
fn chunked(tag: u8, n: usize) -> Vec<u8> {
    vec![tag; 4096 * n]
}

fn fast_refresh() -> QuotaSettings {
    QuotaSettings {
        refresh: Duration::from_millis(100),
        ..QuotaSettings::default()
    }
}

/// A commit past the uploader's own quota answers 507, the manifest stays
/// uncommitted, an upload within quota passes, and an already-committed
/// file re-commits with 200 even when the quota is now full.
#[tokio::test]
async fn commit_past_the_identity_quota_answers_507() {
    let mut settings = fast_refresh();
    settings.identity_quota = 8192;
    let fx = fixture(settings).await;

    upload(&fx.app, &fx.signer, &chunked(1, 1)).await;
    upload(&fx.app, &fx.signer, &chunked(2, 1)).await;

    let third = stage(&fx.app, &fx.signer, &chunked(3, 1)).await;
    let resp = commit(&fx.app, &third).await;
    assert_eq!(
        resp.status(),
        StatusCode::INSUFFICIENT_STORAGE,
        "a commit past the uploader's quota must answer 507"
    );

    // The refused manifest stays uncommitted: nothing was made true.
    let mut conn = connect_admin(&fx.pg.url_admin).await;
    let committed: bool = diesel::sql_query(
        "SELECT committed FROM _cfs_manifests WHERE file_id = $1 AND uploaded_by = 'user:alice'",
    )
    .bind::<Bytea, _>(third.file_id.as_bytes().as_slice())
    .get_result(&mut conn)
    .await
    .map(|r: CommittedFlag| r.committed)
    .unwrap();
    assert!(!committed, "a refused commit must not mark the manifest");

    // Re-committing an already-committed file stays 200 under a full quota:
    // it makes no new bytes true. Fresh write ticket for the first upload.
    let first_bytes = chunked(1, 1);
    let mem = MemStore::new();
    let manifest = process_file(&first_bytes, MimeClass::Generic, &mem)
        .await
        .unwrap();
    let first_id = manifest.file_id();
    let ticket = fx
        .signer
        .mint(&TicketPayload {
            file_id: *first_id.as_bytes(),
            verb: Verb::Write,
            ceiling: 4096 + 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: identified("alice"),
        })
        .unwrap();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{first_id}/commit?t={ticket}"))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = fx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "re-committing committed bytes must stay idempotent under a full quota"
    );
}

#[derive(diesel::QueryableByName)]
struct CommittedFlag {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    committed: bool,
}

/// A commit while the cached deployment storage sits at the ceiling answers
/// 503 with `Retry-After`, and an already-committed file still re-commits.
#[tokio::test]
async fn commit_past_the_storage_ceiling_answers_503_with_retry_after() {
    let mut settings = fast_refresh();
    settings.storage_ceiling = 12288;
    let fx = fixture(settings).await;

    upload(&fx.app, &fx.signer, &chunked(4, 1)).await;
    upload(&fx.app, &fx.signer, &chunked(5, 1)).await;
    upload(&fx.app, &fx.signer, &chunked(6, 1)).await;

    // Wait for the refresh task to see the full 12288 stored.
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let staged = stage(&fx.app, &fx.signer, &chunked(7, 1)).await;
        let resp = commit(&fx.app, &staged).await;
        if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
            let retry = resp
                .headers()
                .get("retry-after")
                .expect("a storage-ceiling refusal carries Retry-After")
                .to_str()
                .unwrap()
                .parse::<u64>()
                .expect("Retry-After is seconds");
            assert!(retry >= 1);
            return;
        }
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "until the refresh notices the full store the commit passes"
        );
    }
    panic!("the storage ceiling never refused a commit");
}

/// The ledger counts accepted upload bytes and served read bytes, and a
/// deployment over the bandwidth window answers reads with 503 and
/// `Retry-After`.
#[tokio::test]
async fn the_ledger_counts_both_directions_and_the_window_refuses_reads() {
    let mut settings = fast_refresh();
    settings.bandwidth_ceiling = 8192 + 1;
    let fx = fixture(settings).await;

    let staged = stage(&fx.app, &fx.signer, &chunked(8, 1)).await;
    assert_eq!(commit(&fx.app, &staged).await.status(), StatusCode::OK);
    // Accepted counted: 4096 in.
    await_traffic(&fx.pg, 0, 4096).await;

    // A served read counts its body once the body completes.
    let ticket = read_ticket(&fx.signer, &staged.file_id, 1 << 20);
    let req = axum::http::Request::builder()
        .uri(format!("/files/{}?t={}", staged.file_hex, ticket))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = fx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "read under the window");
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body.len(), 4096);
    await_traffic(&fx.pg, 4096, 4096).await;

    // The window now holds accepted + served = 8192; one more accepted
    // upload fills it past the ceiling and the next read is refused.
    upload(&fx.app, &fx.signer, &chunked(9, 1)).await;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let req = axum::http::Request::builder()
            .uri(format!("/files/{}?t={}", staged.file_hex, ticket))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = fx.app.clone().oneshot(req).await.unwrap();
        if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
            assert!(
                resp.headers()
                    .get("retry-after")
                    .expect("a bandwidth refusal carries Retry-After")
                    .to_str()
                    .unwrap()
                    .parse::<u64>()
                    .expect("Retry-After is seconds")
                    >= 1,
            );
            return;
        }
    }
    panic!("the bandwidth window never refused a read");
}

/// A commit transaction takes the per-uploader advisory lock, so a second
/// session holding that lock stops the commit and releasing it lets it
/// through.  Without the lock two concurrent commits of two different files
/// by one uploader each SUM past the other and the quota is double-spent.
#[tokio::test]
async fn a_commit_waits_on_the_uploaders_advisory_lock() {
    let fx = fixture(fast_refresh()).await;
    let staged = stage(&fx.app, &fx.signer, &chunked(10, 1)).await;

    // A separate session takes the uploader's advisory lock in a held
    // transaction: exactly what the first committer now takes itself.
    let mut blocker = connect_admin(&fx.pg.url_admin).await;
    diesel::sql_query("BEGIN")
        .execute(&mut blocker)
        .await
        .unwrap();
    diesel::sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind::<Text, _>("user:alice")
        .execute(&mut blocker)
        .await
        .unwrap();

    let app = fx.app.clone();
    let committing = {
        let staged = Staged {
            file_id: staged.file_id,
            file_hex: staged.file_hex.clone(),
            ticket: staged.ticket.clone(),
        };
        tokio::spawn(async move { commit(&app, &staged).await.status() })
    };

    // The commit must still be waiting while the lock is held.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !committing.is_finished(),
        "the commit must block on the uploader's advisory lock"
    );

    // Releasing the lock lets it finish, and it finishes committed.
    diesel::sql_query("COMMIT")
        .execute(&mut blocker)
        .await
        .unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), committing)
        .await
        .expect("the commit proceeds once the lock is released")
        .unwrap();
    assert_eq!(status, StatusCode::OK);

    let mut conn = connect_admin(&fx.pg.url_admin).await;
    let committed: bool = diesel::sql_query(
        "SELECT committed FROM _cfs_manifests WHERE file_id = $1 AND uploaded_by = 'user:alice'",
    )
    .bind::<Bytea, _>(staged.file_id.as_bytes().as_slice())
    .get_result(&mut conn)
    .await
    .map(|r: CommittedFlag| r.committed)
    .unwrap();
    assert!(committed, "the unblocked commit committed");
}
