//! R70 decisions 7, 11, 12, 13 and 15: the boot pass that brings the chunk
//! store and the database back into step after a restore, and healing.
//!
//! A restore rewinds manifests and registry rows and never the store, so each
//! disagreement is built directly here. A committed manifest whose bytes are
//! gone is what a restore produces when the sweep removed the bytes after the
//! backup, and bytes nothing names are what it produces for uploads made after
//! the backup.

use axum::http::StatusCode;
use connetto_file_core::{ChunkMeta, ChunkStore, FileId, MemStore, MimeClass, process_file};
use connetto_file_server::ticket::{TicketPayload, Verb};
use connetto_file_server::{
    AnyStore, CallerSettings, DefaultFileSchema, FsStore, ReconcileError, TicketSigner,
    reconcile_store,
};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use tower::ServiceExt;

use crate::fixture::{
    Pg, build_router, connect_admin, fs_store, identified, insert_committed_manifest,
};

mod tables {
    connetto_file_server::connetto_file_tables!();
}
use tables::{_cfs_chunk_registry as registry, _cfs_manifests as manifests};

diesel::table! {
    /// Every state the deployment's setter was handed, in call order.
    test_content_states (seq) {
        seq -> Integer,
        file_id -> Bytea,
        state -> Text,
        caller -> Text,
    }
}

/// A setter that also records each call, so a test can read what the
/// application was told and on whose behalf.
const RECORDING_SETTER: &[&str] = &[
    "CREATE TABLE test_content_states (
         seq SERIAL PRIMARY KEY, file_id BYTEA NOT NULL, state TEXT NOT NULL, caller TEXT NOT NULL)",
    "CREATE OR REPLACE FUNCTION connetto_set_content_state(
         p_file_id BYTEA, p_new_state TEXT, p_caller TEXT
     ) RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER
         SET search_path TO '' AS $$
     BEGIN
         INSERT INTO public.test_file_metadata (file_id, uploaded_by)
         VALUES (p_file_id, p_caller) ON CONFLICT DO NOTHING;
         INSERT INTO public.test_content_states (file_id, state, caller)
         VALUES (p_file_id, p_new_state, p_caller);
         RETURN p_file_id;
     END;
     $$",
];

/// Five mebibytes of noise, which the generic chunker splits into several
/// chunks, so a file can lose one chunk and keep the rest.
fn several_chunks() -> Vec<u8> {
    let mut state: u64 = 0x5eed_1234_abcd_0001;
    (0..5 * 1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

struct Setup {
    pg: Pg,
    dir: tempfile::TempDir,
    data: Vec<u8>,
    mem: MemStore,
    file_id: FileId,
    chunks: Vec<ChunkMeta>,
}

/// Alice's committed file whose first chunk's bytes are gone from the store.
async fn a_committed_file_missing_one_chunk() -> Setup {
    let pg = Pg::start().await;
    let mut conn = connect_admin(&pg.url_admin).await;
    for stmt in RECORDING_SETTER {
        diesel::sql_query(*stmt)
            .execute(&mut conn)
            .await
            .expect("install the recording setter");
    }
    let dir = tempfile::TempDir::new().unwrap();
    let data = several_chunks();
    let mem = MemStore::new();
    let manifest = process_file(&data, MimeClass::Generic, &mem).await.unwrap();
    let chunks = manifest.chunks().to_vec();
    assert!(chunks.len() >= 2, "the file must span several chunks");
    let fs = FsStore::new(dir.path()).unwrap();
    for c in &chunks[1..] {
        fs.write_chunk(&c.hash, &mem.read_chunk(&c.hash).await.unwrap())
            .await
            .unwrap();
    }
    let file_id = manifest.file_id();
    insert_committed_manifest(&mut conn, &file_id, &identified("alice"), &chunks).await;
    Setup {
        pg,
        dir,
        data,
        mem,
        file_id,
        chunks,
    }
}

async fn reconcile(
    setup: &Setup,
    grace: std::time::Duration,
) -> Result<connetto_file_server::StoreReconciled, ReconcileError> {
    reconcile_store::<DefaultFileSchema>(
        &setup.pg.admin_pool().await,
        &fs_store(&setup.dir),
        &CallerSettings::default(),
        grace,
    )
    .await
}

const HOUR: std::time::Duration = std::time::Duration::from_secs(3600);

async fn states(conn: &mut AsyncPgConnection) -> Vec<(String, String)> {
    test_content_states::table
        .order(test_content_states::seq)
        .select((test_content_states::state, test_content_states::caller))
        .load(conn)
        .await
        .expect("read the setter's calls")
}

/// `(uploaded_by, committed, lost)` for every manifest of `file_id`.
async fn manifest_rows(
    conn: &mut AsyncPgConnection,
    file_id: &FileId,
) -> Vec<(String, bool, bool)> {
    manifests::table
        .filter(manifests::file_id.eq(file_id.as_bytes().to_vec()))
        .order(manifests::uploaded_by)
        .select((
            manifests::uploaded_by,
            manifests::committed,
            manifests::lost,
        ))
        .load(conn)
        .await
        .expect("read the manifests")
}

async fn registry_state(conn: &mut AsyncPgConnection, chunk: &ChunkMeta) -> Option<String> {
    registry::table
        .filter(registry::chunk_hash.eq(chunk.hash.as_bytes().to_vec()))
        .select(registry::state)
        .first(conn)
        .await
        .ok()
}

fn ticket(signer: &TicketSigner, file_id: &FileId, verb: Verb, who: &str) -> String {
    signer
        .mint(&TicketPayload {
            file_id: *file_id.as_bytes(),
            verb,
            ceiling: 64 * 1024 * 1024,
            expiry: chrono::Utc::now().timestamp() + 3600,
            caller: identified(who),
        })
        .unwrap()
}

async fn download(
    app: &axum::Router,
    signer: &TicketSigner,
    file_id: &FileId,
) -> (StatusCode, Vec<u8>) {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri(format!(
            "/files/{file_id}?t={}",
            ticket(signer, file_id, Verb::Read, "alice")
        ))
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024 * 1024)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    (status, body)
}

/// Upload `setup`'s file as `who` under `setup`'s own chunking, returning the intent's answer.
async fn upload(
    app: &axum::Router,
    signer: &TicketSigner,
    setup: &Setup,
    who: &str,
) -> Vec<String> {
    upload_chunked(app, signer, setup, who, &setup.chunks, &setup.mem).await
}

/// Upload `setup`'s file as `who` declaring `chunks`, putting only what the intent answer asks for.
async fn upload_chunked(
    app: &axum::Router,
    signer: &TicketSigner,
    setup: &Setup,
    who: &str,
    chunks: &[ChunkMeta],
    mem: &MemStore,
) -> Vec<String> {
    let write = ticket(signer, &setup.file_id, Verb::Write, who);
    let body = serde_json::json!({
        "total_len": setup.data.len(),
        "chunks": chunks.iter()
            .map(|c| serde_json::json!({ "hash": c.hash.to_string(), "len": c.len }))
            .collect::<Vec<_>>(),
    });
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{}/intent?t={write}", setup.file_id))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "intent");
    let answer: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap(),
    )
    .unwrap();
    let needed: Vec<String> = answer["needed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap().to_owned())
        .collect();
    for c in chunks {
        if !needed.contains(&c.hash.to_string()) {
            continue;
        }
        let req = axum::http::Request::builder()
            .method("PUT")
            .uri(format!("/chunks/{}?t={write}", c.hash))
            .header("content-type", "application/octet-stream")
            .body(axum::body::Body::from(
                mem.read_chunk(&c.hash).await.unwrap(),
            ))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::NO_CONTENT,
            "chunk PUT"
        );
    }
    assert_eq!(
        commit(app, signer, setup, who).await,
        StatusCode::OK,
        "commit"
    );
    needed
}

/// Commit `setup`'s file as `who`, returning the status.
async fn commit(app: &axum::Router, signer: &TicketSigner, setup: &Setup, who: &str) -> StatusCode {
    let write = ticket(signer, &setup.file_id, Verb::Write, who);
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/files/{}/commit?t={write}", setup.file_id))
        .body(axum::body::Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn a_file_whose_bytes_are_gone_turns_lost_and_stops_serving() {
    let setup = a_committed_file_missing_one_chunk().await;
    let (app, signer) = build_router(&setup.pg, fs_store(&setup.dir)).await;

    let reconciled = reconcile(&setup, HOUR).await.expect("the pass runs");
    assert_eq!(reconciled.lost, vec![setup.file_id]);

    let mut conn = connect_admin(&setup.pg.url_admin).await;
    assert_eq!(
        manifest_rows(&mut conn, &setup.file_id).await,
        vec![("user:alice".to_owned(), false, true)],
        "the manifest is kept, uncommitted and marked lost"
    );
    assert_eq!(
        states(&mut conn).await,
        vec![("lost".to_owned(), "alice".to_owned())],
        "the application is told, on the uploader's behalf"
    );
    assert_eq!(
        registry_state(&mut conn, &setup.chunks[0]).await.as_deref(),
        Some("pending"),
        "the missing chunk is declared and not written, so a PUT is accepted again"
    );
    assert_eq!(
        registry_state(&mut conn, &setup.chunks[1]).await.as_deref(),
        Some("stored")
    );
    assert_eq!(
        download(&app, &signer, &setup.file_id).await.0,
        StatusCode::NOT_FOUND,
        "a read is refused before anything streams"
    );

    connetto_file_server::sweep::<DefaultFileSchema>(
        &setup.pg.admin_pool().await,
        &fs_store(&setup.dir),
        std::time::Duration::ZERO,
    )
    .await
    .unwrap();
    assert_eq!(
        manifest_rows(&mut conn, &setup.file_id).await.len(),
        1,
        "the sweep never collects a lost manifest"
    );
    assert!(
        FsStore::new(setup.dir.path())
            .unwrap()
            .has_chunk(&setup.chunks[1].hash)
            .await
            .unwrap(),
        "nor the bytes it still names"
    );

    let again = reconcile(&setup, HOUR).await.expect("the pass runs again");
    assert!(again.lost.is_empty(), "a second boot finds nothing new");
    assert_eq!(states(&mut conn).await.len(), 1);
}

#[tokio::test]
async fn bytes_nothing_names_are_deleted_once_past_the_grace_window() {
    let setup = a_committed_file_missing_one_chunk().await;
    let stray = connetto_file_core::ChunkHash::from_bytes([0xAB; 32]);
    let fs = FsStore::new(setup.dir.path()).unwrap();
    fs.write_chunk(&stray, b"uploaded after the backup")
        .await
        .unwrap();

    let kept = reconcile(&setup, HOUR).await.unwrap();
    assert_eq!(kept.orphans_removed, 0);
    assert!(
        fs.has_chunk(&stray).await.unwrap(),
        "younger than the grace window"
    );

    let swept = reconcile(&setup, std::time::Duration::ZERO).await.unwrap();
    assert_eq!(swept.orphans_removed, 1);
    assert!(!fs.has_chunk(&stray).await.unwrap());
    assert!(
        fs.has_chunk(&setup.chunks[1].hash).await.unwrap(),
        "bytes a manifest names are never orphans"
    );
}

#[tokio::test]
async fn the_uploader_heals_by_sending_only_the_missing_bytes() {
    let setup = a_committed_file_missing_one_chunk().await;
    let (app, signer) = build_router(&setup.pg, fs_store(&setup.dir)).await;
    reconcile(&setup, HOUR).await.unwrap();

    let needed = upload(&app, &signer, &setup, "alice").await;
    assert_eq!(needed, vec![setup.chunks[0].hash.to_string()]);

    let (status, body) = download(&app, &signer, &setup.file_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        FileId::from_chunks([&body[..]]),
        setup.file_id,
        "the whole file serves again"
    );
    let mut conn = connect_admin(&setup.pg.url_admin).await;
    assert_eq!(
        manifest_rows(&mut conn, &setup.file_id).await,
        vec![("user:alice".to_owned(), true, false)]
    );
    assert_eq!(
        states(&mut conn).await.last(),
        Some(&("available".to_owned(), "alice".to_owned()))
    );
}

#[tokio::test]
async fn a_viewer_heals_and_the_uploader_keeps_the_file() {
    let setup = a_committed_file_missing_one_chunk().await;
    let (app, signer) = build_router(&setup.pg, fs_store(&setup.dir)).await;
    reconcile(&setup, HOUR).await.unwrap();

    upload(&app, &signer, &setup, "bob").await;

    let (status, body) = download(&app, &signer, &setup.file_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(FileId::from_chunks([&body[..]]), setup.file_id);
    let mut conn = connect_admin(&setup.pg.url_admin).await;
    assert_eq!(
        manifest_rows(&mut conn, &setup.file_id).await,
        vec![("user:alice".to_owned(), true, false)],
        "the healer's own manifest is gone, so quota and ownership stay with alice"
    );
    assert!(
        !states(&mut conn).await.iter().any(|(_, who)| who == "bob"),
        "the setter never hears the healer's name"
    );
    assert_eq!(
        states(&mut conn).await.last(),
        Some(&("available".to_owned(), "alice".to_owned()))
    );
}

#[tokio::test]
async fn a_viewer_retrying_its_heal_commit_is_answered_ok_and_still_owns_nothing() {
    let setup = a_committed_file_missing_one_chunk().await;
    let (app, signer) = build_router(&setup.pg, fs_store(&setup.dir)).await;
    reconcile(&setup, HOUR).await.unwrap();
    upload(&app, &signer, &setup, "bob").await;

    assert_eq!(
        commit(&app, &signer, &setup, "bob").await,
        StatusCode::OK,
        "a retry after a lost answer must not read as a missing upload"
    );
    let mut conn = connect_admin(&setup.pg.url_admin).await;
    assert_eq!(
        manifest_rows(&mut conn, &setup.file_id).await,
        vec![("user:alice".to_owned(), true, false)]
    );
    assert!(!states(&mut conn).await.iter().any(|(_, who)| who == "bob"));
}

#[tokio::test]
async fn a_healer_chunking_the_file_differently_restores_every_manifest_whole() {
    let setup = a_committed_file_missing_one_chunk().await;
    let (app, signer) = build_router(&setup.pg, fs_store(&setup.dir)).await;
    reconcile(&setup, HOUR).await.unwrap();

    let mem = MemStore::new();
    let rechunked = process_file(&setup.data, MimeClass::Jpeg, &mem)
        .await
        .unwrap();
    assert_eq!(rechunked.file_id(), setup.file_id);
    assert_ne!(
        rechunked.chunks(),
        setup.chunks.as_slice(),
        "the healer's device chunked the same bytes its own way"
    );
    upload_chunked(&app, &signer, &setup, "bob", rechunked.chunks(), &mem).await;

    connetto_file_server::sweep::<DefaultFileSchema>(
        &setup.pg.admin_pool().await,
        &fs_store(&setup.dir),
        std::time::Duration::ZERO,
    )
    .await
    .unwrap();
    assert!(
        reconcile(&setup, HOUR).await.unwrap().lost.is_empty(),
        "every chunk the restored manifest names is in the store"
    );
    let (status, body) = download(&app, &signer, &setup.file_id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(FileId::from_chunks([&body[..]]), setup.file_id);
    let mut conn = connect_admin(&setup.pg.url_admin).await;
    assert_eq!(
        manifest_rows(&mut conn, &setup.file_id).await,
        vec![("user:alice".to_owned(), true, false)]
    );
}

#[tokio::test]
async fn a_setter_refusing_lost_stops_the_pass_and_names_the_file() {
    let setup = a_committed_file_missing_one_chunk().await;
    let mut conn = connect_admin(&setup.pg.url_admin).await;
    diesel::sql_query(
        "CREATE OR REPLACE FUNCTION connetto_set_content_state(
             p_file_id BYTEA, p_new_state TEXT, p_caller TEXT
         ) RETURNS BYTEA LANGUAGE plpgsql SECURITY DEFINER
             SET search_path TO '' AS $$
         BEGIN
             IF p_new_state = 'lost' THEN RAISE EXCEPTION 'content_state check'; END IF;
             RETURN p_file_id;
         END;
         $$",
    )
    .execute(&mut conn)
    .await
    .unwrap();

    let err = reconcile(&setup, HOUR)
        .await
        .expect_err("the pass must stop");
    assert!(
        matches!(&err, ReconcileError::Setter { file_id, .. } if *file_id == setup.file_id),
        "{err:?}"
    );
    assert_eq!(
        manifest_rows(&mut conn, &setup.file_id).await,
        vec![("user:alice".to_owned(), true, false)],
        "the refused file's marking rolled back whole"
    );
    assert_eq!(
        registry_state(&mut conn, &setup.chunks[0]).await.as_deref(),
        Some("stored"),
        "the registry is only rewritten once every file is marked"
    );
}

#[tokio::test]
async fn an_object_store_lists_what_it_holds() {
    let dir = tempfile::TempDir::new().unwrap();
    let store = AnyStore::from_url(&url::Url::from_file_path(dir.path()).unwrap()).unwrap();
    let a = connetto_file_core::ChunkHash::from_bytes([1; 32]);
    let b = connetto_file_core::ChunkHash::from_bytes([2; 32]);
    store
        .write(&a, bytes::Bytes::from_static(b"a"))
        .await
        .unwrap();
    store
        .write(&b, bytes::Bytes::from_static(b"b"))
        .await
        .unwrap();
    let mut listed: Vec<_> = store
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.hash)
        .collect();
    listed.sort_by_key(|h| *h.as_bytes());
    assert_eq!(listed, vec![a, b]);
}
