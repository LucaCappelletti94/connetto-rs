//! Tests for the upload negotiation, driven through [`ContentClient::flush_outbox`].
//!
//! A [`Scripted`] transport grants tickets without a real server, and a local
//! [`SmartHttp`] records every HTTP call and answers intent requests by
//! returning a chosen subset of the declared chunk hashes as needed.

use core::future::ready;
use std::io;
use std::sync::{Arc, Mutex};

use connetto_file_client::{ContentClient, ContentEvent, ContentHttp, FsStore, HttpReply};
use connetto_file_core::MimeClass;
use tempfile::tempdir;

use crate::support::{ROOT_KEY, RecordingHttp, Scripted, Sent, connected_client};

/// A `ContentHttp` that answers intent requests dynamically.
///
/// The first `take_first_n` hashes from the intent body's `chunks` array are
/// returned in `needed`; the rest are omitted. Commit requests answer 200 and
/// chunk `PUT`s answer 204. Every request is recorded.
#[derive(Clone)]
struct SmartHttp {
    sent: Arc<Mutex<Vec<Sent>>>,
    take_first_n: usize,
}

impl SmartHttp {
    /// All declared chunks are marked needed, driving a full upload.
    fn all_needed() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
            take_first_n: usize::MAX,
        }
    }

    /// No declared chunks are marked needed, so no `PUT` goes out.
    fn none_needed() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
            take_first_n: 0,
        }
    }

    /// Every request recorded since construction.
    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().expect("sent lock").clone()
    }
}

impl ContentHttp for SmartHttp {
    type Error = core::convert::Infallible;

    fn post(
        &self,
        url: &str,
        json: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<HttpReply, Self::Error>> {
        let body = json.unwrap_or_default();
        self.sent.lock().expect("sent lock").push(Sent {
            method: "POST",
            url: url.to_owned(),
            body: body.clone(),
        });
        if url.contains("/intent") {
            let intent: serde_json::Value =
                serde_json::from_slice(&body).expect("intent body is valid JSON");
            let all: Vec<serde_json::Value> = intent["chunks"]
                .as_array()
                .expect("intent body has chunks array")
                .iter()
                .map(|c| c["hash"].clone())
                .collect();
            let needed: Vec<serde_json::Value> = all.into_iter().take(self.take_first_n).collect();
            let reply_body =
                serde_json::to_vec(&serde_json::json!({ "needed": needed })).expect("encode");
            ready(Ok(HttpReply {
                status: 200,
                body: reply_body,
            }))
        } else {
            ready(Ok(HttpReply {
                status: 200,
                body: b"{}".to_vec(),
            }))
        }
    }

    fn put(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<HttpReply, Self::Error>> {
        self.sent.lock().expect("sent lock").push(Sent {
            method: "PUT",
            url: url.to_owned(),
            body,
        });
        ready(Ok(HttpReply {
            status: 204,
            body: Vec::new(),
        }))
    }

    fn get(
        &self,
        _url: &str,
        _range: Option<(u64, u64)>,
    ) -> impl Future<Output = Result<HttpReply, Self::Error>> {
        ready(Ok(HttpReply {
            status: 404,
            body: Vec::new(),
        }))
    }
}

/// A syntactically valid intent URL at a fixed file hex and token, for tests
/// that do not need the grant to name the actual staged file.
///
/// Parsing this URL yields base `http://files.test` and token `TOKEN`.
const FAKE_INTENT: &str = "http://files.test/files/\
    0000000000000000000000000000000000000000000000000000000000000000/intent?t=TOKEN";

/// A grant URL with no `?t=` query, which the upload code must refuse without
/// sending any HTTP request.
const MALFORMED_INTENT: &str = "http://files.test/files/\
    0000000000000000000000000000000000000000000000000000000000000000/intent";

/// Creates a connected content client in `dir` with `http` and stages a
/// generic payload, so the outbox has one entry ready for the next flush.
async fn staged_outbox_entry(
    dir: &std::path::Path,
    http: RecordingHttp,
) -> ContentClient<Scripted, FsStore, RecordingHttp> {
    let client =
        connected_client(&dir.join("replica.sqlite"), Scripted::granting(FAKE_INTENT)).await;
    let cc = ContentClient::attach(client, FsStore::new(dir.join("chunks")), ROOT_KEY, http)
        .await
        .expect("attach");
    cc.stage(
        io::Cursor::new(b"payload"),
        MimeClass::Generic,
        |_conn, _id| Ok(()),
    )
    .await
    .expect("stage");
    cc
}

/// Asserts that `sent` starts with the intent `POST` at `intent_url`, contains
/// chunk `PUT`s at the correct base URL with the same token, and ends with a
/// commit `POST` naming `file_id`.
fn assert_upload_request_shapes(
    sent: &[Sent],
    file_id: connetto_file_core::FileId,
    intent_url: &str,
) {
    assert!(!sent.is_empty(), "at least one request must have been sent");
    assert_eq!(
        sent[0].method, "POST",
        "first request must be the intent POST"
    );
    assert_eq!(
        sent[0].url, intent_url,
        "intent POST must use the granted URL verbatim, token and all"
    );
    let puts: Vec<&Sent> = sent.iter().filter(|s| s.method == "PUT").collect();
    assert!(!puts.is_empty(), "at least one chunk PUT must be sent");
    for put in &puts {
        assert!(
            put.url.starts_with("http://files.test/chunks/"),
            "chunk PUT must be at <base>/chunks/<hex>, got {}",
            put.url
        );
        assert!(
            put.url.ends_with("?t=TOKEN"),
            "chunk PUT must carry the same token as the grant, got {}",
            put.url
        );
    }
    let last = sent.last().expect("commit must exist");
    assert_eq!(last.method, "POST", "last request must be the commit POST");
    assert_eq!(
        last.url,
        format!("http://files.test/files/{file_id}/commit?t=TOKEN"),
        "commit POST must name the actual file identity and carry the same token"
    );
}

/// The three upload addresses are derived correctly from one granted intent URL.
///
/// The intent `POST` carries the granted URL verbatim. The chunk `PUT`
/// addresses carry the same base and token. The commit `POST` names the actual
/// file identity (from the manifest, not from the grant URL's path) and the
/// same token, proving the upload code uses all three address shapes correctly.
#[tokio::test]
async fn three_upload_addresses_derived_from_granted_intent_url() {
    let dir = tempdir().expect("temp dir");
    let replica = dir.path().join("replica.sqlite");
    let chunks = dir.path().join("chunks");

    let http = SmartHttp::all_needed();
    let http_ref = http.clone();
    let client = connected_client(&replica, Scripted::granting(FAKE_INTENT)).await;
    let cc = ContentClient::attach(client, FsStore::new(&chunks), ROOT_KEY, http)
        .await
        .expect("attach");
    let (file_id, ()) = cc
        .stage(
            io::Cursor::new(b"one chunk of known content"),
            MimeClass::Generic,
            |_conn, _id| Ok(()),
        )
        .await
        .expect("stage");
    cc.flush_outbox().await.expect("flush");

    let sent = http_ref.sent();
    assert_upload_request_shapes(&sent, file_id, FAKE_INTENT);
}

/// A chunk the intent answer does not declare needed is not sent; the commit still happens.
#[tokio::test]
async fn chunk_not_in_needed_list_is_not_sent_and_commit_still_happens() {
    let dir = tempdir().expect("temp dir");
    let replica = dir.path().join("replica.sqlite");
    let chunks = dir.path().join("chunks");

    let http = SmartHttp::none_needed();
    let http_ref = http.clone();
    let client = connected_client(&replica, Scripted::granting(FAKE_INTENT)).await;
    let cc = ContentClient::attach(client, FsStore::new(&chunks), ROOT_KEY, http)
        .await
        .expect("attach");
    cc.stage(
        io::Cursor::new(b"some content that becomes one chunk"),
        MimeClass::Generic,
        |_conn, _id| Ok(()),
    )
    .await
    .expect("stage");
    cc.flush_outbox().await.expect("flush");

    let sent = http_ref.sent();
    let put_count = sent.iter().filter(|s| s.method == "PUT").count();
    assert_eq!(
        put_count, 0,
        "no PUT must be sent for a chunk the intent did not declare needed"
    );
    let commit_count = sent
        .iter()
        .filter(|s| s.method == "POST" && s.url.contains("/commit"))
        .count();
    assert_eq!(
        commit_count, 1,
        "commit must still happen even when the intent declares no chunks needed"
    );
}

/// The bytes that leave in a `PUT` are the original plaintext, not the ciphertext on disk.
///
/// The chunk store holds `XChaCha20-Poly1305` ciphertext. The upload path
/// decrypts before sending so the file server can verify the `BLAKE3` of each
/// chunk body against the hash in the `PUT` URL.
#[tokio::test]
async fn put_bodies_are_plaintext_not_ciphertext() {
    let dir = tempdir().expect("temp dir");
    let replica = dir.path().join("replica.sqlite");
    let chunks = dir.path().join("chunks");

    let content: &[u8] = b"known plaintext content for upload verification";
    let http = SmartHttp::all_needed();
    let http_ref = http.clone();
    let client = connected_client(&replica, Scripted::granting(FAKE_INTENT)).await;
    let cc = ContentClient::attach(client, FsStore::new(&chunks), ROOT_KEY, http)
        .await
        .expect("attach");
    cc.stage(
        io::Cursor::new(content),
        MimeClass::Generic,
        |_conn, _id| Ok(()),
    )
    .await
    .expect("stage");
    cc.flush_outbox().await.expect("flush");

    let sent = http_ref.sent();
    let put_bytes: Vec<u8> = sent
        .iter()
        .filter(|s| s.method == "PUT")
        .flat_map(|s| s.body.iter().copied())
        .collect();
    assert!(
        !put_bytes.is_empty(),
        "at least one PUT must have been sent"
    );
    assert_eq!(
        put_bytes, content,
        "PUT bodies must be plaintext; sending the on-disk ciphertext would fail the server's hash check"
    );
}

/// `HTTP 413` at the intent stage retires the outbox entry; `HTTP 503` keeps it for retry.
///
/// Both cases are proved through the `ContentEvent` stream and through a
/// second `flush_outbox` that either finds the outbox empty (413) or retries
/// and defers again (503).
#[tokio::test]
async fn http_413_retires_entry_and_503_keeps_it_for_retry() {
    let permanent = tempdir().expect("temp dir");
    let cc = staged_outbox_entry(permanent.path(), RecordingHttp::new([(413_u16, vec![])])).await;
    let mut events = cc.events();
    cc.flush_outbox().await.expect("first flush");
    let ev = events
        .try_recv()
        .expect("UploadRefused must arrive after 413");
    assert!(
        matches!(ev, ContentEvent::UploadRefused { .. }),
        "413 must produce UploadRefused; got {ev:?}"
    );
    cc.flush_outbox().await.expect("second flush");
    assert!(
        events.try_recv().is_err(),
        "outbox is empty after 413 retires the entry; second flush must produce no event"
    );

    let transient = tempdir().expect("temp dir");
    let cc = staged_outbox_entry(
        transient.path(),
        RecordingHttp::new([(503_u16, vec![]), (503_u16, vec![])]),
    )
    .await;
    let mut events = cc.events();
    cc.flush_outbox().await.expect("first flush");
    assert_deferred(&mut events, "UploadDeferred must arrive after first 503");
    cc.flush_outbox().await.expect("second flush");
    assert_deferred(
        &mut events,
        "503 on second flush must produce UploadDeferred again (entry stayed)",
    );
}

/// Asserts the next content event defers an upload, carrying `why` on failure.
fn assert_deferred(events: &mut tokio::sync::broadcast::Receiver<ContentEvent>, why: &str) {
    let event = events.try_recv().expect(why);
    assert!(
        matches!(event, ContentEvent::UploadDeferred { .. }),
        "{why}, got {event:?}"
    );
}

/// A granted URL without a `?t=` query is refused before any HTTP request is sent.
#[tokio::test]
async fn malformed_grant_url_sends_no_requests_and_retires_entry() {
    let dir = tempdir().expect("temp dir");
    let replica = dir.path().join("replica.sqlite");
    let chunks = dir.path().join("chunks");

    let http = RecordingHttp::new(std::iter::empty::<(u16, Vec<u8>)>());
    let http_ref = http.clone();
    let client = connected_client(&replica, Scripted::granting(MALFORMED_INTENT)).await;
    let cc = ContentClient::attach(client, FsStore::new(&chunks), ROOT_KEY, http)
        .await
        .expect("attach");
    cc.stage(
        io::Cursor::new(b"content"),
        MimeClass::Generic,
        |_conn, _id| Ok(()),
    )
    .await
    .expect("stage");
    let mut events = cc.events();

    cc.flush_outbox().await.expect("flush");

    assert!(
        http_ref.sent().is_empty(),
        "no HTTP request must be sent when the grant URL has no ?t= query"
    );
    let ev = events.try_recv().expect("UploadRefused event must arrive");
    assert!(
        matches!(ev, ContentEvent::UploadRefused { .. }),
        "a malformed grant URL must produce UploadRefused; got {ev:?}"
    );
}
