//! Shared scaffolding: an offline replica, a transport that grants tickets,
//! and an HTTP fake that records what the negotiation sent.

use core::future::{Future, ready};
use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use connetto_client::live::ConnettoClient;
use connetto_client::{ClientConfig, ConnettoConnection, Grant, Replica};
use connetto_core::Cursor;
use connetto_core::messages::{
    BulkMessage, ContentTicketGrant, ControlMessage, HandshakeAck, NonFatalError,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_file_client::{ContentClient, ContentHttp, FsStore, HttpReply};
use connetto_file_core::{FileId, MimeClass};
use diesel::prelude::*;

/// The application's own table: a photo entry naming its content.
pub const DDL: &str = "CREATE TABLE photos (id INTEGER PRIMARY KEY, \
                       content_id BLOB NOT NULL, content_state TEXT)";

diesel::table! {
    /// The application's photo entries.
    photos (id) {
        /// Entry identifier.
        id -> Integer,
        /// BLAKE3 identity of the photo's bytes.
        content_id -> diesel::sql_types::Binary,
        /// Availability of the bytes, as the server last said.
        content_state -> Nullable<diesel::sql_types::Text>,
    }
}

/// What a scripted transport answers a ticket request with.
#[derive(Clone)]
pub enum TicketAnswer {
    /// Grant this URL, with the request's own correlation token.
    Grant(String),
    /// Refuse with this detail.
    Refuse(String),
}

/// A transport that completes a handshake and answers ticket requests from a
/// script, so a test drives the whole content path with no server.
///
/// Everything else it is sent is discarded: a mutation upload has nowhere to
/// go here, and the content tests never assert on one.
#[derive(Clone)]
pub struct Scripted {
    greeted: Arc<AtomicBool>,
    answers: Arc<Mutex<VecDeque<TicketAnswer>>>,
    queued: Arc<Mutex<VecDeque<ControlMessage>>>,
}

impl Scripted {
    /// A transport that answers each ticket request with the next scripted
    /// answer, and refuses once the script runs out.
    pub fn new(answers: impl IntoIterator<Item = TicketAnswer>) -> Self {
        Self {
            greeted: Arc::new(AtomicBool::new(false)),
            answers: Arc::new(Mutex::new(answers.into_iter().collect())),
            queued: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// A transport that grants the same URL to every request.
    pub fn granting(url: &str) -> Self {
        Self::new(core::iter::repeat_n(
            TicketAnswer::Grant(url.to_owned()),
            64,
        ))
    }
}

impl Transport for Scripted {
    type Error = core::convert::Infallible;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        if let ControlMessage::ContentTicketRequest(request) = message {
            let answer = self
                .answers
                .lock()
                .expect("answers lock")
                .pop_front()
                .unwrap_or_else(|| {
                    TicketAnswer::Refuse(connetto_core::messages::CONTENT_TICKET_REFUSED.to_owned())
                });
            let reply = match answer {
                TicketAnswer::Grant(url) => {
                    ControlMessage::ContentTicketGrant(ContentTicketGrant {
                        request_id: request.request_id,
                        url,
                    })
                }
                TicketAnswer::Refuse(detail) => ControlMessage::NonFatalError(NonFatalError {
                    related_to: Some(request.request_id),
                    detail,
                }),
            };
            self.queued.lock().expect("queued lock").push_back(reply);
        }
        ready(Ok(()))
    }

    fn send_bulk(
        &mut self,
        _message: BulkMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }

    /// Waits rather than ending the stream when there is nothing to say.
    ///
    /// A `None` here would tell the client the connection closed, and a
    /// closed connection abandons a ticket request that is still in flight,
    /// so this transport stays open the way a real one does.
    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        if !self.greeted.swap(true, Ordering::Relaxed) {
            return Ok(Some(IncomingFrame::Control(ControlMessage::HandshakeAck(
                HandshakeAck {
                    connection_id: "scripted".to_owned(),
                    session_token: "scripted".to_owned(),
                    resume_token: "scripted".to_owned(),
                    current_cursor: Cursor::new(Vec::new()),
                    schema_version: None,
                    initial_credits: 64,
                    last_applied_seq: None,
                },
            ))));
        }
        loop {
            if let Some(next) = self.queued.lock().expect("queued lock").pop_front() {
                return Ok(Some(IncomingFrame::Control(next)));
            }
            tokio::time::sleep(core::time::Duration::from_millis(1)).await;
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }
}

/// One request the negotiation sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    /// The HTTP method.
    pub method: &'static str,
    /// The address it went to, ticket query included.
    pub url: String,
    /// The body, empty when there was none.
    pub body: Vec<u8>,
}

/// An HTTP fake that records every request and answers from a status script.
#[derive(Clone, Default)]
pub struct RecordingHttp {
    sent: Arc<Mutex<Vec<Sent>>>,
    replies: Arc<Mutex<VecDeque<HttpReply>>>,
}

impl RecordingHttp {
    /// A fake whose answers come from `replies`, in order.
    pub fn new(replies: impl IntoIterator<Item = (u16, Vec<u8>)>) -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
            replies: Arc::new(Mutex::new(
                replies
                    .into_iter()
                    .map(|(status, body)| HttpReply { status, body })
                    .collect(),
            )),
        }
    }

    /// Everything sent so far.
    pub fn sent(&self) -> Vec<Sent> {
        self.sent.lock().expect("sent lock").clone()
    }

    /// Records one request and takes the next scripted answer.
    fn answer(&self, method: &'static str, url: &str, body: Vec<u8>) -> HttpReply {
        self.sent.lock().expect("sent lock").push(Sent {
            method,
            url: url.to_owned(),
            body,
        });
        self.replies
            .lock()
            .expect("replies lock")
            .pop_front()
            .unwrap_or(HttpReply {
                status: 500,
                body: Vec::new(),
            })
    }
}

impl ContentHttp for RecordingHttp {
    type Error = core::convert::Infallible;

    fn post(
        &self,
        url: &str,
        json: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<HttpReply, Self::Error>> {
        ready(Ok(self.answer("POST", url, json.unwrap_or_default())))
    }

    fn put(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<HttpReply, Self::Error>> {
        ready(Ok(self.answer("PUT", url, body)))
    }

    fn get(
        &self,
        url: &str,
        _range: Option<(u64, u64)>,
    ) -> impl Future<Output = Result<HttpReply, Self::Error>> {
        ready(Ok(self.answer("GET", url, Vec::new())))
    }
}

/// The client configuration every content test opens with.
pub fn config() -> ClientConfig {
    ClientConfig::new("r67-content").with_login(Some(Grant::new("user:tester")))
}

/// The root key the encrypting store derives from, fixed so a reopened
/// replica reads its own chunks.
pub const ROOT_KEY: [u8; 32] = [9; 32];

/// Opens a replica at `path` and returns a client with no transport attached.
///
/// Nothing is connected, which is the state the offline half of every case
/// needs.
pub fn offline_client(path: &std::path::Path) -> ConnettoClient<Scripted> {
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");
    let conn = ConnettoConnection::<Scripted>::open(&replica, DDL, &config(), None)
        .expect("open with no server");
    ConnettoClient::start(conn)
}

/// Opens a replica at `path` and attaches `transport`, so the client counts as
/// connected and can be granted tickets.
pub async fn connected_client(
    path: &std::path::Path,
    transport: Scripted,
) -> ConnettoClient<Scripted> {
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");
    let mut conn = ConnettoConnection::<Scripted>::open(&replica, DDL, &config(), None)
        .expect("open with no server");
    conn.attach(transport).await.expect("attach the transport");
    ConnettoClient::start(conn)
}

/// A content client over a filesystem store in `chunks`.
pub async fn attach_content(
    client: ConnettoClient<Scripted>,
    chunks: &std::path::Path,
    http: RecordingHttp,
) -> ContentClient<Scripted, FsStore, RecordingHttp> {
    ContentClient::attach(client, FsStore::new(chunks), ROOT_KEY, http)
        .await
        .expect("attach content handling")
}

/// Stages `bytes` as photo row `id` and returns the file identity.
///
/// Inserts into the `photos` table from [`DDL`]: `id` and `content_id` only.
/// Every test module that uses the standard two-column photo table can call
/// this instead of writing the stage closure inline.
pub async fn stage_photo(
    content: &ContentClient<Scripted, FsStore, RecordingHttp>,
    id: i32,
    bytes: &[u8],
    mime: MimeClass,
) -> FileId {
    let (file_id, ()) = content
        .stage(bytes, mime, |conn, file_id| {
            diesel::insert_into(photos::table)
                .values((
                    photos::id.eq(id),
                    photos::content_id.eq(file_id.as_bytes().to_vec()),
                ))
                .execute(conn)
                .map(|_| ())
        })
        .await
        .expect("stage a photo");
    file_id
}

/// Opens an offline replica and attaches a content client backed by
/// `RecordingHttp::default()`.
///
/// Returns both the raw client and the content client so tests that need to
/// inspect the replica directly can call `with_conn` on the client.
pub async fn offline_content(
    dir: &std::path::Path,
) -> (
    ConnettoClient<Scripted>,
    ContentClient<Scripted, FsStore, RecordingHttp>,
) {
    let client = offline_client(&dir.join("replica.sqlite"));
    let content = attach_content(
        client.clone(),
        &dir.join("chunks"),
        RecordingHttp::default(),
    )
    .await;
    (client, content)
}

/// Derives the content identity of `bytes` without committing anything to a
/// persistent replica.
///
/// Creates a throwaway replica that is discarded when this call returns; the
/// returned `FileId` is the BLAKE3-based identity that any replica would
/// assign to the same bytes.
pub async fn learn_file_id(bytes: &[u8]) -> FileId {
    let dir = tempfile::tempdir().expect("temp dir");
    let probe = attach_content(
        offline_client(&dir.path().join("replica.sqlite")),
        &dir.path().join("chunks"),
        RecordingHttp::default(),
    )
    .await;
    let (file_id, ()) = probe
        .stage(bytes, MimeClass::Jpeg, |_, _| Ok(()))
        .await
        .expect("stage against a throwaway replica");
    file_id
}

/// Inserts a photo row naming `file_id` into the client's replica, then pins
/// all `content_id` values from the photos table under the name "album".
///
/// Captures the shared `with_conn` + `pin_content` setup that both
/// `fetch_pinned` tests perform before exercising the download path.
pub async fn insert_row_and_pin_album(
    client: &ConnettoClient<Scripted>,
    content: &ContentClient<Scripted, FsStore, RecordingHttp>,
    file_id: FileId,
) {
    client
        .with_conn(|conn| {
            diesel::insert_into(photos::table)
                .values((
                    photos::id.eq(1),
                    photos::content_id.eq(file_id.as_bytes().to_vec()),
                ))
                .execute(conn.conn())
                .expect("record the row the pin reads")
        })
        .await;
    content
        .pin_content("album", "SELECT content_id FROM photos", "content_id")
        .await
        .expect("pin the album");
}

/// Asserts the file resolves from a local source, carrying `why` on failure.
pub async fn assert_local<H: ContentHttp>(
    content: &ContentClient<Scripted, FsStore, H>,
    file_id: FileId,
    why: &str,
) {
    let resolved = content.resolve(file_id).await.expect("resolve");
    assert!(
        matches!(resolved, connetto_file_client::Resolved::Local { .. }),
        "{why}, got {resolved:?}"
    );
}

/// Asserts the file resolves to a signed URL, carrying `why` on failure.
pub async fn assert_remote<H: ContentHttp>(
    content: &ContentClient<Scripted, FsStore, H>,
    file_id: FileId,
    why: &str,
) {
    let resolved = content.resolve(file_id).await.expect("resolve");
    assert!(
        matches!(resolved, connetto_file_client::Resolved::Remote { .. }),
        "{why}, got {resolved:?}"
    );
}

/// Opens a replica with `transport` attached and a content client over it.
///
/// The pairing every connected case needs: the client for replica reads and
/// writes, and the content client for everything about bytes.
pub async fn connected_content(
    root: &std::path::Path,
    transport: Scripted,
    http: RecordingHttp,
) -> (
    ConnettoClient<Scripted>,
    ContentClient<Scripted, FsStore, RecordingHttp>,
) {
    let client = connected_client(&root.join("replica.sqlite"), transport).await;
    let content = attach_content(client.clone(), &root.join("chunks"), http).await;
    (client, content)
}
