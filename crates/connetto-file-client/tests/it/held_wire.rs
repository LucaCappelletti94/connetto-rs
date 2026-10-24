//! The held-content ticket walk against the raw connection a relay drives
//! (R31): a request whose drain wire dies settles as abandoned and reissues
//! on the redial, an interruption with the wire still up keeps the request,
//! and the in-flight answer settles the wait that sent it.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use connetto_client::{
    ClientBuilder, ClientError, ClientEvent, ConnettoClient, ConnettoConnection, Gate, Grant,
    HeldCredential, MemoryRefreshStore, SyncSchema,
};
use connetto_core::messages::{
    ContentTicketGrant, ContentVerb, ControlMessage, HandshakeAck, HeldWork, RateLimited,
    ReplaceShareKeys, ShareKeysReplaced,
};
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackTransport, MAJOR_DIRECTIVE, Major, SchemaVersion, loopback};
use connetto_file_client::{
    ContentArchive, ContentClient, ContentError, ContentFlush, ContentFlushStart,
    ContentFlushState, ContentUpload, FsStore, held_content,
};
use connetto_file_core::{FileId, MimeClass};
use tempfile::{TempDir, tempdir};
use tokio::sync::{mpsc, oneshot};

use crate::support::{At, FixedKey, ROOT_KEY, RecordingHttp};

const DDL: &str = "CREATE TABLE photos (id INTEGER PRIMARY KEY, \
                   content_id BLOB NOT NULL, content_state TEXT)";

const GRANT_URL: &str = "https://files.test/files/ab/intent?t=TOKEN";

/// A cancel that never fires, so a walk waits only on the wire.
#[derive(Clone, Copy)]
struct Never;

impl Future for Never {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// The bytes the test file holds.
const BYTES: &[u8] = b"held";

fn schema(major: u32) -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            format!("{MAJOR_DIRECTIVE} {major}\n-- {DDL}"),
            "",
            DDL,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )
        .expect("the source declares its major"),
    )
}

fn one() -> Major {
    Major::new(1).expect("one is a major")
}

/// What one scripted drain server does once its held ticket request arrives.
enum DrainScript {
    /// Hang up, so the request's answer can no longer come.
    HangUp,
    /// Hold the wire open until told to drop it.
    Hold { kill: oneshot::Receiver<()> },
    /// Send the grant when told, then hold until told to drop.
    Answer {
        kill: oneshot::Receiver<()>,
        grant: oneshot::Receiver<()>,
    },
}

/// A scripted server for the drain wire of a major 1 replica. It acks the
/// handshake with the held major's hash and no writer, records every ticket
/// request on `seen`, and then plays its script.
fn drain_server(
    version: SchemaVersion,
    script: DrainScript,
    seen: mpsc::UnboundedSender<String>,
) -> LoopbackTransport {
    let (client_end, mut server_end) = loopback();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) =
            server_end.recv().await
        else {
            return;
        };
        let _ = server_end
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "old".to_owned(),
                session_token: "old".to_owned(),
                resume_token: "old".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: Some(version),
                initial_credits: 64,
                writer: None,
            }))
            .await;
        // The server exists to answer one ticket request.
        let Ok(Some(IncomingFrame::Control(ControlMessage::ContentTicketRequest(request)))) =
            server_end.recv().await
        else {
            return;
        };
        let request_id = request.request_id;
        let _ = seen.send(request_id.clone());
        match script {
            DrainScript::HangUp => {
                let _ = server_end.close().await;
            }
            DrainScript::Hold { kill } => {
                let _ = kill.await;
            }
            DrainScript::Answer { kill, grant } => {
                let _ = grant.await;
                let _ = server_end
                    .send_control(ControlMessage::ContentTicketGrant(ContentTicketGrant {
                        request_id,
                        url: GRANT_URL.to_owned(),
                    }))
                    .await;
                let _ = kill.await;
            }
        }
    });
    client_end
}

/// The one request a scripted drain server recorded, if it has any.
fn recorded(rx: &mut mpsc::UnboundedReceiver<String>) -> Option<String> {
    rx.try_recv().ok()
}

/// A replica at major 1 with one staged file and no transport, closed so a
/// reopen at major 2 holds it. Returns the replica directory and the file.
async fn held_file_offline() -> (TempDir, FileId) {
    let dir = tempdir().expect("temp dir");
    let credential =
        HeldCredential::new(Grant::new("user:tester"), "tester").expect("a string identity");
    let (_client, content) = {
        let conn = ClientBuilder::new(schema(1), || async {
            Err::<LoopbackTransport, _>("no server")
        })
        .signed_in(credential)
        .durable(
            At(dir.path().join("replica.sqlite")),
            FixedKey,
            MemoryRefreshStore::default(),
        )
        .with_gate(Gate::off())
        .open_driven()
        .await
        .expect("open offline");
        let (client, pump) = ConnettoClient::with_pump(conn);
        tokio::spawn(pump);
        let content = ContentClient::attach(
            client.clone(),
            FsStore::new(dir.path().join("chunks")),
            ROOT_KEY,
            RecordingHttp::default(),
        )
        .await
        .expect("attach content");
        (client, content)
    };
    let (file_id, ()) = content
        .stage(BYTES, MimeClass::Jpeg, |_, _| Ok(()))
        .await
        .expect("stage the file with no row");
    (dir, file_id)
}

/// Reopens the replica at major 2, so the rebuild holds the staged file.
async fn reopen_held(dir: &TempDir) -> ConnettoConnection<LoopbackTransport> {
    let credential =
        HeldCredential::new(Grant::new("user:tester"), "tester").expect("a string identity");
    ClientBuilder::new(schema(2), || async {
        Err::<LoopbackTransport, _>("no server")
    })
    .with_held_content(held_content())
    .signed_in(credential)
    .durable(
        At(dir.path().join("replica.sqlite")),
        FixedKey,
        MemoryRefreshStore::default(),
    )
    .with_gate(Gate::off())
    .open_driven()
    .await
    .expect("rebuild holds the file")
}

/// One walk of the held drain over `conn`, the shape a relay hub drives.
async fn begin<C: Future<Output = ()>>(
    archive: &ContentArchive<FsStore>,
    conn: &mut ConnettoConnection<LoopbackTransport>,
    state: &mut ContentFlushState,
    cancel: C,
) -> (
    Result<ContentFlushStart<FsStore>, ContentError>,
    Vec<ClientEvent>,
) {
    archive
        .begin_held_flush_next_or(conn, state, one(), cancel)
        .await
}

/// Transfers and finishes one granted held upload, returning the flush.
async fn finish_upload(
    archive: &ContentArchive<FsStore>,
    conn: &mut ConnettoConnection<LoopbackTransport>,
    upload: &ContentUpload<FsStore>,
) -> ContentFlush {
    let http = RecordingHttp::new([(200, br#"{"needed":[]}"#.to_vec()), (200, Vec::new())]);
    upload.transfer(&http).await.expect("the transfer");
    archive
        .finish_held_upload(conn, upload, one(), Ok(()))
        .await
        .expect("the bookkeeping")
}

/// A wire that dies under an in-flight held ticket settles the walk as
/// abandoned, defers the file, and the walk on the redial reissues a fresh
/// request that grants and uploads.
#[tokio::test]
async fn a_wire_lost_under_an_in_flight_held_ticket_reissues_on_the_redial() {
    let (dir, _file_id) = held_file_offline().await;
    let mut conn = reopen_held(&dir).await;
    let archive = ContentArchive::new(FsStore::new(dir.path().join("chunks")), ROOT_KEY);
    assert!(
        archive
            .held_files_pending(&mut conn, one())
            .expect("read the held rows"),
        "the rebuild held the file"
    );

    let first = schema(1);
    let (seen1_tx, mut seen1) = mpsc::unbounded_channel::<String>();
    let timer = conn.drain_timer().expect("the held batch owes a dial");
    conn.attach_drain(
        timer,
        drain_server(first.version(), DrainScript::HangUp, seen1_tx),
    )
    .await
    .expect("attach the drain");
    assert_eq!(
        conn.held_files_ready(),
        Some(one()),
        "the wire is up and the major holds no writes"
    );

    let mut state = ContentFlushState::default();
    let (start, observed) = begin(&archive, &mut conn, &mut state, Never).await;
    assert!(
        matches!(
            start,
            Ok(ContentFlushStart::Complete(ContentFlush::Deferred))
        ),
        "the lost wire settles the walk as a deferral"
    );
    assert!(
        observed.iter().any(|event| {
            matches!(event, ClientEvent::Held(HeldWork::WireLost { major }) if *major == one())
        }),
        "the walk observes that its wire is gone"
    );
    assert!(!state.is_waiting(), "the settled wait frees the slot");

    let (seen2_tx, mut seen2) = mpsc::unbounded_channel::<String>();
    let redial = conn.drain_timer().expect("the drop owes a redial");
    conn.attach_drain(
        redial,
        drain_server(
            first.version(),
            DrainScript::Answer {
                kill: oneshot::channel::<()>().1,
                grant: oneshot::channel::<()>().1,
            },
            seen2_tx,
        ),
    )
    .await
    .expect("attach the redial");

    let (start, _observed) = begin(&archive, &mut conn, &mut state, Never).await;
    let upload = match start.expect("the reissued walk grants") {
        ContentFlushStart::Upload(upload) => upload,
        ContentFlushStart::Complete(flush) => panic!("the reissued walk uploads, not {flush:?}"),
    };
    let first_request = recorded(&mut seen1).expect("the first wire saw the request");
    let fresh = recorded(&mut seen2).expect("the redial saw one request");
    assert_ne!(first_request, fresh, "the reissue carries a fresh id");
    finish_upload(&archive, &mut conn, &upload).await;
    assert!(
        !archive
            .held_files_pending(&mut conn, one())
            .expect("read the held rows"),
        "the uploaded file leaves the held rows"
    );
}

/// An interruption with the wire still up keeps the request, and the walk on
/// the redial recognizes the changed dial and reissues before it waits.
#[tokio::test]
async fn an_interrupted_held_ticket_reissues_on_the_redial() {
    let (dir, _file_id) = held_file_offline().await;
    let mut conn = reopen_held(&dir).await;
    let archive = ContentArchive::new(FsStore::new(dir.path().join("chunks")), ROOT_KEY);

    let first = schema(1);
    let (seen1_tx, mut seen1) = mpsc::unbounded_channel::<String>();
    let (kill1_tx, kill1_rx) = oneshot::channel();
    let timer = conn.drain_timer().expect("the held batch owes a dial");
    conn.attach_drain(
        timer,
        drain_server(
            first.version(),
            DrainScript::Hold { kill: kill1_rx },
            seen1_tx,
        ),
    )
    .await
    .expect("attach the drain");

    let mut state = ContentFlushState::default();
    let (start, _observed) = begin(&archive, &mut conn, &mut state, async {}).await;
    assert!(
        matches!(
            start,
            Ok(ContentFlushStart::Complete(ContentFlush::Interrupted))
        ),
        "the interruption keeps the file queued and unprogressed"
    );
    assert!(state.is_waiting(), "the request still awaits its answer");
    let first_request = tokio::time::timeout(std::time::Duration::from_secs(5), seen1.recv())
        .await
        .expect("the request reached the wire")
        .expect("one request recorded");

    kill1_tx.send(()).expect("the server drops the wire");
    let dropped = tokio::time::timeout(std::time::Duration::from_secs(5), conn.pump_one())
        .await
        .expect("the pump settles within the bound")
        .expect("a pump step");
    assert!(
        matches!(dropped, ClientEvent::Held(HeldWork::WireLost { major }) if major == one()),
        "the dropped wire reports its held work"
    );

    let (seen2_tx, mut seen2) = mpsc::unbounded_channel::<String>();
    let redial = conn.drain_timer().expect("the drop owes a redial");
    conn.attach_drain(
        redial,
        drain_server(
            first.version(),
            DrainScript::Answer {
                kill: oneshot::channel::<()>().1,
                grant: oneshot::channel::<()>().1,
            },
            seen2_tx,
        ),
    )
    .await
    .expect("attach the redial");

    let (start, _observed) = begin(&archive, &mut conn, &mut state, Never).await;
    let upload = match start.expect("the reissued walk grants") {
        ContentFlushStart::Upload(upload) => upload,
        ContentFlushStart::Complete(flush) => panic!("the reissued walk uploads, not {flush:?}"),
    };
    let fresh = tokio::time::timeout(std::time::Duration::from_secs(5), seen2.recv())
        .await
        .expect("the redial saw one request")
        .expect("one request recorded");
    assert_ne!(
        first_request, fresh,
        "the changed dial reissued before the wait"
    );
    finish_upload(&archive, &mut conn, &upload).await;
}

/// An interruption with the wire still up keeps the request, and the answer
/// that arrives on that same wire settles the next walk without a reissue.
#[tokio::test]
async fn an_interrupted_held_ticket_its_answer_settles_the_next_walk() {
    let (dir, _file_id) = held_file_offline().await;
    let mut conn = reopen_held(&dir).await;
    let archive = ContentArchive::new(FsStore::new(dir.path().join("chunks")), ROOT_KEY);

    let first = schema(1);
    let (seen1_tx, mut seen1) = mpsc::unbounded_channel::<String>();
    let (kill1_tx, kill1_rx) = oneshot::channel();
    let (grant1_tx, grant1_rx) = oneshot::channel();
    let timer = conn.drain_timer().expect("the held batch owes a dial");
    conn.attach_drain(
        timer,
        drain_server(
            first.version(),
            DrainScript::Answer {
                kill: kill1_rx,
                grant: grant1_rx,
            },
            seen1_tx,
        ),
    )
    .await
    .expect("attach the drain");

    let mut state = ContentFlushState::default();
    let (start, _observed) = begin(&archive, &mut conn, &mut state, async {}).await;
    assert!(
        matches!(
            start,
            Ok(ContentFlushStart::Complete(ContentFlush::Interrupted))
        ),
        "the interruption keeps the file queued and unprogressed"
    );
    assert!(state.is_waiting(), "the request still awaits its answer");
    let _recorded_request = tokio::time::timeout(std::time::Duration::from_secs(5), seen1.recv())
        .await
        .expect("the request reached the wire")
        .expect("one request recorded");

    grant1_tx
        .send(())
        .expect("the server answers on the same wire");
    let (start, _observed) = begin(&archive, &mut conn, &mut state, Never).await;
    let upload = match start.expect("the kept walk grants") {
        ContentFlushStart::Upload(upload) => upload,
        ContentFlushStart::Complete(flush) => panic!("the kept walk uploads, not {flush:?}"),
    };
    assert_eq!(
        recorded(&mut seen1),
        None,
        "the next walk did not reissue the request"
    );
    let _ = kill1_tx;
    finish_upload(&archive, &mut conn, &upload).await;
}

async fn control(server: &mut LoopbackTransport) -> ControlMessage {
    match tokio::time::timeout(Duration::from_secs(5), server.recv())
        .await
        .expect("the correlated request arrives within its bound")
        .expect("receive the request")
    {
        Some(IncomingFrame::Control(message)) => message,
        _ => panic!("expected a control request"),
    }
}

async fn attach_held(conn: &mut ConnettoConnection<LoopbackTransport>) -> LoopbackTransport {
    let (transport, mut server) = loopback();
    let timer = conn.drain_timer().expect("the held batch owes a dial");
    let answer = async {
        assert!(matches!(
            control(&mut server).await,
            ControlMessage::Handshake(_)
        ));
        server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "held-key-fence".to_owned(),
                session_token: "held-key-fence".to_owned(),
                resume_token: "held-key-fence".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: Some(schema(1).version()),
                initial_credits: 64,
                writer: None,
            }))
            .await
            .expect("acknowledge the held handshake");
    };
    let (attached, ()) = tokio::join!(conn.attach_drain(timer, transport), answer);
    attached.expect("attach the held drain");
    server
}

async fn replacement(server: &mut LoopbackTransport) -> ReplaceShareKeys {
    match control(server).await {
        ControlMessage::ReplaceShareKeys(request) => request,
        _ => panic!("expected the held share-key replacement"),
    }
}

async fn accept_keys(
    conn: &mut ConnettoConnection<LoopbackTransport>,
    server: &mut LoopbackTransport,
    request_id: String,
) {
    server
        .send_control(ControlMessage::ShareKeysReplaced(ShareKeysReplaced {
            request_id,
        }))
        .await
        .expect("answer the correlated replacement");
    conn.pump_one_or(tokio::time::sleep(Duration::from_secs(5)))
        .await
        .expect("process the replacement answer");
}

async fn upload_authorized_file(
    dir: &TempDir,
    conn: &mut ConnettoConnection<LoopbackTransport>,
    server: &mut LoopbackTransport,
) {
    let archive = ContentArchive::new(FsStore::new(dir.path().join("chunks")), ROOT_KEY);
    let mut state = ContentFlushState::default();
    let answer = async {
        let ControlMessage::ContentTicketRequest(request) = control(server).await else {
            panic!("expected the held file's ticket request");
        };
        server
            .send_control(ControlMessage::ContentTicketGrant(ContentTicketGrant {
                request_id: request.request_id,
                url: GRANT_URL.to_owned(),
            }))
            .await
            .expect("grant the correlated file ticket");
    };
    let ((start, _), ()) = tokio::join!(
        begin(
            &archive,
            conn,
            &mut state,
            tokio::time::sleep(Duration::from_secs(5))
        ),
        answer,
    );
    let ContentFlushStart::Upload(upload) = start.expect("the authorized file gets a ticket")
    else {
        panic!("the authorized file must upload");
    };
    assert_eq!(
        finish_upload(&archive, conn, &upload).await,
        ContentFlush::Progressed
    );
    assert!(!conn.held_files_pending().expect("read the held files"));
    assert_eq!(conn.draining_major(), None);
}

#[tokio::test]
async fn a_key_change_holds_tickets_until_the_drain_accepts_its_current_keys() {
    let (dir, file_id) = held_file_offline().await;
    let mut conn = reopen_held(&dir).await;
    let subject = connetto_core::auth::CapabilitySubject::<String>::new("key:a");
    conn.add_share_key(&Grant::new("grant-a"), &subject)
        .await
        .expect("add the initial share key");
    let mut server = attach_held(&mut conn).await;
    let dial = conn.drain_dial_generation();
    assert_eq!(conn.held_files_ready(), Some(one()));
    conn.remove_share_key(&subject)
        .await
        .expect("remove the initial share key");
    assert_eq!(conn.held_files_ready(), None);
    assert!(matches!(
        conn.request_held_ticket(
            "blocked-ticket".to_owned(),
            *file_id.as_bytes(),
            ContentVerb::Write { declared_len: 4 }
        )
        .await,
        Err(ClientError::ShareKeysPending),
    ));
    let archive = ContentArchive::new(FsStore::new(dir.path().join("chunks")), ROOT_KEY);
    let mut state = ContentFlushState::default();
    let (start, _) = begin(&archive, &mut conn, &mut state, async {}).await;
    assert!(matches!(
        start,
        Ok(ContentFlushStart::Complete(ContentFlush::Deferred))
    ));
    assert!(!state.is_waiting());
    assert!(
        conn.held_files_pending()
            .expect("the deferred file remains held")
    );
    conn.pump_one_or(async {})
        .await
        .expect("send the replacement");
    let first = replacement(&mut server).await;
    conn.add_share_key(&Grant::new("grant-b"), &subject)
        .await
        .expect("advance the desired key generation");
    server
        .send_control(ControlMessage::ShareKeysReplaced(ShareKeysReplaced {
            request_id: "foreign-key-request".to_owned(),
        }))
        .await
        .expect("send an unrelated answer");
    assert!(matches!(
        conn.pump_one_or(tokio::time::sleep(Duration::from_secs(5)))
            .await,
        Err(ClientError::Protocol(_)),
    ));
    assert_eq!(conn.held_files_ready(), None);
    accept_keys(&mut conn, &mut server, first.request_id).await;
    assert_eq!(conn.held_files_ready(), None);
    let latest = replacement(&mut server).await;
    assert!(matches!(
        conn.request_held_ticket(
            "still-blocked".to_owned(),
            *file_id.as_bytes(),
            ContentVerb::Write { declared_len: 4 }
        )
        .await,
        Err(ClientError::ShareKeysPending),
    ));
    accept_keys(&mut conn, &mut server, latest.request_id).await;
    assert_eq!(conn.held_files_ready(), Some(one()));
    assert_eq!(conn.drain_dial_generation(), dial);
    assert_eq!(conn.drain_timer(), None);
    upload_authorized_file(&dir, &mut conn, &mut server).await;
}

#[tokio::test]
async fn a_throttled_drain_replacement_waits_for_its_floor_and_uses_the_latest_keys() {
    let (dir, _) = held_file_offline().await;
    let mut conn = reopen_held(&dir).await;
    let mut server = attach_held(&mut conn).await;
    let subject = connetto_core::auth::CapabilitySubject::<String>::new("key:a");
    conn.add_share_key(&Grant::new("grant-a"), &subject)
        .await
        .expect("add a key");
    conn.pump_one_or(async {})
        .await
        .expect("send the replacement");
    let first = replacement(&mut server).await;
    server
        .send_control(ControlMessage::RateLimited(RateLimited {
            related_to: Some(first.request_id),
            retry_after_ms: 30_000,
        }))
        .await
        .expect("defer the correlated replacement");
    conn.pump_one_or(tokio::time::sleep(Duration::from_secs(5)))
        .await
        .expect("process the retry floor");
    conn.remove_share_key(&subject)
        .await
        .expect("remove the deferred key");
    conn.pump_one_or(async {})
        .await
        .expect("honor the retry floor");
    assert_eq!(conn.held_files_ready(), None);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), server.recv())
            .await
            .is_err()
    );
    tokio::time::sleep(
        conn.share_key_timer()
            .expect("the retry floor wakes the pump")
            .wait(),
    )
    .await;
    conn.pump_one_or(async {})
        .await
        .expect("retry the latest set");
    let latest = replacement(&mut server).await;
    assert!(latest.keys.is_empty());
    accept_keys(&mut conn, &mut server, latest.request_id).await;
    assert_eq!(conn.held_files_ready(), Some(one()));
    assert_eq!(conn.drain_timer(), None);
    upload_authorized_file(&dir, &mut conn, &mut server).await;
}

#[tokio::test]
async fn an_unanswered_drain_replacement_recovers_without_losing_its_file() {
    let (dir, file_id) = held_file_offline().await;
    let mut conn = reopen_held(&dir).await;
    let mut server = attach_held(&mut conn).await;
    let subject = connetto_core::auth::CapabilitySubject::<String>::new("key:a");
    conn.add_share_key(&Grant::new("grant-a"), &subject)
        .await
        .expect("add a key");
    conn.pump_one_or(async {})
        .await
        .expect("send the replacement");
    let _unanswered = replacement(&mut server).await;
    tokio::time::sleep(
        conn.share_key_timer()
            .expect("the answer has a deadline")
            .wait(),
    )
    .await;
    let event = conn
        .pump_one_or(async {})
        .await
        .expect("expire the unanswered request");
    assert!(
        matches!(event, Some(ClientEvent::Held(HeldWork::WireLost { major })) if major == one())
    );
    assert!(conn.held_files_pending().expect("keep the held file"));
    assert!(matches!(
        conn.request_held_ticket(
            "disconnected-ticket".to_owned(),
            *file_id.as_bytes(),
            ContentVerb::Write { declared_len: 4 }
        )
        .await,
        Err(ClientError::NotConnected),
    ));
    let mut recovered = attach_held(&mut conn).await;
    assert_eq!(conn.held_files_ready(), Some(one()));
    upload_authorized_file(&dir, &mut conn, &mut recovered).await;
}

fn expiring_grant(expires: u64) -> Grant {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let payload = format!(r#"{{"exp":{expires}}}"#);
    let body: String = payload
        .as_bytes()
        .chunks(3)
        .flat_map(|chunk| {
            let word = (u32::from(chunk[0]) << 16)
                | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
                | u32::from(chunk.get(2).copied().unwrap_or(0));
            (0..(chunk.len() * 8).div_ceil(6))
                .map(move |index| char::from(ALPHABET[((word >> (18 - index * 6)) & 63) as usize]))
        })
        .collect();
    Grant::new(format!("h.{body}.s"))
}

#[tokio::test]
async fn a_held_file_waits_for_the_drain_to_remove_an_expired_key() {
    let (dir, file_id) = held_file_offline().await;
    let mut conn = reopen_held(&dir).await;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the wall clock")
        .as_secs()
        + 5;
    let subject = connetto_core::auth::CapabilitySubject::<String>::new("key:a");
    conn.add_share_key(&expiring_grant(expires), &subject)
        .await
        .expect("hold an expiring key");
    let mut server = attach_held(&mut conn).await;
    assert_eq!(conn.held_files_ready(), Some(one()));
    tokio::time::sleep(
        conn.share_key_timer()
            .expect("the key has an expiry")
            .wait()
            + Duration::from_millis(20),
    )
    .await;
    assert_eq!(conn.held_files_ready(), None);
    assert!(matches!(
        conn.request_held_ticket(
            "expired-ticket".to_owned(),
            *file_id.as_bytes(),
            ContentVerb::Write { declared_len: 4 }
        )
        .await,
        Err(ClientError::ShareKeysPending),
    ));
    conn.pump_one_or(async {})
        .await
        .expect("replace the expired key");
    let latest = replacement(&mut server).await;
    assert!(latest.keys.is_empty());
    accept_keys(&mut conn, &mut server, latest.request_id).await;
    assert_eq!(conn.drain_timer(), None);
    upload_authorized_file(&dir, &mut conn, &mut server).await;
}

#[tokio::test]
async fn a_held_ticket_already_sent_finishes_while_share_keys_are_pending() {
    let (dir, _) = held_file_offline().await;
    let mut conn = reopen_held(&dir).await;
    let mut server = attach_held(&mut conn).await;
    let archive = ContentArchive::new(FsStore::new(dir.path().join("chunks")), ROOT_KEY);
    let mut state = ContentFlushState::default();
    let (start, _) = begin(&archive, &mut conn, &mut state, async {}).await;
    assert!(matches!(
        start,
        Ok(ContentFlushStart::Complete(ContentFlush::Interrupted))
    ));
    let ControlMessage::ContentTicketRequest(ticket) = control(&mut server).await else {
        panic!("expected the earlier held ticket request");
    };
    let subject = connetto_core::auth::CapabilitySubject::<String>::new("key:a");
    conn.add_share_key(&Grant::new("grant-a"), &subject)
        .await
        .expect("add a key");
    conn.pump_one_or(async {})
        .await
        .expect("send the replacement");
    let _pending = replacement(&mut server).await;
    server
        .send_control(ControlMessage::ContentTicketGrant(ContentTicketGrant {
            request_id: ticket.request_id,
            url: GRANT_URL.to_owned(),
        }))
        .await
        .expect("answer the earlier ticket");
    let (start, _) = begin(
        &archive,
        &mut conn,
        &mut state,
        tokio::time::sleep(Duration::from_secs(5)),
    )
    .await;
    let ContentFlushStart::Upload(upload) = start.expect("the earlier ticket settles") else {
        panic!("the granted earlier ticket must upload");
    };
    assert_eq!(conn.held_files_ready(), None);
    assert!(!state.is_waiting());
    assert_eq!(
        finish_upload(&archive, &mut conn, &upload).await,
        ContentFlush::Progressed
    );
    assert!(!conn.held_files_pending().expect("the granted file settled"));
}

#[tokio::test]
async fn the_native_pump_bounds_a_held_key_replacement_without_another_wake() {
    let (dir, _) = held_file_offline().await;
    let mut conn = reopen_held(&dir).await;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the wall clock")
        .as_secs()
        + 3;
    let subject = connetto_core::auth::CapabilitySubject::<String>::new("key:a");
    conn.add_share_key(&expiring_grant(expires), &subject)
        .await
        .expect("hold an expiring key");
    let mut server = attach_held(&mut conn).await;
    let (client, pump) = ConnettoClient::with_pump(conn);
    let pump = tokio::spawn(pump);
    let pending = replacement(&mut server).await;
    let closed = matches!(
        tokio::time::timeout(Duration::from_secs(35), server.recv()).await,
        Ok(Ok(None)),
    );
    assert!(
        client
            .held_files_pending()
            .await
            .expect("keep the held file")
    );
    tokio::time::timeout(Duration::from_secs(5), client.close())
        .await
        .expect("close the retained client");
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("the pump finishes")
        .expect("the pump does not panic");
    assert!(
        closed,
        "the native pump must bound held replacement {} without an external wake",
        pending.request_id,
    );
}
