//! The held-content ticket walk against the raw connection a relay drives
//! (R31): a request whose drain wire dies settles as abandoned and reissues
//! on the redial, an interruption with the wire still up keeps the request,
//! and the in-flight answer settles the wait that sent it.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use connetto_client::{
    ClientBuilder, ClientEvent, ConnettoClient, ConnettoConnection, Gate, Grant, HeldCredential,
    MemoryRefreshStore, SyncSchema,
};
use connetto_core::messages::{ContentTicketGrant, ControlMessage, HandshakeAck, HeldWork};
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
