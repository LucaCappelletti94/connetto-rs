//! The native builder's transport contract. A plain `ws` URL dials loopback
//! only and a `wss` URL verifies against the platform trust store, and the
//! client's pump and the transport die together with the last clone, or on
//! `close()` with the clones still alive.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use connetto_client::{ClientError, NativeClientBuilder, SyncSchema, TransportFactory};
use connetto_core::Cursor;
use connetto_core::messages::{ControlMessage, HandshakeAck};
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::transport::WebSocketTransport;
use diesel::prelude::*;

const DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT);";

diesel::table! {
    /// Synced test table.
    items (id) {
        /// Item identifier, the primary key.
        id -> Integer,
        /// The item's label.
        label -> Nullable<Text>,
    }
}

/// The refusal an injected dialer hands back when it has no more transports.
#[derive(Debug, thiserror::Error)]
enum DialRefused {
    #[error("the dialer handed out its last transport")]
    Exhausted,
}

/// A transport that serves a scripted ack, counts what the client sends and
/// whether the pump closed it, and goes quiet without closing.
#[derive(Clone, Default)]
struct Recorder {
    frames: Arc<Mutex<VecDeque<IncomingFrame>>>,
    sends: Arc<AtomicUsize>,
    closes: Arc<AtomicUsize>,
}

impl Recorder {
    /// One ack frame waiting in the queue, every counter at zero.
    fn new() -> Self {
        Self {
            frames: Arc::new(Mutex::new(VecDeque::from([ack_frame()]))),
            sends: Arc::new(AtomicUsize::new(0)),
            closes: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// How many control frames the client sent.
    fn sends(&self) -> usize {
        self.sends.load(Ordering::Relaxed)
    }

    /// How many times the transport was closed.
    fn closes(&self) -> usize {
        self.closes.load(Ordering::Relaxed)
    }
}

impl Transport for Recorder {
    type Error = std::convert::Infallible;

    fn send_control(
        &mut self,
        _message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        self.sends.fetch_add(1, Ordering::Relaxed);
        std::future::ready(Ok(()))
    }

    fn send_bulk(
        &mut self,
        _message: connetto_core::messages::BulkMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        std::future::ready(Ok(()))
    }

    fn recv(&mut self) -> impl Future<Output = Result<Option<IncomingFrame>, Self::Error>> {
        let frames = Arc::clone(&self.frames);
        async move {
            loop {
                if let Some(frame) = frames.lock().expect("recorder lock").pop_front() {
                    return Ok(Some(frame));
                }
                tokio::task::yield_now().await;
            }
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        self.closes.fetch_add(1, Ordering::Relaxed);
        std::future::ready(Ok(()))
    }
}

/// The handshake answer every quiet server here sends, as the control frame
/// it rides in.
fn ack_frame() -> IncomingFrame {
    IncomingFrame::Control(ack_control())
}

/// The handshake answer every quiet server here sends.
fn ack_control() -> ControlMessage {
    ControlMessage::HandshakeAck(HandshakeAck {
        connection_id: "script".to_owned(),
        session_token: "script".to_owned(),
        resume_token: "script".to_owned(),
        current_cursor: Cursor::from(Vec::new()),
        schema_version: None,
        initial_credits: 64,
        last_applied_seq: None,
    })
}
/// The schema every build in this file carries.
fn schema() -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "CREATE TABLE items (id INT PRIMARY KEY, label TEXT);",
        "",
        DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        None::<&str>,
    ))
}

/// A dialer that hands out at most one scripted transport and counts its
/// dials.
struct Dialer {
    next: Option<Recorder>,
    dials: Arc<AtomicUsize>,
}

impl Dialer {
    /// One transport waiting to be handed out.
    fn one(transport: Recorder) -> (Self, Arc<AtomicUsize>) {
        let dials = Arc::new(AtomicUsize::new(0));
        (
            Self {
                next: Some(transport),
                dials: Arc::clone(&dials),
            },
            dials,
        )
    }
}

impl TransportFactory for Dialer {
    type Transport = Recorder;
    type Error = DialRefused;

    fn connect(&mut self) -> impl Future<Output = Result<Recorder, DialRefused>> + Send {
        self.dials.fetch_add(1, Ordering::Relaxed);
        let transport = self.next.take().ok_or(DialRefused::Exhausted);
        async move { transport }
    }
}

/// Wait, bounded, until the counter reaches `target`.
async fn until_counter(counter: &AtomicUsize, target: usize, why: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while counter.load(Ordering::Relaxed) < target {
        tokio::time::sleep_until(deadline).await;
    }
    assert!(
        counter.load(Ordering::Relaxed) >= target,
        "the bounded wait exceeded: {why}"
    );
}

/// Dropping the last clone of a builder-built client ends the pump and closes
/// the transport, while an earlier drop leaves the pump running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn builder_dropping_the_last_clone_ends_the_pump_and_closes_the_transport() {
    let recorder = Recorder::new();
    let (dialer, dials) = Dialer::one(recorder.clone());
    let (client, pump) = NativeClientBuilder::new("ws://127.0.0.1:1", schema())
        .with_dialer(dialer)
        .connect_with_pump()
        .await
        .expect("the builder connects");
    let pump = tokio::spawn(pump);

    // A clone drops, but another survives. The pump is still the only thing
    // that auto-submits local writes, so a write the transport never receives
    // would mean the pump already left.
    let other = client.client().clone();
    drop(client);
    let baseline = recorder.sends();
    other
        .with_conn(|conn| {
            diesel::insert_into(items::table)
                .values(items::label.eq("kept"))
                .execute(conn.conn())
                .expect("the surviving clone writes")
        })
        .await
        .expect("the surviving clone is not locked");
    until_counter(
        &recorder.sends,
        baseline + 1,
        "the pump auto-submits the write",
    )
    .await;

    drop(other);
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("the last clone's drop ends the pump in time")
        .expect("the pump exits cleanly");
    assert_eq!(
        recorder.closes(),
        1,
        "the transport closed with the close handshake"
    );
    assert_eq!(dials.load(Ordering::Relaxed), 1, "no redial was attempted");
}

/// `close()` ends the pump and closes the transport while the clones stay
/// alive, and the survivors keep answering from the replica.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn builder_close_ends_the_pump_and_closes_the_transport_with_clones_alive() {
    let recorder = Recorder::new();
    let (dialer, dials) = Dialer::one(recorder.clone());
    let (client, pump) = NativeClientBuilder::new("ws://127.0.0.1:1", schema())
        .with_dialer(dialer)
        .connect_with_pump()
        .await
        .expect("the builder connects");
    let pump = tokio::spawn(pump);

    let other = client.client().clone();
    other
        .with_conn(|conn| {
            diesel::insert_into(items::table)
                .values(items::label.eq("kept"))
                .execute(conn.conn())
                .expect("write the row before closing")
        })
        .await
        .expect("not locked");
    client.close().await;
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("close() ends the pump in time")
        .expect("the pump exits cleanly");
    assert_eq!(
        recorder.closes(),
        1,
        "the transport closed with the close handshake"
    );
    assert_eq!(dials.load(Ordering::Relaxed), 1, "no redial was attempted");

    // The clone stayed alive and falls back to the offline half of the
    // contract, so the row it wrote before the close is still there.
    let rows: Vec<i32> = other
        .with_conn(|conn| {
            items::table
                .select(items::id)
                .load(conn.conn())
                .expect("read the row back")
        })
        .await
        .expect("a closed client still answers locally");
    assert_eq!(rows, vec![1], "the surviving clone keeps its replica");
}

/// A plain `ws` URL to a non-loopback host is refused with the typed error
/// before a socket can open. `192.0.2.1` is a TEST-NET-1 literal the machine
/// cannot answer, so the refusal is instant, and a refusal that took a second
/// would be a dial, and the bounded wait would catch it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn builder_plain_websocket_to_a_non_loopback_host_is_refused_before_a_socket_opens() {
    let error = match tokio::time::timeout(Duration::from_secs(5), async {
        NativeClientBuilder::new("ws://192.0.2.1:9", schema())
            .connect()
            .await
    })
    .await
    {
        Ok(Ok(_)) => panic!("a plain ws URL to a non-loopback host is refused"),
        Ok(Err(error)) => error,
        Err(elapsed) => panic!("the refusal is before any dial, so {elapsed}"),
    };
    let ClientError::InsecureWebSocket { host } = error else {
        panic!("the refusal names the host, got {error:?}");
    };
    assert_eq!(host, "192.0.2.1", "the refusal names the host the URL used");
}

/// A plain `ws` URL to `127.0.0.1` dials and connects, the way the desktop
/// demo and the Android `adb reverse` run reach the stack.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn builder_plain_websocket_to_loopback_connects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("the listener's address");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut transport = WebSocketTransport::accept(stream)
            .await
            .expect("ws handshake");
        let Some(IncomingFrame::Control(ControlMessage::Handshake(_))) =
            transport.recv().await.expect("the handshake frame")
        else {
            return;
        };
        transport
            .send_control(ack_control())
            .await
            .expect("ack the handshake");
        while transport.recv().await.expect("quiet").is_some() {}
    });

    let client = NativeClientBuilder::new(format!("ws://{addr}"), schema())
        .connect()
        .await
        .expect("a loopback ws URL connects");
    let count: Vec<i64> = client
        .client()
        .with_conn(|conn| {
            items::table
                .count()
                .load(conn.conn())
                .expect("count the items table")
        })
        .await
        .expect("the client reads");
    assert_eq!(
        count,
        vec![0],
        "the fresh replica carries the bundle's table, empty"
    );

    drop(client);
    server.await.expect("the server task exits with the client");
}

/// A `wss` URL verifies against the platform trust store, so a local listener
/// offering a self-signed certificate is refused, and the refusal is the
/// certificate check rather than the network.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn builder_wss_to_a_self_signed_listener_is_refused_by_certificate_verification() {
    // A config built without an explicit provider needs the process-level
    // default, which this test process has to install.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key_pair = rcgen::KeyPair::generate().expect("generate the key");
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .expect("certificate parameters");
    let cert = params
        .self_signed(&key_pair)
        .expect("self-sign the certificate");
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())],
            rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
                .expect("the key serializes to pkcs8"),
        )
        .expect("the server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("the listener's address");
    let tls = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let _ = acceptor.accept(stream).await;
    });

    let Err(error) = NativeClientBuilder::new(format!("wss://{addr}"), schema())
        .connect()
        .await
    else {
        panic!("a self-signed certificate is not trusted")
    };
    let ClientError::Transport(detail) = error else {
        panic!("a refused dial is a transport error, got {error:?}");
    };
    let detail = detail.to_lowercase();
    assert!(
        detail.contains("certificate") || detail.contains("trusted") || detail.contains("issuer"),
        "the refusal is a certificate verification failure, not a network one: {detail}"
    );
    tls.abort();
}
