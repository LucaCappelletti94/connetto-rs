//! The test-local stand-in for the deployment proxy that routes a
//! connection by the handshake's `schema_major`, for the proofs of an app
//! spanning two majors (R31).
//!
//! It owns the one listener and reads the first control frame of each
//! connection, the `Handshake`, and hands the connection to the hosted entry
//! at the declared major with the handshake replayed, or to the newest hosted
//! major when none matches. That fallback is how a decommissioned major
//! reaches the newer server and gets the `MajorMismatch` refusal. The hosted
//! set changes during the test, which is the deployment's migration and
//! decommission.
//!
//! A hosted entry is whatever one hosted major does with a routed connection,
//! the in-process manager in the sync proofs and a manager with the file
//! server's signer in the content ones. The entry sees the connection through
//! [`Relay`], which replays the handshake so the manager sees the connection
//! it would have accepted itself.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use connetto_core::messages::{BulkMessage, ControlMessage};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Major, WebSocketError, WebSocketTransport};
use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// The future one hosted entry runs with a routed connection.
pub type HostedFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// One hosted major's answer to a routed connection.
///
/// The entry takes the replayed connection and serves it, and may hold the
/// manager it serves on for the next connection routed the same way.
pub type HostedEntry = Arc<dyn Fn(Relay) -> HostedFuture + Send + Sync>;

/// The hosted set one router owns, each major beside its entry.
type Hosted = Vec<(Major, HostedEntry)>;

/// The wire the router hands a hosted entry, replaying the handshake it read
/// so the entry sees the connection it would have accepted itself.
pub struct Relay {
    inner: WebSocketTransport<TcpStream>,
    first: Option<IncomingFrame>,
}

impl Transport for Relay {
    type Error = WebSocketError;

    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        self.inner.send_control(message).await
    }

    async fn send_bulk(&mut self, message: BulkMessage) -> Result<(), Self::Error> {
        self.inner.send_bulk(message).await
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        if let Some(frame) = self.first.take() {
            return Ok(Some(frame));
        }
        self.inner.recv().await
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.inner.close().await
    }
}

/// The test-local stand-in for the deployment proxy. One listener, one
/// hosted set, routing on the handshake's major field.
pub struct Router {
    addr: SocketAddr,
    hosted: Arc<Mutex<Hosted>>,
    accept: JoinHandle<()>,
}

impl Router {
    /// Start accepting on a fresh localhost listener with the hosted set.
    ///
    /// # Panics
    ///
    /// When the localhost listener cannot be bound.
    pub async fn start(hosted: Hosted) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let hosted = Arc::new(Mutex::new(hosted));
        let accept = tokio::spawn({
            let hosted = Arc::clone(&hosted);
            async move {
                loop {
                    let (stream, _) = listener.accept().await.expect("accept");
                    let hosted = Arc::clone(&hosted);
                    tokio::spawn(route(stream, hosted));
                }
            }
        });
        Self {
            addr,
            hosted,
            accept,
        }
    }

    /// The deployment starts hosting a major.
    pub fn host(&self, major: Major, entry: HostedEntry) {
        self.hosted.lock().push((major, entry));
    }

    /// The deployment stops hosting a major.
    pub fn decommission(&self, major: Major) {
        self.hosted.lock().retain(|(at, _)| *at != major);
    }

    /// The address the dialer names.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stop accepting. In-flight connections finish on their own.
    pub fn close(&self) {
        self.accept.abort();
    }
}

/// Serve one accepted connection. Read the first control frame, the
/// handshake, route it on the field, and hand the chosen entry the
/// connection with the handshake replayed.
async fn route(stream: TcpStream, hosted: Arc<Mutex<Hosted>>) {
    let mut wire = WebSocketTransport::accept(stream).await.expect("ws accept");
    let Some(IncomingFrame::Control(ControlMessage::Handshake(handshake))) =
        wire.recv().await.expect("the first frame")
    else {
        panic!("the first frame is the handshake");
    };
    let entry = {
        let hosted = hosted.lock();
        choose(handshake.schema_major, &hosted)
    };
    let relay = Relay {
        inner: wire,
        first: Some(IncomingFrame::Control(ControlMessage::Handshake(handshake))),
    };
    entry(relay).await;
}

/// The deployment's rule on the field. The matching major, or the newest
/// hosted major, which is how a decommissioned one reaches the newer server
/// and gets the mismatch.
fn choose(declared: Option<Major>, hosted: &[(Major, HostedEntry)]) -> HostedEntry {
    if let Some((_, entry)) = declared.and_then(|major| hosted.iter().find(|(at, _)| *at == major))
    {
        Arc::clone(entry)
    } else {
        let newest = hosted
            .iter()
            .max_by_key(|(at, _)| *at)
            .expect("a router always hosts a major");
        Arc::clone(&newest.1)
    }
}
