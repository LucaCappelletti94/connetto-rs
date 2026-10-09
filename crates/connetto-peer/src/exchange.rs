//! The Bluetooth exchange, the link's TLS 1.3 and list swap over a chunk
//! transport, and the offer the host hands the joiner (R76 slice 5).

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use connetto_core::device_cert::{DeviceCertificate, DeviceIdentity};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::ExchangeError;
use crate::event::PeerEvent;
use crate::frame::{PeerFrame, read_frame, write_frame};
use crate::identity::Identity;
use crate::node::{
    DIAL_NAME, NodeState, classify_frame, classify_io, client_config_for, exchange_hello,
    server_config_for,
};

/// The bound the whole exchange gets, on the monotonic clock.
pub const EXCHANGE_BOUND: Duration = Duration::from_secs(30);

/// A byte stream over ordered chunks of at most `chunk_size` bytes each
/// way, the transport a GATT characteristic is.
#[derive(Debug)]
pub struct ChunkStream {
    inbound: mpsc::Receiver<Vec<u8>>,
    /// The bridge task's input, closed once the writes end.
    tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    chunk: usize,
    /// The inbound bytes not yet handed to a read.
    pending: Vec<u8>,
}

impl ChunkStream {
    /// Stream over `inbound`, the peer's chunks in order, writing into
    /// `outbound` split to `chunk_size`, which must be at least 1. A closed
    /// `inbound` ends the reads, and a dropped `outbound` ends the writes.
    ///
    /// A bridge task owns `outbound` and keeps the channel's backpressure,
    /// so a runtime must be present.
    ///
    /// # Panics
    ///
    /// When `chunk_size` is 0, or no tokio runtime drives the bridge.
    #[must_use]
    pub fn new(
        inbound: mpsc::Receiver<Vec<u8>>,
        outbound: mpsc::Sender<Vec<u8>>,
        chunk_size: usize,
    ) -> Self {
        assert!(chunk_size > 0, "a chunk is at least one byte");
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(bridge(outbound, rx));
        Self {
            inbound,
            tx: Some(tx),
            chunk: chunk_size,
            pending: Vec::new(),
        }
    }
}

/// The outbound bridge, keeping the real channel's backpressure until the
/// writes end or the reader is gone.
async fn bridge(outbound: mpsc::Sender<Vec<u8>>, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(chunk) = rx.recv().await {
        if outbound.send(chunk).await.is_err() {
            break;
        }
    }
}

impl AsyncRead for ChunkStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending.is_empty() {
            match this.inbound.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => this.pending = chunk,
                // The peer's chunks are done, and with them the stream.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let take = this.pending.len().min(buf.remaining());
        buf.put_slice(&this.pending[..take]);
        this.pending.drain(..take);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ChunkStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(tx) = this.tx.as_ref() else {
            return Poll::Ready(Err(closed()));
        };
        // The last chunk may be short, the peer rejoins the chunks into the
        // byte stream.
        for chunk in buf.chunks(this.chunk) {
            if tx.send(chunk.to_vec()).is_err() {
                return Poll::Ready(Err(closed()));
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The writes are already with the bridge, so a live bridge is a
        // live flush.
        if self.tx.is_some() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Err(closed()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The last sender's drop ends the bridge after its queue drains, and
        // with it the peer's reads.
        self.get_mut().tx = None;
        Poll::Ready(Ok(()))
    }
}

/// A write into a stream whose chunk reader is gone.
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the chunk reader is gone")
}

/// The hotspot details the host hands the joiner once both have proved
/// their identity.
#[derive(Clone, PartialEq, Eq)]
pub struct OfferFrame {
    /// The network name.
    pub ssid: String,
    /// The passphrase, redacted in the debug form and zeroed on drop.
    passphrase: Vec<u8>,
    /// The security the network carries, 0 for WPA2 and 1 for WPA3.
    pub security: u8,
    /// The peer port the host serves, while it serves.
    pub port: Option<u16>,
}

impl OfferFrame {
    /// An offer with its details.
    #[must_use]
    pub fn new(
        ssid: impl Into<String>,
        passphrase: impl Into<String>,
        security: u8,
        port: Option<u16>,
    ) -> Self {
        Self {
            ssid: ssid.into(),
            passphrase: passphrase.into().into_bytes(),
            security,
            port,
        }
    }

    /// The passphrase.
    ///
    /// # Panics
    ///
    /// Never, a passphrase is built from a string.
    #[must_use]
    pub fn passphrase(&self) -> &str {
        std::str::from_utf8(&self.passphrase).expect("a passphrase is built from a string")
    }

    /// The passphrase as the frame carries it.
    fn wire_passphrase(&self) -> String {
        String::from_utf8(self.passphrase.clone()).expect("a passphrase is built from a string")
    }
}

impl fmt::Debug for OfferFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfferFrame")
            .field("ssid", &self.ssid)
            .field("passphrase", &"<redacted>")
            .field("security", &self.security)
            .field("port", &self.port)
            .finish()
    }
}

impl Drop for OfferFrame {
    fn drop(&mut self) {
        self.passphrase.fill(0);
        self.passphrase.clear();
    }
}

/// Run the exchange as the host over `io`, handing the joiner `offer` once
/// it proves its identity.
pub(crate) async fn offer_exchange<S: AsyncRead + AsyncWrite + Unpin + Send>(
    state: &NodeState,
    io: S,
    identity: &Identity,
    offer: &OfferFrame,
) -> Result<DeviceIdentity, ExchangeError> {
    tokio::time::timeout(EXCHANGE_BOUND, host_exchange(state, io, identity, offer))
        .await
        .map_err(|_| ExchangeError::Timeout)?
}

/// Run the exchange as the joiner over `io`, answering the host's identity
/// and its offer.
pub(crate) async fn fetch_exchange<S: AsyncRead + AsyncWrite + Unpin + Send>(
    state: &NodeState,
    io: S,
    identity: &Identity,
) -> Result<(DeviceIdentity, OfferFrame), ExchangeError> {
    tokio::time::timeout(EXCHANGE_BOUND, joiner_exchange(state, io, identity))
        .await
        .map_err(|_| ExchangeError::Timeout)?
}

/// The host's side, the listener's side of a link without the registration.
async fn host_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    state: &NodeState,
    io: S,
    identity: &Identity,
    offer: &OfferFrame,
) -> Result<DeviceIdentity, ExchangeError> {
    let config = server_config_for(
        &state.trust,
        state.verifier.clock(),
        *state.own_key.read(),
        Arc::clone(&state.crls),
        identity,
    );
    let mut tls = TlsAcceptor::from(config)
        .accept(io)
        .await
        .map_err(|err| ExchangeError::from(classify_io(err)))?;
    let leaf = {
        let certs = tls
            .get_ref()
            .1
            .peer_certificates()
            .expect("the client auth is mandatory");
        let (Some(leaf), Some(_)) = (certs.first(), certs.get(1)) else {
            return Err(ExchangeError::Protocol(
                "the peer presented no issuer certificate".into(),
            ));
        };
        leaf.to_vec()
    };
    let peer = DeviceCertificate::parse(&leaf)
        .expect("the profile was verified at the handshake")
        .identity()
        .clone();
    let _ = exchange_hello(&mut tls, state, 0).await?;
    // The joiner closes its write side once its lists are sent, so the
    // stream's end ends the swap.
    loop {
        let frame = read_frame(&mut tls)
            .await
            .map_err(classify_frame)
            .map_err(ExchangeError::from)?;
        match frame {
            None => break,
            Some(PeerFrame::List { list, signer }) => {
                hand_list(state, list.to_vec(), signer.to_vec());
            }
            Some(frame) => {
                return Err(ExchangeError::Protocol(format!(
                    "the joiner sent a {frame:?} frame where its lists end"
                )));
            }
        }
    }
    write_frame(
        &mut tls,
        &PeerFrame::Offer {
            ssid: offer.ssid.clone(),
            passphrase: offer.wire_passphrase(),
            security: offer.security,
            port: offer.port,
        },
    )
    .await
    .map_err(classify_frame)
    .map_err(ExchangeError::from)?;
    // The joiner's reads may already be done, so the close can fail.
    let _ = tls.shutdown().await;
    Ok(peer)
}

/// The joiner's side, the dial's side of a link without the registration.
async fn joiner_exchange<S: AsyncRead + AsyncWrite + Unpin>(
    state: &NodeState,
    io: S,
    identity: &Identity,
) -> Result<(DeviceIdentity, OfferFrame), ExchangeError> {
    let config = client_config_for(
        &state.trust,
        state.verifier.clock(),
        *state.own_key.read(),
        Arc::clone(&state.crls),
        identity,
    );
    let connector = TlsConnector::from(config);
    let domain = ServerName::try_from(DIAL_NAME).expect("a valid dial name");
    let mut tls = connector
        .connect(domain, io)
        .await
        .map_err(|err| ExchangeError::from(classify_io(err)))?;
    let leaf = {
        let certs = tls
            .get_ref()
            .1
            .peer_certificates()
            .expect("the client auth is mandatory");
        let (Some(leaf), Some(_)) = (certs.first(), certs.get(1)) else {
            return Err(ExchangeError::Protocol(
                "the peer presented no issuer certificate".into(),
            ));
        };
        leaf.to_vec()
    };
    let peer = DeviceCertificate::parse(&leaf)
        .expect("the profile was verified at the handshake")
        .identity()
        .clone();
    let _ = exchange_hello(&mut tls, state, 0).await?;
    // The host reads the joiner's lists until this write side closes, so the
    // close ends the swap, and the offer is the host's next and last frame.
    tls.shutdown().await.map_err(ExchangeError::Io)?;
    loop {
        let frame = read_frame(&mut tls)
            .await
            .map_err(classify_frame)
            .map_err(ExchangeError::from)?;
        match frame {
            Some(PeerFrame::List { list, signer }) => {
                hand_list(state, list.to_vec(), signer.to_vec());
            }
            Some(PeerFrame::Offer {
                ssid,
                passphrase,
                security,
                port,
            }) => {
                return Ok((
                    peer,
                    OfferFrame {
                        ssid,
                        passphrase: passphrase.into_bytes(),
                        security,
                        port,
                    },
                ));
            }
            Some(frame) => {
                return Err(ExchangeError::Protocol(format!(
                    "the host sent a {frame:?} frame where the offer comes"
                )));
            }
            None => {
                return Err(ExchangeError::Protocol(
                    "the host closed before its offer".into(),
                ));
            }
        }
    }
}

/// Hand a received list to the node, the way a link hands one, so it reaches
/// the client's one intake.
fn hand_list(state: &NodeState, list: Vec<u8>, signer: Vec<u8>) {
    state
        .events
        .send(PeerEvent::ListReceived { list, signer })
        .ok();
}
