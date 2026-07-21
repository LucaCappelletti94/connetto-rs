//! [`Transport`] implementations for the session layer.
//!
//! Two backings are provided:
//!
//! * [`LoopbackTransport`]: an in-memory pair connected by channels, for
//!   single-process wiring and fast tests.
//! * [`WebSocketTransport`]: the native `tokio-tungstenite` transport per
//!   `docs/architecture/09-wasm.md`.
//!
//! Over a raw byte transport a control and a bulk frame must be told apart.
//! `connetto-core` leaves that to the transport ("WebSocket binary vs text
//! frames, or the caller's own discipline"). `MessagePack` payloads are not
//! valid UTF-8, so text frames are out. Each WebSocket message is therefore a
//! binary frame whose first byte is a kind tag (`TAG_CONTROL` or `TAG_BULK`)
//! followed by the `MessagePack` payload.

use connetto_core::CodecError;
use connetto_core::codec::{decode_bulk, decode_control, encode_bulk, encode_control};
use connetto_core::messages::{BulkMessage, ControlMessage};
use connetto_core::traits::{IncomingFrame, Transport};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{WebSocketStream, accept_async, client_async};

/// Wire tag for a control-plane frame.
const TAG_CONTROL: u8 = 0;
/// Wire tag for a bulk-plane frame.
const TAG_BULK: u8 = 1;

// ---------------------------------------------------------------------------
// Loopback
// ---------------------------------------------------------------------------

/// Error from the in-memory [`LoopbackTransport`].
#[derive(Debug, thiserror::Error)]
pub enum LoopbackError {
    /// The peer endpoint was dropped, so the channel is closed.
    #[error("loopback peer has hung up")]
    Disconnected,
}

/// One end of an in-memory transport pair.
///
/// Build a connected pair with [`loopback`]. Frames sent on one end surface as
/// [`IncomingFrame`]s on the other, in order.
pub struct LoopbackTransport {
    tx: Option<mpsc::UnboundedSender<IncomingFrame>>,
    rx: mpsc::UnboundedReceiver<IncomingFrame>,
}

/// Build a connected pair of loopback endpoints.
#[must_use]
pub fn loopback() -> (LoopbackTransport, LoopbackTransport) {
    let (a_tx, a_rx) = mpsc::unbounded_channel();
    let (b_tx, b_rx) = mpsc::unbounded_channel();
    (
        LoopbackTransport {
            tx: Some(a_tx),
            rx: b_rx,
        },
        LoopbackTransport {
            tx: Some(b_tx),
            rx: a_rx,
        },
    )
}

impl Transport for LoopbackTransport {
    type Error = LoopbackError;

    #[allow(clippy::unused_async_trait_impl)]
    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        self.tx
            .as_ref()
            .ok_or(LoopbackError::Disconnected)?
            .send(IncomingFrame::Control(message))
            .map_err(|_| LoopbackError::Disconnected)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn send_bulk(&mut self, message: BulkMessage) -> Result<(), Self::Error> {
        self.tx
            .as_ref()
            .ok_or(LoopbackError::Disconnected)?
            .send(IncomingFrame::Bulk(message))
            .map_err(|_| LoopbackError::Disconnected)
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        Ok(self.rx.recv().await)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn close(&mut self) -> Result<(), Self::Error> {
        // Dropping the sender closes the peer's receive channel, so its
        // `recv` returns `None` and its session loop ends.
        self.tx = None;
        self.rx.close();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

/// Error from the native [`WebSocketTransport`].
#[derive(Debug, thiserror::Error)]
pub enum WebSocketError {
    /// The underlying `tungstenite` stream failed.
    #[error("websocket error: {0}")]
    Ws(Box<tokio_tungstenite::tungstenite::Error>),
    /// A frame payload failed to encode or decode.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// A binary frame arrived with no kind tag byte.
    #[error("empty websocket frame")]
    EmptyFrame,
    /// A binary frame carried an unrecognized kind tag.
    #[error("unknown websocket frame tag {0}")]
    UnknownTag(u8),
}

impl From<tokio_tungstenite::tungstenite::Error> for WebSocketError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::Ws(Box::new(err))
    }
}

/// The native WebSocket transport over any async byte stream.
///
/// Construct one with [`WebSocketTransport::accept`] (server side) or
/// [`WebSocketTransport::connect`] (client side) over a [`TcpStream`].
pub struct WebSocketTransport<S> {
    stream: WebSocketStream<S>,
}

impl WebSocketTransport<TcpStream> {
    /// Complete the server-side WebSocket handshake over an accepted TCP stream.
    ///
    /// # Errors
    ///
    /// [`WebSocketError::Ws`] when the handshake fails.
    pub async fn accept(stream: TcpStream) -> Result<Self, WebSocketError> {
        Ok(Self {
            stream: accept_async(stream).await?,
        })
    }

    /// Complete the client-side WebSocket handshake over a connected TCP stream.
    ///
    /// `url` is the request URI (for example `ws://127.0.0.1:0/`). No TLS is
    /// used, so it must be a `ws://` endpoint.
    ///
    /// # Errors
    ///
    /// [`WebSocketError::Ws`] when the handshake fails.
    pub async fn connect(url: &str, stream: TcpStream) -> Result<Self, WebSocketError> {
        let (ws, _response) = client_async(url, stream).await?;
        Ok(Self { stream: ws })
    }
}

impl<S> Transport for WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    type Error = WebSocketError;

    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        let mut framed = Vec::with_capacity(1 + 64);
        framed.push(TAG_CONTROL);
        framed.extend_from_slice(&encode_control(&message)?);
        self.stream.send(Message::Binary(framed)).await?;
        Ok(())
    }

    async fn send_bulk(&mut self, message: BulkMessage) -> Result<(), Self::Error> {
        let mut framed = Vec::with_capacity(1 + 64);
        framed.push(TAG_BULK);
        framed.extend_from_slice(&encode_bulk(&message)?);
        self.stream.send(Message::Binary(framed)).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        loop {
            match self.stream.next().await {
                Some(Ok(Message::Binary(buf))) => {
                    let (tag, payload) = buf.split_first().ok_or(WebSocketError::EmptyFrame)?;
                    return match *tag {
                        TAG_CONTROL => Ok(Some(IncomingFrame::Control(decode_control(payload)?))),
                        TAG_BULK => Ok(Some(IncomingFrame::Bulk(decode_bulk(payload)?))),
                        other => Err(WebSocketError::UnknownTag(other)),
                    };
                }
                // A clean close or an exhausted stream both end the session.
                None | Some(Ok(Message::Close(_))) => return Ok(None),
                // Other WebSocket-level frames (Ping, Pong, Text) are not part
                // of the application protocol. tungstenite answers Ping itself.
                Some(Ok(_)) => {}
                Some(Err(err)) => return Err(err.into()),
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.stream.close(None).await?;
        Ok(())
    }
}
