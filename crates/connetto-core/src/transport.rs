//! In-process and native [`Transport`] implementations.
//!
//! Two backings are provided:
//!
//! * [`LoopbackTransport`]: an in-memory pair connected by channels, for
//!   single-process wiring, fast tests, and the browser relay's tab side. It
//!   rides only the sync primitives, so it compiles on wasm (feature
//!   `loopback`).
//! * [`WebSocketTransport`]: the native `tokio-tungstenite` transport per
//!   `docs/architecture/09-wasm.md` (feature `native-transport`). The browser
//!   client provides its own `web-sys` backed transport instead. A native
//!   client dials a `ws` or `wss` endpoint through [`dial`], which verifies a
//!   `wss` endpoint against the platform's trust store and opens a plain
//!   socket for a `ws` endpoint only when its host is loopback.
//!
//! Over a raw byte transport a control and a bulk frame must be told apart.
//! Each `WebSocket` message is a binary frame whose first byte is a kind tag
//! (`TAG_CONTROL` or `TAG_BULK`) followed by the `MessagePack` payload.
//! `MessagePack` payloads are not valid UTF-8, so text frames are never used.

#[cfg(feature = "native-transport")]
use crate::codec::{
    TAG_BULK, TAG_CONTROL, decode_bulk, decode_control, encode_bulk, encode_control,
};
#[cfg(feature = "native-transport")]
use crate::error::CodecError;
use crate::messages::{BulkMessage, ControlMessage};
use crate::traits::{IncomingFrame, Transport};
#[cfg(feature = "native-transport")]
use futures_util::{SinkExt, StreamExt};
#[cfg(feature = "native-transport")]
use rustls_platform_verifier::BuilderVerifierExt;
#[cfg(feature = "native-transport")]
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(feature = "native-transport")]
use tokio::net::TcpStream;
use tokio::sync::mpsc;
#[cfg(feature = "native-transport")]
use tokio_tungstenite::tungstenite::Message;
#[cfg(feature = "native-transport")]
use tokio_tungstenite::{WebSocketStream, accept_async, client_async};

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

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        self.tx
            .as_ref()
            .ok_or(LoopbackError::Disconnected)?
            .send(IncomingFrame::Control(message))
            .map_err(|_| LoopbackError::Disconnected)
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
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

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
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
#[cfg(feature = "native-transport")]
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

#[cfg(feature = "native-transport")]
impl From<tokio_tungstenite::tungstenite::Error> for WebSocketError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        Self::Ws(Box::new(err))
    }
}

/// The native WebSocket transport over any async byte stream.
///
/// Construct one with [`WebSocketTransport::accept`] (server side) or
/// [`WebSocketTransport::connect`] (client side) over a [`TcpStream`].
#[cfg(feature = "native-transport")]
pub struct WebSocketTransport<S> {
    stream: WebSocketStream<S>,
}

#[cfg(feature = "native-transport")]
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

/// The stream a native [`dial`] produces before the WebSocket handshake,
/// plain TCP for a loopback `ws` endpoint and a rustls stream for `wss`.
#[cfg(feature = "native-transport")]
pub enum NativeStream {
    /// A plain TCP socket, for a loopback `ws` endpoint.
    Plain(TcpStream),
    /// A rustls-encrypted socket, for a `wss` endpoint.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

#[cfg(feature = "native-transport")]
impl std::convert::From<TcpStream> for NativeStream {
    fn from(stream: TcpStream) -> Self {
        NativeStream::Plain(stream)
    }
}

#[cfg(feature = "native-transport")]
impl std::convert::From<tokio_rustls::client::TlsStream<TcpStream>> for NativeStream {
    fn from(stream: tokio_rustls::client::TlsStream<TcpStream>) -> Self {
        NativeStream::Tls(Box::new(stream))
    }
}

#[cfg(feature = "native-transport")]
impl AsyncRead for NativeStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            NativeStream::Plain(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            NativeStream::Tls(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

#[cfg(feature = "native-transport")]
impl AsyncWrite for NativeStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            NativeStream::Plain(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            NativeStream::Tls(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            NativeStream::Plain(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            NativeStream::Tls(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            NativeStream::Plain(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            NativeStream::Tls(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// A refused or failed native dial, at the URL, socket, TLS, or handshake step.
#[cfg(feature = "native-transport")]
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// The URL is not a `ws` or `wss` endpoint.
    #[error("not a WebSocket endpoint: {0}")]
    NotWebSocket(String),
    /// A plain `ws` endpoint naming a host outside the loopback.
    #[error("plain ws:// to a non-loopback host is refused: {0}")]
    PlainToNonLoopback(String),
    /// The socket, TLS, or handshake step failed.
    #[error("dial failed: {0}")]
    Dial(String),
    /// The TLS layer failed, a permanent refusal the platform verifier
    /// will not pass on a retry, such as a certificate it does not trust.
    #[error("tls refused: {0}")]
    Tls(String),
}

/// Whether the host of a `ws` or `wss` URL is loopback, meaning `localhost`,
/// the `127.0.0.0/8` block, or `::1`, in an `IPv6` literal or not.
#[cfg(feature = "native-transport")]
#[must_use]
pub fn ws_host_is_loopback(host: &str) -> bool {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host == "localhost" || host == "::1" {
        return true;
    }
    host.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Dial a native `ws` or `wss` endpoint and complete the client WebSocket
/// handshake.
///
/// A `wss` endpoint is a TLS dial whose certificate the platform's trust
/// store verifies. A plain `ws` endpoint opens a socket only for a
/// loopback host and is refused with
/// [`DialError::PlainToNonLoopback`] before a socket opens for anything
/// else, because the sync loop carries credentials and a plaintext channel
/// to a remote host is not a level a build provides.
///
/// # Errors
///
/// [`DialError`] when the URL is not a `ws` or `wss` endpoint, when a plain
/// `ws` names a non-loopback host, or when the socket, TLS, or handshake
/// step fails.
#[cfg(feature = "native-transport")]
pub async fn dial(url: &str) -> Result<WebSocketTransport<NativeStream>, DialError> {
    let (request, stream) = dial_stream(url).await?;
    let (ws, _response) = client_async(&request, stream)
        .await
        .map_err(|err| DialError::Dial(err.to_string()))?;
    Ok(WebSocketTransport { stream: ws })
}

#[cfg(feature = "native-transport")]
async fn dial_stream(url: &str) -> Result<(String, NativeStream), DialError> {
    let parsed = url::Url::parse(url).map_err(|err| DialError::NotWebSocket(err.to_string()))?;
    match parsed.scheme() {
        "ws" => {
            let host = parsed
                .host_str()
                .ok_or_else(|| DialError::NotWebSocket(url.to_owned()))?
                .to_owned();
            if !ws_host_is_loopback(&host) {
                return Err(DialError::PlainToNonLoopback(host));
            }
            let port = parsed.port().unwrap_or(80);
            let stream = TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|err| DialError::Dial(err.to_string()))?;
            Ok((url.to_owned(), NativeStream::from(stream)))
        }
        "wss" => {
            let host = parsed
                .host_str()
                .ok_or_else(|| DialError::NotWebSocket(url.to_owned()))?
                .to_owned();
            let port = parsed.port().unwrap_or(443);
            let tcp = TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|err| DialError::Dial(err.to_string()))?;
            let provider = rustls::crypto::ring::default_provider();
            let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider))
                .with_safe_default_protocol_versions()
                .map_err(|err| DialError::Tls(err.to_string()))?
                .with_platform_verifier()
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
            let name = rustls::pki_types::ServerName::try_from(host)
                .map_err(|err| DialError::Tls(err.to_string()))?;
            let tls = connector
                .connect(name, tcp)
                .await
                .map_err(|err| DialError::Tls(err.to_string()))?;
            let request = format!("ws://{}", &url["wss://".len()..]);
            Ok((request, NativeStream::from(tls)))
        }
        scheme => Err(DialError::NotWebSocket(format!(
            "the {scheme} scheme is not a WebSocket endpoint"
        ))),
    }
}

#[cfg(feature = "native-transport")]
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

#[cfg(all(test, feature = "native-transport"))]
mod loopback_tests {
    use super::{DialError, dial, ws_host_is_loopback};

    #[test]
    fn loopback_hosts_are_accepted() {
        assert!(ws_host_is_loopback("localhost"));
        assert!(ws_host_is_loopback("127.0.0.7"));
        assert!(ws_host_is_loopback("127.1.1.1"));
        assert!(ws_host_is_loopback("::1"));
        assert!(ws_host_is_loopback("[::1]"));
    }

    #[test]
    fn non_loopback_hosts_are_refused() {
        assert!(!ws_host_is_loopback("10.0.0.5"));
        assert!(!ws_host_is_loopback("192.168.1.1"));
        assert!(!ws_host_is_loopback("8.8.8.8"));
        assert!(!ws_host_is_loopback("example.com"));
    }

    #[test]
    fn plain_ws_to_non_loopback_is_refused_before_a_socket() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let result = runtime.block_on(dial("ws://10.0.0.5:9000/sync"));
        match result {
            Err(DialError::PlainToNonLoopback(host)) => assert_eq!(host, "10.0.0.5"),
            Err(other) => panic!("expected PlainToNonLoopback, got {other:?}"),
            Ok(_) => panic!("expected a refusal, but the dial succeeded"),
        }
    }
}
