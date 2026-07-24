//! Browser WebSocket transport for the connetto client on wasm32.
//!
//! Implements [`Transport`] over `web_sys::WebSocket` with the same framing
//! as the native transport: every message is a binary frame whose first byte
//! is a wire tag from `connetto_core::codec`, followed by the MessagePack
//! payload. The futures are not `Send` (they hold JS values), which is
//! exactly what the `MaybeSend` seam in `connetto-core` exists for.
//!
//! The [`relay`] module builds on it: a [`RelayHub`] re-serves the wire
//! protocol from a worker-held connection to any number of tabs, [`port`]
//! and [`broadcast`] carry that protocol over a `MessagePort` and a named
//! `BroadcastChannel`, [`locks`] provides Web Locks liveness for dead-tab
//! reaping and leader election, [`workers`] holds the DB worker entry point
//! and the page-side glue of the leader topology, and [`leader`] runs the
//! multi-page election that decides which page owns the DB worker.

pub mod broadcast;
pub mod leader;
pub mod locks;
pub mod port;
pub mod relay;
pub mod workers;

pub use broadcast::{BroadcastTransport, BroadcastTransportError};
pub use leader::{Membership, join};
pub use port::{PortTransport, PortTransportError};
pub use relay::{HubNotice, RelayError, RelayHub, TabId};

use connetto_core::codec::{
    TAG_BULK, TAG_CONTROL, decode_bulk, decode_control, encode_bulk, encode_control,
};
use connetto_core::error::CodecError;
use connetto_core::messages::{BulkMessage, ControlMessage};
use connetto_core::traits::{IncomingFrame, Transport};
use futures_channel::mpsc;
use futures_util::StreamExt;
use js_sys::{ArrayBuffer, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{BinaryType, CloseEvent, Event, MessageEvent, WebSocket};

/// Failure surfaced by [`BrowserSocket`].
#[derive(Debug, thiserror::Error)]
pub enum BrowserSocketError {
    /// The browser WebSocket reported an error or refused the operation.
    #[error("websocket error: {0}")]
    Socket(String),
    /// A frame could not be encoded or decoded.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// The peer sent an empty binary frame.
    #[error("empty frame")]
    EmptyFrame,
    /// The peer sent a frame with an unknown wire tag.
    #[error("unknown frame tag {0}")]
    UnknownTag(u8),
}

/// What the JS event handlers feed into the receive queue.
enum Inbound {
    /// The socket finished its opening handshake.
    Opened,
    /// One binary frame arrived.
    Frame(Vec<u8>),
    /// The socket closed or errored. Carries the close reason when known.
    Closed(Option<String>),
}

/// A [`Transport`] over the browser's `WebSocket`.
///
/// The closures stay alive as long as the socket: dropping them would
/// unregister the JS event handlers mid-session.
pub struct BrowserSocket {
    ws: WebSocket,
    inbound: mpsc::UnboundedReceiver<Inbound>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_open: Closure<dyn FnMut(Event)>,
    _on_error: Closure<dyn FnMut(Event)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
}

impl BrowserSocket {
    /// Open a WebSocket to `url` and complete the opening handshake.
    ///
    /// # Errors
    ///
    /// [`BrowserSocketError::Socket`] when the URL is refused or the socket
    /// closes before it opens.
    pub async fn connect(url: &str) -> Result<Self, BrowserSocketError> {
        let ws =
            WebSocket::new(url).map_err(|err| BrowserSocketError::Socket(format!("{err:?}")))?;
        ws.set_binary_type(BinaryType::Arraybuffer);

        let (tx, inbound) = mpsc::unbounded::<Inbound>();

        let on_message = {
            let tx = tx.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                if let Ok(buffer) = event.data().dyn_into::<ArrayBuffer>() {
                    let bytes = Uint8Array::new(&buffer).to_vec();
                    let _ = tx.unbounded_send(Inbound::Frame(bytes));
                }
            })
        };
        let on_open = {
            let tx = tx.clone();
            Closure::<dyn FnMut(Event)>::new(move |_event: Event| {
                let _ = tx.unbounded_send(Inbound::Opened);
            })
        };
        let on_error = {
            let tx = tx.clone();
            Closure::<dyn FnMut(Event)>::new(move |_event: Event| {
                let _ = tx.unbounded_send(Inbound::Closed(Some("websocket error".to_owned())));
            })
        };
        let on_close = {
            let tx = tx.clone();
            Closure::<dyn FnMut(CloseEvent)>::new(move |event: CloseEvent| {
                let reason = event.reason();
                let reason = (!reason.is_empty()).then_some(reason);
                let _ = tx.unbounded_send(Inbound::Closed(reason));
            })
        };
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));

        let mut socket = Self {
            ws,
            inbound,
            _on_message: on_message,
            _on_open: on_open,
            _on_error: on_error,
            _on_close: on_close,
        };
        match socket.inbound.next().await {
            Some(Inbound::Opened) => Ok(socket),
            Some(Inbound::Closed(reason)) => Err(BrowserSocketError::Socket(
                reason.unwrap_or_else(|| "closed before open".to_owned()),
            )),
            Some(Inbound::Frame(_)) | None => Err(BrowserSocketError::Socket(
                "socket gone before open".to_owned(),
            )),
        }
    }

    fn send_frame(&self, tag: u8, payload: &[u8]) -> Result<(), BrowserSocketError> {
        let mut framed = Vec::with_capacity(1 + payload.len());
        framed.push(tag);
        framed.extend_from_slice(payload);
        self.ws
            .send_with_u8_array(&framed)
            .map_err(|err| BrowserSocketError::Socket(format!("{err:?}")))
    }
}

impl Transport for BrowserSocket {
    type Error = BrowserSocketError;

    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        self.send_frame(TAG_CONTROL, &encode_control(&message)?)
    }

    async fn send_bulk(&mut self, message: BulkMessage) -> Result<(), Self::Error> {
        self.send_frame(TAG_BULK, &encode_bulk(&message)?)
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        loop {
            match self.inbound.next().await {
                Some(Inbound::Frame(buf)) => {
                    let (tag, payload) = buf.split_first().ok_or(BrowserSocketError::EmptyFrame)?;
                    return match *tag {
                        TAG_CONTROL => Ok(Some(IncomingFrame::Control(decode_control(payload)?))),
                        TAG_BULK => Ok(Some(IncomingFrame::Bulk(decode_bulk(payload)?))),
                        other => Err(BrowserSocketError::UnknownTag(other)),
                    };
                }
                // A second Opened cannot happen, tolerate it as a no-op.
                Some(Inbound::Opened) => {}
                Some(Inbound::Closed(_)) | None => return Ok(None),
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.ws
            .close_with_code(1000)
            .map_err(|err| BrowserSocketError::Socket(format!("{err:?}")))
    }
}

impl Drop for BrowserSocket {
    fn drop(&mut self) {
        // Unregister the JS handlers before the closures drop, so a late
        // event (the server's close acknowledgement after `close`) never
        // fires into a dropped closure. Plain setter calls, nothing panics.
        self.ws.set_onmessage(None);
        self.ws.set_onopen(None);
        self.ws.set_onerror(None);
        self.ws.set_onclose(None);
    }
}
