//! The frame pump both browser message transports ride.
//!
//! A `MessagePort` and a `BroadcastChannel` differ only in how a context gets
//! hold of one. Both post binary messages, deliver them to an `onmessage`
//! handler, and close, so the framing, the close semantics, and the drop
//! sequence live here once and each object supplies only [`MessageSink`].
//!
//! Framing matches the `WebSocket` transport: one binary message per frame, a
//! wire tag byte followed by the `MessagePack` payload. Neither object reports
//! the peer going away, so a private close sentinel stands in for a close
//! event.

use connetto_core::codec::{
    TAG_BULK, TAG_CONTROL, decode_bulk, decode_control, encode_bulk, encode_control,
};
use connetto_core::error::CodecError;
use connetto_core::messages::{BulkMessage, ControlMessage};
use connetto_core::traits::{IncomingFrame, Transport};
use futures_channel::mpsc;
use futures_util::StreamExt;
use js_sys::Uint8Array;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;
use web_sys::MessageEvent;

/// Private wire tag marking a clean close. Never reaches the codec layer,
/// shared by every message-delimited transport in this crate.
pub(crate) const TAG_CLOSE: u8 = 0xFF;

/// A browser object that carries binary messages one frame at a time.
pub trait MessageSink {
    /// How this sink names itself when it refuses something.
    const LABEL: &'static str;

    /// Post one message to the peer.
    ///
    /// # Errors
    ///
    /// The browser's own error when the sink refuses the message.
    fn post(&self, message: &JsValue) -> Result<(), JsValue>;

    /// Install the inbound handler, or detach it with `None`.
    fn set_handler(&self, handler: Option<&js_sys::Function>);

    /// Close this end.
    fn close(&self);
}

/// Failure surfaced by [`MessageTransport`].
#[derive(Debug, thiserror::Error)]
pub enum MessageTransportError {
    /// The sink refused a message, or could not be created.
    #[error("{0}")]
    Sink(String),
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

impl MessageTransportError {
    /// A refusal by `S`, labelled with what the sink calls itself.
    pub(crate) fn refused<S: MessageSink>(err: &JsValue) -> Self {
        Self::Sink(format!("{}: {err:?}", S::LABEL))
    }
}

/// A [`Transport`] over one end of a browser message sink.
///
/// The closure stays alive as long as the transport: dropping it would
/// unregister the JS message handler mid-session.
pub struct MessageTransport<S: MessageSink> {
    sink: S,
    inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    closed: bool,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
}

impl<S: MessageSink> MessageTransport<S> {
    /// Wrap `sink` and start pumping its inbound messages, handing back the
    /// sender so a caller can inject a synthetic frame of its own.
    ///
    /// Installing the handler starts a port's queued delivery, so frames the
    /// peer posted before this call arrive rather than being lost.
    pub(crate) fn attach(sink: S) -> (Self, mpsc::UnboundedSender<Vec<u8>>) {
        let (tx, inbound) = mpsc::unbounded::<Vec<u8>>();
        let on_message = {
            let tx = tx.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                if let Ok(bytes) = event.data().dyn_into::<Uint8Array>() {
                    let _ = tx.unbounded_send(bytes.to_vec());
                }
            })
        };
        sink.set_handler(Some(on_message.as_ref().unchecked_ref()));
        (
            Self {
                sink,
                inbound,
                closed: false,
                _on_message: on_message,
            },
            tx,
        )
    }

    fn send_frame(&self, tag: u8, payload: &[u8]) -> Result<(), MessageTransportError> {
        let mut framed = Vec::with_capacity(1 + payload.len());
        framed.push(tag);
        framed.extend_from_slice(payload);
        self.sink
            .post(&Uint8Array::from(framed.as_slice()))
            .map_err(|err| MessageTransportError::refused::<S>(&err))
    }
}

impl<S: MessageSink> Transport for MessageTransport<S> {
    type Error = MessageTransportError;

    #[allow(clippy::unused_async_trait_impl)]
    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        self.send_frame(TAG_CONTROL, &encode_control(&message)?)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn send_bulk(&mut self, message: BulkMessage) -> Result<(), Self::Error> {
        self.send_frame(TAG_BULK, &encode_bulk(&message)?)
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        if self.closed {
            return Ok(None);
        }
        match self.inbound.next().await {
            None => Ok(None),
            Some(buf) => {
                let (tag, payload) = buf.split_first().ok_or(MessageTransportError::EmptyFrame)?;
                match *tag {
                    TAG_CONTROL => Ok(Some(IncomingFrame::Control(decode_control(payload)?))),
                    TAG_BULK => Ok(Some(IncomingFrame::Bulk(decode_bulk(payload)?))),
                    TAG_CLOSE => {
                        self.closed = true;
                        Ok(None)
                    }
                    other => Err(MessageTransportError::UnknownTag(other)),
                }
            }
        }
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn close(&mut self) -> Result<(), Self::Error> {
        // Best effort: the peer may already be gone.
        let _ = self.send_frame(TAG_CLOSE, &[]);
        self.sink.close();
        Ok(())
    }
}

impl<S: MessageSink> Drop for MessageTransport<S> {
    fn drop(&mut self) {
        // Tell the peer (a second sentinel after an explicit close is
        // harmless), detach the JS handler before the closure drops, and
        // close the sink. All plain setters and posts, nothing panics.
        let _ = self.send_frame(TAG_CLOSE, &[]);
        self.sink.set_handler(None);
        self.sink.close();
    }
}
