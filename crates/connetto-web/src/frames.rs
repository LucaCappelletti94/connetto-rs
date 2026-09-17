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
//!
//! Alongside the codec frames rides an internal lane for the content
//! protocol: a frame under [`TAG_INTERNAL`] carries JSON rather than
//! `MessagePack`, and a message whose payload is a two-element array carries
//! a `Blob` beside that JSON. The lane never reaches the codec.

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

/// Private wire tag marking the internal content lane. Like the close
/// sentinel it never reaches the codec layer.
pub(crate) const TAG_INTERNAL: u8 = 0xFE;

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

/// One message from a transport's inbound internal lane.
#[derive(Debug)]
pub struct InternalInbound {
    /// The internal frame's JSON, without the tag byte.
    pub json: Vec<u8>,
    /// The bytes attached to the message, when it carried a blob.
    pub blob: Option<web_sys::Blob>,
}

/// Decode an internal message posted as `[bytes, blob]`, the shape
/// [`MessageTransport::post_internal`] writes. `None` rejects anything that
/// is not one.
fn decode_attached_internal(data: &JsValue) -> Option<InternalInbound> {
    let parts = data.dyn_ref::<js_sys::Array>()?;
    if parts.length() != 2 {
        return None;
    }
    let head = parts.get(0);
    let bytes = match head.clone().dyn_into::<Uint8Array>() {
        Ok(view) => view,
        Err(_) => Uint8Array::new(head.dyn_ref::<js_sys::ArrayBuffer>()?),
    };
    let blob = parts.get(1).dyn_into::<web_sys::Blob>().ok()?;
    let framed = bytes.to_vec();
    let (tag, json) = framed.split_first()?;
    if *tag != TAG_INTERNAL {
        return None;
    }
    Some(InternalInbound {
        json: json.to_vec(),
        blob: Some(blob),
    })
}

/// Post one internal message on `sink`: the JSON under the internal tag,
/// with the blob carried beside it rather than inside it.
fn post_internal_to<S: MessageSink>(
    sink: &S,
    json: &[u8],
    blob: Option<&web_sys::Blob>,
) -> Result<(), MessageTransportError> {
    let mut framed = Vec::with_capacity(1 + json.len());
    framed.push(TAG_INTERNAL);
    framed.extend_from_slice(json);
    let message = match blob {
        None => Uint8Array::from(framed.as_slice()).into(),
        Some(blob) => {
            js_sys::Array::of2(&Uint8Array::from(framed.as_slice()), blob.as_ref()).into()
        }
    };
    sink.post(&message)
        .map_err(|err| MessageTransportError::refused::<S>(&err))
}

/// A handle that posts internal messages on a transport's lane without
/// owning the transport, for the side that handed the transport over.
pub struct InternalLane<S: MessageSink> {
    sink: S,
}

impl<S: MessageSink> InternalLane<S> {
    /// Post one internal message, shaped as [`MessageTransport::post_internal`].
    ///
    /// # Errors
    ///
    /// [`MessageTransportError::Sink`] when the browser refuses the post.
    pub fn post_internal(
        &self,
        json: &[u8],
        blob: Option<&web_sys::Blob>,
    ) -> Result<(), MessageTransportError> {
        post_internal_to(&self.sink, json, blob)
    }
}

/// A [`Transport`] over one end of a browser message sink.
///
/// The closure stays alive as long as the transport: dropping it would
/// unregister the JS message handler mid-session.
pub struct MessageTransport<S: MessageSink> {
    sink: S,
    inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    internal: Option<mpsc::UnboundedReceiver<InternalInbound>>,
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
        let (internal_tx, internal) = mpsc::unbounded::<InternalInbound>();
        let on_message = {
            let tx = tx.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let data = event.data();
                if let Ok(bytes) = data.clone().dyn_into::<Uint8Array>() {
                    let raw = bytes.to_vec();
                    if raw.first() == Some(&TAG_INTERNAL) {
                        let _ = internal_tx.unbounded_send(InternalInbound {
                            json: raw[1..].to_vec(),
                            blob: None,
                        });
                    } else {
                        let _ = tx.unbounded_send(raw);
                    }
                    return;
                }
                if let Some(inbound) = decode_attached_internal(&data) {
                    let _ = internal_tx.unbounded_send(inbound);
                }
            })
        };
        sink.set_handler(Some(on_message.as_ref().unchecked_ref()));
        (
            Self {
                sink,
                inbound,
                internal: Some(internal),
                closed: false,
                _on_message: on_message,
            },
            tx,
        )
    }

    /// Take the inbound half of this transport's internal lane, once.
    pub fn take_internal_inbox(&mut self) -> Option<mpsc::UnboundedReceiver<InternalInbound>> {
        self.internal.take()
    }

    /// Hand out a handle that posts internal messages on this lane without
    /// owning the transport.
    pub fn internal_lane(&self) -> InternalLane<S>
    where
        S: Clone,
    {
        InternalLane {
            sink: self.sink.clone(),
        }
    }

    /// Post one internal message: its JSON under the internal tag, with the
    /// blob carried beside it rather than inside it.
    ///
    /// # Errors
    ///
    /// [`MessageTransportError::Sink`] when the browser refuses the post.
    pub fn post_internal(
        &self,
        json: &[u8],
        blob: Option<&web_sys::Blob>,
    ) -> Result<(), MessageTransportError> {
        post_internal_to(&self.sink, json, blob)
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

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        self.send_frame(TAG_CONTROL, &encode_control(&message)?)
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
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

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
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
