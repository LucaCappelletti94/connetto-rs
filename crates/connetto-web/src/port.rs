//! A [`Transport`] over a browser `MessagePort`, the tab-to-worker leg of the
//! relay topology.
//!
//! Framing matches the WebSocket transport: one binary message per frame, a
//! wire tag byte followed by the `MessagePack` payload. A dedicated close
//! sentinel tag stands in for a close event, since `MessagePort` offers no
//! reliable way to observe the peer going away.

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
use wasm_bindgen::closure::Closure;
use web_sys::{MessageEvent, MessagePort};

/// Private wire tag marking a clean close. Never reaches the codec layer,
/// shared by every message-delimited transport in this crate.
pub(crate) const TAG_CLOSE: u8 = 0xFF;

/// Failure surfaced by [`PortTransport`].
#[derive(Debug, thiserror::Error)]
pub enum PortTransportError {
    /// The port refused a message.
    #[error("message port error: {0}")]
    Port(String),
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

/// A [`Transport`] over one end of a browser `MessageChannel`.
///
/// The closure stays alive as long as the transport: dropping it would
/// unregister the JS message handler mid-session.
pub struct PortTransport {
    port: MessagePort,
    inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    closed: bool,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
}

impl PortTransport {
    /// Wrap one end of a `MessageChannel`.
    ///
    /// Assigning `onmessage` starts the port's message queue, so frames the
    /// peer posted before this call are delivered, not lost.
    #[must_use]
    pub fn new(port: MessagePort) -> Self {
        let (tx, inbound) = mpsc::unbounded::<Vec<u8>>();
        let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if let Ok(bytes) = event.data().dyn_into::<Uint8Array>() {
                let _ = tx.unbounded_send(bytes.to_vec());
            }
        });
        port.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        Self {
            port,
            inbound,
            closed: false,
            _on_message: on_message,
        }
    }

    fn send_frame(&self, tag: u8, payload: &[u8]) -> Result<(), PortTransportError> {
        let mut framed = Vec::with_capacity(1 + payload.len());
        framed.push(tag);
        framed.extend_from_slice(payload);
        self.port
            .post_message(&Uint8Array::from(framed.as_slice()))
            .map_err(|err| PortTransportError::Port(format!("{err:?}")))
    }
}

impl Transport for PortTransport {
    type Error = PortTransportError;

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
                let (tag, payload) = buf.split_first().ok_or(PortTransportError::EmptyFrame)?;
                match *tag {
                    TAG_CONTROL => Ok(Some(IncomingFrame::Control(decode_control(payload)?))),
                    TAG_BULK => Ok(Some(IncomingFrame::Bulk(decode_bulk(payload)?))),
                    TAG_CLOSE => {
                        self.closed = true;
                        Ok(None)
                    }
                    other => Err(PortTransportError::UnknownTag(other)),
                }
            }
        }
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn close(&mut self) -> Result<(), Self::Error> {
        // Best effort: the peer may already be gone.
        let _ = self.send_frame(TAG_CLOSE, &[]);
        self.port.close();
        Ok(())
    }
}

impl Drop for PortTransport {
    fn drop(&mut self) {
        // Tell the peer (a second sentinel after an explicit close is
        // harmless), detach the JS handler before the closure drops, and
        // close the port. All plain setters and posts, nothing panics.
        let _ = self.send_frame(TAG_CLOSE, &[]);
        self.port.set_onmessage(None);
        self.port.close();
    }
}
