//! A [`Transport`] over a named `BroadcastChannel`, the tab-to-DB-worker leg
//! of the leader topology.
//!
//! Independent browsing contexts cannot exchange `MessagePort`s without a
//! broker, which is the one irreplaceable thing a SharedWorker provides, and
//! Chrome cannot host the DB tier in a SharedWorker (no nested workers, no
//! OPFS sync access handles there). A `BroadcastChannel` with a per-tab name
//! is the port replacement: it reaches across unrelated same-origin contexts
//! with in-order delivery, and with exactly one context on each end of a
//! uniquely named channel it is a two-party link. Framing matches the other
//! transports: a wire tag byte followed by the `MessagePack` payload, with
//! the private close sentinel standing in for a close event.
//!
//! A channel never delivers to its own context, so both endpoints MUST live
//! in different contexts, and it never buffers for future subscribers, so
//! the peer's channel must exist before the first frame is posted. The
//! worker's intake protocol acknowledges attachment for exactly that reason.

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
use web_sys::{BroadcastChannel, MessageEvent};

use crate::port::TAG_CLOSE;

/// Failure surfaced by [`BroadcastTransport`].
#[derive(Debug, thiserror::Error)]
pub enum BroadcastTransportError {
    /// The channel refused a message or could not be created.
    #[error("broadcast channel error: {0}")]
    Channel(String),
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

/// A [`Transport`] over one end of a uniquely named `BroadcastChannel`.
///
/// The closure stays alive as long as the transport: dropping it would
/// unregister the JS message handler mid-session.
pub struct BroadcastTransport {
    channel: BroadcastChannel,
    inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    closed: bool,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
}

impl BroadcastTransport {
    /// Join the channel `name`.
    ///
    /// # Errors
    ///
    /// [`BroadcastTransportError::Channel`] when the browser refuses the
    /// channel.
    pub fn new(name: &str) -> Result<Self, BroadcastTransportError> {
        Ok(Self::build(name)?.0)
    }

    /// Join the channel `name` and watch the peer's liveness lock: a
    /// broadcast peer dies silently, so when the lock frees (its holder's
    /// context is gone) a synthetic close is injected and `recv` reports a
    /// clean close instead of waiting forever.
    ///
    /// The caller MUST know the peer holds the lock before connecting (the
    /// DB worker holds its alive lock before answering ready), or the
    /// transport closes immediately.
    ///
    /// # Errors
    ///
    /// [`BroadcastTransportError::Channel`] when the browser refuses the
    /// channel.
    pub fn with_peer_liveness(
        name: &str,
        liveness_lock: &str,
    ) -> Result<Self, BroadcastTransportError> {
        let (transport, tx) = Self::build(name)?;
        let lock = liveness_lock.to_owned();
        wasm_bindgen_futures::spawn_local(async move {
            crate::locks::wait_until_free(&lock).await;
            // A dropped transport just means nobody is listening any more.
            let _ = tx.unbounded_send(vec![TAG_CLOSE]);
        });
        Ok(transport)
    }

    /// Shared constructor body, handing back the inbound sender for the
    /// liveness watcher.
    fn build(
        name: &str,
    ) -> Result<(Self, mpsc::UnboundedSender<Vec<u8>>), BroadcastTransportError> {
        let channel = BroadcastChannel::new(name)
            .map_err(|err| BroadcastTransportError::Channel(format!("{err:?}")))?;
        let (tx, inbound) = mpsc::unbounded::<Vec<u8>>();
        let on_message = {
            let tx = tx.clone();
            Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                if let Ok(bytes) = event.data().dyn_into::<Uint8Array>() {
                    let _ = tx.unbounded_send(bytes.to_vec());
                }
            })
        };
        channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        Ok((
            Self {
                channel,
                inbound,
                closed: false,
                _on_message: on_message,
            },
            tx,
        ))
    }

    fn send_frame(&self, tag: u8, payload: &[u8]) -> Result<(), BroadcastTransportError> {
        let mut framed = Vec::with_capacity(1 + payload.len());
        framed.push(tag);
        framed.extend_from_slice(payload);
        self.channel
            .post_message(&Uint8Array::from(framed.as_slice()))
            .map_err(|err| BroadcastTransportError::Channel(format!("{err:?}")))
    }
}

impl Transport for BroadcastTransport {
    type Error = BroadcastTransportError;

    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        self.send_frame(TAG_CONTROL, &encode_control(&message)?)
    }

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
                let (tag, payload) = buf
                    .split_first()
                    .ok_or(BroadcastTransportError::EmptyFrame)?;
                match *tag {
                    TAG_CONTROL => Ok(Some(IncomingFrame::Control(decode_control(payload)?))),
                    TAG_BULK => Ok(Some(IncomingFrame::Bulk(decode_bulk(payload)?))),
                    TAG_CLOSE => {
                        self.closed = true;
                        Ok(None)
                    }
                    other => Err(BroadcastTransportError::UnknownTag(other)),
                }
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        // Best effort: the peer may already be gone.
        let _ = self.send_frame(TAG_CLOSE, &[]);
        self.channel.close();
        Ok(())
    }
}

impl Drop for BroadcastTransport {
    fn drop(&mut self) {
        // Tell the peer (a second sentinel after an explicit close is
        // harmless), detach the JS handler before the closure drops, and
        // close the channel. All plain setters and posts, nothing panics.
        let _ = self.send_frame(TAG_CLOSE, &[]);
        self.channel.set_onmessage(None);
        self.channel.close();
    }
}
