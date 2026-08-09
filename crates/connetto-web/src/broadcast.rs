//! The `BroadcastChannel` end of the [frame pump](crate::frames), the
//! tab-to-DB-worker leg of the leader topology.
//!
//! Independent browsing contexts cannot exchange `MessagePort`s without a
//! broker, which is the one irreplaceable thing a `SharedWorker` provides, and
//! Chrome cannot host the DB tier in a `SharedWorker` (no nested workers, no
//! OPFS sync access handles there). A `BroadcastChannel` with a per-tab name
//! is the port replacement: it reaches across unrelated same-origin contexts
//! with in-order delivery, and with exactly one context on each end of a
//! uniquely named channel it is a two-party link.
//!
//! A channel never delivers to its own context, so both endpoints MUST live
//! in different contexts, and it never buffers for future subscribers, so
//! the peer's channel must exist before the first frame is posted. The
//! worker's intake protocol acknowledges attachment for exactly that reason.

use wasm_bindgen::JsValue;
use web_sys::BroadcastChannel;

use crate::frames::{MessageSink, MessageTransport, MessageTransportError, TAG_CLOSE};

impl MessageSink for BroadcastChannel {
    const LABEL: &'static str = "broadcast channel error";

    fn post(&self, message: &JsValue) -> Result<(), JsValue> {
        self.post_message(message)
    }

    fn set_handler(&self, handler: Option<&js_sys::Function>) {
        self.set_onmessage(handler);
    }

    fn close(&self) {
        BroadcastChannel::close(self);
    }
}

impl MessageTransport<BroadcastChannel> {
    /// Join the channel `name`.
    ///
    /// # Errors
    ///
    /// [`MessageTransportError::Sink`] when the browser refuses the channel.
    pub fn new(name: &str) -> Result<Self, MessageTransportError> {
        Ok(Self::join(name)?.0)
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
    /// [`MessageTransportError::Sink`] when the browser refuses the channel.
    pub fn with_peer_liveness(
        name: &str,
        liveness_lock: &str,
    ) -> Result<Self, MessageTransportError> {
        let (transport, tx) = Self::join(name)?;
        let lock = liveness_lock.to_owned();
        wasm_bindgen_futures::spawn_local(async move {
            crate::locks::wait_until_free(&lock).await;
            // A dropped transport just means nobody is listening any more.
            let _ = tx.unbounded_send(vec![TAG_CLOSE]);
        });
        Ok(transport)
    }

    /// Open the channel and attach, handing back the inbound sender for the
    /// liveness watcher.
    fn join(
        name: &str,
    ) -> Result<(Self, futures_channel::mpsc::UnboundedSender<Vec<u8>>), MessageTransportError>
    {
        let channel = BroadcastChannel::new(name)
            .map_err(|err| MessageTransportError::refused::<BroadcastChannel>(&err))?;
        Ok(Self::attach(channel))
    }
}
