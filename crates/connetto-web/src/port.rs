//! The `MessagePort` end of the [frame pump](crate::frames), the tab-to-worker
//! leg of the relay topology.

use wasm_bindgen::JsValue;
use web_sys::MessagePort;

use crate::frames::{MessageSink, MessageTransport};

impl MessageSink for MessagePort {
    const LABEL: &'static str = "message port error";

    fn post(&self, message: &JsValue) -> Result<(), JsValue> {
        self.post_message(message)
    }

    fn set_handler(&self, handler: Option<&js_sys::Function>) {
        self.set_onmessage(handler);
    }

    fn close(&self) {
        MessagePort::close(self);
    }
}

impl MessageTransport<MessagePort> {
    /// Wrap one end of a `MessageChannel`.
    ///
    /// Assigning `onmessage` starts the port's message queue, so frames the
    /// peer posted before this call are delivered, not lost.
    #[must_use]
    pub fn new(port: MessagePort) -> Self {
        Self::attach(port).0
    }
}
