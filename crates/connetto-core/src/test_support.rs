//! Fakes shared by the client and browser test suites.
//!
//! Behind the `test-support` feature, so nothing here reaches a production build.
//! It lives in the core rather than in a test file because four suites across two
//! crates and both targets need the same fake, and the only things it depends on
//! are the transport trait and the message types, which are here.

use crate::messages::{BulkMessage, ControlMessage, FatalError, FatalErrorReason, HandshakeAck};
use crate::traits::{IncomingFrame, Transport};
use crate::{Cursor, SchemaVersion};
use std::collections::VecDeque;

/// How a [`FakeTransport`] answers the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeReply {
    /// A well-formed acknowledgement, so the handshake succeeds.
    Accept,
    /// `FatalError(AuthenticationFailed)`, so the credential is refused.
    Reject,
}

/// The typed error the transport trait requires. This fake never fails, so it
/// stands only for "the peer is gone".
#[derive(Debug, thiserror::Error)]
#[error("fake transport closed")]
pub struct FakeClosed;

/// A transport that answers the handshake with a canned reply and drops
/// everything else on the floor.
///
/// Enough to drive `connect`, `connect_existing`, and `resume` with no server.
/// Because it acknowledges nothing after the handshake, an uploaded mutation is
/// never retired, which is how a test arranges a replica that still has unsynced
/// work in it.
///
/// By default a drained inbox reads as end of stream, so the peer looks gone. That
/// suits a test driving a connection directly, and not one behind a task that reads
/// the upstream continuously, which would see the close and stop. For those,
/// [`accepting_but_silent`](Self::accepting_but_silent) stays open instead.
pub struct FakeTransport {
    reply: HandshakeReply,
    inbox: VecDeque<IncomingFrame>,
    /// Park on a drained inbox rather than reporting end of stream.
    silent: bool,
}

impl FakeTransport {
    /// A transport whose handshake succeeds.
    #[must_use]
    pub fn accepting() -> Self {
        Self::new(HandshakeReply::Accept)
    }

    /// A transport that refuses the credential at the handshake.
    #[must_use]
    pub fn rejecting() -> Self {
        Self::new(HandshakeReply::Reject)
    }

    /// A transport whose handshake succeeds and which then stays open forever
    /// without saying anything, so an uploaded mutation is neither acknowledged nor
    /// failed. This is a client that is connected but offline, as opposed to one
    /// whose peer has gone.
    #[must_use]
    pub fn accepting_but_silent() -> Self {
        Self {
            silent: true,
            ..Self::new(HandshakeReply::Accept)
        }
    }

    /// A transport answering with `reply`, whose peer looks gone once its inbox
    /// drains.
    #[must_use]
    pub fn new(reply: HandshakeReply) -> Self {
        Self {
            reply,
            inbox: VecDeque::new(),
            silent: false,
        }
    }

    fn answer(&self) -> IncomingFrame {
        match self.reply {
            HandshakeReply::Accept => {
                IncomingFrame::Control(ControlMessage::HandshakeAck(HandshakeAck {
                    connection_id: "connection-fake".to_owned(),
                    session_token: "token-fake".to_owned(),
                    current_cursor: Cursor::new(Vec::new()),
                    schema_version: None::<SchemaVersion>,
                    initial_credits: 64,
                    last_applied_seq: None,
                }))
            }
            HandshakeReply::Reject => IncomingFrame::Control(ControlMessage::FatalError(
                FatalError::new(FatalErrorReason::AuthenticationFailed),
            )),
        }
    }
}

impl Transport for FakeTransport {
    type Error = FakeClosed;

    #[allow(clippy::unused_async_trait_impl)]
    async fn send_control(&mut self, message: ControlMessage) -> Result<(), FakeClosed> {
        if matches!(message, ControlMessage::Handshake(_)) {
            let frame = self.answer();
            self.inbox.push_back(frame);
        }
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn send_bulk(&mut self, _message: BulkMessage) -> Result<(), FakeClosed> {
        Ok(())
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn recv(&mut self) -> Result<Option<IncomingFrame>, FakeClosed> {
        if let Some(frame) = self.inbox.pop_front() {
            return Ok(Some(frame));
        }
        if self.silent {
            core::future::pending::<()>().await;
        }
        Ok(None)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn close(&mut self) -> Result<(), FakeClosed> {
        Ok(())
    }
}
