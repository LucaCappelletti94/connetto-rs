//! Fakes shared by the client and browser test suites.
//!
//! Behind the `test-support` feature, so nothing here reaches a production build.
//! It lives in the core rather than in a test file because four suites across two
//! crates and both targets need the same fake, and the only things it depends on
//! are the transport trait and the message types, which are here.

use crate::messages::{BulkMessage, ControlMessage, FatalError, FatalErrorReason, HandshakeAck};
use crate::traits::{IncomingFrame, Transport};
use crate::{Cursor, ReplicaKey, SchemaVersion};
use std::collections::VecDeque;

/// A fixed key for a test replica.
///
/// A durable replica is always encrypted, so a suite whose subject is something
/// else still needs a key to open one. Sharing the constant keeps those suites
/// from each inventing their own, and it is deliberately not the key any suite
/// that is actually about the codec uses.
#[must_use]
pub fn replica_key() -> ReplicaKey {
    ReplicaKey::from_bytes([0x5a; ReplicaKey::LEN])
}

/// A [`SessionVerifier`](crate::traits::SessionVerifier) that trusts the
/// presented token as the identity, performing no cryptographic verification.
///
/// The test replacement for the deleted production default: it refuses only an
/// empty token (an absent credential) and otherwise resolves the identity and
/// the session from the token, deterministically, so a reconnect on the same
/// token keeps its watermark. It lives behind `test-support` precisely because
/// it verifies nothing, so no production build can reach it and no constructor
/// installs it by default.
///
/// A `user#session` token names one user holding several concurrent sessions:
/// the part before the `#` is the `user_id` and the whole token seeds the
/// session id. A real deployment gets this from the auth store, which mints a
/// fresh session per login, so two devices of one person never collide. A
/// plain token with no `#` is one user with one session, which is what most
/// suites want.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestSessionVerifier;

impl crate::traits::SessionVerifier<String> for TestSessionVerifier {
    fn verify_session<'a>(
        &'a self,
        auth_token: &'a str,
    ) -> crate::traits::SessionVerifyFuture<'a, String> {
        Box::pin(async move {
            if auth_token.trim().is_empty() {
                return Err(crate::traits::SessionVerifyError::Invalid(
                    "no auth token presented at handshake".to_owned(),
                ));
            }
            let user_id = auth_token
                .split_once('#')
                .map_or(auth_token, |(user, _session)| user);
            Ok(crate::auth::VerifiedSession {
                context: crate::auth::AuthContext::new(user_id),
                session_id: crate::SessionId::from_token_hash(auth_token),
            })
        })
    }
}

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
    /// Delivered once, right after the handshake ack, as a deliberate server
    /// close (a shutdown or a revocation) does.
    closing: Option<FatalErrorReason>,
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

    /// A transport whose handshake succeeds and which then closes the session
    /// deliberately, carrying `reason`, as a graceful shutdown or a mid-session
    /// revocation does.
    #[must_use]
    pub fn accepting_then_closing(reason: FatalErrorReason) -> Self {
        Self {
            closing: Some(reason),
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
            closing: None,
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
            if let Some(reason) = self.closing.take() {
                self.inbox
                    .push_back(IncomingFrame::Control(ControlMessage::FatalError(
                        FatalError::new(reason),
                    )));
            }
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
