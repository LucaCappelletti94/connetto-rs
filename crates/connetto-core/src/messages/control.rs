//! Control-plane wire enum.
//!
//! Every message that carries only structured metadata (no bulk `PatchSet` or
//! schema payload) rides here. Control frames are `MessagePack`-encoded and
//! uncompressed per Q2.5. The bulk enum in [`super::bulk`] carries the payload
//! blobs that reference these frames.

use serde::{Deserialize, Serialize};

/// Whether a connection can currently reach a server.
///
/// The only thing that carries connection state. A value handed back once
/// cannot report a server arriving minutes later, so this travels on the same
/// stream every other event does.
///
/// Defaults to [`Offline`](Self::Offline), because nothing has said otherwise
/// yet and claiming a server is reachable before one has answered is the one
/// answer that is certainly wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SyncStatus {
    /// A handshake stands and frames flow.
    Connected,
    /// No server is reachable. Local reads and writes are unaffected and
    /// queued writes go up when one arrives.
    #[default]
    Offline,
}

/// Why live delivery has paused.
///
/// Carried by [`ControlMessage::DeliveryPaused`] so the client can show a
/// precise status rather than a generic message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PauseCause {
    /// The authorization service cannot be reached.
    ///
    /// Change delivery requires authorization checks, so the server holds
    /// new rows rather than forwarding them without verifying the caller.
    AuthServiceUnreachable,
    /// The change stream is connected but no events are arriving.
    ///
    /// This is an absence of events rather than an event, which is why no
    /// log line catches it: the stream is alive but silent.
    ChangeStreamStalled,
    /// The database cannot serve a read the pipeline needs, so delivery is held (R89 decision 2).
    /// The change stream itself stays connected, which is what separates this from [`Self::ChangeStreamStalled`].
    DatabaseUnreachable,
}

/// The worker's gate state, which a relay states to a tab so the tab can
/// refuse application access while the gate is locked.
///
/// A relay states the current value right after each tab's handshake and
/// pushes every change to the tabs that have finished theirs, the way
/// [`SyncStatus`] carries the relay's connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateState {
    /// The gate is locked. Application reads, writes, and new watches are
    /// refused, and live-handle refreshes are held.
    Locked,
    /// The gate is unlocked, and application access has resumed.
    Unlocked,
    /// The gate's prompt was dismissed or failed and the gate stays locked.
    UnlockDismissed,
}

/// Who a relay's worker is signed in as, which a relay states to a tab so the
/// tab's mirror answers its policy views as the worker's replica does.
///
/// A tab holds no credential, the worker having signed in, while the tab's
/// mirror runs the same translated schema, whose views filter on the caller
/// and the subjects the caller holds. The relay states both right after each
/// tab's handshake. Neither is secret on the origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabIdentity {
    /// The caller value the worker's replica answers, `None` when nobody is
    /// signed in.
    pub caller: Option<String>,
    /// The packed subject set the worker's replica answers, `None` when the
    /// worker holds no live share key.
    pub subjects: Option<String>,
}

use super::{
    aggregate::AggregateUpdate,
    content::{ContentTicketGrant, ContentTicketRequest},
    enrolment::{EnrolChallenge, EnrolChallengeRequest, EnrolGrant, EnrolRefused, EnrolRequest},
    error::{FatalError, NonFatalError, RateLimited},
    flow::{AckCredits, Ping, Pong},
    handshake::{Handshake, HandshakeAck},
    mutation::{MutationApplied, MutationConflict, MutationHeader, MutationReject},
    reconnect::FullResyncRequired,
    subscription::{MembershipOpened, SnapshotBegin, SnapshotEnd, Subscribe, Unsubscribe},
};

/// Every control-plane frame flowing between client and server.
///
/// Direction (client-originated vs. server-originated) is enforced at the
/// endpoints, not by the type system, so the same enum represents both halves
/// of the conversation. A server-side dispatcher that receives a
/// [`ControlMessage::HandshakeAck`] treats it as a protocol violation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ControlMessage {
    /// Client opens a session.
    Handshake(Handshake),
    /// Server acknowledges an opened session.
    HandshakeAck(HandshakeAck),

    /// Client registers a subscription.
    Subscribe(Subscribe),
    /// Client cancels a subscription.
    Unsubscribe(Unsubscribe),
    /// Server marks the start of an initial snapshot.
    SnapshotBegin(SnapshotBegin),
    /// Server marks the end of an initial snapshot.
    SnapshotEnd(SnapshotEnd),

    /// Client announces a mutation upload. The matching bulk frame carries
    /// the patchset bytes.
    MutationHeader(MutationHeader),
    /// Server confirms a mutation is durably applied, retiring the client's
    /// pending record.
    MutationApplied(MutationApplied),
    /// Server rejects a mutation before applying it.
    MutationReject(MutationReject),
    /// Server reports that a mutation collided with a newer server-side row.
    MutationConflict(MutationConflict),

    /// Server pushes an aggregate result update (JSON payload).
    AggregateUpdate(AggregateUpdate),

    /// Server tells the client the subscription cannot resume incrementally.
    FullResyncRequired(FullResyncRequired),
    /// Server announces a membership subscription it opened on the client's
    /// behalf (R27). Precedes that subscription's `SnapshotBegin`.
    MembershipOpened(MembershipOpened),

    /// Client asks for a content ticket naming one file and one verb.
    ContentTicketRequest(ContentTicketRequest),
    /// Server hands back the address that ticket authorizes.
    ContentTicketGrant(ContentTicketGrant),

    /// Client asks for a nonce to enrol its device key (R74).
    EnrolChallengeRequest(EnrolChallengeRequest),
    /// Server hands back that nonce.
    EnrolChallenge(EnrolChallenge),
    /// Client asks for its device certificate.
    EnrolRequest(EnrolRequest),
    /// Server hands back the device certificate.
    EnrolGrant(EnrolGrant),
    /// Server refuses a challenge or an enrolment.
    EnrolRefused(EnrolRefused),

    /// Client heartbeat probe.
    Ping(Ping),
    /// Server heartbeat reply.
    Pong(Pong),
    /// Client replenishes the server's delivery credit window.
    AckCredits(AckCredits),

    /// Non-fatal error attached to a specific request.
    NonFatalError(NonFatalError),
    /// Server refuses one request for exceeding a rate limit. The session
    /// stays open and the caller may retry after the stated delay.
    RateLimited(RateLimited),
    /// A relay tells a tab whether the relay itself can reach the server, so a
    /// tab knows whether what it is showing is current. Never sent by a real
    /// server, which cannot say this to a client it is not reaching.
    SyncStatus(SyncStatus),
    /// A relay tells a tab the worker's gate state, so a tab can refuse
    /// application access while the gate is locked. Never sent by a real
    /// server, which has no gate of this kind.
    GateState(GateState),
    /// A relay tells a tab who its worker is signed in as. Never sent by a
    /// real server, which answers the caller's identity through the rows it
    /// serves.
    TabIdentity(TabIdentity),
    /// Session-terminating error.
    FatalError(FatalError),
    /// Server reports that live delivery is temporarily paused.
    DeliveryPaused {
        /// Why delivery is paused.
        cause: PauseCause,
    },
    /// Server reports that live delivery has resumed after a pause.
    DeliveryResumed,
}
