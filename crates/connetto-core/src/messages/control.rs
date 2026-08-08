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

use super::{
    aggregate::AggregateUpdate,
    error::{FatalError, NonFatalError, RateLimited},
    flow::{AckCredits, Ping, Pong},
    handshake::{Handshake, HandshakeAck},
    mutation::{MutationApplied, MutationConflict, MutationHeader, MutationReject},
    reconnect::FullResyncRequired,
    subscription::{SnapshotBegin, SnapshotEnd, Subscribe, Unsubscribe},
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
    /// Session-terminating error.
    FatalError(FatalError),
}
