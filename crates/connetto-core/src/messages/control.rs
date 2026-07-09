//! Control-plane wire enum.
//!
//! Every message that carries only structured metadata (no bulk `PatchSet` or
//! schema payload) rides here. Control frames are `MessagePack`-encoded and
//! uncompressed per Q2.5. The bulk enum in [`super::bulk`] carries the payload
//! blobs that reference these frames.

use serde::{Deserialize, Serialize};

use super::{
    aggregate::AggregateUpdate,
    error::{FatalError, NonFatalError},
    flow::{AckCredits, Ping, Pong},
    handshake::{Handshake, HandshakeAck},
    mutation::{MutationConflict, MutationHeader, MutationReject},
    reconnect::FullResyncRequired,
    schema::SchemaUpdate,
    subscription::{SnapshotBegin, SnapshotEnd, Subscribe, Unsubscribe},
};

/// Every control-plane frame flowing between client and server.
///
/// Direction (client-originated vs. server-originated) is enforced at the
/// endpoints, not by the type system, so the same enum represents both halves
/// of the conversation. A server-side dispatcher that receives a
/// [`ControlMessage::HandshakeAck`] treats it as a protocol violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Server rejects a mutation before applying it.
    MutationReject(MutationReject),
    /// Server reports that a mutation collided with a newer server-side row.
    MutationConflict(MutationConflict),

    /// Server pushes an aggregate result update (JSON payload).
    AggregateUpdate(AggregateUpdate),

    /// Server announces a schema change. The matching bulk frame (when
    /// [`SchemaUpdate::payload_follows`] is true) carries the schema blob.
    SchemaUpdate(SchemaUpdate),

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
    /// Session-terminating error.
    FatalError(FatalError),
}
