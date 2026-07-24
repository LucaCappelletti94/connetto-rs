//! Wire message types split by conceptual group.
//!
//! Two top-level enums assemble every kind of frame the protocol exchanges:
//! [`ControlMessage`] for structured control traffic and [`BulkMessage`] for the
//! Zstd-compressed payload frames that ride alongside it. Sub-modules hold the
//! individual struct types so each concept lives in one file.

pub mod aggregate;
pub mod bulk;
pub mod control;
pub mod error;
pub mod flow;
pub mod handshake;
pub mod mutation;
pub mod reconnect;
pub mod schema;
pub mod subscription;

pub use aggregate::AggregateUpdate;
pub use bulk::{BulkMessage, LivePatch, MutationPatch, SchemaBlob, SnapshotPatch};
pub use control::ControlMessage;
pub use error::{FatalError, FatalErrorReason, NonFatalError};
pub use flow::{AckCredits, Ping, Pong};
pub use handshake::{Handshake, HandshakeAck};
pub use mutation::{
    MutationApplied, MutationConflict, MutationHeader, MutationReject, MutationRejectReason,
};
pub use reconnect::{FullResyncReason, FullResyncRequired};
pub use schema::SchemaUpdate;
pub use subscription::{
    BindValue, SnapshotBegin, SnapshotEnd, Subscribe, SubscriptionPriority, SubscriptionSpec,
    Unsubscribe,
};
