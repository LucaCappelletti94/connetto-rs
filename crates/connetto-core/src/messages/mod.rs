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
pub mod subscription;

pub use aggregate::AggregateUpdate;
pub use bulk::{BulkMessage, LivePatch, MutationPatch, SnapshotPatch};
pub use control::{ControlMessage, PauseCause, SyncStatus};
pub use error::{FatalError, FatalErrorReason, NonFatalError, RateLimited, SUBSCRIPTION_REFUSED};
pub use flow::{AckCredits, Ping, Pong};
pub use handshake::{Grant, Handshake, HandshakeAck};
pub use mutation::{
    ConflictRow, MutationApplied, MutationConflict, MutationHeader, MutationReject,
    MutationRejectReason,
};
pub use reconnect::{FullResyncReason, FullResyncRequired};
pub use subscription::{
    BindValue, MembershipOpened, SnapshotBegin, SnapshotEnd, Subscribe, SubscriptionPriority,
    SubscriptionSpec, Unsubscribe,
};
