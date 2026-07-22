//! connetto-server: the Subscription Materializer.
//!
//! The materializer is the server-side host that drives `subql` and turns its
//! per-consumer output into per-session wire output. `subql` owns CDC ingestion,
//! matching, event to patchset conversion, inbound apply, and the re-execution
//! state machine. This crate owns sessions, authorization, per-session patchset
//! assembly, the write path, the oplog and catchup, and all retry.
//!
//! * [`materializer`] holds the session-agnostic [`Materializer`] core that
//!   wraps one `subql` engine.
//! * the native [`Transport`](connetto_core::traits::Transport) implementations
//!   ([`LoopbackTransport`], [`WebSocketTransport`]) are re-exported from
//!   `connetto-core` behind its `native-transport` feature.
//! * [`session`] holds the [`SessionManager`], the per-session state machine,
//!   and the [`SnapshotSource`] seam.
//! * [`snapshot`] holds [`encode_json_rows`] and the Postgres-backed fill of
//!   that seam.
//!
//! See `docs/architecture/10-subscription-materializer.md` for the normative
//! boundary and `docs/architecture/subql.md` for the shipped `subql` surface.

pub mod auth;
pub mod materializer;
pub mod oplog;
pub mod pk;
pub mod session;
pub mod snapshot;
pub mod write_target;

pub use auth::PermissiveAuth;
#[cfg(feature = "pg-async")]
pub use auth::{RlsAuth, RlsAuthError};
pub use connetto_core::transport::{
    LoopbackError, LoopbackTransport, WebSocketError, WebSocketTransport, loopback,
};
pub use materializer::{
    AggregateCapture, AggregateChange, DeltaAggregateCapture, DeltaAggregateChange, Dispatched,
    MatchedPatch, Materializer, MaterializerError, PendingReExec, Registration,
    RuntimeVersionColumn, RuntimeWritableCatalog, RuntimeWritableCatalogBuilder,
};
pub use oplog::{
    CatchupDecision, ChangeRecord, InMemoryOplog, Oplog, OplogConfig, catchup_decision,
};
#[cfg(feature = "pg-async")]
pub use oplog::{PgOplog, PgOplogError};
pub use session::{
    NoConnector, ReconnectEvent, ReconnectPolicy, SessionConfig, SessionError, SessionManager,
    Snapshot, SnapshotSource,
};
#[cfg(feature = "pg-async")]
pub use snapshot::PgSnapshotSource;
pub use snapshot::{SnapshotError, encode_json_rows};
#[cfg(feature = "pg-async")]
pub use write_target::{PgWriteTarget, pg_write_target};
pub use write_target::{SqliteWriteTarget, WriteTarget, sqlite_write_target};
