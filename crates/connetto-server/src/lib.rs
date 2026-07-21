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
//! * [`transport`] holds the [`Transport`](connetto_core::traits::Transport)
//!   implementations: an in-memory [`LoopbackTransport`] and the native
//!   [`WebSocketTransport`].
//! * [`session`] holds the [`SessionManager`], the per-session state machine,
//!   and the [`SnapshotSource`] seam.
//! * [`snapshot`] holds [`encode_json_rows`] and the Postgres-backed fill of
//!   that seam.
//!
//! See `docs/architecture/10-subscription-materializer.md` for the normative
//! boundary and `docs/architecture/subql.md` for the shipped `subql` surface.

pub mod auth;
pub mod materializer;
pub mod session;
pub mod snapshot;
pub mod transport;

pub use auth::PermissiveAuth;
pub use materializer::{
    AggregateCapture, AggregateChange, Dispatched, MatchedPatch, Materializer, MaterializerError,
    PendingReExec, Registration, RuntimeVersionColumn, RuntimeWritableCatalog,
    RuntimeWritableCatalogBuilder,
};
pub use session::{
    NoConnector, SessionConfig, SessionError, SessionManager, Snapshot, SnapshotSource,
    SqliteWriteTarget, sqlite_write_target,
};
#[cfg(feature = "pg-async")]
pub use snapshot::PgSnapshotSource;
pub use snapshot::{SnapshotError, encode_json_rows};
pub use transport::{
    LoopbackError, LoopbackTransport, WebSocketError, WebSocketTransport, loopback,
};
