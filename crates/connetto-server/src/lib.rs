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
//! * [`snapshot`] holds the Postgres-backed binary fill of that seam through
//!   `subql::emit::pgbinary_patchset`.
//!
//! See `docs/architecture/10-subscription-materializer.md` for the normative
//! boundary and `docs/architecture/subql.md` for the shipped `subql` surface.

pub mod auth;
pub mod authn;
pub mod materializer;
pub mod oplog;
pub mod pk;
pub mod session;
pub mod snapshot;
pub mod watermark_schema;
pub mod write_target;

pub use auth::PermissiveAuth;
pub use auth::{RlsAuth, RlsAuthError};
// Re-exported so the `connetto_auth_tables!` macro can name it as
// `$crate::SessionId` in a consumer's crate, which need not depend on
// connetto-core directly.
pub use authn::http::{RedirectPolicy, auth_router};
pub use authn::{
    AssuranceRequirement, AuthCodes, AuthConfig, AuthError, AuthService, AuthStore, AuthStoreError,
    ConnettoSessionVerifier, DefaultUuidResolver, GenericOidcProvider, IdentityProvider,
    IdentityResolver, InMemoryAuthStore, IssuedAuthCode, IssuedSession, LoginRedirect,
    OidcProviderConfig, PendingLogin, PendingLogins, PermissiveProvider, ProviderError,
    ProviderRegistry, RefreshLifetimes, RefreshOutcome, ResolveError, ResolveFuture,
    ResolvedIdentity, RetainedProviderToken, TokenAuthority, TokenError, TokenPair, VerifiedClaims,
    VerifiedLogin, VerifiedSession,
};
pub use authn::{ConnettoStoreSchema, DbAuthStore, StoreColumn};
pub use connetto_core::SessionId;
pub use connetto_core::transport::{
    LoopbackError, LoopbackTransport, WebSocketError, WebSocketTransport, loopback,
};
pub use materializer::{
    AggregateCapture, AggregateChange, DeltaAggregateCapture, DeltaAggregateChange, Dispatched,
    MatchedPatch, Materializer, MaterializerError, PendingReExec, Registration,
    RuntimeVersionColumn, RuntimeWritableCatalog, RuntimeWritableCatalogBuilder,
    SqliteRegistration,
};
pub use oplog::{
    CatchupDecision, ChangeRecord, InMemoryOplog, Oplog, OplogConfig, catchup_decision,
};
pub use oplog::{PgOplog, PgOplogError};
pub use session::{
    NoConnector, ReconnectEvent, ReconnectPolicy, SessionConfig, SessionError, SessionManager,
    Snapshot, SnapshotSource,
};
pub use snapshot::PgSnapshotSource;
pub use snapshot::SnapshotError;
pub use watermark_schema::ConnettoWatermarkSchema;
pub use write_target::{PgWriteTarget, pg_write_target};
