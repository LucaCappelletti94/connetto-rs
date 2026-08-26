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

pub mod abuse;
pub mod audit;
pub mod auth;
pub mod authn;
pub mod ban;
pub mod capability;
pub mod counters;
pub mod guard;
mod key_filter;
pub mod materializer;
pub mod openfga;
pub mod oplog;
pub mod parity;
pub mod pk;
pub mod preflight;
pub mod reach;
pub mod reexec;
pub mod reserve;
pub mod row_view;
pub mod session;
pub mod slot;
pub mod snapshot;
pub mod throttle;
pub mod watermark_schema;
pub mod write_target;

pub use abuse::{
    AbuseConfig, AbuseConfigError, AbuseLimits, ConnectionLimits, Crossing, Enforcement,
    EnforcementFuture, EnforcementPolicy, PersonLimits, Signal,
};
pub use auth::{RlsAuth, RlsAuthError};
pub use ban::{Ban, BanError, BanFuture, BanStore, ConnettoBanSchema, NewBan, pg_ban_store};
pub use capability::{CapabilityIssuer, CapabilityKey, IssuedCapability, ShareError, ShareLevel};
pub use guard::{PersonCloseHook, RequestGuard};
// Re-exported because `ShareError::NotWritable` names one, so an application
// matching on a refused verb can spell its type.
pub use subql::visibility::WriteOp;
// Re-exported so the `connetto_auth_tables!` macro can name it as
// `$crate::SessionId` in a consumer's crate, which need not depend on
// connetto-core directly.
pub use authn::http::{RedirectPolicy, auth_router, is_loopback_host};
pub use authn::{
    AssuranceRequirement, AuthCodes, AuthConfig, AuthError, AuthService, AuthStore, AuthStoreError,
    ConnettoHandshakeAuthority, DefaultUuidResolver, GenericOidcProvider, IdentityProvider,
    IdentityResolver, InMemoryAuthStore, IssuedAuthCode, IssuedSession, LoginRedirect,
    OidcProviderConfig, PendingLogin, PendingLogins, ProviderError, ProviderRegistry,
    RefreshLifetimes, RefreshOutcome, ResolveError, ResolveFuture, ResolvedIdentity,
    RetainedProviderToken, TokenAuthority, TokenError, TokenPair, VerifiedClaims, VerifiedLogin,
    VerifiedSession,
};
pub use authn::{ConnettoStoreSchema, DbAuthStore, StoreColumn};
pub use connetto_core::SessionId;
pub use connetto_core::transport::{
    LoopbackError, LoopbackTransport, WebSocketError, WebSocketTransport, loopback,
};
pub use materializer::{
    ComputedCapture, ComputedChange, Dispatched, FoldSeeded, MatchedPatch, Materializer,
    MaterializerError, ReadConnector, Registration, RuntimeVersionColumn, RuntimeWritableCatalog,
    RuntimeWritableCatalogBuilder, SeedPlan, SqliteRegistration,
};
pub use oplog::{
    CHANGE_OP_TYPE, CatchupDecision, ChangeOp, ChangeOpSql, ChangeRecord, InMemoryOplog, Oplog,
    OplogConfig, catchup_decision,
};
pub use oplog::{PgOplog, PgOplogError};
pub use preflight::{Artifact, PreflightError};
pub use reexec::{ConnettoReadSetup, NoConnector, PgReadConnector, ReadBudget, TimedOutRead};
pub use reserve::{ReaderGate, ReaderReserve};
pub use row_view::ValuesRow;
pub use session::{
    PageKey, PageSpec, ReconnectEvent, ReconnectPolicy, SessionConfig, SessionError,
    SessionManager, SnapshotEstimate, SnapshotPage, SnapshotSource,
};
pub use slot::{SlotError, SlotLag};
pub use snapshot::{PgSnapshotSource, RowSource, SnapshotError, SourceRow};
pub use throttle::{Limit, ReadLimits, ThrottleConfig, Tier, TierLimits};
pub use watermark_schema::ConnettoWatermarkSchema;
pub use write_target::{PgWriteTarget, pg_write_target};
