//! connetto-server: the Subscription Materializer.
//!
//! The materializer is the server-side host that drives `subql` and turns its
//! per-consumer output into per-session wire output. `subql` owns CDC ingestion,
//! matching, event to patchset conversion, inbound apply, and the re-execution
//! state machine. This crate owns sessions, authorization, per-session patchset
//! assembly, the write path, the oplog and catchup, and all retry.
//!
//! * [`builder`] is the one assembly path. [`ServerBuilder`] names the
//!   collaborators a deployment hands over, [`ServerBuilder::build`] returns
//!   the parts (the merged router, the sync routes and the HTTP routes
//!   separately, the change-stream future, and the shutdown handle) and
//!   [`ServerBuilder::serve`] owns the serving lifecycle. The parts serve
//!   through one listener, the sync route at [`SYNC_PATH`] beside the login
//!   endpoints and the file routes.
//! * The assembled server authorizes every row through OpenFGA. Row-level
//!   security stays available as the optional second opinion that counts and
//!   names divergences.
//! * The production build takes the database auth store and the persisted JWT
//!   keypair. The in-memory store and ephemeral key generation exist only
//!   behind the `test-seams` feature.
//! * The serving lifecycle closes every session when the shutdown signal or a
//!   terminal change-stream outcome arrives, and the library never ends the
//!   process, installs no signal handler and initializes no logging. The
//!   binary is a translation from its environment into the builder, and its
//!   contract is documented in `src/bin/connetto-server.rs`. A program that
//!   embeds the server follows `examples/embed.rs`.
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
pub mod builder;
pub mod capability;
pub mod counters;
pub mod defaults;
pub mod device_cert;
pub mod epoch;
pub mod fence;
pub mod guard;
mod key_filter;
mod manager_builder;
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
pub mod schema;
pub mod session;
pub mod slot;
pub mod snapshot;
pub mod throttle;
pub mod timeline;
pub mod watermark_schema;
pub mod write_target;

pub use abuse::{
    AbuseConfig, AbuseConfigError, AbuseLimits, ConnectionLimits, Crossing, Enforcement,
    EnforcementFuture, EnforcementPolicy, PersonLimits, Signal,
};
pub use auth::{RlsAuth, RlsAuthError};
pub use ban::{Ban, BanError, BanFuture, BanStore, ConnettoBanSchema, NewBan, pg_ban_store};
pub use capability::{CapabilityIssuer, IssuedCapability, ShareError, ShareLevel};
pub use connetto_core::auth::CapabilityKey;
pub use fence::{ReadFence, Unseen, snapshot_cursor, split_snapshot_cursor};
pub use guard::{PersonCloseHook, RequestGuard};
// Re-exported because `ShareError::NotWritable` names one, so an application
// matching on a refused verb can spell its type.
pub use subql::visibility::WriteOp;
// Re-exported so `connetto_schema!` can name it as
// `$crate::SessionId` in a consumer's crate, which need not depend on
// connetto-core directly.
pub use authn::http::{
    BROWSER_CLIENT, CLIENT_KIND_HEADER, CookieSameSite, RedirectPolicy, auth_router,
    is_loopback_host,
};
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
pub use builder::{
    BuildError, ChangeStream, ContentBuildError, ContentSettings, ContentSigner,
    ContentSignerError, PoolError, SHUTDOWN_GRACE, SYNC_PATH, ServeError, ServerBuilder,
    ServerHandle, ServerParts,
};
pub use connetto_core::SessionId;
pub use connetto_core::transport::{
    LoopbackError, LoopbackTransport, WebSocketError, WebSocketTransport, loopback,
};
#[cfg(feature = "content")]
#[doc(hidden)]
pub use connetto_file_server as __files;
#[cfg(feature = "test-seams")]
pub use manager_builder::ManagerBuilder;
#[cfg(feature = "test-seams")]
pub use materializer::MaterializerBuilder;
pub use materializer::{
    CallerMappings, ComputedCapture, ComputedChange, Dispatched, FoldSeeded, MatchedPatch,
    Materializer, MaterializerError, ReadConnector, Registration, RuntimeVersionColumn,
    RuntimeWritableCatalog, RuntimeWritableCatalogBuilder, SeedPlan, SqliteRegistration,
};
pub use oplog::{
    CHANGE_OP_TYPE, CatchupDecision, ChangeOp, ChangeOpSql, ChangeRecord, InMemoryOplog, Oplog,
    OplogConfig, catchup_decision,
};
pub use oplog::{PgOplog, PgOplogError};
pub use preflight::{Artifact, PreflightError};
pub use reexec::{
    ConnettoReadSetup, FailedRead, NoConnector, PgReadConnector, ReadBudget, ReadFailure,
};
pub use reserve::{ReaderGate, ReaderReserve};
pub use row_view::ValuesRow;
pub use schema::ConnettoSchema;
pub use session::{
    NoSigner, PageKey, PageSpec, ReconnectEvent, ReconnectPolicy, ResumePoint, SessionConfig,
    SessionError, SessionManager, SnapshotEstimate, SnapshotPage, SnapshotSource, StreamCheck,
    StreamCheckError, subject_set_reach,
};
pub use slot::{SlotError, SlotLag};
pub use snapshot::{PgSnapshotSource, RowSource, SnapshotError, SourceRow};
pub use throttle::{Limit, ReadLimits, ThrottleConfig, Tier, TierLimits};
pub use timeline::{Position, TimelineError, TimelineHistory};
pub use watermark_schema::ConnettoWatermarkSchema;
pub use write_target::{PgWriteTarget, pg_write_target};
