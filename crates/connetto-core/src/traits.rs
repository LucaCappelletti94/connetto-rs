//! I/O seam traits every connetto crate plugs into.
//!
//! Kept intentionally minimal: signatures only. Implementations live in the
//! consumer crates (`connetto-server`, `connetto-client`, `connetto-client-wasm`).
//! No default methods, because the plumbing that composes these traits belongs
//! above `connetto-core`, not inside it.
//!
//! The `#[allow(async_fn_in_trait)]` lint suppression matches upstream guidance.
//! [`Transport`] futures are bound by [`MaybeSend`]: `Send` on native targets,
//! unconstrained on wasm, where the runtime is single threaded and transport
//! futures hold JS values that cannot be `Send`. Native consumers keep spawning
//! sessions onto multi-threaded runtimes with no change, since on native
//! `MaybeSend` IS `Send`.

use crate::{
    auth::{AuthContext, VerifiedSession},
    cursor::Cursor,
    messages::{BulkMessage, ControlMessage},
};

/// `Send` on native targets, nothing on wasm.
///
/// The single seam through which the two platforms disagree about transport
/// futures: a browser WebSocket future holds `JsValue`s and cannot be `Send`,
/// while native drivers spawn onto multi-threaded runtimes and need it. On
/// native this trait has `Send` as a supertrait with a blanket impl, so a
/// `+ MaybeSend` bound is exactly `+ Send` there. On wasm it is a blanket
/// no-op. Never implement it by hand.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub trait MaybeSend: Send {}
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
impl<T: Send> MaybeSend for T {}

/// `Send` on native targets, nothing on wasm. See the native docs.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub trait MaybeSend {}
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
impl<T> MaybeSend for T {}

/// Incoming frame delivered by [`Transport::recv`].
///
/// The transport layer distinguishes control from bulk at the wire boundary
/// (`WebSocket` binary vs. text frames, or the caller's own discipline over raw
/// byte streams). Higher layers pattern-match on this enum instead of the raw
/// message types.
#[derive(Debug, Clone, PartialEq)]
pub enum IncomingFrame {
    /// A control-plane frame.
    Control(ControlMessage),
    /// A bulk-plane frame.
    Bulk(BulkMessage),
}

/// Bidirectional wire transport for a single session.
///
/// One instance per session on the server. One per open connection on the
/// client. Implementations own their sink/stream state, and `send_*` and `recv`
/// may be called concurrently by the same task via `&mut self`.
///
/// The methods return `impl Future + MaybeSend` explicitly (rather than
/// `async fn`) so a generic driver holding a `T: Transport` can be spawned
/// onto a multi-threaded runtime on native, where [`MaybeSend`] is `Send`.
/// Implementations still write plain `async fn` bodies. On wasm the bound is
/// vacuous and single threaded browser transports implement the trait
/// directly.
pub trait Transport {
    /// Transport-specific error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// Send a control-plane message.
    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>> + MaybeSend;

    /// Send a bulk-plane message.
    fn send_bulk(
        &mut self,
        message: BulkMessage,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>> + MaybeSend;

    /// Receive the next frame from the peer. Returns `Ok(None)` on clean close.
    fn recv(
        &mut self,
    ) -> impl core::future::Future<Output = Result<Option<IncomingFrame>, Self::Error>> + MaybeSend;

    /// Close the underlying connection cleanly.
    fn close(&mut self) -> impl core::future::Future<Output = Result<(), Self::Error>> + MaybeSend;
}

/// Client-side pending mutation record surfaced by [`Store::pending_mutations`].
///
/// Held in the local mutation queue between the moment the app enqueues the
/// write and the moment the server-side echo confirms (or the server rejects).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMutation {
    /// Sequence number assigned when the mutation was enqueued.
    pub client_seq: u64,
    /// Pre-compressed patchset bytes ready to ride on the bulk channel.
    pub patchset_zstd: Vec<u8>,
    /// Number of ops packaged into the patchset. Advisory: matches the header
    /// value uploaded to the server.
    pub op_count: u32,
}

/// Client-side local persistence.
///
/// Owns the local `SQLite` database, the mutation queue, the resume cursor, and
/// the persisted session token. All accessors take `&mut self` so an
/// implementation can serialise transactions internally without extra locking.
#[allow(async_fn_in_trait)]
pub trait Store {
    /// Persistence-specific error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// Apply an incoming bulk frame to local state (snapshot, live patch, or
    /// schema blob). The implementation decides how to route by variant.
    async fn apply_bulk(&mut self, frame: BulkMessage) -> Result<(), Self::Error>;

    /// Enqueue a fresh mutation. Returns the assigned per-session sequence number.
    async fn enqueue_mutation(
        &mut self,
        patchset_zstd: Vec<u8>,
        op_count: u32,
    ) -> Result<u64, Self::Error>;

    /// Snapshot the outstanding mutation queue in ascending sequence order.
    async fn pending_mutations(&mut self) -> Result<Vec<PendingMutation>, Self::Error>;

    /// Drop a mutation from the queue after the server confirmed or rejected it.
    async fn discard_mutation(&mut self, client_seq: u64) -> Result<(), Self::Error>;

    /// Load the last resume cursor persisted for this client, or `None` if
    /// this is a first-run install.
    async fn last_cursor(&self) -> Result<Option<Cursor>, Self::Error>;

    /// Persist the resume cursor advertised by the server.
    async fn set_last_cursor(&mut self, cursor: Cursor) -> Result<(), Self::Error>;

    /// Load the persisted session token, or `None` if the client never handshook.
    async fn session_token(&self) -> Result<Option<String>, Self::Error>;

    /// Persist a fresh session token issued by the server.
    async fn set_session_token(&mut self, token: String) -> Result<(), Self::Error>;
}

/// Content-addressed file chunk store (see `docs/architecture/07-file-sync.md`).
///
/// File sync is out of scope for v1 per Q7 and Q1.2, but the trait shape belongs
/// in `connetto-core` so both server and client can compile against the same
/// signature when file sync lands.
#[allow(async_fn_in_trait)]
pub trait FileStore {
    /// Chunk-store error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// Persist a chunk keyed by its content hash.
    async fn write_chunk(&mut self, hash: &[u8], data: &[u8]) -> Result<(), Self::Error>;

    /// Load a chunk by its content hash.
    async fn read_chunk(&self, hash: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Whether a chunk is present locally.
    async fn has_chunk(&self, hash: &[u8]) -> Result<bool, Self::Error>;
}

/// Verb the auth policy is being asked to authorise on a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationOp {
    /// Insert a new row.
    Insert,
    /// Update an existing row.
    Update,
    /// Delete a row.
    Delete,
}

/// Authorization seam. The server binds this to `OpenFGA` via `rls2fga` (Q8.1).
///
/// Read visibility and write authority are checked separately because their
/// batching profiles differ. Read checks fire per (row, subscription) on the
/// CDC hot path. Write checks fire per client mutation.
#[allow(async_fn_in_trait)]
pub trait AuthPolicy<Id = String> {
    /// Policy-specific error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// Whether `ctx` may see the row identified by `(table, pk)`.
    async fn can_read(
        &self,
        ctx: &AuthContext<Id>,
        table: &str,
        pk: &[u8],
    ) -> Result<bool, Self::Error>;

    /// Whether `ctx` may perform `op` on the row identified by `(table, pk)`.
    async fn can_write(
        &self,
        ctx: &AuthContext<Id>,
        table: &str,
        pk: &[u8],
        op: MutationOp,
    ) -> Result<bool, Self::Error>;
}

/// Why a session credential was refused at the handshake.
///
/// [`run_handshake`](crate::traits::SessionVerifier::verify_session) collapses
/// every refusal to a single wire reason
/// ([`FatalErrorReason::AuthenticationFailed`](crate::messages::FatalErrorReason::AuthenticationFailed)),
/// so the distinction here exists for server-side logging and audit rather than
/// for the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionVerifyError {
    /// The credential was absent, malformed, or failed its signature or expiry
    /// checks, so nothing about the caller can be trusted.
    Invalid(String),
    /// The credential verified cryptographically, but its session is no longer
    /// live in the auth store (revoked or expired), so it is refused.
    Revoked,
}

impl core::fmt::Display for SessionVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "invalid session credential: {detail}"),
            Self::Revoked => write!(f, "session is no longer live"),
        }
    }
}

impl std::error::Error for SessionVerifyError {}

/// Boxed future produced by [`SessionVerifier::verify_session`].
///
/// A trait object cannot carry an `async fn` directly, so verification returns
/// an explicitly boxed `Send` future. Verification fires once per connection
/// off any hot path, so the box allocation is irrelevant.
pub type SessionVerifyFuture<'a, Id = String> = core::pin::Pin<
    Box<dyn Future<Output = Result<VerifiedSession<Id>, SessionVerifyError>> + Send + 'a>,
>;

/// Turns connetto's own session credential into a verified
/// [`VerifiedSession`] (identity context plus the connetto-minted session id).
///
/// The handshake resolves identity only through this seam, never from the
/// client-supplied `client_id`. A real implementation verifies the token's
/// signature and expiry (self-contained, no store round-trip) and checks that
/// the session is still live in the auth store, which is what makes revocation
/// authoritative rather than bounded by the token lifetime. See
/// `docs/architecture/11-authentication.md`.
///
/// It is held as a runtime trait object on the server (`Arc<dyn SessionVerifier<Id>>`)
/// rather than a generic type parameter, because verification is off any hot
/// path so static dispatch buys nothing, and a trait object keeps the server's
/// public type signature stable no matter how a deployment configures identity.
/// This mirrors the [`AuthPolicy`] pattern of a real implementation plus a
/// stand-in, with the stand-in confined to the `test-support` feature so no
/// production build can reach it.
pub trait SessionVerifier<Id = String>: Send + Sync {
    /// Verify `auth_token` (connetto's own access token) and resolve the session
    /// identity plus its session id, or refuse it with a [`SessionVerifyError`].
    fn verify_session<'a>(&'a self, auth_token: &'a str) -> SessionVerifyFuture<'a, Id>;
}
