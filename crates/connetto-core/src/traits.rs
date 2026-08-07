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
    ReplicaKey, SessionId,
    auth::Subject,
    cursor::Cursor,
    messages::{BulkMessage, ControlMessage, Grant},
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

/// Where a device persists its rotating refresh token between runs.
///
/// Both targets implement this: an OS keyring natively, an encrypted `SQLite`
/// database in the browser. Neither needs to await, so this stays synchronous
/// while [`ReplicaKeyStore`] does not.
///
/// Every method names the account whose token it addresses. The store itself is
/// therefore not scoped to anybody, which is what the browser bootstrap
/// requires: the refresh token is what reveals the account, so something has to
/// be readable before any account is known, and a store constructed for an
/// account would have nobody to construct it for.
pub trait RefreshTokenStore {
    /// Store-specific error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// The token stored for `account`, or `None` when none was stored.
    ///
    /// # Errors
    ///
    /// [`Self::Error`] if the backing store cannot be read.
    fn load(&self, account: &str) -> Result<Option<String>, Self::Error>;

    /// Persist `token` for `account`, replacing any prior one.
    ///
    /// # Errors
    ///
    /// [`Self::Error`] if the backing store cannot be written.
    fn store(&self, account: &str, token: &str) -> Result<(), Self::Error>;

    /// Remove the token stored for `account`, if any.
    ///
    /// # Errors
    ///
    /// [`Self::Error`] if the backing store cannot be cleared.
    fn clear(&self, account: &str) -> Result<(), Self::Error>;
}

/// Where a device caches the per-replica encryption keys it minted.
///
/// Both targets implement this: an OS keyring natively, `IndexedDB` plus a
/// non-extractable wrapping key in the browser. It awaits because the browser
/// half has to, reaching `IndexedDB` and `SubtleCrypto` through promises that
/// have no synchronous form in a worker. The native half therefore wears an
/// awaiting signature over a keychain call that returns immediately, and that
/// call blocks whoever polls it. Bounded rather than hidden: key custody runs
/// when a database is opened or an account is logged out, never per change.
///
/// The futures carry [`MaybeSend`] for the same reason [`Transport`]'s do, so a
/// native caller can hold one across a spawn while a browser one holds `JsValue`
/// state that cannot be `Send`.
///
/// `name` is the record this device holds for one replica, the same value
/// `replica_db_name` produced for the replica file, so two identities on one
/// device keep separate keys and a wipe of one cannot reach the other. A literal
/// name is equally valid and is how the browser addresses the device key it
/// needs before any identity exists.
pub trait ReplicaKeyStore {
    /// Store-specific error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// The cached key for `name`, or `None` when none was ever stored here.
    ///
    /// # Errors
    ///
    /// [`Self::Error`] if the backing store cannot be read.
    fn load(
        &self,
        name: &str,
    ) -> impl core::future::Future<Output = Result<Option<ReplicaKey>, Self::Error>> + MaybeSend;

    /// Persist `key` under `name`, replacing any prior value.
    ///
    /// # Errors
    ///
    /// [`Self::Error`] if the backing store cannot be written.
    fn store(
        &self,
        name: &str,
        key: &ReplicaKey,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>> + MaybeSend;

    /// Remove the cached key for `name`, if any. This is the crypto-shred half
    /// of a data wipe: without the key the replica ciphertext is inert.
    ///
    /// # Errors
    ///
    /// [`Self::Error`] if the backing store cannot be cleared.
    fn clear(
        &self,
        name: &str,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>> + MaybeSend;
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

/// Why one grant was refused at the handshake.
///
/// A refusal never reaches the client: the connection stays open, the session
/// proceeds on whatever else resolved, and [`HandshakeAck`] carries nothing
/// about it, so not allowed, no longer allowed and never existed are
/// indistinguishable on the wire. The distinction here exists for the server's
/// structured log, which is the only place a refusal is visible.
///
/// [`HandshakeAck`]: crate::messages::HandshakeAck
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantRefused {
    /// The grant was malformed, or failed its signature, issuer, audience or
    /// expiry checks, so nothing about the bearer can be trusted.
    Invalid(String),
    /// The grant checked out cryptographically, but the login it names is no
    /// longer live in the auth store (revoked or expired).
    Revoked,
}

impl core::fmt::Display for GrantRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "invalid grant: {detail}"),
            Self::Revoked => write!(f, "the login this grant names is no longer live"),
        }
    }
}

impl GrantRefused {
    /// A short stable word for the log, so a refusal can be counted and
    /// filtered without parsing a sentence.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid",
            Self::Revoked => "revoked",
        }
    }
}

impl std::error::Error for GrantRefused {}

/// Boxed future produced by [`HandshakeAuthority::check_grant`].
///
/// A trait object cannot carry an `async fn` directly, so checking returns an
/// explicitly boxed `Send` future. Checking fires once per grant per connection
/// off any hot path, so the box allocation is irrelevant.
pub type GrantCheckFuture<'a, Id = String, Key = String> =
    core::pin::Pin<Box<dyn Future<Output = Result<Subject<Id, Key>, GrantRefused>> + Send + 'a>>;

/// A resume blob could not be minted or was not one this server signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleError(pub String);

impl core::fmt::Display for HandleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "resume blob rejected: {}", self.0)
    }
}

impl std::error::Error for HandleError {}

/// Everything connetto signs and checks at the handshake: the grants a caller
/// presents, and the resume blob it hands a caller back.
///
/// Both halves are one seam because both are the server's own signature under
/// one key, and no deployment would supply one without the other. They stay
/// distinct in the model regardless: a grant says who is calling, a handle says
/// which run this is, and `Handshake` carries them in separate fields.
///
/// It is held as a runtime trait object on the server
/// (`Arc<dyn HandshakeAuthority<Id>>`) rather than a generic type parameter,
/// because none of this is on a hot path so static dispatch buys nothing, and a
/// trait object keeps the server's public type signature stable no matter how a
/// deployment configures identity.
pub trait HandshakeAuthority<Id = String, Key = String>: Send + Sync {
    /// Check one grant and resolve the [`Subject`] it names, or refuse it.
    ///
    /// This half is the generalization of the old single-credential verifier,
    /// and it is not a resolver: mapping a provider's claims to a typed user id
    /// happens once per login and is somebody else's job. Checking is
    /// arithmetic, a signature check against connetto's own public key, with no
    /// database lookup, nothing sniffing the shape of a string, and no order of
    /// checks that changes the outcome. One implementation reads either kind of
    /// subject, because a login token and a share key are the same mechanism
    /// differing only in whom they name.
    ///
    /// The one store round trip that remains is confined to the login case and
    /// is not a lookup that recognises the grant, since the signature already
    /// did that. It asks whether the login the grant names is still live, which
    /// is what makes revocation authoritative rather than bounded by the
    /// token's remaining lifetime. A capability needs no such call, because
    /// withdrawing one is deleting the relation that grants it and there is
    /// nothing to keep alive.
    ///
    /// # Errors
    ///
    /// [`GrantRefused`] when the grant does not check out. A refusal never
    /// reaches the client.
    fn check_grant<'a>(&'a self, grant: &'a Grant) -> GrantCheckFuture<'a, Id, Key>;

    /// Mint the resume blob naming `session_id`, for a caller with no identity
    /// to present on its next connection.
    ///
    /// An identified run needs none: its handle rides inside its login grant.
    ///
    /// # Errors
    ///
    /// [`HandleError`] when signing fails.
    fn mint_handle(&self, session_id: SessionId) -> Result<String, HandleError>;

    /// Read the handle out of a resume blob, refusing one this server did not
    /// sign or one that has expired.
    ///
    /// Refusing an unsigned blob is what stops a caller choosing the key to its
    /// own server-side state, or resuming as another visitor whose handle it
    /// guessed.
    ///
    /// # Errors
    ///
    /// [`HandleError`] when the blob is not one this server signed.
    fn read_handle(&self, blob: &str) -> Result<SessionId, HandleError>;
}
