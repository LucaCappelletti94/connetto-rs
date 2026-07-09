//! I/O seam traits every connetto crate plugs into.
//!
//! Kept intentionally minimal: signatures only. Implementations live in the
//! consumer crates (`connetto-server`, `connetto-client`, `connetto-client-wasm`).
//! No default methods, because the plumbing that composes these traits belongs
//! above `connetto-core`, not inside it.
//!
//! The `#[allow(async_fn_in_trait)]` lint suppression matches upstream guidance.
//! Auto-`Send` is intentionally not required so browser worker impls (which are
//! single-threaded) can implement the trait without unnecessary bounds. Consumer
//! crates that need `Send` should add it at their own trait bound.

use crate::{
    auth::AuthContext,
    cursor::Cursor,
    messages::{BulkMessage, ControlMessage},
};

/// Incoming frame delivered by [`Transport::recv`].
///
/// The transport layer distinguishes control from bulk at the wire boundary
/// (`WebSocket` binary vs. text frames, or the caller's own discipline over raw
/// byte streams). Higher layers pattern-match on this enum instead of the raw
/// message types.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Transport-specific error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// Send a control-plane message.
    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error>;

    /// Send a bulk-plane message.
    async fn send_bulk(&mut self, message: BulkMessage) -> Result<(), Self::Error>;

    /// Receive the next frame from the peer. Returns `Ok(None)` on clean close.
    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error>;

    /// Close the underlying connection cleanly.
    async fn close(&mut self) -> Result<(), Self::Error>;
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
pub trait AuthPolicy {
    /// Policy-specific error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// Whether `ctx` may see the row identified by `(table, pk)`.
    async fn can_read(
        &self,
        ctx: &AuthContext,
        table: &str,
        pk: &[u8],
    ) -> Result<bool, Self::Error>;

    /// Whether `ctx` may perform `op` on the row identified by `(table, pk)`.
    async fn can_write(
        &self,
        ctx: &AuthContext,
        table: &str,
        pk: &[u8],
        op: MutationOp,
    ) -> Result<bool, Self::Error>;
}
