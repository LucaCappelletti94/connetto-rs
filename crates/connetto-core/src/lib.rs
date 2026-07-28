//! Shared wire protocol, framing, and I/O trait signatures for connetto-rs.
//!
//! `connetto-core` is the smallest crate every side of the system agrees on.
//!
//! * [`messages`] holds every control-plane and bulk-plane wire type.
//! * [`codec`] serialises those types to `MessagePack` and wraps them in the
//!   length-prefixed framing documented in `docs/architecture/02-protocol.md`.
//! * [`traits`] defines the [`Transport`], [`Store`], [`FileStore`], and
//!   [`AuthPolicy`] seams the server, native client, and
//!   `WASM` client each fill with a platform-specific implementation.
//!
//! Consumer crates in this workspace depend on `connetto-core` only. They never
//! depend on each other.
//!
//! # Wire protocol at a glance
//!
//! * Control frames: `MessagePack`-encoded [`ControlMessage`], never compressed.
//! * Bulk frames: `MessagePack`-encoded [`BulkMessage`] whose inner payload is
//!   already `Zstd`-compressed by the sender.
//! * Framing: a `u32` big-endian length header prefixes each payload on
//!   byte-stream transports. `WebSocket` transports skip the header because the
//!   frame type already delimits the message.
//! * Protocol version: clients send [`PROTOCOL_VERSION`] in the handshake, and
//!   servers reject any mismatch with
//!   [`FatalErrorReason::ProtocolVersionMismatch`](messages::FatalErrorReason::ProtocolVersionMismatch).
//!
//! See the architecture docs under `docs/architecture/` for the full picture and
//! the decisions each type reifies (indexed in `open-questions.md`).

pub mod auth;
pub mod codec;
pub mod cursor;
pub mod error;
pub mod messages;
pub mod schema;
pub mod traits;
#[cfg(feature = "loopback")]
pub mod transport;
pub mod version;
pub mod write;

pub use auth::{AuthContext, TrustingSessionVerifier, VerifiedSession};
pub use cursor::Cursor;
pub use error::CodecError;
pub use messages::{BulkMessage, ControlMessage};
pub use schema::{SchemaVersion, schema_hash};
pub use traits::{
    AuthPolicy, FileStore, IncomingFrame, MutationOp, PendingMutation, SessionVerifier,
    SessionVerifyError, SessionVerifyFuture, Store, Transport,
};
#[cfg(feature = "loopback")]
pub use transport::{LoopbackError, LoopbackTransport, loopback};
#[cfg(feature = "native-transport")]
pub use transport::{WebSocketError, WebSocketTransport};
pub use version::PROTOCOL_VERSION;
pub use write::{VersionColumn, WritableCatalog};
