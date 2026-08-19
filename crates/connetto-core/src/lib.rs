//! Shared wire protocol, framing, and I/O trait signatures for connetto-rs.
//!
//! `connetto-core` is the smallest crate every side of the system agrees on.
//!
//! * [`messages`] holds every control-plane and bulk-plane wire type.
//! * [`codec`] serialises those types to `MessagePack` and wraps them in the
//!   length-prefixed framing documented in `docs/architecture/02-protocol.md`.
//! * [`traits`] defines the [`Transport`], [`Store`], [`FileStore`],
//!   [`RefreshTokenStore`], and [`ReplicaKeyStore`] seams the server, native
//!   client, and `WASM` client each fill with a platform-specific
//!   implementation.
//! * [`custody`] reports how the key protecting an open replica is held.
//! * [`sql`] and [`percent`] hold the text helpers every side would otherwise
//!   paste: SQL identifier quoting and query-value percent-encoding.
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
pub mod backoff;
pub mod codec;
pub mod cursor;
pub mod custody;
#[cfg(feature = "env")]
pub mod env;
pub mod error;
#[cfg(feature = "logging")]
pub mod logging;
pub mod messages;
pub mod percent;
pub mod replica_key;
pub mod schema;
pub mod session_id;
pub mod sql;
#[cfg(feature = "test-support")]
pub mod test_support;
pub mod traits;
#[cfg(feature = "loopback")]
pub mod transport;
pub mod version;
pub mod write;

pub use auth::{
    AmbiguousIdentity, AuthContext, CapabilitySubject, Principal, Subject, VerifiedSession,
};
pub use backoff::RetryPolicy;
pub use cursor::Cursor;
pub use custody::{Custody, NoGate};
pub use error::CodecError;
pub use messages::{BulkMessage, ControlMessage};
pub use percent::{percent_decode, percent_encode};
pub use replica_key::{ReplicaKey, ReplicaKeyParseError};
pub use schema::{SchemaVersion, schema_hash};
pub use session_id::{SessionId, SessionIdParseError};
pub use sql::quote_ident;
pub use traits::{
    FileStore, GrantCheckFuture, GrantRefused, HandleError, HandshakeAuthority, IncomingFrame,
    PendingMutation, RefreshTokenStore, ReplicaKeyStore, Store, Transport,
};
#[cfg(feature = "loopback")]
pub use transport::{LoopbackError, LoopbackTransport, loopback};
#[cfg(feature = "native-transport")]
pub use transport::{WebSocketError, WebSocketTransport};
pub use version::PROTOCOL_VERSION;
pub use write::{VersionColumn, WritableCatalog};
