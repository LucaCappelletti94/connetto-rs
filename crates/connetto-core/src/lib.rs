#![doc = include_str!("../README.md")]

pub mod auth;
pub mod backoff;
pub mod bots;
pub mod chain;
pub mod clock;
pub mod codec;
pub mod cursor;
pub mod custody;
#[cfg(feature = "device-cert")]
pub mod device_cert;
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
    AmbiguousIdentity, AuthContext, CapabilitySubject, ContentCaller, Principal, Subject,
    VerifiedSession,
};
pub use backoff::{Backoff, RetryPolicy};
pub use cursor::Cursor;
pub use custody::{Custody, NoGate};
pub use error::CodecError;
pub use messages::{BulkMessage, ControlMessage};
pub use percent::{percent_decode, percent_encode};
pub use replica_key::{ReplicaKey, ReplicaKeyParseError};
pub use schema::{
    AUDIT_TABLE, BOT_LIST_FUNCTION, BOT_LIST_SEPARATOR, BOT_LIST_SETTING, BOT_LIST_WILDCARD,
    CALLER_FUNCTION, SUBJECTS_FUNCTION, SchemaBundle, SchemaVersion, SharedLayout, UUID_FUNCTION,
    WRITE_EXEMPTION_FUNCTION, schema_hash,
};
pub use session_id::{SessionId, SessionIdParseError};
pub use sql::quote_ident;
pub use traits::{
    CheckedGrant, ContentTicketSigner, GrantCheckFuture, GrantRefused, HandleError,
    HandshakeAuthority, IncomingFrame, PendingMutation, RefreshFuture, RefreshTokenStore,
    ReplicaKeyStore, Store, Transport,
};
#[cfg(feature = "native-transport")]
pub use transport::{
    DialError, NativeStream, WebSocketError, WebSocketTransport, dial, ws_host_is_loopback,
};
#[cfg(feature = "loopback")]
pub use transport::{LoopbackError, LoopbackTransport, loopback};
pub use version::PROTOCOL_VERSION;
pub use write::{VersionColumn, WritableCatalog};
