#![doc = include_str!("../README.md")]

mod db;
mod error;
mod functions;
mod needed;
pub mod preflight;
mod router;
pub mod schema;
mod serve;
mod store;
mod sweep;
pub mod ticket;
mod upload;

pub use error::ServerError;
pub use preflight::{PreflightError, preflight, preflight_reader};
pub use router::{AppPools, Config, DbPool, serve};
pub use schema::{ConnettoFileSchema, DefaultFileSchema};
pub use store::{AnyStore, CustomStore, FsStore, ObjectStoreBackend, StoreError};
pub use sweep::{SweepError, sweep};
pub use ticket::{TicketPayload, TicketSigner, TicketVerifier, Verb};

/// Encodes 32 bytes as a 64-character lowercase hex string.
///
/// Public because a chunk hash reaches the wire in this form, in chunk paths and in an `ETag`, so a deployment that builds its own URLs must render a hash exactly as the server does.
pub fn hex_32(bytes: &[u8; 32]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// DDL that provisions the file server's own tables.
///
/// Apply this once with a privileged role before starting the server.
/// The DDL also includes commented template examples of the two deployment
/// contracts (`connetto_visible_files` and `connetto_set_content_state`) that
/// the deployment must adapt and install separately.
pub const DEPLOYMENT_DDL: &str = include_str!("../sql/schema.sql");
