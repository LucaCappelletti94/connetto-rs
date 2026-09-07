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

/// DDL that provisions the file server's own tables.
///
/// Apply this once with a privileged role before starting the server.
/// The DDL also includes commented template examples of the two deployment
/// contracts (`connetto_visible_files` and `connetto_set_content_state`) that
/// the deployment must adapt and install separately.
pub const DEPLOYMENT_DDL: &str = include_str!("../sql/schema.sql");
