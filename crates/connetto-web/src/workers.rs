//! DB worker orchestration and page-side glue for the leader topology.

mod archive_channel;
pub(crate) mod blob_io;
mod boot;
pub(crate) mod helpers;
mod intake;
mod logout;
mod session;

pub use archive_channel::{
    ChannelError, request_export, request_export_on, request_import, request_import_on,
    serve_export_requests, serve_export_requests_on, serve_import_requests,
    serve_import_requests_on,
};
pub use blob_io::{BlobError, BlobSink, BlobSource};
pub use boot::{
    BootError, BootIdentity, BootedSession, DbWorkerConfig, WorkerBootstrap, boot_db_worker,
    spawn_db_worker,
};
pub use intake::{
    IntakeError, TabWire, announce_tab, await_db_worker_ready, request_custody, sleep,
    tab_wire_factory,
};
pub use logout::{LogoutConfig, serve_logout_requests};

/// The shared rendezvous channel for worker readiness and tab announcements.
pub const HELLO_CHANNEL: &str = "connetto-hello";
/// The web lock the DB worker holds for its whole life.
pub const DB_ALIVE_LOCK: &str = "connetto-db-alive";
/// The channel a tab asks for a local-data export on.
pub const EXPORT_CHANNEL: &str = "connetto-export";
/// The channel a tab asks for a local-data import on.
pub const IMPORT_CHANNEL: &str = "connetto-import";

#[cfg(test)]
mod tests;
