//! DB worker orchestration and page-side glue for the leader topology.

mod archive_channel;
mod boot;
mod helpers;
mod intake;
mod logout;
mod session;

pub use archive_channel::{
    ChannelError, request_export, request_import, serve_export_requests, serve_import_requests,
};
pub use boot::{
    BootError, BootedSession, DbWorkerConfig, WorkerBootstrap, boot_db_worker, spawn_db_worker,
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
/// Maximum bytes an archive may carry to pass through a browser worker.
///
/// The whole archive is buffered in the worker to be read or written, so the ceiling is
/// what a `wasm32` linear memory can hold beside the rows it compresses.
pub const MAX_ARCHIVE_BUFFER_BYTES: u64 = 2 * 1024 * 1024 * 1024;


#[cfg(test)]
mod tests;
