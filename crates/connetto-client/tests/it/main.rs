//! Single merged integration-test target. Each module below was a standalone
//! `tests/*.rs` binary; merging into one target removes per-binary link steps.
//! Feature gates that lived as file-level `#![cfg]` attributes now live on the
//! `mod` declarations here.

mod aggregate_relay;

mod apply_behaviour;

mod authentication_client;

mod changed_signal;

mod coverage_resync;

mod encrypted_replica;

mod full_resync;

mod hardening;

mod key_requirement;

mod live_dispatch;

mod local_export;

mod local_import;

mod local_tier;

mod loop_emu;

mod mutation_replay;

#[cfg(feature = "native-auth")]
mod native_auth;

mod never_synced;

mod offline_start;

mod reconnect_live;

mod retention;

mod revocation;

mod rls_name_mapping;

mod rls_sync_path;

mod schema_detection;

#[cfg(feature = "native-auth")]
mod secret_stores;

mod sql_functions;

#[cfg(feature = "native-auth")]
mod teardown;

mod truncate_resync;

mod uuid_rls_default;

#[cfg(feature = "native-auth")]
mod verified_topology;

mod write_surface;
