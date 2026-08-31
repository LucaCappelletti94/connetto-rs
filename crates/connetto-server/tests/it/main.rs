//! Single merged integration-test target. Each module below was a standalone
//! `tests/*.rs` binary until 2026-08-31; merging them into one target removes
//! 37 fat link steps from every build.
//!
//! Run one old target's tests via a nextest filter, e.g.
//! `cargo nextest run --cargo-profile testfast --all-features -E 'test(subscription_translate::)'`.

mod abuse;

mod audit_producers;

mod audit_table;

mod auth_retry;

mod authentication;

mod authn_db;

mod authn_flow;

mod authn_generic_id;

mod capabilities;

mod cdc_reconnect;

mod delta_aggregate;

mod e2e;

mod grants;

mod grouped_wire;

mod inprocess_loop;

mod oidc_spine;

mod openfga_live;

mod oplog_previous_image;

mod pg_async;

mod preflight_previous_image;

mod provider;

mod read_ceiling;

mod read_filter;

mod reconnect;

mod reexec;

mod reserve;

mod rls_read_filter;

mod rls_write_filter;

mod rls_write_question;

mod session_loop;

mod slot_watch;

mod snapshot_nonfatal;

mod snapshot_order;

mod stream_gap;

mod subscription_translate;

mod throttle;

mod write_path;
