//! Single merged integration-test target. Each module below was a standalone
//! `tests/*.rs` binary until 2026-08-31; merging them into one target removes
//! 37 fat link steps from every build.
//!
//! Run one old target's tests via a nextest filter, e.g.
//! `cargo nextest run --cargo-profile testfast --all-features -E 'test(subscription_translate::)'`.

mod abuse;
mod anonymous_writer;
mod bot_cap;
mod bot_proof;
mod bot_registration;
mod bots;
mod bots_client;

mod builder_coverage;

mod ticket_shared;

mod ticket_budget;

mod ticket_mint;

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

mod deployment_schema;

mod device_identity;

mod e2e;

mod enrolment;

mod enrolment_store;

mod revocation;

mod epoch;

mod grants;

mod grouped_wire;

mod failover;

mod idle_limit;
mod inprocess_loop;
mod lifecycle;
mod logging;

mod macro_hygiene;

mod oidc_spine;

mod openfga_live;

mod oplog_previous_image;

mod pg_async;

mod preflight_previous_image;

mod preflight_oplog_payload;

mod provider;

mod read_ceiling;

mod read_filter;

mod read_rule_fold;

mod reconnect;

mod reexec;
mod reexec_failure;

mod mutation_budget;

mod reserve;

mod rls_computed;

mod rls_read_filter;

mod rls_write_filter;

mod rls_write_question;

mod session_loop;

mod share_key_clock;
mod share_key_reach;
mod share_key_terms;
mod share_keys;

mod restore;

mod slot_watch;

mod snapshot_nonfatal;

mod snapshot_order;

mod resume_point;

mod stream_gap;

mod subscription_translate;

mod throttle;

mod write_path;

mod writer_frontier;

mod courier_frontier;

mod upkeep_consulted;
