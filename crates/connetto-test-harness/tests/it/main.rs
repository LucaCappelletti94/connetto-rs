//! Single merged integration-test target. Each module below was a standalone
//! `tests/*.rs` binary until 2026-08-31; merging them collapses 12 link steps
//! into one per build cycle.

mod capability_live;

mod fanout_counters;

mod fanout_delegated;

mod fanout_load;

mod grant_withdrawal;

mod membership_term;

mod outage;

mod parity;

mod session_handle;

mod smoke;

mod transitions;

mod truncate;
