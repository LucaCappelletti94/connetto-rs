//! Typed SQL function declarations for the file server.
//!
//! All call sites use the typed DSL through these declarations; the crate
//! contains no `diesel::sql_query` statements on data paths.
//!
//! The deployment contract requires `connetto_set_content_state` to return
//! `BYTEA` (echoing the `file_id`) rather than `VOID`. Postgres does not expose
//! void through a stable diesel SQL type, and making the return type reflect the
//! actual wire value keeps the call fully typed without any raw SQL.

use diesel::sql_types::{Array, Bool, Bytea, Text};

diesel::define_sql_function! {
    /// Postgres built-in: sets a configuration parameter for the current
    /// transaction, threading the caller identity into RLS policies.
    fn set_config(setting_name: Text, new_value: Text, is_local: Bool) -> Text;
}

diesel::define_sql_function! {
    /// Deployment contract: given a deduplicated set of 32-byte file ids that
    /// are candidates for needed-hash scoping, returns the subset the current
    /// caller may see. Runs with caller rights (SECURITY INVOKER default) so
    /// the deployment's own RLS policies apply inside the function body.
    ///
    /// Input: candidate file ids derived from declared chunk hashes via the
    /// committed manifest tables (order and duplicates are immaterial).
    /// Output: the visible subset, also as an unordered set.
    fn connetto_visible_files(file_ids: Array<Bytea>) -> Array<Bytea>;
}

diesel::define_sql_function! {
    /// Deployment contract: writes `content_state` on the deployment's metadata
    /// table after a successful commit. Runs as the function owner
    /// (SECURITY DEFINER) so no direct UPDATE grant on the application table
    /// is required.  The `caller` argument carries the uploader identity so
    /// the deployment can attribute the commit.
    ///
    /// Returns the `file_id` echo so the call is fully typed through diesel's DSL.
    /// The return value is always discarded by the caller.
    fn connetto_set_content_state(file_id: Bytea, new_state: Text, caller: Text) -> Nullable<Bytea>;
}
