//! The deployment every browser demo runs against.
//!
//! One schema, one policy document and one set of roles, held here rather than
//! copied into each demo. The copies had to be byte-identical or the client's
//! schema version stopped matching the server's, and a divergence in the
//! policies was worse than that: it left a replica whose views admitted rows
//! the server refused, or refused rows it served, with nothing reporting it.
//!
//! The demos differ in their surface and in their local tier, which stays in
//! each demo beside the code that reads it. What is shared is what the server
//! and every client must agree on exactly.

/// The synced tier's tables, which the deployment applies and every client
/// replica is translated from.
pub const SCHEMA_SQL: &str = include_str!("../schema.sql");

/// The row-level security the deployment enforces on those tables.
///
/// Hashed into the schema version beside the schema, because a policy decides
/// which view a logical name resolves to on a replica and what its `INSTEAD OF`
/// triggers admit, so a changed policy changes the replica.
pub const POLICIES_SQL: &str = include_str!("../policies.sql");

/// The roles the deployment grants, the reader role among them.
pub const ROLES_SQL: &str = include_str!("../roles.sql");

/// The browser stack's sync endpoint, as `CONNETTO_TEST_WS` named it when this
/// crate was built.
pub const DEMO_WS_URL: &str = match option_env!("CONNETTO_TEST_WS") {
    Some(url) => url,
    None => "ws://127.0.0.1:7777/",
};

/// The browser stack's auth listener, as `CONNETTO_TEST_AUTH_BASE` named it
/// when this crate was built.
pub const AUTH_BASE: &str = match option_env!("CONNETTO_TEST_AUTH_BASE") {
    Some(base) => base,
    None => "http://127.0.0.1:18099",
};

/// The auth stack's route that hands back the delivered code in its URL.
#[must_use]
pub fn auth_landing() -> String {
    format!("{AUTH_BASE}/dev/landing")
}
