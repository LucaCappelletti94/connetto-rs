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

/// The replica's local name for `current_setting('app.user_id')`, which the
/// identity arm of every policy here compares against.
pub const CALLER_FUNCTION: &str = "current_app_user";

/// The replica's local name for `current_setting('app.subjects')`, which the
/// membership arm of `photos_p` searches.
///
/// A caller holding no key answers NULL, and the translated search is NULL
/// with it, so that arm admits nothing rather than everything.
pub const SUBJECTS_FUNCTION: &str = "current_app_subjects";

/// The character joining the keys a caller holds, mirroring the deployment key
/// type's `CapabilityKey::SEPARATOR`. A key whose rendering contains it is
/// refused at minting, so the joined value splits back into the keys that went
/// in.
pub const SUBJECTS_SEPARATOR: char = ',';

/// The version a client presents at handshake, hashed from the documents the
/// server hashes, in the order the server uses.
#[must_use]
pub fn schema_version() -> connetto_core::SchemaVersion {
    connetto_core::SchemaVersion::from_sources([SCHEMA_SQL, POLICIES_SQL])
}

#[cfg(feature = "build")]
pub mod build_support;
