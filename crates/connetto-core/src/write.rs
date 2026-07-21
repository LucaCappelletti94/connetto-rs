//! Write-path catalog policy.
//!
//! The write path needs two schema facts a plain wire type cannot carry: which
//! tables may be the target of a client mutation, and where each finds the
//! version marker used for optimistic-concurrency conflict detection. Both are
//! properties of the application schema, so they live behind traits a catalog
//! type implements rather than as data on the wire.
//!
//! `connetto-core` stays catalog-agnostic: it defines the traits and the server
//! drives the write path against them. A runtime schema implements them by
//! resolving names at run time; a compile-time schema implements them through
//! typed column markers.

/// A column a catalog nominates as an entity's version marker.
///
/// The write path compares the value a client based its edit on against the
/// current server value for this column to detect a concurrent modification.
pub trait VersionColumn {
    /// The column's name within the table that carries it.
    fn name(&self) -> &str;
}

/// A catalog's write policy.
///
/// A table may be a mutation target when it is, or descends from, a base entity
/// that carries a version column. The version column may live in the target
/// table itself or in one of its ancestors, reached through the shared primary
/// key. When it lives in an ancestor, the version-bearing ancestor op travels
/// in the same changeset as the descendant op, so conflict detection runs
/// in-table on whichever ops carry a version column.
///
/// Implemented per catalog: a runtime schema resolves this at run time, a
/// compile-time schema through typed column markers.
pub trait WritableCatalog {
    /// How this catalog identifies a version column.
    type Version: VersionColumn;

    /// Whether `table` may be the target of a client mutation.
    fn is_writable(&self, table: &str) -> bool;

    /// The version column `table` carries directly, or `None` when the table
    /// carries none of its own (its version lives in an ancestor, whose op the
    /// same changeset carries).
    fn version_column(&self, table: &str) -> Option<Self::Version>;
}
