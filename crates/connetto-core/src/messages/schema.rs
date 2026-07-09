//! Announcement that the server-side schema changed.
//!
//! The header travels on the control channel. The schema payload rides on the
//! bulk channel as [`crate::messages::bulk::BulkMessage::SchemaBlob`]. Splitting
//! the two lets the client compare the version and hash before deciding whether
//! it needs to fetch and apply the (potentially large) payload.

use serde::{Deserialize, Serialize};

use crate::schema::SchemaVersion;

/// Server tells the client "the schema is now this version".
///
/// The client compares `version` against its persisted schema version. If
/// identical, no bulk fetch is required (the announcement was defensive). If
/// different, the accompanying bulk `SchemaBlob` carries the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaUpdate {
    /// New schema version.
    pub version: SchemaVersion,
    /// Whether the accompanying bulk blob is required. `false` means the header
    /// alone is enough (typically a defensive re-announcement).
    #[serde(default)]
    pub payload_follows: bool,
}
