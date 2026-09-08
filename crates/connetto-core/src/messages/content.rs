//! The content ticket request and its grant.
//!
//! A content ticket moves an authorization decision from the websocket to HTTP
//! so a plain URL can fetch bytes. It is not a capability: see
//! `docs/architecture/18-file-handling.md`.

use serde::{Deserialize, Serialize};

/// What a caller intends to do with the file it names.
///
/// The declared size sits inside `Write` so a write without one cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentVerb {
    /// Download the named file.
    Read,
    /// Upload the named file, declaring how many bytes it intends to send.
    Write {
        /// Bytes the caller says the upload will carry.
        declared_len: u64,
    },
}

/// Client asks for a ticket naming one file and one verb.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentTicketRequest {
    /// Client-chosen correlation token, echoed by the grant and by any refusal.
    pub request_id: String,
    /// BLAKE3 identity of the file.
    pub file_id: [u8; 32],
    /// What the caller intends to do.
    pub verb: ContentVerb,
}

/// Server hands back an address the caller may fetch or upload to.
///
/// The token rides inside `url`, in a format only the signing crate parses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentTicketGrant {
    /// Correlation token from the request this answers.
    pub request_id: String,
    /// Where to send the request, ticket included.
    pub url: String,
}
