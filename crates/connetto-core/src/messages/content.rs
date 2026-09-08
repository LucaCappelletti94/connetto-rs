//! The content ticket request and its grant.
//!
//! A content ticket carries an already-made authorization decision from the
//! websocket to HTTP, so an `img` tag can fetch bytes without presenting a
//! grant. It is deliberately not a capability: see `docs/architecture/18-file-handling.md`
//! and chapter 12's "A content ticket is not a capability".

use serde::{Deserialize, Serialize};

/// What a caller intends to do with the file it names.
///
/// The write verb carries the declared size because the mint charges a
/// bandwidth rate against it and the ticket's ceiling is cut from it. Holding
/// the number inside the variant makes a write without a declared size
/// unrepresentable rather than merely invalid.
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
    /// Client-chosen correlation token, echoed by the grant and by any
    /// refusal, the same role `sub_id` plays for subscriptions.
    pub request_id: String,
    /// BLAKE3 identity of the file, the same 32 bytes the file crates key on.
    pub file_id: [u8; 32],
    /// What the caller intends to do.
    pub verb: ContentVerb,
}

/// Server hands back an address the caller may fetch or upload to.
///
/// The token rides inside `url` because the whole point is that a URL alone
/// proves the right to fetch. Its format belongs to the file crate that signed
/// it, so nothing here parses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentTicketGrant {
    /// Correlation token from the request this answers.
    pub request_id: String,
    /// Where to send the request, ticket included.
    pub url: String,
}
