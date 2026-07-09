//! Opaque resume cursor issued by the server, echoed by the client on reconnect.
//!
//! `subql` mints the cursor and is the only side that interprets it. The client
//! stores it as-is and returns it verbatim in the next `Handshake`. A wrong or
//! truncated cursor only hurts the reporting client (it triggers a
//! [`crate::messages::FullResyncRequired`]). The server's canonical state cannot
//! be forged from the wire. Decision recorded as Q6.5 and Q6.6.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Opaque bytes handed out by the server and echoed by the client verbatim.
///
/// The client never inspects the contents. It just persists and returns them.
/// Encoded as a `MessagePack` `bin` payload via [`serde_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Cursor(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl Cursor {
    /// Wrap a byte vector as a cursor.
    #[inline]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the cursor and return the underlying bytes.
    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Length of the underlying bytes in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the cursor holds zero bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Cursor {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<Cursor> for Vec<u8> {
    fn from(value: Cursor) -> Self {
        value.0
    }
}

impl From<ByteBuf> for Cursor {
    fn from(value: ByteBuf) -> Self {
        Self(value.into_vec())
    }
}
