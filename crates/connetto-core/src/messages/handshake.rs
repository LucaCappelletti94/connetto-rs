//! Handshake and handshake acknowledgement.
//!
//! The handshake carries the client-declared protocol version, a client-supplied
//! identity, the auth token to be validated by the server, and optionally the
//! opaque session token and last cursor the server issued on a prior connection.
//! On acceptance the server replies with a fresh (or reissued) session token,
//! the current cursor, the schema version, and the initial flow-control credit
//! budget. See `docs/architecture/02-protocol.md` and Q2.3, Q6.5, Q6.6.

use serde::{Deserialize, Serialize};

use crate::{cursor::Cursor, schema::SchemaVersion};

/// First message a client sends after opening the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handshake {
    /// Wire protocol version. Must match [`crate::version::PROTOCOL_VERSION`] on
    /// the server or the session is terminated with
    /// [`crate::messages::FatalErrorReason::ProtocolVersionMismatch`].
    pub protocol_version: u32,
    /// Client-chosen stable id, purely a logging and correlation label. It is
    /// NEVER a server trust input or a durable-state key: the server resolves
    /// identity and the exactly-once watermark key from the verified
    /// `auth_token`, never from this field. The browser relay reuses it as a
    /// tab-local id for lock naming and hub routing, a client-side concern only.
    pub client_id: String,
    /// Opaque JWT or session token, validated once at handshake and used to
    /// build the session `AuthContext`. The server never returns this on the wire.
    pub auth_token: String,
    /// Session token from a prior connection when resuming, absent on a first
    /// connect. Server-issued and opaque to the client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    /// Cursor from a prior connection when resuming. Opaque to the client and
    /// echoed back verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_cursor: Option<Cursor>,
}

impl Handshake {
    /// Build a fresh handshake for a new session (no resume state).
    pub fn new(
        protocol_version: u32,
        client_id: impl Into<String>,
        auth_token: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version,
            client_id: client_id.into(),
            auth_token: auth_token.into(),
            session_token: None,
            last_cursor: None,
        }
    }

    /// Attach a session token from a prior connection.
    #[must_use]
    pub fn with_session_token(mut self, token: impl Into<String>) -> Self {
        self.session_token = Some(token.into());
        self
    }

    /// Attach the resume cursor from a prior connection.
    #[must_use]
    pub fn with_cursor(mut self, cursor: Cursor) -> Self {
        self.last_cursor = Some(cursor);
        self
    }
}

/// Server acknowledgement of a successful handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeAck {
    /// Server-assigned session id. Distinct from `session_token`: the id is
    /// human-readable and used for logging, the token is the resume credential.
    pub session_id: String,
    /// Fresh or reissued session token to persist and present on next connect.
    pub session_token: String,
    /// Server's current cursor. Clients replay from here on a clean start.
    pub current_cursor: Cursor,
    /// Schema version in force server-side, or `None` when the server declares
    /// no version (staleness detection off).
    pub schema_version: Option<SchemaVersion>,
    /// Initial flow-control credit granted to the server for delivery.
    pub initial_credits: u32,
    /// The server's durable per-client mutation watermark: the highest
    /// `client_seq` it has applied for this client identity, `None` when it
    /// never applied one. The client retires every pending mutation at or
    /// below it and replays the rest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_applied_seq: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_new_defaults_are_empty() {
        let hs = Handshake::new(1, "client-a", "tok");
        assert!(hs.session_token.is_none());
        assert!(hs.last_cursor.is_none());
    }

    #[test]
    fn handshake_builders_populate_resume_state() {
        let cursor = Cursor::new(vec![1, 2, 3]);
        let hs = Handshake::new(1, "client-a", "tok")
            .with_session_token("sess-1")
            .with_cursor(cursor.clone());
        assert_eq!(hs.session_token.as_deref(), Some("sess-1"));
        assert_eq!(hs.last_cursor.as_ref(), Some(&cursor));
    }
}
