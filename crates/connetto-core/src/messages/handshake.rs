//! Handshake and handshake acknowledgement.
//!
//! The handshake carries the client-declared protocol version, a client-chosen
//! correlation label, zero or more grants the server checks independently, and
//! optionally the signed resume blob and last cursor the server issued on a
//! prior connection. On acceptance the server replies with the resume blob for
//! next time, the current cursor, the schema version, and the initial
//! flow-control credit budget. See `docs/architecture/02-protocol.md` and
//! `docs/architecture/12-identity-session-capability.md`.

use serde::{Deserialize, Serialize};

use crate::{cursor::Cursor, schema::SchemaVersion};

/// One grant on a handshake: a connetto-signed token asserting that the bearer
/// is a named subject, either a person or a key.
///
/// Opaque to the client with one exception: it reads `exp` out of the payload
/// so it does not present a key it can already tell is dead, which is advisory
/// because the server checks the expiry regardless (`02-protocol.md`). It says
/// nothing about what the subject may do, because the authorization model
/// answers that from a row the application owns.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Grant(String);

impl Grant {
    /// Wrap a token the client received from connetto.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// The token to check, the only thing the server does with it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// First message a client sends after opening the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handshake {
    /// Wire protocol version. Must match [`crate::version::PROTOCOL_VERSION`] on
    /// the server or the session is terminated with
    /// [`crate::messages::FatalErrorReason::ProtocolVersionMismatch`].
    pub protocol_version: u32,
    /// Client-chosen stable id, purely a logging and correlation label. It is
    /// NEVER a server trust input or a durable-state key: the server resolves
    /// identity and the exactly-once watermark key from the checked grants and
    /// the signed resume blob, never from this field. The browser relay reuses
    /// it as a tab-local id for lock naming and hub routing, a client-side
    /// concern only.
    pub client_id: String,
    /// Zero or more grants, each checked on its own. An empty list is a caller
    /// with no identity, which is a supported arrival case rather than an
    /// error, and a grant that fails to check neither ends the connection nor
    /// appears on the reply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Grant>,
    /// The signed resume credential from a prior connection, absent on a first
    /// connect. It names the durable handle of a run with no identity, and the
    /// server refuses one it did not sign, so a caller can neither invent a
    /// handle nor resume as a visitor whose handle it guessed. An identified
    /// run takes its handle from its login grant, so this is ignored there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_token: Option<String>,
    /// Cursor from a prior connection when resuming. Opaque to the client and
    /// echoed back verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_cursor: Option<Cursor>,
}

impl Handshake {
    /// Build a handshake presenting nothing: no grant and no resume state.
    pub fn new(protocol_version: u32, client_id: impl Into<String>) -> Self {
        Self {
            protocol_version,
            client_id: client_id.into(),
            grants: Vec::new(),
            resume_token: None,
            last_cursor: None,
        }
    }

    /// Present one more grant.
    #[must_use]
    pub fn with_grant(mut self, grant: impl Into<Grant>) -> Self {
        self.grants.push(grant.into());
        self
    }

    /// Present several grants.
    #[must_use]
    pub fn with_grants(mut self, grants: impl IntoIterator<Item = Grant>) -> Self {
        self.grants.extend(grants);
        self
    }

    /// Attach the signed resume credential from a prior connection.
    #[must_use]
    pub fn with_resume_token(mut self, token: impl Into<String>) -> Self {
        self.resume_token = Some(token.into());
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
    /// Per-connection routing label the server assigns at handshake. This is
    /// not identity and must not be trusted as such: it is distinct from both
    /// the run's durable handle and the credential that proves it. Used for
    /// logging and routing.
    pub connection_id: String,
    /// The run's durable handle, in the clear.
    ///
    /// An identifier, not a credential. The application needs to read it,
    /// because a synced row written before anybody signed in is attributed to
    /// it and only the application knows which of its own rows to re-key at the
    /// sign-in switch. Presenting it proves nothing: what proves it is
    /// [`resume_token`](Self::resume_token).
    pub session_token: String,
    /// The credential to persist and present on the next connect, proving the
    /// handle above is this caller's.
    ///
    /// A bearer secret, unlike the handle, so it goes wherever the refresh
    /// token goes and never into the local replica, which for a run with no
    /// identity is in memory and would lose it on every reload.
    pub resume_token: String,
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
    fn handshake_new_presents_nothing() {
        let hs = Handshake::new(1, "client-a");
        assert!(hs.grants.is_empty());
        assert!(hs.resume_token.is_none());
        assert!(hs.last_cursor.is_none());
    }

    #[test]
    fn handshake_builders_populate_grants_and_resume_state() {
        let cursor = Cursor::new(vec![1, 2, 3]);
        let hs = Handshake::new(1, "client-a")
            .with_grant(Grant::new("login"))
            .with_grants([Grant::new("key-one"), Grant::new("key-two")])
            .with_resume_token("resume-credential")
            .with_cursor(cursor.clone());
        assert_eq!(hs.grants.len(), 3);
        assert_eq!(hs.grants[0].as_str(), "login");
        assert_eq!(hs.resume_token.as_deref(), Some("resume-credential"));
        assert_eq!(hs.last_cursor.as_ref(), Some(&cursor));
    }

    #[test]
    fn a_grant_is_transparent_on_the_wire() {
        let encoded = serde_json::to_string(&Grant::new("tok")).unwrap();
        assert_eq!(encoded, "\"tok\"");
    }
}
