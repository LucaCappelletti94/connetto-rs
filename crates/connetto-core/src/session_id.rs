//! The connetto-minted identifier of an authenticated session.
//!
//! A session id is minted once at login, carried in the signed access token's
//! `sid` claim, and used as the durable key of the exactly-once mutation
//! watermark. It is connetto's own value, never the client-fabricated
//! `client_id` and never the per-connection routing label the handshake ack
//! returns, so it survives a worker restart or a fresh transport on the same
//! session.
//!
//! It is a fixed 128-bit value and therefore [`Copy`]. Postgres stores it in
//! its native `uuid` column, which enforces the width in the schema and stays
//! legible in an ad-hoc query, rather than an opaque `BYTEA` that would accept
//! any byte string. It never reaches SQLite, so nothing forces it onto the
//! byte-array representation the developer's own `user_id` needs to share
//! between the replica and the server.
//!
//! Text is produced only at the two edges that are inherently textual: the JWT
//! `sid` claim, and the `"<session_id>.<secret>"` refresh token whose halves
//! are concatenated and split as strings. Both use the canonical dashed form,
//! so a claim correlates by eye with the row.

use core::fmt;
use core::str::FromStr;

/// The connetto-minted identifier of an authenticated session.
///
/// Construct one at login with [`SessionId::from_uuid`], or derive one
/// deterministically from a credential with [`SessionId::from_token_hash`].
/// The core deliberately carries no entropy source, so minting belongs to the
/// server that owns the login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "diesel-pg",
    derive(diesel::expression::AsExpression, diesel::deserialize::FromSqlRow),
    diesel(sql_type = diesel::sql_types::Uuid)
)]
pub struct SessionId(uuid::Uuid);

impl SessionId {
    /// Wrap a freshly minted uuid.
    #[must_use]
    pub const fn from_uuid(id: uuid::Uuid) -> Self {
        Self(id)
    }

    /// The underlying uuid.
    #[must_use]
    pub const fn as_uuid(&self) -> &uuid::Uuid {
        &self.0
    }

    /// Derive a session id deterministically from a credential string.
    ///
    /// Used by the test-support session verifier, where the presented token
    /// stands in for a verified session. Deterministic so that a reconnect
    /// presenting the same token lands on the same watermark key, which is the
    /// property that makes the exactly-once gate work in the test and
    /// local-loop paths.
    #[must_use]
    pub fn from_token_hash(token: &str) -> Self {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(token.as_bytes());
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Self(uuid::Uuid::from_bytes(bytes))
    }

    /// Fold the 128-bit id into the `u64` key subql's per-session cursors and
    /// pending buffers are addressed by. Deterministic per handle, so a
    /// reconnect on the same session resumes the same cursor slot where the
    /// old per-connection counter never could.
    #[must_use]
    pub fn as_u64_key(&self) -> u64 {
        let (hi, lo) = self.0.as_u64_pair();
        hi ^ lo
    }
}

/// The canonical dashed uuid form, matching what the `uuid` column shows.
impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A string that is not a valid session id.
///
/// Implemented by hand rather than through `thiserror`, which is an optional
/// dependency here, so the session id costs the core no new mandatory crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdParseError;

impl fmt::Display for SessionIdParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid session id: expected a uuid")
    }
}

impl std::error::Error for SessionIdParseError {}

impl FromStr for SessionId {
    type Err = SessionIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self).map_err(|_| SessionIdParseError)
    }
}

impl serde::Serialize for SessionId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for SessionId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SessionIdVisitor;

        impl serde::de::Visitor<'_> for SessionIdVisitor {
            type Value = SessionId;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a uuid session id")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<SessionId, E> {
                value.parse().map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(SessionIdVisitor)
    }
}

// The Postgres binary form of `uuid` is exactly the 16 raw bytes, which is what
// diesel's own codec for the `uuid` crate writes. Implementing it here keeps
// diesel's optional `uuid` feature out of the dependency graph.
#[cfg(feature = "diesel-pg")]
impl diesel::serialize::ToSql<diesel::sql_types::Uuid, diesel::pg::Pg> for SessionId {
    fn to_sql<'b>(
        &'b self,
        out: &mut diesel::serialize::Output<'b, '_, diesel::pg::Pg>,
    ) -> diesel::serialize::Result {
        use std::io::Write as _;
        out.write_all(self.0.as_bytes())
            .map(|()| diesel::serialize::IsNull::No)
            .map_err(Into::into)
    }
}

#[cfg(feature = "diesel-pg")]
impl diesel::deserialize::FromSql<diesel::sql_types::Uuid, diesel::pg::Pg> for SessionId {
    fn from_sql(
        value: <diesel::pg::Pg as diesel::backend::Backend>::RawValue<'_>,
    ) -> diesel::deserialize::Result<Self> {
        uuid::Uuid::from_slice(value.as_bytes())
            .map(Self)
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::SessionId;

    #[test]
    fn the_canonical_uuid_form_round_trips() {
        let id = SessionId::from_uuid(uuid::Uuid::from_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]));
        let text = id.to_string();
        assert_eq!(
            text, "01234567-89ab-cdef-fedc-ba9876543210",
            "the dashed form the uuid column shows, so a sid claim correlates by eye"
        );
        assert_eq!(text.parse::<SessionId>().expect("parse"), id);
    }

    #[test]
    fn a_malformed_session_id_is_refused() {
        // The refresh token splits on a dot, so a caller can present anything
        // in the id half. Anything that is not a uuid names no session, rather
        // than being silently truncated or padded into one that exists.
        assert!("".parse::<SessionId>().is_err());
        assert!("abc".parse::<SessionId>().is_err());
        assert!(
            "01234567-89ab-cdef-fedc-ba987654321"
                .parse::<SessionId>()
                .is_err(),
            "one character short"
        );
        assert!(
            "01234567-89ab-cdef-fedc-ba98765432zz"
                .parse::<SessionId>()
                .is_err(),
            "non-hex characters"
        );
    }

    #[test]
    fn a_token_derived_id_is_deterministic_and_distinguishing() {
        // The trusting verifier relies on both halves: the same token must
        // resume onto the same watermark key, and two tokens must not collide.
        assert_eq!(
            SessionId::from_token_hash("alice-token"),
            SessionId::from_token_hash("alice-token")
        );
        assert_ne!(
            SessionId::from_token_hash("alice-token"),
            SessionId::from_token_hash("bob-token")
        );
    }

    #[test]
    fn serde_carries_the_canonical_form() {
        let id = SessionId::from_token_hash("session");
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(
            serde_json::from_str::<SessionId>(&json).expect("deserialize"),
            id
        );
    }
}
