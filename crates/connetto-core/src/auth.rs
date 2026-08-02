//! Session-scoped authorization context.
//!
//! Established from the JWT (or session lookup) presented in `Handshake`. Held
//! by the server for the session lifetime. Not carried on the wire once the
//! session is open. Actual permission checks go through [`crate::traits::AuthPolicy`]
//! and (in the server) `OpenFGA`. See `docs/architecture/08-authorization.md`.

use serde::{Deserialize, Serialize};

/// Session-scoped identity: a user id and nothing else.
///
/// Tenant and role belong in the authorization model rather than on the
/// session, so neither is carried here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContext<Id = String> {
    /// Stable user identifier resolved at handshake time. A developer-defined
    /// distributed id type. Text appears only at the one Postgres GUC bind,
    /// through [`Display`](std::fmt::Display).
    pub user_id: Id,
}

impl<Id> AuthContext<Id> {
    /// Build an [`AuthContext`] from a user id.
    pub fn new(user_id: impl Into<Id>) -> Self {
        Self {
            user_id: user_id.into(),
        }
    }
}

/// A verified session credential resolved by a
/// [`SessionVerifier`](crate::traits::SessionVerifier): the identity context
/// plus the connetto-minted session id the exactly-once watermark keys on.
///
/// The session id is connetto-owned (minted at login, carried in the signed
/// access token's `sid` claim), never the client-fabricated `client_id`, so it
/// survives a worker restart or a fresh transport on the same session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSession<Id = String> {
    /// The identity the session carries.
    pub context: AuthContext<Id>,
    /// The connetto-minted session id, keyed on by the durable watermark.
    pub session_id: crate::SessionId,
}
