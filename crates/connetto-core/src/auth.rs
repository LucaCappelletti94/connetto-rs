//! Session-scoped authorization context.
//!
//! Established from the JWT (or session lookup) presented in `Handshake`. Held
//! by the server for the session lifetime. Not carried on the wire once the
//! session is open. Actual permission checks go through [`crate::traits::AuthPolicy`]
//! and (in the server) `OpenFGA`. See `docs/architecture/08-authorization.md`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Session-scoped identity plus tenant and role claims.
///
/// `claims` is a name-keyed map of arbitrary JSON-shaped strings. The server
/// keeps them opaque and forwards them into policy queries. Kept as a
/// `BTreeMap` so serialization ordering is stable across encoders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContext<Id = String> {
    /// Stable user identifier resolved at handshake time. A developer-defined
    /// distributed id type. Text appears only at the one Postgres GUC bind,
    /// through [`Display`](std::fmt::Display).
    pub user_id: Id,
    /// Optional tenant identifier for multi-tenant deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Role names attached to this identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// Extra JWT or session claims, serialized as strings.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, String>,
}

impl<Id> AuthContext<Id> {
    /// Build an [`AuthContext`] from a user id, with no tenant, no roles, no extra claims.
    pub fn new(user_id: impl Into<Id>) -> Self {
        Self {
            user_id: user_id.into(),
            tenant_id: None,
            roles: Vec::new(),
            claims: BTreeMap::new(),
        }
    }

    /// Attach a tenant identifier.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Attach role names.
    #[must_use]
    pub fn with_roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    /// Insert a single extra claim.
    #[must_use]
    pub fn with_claim(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.claims.insert(key.into(), value.into());
        self
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
