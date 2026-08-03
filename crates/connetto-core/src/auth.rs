//! The caller: identity, capability, and the principal a check receives.
//!
//! A handshake carries zero or more grants. Each is checked on its own and
//! resolves to a [`Subject`] or is refused, and what survives is folded into a
//! [`Principal`]. A principal may carry an identity, or capabilities, or both,
//! or neither, and those four arrival cases are the whole space. Permission
//! checks go through the authorization model rather than through anything here.
//! See `docs/architecture/12-identity-session-capability.md`.

use serde::{Deserialize, Serialize};

use crate::SessionId;

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

/// A checked login grant: the identity it names plus the auth store's handle
/// for the run it belongs to.
///
/// The session id is connetto-owned (minted at login, carried in the signed
/// token's `sid` claim), never the client-fabricated `client_id`, so it
/// survives a worker restart or a fresh transport on the same session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSession<Id = String> {
    /// The identity the session carries.
    pub context: AuthContext<Id>,
    /// The connetto-minted session id, keyed on by the durable watermark.
    pub session_id: crate::SessionId,
}

/// The subject a capability grant names, for example `key:abc123`.
///
/// Generic over the deployment's own key type for the same reason
/// [`AuthContext`] is generic over its user id: text belongs at the edges, not
/// in the middle. The key's serde encoding is what the signed token carries,
/// and its [`Display`](core::fmt::Display) rendering is what reaches Postgres.
///
/// It is not a person and it asserts nothing about what it may do: the
/// authorization model holds the permission as a relation on this name, so
/// withdrawing a share is deleting a row rather than revoking a token.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilitySubject<Key = String>(Key);

impl<Key> CapabilitySubject<Key> {
    /// Name a capability subject.
    pub fn new(key: impl Into<Key>) -> Self {
        Self(key.into())
    }

    /// The key the authorization model relates permissions to.
    pub const fn key(&self) -> &Key {
        &self.0
    }

    /// Take the key out.
    pub fn into_key(self) -> Key {
        self.0
    }
}

impl<Key: core::fmt::Display> core::fmt::Display for CapabilitySubject<Key> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// What one checked grant resolved to.
///
/// Both kinds are connetto-signed tokens differing only in the kind of subject
/// they name, which is why one checker reads either and no order of checks is
/// load-bearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject<Id = String, Key = String> {
    /// A login grant, naming a person and the run the auth store opened.
    Identity(VerifiedSession<Id>),
    /// A capability grant, naming a subject that is not a person.
    Capability(CapabilitySubject<Key>),
}

/// The caller an authorization check receives.
///
/// The handle is not optional. An authenticated run uses the auth store's, and
/// a run with no identity uses one connetto minted at the handshake, so resume,
/// the per-subscription cursor, the exactly-once watermark and the connection
/// registry key on the same thing in all four arrival cases.
///
/// An identity is present or it is not, and capabilities are held zero or many
/// times, so the four cases are the entire space and there is no fifth state to
/// leave unused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal<Id = String, Key = String> {
    session_id: SessionId,
    identity: Option<AuthContext<Id>>,
    capabilities: Vec<CapabilitySubject<Key>>,
}

impl<Id, Key> Principal<Id, Key> {
    /// A caller carrying no identity, on the handle connetto minted for it.
    ///
    /// Capabilities are folded in afterwards with [`accept`](Self::accept), so
    /// this is the starting point for every handshake and an identity that
    /// resolves replaces the minted handle with the auth store's.
    #[must_use]
    pub const fn unidentified(session_id: SessionId) -> Self {
        Self {
            session_id,
            identity: None,
            capabilities: Vec::new(),
        }
    }

    /// Fold one checked grant in.
    ///
    /// A capability joins the set. An identity takes the handle with it,
    /// because an identified run is keyed by the store's session rather than by
    /// a minted one. A second identity is refused and both are dropped: a run
    /// has one identity, and keeping whichever arrived first would make the
    /// order of checks decide the caller.
    pub fn accept(&mut self, subject: Subject<Id, Key>) -> Result<(), AmbiguousIdentity> {
        match subject {
            Subject::Capability(subject) => {
                self.capabilities.push(subject);
                Ok(())
            }
            Subject::Identity(session) if self.identity.is_none() => {
                self.identity = Some(session.context);
                self.session_id = session.session_id;
                Ok(())
            }
            Subject::Identity(_) => {
                self.identity = None;
                Err(AmbiguousIdentity)
            }
        }
    }

    /// The durable handle for this run, minted or from the auth store.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The identity, when a login grant resolved.
    #[must_use]
    pub const fn identity(&self) -> Option<&AuthContext<Id>> {
        self.identity.as_ref()
    }

    /// The subjects whose capability grants resolved, in no meaningful order.
    #[must_use]
    pub fn capabilities(&self) -> &[CapabilitySubject<Key>] {
        &self.capabilities
    }
}

/// More than one login grant resolved on one handshake.
///
/// The identity is dropped rather than picked, so the caller proceeds
/// unidentified and the outcome does not depend on which grant was checked
/// first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmbiguousIdentity;

impl core::fmt::Display for AmbiguousIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("more than one login grant resolved")
    }
}

impl std::error::Error for AmbiguousIdentity {}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(byte: u8) -> SessionId {
        SessionId::from_uuid(uuid::Uuid::from_bytes([byte; 16]))
    }

    fn login(byte: u8, user: &str) -> Subject {
        Subject::Identity(VerifiedSession {
            context: AuthContext::new(user),
            session_id: handle(byte),
        })
    }

    #[test]
    fn nothing_resolved_keeps_the_minted_handle() {
        let principal: Principal = Principal::unidentified(handle(1));
        assert_eq!(principal.session_id(), handle(1));
        assert!(principal.identity().is_none());
        assert!(principal.capabilities().is_empty());
    }

    #[test]
    fn a_capability_alone_leaves_the_caller_unidentified() {
        let mut principal: Principal = Principal::unidentified(handle(1));
        principal
            .accept(Subject::Capability(CapabilitySubject::new("key:abc")))
            .unwrap();
        assert_eq!(principal.session_id(), handle(1));
        assert!(principal.identity().is_none());
        assert_eq!(principal.capabilities().len(), 1);
    }

    #[test]
    fn an_identity_takes_the_handle_with_it() {
        let mut principal: Principal = Principal::unidentified(handle(1));
        principal.accept(login(2, "alice")).unwrap();
        assert_eq!(principal.session_id(), handle(2));
        assert_eq!(principal.identity().unwrap().user_id, "alice");
    }

    #[test]
    fn identity_and_capability_arrive_together() {
        let mut principal: Principal = Principal::unidentified(handle(1));
        principal
            .accept(Subject::Capability(CapabilitySubject::new("key:abc")))
            .unwrap();
        principal.accept(login(2, "alice")).unwrap();
        assert_eq!(principal.session_id(), handle(2));
        assert_eq!(principal.identity().unwrap().user_id, "alice");
        assert_eq!(principal.capabilities().len(), 1);
    }

    #[test]
    fn two_logins_drop_the_identity_whichever_arrived_first() {
        let mut first: Principal = Principal::unidentified(handle(1));
        first.accept(login(2, "alice")).unwrap();
        assert!(first.accept(login(3, "bob")).is_err());

        let mut second: Principal = Principal::unidentified(handle(1));
        second.accept(login(3, "bob")).unwrap();
        assert!(second.accept(login(2, "alice")).is_err());

        assert!(first.identity().is_none());
        assert!(second.identity().is_none());
    }
}
