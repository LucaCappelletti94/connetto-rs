//! The caller: identity, capability, and the principal a check receives.
//!
//! A handshake carries zero or more grants. Each is checked on its own and
//! resolves to a [`Subject`] or is refused, and what survives is folded into a
//! [`Principal`]. A principal may carry an identity, or capabilities, or both,
//! or neither, and those four arrival cases are the whole space. Permission
//! checks go through the authorization model rather than through anything here.
//! See `docs/architecture/12-identity-session-capability.md`.

use core::fmt::Display;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::SessionId;

/// The setting an application's policies read the caller's identity from,
/// unless it names another.
pub const DEFAULT_USER_SETTING: &str = "app.user_id";

/// The setting the packed capability subjects are bound to, unless the
/// deployment's key type names another.
pub const DEFAULT_SUBJECTS_SETTING: &str = "app.subjects";

/// The value a binding gives a half of the caller it does not hold.
///
/// Postgres cannot express absence on a pooled connection: once a custom
/// setting has been bound on a session, even transaction-locally, even by a
/// transaction that rolled back, `current_setting(.., true)` answers `''` for
/// the rest of that session and neither `RESET` nor `DISCARD ALL` takes the
/// placeholder away. So a half left unbound reads as a blank identity to the
/// next caller the pool hands that connection to, which is the one thing
/// chapter 08 forbids.
///
/// Binding this instead makes absence mean the same thing on a fresh and a
/// reused connection. It is minted once per process and no row can carry it,
/// so an owner comparison against it is false rather than accidentally true.
pub fn absent_marker() -> &'static str {
    static MARKER: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        use std::hash::{BuildHasher, Hasher, RandomState};
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u8(0);
        format!("connetto:absent:{:016x}", hasher.finish())
    });
    &MARKER
}

/// Session-scoped identity: a user id and nothing else.
///
/// Tenant and role belong in the authorization model rather than on the
/// session, so neither is carried here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContext<Id = String> {
    /// Stable user identifier resolved at handshake time. A developer-defined
    /// distributed id type. Text appears only at the one Postgres GUC bind,
    /// through [`Display`].
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
/// and its [`Display`] rendering is what reaches Postgres.
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
    ///
    /// # Errors
    ///
    /// Returns `AmbiguousIdentity` when a second `Subject::Identity` is offered because a run permits only one identity.
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

/// The caller a content ticket carries: the identity, and the capability
/// subjects it holds.
///
/// Both halves travel so the file server binds what the mint bound, and an
/// unheld half stays unheld rather than becoming `""`, which would be a real
/// identity a policy could match. The subjects ride as the list they are,
/// because a commit is attributed to each of them and only the binding needs
/// them joined, under the separator that deployment's key type chose.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentCaller {
    identity: Option<String>,
    subjects: Vec<String>,
}

impl ContentCaller {
    /// Name both halves.
    #[must_use]
    pub fn new(identity: Option<String>, subjects: impl IntoIterator<Item = String>) -> Self {
        Self {
            identity,
            subjects: subjects.into_iter().collect(),
        }
    }

    /// The identity, when a login grant resolved.
    #[must_use]
    pub fn identity(&self) -> Option<&str> {
        self.identity.as_deref()
    }

    /// The capability subjects the caller holds, sorted and without repeats,
    /// empty when it holds none.
    #[must_use]
    pub fn subjects(&self) -> &[String] {
        &self.subjects
    }

    /// The subjects joined for the one Postgres setting a policy reads them
    /// from, or `None` when the caller holds none.
    #[must_use]
    pub fn packed_subjects(&self, separator: char) -> Option<String> {
        (!self.subjects.is_empty()).then(|| {
            self.subjects
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(&separator.to_string())
        })
    }

    /// Everyone this commit is attributed to: the identity when a login
    /// resolved, else every subject the caller holds, each as the deployment's
    /// own policies spell it.
    ///
    /// A key holder is attributed once per key rather than once for the set,
    /// because a row owned by the joined list matches no single subject and
    /// would hide the file from the caller that uploaded it.
    #[must_use]
    pub fn attributions(&self) -> Vec<&str> {
        self.identity().map_or_else(
            || self.subjects.iter().map(String::as_str).collect(),
            |identity| vec![identity],
        )
    }

    /// The key a caller owns rows and meters under, which names the half it
    /// came from as well as its value.
    ///
    /// An identity and a capability subject can render alike, and a
    /// deployment whose user ids look like its key renderings would otherwise
    /// let one caller resume or commit the other's manifest. The kind is part
    /// of the key so two different callers can never share one row.
    ///
    /// `separator` MUST be the deployment's own
    /// [`CapabilityKey::SEPARATOR`](crate::auth::CapabilityKey::SEPARATOR),
    /// which no single key may contain. Joining under any other character
    /// would let one key rendered `a,b` and two keys rendered `a` and `b`
    /// produce one value, so two distinct callers would share a row and a
    /// meter.
    ///
    /// A caller holding neither half has no key, so it owns nothing.
    #[must_use]
    pub fn storage_key(&self, separator: char) -> Option<String> {
        self.identity()
            .map(|identity| format!("user:{identity}"))
            .or_else(|| {
                self.packed_subjects(separator)
                    .map(|subjects| format!("keys:{subjects}"))
            })
    }
}

/// The deployment's share-key type: how the keys a caller holds reach
/// Postgres.
///
/// A policy can only compare against a value the transaction bound, and a
/// caller may hold several keys, so the set travels as one text value under
/// [`SETTING`](Self::SETTING), joined by [`SEPARATOR`](Self::SEPARATOR), which
/// a policy unpacks:
///
/// ```sql
/// viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))
/// ```
///
/// Whatever a deployment chooses is the contract its policies are written
/// against, so choose before writing policies rather than after. A deployment
/// wanting its own key type, setting, or rendering implements this for that
/// type and everything downstream follows from [`Principal`]'s key parameter.
/// Minting lives beside the issuer rather than here, because a replica needs
/// the rendering to answer its own policies and never needs to make a key.
pub trait CapabilityKey:
    Clone + Display + Serialize + DeserializeOwned + Send + Sync + 'static
{
    /// The Postgres setting the joined keys are bound to.
    const SETTING: &'static str = DEFAULT_SUBJECTS_SETTING;

    /// The character joining the keys. A key whose rendering contains it is
    /// refused at minting, because one that slipped through would split into
    /// two and grant a neighbouring key's access.
    const SEPARATOR: char = ',';

    /// The subjects a caller holds, sorted and without repeats, empty when it
    /// holds none.
    ///
    /// The list rather than one joined value, because a commit is attributed
    /// to each subject and only the binding needs them joined. Sorting and
    /// dropping repeats give one holder one value whatever order its grants
    /// arrived in and however many copies of one grant it presented, so a
    /// manifest or a byte window keyed on that value stays put across runs.
    fn subjects(keys: &[CapabilitySubject<Self>]) -> Vec<String> {
        let mut rendered: Vec<String> = keys.iter().map(|key| key.key().to_string()).collect();
        rendered.sort_unstable();
        rendered.dedup();
        rendered
    }
}

/// The default share-key: `key:` followed by a version 4 UUID, which no
/// rendering of can contain the separator.
impl CapabilityKey for String {}
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
        assert_eq!(principal.capabilities(), []);
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

    /// Two callers under a deployment whose separator is not a comma keep
    /// separate keys, even when one holds a key spelled like the other's pair.
    ///
    /// Only the deployment's own separator is barred from a key's rendering,
    /// so joining under any other character lets `a,b` and the pair `a`, `b`
    /// render alike, and the two callers would share a manifest row and a
    /// meter bucket.
    #[test]
    fn a_key_spelled_like_a_pair_owns_its_own_rows() {
        let one_key = ContentCaller::new(None, ["a,b".to_owned()]);
        let two_keys = ContentCaller::new(None, ["a".to_owned(), "b".to_owned()]);
        assert_ne!(
            one_key.storage_key('|'),
            two_keys.storage_key('|'),
            "the deployment's own separator keeps the two apart"
        );
        assert_eq!(
            two_keys.storage_key('|').as_deref(),
            Some("keys:a|b"),
            "and the pair joins under that separator"
        );
    }
}
