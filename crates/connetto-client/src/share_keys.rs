//! Identity-scoped share-key persistence outside encrypted replicas.

use core::fmt::{Debug, Display};
use core::future::Future;
use core::pin::Pin;

use connetto_core::auth::{CapabilityKey, CapabilitySubject};
use connetto_core::custody::Custody;
use connetto_core::messages::Grant;
use connetto_core::traits::{MaybeSend, MaybeSync, RefreshTokenStore};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::ClientError;

/// A native store operation that may move between runtime workers.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub type ShareKeyFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;
/// A browser store operation confined to its owning thread.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub type ShareKeyFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + 'a>>;

/// The share keys a build holds, each grant beside the subject it renders as.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareKeySet {
    /// The separator the subjects function packs with.
    pub(crate) separator: char,
    /// Each grant beside the subject string it renders as.
    pub(crate) keys: Vec<(Grant, String)>,
}

impl ShareKeySet {
    /// The keys `keys` names, rendered through their own key type.
    pub fn new<K: CapabilityKey>(
        keys: impl IntoIterator<Item = (Grant, CapabilitySubject<K>)>,
    ) -> Self {
        Self {
            separator: K::SEPARATOR,
            keys: keys
                .into_iter()
                .map(|(grant, subject)| (grant, subject.key().to_string()))
                .collect(),
        }
    }

    /// A set rendered from its separator and its pairs, the wire shape the
    /// store persists.
    pub(crate) fn rendered(separator: char, keys: Vec<(Grant, String)>) -> Self {
        Self { separator, keys }
    }

    /// The separator the subjects function packs with.
    pub(crate) fn separator(&self) -> char {
        self.separator
    }

    /// Each grant beside the subject it renders as.
    pub(crate) fn pairs(&self) -> &[(Grant, String)] {
        &self.keys
    }

    /// Add `grant` beside `subject`, leaving the set untouched when the
    /// identical pair is already held.
    pub(crate) fn insert(&mut self, grant: Grant, subject: String) -> bool {
        if self
            .keys
            .iter()
            .any(|(held, subject_held)| held == &grant && subject_held == &subject)
        {
            return false;
        }
        self.keys.push((grant, subject));
        true
    }

    /// Add the pairs `pairs` holds that the set does not, answering whether
    /// anything was added.
    pub(crate) fn union(&mut self, pairs: &[(Grant, String)]) -> bool {
        let mut added = false;
        for (grant, subject) in pairs {
            if self.insert(grant.clone(), subject.clone()) {
                added = true;
            }
        }
        added
    }

    /// Drop the pairs whose grant has expired at `now`, answering whether
    /// anything went.
    pub(crate) fn remove_expired(&mut self, now: i64) -> bool {
        let before = self.keys.len();
        self.keys
            .retain(|(grant, _)| !crate::grant_expiry::has_expired(grant, now));
        before != self.keys.len()
    }
}

impl Debug for ShareKeySet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShareKeySet")
            .field("pairs", &self.keys.len())
            .finish_non_exhaustive()
    }
}

/// Where a durable build persists its share keys.
///
/// The records are addressed by the identity-scoped name
/// [`share_key_record`] produces, so a store that holds several identities
/// keeps their keys apart and a forget of one erases only its own. Natively
/// the adaptation over a [`RefreshTokenStore`]'s string records below
/// supplies the implementation for every refresh store, and the browser
/// supplies its own storage on the same semantic interface.
///
/// The trait carries the target's [`MaybeSend`] and [`MaybeSync`], so a
/// store shared between native workers crosses threads and a wasm store
/// stays local.
pub trait ShareKeyStore: MaybeSend + MaybeSync {
    /// Store-specific error.
    type Error: Debug + Display + Send + Sync + 'static;

    /// The set stored under `record`, or `None` when none was stored.
    ///
    /// # Errors
    ///
    /// [`Self::Error`] if the backing store cannot be read.
    fn load<'a>(&'a self, record: &'a str) -> ShareKeyFuture<'a, Option<ShareKeySet>, Self::Error>;

    /// Persist `set` under `record`, replacing any prior one.
    ///
    /// # Errors
    ///
    /// [`Self::Error`] if the backing store cannot be written.
    fn save<'a>(
        &'a self,
        record: &'a str,
        set: &'a ShareKeySet,
    ) -> ShareKeyFuture<'a, (), Self::Error>;

    /// Remove the set stored under `record`, if any.
    ///
    /// # Errors
    ///
    /// [`Self::Error`] if the backing store cannot be cleared.
    fn clear<'a>(&'a self, record: &'a str) -> ShareKeyFuture<'a, (), Self::Error>;

    /// The protection the items this store writes carry.
    fn protection(&self) -> Custody;
}

/// The adaptation over the shared refresh store a provider sign-in hands to
/// the durable step, which the sign-in reuses for its share keys, since the
/// token and the keys ride one protection either way.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
#[derive(Clone)]
pub(crate) struct RefreshStoreShareKeys(
    pub(crate) Arc<dyn RefreshTokenStore<Error = ClientError> + Send + Sync>,
);

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
impl ShareKeyStore for RefreshStoreShareKeys {
    type Error = ClientError;

    fn load<'a>(&'a self, record: &'a str) -> ShareKeyFuture<'a, Option<ShareKeySet>, ClientError> {
        let store = &self.0;
        Box::pin(async move {
            let raw = RefreshTokenStore::load(store.as_ref(), record).await?;
            raw.map(|raw| decode(&raw)).transpose()
        })
    }

    fn save<'a>(
        &'a self,
        record: &'a str,
        set: &'a ShareKeySet,
    ) -> ShareKeyFuture<'a, (), ClientError> {
        let store = &self.0;
        Box::pin(async move {
            let encoded = encode(set)?;
            RefreshTokenStore::store(store.as_ref(), record, &encoded).await
        })
    }

    fn clear<'a>(&'a self, record: &'a str) -> ShareKeyFuture<'a, (), ClientError> {
        RefreshTokenStore::clear(self.0.as_ref(), record)
    }

    fn protection(&self) -> Custody {
        RefreshTokenStore::protection(self.0.as_ref())
    }
}

/// The prefix of the record holding an identity's share keys.
///
/// The record sits in the credential store beside the refresh token, named
/// from the identity's replica name, so two identities on one device keep
/// separate records and a forget derives the name it erases.
pub const SHARE_KEY_RECORD_PREFIX: &str = "connetto-share-keys:";

/// The share-key record of the account named `account`, its replica name.
#[must_use]
pub fn share_key_record(account: &str) -> String {
    format!("{SHARE_KEY_RECORD_PREFIX}{account}")
}

/// Whether `name` identifies a gated share-key record excluded from account enumeration.
#[must_use]
pub fn is_share_key_record(name: &str) -> bool {
    name.starts_with(SHARE_KEY_RECORD_PREFIX)
}

/// The wire shape a set serializes to.
pub(crate) fn encode(set: &ShareKeySet) -> Result<String, ClientError> {
    serde_json::to_string(set)
        .map_err(|_| ClientError::Session("share keys could not be encoded".to_owned()))
}

/// Reject malformed secret records without echoing their contents.
pub(crate) fn decode(record: &str) -> Result<ShareKeySet, ClientError> {
    serde_json::from_str(record).map_err(|err: serde_json::Error| {
        ClientError::Session(format!(
            "share keys could not be decoded at line {} column {}",
            err.line(),
            err.column(),
        ))
    })
}

/// An identity-scoped secret store with a thread-bound browser handle.
pub(crate) struct ShareKeyPersistence {
    store: ShareStoreHandle,
    record: String,
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub(crate) type ErasedShareKeyStore =
    Arc<dyn ShareKeyStore<Error = ClientError> + Send + Sync + 'static>;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub(crate) type ErasedShareKeyStore = Arc<dyn ShareKeyStore<Error = ClientError> + 'static>;

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
type ShareStoreHandle = ErasedShareKeyStore;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
type ShareStoreHandle = send_wrapper::SendWrapper<ErasedShareKeyStore>;

impl ShareKeyPersistence {
    /// Take the erased store over the identity record `record`.
    pub(crate) fn new(store: ErasedShareKeyStore, record: String) -> Self {
        #[cfg(all(target_family = "wasm", target_os = "unknown"))]
        let store = send_wrapper::SendWrapper::new(store);
        Self { store, record }
    }

    /// The set the store holds for the identity, or `None` when it holds
    /// none.
    pub(crate) async fn load(&self) -> Result<Option<ShareKeySet>, ClientError> {
        self.store
            .load(&self.record)
            .await
            .map_err(|err| ClientError::Auth(err.to_string()))
    }

    /// Persist `set` for the identity, replacing any prior one.
    pub(crate) async fn save(&self, set: &ShareKeySet) -> Result<(), ClientError> {
        self.store
            .save(&self.record, set)
            .await
            .map_err(|err| ClientError::Auth(err.to_string()))
    }
}

/// Stores serialized share keys with the refresh-token store's protection.
impl<S> ShareKeyStore for S
where
    S: RefreshTokenStore<Error = ClientError> + MaybeSend + MaybeSync + 'static,
{
    type Error = ClientError;

    fn load<'a>(&'a self, record: &'a str) -> ShareKeyFuture<'a, Option<ShareKeySet>, ClientError> {
        let this = self;
        Box::pin(async move {
            let raw = RefreshTokenStore::load(this, record).await?;
            raw.map(|raw| decode(&raw)).transpose()
        })
    }

    fn save<'a>(
        &'a self,
        record: &'a str,
        set: &'a ShareKeySet,
    ) -> ShareKeyFuture<'a, (), ClientError> {
        let this = self;
        Box::pin(async move { RefreshTokenStore::store(this, record, &encode(set)?).await })
    }

    fn clear<'a>(&'a self, record: &'a str) -> ShareKeyFuture<'a, (), ClientError> {
        let this = self;
        Box::pin(async move { RefreshTokenStore::clear(this, record).await })
    }

    fn protection(&self) -> Custody {
        RefreshTokenStore::protection(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A three-segment token whose payload is `claims`, signed with nothing.
    fn token(claims: &str) -> Grant {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        Grant::new(format!(
            "{}.{}.{}",
            B64.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#),
            B64.encode(claims.as_bytes()),
            B64.encode(b"not-a-signature")
        ))
    }

    #[test]
    fn the_set_keeps_distinct_grants_for_one_subject_and_ignores_an_identical_pair() {
        let mut set = ShareKeySet::new::<String>([
            (Grant::new("g1"), CapabilitySubject::new("s")),
            (Grant::new("g2"), CapabilitySubject::new("s")),
        ]);
        assert!(!set.insert(Grant::new("g1"), "s".to_owned()));
        assert!(set.insert(Grant::new("g3"), "s".to_owned()));
        assert_eq!(
            set.pairs(),
            &[
                (Grant::new("g1"), "s".to_owned()),
                (Grant::new("g2"), "s".to_owned()),
                (Grant::new("g3"), "s".to_owned()),
            ],
        );
    }

    #[test]
    fn the_union_keeps_each_pair_once_and_says_when_it_added_nothing() {
        let mut set = ShareKeySet::rendered(',', vec![(Grant::new("g1"), "a".to_owned())]);
        assert!(set.union(&[
            (Grant::new("g1"), "a".to_owned()),
            (Grant::new("g2"), "b".to_owned())
        ]));
        assert!(!set.union(&[(Grant::new("g1"), "a".to_owned())]));
        assert_eq!(
            set.pairs(),
            &[
                (Grant::new("g1"), "a".to_owned()),
                (Grant::new("g2"), "b".to_owned())
            ]
        );
    }

    #[test]
    fn the_expiry_check_drops_only_the_dead_grants() {
        let mut set = ShareKeySet::rendered(
            ',',
            vec![
                (token(r#"{"exp":1000}"#), "a".to_owned()),
                (token(r#"{"exp":9000}"#), "b".to_owned()),
                (Grant::new("opaque"), "c".to_owned()),
            ],
        );
        assert!(set.remove_expired(5000));
        assert_eq!(
            set.pairs(),
            &[
                (token(r#"{"exp":9000}"#), "b".to_owned()),
                (Grant::new("opaque"), "c".to_owned())
            ]
        );
        assert!(!set.remove_expired(5000));
    }

    #[test]
    fn a_debug_print_reveals_only_the_pair_count() {
        let set = ShareKeySet::new::<String>([(
            Grant::new("a-secret-grant"),
            CapabilitySubject::new("a-secret-subject"),
        )]);
        let printed = format!("{set:?}");
        assert!(!printed.contains("a-secret-grant"));
        assert!(!printed.contains("a-secret-subject"));
    }

    /// A marker a codec that echoed the stored bytes would print into its
    /// error.
    const MALFORMED_MARKER: &str = "R95-secret-share-marker-9f8e7d";

    /// A record whose separator field is a string, the shape serde refuses
    /// and prints back in its error.
    fn malformed_record() -> String {
        format!(r#"{{"separator":"{MALFORMED_MARKER}","keys":[]}}"#)
    }

    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[tokio::test]
    async fn a_malformed_record_read_through_the_blanket_adapter_echoes_nothing() {
        let store = crate::memory_stores::MemoryRefreshStore::default();
        let record = share_key_record("malformed-read");
        let malformed = malformed_record();
        RefreshTokenStore::store(&store, &record, &malformed)
            .await
            .expect("seed the malformed record");
        let err = ShareKeyStore::load(&store, &record)
            .await
            .expect_err("the malformed record refuses");
        let rendered = err.to_string();
        assert!(
            !rendered.contains(MALFORMED_MARKER),
            "the adapter error must not echo the record, got: {rendered}"
        );
    }
}
