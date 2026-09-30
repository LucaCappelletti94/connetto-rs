//! The in-memory secret stores, for tests and ephemeral sessions on every
//! target.

use std::sync::Mutex;

use connetto_core::custody::{Custody, NoGate};
use connetto_core::traits::{RefreshFuture, RefreshTokenStore, ReplicaKeyStore};

use crate::ClientError;
use crate::cipher::ReplicaKey;

/// An in-memory refresh-token store, for tests and ephemeral sessions.
#[derive(Default)]
pub struct MemoryRefreshStore {
    inner: Mutex<std::collections::HashMap<String, String>>,
}

impl RefreshTokenStore for MemoryRefreshStore {
    type Error = ClientError;

    fn load<'a>(&'a self, account: &'a str) -> RefreshFuture<'a, Option<String>, ClientError> {
        let token = self
            .inner
            .lock()
            .expect("refresh store lock")
            .get(account)
            .cloned();
        Box::pin(std::future::ready(Ok(token)))
    }

    fn store<'a>(&'a self, account: &'a str, token: &'a str) -> RefreshFuture<'a, (), ClientError> {
        self.inner
            .lock()
            .expect("refresh store lock")
            .insert(account.to_owned(), token.to_owned());
        Box::pin(std::future::ready(Ok(())))
    }

    fn clear<'a>(&'a self, account: &'a str) -> RefreshFuture<'a, (), ClientError> {
        self.inner
            .lock()
            .expect("refresh store lock")
            .remove(account);
        Box::pin(std::future::ready(Ok(())))
    }

    /// Enumerated from the map itself, so it cannot disagree with what is stored.
    fn accounts(&self) -> RefreshFuture<'_, Vec<String>, ClientError> {
        let accounts = self
            .inner
            .lock()
            .expect("refresh store lock")
            .keys()
            .filter(|name| !crate::is_reserved_record(name))
            .cloned()
            .collect();
        Box::pin(std::future::ready(Ok(accounts)))
    }

    /// No user-verified gate reaches the stored items until R51 and R52
    /// land one, so nothing can be offered yet (R23, decision 5).
    fn protection(&self) -> Custody {
        Custody::Unverified(NoGate::Unsupported)
    }
}

/// An in-memory replica-key store, for tests and ephemeral sessions.
#[derive(Default)]
pub struct MemoryKeyStore {
    inner: Mutex<std::collections::HashMap<String, ReplicaKey>>,
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the trait method is async and this body finishes without awaiting"
)]
impl ReplicaKeyStore for MemoryKeyStore {
    type Error = ClientError;

    async fn load(&self, name: &str) -> Result<Option<ReplicaKey>, ClientError> {
        Ok(self
            .inner
            .lock()
            .expect("key store lock")
            .get(name)
            .cloned())
    }

    async fn store(&self, name: &str, key: &ReplicaKey) -> Result<(), ClientError> {
        self.inner
            .lock()
            .expect("key store lock")
            .insert(name.to_owned(), key.clone());
        Ok(())
    }

    async fn clear(&self, name: &str) -> Result<(), ClientError> {
        self.inner.lock().expect("key store lock").remove(name);
        Ok(())
    }

    /// No user-verified gate reaches the stored items until R51 and R52
    /// land one, so nothing can be offered yet (R23, decision 5).
    fn protection(&self) -> Custody {
        Custody::Unverified(NoGate::Unsupported)
    }
}
