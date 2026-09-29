//! Shared helpers for the R94 builder migration.
//!
//! Every construction site in this suite builds through the client builders.
//! These helpers carry the pieces the sites share, so a test reads as the
//! build it is. The schema is a translated bundle, the identity is a held
//! credential, the durable key lives in a store, and the transport is a
//! dialer the builder owns.

use connetto_client::{
    ClientError, Custody, Grant, HeldCredential, MemoryKeyStore, NoGate, SyncSchema,
    TransportFactory,
};
use connetto_core::ReplicaKey;
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{MaybeSend, ReplicaKeyStore, Transport};

/// A test schema bundle over one raw DDL, no policies, no local tier.
///
/// The schema and policy sources are empty, which is honest for a bundle a
/// test writes by hand rather than translates, and the version hashes them
/// with the DDL the way a real build does.
#[must_use]
pub fn bundle(ddl: &str) -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "",
        "",
        ddl,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        None::<&str>,
    ))
}

/// A held credential for `user_id`, minting the standard `user:<user_id>` grant.
///
/// The grant the suite's test grant checker resolves to `user_id`, so the
/// credential's caller and the subject it presents agree.
#[must_use]
pub fn held(user_id: &str) -> HeldCredential {
    HeldCredential::new(Grant::new(format!("user:{user_id}")), user_id)
        .expect("a held credential serializes its id")
}

/// A held credential for `user_id` presenting the caller's own grant.
#[must_use]
pub fn held_grant(grant: Grant, user_id: &str) -> HeldCredential {
    HeldCredential::new(grant, user_id).expect("a held credential serializes its id")
}

/// A key store holding the suite's test replica key under the credential's name.
///
/// The durable stage resolves the replica key from the store under the
/// credential's [`replica_name`](HeldCredential::replica_name), so the record
/// the store hands back and the file the build opens agree on the identity.
#[cfg(feature = "native-auth")]
pub async fn key_store(cred: &HeldCredential) -> MemoryKeyStore {
    key_store_with(cred, connetto_core::test_support::replica_key()).await
}

/// A key store holding `key` under the credential's name.
#[cfg(feature = "native-auth")]
pub async fn key_store_with(cred: &HeldCredential, key: ReplicaKey) -> MemoryKeyStore {
    let store = MemoryKeyStore::default();
    store
        .store(cred.replica_name(), &key)
        .await
        .expect("the in-memory store never fails");
    store
}

/// The refusal a one-shot dialer hands back after it has handed out its
/// transport.
#[derive(Debug, thiserror::Error)]
#[error("the one-shot dialer has no second transport")]
pub struct DialExhausted;

/// A dialer that hands out exactly one transport, the one the test attached.
///
/// The builder dials once for `connect_driven` and once for the first
/// `connect_with_pump`, and a build with no reconnect driver never dials again.
pub struct Once<T> {
    transport: Option<T>,
}

impl<T> Once<T> {
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport: Some(transport),
        }
    }
}

impl<T: Transport + MaybeSend + 'static> TransportFactory for Once<T> {
    type Transport = T;
    type Error = DialExhausted;

    fn connect(&mut self) -> impl Future<Output = Result<T, DialExhausted>> + MaybeSend {
        std::future::ready(self.transport.take().ok_or(DialExhausted))
    }
}

/// The refusal a dialer that never reaches a server hands back.
#[derive(Debug, thiserror::Error)]
#[error("no server is reachable")]
pub struct Unreachable;

/// A dialer that never reaches a server, so a running client stays offline
/// and keeps redialing.
pub struct NeverDial<T>(core::marker::PhantomData<fn() -> T>);

impl<T> Default for NeverDial<T> {
    fn default() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<T: Transport + MaybeSend + 'static> TransportFactory for NeverDial<T> {
    type Transport = T;
    type Error = Unreachable;

    fn connect(&mut self) -> impl Future<Output = Result<T, Unreachable>> + MaybeSend {
        std::future::ready(Err(Unreachable))
    }
}

/// A replica-key store that shares its records through every clone.
///
/// The builder's durable stage takes the store by value, and a test that
/// inspects the records afterwards keeps its own clone, so the records sit
/// behind one `Arc` rather than in one owner.
#[derive(Clone, Default)]
pub struct SharedKeys {
    inner: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, ReplicaKey>>>,
}

#[expect(
    clippy::unused_async_trait_impl,
    reason = "the trait methods are async and the bodies finish without awaiting"
)]
impl ReplicaKeyStore for SharedKeys {
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

    fn protection(&self) -> Custody {
        Custody::Unverified(NoGate::Unsupported)
    }
}
