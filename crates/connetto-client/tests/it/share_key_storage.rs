//! R95 native acceptance for the share-key secret store.
//!
//! A durable held-credential build names its share-key store beside its
//! replica-key store. These proofs hold that the store's records survive a
//! restart, that builder and stored pairs form one set with expired grants
//! dropped, that a store refusal fails the build, that identities keep
//! separate records in one store, that the store's custody claim folds into
//! the build, and that a forget removes the record.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use connetto_client::share_keys::{
    ShareKeyFuture, ShareKeySet, ShareKeyStore, is_share_key_record, share_key_record,
};
use connetto_client::{
    ClientBuilder, ConnettoConnection, DataDir, Grant, NativeClientBuilder, REPLICA_PREFIX,
    SyncSchema, is_reserved_record, replica_db_name,
};
use connetto_core::SchemaBundle;
use connetto_core::auth::CapabilitySubject;
use connetto_core::custody::{Custody, NoGate};
use connetto_core::test_support::{FakeTransport, replica_key};
use connetto_core::traits::{RefreshFuture, RefreshTokenStore, ReplicaKeyStore};
use diesel::prelude::*;

/// The grant the suite hands to a subject, distinct per use so one test
/// cannot pass on the subject alone.
fn grant(tag: &str) -> Grant {
    Grant::new(format!("share:{tag}"))
}

/// A grant whose payload claims an expiry long past, so the client's own
/// advisory check drops it while presenting nothing the server would refuse
/// anyway.
fn expired_grant() -> Grant {
    Grant::new("eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJleHAiOjEwMDB9.notation-a-signature")
}

const SQLITE_DDL: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT NOT NULL); \
         CREATE VIEW visible AS SELECT * FROM notes \
         WHERE owner = current_app_user() \
            OR instr(',' || current_app_subjects() || ',', ',' || owner || ',') > 0;";

fn schema() -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "",
        "",
        SQLITE_DDL,
        Vec::<(String, String)>::new(),
        vec!["visible".to_owned()],
        None::<&str>,
    ))
}

diesel::table! {
    /// The rows the view filters on the caller's subject set.
    notes (id) {
        /// Row identifier.
        id -> Integer,
        /// The subject the row belongs to.
        owner -> Text,
    }
}

diesel::table! {
    /// The policy view, readable only for the caller's own and shared rows.
    visible (id) {
        /// Row identifier.
        id -> Integer,
        /// The subject the row belongs to.
        owner -> Text,
    }
}

/// A refresh-token store that shares its records through every clone and
/// refuses every access while a refusal stands, so a test inspects the same
/// records the build reads and writes.
#[derive(Clone, Default)]
struct SharedStore {
    inner: Arc<Mutex<SharedStoreState>>,
    changed: Arc<tokio::sync::Notify>,
}

#[derive(Default)]
struct SharedStoreState {
    records: HashMap<String, String>,
    refusal: Option<&'static str>,
}

impl SharedStore {
    /// The raw record under `name`, if the store holds one.
    fn record(&self, name: &str) -> Option<String> {
        self.inner
            .lock()
            .expect("the store lock is not poisoned")
            .records
            .get(name)
            .cloned()
    }

    /// Refuse every load and store with `reason`.
    fn set_refusal(&self, reason: &'static str) {
        self.inner
            .lock()
            .expect("the store lock is not poisoned")
            .refusal = Some(reason);
    }

    /// Lift the refusal.
    fn lift_refusal(&self) {
        self.inner
            .lock()
            .expect("the store lock is not poisoned")
            .refusal = None;
    }

    fn refused(state: &SharedStoreState) -> Option<String> {
        state.refusal.map(str::to_owned)
    }
}

impl RefreshTokenStore for SharedStore {
    type Error = connetto_client::ClientError;

    fn load<'a>(
        &'a self,
        account: &'a str,
    ) -> RefreshFuture<'a, Option<String>, connetto_client::ClientError> {
        Box::pin(async move {
            let state = self.inner.lock().expect("the store lock is not poisoned");
            match Self::refused(&state) {
                Some(reason) => Err(connetto_client::ClientError::Auth(reason)),
                None => Ok(state.records.get(account).cloned()),
            }
        })
    }

    fn store<'a>(
        &'a self,
        account: &'a str,
        token: &'a str,
    ) -> RefreshFuture<'a, (), connetto_client::ClientError> {
        Box::pin(async move {
            let mut state = self.inner.lock().expect("the store lock is not poisoned");
            if let Some(reason) = Self::refused(&state) {
                return Err(connetto_client::ClientError::Auth(reason));
            }
            state.records.insert(account.to_owned(), token.to_owned());
            self.changed.notify_one();
            Ok(())
        })
    }

    fn clear<'a>(
        &'a self,
        account: &'a str,
    ) -> RefreshFuture<'a, (), connetto_client::ClientError> {
        Box::pin(async move {
            let mut state = self.inner.lock().expect("the store lock is not poisoned");
            if let Some(reason) = Self::refused(&state) {
                return Err(connetto_client::ClientError::Auth(reason));
            }
            state.records.remove(account);
            Ok(())
        })
    }

    fn accounts(&self) -> RefreshFuture<'_, Vec<String>, connetto_client::ClientError> {
        Box::pin(std::future::ready(Ok(self
            .inner
            .lock()
            .expect("the store lock is not poisoned")
            .records
            .keys()
            .filter(|name| !is_reserved_record(name) && !is_share_key_record(name))
            .cloned()
            .collect())))
    }

    /// No user-verified gate reaches the records, so the claim states it.
    fn protection(&self) -> Custody {
        Custody::Unverified(NoGate::Unsupported)
    }
}

/// A share-key store over the same shared records that claims `Ephemeral`
/// custody, the strongest weakness, so a test can see the claim fold into
/// the build.
#[derive(Clone, Default)]
struct EphemeralShareKeys(SharedStore);

impl ShareKeyStore for EphemeralShareKeys {
    type Error = connetto_client::ClientError;

    fn load<'a>(
        &'a self,
        record: &'a str,
    ) -> ShareKeyFuture<'a, Option<ShareKeySet>, connetto_client::ClientError> {
        ShareKeyStore::load(&self.0, record)
    }

    fn save<'a>(
        &'a self,
        record: &'a str,
        set: &'a ShareKeySet,
    ) -> ShareKeyFuture<'a, (), connetto_client::ClientError> {
        ShareKeyStore::save(&self.0, record, set)
    }

    fn clear<'a>(
        &'a self,
        record: &'a str,
    ) -> ShareKeyFuture<'a, (), connetto_client::ClientError> {
        ShareKeyStore::clear(&self.0, record)
    }

    fn protection(&self) -> Custody {
        Custody::Ephemeral
    }
}

/// The replica name a held credential for `user` takes.
fn replica_name(user: &str) -> String {
    replica_db_name(REPLICA_PREFIX, user).expect("a string identity serializes")
}

/// The seed every visibility test reads back, one row per subject.
fn seed(conn: &mut ConnettoConnection<FakeTransport>) {
    diesel::insert_into(notes::table)
        .values([
            (notes::id.eq(1), notes::owner.eq("a1")),
            (notes::id.eq(2), notes::owner.eq("s1")),
        ])
        .execute(conn.conn())
        .expect("seed the rows");
}

/// The ids the policy view shows the caller at its current subject set.
fn visible_ids(conn: &mut ConnettoConnection<FakeTransport>) -> Vec<i32> {
    visible::table
        .select(visible::id)
        .order(visible::id)
        .load(conn.conn())
        .expect("read the policy rows")
}

/// A durable driven build over a held credential, the replica key pre-seeded
/// under the credential's name and the share-key store named beside it.
async fn durable_build(
    user: &str,
    dir: &Path,
    keys: super::support::SharedKeys,
    share: SharedStore,
    builder_keys: Vec<(Grant, CapabilitySubject<String>)>,
) -> Result<ConnettoConnection<FakeTransport>, connetto_client::ClientError> {
    let credential = super::support::held(user);
    ClientBuilder::new(
        schema(),
        super::support::Once::new(FakeTransport::accepting()),
    )
    .with_share_keys(builder_keys)
    .signed_in(credential)
    .durable(DataDir::new(dir.to_path_buf()), keys, share)
    .connect_driven()
    .await
}

/// Seed the replica key store with the suite's key under the credential's name.
async fn seeded_keys(user: &str) -> super::support::SharedKeys {
    let keys = super::support::SharedKeys::default();
    keys.store(&replica_name(user), &replica_key())
        .await
        .expect("seed the replica key");
    keys
}

/// The share-key record a build for `user` reads and writes.
fn share_record(user: &str) -> String {
    share_key_record(&replica_name(user))
}

/// Write `set` into the store's record for `user`, the way a prior run left it.
async fn stored_set(user: &str, share: &SharedStore, set: &ShareKeySet) {
    share
        .store(
            &share_record(user),
            &serde_json::to_string(set).expect("the set serializes"),
        )
        .await
        .expect("seed the stored set");
}

/// The set the store holds for `user`, decoded back through the wire shape.
fn held_set(user: &str, share: &SharedStore) -> Option<ShareKeySet> {
    let raw = share.record(&share_record(user))?;
    Some(serde_json::from_str(&raw).expect("the stored set deserializes"))
}

#[tokio::test]
async fn a_durable_restart_presents_the_stored_share_key() {
    let dir = tempfile::tempdir().expect("a directory");
    let keys = seeded_keys("alice").await;
    let share = SharedStore::default();

    {
        let mut conn = durable_build(
            "alice",
            dir.path(),
            keys.clone(),
            share.clone(),
            vec![(grant("first"), CapabilitySubject::<String>::new("a1"))],
        )
        .await
        .expect("the build connects");
        seed(&mut conn);
        assert_eq!(visible_ids(&mut conn), vec![1]);
    }

    // The builder names no key on the restart, so the stored pair is the
    // whole set and the replica still shows what it held before.
    let mut conn = durable_build("alice", dir.path(), keys, share.clone(), Vec::new())
        .await
        .expect("the restart connects");
    assert_eq!(visible_ids(&mut conn), vec![1]);
    let held = held_set("alice", &share).expect("the build persisted the set");
    let expected = ShareKeySet::new(vec![(
        grant("first"),
        CapabilitySubject::<String>::new("a1"),
    )]);
    assert_eq!(held, expected, "the stored set is the builder's, unchanged");
}

#[tokio::test]
async fn runtime_additions_and_removals_survive_durable_restarts() {
    let dir = tempfile::tempdir().expect("a directory");
    let keys = seeded_keys("alice").await;
    let share = SharedStore::default();
    let subject = CapabilitySubject::<String>::new("a1");
    let mut conn = durable_build("alice", dir.path(), keys.clone(), share.clone(), Vec::new())
        .await
        .expect("open the empty set");
    seed(&mut conn);
    assert_eq!(visible_ids(&mut conn), Vec::<i32>::new());
    conn.add_share_key(&grant("runtime"), &subject)
        .await
        .expect("add a share key");
    assert_eq!(visible_ids(&mut conn), vec![1]);
    drop(conn);

    let mut conn = durable_build("alice", dir.path(), keys.clone(), share.clone(), Vec::new())
        .await
        .expect("restart after the addition");
    assert_eq!(visible_ids(&mut conn), vec![1]);
    conn.remove_share_key(&subject)
        .await
        .expect("remove the stored key");
    assert_eq!(visible_ids(&mut conn), Vec::<i32>::new());
    drop(conn);

    let mut conn = durable_build("alice", dir.path(), keys, share.clone(), Vec::new())
        .await
        .expect("restart after the removal");
    assert_eq!(visible_ids(&mut conn), Vec::<i32>::new());
    assert_eq!(
        held_set("alice", &share),
        Some(ShareKeySet::new::<String>([]))
    );
}

#[tokio::test]
async fn builder_and_stored_pairs_form_one_set() {
    let dir = tempfile::tempdir().expect("a directory");
    let keys = seeded_keys("alice").await;
    let share = SharedStore::default();
    stored_set(
        "alice",
        &share,
        &ShareKeySet::new(vec![(
            grant("stored"),
            CapabilitySubject::<String>::new("s1"),
        )]),
    )
    .await;

    let mut conn = durable_build(
        "alice",
        dir.path(),
        keys,
        share.clone(),
        vec![(grant("builder"), CapabilitySubject::<String>::new("a1"))],
    )
    .await
    .expect("the build connects");
    seed(&mut conn);
    // The caller sees both the stored subject's row and the builder's.
    assert_eq!(visible_ids(&mut conn), vec![1, 2]);

    let held = held_set("alice", &share).expect("the build persisted the set");
    let expected = ShareKeySet::new(vec![
        (grant("builder"), CapabilitySubject::<String>::new("a1")),
        (grant("stored"), CapabilitySubject::<String>::new("s1")),
    ]);
    assert_eq!(
        held, expected,
        "the persisted set is the union, both pairs exactly as held"
    );
}

#[tokio::test]
async fn expired_grants_are_dropped_before_the_set_is_held() {
    let dir = tempfile::tempdir().expect("a directory");
    let keys = seeded_keys("alice").await;
    let share = SharedStore::default();
    stored_set(
        "alice",
        &share,
        &ShareKeySet::new(vec![
            (expired_grant(), CapabilitySubject::<String>::new("s1")),
            (grant("live"), CapabilitySubject::<String>::new("a1")),
        ]),
    )
    .await;

    // The stored expired pair is dropped, and the builder's expired pair is
    // never presented either.
    let mut conn = durable_build(
        "alice",
        dir.path(),
        keys,
        share.clone(),
        vec![(expired_grant(), CapabilitySubject::<String>::new("s1"))],
    )
    .await
    .expect("the build connects");
    seed(&mut conn);
    assert_eq!(
        visible_ids(&mut conn),
        vec![1],
        "only the live grant's subject is visible"
    );

    let held = held_set("alice", &share).expect("the build persisted the set");
    let expected = ShareKeySet::new(vec![(
        grant("live"),
        CapabilitySubject::<String>::new("a1"),
    )]);
    assert_eq!(
        held, expected,
        "the persisted set drops the expired pairs and writes the rest back"
    );
}

#[tokio::test]
async fn a_store_refusal_fails_the_durable_build() {
    let dir = tempfile::tempdir().expect("a directory");
    let keys = seeded_keys("alice").await;
    let share = SharedStore::default();
    share.set_refusal("the secret store is unavailable");

    let result = durable_build("alice", dir.path(), keys.clone(), share.clone(), Vec::new()).await;
    match result {
        Err(connetto_client::ClientError::Auth(reason)) => {
            assert!(
                reason.contains("the secret store is unavailable"),
                "the store's refusal names the store: {reason}"
            );
        }
        Err(other) => panic!("unexpected build error {other}"),
        Ok(_) => panic!("a refusing store must fail construction"),
    }

    share.lift_refusal();
    durable_build("alice", dir.path(), keys, share, Vec::new())
        .await
        .expect("a healthy store builds again");
}

#[tokio::test]
async fn share_keys_are_isolated_per_identity() {
    let alice_dir = tempfile::tempdir().expect("a directory");
    let bob_dir = tempfile::tempdir().expect("a directory");
    let share = SharedStore::default();

    {
        let mut conn = durable_build(
            "alice",
            alice_dir.path(),
            seeded_keys("alice").await,
            share.clone(),
            vec![(grant("alice"), CapabilitySubject::<String>::new("a1"))],
        )
        .await
        .expect("alice connects");
        seed(&mut conn);
        assert_eq!(visible_ids(&mut conn), vec![1]);
    }

    // Bob signs into the same store with no builder keys. Alice's pair must
    // not reach him, and his store holds no record of her subject.
    let mut conn = durable_build(
        "bob",
        bob_dir.path(),
        seeded_keys("bob").await,
        share.clone(),
        Vec::new(),
    )
    .await
    .expect("bob connects");
    seed(&mut conn);
    assert!(
        visible_ids(&mut conn).is_empty(),
        "bob sees none of alice's rows"
    );
    assert_eq!(
        held_set("alice", &share),
        Some(ShareKeySet::new([(
            grant("alice"),
            CapabilitySubject::<String>::new("a1"),
        )])),
    );
}

#[tokio::test]
async fn the_share_store_claim_folds_into_the_reported_custody() {
    let dir = tempfile::tempdir().expect("a directory");
    let credential = super::support::held("alice");
    let keys = super::support::SharedKeys::default();
    keys.store(credential.replica_name(), &replica_key())
        .await
        .expect("seed the replica key");

    let (client, pump) = ClientBuilder::new(
        schema(),
        super::support::Once::new(FakeTransport::accepting()),
    )
    .signed_in(credential)
    .durable(
        DataDir::new(dir.path().to_path_buf()),
        keys,
        EphemeralShareKeys::default(),
    )
    .connect_with_pump()
    .await
    .expect("the build connects");
    drop(pump);
    assert_eq!(
        client.custody(),
        Custody::Ephemeral,
        "the share store's weaker claim wins over the key store's"
    );
}

#[cfg(feature = "native-auth")]
#[tokio::test]
async fn forget_removes_the_share_key_record() {
    let dir = tempfile::tempdir().expect("a directory");
    let credential = super::support::held("alice");
    let keys = super::support::key_store(&credential).await;
    let share = SharedStore::default();
    stored_set(
        "alice",
        &share,
        &ShareKeySet::new(vec![(
            grant("first"),
            CapabilitySubject::<String>::new("a1"),
        )]),
    )
    .await;

    #[expect(
        clippy::large_futures,
        reason = "The startup future is awaited directly without an extra heap allocation."
    )]
    let client = NativeClientBuilder::new("ws://127.0.0.1:9/", schema())
        .signed_in(credential)
        .durable(dir.path().to_path_buf(), keys, share.clone())
        .connect()
        .await
        .expect("the build connects");
    client
        .forget_device(false)
        .await
        .expect("the device is forgotten");

    assert!(
        share.record(&share_record("alice")).is_none(),
        "the share key record goes with the forget"
    );
}

#[tokio::test]
async fn the_share_key_record_is_never_offered_as_an_account() {
    let share = connetto_client::MemoryRefreshStore::default();
    share
        .store("alice", "refresh-token")
        .await
        .expect("store an account");
    let record = share_record("alice");
    let set = ShareKeySet::new([(grant("first"), CapabilitySubject::<String>::new("a1"))]);
    ShareKeyStore::save(&share, &record, &set)
        .await
        .expect("save share keys");
    assert_eq!(
        share.accounts().await.expect("list accounts"),
        vec!["alice"]
    );
}

#[tokio::test]
async fn a_locked_expiry_defers_its_secret_write_until_unlock() {
    use connetto_client::{ClientEvent, ConnettoClient};
    use std::time::{Duration, SystemTime};

    let dir = tempfile::tempdir().expect("replica directory");
    let keys = seeded_keys("alice").await;
    let share = SharedStore::default();
    let subject = CapabilitySubject::<String>::new("a1");
    let authority =
        connetto_server::TokenAuthority::generate(&connetto_server::AuthConfig::default())
            .expect("token authority");
    let token = authority
        .mint_capability(&subject, SystemTime::now(), Duration::from_secs(3))
        .expect("short-lived key");
    let mut conn = durable_build(
        "alice",
        dir.path(),
        keys,
        share.clone(),
        vec![(Grant::new(token), subject)],
    )
    .await
    .expect("open durable replica");
    seed(&mut conn);
    conn.disconnect();
    let wait = conn.share_key_timer().expect("expiry timer").wait();
    let previous = share.record(&share_record("alice")).expect("stored key");
    let (client, pump) = ConnettoClient::with_pump(conn);
    let mut query: connetto_client::LiveQuery<i32> = client
        .watch(visible::table.select(visible::id).order(visible::id))
        .await
        .expect("watch policy rows");
    assert_eq!(query.rows(), vec![1]);
    let gate = Arc::new(super::share_keys::TestGate::default());
    let mut events = client.events();
    client.enable_gate(None, gate.clone()).await;
    share.set_refusal("locked secret store");
    let pump = tokio::spawn(pump);
    tokio::time::sleep(wait + Duration::from_millis(20)).await;
    assert_eq!(share.record(&share_record("alice")), Some(previous));

    share.lift_refusal();
    gate.approve();
    client.unlock().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                events.recv().await.expect("gate event"),
                ClientEvent::Unlocked
            ) {
                break;
            }
        }
        loop {
            if held_set("alice", &share) == Some(ShareKeySet::new::<String>([])) {
                break;
            }
            share.changed.notified().await;
        }
        while !query.rows().is_empty() {
            query
                .changed()
                .await
                .expect("expiry becomes visible after unlock");
        }
    })
    .await
    .expect("unlock persists the expiry");
    tokio::time::timeout(Duration::from_secs(5), client.close())
        .await
        .expect("close");
    tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("pump exits")
        .expect("no panic");
}
