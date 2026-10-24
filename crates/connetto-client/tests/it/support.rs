//! Shared helpers for the R94 builder migration.
//!
//! Every construction site in this suite builds through the client builders.
//! These helpers carry the pieces the sites share, so a test reads as the
//! build it is. The schema is a translated bundle, the identity is a held
//! credential, the durable key lives in a store, and the transport is a
//! dialer the builder owns.

use std::pin::Pin;

use connetto_client::{
    ClientError, Custody, Grant, HeldCredential, MemoryKeyStore, NoGate, SyncSchema,
    TransportFactory,
};
use connetto_core::ReplicaKey;
use connetto_core::messages::ControlMessage;
use connetto_core::schema::SchemaBundle;
use connetto_core::traits::{IncomingFrame, MaybeSend, ReplicaKeyStore, Transport};
use connetto_server::openfga::{GrantMove, StoreUpkeep, UpkeepError};

/// Authorization metadata for static policies that do not depend on share keys.
pub struct KeyIndependentUpkeep;

impl StoreUpkeep for KeyIndependentUpkeep {
    fn keep_current<'a>(
        &'a self,
        _event: &'a subql::PgChangeEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<GrantMove>, UpkeepError>> + Send + 'a>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn key_tables(&self) -> &[String] {
        &[]
    }
}

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

/// One row of the durable pending queue, read raw because `_connetto_pending`
/// is an internal table the typed schema does not name.
#[derive(diesel::QueryableByName)]
struct PendingRow {
    #[diesel(sql_type = diesel::sql_types::Binary)]
    changeset: Vec<u8>,
}

/// The tables a captured changeset names, read from the durable pending record.
///
/// # Panics
///
/// When the record is absent or does not parse as a changeset.
#[must_use]
pub fn captured_tables(replica: &mut diesel::SqliteConnection, seq: u64) -> Vec<String> {
    use diesel::RunQueryDsl as _;
    use sqlite_diff_rs::ParsedDiffSet;

    // The test sequence is a small counter, so it fits the pending i64 column.
    let seq: i64 = i64::try_from(seq).expect("a test sequence fits an i64");
    let row: PendingRow =
        diesel::sql_query("SELECT changeset FROM _connetto_pending WHERE seq = ?")
            .bind::<diesel::sql_types::BigInt, _>(seq)
            .get_result(replica)
            .expect("the pending record is durable");
    let ParsedDiffSet::Changeset(set) =
        ParsedDiffSet::parse(&row.changeset).expect("a captured changeset parses")
    else {
        panic!("the captured record is not a changeset");
    };
    set.iter().map(|op| op.table().name().to_owned()).collect()
}

/// A scripted server or relay that records every control frame the client
/// sends and serves the frames a test queues, idling while none are queued.
#[derive(Clone, Default)]
pub struct Script {
    frames: std::sync::Arc<parking_lot::Mutex<std::collections::VecDeque<IncomingFrame>>>,
    sent: std::sync::Arc<parking_lot::Mutex<Vec<ControlMessage>>>,
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// The scripted socket after a close.
#[derive(Debug, thiserror::Error)]
pub enum Gone {
    #[error("the scripted socket is gone")]
    Closed,
}

impl Script {
    /// Queue `frame` for the client's next receive.
    pub fn say(&self, frame: IncomingFrame) {
        self.frames.lock().push_back(frame);
    }

    /// Drop the wire from the script's side, as a lost socket does.
    pub fn hang_up(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether either side closed the wire.
    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The sent control frames `pick` selects, in the order they were sent.
    pub fn sent<T>(&self, pick: impl FnMut(&ControlMessage) -> Option<T>) -> Vec<T> {
        self.sent.lock().iter().filter_map(pick).collect()
    }

    /// The share-key replacements the client sent.
    pub fn replacements(&self) -> Vec<connetto_core::messages::ReplaceShareKeys> {
        self.sent(|message| match message {
            ControlMessage::ReplaceShareKeys(replacement) => Some(replacement.clone()),
            _ => None,
        })
    }
}

impl Transport for Script {
    type Error = Gone;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        self.sent.lock().push(message);
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            std::future::ready(Err(Gone::Closed))
        } else {
            std::future::ready(Ok(()))
        }
    }

    fn send_bulk(
        &mut self,
        _message: connetto_core::messages::BulkMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        std::future::ready(Ok(()))
    }

    fn recv(&mut self) -> impl Future<Output = Result<Option<IncomingFrame>, Self::Error>> {
        let frames = std::sync::Arc::clone(&self.frames);
        let closed = std::sync::Arc::clone(&self.closed);
        async move {
            loop {
                if closed.load(std::sync::atomic::Ordering::Acquire) {
                    return Ok(None);
                }
                if let Some(frame) = frames.lock().pop_front() {
                    return Ok(Some(frame));
                }
                tokio::task::yield_now().await;
            }
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        std::future::ready(Ok(()))
    }
}

/// The handshake answer a scripted server gives, granting writer number 1.
pub fn handshake_ack() -> IncomingFrame {
    IncomingFrame::Control(ControlMessage::HandshakeAck(
        connetto_core::messages::HandshakeAck {
            connection_id: "script".to_owned(),
            session_token: "script".to_owned(),
            resume_token: "script".to_owned(),
            current_cursor: connetto_core::Cursor::from(Vec::new()),
            schema_version: None,
            initial_credits: 64,
            writer: Some(connetto_core::messages::WriterGrant {
                number: 1,
                frontier: 0,
            }),
        },
    ))
}

/// One `notes` table behind a `visible` view showing the caller's rows and the
/// rows of every share-key subject it holds.
pub fn key_gated_notes() -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "",
        "",
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT NOT NULL); \
         CREATE VIEW visible AS SELECT * FROM notes \
         WHERE owner = current_app_user() \
            OR instr(',' || current_app_subjects() || ',', ',' || owner || ',') > 0;",
        Vec::<(String, String)>::new(),
        vec!["visible".to_owned()],
        None::<&str>,
    ))
}
