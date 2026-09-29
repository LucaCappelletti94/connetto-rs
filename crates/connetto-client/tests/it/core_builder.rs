//! R94 decision 24: the platform-neutral builder over a scripted transport.
//!
//! An in-memory replica over a loopback pair: `connect_driven` hands back the
//! connected, unstarted connection the test pumps through the handshake and a
//! snapshot, and `connect_with_pump` hands back a running client whose live
//! query delivers the same row the snapshot carries.

use std::time::Duration;

use connetto_client::{
    ClientBuilder, ClientEvent, Grant, LiveQuery, ReconnectPolicy, SyncSchema, SyncStatus,
    SyncTuning, TransportFactory,
};
use connetto_core::messages::{
    BulkMessage, ControlMessage, HandshakeAck, Pong, SnapshotBegin, SnapshotEnd, SnapshotPatch,
    SubscriptionPriority,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackTransport, SchemaBundle, loopback};
use diesel::prelude::*;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

const DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, label TEXT);";

diesel::table! {
    /// The one synced table these builds read back.
    orders (id) {
        /// Primary key.
        id -> BigInt,
        /// Payload the snapshot carries.
        label -> Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    label: String,
}

/// The translated bundle these builds present, one table and no policies.
fn bundle() -> SyncSchema {
    SyncSchema::new(SchemaBundle::new(
        "schema",
        "policies",
        DDL,
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        None::<&str>,
    ))
}

/// The refusal a one-shot dialer hands back after it has handed out its
/// transport.
#[derive(Debug, thiserror::Error)]
#[error("the one-shot dialer has no second transport")]
struct DialRefused;

/// A dialer that hands out exactly one transport, the one the test attached.
struct OneShot {
    transport: Option<LoopbackTransport>,
}

impl TransportFactory for OneShot {
    type Transport = LoopbackTransport;
    type Error = DialRefused;

    fn connect(&mut self) -> impl Future<Output = Result<LoopbackTransport, DialRefused>> + Send {
        std::future::ready(self.transport.take().ok_or(DialRefused))
    }
}

/// Compressed one-row patchset bytes for the wire table shape.
fn payload(id: i64) -> Vec<u8> {
    let insert =
        Insert::<_, String, Vec<u8>>::from(SimpleTable::new("orders", &["id", "label"], &[0]))
            .set(0, Value::Integer(id))
            .expect("set id")
            .set(1, Value::Text("seed".to_owned()))
            .expect("set label");
    let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new().insert(insert);
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress payload")
}

/// A server that answers the handshake, answers each subscription with a
/// one-row snapshot, and echoes the keepalives.
fn snapshot_server() -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await
        else {
            return;
        };
        server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "core".to_owned(),
                session_token: "core".to_owned(),
                resume_token: "core".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: None,
                initial_credits: 64,
                last_applied_seq: None,
            }))
            .await
            .expect("ack the handshake");
        while let Ok(Some(frame)) = server.recv().await {
            match frame {
                IncomingFrame::Control(ControlMessage::Subscribe(sub)) => {
                    server
                        .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                            sub_id: sub.sub_id.clone(),
                            priority: SubscriptionPriority::default(),
                        }))
                        .await
                        .expect("snapshot begin");
                    server
                        .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch {
                            sub_id: sub.sub_id.clone(),
                            patchset_zstd: payload(1),
                        }))
                        .await
                        .expect("snapshot patch");
                    server
                        .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
                            sub_id: sub.sub_id.clone(),
                            cursor: Cursor::new(vec![1]),
                        }))
                        .await
                        .expect("snapshot end");
                }
                IncomingFrame::Control(ControlMessage::Ping(ping)) => {
                    server
                        .send_control(ControlMessage::Pong(Pong { nonce: ping.nonce }))
                        .await
                        .expect("pong");
                }
                _ => {}
            }
        }
    });
    client_end
}

/// `connect_driven` returns a connection the test drives through the
/// handshake and a snapshot, and the snapshot's row lands in the replica.
#[tokio::test]
async fn connect_driven_returns_a_connection_the_test_can_pump() {
    let builder = ClientBuilder::new(
        bundle(),
        OneShot {
            transport: Some(snapshot_server()),
        },
    );
    let mut conn = builder.connect_driven().await.expect("connect driven");
    conn.subscribe("sub", "SELECT * FROM orders")
        .await
        .expect("subscribe");
    loop {
        match conn.pump_one().await.expect("pump") {
            ClientEvent::SnapshotEnd { .. } => break,
            ClientEvent::Closed => panic!("closed before the snapshot ended"),
            _ => {}
        }
    }
    let rows: Vec<(i64, String)> = orders::table
        .select((orders::id, orders::label))
        .load(conn.conn())
        .expect("read the replica");
    assert_eq!(
        rows,
        vec![(1, "seed".to_owned())],
        "the snapshot's row landed in the in-memory replica"
    );
}

/// `connect_with_pump` returns a running client whose live query delivers the
/// same row the scripted server's snapshot carries.
#[tokio::test]
async fn connect_with_pump_delivers_the_same_row_through_a_live_query() {
    let builder = ClientBuilder::new(
        bundle(),
        OneShot {
            transport: Some(snapshot_server()),
        },
    )
    .with_tuning(SyncTuning::default())
    .with_reconnect(ReconnectPolicy::default())
    .with_sleeper(|d| tokio::time::sleep(d));
    let (client, pump) = builder
        .connect_with_pump()
        .await
        .expect("connect with pump");
    tokio::spawn(pump);
    let mut live: LiveQuery<Order> = client
        .client()
        .watch_with_grace(orders::table.select(Order::as_select()), Duration::ZERO)
        .await
        .expect("watch");
    tokio::time::timeout(Duration::from_secs(5), live.changed())
        .await
        .expect("the snapshot refresh timed out")
        .expect("the pump is driving the connection");
    assert_eq!(
        live.rows(),
        vec![Order {
            id: 1,
            label: "seed".to_owned()
        }],
        "the live query answers from the snapshot's row"
    );
}

/// The login grant a held credential presents rides the handshake the
/// signed-in stage runs.
#[tokio::test]
async fn signed_in_stage_presents_the_held_credentials_grant() {
    let (mut server, client_end) = loopback();
    let presented = tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(handshake)))) =
            server.recv().await
        else {
            return None;
        };
        let grant = handshake.grants.into_iter().next();
        server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "core".to_owned(),
                session_token: "core".to_owned(),
                resume_token: "core".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: None,
                initial_credits: 64,
                last_applied_seq: None,
            }))
            .await
            .expect("ack the handshake");
        grant
    });
    let builder = ClientBuilder::new(
        bundle(),
        OneShot {
            transport: Some(client_end),
        },
    );
    let conn = builder
        .signed_in(
            connetto_client::HeldCredential::new(Grant::new("user:core"), "alice")
                .expect("a held credential"),
        )
        .connect_driven()
        .await
        .expect("connect driven");
    drop(conn);
    assert_eq!(
        presented.await.expect("the server task ran"),
        Some(Grant::new("user:core")),
        "the held credential's grant presented at the handshake"
    );
}

diesel::define_sql_function! {
    /// The caller function the signed-in build registers on the replica.
    fn current_app_user() -> diesel::sql_types::Text;
}

/// The caller function a held credential binds answers the id's `Display`
/// rendering, the value the server binds the caller as, and not the serde
/// form the id serializes to.
#[tokio::test]
async fn signed_in_build_answers_the_caller_function_with_the_display_identity() {
    let builder = ClientBuilder::new(
        bundle(),
        OneShot {
            transport: Some(snapshot_server()),
        },
    );
    let mut conn = builder
        .signed_in(
            connetto_client::HeldCredential::new(Grant::new("user:identity"), &"alice".to_owned())
                .expect("a held credential"),
        )
        .connect_driven()
        .await
        .expect("connect driven");
    let caller: String = diesel::select(current_app_user())
        .get_result(conn.conn())
        .expect("read the caller");
    assert_eq!(
        caller, "alice",
        "the replica answers the id's Display rendering, not its serde form"
    );
}

/// A key store that records every name it is asked for, so the test can name
/// the record the build chose.
#[cfg(feature = "native-transport")]
#[derive(Clone)]
struct RecordingKeyStore {
    names: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    keys: std::sync::Arc<
        std::sync::Mutex<std::collections::HashMap<String, connetto_core::ReplicaKey>>,
    >,
}

#[cfg(feature = "native-transport")]
impl RecordingKeyStore {
    fn new() -> Self {
        Self {
            names: std::sync::Arc::default(),
            keys: std::sync::Arc::default(),
        }
    }

    fn names(&self) -> Vec<String> {
        self.names.lock().expect("the names lock").clone()
    }

    fn key(&self, name: &str) -> Option<connetto_core::ReplicaKey> {
        self.keys.lock().expect("the keys lock").get(name).cloned()
    }
}

#[cfg(feature = "native-transport")]
#[expect(
    clippy::unused_async_trait_impl,
    reason = "the trait method is async and this body finishes without awaiting"
)]
impl connetto_core::traits::ReplicaKeyStore for RecordingKeyStore {
    type Error = connetto_client::ClientError;

    async fn load(&self, name: &str) -> Result<Option<connetto_core::ReplicaKey>, Self::Error> {
        self.names
            .lock()
            .expect("the names lock")
            .push(name.to_owned());
        Ok(self.keys.lock().expect("the keys lock").get(name).cloned())
    }

    async fn store(&self, name: &str, key: &connetto_core::ReplicaKey) -> Result<(), Self::Error> {
        self.names
            .lock()
            .expect("the names lock")
            .push(name.to_owned());
        self.keys
            .lock()
            .expect("the keys lock")
            .insert(name.to_owned(), key.clone());
        Ok(())
    }

    async fn clear(&self, name: &str) -> Result<(), Self::Error> {
        self.names
            .lock()
            .expect("the names lock")
            .push(name.to_owned());
        self.keys.lock().expect("the keys lock").remove(name);
        Ok(())
    }

    fn protection(&self) -> connetto_client::Custody {
        connetto_client::Custody::Unverified(connetto_client::NoGate::Unsupported)
    }
}

/// The durable replica a held credential builds asks its key record and its
/// file from the name the credential reports, the one derived from the id's
/// own serde encoding.
#[cfg(feature = "native-transport")]
#[tokio::test]
async fn signed_in_build_names_the_key_record_from_the_identity_itself() {
    let dir = tempfile::tempdir().expect("a data directory");
    let store = RecordingKeyStore::new();
    let credential =
        connetto_client::HeldCredential::new(Grant::new("user:durable"), &"alice".to_owned())
            .expect("a held credential");
    let expected = credential.replica_name().to_owned();
    let builder = ClientBuilder::new(
        bundle(),
        OneShot {
            transport: Some(snapshot_server()),
        },
    );
    let (client, pump) = builder
        .signed_in(credential)
        .durable(connetto_client::DataDir::new(dir.path()), store.clone())
        .connect_with_pump()
        .await
        .expect("connect durable");
    tokio::spawn(pump);
    drop(client);
    let names = store.names();
    assert!(
        !names.is_empty(),
        "the build asked the store for its replica key record"
    );
    assert!(
        names.iter().all(|name| name == &expected),
        "every key record access rides the name the credential reports"
    );
    assert!(
        dir.path().join(&expected).exists(),
        "the replica file takes the same name as the key record"
    );
}

/// A dialer that refuses the first dial and accepts the second, so the
/// terminal's first dial fails and the pump's recovery dials again.
struct SecondDial {
    first: bool,
    transport: Option<LoopbackTransport>,
}

impl TransportFactory for SecondDial {
    type Transport = LoopbackTransport;
    type Error = DialRefused;

    fn connect(&mut self) -> impl Future<Output = Result<LoopbackTransport, DialRefused>> + Send {
        let out = if self.first {
            self.first = false;
            Err(DialRefused)
        } else {
            self.transport.take().ok_or(DialRefused)
        };
        std::future::ready(out)
    }
}

/// The first dial is refused, but `connect_with_pump` still succeeds. The
/// terminal opens the replica before it dials, local reads answer offline,
/// and the pump's recovery dials a second time and reports `Connected`.
#[tokio::test]
async fn offline_first_connect_succeeds_when_the_first_dial_is_refused() {
    let builder = ClientBuilder::new(
        bundle(),
        SecondDial {
            first: true,
            transport: Some(snapshot_server()),
        },
    )
    .with_reconnect(ReconnectPolicy::default());
    let (client, pump) = builder
        .connect_with_pump()
        .await
        .expect("connect with pump, offline");
    let rows: Vec<i64> = client
        .client()
        .with_conn(|c| {
            orders::table
                .select(orders::id)
                .load(c.conn())
                .expect("local read")
        })
        .await
        .expect("with conn");
    assert!(
        rows.is_empty(),
        "the fresh replica is empty until the snapshot"
    );
    let mut events = client.client().events();
    tokio::spawn(pump);
    let up = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let Ok(event) = events.recv().await else {
                break false;
            };
            if matches!(event, ClientEvent::Closed) {
                break false;
            }
            if matches!(event, ClientEvent::SyncStatus(SyncStatus::Connected)) {
                break true;
            }
        }
    })
    .await
    .expect("the recovery timed out");
    assert!(up, "the pump recovered and reported the connection up");
}

/// `open_driven` returns the offline, unstarted connection, and no dial happens
/// and local reads answer, and a transport attached by hand brings it up.
#[tokio::test]
async fn open_driven_returns_an_offline_connection_a_test_attaches_by_hand() {
    let builder = ClientBuilder::new(bundle(), OneShot { transport: None });
    let mut conn = builder.open_driven().expect("open driven, no dial");
    assert!(
        !conn.is_connected(),
        "open_driven starts offline, nothing dialed"
    );
    let rows: Vec<i64> = orders::table
        .select(orders::id)
        .load(conn.conn())
        .expect("local read, offline");
    assert!(rows.is_empty(), "the fresh replica is empty");
    conn.attach(snapshot_server())
        .await
        .expect("attach by hand");
    assert!(conn.is_connected(), "the hand-attached transport connects");
}

/// A server that answers the handshake and then drops its end of the
/// transport, so the pump sees the connection go away.
fn closing_server() -> LoopbackTransport {
    let (mut server, client_end) = loopback();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await
        else {
            return;
        };
        server
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "closed".to_owned(),
                session_token: "closed".to_owned(),
                resume_token: "closed".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: None,
                initial_credits: 64,
                last_applied_seq: None,
            }))
            .await
            .expect("ack the handshake");
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(server);
    });
    client_end
}

/// A policy that refuses to retry ends the pump with `Closed` the first time
/// the transport goes away, rather than dialing again.
#[tokio::test]
async fn zero_attempt_policy_ends_the_pump_with_closed() {
    let builder = ClientBuilder::new(
        bundle(),
        OneShot {
            transport: Some(closing_server()),
        },
    )
    .with_tuning(SyncTuning::default())
    .with_reconnect(ReconnectPolicy::default().with_max_attempts(Some(0)))
    .with_sleeper(|d| tokio::time::sleep(d));
    let (client, pump) = builder
        .connect_with_pump()
        .await
        .expect("connect with pump");
    let mut events = client.client().events();
    tokio::spawn(pump);
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Ok(ClientEvent::Closed) => break true,
                Ok(_) => {}
                Err(_) => break false,
            }
        }
    })
    .await
    .expect("the pump did not close in time");
    assert!(closed, "a zero-attempt policy ends the pump with Closed");
}

/// The replica's presence, which only the platform knows, decides between
/// creating a replica and opening one. A key that outlived its file opens a
/// fresh replica under the same key, and a file whose key is gone is refused
/// rather than opened under a new one.
#[cfg(feature = "native-transport")]
#[tokio::test]
async fn a_durable_build_takes_freshness_from_the_file_and_never_rekeys() {
    let dir = tempfile::tempdir().expect("a data directory");
    let store = RecordingKeyStore::new();
    let credential =
        connetto_client::HeldCredential::new(Grant::new("user:fresh"), &"fresh".to_owned())
            .expect("a held credential");
    let name = credential.replica_name().to_owned();
    let open = |store: RecordingKeyStore| {
        ClientBuilder::new(bundle(), OneShot { transport: None })
            .signed_in(credential.clone())
            .durable(connetto_client::DataDir::new(dir.path()), store)
            .open_driven()
    };

    drop(
        open(store.clone())
            .await
            .expect("the first run creates the replica"),
    );
    let key = store.key(&name).expect("the first run stored a key");
    assert!(
        dir.path().join(&name).exists(),
        "the first run wrote the file"
    );

    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.path().join(format!("{name}{suffix}")));
    }
    drop(
        open(store.clone())
            .await
            .expect("a kept key with no file opens a fresh replica"),
    );
    assert_eq!(
        store.key(&name).expect("the key is still stored"),
        key,
        "a fresh replica under a kept key keeps that key"
    );

    let emptied = RecordingKeyStore::new();
    assert!(
        matches!(
            open(emptied).await,
            Err(connetto_client::ClientError::ReplicaKeyMissing)
        ),
        "an existing file whose key is gone is refused, never re-keyed"
    );
}

/// A translated schema calls the caller and subjects functions from its views
/// whether or not anyone signed in or holds a key, so a build registers both
/// and each answers as nobody does.
#[test]
fn an_anonymous_build_answers_the_caller_and_subjects_functions_as_nobody() {
    let ddl = "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT); \
               CREATE VIEW visible AS SELECT * FROM notes \
               WHERE owner = current_app_user() OR owner = current_app_subjects();";
    let schema = SyncSchema::new(SchemaBundle::new(
        "schema",
        "policies",
        ddl,
        Vec::<(String, String)>::new(),
        vec!["visible".to_owned()],
        None::<&str>,
    ));
    let mut conn = ClientBuilder::new(schema, OneShot { transport: None })
        .open_driven()
        .expect("a schema whose views call both functions opens anonymous");
    let subjects: Option<String> = diesel::select(diesel::dsl::sql::<
        diesel::sql_types::Nullable<diesel::sql_types::Text>,
    >("current_app_subjects()"))
    .get_result(conn.conn())
    .expect("the subjects function is registered");
    assert_eq!(subjects, None, "a caller holding no key answers NULL");
}
