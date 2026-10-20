//! Docker-gated acceptance tests for the per-writer applied frontier (R75).
//!
//! Each test drives raw frames through the harness `Client` against the real
//! Postgres write target and walks one row of the server state table. The
//! number writer's handshakes refuse what it does not hold and confirm what
//! it does. The device bind proves the key against the connection's
//! challenge. `settled_through` prunes the rows at and below the report, and
//! a pruned record answers applied by sequence alone. The provenance rows
//! settle the copy with the original's standing. `RetireWriter` retires the
//! account's writers and closes the connections bound to them. The audit
//! names every fork and every cross-path redelivery. The Done-when proofs
//! hold for both writer kinds. A settled entry is never applied twice
//! through another path, and a forged second changeset at an applied
//! `(writer, sequence)` is refused `Forked`.
//!
//! Needs Docker: the fixture starts its own Postgres.

#![expect(
    clippy::too_many_lines,
    reason = "each test walks its state-table row in order and a split would hide the sequence"
)]

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use connetto_core::PROTOCOL_VERSION;
use connetto_core::SessionId;
use connetto_core::auth::Principal;
use connetto_core::chain::{GENESIS, entry_hash};
use connetto_core::device_cert::{AttestationLevel, KeyId};
use connetto_core::messages::{
    BindDevice, ConflictRow, ControlMessage, FatalError, FatalErrorReason, Grant, Handshake,
    MutationRejectReason, Provenance, WriterGrant, WriterOutcome, WriterRef, WriterRequest,
    writer_bind_message,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport as _};
use connetto_server::audit::{AuditHook, AuthEvent, AuthOp};
use connetto_server::defaults::{_connetto_settled, _connetto_writers};
use connetto_server::device_cert::{
    DeviceCertConfig, DeviceEnrolment, Enrolment, EnrolmentStore, MemoryEnrolments,
};
use connetto_server::writer_schema::SettlePath;
use connetto_server::{
    AbuseConfig, ManagerBuilder, Materializer, NoConnector, PageSpec, RequestGuard,
    RuntimeWritableCatalog, SessionConfig, SessionManager, SnapshotEstimate, SnapshotPage,
    SnapshotSource, ThrottleConfig, loopback, pg_write_target,
};
use connetto_test_harness::{Client, ConnettoDefaults, Fixture, RosterAuth, WITHHELD_ID};
use diesel::{ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use parking_lot::Mutex;
use rcgen::{KeyPair, PublicKeyData as _, SigningKey as _};
use sqlite_diff_rs::{ChangeSet, ChangesetFormat, DiffOps, Insert, SimpleTable, Update, Value};

/// The notes table these tests sync.
const PG_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT, edited_at TEXT);";

/// The handshake authority every test manager takes.
fn test_verifier() -> std::sync::Arc<dyn connetto_core::HandshakeAuthority> {
    std::sync::Arc::new(TestGrantChecker)
}

/// No subscriptions are made in these tests, so the snapshot source is never
/// invoked.
struct NoSnapshot;

impl SnapshotSource for NoSnapshot {
    type Error = Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        Ok(SnapshotEstimate {
            rows: 0.0,
            width: 0,
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn snapshot_page(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        Ok(SnapshotPage {
            patchset: Vec::new(),
            cursor: connetto_core::Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: 0,
            rows: 0,
            bytes: 0,
        })
    }
}

diesel::table! {
    /// Row from the notes test fixture.
    notes (id) {
        /// Note identifier, the primary key.
        id -> diesel::sql_types::Integer,
        /// Note text.
        body -> diesel::sql_types::Text,
        /// Timestamp of the last edit.
        edited_at -> diesel::sql_types::Text,
    }
}

#[derive(diesel::Queryable, diesel::Selectable, Debug, PartialEq)]
#[diesel(table_name = notes)]
#[diesel(check_for_backend(diesel::pg::Pg))]
struct Note {
    id: i32,
    body: String,
    edited_at: String,
}

fn note(id: i32, body: &str, edited_at: &str) -> Note {
    Note {
        id,
        body: body.to_owned(),
        edited_at: edited_at.to_owned(),
    }
}

/// The `notes` rows, read through the admin pool.
async fn notes(pool: &Pool<AsyncPgConnection>) -> Vec<Note> {
    let mut conn = pool.get().await.expect("admin connection");
    notes::table
        .order(notes::id)
        .select(Note::as_select())
        .load(&mut *conn)
        .await
        .expect("read notes")
}

/// Reset the fixture to a fresh `notes` table seeded with one versioned row
/// and the writer tables provisioned by the admin.
async fn seed_notes(fixture: &Fixture) {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS notes CASCADE",
            "DROP TABLE IF EXISTS _connetto_settled",
            "DROP TABLE IF EXISTS _connetto_writers",
            "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT, edited_at TEXT)",
        ])
        .await;
    connetto_test_harness::provision_writers(fixture.admin()).await;
    let mut conn = fixture.admin().get().await.expect("admin connection");
    diesel::insert_into(notes::table)
        .values((
            notes::id.eq(1_i32),
            notes::body.eq("hello"),
            notes::edited_at.eq("t0"),
        ))
        .execute(&mut *conn)
        .await
        .expect("seed row");
}

fn writable_catalog() -> RuntimeWritableCatalog {
    RuntimeWritableCatalog::builder()
        .versioned("notes", "edited_at")
        .build()
}

fn note_table() -> SimpleTable {
    SimpleTable::new("notes", &["id", "body", "edited_at"], &[0])
}

/// A changeset that inserts one full row.
fn insert_changeset(id: i64, body: &str, edited_at: &str) -> Vec<u8> {
    let insert = Insert::<_, String, Vec<u8>>::from(note_table())
        .set(0, Value::Integer(id))
        .expect("set id")
        .set(1, Value::Text(body.to_owned()))
        .expect("set body")
        .set(2, Value::Text(edited_at.to_owned()))
        .expect("set edited_at");
    ChangeSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(insert)
        .build()
}

/// The writer's frontier, head and retirement state, read as admin.
struct WriterFacts {
    frontier: i64,
    head: Option<Vec<u8>>,
    retired: bool,
}

async fn writer_facts(pool: &Pool<AsyncPgConnection>, writer: i64) -> WriterFacts {
    let mut conn = pool.get().await.expect("admin connection");
    let (frontier, head, retired) = _connetto_writers::table
        .filter(_connetto_writers::writer.eq(writer))
        .select((
            _connetto_writers::frontier,
            _connetto_writers::head,
            _connetto_writers::retired_at.is_not_null(),
        ))
        .get_result::<(i64, Option<Vec<u8>>, bool)>(&mut *conn)
        .await
        .expect("read the writer row");
    WriterFacts {
        frontier,
        head,
        retired,
    }
}

/// The writer number a device key bound to.
async fn writer_for_key(pool: &Pool<AsyncPgConnection>, key_id: [u8; 32]) -> i64 {
    let mut conn = pool.get().await.expect("admin connection");
    _connetto_writers::table
        .filter(_connetto_writers::device_key.eq(key_id.to_vec()))
        .select(_connetto_writers::writer)
        .get_result(&mut *conn)
        .await
        .expect("read the device writer")
}

/// One settled entry, read as admin, ordered by sequence.
struct SettledFacts {
    seq: i64,
    entry_hash: Vec<u8>,
    outcome: String,
    path: SettlePath,
}

async fn settled_rows(pool: &Pool<AsyncPgConnection>, writer: i64) -> Vec<SettledFacts> {
    let mut conn = pool.get().await.expect("admin connection");
    _connetto_settled::table
        .filter(_connetto_settled::writer.eq(writer))
        .select((
            _connetto_settled::seq,
            _connetto_settled::entry_hash,
            _connetto_settled::outcome,
            _connetto_settled::path,
        ))
        .order(_connetto_settled::seq.asc())
        .load::<(i64, Vec<u8>, String, SettlePath)>(&mut *conn)
        .await
        .expect("read the settled rows")
        .into_iter()
        .map(|(seq, entry_hash, outcome, path)| SettledFacts {
            seq,
            entry_hash,
            outcome,
            path,
        })
        .collect()
}

/// Collects the audit events the guard emits, in order.
#[derive(Default)]
struct Captured(Arc<Mutex<Vec<AuthEvent<String>>>>);

impl Captured {
    /// A fresh sink with its audit hook.
    fn new() -> (Self, AuditHook<String>) {
        let captured = Self::default();
        let sink = Arc::clone(&captured.0);
        let hook = Arc::new(move |event| sink.lock().push(event));
        (captured, hook)
    }

    /// The writer-state events, `write_forked` and `write_redelivered`.
    fn write_events(&self) -> Vec<AuthEvent<String>> {
        self.0
            .lock()
            .iter()
            .filter(|event| matches!(event.op, AuthOp::WriteForked | AuthOp::WriteRedelivered))
            .cloned()
            .collect()
    }
}

/// The device key enrolments the test installs on the manager, in memory.
struct Enrolments {
    store: Arc<MemoryEnrolments<String>>,
}

impl Enrolments {
    /// An empty store, fresh per test.
    fn new() -> Self {
        Self {
            store: Arc::new(MemoryEnrolments::default()),
        }
    }

    /// Enrol `user`'s fresh key with a certificate that stands until
    /// `expires_at`, and hand back the key and its id.
    async fn enrol(&self, user: &str, expires_at: SystemTime) -> (Signer, [u8; 32]) {
        let key = device_key();
        let key_id = *KeyId::of_public_key(&key.subject_public_key_info()).as_bytes();
        let record = Enrolment {
            user: user.to_owned(),
            key: KeyId::from_bytes(key_id),
            serial: [7; 16],
            issuer: KeyId::from_bytes([9; 32]),
            issued_at: SystemTime::now(),
            expires_at,
            session: SessionId::from_uuid(uuid::Uuid::new_v4()),
            public_key: key.subject_public_key_info().clone(),
            descriptor: vec![0x91, 0x01],
            attestation: AttestationLevel::Unproven,
        };
        self.store
            .record(record)
            .await
            .expect("record the certificate");
        (Signer(key), key_id)
    }

    /// Enrol `user` under the fixed key `key_id`, with the public key as
    /// stored, for the cases where the stored public key is not the key that
    /// signs.
    async fn enrol_with(
        &self,
        user: &str,
        key_id: [u8; 32],
        public_key: Vec<u8>,
        expires_at: SystemTime,
    ) -> KeyId {
        let key = KeyId::from_bytes(key_id);
        let record = Enrolment {
            user: user.to_owned(),
            key,
            serial: [7; 16],
            issuer: KeyId::from_bytes([9; 32]),
            issued_at: SystemTime::now(),
            expires_at,
            session: SessionId::from_uuid(uuid::Uuid::new_v4()),
            public_key,
            descriptor: vec![0x91, 0x01],
            attestation: AttestationLevel::Unproven,
        };
        self.store
            .record(record)
            .await
            .expect("record the certificate");
        key
    }

    /// Revoke `key_id` whoever enrolled it, as an operator would.
    fn revoke(&self, key_id: [u8; 32]) {
        self.store.revoke_key(KeyId::from_bytes(key_id));
    }

    /// The enrolment the manager takes, over this store and a fresh issuer.
    fn installable(&self) -> DeviceEnrolment<String> {
        let (_, _, issuer) = rooted_issuer();
        let store = Arc::clone(&self.store);
        let store: Arc<dyn EnrolmentStore<String>> = store;
        DeviceEnrolment::new(DeviceCertConfig::new(issuer), store)
    }
}

/// The device key the test signs as, wrapped so its bind signatures are one
/// call.
struct Signer(KeyPair);

impl Signer {
    /// The ECDSA P-256 SHA-256 signature over the connection's bind message.
    fn signature(&self, nonce: &[u8; 32]) -> Vec<u8> {
        self.0
            .sign(&writer_bind_message(nonce))
            .expect("sign the bind message")
            .clone()
    }
}

/// The enrolment test helpers shared by every suite in this crate.
use super::enrolment::{device_key, rooted_issuer};

fn writing_manager(
    pool: &Pool<AsyncPgConnection>,
    guard: Arc<RequestGuard<String>>,
    enrolment: Option<DeviceEnrolment<String>>,
    session: SessionConfig,
) -> Arc<SessionManager<NoSnapshot, RosterAuth, ConnettoDefaults>> {
    let manager = ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .with_write_catalog(writable_catalog())
            .build()
            .expect("build materializer"),
        NoSnapshot,
        RosterAuth::granting("alice")
            .and("bob")
            .and_the_unnamed_caller()
            .withholding(WITHHELD_ID),
        test_verifier(),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(pool.clone(), PG_DDL).expect("build write target"),
    )
    .with_session(session)
    .with_guard(guard)
    .build();
    if let Some(enrolment) = enrolment
        && manager
            .install_device_enrolment(Arc::new(enrolment))
            .is_err()
    {
        panic!("the enrolment installs once");
    }
    manager
}

/// A one-connection write pool whose checkout gives up quickly, so a test
/// holding its connection is an unreachable database.
async fn single_connection_pool(fixture: &Fixture) -> Pool<AsyncPgConnection> {
    Pool::builder()
        .max_size(1)
        // Opened at build, so the 100 ms checkout bounds only the outage and never the first connect.
        .min_idle(1)
        .connection_timeout(Duration::from_millis(100))
        .build(AsyncDieselConnectionManager::new(fixture.admin_url()))
        .await
        .expect("build the write pool")
}

/// The durable-apply acknowledgement of `client_seq`.
async fn expect_applied(client: &mut Client, client_seq: u64) {
    let ControlMessage::MutationApplied(applied) = client.next_control().await else {
        panic!("expected write {client_seq} to apply");
    };
    assert_eq!(applied.client_seq, client_seq);
}

/// The `Indeterminate` refusal of `client_seq`.
async fn expect_indeterminate(client: &mut Client, client_seq: u64) {
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected write {client_seq} to be refused");
    };
    assert_eq!(
        (reject.client_seq, reject.reason),
        (client_seq, MutationRejectReason::Indeterminate)
    );
}

/// A refused handshake over the raw transport. The challenge leads, the
/// fatal follows, and the reason is handed back.
async fn refused_handshake(
    manager: &Arc<SessionManager<NoSnapshot, RosterAuth, ConnettoDefaults>>,
    client_id: &str,
    grant: &str,
    writer: WriterRequest,
    settled_through: Option<u64>,
) -> FatalError {
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut handshake = Handshake::new(PROTOCOL_VERSION, client_id)
        .with_grant(Grant::new(grant))
        .with_writer(writer);
    if let Some(seq) = settled_through {
        handshake = handshake.with_settled_through(seq);
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    let frame = client.recv().await.expect("recv the challenge");
    let Some(IncomingFrame::Control(ControlMessage::Challenge(_))) = frame else {
        panic!("the server leads every connection with a challenge, got {frame:?}");
    };
    let frame = client.recv().await.expect("recv the refusal");
    let Some(IncomingFrame::Control(ControlMessage::FatalError(fatal))) = frame else {
        panic!("the refused handshake must close the connection, got {frame:?}");
    };
    client.close().await.expect("close the client");
    let _ = server.await.expect("join the server task");
    fatal
}

/// A number the account does not hold refuses the handshake as unknown and
/// creates no writer row, never confirming the number exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_number_at_the_handshake_closes_writer_unknown() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    let fatal = refused_handshake(
        &manager,
        "probe",
        "user:alice",
        WriterRequest::Number(987_654_321),
        None,
    )
    .await;
    assert!(
        matches!(fatal.reason, FatalErrorReason::WriterUnknown),
        "an unknown number must close as WriterUnknown, got {:?}",
        fatal.reason
    );
    let mut conn = fixture.admin().get().await.expect("admin connection");
    let count: i64 = _connetto_writers::table
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count the writers");
    assert_eq!(count, 0, "the refusal must not create a writer");
}

/// The retirement of a number writer closes the handshake that names it
/// with `WriterRetired`, keeps the settled record, and a second retirement
/// reports the standing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retired_number_at_the_handshake_closes_writer_retired() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    // The number settles one entry.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("retired-1", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // The importer retires the archived writer, twice.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("retired-2", "user:alice").await;
    let answer = client.retire_writer("r1", WriterRef::Number(number)).await;
    assert_eq!(answer.outcome, WriterOutcome::Retired);
    let again = client.retire_writer("r2", WriterRef::Number(number)).await;
    assert_eq!(
        again.outcome,
        WriterOutcome::Retired,
        "the second names the standing"
    );
    let facts = writer_facts(fixture.admin(), i64::try_from(number).expect("number fits")).await;
    assert!(facts.retired, "the row is retired");
    assert_eq!(facts.frontier, 1, "retirement keeps the settled record");
    client.close().await;
    server.await.expect("join 2").expect("session ok");

    // A new handshake naming the number is refused.
    let fatal = refused_handshake(
        &manager,
        "retired-3",
        "user:alice",
        WriterRequest::Number(number),
        None,
    )
    .await;
    assert!(
        matches!(fatal.reason, FatalErrorReason::WriterRetired),
        "the retired number must close as WriterRetired, got {:?}",
        fatal.reason
    );
}

/// A number of another account refuses the handshake as unknown, the same
/// way the account's own missing number does, and the owner's record stands
/// untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_foreign_accounts_number_at_the_handshake_closes_writer_unknown() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    // alice settles one entry under her number.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("foreign-1", "user:alice").await;
    let alice_number = ack.writer.expect("the handshake issues a number").number;
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // bob names alice's number.
    let fatal = refused_handshake(
        &manager,
        "foreign-2",
        "user:bob",
        WriterRequest::Number(alice_number),
        None,
    )
    .await;
    assert!(
        matches!(fatal.reason, FatalErrorReason::WriterUnknown),
        "another account's number must close as unknown, got {:?}",
        fatal.reason
    );
    let facts = writer_facts(
        fixture.admin(),
        i64::try_from(alice_number).expect("number fits"),
    )
    .await;
    assert_eq!(facts.frontier, 1, "the owner's record stands");
    assert!(!facts.retired, "the foreign handshake retired nothing");
}

/// The good bind stands the device's writer at frontier 0 and writes take
/// its sequences. The key rebinds at its frontier, replays its settled
/// entries from the record without re-applying, and takes the next
/// sequence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_good_bind_binds_a_live_enrolment_and_rebinds_at_its_frontier() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let device = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // Connection 1: the device handshake takes no number grant, and the
    // good signature binds at frontier 0.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, ack) = client
        .handshake_challenge_writing("bind-1", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    assert!(
        ack.writer.is_none(),
        "a device request takes no number grant"
    );
    let answer = client
        .bind_device("b1", device.1, device.0.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    client.upload(2, insert_changeset(3, "three", "t2")).await;
    expect_applied(&mut client, 2).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // Connection 2: the same key rebinds at its frontier.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, ack) = client
        .handshake_challenge_writing("bind-2", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    assert!(ack.writer.is_none(), "the rebind takes no number grant");
    let answer = client
        .bind_device("b2", device.1, device.0.signature(&challenge.nonce))
        .await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::Bound { frontier: 2 },
        "the rebind answers the standing frontier"
    );
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    client.upload(2, insert_changeset(3, "three", "t2")).await;
    expect_applied(&mut client, 2).await;
    client.upload(3, insert_changeset(4, "four", "t3")).await;
    expect_applied(&mut client, 3).await;
    let ControlMessage::Pong(_) = client.barrier(1).await else {
        panic!("expected the pong after the writes");
    };
    assert_eq!(
        notes(fixture.admin()).await,
        vec![
            note(1, "hello", "t0"),
            note(2, "two", "t1"),
            note(3, "three", "t2"),
            note(4, "four", "t3"),
        ],
        "the replay applied nothing new"
    );
    client.close().await;
    server.await.expect("join 2").expect("session ok");

    // The record holds the three entries direct, the row stands live.
    let writer = writer_for_key(fixture.admin(), device.1).await;
    let rows = settled_rows(fixture.admin(), writer).await;
    assert_eq!(
        rows.iter()
            .map(|row| (row.seq, row.path))
            .collect::<Vec<_>>(),
        vec![
            (1, SettlePath::Direct),
            (2, SettlePath::Direct),
            (3, SettlePath::Direct),
        ]
    );
    let hash_3 = entry_hash(
        &entry_hash(
            &entry_hash(&GENESIS, 1, &insert_changeset(2, "two", "t1")),
            2,
            &insert_changeset(3, "three", "t2"),
        ),
        3,
        &insert_changeset(4, "four", "t3"),
    );
    assert_eq!(
        writer_facts(fixture.admin(), writer).await.head,
        Some(hash_3.to_vec()),
        "the head holds the frontier entry's chain hash"
    );
    let facts = writer_facts(fixture.admin(), writer).await;
    assert_eq!(facts.frontier, 3);
    assert!(!facts.retired);
}

/// A signature over anything but this connection's challenge message
/// answers `NotEnrolled` and stands no writer row. The connection's own
/// nonce still binds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_with_a_bad_signature_is_not_enrolled() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let device = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing("bad-1", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    let wrong_nonce = [0xAB; 32];
    let answer = client
        .bind_device("b1", device.1, device.0.signature(&wrong_nonce))
        .await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::NotEnrolled,
        "the signature names the connection, so a foreign nonce fails here"
    );
    let mut conn = fixture.admin().get().await.expect("admin connection");
    let count: i64 = _connetto_writers::table
        .filter(_connetto_writers::device_key.eq(device.1.to_vec()))
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count the writers");
    assert_eq!(count, 0, "the refused bind stands no row");

    // The connection's own nonce still binds.
    let answer = client
        .bind_device("b2", device.1, device.0.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// A key no enrolment records answers `NotEnrolled` and stands no writer row.
/// A revoked enrolment instead closes the connection with `DeviceRevoked`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_without_a_live_enrolment_is_not_enrolled() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing("none-1", &["user:alice"], None, WriterRequest::Device, None)
        .await;

    // A key the store never recorded.
    let stranger = Signer(device_key());
    let stranger_id = *KeyId::of_public_key(&stranger.0.subject_public_key_info()).as_bytes();
    let answer = client
        .bind_device("b1", stranger_id, stranger.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::NotEnrolled);

    let mut conn = fixture.admin().get().await.expect("admin connection");
    let count: i64 = _connetto_writers::table
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count the writers");
    assert_eq!(count, 0, "no refused bind stands a row");
    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// The bind of a retired writer answers `Retired` rather than binding, and
/// no write stands under the unbound connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_of_a_retired_writer_is_retired() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let device = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // The key binds once, then the importer retires it.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing("retb-1", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    let answer = client
        .bind_device("b1", device.1, device.0.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("retb-2", "user:alice").await;
    let answer = client
        .retire_writer("r1", WriterRef::Device(device.1))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Retired);
    client.close().await;
    server.await.expect("join 2").expect("session ok");

    // A new connection's bind is told the standing, and its write cannot
    // stand under an unbound writer.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing("retb-3", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    let answer = client
        .bind_device("b2", device.1, device.0.signature(&challenge.nonce))
        .await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::Retired,
        "the retired row binds nothing"
    );
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    let ControlMessage::FatalError(fatal) = client.next_control().await else {
        panic!("a write under a refused bind must close the connection");
    };
    assert!(
        matches!(fatal.reason, FatalErrorReason::ProtocolViolation { .. }),
        "the write dies as a protocol violation, got {:?}",
        fatal.reason
    );
    client.close().await;
    let _ = server.await.expect("join 3");
}

/// A device revoked while away learns of it at its bind, the way a connected
/// device learns when the revocation lands: the connection closes with
/// `DeviceRevoked`, and the bind stands no writer row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_of_a_revoked_key_closes_device_revoked() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let device = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // The revocation lands while the device is away.
    store.revoke(device.1);

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "rev-1")
                .with_grant(Grant::new("user:alice"))
                .with_writer(WriterRequest::Device),
        ))
        .await
        .expect("send the handshake");
    let frame = client.recv().await.expect("recv the challenge");
    let Some(IncomingFrame::Control(ControlMessage::Challenge(challenge))) = frame else {
        panic!("the server leads every connection with a challenge, got {frame:?}");
    };
    let frame = client.recv().await.expect("recv the ack");
    let Some(IncomingFrame::Control(ControlMessage::HandshakeAck(ack))) = frame else {
        panic!("the handshake must be acknowledged, got {frame:?}");
    };
    assert!(
        ack.writer.is_none(),
        "a device request takes no number grant"
    );
    client
        .send_control(ControlMessage::BindDevice(BindDevice {
            request_id: "b1".into(),
            key_id: device.1,
            signature: device.0.signature(&challenge.nonce),
        }))
        .await
        .expect("send the bind");
    // The revocation lists, pushed after the handshake, may reach the
    // connection before the fatal the revoked bind sends.
    loop {
        let frame = client.recv().await.expect("recv the next frame");
        match frame {
            Some(IncomingFrame::Control(ControlMessage::FatalError(fatal))) => {
                assert_eq!(
                    fatal.reason,
                    FatalErrorReason::DeviceRevoked,
                    "the device must learn of its revocation, got {fatal:?}"
                );
                break;
            }
            Some(IncomingFrame::Control(ControlMessage::WriterAnswer(answer))) => {
                panic!("a revoked bind must close the connection, got {answer:?}")
            }
            Some(_) => {}
            None => panic!("the connection closed before the revoked bind answered"),
        }
    }
    let mut conn = fixture.admin().get().await.expect("admin connection");
    let count: i64 = _connetto_writers::table
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count the writers");
    assert_eq!(count, 0, "the revoked bind stands no writer row");
    client.close().await.expect("close the client");
    let _ = server.await.expect("join the server task");
}

/// The reconnect's `settled_through` prunes the number writer's rows at and
/// below the report, and a redelivery of a pruned sequence is answered
/// applied by sequence alone, applying nothing twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn settled_through_prunes_the_rows_and_the_pruned_record_answers_by_sequence() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    // alice settles three entries under her number.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("prune-1", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    client.upload(2, insert_changeset(3, "three", "t2")).await;
    expect_applied(&mut client, 2).await;
    client.upload(3, insert_changeset(4, "four", "t3")).await;
    expect_applied(&mut client, 3).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // The reconnect reports the frontier, pruning the rows at and below it.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client
        .handshake_writing(
            "prune-2",
            &["user:alice"],
            None,
            WriterRequest::Number(number),
            Some(3),
        )
        .await;
    assert_eq!(
        ack.writer,
        Some(WriterGrant {
            number,
            frontier: 3
        }),
        "the confirmation carries the pruned frontier"
    );
    let writer = i64::try_from(number).expect("number fits");
    assert!(
        settled_rows(fixture.admin(), writer).await.is_empty(),
        "the rows at and below the report are pruned"
    );

    // A redelivery of a pruned sequence is answered applied by sequence.
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    assert_eq!(
        notes(fixture.admin()).await,
        vec![
            note(1, "hello", "t0"),
            note(2, "two", "t1"),
            note(3, "three", "t2"),
            note(4, "four", "t3"),
        ],
        "the pruned record applied nothing twice"
    );
    assert_eq!(writer_facts(fixture.admin(), writer).await.frontier, 3);
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

/// An `Indeterminate` answer settles nothing. The retry while the outage
/// stands is answered the same way, and the recovered database settles the
/// sequence once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_indeterminate_answer_settles_nothing_and_the_retry_settles_once() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let pool = single_connection_pool(&fixture).await;
    let manager = writing_manager(
        &pool,
        guard,
        None,
        SessionConfig::default().with_write_retry_budget(Duration::ZERO),
    );
    let _ = captured;

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("indet-1", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;

    let outage = pool.get_owned().await.expect("hold the only connection");
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_indeterminate(&mut client, 1).await;
    let writer = i64::try_from(number).expect("number fits");
    assert!(
        settled_rows(fixture.admin(), writer).await.is_empty(),
        "nothing settles under an Indeterminate"
    );
    assert_eq!(
        writer_facts(fixture.admin(), writer).await.frontier,
        0,
        "the frontier stands where the Indeterminate left it"
    );

    // The retry while the outage stands is answered the same way.
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_indeterminate(&mut client, 1).await;
    drop(outage);

    // The recovered database settles the sequence once.
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    let rows = settled_rows(fixture.admin(), writer).await;
    assert_eq!(rows.len(), 1, "the recovered write settled one row");
    assert_eq!(rows[0].seq, 1);
    assert_eq!(rows[0].path, SettlePath::Direct);
    assert_eq!(rows[0].outcome, "\"applied\"");
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the entry applied once"
    );
    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// A different changeset at a settled sequence is refused `Forked` and
/// audited `write_forked`. The standing entry keeps its record, and the
/// forged one never applies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_changeset_at_a_settled_sequence_is_refused_forked_and_audited() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());

    // alice settles one entry under her number.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("fork-1", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;
    let cs1 = insert_changeset(2, "two", "t1");
    client.upload(1, cs1.clone()).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // The reconnect forges a different changeset at the settled sequence.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client
        .handshake_writing(
            "fork-2",
            &["user:alice"],
            None,
            WriterRequest::Number(number),
            None,
        )
        .await;
    client.upload(1, insert_changeset(5, "forged", "t9")).await;
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected the fork refusal");
    };
    assert_eq!(reject.client_seq, 1);
    assert_eq!(reject.reason, MutationRejectReason::Forked);

    // The audit names the writer, the sequence and the two paths.
    let events = captured.write_events();
    assert_eq!(events.len(), 1, "the fork audits once");
    let event = &events[0];
    assert_eq!(event.op, AuthOp::WriteForked);
    assert_eq!(event.user_id.as_deref(), Some("alice"));
    assert_eq!(
        event.writer,
        Some(i64::try_from(number).expect("number fits"))
    );
    assert_eq!(event.seq, Some(1));
    assert_eq!(event.path, Some(SettlePath::Direct));
    assert_eq!(event.other_path, Some(SettlePath::Direct));

    // The standing entry kept its record, and the forged one never applied.
    let writer = i64::try_from(number).expect("number fits");
    let rows = settled_rows(fixture.admin(), writer).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].entry_hash,
        entry_hash(&GENESIS, 1, &cs1).to_vec(),
        "the record stands the original entry"
    );
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the forged changeset never applied"
    );
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

/// A provenance write of an original the account already settled settles
/// the new sequence with the original's stored outcome, applied and
/// refused alike, and audits nothing when both paths are direct.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provenance_write_of_a_settled_original_settles_the_new_sequence_with_the_stored_outcome()
{
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());

    // alice's number A settles an applied entry and a refused one.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("prov-1", "user:alice").await;
    let a = ack.writer.expect("the handshake issues a number").number;
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    client
        .upload(2, insert_changeset(WITHHELD_ID, "withheld", "tw"))
        .await;
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected the refusal of the withheld-row write");
    };
    assert_eq!(reject.reason, MutationRejectReason::Unauthorized);
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // alice's fresh number B settles each copy with the original's stored
    // outcome.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("prov-2", "user:alice").await;
    let b = ack.writer.expect("the handshake issues a number").number;
    assert_ne!(b, a, "B is a fresh number");
    client
        .upload_with_provenance(
            1,
            insert_changeset(2, "two", "t1"),
            Some(Provenance {
                writer: WriterRef::Number(a),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 1).await;
    client
        .upload_with_provenance(
            2,
            insert_changeset(WITHHELD_ID, "withheld", "tw"),
            Some(Provenance {
                writer: WriterRef::Number(a),
                seq: 2,
            }),
        )
        .await;
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected the stored refusal to re-answer");
    };
    assert_eq!(reject.client_seq, 2);
    assert_eq!(reject.reason, MutationRejectReason::Unauthorized);

    // Both paths direct, so no redelivery audit.
    assert!(
        captured.write_events().is_empty(),
        "a same-path copy carries no audit"
    );

    // The copies settled with the stored outcomes under B.
    let rows_b = settled_rows(fixture.admin(), i64::try_from(b).expect("number fits")).await;
    assert_eq!(rows_b.len(), 2);
    assert_eq!(rows_b[0].seq, 1);
    assert_eq!(rows_b[0].outcome, "\"applied\"");
    assert_eq!(rows_b[0].path, SettlePath::Direct);
    assert_eq!(rows_b[1].seq, 2);
    assert!(
        rows_b[1].outcome.contains("rejected"),
        "the stored refusal stands"
    );

    // The original's record is untouched, and nothing applied twice.
    let rows_a = settled_rows(fixture.admin(), i64::try_from(a).expect("number fits")).await;
    assert_eq!(rows_a.len(), 2);
    assert_eq!(rows_a[0].path, SettlePath::Direct);
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the withheld row never landed"
    );
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

/// A provenance write whose original stands at the original writer's
/// frontier plus one applies under the session's caller and settles both
/// the original through restore and the copy direct.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provenance_write_at_the_originals_frontier_plus_one_applies_and_settles_both() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    // alice's fresh numbers A and B settle nothing.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("plus-1", "user:alice").await;
    let a = ack.writer.expect("the handshake issues a number").number;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("plus-2", "user:alice").await;
    let b = ack.writer.expect("the handshake issues a number").number;
    assert_ne!(b, a);

    // B's first write carries A's first entry.
    let cs1 = insert_changeset(2, "two", "t1");
    client
        .upload_with_provenance(
            1,
            cs1.clone(),
            Some(Provenance {
                writer: WriterRef::Number(a),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 2").expect("session ok");

    // The entry applied once, under the session's caller.
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")]
    );

    // Both sequences settled. The original through restore, the copy direct,
    // both with the same chain hash.
    let hash = entry_hash(&GENESIS, 1, &cs1);
    let rows_a = settled_rows(fixture.admin(), i64::try_from(a).expect("number fits")).await;
    assert_eq!(rows_a.len(), 1);
    assert_eq!(rows_a[0].seq, 1);
    assert_eq!(rows_a[0].path, SettlePath::Restore);
    assert_eq!(rows_a[0].entry_hash, hash.to_vec());
    let rows_b = settled_rows(fixture.admin(), i64::try_from(b).expect("number fits")).await;
    assert_eq!(rows_b.len(), 1);
    assert_eq!(rows_b[0].seq, 1);
    assert_eq!(rows_b[0].path, SettlePath::Direct);
    assert_eq!(rows_b[0].entry_hash, hash.to_vec());

    // Both frontiers advanced to the shared entry.
    let facts_a = writer_facts(fixture.admin(), i64::try_from(a).expect("number fits")).await;
    assert_eq!(facts_a.frontier, 1);
    assert_eq!(facts_a.head, Some(hash.to_vec()));
    let facts_b = writer_facts(fixture.admin(), i64::try_from(b).expect("number fits")).await;
    assert_eq!(facts_b.frontier, 1);
}

/// A provenance write whose original stands past the original writer's
/// frontier plus one closes the connection with `SequenceGap` and settles
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provenance_write_past_the_originals_frontier_closes_with_sequence_gap() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    // A settles one entry.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("gap-1", "user:alice").await;
    let a = ack.writer.expect("the handshake issues a number").number;
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // B names a sequence past A's frontier.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("gap-2", "user:alice").await;
    let b = ack.writer.expect("the handshake issues a number").number;
    client
        .upload_with_provenance(
            1,
            insert_changeset(3, "three", "t2"),
            Some(Provenance {
                writer: WriterRef::Number(a),
                seq: 3,
            }),
        )
        .await;
    let ControlMessage::FatalError(fatal) = client.next_control().await else {
        panic!("the past-frontier provenance must close the connection");
    };
    assert_eq!(
        fatal.reason,
        FatalErrorReason::SequenceGap {
            expected: 2,
            got: 3
        }
    );
    assert!(
        settled_rows(fixture.admin(), i64::try_from(b).expect("number fits"))
            .await
            .is_empty(),
        "the gap settles nothing for the copy"
    );
    assert_eq!(
        writer_facts(fixture.admin(), i64::try_from(a).expect("number fits"))
            .await
            .frontier,
        1,
        "the original's frontier stands"
    );
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "nothing new applied"
    );
    client.close().await;
    let _ = server.await.expect("join 2");
}

/// A provenance write naming a device key enrolled to the account that never
/// bound stands the key's writer row live at frontier 0, then settles the
/// entry as the frontier-plus-one row does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provenance_write_naming_an_enrolled_key_that_never_bound_stands_its_row_live() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let key = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // alice's number carries the entry under the never-bound key.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("never-1", "user:alice").await;
    let a = ack.writer.expect("the handshake issues a number").number;
    let cs1 = insert_changeset(2, "two", "t1");
    client
        .upload_with_provenance(
            1,
            cs1.clone(),
            Some(Provenance {
                writer: WriterRef::Device(key.1),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join server").expect("session ok");

    // The key's row stood live, not retired, at the settled frontier.
    let writer = writer_for_key(fixture.admin(), key.1).await;
    let facts = writer_facts(fixture.admin(), writer).await;
    assert!(!facts.retired, "the provenance stands the key's row live");
    assert_eq!(facts.frontier, 1);
    assert_eq!(facts.head, Some(entry_hash(&GENESIS, 1, &cs1).to_vec()));
    let rows = settled_rows(fixture.admin(), writer).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].path, SettlePath::Restore);
    // The copy settled direct under the number.
    let rows_a = settled_rows(fixture.admin(), i64::try_from(a).expect("number fits")).await;
    assert_eq!(rows_a.len(), 1);
    assert_eq!(rows_a[0].path, SettlePath::Direct);
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")]
    );
}

/// A provenance write naming no writer of the caller's account applies as a
/// plain write and never confirms the writer stands. Bob's number and bob's
/// bound device both stand untouched by alice's copies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provenance_write_naming_a_foreign_writer_applies_plainly() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let bob_key = store
        .enrol("bob", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // bob settles an entry under his number.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("foreign-1", "user:bob").await;
    let bob_number = ack.writer.expect("the handshake issues a number").number;
    client.upload(1, insert_changeset(2, "bob-two", "b1")).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // bob settles an entry under his device.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing(
            "foreign-2",
            &["user:bob"],
            None,
            WriterRequest::Device,
            None,
        )
        .await;
    let answer = client
        .bind_device("b1", bob_key.1, bob_key.0.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    client
        .upload(1, insert_changeset(3, "bob-three", "b2"))
        .await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 2").expect("session ok");

    // alice names bob's writers. Both copies apply plainly under her number.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("foreign-3", "user:alice").await;
    let alice_number = ack.writer.expect("the handshake issues a number").number;
    client
        .upload_with_provenance(
            1,
            insert_changeset(4, "alice-four", "a1"),
            Some(Provenance {
                writer: WriterRef::Number(bob_number),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 1).await;
    client
        .upload_with_provenance(
            2,
            insert_changeset(5, "alice-five", "a2"),
            Some(Provenance {
                writer: WriterRef::Device(bob_key.1),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 2).await;

    // The plain apply landed both rows.
    assert_eq!(
        notes(fixture.admin()).await,
        vec![
            note(1, "hello", "t0"),
            note(2, "bob-two", "b1"),
            note(3, "bob-three", "b2"),
            note(4, "alice-four", "a1"),
            note(5, "alice-five", "a2"),
        ]
    );

    // bob's records stand untouched.
    let bob_facts = writer_facts(
        fixture.admin(),
        i64::try_from(bob_number).expect("number fits"),
    )
    .await;
    assert_eq!(bob_facts.frontier, 1);
    let bob_writer = writer_for_key(fixture.admin(), bob_key.1).await;
    assert_eq!(writer_facts(fixture.admin(), bob_writer).await.frontier, 1);
    assert_eq!(
        settled_rows(fixture.admin(), bob_writer).await.len(),
        1,
        "alice's copy settled nothing of bob's key"
    );

    // alice's copies settled direct under her number.
    let rows_a = settled_rows(
        fixture.admin(),
        i64::try_from(alice_number).expect("number fits"),
    )
    .await;
    assert_eq!(rows_a.len(), 2);
    assert_eq!(rows_a[0].path, SettlePath::Direct);
    assert_eq!(rows_a[1].path, SettlePath::Direct);
    client.close().await;
    server.await.expect("join 3").expect("session ok");
}

/// The retirement of a bound device writer closes its live connection with
/// `WriterRetired`, and a second retirement reports the standing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retiring_a_bound_writer_closes_its_live_connection() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let device = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // A binds the key and holds the connection.
    let (server_transport, client) = loopback();
    let server_a = tokio::spawn(manager.clone().serve(server_transport));
    let mut client_a = Client::new(client);
    let (challenge, _) = client_a
        .handshake_challenge_writing(
            "retire-a",
            &["user:alice"],
            None,
            WriterRequest::Device,
            None,
        )
        .await;
    let answer = client_a
        .bind_device("b1", device.1, device.0.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });

    // B retires the writer.
    let (server_transport, client) = loopback();
    let server_b = tokio::spawn(manager.clone().serve(server_transport));
    let mut client_b = Client::new(client);
    // The same account on a second run, so its session handle does not
    // supersede the bound connection's.
    client_b
        .handshake_with("retire-b", "user:alice#retire")
        .await;
    let answer = client_b
        .retire_writer("r1", WriterRef::Device(device.1))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Retired);

    // A's live connection closes with the writer retired.
    let frame = client_a.recv().await;
    let Some(IncomingFrame::Control(ControlMessage::FatalError(fatal))) = frame else {
        panic!("the bound connection must learn of the retirement, got {frame:?}");
    };
    assert_eq!(fatal.reason, FatalErrorReason::WriterRetired);
    client_a.close().await;
    let _ = server_a.await.expect("join A");

    // A second retirement reports the standing, and the row stands retired.
    let again = client_b
        .retire_writer("r2", WriterRef::Device(device.1))
        .await;
    assert_eq!(again.outcome, WriterOutcome::Retired);
    let writer = writer_for_key(fixture.admin(), device.1).await;
    assert!(writer_facts(fixture.admin(), writer).await.retired);
    client_b.close().await;
    server_b.await.expect("join B").expect("session ok");
}

/// The retirement of a writer the account does not hold refuses as unknown
/// and changes nothing, a number and a key alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retiring_a_writer_the_account_does_not_hold_is_unknown() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // bob's number stands.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("unk-1", "user:bob").await;
    let bob_number = ack.writer.expect("the handshake issues a number").number;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // alice retires neither bob's number nor an unrecorded key.
    let stranger = device_key();
    let stranger_id = *KeyId::of_public_key(&stranger.subject_public_key_info()).as_bytes();
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("unk-2", "user:alice").await;
    let answer = client
        .retire_writer("r1", WriterRef::Number(bob_number))
        .await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::Unknown,
        "another account's number is not this account's writer"
    );
    let answer = client
        .retire_writer("r2", WriterRef::Device(stranger_id))
        .await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::Unknown,
        "no enrolment, no writer"
    );
    client.close().await;
    server.await.expect("join 2").expect("session ok");

    // bob's writer stands live, and no row stood for the stranger's key.
    assert!(
        !writer_facts(
            fixture.admin(),
            i64::try_from(bob_number).expect("number fits")
        )
        .await
        .retired
    );
    let mut conn = fixture.admin().get().await.expect("admin connection");
    let count: i64 = _connetto_writers::table
        .filter(_connetto_writers::device_key.eq(stranger_id.to_vec()))
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count the writers");
    assert_eq!(count, 0, "the refused retirement stands no row");
}

/// The retirement of a device key enrolled to the account that never bound
/// creates the key's writer row retired at frontier 0, and a later bind is
/// told the standing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retiring_an_enrolled_device_key_that_never_bound_creates_its_row_retired() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let device = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("never-2", "user:alice").await;
    let answer = client
        .retire_writer("r1", WriterRef::Device(device.1))
        .await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::Retired,
        "the enrolled key retires through its enrolment"
    );
    let writer = writer_for_key(fixture.admin(), device.1).await;
    let facts = writer_facts(fixture.admin(), writer).await;
    assert!(facts.retired, "the row stood retired");
    assert_eq!(
        facts.frontier, 0,
        "the retirement settles nothing of the key's"
    );
    assert!(settled_rows(fixture.admin(), writer).await.is_empty());
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // A bind of the retired key is told the standing.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing(
            "never-3",
            &["user:alice"],
            None,
            WriterRequest::Device,
            None,
        )
        .await;
    let answer = client
        .bind_device("b1", device.1, device.0.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Retired);
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

/// The same fork proof for a device writer. A different changeset at the
/// settled sequence is refused `Forked` and audited, and the standing entry
/// keeps its record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_changeset_at_a_device_sequence_is_refused_forked_and_audited() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let device = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );

    // The device settles one entry.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing("devf-1", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    let answer = client
        .bind_device("b1", device.1, device.0.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    let cs1 = insert_changeset(2, "two", "t1");
    client.upload(1, cs1.clone()).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // The same device forges a different changeset at the settled sequence.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing("devf-2", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    let answer = client
        .bind_device("b2", device.1, device.0.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 1 });
    client.upload(1, insert_changeset(5, "forged", "t9")).await;
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected the fork refusal");
    };
    assert_eq!(reject.client_seq, 1);
    assert_eq!(reject.reason, MutationRejectReason::Forked);

    // Audited, the standing entry untouched.
    let events = captured.write_events();
    assert_eq!(events.len(), 1, "the fork audits once");
    let event = &events[0];
    assert_eq!(event.op, AuthOp::WriteForked);
    assert_eq!(event.user_id.as_deref(), Some("alice"));
    let writer = writer_for_key(fixture.admin(), device.1).await;
    assert_eq!(event.writer, Some(writer));
    assert_eq!(event.seq, Some(1));
    assert_eq!(event.path, Some(SettlePath::Direct));
    assert_eq!(event.other_path, Some(SettlePath::Direct));
    let rows = settled_rows(fixture.admin(), writer).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].entry_hash, entry_hash(&GENESIS, 1, &cs1).to_vec());
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the forged changeset never applied"
    );
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

/// A number writer's restore then re-upload of the same entry. The copy
/// settles the original through restore, and the re-upload is answered from
/// the record and audited `write_redelivered`, the entry applying once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_then_reupload_is_answered_from_the_record_and_audited() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());

    // A and B stand fresh.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("rest-1", "user:alice").await;
    let a = ack.writer.expect("the handshake issues a number").number;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // B's import carries A's first entry.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("rest-2", "user:alice").await;
    let b = ack.writer.expect("the handshake issues a number").number;
    let cs1 = insert_changeset(2, "two", "t1");
    client
        .upload_with_provenance(
            1,
            cs1.clone(),
            Some(Provenance {
                writer: WriterRef::Number(a),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 1).await;
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")]
    );
    let writer_a = i64::try_from(a).expect("number fits");
    let rows_a = settled_rows(fixture.admin(), writer_a).await;
    assert_eq!(rows_a.len(), 1);
    assert_eq!(rows_a[0].seq, 1);
    assert_eq!(rows_a[0].path, SettlePath::Restore);
    let writer_b = i64::try_from(b).expect("number fits");
    let rows_b = settled_rows(fixture.admin(), writer_b).await;
    assert_eq!(rows_b.len(), 1);
    assert_eq!(rows_b[0].path, SettlePath::Direct);

    // B's queue still holds the entry and re-uploads it.
    client
        .upload_with_provenance(
            2,
            cs1,
            Some(Provenance {
                writer: WriterRef::Number(a),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 2).await;

    // Audited redelivered, the copy settled with the stored outcome, the
    // entry applied once.
    let events = captured.write_events();
    assert_eq!(events.len(), 1, "the cross-path redelivery audits once");
    let event = &events[0];
    assert_eq!(event.op, AuthOp::WriteRedelivered);
    assert_eq!(event.user_id.as_deref(), Some("alice"));
    assert_eq!(event.writer, Some(writer_b));
    assert_eq!(event.seq, Some(2));
    assert_eq!(event.path, Some(SettlePath::Direct));
    assert_eq!(event.other_path, Some(SettlePath::Restore));
    let rows_b = settled_rows(fixture.admin(), writer_b).await;
    assert_eq!(rows_b.len(), 2);
    assert_eq!(rows_b[1].seq, 2);
    assert_eq!(rows_b[1].outcome, "\"applied\"");
    assert_eq!(rows_b[1].path, SettlePath::Direct);
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the entry applied once"
    );
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

/// The same restore then re-upload proof for a device writer. The copy
/// settles the original key through restore while standing its row live,
/// and the re-upload is answered from the record and audited.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_restore_then_reupload_is_answered_from_the_record_and_audited() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let k = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let k2 = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );

    // K2's import carries K's first entry. K never bound, so the entry stood
    // unsettled.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing(
            "drest-1",
            &["user:alice"],
            None,
            WriterRequest::Device,
            None,
        )
        .await;
    let answer = client
        .bind_device("b1", k2.1, k2.0.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    let cs1 = insert_changeset(2, "two", "t1");
    client
        .upload_with_provenance(
            1,
            cs1.clone(),
            Some(Provenance {
                writer: WriterRef::Device(k.1),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 1).await;

    // K's record settled restore, K2's copy direct, the entry applied once.
    let writer_k = writer_for_key(fixture.admin(), k.1).await;
    let rows_k = settled_rows(fixture.admin(), writer_k).await;
    assert_eq!(rows_k.len(), 1);
    assert_eq!(rows_k[0].seq, 1);
    assert_eq!(rows_k[0].path, SettlePath::Restore);
    assert!(!writer_facts(fixture.admin(), writer_k).await.retired);
    let writer_k2 = writer_for_key(fixture.admin(), k2.1).await;
    let rows_k2 = settled_rows(fixture.admin(), writer_k2).await;
    assert_eq!(rows_k2.len(), 1);
    assert_eq!(rows_k2[0].path, SettlePath::Direct);
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")]
    );

    // K2's queue still holds the entry and re-uploads it.
    client
        .upload_with_provenance(
            2,
            cs1,
            Some(Provenance {
                writer: WriterRef::Device(k.1),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 2).await;

    // Audited redelivered, the entry applied once.
    let events = captured.write_events();
    assert_eq!(events.len(), 1, "the cross-path redelivery audits once");
    let event = &events[0];
    assert_eq!(event.op, AuthOp::WriteRedelivered);
    assert_eq!(event.user_id.as_deref(), Some("alice"));
    assert_eq!(event.writer, Some(writer_k2));
    assert_eq!(event.seq, Some(2));
    assert_eq!(event.path, Some(SettlePath::Direct));
    assert_eq!(event.other_path, Some(SettlePath::Restore));
    let rows_k2 = settled_rows(fixture.admin(), writer_k2).await;
    assert_eq!(rows_k2.len(), 2);
    assert_eq!(rows_k2[1].outcome, "\"applied\"");
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the entry applied once"
    );
    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// A table versioned on a primary key of text, real and bytea columns, so a
/// conflict re-read proves it binds every stored value kind.
const MULTI_DDL: &str = "CREATE TABLE multi \
    (key TEXT, weight REAL, tag BYTEA, body TEXT, edited_at TEXT, \
     PRIMARY KEY (key, weight, tag));";

diesel::table! {
    /// Row from the multi test fixture.
    multi (key, weight, tag) {
        /// Text key.
        key -> Text,
        /// Real key.
        weight -> Double,
        /// Bytea key.
        tag -> Bytea,
        /// Row body.
        body -> Text,
        /// Version column.
        edited_at -> Text,
    }
}

/// Seed `multi` with its one versioned row.
async fn seed_multi(fixture: &Fixture) {
    let mut conn = fixture.admin().get().await.expect("admin connection");
    diesel::insert_into(multi::table)
        .values((
            multi::key.eq("a"),
            multi::weight.eq(1.5_f64),
            multi::tag.eq(vec![0_u8, 1]),
            multi::body.eq("one"),
            multi::edited_at.eq("t0"),
        ))
        .execute(&mut *conn)
        .await
        .expect("seed row");
}

fn multi_table() -> SimpleTable {
    SimpleTable::new(
        "multi",
        &["key", "weight", "tag", "body", "edited_at"],
        &[0, 1, 2],
    )
}

/// An update of the seeded `multi` row whose old version value is stale, so it
/// conflicts against whatever stands.
fn multi_update_changeset(body: &str, edited_at: &str) -> Vec<u8> {
    let update = Update::<_, ChangesetFormat, String, Vec<u8>>::from(multi_table())
        .set(0, Value::Text("a".to_owned()), Value::Text("a".to_owned()))
        .expect("set key")
        .set(1, Value::Real(1.5), Value::Real(1.5))
        .expect("set weight")
        .set(2, Value::Blob(vec![0_u8, 1]), Value::Blob(vec![0_u8, 1]))
        .expect("set tag")
        .set(
            3,
            Value::Text("one".to_owned()),
            Value::Text(body.to_owned()),
        )
        .expect("set body")
        .set(
            4,
            Value::Text("t9".to_owned()),
            Value::Text(edited_at.to_owned()),
        )
        .expect("set edited_at");
    ChangeSet::<SimpleTable, String, Vec<u8>>::new()
        .update(update)
        .build()
}

/// The conflict reply's `server_row` for `client_seq`, the table named.
async fn expect_conflict(client: &mut Client, client_seq: u64) -> ConflictRow {
    let ControlMessage::MutationConflict(conflict) = client.next_control().await else {
        panic!("expected write {client_seq} to conflict");
    };
    assert_eq!(conflict.client_seq, client_seq);
    assert_eq!(conflict.table, "multi");
    conflict.server_row.expect("the row stands")
}

/// Two connections that each hold the writer's frontier settle one sequence.
/// The second is answered from the first's record, the fork is audited, and
/// the byte-identical redelivery re-answers the standing entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_connections_racing_one_sequence_are_answered_from_the_record() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());

    // Both connections bind the frontier before either writes. B is the same
    // account on its own run, since one handle holds one live connection.
    let (server_transport, client_a) = loopback();
    let server_a = tokio::spawn(manager.clone().serve(server_transport));
    let mut a = Client::new(client_a);
    let ack = a.handshake_with("race-a", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;
    let (server_transport, client_b) = loopback();
    let server_b = tokio::spawn(manager.clone().serve(server_transport));
    let mut b = Client::new(client_b);
    b.handshake_writing(
        "race-b",
        &["user:alice#race-b"],
        None,
        WriterRequest::Number(number),
        None,
    )
    .await;

    // A settles the sequence. B still holds the frontier it bound.
    let cs1 = insert_changeset(2, "two", "t1");
    a.upload(1, cs1.clone()).await;
    expect_applied(&mut a, 1).await;

    // B's copy of the sequence carries a different changeset, so it never
    // applies and the fork is named.
    b.upload(1, insert_changeset(5, "forked", "t9")).await;
    let ControlMessage::MutationReject(reject) = b.next_control().await else {
        panic!("expected the fork refusal");
    };
    assert_eq!(reject.client_seq, 1);
    assert_eq!(reject.reason, MutationRejectReason::Forked);

    // The byte-identical redelivery re-answers the standing entry.
    b.upload(1, cs1.clone()).await;
    expect_applied(&mut b, 1).await;

    // The audit names the fork once, and the standing entry keeps its record.
    let events = captured.write_events();
    assert_eq!(events.len(), 1, "the fork audits once");
    assert_eq!(events[0].seq, Some(1));
    let writer = i64::try_from(number).expect("number fits");
    let rows = settled_rows(fixture.admin(), writer).await;
    assert_eq!(rows.len(), 1, "the race settled one row");
    assert_eq!(
        rows[0].entry_hash,
        entry_hash(&GENESIS, 1, &cs1).to_vec(),
        "the record stands the first entry"
    );
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the racing changeset never applied"
    );
    a.close().await;
    b.close().await;
    server_a.await.expect("join a").expect("session a ok");
    server_b.await.expect("join b").expect("session b ok");
}

/// A conflict settles its sequence with the row's primary key, and the
/// redelivery re-reads the current row fresh instead of re-sending the copy
/// it settled. A primary key of text, real and blob columns survives the
/// stored round trip the re-read binds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conflict_re_answer_reads_the_current_row_fresh() {
    let fixture = Fixture::acquire().await;
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS multi CASCADE",
            MULTI_DDL,
            "DROP TABLE IF EXISTS _connetto_settled",
            "DROP TABLE IF EXISTS _connetto_writers",
        ])
        .await;
    connetto_test_harness::provision_writers(fixture.admin()).await;
    seed_multi(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let _ = captured;
    let manager = ManagerBuilder::new(
        Materializer::builder(MULTI_DDL)
            .with_write_catalog(
                RuntimeWritableCatalog::builder()
                    .versioned("multi", "edited_at")
                    .build(),
            )
            .build()
            .expect("build materializer"),
        NoSnapshot,
        RosterAuth::granting("alice")
            .and("bob")
            .withholding(WITHHELD_ID),
        test_verifier(),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), MULTI_DDL)
            .expect("build write target"),
    )
    .build();

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("conf-1", "user:alice").await;

    // The stale write conflicts, the reply carrying the row as it stands.
    let cs = multi_update_changeset("two", "t1");
    client.upload(1, cs.clone()).await;
    let first = expect_conflict(&mut client, 1).await;
    assert_eq!(first.updated_at, "t0", "the reply is the row as it stands");

    // The row moves while the refusal stands.
    {
        let mut conn = fixture.admin().get().await.expect("admin connection");
        diesel::update(multi::table)
            .set((multi::body.eq("three"), multi::edited_at.eq("t5")))
            .execute(&mut *conn)
            .await
            .expect("move the row");
    }

    // The redelivery re-answers from the record and reads the row fresh.
    client.upload(1, cs).await;
    let second = expect_conflict(&mut client, 1).await;
    assert_eq!(
        second.updated_at, "t5",
        "the re-read is the row as it stands now"
    );
    assert!(
        second.row_json.contains("three"),
        "the re-read carries the new body, got {}",
        second.row_json
    );

    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// A write past the frontier that this connection's own unsettled write
/// explains is not closed as a sequence gap. It is deferred the same way the
/// unsettled write was, and the sequences it stands under settle nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_past_a_deferred_gap_is_answered_indeterminate() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let pool = single_connection_pool(&fixture).await;
    let manager = writing_manager(
        &pool,
        guard,
        None,
        SessionConfig::default().with_write_retry_budget(Duration::ZERO),
    );
    let _ = captured;

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("gap-1", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;

    let outage = pool.get_owned().await.expect("hold the only connection");
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_indeterminate(&mut client, 1).await;
    drop(outage);

    // The gap the unsettled write stands in is not closed. The write past it
    // is deferred the same way, and nothing settles.
    client.upload(2, insert_changeset(3, "three", "t2")).await;
    expect_indeterminate(&mut client, 2).await;
    let writer = i64::try_from(number).expect("number fits");
    assert!(
        settled_rows(fixture.admin(), writer).await.is_empty(),
        "the deferred writes settle nothing"
    );
    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// A patch the server cannot read cannot be hashed, so nothing settles under
/// its sequence. The session ends with the protocol fatal, and the resent
/// entry settles the sequence it left open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_patch_that_does_not_decompress_closes_the_session_and_resends_applied() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("mal-1", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;

    client.upload_raw(1, b"not a zstd frame".to_vec()).await;
    let ControlMessage::FatalError(fatal) = client.next_control().await else {
        panic!("expected the protocol fatal");
    };
    assert!(
        matches!(fatal.reason, FatalErrorReason::ProtocolViolation { .. }),
        "the fatal names the undecodable envelope, got {fatal:?}"
    );
    assert!(client.recv().await.is_none(), "the session ends");
    client.close().await;
    let outcome = server.await.expect("join 1");
    assert!(outcome.is_err(), "the session fails closed");

    // Nothing settled under the unreadable sequence, so the resent entry
    // settles it on the next connection.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client
        .handshake_writing(
            "mal-2",
            &["user:alice"],
            None,
            WriterRequest::Number(number),
            None,
        )
        .await;
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    let writer = i64::try_from(number).expect("number fits");
    assert_eq!(
        settled_rows(fixture.admin(), writer).await.len(),
        1,
        "the readable patch settled the sequence once"
    );
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the resent entry applied"
    );
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

/// A patch the window could never hold is refused and its sequence settled,
/// so the redelivery re-answers the stored refusal rather than re-measuring.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_patch_over_the_byte_window_is_refused_and_settled() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::new().with_mutation_bytes_per_identity(1, Duration::from_secs(60)),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("win-1", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;
    let writer = i64::try_from(number).expect("number fits");

    let cs = insert_changeset(2, "two", "t1");
    client.upload(1, cs.clone()).await;
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected the oversize refusal");
    };
    assert_eq!(reject.client_seq, 1);
    assert!(matches!(reject.reason, MutationRejectReason::Other { .. }));

    // The refusal settled the sequence, so it stands refused and the frontier
    // takes it.
    let rows = settled_rows(fixture.admin(), writer).await;
    assert_eq!(rows.len(), 1, "the refusal settled the sequence");
    assert!(
        rows[0].outcome.contains("exceeds"),
        "the stored refusal names the window, got {}",
        rows[0].outcome
    );
    assert_eq!(
        writer_facts(fixture.admin(), writer).await.frontier,
        1,
        "the frontier took the refusal"
    );

    // The redelivery re-answers the stored refusal.
    client.upload(1, cs).await;
    let ControlMessage::MutationReject(second) = client.next_control().await else {
        panic!("expected the re-answered refusal");
    };
    assert_eq!(second.client_seq, 1);
    assert!(matches!(second.reason, MutationRejectReason::Other { .. }));
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0")],
        "the oversize patch never applied"
    );
    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// A write that arrives before a device writer binds cannot stand under a
/// writer that does not exist yet, so the fatal names the violation and the
/// session ends as a protocol error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_before_a_device_writer_binds_closes_the_session() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client
        .handshake_writing("dev-1", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    assert_eq!(ack.writer, None, "a device request carries no number grant");

    client.upload(1, insert_changeset(2, "two", "t1")).await;
    let ControlMessage::FatalError(fatal) = client.next_control().await else {
        panic!("expected the protocol fatal");
    };
    assert!(
        matches!(
            fatal.reason,
            FatalErrorReason::ProtocolViolation { ref detail }
                if detail == "a write before the device writer bound"
        ),
        "the fatal names the violation, got {fatal:?}"
    );
    assert!(client.recv().await.is_none(), "the session ends");
    client.close().await;
    let outcome = server.await.expect("join server");
    assert!(outcome.is_err(), "the session fails closed");
}

/// A redelivery whose preceding record a prune removed verifies against the
/// retained record's own predecessor hash and re-answers it, applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redelivery_behind_a_pruned_chain_reanswers_the_retained_record() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    // alice settles two entries.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("chain-1", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;
    let writer = i64::try_from(number).expect("number fits");
    let cs2 = insert_changeset(3, "three", "t2");
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    client.upload(2, cs2.clone()).await;
    expect_applied(&mut client, 2).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // The reconnect reports the first entry settled, pruning its record.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client
        .handshake_writing(
            "chain-2",
            &["user:alice"],
            None,
            WriterRequest::Number(number),
            Some(1),
        )
        .await;

    // The redelivery of the second entry re-answers its retained record,
    // which stands its own predecessor evidence.
    client.upload(2, cs2).await;
    expect_applied(&mut client, 2).await;
    client.close().await;
    server.await.expect("join 2").expect("session ok");
    assert_eq!(
        notes(fixture.admin()).await,
        vec![
            note(1, "hello", "t0"),
            note(2, "two", "t1"),
            note(3, "three", "t2")
        ],
        "nothing applied twice over the pruned chain"
    );
    assert_eq!(
        settled_rows(fixture.admin(), writer).await.len(),
        1,
        "the pruned record is gone and the retained one stands"
    );
}

/// A redelivery whose retained record stores a refusal re-answers that
/// refusal, a pruned predecessor standing no way in the record's own
/// predecessor evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redelivery_behind_a_pruned_chain_reanswers_the_stored_refusal() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::new().with_mutation_bytes_per_identity(1, Duration::from_secs(60)),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    // Every patch exceeds the one-byte window, so both settle refused.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("win-2", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;
    let cs2 = insert_changeset(3, "three", "t2");
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    let ControlMessage::MutationReject(first) = client.next_control().await else {
        panic!("expected the first stored refusal");
    };
    assert!(matches!(first.reason, MutationRejectReason::Other { .. }));
    client.upload(2, cs2.clone()).await;
    let ControlMessage::MutationReject(second) = client.next_control().await else {
        panic!("expected the second stored refusal");
    };
    assert!(matches!(second.reason, MutationRejectReason::Other { .. }));
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // The reconnect reports the first entry settled, pruning its record.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client
        .handshake_writing(
            "win-3",
            &["user:alice"],
            None,
            WriterRequest::Number(number),
            Some(1),
        )
        .await;

    // The redelivery of the second entry re-answers the stored refusal.
    client.upload(2, cs2).await;
    let ControlMessage::MutationReject(replayed) = client.next_control().await else {
        panic!("expected the re-answered refusal");
    };
    assert_eq!(replayed.client_seq, 2);
    assert!(matches!(
        replayed.reason,
        MutationRejectReason::Other { .. }
    ));
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0")],
        "the window-refused patches never applied"
    );
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

/// A redelivery with different bytes at a pruned predecessor's successor is
/// refused forked and audited, the retained record's own predecessor hash
/// still deciding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redelivery_with_forged_bytes_behind_a_pruned_chain_is_refused_forked() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());

    // alice settles two entries.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("fork-1", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    client.upload(2, insert_changeset(3, "three", "t2")).await;
    expect_applied(&mut client, 2).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // The reconnect reports the first entry settled, pruning its record.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client
        .handshake_writing(
            "fork-2",
            &["user:alice"],
            None,
            WriterRequest::Number(number),
            Some(1),
        )
        .await;

    // The second sequence re-arrives with bytes the chain never hashed.
    client.upload(2, insert_changeset(9, "nine", "t9")).await;
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected the forked refusal");
    };
    assert_eq!(reject.client_seq, 2);
    assert!(matches!(reject.reason, MutationRejectReason::Forked));
    client.close().await;
    server.await.expect("join 2").expect("session ok");
    assert_eq!(
        captured.write_events().len(),
        1,
        "the fork over the pruned chain audited once"
    );
    assert_eq!(
        notes(fixture.admin()).await,
        vec![
            note(1, "hello", "t0"),
            note(2, "two", "t1"),
            note(3, "three", "t2")
        ],
        "the forged bytes never applied"
    );
}

/// A settled record whose entry hash is not a chain hash is not trusted, so
/// the redelivery closes the session with the write target error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_settled_entry_hash_of_the_wrong_length_closes_the_session() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("hash-1", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;
    let cs1 = insert_changeset(2, "two", "t1");
    client.upload(1, cs1.clone()).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // Corrupt the record the way a torn write would leave it, a hash the
    // chain never produced.
    let writer = i64::try_from(number).expect("number fits");
    {
        let mut conn = fixture.admin().get().await.expect("admin connection");
        diesel::update(_connetto_settled::table)
            .filter(_connetto_settled::writer.eq(writer))
            .set(_connetto_settled::entry_hash.eq(b"broken"))
            .execute(&mut *conn)
            .await
            .expect("corrupt the record");
    }

    // The redelivery cannot verify the chain.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client
        .handshake_writing(
            "hash-2",
            &["user:alice"],
            None,
            WriterRequest::Number(number),
            None,
        )
        .await;
    client.upload(1, cs1).await;
    assert!(
        client.recv().await.is_none(),
        "the session closes rather than re-answer over a bad hash"
    );
    client.close().await;
    let outcome = server.await.expect("join 2");
    assert!(outcome.is_err(), "the session fails closed");
}

/// A retained record whose predecessor hash a torn write corrupted cannot be
/// trusted, so the redelivery closes the session with the write target error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retained_predecessor_hash_of_the_wrong_length_closes_the_session() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());
    let _ = captured;

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("prev-1", "user:alice").await;
    let number = ack.writer.expect("the handshake issues a number").number;
    let cs1 = insert_changeset(2, "two", "t1");
    client.upload(1, cs1.clone()).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // Corrupt the predecessor evidence the way a torn write would leave it.
    let writer = i64::try_from(number).expect("number fits");
    {
        let mut conn = fixture.admin().get().await.expect("admin connection");
        diesel::update(_connetto_settled::table)
            .filter(_connetto_settled::writer.eq(writer))
            .set(_connetto_settled::previous_hash.eq(b"broken"))
            .execute(&mut *conn)
            .await
            .expect("corrupt the record");
    }

    // The redelivery cannot verify the entry against its own evidence.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client
        .handshake_writing(
            "prev-2",
            &["user:alice"],
            None,
            WriterRequest::Number(number),
            None,
        )
        .await;
    client.upload(1, cs1).await;
    assert!(
        client.recv().await.is_none(),
        "the session closes rather than re-answer over a bad predecessor hash"
    );
    client.close().await;
    let outcome = server.await.expect("join 2");
    assert!(outcome.is_err(), "the session fails closed");
}

/// A settled row the deployment wrote over the restore or courier path reads
/// its path back as the variant it stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_settled_row_reads_its_settle_path_back() {
    let fixture = Fixture::acquire().await;
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS _connetto_settled",
            "DROP TABLE IF EXISTS _connetto_writers",
        ])
        .await;
    connetto_test_harness::provision_writers(fixture.admin()).await;

    let mut conn = fixture.admin().get().await.expect("admin connection");
    diesel::insert_into(_connetto_settled::table)
        .values((
            _connetto_settled::writer.eq(1_i64),
            _connetto_settled::seq.eq(1_i64),
            _connetto_settled::entry_hash.eq([0u8; 32]),
            _connetto_settled::previous_hash.eq([0u8; 32]),
            _connetto_settled::outcome.eq(r#""applied""#),
            _connetto_settled::path.eq(SettlePath::Restore),
        ))
        .execute(&mut *conn)
        .await
        .expect("restore row");
    diesel::insert_into(_connetto_settled::table)
        .values((
            _connetto_settled::writer.eq(1_i64),
            _connetto_settled::seq.eq(2_i64),
            _connetto_settled::entry_hash.eq([0u8; 32]),
            _connetto_settled::previous_hash.eq([0u8; 32]),
            _connetto_settled::outcome.eq(r#""applied""#),
            _connetto_settled::path.eq(SettlePath::Courier),
        ))
        .execute(&mut *conn)
        .await
        .expect("courier row");

    let rows = settled_rows(fixture.admin(), 1).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].path, SettlePath::Restore);
    assert_eq!(rows[1].path, SettlePath::Courier);
}

/// Whether no writer row stands for the device key, read as admin.
async fn device_row_absent(pool: &Pool<AsyncPgConnection>, key_id: [u8; 32]) -> bool {
    let mut conn = pool.get().await.expect("admin connection");
    let found: Option<i64> = _connetto_writers::table
        .filter(_connetto_writers::device_key.eq(key_id.to_vec()))
        .select(_connetto_writers::writer)
        .first(&mut *conn)
        .await
        .optional()
        .expect("read the device writer");
    found.is_none()
}

/// An entry settled through a restore stands redelivered when its own
/// writer re-uploads it at its own sequence: the same bytes, answered from
/// the record, and the cross-path delivery audited on both paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_path_entry_reuploaded_at_its_sequence_audits_redelivered() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());

    // A stands fresh.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("rp-1", "user:alice").await;
    let a = ack.writer.expect("the handshake issues a number").number;
    client.close().await;
    server.await.expect("join 1").expect("session ok");
    let writer_a = i64::try_from(a).expect("number fits");

    // B's import settles A's entry through the restore path.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("rp-2", "user:alice").await;
    let cs1 = insert_changeset(2, "two", "t1");
    client
        .upload_with_provenance(
            1,
            cs1.clone(),
            Some(Provenance {
                writer: WriterRef::Number(a),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 1).await;
    assert_eq!(
        settled_rows(fixture.admin(), writer_a).await[0].path,
        SettlePath::Restore,
        "the original stands restore"
    );
    client.close().await;
    server.await.expect("join 2").expect("session ok");

    // A's own writer re-uploads the entry at its own sequence.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client
        .handshake_writing(
            "rp-3",
            &["user:alice"],
            None,
            WriterRequest::Number(a),
            None,
        )
        .await;
    assert_eq!(
        ack.writer.expect("the number confirms").frontier,
        1,
        "the restore advanced the number's frontier"
    );
    client.upload(1, cs1).await;
    expect_applied(&mut client, 1).await;

    // Answered from the record, audited on both paths, applied once.
    let events = captured.write_events();
    assert_eq!(events.len(), 1, "the cross-path redelivery audits once");
    let event = &events[0];
    assert_eq!(event.op, AuthOp::WriteRedelivered);
    assert_eq!(event.user_id.as_deref(), Some("alice"));
    assert_eq!(event.writer, Some(writer_a));
    assert_eq!(event.seq, Some(1));
    assert_eq!(event.path, Some(SettlePath::Direct));
    assert_eq!(event.other_path, Some(SettlePath::Restore));
    let rows_a = settled_rows(fixture.admin(), writer_a).await;
    assert_eq!(rows_a.len(), 1, "the redelivery settles no second row");
    assert_eq!(
        rows_a[0].path,
        SettlePath::Restore,
        "the restore path stands"
    );
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the entry applied once"
    );
    client.close().await;
    server.await.expect("join 3").expect("session ok");
}

/// A retired number's settled row prunes at the handshake that reports how
/// far the client settled it, and a provenance write of a pruned original
/// settles its copy applied, the entry standing applied once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retired_number_with_settled_through_prunes_and_a_provenance_of_it_applies() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());

    // A settles one entry.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("pt-1", "user:alice").await;
    let a = ack.writer.expect("the handshake issues a number").number;
    let cs1 = insert_changeset(2, "two", "t1");
    client.upload(1, cs1.clone()).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");
    let writer_a = i64::try_from(a).expect("number fits");

    // The retirement, then the settle report that prunes the row.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("pt-2", "user:alice").await;
    let answer = client.retire_writer("r1", WriterRef::Number(a)).await;
    assert_eq!(answer.outcome, WriterOutcome::Retired);
    client.close().await;
    server.await.expect("join 2").expect("session ok");

    let fatal = refused_handshake(
        &manager,
        "pt-3",
        "user:alice",
        WriterRequest::Number(a),
        Some(1),
    )
    .await;
    assert!(
        matches!(fatal.reason, FatalErrorReason::WriterRetired),
        "the retired number must close as WriterRetired, got {:?}",
        fatal.reason
    );
    assert!(
        settled_rows(fixture.admin(), writer_a).await.is_empty(),
        "the settle report pruned the settled row"
    );

    // A fresh number's copy of the pruned entry settles applied.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("pt-4", "user:alice").await;
    client
        .upload_with_provenance(
            1,
            cs1,
            Some(Provenance {
                writer: WriterRef::Number(a),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 1).await;
    assert!(
        settled_rows(fixture.admin(), writer_a).await.is_empty(),
        "the pruned record settles nothing of the original"
    );
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the entry applied once"
    );
    client.close().await;
    server.await.expect("join 4").expect("session ok");
}

/// An anonymous caller enrols no device key, so its bind answers not
/// enrolled, standing no writer row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anonymous_bind_is_not_enrolled() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    let enrolments = Enrolments::new();
    let (_, key_id) = enrolments
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(enrolments.installable()),
        SessionConfig::default(),
    );

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (_, _) = client
        .handshake_challenge_writing("anon-bind", &[], None, WriterRequest::Issue, None)
        .await;
    let answer = client.bind_device("b1", key_id, Vec::new()).await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::NotEnrolled,
        "an anonymous caller enrols no device key"
    );
    assert!(device_row_absent(fixture.admin(), key_id).await);
    client.close().await;
    server.await.expect("join the bind").expect("session ok");
}

/// A bind whose key's stored public key is not an EC P-256 point answers
/// not enrolled, the signature never reaching verification, and no writer
/// row standing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bind_of_a_key_with_an_unreadable_public_key_is_not_enrolled() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    let enrolments = Enrolments::new();
    let key_id = enrolments
        .enrol_with(
            "alice",
            [41; 32],
            Vec::new(),
            SystemTime::now() + Duration::from_hours(24),
        )
        .await
        .as_bytes()
        .to_owned();
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(enrolments.installable()),
        SessionConfig::default(),
    );

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing("unr-1", &["user:alice"], None, WriterRequest::Issue, None)
        .await;
    let key = device_key();
    let signature = key
        .sign(&writer_bind_message(&challenge.nonce))
        .expect("sign")
        .clone();
    let answer = client.bind_device("b1", key_id, signature).await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::NotEnrolled,
        "an unreadable public key answers not enrolled"
    );
    assert!(device_row_absent(fixture.admin(), key_id).await);
    client.close().await;
    server.await.expect("join the bind").expect("session ok");
}

/// A device key bound by one account retires nothing when another account
/// names it, never confirming the key exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retiring_a_device_key_another_account_holds_is_unknown() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    let enrolments = Enrolments::new();
    let (signer, key_id) = enrolments
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(enrolments.installable()),
        SessionConfig::default(),
    );

    // alice binds the key.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing("fk-1", &["user:alice"], None, WriterRequest::Issue, None)
        .await;
    let answer = client
        .bind_device("b1", key_id, signer.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // bob names the key.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("fk-2", "user:bob").await;
    let answer = client.retire_writer("r1", WriterRef::Device(key_id)).await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::Unknown,
        "another account's key retires nothing"
    );
    let writer = writer_for_key(fixture.admin(), key_id).await;
    assert!(
        !writer_facts(fixture.admin(), writer).await.retired,
        "the owner's writer stands"
    );
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

/// An anonymous caller retires no device key, the row standing untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anonymous_retire_of_a_device_key_is_unknown() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    let enrolments = Enrolments::new();
    let (signer, key_id) = enrolments
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(enrolments.installable()),
        SessionConfig::default(),
    );

    // alice binds the key.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing("anr-1", &["user:alice"], None, WriterRequest::Issue, None)
        .await;
    let answer = client
        .bind_device("b1", key_id, signer.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // An anonymous caller names the key.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_unidentified("anr-2").await;
    let answer = client.retire_writer("r1", WriterRef::Device(key_id)).await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::Unknown,
        "an anonymous caller retires no device key"
    );
    let writer = writer_for_key(fixture.admin(), key_id).await;
    assert!(
        !writer_facts(fixture.admin(), writer).await.retired,
        "the writer stands"
    );
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

/// A server that installs no device enrolment retires no device key and
/// applies a provenance copy of one plainly, standing no row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_without_enrolment_refuses_device_retire_and_applies_provenance_plain() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    let manager = writing_manager(fixture.admin(), guard, None, SessionConfig::default());

    // The retirement refuses as unknown.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("ne-1", "user:alice").await;
    let answer = client.retire_writer("r1", WriterRef::Device([7; 32])).await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::Unknown,
        "no enrolment stands, so no key retires"
    );
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // A provenance copy of the key applies as a plain write.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("ne-2", "user:alice").await;
    client
        .upload_with_provenance(
            1,
            insert_changeset(2, "two", "t1"),
            Some(Provenance {
                writer: WriterRef::Device([7; 32]),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 1).await;
    assert!(device_row_absent(fixture.admin(), [7; 32]).await);
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

/// A revoked key that never bound retires as unknown, standing no row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retiring_a_revoked_enrolled_key_that_never_bound_is_unknown() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    let enrolments = Enrolments::new();
    let (_, key_id) = enrolments
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    enrolments.revoke(key_id);
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(enrolments.installable()),
        SessionConfig::default(),
    );

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_with("rv-1", "user:alice").await;
    let answer = client.retire_writer("r1", WriterRef::Device(key_id)).await;
    assert_eq!(
        answer.outcome,
        WriterOutcome::Unknown,
        "a revoked key that never bound retires as unknown"
    );
    assert!(device_row_absent(fixture.admin(), key_id).await);
    client.close().await;
    server
        .await
        .expect("join the retirement")
        .expect("session ok");
}

/// A provenance write of a device key that cannot stand as its original
/// applies plainly and stands no row: the revoked key, the other account's
/// key, and a key no account enrolled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provenance_write_of_a_device_key_that_cannot_stand_applies_plain() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    let enrolments = Enrolments::new();
    let (_, revoked) = enrolments
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    enrolments.revoke(revoked);
    let (_, foreign) = enrolments
        .enrol("bob", SystemTime::now() + Duration::from_hours(24))
        .await;
    let unknown = [77; 32];
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(enrolments.installable()),
        SessionConfig::default(),
    );

    // Each copy applies as a plain write.
    for (id, key_id, body) in [
        (2, revoked, "two"),
        (3, foreign, "three"),
        (4, unknown, "four"),
    ] {
        let (server_transport, client) = loopback();
        let server = tokio::spawn(manager.clone().serve(server_transport));
        let mut client = Client::new(client);
        client
            .handshake_with(&format!("pp-{id}"), "user:alice")
            .await;
        client
            .upload_with_provenance(
                1,
                insert_changeset(id, body, "t1"),
                Some(Provenance {
                    writer: WriterRef::Device(key_id),
                    seq: 1,
                }),
            )
            .await;
        expect_applied(&mut client, 1).await;
        assert!(
            device_row_absent(fixture.admin(), key_id).await,
            "the copy that cannot stand settles no row"
        );
        client.close().await;
        server.await.expect("join the copy").expect("session ok");
    }

    let seeded = notes(fixture.admin()).await;
    for id in [1, 2, 3, 4] {
        assert!(
            seeded.iter().any(|row| row.id == id),
            "the copy applied as a plain write"
        );
    }
}

/// An anonymous caller's provenance copy of a device key that another
/// account holds, or that the account holds unbound, settles nothing of the
/// key's row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anonymous_provenance_copy_of_a_device_key_settles_nothing() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    let enrolments = Enrolments::new();
    let (signer, held) = enrolments
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let (_, unbound) = enrolments
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(enrolments.installable()),
        SessionConfig::default(),
    );

    // alice binds the key so it stands a device row with no entries.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let (challenge, _) = client
        .handshake_challenge_writing("ap-1", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    let answer = client
        .bind_device("b1", held, signer.signature(&challenge.nonce))
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    client.close().await;
    server.await.expect("join 1").expect("session ok");
    let writer = writer_for_key(fixture.admin(), held).await;

    // An anonymous copy of the bound key settles nothing of it, and a copy
    // of the account's unbound key stands no row.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let _ = client
        .handshake_writing("ap-2", &[], None, WriterRequest::Issue, None)
        .await;
    client
        .upload_with_provenance(
            1,
            insert_changeset(5, "five", "t1"),
            Some(Provenance {
                writer: WriterRef::Device(held),
                seq: 1,
            }),
        )
        .await;
    let _ = client.next_control().await;
    assert_eq!(
        writer_facts(fixture.admin(), writer).await.frontier,
        0,
        "the copy settles nothing of the other account's key"
    );
    client
        .upload_with_provenance(
            2,
            insert_changeset(6, "six", "t2"),
            Some(Provenance {
                writer: WriterRef::Device(unbound),
                seq: 1,
            }),
        )
        .await;
    let _ = client.next_control().await;
    assert!(device_row_absent(fixture.admin(), unbound).await);
    client.close().await;
    server.await.expect("join 2").expect("session ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_provenance_write_settles_its_unbound_original() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    let store = Enrolments::new();
    let (_, key) = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let (transport, client) = loopback();
    let server = tokio::spawn(manager.serve(transport));
    let mut client = Client::new(client);
    let ack = client
        .handshake_with("refused-original", "user:alice")
        .await;
    let copy = i64::try_from(ack.writer.expect("number writer").number).expect("stored number");
    client
        .upload_with_provenance(
            1,
            vec![0],
            Some(Provenance {
                writer: WriterRef::Device(key),
                seq: 1,
            }),
        )
        .await;
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("the malformed logical write must be refused");
    };
    assert_eq!(reject.client_seq, 1);
    assert!(matches!(
        reject.reason,
        MutationRejectReason::Malformed { .. }
    ));
    client.close().await;
    server.await.expect("server task").expect("session");
    let original = writer_for_key(fixture.admin(), key).await;
    let original_rows = settled_rows(fixture.admin(), original).await;
    let copy_rows = settled_rows(fixture.admin(), copy).await;
    assert_eq!(original_rows.len(), 1);
    assert_eq!(copy_rows.len(), 1);
    assert_eq!(original_rows[0].outcome, copy_rows[0].outcome);
    assert_eq!(writer_facts(fixture.admin(), original).await.frontier, 1);
    assert_eq!(writer_facts(fixture.admin(), copy).await.frontier, 1);
    assert_eq!(notes(fixture.admin()).await, [note(1, "hello", "t0")]);
}
