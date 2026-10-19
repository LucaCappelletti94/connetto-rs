//! Docker-gated acceptance tests for the courier range and the writer-row
//! sweep (R75).
//!
//! A courier range carries one author's queued entries, signed by the
//! author's device key, and settles them through the write path the direct
//! upload takes, as the `Courier` path. The range continues the author's
//! settled chain and applies under the author's account identity. The sweep
//! prunes the settled rows of the device writers whose enrolment no longer
//! stands, and keeps the writer row and its frontier.
//!
//! Needs Docker: the fixture starts its own Postgres.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use connetto_core::SessionId;
use connetto_core::auth::Principal;
use connetto_core::chain::{GENESIS, entry_hash, range_message};
use connetto_core::device_cert::{AttestationLevel, KeyId};
use connetto_core::messages::{ControlMessage, WriterOutcome, WriterRef, WriterRequest};
use connetto_core::test_support::TestGrantChecker;
use connetto_server::audit::{AuditHook, AuthEvent, AuthOp};
use connetto_server::courier::{CourierDelivery, CourierEntry, CourierRefusal};
use connetto_server::defaults::{_connetto_settled, _connetto_writers};
use connetto_server::device_cert::{
    DeviceCertConfig, DeviceEnrolment, Enrolment, EnrolmentStore, MemoryEnrolments,
};
use connetto_server::writer_schema::{SettlePath, SettledOutcome};
use connetto_server::{
    AbuseConfig, ManagerBuilder, Materializer, NoConnector, PageSpec, RequestGuard,
    RuntimeWritableCatalog, SessionConfig, SessionManager, SnapshotEstimate, SnapshotPage,
    SnapshotSource, ThrottleConfig, pg_write_target,
};
use connetto_test_harness::{Client, ConnettoDefaults, Fixture, RosterAuth, WITHHELD_ID};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use parking_lot::Mutex;
use rcgen::{KeyPair, PublicKeyData as _, SigningKey as _};
use sqlite_diff_rs::{ChangeSet, DiffOps, Insert, SimpleTable, Value};

use super::enrolment::device_key;

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

/// The writer's account, frontier, head and retirement state, read as admin.
struct WriterFacts {
    user: Option<String>,
    frontier: i64,
    head: Option<Vec<u8>>,
    retired: bool,
}

async fn writer_facts(pool: &Pool<AsyncPgConnection>, writer: i64) -> WriterFacts {
    let mut conn = pool.get().await.expect("admin connection");
    let (user, frontier, head, retired) = _connetto_writers::table
        .filter(_connetto_writers::writer.eq(writer))
        .select((
            _connetto_writers::user_id,
            _connetto_writers::frontier,
            _connetto_writers::head,
            _connetto_writers::retired_at.is_not_null(),
        ))
        .get_result::<(Option<String>, i64, Option<Vec<u8>>, bool)>(&mut *conn)
        .await
        .expect("read the writer row");
    WriterFacts {
        user,
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
    async fn enrol(&self, user: &str, expires_at: SystemTime) -> (KeyPair, [u8; 32]) {
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
        (key, key_id)
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

/// The ECDSA P-256 SHA-256 signature of `key` over `message`.
fn sign(key: &KeyPair, message: &[u8]) -> Vec<u8> {
    key.sign(message).expect("sign the message").clone()
}

/// The signature the author's key signs to vouch for its chain up to the
/// last entry of the range.
fn range_signature(key: &KeyPair, key_id: [u8; 32], seq: u64, head: [u8; 32]) -> Vec<u8> {
    sign(key, &range_message(&key_id, seq, &head))
}

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

/// The durable-apply acknowledgement of `client_seq`.
async fn expect_applied(client: &mut Client, client_seq: u64) {
    let ControlMessage::MutationApplied(applied) = client.next_control().await else {
        panic!("expected write {client_seq} to apply");
    };
    assert_eq!(applied.client_seq, client_seq);
}

/// The enrolment test helpers shared by every suite in this crate.
use super::enrolment::rooted_issuer;

/// A courier range over a fresh author's chain settles every entry in order
/// as the `Courier` path, under the author's account identity, and stands
/// the author's writer row at the range's head.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_good_courier_range_settles_the_authors_entries_under_courier() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let (key, key_id) = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // The range carries the author's first two entries, chained from genesis.
    let cs1 = insert_changeset(2, "two", "t1");
    let cs2 = insert_changeset(3, "three", "t2");
    let head1 = entry_hash(&GENESIS, 1, &cs1);
    let head2 = entry_hash(&head1, 2, &cs2);
    let entries = vec![
        CourierEntry {
            seq: 1,
            changeset: cs1.clone(),
        },
        CourierEntry {
            seq: 2,
            changeset: cs2.clone(),
        },
    ];
    let signature = range_signature(&key, key_id, 2, head2);
    let delivery = manager
        .courier_deliver(KeyId::from_bytes(key_id), &entries, &signature)
        .await
        .expect("deliver the range");
    let CourierDelivery::Entries(outcomes) = delivery else {
        panic!("expected delivered entries, got a refusal");
    };
    assert_eq!(
        outcomes,
        vec![SettledOutcome::Applied, SettledOutcome::Applied]
    );

    // Both entries landed, under the author's account.
    assert_eq!(
        notes(fixture.admin()).await,
        vec![
            note(1, "hello", "t0"),
            note(2, "two", "t1"),
            note(3, "three", "t2"),
        ]
    );
    let writer = writer_for_key(fixture.admin(), key_id).await;
    let facts = writer_facts(fixture.admin(), writer).await;
    assert_eq!(
        facts.user,
        Some("alice".to_owned()),
        "the range applies as the author"
    );
    assert_eq!(facts.frontier, 2);
    assert_eq!(facts.head, Some(head2.to_vec()));
    assert!(!facts.retired);
    let rows = settled_rows(fixture.admin(), writer).await;
    assert_eq!(
        rows.iter()
            .map(|row| (row.seq, row.path))
            .collect::<Vec<_>>(),
        vec![(1, SettlePath::Courier), (2, SettlePath::Courier),]
    );
    assert_eq!(rows[0].entry_hash, head1.to_vec());
    assert_eq!(rows[1].entry_hash, head2.to_vec());
    assert_eq!(
        rows.iter()
            .map(|row| row.outcome.as_str())
            .collect::<Vec<_>>(),
        vec!["\"applied\"", "\"applied\""]
    );
}

/// A range the author's key did not sign over its own chain is refused
/// before anything settles, the same way a key no enrolment holds is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_courier_range_missing_the_authors_signature_is_refused() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let (key, key_id) = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // The signature vouches a chain head the range does not reach.
    let cs1 = insert_changeset(2, "two", "t1");
    let entries = vec![CourierEntry {
        seq: 1,
        changeset: cs1,
    }];
    let wrong_signature = range_signature(&key, key_id, 1, GENESIS);
    let delivery = manager
        .courier_deliver(KeyId::from_bytes(key_id), &entries, &wrong_signature)
        .await
        .expect("deliver the range");
    let CourierDelivery::Refused(refusal) = delivery else {
        panic!("expected a courier refusal");
    };
    assert_eq!(refusal, CourierRefusal::NotEnrolled);
    let mut conn = fixture.admin().get().await.expect("admin connection");
    let settled: i64 = _connetto_settled::table
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count the settled rows");
    assert_eq!(settled, 0, "the refusal settled nothing");
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0")],
        "the refusal settled nothing"
    );
}

/// A range that starts past the author's settled frontier is refused with
/// the gap, and settles nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_courier_range_past_the_authors_frontier_is_refused() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let (key, key_id) = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // The author settles one entry directly.
    let (mut client, server) = loopback_client(&manager);
    let (challenge, _) = client
        .handshake_challenge_writing("gap-1", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    let answer = client
        .bind_device(
            "b1",
            key_id,
            sign(&key, &bind_nonce_message(&challenge.nonce)),
        )
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    let cs1 = insert_changeset(2, "two", "t1");
    client.upload(1, cs1).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    // The range names the third sequence, past the frontier.
    let cs3 = insert_changeset(4, "four", "t3");
    let entries = vec![CourierEntry {
        seq: 3,
        changeset: cs3,
    }];
    let head1 = entry_hash(&GENESIS, 1, &insert_changeset(2, "two", "t1"));
    let head3 = entry_hash(&head1, 3, &entries[0].changeset);
    let signature = range_signature(&key, key_id, 3, head3);
    let delivery = manager
        .courier_deliver(KeyId::from_bytes(key_id), &entries, &signature)
        .await
        .expect("deliver the range");
    let CourierDelivery::Refused(refusal) = delivery else {
        panic!("expected a courier refusal");
    };
    assert_eq!(
        refusal,
        CourierRefusal::SequenceGap {
            expected: 2,
            got: 3
        }
    );
    let writer = writer_for_key(fixture.admin(), key_id).await;
    assert_eq!(
        writer_facts(fixture.admin(), writer).await.frontier,
        1,
        "the gap settles nothing"
    );
    assert_eq!(settled_rows(fixture.admin(), writer).await.len(), 1);
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the gap settled nothing"
    );
}

/// A range for a retired author is refused, and the author's record stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_courier_range_for_a_retired_author_is_refused() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let (key, key_id) = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // The author settles one entry directly, then retires the writer.
    let (mut client, server) = loopback_client(&manager);
    let (challenge, _) = client
        .handshake_challenge_writing("ret-1", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    let answer = client
        .bind_device(
            "b1",
            key_id,
            sign(&key, &bind_nonce_message(&challenge.nonce)),
        )
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    let cs1 = insert_changeset(2, "two", "t1");
    client.upload(1, cs1.clone()).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    let (mut client, server) = loopback_client(&manager);
    client.handshake_with("ret-2", "user:alice").await;
    let answer = client.retire_writer("r1", WriterRef::Device(key_id)).await;
    assert_eq!(answer.outcome, WriterOutcome::Retired);
    client.close().await;
    server.await.expect("join 2").expect("session ok");

    // The range for the retired author settles nothing.
    let cs2 = insert_changeset(3, "three", "t2");
    let head1 = entry_hash(&GENESIS, 1, &cs1);
    let head2 = entry_hash(&head1, 2, &cs2);
    let entries = vec![CourierEntry {
        seq: 2,
        changeset: cs2.clone(),
    }];
    let signature = range_signature(&key, key_id, 2, head2);
    let delivery = manager
        .courier_deliver(KeyId::from_bytes(key_id), &entries, &signature)
        .await
        .expect("deliver the range");
    let CourierDelivery::Refused(CourierRefusal::WriterRetired) = delivery else {
        panic!("expected a WriterRetired refusal");
    };
    let writer = writer_for_key(fixture.admin(), key_id).await;
    let facts = writer_facts(fixture.admin(), writer).await;
    assert!(facts.retired);
    assert_eq!(facts.frontier, 1, "the retirement stands the record");
    assert_eq!(settled_rows(fixture.admin(), writer).await.len(), 1);
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the refusal settled nothing"
    );
}

/// The direct re-upload of a courier-settled entry is answered applied from
/// the record, audited `write_redelivered` across the two paths, and applies
/// the entry once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_reupload_of_a_courier_settled_entry_is_answered_from_the_record_and_audited() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let (key, key_id) = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );

    // The courier settles the author's first entry.
    let cs1 = insert_changeset(2, "two", "t1");
    let head1 = entry_hash(&GENESIS, 1, &cs1);
    let entries = vec![CourierEntry {
        seq: 1,
        changeset: cs1.clone(),
    }];
    let signature = range_signature(&key, key_id, 1, head1);
    let delivery = manager
        .courier_deliver(KeyId::from_bytes(key_id), &entries, &signature)
        .await
        .expect("deliver the range");
    let CourierDelivery::Entries(outcomes) = delivery else {
        panic!("expected delivered entries, got a refusal");
    };
    assert_eq!(outcomes, vec![SettledOutcome::Applied]);
    let writer = writer_for_key(fixture.admin(), key_id).await;
    assert_eq!(
        settled_rows(fixture.admin(), writer).await[0].path,
        SettlePath::Courier
    );

    // The author's direct connection re-uploads the same entry at its
    // settled sequence.
    let (mut client, server) = loopback_client(&manager);
    let (challenge, _) = client
        .handshake_challenge_writing("reup-1", &["user:alice"], None, WriterRequest::Device, None)
        .await;
    let answer = client
        .bind_device(
            "b1",
            key_id,
            sign(&key, &bind_nonce_message(&challenge.nonce)),
        )
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 1 });
    client.upload(1, cs1).await;
    expect_applied(&mut client, 1).await;

    // Audited redelivered across the two paths, the entry applied once.
    let events = captured.write_events();
    assert_eq!(events.len(), 1, "the cross-path redelivery audits once");
    let event = &events[0];
    assert_eq!(event.op, AuthOp::WriteRedelivered);
    assert_eq!(event.user_id.as_deref(), Some("alice"));
    assert_eq!(event.writer, Some(writer));
    assert_eq!(event.seq, Some(1));
    assert_eq!(event.path, Some(SettlePath::Direct));
    assert_eq!(event.other_path, Some(SettlePath::Courier));
    let rows = settled_rows(fixture.admin(), writer).await;
    assert_eq!(rows.len(), 1, "the re-upload settles nothing new");
    assert_eq!(rows[0].path, SettlePath::Courier, "the first path stands");
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")],
        "the entry applied once"
    );
    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// The sweep prunes the settled rows of the writers whose enrolment no
/// longer stands, keeps the writer row and its frontier, and spares the
/// writers whose enrolment still does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sweep_prunes_a_revoked_writers_settled_rows_and_keeps_its_row() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let (captured, hook) = Captured::new();
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    guard.set_audit_hook(hook);
    let store = Enrolments::new();
    let (k1, k1_id) = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let (k2, k2_id) = store
        .enrol("alice", SystemTime::now() + Duration::from_hours(24))
        .await;
    let manager = writing_manager(
        fixture.admin(),
        guard,
        Some(store.installable()),
        SessionConfig::default(),
    );
    let _ = captured;

    // Both keys bind and settle one entry directly.
    let (mut client, server) = loopback_client(&manager);
    let (challenge, _) = client
        .handshake_challenge_writing(
            "sweep-1",
            &["user:alice"],
            None,
            WriterRequest::Device,
            None,
        )
        .await;
    let answer = client
        .bind_device(
            "b1",
            k1_id,
            sign(&k1, &bind_nonce_message(&challenge.nonce)),
        )
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    let cs1 = insert_changeset(2, "two", "t1");
    client.upload(1, cs1).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 1").expect("session ok");

    let (mut client, server) = loopback_client(&manager);
    let (challenge, _) = client
        .handshake_challenge_writing(
            "sweep-2",
            &["user:alice"],
            None,
            WriterRequest::Device,
            None,
        )
        .await;
    let answer = client
        .bind_device(
            "b1",
            k2_id,
            sign(&k2, &bind_nonce_message(&challenge.nonce)),
        )
        .await;
    assert_eq!(answer.outcome, WriterOutcome::Bound { frontier: 0 });
    let cs2 = insert_changeset(3, "three", "t2");
    client.upload(1, cs2).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join 2").expect("session ok");

    // The revocation of the first key makes its writer sweepable.
    store.revoke(k1_id);
    let pruned = manager.sweep_writer_rows().await.expect("sweep the rows");
    assert_eq!(pruned, 1, "one writer's rows pruned");

    // The pruned writer's rows are gone, its row stands, and the live
    // writer's rows stand.
    let writer_1 = writer_for_key(fixture.admin(), k1_id).await;
    assert!(settled_rows(fixture.admin(), writer_1).await.is_empty());
    let facts_1 = writer_facts(fixture.admin(), writer_1).await;
    assert_eq!(facts_1.frontier, 1, "the sweep keeps the frontier");
    assert!(facts_1.head.is_some(), "the sweep keeps the head");
    assert!(!facts_1.retired);
    let writer_2 = writer_for_key(fixture.admin(), k2_id).await;
    assert_eq!(settled_rows(fixture.admin(), writer_2).await.len(), 1);
    assert_eq!(
        notes(fixture.admin()).await,
        vec![
            note(1, "hello", "t0"),
            note(2, "two", "t1"),
            note(3, "three", "t2"),
        ],
        "the sweep prunes records, not rows"
    );

    // A second pass stands the same state.
    manager.sweep_writer_rows().await.expect("sweep again");
    assert!(settled_rows(fixture.admin(), writer_1).await.is_empty());
    assert_eq!(settled_rows(fixture.admin(), writer_2).await.len(), 1);
}

/// A loopback connection driven as a harness `Client`.
fn loopback_client(
    manager: &Arc<SessionManager<NoSnapshot, RosterAuth, ConnettoDefaults>>,
) -> (
    Client,
    tokio::task::JoinHandle<Result<(), connetto_server::SessionError>>,
) {
    let (server_transport, client) = connetto_server::loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    (Client::new(client), server)
}

/// The message a device key signs to bind to a connection's challenge.
fn bind_nonce_message(nonce: &[u8; 32]) -> Vec<u8> {
    connetto_core::messages::writer_bind_message(nonce)
}
