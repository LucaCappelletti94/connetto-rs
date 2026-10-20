//! Docker-gated acceptance tests for the per-writer applied frontier (R75).
//!
//! Each test drives raw frames through the harness `Client` against the real
//! Postgres write target and walks one row of the server state table. The
//! number writer's handshakes refuse what it does not hold and confirm what
//! it does. `settled_through` prunes the rows at and below the report, and a
//! pruned record answers applied by sequence alone. The audit names every
//! fork. A settled entry is never applied twice, and a forged second
//! changeset at an applied `(writer, sequence)` is refused `Forked`.
//!
//! Needs Docker: the fixture starts its own Postgres.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::auth::Principal;
use connetto_core::chain::{GENESIS, entry_hash};
use connetto_core::messages::{
    ConflictRow, ControlMessage, FatalError, FatalErrorReason, Grant, Handshake,
    MutationRejectReason, WriterGrant, WriterRequest,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport as _};
use connetto_server::audit::{AuditHook, AuthEvent, AuthOp};
use connetto_server::defaults::{_connetto_settled, _connetto_writers};
use connetto_server::writer_schema::SettlePath;
use connetto_server::{
    AbuseConfig, ManagerBuilder, Materializer, NoConnector, PageSpec, RequestGuard,
    RuntimeWritableCatalog, SessionConfig, SessionManager, SnapshotEstimate, SnapshotPage,
    SnapshotSource, ThrottleConfig, loopback, pg_write_target,
};
use connetto_test_harness::{Client, ConnettoDefaults, Fixture, RosterAuth, WITHHELD_ID};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use parking_lot::Mutex;
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

/// The writer's frontier and retirement state, read as admin.
struct WriterFacts {
    frontier: i64,
    retired: bool,
}

async fn writer_facts(pool: &Pool<AsyncPgConnection>, writer: i64) -> WriterFacts {
    let mut conn = pool.get().await.expect("admin connection");
    let (frontier, retired) = _connetto_writers::table
        .filter(_connetto_writers::writer.eq(writer))
        .select((
            _connetto_writers::frontier,
            _connetto_writers::retired_at.is_not_null(),
        ))
        .get_result::<(i64, bool)>(&mut *conn)
        .await
        .expect("read the writer row");
    WriterFacts { frontier, retired }
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

    /// The writer-state events, `write_forked`.
    fn write_events(&self) -> Vec<AuthEvent<String>> {
        self.0
            .lock()
            .iter()
            .filter(|event| matches!(event.op, AuthOp::WriteForked))
            .cloned()
            .collect()
    }
}

fn writing_manager(
    pool: &Pool<AsyncPgConnection>,
    guard: Arc<RequestGuard<String>>,
    session: SessionConfig,
) -> Arc<SessionManager<NoSnapshot, RosterAuth, ConnettoDefaults>> {
    ManagerBuilder::new(
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
    .build()
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
) -> FatalError {
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, client_id)
                .with_grant(Grant::new(grant))
                .with_writer(writer),
        ))
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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());
    let _ = captured;

    let fatal = refused_handshake(
        &manager,
        "probe",
        "user:alice",
        WriterRequest::Number(987_654_321),
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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());
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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());
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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());

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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());

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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());
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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());
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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());
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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());
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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());
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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());

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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());
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
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());
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
