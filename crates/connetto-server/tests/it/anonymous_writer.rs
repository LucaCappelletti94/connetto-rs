//! Docker-gated tests for the anonymous caller's writer binding (R75).
//!
//! A caller with no identity has no account to check a number against, and
//! numbers are sequential, so a number writer issued to such a caller belongs
//! to the run that holds the resume credential naming its durable handle. A
//! second run that guesses the first run's number is told it is unknown,
//! prunes nothing of it, retires nothing of it, and settles a copy that names
//! it as a plain write. The owning run, resuming on its own token, still
//! confirms the number and retires it itself.
//!
//! Needs Docker: the fixture starts its own Postgres.

#![expect(
    clippy::too_many_lines,
    reason = "each test walks the run's writer against the state table in order and a split would hide the sequence"
)]

use std::convert::Infallible;
use std::sync::Arc;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{
    ControlMessage, FatalError, FatalErrorReason, Handshake, Provenance, WriterRef, WriterRequest,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport as _};
use connetto_server::defaults::{_connetto_settled, _connetto_writers};
use connetto_server::writer_schema::SettlePath;
use connetto_server::{
    AbuseConfig, ManagerBuilder, Materializer, NoConnector, PageSpec, RequestGuard,
    RuntimeWritableCatalog, SessionConfig, SessionManager, SnapshotEstimate, SnapshotPage,
    SnapshotSource, ThrottleConfig, loopback, pg_write_target,
};
use connetto_test_harness::{Client, ConnettoDefaults, Fixture, RosterAuth};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sqlite_diff_rs::{ChangeSet, DiffOps, Insert, SimpleTable, Value};

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
        _caller: &connetto_core::auth::Principal,
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
        _auth: &connetto_core::auth::Principal,
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

/// Reset the fixture to a fresh `notes` table seeded with one row and the
/// writer tables provisioned by the admin.
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

/// The settled entries of a writer, read as admin, ordered by sequence.
async fn settled_count(pool: &Pool<AsyncPgConnection>, writer: i64) -> i64 {
    let mut conn = pool.get().await.expect("admin connection");
    _connetto_settled::table
        .filter(_connetto_settled::writer.eq(writer))
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count the settled rows")
}

/// One settled entry's path, read as admin, for the row at `seq`.
async fn settled_path(pool: &Pool<AsyncPgConnection>, writer: i64, seq: i64) -> Option<SettlePath> {
    let mut conn = pool.get().await.expect("admin connection");
    _connetto_settled::table
        .filter(_connetto_settled::writer.eq(writer))
        .filter(_connetto_settled::seq.eq(seq))
        .select(_connetto_settled::path)
        .first(&mut *conn)
        .await
        .ok()
}

/// A manager whose write policy admits the unnamed caller, so an anonymous
/// run reaches the database and the writer binding is what decides.
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
        RosterAuth::granting_nobody().and_the_unnamed_caller(),
        test_verifier(),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(pool.clone(), PG_DDL).expect("build write target"),
    )
    .with_session(session)
    .with_guard(guard)
    .build()
}

/// The durable-apply acknowledgement of `client_seq`.
async fn expect_applied(client: &mut Client, client_seq: u64) {
    let ControlMessage::MutationApplied(applied) = client.next_control().await else {
        panic!("expected write {client_seq} to apply");
    };
    assert_eq!(applied.client_seq, client_seq);
}

/// An anonymous handshake naming a number that the run does not hold. The
/// challenge leads, the fatal follows, and the reason is handed back.
async fn refused_anonymous_handshake(
    manager: &Arc<SessionManager<NoSnapshot, RosterAuth, ConnettoDefaults>>,
    client_id: &str,
    writer: WriterRequest,
) -> FatalError {
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, client_id).with_writer(writer),
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

/// A second anonymous run that names the first run's number is told it is
/// unknown, prunes nothing of it and retires nothing of it, and a copy that
/// names the number applies as a plain write. The owning run, resuming on its
/// own token, still confirms the number and retires it itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anonymous_run_cannot_reach_another_run_number() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default(),
        AbuseConfig::default(),
    ));
    let manager = writing_manager(fixture.admin(), guard, SessionConfig::default());

    // Run A: an anonymous caller issues a number and settles one entry.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_unidentified("anon-a").await;
    let number = ack
        .writer
        .expect("the anonymous handshake issues a number")
        .number;
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server.await.expect("join run A").expect("session ok");
    let db_number = i64::try_from(number).expect("the number fits");

    // Run B: a second anonymous run names the first run's number. It is told
    // unknown, and the owner's record stands untouched.
    let fatal =
        refused_anonymous_handshake(&manager, "anon-b", WriterRequest::Number(number)).await;
    assert!(
        matches!(fatal.reason, FatalErrorReason::WriterUnknown),
        "another run's number must close as unknown, got {:?}",
        fatal.reason
    );
    let facts = writer_facts(fixture.admin(), db_number).await;
    assert_eq!(facts.frontier, 1, "the owner's record stands");
    assert!(!facts.retired, "the foreign run retired nothing");
    assert_eq!(
        settled_count(fixture.admin(), db_number).await,
        1,
        "the owner's record is not pruned"
    );

    // Run B cannot prune the owner's records, its settle report never reaching
    // a number it does not hold.
    let fatal =
        refused_anonymous_handshake(&manager, "anon-b-prune", WriterRequest::Number(number)).await;
    assert!(
        matches!(fatal.reason, FatalErrorReason::WriterUnknown),
        "a foreign settle report is refused as unknown"
    );
    assert_eq!(
        settled_count(fixture.admin(), db_number).await,
        1,
        "a settle report from a foreign run prunes nothing"
    );

    // Run B cannot retire the owner's writer.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_unidentified("anon-b-retire").await;
    let answer = client.retire_writer("r1", WriterRef::Number(number)).await;
    assert_eq!(
        answer.outcome,
        connetto_core::messages::WriterOutcome::Unknown,
        "a foreign run retires nothing"
    );
    client.close().await;
    server
        .await
        .expect("join the retire run")
        .expect("session ok");
    assert!(
        !writer_facts(fixture.admin(), db_number).await.retired,
        "the writer still stands after a foreign retirement"
    );

    // Run B's copy that names the owner's writer settles nothing of it and
    // applies as a plain write.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake_unidentified("anon-b-copy").await;
    client
        .upload_with_provenance(
            1,
            insert_changeset(3, "three", "t2"),
            Some(Provenance {
                writer: WriterRef::Number(number),
                seq: 1,
            }),
        )
        .await;
    expect_applied(&mut client, 1).await;
    client.close().await;
    server
        .await
        .expect("join the copy run")
        .expect("session ok");
    assert_eq!(
        settled_count(fixture.admin(), db_number).await,
        1,
        "the copy settles nothing of the owner's writer"
    );
    assert_eq!(
        settled_path(fixture.admin(), db_number, 1).await,
        Some(SettlePath::Direct),
        "the owner's entry still stands direct"
    );
    assert!(
        notes(fixture.admin()).await.iter().any(|row| row.id == 3),
        "the copy that names a foreign writer applies as a plain write"
    );

    // Run A, resuming on its own token, still confirms the number and retires
    // it itself.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let resume_ack = client
        .handshake_writing(
            "anon-a-resume",
            &[],
            Some(&ack.resume_token),
            WriterRequest::Number(number),
            None,
        )
        .await;
    let grant = resume_ack
        .writer
        .expect("the resumed run confirms its number");
    assert_eq!(grant.number, number, "the resumed run names its own number");
    assert_eq!(
        grant.frontier, 1,
        "the resumed run answers the standing frontier"
    );
    let answer = client.retire_writer("r2", WriterRef::Number(number)).await;
    assert_eq!(
        answer.outcome,
        connetto_core::messages::WriterOutcome::Retired,
        "the owning run retires its own writer"
    );
    client.close().await;
    server
        .await
        .expect("join the resumed run")
        .expect("session ok");
    assert!(
        writer_facts(fixture.admin(), db_number).await.retired,
        "the owner's retirement stands"
    );
}
