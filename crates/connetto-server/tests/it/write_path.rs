//! Docker-gated write-path acceptance tests.
//!
//! Drives a `MutationHeader` plus `MutationPatch` through a session over the
//! loopback transport against the real Postgres write target and checks the
//! four contracts: the happy path applies, a stale version yields
//! `MutationConflict`, an unauthorized write yields `MutationReject`, and a
//! replayed `client_seq` applies exactly once. The write lands in Postgres and
//! is read back through the admin pool; the `notes` table carries its own
//! version column (`edited_at`). A database the write cannot reach is retried
//! within the write budget, then answered `Indeterminate` with every later
//! write of the connection held behind it.
//!
//! Needs Docker: the fixture starts its own Postgres.

#![expect(
    clippy::too_many_lines,
    reason = "the test walks its scenario in order and a split would hide the sequence"
)]

use connetto_core::auth::Principal;
use connetto_core::messages::{ControlMessage, MutationRejectReason};
use connetto_core::test_support::TestGrantChecker;
use connetto_server::{
    Materializer, PageSpec, RequestGuard, RuntimeWritableCatalog, SessionConfig, SessionManager,
    SnapshotEstimate, SnapshotPage, SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{Client, ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use sqlite_diff_rs::{ChangeSet, ChangesetFormat, DiffOps, Insert, SimpleTable, Update, Value};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use subql::backend::Postgres;
use subql::visibility::{RowView, RowWrite, Verdict, VisibilityPolicy};

const PG_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT, edited_at TEXT);";

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

/// A policy that denies every write, to exercise the reject path.
struct DenyAuth;

impl VisibilityPolicy for DenyAuth {
    type Watcher = std::sync::Arc<Principal>;
    type Error = Infallible;
    type Backend = Postgres;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn may_see<R>(
        &self,
        _row: &R,
        _watchers: &[Self::Watcher],
        _verdicts: &mut [Verdict],
    ) -> Result<(), Infallible>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        Ok(())
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn may_write<R>(
        &self,
        _write: RowWrite<'_, R>,
        _watcher: &Self::Watcher,
    ) -> Result<Verdict, Infallible>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        Ok(Verdict::Deny)
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

/// The `notes` rows, read through the admin pool. Typed DSL against the `notes`
/// `table!`, checked at compile time.
async fn notes(pool: &Pool<AsyncPgConnection>) -> Vec<Note> {
    let mut conn = pool.get().await.expect("admin connection");
    notes::table
        .order(notes::id)
        .select(Note::as_select())
        .load(&mut *conn)
        .await
        .expect("read notes")
}

/// Reset the fixture to a fresh `notes` table seeded with one versioned row and
/// the watermark table provisioned by the admin.
async fn seed_notes(fixture: &Fixture) {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS notes CASCADE",
            "DROP TABLE IF EXISTS _connetto_mutations",
            "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT, edited_at TEXT)",
        ])
        .await;
    connetto_test_harness::provision_watermark(fixture.admin()).await;
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

/// A changeset that updates one row, carrying the old image (the version basis).
fn update_changeset(
    id: i64,
    old_body: &str,
    new_body: &str,
    old_edited_at: &str,
    new_edited_at: &str,
) -> Vec<u8> {
    let update = Update::<_, ChangesetFormat, String, Vec<u8>>::from(note_table())
        .set(0, Value::Integer(id), Value::Integer(id))
        .expect("set id")
        .set(
            1,
            Value::Text(old_body.to_owned()),
            Value::Text(new_body.to_owned()),
        )
        .expect("set body")
        .set(
            2,
            Value::Text(old_edited_at.to_owned()),
            Value::Text(new_edited_at.to_owned()),
        )
        .expect("set edited_at");
    ChangeSet::<SimpleTable, String, Vec<u8>>::new()
        .update(update)
        .build()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_path_applies_conflicts_and_dedups() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;

    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable_catalog()).expect("build materializer");
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::new(
        materializer,
        NoSnapshot,
        RosterAuth::granting("writer").withholding(WITHHELD_ID),
        test_verifier(),
        target,
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);

    client.handshake("writer").await;

    // Happy insert: a new versioned row lands in Postgres and the durable apply
    // is acknowledged.
    client.upload(1, insert_changeset(2, "new", "t1")).await;
    let ControlMessage::MutationApplied(ack) = client.next_control().await else {
        panic!("expected the durable-apply acknowledgement");
    };
    assert_eq!(ack.client_seq, 1);
    let ControlMessage::Pong(_) = client.barrier(1).await else {
        panic!("expected pong after insert");
    };
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "new", "t1")]
    );

    // Happy update: basis edited_at t0 matches the server, so it applies.
    client
        .upload(2, update_changeset(1, "hello", "updated", "t0", "t2"))
        .await;
    let ControlMessage::MutationApplied(ack) = client.next_control().await else {
        panic!("expected the durable-apply acknowledgement");
    };
    assert_eq!(ack.client_seq, 2);
    let ControlMessage::Pong(_) = client.barrier(2).await else {
        panic!("expected pong after update");
    };
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "updated", "t2"), note(2, "new", "t1")]
    );

    // Stale update: basis edited_at t0 no longer matches (server is t2), so the
    // server reports a conflict carrying the current row and does not apply.
    client
        .upload(3, update_changeset(1, "updated", "stale", "t0", "t3"))
        .await;
    let ControlMessage::MutationConflict(conflict) = client.next_control().await else {
        panic!("expected mutation conflict");
    };
    assert_eq!(conflict.client_seq, 3);
    assert_eq!(conflict.table, "notes");
    let row = conflict
        .server_row
        .expect("the conflicting row still exists");
    assert_eq!(row.updated_at, "t2");
    let current: serde_json::Value = serde_json::from_str(&row.row_json).expect("row json");
    assert_eq!(current["body"], "updated");
    assert_eq!(current["edited_at"], "t2");
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "updated", "t2"), note(2, "new", "t1")]
    );

    // Exactly-once: the same client_seq applied twice inserts once, and the
    // replay is re-acknowledged from the durable watermark instead of colliding
    // on the primary key.
    client.upload(4, insert_changeset(3, "three", "t4")).await;
    client.upload(4, insert_changeset(3, "three", "t4")).await;
    let ControlMessage::MutationApplied(first) = client.next_control().await else {
        panic!("expected the durable-apply acknowledgement");
    };
    assert_eq!(first.client_seq, 4);
    let ControlMessage::MutationApplied(replayed) = client.next_control().await else {
        panic!("a replayed mutation is re-acknowledged, not rejected");
    };
    assert_eq!(replayed.client_seq, 4);
    let ControlMessage::Pong(_) = client.barrier(9).await else {
        panic!("expected pong after the replay");
    };
    assert_eq!(
        notes(fixture.admin()).await,
        vec![
            note(1, "updated", "t2"),
            note(2, "new", "t1"),
            note(3, "three", "t4"),
        ]
    );

    client
        .upload(5, insert_changeset(WITHHELD_ID, "withheld", "tw"))
        .await;
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected rejection of withheld-row write");
    };
    assert_eq!(reject.client_seq, 5);
    assert_eq!(reject.reason, MutationRejectReason::Unauthorized);
    assert!(
        !notes(fixture.admin())
            .await
            .iter()
            .any(|n| i64::from(n.id) == WITHHELD_ID),
        "withheld row must not appear in Postgres"
    );

    client.close().await;
    server.await.expect("join server").expect("session ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_path_rejects_unauthorized() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;

    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable_catalog()).expect("build materializer");
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::new(
        materializer,
        NoSnapshot,
        DenyAuth,
        test_verifier(),
        target,
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);

    client.handshake("writer").await;

    client.upload(1, insert_changeset(2, "new", "t1")).await;
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected mutation reject");
    };
    assert_eq!(reject.client_seq, 1);
    assert_eq!(reject.reason, MutationRejectReason::Unauthorized);
    // Nothing applied: the seed row is untouched and no new row appeared.
    assert_eq!(notes(fixture.admin()).await, vec![note(1, "hello", "t0")]);

    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// Exactly-once survives a transport reconnect that reuses the verified session.
///
/// This is the Phase 3 acceptance: the watermark keys on the connetto-minted
/// session id from the verified token, not the client-fabricated `client_id`.
/// A first connection commits mutations, the transport is torn down, and a
/// second connection mints a DIFFERENT `client_id` (a worker restart or leader
/// failover) but presents the SAME token. Its handshake reports the surviving
/// watermark and the replayed uploads are re-acknowledged without re-applying,
/// so no primary-key collision occurs. A genuinely different token is a new
/// session and correctly starts fresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watermark_survives_reconnect_reusing_session() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;

    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable_catalog()).expect("build materializer");
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::new(
        materializer,
        NoSnapshot,
        RosterAuth::granting("alice")
            .and("bob")
            .withholding(WITHHELD_ID),
        test_verifier(),
        target,
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    // Connection 1: a fresh session for token "alice" commits two inserts.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("worker-boot-1", "user:alice").await;
    assert_eq!(
        ack.last_applied_seq, None,
        "a fresh session has no watermark"
    );
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    client.upload(2, insert_changeset(3, "three", "t2")).await;
    for expected in [1, 2] {
        let ControlMessage::MutationApplied(applied) = client.next_control().await else {
            panic!("expected the durable-apply acknowledgement");
        };
        assert_eq!(applied.client_seq, expected);
    }
    let ControlMessage::Pong(_) = client.barrier(1).await else {
        panic!("expected pong after the first session's writes");
    };
    assert_eq!(
        notes(fixture.admin()).await,
        vec![
            note(1, "hello", "t0"),
            note(2, "two", "t1"),
            note(3, "three", "t2"),
        ]
    );
    client.close().await;
    server.await.expect("join server 1").expect("session 1 ok");

    // Connection 2: a NEW client id but the SAME token. The watermark survived
    // the reconnect because it is keyed on the verified session, so the ack
    // reports it and the replayed uploads are deduped, never re-applied (a
    // re-applied INSERT would collide on the primary key and be rejected).
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("worker-boot-2", "user:alice").await;
    assert_eq!(
        ack.last_applied_seq,
        Some(2),
        "the same session's watermark survives a transport reconnect"
    );
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    client.upload(2, insert_changeset(3, "three", "t2")).await;
    for expected in [1, 2] {
        let ControlMessage::MutationApplied(applied) = client.next_control().await else {
            panic!("a replayed mutation is re-acknowledged, not rejected");
        };
        assert_eq!(applied.client_seq, expected);
    }
    // A genuinely new sequence still applies on the reused session.
    client.upload(3, insert_changeset(4, "four", "t3")).await;
    let ControlMessage::MutationApplied(applied) = client.next_control().await else {
        panic!("expected the durable-apply acknowledgement for the new sequence");
    };
    assert_eq!(applied.client_seq, 3);
    let ControlMessage::Pong(_) = client.barrier(2).await else {
        panic!("expected pong after the reconnect's writes");
    };
    assert_eq!(
        notes(fixture.admin()).await,
        vec![
            note(1, "hello", "t0"),
            note(2, "two", "t1"),
            note(3, "three", "t2"),
            note(4, "four", "t3"),
        ],
        "the replay applied nothing new: exactly-once held across the reconnect"
    );
    client
        .upload(4, insert_changeset(WITHHELD_ID, "withheld", "tw"))
        .await;
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected rejection of withheld-row write");
    };
    assert_eq!(reject.client_seq, 4);
    assert_eq!(reject.reason, MutationRejectReason::Unauthorized);
    assert!(
        !notes(fixture.admin())
            .await
            .iter()
            .any(|n| i64::from(n.id) == WITHHELD_ID),
        "withheld row must not appear in Postgres"
    );

    client.close().await;
    server.await.expect("join server 2").expect("session 2 ok");

    // Connection 3: a different token is a different session and starts fresh.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("worker-boot-3", "user:bob").await;
    assert_eq!(
        ack.last_applied_seq, None,
        "a different session carries its own watermark"
    );
    client.close().await;
    server.await.expect("join server 3").expect("session 3 ok");
}

/// A one-connection write pool whose checkout gives up quickly, so a test holding its connection is an unreachable database.
async fn single_connection_pool(fixture: &Fixture) -> Pool<AsyncPgConnection> {
    Pool::builder()
        .max_size(1)
        .connection_timeout(Duration::from_millis(100))
        .build(AsyncDieselConnectionManager::new(fixture.admin_url()))
        .await
        .expect("build the write pool")
}

fn writing_manager(
    pool: &Pool<AsyncPgConnection>,
    config: SessionConfig,
) -> Arc<SessionManager<NoSnapshot, RosterAuth, ConnettoWatermark>> {
    SessionManager::new(
        Materializer::with_write_catalog(PG_DDL, writable_catalog()).expect("build materializer"),
        NoSnapshot,
        RosterAuth::granting("writer").withholding(WITHHELD_ID),
        test_verifier(),
        pg_write_target::<ConnettoWatermark>(pool.clone(), PG_DDL).expect("build write target"),
        Arc::new(RequestGuard::default()),
        config,
    )
}

async fn expect_indeterminate(client: &mut Client, client_seq: u64) {
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected write {client_seq} to be refused");
    };
    assert_eq!(
        (reject.client_seq, reject.reason),
        (client_seq, MutationRejectReason::Indeterminate)
    );
}

async fn expect_applied(client: &mut Client, client_seq: u64) {
    let ControlMessage::MutationApplied(applied) = client.next_control().await else {
        panic!("expected write {client_seq} to apply");
    };
    assert_eq!(applied.client_seq, client_seq);
}

/// A database unreachable past the retry budget answers `Indeterminate`, and no later write of the connection applies ahead of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_database_defers_the_write_and_every_later_one() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let pool = single_connection_pool(&fixture).await;
    let manager = writing_manager(
        &pool,
        SessionConfig::default().with_write_retry_budget(Duration::from_millis(500)),
    );
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake("writer").await;

    let outage = pool.get_owned().await.expect("hold the only connection");
    client.upload(1, insert_changeset(2, "first", "t1")).await;
    expect_indeterminate(&mut client, 1).await;
    client.upload(2, insert_changeset(3, "second", "t2")).await;
    expect_indeterminate(&mut client, 2).await;
    drop(outage);

    // Applying 2 first would raise the watermark past 1, and a resent 1 would then be acknowledged unapplied.
    client.upload(2, insert_changeset(3, "second", "t2")).await;
    expect_indeterminate(&mut client, 2).await;
    assert_eq!(notes(fixture.admin()).await, vec![note(1, "hello", "t0")]);

    client.upload(1, insert_changeset(2, "first", "t1")).await;
    expect_applied(&mut client, 1).await;
    client.upload(2, insert_changeset(3, "second", "t2")).await;
    expect_applied(&mut client, 2).await;
    assert_eq!(
        notes(fixture.admin()).await,
        vec![
            note(1, "hello", "t0"),
            note(2, "first", "t1"),
            note(3, "second", "t2"),
        ]
    );

    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// An outage shorter than the retry budget costs the client nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_brief_outage_is_retried_through() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let pool = single_connection_pool(&fixture).await;
    let manager = writing_manager(&pool, SessionConfig::default());
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake("writer").await;

    let outage = pool.get_owned().await.expect("hold the only connection");
    let recovery = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        drop(outage);
    });
    client.upload(1, insert_changeset(2, "patient", "t1")).await;
    expect_applied(&mut client, 1).await;
    recovery.await.expect("join recovery");
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "patient", "t1")]
    );

    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// A deferred write that comes back refused is settled, so the writes behind it apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deferred_write_settled_by_a_refusal_releases_the_writes_behind_it() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let pool = single_connection_pool(&fixture).await;
    let manager = writing_manager(
        &pool,
        SessionConfig::default().with_write_retry_budget(Duration::ZERO),
    );
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake("writer").await;

    let outage = pool.get_owned().await.expect("hold the only connection");
    client.upload(1, insert_changeset(2, "first", "t1")).await;
    expect_indeterminate(&mut client, 1).await;
    drop(outage);

    // The same sequence comes back naming a row the caller may not write, as after a grant was withdrawn.
    client
        .upload(1, insert_changeset(WITHHELD_ID, "withheld", "tw"))
        .await;
    let ControlMessage::MutationReject(reject) = client.next_control().await else {
        panic!("expected the resent write to be refused");
    };
    assert_eq!(reject.reason, MutationRejectReason::Unauthorized);
    client.upload(2, insert_changeset(3, "second", "t2")).await;
    expect_applied(&mut client, 2).await;

    client.close().await;
    server.await.expect("join server").expect("session ok");
}

/// The apply asks the durable watermark itself, so a commit that landed while its answer was lost is acknowledged again rather than applied twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_the_durable_watermark_covers_is_acknowledged_unapplied() {
    let fixture = Fixture::acquire().await;
    seed_notes(&fixture).await;
    let manager = writing_manager(fixture.admin(), SessionConfig::default());
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    client.handshake("writer").await;
    client.upload(1, insert_changeset(2, "two", "t1")).await;
    expect_applied(&mut client, 1).await;

    // Stands in for a commit of 2 whose reply never reached this connection.
    fixture
        .setup(&["UPDATE _connetto_mutations SET last_seq = 2"])
        .await;
    client.upload(2, insert_changeset(3, "three", "t2")).await;
    expect_applied(&mut client, 2).await;
    assert_eq!(
        notes(fixture.admin()).await,
        vec![note(1, "hello", "t0"), note(2, "two", "t1")]
    );

    client.close().await;
    server.await.expect("join server").expect("session ok");
}
