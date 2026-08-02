//! Docker-gated write-path acceptance tests.
//!
//! Drives a `MutationHeader` plus `MutationPatch` through a session over the
//! loopback transport against the real Postgres write target and checks the
//! four contracts: the happy path applies, a stale version yields
//! `MutationConflict`, an unauthorized write yields `MutationReject`, and a
//! replayed `client_seq` applies exactly once. The write lands in Postgres and
//! is read back through the admin pool; the `notes` table carries its own
//! version column (`edited_at`).
//!
//! `#[ignore]` by default: it needs a running Postgres. Point `DATABASE_URL` at
//! one and run with `--ignored` under Docker.

#![allow(clippy::too_many_lines)]

use std::convert::Infallible;
use std::sync::Arc;

use connetto_core::auth::AuthContext;
use connetto_core::messages::{ControlMessage, MutationRejectReason};
use connetto_core::test_support::TestSessionVerifier;
use connetto_core::traits::{AuthPolicy, MutationOp, SessionVerifier};
use connetto_server::{
    Materializer, PermissiveAuth, RuntimeWritableCatalog, SessionConfig, SessionManager, Snapshot,
    SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{Client, ConnettoWatermark, Fixture};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::bb8::Pool;
use sqlite_diff_rs::{ChangeSet, ChangesetFormat, DiffOps, Insert, SimpleTable, Update, Value};

const PG_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT, edited_at TEXT);";

fn test_verifier() -> Arc<dyn SessionVerifier> {
    Arc::new(TestSessionVerifier)
}
/// No subscriptions are made in these tests, so the snapshot source is never
/// invoked.
struct NoSnapshot;

impl SnapshotSource for NoSnapshot {
    type Error = Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::AuthContext,
    ) -> Result<Snapshot, Self::Error> {
        Ok(Snapshot {
            patchset: Vec::new(),
            cursor: connetto_core::Cursor::new(Vec::new()),
        })
    }
}

/// An auth policy that denies every write, to exercise the reject path.
struct DenyAuth;

impl AuthPolicy for DenyAuth {
    type Error = Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn can_read(
        &self,
        _ctx: &AuthContext,
        _table: &str,
        _pk: &[u8],
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn can_write(
        &self,
        _ctx: &AuthContext,
        _table: &str,
        _pk: &[u8],
        _op: MutationOp,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

diesel::table! {
    notes (id) {
        id -> diesel::sql_types::Integer,
        body -> diesel::sql_types::Text,
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
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
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
        PermissiveAuth,
        test_verifier(),
        target,
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

    client.close().await;
    server.await.expect("join server").expect("session ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
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
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
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
        PermissiveAuth,
        test_verifier(),
        target,
        SessionConfig::default(),
    );

    // Connection 1: a fresh session for token "alice" commits two inserts.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("worker-boot-1", "alice").await;
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
    let ack = client.handshake_with("worker-boot-2", "alice").await;
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
    client.close().await;
    server.await.expect("join server 2").expect("session 2 ok");

    // Connection 3: a different token is a different session and starts fresh.
    let (server_transport, client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    let mut client = Client::new(client);
    let ack = client.handshake_with("worker-boot-3", "bob").await;
    assert_eq!(
        ack.last_applied_seq, None,
        "a different session carries its own watermark"
    );
    client.close().await;
    server.await.expect("join server 3").expect("session 3 ok");
}
