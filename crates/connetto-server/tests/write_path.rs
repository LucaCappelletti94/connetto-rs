//! Phase 3 write-path acceptance tests.
//!
//! Drives a `MutationHeader` plus `MutationPatch` through a session over the
//! loopback transport and checks the four contracts: the happy path applies,
//! a stale version yields `MutationConflict`, an unauthorized write yields
//! `MutationReject`, and a replayed `client_seq` applies exactly once. The
//! target is a Docker-free SQLite connection whose `notes` table carries its
//! own version column (`edited_at`).

#![allow(clippy::too_many_lines)]

use std::convert::Infallible;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::auth::AuthContext;
use connetto_core::messages::{
    BulkMessage, ControlMessage, Handshake, MutationHeader, MutationPatch, MutationRejectReason,
    Ping,
};
use connetto_core::traits::{AuthPolicy, IncomingFrame, MutationOp, Transport};
use connetto_server::{
    Materializer, PermissiveAuth, RuntimeWritableCatalog, SessionConfig, SessionManager, Snapshot,
    SnapshotSource, SqliteWriteTarget, loopback, sqlite_write_target,
};
use diesel::prelude::*;
use diesel::sql_query;
use sqlite_diff_rs::{ChangeSet, ChangesetFormat, DiffOps, Insert, SimpleTable, Update, Value};

const PG_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT, edited_at TEXT);";
const SQLITE_DDL: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT, edited_at TEXT);";

/// No subscriptions are made in these tests, so the snapshot source is never
/// invoked.
struct NoSnapshot;

impl SnapshotSource for NoSnapshot {
    type Error = Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
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
        id -> diesel::sql_types::BigInt,
        body -> diesel::sql_types::Text,
        edited_at -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq)]
#[diesel(table_name = notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Note {
    id: i64,
    body: String,
    edited_at: String,
}

fn note(id: i64, body: &str, edited_at: &str) -> Note {
    Note {
        id,
        body: body.to_owned(),
        edited_at: edited_at.to_owned(),
    }
}

fn notes(target: &SqliteWriteTarget) -> Vec<Note> {
    let mut conn = target.lock();
    notes::table
        .order(notes::id)
        .select(Note::as_select())
        .load(&mut *conn)
        .expect("read notes")
}

/// A SQLite target seeded with one versioned row.
fn seeded_target() -> SqliteWriteTarget {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    diesel::insert_into(notes::table)
        .values((
            notes::id.eq(1_i64),
            notes::body.eq("hello"),
            notes::edited_at.eq("t0"),
        ))
        .execute(&mut conn)
        .expect("seed row");
    sqlite_write_target(conn)
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

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

/// Send a `MutationHeader` then its paired `MutationPatch`.
async fn upload<T: Transport>(transport: &mut T, client_seq: u64, changeset: Vec<u8>) {
    let payload = zstd::encode_all(changeset.as_slice(), 3).expect("compress changeset");
    transport
        .send_control(ControlMessage::MutationHeader(MutationHeader::new(
            client_seq, 1,
        )))
        .await
        .expect("send header");
    transport
        .send_bulk(BulkMessage::MutationPatch(MutationPatch::new(
            client_seq, payload,
        )))
        .await
        .expect("send patch");
}

/// Round-trip a ping. The server processes frames in order, so the returned
/// pong proves every preceding upload was fully handled.
async fn barrier<T: Transport>(transport: &mut T, nonce: u64) -> ControlMessage {
    transport
        .send_control(ControlMessage::Ping(Ping { nonce }))
        .await
        .expect("send ping");
    next_control(transport).await
}

async fn handshake<T: Transport>(transport: &mut T) {
    transport
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "writer",
            "token",
        )))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(transport).await else {
        panic!("expected handshake ack");
    };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_path_applies_conflicts_and_dedups() {
    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable_catalog()).expect("build materializer");
    let target = seeded_target();
    let manager = SessionManager::new(
        materializer,
        NoSnapshot,
        PermissiveAuth,
        target.clone(),
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));

    handshake(&mut client).await;

    // Happy insert: a new versioned row lands on the target.
    upload(&mut client, 1, insert_changeset(2, "new", "t1")).await;
    let ControlMessage::Pong(_) = barrier(&mut client, 1).await else {
        panic!("expected pong after insert");
    };
    assert_eq!(
        notes(&target),
        vec![note(1, "hello", "t0"), note(2, "new", "t1")]
    );

    // Happy update: basis edited_at t0 matches the server, so it applies.
    upload(
        &mut client,
        2,
        update_changeset(1, "hello", "updated", "t0", "t2"),
    )
    .await;
    let ControlMessage::Pong(_) = barrier(&mut client, 2).await else {
        panic!("expected pong after update");
    };
    assert_eq!(
        notes(&target),
        vec![note(1, "updated", "t2"), note(2, "new", "t1")]
    );

    // Stale update: basis edited_at t0 no longer matches (server is t2), so the
    // server reports a conflict carrying the current row and does not apply.
    upload(
        &mut client,
        3,
        update_changeset(1, "updated", "stale", "t0", "t3"),
    )
    .await;
    let ControlMessage::MutationConflict(conflict) = next_control(&mut client).await else {
        panic!("expected mutation conflict");
    };
    assert_eq!(conflict.client_seq, 3);
    assert_eq!(conflict.table, "notes");
    assert_eq!(conflict.server_updated_at, "t2");
    let current: serde_json::Value =
        serde_json::from_str(&conflict.server_row_json).expect("row json");
    assert_eq!(current["body"], "updated");
    assert_eq!(current["edited_at"], "t2");
    assert_eq!(
        notes(&target),
        vec![note(1, "updated", "t2"), note(2, "new", "t1")]
    );

    // Idempotency: the same client_seq applied twice inserts once. Without
    // dedup the second apply would collide on the primary key and reject.
    upload(&mut client, 4, insert_changeset(3, "three", "t4")).await;
    upload(&mut client, 4, insert_changeset(3, "three", "t4")).await;
    let ControlMessage::Pong(_) = barrier(&mut client, 9).await else {
        panic!("replayed mutation must be a silent no-op, not a reject");
    };
    assert_eq!(
        notes(&target),
        vec![
            note(1, "updated", "t2"),
            note(2, "new", "t1"),
            note(3, "three", "t4"),
        ]
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_path_rejects_unauthorized() {
    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable_catalog()).expect("build materializer");
    let target = seeded_target();
    let manager = SessionManager::new(
        materializer,
        NoSnapshot,
        DenyAuth,
        target.clone(),
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));

    handshake(&mut client).await;

    upload(&mut client, 1, insert_changeset(2, "new", "t1")).await;
    let ControlMessage::MutationReject(reject) = next_control(&mut client).await else {
        panic!("expected mutation reject");
    };
    assert_eq!(reject.client_seq, 1);
    assert_eq!(reject.reason, MutationRejectReason::Unauthorized);
    // Nothing applied: the seed row is untouched and no new row appeared.
    assert_eq!(notes(&target), vec![note(1, "hello", "t0")]);

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}
