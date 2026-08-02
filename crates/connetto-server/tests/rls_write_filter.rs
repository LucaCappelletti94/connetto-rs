//! Docker-gated Row-Level Security write-path test.
//!
//! Drives client mutations through a session whose write target is the source
//! Postgres, applying under the requesting user's RLS context via
//! `SET LOCAL app.user_id`. An insert the user is allowed to own lands; an
//! insert naming another owner is refused by the policy's `WITH CHECK` and comes
//! back as `MutationReject`, leaving Postgres unchanged.
//!
//! `#[ignore]` by default. It needs a running Postgres. Point `DATABASE_URL` at
//! one and run with `--ignored` after explicit approval.
//!
//! Like the read filter, the write must apply as a non-superuser role, since a
//! superuser bypasses RLS. The test creates `app_writer` for the write target
//! and does privileged setup as the admin role.

#![allow(clippy::too_many_lines)]

use std::convert::Infallible;
use std::sync::Arc;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{
    BulkMessage, ControlMessage, Handshake, MutationHeader, MutationPatch, Ping,
};
use connetto_core::test_support::TestSessionVerifier;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{
    Materializer, PermissiveAuth, RuntimeWritableCatalog, SessionConfig, SessionManager, Snapshot,
    SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::ConnettoWatermark;
use diesel::QueryableByName;
use diesel::sql_query;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sqlite_diff_rs::{ChangeSet, DiffOps, Insert, SimpleTable, Value};

const PG_DDL: &str =
    "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT, edited_at TEXT);";

fn admin_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned())
}

/// Rewrite a Postgres URL's user info, keeping host, port, and database.
fn with_user(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("url has a scheme");
    let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    format!("{scheme}://{user}:{password}@{host}")
}

async fn pool_for(url: &str) -> Pool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.to_owned());
    Pool::builder().build(manager).await.expect("build pool")
}

async fn exec(pool: &Pool<AsyncPgConnection>, sql: &str) {
    let mut conn = pool.get().await.expect("admin connection");
    sql_query(sql)
        .execute(&mut *conn)
        .await
        .unwrap_or_else(|err| panic!("statement failed ({sql}): {err}"));
}

/// The `(id, owner)` rows in `notes`, read as admin so RLS does not hide any.
async fn notes(pool: &Pool<AsyncPgConnection>) -> Vec<(i32, String)> {
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type = diesel::sql_types::Integer)]
        id: i32,
        #[diesel(sql_type = diesel::sql_types::Text)]
        owner: String,
    }
    let mut conn = pool.get().await.expect("admin connection");
    let rows: Vec<Row> = sql_query("SELECT id, owner FROM notes ORDER BY id")
        .load(&mut *conn)
        .await
        .expect("read notes");
    rows.into_iter().map(|row| (row.id, row.owner)).collect()
}

/// A snapshot source that is never invoked (no subscriptions).
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

/// A changeset inserting one fully-specified `notes` row.
fn insert_changeset(id: i64, owner: &str, body: &str, edited_at: &str) -> Vec<u8> {
    let table = SimpleTable::new("notes", &["id", "owner", "body", "edited_at"], &[0]);
    let insert = Insert::<_, String, Vec<u8>>::from(table)
        .set(0, Value::Integer(id))
        .expect("set id")
        .set(1, Value::Text(owner.to_owned()))
        .expect("set owner")
        .set(2, Value::Text(body.to_owned()))
        .expect("set body")
        .set(3, Value::Text(edited_at.to_owned()))
        .expect("set edited_at");
    ChangeSet::<SimpleTable, String, Vec<u8>>::new()
        .insert(insert)
        .build()
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

async fn handshake<T: Transport>(transport: &mut T, client_id: &str) {
    transport
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            client_id,
            // Identity is resolved from the token, so the trusting verifier
            // maps this to app.user_id under RLS.
            client_id,
        )))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(transport).await else {
        panic!("expected handshake ack");
    };
}

async fn upload<T: Transport>(transport: &mut T, client_seq: u64, changeset: Vec<u8>) {
    let payload = zstd::encode_all(changeset.as_slice(), 3).expect("compress");
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

/// Ping and return the next control frame. A pong proves every preceding frame
/// was handled; a reject for an earlier upload arrives before it.
async fn barrier<T: Transport>(transport: &mut T, nonce: u64) -> ControlMessage {
    transport
        .send_control(ControlMessage::Ping(Ping { nonce }))
        .await
        .expect("send ping");
    next_control(transport).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn rls_write_filter_applies_owned_and_refuses_foreign() {
    let url = admin_url();
    let admin = pool_for(&url).await;
    let setup: Vec<String> = vec![
        "DROP TABLE IF EXISTS notes CASCADE".to_owned(),
        // Stale per-client watermarks would suppress replayed uploads.
        "DROP TABLE IF EXISTS _connetto_mutations".to_owned(),
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
         THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$"
            .to_owned(),
        "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT, edited_at TEXT)".to_owned(),
        "ALTER TABLE notes ENABLE ROW LEVEL SECURITY".to_owned(),
        "CREATE POLICY notes_p ON notes USING (owner = current_setting('app.user_id', true))"
            .to_owned(),
        "GRANT USAGE ON SCHEMA public TO app_writer".to_owned(),
        "GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO app_writer".to_owned(),
    ];
    for stmt in setup {
        exec(&admin, &stmt).await;
    }
    // The watermark table is provisioned by the admin, like a deployment
    // would: the restricted writer role cannot CREATE in schema public and
    // only needs DML on it.
    connetto_test_harness::provision_watermark(&admin).await;
    exec(
        &admin,
        "GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_writer",
    )
    .await;

    let writer_pool = pool_for(&with_user(&url, "app_writer", "app_writer")).await;
    let materializer = Materializer::with_write_catalog(
        PG_DDL,
        RuntimeWritableCatalog::builder()
            .versioned("notes", "edited_at")
            .build(),
    )
    .expect("build materializer");
    let target =
        pg_write_target::<ConnettoWatermark>(writer_pool, PG_DDL).expect("build write target");
    let manager = SessionManager::new(
        materializer,
        NoSnapshot,
        PermissiveAuth,
        Arc::new(TestSessionVerifier),
        target,
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));

    // The session's identity is the verified token, bound into app.user_id.
    handshake(&mut client, "alice").await;

    // Alice may insert a row she owns: it lands, acknowledged by the durable
    // apply ack, and the barrier pong confirms nothing else was in flight.
    upload(&mut client, 1, insert_changeset(1, "alice", "mine", "t1")).await;
    match next_control(&mut client).await {
        ControlMessage::MutationApplied(applied) => assert_eq!(applied.client_seq, 1),
        other => panic!("owned insert should apply, got {other:?}"),
    }
    match barrier(&mut client, 1).await {
        ControlMessage::Pong(_) => {}
        other => panic!("expected pong after the apply ack, got {other:?}"),
    }

    // Alice may not insert a row owned by someone else: the policy's WITH CHECK
    // refuses it and the server replies with a reject before the pong.
    upload(&mut client, 2, insert_changeset(2, "bob", "theirs", "t1")).await;
    match next_control(&mut client).await {
        ControlMessage::MutationReject(reject) => assert_eq!(reject.client_seq, 2),
        other => panic!("foreign insert should be rejected, got {other:?}"),
    }
    match barrier(&mut client, 2).await {
        ControlMessage::Pong(_) => {}
        other => panic!("expected pong after reject, got {other:?}"),
    }

    // Postgres holds only the owned row.
    assert_eq!(notes(&admin).await, vec![(1, "alice".to_owned())]);

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}
