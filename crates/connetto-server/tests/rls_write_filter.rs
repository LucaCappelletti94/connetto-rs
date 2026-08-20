//! Docker-gated Row-Level Security write-path test.
//!
//! Drives client mutations through a session whose write target is the source
//! Postgres, applying under the requesting user's RLS context via
//! `SET LOCAL app.user_id`. An insert the user is allowed to own lands; an
//! insert naming another owner is refused by the policy's `WITH CHECK` and comes
//! back as `MutationReject`, leaving Postgres unchanged.
//!
//! Needs Docker: the fixture starts its own Postgres.
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
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::{
    Materializer, RequestGuard, RuntimeWritableCatalog, SessionConfig, SessionManager, Snapshot,
    SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};
use diesel::QueryableByName;
use diesel::sql_query;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use sqlite_diff_rs::{ChangeSet, ChangesetFormat, DiffOps, Insert, SimpleTable, Update, Value};

const PG_DDL: &str =
    "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT, edited_at TEXT);";

/// Shared setup for both tests. `Fixture` holds the process-wide serialization
/// lock, so the two do not race each other's `DROP TABLE notes`, and it
/// provisions `_connetto_mutations` fresh, which the writer role is granted on
/// below.
async fn setup(fixture: &Fixture) -> Pool<AsyncPgConnection> {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS notes CASCADE",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
             THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$",
            "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT, edited_at TEXT)",
            "ALTER TABLE notes ENABLE ROW LEVEL SECURITY",
            // The union: a row you own, or a row owned by a share key you hold.
            // A caller holding no key leaves `app.subjects` unset, so
            // `string_to_array` yields NULL and the second disjunct is NULL
            // rather than true.
            "CREATE POLICY notes_p ON notes USING ( \
               owner = current_setting('app.user_id', true) \
               OR owner = ANY(string_to_array(current_setting('app.subjects', true), ',')))",
            "GRANT USAGE ON SCHEMA public TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO app_writer",
            "GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_writer",
        ])
        .await;
    pool_for(&with_user(fixture.admin_url(), "app_writer", "app_writer")).await
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
        _auth: &connetto_core::Principal,
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

/// A changeset that reassigns one row's owner, carrying the old image so the
/// version basis and the pre-update owner both reach Postgres.
fn reassign_changeset(id: i64, old_owner: &str, new_owner: &str, edited_at: &str) -> Vec<u8> {
    let table = SimpleTable::new("notes", &["id", "owner", "body", "edited_at"], &[0]);
    let update = Update::<_, ChangesetFormat, String, Vec<u8>>::from(table)
        .set(0, Value::Integer(id), Value::Integer(id))
        .expect("set id")
        .set(
            1,
            Value::Text(old_owner.to_owned()),
            Value::Text(new_owner.to_owned()),
        )
        .expect("set owner")
        .set(
            2,
            Value::Text("mine".to_owned()),
            Value::Text("mine".to_owned()),
        )
        .expect("set body")
        .set(
            3,
            Value::Text(edited_at.to_owned()),
            Value::Text(edited_at.to_owned()),
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

async fn handshake<T: Transport>(transport: &mut T, client_id: &str) {
    // The verified grant's user_id becomes app.user_id under RLS.
    handshake_with(transport, client_id, &[&format!("user:{client_id}")]).await;
}

async fn handshake_with<T: Transport>(transport: &mut T, client_id: &str, grants: &[&str]) {
    transport
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, client_id).with_grants(
                grants
                    .iter()
                    .map(|grant| connetto_core::messages::Grant::new(*grant)),
            ),
        ))
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
async fn rls_write_filter_applies_owned_and_refuses_foreign() {
    let fixture = Fixture::acquire().await;
    let admin = fixture.admin().clone();
    let writer_pool = setup(&fixture).await;
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
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        target,
        Arc::new(RequestGuard::default()),
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

    // The stand-in refuses the withheld key. The owner is "alice" so Postgres
    // would permit it, and refusal comes from the roster alone.
    upload(
        &mut client,
        3,
        insert_changeset(WITHHELD_ID, "alice", "withheld", "t1"),
    )
    .await;
    match next_control(&mut client).await {
        ControlMessage::MutationReject(reject) => assert_eq!(reject.client_seq, 3),
        other => panic!("stand-in must refuse the withheld key, got {other:?}"),
    }
    match barrier(&mut client, 3).await {
        ControlMessage::Pong(_) => {}
        other => panic!("expected pong after withheld reject, got {other:?}"),
    }

    // Postgres holds only the owned row.
    assert_eq!(notes(&admin).await, vec![(1, "alice".to_owned())]);

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}

/// A write that moves the row out of the writer's own reach is refused.
///
/// Alice owns note 1 and may edit it. Reassigning its `owner` to Bob passes the
/// policy on the row she is holding and fails it on the row she would leave
/// behind, because a `FOR ALL` policy's `USING` clause doubles as its
/// `WITH CHECK`. This is the update counterpart of the foreign-insert case: the
/// insert is refused for a row she never owned, this one for a row she owns
/// right up until the statement lands. Postgres must keep the original owner,
/// because a half-applied handoff would strand the row with nobody able to see
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rls_write_filter_refuses_handing_a_row_to_another_owner() {
    let fixture = Fixture::acquire().await;
    let admin = fixture.admin().clone();
    let writer_pool = setup(&fixture).await;
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
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        target,
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    handshake(&mut client, "alice").await;

    upload(&mut client, 1, insert_changeset(1, "alice", "mine", "t1")).await;
    match next_control(&mut client).await {
        ControlMessage::MutationApplied(applied) => assert_eq!(applied.client_seq, 1),
        other => panic!("alice must be able to insert her own row, got {other:?}"),
    }

    upload(&mut client, 2, reassign_changeset(1, "alice", "bob", "t1")).await;
    match next_control(&mut client).await {
        ControlMessage::MutationReject(reject) => assert_eq!(reject.client_seq, 2),
        other => panic!("handing the row to bob should be rejected, got {other:?}"),
    }
    match barrier(&mut client, 1).await {
        ControlMessage::Pong(_) => {}
        other => panic!("expected pong after the reject, got {other:?}"),
    }

    // The stand-in refuses the withheld key. The owner is "alice" so Postgres
    // would permit it, and refusal comes from the roster alone.
    upload(
        &mut client,
        3,
        insert_changeset(WITHHELD_ID, "alice", "withheld", "t1"),
    )
    .await;
    match next_control(&mut client).await {
        ControlMessage::MutationReject(reject) => assert_eq!(reject.client_seq, 3),
        other => panic!("stand-in must refuse the withheld key, got {other:?}"),
    }
    match barrier(&mut client, 3).await {
        ControlMessage::Pong(_) => {}
        other => panic!("expected pong after withheld reject, got {other:?}"),
    }

    // The row is untouched, so nothing was left half-applied.
    assert_eq!(notes(&admin).await, vec![(1, "alice".to_owned())]);

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}

/// Row two of the arrival table: a caller with no identity writes where a
/// capability allows it, and nowhere otherwise (R4).
///
/// The same caller sends the same insert twice, once presenting nothing and
/// once presenting the key. Only the difference in what was presented can
/// explain the difference in outcome, which is what makes this an assertion
/// about the capability rather than about the policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unidentified_caller_writes_under_a_capability_and_not_without_one() {
    const KEY: &str = "key:can-write-here";

    let fixture = Fixture::acquire().await;
    let admin = fixture.admin().clone();
    let writer_pool = setup(&fixture).await;
    let build = || {
        let materializer = Materializer::with_write_catalog(
            PG_DDL,
            RuntimeWritableCatalog::builder()
                .versioned("notes", "edited_at")
                .build(),
        )
        .expect("build materializer");
        SessionManager::new(
            materializer,
            NoSnapshot,
            // Admit the unnamed caller so the seq-1 refusal comes from Postgres, not from
            // here. If the stand-in refused it, both inserts would fail the same way and
            // the test would prove nothing about the capability.
            RosterAuth::granting(KEY)
                .and_the_unnamed_caller()
                .withholding(WITHHELD_ID),
            Arc::new(TestGrantChecker),
            pg_write_target::<ConnettoWatermark>(writer_pool.clone(), PG_DDL)
                .expect("build write target"),
            Arc::new(RequestGuard::default()),
            SessionConfig::default(),
        )
    };

    // Presenting nothing: the insert is refused, because with neither an
    // identity nor a key bound both halves of the policy are NULL.
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(build().serve(server_transport));
    handshake_with(&mut client, "visitor", &[]).await;
    upload(&mut client, 1, insert_changeset(1, KEY, "shared", "t1")).await;
    match next_control(&mut client).await {
        ControlMessage::MutationReject(reject) => assert_eq!(reject.client_seq, 1),
        other => panic!("a caller holding nothing must be refused, got {other:?}"),
    }
    assert_eq!(notes(&admin).await, Vec::new());
    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");

    // Same caller, same row, now presenting the key: it lands.
    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(build().serve(server_transport));
    handshake_with(&mut client, "visitor", &[KEY]).await;
    upload(&mut client, 1, insert_changeset(1, KEY, "shared", "t1")).await;
    match next_control(&mut client).await {
        ControlMessage::MutationApplied(applied) => assert_eq!(applied.client_seq, 1),
        other => panic!("the key must authorize the write, got {other:?}"),
    }

    // And the key does not become a licence to write anywhere: a row owned by
    // somebody else is still refused on the same connection.
    upload(&mut client, 2, insert_changeset(2, "alice", "hers", "t1")).await;
    match next_control(&mut client).await {
        ControlMessage::MutationReject(reject) => assert_eq!(reject.client_seq, 2),
        other => panic!("the key grants its own row only, got {other:?}"),
    }
    match barrier(&mut client, 1).await {
        ControlMessage::Pong(_) => {}
        other => panic!("expected pong after the reject, got {other:?}"),
    }

    // seq 3: the stand-in refuses the withheld key. The owner is KEY so Postgres
    // would permit it, and the refusal comes from the roster alone.
    upload(
        &mut client,
        3,
        insert_changeset(WITHHELD_ID, KEY, "withheld", "t1"),
    )
    .await;
    match next_control(&mut client).await {
        ControlMessage::MutationReject(reject) => assert_eq!(reject.client_seq, 3),
        other => panic!("stand-in must refuse the withheld key, got {other:?}"),
    }
    match barrier(&mut client, 2).await {
        ControlMessage::Pong(_) => {}
        other => panic!("expected pong after withheld reject, got {other:?}"),
    }
    assert_eq!(notes(&admin).await, vec![(1, KEY.to_owned())]);
    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}
