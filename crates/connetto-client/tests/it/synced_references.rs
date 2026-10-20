//! A replica is a partial copy, so a synced child can arrive without its parent
//! (R92, step 0 (a) and proof 4).
//!
//! Row-level security, paging and eviction all leave a child on the device
//! whose parent is not there, and the server is the only enforcer of synced
//! references. The replica's own enforcement over those clauses could only
//! refuse what the server already accepted.
//!
//! Needs Docker, since the fixture starts its own Postgres.

use std::time::Duration;

use connetto_client::{ClientBuilder, ClientEvent, ConnettoConnection, SyncSchema};
use connetto_core::traits::Transport;
use connetto_server::{PgSnapshotSource, RlsAuth, RuntimeWritableCatalog, SessionConfig};
use connetto_test_harness::{
    Fixture, HarnessAuth, Server, ServerConfig, pool_for, spawn_server, with_user,
};
use diesel::prelude::*;

/// A folder belongs to one person, and a note can sit in somebody else's
/// folder. Alice owns notes in Bob's folder, so she sees the children and
/// never the parent.
const PG_DDL: &str = "-- connetto:major 1
CREATE TABLE folders (id INT PRIMARY KEY, owner TEXT NOT NULL);
CREATE TABLE notes (id INT PRIMARY KEY, folder_id INT NOT NULL REFERENCES folders(id), owner TEXT NOT NULL, body TEXT);";

const POLICIES: &str = "ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
CREATE POLICY folders_p ON folders USING (owner = current_setting('app.user_id', true));
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY notes_p ON notes
    USING (owner = current_setting('app.user_id', true))
    WITH CHECK (owner = current_setting('app.user_id', true));";

/// How long a frame that should arrive is given.
const DELIVERY: Duration = Duration::from_secs(30);

diesel::table! {
    /// The replica's copy of the server's notes.
    notes (id) {
        /// Row key.
        id -> Integer,
        /// The folder the note sits in, owned by whoever owns the folder.
        folder_id -> Integer,
        /// Whose note it is.
        owner -> Text,
        /// Payload.
        body -> Nullable<Text>,
    }
}

diesel::table! {
    /// The replica's copy of the server's folders.
    folders (id) {
        /// Row key.
        id -> Integer,
        /// Whose folder it is.
        owner -> Text,
    }
}

/// The client's schema, translated from the server's as a build bakes it.
fn schema() -> connetto_core::schema::SchemaBundle {
    connetto_schema::translate::<String, connetto_core::bots::TextIds>(PG_DDL, POLICIES)
        .expect("translate the sources")
}

/// Bob's folder with one of Alice's notes in it, and the server wired to serve
/// them under row-level security.
async fn server(fixture: &Fixture) -> Server {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS notes CASCADE",
            "DROP TABLE IF EXISTS folders CASCADE",
            "DROP TABLE IF EXISTS _connetto_writers, _connetto_settled CASCADE",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
             THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$",
            PG_DDL,
            POLICIES,
            "GRANT USAGE ON SCHEMA public TO app_writer",
            "GRANT SELECT ON folders TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO app_writer",
        ])
        .await;
    connetto_test_harness::provision_writers(fixture.admin()).await;
    fixture
        .exec(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON _connetto_writers, _connetto_settled \
             TO app_writer",
        )
        .await;
    fixture
        .exec(
            "INSERT INTO folders (id, owner) VALUES (1, 'bob'); \
             INSERT INTO notes (id, folder_id, owner, body) VALUES (10, 1, 'alice', 'in Bob''s folder')",
        )
        .await;
    let writer = pool_for(&with_user(fixture.admin_url(), "app_writer", "app_writer")).await;
    let snapshot = PgSnapshotSource::from_ddl(writer.clone(), PG_DDL).expect("snapshot source");
    let auth = HarnessAuth::rls(RlsAuth::from_ddl(writer.clone(), PG_DDL).expect("rls auth"));
    spawn_server(
        ServerConfig::new(PG_DDL, fixture.admin_url())
            .with_writable(RuntimeWritableCatalog::builder().writable("notes").build())
            .with_replication(["folders", "notes"])
            .with_session(SessionConfig::new().with_schema_version(Some(schema().version()))),
        snapshot,
        auth,
        writer,
        fixture.admin().clone(),
    )
    .await
}

/// Pump events until `done` accepts one, failing on a close or after
/// [`DELIVERY`].
async fn pump_until<T>(conn: &mut ConnettoConnection<T>, mut done: impl FnMut(&ClientEvent) -> bool)
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    let deadline = tokio::time::Instant::now() + DELIVERY;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let event = tokio::time::timeout(remaining, conn.pump_one())
            .await
            .expect("the awaited event did not arrive in time")
            .expect("pump");
        if let ClientEvent::MutationRejected { .. } = event {
            panic!("the server refused the write: {event:?}");
        }
        if done(&event) {
            return;
        }
    }
}

fn note_ids<T>(conn: &mut ConnettoConnection<T>) -> Vec<i32>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    notes::table
        .order(notes::id.asc())
        .select(notes::id)
        .load(conn.conn())
        .expect("read notes")
}

/// A snapshot and a live change each carry a note whose folder the caller
/// cannot see, both land, and a note the caller writes into that folder goes
/// up and the server applies it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_child_whose_parent_is_invisible_lands_and_uploads() {
    let fixture = Fixture::acquire().await;
    let server = server(&fixture).await;
    let mut alice = ClientBuilder::new(
        SyncSchema::new(schema()),
        super::support::Once::new(server.attach()),
    )
    .signed_in(super::support::held("alice"))
    .connect_driven()
    .await
    .expect("connect");

    alice
        .subscribe("folders", "SELECT * FROM folders")
        .await
        .expect("subscribe to folders");
    pump_until(&mut alice, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    alice
        .subscribe("notes", "SELECT * FROM notes")
        .await
        .expect("subscribe to notes");
    pump_until(&mut alice, |event| {
        matches!(event, ClientEvent::SnapshotEnd { .. })
    })
    .await;
    let folders: i64 = folders::table
        .count()
        .get_result(alice.conn())
        .expect("count folders");
    assert_eq!(folders, 0, "the caller cannot see Bob's folder");
    assert_eq!(
        note_ids(&mut alice),
        vec![10],
        "the snapshot's note landed without its folder"
    );

    fixture
        .exec("INSERT INTO notes (id, folder_id, owner, body) VALUES (12, 1, 'alice', 'live')")
        .await;
    pump_until(&mut alice, |event| {
        matches!(event, ClientEvent::LivePatch { .. })
    })
    .await;
    assert_eq!(
        note_ids(&mut alice),
        vec![10, 12],
        "the live note landed without its folder"
    );

    diesel::insert_into(notes::table)
        .values((
            notes::id.eq(11),
            notes::folder_id.eq(1),
            notes::owner.eq("alice"),
            notes::body.eq("written here"),
        ))
        .execute(alice.conn())
        .expect("a local note in a folder the replica does not hold");
    alice.push().await.expect("push");
    pump_until(&mut alice, |event| {
        matches!(event, ClientEvent::MutationApplied { .. })
    })
    .await;
    assert_eq!(note_ids(&mut alice), vec![10, 11, 12]);
    drop(server);
}
