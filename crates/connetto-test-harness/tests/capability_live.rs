//! A share key filters live delivery, not only the snapshot (R4).
//!
//! The snapshot and the change path are different executors and they can
//! disagree silently. A snapshot runs one policy-filtered `SELECT`, while live
//! delivery asks `RlsAuth::can_read` per row per subscriber in its own
//! transaction. Binding the caller's keys in one and forgetting the other would
//! show a shared row once and then never update it, which is the divergence
//! `docs/architecture/08-authorization.md` warns about. This drives the whole
//! loop over real Postgres logical replication and proves both halves agree.
//!
//! The caller here has no identity at all, so nothing but the key can explain
//! what it receives. Two rows are inserted after the stream is live, in a fixed
//! order: the one the key does not cover first. Replication preserves order, so
//! if the filter leaked, the uncovered row would be the first live patch to
//! arrive.
//!
//! `#[ignore]` by default: it needs a Postgres started with `wal_level=logical`.

use std::time::Duration;

use connetto_server::{
    Materializer, PgSnapshotSource, RlsAuth, RuntimeWritableCatalog, SessionConfig,
};
use connetto_test_harness::{
    Fixture, HarnessAuth, ServerConfig, pool_for, spawn_server, with_user,
};
use diesel::prelude::*;

/// The catalog the snapshot encoder and the read filter both parse.
const PG_DDL: &str = "\
CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT);\
CREATE TABLE note_shares (note_id INT, viewer TEXT, PRIMARY KEY (note_id, viewer));";

const REPLICA_DDL: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT);";

/// The key alice grants over notes 1 and 3, and nothing else.
const KEY: &str = "key:live-share";

diesel::table! {
    notes (id) {
        id -> Integer,
        owner -> Text,
        body -> Text,
    }
}

/// The note ids a patchset carries, read off a replica it was applied to, which
/// is what a client would actually be holding.
fn ids_in(patchset_zstd: &[u8]) -> Vec<i32> {
    let mut replica = SqliteConnection::establish(":memory:").expect("open replica");
    diesel::RunQueryDsl::execute(diesel::sql_query(REPLICA_DDL), &mut replica)
        .expect("replica ddl");
    Materializer::new(PG_DDL)
        .expect("applier")
        .apply_diffset(patchset_zstd, &mut replica)
        .expect("apply patchset");
    diesel::RunQueryDsl::load(
        notes::table.order(notes::id).select(notes::id),
        &mut replica,
    )
    .expect("read replica")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker)"]
async fn a_share_key_filters_the_snapshot_and_the_live_stream_alike() {
    let fixture = Fixture::acquire().await;
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS notes, note_shares CASCADE",
            "DROP TABLE IF EXISTS _connetto_mutations",
            "DROP PUBLICATION IF EXISTS connetto_pub",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
             THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$",
            "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT)",
            "CREATE TABLE note_shares (note_id INT, viewer TEXT, PRIMARY KEY (note_id, viewer))",
            "ALTER TABLE notes REPLICA IDENTITY FULL",
            "ALTER TABLE notes ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE note_shares ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY notes_p ON notes USING ( \
               owner = current_setting('app.user_id', true) \
               OR EXISTS (SELECT 1 FROM note_shares s WHERE s.note_id = notes.id \
                          AND s.viewer = ANY(string_to_array(current_setting('app.subjects', true), ','))))",
            "CREATE POLICY shares_read ON note_shares FOR SELECT USING ( \
               viewer = ANY(string_to_array(current_setting('app.subjects', true), ',')))",
            "GRANT USAGE ON SCHEMA public TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO app_writer",
            "GRANT SELECT ON note_shares TO app_writer",
            // Note 1 exists before the slot, so it can only reach the client
            // through the snapshot. Note 2 is alice's and is never shared.
            "INSERT INTO notes VALUES (1, 'alice', 'shared'), (2, 'alice', 'private')",
            &format!("INSERT INTO note_shares VALUES (1, '{KEY}'), (3, '{KEY}')"),
        ])
        .await;
    connetto_test_harness::provision_watermark(fixture.admin()).await;
    fixture
        .exec("GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_writer")
        .await;
    fixture.start_replication(&["notes"]).await;

    let writer_pool = pool_for(&with_user(fixture.admin_url(), "app_writer", "app_writer")).await;
    let server = spawn_server(
        ServerConfig {
            pg_ddl: PG_DDL.to_owned(),
            writable: RuntimeWritableCatalog::builder().build(),
            admin_url: fixture.admin_url().to_owned(),
            session: SessionConfig::default(),
        },
        PgSnapshotSource::from_ddl(writer_pool.clone(), PG_DDL).expect("snapshot source"),
        HarnessAuth::rls(RlsAuth::from_ddl(writer_pool.clone(), PG_DDL).expect("rls auth")),
        writer_pool,
        fixture.admin().clone(),
    );

    // A caller with no identity whatsoever, holding one share key.
    let mut bearer = server.connect();
    bearer.handshake_presenting("bearer", &[KEY], None).await;
    bearer.subscribe("notes", "SELECT * FROM notes").await;

    // The snapshot carries the shared note and not alice's private one.
    let patches = bearer.expect_snapshot("notes").await;
    let snapshot_ids: Vec<i32> = patches
        .iter()
        .flat_map(|patch| ids_in(&patch.patchset_zstd))
        .collect();
    assert_eq!(
        snapshot_ids,
        vec![1],
        "the snapshot shows exactly what the key is granted"
    );

    // Now the live half. The uncovered row is written first, so replication
    // order alone would deliver it first if the filter were not applied.
    fixture
        .exec("INSERT INTO notes VALUES (4, 'alice', 'still private')")
        .await;
    fixture
        .exec("INSERT INTO notes VALUES (3, 'alice', 'also shared')")
        .await;

    let live = bearer.wait_for_live(Duration::from_secs(20)).await;
    assert_eq!(
        live.sub_id, "notes",
        "live patch for the right subscription"
    );
    assert_eq!(
        ids_in(&live.patchset_zstd),
        vec![3],
        "the first live patch is the shared row, so the earlier unshared write was withheld"
    );

    bearer.close().await;
    drop(server);
}
