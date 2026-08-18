//! A real `TRUNCATE` has to reach the subscriber as a replacement (R48).
//!
//! The client half is pinned without a database in
//! `crates/connetto-client/tests/truncate_resync.rs`: given the notice, the
//! replica empties and the caller's own unacknowledged write survives. This is
//! the other half, and it is the one that needs Postgres: that emptying a
//! replicated table produces the notice at all, naming the table, over a real
//! logical replication stream.
//!
//! Before R48 the payload folded for a truncate carried zero operations and was
//! delivered as an ordinary live patch, so the subscriber applied nothing, its
//! cursor moved past the event, and its copy stayed populated for ever.
//!
//! `#[ignore]` by default: it needs a Postgres started with `wal_level=logical`.

use std::time::Duration;

use connetto_core::messages::FullResyncReason;
use connetto_server::{PgSnapshotSource, RlsAuth, RuntimeWritableCatalog};
use connetto_test_harness::{
    Fixture, HarnessAuth, ServerConfig, pool_for, spawn_server, with_user,
};

const PG_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT);";

/// Two of alice's rows in a table the change stream carries.
async fn provision(fixture: &Fixture) {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS notes CASCADE",
            "DROP TABLE IF EXISTS _connetto_mutations",
            "DROP PUBLICATION IF EXISTS connetto_pub",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
             THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$",
            "CREATE TABLE notes (id INT PRIMARY KEY, owner TEXT, body TEXT)",
            "ALTER TABLE notes REPLICA IDENTITY FULL",
            "ALTER TABLE notes ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY notes_p ON notes \
             USING (owner = current_setting('app.user_id', true))",
            "GRANT USAGE ON SCHEMA public TO app_writer",
            "GRANT SELECT ON notes TO app_writer",
            "INSERT INTO notes (id, owner, body) VALUES (1, 'alice', 'one'), (2, 'alice', 'two')",
        ])
        .await;
    // The handshake reads the durable mutation watermark, so the table has to
    // exist before a client connects. Provisioned by the admin, as a deployment
    // would: the restricted role cannot CREATE in schema public.
    connetto_test_harness::provision_watermark(fixture.admin()).await;
    fixture
        .exec("GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_writer")
        .await;
    fixture.start_replication(&["notes"]).await;
}

/// A server over that fixture, reading as the restricted role.
async fn spawn(fixture: &Fixture) -> connetto_test_harness::Server {
    let writer_pool = pool_for(&with_user(fixture.admin_url(), "app_writer", "app_writer")).await;
    let snapshot =
        PgSnapshotSource::from_ddl(writer_pool.clone(), PG_DDL).expect("snapshot source");
    let auth = HarnessAuth::rls(RlsAuth::from_ddl(writer_pool.clone(), PG_DDL).expect("rls auth"));
    spawn_server(
        ServerConfig::new(PG_DDL, fixture.admin_url())
            .with_writable(RuntimeWritableCatalog::builder().build()),
        snapshot,
        auth,
        writer_pool,
        fixture.admin().clone(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker)"]
async fn truncating_a_table_replaces_the_subscription_naming_that_table() {
    let fixture = Fixture::acquire().await;
    provision(&fixture).await;
    let server = spawn(&fixture).await;

    let mut alice = server.connect();
    alice.handshake_with("client-a", "user:alice#reader").await;
    alice
        .subscribe("notes", "SELECT * FROM notes WHERE owner = 'alice'")
        .await;
    let seeded = alice.expect_snapshot("notes").await;
    assert!(
        seeded.iter().any(|patch| !patch.patchset_zstd.is_empty()),
        "the subscription starts holding rows, or emptying the table proves nothing"
    );

    fixture.exec("TRUNCATE notes").await;

    let (reason, replacement) = alice
        .try_resync("notes", Duration::from_secs(30))
        .await
        .expect(
            "emptying the table has to replace the subscription: the patchset folded for a \
             truncate carries no operations, so delivering it leaves every row in place",
        );
    assert_eq!(
        reason,
        FullResyncReason::TableTruncated {
            table: "notes".to_owned()
        },
        "the notice names the emptied table, which is what entitles the client to \
         delete the whole of it rather than sparing what a sibling still claims"
    );
    // An empty snapshot still carries a patch frame, so the emptiness is in the
    // payload rather than in the frame count: zstd of nothing is nine bytes.
    for patch in &replacement {
        let bytes = zstd::decode_all(patch.patchset_zstd.as_slice()).expect("decompress");
        assert!(
            bytes.is_empty(),
            "the replacement snapshot of an emptied table carries no rows, which is why \
             this is the cheapest replacement there is: {bytes:?}"
        );
    }

    alice.close().await;
    drop(server);
}

/// **The phase's second proof obligation.** A device that was offline when the
/// table was emptied must not get the rows back on reconnect.
///
/// The truncate is in the oplog and replays in order, and before R48 it replayed
/// as the same zero-operation patchset the live path sent, advancing the cursor
/// past it. So the reconnecting client applied nothing and kept every row, which
/// is the identical defect narrowed to offline clients.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker)"]
async fn a_client_offline_across_the_truncate_is_replaced_on_reconnect() {
    let fixture = Fixture::acquire().await;
    provision(&fixture).await;
    let server = spawn(&fixture).await;

    // Online first, so it holds rows and persists a cursor to come back on.
    let mut alice = server.connect();
    alice.handshake_with("r48-away", "user:alice#away").await;
    alice
        .subscribe("notes", "SELECT * FROM notes WHERE owner = 'alice'")
        .await;
    let seeded = alice.expect_snapshot("notes").await;
    assert!(
        seeded.iter().any(|patch| !patch.patchset_zstd.is_empty()),
        "the subscription starts holding rows, or emptying the table proves nothing"
    );
    // A committed row after the snapshot, so the resume cursor names a real
    // position in the log rather than the snapshot's own.
    fixture
        .exec("INSERT INTO notes (id, owner, body) VALUES (3, 'alice', 'three')")
        .await;
    let resume_from = alice.wait_for_live(Duration::from_secs(30)).await.cursor;
    alice.close().await;

    fixture.exec("TRUNCATE notes").await;

    let mut back = server.connect();
    back.handshake_resuming("r48-away", "user:alice#away", resume_from)
        .await;
    back.subscribe("notes", "SELECT * FROM notes WHERE owner = 'alice'")
        .await;
    let (reason, _) = back
        .try_resync("notes", Duration::from_secs(30))
        .await
        .expect(
            "catchup has to replace the subscription rather than replay a truncate as the \
         empty patch it folds to, which would leave the emptied table populated",
        );
    assert_eq!(
        reason,
        FullResyncReason::TableTruncated {
            table: "notes".to_owned()
        },
        "the catchup replacement names the emptied table for the same reason the \
         live one does"
    );

    back.close().await;
    drop(server);
}
