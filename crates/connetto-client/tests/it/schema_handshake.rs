//! The handshake's schema-version gate, driven end to end by the bundle step.
//!
//! The server derives the version it declares from the translated bundle, the
//! way the production binary does. A client that presents the same bundle
//! connects, and a client that presents a bundle over the same sources but a
//! different replica DDL is refused `ClientError::SchemaOutdated`, because the
//! two sides hashed different things.
//!
//! Needs Docker, since the fixture starts its own Postgres.

use connetto_client::{ClientBuilder, ClientError, SyncSchema};
use connetto_core::{SchemaBundle, SchemaVersion};
use connetto_server::{PgSnapshotSource, RlsAuth, SessionConfig};
use connetto_test_harness::{
    Fixture, HarnessAuth, ServerConfig, pool_for, spawn_server, with_user,
};

const PG_DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, owner TEXT, body TEXT);";
const POLICIES: &str = "ALTER TABLE orders ENABLE ROW LEVEL SECURITY; \
     CREATE POLICY orders_p ON orders \
     USING (owner = current_setting('app.user_id', true)) \
     WITH CHECK (owner = current_setting('app.user_id', true));";

/// The bundle version a side declares, derived the way the production binary
/// derives it, from the same sources both sides hold.
fn derived_version() -> SchemaVersion {
    connetto_schema::translate::<String>(PG_DDL, POLICIES)
        .expect("translate the sources")
        .version()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_handshake_gate_hashes_the_same_bundle_on_both_sides() {
    let fixture = Fixture::acquire().await;
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS orders CASCADE",
            "DROP TABLE IF EXISTS _connetto_mutations",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
             THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$",
            PG_DDL,
            POLICIES,
            "GRANT USAGE ON SCHEMA public TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO app_writer",
        ])
        .await;
    connetto_test_harness::provision_watermark(fixture.admin()).await;
    fixture
        .exec("GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_writer")
        .await;
    let writer_pool = pool_for(&with_user(fixture.admin_url(), "app_writer", "app_writer")).await;
    let snapshot =
        PgSnapshotSource::from_ddl(writer_pool.clone(), PG_DDL).expect("snapshot source");
    let auth = HarnessAuth::rls(RlsAuth::from_ddl(writer_pool.clone(), PG_DDL).expect("rls auth"));
    let server = spawn_server(
        ServerConfig::new(PG_DDL, fixture.admin_url())
            .with_replication(["orders"])
            .with_session(SessionConfig::new().with_schema_version(Some(derived_version()))),
        snapshot,
        auth,
        writer_pool,
        fixture.admin().clone(),
    )
    .await;

    let connected = ClientBuilder::new(
        SyncSchema::new(
            connetto_schema::translate::<String>(PG_DDL, POLICIES).expect("translate the sources"),
        ),
        super::support::Once::new(server.attach()),
    )
    .signed_in(super::support::held("alice"))
    .connect_driven()
    .await;
    assert!(
        connected.is_ok(),
        "the matching bundle connects: {:?}",
        connected.err()
    );
    drop(connected);

    // A client over the same sources but a different replica DDL hashed a
    // different bundle, and is told to reload rather than mis-parse.
    let stale_bundle = SchemaBundle::new(
        PG_DDL,
        POLICIES,
        "CREATE TABLE orders_rls (id INTEGER PRIMARY KEY, owner TEXT, body TEXT);",
        Vec::<(String, String)>::new(),
        Vec::<String>::new(),
        None::<&str>,
    );
    let stale = stale_bundle.version();
    assert_ne!(
        stale,
        derived_version(),
        "a different replica DDL changes the hash"
    );
    match ClientBuilder::new(
        SyncSchema::new(stale_bundle),
        super::support::Once::new(server.attach()),
    )
    .signed_in(super::support::held("alice"))
    .connect_driven()
    .await
    {
        Err(ClientError::SchemaOutdated { client, server }) => {
            assert_eq!(
                client,
                Some(stale),
                "the client reports the version it baked"
            );
            assert_eq!(
                server,
                derived_version(),
                "the server reports the version it derived"
            );
        }
        Err(other) => panic!("expected SchemaOutdated, got {other:?}"),
        Ok(_) => panic!("a stale client connected to a versioned server"),
    }
}
