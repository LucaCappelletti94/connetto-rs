//! End-to-end proof for the demo's photos surface.
//!
//! Applies the shared deployment's own `schema.sql`, `policies.sql`,
//! `roles.sql` and `content.sql` in the documented order, then proves:
//!
//! - stage (`orders` + `photos` row in one transaction), local resolve, upload,
//!   `content_state` flip via `connetto_set_content_state`, signed-URL resolve,
//!   bytes-equal fetch on a second device.
//! - archive export with unsent content then import under a second device key:
//!   bytes survive re-encryption, and the device-private tier (`notes`) rides
//!   along the archive and comes back on the importing device.
//!
//! The clients run the demo's own schema bundle, the one `build.rs` translates
//! from the deployment documents.
//!
//! CI does NOT run tests in the examples workspaces. This proof is local only.
//!
//! Needs Docker: the fixture starts its own Postgres.

#![cfg(not(target_arch = "wasm32"))]
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::marker::PhantomData;
use std::sync::Arc;

use connetto_client::live::ConnettoClient;
use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{
    ClientBuilder, DataDir, ExportScope, Gate, Grant, HeldCredential, ImportChoices, MemoryKeyStore,
    MemoryRefreshStore,
};
use connetto_core::traits::ReplicaKeyStore;
use connetto_core::transport::LoopbackTransport;
use connetto_demo_deployment::{CONTENT_SQL, POLICIES_SQL, ROLES_SQL, SCHEMA_SQL};
use connetto_dioxus_demo::{demo_schema, notes, photos, stage_photo_row};
use connetto_file_client::{ContentClient, FsStore, MimeClass, ReqwestHttp, Resolved};
use connetto_file_server::{
    AppPools, Config, DefaultFileSchema, FsStore as ServerStore, TicketSigner, TicketVerifier,
};
use connetto_server::epoch::EPOCH_DDL;
use connetto_server::{PgSnapshotSource, RlsAuth, RuntimeWritableCatalog};
use connetto_test_harness::{
    Fixture, HarnessAuth, Server, ServerConfig, pool_for, spawn_server, with_user,
};
use diesel::prelude::*;
use tempfile::tempdir;

/// The bytes staged and verified through the full flow.
const PHOTO: &[u8] = b"JPEG bytes representing a photo staged through the demo UI";

/// The user the test's devices sign in as, and the `owner_id` every row names.
/// The deployment's visibility policies compare `owner_id` against
/// `current_setting('app.user_id')`, which the server binds from the
/// credential's user id.
const OWNER: &str = "alice";

/// Simplified DDL for the server's internal catalog (`PgSnapshotSource`,
/// `RlsAuth`). The actual Postgres tables are created from the deployment's
/// `schema.sql`; this version omits the `gen_random_uuid()` defaults and
/// foreign-key references that the `subql` parser does not need and may not
/// handle.
const CATALOG_DDL: &str = concat!(
    "CREATE TABLE orders (id UUID PRIMARY KEY, owner_id TEXT NOT NULL,",
    " quantity BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL);",
    "CREATE TABLE order_lines (order_id UUID NOT NULL, line_no INTEGER NOT NULL,",
    " owner_id TEXT NOT NULL, quantity BIGINT NOT NULL,",
    " PRIMARY KEY (order_id, line_no));",
    "CREATE TABLE photos (id UUID PRIMARY KEY, order_id UUID NOT NULL,",
    " owner_id TEXT NOT NULL, content_id BYTEA NOT NULL, content_state TEXT)"
);


/// Stage, upload, flip, resolve, fetch, and archive round trip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker: the fixture starts its own Postgres"]
async fn demo_photo_flow_stage_upload_resolve_and_archive_round_trip() {
    let fixture = Fixture::acquire().await;
    provision(&fixture).await;

    let chunk_dir = tempdir().expect("chunk tempdir");
    let (base_url, signer, file_task) = start_file_server(&fixture, chunk_dir.path()).await;
    let server = Arc::new(spawn_sync_server(&fixture, signer).await);

    let replica_dir = tempdir().expect("replica tempdir");

    // Device A opens offline; the gate controls when its reconnect factory
    // starts returning a real transport.
    let (a, open) = offline_device(replica_dir.path(), "device-a", &server).await;
    let mut a_client_events = a.events();
    let a_content = attach_content(a.clone(), chunk_dir.path(), "a").await;

    // The build bundle's tier rides along with the offline device: the table
    // is there before anything is written to it.
    let tier_tables = a
        .with_conn(|conn| conn.local_tables().iter().cloned().collect::<Vec<_>>())
        .await
        .expect("read device A's tier tables");
    assert!(
        tier_tables.contains(&"notes".to_owned()),
        "the tier table must ride along with the offline device, got {tier_tables:?}"
    );

    // A row written to the tier must ride along the archive to device C.
    a.with_conn(|conn| {
        diesel::insert_into(notes::table)
            .values((
                notes::id.eq(1),
                notes::body.eq("a note that stays on this device"),
            ))
            .execute(&mut *conn.conn())
    })
    .await
    .expect("write into the tier")
    .expect("insert device-only note");

    // Stage using the demo pattern: orders row + photos row in one
    // transaction, the same row the pick handler writes.
    let file_id = a_content
        .stage(PHOTO, MimeClass::Jpeg, |conn, file_id| {
            stage_photo_row(conn, file_id, OWNER)
        })
        .await
        .expect("stage demo photo")
        .0;

    // Bytes resolve locally before any upload.
    assert!(
        matches!(
            a_content.resolve(file_id).await.expect("resolve offline"),
            Resolved::Local { .. }
        ),
        "locally staged bytes are readable before upload"
    );

    // Export BEFORE opening the gate: the content is still unsent, exercising
    // the silent-loss protection path the archive exists for.
    let archive = a_content
        .export_local_data(ExportScope::Everything, Vec::new())
        .await
        .expect("export archive with unsent content");
    assert!(!archive.is_empty(), "archive is non-empty");

    // Open the gate: mutation lands, then the outbox walk mints a ticket.
    open.store(true, Ordering::Relaxed);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let sent = loop {
        let sent = a_content.flush_outbox().await.expect("flush");
        if sent > 0 {
            break sent;
        }
        while let Ok(ev) = a_client_events.try_recv() {
            let _ = ev;
        }
        assert!(tokio::time::Instant::now() < deadline, "upload timeout");
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(sent, 1, "one file uploaded from the outbox");

    // The server's commit called `connetto_set_content_state`.
    let pg_state = wait_for_pg_state(&fixture, file_id.as_bytes()).await;
    assert_eq!(
        pg_state.as_deref(),
        Some("available"),
        "content_state flipped in Postgres"
    );

    // Device B connects and sees the flip via replication.
    let (b, b_content) =
        connect_device(replica_dir.path(), "device-b", &server, chunk_dir.path()).await;
    b.pin("photos", "SELECT * FROM photos").await.expect("pin");
    let replica_state = wait_for_replica_state(&b, file_id.as_bytes()).await;
    assert_eq!(
        replica_state.as_deref(),
        Some("available"),
        "content_state reaches device B via replication"
    );

    // Device B resolves a signed URL and fetches the bytes.
    let resolved = b_content
        .resolve(file_id)
        .await
        .expect("resolve on device B");
    let Resolved::Remote { url } = resolved else {
        panic!(
            "device B holds no local bytes, so resolve must yield a signed URL, got {resolved:?}"
        );
    };
    assert!(
        url.starts_with(&base_url),
        "the granted URL addresses the file server, got {url}"
    );
    let fetched = b_content
        .bytes(file_id)
        .await
        .expect("bytes via signed URL");
    assert_eq!(
        fetched.as_deref(),
        Some(PHOTO),
        "fetched bytes equal the original"
    );

    // Import the archive, captured while content was still unsent, on device C
    // under a distinct key, proving re-encryption of the unsent bytes.
    let c_client = device(replica_dir.path(), "device-c", || async {
        Err::<LoopbackTransport, _>("device C stays offline")
    })
    .await;
    let c_content = ContentClient::attach(
        c_client.clone(),
        FsStore::new(chunk_dir.path().join("device-c")),
        [7u8; 32],
        ReqwestHttp::new(),
    )
    .await
    .expect("attach device C content");

    let mut plan = c_content
        .prepare_local_data_import(std::io::Cursor::new(archive))
        .await
        .expect("prepare import");
    assert_eq!(
        plan.content_files(),
        1,
        "archive carries the one unsent photo"
    );
    assert_eq!(
        plan.replica_plan().device_only_rows(),
        1,
        "the archive carries the one device-only note"
    );
    c_content
        .apply_local_data_import(&mut plan, &ImportChoices::keeping_the_file())
        .await
        .expect("apply import");

    // The tier row rides back through the archive into device C's own tier.
    let imported_note = c_client
        .with_conn(|conn| {
            notes::table
                .select(notes::body)
                .filter(notes::id.eq(1))
                .first::<String>(&mut *conn.conn())
                .optional()
        })
        .await
        .expect("read the imported tier row")
        .expect("read the note");
    assert_eq!(
        imported_note.as_deref(),
        Some("a note that stays on this device"),
        "the device-only note survives the archive round trip"
    );

    // After import the bytes are in device C's local store under its own key.
    assert!(
        matches!(
            c_content
                .resolve(file_id)
                .await
                .expect("resolve after import"),
            Resolved::Local { .. }
        ),
        "unsent bytes survive export and import under a second device key"
    );

    file_task.abort();
}

/// Applies the deployment's `schema.sql`, the file server's `DEPLOYMENT_DDL`,
/// the epoch DDL, `roles.sql`, `content.sql` and `policies.sql`, in the order
/// the deployment documents. `provision_writers` runs before `roles.sql`
/// because `roles.sql` grants on the writer tables, which the writer step
/// creates.
async fn provision(fixture: &Fixture) {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS photos CASCADE",
            "DROP TABLE IF EXISTS order_lines CASCADE",
            "DROP TABLE IF EXISTS orders CASCADE",
            "DROP TABLE IF EXISTS _connetto_settled",
            "DROP TABLE IF EXISTS _connetto_writers",
        ])
        .await;
    for stmt in split_plain(SCHEMA_SQL) {
        fixture.exec(&stmt).await;
    }
    for stmt in split_plain(connetto_file_server::DEPLOYMENT_DDL) {
        fixture.exec(&stmt).await;
    }
    fixture.exec(EPOCH_DDL).await;
    connetto_test_harness::provision_writers(fixture.admin()).await;
    fixture.exec(ROLES_SQL).await;
    fixture.exec(CONTENT_SQL).await;
    fixture.exec(POLICIES_SQL).await;
    // `app_writer` is a test-infrastructure writer role; not part of the
    // deployment's SQL files. The server's mutation path uses it to apply
    // changesets, and it is subject to the row-level security that
    // `policies.sql` enables.
    fixture
        .setup(&[
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
             THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$",
            "GRANT USAGE ON SCHEMA public TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON order_lines TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON photos TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON _connetto_writers, _connetto_settled TO app_writer",
            "GRANT SELECT ON _cfs_manifests TO app_writer",
            "GRANT SELECT ON _cfs_manifest_chunks TO app_writer",
        ])
        .await;
}

async fn start_file_server(
    fixture: &Fixture,
    chunk_root: &std::path::Path,
) -> (String, TicketSigner, tokio::task::JoinHandle<()>) {
    let reader_pool = pool_for(&with_user(
        fixture.admin_url(),
        "connetto_reader",
        "connetto_reader",
    ))
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind file server");
    let base_url = format!("http://{}", listener.local_addr().expect("address"));
    let (signer, public_key) = TicketSigner::generate(&base_url, Duration::from_secs(600), 1 << 20)
        .expect("generate key pair");
    let router = connetto_file_server::serve(Config::<DefaultFileSchema> {
        pools: AppPools {
            admin: fixture.admin().clone(),
            reader: reader_pool,
        },
        store: connetto_file_server::AnyStore::Fs(
            ServerStore::new(chunk_root.join("server")).expect("server chunk store"),
        ),
        verifier: TicketVerifier::new(public_key),
        grace: Duration::from_secs(600),
        caller_settings: connetto_file_server::CallerSettings::default(),
        quotas: connetto_file_server::QuotaSettings::default(),
        ceilings: connetto_file_server::CeilingCache::default(),
        _schema: PhantomData,
    })
    .await
    .expect("deployment contracts in place");
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (base_url, signer, task)
}

async fn spawn_sync_server(fixture: &Fixture, signer: TicketSigner) -> Server {
    let writer_pool = pool_for(&with_user(fixture.admin_url(), "app_writer", "app_writer")).await;
    let snapshot =
        PgSnapshotSource::from_ddl(writer_pool.clone(), CATALOG_DDL).expect("snapshot source");
    let auth =
        HarnessAuth::rls(RlsAuth::from_ddl(writer_pool.clone(), CATALOG_DDL).expect("rls auth"));
    spawn_server(
        ServerConfig::new(CATALOG_DDL, fixture.admin_url())
            .with_writable(
                RuntimeWritableCatalog::builder()
                    .writable("orders")
                    .writable("order_lines")
                    .writable("photos")
                    .build(),
            )
            .with_replication(["orders", "order_lines", "photos"])
            .with_content_signer(signer),
        snapshot,
        auth,
        writer_pool,
        fixture.admin().clone(),
    )
    .await
}

/// A device named `name` in its own directory under `root`, on the demo's own
/// schema bundle, dialing through `dial` and redialing under the default
/// policy while it cannot reach the server.
async fn device<F, Fut>(
    root: &std::path::Path,
    name: &str,
    dial: F,
) -> ConnettoClient<LoopbackTransport>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<LoopbackTransport, &'static str>> + Send + 'static,
{
    // One user on several devices, each device its own session and its own
    // directory, so an archive from one restores on another.
    let credential = HeldCredential::new(Grant::new(format!("user:{OWNER}#{name}")), OWNER)
        .expect("a string identity serializes");
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).expect("the device directory");
    let keys = MemoryKeyStore::default();
    keys.store(
        credential.replica_name(),
        &connetto_core::test_support::replica_key(),
    )
    .await
    .expect("the in-memory store never fails");
    let (running, pump) = ClientBuilder::new(demo_schema(), dial)
        .with_reconnect(ReconnectPolicy::default())
        .signed_in(credential)
        .durable(DataDir::new(dir), keys, MemoryRefreshStore::default())
        .with_gate(Gate::off())
        .connect_with_pump()
        .await
        .expect("open the device");
    tokio::spawn(pump);
    running.client().clone()
}

async fn offline_device(
    root: &std::path::Path,
    name: &str,
    server: &Arc<Server>,
) -> (ConnettoClient<LoopbackTransport>, Arc<AtomicBool>) {
    let open = Arc::new(AtomicBool::new(false));
    let factory_open = Arc::clone(&open);
    let factory_server = Arc::clone(server);
    let client = device(root, name, move || {
        let open = Arc::clone(&factory_open);
        let server = Arc::clone(&factory_server);
        async move {
            if (*open).load(Ordering::Relaxed) {
                Ok(server.attach())
            } else {
                Err("gate not open yet")
            }
        }
    })
    .await;
    (client, open)
}

async fn connect_device(
    root: &std::path::Path,
    name: &str,
    server: &Arc<Server>,
    chunk_root: &std::path::Path,
) -> (
    ConnettoClient<LoopbackTransport>,
    ContentClient<LoopbackTransport, FsStore, ReqwestHttp>,
) {
    let server = Arc::clone(server);
    let client = device(root, name, move || {
        let server = Arc::clone(&server);
        async move { Ok(server.attach()) }
    })
    .await;
    let content = attach_content(client.clone(), chunk_root, name).await;
    (client, content)
}

async fn attach_content(
    client: ConnettoClient<LoopbackTransport>,
    chunk_root: &std::path::Path,
    name: &str,
) -> ContentClient<LoopbackTransport, FsStore, ReqwestHttp> {
    // Each device gets a distinct root key so the archive round-trip test
    // verifies re-encryption, not a byte-for-byte copy.
    let mut root_key = [0u8; 32];
    root_key[0] = name.as_bytes()[0];
    ContentClient::attach(
        client,
        FsStore::new(chunk_root.join(name)),
        root_key,
        ReqwestHttp::new(),
    )
    .await
    .expect("attach content")
}

/// Polls Postgres until `content_state` is non-null for the given `file_id`.
async fn wait_for_pg_state(fixture: &Fixture, file_id: &[u8; 32]) -> Option<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut conn = fixture.admin().get().await.expect("admin connection");
    loop {
        let rows = diesel_async::RunQueryDsl::load::<Option<String>>(
            photos::table
                .filter(photos::content_id.eq(file_id.to_vec()))
                .select(photos::content_state),
            &mut *conn,
        )
        .await
        .expect("read content_state from Postgres");
        if let Some(state) = rows.into_iter().next().flatten() {
            return Some(state);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "content_state never flipped in Postgres"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Polls the replica until `content_state` is set for the given `file_id`.
async fn wait_for_replica_state(
    client: &ConnettoClient<LoopbackTransport>,
    file_id: &[u8; 32],
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let wanted = file_id.to_vec();
    loop {
        let state = client
            .with_conn(|conn| {
                diesel::RunQueryDsl::load::<Option<String>>(
                    photos::table
                        .filter(photos::content_id.eq(wanted.clone()))
                        .select(photos::content_state),
                    &mut *conn.conn(),
                )
                .expect("read replica state")
            })
            .await
            .expect("gate not locked");
        if let Some(s) = state.into_iter().next().flatten() {
            return Some(s);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "content_state never reached the replica"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Splits DDL that contains no dollar-quoted bodies on semicolons.
fn split_plain(ddl: &str) -> Vec<String> {
    ddl.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("{s};"))
        .collect()
}
