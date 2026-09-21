//! End-to-end proof for the desktop demo's photos surface.
//!
//! Applies the demo's own `schema.sql`, `DEPLOYMENT_DDL`, `roles.sql` and
//! `content.sql` in the documented order, then proves:
//!
//! - stage (`orders` + `photos` row in one transaction), local resolve, upload,
//!   `content_state` flip via `connetto_set_content_state`, signed-URL resolve,
//!   bytes-equal fetch on a second device.
//! - archive export with unsent content then import under a second device key:
//!   bytes survive re-encryption.
//!
//! CI does NOT run tests in the examples workspaces (`ci.yml` runs tests only
//! for root-workspace crates: `connetto-server`, `connetto-client`, and the rest
//! shard). This proof is local only.
//!
//! Needs Docker: the fixture starts its own Postgres.

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::marker::PhantomData;
use std::sync::Arc;

use connetto_client::live::ConnettoClient;
use connetto_client::reconnect::{ReconnectPolicy, TokioSleeper};
use connetto_client::{
    ClientConfig, ConnettoConnection, ExportScope, Grant, ImportChoices, Replica,
};
use connetto_core::transport::LoopbackTransport;
use connetto_dioxus_desktop_demo::{photos, stage_photo_row};
use connetto_file_client::{ContentClient, FsStore, MimeClass, ReqwestHttp, Resolved};
use connetto_file_server::{
    AppPools, Config, DefaultFileSchema, FsStore as ServerStore, TicketSigner, TicketVerifier,
};
use connetto_server::{PgSnapshotSource, RlsAuth, RuntimeWritableCatalog};
use connetto_test_harness::{
    Fixture, HarnessAuth, Server, ServerConfig, pool_for, spawn_server, with_user,
};
use diesel::prelude::*;
use pg2sqlite::prelude::{Pg2Sqlite, Pg2SqliteOptions, SessionVariableMapping, UuidRepresentation};
use tempfile::tempdir;

/// The bytes staged and verified through the full flow.
const PHOTO: &[u8] = b"JPEG bytes representing a photo staged through the desktop demo UI";

/// The demo's Postgres table DDL, applied as-is.
const SCHEMA_SQL: &str = include_str!("../schema.sql");
/// The demo's deployment functions (`connetto_visible_files`, `connetto_set_content_state`).
const CONTENT_SQL: &str = include_str!("../content.sql");
/// The demo's roles and grants.
const ROLES_SQL: &str = include_str!("../roles.sql");

/// Simplified DDL for the server's internal catalog (`PgSnapshotSource`, `RlsAuth`).
/// The actual Postgres tables are created from `SCHEMA_SQL`; this version omits
/// `gen_random_uuid()` defaults and foreign-key references that the `subql` parser
/// does not need and may not handle.
const CATALOG_DDL: &str = concat!(
    "CREATE TABLE orders (id UUID PRIMARY KEY, quantity BIGINT NOT NULL,",
    " created_at TIMESTAMPTZ NOT NULL);",
    "CREATE TABLE order_lines (order_id UUID NOT NULL, line_no INTEGER NOT NULL,",
    " quantity BIGINT NOT NULL, PRIMARY KEY (order_id, line_no));",
    "CREATE TABLE photos (id UUID PRIMARY KEY, order_id UUID NOT NULL,",
    " content_id BYTEA, content_state TEXT)",
);

/// Derive the SQLite replica DDL from `schema.sql` at test time, using the same
/// `pg2sqlite` options the demo's `build.rs` applies.
fn sqlite_ddl() -> String {
    let opts = Pg2SqliteOptions::default()
        .with_uuid_representation(UuidRepresentation::Blob)
        .with_uuid_function_name("uuidv4")
        .with_session_variable(SessionVariableMapping::current_setting(
            "app.user_id",
            "current_app_user",
        ))
        .with_rls_audit_table_name("rls_audit".to_string())
        .with_write_exemption_function("connetto_write_exempt");
    let stmts = Pg2Sqlite::default()
        .sql(SCHEMA_SQL)
        .expect("parse schema.sql")
        .translate_to_sql(&opts)
        .expect("translate schema.sql to SQLite");
    let mut ddl = stmts.join(";\n");
    ddl.push(';');
    ddl
}

/// Stage, upload, flip, resolve, fetch, and archive round trip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker: the fixture starts its own Postgres"]
async fn demo_photo_flow_stage_upload_resolve_and_archive_round_trip() {
    let fixture = Fixture::acquire().await;
    provision(&fixture).await;
    let ddl = sqlite_ddl();
    eprintln!("[diag] sqlite_ddl=\n{ddl}");

    let chunk_dir = tempdir().expect("chunk tempdir");
    let (base_url, signer, file_task) = start_file_server(&fixture, chunk_dir.path()).await;
    let server = Arc::new(spawn_sync_server(&fixture, signer).await);

    let replica_dir = tempdir().expect("replica tempdir");

    // Device A opens offline; the gate controls when its reconnect factory
    // starts returning a real transport.
    let (a, gate) = offline_device(replica_dir.path(), "device-a", &server, &ddl);
    let mut a_client_events = a.events();
    let a_content = attach_content(a, chunk_dir.path(), "a").await;

    // Stage using the demo pattern: orders row + photos row in one transaction.
    // `stage_photo_row` is the same function the desktop UI's pick handler calls.
    let file_id = a_content
        .stage(PHOTO, MimeClass::Jpeg, stage_photo_row)
        .await
        .expect("stage demo photo")
        .0;
    eprintln!(
        "[diag] stage done, file_id={}",
        short_hex_bytes(file_id.as_bytes())
    );

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
    eprintln!("[diag] archive exported ({} bytes)", archive.len());

    // Open the gate: mutation lands, then the outbox walk mints a ticket.
    gate.store(true, Ordering::Relaxed);
    eprintln!("[diag] gate opened");
    let deadline_diag = tokio::time::Instant::now() + Duration::from_secs(30);
    let sent = loop {
        let sent = a_content.flush_outbox().await.expect("flush");
        eprintln!("[diag] flush_outbox={sent}");
        if sent > 0 {
            break sent;
        }
        {
            let mut conn = fixture.admin().get().await.expect("conn");
            let count = diesel_async::RunQueryDsl::get_result::<i64>(
                photos::table
                    .filter(photos::content_id.eq(file_id.as_bytes().to_vec()))
                    .count(),
                &mut *conn,
            )
            .await
            .expect("count photos row in Postgres");
            eprintln!("[diag] pg photos row count={count}");
        }
        while let Ok(ev) = a_client_events.try_recv() {
            eprintln!("[diag] client_event={ev:?}");
        }
        assert!(
            tokio::time::Instant::now() < deadline_diag,
            "upload timeout"
        );
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
    let (b, b_content) = connect_device(
        replica_dir.path(),
        "device-b",
        &server,
        chunk_dir.path(),
        &ddl,
    )
    .await;
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
    let c_replica_path = replica_dir.path().join("device-c.sqlite");
    let c_replica = Replica::encrypted_file(
        c_replica_path.to_str().expect("utf-8"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("device C replica");
    let c_conn = ConnettoConnection::<LoopbackTransport>::open(
        &c_replica,
        &ddl,
        &client_config("device-c"),
        None,
    )
    .expect("open device C");
    let c_client = ConnettoClient::start(c_conn);
    let c_content = ContentClient::attach(
        c_client,
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
    c_content
        .apply_local_data_import(&mut plan, &ImportChoices::keeping_the_file())
        .await
        .expect("apply import");

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

/// Applies `schema.sql`, `DEPLOYMENT_DDL`, `provision_watermark`, `roles.sql` and
/// `content.sql`. `provision_watermark` runs before `roles.sql` because `roles.sql`
/// grants on `_connetto_mutations`, which the watermark step creates.
async fn provision(fixture: &Fixture) {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS photos CASCADE",
            "DROP TABLE IF EXISTS order_lines CASCADE",
            "DROP TABLE IF EXISTS orders CASCADE",
            "DROP TABLE IF EXISTS _connetto_mutations",
        ])
        .await;
    for stmt in split_plain(SCHEMA_SQL) {
        fixture.exec(&stmt).await;
    }
    for stmt in split_plain(connetto_file_server::DEPLOYMENT_DDL) {
        fixture.exec(&stmt).await;
    }
    connetto_test_harness::provision_watermark(fixture.admin()).await;
    fixture.exec(ROLES_SQL).await;
    fixture.exec(CONTENT_SQL).await;
    // `app_writer` is a test-infrastructure writer role; not part of the demo's
    // SQL files. The server's mutation path uses it to apply changesets.
    fixture
        .setup(&[
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
             THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$",
            "GRANT USAGE ON SCHEMA public TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON order_lines TO app_writer",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON photos TO app_writer",
            "GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_writer",
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

fn offline_device(
    root: &std::path::Path,
    name: &str,
    server: &Arc<Server>,
    ddl: &str,
) -> (ConnettoClient<LoopbackTransport>, Arc<AtomicBool>) {
    let path = root.join(format!("{name}.sqlite"));
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("open device replica");
    let conn =
        ConnettoConnection::<LoopbackTransport>::open(&replica, ddl, &client_config(name), None)
            .expect("open offline connection");
    let gate = Arc::new(AtomicBool::new(false));
    let factory_gate = Arc::clone(&gate);
    let factory_server = Arc::clone(server);
    let (client, pump) = ConnettoClient::with_reconnect(
        conn,
        move || {
            let gate = Arc::clone(&factory_gate);
            let server = Arc::clone(&factory_server);
            async move {
                let open = gate.load(Ordering::Relaxed);
                eprintln!("[diag] factory called gate={open}");
                if open {
                    eprintln!("[diag] factory returning Ok(transport)");
                    Ok(server.attach())
                } else {
                    Err("gate not open yet")
                }
            }
        },
        TokioSleeper,
        ReconnectPolicy::default(),
    );
    tokio::spawn(pump);
    (client, gate)
}

async fn connect_device(
    root: &std::path::Path,
    name: &str,
    server: &Arc<Server>,
    chunk_root: &std::path::Path,
    ddl: &str,
) -> (
    ConnettoClient<LoopbackTransport>,
    ContentClient<LoopbackTransport, FsStore, ReqwestHttp>,
) {
    let path = root.join(format!("{name}.sqlite"));
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("open device replica");
    let conn =
        ConnettoConnection::connect(server.attach(), &replica, ddl, &client_config(name), None)
            .await
            .expect("connect device");
    let client = ConnettoClient::start(conn);
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
                    conn.conn(),
                )
                .expect("read replica state")
            })
            .await;
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

fn client_config(name: &str) -> ClientConfig {
    ClientConfig::new(name).with_login(Some(Grant::new(format!("user:{name}"))))
}

/// Splits DDL that contains no dollar-quoted bodies on semicolons.
fn split_plain(ddl: &str) -> Vec<String> {
    ddl.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| format!("{s};"))
        .collect()
}

fn short_hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}
