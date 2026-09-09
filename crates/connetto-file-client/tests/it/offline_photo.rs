//! The phase's acceptance: the offline photo case, end to end and native.
//!
//! One device writes an entry and its bytes with nothing listening. It
//! reconnects, and both arrive: the row over the sync path, the bytes over the
//! content channel under a websocket-minted write ticket. A second device sees
//! `content_state` flip on its own replica and fetches the bytes by ranged
//! `GET` under a read ticket.
//!
//! Needs Docker: the fixture starts its own Postgres, and the file server runs
//! beside it on a real socket.

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::marker::PhantomData;
use std::sync::Arc;

use connetto_client::live::ConnettoClient;
use connetto_client::reconnect::{ReconnectPolicy, TokioSleeper};
use connetto_client::{ClientConfig, ConnettoConnection, Grant, Replica};
use connetto_core::transport::LoopbackTransport;
use connetto_file_client::{ContentClient, FsStore, ReqwestHttp, Resolved};
use connetto_file_core::{FileId, MimeClass};
use connetto_file_server::{
    AppPools, Config, DefaultFileSchema, FsStore as ServerStore, TicketSigner, TicketVerifier,
};
use connetto_server::{PgSnapshotSource, RlsAuth, RuntimeWritableCatalog};
use connetto_test_harness::{
    Fixture, HarnessAuth, Server, ServerConfig, pool_for, spawn_server, with_user,
};
use diesel::prelude::*;
use tempfile::tempdir;

/// The application's own table, as Postgres holds it.
const PG_DDL: &str = "CREATE TABLE photos (id INT PRIMARY KEY, owner TEXT, \
                      content_id BYTEA, content_state TEXT, edited_at TEXT);";

/// The same table as the replica holds it.
const SQLITE_DDL: &str = "CREATE TABLE photos (id INTEGER PRIMARY KEY, owner TEXT, \
                          content_id BLOB, content_state TEXT, edited_at TEXT)";

/// The photograph this case carries the whole way.
const PHOTO: &[u8] = b"JPEG-ish bytes standing in for a photograph taken in the field, \
                       long enough that a ranged request over it means something";

diesel::table! {
    /// The application's photo entries, on the replica.
    photos (id) {
        /// Entry identifier.
        id -> diesel::sql_types::Integer,
        /// Identity that owns the entry.
        owner -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
        /// BLAKE3 identity of the photo's bytes.
        content_id -> diesel::sql_types::Nullable<diesel::sql_types::Binary>,
        /// Availability of the bytes, as the server last said.
        content_state -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
        /// Optimistic concurrency column.
        edited_at -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

/// The deployment statements this case needs beside the file server's own DDL.
///
/// `connetto_visible_files` and `connetto_set_content_state` are the two
/// contracts the file server requires, here answered from the application's
/// own `photos` table. The setter writes `content_state`, which is what makes
/// the availability signal an ordinary row change the sync path already
/// carries.
const DEPLOYMENT: &[&str] = &[
    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_writer') \
     THEN CREATE ROLE app_writer LOGIN PASSWORD 'app_writer'; END IF; END $$",
    "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'file_reader') \
     THEN CREATE ROLE file_reader LOGIN PASSWORD 'file_reader' NOINHERIT; END IF; END $$",
    "CREATE TABLE photos (id INT PRIMARY KEY, owner TEXT, content_id BYTEA, \
     content_state TEXT, edited_at TEXT)",
    "ALTER TABLE photos REPLICA IDENTITY FULL",
    "GRANT USAGE ON SCHEMA public TO app_writer",
    "GRANT USAGE ON SCHEMA public TO file_reader",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON photos TO app_writer",
    "GRANT SELECT, UPDATE ON photos TO file_reader",
    "GRANT SELECT ON _cfs_manifests TO file_reader",
    "GRANT SELECT ON _cfs_manifest_chunks TO file_reader",
    "CREATE OR REPLACE FUNCTION connetto_visible_files(p_file_ids BYTEA[]) \
     RETURNS BYTEA[] LANGUAGE sql SECURITY INVOKER SET search_path TO '' AS $$ \
       SELECT ARRAY(SELECT f FROM UNNEST(p_file_ids) AS f \
         WHERE EXISTS (SELECT 1 FROM public.photos p WHERE p.content_id = f)) \
     $$",
    "GRANT EXECUTE ON FUNCTION connetto_visible_files TO file_reader",
    "GRANT EXECUTE ON FUNCTION connetto_visible_files TO app_writer",
    "CREATE OR REPLACE FUNCTION connetto_set_content_state(p_file_id BYTEA, \
     p_new_state TEXT, p_caller TEXT) RETURNS BYTEA LANGUAGE plpgsql \
     SECURITY DEFINER SET search_path TO '' AS $$ BEGIN \
       UPDATE public.photos SET content_state = p_new_state WHERE content_id = p_file_id; \
       RETURN p_file_id; END; $$",
    "GRANT EXECUTE ON FUNCTION connetto_set_content_state TO file_reader",
];

/// The whole case, in one test because each half is the other's premise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker: the fixture starts its own Postgres"]
async fn a_photo_written_offline_arrives_and_a_second_device_fetches_it() {
    let fixture = Fixture::acquire().await;
    provision(&fixture).await;
    let chunk_dir = tempdir().expect("temp dir");
    let (base_url, signer, files) = start_file_server(&fixture, chunk_dir.path()).await;

    // The sync server, with that signer wired into its session loop.
    let server = Arc::new(spawn_sync_server(&fixture, signer).await);

    // Device A: replica opened with no transport, so the entry and its bytes
    // are written while the gate is closed.
    let replica_dir = tempdir().expect("temp dir");
    let (a, gate) = offline_device_a(replica_dir.path(), &server);
    let a_content = attach_device_a_content(a, chunk_dir.path()).await;
    let file_id = stage_offline_photo(&a_content).await;

    // Reconnect: the row goes up as an ordinary mutation, the bytes go up
    // through the outbox walk, and the walk has to wait for the row: a write
    // ticket is refused for a file the deployment cannot yet see, and what
    // makes it visible is the mutation landing.
    gate.store(true, Ordering::Relaxed);
    let uploaded = wait_for_upload(&a_content).await;
    assert_eq!(uploaded, 1, "the outbox walk sent the one file waiting");

    // Postgres now holds the row, the manifest, and the flipped state.
    let state = wait_for_state(&fixture, file_id.as_bytes()).await;
    assert_eq!(
        state.as_deref(),
        Some("available"),
        "the commit called the deployment's setter, which is the availability signal"
    );

    // Device B, a second device, sees the row and the flipped state on its
    // own replica through an ordinary subscription.
    let (b, b_content) = setup_device_b(replica_dir.path(), &server, chunk_dir.path()).await;
    b.pin("photos", "SELECT * FROM photos")
        .await
        .expect("device B declares a durable interest in the photos");
    let seen = wait_for_replica_state(&b, file_id.as_bytes()).await;
    assert_eq!(
        seen.as_deref(),
        Some("available"),
        "device B learns the bytes are fetchable from the row, not from the content channel"
    );
    assert_device_b_fetches_photo(&b_content, &base_url, file_id).await;

    files.abort();
}

/// Attaches a content client to device A's dedicated chunk directory.
async fn attach_device_a_content(
    a: ConnettoClient<LoopbackTransport>,
    chunk_dir: &std::path::Path,
) -> ContentClient<LoopbackTransport, FsStore, ReqwestHttp> {
    ContentClient::attach(
        a,
        FsStore::new(chunk_dir.join("device-a")),
        [3; 32],
        ReqwestHttp::new(),
    )
    .await
    .expect("attach content handling to device A")
}

/// Stages the test photograph on device A as photo row 1 and asserts the
/// bytes resolve from the local chunk store.
///
/// Returns the file identity so the reconnect path can reference it.
async fn stage_offline_photo(
    a_content: &ContentClient<LoopbackTransport, FsStore, ReqwestHttp>,
) -> FileId {
    let (file_id, ()) = a_content
        .stage(PHOTO, MimeClass::Jpeg, |conn, file_id| {
            diesel::insert_into(photos::table)
                .values((
                    photos::id.eq(1),
                    photos::owner.eq("alice"),
                    photos::content_id.eq(file_id.as_bytes().to_vec()),
                    photos::edited_at.eq("t0"),
                ))
                .execute(conn)
                .map(|_| ())
        })
        .await
        .expect("stage the photo offline");
    assert!(
        matches!(
            a_content.resolve(file_id).await.expect("resolve offline"),
            Resolved::Local { .. }
        ),
        "the bytes are readable on the device that authored them, with no server"
    );
    file_id
}

/// Connects device B to the sync server and attaches a fresh content client.
///
/// Returns both so the test can pin a subscription and then poll replica state.
async fn setup_device_b(
    replica_root: &std::path::Path,
    server: &Arc<Server>,
    chunk_dir: &std::path::Path,
) -> (
    ConnettoClient<LoopbackTransport>,
    ContentClient<LoopbackTransport, FsStore, ReqwestHttp>,
) {
    let b = connect_device_b(replica_root, server).await;
    let b_content = ContentClient::attach(
        b.clone(),
        FsStore::new(chunk_dir.join("device-b")),
        [4; 32],
        ReqwestHttp::new(),
    )
    .await
    .expect("attach content handling to device B");
    (b, b_content)
}

/// Resolves the photograph on device B via a signed URL, performs a ranged
/// GET and checks the partial-content status and the first sixteen bytes,
/// then downloads the whole file and checks it is byte-identical to the
/// original.
async fn assert_device_b_fetches_photo(
    b_content: &ContentClient<LoopbackTransport, FsStore, ReqwestHttp>,
    base_url: &str,
    file_id: FileId,
) {
    let resolved = b_content
        .resolve(file_id)
        .await
        .expect("resolve on device B");
    let Resolved::Remote { url } = resolved else {
        panic!("device B holds no local bytes, so the answer is a signed URL, got {resolved:?}");
    };
    assert!(
        url.starts_with(base_url),
        "the granted URL addresses the file server, got {url}"
    );
    let ranged = reqwest::Client::new()
        .get(&url)
        .header(reqwest::header::RANGE, "bytes=0-15")
        .send()
        .await
        .expect("ranged request");
    assert_eq!(
        ranged.status().as_u16(),
        206,
        "a range is served as a partial response"
    );
    let head = ranged.bytes().await.expect("ranged body");
    assert_eq!(
        head.as_ref(),
        &PHOTO[..16],
        "the range is the first sixteen bytes of the photograph"
    );
    let whole = b_content
        .bytes(file_id)
        .await
        .expect("download the whole file")
        .expect("the server holds it");
    assert_eq!(whole, PHOTO, "device B reads the photograph device A wrote");
}

/// Opens device A's replica with no transport at all and drives it with the
/// reconnect pump behind a gate.
///
/// The gate is what makes the offline half genuine: the factory refuses to
/// produce a transport until the test opens it, so the device is offline in
/// exactly the way a device with no network is, and the reconnect is the
/// production reconnect path rather than a hand-placed attach.
fn offline_device_a(
    replica_root: &std::path::Path,
    server: &Arc<Server>,
) -> (ConnettoClient<LoopbackTransport>, Arc<AtomicBool>) {
    let path = replica_root.join("a.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");
    let conn = ConnettoConnection::<LoopbackTransport>::open(
        &replica,
        SQLITE_DDL,
        &config("device-a", "user:alice#writer"),
        None,
    )
    .expect("open device A with no server");
    assert!(
        !conn.is_connected(),
        "device A is offline, which is the premise of the whole case"
    );
    let gate = Arc::new(AtomicBool::new(false));
    let factory_gate = Arc::clone(&gate);
    let factory_server = Arc::clone(server);
    let (client, pump) = ConnettoClient::with_reconnect(
        conn,
        move || {
            let gate = Arc::clone(&factory_gate);
            let server = Arc::clone(&factory_server);
            async move {
                if gate.load(Ordering::Relaxed) {
                    Ok(server.attach())
                } else {
                    Err("device A has no server yet")
                }
            }
        },
        TokioSleeper,
        ReconnectPolicy::default(),
    );
    tokio::spawn(pump);
    (client, gate)
}

/// Connects the second device, which was never offline and holds no bytes.
async fn connect_device_b(
    replica_root: &std::path::Path,
    server: &Arc<Server>,
) -> ConnettoClient<LoopbackTransport> {
    let path = replica_root.join("b.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");
    let conn = ConnettoConnection::connect(
        server.attach(),
        &replica,
        SQLITE_DDL,
        &config("device-b", "user:alice#reader"),
        None,
    )
    .await
    .expect("connect device B");
    ConnettoClient::start(conn)
}

/// Installs the file server's own schema, the application's table, the two
/// deployment contracts, and the roles each side connects as.
async fn provision(fixture: &Fixture) {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS photos CASCADE",
            "DROP TABLE IF EXISTS _connetto_mutations",
        ])
        .await;
    for statement in split_statements(connetto_file_server::DEPLOYMENT_DDL) {
        fixture.exec(&statement).await;
    }
    for statement in DEPLOYMENT {
        fixture.exec(statement).await;
    }
    connetto_test_harness::provision_watermark(fixture.admin()).await;
    fixture
        .exec("GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_writer")
        .await;
}

/// Starts the file server on its own socket, so the ticket's base URL is real
/// and the ranged `GET` at the end goes over a real one.
///
/// Returns that base URL, the signer the sync server mints with, and the task
/// serving it.
async fn start_file_server(
    fixture: &Fixture,
    chunk_root: &std::path::Path,
) -> (String, TicketSigner, tokio::task::JoinHandle<()>) {
    let reader_pool = pool_for(&with_user(
        fixture.admin_url(),
        "file_reader",
        "file_reader",
    ))
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the file server");
    let base_url = format!("http://{}", listener.local_addr().expect("address"));
    let (signer, public_key) =
        TicketSigner::generate(base_url.clone(), Duration::from_secs(600), 1 << 20)
            .expect("generate a ticket key");
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
        _schema: PhantomData,
    })
    .await
    .expect("the deployment contracts are in place");
    let serving = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (base_url, signer, serving)
}

/// The client configuration one device opens with.
///
/// The grant differs per device on purpose: a session handle is durable and a
/// second connection presenting the same grant supersedes the first, so two
/// devices of one user are two grants.
fn config(client_id: &str, grant: &str) -> ClientConfig {
    ClientConfig::new(client_id).with_login(Some(Grant::new(grant)))
}

/// A harness server with the file server's signer wired into its session loop.
async fn spawn_sync_server(fixture: &Fixture, signer: TicketSigner) -> Server {
    let writer_pool = pool_for(&with_user(fixture.admin_url(), "app_writer", "app_writer")).await;
    let snapshot =
        PgSnapshotSource::from_ddl(writer_pool.clone(), PG_DDL).expect("snapshot source");
    let auth = HarnessAuth::rls(RlsAuth::from_ddl(writer_pool.clone(), PG_DDL).expect("rls auth"));
    spawn_server(
        ServerConfig::new(PG_DDL, fixture.admin_url())
            .with_writable(
                RuntimeWritableCatalog::builder()
                    .versioned("photos", "edited_at")
                    .build(),
            )
            .with_replication(["photos"])
            .with_content_signer(signer),
        snapshot,
        auth,
        writer_pool,
        fixture.admin().clone(),
    )
    .await
}

/// Walks the outbox until it sends, or gives up loudly.
async fn wait_for_upload(
    content: &ContentClient<LoopbackTransport, FsStore, ReqwestHttp>,
) -> usize {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let sent = content.flush_outbox().await.expect("walk the outbox");
        if sent > 0 {
            return sent;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the outbox never drained"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Reads `content_state` out of Postgres until the commit has flipped it.
async fn wait_for_state(fixture: &Fixture, file_id: &[u8; 32]) -> Option<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    // One connection for the whole wait: taking a fresh one per turn starves
    // the pool the server is also using.
    let mut conn = fixture.admin().get().await.expect("admin connection");
    loop {
        let query = diesel::sql_query("SELECT content_state FROM photos WHERE content_id = $1")
            .bind::<diesel::sql_types::Bytea, _>(file_id.to_vec());
        let rows: Vec<Option<String>> =
            diesel_async::RunQueryDsl::load::<StateRow>(query, &mut *conn)
                .await
                .expect("read the state")
                .into_iter()
                .map(|row| row.content_state)
                .collect();
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

/// One `content_state` cell.
#[derive(diesel::QueryableByName)]
struct StateRow {
    /// Availability of the bytes.
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    content_state: Option<String>,
}

/// Reads `content_state` off a device's own replica until sync delivers it.
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
                .expect("read the replica")
            })
            .await;
        if let Some(state) = state.into_iter().next().flatten() {
            return Some(state);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the state never reached the second device's replica"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Splits DDL with no dollar-quoted bodies on semicolons.
fn split_statements(ddl: &str) -> Vec<String> {
    ddl.split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .map(str::to_owned)
        .collect()
}
