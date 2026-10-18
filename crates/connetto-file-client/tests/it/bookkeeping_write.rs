//! Content bookkeeping never rides an application upload.
//!
//! One online device uploads a photo, which deletes its row from
//! `_connetto_content_outbox` through `with_conn`, and then makes an ordinary
//! write. The server has no `_connetto_content_outbox` table, so a captured
//! delete would come back as a refused mutation. The application's row must
//! reach Postgres and no `ClientEvent::MutationRejected` may arrive.
//!
//! Needs Docker. The fixture starts its own Postgres, and the file server
//! runs beside it on a real socket.

use core::future::Future;
use core::time::Duration;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use connetto_client::live::ConnettoClient;
use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientBuilder, ClientEvent, Gate, Grant, HeldCredential, SyncSchema};
use connetto_core::schema::SchemaBundle;
use connetto_core::transport::LoopbackTransport;
use connetto_file_client::{ContentClient, FsStore, ReqwestHttp};
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

/// The two contracts the file server requires, answered from the application's `photos` table.
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

/// An upload's outbox delete leaves the next application write landing unrefused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker: the fixture starts its own Postgres"]
async fn the_content_outbox_delete_never_rides_an_application_write() {
    let fixture = Fixture::acquire().await;
    provision(&fixture).await;
    let chunk_dir = tempdir().expect("temp dir");
    let (signer, files) = start_file_server(&fixture, chunk_dir.path()).await;

    let server = Arc::new(spawn_sync_server(&fixture, signer).await);

    let replica_dir = tempdir().expect("temp dir");
    let a = online_device_a(replica_dir.path(), &server).await;

    // A broadcast receiver only sees events sent after it subscribes.
    let mut events = a.events();
    let seen = Arc::new(Mutex::new(Vec::<ClientEvent>::new()));
    {
        let seen = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                seen.lock().expect("seen lock poisoned").push(event);
            }
        });
    }

    let a_content = attach_content(a.clone(), chunk_dir.path()).await;
    let file_id = stage_photo(&a_content).await;

    let uploaded = wait_for_upload(&a_content).await;
    assert_eq!(uploaded, 1, "the outbox walk sent the one file waiting");
    wait_for_pg_state(&fixture, file_id.as_bytes(), "available").await;

    // Made while the upload's outbox delete would still sit in an unfiltered capture session.
    a.with_conn(|conn| {
        diesel::insert_into(photos::table)
            .values((
                photos::id.eq(2),
                photos::owner.eq("bob"),
                photos::content_id.eq::<Option<Vec<u8>>>(None),
                photos::edited_at.eq("t1"),
            ))
            .execute(conn.conn())
            .expect("write the ordinary application row")
    })
    .await
    .expect("the application write runs");

    wait_for_app_row(&fixture).await;

    // Lets the collector drain every event sent before the row landed.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let seen = seen.lock().expect("seen lock poisoned").clone();
    let rejected: Vec<u64> = seen
        .iter()
        .filter_map(|event| match event {
            ClientEvent::MutationRejected { client_seq, .. } => Some(*client_seq),
            _ => None,
        })
        .collect();
    assert_eq!(
        rejected,
        Vec::<u64>::new(),
        "the server refused a mutation carrying content bookkeeping"
    );

    files.abort();
}

/// One device of alice's at `path`, redialing through `dial` under the default policy.
async fn device<F, Fut>(
    path: &std::path::Path,
    grant: &str,
    dial: F,
) -> ConnettoClient<LoopbackTransport>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<LoopbackTransport, &'static str>> + Send + 'static,
{
    let credential =
        HeldCredential::new(Grant::new(grant), "alice").expect("a string identity serializes");
    let (running, pump) = ClientBuilder::new(
        SyncSchema::new(SchemaBundle::new(
            PG_DDL,
            "",
            SQLITE_DDL,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )),
        dial,
    )
    .with_reconnect(ReconnectPolicy::default())
    .signed_in(credential)
    .durable(
        super::support::At(path.to_path_buf()),
        super::support::FixedKey,
    )
    .with_gate(Gate::off())
    .connect_with_pump()
    .await
    .expect("open the device");
    tokio::spawn(pump);
    running.client().clone()
}

/// The one device, online from the start and holding the bytes it stages.
async fn online_device_a(
    replica_root: &std::path::Path,
    server: &Arc<Server>,
) -> ConnettoClient<LoopbackTransport> {
    let server = Arc::clone(server);
    device(
        &replica_root.join("a.sqlite"),
        "user:alice#writer",
        move || {
            let server = Arc::clone(&server);
            async move { Ok(server.attach()) }
        },
    )
    .await
}

/// Attaches a content client to the device's dedicated chunk directory.
async fn attach_content(
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
    .expect("attach content handling to the device")
}

/// Stages the test photograph as photo row 1 and returns the file identity.
async fn stage_photo(a_content: &ContentClient<LoopbackTransport, FsStore, ReqwestHttp>) -> FileId {
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
        .expect("stage the photo");
    file_id
}

/// Installs the file server's schema, the application's table, the deployment contracts and the roles.
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

/// Starts the file server on its own socket and returns the signer the sync server mints with.
async fn start_file_server(
    fixture: &Fixture,
    chunk_root: &std::path::Path,
) -> (TicketSigner, tokio::task::JoinHandle<()>) {
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
    let (signer, public_key) = TicketSigner::generate(&base_url, Duration::from_secs(600), 1 << 20)
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
        caller_settings: connetto_file_server::CallerSettings::default(),
        quotas: connetto_file_server::QuotaSettings::default(),
        ceilings: connetto_file_server::CeilingCache::default(),
        _schema: PhantomData,
    })
    .await
    .expect("the deployment contracts are in place");
    let serving = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (signer, serving)
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

/// Reads `content_state` out of Postgres until it equals `wanted`.
async fn wait_for_pg_state(fixture: &Fixture, file_id: &[u8; 32], wanted: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut conn = fixture.admin().get().await.expect("admin connection");
    loop {
        let rows: Vec<Option<String>> = diesel_async::RunQueryDsl::load(
            photos::table
                .filter(photos::content_id.eq(file_id.to_vec()))
                .select(photos::content_state),
            &mut *conn,
        )
        .await
        .expect("read the state");
        if rows.into_iter().flatten().any(|state| state == wanted) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "content_state never became {wanted} in Postgres"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Waits, bounded, until Postgres holds the application's second row.
async fn wait_for_app_row(fixture: &Fixture) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut conn = fixture.admin().get().await.expect("admin connection");
    loop {
        let rows: Vec<(i32, Option<String>)> = diesel_async::RunQueryDsl::load(
            photos::table
                .filter(photos::id.eq(2))
                .select((photos::id, photos::owner)),
            &mut *conn,
        )
        .await
        .expect("read the application's own row");
        if rows
            .iter()
            .any(|(_, owner)| owner.as_deref() == Some("bob"))
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the application's own write never reached Postgres; the content \
             bookkeeping rode the same mutation and the server refused the whole thing"
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
