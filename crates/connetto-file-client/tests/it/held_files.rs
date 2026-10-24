//! R31 content proof: a rebuild at a newer major holds an older major's
//! unsent file beside its unsent writes, and a drain uploads both over a
//! second wire whose handshake presents the old major.
//!
//! A test-local router stands in for the deployment proxy, routing each
//! connection to the hosted entry at the declared `schema_major`, or to the
//! newest hosted major when none matches. Each hosted major is an in-process
//! manager over the fixture's Postgres with the file server's ticket signer,
//! so a held file's write ticket is minted on the drain wire the way the
//! deployment mints it. The file server runs beside the router on a real
//! socket and is reachable for every hosted major.
//!
//! The offline open models the old app's process, which the update ends.
//!
//! `a_held_file_drains_to_its_major` proves the drain. A device at major 1
//! stages a photo while no server is reachable, so its row write and its
//! file are both pending. The deployment migrates Postgres additively and
//! hosts major 2 beside major 1, and the device reopens at major 2. The
//! held write drains to the major 1 manager as `HeldWork::Applied`, the
//! held file uploads through the drain wire's ticket to the file server and
//! its `content_state` flips in Postgres, and the batch closes as
//! `HeldWork::Drained` with nothing left pending.
//!
//! `a_held_file_of_a_decommissioned_major_is_lost` proves the decommission
//! half. With major 1 retired before the reopen, the drained major is gone,
//! and the held work reaches its drain as `HeldWork::Lost` naming the
//! write's sequence and the file, with nothing reaching the file server or
//! Postgres.
//!
//! Needs Docker, since the fixture starts its own Postgres.
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use connetto_client::teardown::content_dir;
use connetto_client::{
    ClientBuilder, ClientError, ClientEvent, ConnettoClient, CoreClient, CorePump, DataDir, Grant,
    HeldCredential, MemoryRefreshStore, PendingWork, ReconnectPolicy, SyncSchema, TransportFactory,
};
use connetto_core::auth::ContentCaller;
use connetto_core::messages::{BulkMessage, ContentVerb, ControlMessage, HeldWork};
use connetto_core::schema::SchemaBundle;
use connetto_core::test_support::{TestGrantChecker, replica_key};
use connetto_core::traits::{ContentTicketSigner, IncomingFrame, Transport};
use connetto_core::{MAJOR_DIRECTIVE, Major, SchemaVersion, WebSocketError};
use connetto_file_client::{Content, ContentClient, ContentHandle, FsStore, ReqwestHttp};
use connetto_file_core::{FileId, MimeClass};
use connetto_file_server::{
    AppPools, Config, DefaultFileSchema, FsStore as ServerStore, TicketSigner, TicketVerifier,
    ticket::TicketError,
};
use connetto_server::{
    ConnettoSchema, InMemoryOplog, ManagerBuilder, Materializer, PgReadConnector, PgSnapshotSource,
    RuntimeWritableCatalog, SessionConfig, SessionManager, WebSocketTransport, pg_write_target,
};
use connetto_test_harness::router::{HostedEntry, Relay, Router};
use connetto_test_harness::{ConnettoDefaults, Fixture, RosterAuth, pool_for, with_user};
use diesel::prelude::*;
use tempfile::tempdir;
use tokio::net::TcpStream;

/// The application's own table, as major 1's manager serves it.
const PG_DDL_V1: &str = "-- connetto:major 1\nCREATE TABLE photos (id INT PRIMARY KEY, owner TEXT, content_id BYTEA, \
     content_state TEXT, edited_at TEXT);";
/// The same table after the deployment's additive migration, as major 2's
/// manager serves it.
const PG_DDL_V2: &str = "-- connetto:major 2\nCREATE TABLE photos (id INT PRIMARY KEY, owner TEXT, content_id BYTEA, \
     content_state TEXT, edited_at TEXT, taken_at TEXT);";
/// The replica DDL at each major, `IF NOT EXISTS` because `connect` replays
/// the caller's DDL on every open.
const SQLITE_DDL_V1: &str = "CREATE TABLE IF NOT EXISTS photos (id INTEGER PRIMARY KEY, owner TEXT, \
                              content_id BLOB, content_state TEXT, edited_at TEXT)";
const SQLITE_DDL_V2: &str = "CREATE TABLE IF NOT EXISTS photos (id INTEGER PRIMARY KEY, owner TEXT, \
                              content_id BLOB, content_state TEXT, edited_at TEXT, taken_at TEXT)";

/// The photograph this case carries the whole way.
const PHOTO: &[u8] = b"JPEG-ish bytes standing in for a photograph taken in the field, \
                       long enough that a ranged request over it means something";

/// The deployment statements this case needs beside the file server's own
/// DDL.
///
/// `connetto_visible_files` and `connetto_set_content_state` are the two
/// contracts the file server requires, here answered from the application's
/// own `photos` table. The setter writes `content_state`, which is what
/// makes the availability signal an ordinary row change the sync path
/// already carries.
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

diesel::table! {
    /// The application's photo entries, as the replica holds them at major 2.
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
        /// Field time the deployment added at major 2.
        taken_at -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

diesel::table! {
    /// The file server's manifest records, read as admin when a case proves
    /// that a file never reached the store.
    #[sql_name = "_cfs_manifests"]
    cfs_manifests (file_id, uploaded_by) {
        /// BLAKE3 identity of the file.
        file_id -> diesel::sql_types::Binary,
        /// The caller that uploaded the bytes.
        uploaded_by -> diesel::sql_types::Text,
    }
}

/// The hosted major a device leaves behind when the deployment migrates.
fn one() -> Major {
    Major::new(1).expect("one is a major")
}

/// The hosted major an updated device opens at.
fn two() -> Major {
    Major::new(2).expect("two is a major")
}

/// The build at `major` over `ddl`, the source the real `build.rs` would
/// translate.
#[must_use]
fn build(major: u32, ddl: &str) -> SyncSchema {
    SyncSchema::new(
        SchemaBundle::new(
            format!("{MAJOR_DIRECTIVE} {major}"),
            "",
            ddl,
            Vec::<(String, String)>::new(),
            Vec::<String>::new(),
            None::<&str>,
        )
        .expect("the source declares its major"),
    )
}

/// The version a manager built from the same source advertises, so a
/// matching build passes the hash check at the ack.
#[must_use]
fn advertised(major: u32, ddl: &str) -> SchemaVersion {
    build(major, ddl).version()
}

/// A dial through the router that failed, at the socket or the handshake
/// step.
#[derive(Debug, thiserror::Error)]
#[error("the dial to the router failed: {0}")]
struct DialFailed(String);

/// A dial refused before the socket, the offline device's only answer.
#[derive(Debug, thiserror::Error)]
#[error("no server is reachable")]
struct Unreachable;

/// The file server's ticket signer, shared by every hosted major's manager.
#[derive(Clone)]
struct Signer(Arc<TicketSigner>);

impl ContentTicketSigner for Signer {
    type Error = TicketError;

    fn mint(
        &self,
        caller: &ContentCaller,
        file_id: [u8; 32],
        verb: ContentVerb,
    ) -> impl core::future::Future<Output = Result<String, Self::Error>> + Send {
        ContentTicketSigner::mint(&*self.0, caller, file_id, verb)
    }
}

/// The router entry that serves `manager` with whatever connection the
/// router routed, the replayed handshake included.
fn entry(manager: Arc<Manager>) -> HostedEntry {
    Arc::new(move |relay: Relay| {
        let manager = Arc::clone(&manager);
        Box::pin(async move {
            let _ = manager.serve(relay).await;
        })
    })
}

/// A manager for one hosted major over the fixture's Postgres, serving `ddl`
/// and minting content tickets with `signer`.
fn manager(
    fixture: &Fixture,
    ddl: &str,
    major: Major,
    version: SchemaVersion,
    signer: &Signer,
) -> Arc<Manager> {
    let pool = fixture.admin().clone();
    ManagerBuilder::new(
        Materializer::builder(ddl)
            .with_write_catalog(RuntimeWritableCatalog::builder().writable("photos").build())
            .with_read_connector(PgReadConnector::with_session_setup(pool.clone()))
            .build()
            .expect("build materializer"),
        PgSnapshotSource::from_ddl(pool.clone(), ddl).expect("snapshot source"),
        RosterAuth::granting("token"),
        Arc::new(TestGrantChecker),
        PgReadConnector::with_session_setup(pool.clone()),
        pg_write_target::<ConnettoDefaults>(pool, ddl).expect("build write target"),
    )
    .with_signer(signer.clone())
    .with_session(
        SessionConfig::new()
            .with_schema_major(Some(major))
            .with_schema_version(Some(version)),
    )
    .build()
}

/// A manager whose writes and content tickets run over the fixture's
/// Postgres, serving one hosted major.
type Manager = SessionManager<
    PgSnapshotSource,
    RosterAuth,
    ConnettoDefaults,
    PgReadConnector,
    InMemoryOplog,
    <ConnettoDefaults as ConnettoSchema>::Id,
    String,
    Signer,
>;

/// The one dialer a build names, the socket connect and the upgrade.
/// Routing by major stays the router's business.
fn dial(
    addr: std::net::SocketAddr,
) -> impl TransportFactory<Transport = WebSocketTransport<TcpStream>, Error = DialFailed> {
    move || async move {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|err| DialFailed(err.to_string()))?;
        WebSocketTransport::connect("ws://127.0.0.1/", stream)
            .await
            .map_err(|err| DialFailed(err.to_string()))
    }
}

/// A dialer that refuses every dial, so the device is offline the way a
/// device with no network is.
fn dial_dead()
-> impl TransportFactory<Transport = WebSocketTransport<TcpStream>, Error = Unreachable> {
    move || core::future::ready(Err(Unreachable))
}

/// The held credential for a device, the grant the roster resolves.
#[must_use]
fn credential(device: &str) -> HeldCredential {
    HeldCredential::new(Grant::new(format!("user:token#{device}")), "token")
        .expect("a string identity serializes")
}

/// The reconnect policy the test pumps drive, with a short backoff so a
/// broken dial surfaces inside the test bounds.
#[must_use]
fn test_policy() -> ReconnectPolicy {
    ReconnectPolicy::new()
        .with_initial_backoff(Duration::from_millis(1))
        .with_max_backoff(Duration::from_millis(20))
}

/// A running client over the router dial, with its durable content handle.
type Core = CoreClient<WebSocketTransport<TcpStream>, ContentHandle<WebSocketTransport<TcpStream>>>;

/// Open the build at `dir` with no server reachable, the way an app opens
/// offline, its content attached.
///
/// The offline phase models the old process an update ends, so content is
/// attached by hand and `drive_outbox` is never spawned, which would otherwise
/// keep the replica locked past the close.
async fn open_offline(
    schema: SyncSchema,
    device: &str,
    dir: &std::path::Path,
) -> Result<
    (
        ConnettoClient<WebSocketTransport<TcpStream>>,
        CorePump,
        Arc<ContentClient<WebSocketTransport<TcpStream>, FsStore, ReqwestHttp>>,
    ),
    ClientError,
> {
    let held = credential(device);
    let replica_name = held.replica_name().to_owned();
    let conn = ClientBuilder::new(schema, dial_dead())
        .signed_in(held)
        .durable(
            DataDir::new(dir.to_path_buf()),
            super::support::FixedKey,
            MemoryRefreshStore::default(),
        )
        .open_driven()
        .await?;
    let (client, pump) = ConnettoClient::with_pump(conn);
    let root_key = *replica_key().as_bytes();
    let content_path = content_dir(&dir.join(&replica_name));
    let content = Arc::new(
        ContentClient::attach(
            client.clone(),
            FsStore::new(content_path),
            root_key,
            ReqwestHttp::new(),
        )
        .await
        .map_err(|err| ClientError::Content(err.to_string()))?,
    );
    Ok((client, Box::pin(pump), content))
}

/// Connect the build at `dir` through the router with the live pump, the
/// path a deployed app takes.
async fn connect_pumped(
    router: &Router,
    schema: SyncSchema,
    device: &str,
    dir: &std::path::Path,
) -> Result<(Core, CorePump), ClientError> {
    let held = credential(device);
    ClientBuilder::new(schema, dial(router.addr()))
        .with_content(Content::new())
        .with_reconnect(test_policy())
        .signed_in(held)
        .durable(
            DataDir::new(dir.to_path_buf()),
            super::support::FixedKey,
            MemoryRefreshStore::default(),
        )
        .connect_with_pump()
        .await
}

/// Stages the test photograph on the device as photo row 1 and returns the
/// file identity so the drain can be watched for it.
async fn stage_offline_photo(
    content: &ContentClient<WebSocketTransport<TcpStream>, FsStore, ReqwestHttp>,
) -> FileId {
    let (file_id, ()) = content
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
    file_id
}

/// Reads `content_state` out of Postgres until it equals `wanted`.
async fn wait_for_pg_state(fixture: &Fixture, file_id: &[u8; 32], wanted: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let row = file_id.to_vec();
    loop {
        let mut conn = fixture.admin().get().await.expect("admin connection");
        let states: Vec<Option<String>> = diesel_async::RunQueryDsl::load::<Option<String>>(
            photos::table
                .filter(photos::content_id.eq(row.clone()))
                .select(photos::content_state),
            &mut *conn,
        )
        .await
        .expect("read the state");
        if states.into_iter().next().flatten().as_deref() == Some(wanted) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "content_state never became {wanted}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The number of Postgres `photos` rows, read as admin.
async fn server_photos(fixture: &Fixture) -> i64 {
    let mut conn = fixture.admin().get().await.expect("admin connection");
    let count: i64 = diesel_async::RunQueryDsl::get_result(photos::table.count(), &mut *conn)
        .await
        .expect("count the photos rows");
    count
}

/// The number of file server manifest rows for `file_id`, read as admin.
async fn server_manifests_for(fixture: &Fixture, file_id: &[u8; 32]) -> i64 {
    let mut conn = fixture.admin().get().await.expect("admin connection");
    let count: i64 = diesel_async::RunQueryDsl::get_result(
        cfs_manifests::table
            .filter(cfs_manifests::file_id.eq(file_id.to_vec()))
            .count(),
        &mut *conn,
    )
    .await
    .expect("count the manifest rows");
    count
}

/// Read events until `wanted` arrives by `deadline`, failing on any event
/// `forbidden` names.
async fn await_event(
    events: &mut tokio::sync::broadcast::Receiver<ClientEvent>,
    deadline: tokio::time::Instant,
    wanted: impl Fn(&ClientEvent) -> bool,
    forbidden: impl Fn(&ClientEvent) -> bool,
) {
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("the awaited event arrives within the deadline")
            .expect("event stream closed");
        assert!(!forbidden(&event), "unexpected event {event:?}");
        if wanted(&event) {
            return;
        }
    }
}

/// A refused write, which no step of the drain may cause, since it carries
/// no write of the application's own.
fn rejected(event: &ClientEvent) -> bool {
    matches!(event, ClientEvent::MutationRejected { .. })
}

/// The bound every wait in this file honors, so a wedged path fails, not
/// hangs.
fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_secs(10)
}

/// Installs the file server's own schema, the application's table, the two
/// deployment contracts, and the roles each side connects as.
async fn provision(fixture: &Fixture) {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS photos CASCADE",
            "DROP TABLE IF EXISTS _connetto_writers, _connetto_settled CASCADE",
        ])
        .await;
    for statement in split_statements(connetto_file_server::DEPLOYMENT_DDL) {
        fixture.exec(&statement).await;
    }
    for statement in DEPLOYMENT {
        fixture.exec(statement).await;
    }
    connetto_test_harness::provision_writers(fixture.admin()).await;
    fixture
        .exec(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON _connetto_writers, _connetto_settled \
             TO app_writer",
        )
        .await;
}

/// Starts the file server on its own socket, so the ticket's base URL is
/// real and the drain's upload goes over a real one.
///
/// Returns that base URL, the signer the managers mint with, and the task
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
    (base_url, signer, serving)
}

/// Splits DDL with no dollar-quoted bodies on semicolons.
fn split_statements(ddl: &str) -> Vec<String> {
    ddl.split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The drain story. Device A stages a photo at major 1 while offline, the
/// deployment migrates and hosts major 2 beside major 1, and the device
/// reopens at major 2. The held write lands in Postgres as `Applied`, the
/// held file uploads through the drain wire's ticket, and the batch closes
/// as `Drained` with nothing left pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_file_drains_to_its_major() {
    let fixture = Fixture::acquire().await;
    provision(&fixture).await;
    let chunk_dir = tempdir().expect("temp dir");
    let (_base_url, signer, files) = start_file_server(&fixture, chunk_dir.path()).await;
    let signer = Signer(Arc::new(signer));

    // Major 1 is hosted from the start. The device stays offline behind
    // its own refusal to dial.
    let manager1 = manager(
        &fixture,
        PG_DDL_V1,
        one(),
        advertised(1, SQLITE_DDL_V1),
        &signer,
    );
    let router = Router::start(vec![(one(), entry(manager1))]).await;
    let dir = tempdir().expect("device A's replica dir");

    // Device A at major 1, offline. The entry and the bytes both stay
    // pending.
    let file_id = {
        let (client, pump, content) = open_offline(build(1, SQLITE_DDL_V1), "device-a", dir.path())
            .await
            .expect("the offline open");
        let pump_task = tokio::spawn(pump);
        let file_id = stage_offline_photo(&content).await;
        client.close().await;
        pump_task.await.expect("the pump ends on close");
        file_id
    };

    // The deployment migrates Postgres and hosts major 2 beside major 1.
    fixture
        .exec("ALTER TABLE photos ADD COLUMN taken_at TEXT")
        .await;
    let manager2 = manager(
        &fixture,
        PG_DDL_V2,
        two(),
        advertised(2, SQLITE_DDL_V2),
        &signer,
    );
    router.host(two(), entry(manager2));

    // Device A reopens on the same replica directory with the major 2
    // build, the way an updated app opens.
    let (core, pump) = connect_pumped(&router, build(2, SQLITE_DDL_V2), "device-a", dir.path())
        .await
        .expect("the update opens");
    let client = core.client().clone();
    let ContentHandle::Durable(content) = core.content().expect("content attached") else {
        panic!("the durable build places content beside the replica file")
    };

    // DRAIN GATE, after the update and before the drain. The rebuilt
    // replica reports the write still queued under major 1 and the held
    // file.
    let work = content.pending_work().await.expect("the gate answers");
    let [held] = work.unsynced.as_slice() else {
        panic!("the one staged row is queued, got {:?}", work.unsynced)
    };
    assert_eq!(
        held.major,
        Some(one()),
        "the staged row waits under the major it was captured in"
    );
    let seq = held.seq;
    assert_eq!(
        work.held_files, 1,
        "the staged file is held beside its row write"
    );

    let pump_task = tokio::spawn(pump);
    let mut events = client.events();

    // The held write drains to the major 1 manager and lands in Postgres.
    await_event(
        &mut events,
        deadline(),
        |event| {
            matches!(
                event,
                ClientEvent::Held(HeldWork::Applied { major, write })
                    if *major == one() && write.seq == seq
            )
        },
        rejected,
    )
    .await;

    // The held file drains over the same wire and reaches the file server,
    // whose commit calls the deployment's setter.
    wait_for_pg_state(&fixture, file_id.as_bytes(), "available").await;

    // The batch is done once the last held file is settled.
    await_event(
        &mut events,
        deadline(),
        |event| matches!(event, ClientEvent::Held(HeldWork::Drained { major }) if *major == one()),
        rejected,
    )
    .await;

    // DRAIN GATE, after the drain. The gate reports nothing.
    assert_eq!(
        content.pending_work().await.expect("the gate answers"),
        PendingWork::default(),
        "nothing is pending after the drain"
    );

    client.close().await;
    pump_task.await.expect("the pump ends on close");
    router.close();
    files.abort();
}

/// The relay that kills its connection on the first content ticket
/// request it is sent, so that request's answer can no longer come. A
/// connection served after the kill forwards everything, which is how the
/// redial reaches the manager.
struct KillOnce {
    inner: Relay,
    kill: Arc<AtomicBool>,
}

impl Transport for KillOnce {
    type Error = WebSocketError;

    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        self.inner.send_control(message).await
    }

    async fn send_bulk(&mut self, message: BulkMessage) -> Result<(), Self::Error> {
        self.inner.send_bulk(message).await
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        let frame = self.inner.recv().await?;
        if matches!(
            &frame,
            Some(IncomingFrame::Control(
                ControlMessage::ContentTicketRequest(_)
            ))
        ) && self.kill.swap(false, Ordering::AcqRel)
        {
            let _ = self.inner.close().await;
            return Ok(None);
        }
        Ok(frame)
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.inner.close().await
    }
}

/// The drain story where the wire dies under the in-flight content ticket.
/// Device A stages a photo at major 1 while offline, the deployment
/// migrates and hosts major 2 beside major 1, and the device reopens at
/// major 2. The held write drains over the first drain connection, which
/// dies when the ticket request goes out, so the wait settles as abandoned
/// and the walk defers the file. The redial serves the manager directly,
/// the walk reissues the request on the fresh wire, and the file uploads
/// once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_ticket_its_wire_dies_and_the_redial_reissues() {
    let fixture = Fixture::acquire().await;
    provision(&fixture).await;
    let chunk_dir = tempdir().expect("temp dir");
    let (_base_url, signer, files) = start_file_server(&fixture, chunk_dir.path()).await;
    let signer = Signer(Arc::new(signer));

    // The deployment migrates and hosts both majors. Major 1's first
    // connection is the drain wire, and its ticket request kills it.
    fixture
        .exec("ALTER TABLE photos ADD COLUMN taken_at TEXT")
        .await;
    let manager1 = manager(
        &fixture,
        PG_DDL_V1,
        one(),
        advertised(1, SQLITE_DDL_V1),
        &signer,
    );
    let kill = Arc::new(AtomicBool::new(true));
    let kill_once: HostedEntry = Arc::new({
        let manager1 = Arc::clone(&manager1);
        let kill = Arc::clone(&kill);
        move |relay: Relay| {
            let manager1 = Arc::clone(&manager1);
            let kill = Arc::clone(&kill);
            Box::pin(async move {
                let _ = manager1.serve(KillOnce { inner: relay, kill }).await;
            })
        }
    });
    let manager2 = manager(
        &fixture,
        PG_DDL_V2,
        two(),
        advertised(2, SQLITE_DDL_V2),
        &signer,
    );
    let router = Router::start(vec![(one(), kill_once), (two(), entry(manager2))]).await;
    let dir = tempdir().expect("device A's replica dir");

    // Device A at major 1, offline. The entry and the bytes both stay
    // pending.
    let file_id = {
        let (client, pump, content) = open_offline(build(1, SQLITE_DDL_V1), "device-a", dir.path())
            .await
            .expect("the offline open");
        let pump_task = tokio::spawn(pump);
        let file_id = stage_offline_photo(&content).await;
        client.close().await;
        pump_task.await.expect("the pump ends on close");
        file_id
    };

    // Device A reopens on the same replica directory with the major 2
    // build, the way an updated app opens.
    let (core, pump) = connect_pumped(&router, build(2, SQLITE_DDL_V2), "device-a", dir.path())
        .await
        .expect("the update opens");
    let client = core.client().clone();
    let ContentHandle::Durable(_content) = core.content().expect("content attached") else {
        panic!("the durable build places content beside the replica file")
    };
    let pump_task = tokio::spawn(pump);
    let mut events = client.events();

    // The first drain wire settles the held write and then dies under the
    // ticket request, so the connection says the wire is gone.
    await_event(
        &mut events,
        deadline(),
        |event| {
            matches!(
                event,
                ClientEvent::Held(HeldWork::WireLost { major }) if *major == one()
            )
        },
        rejected,
    )
    .await;

    // The redial reissues the request on its own wire, and the file
    // reaches the file server through it.
    wait_for_pg_state(&fixture, file_id.as_bytes(), "available").await;
    assert_eq!(
        server_manifests_for(&fixture, file_id.as_bytes()).await,
        1,
        "the reissued ticket uploaded the file once"
    );

    // The batch is done once the settled file leaves the held rows.
    await_event(
        &mut events,
        deadline(),
        |event| matches!(event, ClientEvent::Held(HeldWork::Drained { major }) if *major == one()),
        rejected,
    )
    .await;

    client.close().await;
    pump_task.await.expect("the pump ends on close");
    router.close();
    files.abort();
}

/// The decommission half. With major 1 retired before the reopen, the
/// drained major is gone, and the held work reaches its drain as `Lost`
/// naming the write's sequence and the file, with nothing reaching the
/// file server or Postgres.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_file_of_a_decommissioned_major_is_lost() {
    let fixture = Fixture::acquire().await;
    provision(&fixture).await;
    let chunk_dir = tempdir().expect("temp dir");
    let (_base_url, signer, files) = start_file_server(&fixture, chunk_dir.path()).await;
    let signer = Signer(Arc::new(signer));

    // The deployment migrates and hosts both majors, then retires major 1.
    // The router's fallback routes what is left to the newest hosted major.
    fixture
        .exec("ALTER TABLE photos ADD COLUMN taken_at TEXT")
        .await;
    let manager1 = manager(
        &fixture,
        PG_DDL_V1,
        one(),
        advertised(1, SQLITE_DDL_V1),
        &signer,
    );
    let manager2 = manager(
        &fixture,
        PG_DDL_V2,
        two(),
        advertised(2, SQLITE_DDL_V2),
        &signer,
    );
    let router = Router::start(vec![(one(), entry(manager1)), (two(), entry(manager2))]).await;
    router.decommission(one());
    let dir = tempdir().expect("device B's replica dir");

    // Device B at major 1, offline. The entry and the bytes both stay
    // pending.
    let file_id = {
        let (client, pump, content) = open_offline(build(1, SQLITE_DDL_V1), "device-b", dir.path())
            .await
            .expect("the offline open");
        let pump_task = tokio::spawn(pump);
        let file_id = stage_offline_photo(&content).await;
        client.close().await;
        pump_task.await.expect("the pump ends on close");
        file_id
    };

    // Device B reopens on the same replica directory with the major 2
    // build.
    let (core, pump) = connect_pumped(&router, build(2, SQLITE_DDL_V2), "device-b", dir.path())
        .await
        .expect("device B updates");
    let client = core.client().clone();
    let ContentHandle::Durable(content) = core.content().expect("content attached") else {
        panic!("the durable build places content beside the replica file")
    };

    // DRAIN GATE, after the update and before the drain.
    let work = content.pending_work().await.expect("the gate answers");
    let [held] = work.unsynced.as_slice() else {
        panic!("the one staged row is queued, got {:?}", work.unsynced)
    };
    let seq = held.seq;
    assert_eq!(
        work.held_files, 1,
        "the staged file is held beside its row write"
    );

    let pump_task = tokio::spawn(pump);
    let mut events = client.events();

    // The drain dials the router, which routes the retired major to the
    // newest hosted one, and the batch is lost naming the write's sequence.
    await_event(
        &mut events,
        deadline(),
        |event| {
            matches!(
                event,
                ClientEvent::Held(HeldWork::Lost { major, writes, files })
                    if *major == one()
                        && writes.iter().map(|write| write.seq).eq([seq])
                        && *files == 1
            )
        },
        rejected,
    )
    .await;

    // Nothing reaches the file server or Postgres.
    assert_eq!(
        server_photos(&fixture).await,
        0,
        "the lost write never reaches Postgres"
    );
    assert_eq!(
        server_manifests_for(&fixture, file_id.as_bytes()).await,
        0,
        "the lost file never reaches the file server"
    );

    // DRAIN GATE, after the loss. The gate reports nothing.
    assert_eq!(
        content.pending_work().await.expect("the gate answers"),
        PendingWork::default(),
        "nothing is pending after the loss"
    );

    client.close().await;
    pump_task.await.expect("the pump ends on close");
    router.close();
    files.abort();
}
