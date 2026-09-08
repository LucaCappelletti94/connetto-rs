//! Shared fixtures and helpers for the content-ticket test modules.

use core::sync::atomic::{AtomicU32, Ordering};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{
    ContentTicketRequest, ContentVerb, ControlMessage, Grant, Handshake,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{ContentTicketSigner, IncomingFrame, Transport};
use connetto_server::{
    InMemoryOplog, LoopbackTransport, Materializer, NoConnector, PageSpec, RequestGuard,
    SessionConfig, SessionError, SessionManager, SnapshotEstimate, SnapshotPage, SnapshotSource,
    ThrottleConfig, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, with_user};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use tokio::task::JoinHandle;

/// No application tables; tickets do not subscribe or mutate.
pub(crate) const PG_DDL: &str = "CREATE TABLE _placeholder (id INT PRIMARY KEY);";

/// Arbitrary 32-byte file id used across all cases.
pub(crate) const FILE_ID: [u8; 32] = [0xAB; 32];

/// Window long enough that no budget rolls within one test.
pub(crate) const WINDOW: Duration = Duration::from_secs(300);

/// A snapshot source that is never invoked.
pub(crate) struct NeverSnapshot;

impl SnapshotSource for NeverSnapshot {
    type Error = Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &connetto_core::Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        Ok(SnapshotEstimate {
            rows: 0.0,
            width: 0,
        })
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot_page(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &connetto_core::Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        Ok(SnapshotPage {
            patchset: Vec::new(),
            cursor: connetto_core::Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: 0,
            rows: 0,
            bytes: 0,
        })
    }
}

/// A signer that returns a deterministic URL encoding the caller and the
/// first byte of the file id, so a test can assert the URL without magic strings.
pub(crate) struct OkSigner;

impl ContentTicketSigner for OkSigner {
    type Error = Infallible;

    fn mint(
        &self,
        caller: &str,
        file_id: [u8; 32],
        _verb: ContentVerb,
    ) -> impl Future<Output = Result<String, Self::Error>> + Send {
        let url = format!("https://cdn.example.com/files/{:02x}/{caller}", file_id[0]);
        async move { Ok(url) }
    }
}

/// A signer that always errors, representing a key that was not loaded.
pub(crate) struct BrokenSigner;

impl ContentTicketSigner for BrokenSigner {
    type Error = String;

    fn mint(
        &self,
        _caller: &str,
        _file_id: [u8; 32],
        _verb: ContentVerb,
    ) -> impl Future<Output = Result<String, Self::Error>> + Send {
        core::future::ready(Err("key not loaded".to_owned()))
    }
}

/// A signer that fails on its first mint call and succeeds on subsequent ones.
/// The counter uses `Relaxed` ordering: no other memory is synchronized through it.
pub(crate) struct FlakyFirstSigner {
    calls: AtomicU32,
}

impl FlakyFirstSigner {
    pub(crate) const fn new() -> Self {
        Self {
            calls: AtomicU32::new(0),
        }
    }
}

impl ContentTicketSigner for FlakyFirstSigner {
    type Error = String;

    fn mint(
        &self,
        caller: &str,
        file_id: [u8; 32],
        _verb: ContentVerb,
    ) -> impl Future<Output = Result<String, Self::Error>> + Send {
        let prev = self.calls.fetch_add(1, Ordering::Relaxed);
        if prev == 0 {
            core::future::ready(Err("key not loaded".to_owned()))
        } else {
            let url = format!("https://cdn.example.com/files/{:02x}/{caller}", file_id[0]);
            core::future::ready(Ok(url))
        }
    }
}

/// Install the test-fixture schema: non-superuser reader, `connetto_visible_files`
/// that admits alice only, and the necessary grants.
///
/// Returns a pool authenticated as `app_reader` (the non-owning role the
/// visibility check must use so RLS fires inside the SECURITY INVOKER function).
pub(crate) async fn setup_reader(fixture: &Fixture) -> Pool<AsyncPgConnection> {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS _placeholder CASCADE",
            "CREATE TABLE _placeholder (id INT PRIMARY KEY)",
            "DO $$ BEGIN \
             IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') \
             THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; \
             END $$",
            // Visibility function: admits file_ids when the session user is alice.
            "CREATE OR REPLACE FUNCTION connetto_visible_files(file_ids bytea[]) \
             RETURNS bytea[] LANGUAGE sql SECURITY INVOKER SET search_path = public AS $$ \
                 SELECT ARRAY( \
                     SELECT id FROM unnest($1) AS id \
                     WHERE current_setting('app.user_id', true) = 'alice' \
                 ) \
             $$",
            "GRANT USAGE ON SCHEMA public TO app_reader",
            "GRANT EXECUTE ON FUNCTION connetto_visible_files(bytea[]) TO app_reader",
            // The watermark table is provisioned by the fixture; reader needs SELECT
            // for last_applied at handshake.
            "GRANT SELECT ON _connetto_mutations TO app_reader",
        ])
        .await;
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(with_user(
        fixture.admin_url(),
        "app_reader",
        "app_reader",
    ));
    Pool::builder()
        .build(manager)
        .await
        .expect("build reader pool")
}

/// Install the test-fixture schema for the reader-permit saturation test.
///
/// The visibility function sleeps 2 seconds before returning, which holds the
/// reader-pool connection long enough for a concurrent anonymous request to
/// observe the saturated share.
pub(crate) async fn setup_slow_reader(fixture: &Fixture) -> Pool<AsyncPgConnection> {
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS _placeholder CASCADE",
            "CREATE TABLE _placeholder (id INT PRIMARY KEY)",
            "DO $$ BEGIN \
             IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') \
             THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; \
             END $$",
            "CREATE OR REPLACE FUNCTION connetto_visible_files(file_ids bytea[]) \
             RETURNS bytea[] LANGUAGE plpgsql SECURITY INVOKER \
             SET search_path = public AS $$ \
             BEGIN \
                 PERFORM pg_sleep(2); \
                 RETURN ARRAY( \
                     SELECT id FROM unnest(file_ids) AS id \
                     WHERE current_setting('app.user_id', true) = 'alice' \
                 ); \
             END; $$",
            "GRANT USAGE ON SCHEMA public TO app_reader",
            "GRANT EXECUTE ON FUNCTION connetto_visible_files(bytea[]) TO app_reader",
            "GRANT SELECT ON _connetto_mutations TO app_reader",
        ])
        .await;
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(with_user(
        fixture.admin_url(),
        "app_reader",
        "app_reader",
    ));
    Pool::builder()
        .build(manager)
        .await
        .expect("build slow reader pool")
}

/// Complete a handshake for `identity`, consuming the `HandshakeAck`.
pub(crate) async fn do_handshake(client: &mut LoopbackTransport, identity: &str) {
    let mut hs = Handshake::new(PROTOCOL_VERSION, identity);
    hs = hs.with_grant(Grant::new(format!("user:{identity}")));
    client
        .send_control(ControlMessage::Handshake(hs))
        .await
        .expect("send handshake");
    match client.recv().await.expect("recv ack") {
        Some(IncomingFrame::Control(ControlMessage::HandshakeAck(_))) => {}
        other => panic!("expected HandshakeAck, got {other:?}"),
    }
}

/// Complete an anonymous handshake (no user grant), consuming the `HandshakeAck`.
pub(crate) async fn do_handshake_anon(client: &mut LoopbackTransport, session_id: &str) {
    let hs = Handshake::new(PROTOCOL_VERSION, session_id);
    client
        .send_control(ControlMessage::Handshake(hs))
        .await
        .expect("send anonymous handshake");
    match client.recv().await.expect("recv ack") {
        Some(IncomingFrame::Control(ControlMessage::HandshakeAck(_))) => {}
        other => panic!("expected HandshakeAck, got {other:?}"),
    }
}

/// Send a ticket request and return the next control frame the server sends.
pub(crate) async fn request_ticket(
    client: &mut LoopbackTransport,
    request_id: &str,
    file_id: [u8; 32],
    verb: ContentVerb,
) -> ControlMessage {
    client
        .send_control(ControlMessage::ContentTicketRequest(ContentTicketRequest {
            request_id: request_id.to_owned(),
            file_id,
            verb,
        }))
        .await
        .expect("send ticket request");
    loop {
        match client.recv().await.expect("recv frame") {
            Some(IncomingFrame::Control(msg)) => return msg,
            Some(IncomingFrame::Bulk(_)) => {}
            None => panic!("connection closed waiting for ticket response"),
        }
    }
}

/// The manager shape every test in these modules builds.
pub(crate) type TicketManager<S> = SessionManager<
    NeverSnapshot,
    RosterAuth,
    ConnettoWatermark,
    NoConnector,
    InMemoryOplog,
    String,
    String,
    S,
>;

/// Build a session manager whose reader gate the caller chooses.
pub(crate) fn build_manager_with_guard<S: ContentTicketSigner>(
    reader_pool: Pool<AsyncPgConnection>,
    roster: RosterAuth,
    guard: Arc<RequestGuard<String>>,
    signer: S,
    throttle: &ThrottleConfig,
) -> Arc<TicketManager<S>> {
    SessionManager::with_oplog(
        Materializer::new(PG_DDL).expect("build materializer"),
        NeverSnapshot,
        roster,
        Arc::new(TestGrantChecker),
        NoConnector,
        InMemoryOplog::default(),
        pg_write_target::<ConnettoWatermark>(reader_pool, PG_DDL).expect("build write target"),
        guard,
        SessionConfig::default(),
        None,
        signer,
        *throttle,
    )
}

/// Build a session manager with the default guard and oplog.
pub(crate) fn build_standard_manager<S: ContentTicketSigner>(
    reader_pool: Pool<AsyncPgConnection>,
    roster: RosterAuth,
    signer: S,
    throttle: &ThrottleConfig,
) -> Arc<TicketManager<S>> {
    build_manager_with_guard(
        reader_pool,
        roster,
        Arc::new(RequestGuard::default()),
        signer,
        throttle,
    )
}

/// Open one session against a standard manager, completing the handshake for `identity`.
pub(crate) async fn open_session_with_handshake<S: ContentTicketSigner + Send + Sync + 'static>(
    reader_pool: Pool<AsyncPgConnection>,
    roster: RosterAuth,
    signer: S,
    throttle: &ThrottleConfig,
    identity: &str,
) -> (LoopbackTransport, JoinHandle<Result<(), SessionError>>) {
    let manager = build_standard_manager(reader_pool, roster, signer, throttle);
    let (server_end, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_end));
    do_handshake(&mut client, identity).await;
    (client, server)
}

/// Queue a `ContentTicketRequest` on `client` without reading the response.
pub(crate) async fn send_ticket_request(
    client: &mut LoopbackTransport,
    request_id: &str,
    file_id: [u8; 32],
    verb: ContentVerb,
) {
    client
        .send_control(ControlMessage::ContentTicketRequest(ContentTicketRequest {
            request_id: request_id.to_owned(),
            file_id,
            verb,
        }))
        .await
        .expect("send ticket request");
}

/// Drain bulk frames from `client` until a control frame or clean close arrives.
pub(crate) async fn drain_to_control(client: &mut LoopbackTransport) {
    loop {
        match client.recv().await.expect("recv frame") {
            Some(IncomingFrame::Control(_)) | None => break,
            Some(IncomingFrame::Bulk(_)) => {}
        }
    }
}
