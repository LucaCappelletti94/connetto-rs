//! Shared fixtures and helpers for the content-ticket test modules.

use core::sync::atomic::{AtomicU32, Ordering};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::auth::ContentCaller;
use connetto_core::auth::DEFAULT_USER_SETTING;
use connetto_core::messages::{
    ContentTicketRequest, ContentVerb, ControlMessage, Grant, Handshake,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{ContentTicketSigner, IncomingFrame, Transport};
use connetto_server::{
    AbuseConfig, InMemoryOplog, LoopbackTransport, Materializer, NoConnector, PageSpec,
    RequestGuard, SessionConfig, SessionError, SessionManager, SnapshotEstimate, SnapshotPage,
    SnapshotSource, ThrottleConfig, loopback, pg_write_target,
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

/// The share-key grant `TestGrantChecker` resolves to a capability subject.
/// The subject is the whole token rather than the part after the prefix, so a
/// policy predicate matches `key:k1` and not `k1`.
pub(crate) const KEY_GRANT: &str = "key:k1";

/// The predicate every identity-only case installs: the fixture's
/// `connetto_visible_files` admits a file when the bound identity is alice.
pub(crate) const ADMITS_ALICE: &str = "current_setting('app.user_id', true) = 'alice'";

/// Admits when [`KEY_GRANT`]'s subject is among the packed subjects, in the
/// `ANY(string_to_array(..))` form chapter 12 gives a capability predicate.
pub(crate) const ADMITS_KEY: &str =
    "'key:k1' = ANY(string_to_array(current_setting('app.subjects', true), ','))";

/// Admits a caller whose identity is bound to the empty string, the blank
/// identity chapter 08 forbids. An unbound setting reads as NULL and fails
/// this comparison, so only a path that binds `""` is admitted here.
pub(crate) const ADMITS_BLANK_IDENTITY: &str = "current_setting('app.user_id', true) = ''";

/// Admits either half, which is the union row of chapter 08's arrival table.
pub(crate) const ADMITS_ALICE_OR_KEY: &str = "current_setting('app.user_id', true) = 'alice' OR 'key:k1' = ANY(string_to_array(current_setting('app.subjects', true), ','))";

/// [`ADMITS_ALICE`] for a deployment that named its own identity setting.
pub(crate) const ADMITS_ALICE_UNDER_OWN_SETTING: &str =
    "current_setting('app.who', true) = 'alice'";

/// The setting name [`ADMITS_ALICE_UNDER_OWN_SETTING`] reads.
pub(crate) const OWN_SETTING: &str = "app.who";

/// A snapshot source that is never invoked.
pub(crate) struct NeverSnapshot;

impl SnapshotSource for NeverSnapshot {
    type Error = Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
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

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
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

/// The caller as a signer renders it into a URL: the identity, else every key
/// it holds, else `nobody` when it binds neither half.
pub(crate) fn rendered(caller: &ContentCaller) -> String {
    let named = caller.attributions().join(",");
    if named.is_empty() {
        return "nobody".to_owned();
    }
    named
}

/// A signer that returns a deterministic URL encoding the caller and the
/// first byte of the file id, so a test can assert the URL without magic strings.
pub(crate) struct OkSigner;

impl ContentTicketSigner for OkSigner {
    type Error = Infallible;

    fn mint(
        &self,
        caller: &ContentCaller,
        file_id: [u8; 32],
        _verb: ContentVerb,
    ) -> impl Future<Output = Result<String, Self::Error>> + Send {
        let url = format!(
            "https://cdn.example.com/files/{:02x}/{}",
            file_id[0],
            rendered(caller)
        );
        async move { Ok(url) }
    }
}

/// A signer that records every caller it was asked to mint for.
pub(crate) struct RecordingSigner(pub(crate) Arc<std::sync::Mutex<Vec<ContentCaller>>>);

impl ContentTicketSigner for RecordingSigner {
    type Error = Infallible;

    fn mint(
        &self,
        caller: &ContentCaller,
        file_id: [u8; 32],
        _verb: ContentVerb,
    ) -> impl Future<Output = Result<String, Self::Error>> + Send {
        self.0
            .lock()
            .expect("the recording signer's mutex is never poisoned")
            .push(caller.clone());
        let url = format!(
            "https://cdn.example.com/files/{:02x}/{}",
            file_id[0],
            rendered(caller)
        );
        async move { Ok(url) }
    }
}

/// A signer that always errors, representing a key that was not loaded.
pub(crate) struct BrokenSigner;

impl ContentTicketSigner for BrokenSigner {
    type Error = String;

    fn mint(
        &self,
        _caller: &ContentCaller,
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
        caller: &ContentCaller,
        file_id: [u8; 32],
        _verb: ContentVerb,
    ) -> impl Future<Output = Result<String, Self::Error>> + Send {
        let prev = self.calls.fetch_add(1, Ordering::Relaxed);
        if prev == 0 {
            core::future::ready(Err("key not loaded".to_owned()))
        } else {
            let url = format!(
                "https://cdn.example.com/files/{:02x}/{}",
                file_id[0],
                rendered(caller)
            );
            core::future::ready(Ok(url))
        }
    }
}

/// Install the test-fixture schema whose `connetto_visible_files` admits a
/// file when `predicate` holds, plus the non-superuser reader and its grants.
///
/// Returns a pool authenticated as `app_reader` (the non-owning role the
/// visibility check must use so RLS fires inside the SECURITY INVOKER function).
/// The predicate is the only thing the ticket cases vary, and it is the only
/// place a test can observe which settings the ticket path bound.
pub(crate) async fn setup_reader_admitting(
    fixture: &Fixture,
    predicate: &str,
) -> Pool<AsyncPgConnection> {
    let visible_files = format!(
        "CREATE OR REPLACE FUNCTION connetto_visible_files(file_ids bytea[]) \
         RETURNS bytea[] LANGUAGE sql SECURITY INVOKER SET search_path = public AS $$ \
             SELECT ARRAY(SELECT id FROM unnest($1) AS id WHERE {predicate}) \
         $$"
    );
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS _placeholder CASCADE",
            "CREATE TABLE _placeholder (id INT PRIMARY KEY)",
            "DO $$ BEGIN \
             IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') \
             THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; \
             END $$",
            visible_files.as_str(),
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

/// [`setup_reader_admitting`] under [`ADMITS_ALICE`].
pub(crate) async fn setup_reader(fixture: &Fixture) -> Pool<AsyncPgConnection> {
    setup_reader_admitting(fixture, ADMITS_ALICE).await
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

/// Complete a handshake presenting `grants`, consuming the `HandshakeAck`.
pub(crate) async fn do_handshake_with(
    client: &mut LoopbackTransport,
    session_id: &str,
    grants: &[&str],
) {
    let mut hs = Handshake::new(PROTOCOL_VERSION, session_id);
    for grant in grants {
        hs = hs.with_grant(Grant::new(*grant));
    }
    client
        .send_control(ControlMessage::Handshake(hs))
        .await
        .expect("send handshake");
    match client.recv().await.expect("recv ack") {
        Some(IncomingFrame::Control(ControlMessage::HandshakeAck(_))) => {}
        other => panic!("expected HandshakeAck, got {other:?}"),
    }
}

/// Complete a handshake for `identity`, presenting its login grant.
pub(crate) async fn do_handshake(client: &mut LoopbackTransport, identity: &str) {
    do_handshake_with(client, identity, &[&format!("user:{identity}")]).await;
}

/// Complete an anonymous handshake, presenting no grant at all.
pub(crate) async fn do_handshake_anon(client: &mut LoopbackTransport, session_id: &str) {
    do_handshake_with(client, session_id, &[]).await;
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

/// Build a session manager that binds the caller's identity under
/// `user_setting`, with the guard the caller chooses.
///
/// The name is set once, on the write target that owns it, so nothing here can
/// paper over a second field disagreeing with it.
pub(crate) fn build_manager_named_setting<S: ContentTicketSigner>(
    reader_pool: Pool<AsyncPgConnection>,
    roster: RosterAuth,
    guard: Arc<RequestGuard<String>>,
    signer: S,
    user_setting: &str,
) -> Arc<TicketManager<S>> {
    SessionManager::with_oplog(
        Materializer::new(PG_DDL).expect("build materializer"),
        NeverSnapshot,
        roster,
        Arc::new(TestGrantChecker),
        NoConnector,
        InMemoryOplog::default(),
        pg_write_target::<ConnettoWatermark>(reader_pool, PG_DDL)
            .expect("build write target")
            .with_user_setting(user_setting),
        guard,
        SessionConfig::default(),
        None,
        signer,
    )
}

/// Build a session manager whose guard the caller chooses.
pub(crate) fn build_manager_with_guard<S: ContentTicketSigner>(
    reader_pool: Pool<AsyncPgConnection>,
    roster: RosterAuth,
    guard: Arc<RequestGuard<String>>,
    signer: S,
) -> Arc<TicketManager<S>> {
    build_manager_named_setting(reader_pool, roster, guard, signer, DEFAULT_USER_SETTING)
}

/// Build a session manager whose guard carries `throttle`, with the default oplog.
pub(crate) fn build_standard_manager<S: ContentTicketSigner>(
    reader_pool: Pool<AsyncPgConnection>,
    roster: RosterAuth,
    signer: S,
    throttle: &ThrottleConfig,
) -> Arc<TicketManager<S>> {
    build_manager_with_guard(
        reader_pool,
        roster,
        Arc::new(RequestGuard::new(*throttle, AbuseConfig::default())),
        signer,
    )
}

/// Open one session presenting `grants`, against a manager binding the
/// identity under `user_setting`.
pub(crate) async fn open_session_named_setting<S: ContentTicketSigner + Send + Sync + 'static>(
    reader_pool: Pool<AsyncPgConnection>,
    roster: RosterAuth,
    signer: S,
    throttle: &ThrottleConfig,
    session_id: &str,
    grants: &[&str],
    user_setting: &str,
) -> (LoopbackTransport, JoinHandle<Result<(), SessionError>>) {
    let manager = build_manager_named_setting(
        reader_pool,
        roster,
        Arc::new(RequestGuard::new(*throttle, AbuseConfig::default())),
        signer,
        user_setting,
    );
    let (server_end, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_end));
    do_handshake_with(&mut client, session_id, grants).await;
    (client, server)
}

/// Open one session against a standard manager, presenting `grants`.
pub(crate) async fn open_session_with_grants<S: ContentTicketSigner + Send + Sync + 'static>(
    reader_pool: Pool<AsyncPgConnection>,
    roster: RosterAuth,
    signer: S,
    throttle: &ThrottleConfig,
    session_id: &str,
    grants: &[&str],
) -> (LoopbackTransport, JoinHandle<Result<(), SessionError>>) {
    open_session_named_setting(
        reader_pool,
        roster,
        signer,
        throttle,
        session_id,
        grants,
        DEFAULT_USER_SETTING,
    )
    .await
}

/// Open one session against a standard manager, completing the handshake for `identity`.
pub(crate) async fn open_session_with_handshake<S: ContentTicketSigner + Send + Sync + 'static>(
    reader_pool: Pool<AsyncPgConnection>,
    roster: RosterAuth,
    signer: S,
    throttle: &ThrottleConfig,
    identity: &str,
) -> (LoopbackTransport, JoinHandle<Result<(), SessionError>>) {
    open_session_with_grants(
        reader_pool,
        roster,
        signer,
        throttle,
        identity,
        &[&format!("user:{identity}")],
    )
    .await
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
