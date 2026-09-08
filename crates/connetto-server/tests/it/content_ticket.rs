//! Content ticket mint tests.
//!
//! Needs Docker. The visibility check runs on a non-superuser pool, because the
//! admin role owns the tables and would bypass RLS inside the deployment's
//! `connetto_visible_files` body.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::PROTOCOL_VERSION;
use connetto_core::messages::{
    CONTENT_TICKET_REFUSED, CONTENT_TICKET_SIGNER_ERROR, ContentTicketGrant, ContentTicketRequest,
    ContentVerb, ControlMessage, Grant, Handshake, NonFatalError,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{ContentTicketSigner, IncomingFrame, Transport};
use connetto_server::{
    InMemoryOplog, LoopbackTransport, Materializer, NoConnector, PageSpec, RequestGuard,
    SessionConfig, SessionManager, SnapshotEstimate, SnapshotPage, SnapshotSource, ThrottleConfig,
    loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID, with_user};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;

/// No application tables; tickets do not subscribe or mutate.
const PG_DDL: &str = "CREATE TABLE _placeholder (id INT PRIMARY KEY);";

/// The file id used across all cases. Arbitrary 32 bytes.
const FILE_ID: [u8; 32] = [0xAB; 32];

/// Window long enough that nothing rolls within one test.
const WINDOW: Duration = Duration::from_secs(300);

/// A snapshot source that is never invoked.
struct NeverSnapshot;

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
struct OkSigner;

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
struct BrokenSigner;

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

/// Install the test-fixture schema: non-superuser reader, `connetto_visible_files`
/// that admits alice only, and the necessary grants.
///
/// Returns a pool authenticated as `app_reader` (the non-owning role the
/// visibility check must use so RLS fires inside the SECURITY INVOKER function).
async fn setup_reader(fixture: &Fixture) -> Pool<AsyncPgConnection> {
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

/// Complete a handshake for `identity`, consuming the `HandshakeAck`.
async fn do_handshake(client: &mut LoopbackTransport, identity: &str) {
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

/// Send a ticket request and return the next control frame the server sends.
async fn request_ticket(
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

/// A visible file yields a `ContentTicketGrant` carrying the signer's URL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn visible_file_yields_grant() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader(&fixture).await;

    let manager = SessionManager::with_oplog(
        Materializer::new(PG_DDL).expect("build materializer"),
        NeverSnapshot,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        InMemoryOplog::default(),
        pg_write_target::<ConnettoWatermark>(reader_pool, PG_DDL).expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
        None,
        OkSigner,
        ThrottleConfig::default(),
    );

    let (server_end, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_end));

    do_handshake(&mut client, "alice").await;

    // Before: alice requests a read ticket.
    let resp = request_ticket(&mut client, "req-1", FILE_ID, ContentVerb::Read).await;

    // After: grant with the signer's URL.
    let ControlMessage::ContentTicketGrant(ContentTicketGrant { request_id, url }) = resp else {
        panic!("expected ContentTicketGrant, got {resp:?}");
    };
    assert_eq!(request_id, "req-1", "request_id is echoed");
    assert_eq!(
        url,
        format!("https://cdn.example.com/files/{:02x}/alice", FILE_ID[0]),
        "URL comes from OkSigner"
    );

    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
}

/// An invisible file is refused with `CONTENT_TICKET_REFUSED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invisible_file_is_refused() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader(&fixture).await;

    let manager = SessionManager::with_oplog(
        Materializer::new(PG_DDL).expect("build materializer"),
        NeverSnapshot,
        RosterAuth::granting("bob").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        InMemoryOplog::default(),
        pg_write_target::<ConnettoWatermark>(reader_pool, PG_DDL).expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
        None,
        OkSigner,
        ThrottleConfig::default(),
    );

    let (server_end, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_end));

    do_handshake(&mut client, "bob").await;

    // Before: bob requests a ticket for a file the visibility function does not return.
    let resp = request_ticket(&mut client, "req-2", FILE_ID, ContentVerb::Read).await;

    // After: `NonFatalError` with the shared refusal detail.
    let ControlMessage::NonFatalError(NonFatalError { related_to, detail }) = resp else {
        panic!("expected NonFatalError, got {resp:?}");
    };
    assert_eq!(related_to.as_deref(), Some("req-2"), "request_id echoed");
    assert_eq!(
        detail, CONTENT_TICKET_REFUSED,
        "invisible file uses the shared detail"
    );

    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
}

/// An over-budget write is refused with the SAME detail as an invisible file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_budget_write_refused_with_same_detail_as_invisible() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader(&fixture).await;

    // 1-byte limit: the first 1-byte write ticket uses the whole budget.
    let content_config = ThrottleConfig::new().with_content_bytes_per_identity(1, WINDOW);

    let manager = SessionManager::with_oplog(
        Materializer::new(PG_DDL).expect("build materializer"),
        NeverSnapshot,
        // Granting alice lets her open a session; bob is not withheld either
        // (only WITHHELD_ID is withheld) so bob can open a session too.
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        InMemoryOplog::default(),
        pg_write_target::<ConnettoWatermark>(reader_pool, PG_DDL).expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
        None,
        OkSigner,
        content_config,
    );

    let (alice_end, mut alice) = loopback();
    let alice_server = tokio::spawn(Arc::clone(&manager).serve(alice_end));
    do_handshake(&mut alice, "alice").await;

    // Before: first write ticket (declared_len=1, within the 1-byte budget).
    let first = request_ticket(
        &mut alice,
        "write-1",
        FILE_ID,
        ContentVerb::Write { declared_len: 1 },
    )
    .await;
    // After: grant confirms the budget was available.
    assert!(
        matches!(first, ControlMessage::ContentTicketGrant(_)),
        "first write ticket must succeed; budget was not yet exhausted, got {first:?}"
    );

    // Before: second write ticket (declared_len=1, budget now at ceiling).
    let second = request_ticket(
        &mut alice,
        "write-2",
        FILE_ID,
        ContentVerb::Write { declared_len: 1 },
    )
    .await;
    // After: NonFatalError; capture its detail for comparison.
    let ControlMessage::NonFatalError(NonFatalError {
        detail: over_budget_detail,
        related_to: ref over_budget_ref,
    }) = second
    else {
        panic!("second write ticket must be refused when over budget, got {second:?}");
    };
    assert_eq!(
        over_budget_ref.as_deref(),
        Some("write-2"),
        "request_id echoed on over-budget refusal"
    );

    let (bob_end, mut bob) = loopback();
    let bob_server = tokio::spawn(Arc::clone(&manager).serve(bob_end));
    do_handshake(&mut bob, "bob").await;

    // Before: bob requests a ticket; `connetto_visible_files` returns empty for bob.
    let bob_resp = request_ticket(&mut bob, "bob-req", FILE_ID, ContentVerb::Read).await;
    // After: NonFatalError; capture its detail.
    let ControlMessage::NonFatalError(NonFatalError {
        detail: invisible_detail,
        ..
    }) = bob_resp
    else {
        panic!("bob's invisible-file request must be refused, got {bob_resp:?}");
    };

    // Core assertion: the two detail strings are byte-identical.
    assert_eq!(
        over_budget_detail, invisible_detail,
        "over-budget write and invisible file must carry byte-identical detail so a \
         caller cannot learn a file exists from the difference"
    );

    bob.close().await.expect("close bob");
    bob_server.await.expect("join bob").expect("bob session ok");
    alice.close().await.expect("close alice");
    alice_server
        .await
        .expect("join alice")
        .expect("alice session ok");
}

/// A signer fault yields a distinct detail so a retry is meaningful.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signer_failure_yields_distinct_detail() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader(&fixture).await;

    let manager = SessionManager::with_oplog(
        Materializer::new(PG_DDL).expect("build materializer"),
        NeverSnapshot,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        InMemoryOplog::default(),
        pg_write_target::<ConnettoWatermark>(reader_pool, PG_DDL).expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
        None,
        BrokenSigner,
        ThrottleConfig::default(),
    );

    let (server_end, mut client) = loopback();
    let server = tokio::spawn(manager.serve(server_end));

    do_handshake(&mut client, "alice").await;

    // Before: alice requests a ticket; file is visible but signer is broken.
    let resp = request_ticket(&mut client, "req-4", FILE_ID, ContentVerb::Read).await;

    // After: `NonFatalError` with the signer-error detail, distinct from CONTENT_TICKET_REFUSED.
    let ControlMessage::NonFatalError(NonFatalError { related_to, detail }) = resp else {
        panic!("expected NonFatalError, got {resp:?}");
    };
    assert_eq!(related_to.as_deref(), Some("req-4"), "request_id echoed");
    assert_eq!(
        detail, CONTENT_TICKET_SIGNER_ERROR,
        "signer failure uses the distinct signer-error detail"
    );
    assert_ne!(
        detail, CONTENT_TICKET_REFUSED,
        "signer failure must be distinguishable from a visibility refusal"
    );

    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
}
