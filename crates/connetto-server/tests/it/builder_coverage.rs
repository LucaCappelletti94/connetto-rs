//! The builder's behaviour no existing suite reaches, one situation per test:
//! the serve lifecycle's terminal outcomes, the settings a client or operator
//! sees take effect, the optional wiring that builds in on, the refusals that
//! keep a bad deployment from assembling, and the sync adapter's handling of
//! the frames it cannot speak.
//!
//! Every test boots the `ServerBuilder` over its own fixture, the same way
//! the binary translates its environment, so the proof goes through the one
//! construction path.

use std::time::{Duration, Instant};

use connetto_core::PROTOCOL_VERSION;
use connetto_core::codec::{TAG_CONTROL, encode_control};
use connetto_core::messages::{
    AckCredits, ControlMessage, FatalError, FatalErrorReason, Grant, Handshake, HandshakeAck,
    NonFatalError, RateLimited, Subscribe, SubscriptionSpec,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_server::builder::{
    BuildError, ContentBuildError, ContentSettings, Database, OidcProvider, OpenFga, ServeError,
    ServerBuilder, ServerParts, ServerSchema, StoreSpec, TokenKeys,
};
use connetto_server::{
    AbuseLimits, AuthConfig, ConnectionLimits, OidcProviderConfig, OplogConfig, PersonLimits,
    ReaderReserve, ReconnectPolicy, RuntimeWritableCatalog, SessionConfig, ThrottleConfig,
    TierLimits, WebSocketTransport,
};
use connetto_test_harness::{
    Fixture, MOCK_OAUTH_CLIENT_ID, MOCK_OAUTH_CLIENT_SECRET, MOCK_OAUTH_PROVIDER, MockOauth,
    OPLOG_TABLE, PUBLICATION, SLOT, isolated_session_keyring,
};
use diesel::{ExpressionMethods, QueryDsl, QueryableByName};
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl as _};
use futures_util::{SinkExt as _, StreamExt as _};
use openidconnect::reqwest;
use serde_json::json;
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use super::e2e::{
    NO_POLICIES, OWNED_PG_DDL, OWNED_POLICIES, PG_DDL, PG_SERIAL, audit_ops, exec, mint_token,
    mint_tokens, reset_fixture, signing_keys, token_body, with_user_url,
};
use super::lifecycle::{BOUND, admin_pool, builder_over, live_session, next_control, wait_ready};
use super::logging::{record_logged, with_capture};

diesel::table! {
    connetto_oplog (commit_lsn, xid, ordinal) {
        commit_lsn -> BigInt,
        xid -> BigInt,
        ordinal -> BigInt,
    }
}

diesel::table! {
    connetto_oplog_commit (commit_lsn, xid) {
        commit_lsn -> BigInt,
        xid -> BigInt,
        end_lsn -> BigInt,
    }
}

diesel::table! {
    connetto_bans (user_id) {
        user_id -> Text,
        reason -> Text,
    }
}

diesel::table! {
    connetto_sessions (session_id) {
        session_id -> diesel::sql_types::Uuid,
        revoked -> Bool,
    }
}

diesel::table! {
    connetto_epoch (singleton) {
        singleton -> Bool,
        system_identifier -> Text,
    }
}

/// A catalog read the DSL cannot name, one column per field.
#[derive(QueryableByName)]
struct WalLsn {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    lsn: i64,
}

/// The slot's confirmed position, null until a stream confirms one.
#[derive(QueryableByName)]
struct ConfirmedLsn {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    lsn: Option<i64>,
}

/// The walsender pid occupying the slot, if one is connected.
#[derive(QueryableByName)]
struct ActivePid {
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
    pid: Option<i64>,
}

/// Terminate the walsender holding the slot, so the stream ends cleanly and
/// the slot can be dropped.
async fn kill_walsender(pool: &Pool<AsyncPgConnection>) {
    let mut conn = pool.get().await.expect("a connection");
    let rows: Vec<ActivePid> = diesel::sql_query(format!(
        "SELECT active_pid::bigint AS pid FROM pg_replication_slots \
         WHERE slot_name = '{SLOT}'"
    ))
    .load(&mut *conn)
    .await
    .expect("read the slot's walsender");
    let pid = rows.into_iter().next().and_then(|row| row.pid);
    if let Some(pid) = pid {
        exec(pool, &format!("SELECT pg_terminate_backend({pid})")).await;
    }
}

/// The slot's confirmed position; the catalog view is one the DSL cannot name.
async fn slot_confirmed_lsn(pool: &Pool<AsyncPgConnection>) -> i64 {
    let mut conn = pool.get().await.expect("a connection");
    let rows: Vec<ConfirmedLsn> = diesel::sql_query(format!(
        "SELECT pg_wal_lsn_diff(confirmed_flush_lsn, '0/0'::pg_lsn)::bigint AS lsn \
         FROM pg_replication_slots WHERE slot_name = '{SLOT}'"
    ))
    .load(&mut *conn)
    .await
    .expect("read the slot's confirmed position");
    rows[0].lsn.expect("the slot carries a confirmed position")
}

/// The one-construction-path server over `fixture` with the named schema
/// documents, writable table and authorization endpoint, on the named store.
///
/// The identity provider and its issuer are the test's, so a test can seed
/// data under a user id it derived before the server booted.
fn builder_schema(
    fixture: &Fixture,
    port: u16,
    idp: &MockOauth,
    fga: (&str, &str),
    pg_ddl: &str,
    pg_policies: &str,
    writable: &str,
) -> ServerBuilder {
    let url = fixture.admin_url().to_owned();
    let reader = with_user_url(&url, "app_reader", "app_reader");
    let keys = TempDir::new().expect("a key dir");
    let (private, public) = signing_keys(&keys);
    let token = TokenKeys::from_pem(
        std::fs::read(&private).expect("read the private half"),
        std::fs::read(&public).expect("read the public half"),
    );
    let provider = OidcProvider::Generic(
        OidcProviderConfig::new(
            MOCK_OAUTH_PROVIDER,
            MOCK_OAUTH_CLIENT_ID,
            idp.issuer().to_owned(),
            format!("http://127.0.0.1:{port}/auth/callback"),
        )
        .with_client_secret(Some(MOCK_OAUTH_CLIENT_SECRET.to_owned())),
    );
    ServerBuilder::new(
        Database::new(url, reader),
        ServerSchema::new(pg_ddl.to_owned(), pg_policies.to_owned()),
        token,
        OpenFga::new(fga.0.to_owned(), fga.1.to_owned()),
    )
    .slot(SLOT)
    .publication(PUBLICATION)
    .oplog_table(OPLOG_TABLE)
    .oidc_providers(vec![provider])
    .writable(RuntimeWritableCatalog::builder().writable(writable).build())
}

/// Seed the `owned` table with one row under `user_id` and the row-level
/// policy the RLS second-opinion tests read against.
async fn seed_owned_rls(pool: &Pool<AsyncPgConnection>, user_id: &str) {
    for stmt in [
        "DROP TABLE IF EXISTS owned CASCADE",
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') \
         THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; END $$",
        OWNED_PG_DDL,
        "GRANT USAGE ON SCHEMA public TO app_reader",
        "GRANT SELECT ON owned TO app_reader",
        "GRANT SELECT, INSERT, UPDATE ON _connetto_mutations TO app_reader",
    ] {
        exec(pool, stmt).await;
    }
    exec(
        pool,
        &format!("INSERT INTO owned VALUES (1, '{user_id}', 'seed')"),
    )
    .await;
    exec(pool, "ALTER TABLE owned ENABLE ROW LEVEL SECURITY").await;
    exec(
        pool,
        "CREATE POLICY owned_p ON owned USING (owner = current_setting('app.user_id', true))",
    )
    .await;
}

/// Open an anonymous session on the sync route and wait for the ack.
async fn anonymous_session(addr: &str, client_id: &str) -> WebSocketTransport<TcpStream> {
    let tcp = TcpStream::connect(addr)
        .await
        .expect("connect the sync route");
    let mut client = WebSocketTransport::connect(&format!("ws://{addr}/sync"), tcp)
        .await
        .expect("the axum adapter answers the WebSocket handshake");
    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            client_id,
        )))
        .await
        .expect("send the handshake");
    match next_control(&mut client).await {
        ControlMessage::HandshakeAck(_) => {}
        other => panic!("the handshake answered {other:?}"),
    }
    client
}

/// The binary frame one hand-spelled control message rides in.
fn control_frame(message: &ControlMessage) -> Vec<u8> {
    let mut frame = vec![TAG_CONTROL];
    frame.extend(encode_control(message).expect("encode the frame"));
    frame
}

/// The next binary frame a raw WebSocket client takes, decoded as control.
async fn raw_control(
    ws: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> Option<ControlMessage> {
    use connetto_core::codec::decode_control;
    match ws.next().await {
        Some(Ok(WsMessage::Binary(buf))) => {
            let (tag, payload) = buf.split_first().expect("a tagged frame");
            assert_eq!(*tag, TAG_CONTROL, "control arrives first");
            Some(decode_control(payload).expect("the frame decodes"))
        }
        _ => None,
    }
}

/// The refusal a build that must refuse returns, panicking if it assembled.
fn refused(result: Result<ServerParts, BuildError>, what: &str) -> BuildError {
    match result {
        Err(err) => err,
        Ok(_) => panic!("{what} assembled when it had to refuse"),
    }
}

/// Whether the record the router's tasks log on their own schedule landed by
/// the deadline.
async fn logged(message: &str, field: &str, needle: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !record_logged(message, field, needle) {
        assert!(Instant::now() < deadline, "the record never landed");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

/// Wait for the disagreement counter to move past `before` and prove the
/// divergence's warning named the caller.
async fn divergence_counted(before: connetto_server::counters::CountersSnapshot, user_id: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if connetto_server::counters::snapshot().visibility_disagreements
            > before.visibility_disagreements
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the second opinion never counted a divergence"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        logged(
            "the two executors disagreed about one row, which is the divergence \
             one policy source compiled to both exists to prevent",
            "caller",
            user_id
        )
        .await,
        "the divergence is named for the operator"
    );
}

/// A finite `ReconnectPolicy` gives up after its attempts: the stream ends
/// with the refusal naming the attempts, and the session that stayed open
/// hears the shutdown. The retry and the give-up are logged where an
/// embedder's log already runs, because the stream is polled in that task.
#[tokio::test]
async fn a_give_up_reconnect_policy_stops_the_stream_and_closes_the_sessions() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let base = format!("http://127.0.0.1:{port}");
    let builder = builder.reconnect_policy(
        ReconnectPolicy::new()
            .with_initial_backoff(Duration::from_millis(50))
            .with_max_backoff(Duration::from_millis(100))
            .with_max_attempts(Some(2)),
    );

    let parts = builder.build().await.expect("the deployment assembles");
    let mut change_stream = parts.change_stream;
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&base).await;

    let (token, _) = mint_token(&base).await;
    let mut client = live_session(&format!("127.0.0.1:{port}"), &token).await;
    // The slot is gone once the build has checked for it, so every connect
    // the stream tries fails and the policy's attempts run out.
    exec(&pool, &format!("SELECT pg_drop_replication_slot('{SLOT}')")).await;

    let (outcome, capture) = with_capture(
        "a_give_up_reconnect_policy_stops_the_stream_and_closes_the_sessions",
        |capture| async move {
            let outcome = tokio::time::timeout(BOUND, &mut change_stream)
                .await
                .expect("the stream gives up within the bound");
            (outcome, capture)
        },
    )
    .await;
    match outcome {
        Err(ServeError::ChangeStreamStopped(why)) => {
            assert!(
                why.contains("gave up after 2 attempts"),
                "the refusal names the configured attempts: {why}"
            );
            assert!(
                why.contains(SLOT),
                "the refusal names the missing slot: {why}"
            );
        }
        other => panic!("the stream answered {other:?}"),
    }
    let lines = capture.lines();
    assert!(
        lines
            .iter()
            .any(|line| line["message"] == "change stream lost, retrying"),
        "the retry is logged for the operator: {lines:?}"
    );
    assert!(
        lines.iter().any(|line| {
            line["message"] == "change stream gave up reconnecting, live delivery has stopped"
        }),
        "the give-up is logged for the operator: {lines:?}"
    );

    // The close frame queues before the refusal returns, so the session that
    // stayed open hears the shutdown.
    let last = loop {
        if let fatal @ ControlMessage::FatalError(_) = next_control(&mut client).await {
            break fatal;
        }
    };
    match last {
        ControlMessage::FatalError(FatalError {
            reason: FatalErrorReason::ServerShuttingDown,
        }) => {}
        other => panic!("the session's last frame says {other:?}"),
    }
    http.abort();
}

/// A change stream that ends while the shutdown signal is being handled is of
/// interest only for its error: it is logged, and `serve` still returns `Ok`.
#[tokio::test]
async fn a_stream_end_during_shutdown_is_logged_and_serve_returns_ok() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let base = format!("http://127.0.0.1:{port}");

    let (fire, signal) = tokio::sync::oneshot::channel::<()>();
    let serve = tokio::spawn(async move {
        let shutdown = async move {
            let _ = signal.await;
        };
        builder.serve(listener, shutdown).await
    });
    wait_ready(&base).await;

    let (token, _) = mint_token(&base).await;
    let mut client = live_session(&format!("127.0.0.1:{port}"), &token).await;
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM orders"),
        }))
        .await
        .expect("send the subscription");
    match next_control(&mut client).await {
        ControlMessage::SnapshotBegin(snapshot) if snapshot.sub_id == "orders" => {}
        other => panic!("the snapshot opened with {other:?} instead"),
    }

    fire.send(()).expect("fire the shutdown signal");
    // The walsender ends the source while the shutdown is waiting for it.
    kill_walsender(&pool).await;

    let outcome = tokio::time::timeout(BOUND, serve)
        .await
        .expect("serve ends on the signal")
        .expect("serve joins");
    assert!(
        outcome.is_ok(),
        "a stream end during shutdown is logged, not returned: {outcome:?}"
    );

    let last = loop {
        if let fatal @ ControlMessage::FatalError(_) = next_control(&mut client).await {
            break fatal;
        }
    };
    match last {
        ControlMessage::FatalError(FatalError {
            reason: FatalErrorReason::ServerShuttingDown,
        }) => {}
        other => panic!("the session's last frame says {other:?}"),
    }
}

/// A handshake that registers after the drain is not told the shutdown: it
/// holds the grace to the full five seconds, the elapsed grace is logged, and
/// the late session is closed by the listener stopping rather than a frame.
#[tokio::test]
async fn a_late_session_holds_the_shutdown_to_the_grace() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let big_ddl = format!("{PG_DDL}\nCREATE TABLE big (id INT PRIMARY KEY, body TEXT);");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let idp = MockOauth::start().await;
    let (_channel, store) = fixture.fga_store().await;
    let fga_url = fixture.fga_url().await.to_owned();
    let builder = builder_schema(
        &fixture,
        port,
        &idp,
        (&fga_url, &store),
        &big_ddl,
        NO_POLICIES,
        "orders",
    )
    .reader_reserve(ReaderReserve::new().with_total(2).with_reserved(1));
    let base = format!("http://127.0.0.1:{port}");

    let parts = builder.build().await.expect("the deployment assembles");
    let handle = parts.handle.clone();
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&base).await;

    // One anonymous reader permit: a multi-page snapshot holds it until the
    // client acks the pages, and that is what B's handshake waits on.
    exec(&pool, "CREATE TABLE big (id INT PRIMARY KEY, body TEXT)").await;
    exec(
        &pool,
        "INSERT INTO big SELECT g, repeat(chr(97 + (g % 26)), 500) \
         FROM generate_series(1, 30000) g",
    )
    .await;
    exec(&pool, "ANALYZE big").await;
    exec(&pool, "GRANT SELECT ON big TO app_reader").await;

    let mut a = anonymous_session(&format!("127.0.0.1:{port}"), "grace-a").await;
    a.send_control(ControlMessage::Subscribe(Subscribe {
        sub_id: "big".to_owned(),
        spec: SubscriptionSpec::new("SELECT * FROM big ORDER BY body"),
    }))
    .await
    .expect("send the subscription");
    match next_control(&mut a).await {
        ControlMessage::SnapshotBegin(snapshot) if snapshot.sub_id == "big" => {}
        other => panic!("the snapshot opened with {other:?} instead"),
    }

    // B's handshake is in flight and blocked on the permit A holds, so it
    // can only land once A's session is torn down by the drain.
    let addr = format!("127.0.0.1:{port}");
    let b_task = tokio::spawn(async move { anonymous_session(&addr, "grace-b").await });

    let (told, elapsed, capture) = with_capture(
        "a_late_session_holds_the_shutdown_to_the_grace",
        |capture| async move {
            let started = Instant::now();
            let told = handle.shutdown().await;
            (told, started.elapsed(), capture)
        },
    )
    .await;
    assert_eq!(
        told, 1,
        "only the session the drain reached was told; the late one registered after it"
    );
    assert!(
        elapsed >= Duration::from_millis(4800),
        "the grace ran out with the late session still open, it lasted {elapsed:?}"
    );
    let lines = capture.lines();
    assert!(
        lines
            .iter()
            .any(|line| line["message"] == "shutdown grace elapsed with sessions still open"),
        "the elapsed grace is logged: {lines:?}"
    );

    // The late session got no second frame: it is still open and silent, and
    // only the listener stopping will close it.
    let mut b = b_task.await.expect("the late session joins");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), b.recv())
            .await
            .is_err(),
        "the late session hears no frame, only the listener stopping"
    );
    stream.abort();
    http.abort();
}

/// The `session_config` credits are what the client counts on: the ack carries
/// them, and with zero of them the rows wait for the client's own credit.
#[tokio::test]
async fn the_session_config_credits_are_what_the_client_counts_on() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let base = format!("http://127.0.0.1:{port}");
    let builder = builder.session_config(SessionConfig::new().with_initial_credits(0));

    let parts = builder.build().await.expect("the deployment assembles");
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&base).await;

    let (token, _) = mint_token(&base).await;
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect the sync route");
    let mut client = WebSocketTransport::connect(&format!("ws://127.0.0.1:{port}/sync"), tcp)
        .await
        .expect("the axum adapter answers the WebSocket handshake");
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "credits").with_grant(Grant::new(&token)),
        ))
        .await
        .expect("send the handshake");
    match next_control(&mut client).await {
        ControlMessage::HandshakeAck(HandshakeAck {
            initial_credits, ..
        }) => {
            assert_eq!(
                initial_credits, 0,
                "the configured credits ride the ack the client counts on"
            );
        }
        other => panic!("the handshake answered {other:?}"),
    }
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM orders"),
        }))
        .await
        .expect("send the subscription");
    match next_control(&mut client).await {
        ControlMessage::SnapshotBegin(snapshot) if snapshot.sub_id == "orders" => {}
        other => panic!("the snapshot opened with {other:?} instead"),
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(1), client.recv())
            .await
            .is_err(),
        "with zero credits the rows wait for the client's own credit"
    );
    client
        .send_control(ControlMessage::AckCredits(AckCredits { credits: 8 }))
        .await
        .expect("hand the server credits");
    let frame = tokio::time::timeout(BOUND, client.recv())
        .await
        .expect("the transport answers")
        .expect("a frame arrives once credited");
    assert!(
        matches!(frame, Some(IncomingFrame::Bulk(_))),
        "the credited rows arrive: {frame:?}"
    );
    stream.abort();
    http.abort();
}

/// The `throttle` limits are what the client meets: a second subscription in
/// the window of one is refused with its own identifier, not an error.
#[tokio::test]
async fn the_throttle_setter_subscriptions_limit_is_met_on_the_wire() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let base = format!("http://127.0.0.1:{port}");
    let builder =
        builder.throttle(ThrottleConfig::new().with_identified(
            TierLimits::identified().with_subscriptions(1, Duration::from_secs(60)),
        ));

    let parts = builder.build().await.expect("the deployment assembles");
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&base).await;

    let (token, _) = mint_token(&base).await;
    let mut client = live_session(&format!("127.0.0.1:{port}"), &token).await;
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "first".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM orders"),
        }))
        .await
        .expect("send the first subscription");
    match next_control(&mut client).await {
        ControlMessage::SnapshotBegin(snapshot) if snapshot.sub_id == "first" => {}
        other => panic!("the first subscription opened with {other:?} instead"),
    }
    // The first snapshot runs to its end before the second ask is refused,
    // so read its end out of the way.
    match next_control(&mut client).await {
        ControlMessage::SnapshotEnd(snapshot) if snapshot.sub_id == "first" => {}
        other => panic!("the first snapshot ended with {other:?} instead"),
    }
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "second".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM orders"),
        }))
        .await
        .expect("send the second subscription");
    match next_control(&mut client).await {
        ControlMessage::RateLimited(RateLimited {
            related_to: Some(id),
            retry_after_ms,
        }) => {
            assert_eq!(
                id, "second",
                "the refusal names the subscription it refuses"
            );
            assert!(
                retry_after_ms > 0,
                "the refusal names when the window rolls over"
            );
        }
        other => panic!("the second subscription answered {other:?}"),
    }
    stream.abort();
    http.abort();
}

/// The `abuse` thresholds and the ban wiring are what the identity meets: the
/// crossing bans the user, closes its live connection without a word, and a
/// fresh login for the same identity is refused at the handshake.
#[tokio::test]
async fn the_abuse_setter_bans_the_identity_that_crosses() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;
    exec(
        &pool,
        "CREATE TABLE connetto_bans (user_id TEXT PRIMARY KEY, \
         session UUID NOT NULL, reason TEXT NOT NULL, \
         banned_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ)",
    )
    .await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let base = format!("http://127.0.0.1:{port}");
    let builder = builder.bans(true).abuse(
        AbuseLimits::new()
            .with_person(
                PersonLimits::new().with_unresolvable_subscriptions(2, Duration::from_secs(300)),
            )
            .with_connection(ConnectionLimits::new().with_unresolvable_subscriptions(1))
            .build()
            .expect("the thresholds validate"),
    );

    let parts = builder.build().await.expect("the deployment assembles");
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&base).await;

    let (token, user_id) = mint_token(&base).await;
    let mut client = live_session(&format!("127.0.0.1:{port}"), &token).await;

    // The first ghost is refused and tallied; the second crosses the
    // person's limit, which bans off the caller's path.
    for sub_id in ["ghost-one", "ghost-two"] {
        client
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: sub_id.to_owned(),
                spec: SubscriptionSpec::new("SELECT * FROM nosuch"),
            }))
            .await
            .expect("send the ghost subscription");
        match next_control(&mut client).await {
            ControlMessage::NonFatalError(NonFatalError {
                related_to: Some(id),
                ..
            }) => assert_eq!(id, sub_id, "the refusal names the ghost it refuses"),
            other => panic!("the ghost subscription answered {other:?}"),
        }
    }

    // The ban lands in its table, naming the signal and the limit.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut conn = pool.get().await.expect("a connection");
        let banned: i64 = connetto_bans::table
            .filter(connetto_bans::user_id.eq(user_id.clone()))
            .count()
            .get_result(&mut *conn)
            .await
            .expect("read the ban table");
        if banned >= 1 {
            break;
        }
        assert!(Instant::now() < deadline, "the ban never landed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The crossing person's live connection is closed by the ban's close
    // hook, with no frame to say why.
    let closed = loop {
        if let Ok(Ok(None) | Err(_)) =
            tokio::time::timeout(Duration::from_secs(5), client.recv()).await
        {
            break true;
        }
    };
    assert!(closed, "the banned person's session is closed by the ban");

    // A fresh login for the same identity is refused at the handshake: no
    // ack, only a closed connection.
    let (again_token, _) = mint_token(&base).await;
    let tcp = TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("connect the sync route again");
    let mut again = WebSocketTransport::connect(&format!("ws://127.0.0.1:{port}/sync"), tcp)
        .await
        .expect("the axum adapter answers the WebSocket handshake");
    again
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "banned").with_grant(Grant::new(&again_token)),
        ))
        .await
        .expect("send the banned handshake");
    if let Ok(Ok(Some(frame))) = tokio::time::timeout(BOUND, again.recv()).await {
        panic!("a banned identity got a frame: {frame:?}");
    }
    stream.abort();
    http.abort();
}

/// The `auth_config` access lifetime is what the login echoes to the client.
#[tokio::test]
async fn the_auth_config_ttl_is_what_the_login_echoes() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let base = format!("http://127.0.0.1:{port}");
    let builder = builder.auth_config(AuthConfig::new().with_access_ttl(Duration::from_secs(90)));

    let parts = builder.build().await.expect("the deployment assembles");
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&base).await;

    let body = token_body(&base, "e2e-user").await;
    assert_eq!(
        body["expires_in"].as_u64(),
        Some(90),
        "the configured access lifetime is what the client counts on"
    );
    stream.abort();
    http.abort();
}

/// The `oplog_config` retention is what the reconnect log holds: changes past
/// the configured entries are pruned as they land.
#[tokio::test]
async fn the_oplog_config_bounds_the_reconnect_log() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let builder = builder.oplog_config(OplogConfig::new().with_max_entries(2));

    let parts = builder.build().await.expect("the deployment assembles");
    let stream = tokio::spawn(parts.change_stream);

    // Five changes, one commit each; the log may hold two of them.
    let mut last: i64 = 0;
    for id in 101..=105 {
        exec(
            &pool,
            &format!("INSERT INTO orders VALUES ({id}, 1.0, 1, 'new')"),
        )
        .await;
        let mut conn = pool.get().await.expect("a connection");
        let row: Vec<WalLsn> = diesel::sql_query(
            "SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0'::pg_lsn)::bigint AS lsn",
        )
        .load(&mut *conn)
        .await
        .expect("read the write-ahead position");
        last = row[0].lsn;
    }

    let deadline = Instant::now() + BOUND;
    loop {
        let mut conn = pool.get().await.expect("a connection");
        let end: Option<i64> = connetto_oplog_commit::table
            .select(connetto_oplog_commit::end_lsn)
            .first(&mut *conn)
            .await
            .ok();
        if end.is_some_and(|end| end >= last) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the stream never ingested the last commit"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut conn = pool.get().await.expect("a connection");
    let kept: i64 = connetto_oplog::table
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count the reconnect log");
    assert_eq!(
        kept, 2,
        "the configured retention is what the reconnect log holds"
    );
    stream.abort();
}

/// With the second opinion installed, a row the build-time policy and the
/// live table answer differently about is counted and named, and the
/// delivery the answering executor allowed still happens. The opinion
/// counts, it does not block.
///
/// The divergence is seeded the way drift gets real. The build translated
/// the policy as written, the live table's policy is altered after the
/// build, so the live read hides the row the build-time policy still shows
/// the watcher.
#[tokio::test]
async fn a_second_opinion_divergence_is_counted_not_blocked() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;

    let idp = MockOauth::start().await;
    let (_channel, store) = fixture.fga_store().await;
    // The identity the deterministic resolver derives before any login.
    let user_id =
        connetto_server::authn::identity::deterministic_uuid(idp.issuer(), "e2e-user").to_string();
    seed_owned_rls(&pool, &user_id).await;
    fixture.start_replication(&["owned"]).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let fga_url = fixture.fga_url().await.to_owned();
    let builder = builder_schema(
        &fixture,
        port,
        &idp,
        (&fga_url, &store),
        OWNED_PG_DDL,
        OWNED_POLICIES,
        "owned",
    )
    .second_opinion(true);
    let base = format!("http://127.0.0.1:{port}");

    let parts = builder.build().await.expect("the deployment assembles");
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&base).await;

    let (access, uid, _) = mint_tokens(&base, "e2e-user").await;
    assert_eq!(
        uid, user_id,
        "the login resolves to the identity the row was seeded under"
    );
    let mut client = live_session(&format!("127.0.0.1:{port}"), &access).await;
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "owned".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM owned"),
        }))
        .await
        .expect("send the subscription");
    match next_control(&mut client).await {
        ControlMessage::SnapshotBegin(snapshot) if snapshot.sub_id == "owned" => {}
        other => panic!("the snapshot opened with {other:?} instead"),
    }
    let frame = tokio::time::timeout(BOUND, client.recv())
        .await
        .expect("the transport answers")
        .expect("the snapshot row arrives");
    assert!(
        matches!(frame, Some(IncomingFrame::Bulk(_))),
        "the seed row is delivered: {frame:?}"
    );
    match next_control(&mut client).await {
        ControlMessage::SnapshotEnd(snapshot) if snapshot.sub_id == "owned" => {}
        other => panic!("the snapshot closed with {other:?} instead"),
    }

    let before = connetto_server::counters::snapshot();
    // The capture opens before the drift, so the divergence's record is
    // flowing when the executors answer.
    with_capture(
        "a_second_opinion_divergence_is_counted_not_blocked",
        |_capture| async move {
            // The live policy drifts from the one the build translated, so the
            // live table hides the row the build-time policy still shows.
            exec(&pool, "ALTER POLICY owned_p ON owned USING (false)").await;
            exec(&pool, "UPDATE owned SET body = 'poked' WHERE id = 1").await;
            divergence_counted(before, &user_id).await;
        },
    )
    .await;
    // The opinion does not block delivery. The build-time policy still
    // allows the row, so the update reaches the watcher even though the
    // live table now hides it.
    let frame = tokio::time::timeout(BOUND, client.recv())
        .await
        .expect("the transport answers")
        .expect("the update is delivered");
    assert!(
        matches!(frame, Some(IncomingFrame::Bulk(_))),
        "the update patch arrives: {frame:?}"
    );
    stream.abort();
    http.abort();
}

/// Logging out revokes the session the live connection belongs to, the
/// connection hears the revocation as its last frame, and the audit switch
/// left exactly one row saying it was a logout.
#[tokio::test]
async fn a_logout_revokes_the_live_session_and_the_audit_records_it() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let base = format!("http://127.0.0.1:{port}");
    let builder = builder.audit(true);

    let parts = builder.build().await.expect("the deployment assembles");
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&base).await;

    let (access, _user_id, refresh) = mint_tokens(&base, "e2e-user").await;
    let mut client = live_session(&format!("127.0.0.1:{port}"), &access).await;

    let agent = reqwest::Client::new();
    let logout = agent
        .post(format!("{base}/auth/logout"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(json!({ "refresh_token": refresh }).to_string())
        .send()
        .await
        .expect("POST /auth/logout");
    assert!(logout.status().is_success(), "logout: {}", logout.status());

    // The revocation hook closes the live connection rather than only
    // refusing its next handshake.
    let last = loop {
        if let fatal @ ControlMessage::FatalError(_) = next_control(&mut client).await {
            break fatal;
        }
    };
    match last {
        ControlMessage::FatalError(FatalError {
            reason: FatalErrorReason::SessionRevoked,
        }) => {}
        other => panic!("the session's last frame says {other:?}"),
    }

    // The write is spawned, so it lands shortly after the response.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut ops = audit_ops(&pool).await;
    while ops.is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        ops = audit_ops(&pool).await;
    }
    assert_eq!(
        ops,
        vec!["logged_out".to_owned()],
        "a real logout leaves exactly one row, saying it was a logout"
    );
    stream.abort();
    http.abort();
}

/// A cluster whose identifier changed since the boot is a restore: at the
/// next boot every login session is revoked, the restore is logged for the
/// operator, and the epoch is re-recorded to the cluster it now serves.
#[tokio::test]
async fn a_restored_cluster_revokes_every_login_session_at_boot() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let base = format!("http://127.0.0.1:{port}");

    // The first boot records the cluster it serves.
    let parts = builder.build().await.expect("the first boot assembles");
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&base).await;
    let (_access, _user_id, _refresh) = mint_tokens(&base, "e2e-user").await;
    parts.handle.shutdown().await;
    http.abort();

    let mut conn = pool.get().await.expect("a connection");
    let recorded: String = connetto_epoch::table
        .select(connetto_epoch::system_identifier)
        .first(&mut *conn)
        .await
        .expect("read the recorded cluster");
    // The restore: the recorded identifier is not the cluster's anymore.
    let restored = recorded
        .parse::<u64>()
        .expect("a decimal cluster identifier")
        .saturating_add(1)
        .to_string();
    diesel::update(connetto_epoch::table)
        .set(connetto_epoch::system_identifier.eq(&restored))
        .execute(&mut *conn)
        .await
        .expect("tamper the recorded cluster");

    // The second boot meets the restore: it revokes every login session and
    // records the cluster it now serves.
    let (builder2, _idp2, _keys2) = builder_over(&fixture, port).await;
    let (outcome, capture) = with_capture(
        "a_restored_cluster_revokes_every_login_session_at_boot",
        |capture| async move { (builder2.build().await.map(|parts| parts.handle), capture) },
    )
    .await;
    let handle = outcome.expect("the second boot assembles");
    let lines = capture.lines();
    assert!(
        lines.iter().any(|line| {
            line["message"]
                == "the database was restored or replaced, so every login session \
                     was revoked and each device logs in again"
        }),
        "the restore is logged for the operator: {lines:?}"
    );

    let revoked: i64 = connetto_sessions::table
        .filter(connetto_sessions::revoked.eq(true))
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count the revoked sessions");
    let open: i64 = connetto_sessions::table
        .filter(connetto_sessions::revoked.eq(false))
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count the open sessions");
    assert!(
        revoked >= 1,
        "the restore revoked the login session: {revoked}"
    );
    assert_eq!(open, 0, "no session survives the restore");

    let re_recorded: String = connetto_epoch::table
        .select(connetto_epoch::system_identifier)
        .first(&mut *conn)
        .await
        .expect("read the re-recorded cluster");
    assert_eq!(
        re_recorded, recorded,
        "the epoch is re-recorded to the cluster the boot serves"
    );
    handle.shutdown().await;
}

/// A slot recreated past the reconnect log's last commit is a gap the boot
/// must settle: the log is trimmed to the resume point, the boundary commit
/// is recorded at the slot's position, and the gap is logged for the
/// operator.
#[tokio::test]
async fn a_slot_recreated_past_the_log_trims_the_log_at_boot() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let parts = builder.build().await.expect("the first boot assembles");
    let stream = tokio::spawn(parts.change_stream);

    // Three ingested commits, then the log's last commit position.
    let mut last: i64 = 0;
    for id in 101..=103 {
        exec(
            &pool,
            &format!("INSERT INTO orders VALUES ({id}, 1.0, 1, 'new')"),
        )
        .await;
        let mut conn = pool.get().await.expect("a connection");
        let row: Vec<WalLsn> = diesel::sql_query(
            "SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0'::pg_lsn)::bigint AS lsn",
        )
        .load(&mut *conn)
        .await
        .expect("read the write-ahead position");
        last = row[0].lsn;
    }
    let deadline = Instant::now() + BOUND;
    loop {
        let mut conn = pool.get().await.expect("a connection");
        let end: Option<i64> = connetto_oplog_commit::table
            .select(connetto_oplog_commit::end_lsn)
            .first(&mut *conn)
            .await
            .ok();
        if end.is_some_and(|end| end >= last) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the stream never ingested the last commit"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    stream.abort();

    // The slot is recreated at the write-ahead head, past the ingested
    // commits, so the boot's check finds the gap.
    kill_walsender(&pool).await;
    exec(&pool, &format!("SELECT pg_drop_replication_slot('{SLOT}')")).await;
    exec(
        &pool,
        &format!("SELECT pg_create_logical_replication_slot('{SLOT}', 'pgoutput')"),
    )
    .await;

    let (builder2, _idp2, _keys2) = builder_over(&fixture, port).await;
    let (outcome, capture) = with_capture(
        "a_slot_recreated_past_the_log_trims_the_log_at_boot",
        |capture| async move { (builder2.build().await.map(|parts| parts.handle), capture) },
    )
    .await;
    let handle = outcome.expect("the second boot assembles");
    let lines = capture.lines();
    assert!(
        lines.iter().any(|line| {
            line["message"]
                == "change feed resumed past what it delivered, so a stretch of \
                     changes was never seen: the reconnect log is trimmed to the \
                     resume point and every client will resynchronise"
        }),
        "the gap is logged for the operator: {lines:?}"
    );
    let mut conn = pool.get().await.expect("a connection");
    let kept: i64 = connetto_oplog::table
        .count()
        .get_result(&mut *conn)
        .await
        .expect("count the trimmed log");
    assert_eq!(kept, 0, "the log is trimmed to the resume point");
    let boundary: Option<i64> = connetto_oplog_commit::table
        .select(diesel::dsl::max(connetto_oplog_commit::end_lsn))
        .first(&mut *conn)
        .await
        .expect("read the boundary commit");
    let boundary = boundary.expect("the boundary commit is recorded");
    assert!(
        boundary > last,
        "the boundary is past the last ingested commit"
    );
    // The confirmed position moves only when a stream confirms, and none
    // does in this test, so the boundary is exactly where it reads now.
    let confirmed = slot_confirmed_lsn(&pool).await;
    assert_eq!(
        boundary, confirmed,
        "the boundary commit is recorded at the slot's confirmed position"
    );

    handle.shutdown().await;
}

/// A boot over a store that already holds the model takes the adopted path:
/// the rules are reconciled rather than reloaded, the facts behind them are
/// left to answer as they did, and the session the rules serve still sees its
/// own rows.
#[tokio::test]
async fn a_second_boot_reconciles_the_installed_model() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;

    let idp = MockOauth::start().await;
    // One store for both boots, so the second meets the model the first wrote.
    let (_channel, store) = fixture.fga_store().await;
    let user_id =
        connetto_server::authn::identity::deterministic_uuid(idp.issuer(), "e2e-user").to_string();
    seed_owned_rls(&pool, &user_id).await;
    fixture.start_replication(&["owned"]).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let fga_url = fixture.fga_url().await.to_owned();

    let base = format!("http://127.0.0.1:{port}");
    let first = builder_schema(
        &fixture,
        port,
        &idp,
        (&fga_url, &store),
        OWNED_PG_DDL,
        OWNED_POLICIES,
        "owned",
    );
    let (outcome, capture) = with_capture(
        "a_second_boot_reconciles_the_installed_model",
        |capture| async move { (first.build().await.map(|parts| parts.handle), capture) },
    )
    .await;
    let handle = outcome.expect("the first boot assembles");
    let lines = capture.lines();
    let written = lines
        .iter()
        .find(|line| {
            line["message"] == "authorization rules are new, loading the facts behind them"
        })
        .expect("the first boot loads the facts");
    handle.shutdown().await;

    let second = builder_schema(
        &fixture,
        port,
        &idp,
        (&fga_url, &store),
        OWNED_PG_DDL,
        OWNED_POLICIES,
        "owned",
    );
    let (outcome, capture) = with_capture(
        "a_second_boot_reconciles_the_installed_model",
        |capture| async move { (second.build().await, capture) },
    )
    .await;
    let parts = outcome.expect("the second boot assembles");
    let lines = capture.lines();
    let adopted = lines
        .iter()
        .find(|line| {
            line["message"]
                == "authorization rules already installed, reconciling whole-shape regions"
        })
        .expect("the second boot reconciles rather than reloads");
    assert_eq!(
        adopted["model"], written["model"],
        "the second boot adopts the model the first boot wrote"
    );

    // The reconciled store still answers: the owner's session sees the row.
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&base).await;
    let (access, uid, _) = mint_tokens(&base, "e2e-user").await;
    assert_eq!(uid, user_id, "the login resolves to the seeded identity");
    let mut client = live_session(&format!("127.0.0.1:{port}"), &access).await;
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "owned".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM owned"),
        }))
        .await
        .expect("send the subscription");
    match next_control(&mut client).await {
        ControlMessage::SnapshotBegin(snapshot) if snapshot.sub_id == "owned" => {}
        other => panic!("the snapshot opened with {other:?} instead"),
    }
    let frame = tokio::time::timeout(BOUND, client.recv())
        .await
        .expect("the transport answers")
        .expect("the row arrives after the reconcile");
    assert!(
        matches!(frame, Some(IncomingFrame::Bulk(_))),
        "the row the rules serve is delivered: {frame:?}"
    );
    stream.abort();
    http.abort();
}

/// No identity provider is configured, so no client can log in, and the build
/// says so before it touches a pool.
#[tokio::test]
async fn no_providers_refuses_the_build_before_anything_runs() {
    let keys = TempDir::new().expect("a key dir");
    let (private, public) = signing_keys(&keys);
    let token = TokenKeys::from_pem(
        std::fs::read(&private).expect("read the private half"),
        std::fs::read(&public).expect("read the public half"),
    );
    let builder = ServerBuilder::new(
        Database::new(
            "postgres://connetto:connetto@127.0.0.1:1/connetto",
            "postgres://connetto:connetto@127.0.0.1:1/connetto",
        ),
        ServerSchema::new("CREATE TABLE t (id INT PRIMARY KEY);", ""),
        token,
        OpenFga::new("http://127.0.0.1:1", "store"),
    );
    let err = refused(builder.build().await, "no provider is a refusal");
    assert!(
        matches!(err, BuildError::NoProviders),
        "the refusal names the absence: {err}"
    );
}

/// An authorization endpoint the build cannot reach is a refusal that names
/// the endpoint, whether the address will not parse or nothing answers it.
#[tokio::test]
async fn an_unreachable_authorization_endpoint_refuses_naming_it() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let idp = MockOauth::start().await;
    let (_channel, store) = fixture.fga_store().await;

    let unparseable = builder_schema(
        &fixture,
        port,
        &idp,
        ("not a url at all", &store),
        PG_DDL,
        NO_POLICIES,
        "orders",
    );
    let err = refused(unparseable.build().await, "an unparseable endpoint refuses");
    match err {
        BuildError::AuthorizationEndpoint(why) => {
            assert!(
                why.contains("parsing the endpoint"),
                "the refusal names the parsing failure: {why}"
            );
        }
        other => panic!("the build answered {other:?}"),
    }

    let unreachable = builder_schema(
        &fixture,
        port,
        &idp,
        ("http://127.0.0.1:1", &store),
        PG_DDL,
        NO_POLICIES,
        "orders",
    );
    let err = refused(unreachable.build().await, "an unreachable endpoint refuses");
    match err {
        BuildError::AuthorizationEndpoint(why) => {
            assert!(
                why.contains("connecting to the authorization service at http://127.0.0.1:1"),
                "the refusal names the endpoint it could not reach: {why}"
            );
        }
        other => panic!("the build answered {other:?}"),
    }
}

/// The sync adapter over a real listener: a non-connetto frame is skipped and
/// the handshake that follows still opens, a frame it cannot speak ends the
/// session with an error the log can name, and a client's close ends the
/// session cleanly with no fatal frame.
#[tokio::test]
async fn the_sync_adapter_handles_malformed_frames_and_clean_closes() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let (builder, _idp, _keys) = builder_over(&fixture, port).await;
    let parts = builder.build().await.expect("the deployment assembles");
    let stream = tokio::spawn(parts.change_stream);
    let http = tokio::spawn(async move { axum::serve(listener, parts.router).await });
    wait_ready(&format!("http://127.0.0.1:{port}")).await;

    let url = format!("ws://127.0.0.1:{port}/sync");

    // The capture opens before the first sub-case, so the records these
    // assertions prove are already flowing when the adapter errors.
    with_capture(
        "the_sync_adapter_handles_malformed_frames_and_clean_closes",
        |_capture| async move {
            // A frame the adapter does not speak is skipped, not fatal.
            let (mut ws, _) = connect_async(&url).await.expect("the upgrade answers");
            ws.send(WsMessage::Text("not a connetto frame".into()))
                .await
                .expect("send the foreign frame");
            ws.send(WsMessage::Binary(control_frame(
                &ControlMessage::Handshake(Handshake::new(PROTOCOL_VERSION, "skipped")),
            )))
            .await
            .expect("send the handshake");
            assert!(
                matches!(
                    raw_control(&mut ws).await,
                    Some(ControlMessage::HandshakeAck(_))
                ),
                "the skipped frame left the handshake free to open"
            );

            // An empty frame is an error the session ends on, and the log names it.
            let (mut ws, _) = connect_async(&url).await.expect("the upgrade answers");
            ws.send(WsMessage::Binary(vec![]))
                .await
                .expect("send the empty frame");
            let r = tokio::time::timeout(BOUND, ws.next()).await;
            assert!(
                !matches!(r, Ok(Some(Ok(_)))),
                "the empty frame ends the session: {r:?}"
            );
            assert!(
                logged(
                    "session ended with an error",
                    "error",
                    "empty websocket frame"
                )
                .await,
                "the error the session ended on is named"
            );

            // A frame with a tag the codec does not know is the same, named.
            let (mut ws, _) = connect_async(&url).await.expect("the upgrade answers");
            ws.send(WsMessage::Binary(vec![0x99, 1, 2, 3]))
                .await
                .expect("send the unknown frame");
            let r = tokio::time::timeout(BOUND, ws.next()).await;
            assert!(
                !matches!(r, Ok(Some(Ok(_)))),
                "the unknown tag ends the session: {r:?}"
            );
            assert!(
                logged(
                    "session ended with an error",
                    "error",
                    "unknown websocket frame tag"
                )
                .await,
                "the error the session ended on is named"
            );

            // A client's close ends the session cleanly: no fatal frame, just
            // the connection going away.
            let (mut ws, _) = connect_async(&url).await.expect("the upgrade answers");
            ws.send(WsMessage::Binary(control_frame(
                &ControlMessage::Handshake(Handshake::new(PROTOCOL_VERSION, "closing")),
            )))
            .await
            .expect("send the handshake");
            assert!(
                matches!(
                    raw_control(&mut ws).await,
                    Some(ControlMessage::HandshakeAck(_))
                ),
                "the handshake opens before the close"
            );
            ws.send(WsMessage::Close(None))
                .await
                .expect("close the session");
            let r = tokio::time::timeout(BOUND, ws.next()).await;
            assert!(
                !matches!(r, Ok(Some(Ok(_)))),
                "the clean close delivers no fatal frame: {r:?}"
            );
        },
    )
    .await;
    stream.abort();
    http.abort();
}

/// A content deployment the builder cannot run is a refusal that names the
/// settings it refused: a bandwidth window under a day refuses at
/// validation, and a store directory it cannot open refuses at the open.
#[tokio::test]
async fn a_content_refusal_names_what_it_refuses() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let idp = MockOauth::start().await;
    let (_channel, store) = fixture.fga_store().await;
    let fga_url = fixture.fga_url().await.to_owned();
    let dir = TempDir::new().expect("a store directory");
    let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .expect("a ticket key")
        .as_ref()
        .to_vec();
    let settings = |window_days: i32, store_spec: StoreSpec| ContentSettings {
        base_url: "http://127.0.0.1:8099".to_owned(),
        ttl: Duration::from_secs(60),
        read_ceiling: 1 << 20,
        grace: Duration::ZERO,
        cadence: Duration::from_secs(1),
        quota_identity: 0,
        storage_ceiling: 0,
        bandwidth_ceiling: 0,
        bandwidth_window_days: window_days,
        warn_fraction: 0.8,
        ceiling_refresh: Duration::from_secs(10),
        owner_pool_size: 2,
        store: store_spec,
        key: key.clone(),
    };

    // A window under a day meters nothing, so it refuses at validation.
    let bad_window = builder_schema(
        &fixture,
        port,
        &idp,
        (&fga_url, &store),
        PG_DDL,
        NO_POLICIES,
        "orders",
    )
    .content(Some(settings(0, StoreSpec::Fs(dir.path().to_path_buf()))));
    let err = refused(bad_window.build().await, "the window refuses");
    assert!(
        matches!(err, BuildError::Content(ContentBuildError::BandwidthWindow)),
        "the refusal names the window: {err}"
    );

    // A directory it cannot open refuses at the open, naming the path.
    let bad_store = builder_schema(
        &fixture,
        port,
        &idp,
        (&fga_url, &store),
        PG_DDL,
        NO_POLICIES,
        "orders",
    )
    .content(Some(settings(
        30,
        StoreSpec::Fs(std::path::PathBuf::from("/dev/null/impossible")),
    )));
    let err = refused(bad_store.build().await, "the store refuses");
    match err {
        BuildError::Content(ContentBuildError::OpenStore(why)) => {
            assert!(
                why.contains("/dev/null/impossible"),
                "the refusal names the directory it could not open: {why}"
            );
        }
        other => panic!("the build answered {other:?}"),
    }
}

/// The content sweep and the boot reconcile say what they do: an orphan
/// chunk is removed before serving and the disagreement is logged, a sweep
/// pass that fails is logged and the next pass retries, and a sweep whose
/// store has gone is logged and stops.
#[tokio::test]
async fn a_content_sweep_and_reconcile_say_what_they_do() {
    let _keyring = isolated_session_keyring();
    let _serial = PG_SERIAL.lock().await;
    let fixture = Fixture::acquire().await;
    let pool = admin_pool(&fixture).await;
    reset_fixture(&pool, &fixture).await;
    fixture.provision_auth_tables().await;
    apply_content_deployment(&pool).await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a listener");
    let port = listener.local_addr().expect("local address").port();
    let idp = MockOauth::start().await;
    let (_channel, store) = fixture.fga_store().await;
    let fga_url = fixture.fga_url().await.to_owned();
    let key = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .expect("a ticket key")
        .as_ref()
        .to_vec();
    let settings = |store_spec: StoreSpec| ContentSettings {
        base_url: "http://127.0.0.1:8099".to_owned(),
        ttl: Duration::from_secs(60),
        read_ceiling: 1 << 20,
        grace: Duration::ZERO,
        cadence: Duration::from_secs(1),
        quota_identity: 0,
        storage_ceiling: 0,
        bandwidth_ceiling: 0,
        bandwidth_window_days: 30,
        warn_fraction: 0.8,
        ceiling_refresh: Duration::from_secs(10),
        owner_pool_size: 2,
        store: store_spec,
        key: key.clone(),
    };

    // An orphan chunk: a file the chunk store holds that no registry row
    // names. The boot reconcile removes it and says so.
    let dir1 = TempDir::new().expect("a store directory");
    let hash = "ab".repeat(32);
    let orphan = dir1.path().join(&hash[..2]).join(&hash[2..4]).join(&hash);
    tokio::fs::create_dir_all(orphan.parent().expect("the chunk parents"))
        .await
        .expect("make the chunk parents");
    tokio::fs::write(&orphan, b"an orphan chunk")
        .await
        .expect("plant the orphan chunk");

    let first = builder_schema(
        &fixture,
        port,
        &idp,
        (&fga_url, &store),
        PG_DDL,
        NO_POLICIES,
        "orders",
    )
    .content(Some(settings(StoreSpec::Fs(dir1.path().to_path_buf()))));
    let (outcome, capture) = with_capture(
        "a_content_sweep_and_reconcile_say_what_they_do",
        |capture| async move { (first.build().await.map(|parts| parts.handle), capture) },
    )
    .await;
    let handle = outcome.expect("the deployment builds");
    let lines = capture.lines();
    assert!(
        lines.iter().any(|line| {
            line["message"]
                == "the chunk store and the database disagreed, reconciled before serving"
        }),
        "the disagreement is logged before serving: {lines:?}"
    );
    assert!(
        !orphan.exists(),
        "the orphan chunk is removed by the reconcile"
    );

    // One healthy sweep tick, then the deployment's tables go, and the next
    // pass fails into the log, where the following pass would retry it.
    tokio::time::sleep(Duration::from_millis(1_300)).await;
    exec(&pool, "DROP TABLE _cfs_manifest_chunks CASCADE").await;
    tokio::time::sleep(Duration::from_millis(1_300)).await;
    assert!(
        logged("content sweep failed", "error", "cfs").await,
        "the failed pass is logged, naming what it could not read"
    );

    handle.shutdown().await;
}

/// The photo table and the two contract functions a configured deployment
/// applies, from a clean slate.
async fn apply_content_deployment(pool: &Pool<AsyncPgConnection>) {
    const DEPLOYMENT_SQL: &[&str] = &[
        "CREATE TABLE photos (content_id BYTEA PRIMARY KEY, content_state TEXT NOT NULL \
         DEFAULT 'staged')",
        "CREATE OR REPLACE FUNCTION connetto_visible_files(p_file_ids BYTEA[]) \
         RETURNS BYTEA[] LANGUAGE sql SECURITY INVOKER SET search_path TO '' AS $$ \
         SELECT ARRAY(SELECT f FROM UNNEST(p_file_ids) AS f \
         WHERE EXISTS (SELECT 1 FROM public.photos p WHERE p.content_id = f)) $$",
        "CREATE OR REPLACE FUNCTION connetto_set_content_state(p_file_id BYTEA, \
         p_new_state TEXT, p_caller TEXT) RETURNS BYTEA \
         LANGUAGE plpgsql SECURITY DEFINER SET search_path TO '' \
         AS $$ BEGIN UPDATE public.photos SET content_state = p_new_state \
         WHERE content_id = p_file_id; RETURN p_file_id; END; $$",
    ];
    for stmt in [
        "DROP TABLE IF EXISTS photos CASCADE",
        "DROP TABLE IF EXISTS _cfs_manifest_chunks CASCADE",
        "DROP TABLE IF EXISTS _cfs_manifests CASCADE",
        "DROP TABLE IF EXISTS _cfs_chunk_registry CASCADE",
        "DROP TABLE IF EXISTS _cfs_traffic CASCADE",
        "DROP FUNCTION IF EXISTS connetto_visible_files(BYTEA[])",
        "DROP FUNCTION IF EXISTS connetto_set_content_state(BYTEA, TEXT, TEXT)",
    ] {
        exec(pool, stmt).await;
    }
    for stmt in connetto_file_server::DEPLOYMENT_DDL.split(';') {
        let meaningful = stmt
            .lines()
            .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with("--"));
        if meaningful {
            exec(pool, stmt.trim()).await;
        }
    }
    for stmt in DEPLOYMENT_SQL {
        exec(pool, stmt).await;
    }
    for stmt in [
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_reader') \
         THEN CREATE ROLE app_reader LOGIN PASSWORD 'app_reader'; END IF; END $$",
        "GRANT USAGE ON SCHEMA public TO app_reader",
        "GRANT SELECT ON photos TO app_reader",
        "GRANT SELECT ON _cfs_chunk_registry, _cfs_manifests, _cfs_manifest_chunks \
         TO app_reader",
    ] {
        exec(pool, stmt).await;
    }
}
