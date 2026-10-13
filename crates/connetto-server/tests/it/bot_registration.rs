//! R91: the registration exchange on the wire, against the real manager.
//!
//! The server opens every connection with a `Challenge`, and a bot's
//! `RegisterBot` settles against the registry on the owner pool before any
//! identity. Every refusal is the identical `RegistrationRefused` followed by
//! a fresh challenge, and a settled registration is proven against the
//! database rows.
//!
//! Needs Docker, because the fixture starts its own Postgres.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{
    BotListEntry, Challenge, ControlMessage, FatalErrorReason, Handshake, Ping, RegisterBot,
    bot_registration_message,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{LoopbackTransport, PROTOCOL_VERSION, loopback};
use connetto_server::bots::pg_bot_registry;
use connetto_server::defaults::ConnettoDefaults;
use connetto_server::{
    AbuseLimits, ConnectionLimits, ManagerBuilder, Materializer, PersonLimits, PgReadConnector,
    PgSnapshotSource, RequestGuard, RuntimeWritableCatalog, SessionConfig, SessionError,
    SessionManager, ThrottleConfig, TierLimits, pg_write_target,
};
use connetto_test_harness::{Fixture, RosterAuth};
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

use super::e2e::exec;

/// The one synced table a list entry may name.
const PG_DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, label TEXT);";
/// The window the test's abuse counters use.
const WINDOW: Duration = Duration::from_secs(300);
/// How long a test waits for a settle that must not happen.
const SETTLE: Duration = Duration::from_secs(5);

/// A manager over the fixture with the bot registry wired over the owner pool.
type Manager = SessionManager<PgSnapshotSource, RosterAuth, ConnettoDefaults, PgReadConnector>;

/// A refusal case, with its name and the registration it builds for a nonce.
type RefusalCase = (
    &'static str,
    Box<dyn Fn(&[u8; 32], &Ed25519KeyPair) -> RegisterBot + Send>,
);

/// The registry tables re-created from the shipped DDL.
async fn registry(pool: &Pool<AsyncPgConnection>) {
    for statement in [
        "DROP TABLE IF EXISTS connetto_installation_optional_tables",
        "DROP TABLE IF EXISTS connetto_installations",
        "DROP TABLE IF EXISTS connetto_bot_lists",
        "DROP TABLE IF EXISTS connetto_registration_codes",
        "DROP TABLE IF EXISTS connetto_bots",
    ] {
        exec(pool, statement).await;
    }
    for statement in connetto_server::defaults::BOTS_DDL.split(';') {
        if !statement.trim().is_empty() {
            exec(pool, statement).await;
        }
    }
}

/// Seed one registration code for `code`, expiring an hour after or before the
/// database clock as `future` says.
async fn code(pool: &Pool<AsyncPgConnection>, code: &str, future: bool) {
    let sign = if future { "+" } else { "-" };
    exec(
        pool,
        &format!(
            "INSERT INTO connetto_registration_codes \
             (code_hash, creator, bot, expires_at) \
             VALUES (decode('{hex}', 'hex'), 'alice', NULL, now() {sign} interval '1 hour')",
            hex = hex_of(&sha256_of(code)),
        ),
    )
    .await;
}

fn sha256_of(code: &str) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(Sha256::digest(code.as_bytes()).as_slice());
    out
}

fn hex_of(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        hex.push(DIGITS[usize::from(byte >> 4)] as char);
        hex.push(DIGITS[usize::from(*byte & 0xf)] as char);
    }
    hex
}

/// A fresh Ed25519 key pair, through the PKCS#8 round trip an app would use.
fn mint_key() -> Ed25519KeyPair {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate");
    Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("parse the key pair")
}

/// The manager the tests serve, with the bot registry wired over `registry`.
fn manager(
    pool: Pool<AsyncPgConnection>,
    guard: Arc<RequestGuard<String>>,
    registry: Pool<AsyncPgConnection>,
    session: SessionConfig,
) -> Arc<Manager> {
    ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .with_write_catalog(RuntimeWritableCatalog::default())
            .with_read_connector(PgReadConnector::with_session_setup(pool.clone()))
            .build()
            .expect("build materializer"),
        PgSnapshotSource::from_ddl(pool.clone(), PG_DDL).expect("snapshot source"),
        RosterAuth::granting_nobody(),
        Arc::new(TestGrantChecker),
        PgReadConnector::with_session_setup(pool.clone()),
        pg_write_target::<ConnettoDefaults>(pool, PG_DDL).expect("build write target"),
    )
    .with_guard(guard)
    .with_session(session)
    .with_bot_registry(pg_bot_registry::<ConnettoDefaults>(registry))
    .build()
}

/// A pool that answers nothing, for the test whose subject is a registry whose
/// database is unreachable.
async fn dead_pool() -> Pool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(
        "postgres://nobody@127.0.0.1:9/none".to_owned(),
    );
    Pool::builder()
        .max_size(1)
        .connection_timeout(Duration::from_millis(500))
        .build(manager)
        .await
        .expect("the pool builds even though it connects nowhere")
}

fn guard_with_connection_refusals(limit: u32) -> Arc<RequestGuard<String>> {
    Arc::new(RequestGuard::new(
        ThrottleConfig::default()
            .with_identified(TierLimits::identified().with_read_timeout(Duration::from_secs(30))),
        AbuseLimits::new()
            .with_person(
                PersonLimits::new()
                    .with_refused_grants(1000, WINDOW)
                    .with_unresolvable_subscriptions(1000, WINDOW)
                    .with_rejected_writes(1000, WINDOW)
                    .with_failed_renewals(1000, WINDOW),
            )
            .with_connection(
                ConnectionLimits::new()
                    .with_refused_grants(limit)
                    .with_unresolvable_subscriptions(100)
                    .with_rejected_writes(100),
            )
            .build()
            .expect("the thresholds a test names are valid"),
    ))
}

/// A loopback client with its serving task, the opening challenge read back.
async fn open(manager: &Arc<Manager>) -> (LoopbackTransport, Challenge) {
    let (server_end, mut client) = loopback();
    let serving = Arc::clone(manager);
    tokio::spawn(async move {
        let _ = serving.serve(server_end).await;
    });
    let frame = client.recv().await.expect("recv the opening frame");
    let Some(IncomingFrame::Control(ControlMessage::Challenge(challenge))) = frame else {
        panic!("the connection did not open with a challenge: {frame:?}");
    };
    (client, challenge)
}

/// The one registration the tests present over `code`, signed by `key` for the
/// connection's `nonce`.
fn registration(code: &str, key: &Ed25519KeyPair, nonce: &[u8; 32]) -> RegisterBot {
    let mut public_key = [0_u8; 32];
    public_key.copy_from_slice(key.public_key().as_ref());
    RegisterBot {
        code: code.to_owned(),
        name: "bot-a".to_owned(),
        public_key,
        list: vec![BotListEntry {
            table: "orders".to_owned(),
            verb: "read".to_owned(),
            optional: false,
        }],
        signature: key.sign(&bot_registration_message(nonce)).as_ref().to_vec(),
    }
}

/// Read the next control frame, skipping none. The exchange's frames are all
/// control, so a bulk frame or a closed connection is a test failure.
async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    let Some(IncomingFrame::Control(control)) = transport.recv().await.expect("recv") else {
        panic!("expected a control frame, the connection closed");
    };
    control
}

/// Read the next control frame and report whether it is the fresh challenge a
/// settled or refused registration is followed by, with a fresh nonce.
async fn fresh_challenge(client: &mut LoopbackTransport, spent: &[u8; 32], what: &str) -> [u8; 32] {
    let frame = client.recv().await.expect("recv the next frame");
    let Some(IncomingFrame::Control(ControlMessage::Challenge(challenge))) = frame else {
        panic!("{what}: the answer is followed by a fresh challenge: {frame:?}");
    };
    assert_ne!(
        challenge.nonce, *spent,
        "{what}: the fresh challenge carries a fresh nonce"
    );
    challenge.nonce
}

/// Whether a registration spent its code, read back from the registry.
async fn code_used(pool: &Pool<AsyncPgConnection>, code: &str) -> bool {
    let mut conn = pool.get().await.expect("a connection");
    let used_at: Option<connetto_server::ban::Instant> =
        connetto_server::defaults::connetto_registration_codes::table
            .filter(
                connetto_server::defaults::connetto_registration_codes::code_hash
                    .eq(sha256_of(code).to_vec()),
            )
            .select(connetto_server::defaults::connetto_registration_codes::used_at)
            .first(&mut *conn)
            .await
            .expect("read the code");
    used_at.is_some()
}

/// The server's opening frame of a fresh connection is a challenge, and the
/// connection then handshakes as if the challenge were not there.
#[tokio::test]
async fn a_fresh_connection_opens_with_a_challenge() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    registry(&pool).await;
    let manager = manager(
        pool.clone(),
        guard_with_connection_refusals(100),
        pool.clone(),
        SessionConfig::new(),
    );
    let (mut client, challenge) = open(&manager).await;
    assert_eq!(challenge.nonce.len(), 32);
    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "person-a",
        )))
        .await
        .expect("send the handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected the handshake ack behind the challenge");
    };
}

/// A valid registration settles with the minted bot id, spends the code in the
/// database, and the connection carries on with a fresh challenge behind which
/// a person's handshake still completes.
#[tokio::test]
async fn a_valid_registration_sets_and_the_connection_carries_on() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    registry(&pool).await;
    code(&pool, "valid-code", true).await;
    let key = mint_key();
    let manager = manager(
        pool.clone(),
        guard_with_connection_refusals(100),
        pool.clone(),
        SessionConfig::new(),
    );
    let (mut client, challenge) = open(&manager).await;
    client
        .send_control(ControlMessage::RegisterBot(registration(
            "valid-code",
            &key,
            &challenge.nonce,
        )))
        .await
        .expect("send the registration");
    let ControlMessage::BotRegistered(answer) = next_control(&mut client).await else {
        panic!("the registration did not settle");
    };
    let bot_id = uuid::Uuid::parse_str(&answer.bot_id).expect("the bot id is a uuid");
    // The settlement is in the database, in the bot row and the spent code.
    assert!(
        code_used(&pool, "valid-code").await,
        "the code is spent in the database"
    );
    let mut conn = pool.get().await.expect("a connection");
    let bot_name: String = connetto_server::defaults::connetto_bots::table
        .filter(connetto_server::defaults::connetto_bots::id.eq(bot_id))
        .select(connetto_server::defaults::connetto_bots::name)
        .first(&mut *conn)
        .await
        .expect("read the bot");
    assert_eq!(bot_name, "bot-a", "the bot row carries the registered name");
    // The connection carries on with a fresh challenge, and a person's
    // handshake still completes behind it.
    let nonce = fresh_challenge(&mut client, &challenge.nonce, "a settled registration").await;
    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "person-after",
        )))
        .await
        .expect("send the handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("the person's handshake completes behind the fresh challenge");
    };
    assert_eq!(nonce.len(), 32);
}

/// Every refusal is the identical `RegistrationRefused` and a fresh challenge:
/// a code that is unknown or expired, a list that names a table the
/// deployment does not sync, a verb outside the four, a `*` table, and a
/// signature that does not verify. The code a refusal never reaches stays
/// spendable, and a spent code is refused too.
#[tokio::test]
async fn every_refusal_is_the_same_frame_and_a_fresh_challenge() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    registry(&pool).await;
    code(&pool, "known-code", true).await;
    code(&pool, "expired-code", false).await;
    let key = mint_key();
    let cases: Vec<RefusalCase> = vec![
        (
            "an unknown code",
            Box::new(|nonce, key| registration("no-such-code", key, nonce)),
        ),
        (
            "an expired code",
            Box::new(|nonce, key| registration("expired-code", key, nonce)),
        ),
        (
            "a list naming a table that is not synced",
            Box::new(|nonce, key| {
                let mut reg = registration("known-code", key, nonce);
                reg.list = vec![BotListEntry {
                    table: "ghosts".to_owned(),
                    verb: "read".to_owned(),
                    optional: false,
                }];
                reg
            }),
        ),
        (
            "a verb outside the four",
            Box::new(|nonce, key| {
                let mut reg = registration("known-code", key, nonce);
                reg.list[0].verb = "drop".to_owned();
                reg
            }),
        ),
        (
            "a table that is `*`",
            Box::new(|nonce, key| {
                let mut reg = registration("known-code", key, nonce);
                reg.list[0].table = "*".to_owned();
                reg
            }),
        ),
        (
            "a signature that does not verify",
            Box::new(|nonce, key| {
                let mut reg = registration("known-code", key, nonce);
                reg.signature[0] ^= 0xff;
                reg
            }),
        ),
    ];
    let manager = manager(
        pool.clone(),
        guard_with_connection_refusals(100),
        pool.clone(),
        SessionConfig::new(),
    );
    for (what, make) in cases {
        let (mut client, challenge) = open(&manager).await;
        client
            .send_control(ControlMessage::RegisterBot(make(&challenge.nonce, &key)))
            .await
            .expect("send the registration");
        let ControlMessage::RegistrationRefused = next_control(&mut client).await else {
            panic!("{what} drew no refusal");
        };
        fresh_challenge(&mut client, &challenge.nonce, what).await;
    }
    // The refusals never spent `known-code`, so a valid registration with it
    // settles.
    let (mut client, challenge) = open(&manager).await;
    client
        .send_control(ControlMessage::RegisterBot(registration(
            "known-code",
            &key,
            &challenge.nonce,
        )))
        .await
        .expect("send the registration");
    let ControlMessage::BotRegistered(_) = next_control(&mut client).await else {
        panic!("the code the refusals never spent still settles");
    };
    // A spent code is refused too, and nothing moves a second time.
    let (mut client, challenge) = open(&manager).await;
    client
        .send_control(ControlMessage::RegisterBot(registration(
            "known-code",
            &key,
            &challenge.nonce,
        )))
        .await
        .expect("send the registration again");
    let ControlMessage::RegistrationRefused = next_control(&mut client).await else {
        panic!("a spent code is refused");
    };
}

/// A refused registration counts in the connection's abuse tally, and a
/// crossing closes the connection silently instead of serving a fresh
/// challenge.
#[tokio::test]
async fn a_refused_registration_counts_in_the_abuse_tally() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    registry(&pool).await;
    let key = mint_key();
    // Two refusals on one connection. The ceiling is two, so the first is
    // answered with a fresh challenge and the crossing second is answered too
    // and then closes the connection with no fresh challenge.
    let guard = guard_with_connection_refusals(2);
    let manager = manager(pool.clone(), guard, pool.clone(), SessionConfig::new());
    let (mut client, challenge) = open(&manager).await;
    client
        .send_control(ControlMessage::RegisterBot(registration(
            "no-such-code",
            &key,
            &challenge.nonce,
        )))
        .await
        .expect("send the bad registration");
    let ControlMessage::RegistrationRefused = next_control(&mut client).await else {
        panic!("the first refusal is answered");
    };
    let nonce = fresh_challenge(&mut client, &challenge.nonce, "the first refusal").await;
    client
        .send_control(ControlMessage::RegisterBot(registration(
            "no-such-code",
            &key,
            &nonce,
        )))
        .await
        .expect("send the bad registration again");
    let ControlMessage::RegistrationRefused = next_control(&mut client).await else {
        panic!("the crossing refusal is answered too");
    };
    let closed = tokio::time::timeout(SETTLE, client.recv()).await;
    assert!(
        matches!(closed, Ok(Ok(None))),
        "a crossing refusal closes the connection silently, got {closed:?}"
    );
}

/// A `RegisterBot` signed for one connection is refused on a second, because
/// the signature binds the nonce only the first connection holds, and the
/// code stays spendable.
#[tokio::test]
async fn a_registration_replayed_on_a_second_connection_is_refused() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    registry(&pool).await;
    code(&pool, "replay-code", true).await;
    let key = mint_key();
    let manager = manager(
        pool.clone(),
        guard_with_connection_refusals(100),
        pool.clone(),
        SessionConfig::new(),
    );
    let (_first, challenge) = open(&manager).await;
    let frame = registration("replay-code", &key, &challenge.nonce);
    let (mut second, second_challenge) = open(&manager).await;
    second
        .send_control(ControlMessage::RegisterBot(frame))
        .await
        .expect("send the replayed registration");
    let ControlMessage::RegistrationRefused = next_control(&mut second).await else {
        panic!("a replayed registration is refused");
    };
    fresh_challenge(&mut second, &second_challenge.nonce, "the replay refusal").await;
    assert!(
        !code_used(&pool, "replay-code").await,
        "the refused replay left the code spendable"
    );
}

/// A `RegisterBot` after the identity is settled is a protocol violation,
/// answered with the fatal and the connection dropped.
#[tokio::test]
async fn a_registration_after_identity_is_a_protocol_violation() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    registry(&pool).await;
    code(&pool, "late-code", true).await;
    let key = mint_key();
    let manager = manager(
        pool.clone(),
        guard_with_connection_refusals(100),
        pool.clone(),
        SessionConfig::new(),
    );
    let (mut client, challenge) = open(&manager).await;
    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "person-late",
        )))
        .await
        .expect("send the handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected the handshake ack");
    };
    client
        .send_control(ControlMessage::RegisterBot(registration(
            "late-code",
            &key,
            &challenge.nonce,
        )))
        .await
        .expect("send the late registration");
    let ControlMessage::FatalError(fatal) = next_control(&mut client).await else {
        panic!("a late registration is a protocol violation");
    };
    assert!(
        matches!(fatal.reason, FatalErrorReason::ProtocolViolation { .. }),
        "the fatal names the violation, got {fatal:?}"
    );
}

/// A connection that stays open at its first frame past the budget is closed
/// silently, so a silent peer holds no connection for the budget's length.
#[tokio::test]
async fn a_silent_connection_is_closed_at_the_first_frame_deadline() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    registry(&pool).await;
    let session = SessionConfig::new().with_first_frame_budget(Duration::from_millis(300));
    let manager = manager(
        pool.clone(),
        guard_with_connection_refusals(100),
        pool.clone(),
        session,
    );
    let (mut client, _challenge) = open(&manager).await;
    let closed = tokio::time::timeout(Duration::from_secs(5), client.recv()).await;
    assert!(
        matches!(closed, Ok(Ok(None))),
        "the silent connection is closed at the deadline, got {closed:?}"
    );
}

/// A registry whose database is unreachable drops the connection without
/// answering, so a failure is not mistaken for a refusal that would spend the
/// bot's only code.
#[tokio::test]
async fn a_registry_failure_drops_the_connection_without_a_refusal() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    registry(&pool).await;
    code(&pool, "dead-pool-code", true).await;
    let key = mint_key();
    // The manager's own pools are live, and only the registry's pool is dead.
    let manager = manager(
        pool.clone(),
        guard_with_connection_refusals(100),
        dead_pool().await,
        SessionConfig::new(),
    );
    let (mut client, challenge) = open(&manager).await;
    client
        .send_control(ControlMessage::RegisterBot(registration(
            "dead-pool-code",
            &key,
            &challenge.nonce,
        )))
        .await
        .expect("send the registration");
    let closed = tokio::time::timeout(SETTLE, client.recv()).await;
    assert!(
        matches!(closed, Ok(Ok(None))),
        "a registry failure drops the connection without a frame, got {closed:?}"
    );
}

/// A first frame that is neither the exchange's handshake nor a registration
/// is a protocol violation, and the run ends with it, so a peer that speaks
/// another protocol is told so and is not served.
#[tokio::test]
async fn a_first_frame_that_is_not_the_exchange_is_a_protocol_violation() {
    let pool = dead_pool().await;
    let registry_pool = dead_pool().await;
    let session = SessionConfig::new().with_first_frame_budget(Duration::from_secs(5));
    let manager = manager(
        pool,
        guard_with_connection_refusals(100),
        registry_pool,
        session,
    );
    let (server_end, mut client) = loopback();
    let serving = Arc::clone(&manager);
    let serving_task = tokio::spawn(async move { serving.serve(server_end).await });
    let frame = client.recv().await.expect("recv the opening frame");
    let Some(IncomingFrame::Control(ControlMessage::Challenge(_))) = frame else {
        panic!("the connection did not open with a challenge: {frame:?}");
    };
    client
        .send_control(ControlMessage::Ping(Ping { nonce: 7 }))
        .await
        .expect("send the wrong first frame");
    let SessionError::Protocol(why) = serving_task
        .await
        .expect("serve ends")
        .expect_err("the violation ends the run")
    else {
        panic!("a first frame outside the exchange is a protocol violation");
    };
    assert_eq!(why, "expected a handshake or a registration first");
    let closed = client.recv().await.expect("recv the close");
    assert!(closed.is_none(), "the peer is dropped without a frame");
}

/// A peer that hangs up before the first frame ends the run with a transport
/// error, so a hung peer is not waited on for the first frame budget.
#[tokio::test]
async fn a_peer_that_hangs_up_before_the_first_frame_ends_the_run() {
    let pool = dead_pool().await;
    let registry_pool = dead_pool().await;
    let manager = manager(
        pool,
        guard_with_connection_refusals(100),
        registry_pool,
        SessionConfig::new(),
    );
    let (server_end, client_end) = loopback();
    drop(client_end);
    let SessionError::Transport(why) = manager
        .serve(server_end)
        .await
        .expect_err("the hung peer ends the run")
    else {
        panic!("a peer that hung up is a transport error");
    };
    assert!(
        why.contains("hung up"),
        "the transport names the hang up, got {why}"
    );
}

/// A settled registration whose peer hangs up ends the run with a transport
/// error, so a settlement whose answer never lands is not mistaken for a
/// live session.
#[tokio::test]
async fn a_lost_peer_ends_a_settled_registration_with_a_transport_error() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    registry(&pool).await;
    code(&pool, "hangup-code", true).await;
    let key = mint_key();
    let manager = manager(
        pool.clone(),
        guard_with_connection_refusals(100),
        pool.clone(),
        SessionConfig::new(),
    );
    let (server_end, mut client) = loopback();
    let serving = Arc::clone(&manager);
    let serving_task = tokio::spawn(async move { serving.serve(server_end).await });
    let frame = client.recv().await.expect("recv the opening frame");
    let Some(IncomingFrame::Control(ControlMessage::Challenge(challenge))) = frame else {
        panic!("the connection did not open with a challenge: {frame:?}");
    };
    client
        .send_control(ControlMessage::RegisterBot(registration(
            "hangup-code",
            &key,
            &challenge.nonce,
        )))
        .await
        .expect("send the registration");
    drop(client);
    let err = serving_task
        .await
        .expect("serve ends")
        .expect_err("the lost peer ends the run");
    assert!(
        matches!(err, SessionError::Transport(_)),
        "a lost peer is a transport error, got {err:?}"
    );
}

/// A refused registration whose peer hangs up ends the run with a transport
/// error, so the refusal is not waited on or retried against a dead peer.
#[tokio::test]
async fn a_lost_peer_ends_a_refused_registration_with_a_transport_error() {
    let pool = dead_pool().await;
    let registry_pool = dead_pool().await;
    let manager = manager(
        pool,
        guard_with_connection_refusals(100),
        registry_pool,
        SessionConfig::new(),
    );
    let (server_end, mut client) = loopback();
    let serving = Arc::clone(&manager);
    let serving_task = tokio::spawn(async move { serving.serve(server_end).await });
    let frame = client.recv().await.expect("recv the opening frame");
    let Some(IncomingFrame::Control(ControlMessage::Challenge(challenge))) = frame else {
        panic!("the connection did not open with a challenge: {frame:?}");
    };
    let mut reg = registration("no-such-code", &mint_key(), &challenge.nonce);
    reg.list[0].table = "nobody".to_owned();
    client
        .send_control(ControlMessage::RegisterBot(reg))
        .await
        .expect("send the registration");
    drop(client);
    let err = serving_task
        .await
        .expect("serve ends")
        .expect_err("the lost peer ends the run");
    assert!(
        matches!(err, SessionError::Transport(_)),
        "a lost peer is a transport error, got {err:?}"
    );
}

/// A shutdown that lands while a refused round settles is told to the peer
/// with the fatal, and the run ends cleanly, so a peer that was just refused
/// is not re-invited into a server that is going away.
#[tokio::test]
async fn a_shutdown_landing_on_a_refused_round_is_told_with_the_fatal() {
    let pool = dead_pool().await;
    let registry_pool = dead_pool().await;
    let manager = manager(
        pool,
        guard_with_connection_refusals(100),
        registry_pool,
        SessionConfig::new(),
    );
    let (server_end, mut client) = loopback();
    let serving = Arc::clone(&manager);
    let serving_task = tokio::spawn(async move { serving.serve(server_end).await });
    let frame = client.recv().await.expect("recv the opening frame");
    let Some(IncomingFrame::Control(ControlMessage::Challenge(challenge))) = frame else {
        panic!("the connection did not open with a challenge: {frame:?}");
    };
    manager.shutdown().await;
    let mut reg = registration("no-such-code", &mint_key(), &challenge.nonce);
    reg.list[0].table = "nobody".to_owned();
    client
        .send_control(ControlMessage::RegisterBot(reg))
        .await
        .expect("send the registration");
    let ControlMessage::RegistrationRefused = next_control(&mut client).await else {
        panic!("the list that names no synced table is refused");
    };
    let ControlMessage::FatalError(fatal) = next_control(&mut client).await else {
        panic!("the shutdown is told to the peer");
    };
    assert!(
        matches!(fatal.reason, FatalErrorReason::ServerShuttingDown),
        "the fatal names the shutdown, got {fatal:?}"
    );
    let closed = client.recv().await.expect("recv the close");
    assert!(closed.is_none(), "the run ends after the fatal");
    let Ok(()) = serving_task.await.expect("serve joins") else {
        panic!("the shutdown ends the run cleanly");
    };
}

/// A registration that lists the write verbs settles with the list it asked
/// for, so a bot that earns insert, update and delete holds exactly those.
#[tokio::test]
async fn a_registration_that_earns_the_write_verbs_settles_with_them() {
    let fixture = Fixture::acquire().await;
    let pool = fixture.admin().clone();
    registry(&pool).await;
    code(&pool, "write-code", true).await;
    let key = mint_key();
    let manager = manager(
        pool.clone(),
        guard_with_connection_refusals(100),
        pool.clone(),
        SessionConfig::new(),
    );
    let (mut client, challenge) = open(&manager).await;
    let mut public_key = [0_u8; 32];
    public_key.copy_from_slice(key.public_key().as_ref());
    let reg = RegisterBot {
        code: "write-code".to_owned(),
        name: "bot-a".to_owned(),
        public_key,
        list: vec![
            BotListEntry {
                table: "orders".to_owned(),
                verb: "insert".to_owned(),
                optional: false,
            },
            BotListEntry {
                table: "orders".to_owned(),
                verb: "update".to_owned(),
                optional: true,
            },
            BotListEntry {
                table: "orders".to_owned(),
                verb: "delete".to_owned(),
                optional: false,
            },
        ],
        signature: key
            .sign(&bot_registration_message(&challenge.nonce))
            .as_ref()
            .to_vec(),
    };
    client
        .send_control(ControlMessage::RegisterBot(reg))
        .await
        .expect("send the registration");
    let ControlMessage::BotRegistered(answer) = next_control(&mut client).await else {
        panic!("the registration settles");
    };
    let bot_id = uuid::Uuid::parse_str(&answer.bot_id).expect("the bot id is a uuid");
    let mut conn = pool.get().await.expect("a connection");
    let verbs: Vec<String> = connetto_server::defaults::connetto_bot_lists::table
        .filter(connetto_server::defaults::connetto_bot_lists::bot.eq(bot_id))
        .order_by(connetto_server::defaults::connetto_bot_lists::verb.asc())
        .select(connetto_server::defaults::connetto_bot_lists::verb)
        .load(&mut *conn)
        .await
        .expect("read the list");
    assert_eq!(
        verbs,
        vec![
            "delete".to_owned(),
            "insert".to_owned(),
            "update".to_owned()
        ],
        "the deployment holds exactly the list the bot registered"
    );
}
