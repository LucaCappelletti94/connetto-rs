//! Phase R19: what a caller may ask for is bounded, and the bound is tiered.
//!
//! Five properties, each asserted rather than assumed:
//!
//! * an over-limit subscription is refused rather than served slowly, and the
//!   session survives it;
//! * the two tiers are separate allowances, so a caller with no identity is
//!   held to less than one that signed in;
//! * **the limit holds across a reconnection**, which is the property a
//!   per-connection counter would fail and therefore the one that pins the
//!   durable session handle as the key;
//! * a rate refusal stays distinguishable from phase R38's fixed refusal text,
//!   because "slow down" and "that will never work" ask a client for opposite
//!   behaviour;
//! * **a limit that trips stops the work it bounds**, rather than being noted
//!   and then paid for anyway.
//!
//! Every limit is reached through [`RequestGuard`], which owns the counters
//! since R36 so one call per site defines the moment for the rate limit and the
//! abuse tally alike.
//!
//! Needs Docker: the fixture starts its own Postgres.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{
    ControlMessage, FatalErrorReason, Grant, Handshake, Ping, SUBSCRIPTION_REFUSED, Subscribe,
    SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{
    GrantCheckFuture, GrantRefused, HandleError, HandshakeAuthority, IncomingFrame, Transport,
};
use connetto_core::{Cursor, PROTOCOL_VERSION, SessionId};
use connetto_server::{
    AbuseConfig, LoopbackTransport, Materializer, PageSpec, RequestGuard, SessionConfig,
    SessionManager, SnapshotEstimate, SnapshotPage, SnapshotSource, ThrottleConfig, TierLimits,
    loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
/// A window long enough that nothing rolls over mid-test.
const WINDOW: Duration = Duration::from_secs(300);

/// A snapshot source that always succeeds, so a refusal in these tests is the
/// throttle and never the backing store.
struct SeedSnapshot;

impl SnapshotSource for SeedSnapshot {
    type Error = std::convert::Infallible;

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
        _auth: &connetto_core::Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        let table = SimpleTable::new("orders", &["id", "price", "quantity", "status"], &[0]);
        let insert = Insert::<_, String, Vec<u8>>::from(table)
            .set(0, Value::Integer(1))
            .expect("set id")
            .set(1, Value::Real(1.0))
            .expect("set price")
            .set(2, Value::Integer(3))
            .expect("set quantity")
            .set(3, Value::Text("seed".to_owned()))
            .expect("set status");
        Ok(SnapshotPage {
            patchset: PatchSet::<SimpleTable, String, Vec<u8>>::new()
                .insert(insert)
                .build(),
            cursor: Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: 0,
            rows: 0,
            bytes: 0,
        })
    }
}

type Manager = Arc<SessionManager<SeedSnapshot, RosterAuth, ConnettoWatermark>>;

/// Build a manager whose only unusual setting is the throttle.
fn manager(fixture: &Fixture, throttle: &ThrottleConfig) -> Manager {
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    SessionManager::new(
        materializer,
        SeedSnapshot,
        // Rows come from the SeedSnapshot stub, not the live path.
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::new(*throttle, AbuseConfig::default())),
        SessionConfig::default(),
    )
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    loop {
        match transport.recv().await.expect("recv") {
            Some(IncomingFrame::Control(msg)) => return msg,
            Some(IncomingFrame::Bulk(_)) => {}
            None => panic!("connection closed while waiting for a control frame"),
        }
    }
}

/// Open a connection, presenting `grants` and optionally resuming `resume`.
/// Returns the client half, the server task, and the resume token the ack
/// carried, so the next connection can continue the same run.
async fn connect(
    manager: &Manager,
    client_id: &str,
    grants: &[&str],
    resume: Option<String>,
) -> (LoopbackTransport, tokio::task::JoinHandle<()>, String) {
    let (server_end, mut client) = loopback();
    let server = Arc::clone(manager);
    let handle = tokio::spawn(async move {
        server.serve(server_end).await.expect("session ok");
    });
    let mut handshake = Handshake::new(PROTOCOL_VERSION, client_id);
    for grant in grants {
        handshake = handshake.with_grant(Grant::new(*grant));
    }
    if let Some(token) = resume {
        handshake = handshake.with_resume_token(token);
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(ack) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };
    (client, handle, ack.resume_token)
}

/// Subscribe under `sub_id` and read frames until the subscription resolves,
/// returning the frame that settled it: a `SnapshotEnd` when it was served, or
/// the refusal that turned it away.
async fn subscribe<T: Transport>(client: &mut T, sub_id: &str, query: &str) -> ControlMessage {
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: sub_id.to_owned(),
            spec: SubscriptionSpec::new(query),
        }))
        .await
        .expect("send subscribe");
    loop {
        match next_control(client).await {
            ControlMessage::SnapshotBegin(_) => {}
            settled => return settled,
        }
    }
}

/// A throttle whose only tight limit is how many subscriptions each tier gets.
fn subscription_limits(identified: u32, anonymous: u32) -> ThrottleConfig {
    ThrottleConfig::new()
        .with_identified(TierLimits::identified().with_subscriptions(identified, WINDOW))
        .with_anonymous(TierLimits::anonymous().with_subscriptions(anonymous, WINDOW))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_over_limit_subscription_is_refused_and_the_session_survives() {
    let fixture = Fixture::acquire().await;
    let manager = manager(&fixture, &subscription_limits(2, 2));
    let (mut client, server, _) = connect(&manager, "greedy", &["user:greedy"], None).await;

    for nth in 0..2 {
        let settled = subscribe(&mut client, &format!("sub-{nth}"), QUERY).await;
        assert!(
            matches!(settled, ControlMessage::SnapshotEnd(_)),
            "the first two are served, got {settled:?}"
        );
    }

    let settled = subscribe(&mut client, "one-too-many", QUERY).await;
    let ControlMessage::RateLimited(limited) = settled else {
        panic!("the third must be refused for rate, got {settled:?}");
    };
    assert_eq!(limited.related_to.as_deref(), Some("one-too-many"));
    assert!(
        limited.retry_after_ms > 0,
        "the refusal states how long to wait, so a caller waits once instead of probing"
    );

    // Refused rather than served slowly: the run loop is untouched.
    client
        .send_control(ControlMessage::Ping(Ping { nonce: 5 }))
        .await
        .expect("send ping");
    let ControlMessage::Pong(pong) = next_control(&mut client).await else {
        panic!("expected pong after the refusal");
    };
    assert_eq!(pong.nonce, 5);

    client.close().await.expect("close");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_two_tiers_are_different_allowances() {
    let fixture = Fixture::acquire().await;
    let manager = manager(&fixture, &subscription_limits(3, 1));

    // No grant, so nothing resolves an identity and the caller is anonymous.
    let (mut visitor, visitor_server, _) = connect(&manager, "visitor", &[], None).await;
    let served = subscribe(&mut visitor, "v0", QUERY).await;
    assert!(matches!(served, ControlMessage::SnapshotEnd(_)));
    let refused = subscribe(&mut visitor, "v1", QUERY).await;
    assert!(
        matches!(refused, ControlMessage::RateLimited(_)),
        "the anonymous tier runs out after one, got {refused:?}"
    );
    visitor.close().await.expect("close visitor");
    visitor_server.await.expect("join visitor server");

    let (mut member, member_server, _) = connect(&manager, "member", &["user:member"], None).await;
    for nth in 0..3 {
        let served = subscribe(&mut member, &format!("m{nth}"), QUERY).await;
        assert!(
            matches!(served, ControlMessage::SnapshotEnd(_)),
            "the identified tier is served past the anonymous limit, got {served:?}"
        );
    }
    let refused = subscribe(&mut member, "m3", QUERY).await;
    assert!(
        matches!(refused, ControlMessage::RateLimited(_)),
        "and is bounded too, got {refused:?}"
    );
    member.close().await.expect("close member");
    member_server.await.expect("join member server");
}

/// The anonymous key is the one this pins. An identified run takes its handle
/// from the login grant, so its allowance would survive a reconnect however the
/// resume credential behaved. A caller with no identity has nothing but the
/// handle connetto minted and handed back, which is exactly the key a
/// per-connection counter would throw away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_anonymous_limit_holds_across_a_reconnection() {
    let fixture = Fixture::acquire().await;
    let manager = manager(&fixture, &subscription_limits(2, 2));

    let (mut first, first_server, resume) = connect(&manager, "loop", &[], None).await;
    for nth in 0..2 {
        let served = subscribe(&mut first, &format!("a{nth}"), QUERY).await;
        assert!(matches!(served, ControlMessage::SnapshotEnd(_)));
    }
    first.close().await.expect("close first");
    first_server.await.expect("join first server");

    // Same run, new connection, resumed on the credential connetto signed. A
    // per-connection counter would hand this a fresh allowance.
    let (mut second, second_server, _) = connect(&manager, "loop", &[], Some(resume)).await;
    let refused = subscribe(&mut second, "a2", QUERY).await;
    assert!(
        matches!(refused, ControlMessage::RateLimited(_)),
        "reconnecting must not refill the allowance, got {refused:?}"
    );

    second.close().await.expect("close second");
    second_server.await.expect("join second server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rate_refusal_and_a_schema_refusal_stay_distinguishable() {
    let fixture = Fixture::acquire().await;
    let manager = manager(&fixture, &subscription_limits(2, 2));
    let (mut client, server, _) = connect(&manager, "prober", &["user:prober"], None).await;

    // R38 keeps every schema refusal byte-identical so a caller cannot learn
    // what exists. A rate refusal reports only the caller's own quota, so it
    // must not be folded into that text: a client that cannot tell them apart
    // either retries forever or gives up on work that would succeed later.
    let schema = subscribe(
        &mut client,
        "ghost",
        "SELECT * FROM nosuch WHERE quantity > 0",
    )
    .await;
    let ControlMessage::NonFatalError(refusal) = schema else {
        panic!("a table that does not exist draws the fixed refusal, got {schema:?}");
    };
    assert_eq!(refusal.detail, SUBSCRIPTION_REFUSED);

    let accepted = subscribe(&mut client, "real", QUERY).await;
    assert!(matches!(accepted, ControlMessage::SnapshotEnd(_)));

    // Naming something that does not resolve spent allowance all the same, so
    // the second subscription exhausted the limit rather than the third. That
    // is deliberate: the limit is charged before registration, so an over-limit
    // caller costs no parse, and probing is the one behaviour R36 counts, which
    // a free failure would hand an unlimited budget.
    let rate = subscribe(&mut client, "over", QUERY).await;
    let ControlMessage::RateLimited(limited) = rate else {
        panic!("over the limit draws the typed signal, got {rate:?}");
    };
    assert_eq!(limited.related_to.as_deref(), Some("over"));
    assert!(limited.retry_after_ms > 0);

    client.close().await.expect("close");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn too_many_connections_on_one_handle_are_closed() {
    let fixture = Fixture::acquire().await;
    let throttle = ThrottleConfig::new()
        .with_identified(TierLimits::identified().with_connections(2, WINDOW))
        .with_anonymous(TierLimits::anonymous().with_connections(2, WINDOW));
    let manager = manager(&fixture, &throttle);

    let (client, server, resume) = connect(&manager, "flapper", &["user:flapper"], None).await;
    drop(client);
    server.await.expect("join first");

    let (client, server, resume) = {
        let (client, server, token) =
            connect(&manager, "flapper", &["user:flapper"], Some(resume)).await;
        (client, server, token)
    };
    drop(client);
    server.await.expect("join second");

    // The third handshake on the same handle is over the limit, so the server
    // closes it with the reason rather than serving it.
    let (server_end, mut client) = loopback();
    let serving = Arc::clone(&manager);
    let third = tokio::spawn(async move {
        serving.serve(server_end).await.expect("session ok");
    });
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "flapper")
                .with_grant(Grant::new("user:flapper"))
                .with_resume_token(resume),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::FatalError(fatal) = next_control(&mut client).await else {
        panic!("the third connection is closed rather than acknowledged");
    };
    let FatalErrorReason::RateLimited { retry_after_ms } = fatal.reason else {
        panic!("closed for the wrong reason: {:?}", fatal.reason);
    };
    assert!(retry_after_ms > 0);

    drop(client);
    third.await.expect("join third");
}

/// The same bound for a caller with no identity, which is the one it is for.
///
/// The sibling above carries a login grant, and a login grant supplies the
/// handle, so it holds however the resume credential behaves and says nothing
/// about an unidentified caller. This one has nothing but the credential
/// connetto minted and handed back, so it fails the moment that stops carrying
/// the run. An anonymous tier without a working bound is the unauthenticated
/// cost centre this phase exists to close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anonymous_caller_cannot_reconnect_past_its_connection_limit() {
    let fixture = Fixture::acquire().await;
    let manager = manager(
        &fixture,
        &ThrottleConfig::new().with_anonymous(TierLimits::anonymous().with_connections(2, WINDOW)),
    );

    let (client, server, resume) = connect(&manager, "visitor", &[], None).await;
    drop(client);
    server.await.expect("join first");

    let (client, server, resume) = connect(&manager, "visitor", &[], Some(resume)).await;
    drop(client);
    server.await.expect("join second");

    let (server_end, mut client) = loopback();
    let serving = Arc::clone(&manager);
    let third = tokio::spawn(async move {
        serving.serve(server_end).await.expect("session ok");
    });
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "visitor").with_resume_token(resume),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::FatalError(fatal) = next_control(&mut client).await else {
        panic!("the third connection on this run is closed rather than acknowledged");
    };
    assert!(matches!(fatal.reason, FatalErrorReason::RateLimited { .. }));

    drop(client);
    third.await.expect("join third");
}

/// Counts how many grants it was asked to check, and refuses every one.
struct CountingAuthority(Arc<std::sync::atomic::AtomicUsize>);

impl HandshakeAuthority for CountingAuthority {
    fn check_grant<'a>(&'a self, _grant: &'a Grant) -> GrantCheckFuture<'a> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Box::pin(async move { Err(GrantRefused::Invalid("refused".to_owned())) })
    }

    fn mint_handle(&self, session_id: SessionId) -> Result<String, HandleError> {
        Ok(format!("run:{session_id}"))
    }

    fn read_handle(&self, blob: &str) -> Result<SessionId, HandleError> {
        blob.strip_prefix("run:")
            .and_then(|handle| handle.parse().ok())
            .ok_or_else(|| HandleError(format!("not a test handle: {blob:?}")))
    }
}

/// Tripping the credential limit must stop the checking, not merely note it.
///
/// One handshake carries as many grants as fit in a frame, and the cap is 64
/// MiB, so a limit that is recorded and then ignored for the rest of the loop
/// bounds nothing: the caller still buys every signature check it asked for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tripped_credential_limit_stops_checking_grants() {
    const LIMIT: u32 = 3;
    const PRESENTED: usize = 500;

    let fixture = Fixture::acquire().await;
    let checked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        Arc::new(CountingAuthority(Arc::clone(&checked))),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::new(
            ThrottleConfig::new()
                .with_anonymous(TierLimits::anonymous().with_credential_refusals(LIMIT, WINDOW)),
            AbuseConfig::default(),
        )),
        SessionConfig::default(),
    );

    let (server_end, mut client) = loopback();
    let server = Arc::clone(&manager);
    let serve = tokio::spawn(async move {
        server.serve(server_end).await.expect("session ok");
    });

    let mut handshake = Handshake::new(PROTOCOL_VERSION, "flood");
    for nth in 0..PRESENTED {
        handshake = handshake.with_grant(Grant::new(format!("forged-{nth}")));
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");

    let ControlMessage::FatalError(fatal) = next_control(&mut client).await else {
        panic!("a caller past its credential limit is closed, not acknowledged");
    };
    assert!(matches!(fatal.reason, FatalErrorReason::RateLimited { .. }));

    let checked = checked.load(std::sync::atomic::Ordering::Relaxed);
    let allowed = usize::try_from(LIMIT).expect("a small limit fits a usize") + 1;
    assert!(
        checked <= allowed,
        "checking must stop when the limit trips: {checked} of {PRESENTED} grants checked, \
         expected at most {allowed}"
    );

    drop(client);
    serve.await.expect("join server");
}
