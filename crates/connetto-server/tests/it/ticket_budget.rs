//! Content ticket budget and reader-permit tests.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{
    CONTENT_TICKET_SIGNER_ERROR, ContentVerb, ControlMessage, NonFatalError, RateLimited,
};
use connetto_core::traits::Transport;
use connetto_server::{
    AbuseConfig, LoopbackTransport, ReaderReserve, RequestGuard, ThrottleConfig, loopback,
};
use connetto_test_harness::{Fixture, RosterAuth, WITHHELD_ID};

use super::ticket_shared::{
    FILE_ID, FlakyFirstSigner, OkSigner, TicketManager, WINDOW, build_manager_with_guard,
    build_standard_manager, do_handshake, do_handshake_anon, drain_to_control,
    open_session_with_handshake, request_ticket, send_ticket_request, setup_reader,
    setup_slow_reader,
};

/// Send one ticket request on an open session and return the `NonFatalError` detail.
async fn refused_detail(
    client: &mut LoopbackTransport,
    request_id: &str,
    verb: ContentVerb,
) -> String {
    let resp = request_ticket(client, request_id, FILE_ID, verb).await;
    let ControlMessage::NonFatalError(NonFatalError { detail, .. }) = resp else {
        panic!("expected NonFatalError, got {resp:?}");
    };
    detail
}

/// Open a session for `identity` against `manager`, send one ticket request, and return the refusal detail.
async fn session_with_refusal(
    manager: &Arc<TicketManager<OkSigner>>,
    identity: &str,
    request_id: &str,
    verb: ContentVerb,
) -> String {
    let (end, mut client) = loopback();
    let server = tokio::spawn(Arc::clone(manager).serve(end));
    do_handshake(&mut client, identity).await;
    let detail = refused_detail(&mut client, request_id, verb).await;
    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
    detail
}

/// An over-budget write is refused with the SAME detail as an invisible file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_budget_write_refused_with_same_detail_as_invisible() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader(&fixture).await;
    // 1-byte limit: the first 1-byte write ticket uses the whole budget.
    let content_config = ThrottleConfig::new().with_content_bytes_per_identity(1, WINDOW);
    // alice is granted; WITHHELD_ID is the only withheld principal, so bob can also open a session.
    let manager = build_standard_manager(
        reader_pool,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        OkSigner,
        &content_config,
    );
    let (alice_end, mut alice) = loopback();
    let alice_server = tokio::spawn(Arc::clone(&manager).serve(alice_end));
    do_handshake(&mut alice, "alice").await;
    let first = request_ticket(
        &mut alice,
        "write-1",
        FILE_ID,
        ContentVerb::Write { declared_len: 1 },
    )
    .await;
    assert!(
        matches!(first, ControlMessage::ContentTicketGrant(_)),
        "first write ticket must succeed; budget was not yet exhausted, got {first:?}",
    );
    let over_budget_detail = refused_detail(
        &mut alice,
        "write-2",
        ContentVerb::Write { declared_len: 1 },
    )
    .await;
    let invisible_detail =
        session_with_refusal(&manager, "bob", "bob-req", ContentVerb::Read).await;
    // Core assertion: the two detail strings are byte-identical.
    assert_eq!(
        over_budget_detail, invisible_detail,
        "over-budget write and invisible file must carry byte-identical detail so a \
         caller cannot learn a file exists from the difference",
    );
    alice.close().await.expect("close alice");
    alice_server
        .await
        .expect("join alice")
        .expect("alice session ok");
}

/// A saturated reader-share permit causes an anonymous ticket request to be refused with `RateLimited`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ticket_path_holds_reader_permit() {
    let fixture = Fixture::acquire().await;
    let reader_pool = setup_slow_reader(&fixture).await;

    // One anonymous slot: the pool has capacity for many connections, so only
    // the semaphore separates the permit gate from an unguarded pool checkout.
    let guard = Arc::new(
        RequestGuard::new(ThrottleConfig::default(), AbuseConfig::default())
            .with_reader_gate(ReaderReserve::new().with_total(10).with_reserved(9).gate()),
    );

    let manager = build_manager_with_guard(
        reader_pool,
        RosterAuth::granting("alice")
            .and_the_unnamed_caller()
            .withholding(WITHHELD_ID),
        guard,
        OkSigner,
        &ThrottleConfig::default(),
    );

    // Both sessions handshake while the anonymous share is free: the watermark
    // read is fast so each permit is taken and released before the next session
    // starts its handshake.
    let (srv_a, mut anon_a) = loopback();
    let task_a = tokio::spawn(Arc::clone(&manager).serve(srv_a));
    do_handshake_anon(&mut anon_a, "anon-a").await;

    let (srv_b, mut anon_b) = loopback();
    let task_b = tokio::spawn(Arc::clone(&manager).serve(srv_b));
    do_handshake_anon(&mut anon_b, "anon-b").await;

    // Session A acquires the one anonymous permit before entering the slow visibility function.
    send_ticket_request(&mut anon_a, "req-a", FILE_ID, ContentVerb::Read).await;

    // Give session A time to enter the slow visibility function and hold the permit.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Session B waits for the permit and receives RateLimited rather than a second pool checkout.
    let resp_b = request_ticket(&mut anon_b, "req-b", FILE_ID, ContentVerb::Read).await;
    let ControlMessage::RateLimited(RateLimited {
        related_to,
        retry_after_ms,
    }) = resp_b
    else {
        panic!("over-share ticket request must be RateLimited; got {resp_b:?}");
    };
    assert_eq!(
        related_to.as_deref(),
        Some("req-b"),
        "request_id echoed in the deferral"
    );
    assert!(retry_after_ms > 0, "deferral states a wait duration");

    drain_to_control(&mut anon_a).await;

    anon_b.close().await.expect("close session B");
    anon_a.close().await.expect("close session A");
    let _ = task_b.await;
    let _ = task_a.await;
}

/// A signer failure costs no upload budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signer_failure_costs_no_budget() {
    const DECLARED: u64 = 1;

    let fixture = Fixture::acquire().await;
    let reader_pool = setup_reader(&fixture).await;
    let content_config = ThrottleConfig::new().with_content_bytes_per_identity(DECLARED, WINDOW);

    let (mut client, server) = open_session_with_handshake(
        reader_pool,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        FlakyFirstSigner::new(),
        &content_config,
        "alice",
    )
    .await;

    // Signer fails on the first call; the server mints before charging so no budget is consumed.
    let first = request_ticket(
        &mut client,
        "req-1",
        FILE_ID,
        ContentVerb::Write {
            declared_len: DECLARED,
        },
    )
    .await;
    let ControlMessage::NonFatalError(NonFatalError {
        detail: ref first_detail,
        ..
    }) = first
    else {
        panic!("first request must fail with NonFatalError; got {first:?}");
    };
    assert_eq!(
        first_detail, CONTENT_TICKET_SIGNER_ERROR,
        "first request fails at the signer, not as a budget refusal"
    );

    // Budget is intact because the first request charged nothing; signer succeeds.
    let second = request_ticket(
        &mut client,
        "req-2",
        FILE_ID,
        ContentVerb::Write {
            declared_len: DECLARED,
        },
    )
    .await;
    assert!(
        matches!(second, ControlMessage::ContentTicketGrant(_)),
        "second request must succeed because the first signer failure charged no budget; \
         got {second:?}"
    );

    client.close().await.expect("close");
    server.await.expect("join").expect("session ok");
}
