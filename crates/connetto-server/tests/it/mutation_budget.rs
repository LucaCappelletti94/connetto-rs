//! Docker-gated: the per-identity mutation byte window.
//!
//! A write past the window is deferred in the reader-share shape, the client
//! keeps it pending, and resending it after the named wait applies it.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::ControlMessage;
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::Transport;
use connetto_server::{
    AbuseConfig, Materializer, RequestGuard, RuntimeWritableCatalog, SessionConfig, SessionManager,
    ThrottleConfig, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};

use super::rls_write_filter::{
    NoSnapshot, PG_DDL, barrier, handshake, insert_changeset, next_control, notes, setup, upload,
};

const WINDOW: Duration = Duration::from_millis(400);

/// A write past the window is deferred with the sequence it names and a wait
/// that is enough, and applies once resent after it. A second identity's
/// window is its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_past_the_window_is_deferred_and_applies_after_the_wait() {
    let fixture = Fixture::acquire().await;
    let admin = fixture.admin().clone();
    let writer_pool = setup(&fixture).await;
    let first = insert_changeset(1, "alice", "mine", "t1");
    let second = insert_changeset(2, "alice", "mine", "t1");
    // Exactly one compressed patch per window, so the first passes and the
    // second, of the same shape, is short by its whole size.
    let one_patch = u64::try_from(
        zstd::encode_all(first.as_slice(), 3)
            .expect("compress")
            .len(),
    )
    .expect("a small patch fits a u64");
    let materializer = Materializer::with_write_catalog(
        PG_DDL,
        RuntimeWritableCatalog::builder()
            .versioned("notes", "edited_at")
            .build(),
    )
    .expect("build materializer");
    let target =
        pg_write_target::<ConnettoWatermark>(writer_pool, PG_DDL).expect("build write target");
    let guard = RequestGuard::new(
        ThrottleConfig::new().with_mutation_bytes_per_identity(one_patch, WINDOW),
        AbuseConfig::default(),
    );
    let manager = SessionManager::new(
        materializer,
        NoSnapshot,
        RosterAuth::granting("alice")
            .and("bob")
            .withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        target,
        Arc::new(guard),
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    handshake(&mut client, "alice").await;

    upload(&mut client, 1, first).await;
    match next_control(&mut client).await {
        ControlMessage::MutationApplied(applied) => assert_eq!(applied.client_seq, 1),
        other => panic!("the first write fits the window, got {other:?}"),
    }

    upload(&mut client, 2, second.clone()).await;
    let retry_after_ms = match next_control(&mut client).await {
        ControlMessage::RateLimited(deferral) => {
            assert_eq!(deferral.related_to.as_deref(), Some("2"));
            deferral.retry_after_ms
        }
        other => panic!("the second write is deferred, got {other:?}"),
    };
    assert!(retry_after_ms > 0, "the deferral names a wait");
    assert!(
        retry_after_ms <= u64::try_from(WINDOW.as_millis()).expect("fits"),
        "the wait never exceeds the window: {retry_after_ms} ms"
    );
    match barrier(&mut client, 1).await {
        ControlMessage::Pong(_) => {}
        other => panic!("expected pong after the deferral, got {other:?}"),
    }
    assert_eq!(
        notes(&admin).await,
        vec![(1, "alice".to_owned())],
        "a deferred write reaches Postgres only when resent"
    );

    // Another identity's window is untouched by alice's spending.
    let (bob_transport, mut bob) = loopback();
    let bob_server = tokio::spawn(manager.clone().serve(bob_transport));
    handshake(&mut bob, "bob").await;
    upload(&mut bob, 1, insert_changeset(3, "bob", "theirs", "t1")).await;
    match next_control(&mut bob).await {
        ControlMessage::MutationApplied(applied) => assert_eq!(applied.client_seq, 1),
        other => panic!("bob's first write fits his own window, got {other:?}"),
    }
    bob.close().await.expect("close bob");
    bob_server.await.expect("join bob").expect("bob session ok");

    tokio::time::sleep(Duration::from_millis(retry_after_ms) + Duration::from_millis(20)).await;
    upload(&mut client, 2, second).await;
    match next_control(&mut client).await {
        ControlMessage::MutationApplied(applied) => assert_eq!(applied.client_seq, 2),
        other => panic!("the resent write applies after the wait, got {other:?}"),
    }
    assert_eq!(
        notes(&admin).await,
        vec![
            (1, "alice".to_owned()),
            (2, "alice".to_owned()),
            (3, "bob".to_owned())
        ]
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}
