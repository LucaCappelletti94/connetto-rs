//! Docker-gated: the per-identity mutation byte window.
//!
//! A write past the window is deferred in the reader-share shape and every
//! later sequence waits behind it, the client keeps them pending, and resending
//! after the named wait applies them in order. A patch that can never fit is
//! rejected outright.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{ControlMessage, MutationRejectReason};
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

/// The compressed size of one patch, which is what the meter charges.
fn compressed_len(changeset: &[u8]) -> u64 {
    u64::try_from(zstd::encode_all(changeset, 3).expect("compress").len())
        .expect("a patch fits a u64")
}

/// A body zstd cannot fold, so the patch carrying it is measurably large.
fn incompressible_body(len: usize) -> String {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            char::from(b'a' + u8::try_from(state % 26).expect("under 26"))
        })
        .collect()
}

fn manager(
    writer_pool: diesel_async::pooled_connection::bb8::Pool<diesel_async::AsyncPgConnection>,
    limit: u64,
) -> Arc<SessionManager<NoSnapshot, RosterAuth, ConnettoWatermark, connetto_server::NoConnector>> {
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
        ThrottleConfig::new().with_mutation_bytes_per_identity(limit, WINDOW),
        AbuseConfig::default(),
    );
    SessionManager::new(
        materializer,
        NoSnapshot,
        RosterAuth::granting("alice")
            .and("bob")
            .withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        target,
        Arc::new(guard),
        SessionConfig::default(),
    )
}

async fn expect_applied<T: Transport>(client: &mut T, client_seq: u64, what: &str) {
    match next_control(client).await {
        ControlMessage::MutationApplied(applied) => assert_eq!(applied.client_seq, client_seq),
        other => panic!("{what}: expected apply of {client_seq}, got {other:?}"),
    }
}

async fn expect_deferred<T: Transport>(client: &mut T, client_seq: u64, what: &str) -> u64 {
    match next_control(client).await {
        ControlMessage::RateLimited(deferral) => {
            assert_eq!(
                deferral.related_to.as_deref(),
                Some(client_seq.to_string().as_str())
            );
            assert!(
                deferral.retry_after_ms > 0,
                "{what}: the deferral names a wait"
            );
            assert!(
                deferral.retry_after_ms <= u64::try_from(WINDOW.as_millis()).expect("fits"),
                "{what}: the wait never exceeds the window: {} ms",
                deferral.retry_after_ms
            );
            deferral.retry_after_ms
        }
        other => panic!("{what}: expected deferral of {client_seq}, got {other:?}"),
    }
}

async fn expect_pong<T: Transport>(client: &mut T, nonce: u64) {
    match barrier(client, nonce).await {
        ControlMessage::Pong(_) => {}
        other => panic!("expected pong, got {other:?}"),
    }
}

/// A large write past the window is deferred, a small one numbered after it
/// is deferred behind it even though it would fit, both apply in order once
/// resent after the wait, and another identity's window is its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn later_sequences_wait_behind_a_deferred_write_and_apply_in_order() {
    let fixture = Fixture::acquire().await;
    let admin = fixture.admin().clone();
    let writer_pool = setup(&fixture).await;
    let small = insert_changeset(1, "alice", "mine", "t1");
    let large = insert_changeset(2, "alice", &incompressible_body(3000), "t1");
    let small_after = insert_changeset(3, "alice", "mine", "t1");
    let (small_len, large_len) = (compressed_len(&small), compressed_len(&large));
    assert!(
        large_len >= 3 * small_len,
        "the large patch must dwarf the small one"
    );
    // One small write fits, the large one is then short by half a small patch,
    // and a small one would still fit the remainder: exactly the shape where
    // the watermark would run ahead without the ordering gate.
    let limit = large_len + small_len / 2;
    let manager = manager(writer_pool, limit);

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    handshake(&mut client, "alice").await;

    upload(&mut client, 1, small).await;
    expect_applied(&mut client, 1, "first small write").await;

    upload(&mut client, 2, large.clone()).await;
    let wait_ms = expect_deferred(&mut client, 2, "large write").await;

    upload(&mut client, 3, small_after.clone()).await;
    let wait_behind_ms =
        expect_deferred(&mut client, 3, "small write behind the deferred one").await;
    assert!(
        wait_behind_ms <= wait_ms,
        "a write behind the deferred one shares its deadline: {wait_behind_ms} after {wait_ms}"
    );
    expect_pong(&mut client, 1).await;
    assert_eq!(
        notes(&admin).await,
        vec![(1, "alice".to_owned())],
        "nothing past the deferred write reaches Postgres"
    );

    let (bob_transport, mut bob) = loopback();
    let bob_server = tokio::spawn(manager.clone().serve(bob_transport));
    handshake(&mut bob, "bob").await;
    upload(&mut bob, 1, insert_changeset(4, "bob", "theirs", "t1")).await;
    expect_applied(&mut bob, 1, "bob's first write in his own window").await;
    bob.close().await.expect("close bob");
    bob_server.await.expect("join bob").expect("bob session ok");

    tokio::time::sleep(Duration::from_millis(wait_ms) + Duration::from_millis(20)).await;
    upload(&mut client, 2, large).await;
    expect_applied(&mut client, 2, "the large write resent after the wait").await;
    // The large write spent the bucket again, so the small one behind it waits
    // for its own refill and then applies: order held throughout.
    upload(&mut client, 3, small_after.clone()).await;
    let wait_ms = expect_deferred(&mut client, 3, "small write after the bucket drained").await;
    tokio::time::sleep(Duration::from_millis(wait_ms) + Duration::from_millis(20)).await;
    upload(&mut client, 3, small_after).await;
    expect_applied(&mut client, 3, "the small write resent after its wait").await;
    assert_eq!(
        notes(&admin).await,
        vec![
            (1, "alice".to_owned()),
            (2, "alice".to_owned()),
            (3, "alice".to_owned()),
            (4, "bob".to_owned()),
        ]
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}

/// A patch larger than the whole window is rejected, never deferred, because
/// no wait would ever let it fit, and it leaves no deferral behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_patch_larger_than_the_window_is_rejected_not_deferred() {
    let fixture = Fixture::acquire().await;
    let admin = fixture.admin().clone();
    let writer_pool = setup(&fixture).await;
    let small = insert_changeset(1, "alice", "mine", "t1");
    let large = insert_changeset(2, "alice", &incompressible_body(3000), "t1");
    let manager = manager(writer_pool, compressed_len(&large) - 1);

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));
    handshake(&mut client, "alice").await;

    upload(&mut client, 1, large).await;
    match next_control(&mut client).await {
        ControlMessage::MutationReject(reject) => {
            assert_eq!(reject.client_seq, 1);
            assert!(
                matches!(reject.reason, MutationRejectReason::Other { ref detail } if detail.contains("exceeds")),
                "the reject names the window: {:?}",
                reject.reason
            );
        }
        other => panic!("an oversized patch is rejected, got {other:?}"),
    }
    // The reject charged nothing and gated nothing: a fitting write applies.
    upload(&mut client, 2, small).await;
    expect_applied(&mut client, 2, "a fitting write after an oversized reject").await;
    assert_eq!(notes(&admin).await, vec![(1, "alice".to_owned())]);

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}
