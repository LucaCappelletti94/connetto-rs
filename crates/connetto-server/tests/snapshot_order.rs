//! R33: a snapshot's completion frame must not overtake its own rows.
//!
//! `SnapshotPatch` travels on the bulk plane and is held once the credit
//! window closes. `SnapshotEnd` is a control frame and bypasses that queue by
//! design, because flow control bounds bulk data rather than control. A client
//! whose window is closed can therefore be told the snapshot is complete while
//! the rows it names are still queued behind the client's own acknowledgement.
//!
//! `snapshot_order_holds_when_the_credit_window_is_closed` demonstrates that:
//! it fails before the fix, with `SnapshotEnd` arriving ahead of the patch.
//!
//! The window is closed by configuration rather than by flooding, so there is
//! no timing here: `initial_credits` is zero, the caller is a raw frame-level
//! transport that acknowledges on the test's schedule, and the frames are read
//! in wire order rather than filtered by plane.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{
    AckCredits, BulkMessage, ControlMessage, Handshake, Ping, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    Materializer, PermissiveAuth, RequestGuard, SessionConfig, SessionManager, Snapshot,
    SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture};
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

/// A snapshot source returning one seed row under a non-empty cursor.
///
/// The cursor matters: the client only persists a resume position when the
/// completion frame carries one, so an empty cursor would hide the durability
/// half of this defect behind a guard rather than exercising it.
struct SeedSnapshot;

impl SnapshotSource for SeedSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::Principal,
    ) -> Result<Snapshot, Self::Error> {
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
        let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new()
            .insert(insert)
            .build();
        Ok(Snapshot {
            patchset,
            cursor: Cursor::new(42_u64.to_be_bytes().to_vec()),
        })
    }
}

/// The next frame in wire order, whichever plane it came in on.
async fn next_frame<T: Transport>(transport: &mut T) -> IncomingFrame {
    tokio::time::timeout(Duration::from_secs(5), transport.recv())
        .await
        .expect("a frame within five seconds")
        .expect("recv")
        .expect("connection open")
}

/// A short name for a frame, so an ordering failure reads as a sequence.
fn label(frame: &IncomingFrame) -> String {
    match frame {
        IncomingFrame::Control(ControlMessage::SnapshotBegin(_)) => "SnapshotBegin".to_owned(),
        IncomingFrame::Control(ControlMessage::SnapshotEnd(_)) => "SnapshotEnd".to_owned(),
        IncomingFrame::Bulk(BulkMessage::SnapshotPatch(_)) => "SnapshotPatch".to_owned(),
        IncomingFrame::Control(other) => format!("control {other:?}"),
        IncomingFrame::Bulk(_) => "other bulk".to_owned(),
    }
}

/// Every frame the server has already emitted, named in wire order.
///
/// The barrier is a ping rather than a timeout: the run loop handles frames one
/// at a time in order, so a pong proves everything the preceding frames were
/// going to produce is already in the transport ahead of it. Nothing here
/// depends on how long anything takes.
async fn drain_to_barrier<T: Transport>(transport: &mut T, nonce: u64) -> Vec<String> {
    transport
        .send_control(ControlMessage::Ping(Ping { nonce }))
        .await
        .expect("send ping");
    let mut seen = Vec::new();
    loop {
        let frame = next_frame(transport).await;
        if let IncomingFrame::Control(ControlMessage::Pong(pong)) = &frame {
            assert_eq!(pong.nonce, nonce, "the barrier's own pong");
            return seen;
        }
        seen.push(label(&frame));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn snapshot_order_holds_when_the_credit_window_is_closed() {
    let fixture = Fixture::acquire().await;
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        SeedSnapshot,
        PermissiveAuth,
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::new().with_initial_credits(0),
    );

    let (server_end, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_end));

    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "order-client")
                .with_grant(connetto_core::messages::Grant::new("user:order-client")),
        ))
        .await
        .expect("send handshake");
    let IncomingFrame::Control(ControlMessage::HandshakeAck(ack)) = next_frame(&mut client).await
    else {
        panic!("expected a handshake ack");
    };
    assert_eq!(ack.initial_credits, 0, "the window starts closed");

    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::new(QUERY),
        }))
        .await
        .expect("send subscribe");

    // What the shut window let out, then what one credit released. The
    // completion frame belongs in the second group: it is queued behind the
    // rows it completes, and only their departure frees it.
    let withheld = drain_to_barrier(&mut client, 1).await;
    assert_eq!(
        withheld,
        vec!["SnapshotBegin"],
        "with no credits the rows cannot leave, so nothing that describes them may either"
    );

    client
        .send_control(ControlMessage::AckCredits(AckCredits { credits: 1 }))
        .await
        .expect("send ack credits");
    let released = drain_to_barrier(&mut client, 2).await;
    assert_eq!(
        released,
        vec!["SnapshotPatch", "SnapshotEnd"],
        "the completion frame must not overtake the rows it completes"
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}
