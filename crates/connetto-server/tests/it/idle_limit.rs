//! The server-side half of the keepalive contract.
//!
//! A session whose client never sends a frame is dropped at the idle limit,
//! and a client that probes stays connected indefinitely, so a live link is
//! never cut and a dead one is not held.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{BindValue, ControlMessage, Grant, Handshake, Ping};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION, Principal};
use connetto_server::{
    ManagerBuilder, Materializer, NoConnector, PageSpec, SessionConfig, SessionError,
    SnapshotEstimate, SnapshotPage, SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoDefaults, Fixture, RosterAuth, WITHHELD_ID};

const SUBJECT: &str = "reader";
const PG_DDL: &str = "CREATE TABLE items (id INT PRIMARY KEY, label TEXT);";

/// An empty snapshot source: the session registration gate reads nothing.
#[derive(Default)]
struct EmptySnapshot;

impl SnapshotSource for EmptySnapshot {
    type Error = std::convert::Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[BindValue],
        _caller: &Principal,
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
        _binds: &[BindValue],
        _caller: &Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        Ok(SnapshotPage {
            patchset: Vec::new(),
            cursor: Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: 0,
            rows: 0,
            bytes: 0,
        })
    }
}

fn connect(
    fixture: &Fixture,
    session: SessionConfig,
) -> (
    impl Transport,
    tokio::task::JoinHandle<Result<(), SessionError>>,
) {
    let manager = ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .build()
            .expect("build materializer"),
        EmptySnapshot,
        RosterAuth::granting(SUBJECT).withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    )
    .with_session(session)
    .build();
    let (server_transport, client) = loopback();
    let handle = tokio::spawn(manager.clone().serve(server_transport));
    (client, handle)
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

async fn open_session(client: &mut impl Transport) {
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, SUBJECT).with_grant(Grant::new("user:reader")),
        ))
        .await
        .expect("send handshake");
    // The server opens every connection with a challenge the handshake
    // answers nothing with, then the ack.
    loop {
        let answer = next_control(client).await;
        if matches!(answer, ControlMessage::HandshakeAck { .. }) {
            break;
        }
        assert!(
            matches!(answer, ControlMessage::Challenge(_)),
            "expected the challenge before the handshake ack, got {answer:?}"
        );
    }
}

#[tokio::test]
async fn a_silent_session_is_closed_at_the_idle_limit() {
    let fixture = Fixture::acquire().await;
    let session = SessionConfig::default().with_idle_limit(Duration::from_millis(300));
    let (mut client, handle) = connect(&fixture, session);
    open_session(&mut client).await;

    // No inbound frame follows, so the idle limit closes the session and the
    // client reads the close.
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Ok(Some(_)) = client.recv().await {}
    })
    .await
    .expect("the session ends within the test bound");
    handle.await.expect("the serve task ran").expect("serve");
}

#[tokio::test]
async fn a_probing_session_survives_past_the_idle_limit() {
    let fixture = Fixture::acquire().await;
    let session = SessionConfig::default().with_idle_limit(Duration::from_millis(300));
    let (mut client, handle) = connect(&fixture, session);
    open_session(&mut client).await;

    // A probe every 100 ms across more than two limits resets the clock each
    // time, so the session stays open the whole time.
    for _ in 0..8 {
        client
            .send_control(ControlMessage::Ping(Ping { nonce: 1 }))
            .await
            .expect("send ping");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The final answer proves the session is still alive at the end.
    let answer = next_control(&mut client).await;
    assert!(
        matches!(answer, ControlMessage::Pong(_)),
        "expected a pong, got {answer:?}"
    );
    assert!(
        !handle.is_finished(),
        "the probing session was closed early"
    );
}
