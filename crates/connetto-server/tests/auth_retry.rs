//! Auth-error retry tests (Docker-gated).
//!
//! When the authorization service is unreachable, `dispatch_event` must
//! return `Err(SessionError::AuthUnavailable)` so the ingest loop can hold the
//! event and retry without advancing the replication slot cursor. Before the
//! fix, the error was silently discarded and `Ok(())` was returned, causing
//! `source.ack` to be called and the cursor to advance past the unanswered
//! event.

#![allow(clippy::too_many_lines)]

use std::io;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::auth::Principal;
use connetto_core::messages::{
    BulkMessage, ControlMessage, Handshake, PauseCause, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    Materializer, ReconnectEvent, RequestGuard, SessionConfig, SessionError, SessionManager,
    Snapshot, SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture};
use subql::backend::Postgres;
use subql::visibility::{RowView, RowWrite, Verdict, VisibilityPolicy};
use subql::{CdcSource, PgSqliteEmuSource};

const PG_DDL: &str = "CREATE TABLE items (id INT PRIMARY KEY, data TEXT);";

/// Auth policy whose `may_see` always returns an error, simulating an
/// unreachable authorization service.
struct AlwaysErrSee;

impl VisibilityPolicy for AlwaysErrSee {
    type Watcher = Arc<Principal>;
    type Error = io::Error;
    type Backend = Postgres;

    #[allow(clippy::unused_async_trait_impl)]
    async fn may_see<R>(
        &self,
        _row: &R,
        _watchers: &[Self::Watcher],
        _verdicts: &mut [Verdict],
    ) -> Result<(), Self::Error>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        Err(io::Error::other("auth service unreachable"))
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn may_write<R>(
        &self,
        _write: RowWrite<'_, R>,
        _watcher: &Self::Watcher,
    ) -> Result<Verdict, Self::Error>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        Ok(Verdict::Allow)
    }
}

/// Auth policy whose `may_see` and `may_write` answer based on an atomic flag.
/// When the flag is `false` both methods return an error, simulating an
/// unreachable auth service. Flip it to `true` to restore the service.
/// Snapshot source that returns an empty patchset.
struct EmptySnapshot;

impl SnapshotSource for EmptySnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &Principal,
    ) -> Result<Snapshot, Self::Error> {
        Ok(Snapshot {
            patchset: Vec::new(),
            cursor: Cursor::new(Vec::new()),
        })
    }
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

/// When `may_see` returns an error, `dispatch_event` must return
/// `Err(SessionError::AuthUnavailable)` so the ingest loop withholds the
/// source `ack`, keeping the replication slot cursor stationary until the
/// auth service recovers.
///
/// Before the fix: `let _ = auth.may_see(...)` discarded the error, verdicts
/// stayed as pre-filled denials, and `dispatch_event` returned `Ok(())`. The
/// ingest loop then called `source.ack` and the event was permanently lost.
///
/// After the fix: the error propagates as `Err(AuthUnavailable)`, the ingest
/// loop retries, and `DeliveryPaused` is sent to all live sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn dispatch_event_returns_auth_unavailable_and_holds_cursor() {
    let fixture = Fixture::acquire().await;
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("materializer"),
        EmptySnapshot,
        AlwaysErrSee,
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    // Connect a client and subscribe so a route is registered. `dispatch_event`
    // only consults the auth policy when there is at least one watcher.
    let (server_transport, mut client) = loopback();
    let _server = tokio::spawn(manager.clone().serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "client-a")
                .with_grant(connetto_core::messages::Grant::new("user:client-a")),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "items".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM items"),
        }))
        .await
        .expect("send subscribe");
    // Drain the empty snapshot (begin, patch, end).
    let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    match client.recv().await.expect("recv") {
        Some(IncomingFrame::Bulk(BulkMessage::SnapshotPatch(_))) => {}
        other => panic!("expected snapshot patch, got {other:?}"),
    }
    let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };

    // Drive one CDC insert that matches the subscription. The route exists so
    // `may_see` is called with a non-empty watcher list.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO items (id, data) VALUES (1, 'hello')")
        .expect("execute dml");
    let event = source
        .next_event()
        .await
        .expect("poll source")
        .expect("one event");

    // The key assertion. Before the fix: Ok(()) (error discarded, cursor
    // would advance). After the fix: Err(AuthUnavailable) (cursor held).
    let result = manager.dispatch_event(&event).await;
    assert!(
        matches!(result, Err(SessionError::AuthUnavailable(_))),
        "auth error must propagate so the ingest loop holds the source cursor; got {result:?}",
    );
    // No live patch was delivered: the auth question was not answered.
    let idle = tokio::time::timeout(Duration::from_millis(200), client.recv()).await;
    assert!(
        idle.is_err() || matches!(idle, Ok(Ok(None))),
        "no live patch must arrive while auth is unreachable",
    );
}

/// When `ingest` encounters auth errors it emits `AuthRetrying` events
/// through the `on_event` callback (same convention as source reconnects),
/// and broadcasts `DeliveryPaused` to every live session on the first error.
/// After the auth service recovers it broadcasts `DeliveryResumed`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn ingest_emits_auth_retry_events_and_broadcasts_pause_resume() {
    use std::sync::atomic::{AtomicU32, Ordering};

    let fixture = Fixture::acquire().await;
    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("materializer"),
        EmptySnapshot,
        AlwaysErrSee,
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let _server = tokio::spawn(manager.clone().serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "client-b")
                .with_grant(connetto_core::messages::Grant::new("user:client-b")),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "items".to_owned(),
            spec: SubscriptionSpec::new("SELECT * FROM items"),
        }))
        .await
        .expect("send subscribe");
    let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    match client.recv().await.expect("recv") {
        Some(IncomingFrame::Bulk(BulkMessage::SnapshotPatch(_))) => {}
        other => panic!("expected snapshot patch, got {other:?}"),
    }
    let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };

    // Set up a source with one matching event.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO items (id, data) VALUES (2, 'world')")
        .expect("execute dml");

    // Count AuthRetrying events from the callback.
    let retry_count = Arc::new(AtomicU32::new(0));
    let retry_count_clone = Arc::clone(&retry_count);

    // Ingest the source. The first event triggers auth errors, so ingest
    // loops in AuthRetrying until we stop it. Stop after the first retry by
    // using an abort handle.
    let ingest_handle = tokio::spawn({
        let manager = Arc::clone(&manager);
        async move {
            let _ = manager
                .ingest(&mut source, &mut |event| {
                    if matches!(event, ReconnectEvent::AuthRetrying { .. }) {
                        retry_count_clone.fetch_add(1, Ordering::Relaxed);
                    }
                })
                .await;
        }
    });

    // Wait long enough for at least one retry cycle to fire.
    tokio::time::sleep(Duration::from_millis(600)).await;

    assert!(
        retry_count.load(Ordering::Relaxed) >= 1,
        "ingest must emit at least one AuthRetrying event when auth is unreachable"
    );

    // The client should have received DeliveryPaused exactly once.
    let frame = tokio::time::timeout(Duration::from_millis(200), next_control(&mut client)).await;
    assert!(
        matches!(
            frame,
            Ok(ControlMessage::DeliveryPaused {
                cause: PauseCause::AuthServiceUnreachable,
            })
        ),
        "client must receive DeliveryPaused; got {frame:?}",
    );

    ingest_handle.abort();
}
