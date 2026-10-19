//! Connection termination while replay waits for its cursor lock.

use std::future::Future;
use std::io;

use connetto_core::loopback;
use connetto_core::test_support::TestGrantChecker;
use connetto_core::transport::LoopbackTransport;
use connetto_test_harness::{Fixture, RosterAuth};
use subql::visibility::{RowView, RowWrite};
use subql::{PgSqliteEmuSource, SourceItem};

use super::*;
use crate::defaults::ConnettoDefaults;
use crate::{ManagerBuilder, PgSnapshotSource, pg_write_target};

const WAIT: Duration = Duration::from_secs(15);
const DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, quantity INT);";

#[derive(Default)]
struct PermissionGate {
    armed: AtomicBool,
    arrived: Notify,
    release: Notify,
}

struct GatedAuthorization {
    roster: RosterAuth,
    gate: Arc<PermissionGate>,
}

impl VisibilityPolicy for GatedAuthorization {
    type Watcher = Arc<Principal>;
    type Error = io::Error;
    type Backend = Postgres;

    async fn may_see<R>(
        &self,
        row: &R,
        watchers: &[Self::Watcher],
        verdicts: &mut [Verdict],
    ) -> Result<(), Self::Error>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        if self.gate.armed.swap(false, Ordering::AcqRel) {
            self.gate.arrived.notify_one();
            tokio::time::timeout(WAIT, self.gate.release.notified())
                .await
                .expect("the permission question is released before its deadline");
        }
        self.roster
            .may_see(row, watchers, verdicts)
            .await
            .map_err(|never| match never {})
    }

    async fn may_write<R>(
        &self,
        write: RowWrite<'_, R>,
        watcher: &Self::Watcher,
    ) -> Result<Verdict, Self::Error>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        self.roster
            .may_write(write, watcher)
            .await
            .map_err(|never| match never {})
    }
}

struct ReceiveProgress {
    calls: AtomicUsize,
    cursor_wait: Notify,
}

impl Default for ReceiveProgress {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(usize::MAX),
            cursor_wait: Notify::new(),
        }
    }
}

struct ObservedTransport {
    inner: LoopbackTransport,
    progress: Arc<ReceiveProgress>,
}

impl Transport for ObservedTransport {
    type Error = <LoopbackTransport as Transport>::Error;

    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        self.inner.send_control(message).await
    }

    async fn send_bulk(&mut self, message: BulkMessage) -> Result<(), Self::Error> {
        self.inner.send_bulk(message).await
    }

    fn recv(&mut self) -> impl Future<Output = Result<Option<IncomingFrame>, Self::Error>> {
        if self.progress.calls.load(Ordering::Acquire) != usize::MAX
            && self.progress.calls.fetch_add(1, Ordering::AcqRel) == 1
        {
            self.progress.cursor_wait.notify_one();
        }
        async {
            let frame = self.inner.recv().await?;
            if matches!(
                frame,
                Some(IncomingFrame::Control(ControlMessage::Subscribe(_)))
            ) {
                self.progress.calls.store(0, Ordering::Release);
            }
            Ok(frame)
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.inner.close().await
    }
}

async fn control(client: &mut LoopbackTransport) -> ControlMessage {
    match tokio::time::timeout(WAIT, client.recv())
        .await
        .expect("the control frame arrives before its deadline")
        .expect("receive control frame")
    {
        Some(IncomingFrame::Control(message)) => message,
        other => panic!("expected a control frame, got {other:?}"),
    }
}

async fn handshake(client: &mut LoopbackTransport, cursor: Cursor) {
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "cursor-lock")
                .with_grant(connetto_core::messages::Grant::new("user:gone"))
                .with_cursor(cursor),
        ))
        .await
        .expect("handshake");
    assert!(matches!(
        control(client).await,
        ControlMessage::Challenge(_)
    ));
    assert!(matches!(
        control(client).await,
        ControlMessage::HandshakeAck(_)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_interrupts_a_replay_waiting_for_the_cursor_lock() {
    let fixture = tokio::time::timeout(Duration::from_secs(120), Fixture::acquire())
        .await
        .expect("the fixture starts before its deadline");
    tokio::time::timeout(Duration::from_secs(90), async {
        let gate = Arc::new(PermissionGate::default());
        let manager = ManagerBuilder::new(
            Materializer::builder(DDL).build().expect("materializer"),
            PgSnapshotSource::from_ddl(fixture.admin().clone(), DDL).expect("snapshot source"),
            GatedAuthorization {
                roster: RosterAuth::granting("gone"),
                gate: Arc::clone(&gate),
            },
            Arc::new(TestGrantChecker),
            NoConnector,
            pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), DDL)
                .expect("write target"),
        )
        .build();
        let mut source = PgSqliteEmuSource::open_in_memory(DDL).expect("emulated source");
        source
            .execute_sql("INSERT INTO orders VALUES (1, 1), (2, 2), (3, 3)")
            .expect("seed orders");
        let mut from = None;
        while let Some(item) = source.next_item().await.expect("source event") {
            if let SourceItem::Event(event) = item {
                from.get_or_insert(event.position());
                manager
                    .dispatch_event(&event)
                    .await
                    .expect("dispatch event");
            }
        }
        let (server, mut client) = loopback();
        let progress = Arc::new(ReceiveProgress::default());
        let transport = ObservedTransport {
            inner: server,
            progress: Arc::clone(&progress),
        };
        let serving = Arc::clone(&manager);
        let task = tokio::spawn(async move { serving.serve(transport).await });
        handshake(
            &mut client,
            Cursor::new(manager.stamp(from.expect("seed position"))),
        )
        .await;
        gate.armed.store(true, Ordering::Release);
        client
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: "orders".to_owned(),
                spec: SubscriptionSpec::new("SELECT * FROM orders WHERE quantity > 0"),
            }))
            .await
            .expect("subscribe");
        tokio::time::timeout(WAIT, gate.arrived.notified())
            .await
            .expect("the worker reached the permission question");
        let materializer = tokio::time::timeout(WAIT, manager.materializer.lock())
            .await
            .expect("the cursor lock is acquired before its deadline");
        gate.release.notify_one();
        tokio::time::timeout(WAIT, progress.cursor_wait.notified())
            .await
            .expect("the session started its cursor-lock wait");
        assert!(
            manager
                .close_session(
                    SessionId::from_token_hash("user:gone"),
                    FatalErrorReason::SessionRevoked
                )
                .await
        );
        let terminal = control(&mut client).await;
        drop(materializer);
        let ControlMessage::FatalError(fatal) = terminal else {
            panic!("the revocation precedes any replayed row");
        };
        assert_eq!(fatal.reason, FatalErrorReason::SessionRevoked);
        let trailing = tokio::time::timeout(WAIT, client.recv())
            .await
            .expect("the revoked session closes before its deadline")
            .expect("read terminal closure");
        assert!(
            trailing.is_none(),
            "revocation must be the last frame {trailing:?}"
        );
        tokio::time::timeout(WAIT, task)
            .await
            .expect("the session finishes before its deadline")
            .expect("the session task did not panic")
            .expect("the revoked session ends cleanly");
    })
    .await
    .expect("cursor-lock revocation completes before its deadline");
}
