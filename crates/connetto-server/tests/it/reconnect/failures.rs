use std::future::{Future, poll_fn};
use std::io;
use std::sync::Mutex;
use std::task::Poll;

use connetto_core::Principal;
use connetto_core::messages::PauseCause;
use connetto_server::SessionError;
use pg_walstream::{ChangeEvent, Lsn};
use subql::visibility::{RowView, RowWrite, Verdict};
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinHandle;

use super::*;

const WAIT: Duration = Duration::from_secs(15);

type SessionTask = JoinHandle<Result<(), SessionError>>;

struct WaveClient {
    transport: LoopbackTransport,
    enrolled: oneshot::Receiver<()>,
    task: SessionTask,
}

impl WaveClient {
    async fn subscribe(&mut self, query: &str) {
        self.transport
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: "orders".to_owned(),
                spec: SubscriptionSpec::new(query),
            }))
            .await
            .expect("send subscription");
        tokio::time::timeout(WAIT, &mut self.enrolled)
            .await
            .expect("resume enrolled before deadline")
            .expect("session reached catch-up");
    }

    async fn close(mut self) {
        self.transport.close().await.expect("close client");
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("session stopped before deadline")
            .expect("session did not panic")
            .expect("session closed cleanly");
    }
}

async fn wave_client<A>(
    manager: &Arc<ScriptedManager<A>>,
    script: &Arc<Mutex<Script>>,
    name: &str,
    resume: Cursor,
) -> WaveClient
where
    A: VisibilityPolicy<Watcher = Arc<Principal>, Backend = Postgres> + Send + Sync + 'static,
    A::Error: core::fmt::Display + connetto_server::FailedAuthorization,
{
    let (transport, mut client) = loopback();
    let (enrolled, ready) = oneshot::channel();
    let server = Arc::clone(manager);
    let script = Arc::clone(script);
    let task = tokio::spawn(async move {
        let mut serving = std::pin::pin!(server.serve(transport));
        let mut enrolled = Some(enrolled);
        poll_fn(|cx| {
            let outcome = serving.as_mut().poll(cx);
            let position_reads = script
                .lock()
                .expect("script")
                .current_reads
                .get(&tokio::task::id())
                .copied()
                .unwrap_or_default();
            // No await separates the third position read from enrollment.
            if position_reads >= 3
                && let Some(enrolled) = enrolled.take()
            {
                assert!(matches!(outcome, Poll::Pending), "resume is still active");
                let _ = enrolled.send(());
            }
            outcome
        })
        .await
    });
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, name)
                .with_grant(connetto_core::messages::Grant::new(format!("user:{name}")))
                .with_cursor(resume),
        ))
        .await
        .expect("send handshake");
    assert!(matches!(
        next_control(&mut client).await,
        ControlMessage::Challenge(_)
    ));
    assert!(matches!(
        next_control(&mut client).await,
        ControlMessage::HandshakeAck(_)
    ));
    WaveClient {
        transport: client,
        enrolled: ready,
        task,
    }
}

fn hold_page(script: &Mutex<Script>) -> (Arc<Notify>, Arc<Notify>) {
    let arrived = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let previous = script
        .lock()
        .expect("script")
        .hold
        .replace((Arc::clone(&arrived), Arc::clone(&release)));
    assert!(previous.is_none(), "each held page has its own release");
    (arrived, release)
}

async fn page_arrived(arrived: &Notify) {
    tokio::time::timeout(WAIT, arrived.notified())
        .await
        .expect("held page arrived before deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_wave_truncate_replaces_only_the_affected_table() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let fixture = Fixture::acquire().await;
        let ddl = format!("{PG_DDL} {}", PG_DDL.replace("orders", "archived_orders"));
        let (manager, script, mut events, mut source) = scripted_with_auth(
            &fixture,
            SessionConfig::default(),
            RosterAuth::granting("leader")
                .and("affected")
                .and("unaffected"),
            &ddl,
        )
        .await;
        events.extend(
            drive(
                &mut source,
                &manager,
                "INSERT INTO archived_orders VALUES (1, 2.0, 7, 'archived')",
            )
            .await,
        );
        source
            .execute_sql("DELETE FROM orders WHERE id = 2")
            .expect("delete marker row");
        let marker = source
            .next_item()
            .await
            .expect("read marker")
            .and_then(SourceItem::into_event)
            .expect("marker event");
        let truncate = PgChangeEvent::new(
            ChangeEvent::truncate(vec![Arc::from("orders")], false, false, Lsn::new(1)),
            marker.checkpoint().expect("truncate position"),
        );
        manager
            .dispatch_event(&truncate)
            .await
            .expect("record truncate");
        events.extend(
            drive(
                &mut source,
                &manager,
                "INSERT INTO archived_orders VALUES (2, 3.0, 8, 'later')",
            )
            .await,
        );
        arm(&script, &[], true, None);
        let (arrived, release) = hold_page(&script);
        let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[0])).await;
        leader.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        let mut affected = wave_client(&manager, &script, "affected", cursor_of(&events[0])).await;
        affected.subscribe(QUERY).await;
        let mut unaffected =
            wave_client(&manager, &script, "unaffected", cursor_of(&events[0])).await;
        unaffected
            .subscribe("SELECT * FROM archived_orders WHERE quantity > 0")
            .await;
        release.notify_one();

        expect_patches_before_truncate(&mut affected.transport, &events[1..3]).await;
        let ControlMessage::FullResyncRequired(resync) =
            next_control(&mut affected.transport).await
        else {
            panic!("truncate requires a replacement");
        };
        assert_eq!(resync.sub_id, "orders");
        assert_eq!(
            resync.reason,
            FullResyncReason::TableTruncated {
                table: "orders".to_owned()
            }
        );
        assert!(matches!(
            next_control(&mut affected.transport).await,
            ControlMessage::SnapshotBegin(_)
        ));
        assert!(matches!(
            next_bulk(&mut affected.transport).await,
            BulkMessage::SnapshotPatch(_)
        ));
        assert!(matches!(
            next_control(&mut affected.transport).await,
            ControlMessage::SnapshotEnd(_)
        ));
        expect_idle(&mut affected.transport).await;
        expect_patches(&mut unaffected.transport, &events[3..]).await;
        leader.close().await;
        affected.close().await;
        unaffected.close().await;
    })
    .await
    .expect("truncate isolation completed before deadline");
}

async fn expect_patches_before_truncate(
    client: &mut LoopbackTransport,
    expected: &[PgChangeEvent],
) {
    for event in expected {
        let BulkMessage::LivePatch(patch) = next_bulk(client).await else {
            panic!("expected a patch before the truncate");
        };
        assert_eq!(patch.cursor, cursor_of(event));
    }
}

async fn expect_recovered_orders(client: &mut LoopbackTransport, events: &[PgChangeEvent]) {
    let applier = Materializer::builder(PG_DDL)
        .build()
        .expect("build applier");
    let mut replica = client_replica();
    let prefix = applier.encode_patch(&events[0]).expect("encode held row");
    applier
        .apply_diffset(&prefix, &mut replica)
        .expect("apply held row");
    for event in &events[1..] {
        let BulkMessage::LivePatch(patch) = next_bulk(client).await else {
            panic!("expected a recovered order");
        };
        assert_eq!(patch.sub_id, "orders");
        assert_eq!(patch.cursor, cursor_of(event));
        applier
            .apply_diffset(&patch.patchset_zstd, &mut replica)
            .expect("apply recovered order");
    }
    assert_eq!(
        orders(&mut replica),
        vec![
            order(1, 1.0, 1, "row"),
            order(2, 1.0, 2, "row"),
            order(3, 1.0, 3, "row"),
        ]
    );
    expect_idle(client).await;
}

#[derive(Default)]
struct AuthState {
    down: bool,
    refused: Vec<Vec<String>>,
}

struct OutageAuth {
    roster: RosterAuth,
    state: Arc<Mutex<AuthState>>,
}

impl VisibilityPolicy for OutageAuth {
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
        {
            let mut state = self.state.lock().expect("auth state");
            if state.down {
                state.refused.push(
                    watchers
                        .iter()
                        .map(|watcher| {
                            watcher
                                .identity()
                                .expect("identified watcher")
                                .user_id
                                .clone()
                        })
                        .collect(),
                );
                return Err(io::Error::other("authorization service unreachable"));
            }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_wave_auth_outage_pauses_every_match_then_replays_in_order() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let fixture = Fixture::acquire().await;
        let state = Arc::new(Mutex::new(AuthState::default()));
        let auth = OutageAuth {
            roster: RosterAuth::granting("leader")
                .and("first")
                .and("second")
                .and("unmatched"),
            state: Arc::clone(&state),
        };
        let (manager, script, events, _source) =
            scripted_with_auth(&fixture, SessionConfig::default(), auth, PG_DDL).await;
        arm(&script, &[], true, None);
        let (arrived, release) = hold_page(&script);
        let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[0])).await;
        leader.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        let mut first = wave_client(&manager, &script, "first", cursor_of(&events[0])).await;
        first.subscribe(QUERY).await;
        let mut second = wave_client(&manager, &script, "second", cursor_of(&events[0])).await;
        second.subscribe(QUERY).await;
        let mut unmatched =
            wave_client(&manager, &script, "unmatched", cursor_of(&events[0])).await;
        unmatched
            .subscribe("SELECT * FROM orders WHERE quantity > 100")
            .await;
        let (wave_arrived, wave_release) = hold_page(&script);
        release.notify_one();
        page_arrived(&wave_arrived).await;
        expect_patches(&mut leader.transport, &events[1..]).await;
        state.lock().expect("auth state").down = true;
        wave_release.notify_one();
        for client in [&mut first, &mut second] {
            assert!(matches!(
                next_control(&mut client.transport).await,
                ControlMessage::DeliveryPaused {
                    cause: PauseCause::AuthServiceUnreachable
                }
            ));
            expect_idle(&mut client.transport).await;
        }
        expect_idle(&mut unmatched.transport).await;
        {
            let mut state = state.lock().expect("auth state");
            assert!(
                !state.refused.is_empty(),
                "visibility was refused during the wave"
            );
            for watchers in &state.refused {
                let mut watchers = watchers.clone();
                watchers.sort();
                assert_eq!(watchers, ["first", "second"]);
            }
            state.down = false;
        }
        for client in [&mut first, &mut second] {
            assert!(matches!(
                next_control(&mut client.transport).await,
                ControlMessage::DeliveryResumed
            ));
            expect_recovered_orders(&mut client.transport, &events).await;
        }
        expect_idle(&mut unmatched.transport).await;
        leader.close().await;
        first.close().await;
        second.close().await;
        unmatched.close().await;
    })
    .await
    .expect("authorization recovery completed before deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_wave_panic_releases_members_and_waiters_then_restarts() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let fixture = Fixture::acquire().await;
        let (manager, script, events, _source) = scripted_for(
            &fixture,
            SessionConfig::default(),
            &["leader", "first", "second", "waiting", "fresh"],
        )
        .await;
        arm(&script, &[], true, None);
        let (arrived, release) = hold_page(&script);
        let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[0])).await;
        leader.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        let mut first = wave_client(&manager, &script, "first", cursor_of(&events[0])).await;
        first.subscribe(QUERY).await;
        let mut second = wave_client(&manager, &script, "second", cursor_of(&events[0])).await;
        second.subscribe(QUERY).await;
        let (wave_arrived, wave_release) = hold_page(&script);
        release.notify_one();
        page_arrived(&wave_arrived).await;
        let mut waiting = wave_client(&manager, &script, "waiting", cursor_of(&events[0])).await;
        waiting.subscribe(QUERY).await;
        script.lock().expect("script").panic_next_page = true;
        wave_release.notify_one();

        let first_result = tokio::time::timeout(WAIT, first.task)
            .await
            .expect("leader released");
        let second_result = tokio::time::timeout(WAIT, second.task)
            .await
            .expect("member released");
        let panics = [&first_result, &second_result]
            .into_iter()
            .filter(|outcome| {
                outcome
                    .as_ref()
                    .err()
                    .is_some_and(tokio::task::JoinError::is_panic)
            })
            .count();
        assert_eq!(panics, 1, "only the wave leader panicked");
        for outcome in [first_result, second_result] {
            match outcome {
                Err(err) => assert!(err.is_panic()),
                Ok(result) => assert!(matches!(result, Err(SessionError::CatchupFailed(_)))),
            }
        }
        let result = tokio::time::timeout(WAIT, waiting.task)
            .await
            .expect("waiter released")
            .expect("waiter did not panic");
        assert!(matches!(result, Err(SessionError::CatchupFailed(_))));
        for client in [
            &mut first.transport,
            &mut second.transport,
            &mut waiting.transport,
        ] {
            assert!(
                client.recv().await.expect("closed transport").is_none(),
                "failed wave sent no patch"
            );
        }
        let mut fresh = wave_client(&manager, &script, "fresh", cursor_of(&events[0])).await;
        fresh.subscribe(QUERY).await;
        expect_recovered_orders(&mut fresh.transport, &events).await;
        expect_patches(&mut leader.transport, &events[1..]).await;
        leader.close().await;
        fresh.close().await;
    })
    .await
    .expect("panic recovery completed before deadline");
}
