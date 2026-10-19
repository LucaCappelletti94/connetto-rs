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

mod term_termination;
mod transport_lifetime;
mod worker_cancellation;

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

/// A session parked after enrollment leaves wave execution to the worker.
async fn parked_client(
    manager: &Arc<ScriptedManager>,
    script: &Arc<Mutex<Script>>,
    name: &str,
    resume: Cursor,
) -> WaveClient {
    let (transport, mut client) = loopback();
    let (enrolled, ready) = oneshot::channel();
    let server = Arc::clone(manager);
    let script = Arc::clone(script);
    let task = tokio::spawn(async move {
        let mut serving = std::pin::pin!(server.serve(transport));
        let mut enrolled = Some(enrolled);
        let mut parked = false;
        poll_fn(|cx| {
            if parked {
                return Poll::Pending;
            }
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
                parked = true;
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

/// Acquire the fixture under its own deadline, so a slow container start never burns the scenario budget.
async fn acquire_fixture() -> Fixture {
    tokio::time::timeout(Duration::from_secs(120), Fixture::acquire())
        .await
        .expect("fixture acquired before the setup deadline")
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

/// Refuses visibility questions naming `gone` while its lookup is unavailable.
struct SelectiveOutage {
    roster: RosterAuth,
    state: Arc<Mutex<AuthState>>,
}

impl VisibilityPolicy for SelectiveOutage {
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
            if state.down
                && watchers.iter().any(|watcher| {
                    watcher
                        .identity()
                        .is_some_and(|identity| identity.user_id == "gone")
                })
            {
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
                return Err(io::Error::other(
                    "authorization lookup unavailable for gone",
                ));
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
    let fixture = acquire_fixture().await;
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

    // A worker panic releases every session without unwinding its task.
    let first_result = tokio::time::timeout(WAIT, first.task)
        .await
        .expect("the failed walk released first before the deadline");
    let second_result = tokio::time::timeout(WAIT, second.task)
        .await
        .expect("the failed walk released second before the deadline");
    let waiting_result = tokio::time::timeout(WAIT, waiting.task)
        .await
        .expect("the failed walk released waiting before the deadline");
    for outcome in [first_result, second_result, waiting_result] {
        let result = outcome.expect("no session task panicked");
        assert!(
            matches!(result, Err(SessionError::CatchupFailed(_))),
            "the failed walk releases the session with CatchupFailed"
        );
    }
    for client in [
        &mut first.transport,
        &mut second.transport,
        &mut waiting.transport,
    ] {
        let closed = tokio::time::timeout(WAIT, client.recv()).await;
        assert!(matches!(closed, Ok(Ok(None))), "failed wave sent no patch");
    }
    let mut fresh = wave_client(&manager, &script, "fresh", cursor_of(&events[0])).await;
    fresh.subscribe(QUERY).await;
    let restarted = tokio::time::timeout(WAIT, async {
        expect_recovered_orders(&mut fresh.transport, &events).await;
    })
    .await;
    assert!(
        restarted.is_ok(),
        "a fresh resume walks the log after the panic"
    );
    expect_patches(&mut leader.transport, &events[1..]).await;
    leader.close().await;
    fresh.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handoff_recipient_cancellation_does_not_strand_future_resumes() {
    let fixture = acquire_fixture().await;
    let (manager, script, events, _source) = scripted_for(
        &fixture,
        SessionConfig::default(),
        &["leader", "handoff", "member", "fresh"],
    )
    .await;
    arm(&script, &[], true, None);
    let (arrived, release) = hold_page(&script);
    let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[0])).await;
    leader.subscribe(QUERY).await;
    page_arrived(&arrived).await;
    let mut handoff = parked_client(&manager, &script, "handoff", cursor_of(&events[0])).await;
    handoff.subscribe(QUERY).await;
    let mut member = wave_client(&manager, &script, "member", cursor_of(&events[0])).await;
    member.subscribe(QUERY).await;
    release.notify_one();
    expect_patches(&mut leader.transport, &events[1..]).await;
    leader
        .transport
        .send_control(ControlMessage::Ping(connetto_core::messages::Ping {
            nonce: 41,
        }))
        .await
        .expect("post-walk ping");
    let ControlMessage::Pong(pong) = next_control(&mut leader.transport).await else {
        panic!("post-walk pong");
    };
    assert_eq!(pong.nonce, 41);
    handoff.task.abort();
    let canceled = tokio::time::timeout(WAIT, handoff.task)
        .await
        .expect("the canceled task settled before the deadline");
    assert!(
        canceled.expect_err("handoff was canceled").is_cancelled(),
        "handoff ended by cancellation"
    );
    let member_caught_up = tokio::time::timeout(WAIT, async {
        expect_patches(&mut member.transport, &events[1..]).await;
    })
    .await;
    assert!(
        member_caught_up.is_ok(),
        "the surviving member lost its catch-up to the cancellation"
    );
    let mut fresh = wave_client(&manager, &script, "fresh", cursor_of(&events[0])).await;
    fresh.subscribe(QUERY).await;
    let fresh_caught_up = tokio::time::timeout(WAIT, async {
        expect_patches(&mut fresh.transport, &events[1..]).await;
    })
    .await;
    assert!(
        fresh_caught_up.is_ok(),
        "a fresh resume is stranded after the queued member was canceled"
    );
    leader.close().await;
    member.close().await;
    fresh.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncated_wave_leader_resnapshots_before_an_unrelated_lookup_recovers() {
    let fixture = acquire_fixture().await;
    let state = Arc::new(Mutex::new(AuthState::default()));
    let auth = SelectiveOutage {
        roster: RosterAuth::granting("leader").and("affected").and("gone"),
        state: Arc::clone(&state),
    };
    let ddl = format!("{PG_DDL} {}", PG_DDL.replace("orders", "archived_orders"));
    let (manager, script, events, mut source) =
        scripted_with_auth(&fixture, SessionConfig::default(), auth, &ddl).await;
    source
        .execute_sql("DELETE FROM orders WHERE id = 2")
        .expect("truncate marker");
    let marker = source
        .next_item()
        .await
        .expect("marker")
        .and_then(SourceItem::into_event)
        .expect("row event");
    let truncate = PgChangeEvent::new(
        ChangeEvent::truncate(vec![Arc::from("orders")], false, false, Lsn::new(1)),
        marker.checkpoint().expect("checkpoint"),
    );
    manager
        .dispatch_event(&truncate)
        .await
        .expect("dispatch truncate");
    let archive = drive(
        &mut source,
        &manager,
        "INSERT INTO archived_orders VALUES (1, 1.0, 3, 'later')",
    )
    .await;
    arm(&script, &[], true, None);
    let (arrived, release) = hold_page(&script);
    let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[0])).await;
    leader.subscribe(QUERY).await;
    page_arrived(&arrived).await;
    let mut affected = wave_client(&manager, &script, "affected", cursor_of(&events[0])).await;
    affected.subscribe(QUERY).await;
    let mut unrelated = wave_client(&manager, &script, "gone", cursor_of(&events[0])).await;
    unrelated.subscribe("SELECT * FROM archived_orders").await;
    let (wave_arrived, wave_release) = hold_page(&script);
    release.notify_one();
    page_arrived(&wave_arrived).await;
    state.lock().expect("auth state").down = true;
    wave_release.notify_one();
    expect_patches_before_truncate(&mut affected.transport, &events[1..]).await;
    let paused = tokio::time::timeout(WAIT, next_control(&mut unrelated.transport)).await;
    assert!(
        matches!(
            paused.expect("the unrelated member pauses before the deadline"),
            ControlMessage::DeliveryPaused {
                cause: PauseCause::AuthServiceUnreachable
            }
        ),
        "the unrelated member's outage pauses its delivery"
    );
    let resync = tokio::time::timeout(WAIT, next_control(&mut affected.transport)).await;
    let ControlMessage::FullResyncRequired(resync) =
        resync.expect("the resync is not held by the unrelated lookup")
    else {
        panic!("the truncated table demands a replacement");
    };
    assert_eq!(resync.sub_id, "orders");
    assert_eq!(
        resync.reason,
        FullResyncReason::TableTruncated {
            table: "orders".to_owned()
        }
    );
    let replacement = tokio::time::timeout(WAIT, async {
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
    })
    .await;
    assert!(
        replacement.is_ok(),
        "the resnapshot completes while the unrelated lookup stays down"
    );
    state.lock().expect("auth state").down = false;
    assert!(matches!(
        next_control(&mut unrelated.transport).await,
        ControlMessage::DeliveryResumed
    ));
    expect_patches(&mut unrelated.transport, &archive).await;
    leader.close().await;
    affected.close().await;
    unrelated.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canceled_record_recipient_does_not_hold_the_shared_walker() {
    let fixture = acquire_fixture().await;
    let state = Arc::new(Mutex::new(AuthState::default()));
    let auth = SelectiveOutage {
        roster: RosterAuth::granting("leader")
            .and("healthy")
            .and("gone")
            .and("fresh"),
        state: Arc::clone(&state),
    };
    let (manager, script, events, _source) =
        scripted_with_auth(&fixture, SessionConfig::default(), auth, PG_DDL).await;
    arm(&script, &[], true, None);
    let (arrived, release) = hold_page(&script);
    let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[0])).await;
    leader.subscribe(QUERY).await;
    page_arrived(&arrived).await;
    let mut healthy = wave_client(&manager, &script, "healthy", cursor_of(&events[0])).await;
    healthy
        .subscribe("SELECT * FROM orders WHERE quantity = 3")
        .await;
    let mut gone = wave_client(&manager, &script, "gone", cursor_of(&events[0])).await;
    gone.subscribe("SELECT * FROM orders WHERE quantity = 2")
        .await;
    let (wave_arrived, wave_release) = hold_page(&script);
    release.notify_one();
    page_arrived(&wave_arrived).await;
    expect_patches(&mut leader.transport, &events[1..]).await;
    state.lock().expect("auth state").down = true;
    wave_release.notify_one();
    let paused = tokio::time::timeout(WAIT, next_control(&mut gone.transport)).await;
    assert!(
        matches!(
            paused.expect("the outage pauses before the deadline"),
            ControlMessage::DeliveryPaused {
                cause: PauseCause::AuthServiceUnreachable
            }
        ),
        "the outage pauses the member whose lookup is down"
    );
    gone.task.abort();
    let canceled = tokio::time::timeout(WAIT, gone.task)
        .await
        .expect("the canceled task settled before the deadline");
    assert!(
        canceled.expect_err("gone was canceled").is_cancelled(),
        "gone ended by cancellation"
    );
    let caught_up = tokio::time::timeout(WAIT, async {
        expect_patches(&mut healthy.transport, &events[2..]).await;
    })
    .await;
    assert!(
        caught_up.is_ok(),
        "the healthy member is held by the outage of a caller it does not name"
    );
    let refused_before = state.lock().expect("auth state").refused.len();
    let mut fresh = wave_client(&manager, &script, "fresh", cursor_of(&events[0])).await;
    fresh.subscribe(QUERY).await;
    let fresh_caught_up = tokio::time::timeout(WAIT, async {
        expect_patches(&mut fresh.transport, &events[1..]).await;
    })
    .await;
    assert!(
        fresh_caught_up.is_ok(),
        "a fresh resume is held by the outage of a caller it does not name"
    );
    let queried_departed = state
        .lock()
        .expect("auth state")
        .refused
        .iter()
        .skip(refused_before)
        .any(|watchers| watchers.iter().any(|user| user == "gone"));
    assert!(
        !queried_departed,
        "a permission question still names the canceled caller"
    );
    leader.close().await;
    healthy.close().await;
    fresh.close().await;
}

async fn shared_record_cancellation(fixture: &Fixture, gone_first: bool) {
    let state = Arc::new(Mutex::new(AuthState::default()));
    let auth = SelectiveOutage {
        roster: RosterAuth::granting("leader").and("healthy").and("gone"),
        state: Arc::clone(&state),
    };
    let (manager, script, events, _source) =
        scripted_with_auth(fixture, SessionConfig::default(), auth, PG_DDL).await;
    arm(&script, &[], true, None);
    let (arrived, release) = hold_page(&script);
    let mut leader = wave_client(&manager, &script, "leader", cursor_of(&events[0])).await;
    leader.subscribe(QUERY).await;
    page_arrived(&arrived).await;
    let mut healthy = wave_client(&manager, &script, "healthy", cursor_of(&events[0])).await;
    let mut gone = wave_client(&manager, &script, "gone", cursor_of(&events[0])).await;
    if gone_first {
        gone.subscribe("SELECT * FROM orders WHERE quantity = 2")
            .await;
        healthy
            .subscribe("SELECT * FROM orders WHERE quantity > 1")
            .await;
    } else {
        healthy
            .subscribe("SELECT * FROM orders WHERE quantity > 1")
            .await;
        gone.subscribe("SELECT * FROM orders WHERE quantity = 2")
            .await;
    }
    let (wave_arrived, wave_release) = hold_page(&script);
    release.notify_one();
    page_arrived(&wave_arrived).await;
    expect_patches(&mut leader.transport, &events[1..]).await;
    state.lock().expect("auth state").down = true;
    wave_release.notify_one();
    let paused = tokio::time::timeout(WAIT, next_control(&mut gone.transport)).await;
    assert!(
        matches!(
            paused.expect("the shared record pauses before the deadline"),
            ControlMessage::DeliveryPaused {
                cause: PauseCause::AuthServiceUnreachable
            }
        ),
        "the outage pauses the member whose lookup is down"
    );
    assert!(matches!(
        tokio::time::timeout(WAIT, next_control(&mut healthy.transport))
            .await
            .expect("the healthy member pauses before the deadline"),
        ControlMessage::DeliveryPaused {
            cause: PauseCause::AuthServiceUnreachable
        }
    ));
    gone.task.abort();
    let canceled = tokio::time::timeout(WAIT, gone.task)
        .await
        .expect("the canceled task settled before the deadline");
    assert!(
        canceled.expect_err("gone was canceled").is_cancelled(),
        "gone ended by cancellation"
    );
    let refused_before = state.lock().expect("auth state").refused.len();
    tokio::time::timeout(WAIT, async {
        assert!(matches!(
            next_control(&mut healthy.transport).await,
            ControlMessage::DeliveryResumed
        ));
        expect_recovered_orders(&mut healthy.transport, &events).await;
    })
    .await
    .expect("the healthy member receives the shared record after cancellation");
    let queried_departed = state
        .lock()
        .expect("auth state")
        .refused
        .iter()
        .skip(refused_before)
        .any(|watchers| watchers.iter().any(|user| user == "gone"));
    assert!(
        !queried_departed,
        "a permission question still names the canceled caller"
    );
    leader.close().await;
    healthy.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_canceled_member_is_dropped_from_the_permission_question_of_a_shared_record() {
    let fixture = acquire_fixture().await;
    for gone_first in [false, true] {
        tokio::time::timeout(WAIT, shared_record_cancellation(&fixture, gone_first))
            .await
            .expect("canceled and surviving principal slots stay aligned");
    }
}
