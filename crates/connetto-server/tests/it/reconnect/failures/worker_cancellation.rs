use connetto_core::messages::FatalErrorReason;

use super::*;

struct PendingAuth {
    roster: RosterAuth,
    asked: Arc<Notify>,
    release: Arc<Notify>,
}

impl VisibilityPolicy for PendingAuth {
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
        if watchers.iter().any(|watcher| {
            watcher
                .identity()
                .is_some_and(|identity| identity.user_id == "gone")
        }) {
            self.asked.notify_one();
            tokio::time::timeout(WAIT * 2, self.release.notified())
                .await
                .expect("the pending policy call is canceled before its deadline");
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
async fn dropping_the_last_receiver_interrupts_a_pending_log_read() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(WAIT, async {
        let (manager, script, events, _source) =
            scripted_for(&fixture, SessionConfig::default(), &["gone", "fresh"]).await;
        arm(&script, &[], true, None);
        let (arrived, _release) = hold_page(&script);
        let mut gone = wave_client(&manager, &script, "gone", cursor_of(&events[0])).await;
        gone.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        gone.task.abort();
        assert!(
            gone.task
                .await
                .expect_err("the member was canceled")
                .is_cancelled()
        );
        let mut fresh = wave_client(&manager, &script, "fresh", cursor_of(&events[0])).await;
        fresh.subscribe(QUERY).await;
        expect_recovered_orders(&mut fresh.transport, &events).await;
        fresh.close().await;
    })
    .await
    .expect("a canceled log read cannot hold the next wave");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_a_recipient_interrupts_its_pending_permission_question() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(WAIT, async {
        let asked = Arc::new(Notify::new());
        let auth = PendingAuth {
            roster: RosterAuth::granting("gone").and("healthy"),
            asked: Arc::clone(&asked),
            release: Arc::new(Notify::new()),
        };
        let (manager, script, events, _source) =
            scripted_with_auth(&fixture, SessionConfig::default(), auth, PG_DDL).await;
        arm(&script, &[], true, None);
        let mut gone = wave_client(&manager, &script, "gone", cursor_of(&events[0])).await;
        gone.subscribe("SELECT * FROM orders WHERE quantity = 2")
            .await;
        asked.notified().await;
        let mut healthy = wave_client(&manager, &script, "healthy", cursor_of(&events[0])).await;
        healthy
            .subscribe("SELECT * FROM orders WHERE quantity = 3")
            .await;
        gone.task.abort();
        assert!(
            gone.task
                .await
                .expect_err("the member was canceled")
                .is_cancelled()
        );
        expect_patches(&mut healthy.transport, &events[2..]).await;
        healthy.close().await;
    })
    .await
    .expect("a canceled permission call cannot hold the next wave");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_interrupts_a_pending_catchup_read_and_sends_its_fatal_frame() {
    let fixture = acquire_fixture().await;
    tokio::time::timeout(WAIT, async {
        let (manager, script, events, _source) =
            scripted_for(&fixture, SessionConfig::default(), &["closing"]).await;
        arm(&script, &[], true, None);
        let (arrived, _release) = hold_page(&script);
        let mut closing = wave_client(&manager, &script, "closing", cursor_of(&events[0])).await;
        closing.subscribe(QUERY).await;
        page_arrived(&arrived).await;
        assert_eq!(manager.shutdown().await, 1);
        let ControlMessage::FatalError(fatal) = next_control(&mut closing.transport).await else {
            panic!("shutdown sends a fatal frame");
        };
        assert_eq!(fatal.reason, FatalErrorReason::ServerShuttingDown);
        closing
            .task
            .await
            .expect("shutdown does not panic")
            .expect("shutdown closes the session");
    })
    .await
    .expect("shutdown cannot wait for the blocked log read");
}
