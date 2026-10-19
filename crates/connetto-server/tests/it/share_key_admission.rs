use parking_lot::Mutex;
use tokio::sync::Notify;

use super::*;

#[derive(Clone)]
struct HeldPage {
    inner: KeyedSnapshot,
    entered: Arc<Notify>,
    release: Arc<Notify>,
    paged: Arc<Mutex<bool>>,
}

impl HeldPage {
    fn new(paged: bool) -> Self {
        Self {
            inner: KeyedSnapshot::default(),
            entered: Arc::default(),
            release: Arc::default(),
            paged: Arc::new(Mutex::new(paged)),
        }
    }
}

impl SnapshotSource for HeldPage {
    type Error = std::convert::Infallible;

    async fn estimate(
        &self,
        sql: &str,
        binds: &[connetto_core::messages::BindValue],
        caller: &Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        self.inner.estimate(sql, binds, caller).await
    }

    async fn snapshot_page(
        &self,
        sql: &str,
        binds: &[connetto_core::messages::BindValue],
        caller: &Principal,
        page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        if keys_of(caller) == ["key:blocker"] {
            self.entered.notify_one();
            tokio::time::timeout(Duration::from_secs(10), self.release.notified())
                .await
                .expect("the blocking read is released");
        }
        let more = {
            let mut paged = self.paged.lock();
            if page.after.is_none() {
                std::mem::take(&mut *paged)
            } else {
                false
            }
        };
        let mut result = self.inner.snapshot_page(sql, binds, caller, page).await?;
        result.next = more.then(|| connetto_server::PageKey {
            values: vec![subql::backend::Value::Int(1)],
        });
        Ok(result)
    }
}

type Manager = Arc<SessionManager<HeldPage, RosterAuth, ConnettoDefaults>>;

fn manager(fixture: &Fixture, source: &HeldPage, credits: u32) -> Manager {
    let gate = connetto_server::ReaderReserve::new()
        .with_total(2)
        .with_reserved(1)
        .gate();
    ManagerBuilder::new(
        Materializer::builder(PG_DDL).build().expect("materializer"),
        source.clone(),
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL).expect("write target"),
    )
    .with_guard(Arc::new(
        RequestGuard::new(
            ThrottleConfig::default()
                .with_anonymous(TierLimits::anonymous().with_read_timeout(Duration::from_secs(30))),
            AbuseConfig::default(),
        )
        .with_reader_gate(gate),
    ))
    .with_session(SessionConfig::new().with_initial_credits(credits))
    .build()
}

async fn connect(manager: &Manager, key: &str) -> LoopbackTransport {
    let (server_end, mut client) = loopback();
    let server = Arc::clone(manager);
    tokio::spawn(async move { server.serve(server_end).await });
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "admission").with_grant(Grant::new(key)),
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
    client
}

async fn first_page(client: &mut LoopbackTransport) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = client
                .recv()
                .await
                .expect("snapshot frame")
                .expect("open connection");
            if let IncomingFrame::Bulk(BulkMessage::SnapshotPatch(_)) = frame {
                break;
            }
        }
    })
    .await
    .expect("the first page arrives");
}

async fn limited(client: &mut LoopbackTransport, id: &str) {
    let response = next_control(client).await;
    assert!(
        matches!(&response, ControlMessage::RateLimited(value) if value.related_to.as_deref() == Some(id)),
        "expected a correlated rate refusal, got {response:?}",
    );
}

async fn credits(client: &mut LoopbackTransport) {
    client
        .send_control(ControlMessage::AckCredits(AckCredits { credits: 4 }))
        .await
        .expect("grant delivery credits");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_reader_refuses_a_swap_and_preserves_its_old_keys() {
    let fixture = Fixture::acquire().await;
    let source = HeldPage::new(false);
    let manager = manager(&fixture, &source, 4);
    let mut victim = connect(&manager, "key:a").await;
    let mut blocker = connect(&manager, "key:blocker").await;
    subscribe(&mut victim, "items").await;
    controls_until(&mut victim, is_end).await;
    subscribe(&mut blocker, "occupied").await;
    tokio::time::timeout(Duration::from_secs(10), source.entered.notified())
        .await
        .expect("the blocker owns the anonymous slot");

    subscribe(&mut victim, "other").await;
    limited(&mut victim, "other").await;
    swap(&mut victim, "denied", &["key:b"]).await;
    limited(&mut victim, "denied").await;
    swap(&mut victim, "unchanged", &["key:a"]).await;
    assert_eq!(
        kinds(&controls_until(&mut victim, is_answer("unchanged")).await),
        ["answer"]
    );

    source.release.notify_one();
    controls_until(&mut blocker, is_end).await;
    swap(&mut victim, "admitted", &["key:b"]).await;
    let frames = controls_until(&mut victim, is_answer("admitted")).await;
    assert_eq!(kinds(&frames), ["resync", "begin", "end", "answer"]);
    assert_eq!(keys_of(&source.inner.last()), ["key:b"]);

    subscribe(&mut blocker, "occupied-again").await;
    tokio::time::timeout(Duration::from_secs(10), source.entered.notified())
        .await
        .expect("the returned slot is occupied again");
    swap(&mut victim, "expired-reservation", &["key:c"]).await;
    limited(&mut victim, "expired-reservation").await;
    source.release.notify_one();
    controls_until(&mut blocker, is_end).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_swap_reuses_its_paged_slot_until_replacement_delivery_finishes() {
    let fixture = Fixture::acquire().await;
    let source = HeldPage::new(true);
    let manager = manager(&fixture, &source, 1);
    let mut client = connect(&manager, "key:a").await;
    subscribe(&mut client, "items").await;
    first_page(&mut client).await;
    subscribe(&mut client, "other").await;
    limited(&mut client, "other").await;

    *source.paged.lock() = true;
    swap(&mut client, "reuse", &["key:b"]).await;
    let frames = controls_until(&mut client, is_answer("reuse")).await;
    assert_eq!(kinds(&frames), ["resync", "begin", "answer"]);
    subscribe(&mut client, "other").await;
    limited(&mut client, "other").await;

    credits(&mut client).await;
    controls_until(&mut client, is_end).await;
    subscribe(&mut client, "other").await;
    assert_eq!(
        kinds(&controls_until(&mut client, is_end).await),
        ["begin", "end"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_a_paged_read_releases_its_reader_slot() {
    let fixture = Fixture::acquire().await;
    let source = HeldPage::new(true);
    let manager = manager(&fixture, &source, 1);
    let mut client = connect(&manager, "key:a").await;
    subscribe(&mut client, "items").await;
    first_page(&mut client).await;
    client
        .send_control(ControlMessage::Unsubscribe(
            connetto_core::messages::Unsubscribe {
                sub_id: "items".to_owned(),
            },
        ))
        .await
        .expect("cancel the paged read");
    credits(&mut client).await;
    subscribe(&mut client, "other").await;
    assert_eq!(
        kinds(&controls_until(&mut client, is_end).await),
        ["begin", "end"]
    );
}
