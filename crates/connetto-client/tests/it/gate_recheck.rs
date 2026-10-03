//! R94 step 5: the platform-neutral away/return re-check.
//!
//! The client keeps at most one pending away moment, measures the time away as
//! the larger of a sleep-counting monotonic and a wall delta, and re-asks the
//! mechanism on a return that exceeds the grace. The tests inject a
//! deterministic clock and mechanism, so the re-check is proven without a real
//! prompt and without a real sleep.

use connetto_client::{
    ClientBuilder, ClientError, ClientEvent, Clock, ConnettoClient, DataDir, Gate, GateAskFuture,
    GateAskOutcome, GateMechanism, Moment,
};
use connetto_core::messages::{
    AggregateUpdate, BulkMessage, ControlMessage, GateState, HandshakeAck, LivePatch,
};
use connetto_core::traits::{IncomingFrame, Transport};
use diesel::prelude::*;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use std::collections::VecDeque;
use std::future::ready;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::oneshot;

const DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

diesel::table! {
    /// Synced test table.
    items (id) {
        /// Item identifier, the primary key
        id -> Integer,
        /// Optional item label
        label -> Nullable<Text>,
    }
}

/// A transport handing out a scripted sequence of frames, then going quiet
/// without closing, so the pump idles on the frame wait.
#[derive(Clone, Default)]
struct Script {
    frames: Arc<Mutex<VecDeque<IncomingFrame>>>,
    hung_up: Arc<std::sync::atomic::AtomicBool>,
    subscribed: Arc<Mutex<Vec<String>>>,
}

impl Script {
    fn with(frames: Vec<IncomingFrame>) -> Self {
        Self {
            frames: Arc::new(Mutex::new(frames.into())),
            hung_up: Arc::default(),
            subscribed: Arc::default(),
        }
    }

    /// The wire id of the last subscription the client declared.
    fn last_subscribed(&self) -> String {
        self.subscribed
            .lock()
            .expect("script lock")
            .last()
            .cloned()
            .expect("the client subscribed")
    }

    /// End the connection once the queued frames are delivered.
    fn hang_up(&self) {
        self.hung_up.store(true, Ordering::Relaxed);
    }

    /// Push a frame onto the queue for the pump to receive.
    fn say(&self, frame: IncomingFrame) {
        self.frames.lock().expect("script lock").push_back(frame);
    }
}

impl Transport for Script {
    type Error = std::convert::Infallible;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        if let ControlMessage::Subscribe(subscribe) = message {
            self.subscribed
                .lock()
                .expect("script lock")
                .push(subscribe.sub_id);
        }
        ready(Ok(()))
    }

    fn send_bulk(
        &mut self,
        _message: BulkMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }

    fn recv(&mut self) -> impl Future<Output = Result<Option<IncomingFrame>, Self::Error>> {
        let frames = Arc::clone(&self.frames);
        let hung_up = Arc::clone(&self.hung_up);
        async move {
            loop {
                if let Some(frame) = frames.lock().expect("script lock").pop_front() {
                    return Ok(Some(frame));
                }
                if hung_up.load(Ordering::Relaxed) {
                    return Ok(None);
                }
                tokio::task::yield_now().await;
            }
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }
}

fn ack() -> IncomingFrame {
    IncomingFrame::Control(ControlMessage::HandshakeAck(HandshakeAck {
        connection_id: "script".to_owned(),
        session_token: "script".to_owned(),
        resume_token: "script".to_owned(),
        current_cursor: connetto_core::Cursor::from(Vec::new()),
        schema_version: None,
        initial_credits: 64,
        last_applied_seq: None,
    }))
}

/// A manually advanced clock, whose monotonic and wall readings the test sets,
/// then reads moments from it.
#[derive(Clone)]
struct FakeClock {
    state: Arc<Mutex<(Duration, Duration)>>,
}

impl FakeClock {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new((Duration::ZERO, Duration::ZERO))),
        }
    }

    /// Set the monotonic and wall readings.
    fn set(&self, monotonic: Duration, wall: Duration) {
        *self.state.lock().expect("clock lock") = (monotonic, wall);
    }
}

impl Clock for FakeClock {
    fn monotonic(&self) -> Duration {
        self.state.lock().expect("clock lock").0
    }

    fn wall(&self) -> Duration {
        self.state.lock().expect("clock lock").1
    }
}

/// A gate mechanism that records its calls and resolves its prompt from a
/// oneshot the test drives.
#[derive(Clone)]
struct FakeMechanism {
    state: Arc<FakeMechanismState>,
}

struct FakeMechanismState {
    locks: AtomicUsize,
    asks: AtomicUsize,
    /// Whether the platform already verified the user this launch.
    open: std::sync::atomic::AtomicBool,
    senders: Mutex<Vec<oneshot::Sender<GateAskOutcome>>>,
}

impl FakeMechanism {
    fn new() -> Self {
        Self {
            state: Arc::new(FakeMechanismState {
                locks: AtomicUsize::new(0),
                asks: AtomicUsize::new(0),
                open: std::sync::atomic::AtomicBool::new(false),
                senders: Mutex::new(Vec::new()),
            }),
        }
    }

    /// How many times the mechanism was locked.
    fn locks(&self) -> usize {
        self.state.locks.load(Ordering::Relaxed)
    }

    /// How many times the mechanism was asked.
    fn asks(&self) -> usize {
        self.state.asks.load(Ordering::Relaxed)
    }

    /// Resolve the pending prompt with the given outcome.
    fn resolve(&self, outcome: GateAskOutcome) {
        let mut senders = self.state.senders.lock().expect("senders lock");
        if let Some(sender) = senders.pop() {
            sender.send(outcome).expect("the pump holds the prompt");
        }
    }
}

impl GateMechanism for FakeMechanism {
    fn lock(&self) {
        self.state.locks.fetch_add(1, Ordering::Relaxed);
        self.state.open.store(false, Ordering::Relaxed);
    }

    fn is_open(&self) -> bool {
        self.state.open.load(Ordering::Relaxed)
    }

    fn ask(&self) -> GateAskFuture {
        self.state.asks.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.state.senders.lock().expect("senders lock").push(tx);
        Box::pin(async move { rx.await.expect("the test resolves the prompt") })
    }
}

async fn client() -> (ConnettoClient<Script>, Script) {
    let dir = tempdir().expect("temp dir");
    let script = Script::with(vec![ack()]);
    let credential = super::support::held("tester");
    let key_store = super::support::key_store(&credential).await;
    let (running, pump) = ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::Once::new(script.clone()),
    )
    .signed_in(credential)
    .durable(DataDir::new(dir.path().to_path_buf()), key_store)
    .connect_with_pump()
    .await
    .expect("the builder connects");
    tokio::spawn(pump);
    (running.client().clone(), script)
}

/// Wait for the next `Locked`, `Unlocked` or `UnlockDismissed` event on the stream.
async fn next_gate_event(
    events: &mut tokio::sync::broadcast::Receiver<ClientEvent>,
) -> ClientEvent {
    loop {
        match events
            .recv()
            .await
            .expect("the pump keeps producing events")
        {
            ClientEvent::Locked => return ClientEvent::Locked,
            ClientEvent::Unlocked => return ClientEvent::Unlocked,
            ClientEvent::UnlockDismissed => return ClientEvent::UnlockDismissed,
            _ => {}
        }
    }
}

/// A gated launch starts locked, so the first access asks, and approving it
/// opens the gate.
async fn unlock_gate(
    client: &ConnettoClient<Script>,
    events: &mut tokio::sync::broadcast::Receiver<ClientEvent>,
    mechanism: &FakeMechanism,
) {
    client.unlock().await;
    assert_eq!(
        next_gate_event(events).await,
        ClientEvent::Locked,
        "the gated launch starts locked"
    );
    mechanism.resolve(GateAskOutcome::Approved);
    assert_eq!(
        next_gate_event(events).await,
        ClientEvent::Unlocked,
        "approval opens the gate"
    );
}

/// Without a gate the away/return inputs are ignored and nothing is refused.
#[tokio::test]
async fn away_and_back_without_a_gate_are_ignored() {
    let (client, _script) = client().await;
    let clock = FakeClock::new();

    // With no mechanism the inputs are ignored, and access is never refused.
    client.away(Moment::now(&clock)).await;
    client.back(Moment::now(&clock)).await;
    assert!(
        client
            .with_conn(|conn| conn.local_tables().contains("items"))
            .await
            .is_ok(),
        "no gate means no refusal"
    );
}

/// A gated, open client keeps the away moment when a grace is set, and a
/// return within the grace does not lock.
#[tokio::test]
async fn a_return_within_the_grace_does_not_lock() {
    let (client, _script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();

    client
        .enable_gate(Some(Duration::from_secs(60)), Arc::new(mechanism.clone()))
        .await;
    unlock_gate(&client, &mut events, &mechanism).await;

    // Go away, then return well within the one-minute grace, and nothing re-checks.
    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(10), Duration::from_secs(10));
    client.back(Moment::now(&clock)).await;

    assert_eq!(mechanism.locks(), 1, "only the launch locked");
    assert!(
        client
            .with_conn(|conn| conn.local_tables().contains("items"))
            .await
            .is_ok(),
        "a return within the grace does not refuse access"
    );
}

/// A return beyond the grace locks the mechanism, emits `Locked`, and refuses
/// the application's access.
#[tokio::test]
async fn a_return_beyond_the_grace_locks_and_refuses() {
    let (client, _script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();

    client
        .enable_gate(Some(Duration::from_secs(60)), Arc::new(mechanism.clone()))
        .await;
    unlock_gate(&client, &mut events, &mechanism).await;

    // Go away, then return beyond the one-minute grace, and the re-check fires.
    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(70), Duration::from_secs(70));
    client.back(Moment::now(&clock)).await;

    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Locked,
        "the re-check locks the gate"
    );
    assert_eq!(mechanism.locks(), 2, "the re-check locked the mechanism");
    assert!(
        matches!(client.with_conn(|_| ()).await, Err(ClientError::Locked)),
        "reads are refused while locked"
    );
    assert!(
        matches!(
            client.pin("pin", "SELECT id FROM items").await,
            Err(ClientError::Locked)
        ),
        "pins are refused while locked"
    );
    assert!(
        matches!(client.unpin("pin").await, Err(ClientError::Locked)),
        "unpins are refused while locked"
    );
    assert!(
        matches!(
            client.watch::<_, i32>(items::table.select(items::id)).await,
            Err(ClientError::Locked)
        ),
        "watches are refused while locked"
    );
    assert!(
        matches!(
            client.watch_value::<_, i64>(items::table.count()).await,
            Err(ClientError::Locked)
        ),
        "value watches are refused while locked"
    );
    assert!(
        matches!(
            client
                .watch_groups::<_, Option<String>, i64>(
                    items::table
                        .group_by(items::label)
                        .select((items::label, diesel::dsl::count_star())),
                )
                .await,
            Err(ClientError::Locked)
        ),
        "group watches are refused while locked"
    );
    assert!(
        matches!(
            client
                .watch_rows::<_, (i32,)>(items::table.select((items::id,)))
                .await,
            Err(ClientError::Locked)
        ),
        "row watches are refused while locked"
    );
    assert!(
        matches!(client.unsynced().await, Err(ClientError::Locked)),
        "the unsynced list is refused while locked"
    );
}

/// A zero grace re-checks on every return, however brief.
#[tokio::test]
async fn a_zero_grace_rechecks_on_every_return() {
    let (client, _script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();

    client
        .enable_gate(Some(Duration::ZERO), Arc::new(mechanism.clone()))
        .await;
    unlock_gate(&client, &mut events, &mechanism).await;

    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_millis(5), Duration::from_millis(5));
    client.back(Moment::now(&clock)).await;

    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Locked,
        "a zero grace re-checks on every return"
    );
}

/// Approving the re-check's prompt unlocks the gate and resumes access.
#[tokio::test]
async fn approving_the_recheck_unlocks_and_resumes() {
    let (client, _script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();

    client
        .enable_gate(Some(Duration::from_secs(60)), Arc::new(mechanism.clone()))
        .await;
    unlock_gate(&client, &mut events, &mechanism).await;

    // A return beyond the grace locks, and approving the prompt resumes.
    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(70), Duration::from_secs(70));
    client.back(Moment::now(&clock)).await;
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Locked);
    mechanism.resolve(GateAskOutcome::Approved);
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Unlocked,
        "approval unlocks the gate"
    );
    assert!(
        client
            .with_conn(|conn| conn.local_tables().contains("items"))
            .await
            .is_ok(),
        "access resumes after approval"
    );
}

/// Dismissing the re-check's prompt keeps the gate locked, and the next return
/// or the application's unlock call asks again.
#[tokio::test]
async fn dismissing_the_recheck_stays_locked_and_reasks() {
    let (client, _script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();

    client
        .enable_gate(Some(Duration::from_secs(60)), Arc::new(mechanism.clone()))
        .await;
    unlock_gate(&client, &mut events, &mechanism).await;

    // A return beyond the grace locks, and dismissing stays locked.
    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(70), Duration::from_secs(70));
    client.back(Moment::now(&clock)).await;
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Locked);
    mechanism.resolve(GateAskOutcome::Dismissed);
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::UnlockDismissed,
        "the dismissal is reported so an application can offer a retry"
    );

    // Dismissed, so still locked with no prompt pending. The next unlock re-asks.
    assert!(
        matches!(client.with_conn(|_| ()).await, Err(ClientError::Locked)),
        "a dismissal keeps the gate locked"
    );
    client.unlock().await;
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Locked,
        "the next unlock asks again"
    );
    mechanism.resolve(GateAskOutcome::Approved);
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Unlocked);
}

/// A wall clock stepped back cannot shorten the time away below the monotonic
/// reading, so the re-check still fires.
#[tokio::test]
async fn a_wall_step_back_cannot_shorten_time_away() {
    let (client, _script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();

    client
        .enable_gate(Some(Duration::from_secs(60)), Arc::new(mechanism.clone()))
        .await;
    unlock_gate(&client, &mut events, &mechanism).await;

    // Go away while the monotonic advances 70 s and the wall steps back 30 s.
    // The time away is the larger delta (70 s), beyond the grace.
    let clock = FakeClock::new();
    clock.set(Duration::ZERO, Duration::from_secs(100));
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(70), Duration::from_secs(70));
    client.back(Moment::now(&clock)).await;

    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Locked,
        "the monotonic reading cannot be shortened by a wall step back"
    );
}

/// A simulated suspension, in which the monotonic clock is frozen (no timer runs) and
/// the wall advances, so the re-check fires on the wall delta.
#[tokio::test]
async fn a_suspension_with_a_frozen_monotonic_still_rechecks() {
    let (client, _script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();

    client
        .enable_gate(Some(Duration::from_secs(60)), Arc::new(mechanism.clone()))
        .await;
    unlock_gate(&client, &mut events, &mechanism).await;

    // The device suspends, so the monotonic clock is frozen and the wall advances.
    let clock = FakeClock::new();
    clock.set(Duration::ZERO, Duration::from_secs(100));
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::ZERO, Duration::from_secs(180));
    client.back(Moment::now(&clock)).await;

    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Locked,
        "a frozen monotonic still re-checks on the wall delta"
    );
}

/// A tab with no mechanism of its own takes the lock state its relay states,
/// and each change reaches the application once.
#[tokio::test]
async fn a_relayed_gate_state_locks_a_mechanismless_tab() {
    let (client, script) = client().await;
    let mut events = client.events();

    script.say(IncomingFrame::Control(ControlMessage::GateState(
        GateState::Locked,
    )));
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Locked,
        "the relayed lock emits Locked"
    );
    assert!(
        matches!(client.with_conn(|_| ()).await, Err(ClientError::Locked)),
        "the relayed lock refuses access"
    );
    script.say(IncomingFrame::Control(ControlMessage::GateState(
        GateState::Unlocked,
    )));
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Unlocked,
        "the relayed unlock emits Unlocked, with no second Locked before it"
    );
    assert!(
        client
            .with_conn(|conn| conn.local_tables().contains("items"))
            .await
            .is_ok(),
        "the relayed unlock resumes access"
    );
}

/// A row of the `items` table.
#[derive(Queryable, Selectable, Identifiable, Debug, PartialEq, Clone)]
#[diesel(table_name = items)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Item {
    id: i32,
    label: Option<String>,
}

/// Compressed insert-patchset bytes for the given `items` rows.
fn items_payload(rows: &[(i32, &str)]) -> Vec<u8> {
    let mut patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new();
    for &(id, label) in rows {
        let insert =
            Insert::<_, String, Vec<u8>>::from(SimpleTable::new("items", &["id", "label"], &[0]))
                .set(0, Value::Integer(i64::from(id)))
                .expect("set the id")
                .set(1, Value::Text(label.to_owned()))
                .expect("set the label");
        patchset = patchset.insert(insert);
    }
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress the payload")
}

/// Wait for the `LivePatch` event for `sub`.
async fn until_live_patch(events: &mut tokio::sync::broadcast::Receiver<ClientEvent>, sub: &str) {
    loop {
        match events
            .recv()
            .await
            .expect("the pump keeps producing events")
        {
            ClientEvent::LivePatch { sub_id, .. } if sub_id == sub => return,
            _ => {}
        }
    }
}

/// Without a grace the re-check runs once per launch, so a return, however
/// long after the away, never locks.
#[tokio::test]
async fn a_return_without_a_grace_never_locks() {
    let (client, _script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();

    client.enable_gate(None, Arc::new(mechanism.clone())).await;
    unlock_gate(&client, &mut events, &mechanism).await;

    // Go away, then return a whole hour later, and nothing re-checks without a grace.
    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(3600), Duration::from_secs(3600));
    client.back(Moment::now(&clock)).await;

    assert_eq!(mechanism.locks(), 1, "only the launch locked");
    assert!(
        client.with_conn(|_| ()).await.is_ok(),
        "a return without a grace never refuses access"
    );
}

/// Returning while locked, with no prompt pending, asks the mechanism again
/// instead of waiting on a prompt the dismissal already closed.
#[tokio::test]
async fn a_return_while_locked_without_a_prompt_asks_again() {
    let (client, _script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();

    client
        .enable_gate(Some(Duration::from_secs(60)), Arc::new(mechanism.clone()))
        .await;
    unlock_gate(&client, &mut events, &mechanism).await;

    // A return beyond the grace locks, and the dismissal keeps it locked.
    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(70), Duration::from_secs(70));
    client.back(Moment::now(&clock)).await;
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Locked);
    mechanism.resolve(GateAskOutcome::Dismissed);
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::UnlockDismissed
    );

    // Still locked with no prompt pending, so another return asks again.
    let asks_before = mechanism.asks();
    client.back(Moment::now(&clock)).await;
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Locked,
        "the return while locked asks again"
    );
    assert_eq!(
        mechanism.asks(),
        asks_before + 1,
        "the mechanism was asked again"
    );
    mechanism.resolve(GateAskOutcome::Approved);
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Unlocked);
}

/// A live handle whose table changed while locked keeps its old rows, wakes
/// exactly once with the new rows after the unlock, and no more.
#[tokio::test]
async fn a_locked_handle_keeps_old_rows_and_wakes_once_after_unlock() {
    let (client, script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();

    client
        .enable_gate(Some(Duration::from_secs(60)), Arc::new(mechanism.clone()))
        .await;
    unlock_gate(&client, &mut events, &mechanism).await;

    let mut query = client
        .watch::<_, Item>(items::table.order(items::id))
        .await
        .expect("watch the synced table");
    client
        .with_conn(|conn| {
            diesel::insert_into(items::table)
                .values(items::label.eq("first"))
                .execute(conn.conn())
                .expect("write the row")
        })
        .await
        .expect("the gate is open");
    tokio::time::timeout(Duration::from_secs(5), query.changed())
        .await
        .expect("the local write wakes the handle in time")
        .expect("the client is alive");
    assert_eq!(
        query.rows(),
        vec![Item {
            id: 1,
            label: Some("first".to_owned())
        }]
    );

    // Go away, return beyond the grace, and dismiss the re-check, so the gate
    // stays locked with no prompt pending.
    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(70), Duration::from_secs(70));
    client.back(Moment::now(&clock)).await;
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Locked);
    mechanism.resolve(GateAskOutcome::Dismissed);
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::UnlockDismissed
    );

    // A server row lands while the gate stays locked.
    script.say(IncomingFrame::Bulk(BulkMessage::LivePatch(LivePatch::new(
        query.sub_id().to_owned(),
        connetto_core::Cursor::from(vec![0, 0, 0, 0, 0, 0, 1, 0]),
        items_payload(&[(2, "second")]),
    ))));
    until_live_patch(&mut events, query.sub_id()).await;

    // While locked the application cannot read the replica, and the handle stays
    // on its old rows without waking.
    assert!(
        matches!(client.with_conn(|_| ()).await, Err(ClientError::Locked)),
        "reads are refused while locked"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(500), query.changed())
            .await
            .is_err(),
        "the held refresh does not wake the handle while locked"
    );

    // Return again while locked, and the re-ask, then the approval, wakes the
    // handle exactly once with both rows.
    client.back(Moment::now(&clock)).await;
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Locked);
    mechanism.resolve(GateAskOutcome::Approved);
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Unlocked);
    tokio::time::timeout(Duration::from_secs(5), query.changed())
        .await
        .expect("the unlock wakes the held refresh in time")
        .expect("the client is alive");
    assert_eq!(
        query.rows(),
        vec![
            Item {
                id: 1,
                label: Some("first".to_owned())
            },
            Item {
                id: 2,
                label: Some("second".to_owned())
            },
        ],
        "the row that landed while locked appears in one wake"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), query.changed())
            .await
            .is_err(),
        "the held refresh wakes once, not per row"
    );
}

/// A gated launch starts locked: `with_conn` and pins are refused with
/// `Locked` until the mechanism approves the launch's prompt.
#[tokio::test]
async fn a_gated_launch_refuses_with_conn_until_approval() {
    let (client, _script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();

    client
        .enable_gate(Some(Duration::from_secs(60)), Arc::new(mechanism.clone()))
        .await;

    // The launch is locked from the start, and it asks nothing until the
    // application asks the gate to unlock.
    assert!(
        matches!(client.with_conn(|_| ()).await, Err(ClientError::Locked)),
        "a gated launch refuses with_conn until approval"
    );
    assert!(
        matches!(
            client.pin("pin", "SELECT id FROM items").await,
            Err(ClientError::Locked)
        ),
        "a gated launch refuses pins until approval"
    );
    assert_eq!(mechanism.asks(), 0, "the launch prompt is not asked yet");

    // The application's unlock asks the mechanism, and approval opens the gate.
    client.unlock().await;
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Locked,
        "the unlock reports the launch lock"
    );
    mechanism.resolve(GateAskOutcome::Approved);
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Unlocked,
        "approval opens the gate"
    );
    assert!(
        client.with_conn(|_| ()).await.is_ok(),
        "after approval, access resumes"
    );
}

/// Build a gated client over `mechanism`, the connect running in its own task
/// so the test can answer the launch prompt it waits on.
fn gated_connect(
    mechanism: &FakeMechanism,
) -> tokio::task::JoinHandle<Result<(ConnettoClient<Script>, tempfile::TempDir), ClientError>> {
    let mechanism = mechanism.clone();
    tokio::spawn(async move {
        let dir = tempdir().expect("temp dir");
        let script = Script::with(vec![ack()]);
        let credential = super::support::held("tester");
        let key_store = super::support::key_store(&credential).await;
        let (running, pump) = ClientBuilder::new(
            super::support::bundle(DDL),
            super::support::Once::new(script),
        )
        .signed_in(credential)
        .durable(DataDir::new(dir.path().to_path_buf()), key_store)
        .with_gate(Gate::default().with_recheck(Some(Duration::from_secs(60))))
        .with_gate_mechanism(mechanism)
        .connect_with_pump()
        .await?;
        tokio::spawn(pump);
        Ok((running.client().clone(), dir))
    })
}

/// Wait until the mechanism was asked `count` times.
async fn until_asked(mechanism: &FakeMechanism, count: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while mechanism.asks() < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the mechanism is asked in time");
}

/// A gated durable build's connect waits on the launch prompt, so the client
/// it returns is open and nothing the application starts meets the lock, and
/// the gate then carries the build's grace: a return within it stays open, a
/// return beyond it locks.
#[tokio::test]
async fn a_built_gate_connects_after_the_launch_prompt_and_rechecks_beyond_its_grace() {
    let mechanism = FakeMechanism::new();
    let connecting = gated_connect(&mechanism);
    until_asked(&mechanism, 1).await;
    assert!(!connecting.is_finished(), "the connect waits on the prompt");
    mechanism.resolve(GateAskOutcome::Approved);
    let (client, _dir) = connecting
        .await
        .expect("the connect task")
        .expect("the approved build connects");
    let mut events = client.events();
    assert!(
        client.with_conn(|_| ()).await.is_ok(),
        "the client comes back open"
    );
    assert_eq!(
        mechanism.asks(),
        1,
        "the launch asked once, though the mechanism never reports itself open"
    );

    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(30), Duration::from_secs(30));
    client.back(Moment::now(&clock)).await;
    assert!(
        client.with_conn(|_| ()).await.is_ok(),
        "a return within the build's grace keeps the gate open"
    );

    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(100), Duration::from_secs(100));
    client.back(Moment::now(&clock)).await;
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Locked,
        "a return beyond the build's grace locks"
    );
}

/// A launch prompt the user dismisses fails the connect with the lock.
#[tokio::test]
async fn a_dismissed_launch_prompt_fails_the_connect() {
    let mechanism = FakeMechanism::new();
    let connecting = gated_connect(&mechanism);
    until_asked(&mechanism, 1).await;
    mechanism.resolve(GateAskOutcome::Dismissed);
    assert!(
        matches!(
            connecting.await.expect("the connect task"),
            Err(ClientError::Locked)
        ),
        "a dismissed launch refuses the client"
    );
}

/// A zero grace re-checks a return even when the clocks read no time away.
#[tokio::test]
async fn a_zero_grace_rechecks_a_return_that_measures_no_time_away() {
    let (client, _script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();
    client
        .enable_gate(Some(Duration::ZERO), Arc::new(mechanism.clone()))
        .await;
    unlock_gate(&client, &mut events, &mechanism).await;

    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    client.back(Moment::now(&clock)).await;
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Locked,
        "a zero grace re-checks a return of no measurable length"
    );
}

/// A locked gate refuses a pinned insert and a watched update before either
/// writes anything.
#[tokio::test]
async fn a_locked_gate_refuses_pinned_inserts_and_watched_updates_before_writing() {
    let (client, _script) = client().await;
    client
        .with_conn(|conn| {
            diesel::insert_into(items::table)
                .values((items::id.eq(1), items::label.eq("kept")))
                .execute(conn.conn())
                .expect("seed the row")
        })
        .await
        .expect("no gate yet");
    let mechanism = FakeMechanism::new();
    let mut events = client.events();
    client.enable_gate(None, Arc::new(mechanism.clone())).await;

    assert!(
        matches!(
            client
                .insert_pinned::<_, Item, i32>("pin", items::label.eq("new"))
                .await,
            Err(ClientError::Locked)
        ),
        "a pinned insert is refused while locked"
    );
    assert!(
        matches!(
            client
                .update_watched::<_, _, Item, i32>(items::table.find(1), items::label.eq("changed"))
                .await,
            Err(ClientError::Locked)
        ),
        "a watched update is refused while locked"
    );

    unlock_gate(&client, &mut events, &mechanism).await;
    let rows: Vec<Item> = client
        .with_conn(|conn| {
            items::table
                .order(items::id)
                .load(conn.conn())
                .expect("read the table")
        })
        .await
        .expect("the gate is open");
    assert_eq!(
        rows,
        vec![Item {
            id: 1,
            label: Some("kept".to_owned())
        }],
        "nothing was written while locked"
    );
}

/// A prompt pending when the connection drops survives the reconnect
/// attempts, so approving it afterwards still unlocks the gate.
#[tokio::test]
async fn a_prompt_pending_across_a_dropped_connection_still_unlocks() {
    let (client, script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();
    client.enable_gate(None, Arc::new(mechanism.clone())).await;
    client.unlock().await;
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Locked);
    assert_eq!(mechanism.asks(), 1, "the unlock asked the mechanism");

    script.hang_up();
    loop {
        if let ClientEvent::Reconnecting { .. } = events
            .recv()
            .await
            .expect("the pump keeps producing events")
        {
            break;
        }
    }
    mechanism.resolve(GateAskOutcome::Approved);
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::Unlocked,
        "the approval given while reconnecting unlocks"
    );
}

/// The scalar aggregate push a server sends.
fn scalar_push(sub_id: &str, value: &str) -> IncomingFrame {
    IncomingFrame::Control(ControlMessage::AggregateUpdate(AggregateUpdate {
        sub_id: sub_id.to_owned(),
        group_key: None,
        group_values_json: None,
        result_json: Some(value.to_owned()),
        is_full_result: true,
    }))
}

/// Wait for the aggregate push for `sub` to reach the event stream.
async fn until_aggregate(events: &mut tokio::sync::broadcast::Receiver<ClientEvent>, sub: &str) {
    loop {
        match events
            .recv()
            .await
            .expect("the pump keeps producing events")
        {
            ClientEvent::Aggregate { sub_id, .. } if sub_id == sub => return,
            _ => {}
        }
    }
}

/// A value handle whose aggregate moved while locked keeps its old value and
/// wakes with the new one only after the unlock.
#[tokio::test]
async fn a_locked_value_handle_keeps_its_value_until_the_unlock() {
    let (client, script) = client().await;
    let mechanism = FakeMechanism::new();
    let mut events = client.events();
    client
        .enable_gate(Some(Duration::from_secs(60)), Arc::new(mechanism.clone()))
        .await;
    unlock_gate(&client, &mut events, &mechanism).await;

    let mut count = client
        .watch_value::<_, i64>(items::table.count())
        .await
        .expect("watch the count");
    let wire = script.last_subscribed();
    script.say(scalar_push(&wire, "1"));
    tokio::time::timeout(Duration::from_secs(5), count.changed())
        .await
        .expect("the push wakes the handle in time")
        .expect("the client is alive");
    assert_eq!(count.value(), Some(1));

    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(70), Duration::from_secs(70));
    client.back(Moment::now(&clock)).await;
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Locked);
    mechanism.resolve(GateAskOutcome::Dismissed);
    assert_eq!(
        next_gate_event(&mut events).await,
        ClientEvent::UnlockDismissed
    );

    script.say(scalar_push(&wire, "2"));
    until_aggregate(&mut events, &wire).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), count.changed())
            .await
            .is_err(),
        "the held push does not wake the handle while locked"
    );
    assert_eq!(count.value(), Some(1), "the handle keeps its old value");

    client.back(Moment::now(&clock)).await;
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Locked);
    mechanism.resolve(GateAskOutcome::Approved);
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Unlocked);
    tokio::time::timeout(Duration::from_secs(5), count.changed())
        .await
        .expect("the unlock wakes the held push in time")
        .expect("the client is alive");
    assert_eq!(count.value(), Some(2));
}

/// A mechanism the platform already opened this launch, as a native keyring
/// whose secrets the sign-in read behind the user's verification, starts the
/// gate open and asks nothing more, and a return beyond the grace still locks.
#[tokio::test]
async fn a_mechanism_already_open_at_launch_starts_the_gate_open() {
    let dir = tempdir().expect("temp dir");
    let script = Script::with(vec![ack()]);
    let credential = super::support::held("tester");
    let key_store = super::support::key_store(&credential).await;
    let mechanism = FakeMechanism::new();
    mechanism.state.open.store(true, Ordering::Relaxed);
    let (running, pump) = ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::Once::new(script.clone()),
    )
    .signed_in(credential)
    .durable(DataDir::new(dir.path().to_path_buf()), key_store)
    .with_gate(Gate::default().with_recheck(Some(Duration::from_secs(60))))
    .with_gate_mechanism(mechanism.clone())
    .connect_with_pump()
    .await
    .expect("the gated build connects");
    tokio::spawn(pump);
    let client = running.client().clone();
    let mut events = client.events();
    assert_eq!(mechanism.asks(), 0, "an open launch asks nothing");
    assert!(
        client.with_conn(|_| ()).await.is_ok(),
        "an open launch refuses nothing"
    );

    let clock = FakeClock::new();
    client.away(Moment::now(&clock)).await;
    clock.set(Duration::from_secs(90), Duration::from_secs(90));
    client.back(Moment::now(&clock)).await;
    assert_eq!(next_gate_event(&mut events).await, ClientEvent::Locked);
    assert_eq!(mechanism.asks(), 1, "the re-check asks");
}
