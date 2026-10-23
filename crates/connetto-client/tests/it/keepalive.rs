//! The client keepalive against scripted servers over loopback pairs. A
//! silent upstream is noticed once the probe and answer bounds elapse and the
//! client recovers, a busy link is never probed, a handshake that draws no
//! answer is abandoned and redialed, and the probe still goes out while the
//! away gate is locked.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use connetto_client::{
    ClientBuilder, ClientEvent, ConnettoClient, DataDir, Gate, GateAskFuture, GateAskOutcome,
    GateMechanism, MemoryRefreshStore, Moment, ReconnectPolicy, SyncStatus, SyncTuning,
    SystemClock, TransportFactory,
};
use connetto_core::messages::{
    BulkMessage, ControlMessage, HandshakeAck, Pong, SnapshotBegin, SnapshotEnd, SnapshotPatch,
    SubscriptionPriority,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, LoopbackTransport, loopback};
use parking_lot::Mutex;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use tempfile::tempdir;
use tokio::sync::oneshot;

const DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, label TEXT);";

diesel::table! {
    /// The one synced table these builds read back.
    orders (id) {
        /// Primary key.
        id -> BigInt,
        /// Payload the snapshot carries.
        label -> Text,
    }
}

/// The probe bound: the silence after which a probe goes out.
const PROBE_AFTER: Duration = Duration::from_millis(150);
/// The answer bound: the time a probe (or a handshake) waits.
const ANSWER_WITHIN: Duration = Duration::from_millis(200);
/// The bound every wait in these tests runs under.
const BOUND: Duration = Duration::from_secs(5);

/// The ack every scripted server here answers the handshake with.
fn ack() -> ControlMessage {
    ControlMessage::HandshakeAck(HandshakeAck {
        connection_id: "keepalive".to_owned(),
        session_token: "keepalive".to_owned(),
        resume_token: "keepalive".to_owned(),
        current_cursor: Cursor::new(Vec::new()),
        schema_version: None,
        initial_credits: 64,
        writer: Some(connetto_core::messages::WriterGrant {
            number: 1,
            frontier: 0,
        }),
    })
}

/// Compressed one-row patchset bytes for the wire table shape.
fn payload() -> Vec<u8> {
    let insert =
        Insert::<_, String, Vec<u8>>::from(SimpleTable::new("orders", &["id", "label"], &[0]))
            .set(0, Value::Integer(1))
            .expect("set id")
            .set(1, Value::Text("seed".to_owned()))
            .expect("set label");
    let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new().insert(insert);
    zstd::encode_all(patchset.build().as_slice(), 3).expect("compress payload")
}

/// The test tuning: a probe shortly after the silence, a short answer bound.
fn tuning() -> SyncTuning {
    SyncTuning::default()
        .with_probe_after(PROBE_AFTER)
        .with_answer_within(ANSWER_WITHIN)
}

/// A dialer that opens a fresh scripted server on every attempt. While
/// `quiet` is set the server answers the handshake and the one snapshot and
/// then holds its silence, counting the probes it draws.
struct Scripted {
    quiet: Arc<AtomicBool>,
    pings: Arc<AtomicU32>,
}

impl TransportFactory for Scripted {
    type Transport = LoopbackTransport;
    type Error = std::convert::Infallible;

    fn connect(
        &mut self,
    ) -> impl Future<Output = Result<LoopbackTransport, std::convert::Infallible>> + Send {
        let quiet = Arc::clone(&self.quiet);
        let pings = Arc::clone(&self.pings);
        async move {
            let (mut server, client_end) = loopback();
            tokio::spawn(async move {
                let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) =
                    server.recv().await
                else {
                    return;
                };
                server.send_control(ack()).await.expect("ack the handshake");
                loop {
                    let Ok(Some(frame)) = server.recv().await else {
                        return;
                    };
                    match frame {
                        IncomingFrame::Control(ControlMessage::Ping(ping)) => {
                            pings.fetch_add(1, Ordering::Relaxed);
                            if !quiet.load(Ordering::Acquire) {
                                server
                                    .send_control(ControlMessage::Pong(Pong { nonce: ping.nonce }))
                                    .await
                                    .expect("pong the probe");
                            }
                        }
                        IncomingFrame::Control(ControlMessage::Subscribe(sub)) => {
                            server
                                .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                                    sub_id: sub.sub_id.clone(),
                                    priority: SubscriptionPriority::default(),
                                }))
                                .await
                                .expect("snapshot begin");
                            server
                                .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch {
                                    sub_id: sub.sub_id.clone(),
                                    patchset_zstd: payload(),
                                }))
                                .await
                                .expect("snapshot patch");
                            server
                                .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
                                    sub_id: sub.sub_id.clone(),
                                    cursor: Cursor::new(vec![1]),
                                }))
                                .await
                                .expect("snapshot end");
                        }
                        _ => {}
                    }
                }
            });
            Ok(client_end)
        }
    }
}

/// A pump over a scripted dialer, backoff and all, with the probe counter to
/// watch.
async fn running(quiet: Arc<AtomicBool>) -> (ConnettoClient<LoopbackTransport>, Arc<AtomicU32>) {
    let pings = Arc::new(AtomicU32::new(0));
    let dialer = Scripted {
        quiet,
        pings: Arc::clone(&pings),
    };
    let (running, pump) = ClientBuilder::new(super::support::bundle(DDL), dialer)
        .with_tuning(tuning())
        .with_reconnect(ReconnectPolicy::default())
        .with_sleeper(|d| tokio::time::sleep(d))
        .connect_with_pump()
        .await
        .expect("the first dial hands back a transport");
    tokio::spawn(pump);
    (running.client().clone(), pings)
}

/// Read events until `matches` accepts one or the bound runs out, panicking
/// on the bound.
async fn next_event(
    events: &mut tokio::sync::broadcast::Receiver<ClientEvent>,
    deadline: std::time::Instant,
    what: &str,
    matches: impl Fn(&ClientEvent) -> bool,
) -> ClientEvent {
    loop {
        tokio::select! {
            event = events.recv() => {
                let event = event.expect("the pump is running");
                if matches(&event) {
                    return event;
                }
            }
            () = tokio::time::sleep_until(deadline.into()) => {
                panic!("{what} within {BOUND:?}");
            }
        }
    }
}

/// A silent upstream is noticed once the probe and the answer bound elapse,
/// the client goes offline and reconnects, and the probe went out before the
/// drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_upstream_is_dropped_and_the_client_recovers() {
    let quiet = Arc::new(AtomicBool::new(true));
    let (client, pings) = running(Arc::clone(&quiet)).await;
    let mut events = client.events();
    let deadline = std::time::Instant::now() + BOUND;
    next_event(&mut events, deadline, "the connection never stood", |e| {
        matches!(e, ClientEvent::SyncStatus(SyncStatus::Connected))
    })
    .await;
    // The silence outlasts the probe and the answer bound, so the transport
    // is dropped and the client says so.
    next_event(
        &mut events,
        deadline,
        "the silent upstream was never noticed",
        |e| matches!(e, ClientEvent::SyncStatus(SyncStatus::Offline)),
    )
    .await;
    assert!(
        pings.load(Ordering::Acquire) >= 1,
        "the probe went out into the silence before the drop"
    );
    // The upstream wakes on the redial, and the client is connected again.
    quiet.store(false, Ordering::Release);
    next_event(
        &mut events,
        std::time::Instant::now() + BOUND,
        "the recovery never reconnected",
        |e| matches!(e, ClientEvent::SyncStatus(SyncStatus::Connected)),
    )
    .await;
}

/// Frames faster than the probe bound reset the clock, so a busy link never
/// draws a probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_link_is_never_probed() {
    let (mut server, client_end) = loopback();
    let pings = Arc::new(AtomicU32::new(0));
    let pings_task = Arc::clone(&pings);
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await
        else {
            return;
        };
        server.send_control(ack()).await.expect("ack the handshake");
        // An inbound frame every 50 ms, faster than the 150 ms probe bound,
        // alongside the subscription's one-row snapshot.
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    server
                        .send_control(ControlMessage::Pong(Pong { nonce: 0 }))
                        .await
                        .expect("the link stays busy");
                }
                frame = server.recv() => {
                    let Ok(Some(frame)) = frame else {
                        return;
                    };
                    match frame {
                        IncomingFrame::Control(ControlMessage::Ping(_)) => {
                            pings_task.fetch_add(1, Ordering::Relaxed);
                        }
                        IncomingFrame::Control(ControlMessage::Subscribe(sub)) => {
                            server
                                .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                                    sub_id: sub.sub_id.clone(),
                                    priority: SubscriptionPriority::default(),
                                }))
                                .await
                                .expect("snapshot begin");
                            server
                                .send_bulk(BulkMessage::SnapshotPatch(SnapshotPatch {
                                    sub_id: sub.sub_id.clone(),
                                    patchset_zstd: payload(),
                                }))
                                .await
                                .expect("snapshot patch");
                            server
                                .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
                                    sub_id: sub.sub_id.clone(),
                                    cursor: Cursor::new(vec![1]),
                                }))
                                .await
                                .expect("snapshot end");
                        }
                        _ => {}
                    }
                }
            }
        }
    });
    let (running, pump) = ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::Once::new(client_end),
    )
    .with_tuning(tuning())
    .with_reconnect(ReconnectPolicy::default())
    .with_sleeper(|d| tokio::time::sleep(d))
    .connect_with_pump()
    .await
    .expect("the one transport hands back");
    let client = running.client().clone();
    let mut events = client.events();
    tokio::spawn(pump);
    next_event(
        &mut events,
        std::time::Instant::now() + BOUND,
        "the connection never stood",
        |e| matches!(e, ClientEvent::SyncStatus(SyncStatus::Connected)),
    )
    .await;
    // Four probe bounds pass over the busy link.
    tokio::time::sleep(PROBE_AFTER * 4).await;
    assert_eq!(
        pings.load(Ordering::Acquire),
        0,
        "a busy link is never probed"
    );
}

/// A dialer that hands back a transport whose server reads the handshake and
/// answers nothing with.
struct Unanswered {
    dials: Arc<AtomicU32>,
}

impl TransportFactory for Unanswered {
    type Transport = LoopbackTransport;
    type Error = std::convert::Infallible;

    fn connect(
        &mut self,
    ) -> impl Future<Output = Result<LoopbackTransport, std::convert::Infallible>> + Send {
        self.dials.fetch_add(1, Ordering::Relaxed);
        async move {
            let (mut server, client_end) = loopback();
            tokio::spawn(async move {
                // The server reads the handshake and holds the link open in silence.
                let Ok(Some(_)) = server.recv().await else {
                    return;
                };
                let _held = server;
                core::future::pending::<()>().await;
            });
            Ok(client_end)
        }
    }
}

/// A handshake that draws no answer is abandoned after the answer bound and
/// redialed, which the reconnect attempts say.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handshake_without_an_ack_is_abandoned_and_redialed() {
    let dials = Arc::new(AtomicU32::new(0));
    let (running, pump) = ClientBuilder::new(
        super::support::bundle(DDL),
        Unanswered {
            dials: Arc::clone(&dials),
        },
    )
    .with_tuning(tuning())
    .with_reconnect(ReconnectPolicy::default())
    .with_sleeper(|d| tokio::time::sleep(d))
    .connect_with_pump()
    .await
    .expect("the first dial hands back a transport");
    let client = running.client().clone();
    let mut events = client.events();
    tokio::spawn(pump);
    // The second attempt says the first handshake was abandoned and redialed.
    next_event(
        &mut events,
        std::time::Instant::now() + BOUND,
        "the unanswered handshake was never redialed",
        |e| matches!(e, ClientEvent::Reconnecting { attempt } if *attempt >= 2),
    )
    .await;
    assert!(
        dials.load(Ordering::Acquire) >= 2,
        "the dialer drew a fresh transport for the redial"
    );
}

/// The probe still goes out while the away gate is locked and its prompt is
/// pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_probe_runs_while_the_gate_is_locked() {
    let pings = Arc::new(AtomicU32::new(0));
    let mechanism = LockedMechanism::new();
    let connecting = tokio::spawn({
        let pings = Arc::clone(&pings);
        let mechanism = mechanism.clone();
        async move {
            let dir = tempdir().expect("a temp dir");
            let credential = super::support::held("tester");
            let key_store = super::support::key_store(&credential).await;
            let (running, pump) = ClientBuilder::new(
                super::support::bundle(DDL),
                Scripted {
                    quiet: Arc::new(AtomicBool::new(true)),
                    pings,
                },
            )
            .with_tuning(tuning())
            .with_reconnect(ReconnectPolicy::default())
            .with_sleeper(|d| tokio::time::sleep(d))
            .signed_in(credential)
            .durable(
                DataDir::new(dir.path().to_path_buf()),
                key_store,
                MemoryRefreshStore::default(),
            )
            .with_gate(Gate::default().with_recheck(Some(Duration::ZERO)))
            .with_gate_mechanism(mechanism)
            .connect_with_pump()
            .await
            .expect("the approved build connects");
            tokio::spawn(pump);
            (running.client().clone(), dir)
        }
    });
    // The gated launch asks once before the build returns, and it is approved.
    mechanism.until_asked(1).await;
    mechanism.resolve(GateAskOutcome::Approved);
    let (client, _dir) = tokio::time::timeout(BOUND, connecting)
        .await
        .expect("the build returns once the launch prompt resolves")
        .expect("the connect task");
    let mut events = client.events();
    // A zero grace re-checks this return, so the gate locks and its prompt
    // stays pending while the silence runs out.
    client.away(Moment::now(&SystemClock)).await;
    client.back(Moment::now(&SystemClock)).await;
    next_event(
        &mut events,
        std::time::Instant::now() + BOUND,
        "the gate never said locked",
        |e| matches!(e, ClientEvent::Locked),
    )
    .await;
    mechanism.until_asked(2).await;
    let before = pings.load(Ordering::Acquire);
    tokio::time::sleep(PROBE_AFTER * 4).await;
    assert!(
        pings.load(Ordering::Acquire) > before,
        "the probe went out while the gate was locked and asking"
    );
    mechanism.resolve(GateAskOutcome::Approved);
}

/// A gate mechanism that stays locked and asks a prompt the test holds.
#[derive(Clone)]
struct LockedMechanism {
    open: Arc<AtomicBool>,
    asks: Arc<AtomicU32>,
    senders: Arc<Mutex<Vec<oneshot::Sender<GateAskOutcome>>>>,
}

impl LockedMechanism {
    fn new() -> Self {
        Self {
            open: Arc::new(AtomicBool::new(false)),
            asks: Arc::new(AtomicU32::new(0)),
            senders: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Wait until the mechanism was asked `count` times.
    async fn until_asked(&self, count: u32) {
        tokio::time::timeout(BOUND, async {
            while self.asks.load(Ordering::Acquire) < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the mechanism is asked in time");
    }

    /// Resolve the pending prompt with the given outcome.
    fn resolve(&self, outcome: GateAskOutcome) {
        let mut senders = self.senders.lock();
        if let Some(sender) = senders.pop() {
            sender.send(outcome).expect("the pump holds the prompt");
        }
    }
}

impl GateMechanism for LockedMechanism {
    fn lock(&self) {
        self.open.store(false, Ordering::Release);
    }

    fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    fn ask(&self) -> GateAskFuture {
        self.asks.fetch_add(1, Ordering::AcqRel);
        let (tx, rx) = oneshot::channel();
        self.senders.lock().push(tx);
        Box::pin(async move { rx.await.unwrap_or(GateAskOutcome::Dismissed) })
    }
}
