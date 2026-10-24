//! The client keepalive against scripted servers over loopback pairs. A
//! silent upstream is noticed once the probe and answer bounds elapse and the
//! client recovers, an answered probe keeps the link while a pong with
//! another nonce does not, a probe that cannot be sent drops the link, a
//! deadline fires only when due and current, a busy link is never probed, a
//! handshake that draws no answer is abandoned and redialed, the probe still
//! goes out while the away gate is locked, and pump steps without a frame
//! keep the one armed sleep.

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
/// then holds its silence, counting the probes it draws. Otherwise it answers
/// every probe with a pong whose nonce is the probe's plus `nonce_offset`.
struct Scripted {
    quiet: Arc<AtomicBool>,
    pings: Arc<AtomicU32>,
    nonce_offset: u64,
}

impl TransportFactory for Scripted {
    type Transport = LoopbackTransport;
    type Error = std::convert::Infallible;

    fn connect(
        &mut self,
    ) -> impl Future<Output = Result<LoopbackTransport, std::convert::Infallible>> + Send {
        let quiet = Arc::clone(&self.quiet);
        let pings = Arc::clone(&self.pings);
        let nonce_offset = self.nonce_offset;
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
                                    .send_control(ControlMessage::Pong(Pong {
                                        nonce: ping.nonce + nonce_offset,
                                    }))
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
    running_offset(quiet, 0).await
}

/// [`running`] over a server whose pongs carry the probe's nonce plus
/// `nonce_offset`.
async fn running_offset(
    quiet: Arc<AtomicBool>,
    nonce_offset: u64,
) -> (ConnettoClient<LoopbackTransport>, Arc<AtomicU32>) {
    let pings = Arc::new(AtomicU32::new(0));
    let dialer = Scripted {
        quiet,
        pings: Arc::clone(&pings),
        nonce_offset,
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

/// A probe answered by its own pong clears, so the link stays up across many
/// probe bounds and the next silence draws a fresh probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answered_probe_keeps_the_link_and_probes_again() {
    let (client, pings) = running(Arc::new(AtomicBool::new(false))).await;
    let mut events = client.events();
    next_event(
        &mut events,
        std::time::Instant::now() + BOUND,
        "the connection never stood",
        |e| matches!(e, ClientEvent::SyncStatus(SyncStatus::Connected)),
    )
    .await;
    // Six probe bounds, each probe answered well inside the answer bound.
    let watched = tokio::time::timeout(PROBE_AFTER * 6, async {
        loop {
            if let ClientEvent::SyncStatus(SyncStatus::Offline) =
                events.recv().await.expect("the pump is running")
            {
                return;
            }
        }
    })
    .await;
    assert!(watched.is_err(), "an answered probe never drops the link");
    assert!(
        pings.load(Ordering::Acquire) >= 2,
        "the pong returned the link to its silence clock, so it was probed again"
    );
}

/// A pong carrying another nonce restarts the answer bound but does not
/// answer the probe, so a server that only ever answers with the wrong nonce
/// is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pong_with_another_nonce_does_not_answer_the_probe() {
    let (client, pings) = running_offset(Arc::new(AtomicBool::new(false)), 1_000).await;
    let mut events = client.events();
    let deadline = std::time::Instant::now() + BOUND;
    next_event(&mut events, deadline, "the connection never stood", |e| {
        matches!(e, ClientEvent::SyncStatus(SyncStatus::Connected))
    })
    .await;
    next_event(
        &mut events,
        deadline,
        "a probe answered with another nonce was taken as answered",
        |e| matches!(e, ClientEvent::SyncStatus(SyncStatus::Offline)),
    )
    .await;
    assert!(
        pings.load(Ordering::Acquire) >= 1,
        "the probe went out and drew the stale pong before the drop"
    );
}

/// A server that acks, answers the first probe with its own nonce and every
/// later probe with that first nonce again, counting the probes.
fn replaying_server() -> (LoopbackTransport, Arc<AtomicU32>) {
    let (mut server, client_end) = loopback();
    let pings = Arc::new(AtomicU32::new(0));
    let counted = Arc::clone(&pings);
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await
        else {
            return;
        };
        server.send_control(ack()).await.expect("ack the handshake");
        let mut first = None;
        while let Ok(Some(frame)) = server.recv().await {
            if let IncomingFrame::Control(ControlMessage::Ping(ping)) = frame {
                counted.fetch_add(1, Ordering::Relaxed);
                let nonce = *first.get_or_insert(ping.nonce);
                if server
                    .send_control(ControlMessage::Pong(Pong { nonce }))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    });
    (client_end, pings)
}

/// Every probe carries a fresh nonce, so a late pong for an earlier probe
/// does not answer the current one, and a server that only replays its first
/// answer is dropped after the second probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_pong_for_an_earlier_probe_does_not_answer_the_next() {
    let (transport, pings) = replaying_server();
    let (running, pump) = ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::Once::new(transport),
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
    let deadline = std::time::Instant::now() + BOUND;
    next_event(&mut events, deadline, "the connection never stood", |e| {
        matches!(e, ClientEvent::SyncStatus(SyncStatus::Connected))
    })
    .await;
    // The one transport is spent, so the drop shows as the redial attempts.
    next_event(
        &mut events,
        deadline,
        "a replayed answer to an earlier probe was taken as answering the next",
        |e| matches!(e, ClientEvent::Reconnecting { .. }),
    )
    .await;
    assert_eq!(
        pings.load(Ordering::Acquire),
        2,
        "the first probe was answered and the second was not"
    );
}

/// A client end whose probe sends fail, as a link that died under the probe
/// would, and that forwards every other frame.
struct ProbeFails(LoopbackTransport);

impl Transport for ProbeFails {
    type Error = String;

    async fn send_control(&mut self, message: ControlMessage) -> Result<(), Self::Error> {
        if matches!(message, ControlMessage::Ping(_)) {
            return Err("the link died under the probe".to_owned());
        }
        self.0
            .send_control(message)
            .await
            .map_err(|e| e.to_string())
    }

    async fn send_bulk(&mut self, message: BulkMessage) -> Result<(), Self::Error> {
        self.0.send_bulk(message).await.map_err(|e| e.to_string())
    }

    async fn recv(&mut self) -> Result<Option<IncomingFrame>, Self::Error> {
        self.0.recv().await.map_err(|e| e.to_string())
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.0.close().await.map_err(|e| e.to_string())
    }
}

/// A dialer handing out [`ProbeFails`] ends over servers that ack and then
/// hold their silence.
struct ProbeFailing;

impl TransportFactory for ProbeFailing {
    type Transport = ProbeFails;
    type Error = std::convert::Infallible;

    fn connect(
        &mut self,
    ) -> impl Future<Output = Result<ProbeFails, std::convert::Infallible>> + Send {
        let (transport, _pings, nudge) = counting_server();
        // The server outlives the nudge sender, so dropping it keeps the link.
        drop(nudge);
        core::future::ready(Ok(ProbeFails(transport)))
    }
}

/// A probe that cannot be sent is the link dying, so the pump drops it and
/// goes back to dialing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_probe_that_cannot_be_sent_drops_the_link() {
    let (running, pump) = ClientBuilder::new(super::support::bundle(DDL), ProbeFailing)
        .with_tuning(tuning())
        .with_reconnect(ReconnectPolicy::default())
        .with_sleeper(|d| tokio::time::sleep(d))
        .connect_with_pump()
        .await
        .expect("the first dial hands back a transport");
    let client = running.client().clone();
    let mut events = client.events();
    tokio::spawn(pump);
    let deadline = std::time::Instant::now() + BOUND;
    next_event(&mut events, deadline, "the connection never stood", |e| {
        matches!(e, ClientEvent::SyncStatus(SyncStatus::Connected))
    })
    .await;
    next_event(
        &mut events,
        deadline,
        "the failed probe never dropped the link",
        |e| matches!(e, ClientEvent::SyncStatus(SyncStatus::Offline)),
    )
    .await;
    next_event(
        &mut events,
        deadline,
        "the dropped link was never redialed",
        |e| matches!(e, ClientEvent::Reconnecting { .. }),
    )
    .await;
}

/// A loopback server that acks the handshake, counts the probes it draws and
/// sends one frame other than a pong to a probe for every nudge.
fn counting_server() -> (
    LoopbackTransport,
    Arc<AtomicU32>,
    tokio::sync::mpsc::UnboundedSender<()>,
) {
    let (mut server, client_end) = loopback();
    let pings = Arc::new(AtomicU32::new(0));
    let counted = Arc::clone(&pings);
    let (nudge, mut nudges) = tokio::sync::mpsc::unbounded_channel::<()>();
    tokio::spawn(async move {
        let Ok(Some(IncomingFrame::Control(ControlMessage::Handshake(_)))) = server.recv().await
        else {
            return;
        };
        server.send_control(ack()).await.expect("ack the handshake");
        let mut nudging = true;
        loop {
            tokio::select! {
                frame = server.recv() => match frame {
                    Ok(Some(IncomingFrame::Control(ControlMessage::Ping(_)))) => {
                        counted.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Some(_)) => {}
                    _ => return,
                },
                request = nudges.recv(), if nudging => match request {
                    // Probe nonces start at one, so this pong answers none.
                    Some(()) => server
                        .send_control(ControlMessage::Pong(Pong { nonce: 0 }))
                        .await
                        .expect("send the nudge"),
                    None => nudging = false,
                },
            }
        }
    });
    (client_end, pings, nudge)
}

/// A deadline fires only when it is both due and current: one read before
/// the silence ran out sends nothing, one a frame re-armed sends nothing, the
/// current one sends the probe, and the answer bound then runs from the probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_keepalive_deadline_fires_only_when_due_and_current() {
    // Wide bounds, so a loaded machine cannot let one run out between steps.
    const PROBE: Duration = Duration::from_millis(600);
    const ANSWER: Duration = Duration::from_millis(600);
    let (transport, pings, nudge) = counting_server();
    let mut conn = ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::Once::new(transport),
    )
    .with_tuning(
        SyncTuning::default()
            .with_probe_after(PROBE)
            .with_answer_within(ANSWER),
    )
    .connect_driven()
    .await
    .expect("connect");
    // The build states Offline and then Connected before any frame.
    conn.pump_one().await.expect("the offline status");
    conn.pump_one().await.expect("the connected status");

    let early = conn
        .keepalive_timer()
        .expect("a standing link arms a deadline");
    conn.keepalive_fire(early)
        .await
        .expect("a deadline not yet due is a no-op");

    tokio::time::sleep(PROBE).await;
    let re_armed = conn.keepalive_timer().expect("the deadline still stands");
    nudge.send(()).expect("the server takes nudges");
    conn.pump_one().await.expect("the nudge arrives");
    conn.keepalive_fire(re_armed)
        .await
        .expect("a deadline a frame re-armed is a no-op");

    tokio::time::sleep(PROBE).await;
    let due = conn.keepalive_timer().expect("the deadline stands");
    conn.keepalive_fire(due).await.expect("the probe goes out");
    let answer = conn.keepalive_timer().expect("the answer bound stands");
    conn.keepalive_fire(answer)
        .await
        .expect("an answer bound not yet run out is a no-op");
    assert!(conn.is_connected(), "the answer bound runs from the probe");

    tokio::time::sleep(ANSWER).await;
    let answer = conn.keepalive_timer().expect("the answer bound stands");
    conn.keepalive_fire(answer)
        .await
        .expect("the unanswered probe drops the link");
    assert!(
        !conn.is_connected(),
        "the unanswered probe dropped the link"
    );
    assert!(
        conn.keepalive_timer().is_none(),
        "no deadline stands without a link"
    );
    // The server counts each probe when it reads it, so give it a turn.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        pings.load(Ordering::Acquire),
        1,
        "only the deadline that was due and current sent a probe"
    );
}

/// Pump steps that take no frame keep the keepalive sleep already armed, so
/// the app's sleeper is not asked for a fresh timer on every step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn steps_without_a_frame_keep_the_armed_keepalive_sleep() {
    let sleeps = Arc::new(AtomicU32::new(0));
    let counted = Arc::clone(&sleeps);
    let dialer = Scripted {
        quiet: Arc::new(AtomicBool::new(false)),
        pings: Arc::new(AtomicU32::new(0)),
        nonce_offset: 0,
    };
    // The default probe bound outlasts the test, so no probe or pong moves
    // the deadline while the steps run.
    let (running, pump) = ClientBuilder::new(super::support::bundle(DDL), dialer)
        .with_reconnect(ReconnectPolicy::default())
        .with_sleeper(move |d| {
            counted.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(d)
        })
        .connect_with_pump()
        .await
        .expect("the first dial hands back a transport");
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
    // A first step arms the deadline the handshake ack set.
    client.with_conn(|_| ()).await.expect("the client serves");
    let armed = sleeps.load(Ordering::Acquire);
    // Every lock waiter wakes the pump into a step that takes no frame.
    for _ in 0..50 {
        client.with_conn(|_| ()).await.expect("the client serves");
    }
    let rearmed = sleeps.load(Ordering::Acquire) - armed;
    assert!(
        rearmed <= 1,
        "50 frameless steps asked the sleeper for {rearmed} fresh timers"
    );
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
                    nonce_offset: 0,
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
