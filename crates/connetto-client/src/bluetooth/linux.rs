//! The Linux Bluetooth backend, over `BlueZ` (R76 slice 9b).
//!
//! The backend drives the `BlueZ` peripheral on one thread of its own, the
//! machine's polled calls reaching it over a channel and the service's
//! events coming back through the shared queue. The adapter's standing, the
//! peripheral's column and the open notify sessions stand on the shared
//! standing, the thread's first read standing the adapter's.

use std::collections::BTreeSet;
use std::sync::Arc;

use connetto_peer::linux::{AdapterStanding, BluezIo, DeviceKey, PeripheralAnswer};
use parking_lot::Mutex;
use tokio::sync::mpsc;

use super::{
    BluetoothError, BluetoothState, PeripheralBackend, PeripheralEvent, PromptOutcome,
    ReadinessBackend,
};

/// What the machine's polled calls ask of the thread.
enum Command {
    /// The peripheral table's start row, the request's generation under the
    /// beacon.
    Start(u64, [u8; 9]),
    /// The peripheral table's stop row.
    Stop,
    /// The readiness table's prompt row.
    Prompt,
    /// The peripheral table's notify row, the device's key and the chunk.
    Notify(DeviceKey, Vec<u8>),
    /// The peripheral table's disconnect row, the device's key.
    Disconnect(DeviceKey),
}

/// The peripheral table's column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Advertising {
    /// Off, nothing running.
    Off,
    /// The start is in flight, under the beacon.
    Starting([u8; 9]),
    /// Advertising, under the beacon.
    Running([u8; 9]),
}

/// The backend's shared state, the polled calls' read.
struct State {
    /// The adapter's standing, the thread's read and its powered signal.
    adapter: AdapterStanding,
    /// The peripheral table's column.
    column: Advertising,
    /// The notify sessions open, by the device's key.
    sessions: BTreeSet<DeviceKey>,
    /// The prompt's outcome, once the action stands.
    prompt: Option<PromptOutcome>,
    /// The start request's generation, the stale answers' refusal.
    start_gen: u64,
}

impl Default for State {
    fn default() -> Self {
        Self {
            adapter: AdapterStanding::None,
            column: Advertising::Off,
            sessions: BTreeSet::new(),
            prompt: None,
            start_gen: 0,
        }
    }
}

/// The backend's shared standing, the polled calls' read.
type Standing = Arc<Mutex<State>>;

/// The service's events, drained by the machine.
type Queue = Arc<Mutex<Vec<PeripheralEvent>>>;

/// The Linux Bluetooth backend, over `BlueZ` (R76 slice 9b).
pub(crate) struct LinuxBluetoothBackend {
    commands: mpsc::UnboundedSender<Command>,
    standing: Standing,
    events: Queue,
}

impl LinuxBluetoothBackend {
    /// The backend over `io`, its thread driving the tables on its own
    /// current-thread runtime.
    pub(crate) fn new<IO>(io: Arc<IO>) -> Self
    where
        IO: BluezIo + Send + 'static,
    {
        let (commands, receiver) = mpsc::unbounded_channel();
        let standing: Standing = Arc::new(Mutex::new(State::default()));
        let events: Queue = Arc::new(Mutex::new(Vec::new()));
        let drive_standing = Arc::clone(&standing);
        let drive_events = Arc::clone(&events);
        match std::thread::Builder::new()
            .name("connetto-bluez".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    tracing::error!("BlueZ's thread could not run");
                    return;
                };
                runtime.block_on(Self::drive(io, drive_standing, drive_events, receiver));
            }) {
            Ok(_) => {}
            Err(err) => tracing::error!("BlueZ's thread did not start: {err}"),
        }
        Self {
            commands,
            standing,
            events,
        }
    }

    /// The backend's channel, standing and queue, the thread's loop left to
    /// the caller's runtime, for the table proofs.
    #[cfg(test)]
    fn unstarted() -> (Self, mpsc::UnboundedReceiver<Command>) {
        let (commands, receiver) = mpsc::unbounded_channel();
        (
            Self {
                commands,
                standing: Arc::new(Mutex::new(State::default())),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            receiver,
        )
    }

    fn send(&self, command: Command) {
        if self.commands.send(command).is_err() {
            tracing::warn!("BlueZ's thread has ended");
        }
    }

    /// The thread's loop: the machine's commands and `BlueZ`'s answers
    /// against the tables, until the client drops its end.
    async fn drive<IO>(
        io: Arc<IO>,
        standing: Standing,
        events: Queue,
        mut commands: mpsc::UnboundedReceiver<Command>,
    ) where
        IO: BluezIo + Send + 'static,
    {
        let io: &IO = io.as_ref();
        standing.lock().adapter = io.standing().await;
        loop {
            let Some(item) = next_item(io, &mut commands).await else {
                break;
            };
            match item {
                Item::Command(Command::Start(generation, beacon)) => {
                    start_row(io, &standing, &events, beacon, generation).await;
                }
                Item::Command(Command::Stop) => {
                    io.stop().await;
                }
                Item::Command(Command::Prompt) => prompt_row(io, &standing).await,
                Item::Command(Command::Notify(device, bytes)) => {
                    if let Err(err) = io.notify(device, &bytes).await {
                        tracing::debug!(?device, %err, "the notification will not send");
                        standing.lock().sessions.remove(&device);
                    }
                }
                Item::Command(Command::Disconnect(device)) => {
                    io.disconnect(device).await;
                }
                Item::Event(answer) => handle_answer(io, &standing, &events, answer).await,
            }
        }
    }
}

/// What the thread's look takes, from either end.
enum Item {
    /// The machine's command.
    Command(Command),
    /// `BlueZ`'s answer.
    Event(PeripheralAnswer),
}

/// The machine's command or `BlueZ`'s answer, whichever stands first.
async fn next_item<IO: BluezIo>(
    io: &IO,
    commands: &mut mpsc::UnboundedReceiver<Command>,
) -> Option<Item> {
    tokio::select! {
        command = commands.recv() => command.map(Item::Command),
        event = io.next_event() => Some(Item::Event(event)),
    }
}

/// The peripheral table's start row, which stands the `GATT` application
/// and the advertisement under the beacon. The column takes the answer of
/// the current generation, and a stale answer orphans without touching it.
async fn start_row<IO: BluezIo>(
    io: &IO,
    standing: &Standing,
    events: &Queue,
    beacon: [u8; 9],
    generation: u64,
) {
    let outcome = io.start(beacon).await;
    let (orphaned, refused) = {
        let mut s = standing.lock();
        if s.start_gen == generation {
            match &outcome {
                Ok(()) => {
                    s.column = Advertising::Running(beacon);
                    (false, false)
                }
                Err(err) => {
                    // The fresh start's refusal stands the column Off and
                    // the machine's look the refusal's event, the renewal's
                    // refusal keeps the old advertisement standing.
                    let fresh = matches!(s.column, Advertising::Starting(_));
                    if fresh {
                        s.column = Advertising::Off;
                    }
                    tracing::warn!(%err, "the beacon could not stand");
                    (false, fresh)
                }
            }
        } else {
            // A later row superseded this start, so its objects orphan
            // to the stop, the stale refusal's new row owning the answer.
            (true, false)
        }
    };
    if orphaned && outcome.is_ok() {
        io.stop().await;
    }
    if refused && let Err(err) = outcome {
        push(events, PeripheralEvent::Failed(err.to_string()));
    }
}

/// The readiness table's prompt row: the adapter's `Powered` set true, the
/// outcome the refusal's or the powered signal's.
async fn prompt_row<IO: BluezIo>(io: &IO, standing: &Standing) {
    if let Err(err) = io.set_powered(true).await {
        // `BlueZ`'s refusal, the rfkill's hard block.
        tracing::debug!(%err, "the adapter will not power");
        standing.lock().prompt = Some(PromptOutcome::Blocked);
        return;
    }
    let mut s = standing.lock();
    // The standing already the call's, so the outcome stands.
    if matches!(s.adapter, AdapterStanding::Powered(true)) {
        s.prompt = Some(PromptOutcome::NotAsked);
    }
}

/// `BlueZ`'s answer, the peripheral table's rows.
async fn handle_answer<IO: BluezIo>(
    io: &IO,
    standing: &Standing,
    events: &Queue,
    answer: PeripheralAnswer,
) {
    match answer {
        PeripheralAnswer::Connected { device, mtu } => {
            standing.lock().sessions.insert(device);
            push(events, PeripheralEvent::Connected { device, mtu });
        }
        PeripheralAnswer::Chunk { device, bytes } => {
            push(events, PeripheralEvent::Chunk { device, bytes });
        }
        PeripheralAnswer::Disconnected { device } => {
            standing.lock().sessions.remove(&device);
            push(events, PeripheralEvent::Disconnected { device });
        }
        PeripheralAnswer::Powered(on) => {
            let powered_off = {
                let mut s = standing.lock();
                s.adapter = AdapterStanding::Powered(on);
                if on {
                    // The action's outcome, once the adapter reports
                    // powered.
                    s.prompt = Some(PromptOutcome::NotAsked);
                    false
                } else {
                    let running = !matches!(s.column, Advertising::Off);
                    if running {
                        s.column = Advertising::Off;
                        // The power-off supersedes the in-flight start, its
                        // stale answer orphaning without the column.
                        s.start_gen += 1;
                    }
                    running
                }
            };
            if powered_off {
                // The row: the column stands Off, the machine's look
                // stands the failure's event, the objects release.
                push(
                    events,
                    PeripheralEvent::Failed("the adapter powered off".into()),
                );
                io.stop().await;
            }
        }
    }
}

fn push(events: &Queue, event: PeripheralEvent) {
    events.lock().push(event);
}

impl ReadinessBackend for LinuxBluetoothBackend {
    fn state(&self) -> BluetoothState {
        let s = self.standing.lock();
        match s.adapter {
            AdapterStanding::None => BluetoothState::Unsupported,
            AdapterStanding::Powered(true) => BluetoothState::Ready,
            AdapterStanding::Powered(false) => BluetoothState::Off,
        }
    }

    fn missing_permissions(&self) -> Vec<String> {
        // The default D-Bus policy lets any user reach `BlueZ`.
        Vec::new()
    }

    fn prompt(&self) -> Result<(), BluetoothError> {
        self.standing.lock().prompt = None;
        self.send(Command::Prompt);
        Ok(())
    }

    fn prompt_outcome(&self) -> Option<PromptOutcome> {
        self.standing.lock().prompt
    }
}

impl PeripheralBackend for LinuxBluetoothBackend {
    fn start(&self, beacon: [u8; 9]) -> Result<(), BluetoothError> {
        let (send, generation) = {
            let mut s = self.standing.lock();
            let send = match s.column {
                // The advertisement already stands the beacon's service
                // data.
                Advertising::Running(standing_beacon) if standing_beacon == beacon => false,
                Advertising::Off => {
                    s.column = Advertising::Starting(beacon);
                    true
                }
                Advertising::Starting(_) | Advertising::Running(_) => true,
            };
            if send {
                s.start_gen += 1;
            }
            (send, s.start_gen)
        };
        if send {
            self.send(Command::Start(generation, beacon));
        }
        Ok(())
    }

    fn stop(&self) {
        let send = {
            let mut s = self.standing.lock();
            let send = !matches!(s.column, Advertising::Off);
            if send {
                s.start_gen += 1;
                s.column = Advertising::Off;
                s.sessions.clear();
            }
            send
        };
        if send {
            self.send(Command::Stop);
        }
    }

    fn poll(&self) -> Vec<PeripheralEvent> {
        core::mem::take(&mut *self.events.lock())
    }

    fn notify(&self, device: u64, bytes: &[u8]) -> Result<(), BluetoothError> {
        let s = self.standing.lock();
        if matches!(s.column, Advertising::Off) {
            return Err(BluetoothError::Failed("the beacon is off".to_string()));
        }
        if !s.sessions.contains(&device) {
            return Err(BluetoothError::Failed(
                "the device's notify session is closed".to_string(),
            ));
        }
        drop(s);
        self.send(Command::Notify(device, bytes.to_vec()));
        Ok(())
    }

    fn disconnect(&self, device: u64) {
        if matches!(self.standing.lock().column, Advertising::Off) {
            return;
        }
        self.send(Command::Disconnect(device));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use connetto_peer::linux::BluezError;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, Ordering};

    const BEACON: [u8; 9] = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    const BEACON_RENEWED: [u8; 9] = [9, 8, 7, 6, 5, 4, 3, 2, 1];
    const DEVICE: DeviceKey = 7;

    /// The fake `BlueZ` I/O, the table's rows driven.
    struct FakeBluez {
        adapter: Mutex<AdapterStanding>,
        /// The queued `set_powered` answers, in order.
        set_powered: Mutex<VecDeque<Result<(), BluezError>>>,
        /// The `set_powered` calls' standing.
        powered_set: Mutex<Vec<bool>>,
        /// The queued `start` answers, in order.
        start_answers: Mutex<VecDeque<Result<(), BluezError>>>,
        /// The `start` hold, the test's gate on the answer.
        start_gate: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        /// The beacons the GATT application registered under.
        started: Mutex<Vec<[u8; 9]>>,
        stops: AtomicU32,
        /// The queued `notify` answers, in order.
        notify_answers: Mutex<VecDeque<Result<(), BluezError>>>,
        notified: Mutex<Vec<(DeviceKey, Vec<u8>)>>,
        disconnected: Mutex<Vec<DeviceKey>>,
        events: tokio::sync::Mutex<mpsc::UnboundedReceiver<PeripheralAnswer>>,
    }

    impl FakeBluez {
        fn new(adapter: AdapterStanding) -> (Arc<Self>, mpsc::UnboundedSender<PeripheralAnswer>) {
            let (tx, rx) = mpsc::unbounded_channel();
            (
                Arc::new(Self {
                    adapter: Mutex::new(adapter),
                    set_powered: Mutex::new(VecDeque::new()),
                    powered_set: Mutex::new(Vec::new()),
                    start_answers: Mutex::new(VecDeque::new()),
                    start_gate: Mutex::new(None),
                    started: Mutex::new(Vec::new()),
                    stops: AtomicU32::new(0),
                    notify_answers: Mutex::new(VecDeque::new()),
                    notified: Mutex::new(Vec::new()),
                    disconnected: Mutex::new(Vec::new()),
                    events: tokio::sync::Mutex::new(rx),
                }),
                tx,
            )
        }

        fn hold_start(&self) -> tokio::sync::oneshot::Sender<()> {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.start_gate.lock().replace(rx);
            tx
        }

        fn stops(&self) -> u32 {
            self.stops.load(Ordering::Relaxed)
        }
    }

    impl BluezIo for FakeBluez {
        fn standing(&self) -> impl Future<Output = AdapterStanding> {
            std::future::ready(*self.adapter.lock())
        }

        fn set_powered(&self, on: bool) -> impl Future<Output = Result<(), BluezError>> {
            self.powered_set.lock().push(on);
            std::future::ready(self.set_powered.lock().pop_front().unwrap_or(Ok(())))
        }

        async fn start(&self, beacon: [u8; 9]) -> Result<(), BluezError> {
            self.started.lock().push(beacon);
            let gate = self.start_gate.lock().take();
            if let Some(gate) = gate {
                assert!(
                    gate.await.is_ok(),
                    "the test's gate never released the start"
                );
            }
            self.start_answers.lock().pop_front().unwrap_or(Ok(()))
        }

        fn stop(&self) -> impl Future<Output = ()> {
            self.stops.fetch_add(1, Ordering::Relaxed);
            std::future::ready(())
        }

        fn notify(
            &self,
            device: DeviceKey,
            bytes: &[u8],
        ) -> impl Future<Output = Result<(), BluezError>> {
            self.notified.lock().push((device, bytes.to_vec()));
            std::future::ready(self.notify_answers.lock().pop_front().unwrap_or(Ok(())))
        }

        fn disconnect(&self, device: DeviceKey) -> impl Future<Output = ()> {
            self.disconnected.lock().push(device);
            std::future::ready(())
        }

        async fn next_event(&self) -> PeripheralAnswer {
            let mut events = self.events.lock().await;
            events
                .recv()
                .await
                .expect("the test's events end with the fake")
        }
    }

    struct Harness {
        backend: LinuxBluetoothBackend,
        fake: Arc<FakeBluez>,
        events: mpsc::UnboundedSender<PeripheralAnswer>,
        driver: tokio::task::JoinHandle<()>,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.driver.abort();
        }
    }

    fn harness(adapter: AdapterStanding) -> Harness {
        let (fake, events) = FakeBluez::new(adapter);
        let (backend, receiver) = LinuxBluetoothBackend::unstarted();
        let standing = backend.standing.clone();
        let queue = backend.events.clone();
        let driver = tokio::spawn(LinuxBluetoothBackend::drive(
            fake.clone(),
            standing,
            queue,
            receiver,
        ));
        Harness {
            backend,
            fake,
            events,
            driver,
        }
    }

    async fn pump_until(mut condition: impl FnMut() -> bool) {
        let start = std::time::Instant::now();
        while !condition() {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "the standing did not reach"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// The pump's bound, the rows that stand done already.
    async fn pump() {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(20) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    fn beacon(h: &Harness) -> Vec<[u8; 9]> {
        h.fake.started.lock().clone()
    }

    fn notified(h: &Harness) -> Vec<(DeviceKey, Vec<u8>)> {
        h.fake.notified.lock().clone()
    }

    fn disconnected(h: &Harness) -> Vec<DeviceKey> {
        h.fake.disconnected.lock().clone()
    }

    // The readiness table.

    #[tokio::test]
    async fn readiness_without_an_adapter_is_unsupported() {
        tokio::time::pause();
        let h = harness(AdapterStanding::None);
        pump_until(|| h.backend.state() == BluetoothState::Unsupported).await;
        assert_eq!(h.backend.state(), BluetoothState::Unsupported);
    }

    #[tokio::test]
    async fn readiness_with_the_adapter_off() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(false));
        pump_until(|| h.backend.state() == BluetoothState::Off).await;
        assert_eq!(h.backend.state(), BluetoothState::Off);
    }

    #[tokio::test]
    async fn readiness_with_the_adapter_on() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert_eq!(h.backend.state(), BluetoothState::Ready);
    }

    #[tokio::test]
    async fn readiness_reports_no_missing_permissions() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert_eq!(h.backend.missing_permissions(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn prompt_powers_the_adapter() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(false));
        assert!(h.backend.prompt().is_ok());
        pump_until(|| h.fake.powered_set.lock().len() == 1).await;
        assert_eq!(*h.fake.powered_set.lock(), vec![true]);
        // The adapter's powered signal stands the action's outcome.
        h.events
            .send(PeripheralAnswer::Powered(true))
            .expect("the event goes in");
        pump_until(|| h.backend.prompt_outcome() == Some(PromptOutcome::NotAsked)).await;
    }

    #[tokio::test]
    async fn prompt_answered_blocked_by_the_refusal() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(false));
        pump_until(|| h.backend.state() == BluetoothState::Off).await;
        h.fake
            .set_powered
            .lock()
            .push_back(Err(BluezError::Refused("the rfkill's block".into())));
        assert!(h.backend.prompt().is_ok());
        pump_until(|| h.backend.prompt_outcome() == Some(PromptOutcome::Blocked)).await;
    }

    #[tokio::test]
    async fn prompt_while_powered_answers_not_asked() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(h.backend.prompt().is_ok());
        pump_until(|| h.backend.prompt_outcome() == Some(PromptOutcome::NotAsked)).await;
    }

    #[tokio::test]
    async fn readiness_follows_the_powered_signal() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        h.events
            .send(PeripheralAnswer::Powered(false))
            .expect("the event goes in");
        pump_until(|| h.backend.state() == BluetoothState::Off).await;
        h.events
            .send(PeripheralAnswer::Powered(true))
            .expect("the event goes in");
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
    }

    // The peripheral table.

    #[tokio::test]
    async fn start_registers_the_service_and_advertisement() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        assert_eq!(beacon(&h), vec![BEACON]);
    }

    #[tokio::test]
    async fn start_replaces_the_service_data() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        assert!(h.backend.start(BEACON_RENEWED).is_ok());
        pump_until(|| beacon(&h).len() == 2).await;
        assert_eq!(beacon(&h), vec![BEACON, BEACON_RENEWED]);
    }

    #[tokio::test]
    async fn start_is_a_no_op_under_the_same_beacon() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        assert!(h.backend.start(BEACON).is_ok());
        pump().await;
        assert_eq!(beacon(&h).len(), 1);
    }

    #[tokio::test]
    async fn stop_unregisters_both() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        h.backend.stop();
        pump_until(|| h.fake.stops() == 1).await;
        // The column stands Off, the notify's refusal the table's.
        assert!(matches!(
            h.backend.notify(DEVICE, &[1]),
            Err(BluetoothError::Failed(_))
        ));
    }

    #[tokio::test]
    async fn stop_does_nothing_while_off() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        h.backend.stop();
        pump().await;
        assert_eq!(h.fake.stops(), 0);
    }

    #[tokio::test]
    async fn a_central_notify_session_stands_connected() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        h.events
            .send(PeripheralAnswer::Connected {
                device: DEVICE,
                mtu: 517,
            })
            .expect("the event goes in");
        pump_until(|| !h.backend.events.lock().is_empty()).await;
        let polled = h.backend.poll();
        assert!(matches!(
            polled.as_slice(),
            [PeripheralEvent::Connected { device, mtu }] if *device == DEVICE && *mtu == 517
        ));
    }

    #[tokio::test]
    async fn a_central_write_stands_a_chunk() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        h.events
            .send(PeripheralAnswer::Chunk {
                device: DEVICE,
                bytes: vec![1, 2, 3],
            })
            .expect("the event goes in");
        pump_until(|| !h.backend.events.lock().is_empty()).await;
        let polled = h.backend.poll();
        assert!(matches!(
            polled.as_slice(),
            [PeripheralEvent::Chunk { device, bytes }] if *device == DEVICE && *bytes == vec![1, 2, 3]
        ));
    }

    #[tokio::test]
    async fn a_session_end_stands_disconnected() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        h.events
            .send(PeripheralAnswer::Disconnected { device: DEVICE })
            .expect("the event goes in");
        pump_until(|| !h.backend.events.lock().is_empty()).await;
        let polled = h.backend.poll();
        assert!(matches!(
            polled.as_slice(),
            [PeripheralEvent::Disconnected { device }] if *device == DEVICE
        ));
    }

    #[tokio::test]
    async fn notify_sends_on_the_session() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        h.events
            .send(PeripheralAnswer::Connected {
                device: DEVICE,
                mtu: 517,
            })
            .expect("the event goes in");
        pump_until(|| !h.backend.poll().is_empty()).await;
        assert!(h.backend.notify(DEVICE, &[4, 5]).is_ok());
        pump_until(|| notified(&h).len() == 1).await;
        assert_eq!(notified(&h), vec![(DEVICE, vec![4, 5])]);
    }

    #[tokio::test]
    async fn notify_answers_failed_while_off() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(matches!(
            h.backend.notify(DEVICE, &[1]),
            Err(BluetoothError::Failed(_))
        ));
        assert_eq!(notified(&h), Vec::<(DeviceKey, Vec<u8>)>::new());
    }

    #[tokio::test]
    async fn notify_answers_failed_on_a_closed_session() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        // The session not open, so the notify's refusal the table's.
        assert!(matches!(
            h.backend.notify(DEVICE, &[1]),
            Err(BluetoothError::Failed(_))
        ));
        h.events
            .send(PeripheralAnswer::Connected {
                device: DEVICE,
                mtu: 517,
            })
            .expect("the event goes in");
        pump_until(|| !h.backend.poll().is_empty()).await;
        assert!(h.backend.notify(DEVICE, &[1]).is_ok());
        pump_until(|| notified(&h).len() == 1).await;
    }

    #[tokio::test]
    async fn notify_answered_closed_releases_the_session() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        h.events
            .send(PeripheralAnswer::Connected {
                device: DEVICE,
                mtu: 517,
            })
            .expect("the event goes in");
        pump_until(|| !h.backend.poll().is_empty()).await;
        // The session's closure answers the send, the standing follows.
        h.fake
            .notify_answers
            .lock()
            .push_back(Err(BluezError::Closed));
        assert!(h.backend.notify(DEVICE, &[1]).is_ok());
        pump_until(|| notified(&h).len() == 1).await;
        pump().await;
        assert!(matches!(
            h.backend.notify(DEVICE, &[2]),
            Err(BluetoothError::Failed(_))
        ));
    }

    #[tokio::test]
    async fn disconnect_ends_the_device() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        h.backend.disconnect(DEVICE);
        pump_until(|| disconnected(&h).len() == 1).await;
        assert_eq!(disconnected(&h), vec![DEVICE]);
    }

    #[tokio::test]
    async fn disconnect_does_nothing_while_off() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        h.backend.disconnect(DEVICE);
        pump().await;
        assert_eq!(disconnected(&h), Vec::<DeviceKey>::new());
    }

    #[tokio::test]
    async fn the_adapter_powering_off_ends_the_beacon() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        h.events
            .send(PeripheralAnswer::Powered(false))
            .expect("the event goes in");
        pump_until(|| h.fake.stops() >= 1).await;
        // The row's event stands the machine's look.
        pump_until(|| {
            h.backend.poll().iter().any(|event| {
                matches!(event, PeripheralEvent::Failed(reason)
                    if reason == "the adapter powered off")
            })
        })
        .await;
        // The column stands Off, the machine restarting the beacon once
        // readiness stands Ready again.
        assert!(matches!(
            h.backend.notify(DEVICE, &[1]),
            Err(BluetoothError::Failed(_))
        ));
        h.events
            .send(PeripheralAnswer::Powered(true))
            .expect("the event goes in");
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 2).await;
    }

    #[tokio::test]
    async fn the_adapter_powering_off_while_off_is_a_no_op() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        h.events
            .send(PeripheralAnswer::Powered(false))
            .expect("the event goes in");
        pump_until(|| h.backend.state() == BluetoothState::Off).await;
        assert_eq!(h.fake.stops(), 0);
        assert!(h.backend.poll().is_empty());
    }

    #[tokio::test]
    async fn a_start_refusal_stands_the_refusal_event() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        h.fake
            .start_answers
            .lock()
            .push_back(Err(BluezError::Refused("the refusal".into())));
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| {
            h.backend
                .poll()
                .iter()
                .any(|event| matches!(event, PeripheralEvent::Failed(_)))
        })
        .await;
        // The column stands Off, so the machine's next look retries the
        // row.
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 2).await;
    }

    #[tokio::test]
    async fn a_renewal_refusal_keeps_the_old_advertisement() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        // The renewal's refusal: the old advertisement still stands.
        h.fake
            .start_answers
            .lock()
            .push_back(Err(BluezError::Refused("the refusal".into())));
        assert!(h.backend.start(BEACON_RENEWED).is_ok());
        pump_until(|| beacon(&h).len() == 2).await;
        pump().await;
        assert!(h.backend.poll().is_empty());
        // The column keeps the old beacon's standing, the notify's rows
        // the old session's.
        h.events
            .send(PeripheralAnswer::Connected {
                device: DEVICE,
                mtu: 517,
            })
            .expect("the event goes in");
        pump_until(|| !h.backend.poll().is_empty()).await;
        assert!(h.backend.notify(DEVICE, &[1]).is_ok());
    }

    /// The stop's queue ahead of the start's answer, the new beacon's
    /// standing kept by the start's own generation.
    #[tokio::test]
    async fn a_stop_then_a_start_stands_the_new_beacon() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        // The stop queues before the start's answer, and the thread
        // answers the rows in order.
        h.backend.stop();
        assert!(h.backend.start(BEACON_RENEWED).is_ok());
        pump_until(|| beacon(&h).len() == 2).await;
        pump_until(|| {
            matches!(
                h.backend.standing.lock().column,
                Advertising::Running(BEACON_RENEWED)
            )
        })
        .await;
    }

    /// The stale start's success orphaned to the stop, the fresh start's
    /// refusal standing the column Off and the machine's `Failed`.
    #[tokio::test]
    async fn a_stale_success_and_a_fresh_refusal_stand_the_refusal() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        let gate = h.fake.hold_start();
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        h.backend.stop();
        // The stale start's answer is the success, the fresh start's
        // the refusal, in the thread's order.
        h.fake.start_answers.lock().push_back(Ok(()));
        h.fake
            .start_answers
            .lock()
            .push_back(Err(BluezError::Refused("the refusal".into())));
        assert!(h.backend.start(BEACON_RENEWED).is_ok());
        gate.send(()).expect("the gate opens");
        // The stale start's objects release, then the stop's row runs.
        pump_until(|| h.fake.stops() == 2).await;
        pump_until(|| {
            h.backend
                .poll()
                .iter()
                .any(|event| matches!(event, PeripheralEvent::Failed(_)))
        })
        .await;
        assert!(matches!(h.backend.standing.lock().column, Advertising::Off));
        assert!(matches!(
            h.backend.notify(DEVICE, &[1]),
            Err(BluetoothError::Failed(_))
        ));
    }

    #[tokio::test]
    async fn a_start_after_the_stop_releases_the_orphan() {
        tokio::time::pause();
        let h = harness(AdapterStanding::Powered(true));
        pump_until(|| h.backend.state() == BluetoothState::Ready).await;
        let gate = h.fake.hold_start();
        assert!(h.backend.start(BEACON).is_ok());
        pump_until(|| beacon(&h).len() == 1).await;
        // The stop's column move, the start's answer orphaning to it.
        h.backend.stop();
        gate.send(()).expect("the gate opens");
        pump_until(|| h.fake.stops() == 2).await;
        assert_eq!(h.fake.stops(), 2);
    }
}
