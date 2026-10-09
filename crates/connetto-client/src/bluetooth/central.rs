//! The joiner's Bluetooth central over btleplug (R76 decision 22).
//!
//! btleplug runs on one thread of its own, prepared once for the platform
//! and driving its own runtime. The machine's polled calls reach it over a
//! channel, and its scan results, connections and notifications come back
//! through a shared queue the machine drains.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use btleplug::api::{
    Central as _, CentralEvent as BtEvent, Characteristic, Manager as _, Peripheral as _,
    ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral, PeripheralId};
use connetto_peer::{INBOX_UUID, OUTBOX_UUID, SERVICE_UUID};
use futures_util::StreamExt as _;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use uuid::Uuid;

use super::{BluetoothError, CentralBackend, CentralEvent, HostId};

/// The bound btleplug's thread gets to prepare and find its adapter.
const START_BOUND: Duration = Duration::from_secs(10);
/// The bound a connection and its service discovery each get.
const LINK_STEP_BOUND: Duration = Duration::from_secs(10);

/// What the machine asks of btleplug's thread.
enum Command {
    StartScan,
    StopScan,
    Connect(HostId),
    Write(HostId, Vec<u8>),
    Disconnect(HostId),
}

/// The events btleplug's thread reports, drained by the machine.
type Queue = Arc<Mutex<Vec<CentralEvent>>>;

/// Why btleplug's central does not start.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CentralError {
    /// The platform's preparation of btleplug's thread failed.
    #[error("btleplug's thread could not be prepared: {0}")]
    Prepare(String),
    /// The virtual machine refused a call while the thread was prepared.
    #[error("the virtual machine refused: {0}")]
    Jni(#[from] connetto_peer_android::jni::errors::Error),
    /// btleplug refused a call.
    #[error("btleplug refused: {0}")]
    Btleplug(#[from] btleplug::Error),
    /// The platform shows no Bluetooth adapter.
    #[error("the platform shows no Bluetooth adapter")]
    NoAdapter,
    /// The thread or its runtime did not start.
    #[error("btleplug's thread did not start: {0}")]
    Thread(String),
    /// The thread did not answer within its bound.
    #[error("btleplug's thread did not answer within {0:?}")]
    TimedOut(Duration),
}

/// The joiner's central over btleplug (R76 decision 22).
pub(crate) struct BtleplugCentral {
    commands: mpsc::UnboundedSender<Command>,
    events: Queue,
}

impl BtleplugCentral {
    /// Start btleplug's thread, answering once it found its adapter.
    ///
    /// # Errors
    ///
    /// [`CentralError`] when the thread cannot be prepared, btleplug finds no
    /// adapter, or the thread does not answer within its bound.
    pub(crate) async fn start() -> Result<Self, CentralError> {
        let (commands, receiver) = mpsc::unbounded_channel();
        let events: Queue = Arc::new(Mutex::new(Vec::new()));
        let (started, answer) = tokio::sync::oneshot::channel();
        let queue = Arc::clone(&events);
        std::thread::Builder::new()
            .name("connetto-btleplug".into())
            // A thread of its own, which no runtime owns, so its runtime
            // blocks on btleplug's loop.
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        let _ = started.send(Err(CentralError::Thread(err.to_string())));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let adapter = match prepare().await {
                        Ok(adapter) => adapter,
                        Err(err) => {
                            let _ = started.send(Err(err));
                            return;
                        }
                    };
                    let _ = started.send(Ok(()));
                    drive(adapter, receiver, queue).await;
                });
            })
            .map_err(|err| CentralError::Thread(err.to_string()))?;
        match tokio::time::timeout(START_BOUND, answer).await {
            Ok(Ok(Ok(()))) => Ok(Self { commands, events }),
            Ok(Ok(Err(err))) => Err(err),
            Ok(Err(_)) => Err(CentralError::Thread(
                "the thread ended before it answered".into(),
            )),
            Err(_) => Err(CentralError::TimedOut(START_BOUND)),
        }
    }

    fn send(&self, command: Command) {
        if self.commands.send(command).is_err() {
            tracing::warn!("btleplug's thread has ended");
        }
    }
}

impl CentralBackend for BtleplugCentral {
    fn start_scan(&self) {
        self.send(Command::StartScan);
    }

    fn stop_scan(&self) {
        self.send(Command::StopScan);
    }

    fn poll(&self) -> Vec<CentralEvent> {
        core::mem::take(&mut *self.events.lock())
    }

    fn connect(&self, host: HostId) {
        self.send(Command::Connect(host));
    }

    fn write(&self, host: HostId, bytes: &[u8]) -> Result<(), BluetoothError> {
        self.commands
            .send(Command::Write(host, bytes.to_vec()))
            .map_err(|_| BluetoothError::Failed("btleplug's thread has ended".into()))
    }

    fn disconnect(&self, host: HostId) {
        self.send(Command::Disconnect(host));
    }
}

/// Prepare the thread for btleplug and find its first adapter.
async fn prepare() -> Result<Adapter, CentralError> {
    prepare_thread()?;
    let manager = Manager::new().await?;
    manager
        .adapters()
        .await?
        .into_iter()
        .next()
        .ok_or(CentralError::NoAdapter)
}

/// Attach the thread to the virtual machine for good, point its class loader
/// at the application's so btleplug's lookups find its Java, and initialise
/// btleplug's Android half (R76 decision 22).
#[cfg(target_os = "android")]
fn prepare_thread() -> Result<(), CentralError> {
    let vm =
        connetto_peer_android::java_vm().map_err(|err| CentralError::Prepare(err.to_string()))?;
    vm.attach_current_thread(|env| -> Result<(), CentralError> {
        connetto_peer_android::use_application_class_loader(env)?;
        btleplug::platform::init(env)?;
        Ok(())
    })
}

/// The thread's loop: the machine's commands against btleplug, and
/// btleplug's events back to the machine, until the client drops its end.
async fn drive(adapter: Adapter, mut commands: mpsc::UnboundedReceiver<Command>, queue: Queue) {
    let mut bt_events = match adapter.events().await {
        Ok(events) => events,
        Err(err) => {
            tracing::warn!(%err, "btleplug's events could not be read");
            return;
        }
    };
    let mut hosts = Hosts::default();
    let mut links: HashMap<HostId, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    Command::StartScan => {
                        if let Err(err) = adapter.start_scan(ScanFilter::default()).await {
                            tracing::warn!(%err, "the scan did not start");
                        }
                    }
                    Command::StopScan => {
                        if let Err(err) = adapter.stop_scan().await {
                            tracing::warn!(%err, "the scan did not stop");
                        }
                    }
                    Command::Connect(host) => {
                        let Some(id) = hosts.id(host) else {
                            push(&queue, CentralEvent::Disconnected { host });
                            continue;
                        };
                        match adapter.peripheral(id).await {
                            Ok(peripheral) => {
                                let (writes, pending) = mpsc::unbounded_channel();
                                links.insert(host, writes);
                                tokio::spawn(link(peripheral, host, pending, Arc::clone(&queue)));
                            }
                            Err(err) => {
                                tracing::warn!(%err, "the host is unknown to btleplug");
                                push(&queue, CentralEvent::Disconnected { host });
                            }
                        }
                    }
                    Command::Write(host, bytes) => {
                        if links.get(&host).is_none_or(|link| link.send(bytes).is_err()) {
                            push(&queue, CentralEvent::Disconnected { host });
                        }
                    }
                    // The link's write queue closes, so its task disconnects.
                    Command::Disconnect(host) => {
                        links.remove(&host);
                    }
                }
            }
            event = bt_events.next() => {
                let Some(event) = event else { break };
                match event {
                    BtEvent::ServiceDataAdvertisement { id, service_data } => {
                        let Some(data) = service_data.get(&Uuid::from_bytes(SERVICE_UUID)) else {
                            continue;
                        };
                        let rssi = rssi_of(&adapter, &id).await;
                        let host = hosts.host(id);
                        push(&queue, CentralEvent::Seen { host, service_data: data.clone(), rssi });
                    }
                    BtEvent::DeviceDisconnected(id) => {
                        if let Some(host) = hosts.known(&id) && links.remove(&host).is_some() {
                            push(&queue, CentralEvent::Disconnected { host });
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    let _ = adapter.stop_scan().await;
}

/// The signal of the peripheral's last advertisement, where the platform
/// reports one.
async fn rssi_of(adapter: &Adapter, id: &PeripheralId) -> Option<i16> {
    let peripheral = adapter.peripheral(id).await.ok()?;
    peripheral.properties().await.ok()??.rssi
}

/// One connection to a host: connect, find the two characteristics,
/// subscribe, then carry the machine's writes out in order and the host's
/// notifications in, until either side ends it.
async fn link(
    peripheral: Peripheral,
    host: HostId,
    mut writes: mpsc::UnboundedReceiver<Vec<u8>>,
    queue: Queue,
) {
    let ready = async {
        peripheral.connect_with_timeout(LINK_STEP_BOUND).await?;
        peripheral
            .discover_services_with_timeout(LINK_STEP_BOUND)
            .await?;
        let characteristics = peripheral.characteristics();
        let find = |uuid: [u8; 16]| -> Result<Characteristic, btleplug::Error> {
            characteristics
                .iter()
                .find(|characteristic| characteristic.uuid == Uuid::from_bytes(uuid))
                .cloned()
                .ok_or(btleplug::Error::NoSuchCharacteristic)
        };
        let inbox = find(INBOX_UUID)?;
        let outbox = find(OUTBOX_UUID)?;
        peripheral.subscribe(&outbox).await?;
        let notifications = peripheral.notifications().await?;
        Ok::<_, btleplug::Error>((inbox, outbox, notifications))
    }
    .await;
    let (inbox, outbox, mut notifications) = match ready {
        Ok(ready) => ready,
        Err(err) => {
            tracing::warn!(%err, "the host's link did not settle");
            let _ = peripheral.disconnect().await;
            push(&queue, CentralEvent::Disconnected { host });
            return;
        }
    };
    push(
        &queue,
        CentralEvent::Connected {
            host,
            mtu: peripheral.mtu(),
        },
    );
    loop {
        tokio::select! {
            outgoing = writes.recv() => {
                let Some(bytes) = outgoing else { break };
                if let Err(err) = peripheral.write(&inbox, &bytes, WriteType::WithResponse).await {
                    tracing::warn!(%err, "a chunk to the host did not go");
                    break;
                }
            }
            notification = notifications.next() => {
                let Some(notification) = notification else { break };
                if notification.uuid == outbox.uuid {
                    push(&queue, CentralEvent::Chunk { host, bytes: notification.value });
                }
            }
        }
    }
    let _ = peripheral.disconnect().await;
    push(&queue, CentralEvent::Disconnected { host });
}

fn push(queue: &Queue, event: CentralEvent) {
    queue.lock().push(event);
}

/// The client's keys for the peripherals btleplug names, so a host keeps one
/// key for as long as the client runs.
#[derive(Default)]
struct Hosts {
    by_id: HashMap<PeripheralId, HostId>,
    by_host: HashMap<HostId, PeripheralId>,
    next: HostId,
}

impl Hosts {
    /// The peripheral's key, minted on its first sighting.
    fn host(&mut self, id: PeripheralId) -> HostId {
        if let Some(host) = self.by_id.get(&id) {
            return *host;
        }
        self.next += 1;
        self.by_id.insert(id.clone(), self.next);
        self.by_host.insert(self.next, id);
        self.next
    }

    fn known(&self, id: &PeripheralId) -> Option<HostId> {
        self.by_id.get(id).copied()
    }

    fn id(&self, host: HostId) -> Option<&PeripheralId> {
        self.by_host.get(&host)
    }
}
