//! The `BlueZ` peripheral I/O the Bluetooth backend drives over `bluer`
//! (R76 slice 9b).
//!
//! The host's GATT service and its legacy advertisement live behind one
//! `bluer` session on the system bus. The outbox characteristic uses the
//! `Io` notify method, so a central's notify session hands the backend the
//! device and the session's MTU, and the inbox characteristic uses the
//! `Fun` write method, so a central's write hands the backend its bytes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use bluer::adv::{Advertisement, AdvertisementHandle, Type};
use bluer::gatt::CharacteristicWriter;
use bluer::gatt::local::{
    Application, ApplicationHandle, Characteristic, CharacteristicControl,
    CharacteristicControlEvent, CharacteristicControlHandle, CharacteristicNotify,
    CharacteristicNotifyMethod, CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod,
    Service, characteristic_control, service_control,
};
use bluer::{Adapter, Address, ErrorKind, Session, Uuid};
use futures_util::{FutureExt, StreamExt};
use parking_lot::Mutex;

/// How long a single `BlueZ` call gets, on the monotonic clock.
const CALL_BOUND: Duration = Duration::from_secs(5);

/// The device of a nearby central, its 48-bit address folded to one `u64`.
pub type DeviceKey = u64;

/// The adapter's standing, as the I/O reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterStanding {
    /// `BlueZ` shows no adapter.
    None,
    /// The adapter, and whether it is powered.
    Powered(bool),
}

/// Why a `BlueZ` call will not go.
#[derive(Debug, thiserror::Error)]
pub enum BluezError {
    /// `BlueZ` refused the call, with its reason.
    #[error("BlueZ refused: {0}")]
    Refused(String),
    /// The device's notify session is closed.
    #[error("the device's notify session is closed")]
    Closed,
    /// The call did not answer within its bound.
    #[error("the call did not answer within {0:?}")]
    TimedOut(Duration),
}

/// An event the peripheral's I/O reports.
#[derive(Clone, Debug)]
pub enum PeripheralAnswer {
    /// A central started a notify session on the outbox, with its MTU.
    Connected {
        /// The device's key.
        device: DeviceKey,
        /// The session's MTU.
        mtu: u16,
    },
    /// A central wrote the inbox, with its bytes.
    Chunk {
        /// The device's key.
        device: DeviceKey,
        /// The chunk's bytes.
        bytes: Vec<u8>,
    },
    /// A notify session ended, or the device disconnected.
    Disconnected {
        /// The device's key.
        device: DeviceKey,
    },
    /// The adapter's powered state, once it stands.
    Powered(bool),
}

/// The I/O the Bluetooth backend needs from `BlueZ`.
#[expect(
    async_fn_in_trait,
    reason = "the backend runs its calls on its own thread's current-thread runtime, so the futures are consumed there"
)]
pub trait BluezIo: Send + Sync {
    /// The adapter's standing.
    async fn standing(&self) -> AdapterStanding;
    /// Set the adapter powered, `Refused` on a hard block.
    async fn set_powered(&self, on: bool) -> Result<(), BluezError>;
    /// Register the GATT application and the advertisement under `beacon`.
    async fn start(&self, beacon: [u8; 9]) -> Result<(), BluezError>;
    /// Stop the advertisement and the GATT application.
    async fn stop(&self);
    /// Send a chunk on the device's notify session.
    async fn notify(&self, device: DeviceKey, bytes: &[u8]) -> Result<(), BluezError>;
    /// End the device's connection.
    async fn disconnect(&self, device: DeviceKey);
    /// The next peripheral event.
    async fn next_event(&self) -> PeripheralAnswer;
}

/// The real `BlueZ` peripheral I/O, over `bluer`.
pub struct BluerBluez {
    app: Mutex<Option<ApplicationHandle>>,
    adv: Mutex<Option<AdvertisementHandle>>,
    sessions: Arc<Mutex<HashMap<DeviceKey, Arc<CharacteristicWriter>>>>,
    events: tokio::sync::mpsc::Sender<PeripheralAnswer>,
    event_rx: Mutex<tokio::sync::mpsc::Receiver<PeripheralAnswer>>,
    #[expect(
        dead_code,
        reason = "the field owns the session's D-Bus connection, the GATT application and the advertisement run on it"
    )]
    session: Option<Session>,
    adapter: Option<Adapter>,
}

type Sessions = Arc<Mutex<HashMap<DeviceKey, Arc<CharacteristicWriter>>>>;

impl BluerBluez {
    /// Connect to `bluer` and its default adapter.
    ///
    /// # Errors
    ///
    /// [`BluezError`] when the session or the adapter will not stand. A
    /// system with no adapter answers the `None` standing, not an error.
    pub async fn new() -> Result<Self, BluezError> {
        let session = bounded(CALL_BOUND, Session::new()).await?;
        let adapter = match tokio::time::timeout(CALL_BOUND, session.default_adapter()).await {
            Ok(Ok(adapter)) => Some(adapter),
            Ok(Err(err)) if err.kind == ErrorKind::NotFound => None,
            Ok(Err(err)) => return Err(refuse(&err)),
            Err(_) => return Err(BluezError::TimedOut(CALL_BOUND)),
        };
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
        if let Some(adapter) = &adapter {
            tokio::spawn(forward_adapter_events(
                adapter.clone(),
                sessions.clone(),
                tx.clone(),
            ));
        }
        Ok(Self {
            app: Mutex::new(None),
            adv: Mutex::new(None),
            sessions,
            events: tx,
            event_rx: Mutex::new(rx),
            session: Some(session),
            adapter,
        })
    }
}

/// Run `fut` bounded on `bound`, a refusal and a timeout each mapped.
async fn bounded<T, F>(bound: Duration, fut: F) -> Result<T, BluezError>
where
    F: Future<Output = Result<T, bluer::Error>>,
{
    match tokio::time::timeout(bound, fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(refuse(&err)),
        Err(_) => Err(BluezError::TimedOut(bound)),
    }
}

/// Map a `bluer` refusal to the I/O's reason.
fn refuse(err: &bluer::Error) -> BluezError {
    BluezError::Refused(format!("{err:?}"))
}

/// The 48-bit address folded to the device's key, big-endian.
#[must_use]
fn key(address: Address) -> DeviceKey {
    let mut folded = 0u64;
    for byte in address.0 {
        folded = (folded << 8) | u64::from(byte);
    }
    folded
}

/// The device's key unfolded to its 48-bit address.
#[must_use]
fn address_of(key: DeviceKey) -> Address {
    let bytes = key.to_be_bytes();
    Address(bytes[2..8].try_into().unwrap())
}

/// Build the host's GATT application, its outbox's control stream kept.
fn gatt_app(
    events: &tokio::sync::mpsc::Sender<PeripheralAnswer>,
) -> (Application, CharacteristicControl) {
    let (_service_control, service_control_handle) = service_control();

    let inbox_events = events.clone();
    let inbox = Characteristic {
        uuid: Uuid::from_bytes(crate::beacon::INBOX_UUID),
        handle: None,
        broadcast: false,
        writable_auxiliaries: false,
        authorize: false,
        descriptors: Vec::new(),
        read: None,
        write: Some(CharacteristicWrite {
            write: true,
            write_without_response: false,
            reliable_write: false,
            authenticated_signed_writes: false,
            encrypt_write: false,
            encrypt_authenticated_write: false,
            secure_write: false,
            method: CharacteristicWriteMethod::Fun(Box::new(move |bytes, request| {
                let device = key(request.device_address);
                let events = inbox_events.clone();
                async move {
                    let _ = events.send(PeripheralAnswer::Chunk { device, bytes }).await;
                    Ok(())
                }
                .boxed()
            })),
            _non_exhaustive: (),
        }),
        notify: None,
        control_handle: CharacteristicControlHandle::default(),
        _non_exhaustive: (),
    };

    let (control, control_handle) = characteristic_control();
    let outbox = Characteristic {
        uuid: Uuid::from_bytes(crate::beacon::OUTBOX_UUID),
        handle: None,
        broadcast: false,
        writable_auxiliaries: false,
        authorize: false,
        descriptors: Vec::new(),
        read: Some(CharacteristicRead {
            read: true,
            encrypt_read: false,
            encrypt_authenticated_read: false,
            secure_read: false,
            fun: Box::new(|_request| async move { Ok(Vec::<u8>::new()) }.boxed()),
            _non_exhaustive: (),
        }),
        write: None,
        notify: Some(CharacteristicNotify {
            notify: true,
            indicate: false,
            method: CharacteristicNotifyMethod::Io,
            _non_exhaustive: (),
        }),
        control_handle,
        _non_exhaustive: (),
    };

    let service = Service {
        uuid: Uuid::from_bytes(crate::beacon::SERVICE_UUID),
        handle: None,
        primary: true,
        characteristics: vec![inbox, outbox],
        control_handle: service_control_handle,
        _non_exhaustive: (),
    };
    (
        Application {
            services: vec![service],
            _non_exhaustive: (),
        },
        control,
    )
}

/// Follow the outbox's control stream, standing the notify sessions.
async fn drive_control(
    control: CharacteristicControl,
    sessions: Sessions,
    events: tokio::sync::mpsc::Sender<PeripheralAnswer>,
) {
    let mut control = control;
    while let Some(event) = control.next().await {
        let CharacteristicControlEvent::Notify(writer) = event else {
            continue;
        };
        let device = key(writer.device_address());
        let mtu = u16::try_from(writer.mtu()).unwrap_or(512);
        let writer = Arc::new(writer);
        sessions.lock().insert(device, writer.clone());
        let _ = events
            .send(PeripheralAnswer::Connected { device, mtu })
            .await;
        let sessions = sessions.clone();
        let events = events.clone();
        tokio::spawn(async move {
            let _ = writer.closed().await;
            sessions.lock().remove(&device);
            let _ = events.send(PeripheralAnswer::Disconnected { device }).await;
        });
    }
}

/// Follow the adapter's events, the powered change and a device's removal.
async fn forward_adapter_events(
    adapter: Adapter,
    sessions: Sessions,
    events: tokio::sync::mpsc::Sender<PeripheralAnswer>,
) {
    let Ok(mut stream) = adapter.events().await else {
        return;
    };
    while let Some(event) = stream.next().await {
        match event {
            bluer::AdapterEvent::DeviceRemoved(address) => {
                let device = key(address);
                sessions.lock().remove(&device);
                let _ = events.send(PeripheralAnswer::Disconnected { device }).await;
            }
            bluer::AdapterEvent::PropertyChanged(bluer::AdapterProperty::Powered(on)) => {
                let _ = events.send(PeripheralAnswer::Powered(on)).await;
            }
            _ => {}
        }
    }
}

impl BluezIo for BluerBluez {
    async fn standing(&self) -> AdapterStanding {
        let Some(adapter) = self.adapter.clone() else {
            return AdapterStanding::None;
        };
        match bounded(CALL_BOUND, adapter.is_powered()).await {
            Ok(powered) => AdapterStanding::Powered(powered),
            Err(_) => AdapterStanding::None,
        }
    }

    async fn set_powered(&self, on: bool) -> Result<(), BluezError> {
        let Some(adapter) = self.adapter.clone() else {
            return Err(BluezError::Refused("no adapter".into()));
        };
        bounded(CALL_BOUND, adapter.set_powered(on)).await
    }

    async fn start(&self, beacon: [u8; 9]) -> Result<(), BluezError> {
        let Some(adapter) = self.adapter.clone() else {
            return Err(BluezError::Refused("no adapter".into()));
        };
        // The application runs, so the advertisement's service data is
        // replaced, the GATT application kept.
        if self.app.lock().is_some() {
            let advertisement = advertisement(beacon);
            let handle = bounded(CALL_BOUND, adapter.advertise(advertisement)).await?;
            self.adv.lock().replace(handle);
            return Ok(());
        }
        let (app, control) = gatt_app(&self.events);
        let handle = bounded(CALL_BOUND, adapter.serve_gatt_application(app)).await?;
        self.app.lock().replace(handle);
        let advertisement = advertisement(beacon);
        let handle = bounded(CALL_BOUND, adapter.advertise(advertisement)).await?;
        self.adv.lock().replace(handle);
        let sessions = self.sessions.clone();
        let events = self.events.clone();
        tokio::spawn(drive_control(control, sessions, events));
        Ok(())
    }

    async fn stop(&self) {
        self.app.lock().take();
        self.adv.lock().take();
        self.sessions.lock().clear();
    }

    async fn notify(&self, device: DeviceKey, bytes: &[u8]) -> Result<(), BluezError> {
        let Some(writer) = self.sessions.lock().get(&device).cloned() else {
            return Err(BluezError::Closed);
        };
        match tokio::time::timeout(CALL_BOUND, writer.send(bytes)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(BluezError::Closed),
            Err(_) => Err(BluezError::TimedOut(CALL_BOUND)),
        }
    }

    async fn disconnect(&self, device: DeviceKey) {
        self.sessions.lock().remove(&device);
        let Some(adapter) = self.adapter.clone() else {
            return;
        };
        let Ok(device) = adapter.device(address_of(device)) else {
            return;
        };
        let _ = bounded(CALL_BOUND, device.disconnect()).await;
    }

    #[expect(
        clippy::await_holding_lock,
        reason = "the receiver's guard is held only across its own bounded recv"
    )]
    async fn next_event(&self) -> PeripheralAnswer {
        self.event_rx
            .lock()
            .recv()
            .await
            .unwrap_or(PeripheralAnswer::Powered(false))
    }
}

/// The peripheral's legacy advertisement, the service data under the UUID.
fn advertisement(beacon: [u8; 9]) -> Advertisement {
    let mut service_data = BTreeMap::new();
    service_data.insert(
        Uuid::from_bytes(crate::beacon::SERVICE_UUID),
        beacon.to_vec(),
    );
    Advertisement {
        advertisement_type: Type::Peripheral,
        service_uuids: BTreeSet::new(),
        manufacturer_data: BTreeMap::new(),
        solicit_uuids: BTreeSet::new(),
        service_data,
        advertising_data: BTreeMap::new(),
        discoverable: None,
        discoverable_timeout: None,
        system_includes: BTreeSet::new(),
        local_name: None,
        appearance: None,
        duration: None,
        timeout: None,
        secondary_channel: None,
        min_interval: None,
        max_interval: None,
        tx_power: None,
        _non_exhaustive: (),
    }
}

#[cfg(test)]
mod tests {
    use super::{PeripheralAnswer, address_of, advertisement, key};
    use bluer::{Address, Uuid};

    #[test]
    fn the_key_folds_the_address_big_endian() {
        let address = Address([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(key(address), 0xaabb_ccdd_eeff);
        assert_eq!(key(Address([0; 6])), 0);
    }

    #[test]
    fn the_address_unfolds_the_key() {
        for device_key in [0u64, 1, 0xff, 0xaabb_ccdd_eeff, 0xffff_ffff_ffff] {
            let address = address_of(device_key);
            assert_eq!(key(address), device_key);
        }
        assert_eq!(
            address_of(0xaabb_ccdd_eeff),
            Address([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn the_advertisement_carries_the_service_data() {
        let beacon = [0x01, 2, 3, 4, 5, 6, 7, 8, 9];
        let advertisement = advertisement(beacon);
        let uuid = Uuid::from_bytes(crate::beacon::SERVICE_UUID);
        assert_eq!(
            advertisement.service_data.get(&uuid),
            Some(&beacon.to_vec())
        );
        assert_eq!(advertisement.service_data.len(), 1);
        assert!(matches!(
            advertisement.advertisement_type,
            bluer::adv::Type::Peripheral
        ));
    }

    #[test]
    fn the_answer_carries_the_session() {
        let answer = PeripheralAnswer::Connected {
            device: 0xaabb_ccdd_eeff,
            mtu: 247,
        };
        match answer {
            PeripheralAnswer::Connected { device, mtu } => {
                assert_eq!(device, 0xaabb_ccdd_eeff);
                assert_eq!(mtu, 247);
            }
            other => panic!("the answer is not a connect, {other:?}"),
        }
    }
}
