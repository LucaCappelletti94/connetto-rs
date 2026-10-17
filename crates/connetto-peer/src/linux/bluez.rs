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
        // The handle stands local until the advertisement stands, so a
        // refusal unregisters the application and the retry's stand is
        // complete.
        let (app, control) = gatt_app(&self.events);
        let app_handle = bounded(CALL_BOUND, adapter.serve_gatt_application(app)).await?;
        let advertisement = advertisement(beacon);
        let handle = bounded(CALL_BOUND, adapter.advertise(advertisement)).await?;
        self.app.lock().replace(app_handle);
        self.adv.lock().replace(handle);
        tokio::spawn(drive_control(
            control,
            self.sessions.clone(),
            self.events.clone(),
        ));
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
    use super::{
        AdapterStanding, BluerBluez, BluezError, BluezIo, CALL_BOUND, PeripheralAnswer, address_of,
        advertisement, key,
    };
    use bluer::{Address, Uuid};
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::io::Read as _;
    use std::sync::Arc;
    use std::time::Duration;
    use zbus::message::Header;
    use zbus::zvariant::{ObjectPath, OwnedFd, OwnedObjectPath, OwnedValue};

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

    const PROBE_NAME: &str =
        "linux::bluez::tests::a_refused_advertisement_restands_its_control_stream";

    /// A refused advertisement's retry restands the control stream, the
    /// notify session and the delivery onto it, over a fake `BlueZ` on a
    /// private bus.
    ///
    /// The `bluer` session connects to whatever `DBUS_SYSTEM_BUS_ADDRESS`
    /// names and the process's environment stays fixed, so the scenario
    /// runs in a re-executed child of this binary, the child's bus the
    /// private daemon's.
    #[tokio::test]
    async fn a_refused_advertisement_restands_its_control_stream() {
        if std::env::var_os("CONNETTO_BLUEZ_PROBE").is_some() {
            bluez_probe().await;
            return;
        }
        let bus = crate::linux::test_bus::PrivateBus::start();
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            tokio::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args(["--exact", PROBE_NAME])
                .env("CONNETTO_BLUEZ_PROBE", "1")
                .env("DBUS_SYSTEM_BUS_ADDRESS", bus.address.as_str())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("the probe did not end within its bound")
        .expect("the probe's output");
        let text = format!(
            "{}{}",
            String::from_utf8(output.stdout).expect("the child's stdout"),
            String::from_utf8(output.stderr).expect("the child's stderr"),
        );
        assert!(output.status.success(), "the probe failed:\n{text}");
    }

    const STANDING_PROBE_NAME: &str =
        "linux::bluez::tests::the_standing_reads_the_power_and_the_events_follow_the_adapter";

    /// The standing reads the adapter's power, a set stands on the
    /// fake and reports its change, and a removed device arrives as
    /// its disconnect, over a fake `BlueZ` on a private bus.
    #[tokio::test]
    async fn the_standing_reads_the_power_and_the_events_follow_the_adapter() {
        if std::env::var_os("CONNETTO_BLUEZ_STANDING_PROBE").is_some() {
            standing_probe().await;
            return;
        }
        let bus = crate::linux::test_bus::PrivateBus::start();
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args(["--exact", STANDING_PROBE_NAME])
                .env("CONNETTO_BLUEZ_STANDING_PROBE", "1")
                .env("DBUS_SYSTEM_BUS_ADDRESS", bus.address.as_str())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("the probe did not end within its bound")
        .expect("the probe's output");
        let text = format!(
            "{}{}",
            String::from_utf8(output.stdout).expect("the child's stdout"),
            String::from_utf8(output.stderr).expect("the child's stderr"),
        );
        assert!(output.status.success(), "the probe failed:\n{text}");
    }

    /// The probe's scenario, the fake `BlueZ` standing on the private
    /// bus the parent pointed `DBUS_SYSTEM_BUS_ADDRESS` at.
    #[expect(
        clippy::too_many_lines,
        reason = "the probe runs the scenario as one straight line"
    )]
    async fn standing_probe() {
        let powered = Arc::new(Mutex::new(false));
        let address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").expect("the probe's bus address");
        let server = zbus::connection::Builder::address(address.as_str())
            .expect("the bus address")
            .name("org.bluez")
            .expect("the service name")
            .serve_at("/", zbus::fdo::ObjectManager)
            .expect("the object manager")
            .serve_at(
                "/org/bluez/hci0",
                FakeAdapter {
                    powered: powered.clone(),
                },
            )
            .expect("the adapter")
            .build()
            .await
            .expect("the bluez service");

        let io = BluerBluez::new().await.expect("the bluez client");
        assert_eq!(
            io.standing().await,
            AdapterStanding::Powered(false),
            "the standing reads the power"
        );

        io.set_powered(true).await.expect("the set stands");
        assert!(*powered.lock(), "the fake recorded the set");
        assert_eq!(
            io.standing().await,
            AdapterStanding::Powered(true),
            "the standing follows the set"
        );

        let mut changed = HashMap::new();
        changed.insert("Powered".to_owned(), OwnedValue::from(true));
        let invalidated: Vec<String> = Vec::new();
        let change = ("org.bluez.Adapter1", &changed, &invalidated);
        let answer = answer_after(
            &io,
            Duration::from_secs(10),
            || {
                emit_signal(
                    &server,
                    "/org/bluez/hci0",
                    "org.freedesktop.DBus.Properties",
                    "PropertiesChanged",
                    &change,
                )
            },
            |answer| matches!(answer, PeripheralAnswer::Powered(true)),
        )
        .await;
        assert!(
            matches!(answer, PeripheralAnswer::Powered(true)),
            "the powered change is its answer"
        );

        io.set_powered(false).await.expect("the set stands");
        assert!(!*powered.lock(), "the fake recorded the set");
        assert_eq!(
            io.standing().await,
            AdapterStanding::Powered(false),
            "the standing follows the set"
        );

        changed.insert("Powered".to_owned(), OwnedValue::from(false));
        let change = ("org.bluez.Adapter1", &changed, &invalidated);
        let answer = answer_after(
            &io,
            Duration::from_secs(10),
            || {
                emit_signal(
                    &server,
                    "/org/bluez/hci0",
                    "org.freedesktop.DBus.Properties",
                    "PropertiesChanged",
                    &change,
                )
            },
            |answer| matches!(answer, PeripheralAnswer::Powered(false)),
        )
        .await;
        assert!(
            matches!(answer, PeripheralAnswer::Powered(false)),
            "the powered change is its answer"
        );

        // The other property change passes over, the removal arrives
        // as its disconnect.
        let mut other = HashMap::new();
        other.insert("Discovering".to_owned(), OwnedValue::from(true));
        let change = ("org.bluez.Adapter1", &other, &invalidated);
        let removed = (
            ObjectPath::try_from("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF").expect("the device path"),
            vec!["org.bluez.Device1".to_owned()],
        );
        let answer = answer_after(
            &io,
            Duration::from_secs(10),
            || async {
                emit_signal(
                    &server,
                    "/org/bluez/hci0",
                    "org.freedesktop.DBus.Properties",
                    "PropertiesChanged",
                    &change,
                )
                .await;
                emit_signal(
                    &server,
                    "/org/freedesktop/DBus/ObjectManager",
                    "org.freedesktop.DBus.ObjectManager",
                    "InterfacesRemoved",
                    &removed,
                )
                .await;
            },
            |answer| matches!(answer, PeripheralAnswer::Disconnected { .. }),
        )
        .await;
        let device = key(Address([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert!(
            matches!(&answer, PeripheralAnswer::Disconnected { device: other } if *other == device),
            "the removal is its disconnect, {answer:?}"
        );
    }

    const NO_ADAPTER_PROBE_NAME: &str =
        "linux::bluez::tests::the_missing_adapter_stands_none_and_refuses_the_calls";

    /// The missing adapter stands the none standing and refuses the
    /// power and start calls, over a `BlueZ` service with no adapter
    /// on a private bus.
    #[tokio::test]
    async fn the_missing_adapter_stands_none_and_refuses_the_calls() {
        if std::env::var_os("CONNETTO_BLUEZ_NO_ADAPTER_PROBE").is_some() {
            missing_adapter_probe().await;
            return;
        }
        let bus = crate::linux::test_bus::PrivateBus::start();
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args(["--exact", NO_ADAPTER_PROBE_NAME])
                .env("CONNETTO_BLUEZ_NO_ADAPTER_PROBE", "1")
                .env("DBUS_SYSTEM_BUS_ADDRESS", bus.address.as_str())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("the probe did not end within its bound")
        .expect("the probe's output");
        let text = format!(
            "{}{}",
            String::from_utf8(output.stdout).expect("the child's stdout"),
            String::from_utf8(output.stderr).expect("the child's stderr"),
        );
        assert!(output.status.success(), "the probe failed:\n{text}");
    }

    /// The probe's scenario, the `BlueZ` service with no adapter on
    /// the private bus.
    async fn missing_adapter_probe() {
        let address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").expect("the probe's bus address");
        let _server = zbus::connection::Builder::address(address.as_str())
            .expect("the bus address")
            .name("org.bluez")
            .expect("the service name")
            .serve_at("/", zbus::fdo::ObjectManager)
            .expect("the object manager")
            .build()
            .await
            .expect("the bluez service");

        let io = BluerBluez::new()
            .await
            .expect("the client stands without an adapter");
        assert_eq!(
            io.standing().await,
            AdapterStanding::None,
            "the standing is the missing adapter"
        );
        let err = io.set_powered(true).await.expect_err("the set is refused");
        assert!(
            matches!(err, BluezError::Refused(_)),
            "the refusal is the missing adapter, {err:?}"
        );
        let err = io.start([1; 9]).await.expect_err("the start is refused");
        assert!(
            matches!(err, BluezError::Refused(_)),
            "the refusal is the missing adapter, {err:?}"
        );
        io.disconnect(0).await;
        let err = io
            .notify(0, b"none")
            .await
            .expect_err("the notify is refused");
        assert!(
            matches!(err, BluezError::Closed),
            "the refusal is the closed session, {err:?}"
        );
    }

    const RESTART_PROBE_NAME: &str =
        "linux::bluez::tests::a_second_start_readvertises_under_the_standing_application";

    /// A second start restands the advertisement under the standing
    /// GATT application, the application itself kept, over a fake
    /// `BlueZ` on a private bus.
    #[tokio::test]
    async fn a_second_start_readvertises_under_the_standing_application() {
        if std::env::var_os("CONNETTO_BLUEZ_RESTART_PROBE").is_some() {
            restart_probe().await;
            return;
        }
        let bus = crate::linux::test_bus::PrivateBus::start();
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args(["--exact", RESTART_PROBE_NAME])
                .env("CONNETTO_BLUEZ_RESTART_PROBE", "1")
                .env("DBUS_SYSTEM_BUS_ADDRESS", bus.address.as_str())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("the probe did not end within its bound")
        .expect("the probe's output");
        let text = format!(
            "{}{}",
            String::from_utf8(output.stdout).expect("the child's stdout"),
            String::from_utf8(output.stderr).expect("the child's stderr"),
        );
        assert!(output.status.success(), "the probe failed:\n{text}");
    }

    /// The probe's scenario, the standing application and the two
    /// advertisements, over a fake `BlueZ` on the private bus the
    /// parent pointed `DBUS_SYSTEM_BUS_ADDRESS` at.
    async fn restart_probe() {
        let registration = Arc::new(Mutex::new(None));
        let unregisters = Arc::new(Mutex::new(0));
        let registers = Arc::new(Mutex::new(0));
        let attempts = Arc::new(Mutex::new(0));
        let adv_unregisters = Arc::new(Mutex::new(0));
        let address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").expect("the probe's bus address");
        let _server = zbus::connection::Builder::address(address.as_str())
            .expect("the bus address")
            .name("org.bluez")
            .expect("the service name")
            .serve_at("/", zbus::fdo::ObjectManager)
            .expect("the object manager")
            .serve_at(
                "/org/bluez/hci0",
                FakeAdapter {
                    powered: Arc::new(Mutex::new(true)),
                },
            )
            .expect("the adapter")
            .serve_at(
                "/org/bluez/hci0",
                FakeGatt {
                    registration: registration.clone(),
                    unregisters: unregisters.clone(),
                    registers: registers.clone(),
                },
            )
            .expect("the gatt manager")
            .serve_at(
                "/org/bluez/hci0",
                FakeAds {
                    attempts: attempts.clone(),
                    refuse_first: false,
                    adv_unregisters: adv_unregisters.clone(),
                },
            )
            .expect("the advertisement manager")
            .build()
            .await
            .expect("the bluez service");

        let io = BluerBluez::new().await.expect("the bluez client");
        io.start([1; 9]).await.expect("the first start stands");
        io.start([2; 9]).await.expect("the second start stands");
        assert_eq!(*registers.lock(), 1, "the application stands once");
        assert_eq!(*attempts.lock(), 2, "the advertisement stands twice");
        io.stop().await;
    }

    const SESSIONS_PROBE_NAME: &str =
        "linux::bluez::tests::the_central_write_and_the_sessions_drive_their_answers";

    /// The central's write arrives as its chunk, the notify sessions
    /// hand their MTUs and end as their disconnects, a write past the
    /// session's MTU or without a session is refused, a dropped
    /// session's device gets its disconnect, and a full delivery
    /// queue times out, over a fake `BlueZ` on a private bus.
    #[tokio::test]
    async fn the_central_write_and_the_sessions_drive_their_answers() {
        if std::env::var_os("CONNETTO_BLUEZ_SESSIONS_PROBE").is_some() {
            sessions_probe().await;
            return;
        }
        let bus = crate::linux::test_bus::PrivateBus::start();
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args(["--exact", SESSIONS_PROBE_NAME])
                .env("CONNETTO_BLUEZ_SESSIONS_PROBE", "1")
                .env("DBUS_SYSTEM_BUS_ADDRESS", bus.address.as_str())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("the probe did not end within its bound")
        .expect("the probe's output");
        let text = format!(
            "{}{}",
            String::from_utf8(output.stdout).expect("the child's stdout"),
            String::from_utf8(output.stderr).expect("the child's stderr"),
        );
        assert!(output.status.success(), "the probe failed:\n{text}");
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the probe runs the whole scenario as one straight line"
    )]
    /// The probe's scenario, the fake `BlueZ` standing on the private
    /// bus the parent pointed `DBUS_SYSTEM_BUS_ADDRESS` at.
    async fn sessions_probe() {
        let registration = Arc::new(Mutex::new(None));
        let unregisters = Arc::new(Mutex::new(0));
        let registers = Arc::new(Mutex::new(0));
        let attempts = Arc::new(Mutex::new(0));
        let disconnects_aa = Arc::new(Mutex::new(0));
        let disconnects_bb = Arc::new(Mutex::new(0));
        let adv_unregisters = Arc::new(Mutex::new(0));
        let address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").expect("the probe's bus address");
        let server = zbus::connection::Builder::address(address.as_str())
            .expect("the bus address")
            .name("org.bluez")
            .expect("the service name")
            .serve_at("/", zbus::fdo::ObjectManager)
            .expect("the object manager")
            .serve_at(
                "/org/bluez/hci0",
                FakeAdapter {
                    powered: Arc::new(Mutex::new(true)),
                },
            )
            .expect("the adapter")
            .serve_at(
                "/org/bluez/hci0",
                FakeGatt {
                    registration: registration.clone(),
                    unregisters: unregisters.clone(),
                    registers: registers.clone(),
                },
            )
            .expect("the gatt manager")
            .serve_at(
                "/org/bluez/hci0",
                FakeAds {
                    attempts: attempts.clone(),
                    refuse_first: false,
                    adv_unregisters: adv_unregisters.clone(),
                },
            )
            .expect("the advertisement manager")
            .serve_at(
                "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF",
                FakeDevice {
                    disconnects: disconnects_aa.clone(),
                },
            )
            .expect("the device")
            .serve_at(
                "/org/bluez/hci0/dev_11_22_33_44_55_66",
                FakeDevice {
                    disconnects: disconnects_bb.clone(),
                },
            )
            .expect("the device")
            .build()
            .await
            .expect("the bluez service");

        let io = BluerBluez::new().await.expect("the bluez client");
        io.start([1; 9]).await.expect("the start stands");

        let (sender, application) = registration.lock().clone().expect("the gatt application");
        let manager = zbus::fdo::ObjectManagerProxy::builder(&server)
            .destination(sender.as_str())
            .expect("the application owner")
            .path(application.as_str())
            .expect("the application path")
            .build()
            .await
            .expect("the application manager proxy");
        let paths: Vec<(String, Vec<String>)> = manager
            .get_managed_objects()
            .await
            .expect("the application objects")
            .into_iter()
            .filter_map(|(path, interfaces)| {
                let props = interfaces.get("org.bluez.GattCharacteristic1")?;
                let flags = Vec::<String>::try_from(props.get("Flags")?.try_clone().ok()?).ok()?;
                Some((path.to_string(), flags))
            })
            .collect();
        let outbox = paths
            .iter()
            .find(|(_, flags)| flags.iter().any(|flag| flag == "notify"))
            .expect("the outbox characteristic")
            .0
            .clone();
        let inbox = paths
            .iter()
            .find(|(_, flags)| flags.iter().any(|flag| flag == "write"))
            .expect("the inbox characteristic")
            .0
            .clone();

        let device_aa = key(Address([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        let device_bb = key(Address([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));

        let outbox_proxy = zbus::Proxy::new(
            &server,
            sender.as_str(),
            outbox.as_str(),
            "org.bluez.GattCharacteristic1",
        )
        .await
        .expect("the outbox proxy");
        let options = HashMap::from([
            (
                "device".to_owned(),
                OwnedValue::from(
                    ObjectPath::try_from("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF")
                        .expect("the device path"),
                ),
            ),
            ("mtu".to_owned(), OwnedValue::from(64_u16)),
        ]);
        let read: Vec<u8> = outbox_proxy
            .call("ReadValue", &(&options,))
            .await
            .expect("the read stands");
        assert!(read.is_empty(), "the read answers empty");

        let inbox_proxy = zbus::Proxy::new(
            &server,
            sender.as_str(),
            inbox.as_str(),
            "org.bluez.GattCharacteristic1",
        )
        .await
        .expect("the inbox proxy");
        let inbox_options = HashMap::from([
            (
                "device".to_owned(),
                OwnedValue::from(
                    ObjectPath::try_from("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF")
                        .expect("the device path"),
                ),
            ),
            ("mtu".to_owned(), OwnedValue::from(23_u16)),
        ]);
        inbox_proxy
            .call::<_, _, ()>("WriteValue", &(vec![1_u8, 2, 3], &inbox_options))
            .await
            .expect("the write stands");

        let answer = answer_bounded(&io).await;
        assert!(
            matches!(&answer, PeripheralAnswer::Chunk { device, bytes } if *device == device_aa && *bytes == [1, 2, 3]),
            "the write is its chunk, {answer:?}"
        );

        let (fd, _mtu): (OwnedFd, u16) = outbox_proxy
            .call("AcquireNotify", &(options,))
            .await
            .expect("acquire the notify session");

        let answer = answer_bounded(&io).await;
        assert!(
            matches!(&answer, PeripheralAnswer::Connected { device, mtu } if *device == device_aa && *mtu == 59),
            "the session is its connect, {answer:?}"
        );

        io.notify(device_aa, b"ping")
            .await
            .expect("the delivery stands");
        let fd = std::os::fd::OwnedFd::from(fd);
        let mut file = std::fs::File::from(fd);
        let mut bytes = [0_u8; 4];
        file.read_exact(&mut bytes)
            .expect("the bytes reach the central");
        assert_eq!(&bytes, b"ping");

        // The session's end arrives as its disconnect.
        drop(file);
        let answer = answer_bounded(&io).await;
        assert!(
            matches!(&answer, PeripheralAnswer::Disconnected { device } if *device == device_aa),
            "the session's end is its disconnect, {answer:?}"
        );

        let err = io
            .notify(device_aa, b"none")
            .await
            .expect_err("the refusal stands");
        assert!(
            matches!(err, BluezError::Closed),
            "the refusal is the closed session, {err:?}"
        );

        // A session below the write's length refuses the delivery.
        let options = HashMap::from([
            (
                "device".to_owned(),
                OwnedValue::from(
                    ObjectPath::try_from("/org/bluez/hci0/dev_11_22_33_44_55_66")
                        .expect("the device path"),
                ),
            ),
            ("mtu".to_owned(), OwnedValue::from(5_u16)),
        ]);
        let (_fd, _mtu): (OwnedFd, u16) = outbox_proxy
            .call("AcquireNotify", &(options,))
            .await
            .expect("acquire the session");

        let answer = answer_bounded(&io).await;
        assert!(
            matches!(&answer, PeripheralAnswer::Connected { device, mtu } if *device == device_bb && *mtu == 0),
            "the session is its connect, {answer:?}"
        );

        let err = io
            .notify(device_bb, b"ping")
            .await
            .expect_err("the refusal stands");
        assert!(
            matches!(err, BluezError::Closed),
            "the refusal is the closed write, {err:?}"
        );

        // The disconnect ends the session and calls the device's
        // disconnect.
        io.disconnect(device_bb).await;
        assert_eq!(*disconnects_bb.lock(), 1, "the device's disconnect stands");
        let err = io
            .notify(device_bb, b"none")
            .await
            .expect_err("the refusal stands");
        assert!(
            matches!(err, BluezError::Closed),
            "the refusal is the dropped session, {err:?}"
        );

        // A delivery past the bound is the timeout's refusal, the
        // central's queue full.
        let options = HashMap::from([
            (
                "device".to_owned(),
                OwnedValue::from(
                    ObjectPath::try_from("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF")
                        .expect("the device path"),
                ),
            ),
            ("mtu".to_owned(), OwnedValue::from(64_u16)),
        ]);
        let (fd, _mtu): (OwnedFd, u16) = outbox_proxy
            .call("AcquireNotify", &(options,))
            .await
            .expect("acquire the session");

        let answer = answer_bounded(&io).await;
        assert!(
            matches!(&answer, PeripheralAnswer::Connected { device, mtu } if *device == device_aa && *mtu == 59),
            "the session is its connect, {answer:?}"
        );

        let chunk: [u8; 59] = [0xab; 59];
        let mut timed_out = false;
        for _ in 0..10000 {
            match io.notify(device_aa, &chunk).await {
                Ok(()) => {}
                Err(BluezError::TimedOut(bound)) => {
                    assert_eq!(bound, CALL_BOUND, "the bound is the call's");
                    timed_out = true;
                    break;
                }
                Err(other) => panic!("the delivery is refused, {other:?}"),
            }
        }
        assert!(timed_out, "the full queue does not stall the delivery");
        drop(fd);
        io.stop().await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while *adv_unregisters.lock() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the stop unregisters the advertisement");
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the probe runs the whole scenario as one straight line"
    )]
    /// The probe's scenario, the fake `BlueZ` standing on the private bus
    /// the parent pointed `DBUS_SYSTEM_BUS_ADDRESS` at.
    async fn bluez_probe() {
        let registration: Arc<Mutex<Option<(String, OwnedObjectPath)>>> =
            Arc::new(Mutex::new(None));
        let unregisters: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let attempts: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let registers: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let adv_unregisters: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").expect("the probe's bus address");
        let server = zbus::connection::Builder::address(address.as_str())
            .expect("the bus address")
            .name("org.bluez")
            .expect("the service name")
            .serve_at("/", zbus::fdo::ObjectManager)
            .expect("the object manager")
            .serve_at(
                "/org/bluez/hci0",
                FakeAdapter {
                    powered: Arc::new(Mutex::new(true)),
                },
            )
            .expect("the adapter")
            .serve_at(
                "/org/bluez/hci0",
                FakeGatt {
                    registration: registration.clone(),
                    unregisters: unregisters.clone(),
                    registers: registers.clone(),
                },
            )
            .expect("the gatt manager")
            .serve_at(
                "/org/bluez/hci0",
                FakeAds {
                    attempts: attempts.clone(),
                    refuse_first: true,
                    adv_unregisters: adv_unregisters.clone(),
                },
            )
            .expect("the advertisement manager")
            .build()
            .await
            .expect("the bluez service");

        let io = BluerBluez::new().await.expect("the bluez client");
        assert!(
            io.start([1; 9]).await.is_err(),
            "the first advertisement stands"
        );
        the_refusal_unregisters(&unregisters).await;
        io.start([2; 9])
            .await
            .expect("the retry's advertisement stands");

        let (sender, application) = registration.lock().clone().expect("the gatt application");
        let manager = zbus::fdo::ObjectManagerProxy::builder(&server)
            .destination(sender.as_str())
            .expect("the application owner")
            .path(application.as_str())
            .expect("the application path")
            .build()
            .await
            .expect("the application manager proxy");
        let outbox = manager
            .get_managed_objects()
            .await
            .expect("the application objects")
            .into_iter()
            .find_map(|(path, interfaces)| {
                let props = interfaces.get("org.bluez.GattCharacteristic1")?;
                let flags = Vec::<String>::try_from(props.get("Flags")?.try_clone().ok()?).ok()?;
                flags.iter().any(|flag| flag == "notify").then_some(path)
            })
            .expect("the outbox characteristic");
        let proxy = zbus::Proxy::new(
            &server,
            sender.as_str(),
            outbox.as_str(),
            "org.bluez.GattCharacteristic1",
        )
        .await
        .expect("the outbox proxy");
        let options = HashMap::from([
            (
                "device".to_owned(),
                OwnedValue::from(
                    ObjectPath::try_from("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF")
                        .expect("the device path"),
                ),
            ),
            ("mtu".to_owned(), OwnedValue::from(64_u16)),
        ]);
        let (fd, _mtu): (OwnedFd, u16) = proxy
            .call("AcquireNotify", &(options,))
            .await
            .expect("acquire the notify session");

        let device = loop {
            let answer = tokio::time::timeout(std::time::Duration::from_secs(10), io.next_event())
                .await
                .expect("no peripheral event within the bound");
            if let PeripheralAnswer::Connected { device, .. } = answer {
                break device;
            }
        };
        assert_eq!(device, key(Address([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])));

        io.notify(device, b"ping")
            .await
            .expect("the delivery stands");
        let fd = std::os::fd::OwnedFd::from(fd);
        let mut file = std::fs::File::from(fd);
        let mut bytes = [0_u8; 4];
        file.read_exact(&mut bytes)
            .expect("the bytes reach the central");
        assert_eq!(&bytes, b"ping");

        io.stop().await;
    }

    /// Polls the `unregisters` count past zero until its bound.
    async fn the_refusal_unregisters(unregisters: &Arc<Mutex<u32>>) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while *unregisters.lock() == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the refusal unregisters the gatt application");
    }

    const SLOW_PROBE_NAME: &str = "linux::bluez::tests::a_slow_answer_times_out_on_the_call_bound";

    /// A slow adapter's answer times out the call bound in the
    /// constructor, over a slow fake `BlueZ` on a private bus.
    #[tokio::test]
    async fn a_slow_answer_times_out_on_the_call_bound() {
        if std::env::var_os("CONNETTO_BLUEZ_SLOW_PROBE").is_some() {
            slow_probe().await;
            return;
        }
        let bus = crate::linux::test_bus::PrivateBus::start();
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args(["--exact", SLOW_PROBE_NAME])
                .env("CONNETTO_BLUEZ_SLOW_PROBE", "1")
                .env("DBUS_SYSTEM_BUS_ADDRESS", bus.address.as_str())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("the probe did not end within its bound")
        .expect("the probe's output");
        let text = format!(
            "{}{}",
            String::from_utf8(output.stdout).expect("the child's stdout"),
            String::from_utf8(output.stderr).expect("the child's stderr"),
        );
        assert!(output.status.success(), "the probe failed:\n{text}");
    }

    /// The probe's scenario, the slow fake adapter on the private bus
    /// the parent pointed `DBUS_SYSTEM_BUS_ADDRESS` at.
    async fn slow_probe() {
        let address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").expect("the probe's bus address");
        let _server = zbus::connection::Builder::address(address.as_str())
            .expect("the bus address")
            .name("org.bluez")
            .expect("the service name")
            .serve_at("/", zbus::fdo::ObjectManager)
            .expect("the object manager")
            .serve_at("/org/bluez/hci0", SlowAdapter)
            .expect("the adapter")
            .build()
            .await
            .expect("the bluez service");

        let Err(err) = BluerBluez::new().await else {
            panic!("the session stands over a slow adapter")
        };
        assert!(
            matches!(err, BluezError::TimedOut(CALL_BOUND)),
            "the slow answer times out the call bound, {err:?}"
        );
    }

    const BROKEN_OM_PROBE_NAME: &str =
        "linux::bluez::tests::a_missing_object_manager_refuses_the_constructor";

    /// The constructor refuses a `BlueZ` without its object manager,
    /// the adapter standing alone on the private bus.
    #[tokio::test]
    async fn a_missing_object_manager_refuses_the_constructor() {
        if std::env::var_os("CONNETTO_BLUEZ_BROKEN_OM_PROBE").is_some() {
            broken_om_probe().await;
            return;
        }
        let bus = crate::linux::test_bus::PrivateBus::start();
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args(["--exact", BROKEN_OM_PROBE_NAME])
                .env("CONNETTO_BLUEZ_BROKEN_OM_PROBE", "1")
                .env("DBUS_SYSTEM_BUS_ADDRESS", bus.address.as_str())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("the probe did not end within its bound")
        .expect("the probe's output");
        let text = format!(
            "{}{}",
            String::from_utf8(output.stdout).expect("the child's stdout"),
            String::from_utf8(output.stderr).expect("the child's stderr"),
        );
        assert!(output.status.success(), "the probe failed:\n{text}");
    }

    /// The probe's scenario, the fake `BlueZ` standing without its
    /// object manager on the private bus.
    async fn broken_om_probe() {
        let address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").expect("the probe's bus address");
        let _server = zbus::connection::Builder::address(address.as_str())
            .expect("the bus address")
            .name("org.bluez")
            .expect("the service name")
            .serve_at(
                "/org/bluez/hci0",
                FakeAdapter {
                    powered: Arc::new(Mutex::new(true)),
                },
            )
            .expect("the adapter")
            .build()
            .await
            .expect("the bluez service");

        let Err(err) = BluerBluez::new().await else {
            panic!("the session stands over a missing object manager")
        };
        assert!(
            matches!(err, BluezError::Refused(_)),
            "the refusal is the missing object manager, {err:?}"
        );
    }

    const SLOW_SET_PROBE_NAME: &str = "linux::bluez::tests::a_slow_set_times_out_on_the_call_bound";

    /// A slow set times out the call bound, the standing still reading,
    /// over a slow-setter fake `BlueZ` on a private bus.
    #[tokio::test]
    async fn a_slow_set_times_out_on_the_call_bound() {
        if std::env::var_os("CONNETTO_BLUEZ_SLOW_SET_PROBE").is_some() {
            slow_set_probe().await;
            return;
        }
        let bus = crate::linux::test_bus::PrivateBus::start();
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args(["--exact", SLOW_SET_PROBE_NAME])
                .env("CONNETTO_BLUEZ_SLOW_SET_PROBE", "1")
                .env("DBUS_SYSTEM_BUS_ADDRESS", bus.address.as_str())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("the probe did not end within its bound")
        .expect("the probe's output");
        let text = format!(
            "{}{}",
            String::from_utf8(output.stdout).expect("the child's stdout"),
            String::from_utf8(output.stderr).expect("the child's stderr"),
        );
        assert!(output.status.success(), "the probe failed:\n{text}");
    }

    /// The probe's scenario, the slow-setter fake adapter on the
    /// private bus the parent pointed `DBUS_SYSTEM_BUS_ADDRESS` at.
    async fn slow_set_probe() {
        let address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").expect("the probe's bus address");
        let _server = zbus::connection::Builder::address(address.as_str())
            .expect("the bus address")
            .name("org.bluez")
            .expect("the service name")
            .serve_at("/", zbus::fdo::ObjectManager)
            .expect("the object manager")
            .serve_at(
                "/org/bluez/hci0",
                SlowSetterAdapter {
                    powered: Arc::new(Mutex::new(true)),
                },
            )
            .expect("the adapter")
            .build()
            .await
            .expect("the bluez service");

        let io = BluerBluez::new().await.expect("the bluez client");
        assert_eq!(
            io.standing().await,
            AdapterStanding::Powered(true),
            "the standing reads the fast property"
        );
        let err = io.set_powered(false).await.expect_err("the set times out");
        assert!(
            matches!(err, BluezError::TimedOut(CALL_BOUND)),
            "the slow set times out the call bound, {err:?}"
        );
    }

    const NEW_PROBE_NAME: &str = "linux::bluez::tests::new_refuses_an_unreachable_system_bus";

    /// The constructor refuses an unreachable system bus. The `bluer`
    /// session reads the process's `DBUS_SYSTEM_BUS_ADDRESS`, so the
    /// scenario runs in a re-executed child pointed at an absent
    /// socket, the child's environment the only one changed.
    #[tokio::test]
    async fn new_refuses_an_unreachable_system_bus() {
        if std::env::var_os("CONNETTO_BLUEZ_NEW_PROBE").is_some() {
            let Err(err) = BluerBluez::new().await else {
                panic!("the session stands over an absent bus")
            };
            assert!(
                matches!(err, BluezError::Refused(_)),
                "the refusal is the unreachable bus, {err:?}"
            );
            return;
        }
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args(["--exact", NEW_PROBE_NAME])
                .env("CONNETTO_BLUEZ_NEW_PROBE", "1")
                .env(
                    "DBUS_SYSTEM_BUS_ADDRESS",
                    "unix:path=/run/connetto-proof/absent-socket",
                )
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("the probe did not end within its bound")
        .expect("the probe's output");
        let text = format!(
            "{}{}",
            String::from_utf8(output.stdout).expect("the child's stdout"),
            String::from_utf8(output.stderr).expect("the child's stderr"),
        );
        assert!(output.status.success(), "the probe failed:\n{text}");
    }

    /// Emit a signal on the fake's service connection, the client's
    /// match rules its receiver.
    async fn emit_signal(
        bus: &zbus::Connection,
        path: &str,
        interface: &str,
        member: &str,
        body: &(impl serde::Serialize + zbus::zvariant::DynamicType),
    ) {
        let message = zbus::Message::signal(path, interface, member)
            .expect("the signal stands")
            .build(body)
            .expect("the signal body serializes");
        bus.send(&message)
            .await
            .expect("the signal reaches the bus");
    }

    /// The first answer of the kind `wanted` names, `emit` sent again
    /// until it arrives within its bound, answers of other kinds
    /// passed over.
    async fn answer_after<F: Future<Output = ()>>(
        io: &BluerBluez,
        bound: Duration,
        emit: impl Fn() -> F,
        wanted: impl Fn(&PeripheralAnswer) -> bool,
    ) -> PeripheralAnswer {
        let deadline = tokio::time::Instant::now() + bound;
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the answer did not arrive within its bound"
            );
            emit().await;
            while let Ok(answer) =
                tokio::time::timeout(Duration::from_millis(200), io.next_event()).await
            {
                if wanted(&answer) {
                    return answer;
                }
            }
        }
    }

    /// The next answer within its bound, the bound's end a failure.
    async fn answer_bounded(io: &BluerBluez) -> PeripheralAnswer {
        tokio::time::timeout(Duration::from_secs(5), io.next_event())
            .await
            .expect("no answer within the bound")
    }

    struct FakeAdapter {
        powered: Arc<Mutex<bool>>,
    }

    #[zbus::interface(name = "org.bluez.Adapter1")]
    impl FakeAdapter {
        #[zbus(property)]
        fn powered(&self) -> bool {
            *self.powered.lock()
        }

        #[zbus(property)]
        fn set_powered(&self, value: bool) {
            *self.powered.lock() = value;
        }
    }

    struct SlowAdapter;

    #[zbus::interface(name = "org.bluez.Adapter1")]
    impl SlowAdapter {
        #[zbus(property)]
        async fn powered(&self) -> bool {
            tokio::time::sleep(Duration::from_secs(6)).await;
            true
        }
    }

    struct SlowSetterAdapter {
        powered: Arc<Mutex<bool>>,
    }

    #[zbus::interface(name = "org.bluez.Adapter1")]
    impl SlowSetterAdapter {
        #[zbus(property)]
        fn powered(&self) -> bool {
            *self.powered.lock()
        }

        #[zbus(property)]
        async fn set_powered(&self, value: bool) {
            *self.powered.lock() = value;
            tokio::time::sleep(Duration::from_secs(6)).await;
        }
    }

    struct FakeGatt {
        registration: Arc<Mutex<Option<(String, OwnedObjectPath)>>>,
        unregisters: Arc<Mutex<u32>>,
        registers: Arc<Mutex<u32>>,
    }

    #[zbus::interface(name = "org.bluez.GattManager1")]
    impl FakeGatt {
        #[expect(
            clippy::needless_pass_by_value,
            reason = "the zbus header attribute takes the header by value"
        )]
        fn register_application(
            &self,
            application: OwnedObjectPath,
            options: HashMap<String, OwnedValue>,
            #[zbus(header)] header: Header<'_>,
        ) {
            *self.registers.lock() += 1;
            std::mem::drop(options);
            let sender = header.sender().expect("the request sender").to_string();
            self.registration.lock().replace((sender, application));
        }

        fn unregister_application(&self, application: OwnedObjectPath) {
            std::mem::drop(application);
            *self.unregisters.lock() += 1;
            self.registration.lock().take();
        }
    }

    #[derive(Debug, zbus::DBusError)]
    #[zbus(prefix = "org.bluez.Error")]
    enum ProbeRefusal {
        Failed(String),
    }

    struct FakeAds {
        attempts: Arc<Mutex<u32>>,
        refuse_first: bool,
        adv_unregisters: Arc<Mutex<u32>>,
    }

    #[zbus::interface(name = "org.bluez.LEAdvertisingManager1")]
    impl FakeAds {
        fn register_advertisement(
            &self,
            advertisement: OwnedObjectPath,
            options: HashMap<String, OwnedValue>,
        ) -> Result<(), ProbeRefusal> {
            std::mem::drop(advertisement);
            std::mem::drop(options);
            let mut attempts = self.attempts.lock();
            *attempts += 1;
            if self.refuse_first && *attempts == 1 {
                Err(ProbeRefusal::Failed(
                    "the first advertisement refused".into(),
                ))
            } else {
                Ok(())
            }
        }

        fn unregister_advertisement(&self, advertisement: OwnedObjectPath) {
            *self.adv_unregisters.lock() += 1;
            std::mem::drop(advertisement);
        }
    }

    struct FakeDevice {
        disconnects: Arc<Mutex<u32>>,
    }

    #[zbus::interface(name = "org.bluez.Device1")]
    impl FakeDevice {
        fn disconnect(&self) {
            *self.disconnects.lock() += 1;
        }
    }
}
