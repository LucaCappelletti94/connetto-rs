//! The host's GATT service and beacon advertisement, over the process-wide
//! peripheral manager on its one serial queue (R76).

use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, mpsc};
use std::time::Duration;

use dispatch2::{DispatchQueue, DispatchRetained};
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{AnyThread, Message, define_class, msg_send};
use objc2_core_bluetooth::{
    CBATTError, CBATTRequest, CBAdvertisementDataServiceUUIDsKey, CBAttributePermissions,
    CBCentral, CBCharacteristic, CBCharacteristicProperties, CBError, CBManager,
    CBManagerAuthorization, CBManagerState, CBMutableCharacteristic, CBMutableService,
    CBPeripheralManager, CBPeripheralManagerDelegate, CBPeripheralManagerOptionShowPowerAlertKey,
    CBService, CBUUID,
};
use objc2_foundation::{
    NSArray, NSData, NSDictionary, NSError, NSNumber, NSObject, NSObjectProtocol, NSString, NSUUID,
};
use parking_lot::Mutex;

use connetto_peer::{INBOX_UUID, OUTBOX_UUID, SERVICE_UUID};

use crate::bluetooth::{Event, PromptOutcome, State};
use crate::{Error, HOP_WITHIN, key_from_uuid_text};

/// The bound one hop onto the manager's queue gets.
const HOP: Duration = HOP_WITHIN;

/// What the manager's queue and its delegate stand at.
#[derive(Default)]
struct Standing {
    /// The manager's dedicated queue.
    queue: Option<DispatchRetained<DispatchQueue>>,
    /// The manager, alive for the process.
    manager: Option<Retained<CBPeripheralManager>>,
    /// The manager's delegate, alive for the process.
    delegate: Option<Retained<PeripheralDelegate>>,
    /// The service the centrals discover.
    service: Option<Retained<CBMutableService>>,
    /// The characteristic the centrals write to.
    inbox: Option<Retained<CBMutableCharacteristic>>,
    /// The characteristic the centrals subscribe to.
    outbox: Option<Retained<CBMutableCharacteristic>>,
    /// The platform's standing of the radio.
    radio: Option<CBManagerState>,
    /// The centrals subscribed to the outbox, by key.
    centrals: HashMap<u64, Retained<CBCentral>>,
    /// The frames the platform has not yet taken, by central's key.
    held: HashMap<u64, VecDeque<Vec<u8>>>,
    /// The advertisement is live.
    advertising: bool,
    /// Where the service's registration with the platform stands.
    registration: Registration,
    /// The host wants the service and the advertisement.
    wanted: bool,
}

/// Where the service's registration with the platform stands.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Registration {
    /// No service is registered or being added.
    #[default]
    Absent,
    /// A service add is in flight on the platform's queue.
    Adding,
    /// The service is registered.
    Registered,
}

static STANDING: LazyLock<Mutex<Standing>> = LazyLock::new(|| Mutex::new(Standing::default()));
// SAFETY: every field is read and written only under the one STANDING lock,
// the manager and its objects are dispatched only to the manager's one
// serial queue, and the platform's retain and release are thread-safe.
unsafe impl Send for Standing {}
static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

/// The radio's standing. Before the manager exists the app's Bluetooth
/// authorization answers, and an app the user already allowed creates the
/// manager at once, without the power alert, to learn the radio's standing.
pub(crate) fn state() -> State {
    let (exists, radio) = {
        let standing = STANDING.lock();
        (standing.manager.is_some(), standing.radio)
    };
    if !exists {
        // SAFETY: the class property reads the app's standing and takes no
        // argument.
        let authorization = unsafe { CBManager::authorization_class() };
        if authorization != CBManagerAuthorization::AllowedAlways {
            return State::NotPermitted;
        }
        ensure_manager(false, false);
        return State::Off;
    }
    match radio {
        Some(CBManagerState::PoweredOn) => State::Ready,
        Some(CBManagerState::Unauthorized) => State::NotPermitted,
        Some(CBManagerState::Unsupported) => State::Unsupported,
        _ => State::Off,
    }
}

/// Run the platform's strongest action once.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the unsupported platform's prompt refuses, and both answer the one signature lib.rs exposes"
)]
pub(crate) fn prompt() -> Result<(), Error> {
    // A recreated manager re-shows the platform's power alert where the
    // radio stands off. An existing manager whose radio is on has nothing to
    // show.
    let recreate = {
        let standing = STANDING.lock();
        standing.manager.is_some() && standing.radio == Some(CBManagerState::PoweredOff)
    };
    ensure_manager(recreate, true);
    Ok(())
}

/// The last prompt's outcome, once it settles.
pub(crate) fn prompt_outcome() -> Option<PromptOutcome> {
    let standing = STANDING.lock();
    match standing.radio {
        Some(CBManagerState::PoweredOn) => Some(PromptOutcome::NotAsked),
        Some(CBManagerState::Unauthorized) => Some(PromptOutcome::Declined),
        _ => None,
    }
}

/// Open the GATT service and begin its beacon advertisement.
pub(crate) fn start() -> Result<(), Error> {
    ensure_manager(false, true);
    hop(|standing| {
        if standing.radio != Some(CBManagerState::PoweredOn) {
            return Err(off_error());
        }
        if standing.advertising {
            return Ok(());
        }
        standing.wanted = true;
        match standing.registration {
            Registration::Registered => begin_advertising(standing),
            Registration::Absent => add_service(standing),
            Registration::Adding => {}
        }
        // A pending add settles on the platform's queue and
        // answers the advertisement itself.
        Ok(())
    })
    .and_then(|answer| answer)
}

/// Stop the advertisement and close the service.
pub(crate) fn stop() -> Result<(), Error> {
    hop(|standing| {
        let Some(manager) = standing.manager.as_ref() else {
            return Ok(());
        };
        standing.wanted = false;
        if standing.advertising {
            // SAFETY: the manager is alive for the process, and the
            // platform's stop answers nothing to return.
            unsafe { manager.stopAdvertising() };
        }
        if standing.registration == Registration::Registered {
            // SAFETY: the manager is alive for the process, and the
            // platform's removal answers nothing to return. The removal is
            // done when the call returns, the platform reporting nothing
            // after it.
            unsafe { manager.removeAllServices() };
            standing.registration = Registration::Absent;
            standing.service = None;
            standing.inbox = None;
            standing.outbox = None;
        }
        clear_subscribers(standing);
        Ok(())
    })
    .and_then(|answer| answer)
}

/// Take the events the service has reported since the last call.
pub(crate) fn poll() -> Vec<Event> {
    std::mem::take(&mut *EVENTS.lock())
}

/// Send one outbox notification to a subscribed central.
pub(crate) fn notify(device: u64, bytes: &[u8]) -> Result<(), Error> {
    let frame = bytes.to_vec();
    hop(move |standing| {
        let (Some(manager), Some(outbox)) = (standing.manager.as_ref(), standing.outbox.as_ref())
        else {
            return Err(not_connected());
        };
        let Some(central) = standing.centrals.get(&device) else {
            return Err(not_connected());
        };
        // A frame queued behind held ones keeps its place, so the central
        // reads them in order.
        let queued = standing
            .held
            .get(&device)
            .is_some_and(|held| !held.is_empty());
        if !queued && send_frame(manager, outbox, central, &frame) {
            Ok(())
        } else {
            standing.held.entry(device).or_default().push_back(frame);
            Ok(())
        }
    })
    .and_then(|answer| answer)
}

/// Close the central's connection, which the platform's peripheral role
/// cannot cancel (R76).
pub(crate) fn disconnect(_device: u64) {}

/// Create the manager, with the platform's power alert where `power_alert`
/// stands, or recreate it when `recreate` stands to show the alert again.
fn ensure_manager(recreate: bool, power_alert: bool) {
    let mut standing = STANDING.lock();
    if standing.manager.is_some() && !recreate {
        return;
    }
    standing.queue = None;
    standing.manager = None;
    standing.delegate = None;
    standing.service = None;
    standing.inbox = None;
    standing.outbox = None;
    standing.centrals.clear();
    standing.held.clear();
    standing.advertising = false;
    standing.registration = Registration::Absent;
    standing.wanted = false;
    let queue = DispatchQueue::new("connetto-peer-apple", None);
    let delegate = PeripheralDelegate::new();
    // SAFETY: the delegate and the queue are valid for the process, the
    // options dictionary carries one valid key and value, and the init
    // answers a manager the caller owns.
    let manager = unsafe {
        CBPeripheralManager::initWithDelegate_queue_options(
            CBPeripheralManager::alloc(),
            Some(ProtocolObject::from_ref(&*delegate)),
            Some(&queue),
            Some(&options(power_alert)),
        )
    };
    standing.queue = Some(queue);
    standing.delegate = Some(delegate);
    standing.manager = Some(manager);
}

/// The manager's options, the platform's power alert on where `power_alert`
/// stands.
fn options(power_alert: bool) -> Retained<NSDictionary<NSString, AnyObject>> {
    let value = NSNumber::new_bool(power_alert);
    // SAFETY: the platform's power-alert key is an immutable string the
    // platform owns for the process.
    let key: &NSString = unsafe { CBPeripheralManagerOptionShowPowerAlertKey };
    NSDictionary::from_slices(&[key], &[value.as_ref()])
}

/// The advertisement's data, the service's UUID alone (R76 decision 25).
fn advertise_data() -> Retained<NSDictionary<NSString, AnyObject>> {
    let service_uuid = uuid(&SERVICE_UUID);
    let uuid_array = NSArray::<CBUUID>::from_slice(&[&*service_uuid]);
    // SAFETY: the platform's service-UUIDs key is an immutable string the
    // platform owns for the process.
    let key: &NSString = unsafe { CBAdvertisementDataServiceUUIDsKey };
    NSDictionary::from_slices(&[key], &[uuid_array.as_ref()])
}

/// The platform's UUID for one of the peer's 16-byte constants.
fn uuid(bytes: &[u8; 16]) -> Retained<CBUUID> {
    // SAFETY: the bytes are a valid 16-byte UUID, so the platform answers a
    // UUID the caller owns.
    unsafe { CBUUID::UUIDWithData(&NSData::with_bytes(bytes)) }
}

/// Begin the advertisement from the platform's queue.
fn begin_advertising(standing: &mut Standing) {
    let Some(manager) = standing.manager.as_ref() else {
        return;
    };
    // SAFETY: the manager is alive for the process, the data carries the
    // service's UUID alone, and the platform's start answers nothing to
    // return.
    unsafe { manager.startAdvertising(Some(&advertise_data())) };
}

/// Register the service on the platform's queue.
fn add_service(standing: &mut Standing) {
    let Some(manager) = standing.manager.as_ref() else {
        return;
    };
    let inbox_uuid = uuid(&INBOX_UUID);
    let outbox_uuid = uuid(&OUTBOX_UUID);
    let service_uuid = uuid(&SERVICE_UUID);
    // SAFETY: the UUID is the peer's inbox constant, the properties and
    // permissions are valid for a writable characteristic, and the init
    // answers an object the caller owns.
    let inbox = unsafe {
        CBMutableCharacteristic::initWithType_properties_value_permissions(
            CBMutableCharacteristic::alloc(),
            &inbox_uuid,
            CBCharacteristicProperties::Write,
            None,
            CBAttributePermissions::Writeable,
        )
    };
    // SAFETY: the UUID is the peer's outbox constant, the properties and
    // permissions are valid for a readable, notifying characteristic, and the
    // init answers an object the caller owns.
    let outbox = unsafe {
        CBMutableCharacteristic::initWithType_properties_value_permissions(
            CBMutableCharacteristic::alloc(),
            &outbox_uuid,
            CBCharacteristicProperties::Read | CBCharacteristicProperties::Notify,
            None,
            CBAttributePermissions::Readable,
        )
    };
    // SAFETY: the UUID is the peer's service constant, and the init answers a
    // service the caller owns.
    let service = unsafe {
        CBMutableService::initWithType_primary(CBMutableService::alloc(), &service_uuid, true)
    };
    let characteristics = NSArray::<CBCharacteristic>::from_slice(&[&inbox, &outbox]);
    // SAFETY: the platform's set answers nothing to return, and the array
    // holds the service's own characteristics.
    unsafe { service.setCharacteristics(Some(&characteristics)) };
    // SAFETY: the manager is alive for the process, the service is a valid
    // object the platform retains, and the platform's add answers nothing to
    // return.
    unsafe { manager.addService(&service) };
    standing.inbox = Some(inbox);
    standing.outbox = Some(outbox);
    standing.service = Some(service);
    standing.registration = Registration::Adding;
}

/// Send one frame to one subscribed central, true when the platform took it.
fn send_frame(
    manager: &CBPeripheralManager,
    outbox: &CBMutableCharacteristic,
    central: &CBCentral,
    frame: &[u8],
) -> bool {
    let data = NSData::with_bytes(frame);
    let centrals = NSArray::from_slice(&[central]);
    // SAFETY: the manager is alive for the process, the frame is valid data
    // the platform copies, and the platform's send answers a plain bool.
    unsafe {
        manager.updateValue_forCharacteristic_onSubscribedCentrals(&data, outbox, Some(&centrals))
    }
}

/// Clear the centrals and their held frames, reporting their endings.
fn clear_subscribers(standing: &mut Standing) {
    for device in standing.centrals.keys().copied() {
        EVENTS.lock().push(Event::Disconnected { device });
    }
    standing.centrals.clear();
    standing.held.clear();
    standing.advertising = false;
}

/// The central's key, the first eight bytes of its identifier.
fn device_key(identifier: &NSUUID) -> u64 {
    key_from_uuid_text(&identifier.to_string()).unwrap_or(u64::MAX)
}

/// Whether `characteristic` is the one `uuid` names, by its UUID's bytes,
/// since the platform may hand a delegate another object for the same
/// characteristic.
fn is_characteristic(characteristic: &CBCharacteristic, uuid: &[u8; 16]) -> bool {
    // SAFETY: the platform passes the characteristic for the duration of the
    // call, and its UUID is a valid object it owns.
    let id = unsafe { characteristic.UUID() };
    // SAFETY: the UUID answers its bytes as a valid data object.
    let bytes = unsafe { id.data() };
    bytes.to_vec() == uuid
}

/// The platform's answer for a radio that is not on.
fn off_error() -> Error {
    Error::Apple {
        domain: "CoreBluetooth".to_owned(),
        code: CBError(2).0,
        description: "the radio is not on".to_owned(),
    }
}

/// The platform's answer for a central that is not subscribed.
fn not_connected() -> Error {
    Error::Apple {
        domain: "CoreBluetooth".to_owned(),
        code: CBError(3).0,
        description: "the central is not subscribed".to_owned(),
    }
}

/// What a framework error stands for.
fn describe(error: &NSError) -> String {
    format!("{} {}", error.domain(), error.localizedDescription())
}

/// Run `work` on the manager's queue and take its answer.
fn hop<T: Send + 'static>(
    work: impl FnOnce(&mut Standing) -> T + Send + 'static,
) -> Result<T, Error> {
    let queue = STANDING.lock().queue.clone().ok_or(Error::Unsupported)?;
    let (tx, rx) = mpsc::channel();
    queue.exec_async(move || {
        let answer = work(&mut STANDING.lock());
        let _ = tx.send(answer);
    });
    rx.recv_timeout(HOP).map_err(|_| Error::TimedOut(HOP))
}

define_class!(
    #[derive(Debug)]
    #[unsafe(super(NSObject))]
    #[thread_kind = AnyThread]
    pub struct PeripheralDelegate;

    unsafe impl NSObjectProtocol for PeripheralDelegate {}

    unsafe impl CBPeripheralManagerDelegate for PeripheralDelegate {
        #[unsafe(method(peripheralManagerDidUpdateState:))]
        fn peripheral_manager_did_update_state(&self, peripheral: &CBPeripheralManager) {
            // SAFETY: the manager is alive for the process, and the
            // platform's state answer is a plain enum.
            let state = unsafe { peripheral.state() };
            let mut standing = STANDING.lock();
            standing.radio = Some(state);
            if state != CBManagerState::PoweredOn {
                // The platform ends every central's subscription with the
                // radio, and clears its local database with the radio.
                clear_subscribers(&mut standing);
                standing.service = None;
                standing.inbox = None;
                standing.outbox = None;
                standing.registration = Registration::Absent;
                standing.wanted = false;
            }
        }

        #[unsafe(method(peripheralManagerDidStartAdvertising:error:))]
        fn peripheral_manager_did_start_advertising_error(
            &self,
            _peripheral: &CBPeripheralManager,
            error: Option<&NSError>,
        ) {
            let mut standing = STANDING.lock();
            match error {
                None => standing.advertising = true,
                Some(error) => {
                    standing.advertising = false;
                    EVENTS.lock().push(Event::Failed(describe(error)));
                }
            }
        }

        #[unsafe(method(peripheralManager:didAddService:error:))]
        fn peripheral_manager_did_add_service_error(
            &self,
            _peripheral: &CBPeripheralManager,
            _service: &CBService,
            error: Option<&NSError>,
        ) {
            let mut standing = STANDING.lock();
            standing.registration = Registration::Absent;
            match error {
                // A service added after the host stopped wanting it is
                // removed again.
                None if !standing.wanted => {
                    if let Some(manager) = standing.manager.as_ref() {
                        // SAFETY: the manager is alive for the process, and
                        // the platform's removal answers nothing to return.
                        unsafe { manager.removeAllServices() };
                    }
                    standing.service = None;
                    standing.inbox = None;
                    standing.outbox = None;
                }
                None => {
                    standing.registration = Registration::Registered;
                    if !standing.advertising {
                        begin_advertising(&mut standing);
                    }
                }
                Some(error) => {
                    standing.wanted = false;
                    standing.service = None;
                    standing.inbox = None;
                    standing.outbox = None;
                    EVENTS.lock().push(Event::Failed(describe(error)));
                }
            }
        }

        #[unsafe(method(peripheralManager:central:didSubscribeToCharacteristic:))]
        fn peripheral_manager_central_did_subscribe_to_characteristic(
            &self,
            _peripheral: &CBPeripheralManager,
            central: &CBCentral,
            characteristic: &CBCharacteristic,
        ) {
            if !is_characteristic(characteristic, &OUTBOX_UUID) {
                return;
            }
            // SAFETY: the platform passes the central's identifier for the
            // duration of this call, a valid NSUUID copied before the call
            // returns.
            let identifier = unsafe { central.identifier() };
            let device = device_key(&identifier);
            // SAFETY: the platform passes the central's frame length for the
            // duration of this call, a plain size.
            let mtu =
                u16::try_from(unsafe { central.maximumUpdateValueLength() }).unwrap_or(u16::MAX);
            let mut standing = STANDING.lock();
            let central = central.retain();
            standing.centrals.insert(device, central);
            EVENTS.lock().push(Event::Connected { device, mtu });
        }

        #[unsafe(method(peripheralManager:central:didUnsubscribeFromCharacteristic:))]
        fn peripheral_manager_central_did_unsubscribe_from_characteristic(
            &self,
            _peripheral: &CBPeripheralManager,
            central: &CBCentral,
            characteristic: &CBCharacteristic,
        ) {
            if !is_characteristic(characteristic, &OUTBOX_UUID) {
                return;
            }
            // SAFETY: the platform passes the central's identifier for the
            // duration of this call, a valid NSUUID copied before the call
            // returns.
            let identifier = unsafe { central.identifier() };
            let device = device_key(&identifier);
            let mut standing = STANDING.lock();
            if standing.centrals.remove(&device).is_some() {
                standing.held.remove(&device);
                EVENTS.lock().push(Event::Disconnected { device });
            }
        }

        #[unsafe(method(peripheralManager:didReceiveReadRequest:))]
        fn peripheral_manager_did_receive_read_request(
            &self,
            peripheral: &CBPeripheralManager,
            request: &CBATTRequest,
        ) {
            // SAFETY: the platform passes the request's characteristic for
            // the duration of this call, a valid object.
            let characteristic = unsafe { request.characteristic() };
            let result = if is_characteristic(&characteristic, &OUTBOX_UUID) {
                // SAFETY: the platform passes the request for the duration of
                // this call, and the outbox read stands answered with an
                // empty value.
                unsafe { request.setValue(None) };
                CBATTError::Success
            } else if is_characteristic(&characteristic, &INBOX_UUID) {
                CBATTError::ReadNotPermitted
            } else {
                CBATTError::RequestNotSupported
            };
            // SAFETY: the manager is alive for the process, and the platform
            // answers the response with nothing to return.
            unsafe { peripheral.respondToRequest_withResult(request, result) };
        }

        /// The platform hands one write, or the parts of a long write in
        /// offset order, as one array, and waits for one answer on its first
        /// request, so the parts become one chunk and the answer covers them
        /// all.
        #[unsafe(method(peripheralManager:didReceiveWriteRequests:))]
        fn peripheral_manager_did_receive_write_requests(
            &self,
            peripheral: &CBPeripheralManager,
            requests: &NSArray<CBATTRequest>,
        ) {
            let Some(first) = requests.firstObject() else {
                return;
            };
            let mut bytes = Vec::new();
            let mut device = None;
            let mut result = CBATTError::Success;
            for index in 0..requests.count() {
                let request = requests.objectAtIndex(index);
                // SAFETY: the platform passes the request's characteristic
                // for the duration of this call, a valid object.
                let characteristic = unsafe { request.characteristic() };
                if !is_characteristic(&characteristic, &INBOX_UUID) {
                    result = CBATTError::WriteNotPermitted;
                    break;
                }
                // SAFETY: the platform passes the request's central for the
                // duration of this call, a valid object.
                let central = unsafe { request.central() };
                // SAFETY: the platform passes the central's identifier for
                // the duration of this call, a valid NSUUID.
                let identifier = unsafe { central.identifier() };
                device = Some(device_key(&identifier));
                // SAFETY: the platform passes the written data for the
                // duration of this call, copied before the call returns, and
                // an empty write answers none.
                if let Some(value) = unsafe { request.value() } {
                    bytes.extend_from_slice(&value.to_vec());
                }
            }
            if result == CBATTError::Success
                && let Some(device) = device
            {
                EVENTS.lock().push(Event::Chunk { device, bytes });
            }
            // SAFETY: the manager is alive for the process, the first request
            // stands for the call's duration, and the platform answers the
            // response with nothing to return.
            unsafe { peripheral.respondToRequest_withResult(&first, result) };
        }

        #[unsafe(method(peripheralManagerIsReadyToUpdateSubscribers:))]
        fn peripheral_manager_is_ready_to_update_subscribers(
            &self,
            peripheral: &CBPeripheralManager,
        ) {
            let (held, outbox, centrals) = {
                let mut standing = STANDING.lock();
                (
                    std::mem::take(&mut standing.held),
                    standing.outbox.clone(),
                    standing.centrals.clone(),
                )
            };
            let Some(outbox) = outbox else {
                return;
            };
            for (device, mut frames) in held {
                let Some(central) = centrals.get(&device) else {
                    continue;
                };
                // The frames go in order until the platform's queue fills,
                // and every frame not sent stays held, ahead of any held
                // since the take.
                while let Some(frame) = frames.pop_front() {
                    if !send_frame(peripheral, &outbox, central, &frame) {
                        frames.push_front(frame);
                        break;
                    }
                }
                if !frames.is_empty() {
                    let mut standing = STANDING.lock();
                    if let Some(later) = standing.held.remove(&device) {
                        frames.extend(later);
                    }
                    standing.held.insert(device, frames);
                }
            }
        }
    }
);

impl PeripheralDelegate {
    /// The delegate's one instance.
    fn new() -> Retained<Self> {
        let this = Self::alloc().set_ivars(());
        // SAFETY: the definition registers the class, the alloc answered an
        // uninit object of this class, and NSObject's init answers the
        // initialized object the caller owns.
        unsafe { msg_send![super(this), init] }
    }
}
