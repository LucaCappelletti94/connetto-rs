//! The Apple Bluetooth backend, over the process-wide peer bridge (R76).
//!
//! The readiness stands on the platform's `CBPeripheralManager`, the
//! service on its GATT service and advert, and the joiner's central stays
//! btleplug's, over the same platform.

use connetto_peer_apple::bluetooth as apple;

use super::{
    BluetoothError, BluetoothState, PeripheralBackend, PeripheralEvent, PromptOutcome,
    ReadinessBackend,
};

/// The Apple Bluetooth backend, over `connetto-peer-apple` (R76).
pub(crate) struct AppleBluetoothBackend;

impl AppleBluetoothBackend {
    /// The backend's new.
    pub(crate) fn new() -> Self {
        Self
    }
}

/// The permission a `NotPermitted` standing names.
const BLUETOOTH_PERMISSION: &str = "Bluetooth";

/// Map the platform's standing to the client's.
fn state(state: apple::State) -> BluetoothState {
    match state {
        apple::State::Ready => BluetoothState::Ready,
        apple::State::Off => BluetoothState::Off,
        apple::State::NotPermitted => BluetoothState::NotPermitted,
        apple::State::Unsupported => BluetoothState::Unsupported,
    }
}

/// Map the platform's prompt outcome to the client's.
fn outcome(outcome: apple::PromptOutcome) -> PromptOutcome {
    match outcome {
        apple::PromptOutcome::NotAsked => PromptOutcome::NotAsked,
        apple::PromptOutcome::Declined => PromptOutcome::Declined,
    }
}

/// The platform's service event as the client's.
fn event(event: apple::Event) -> PeripheralEvent {
    match &event {
        apple::Event::Chunk { device, bytes } => {
            tracing::debug!(device, len = bytes.len(), "the service took a chunk");
        }
        other => tracing::debug!(event = ?other, "the service reported"),
    }
    match event {
        apple::Event::Connected { device, mtu } => PeripheralEvent::Connected { device, mtu },
        apple::Event::Chunk { device, bytes } => PeripheralEvent::Chunk { device, bytes },
        apple::Event::Disconnected { device } => PeripheralEvent::Disconnected { device },
        apple::Event::Failed(reason) => PeripheralEvent::Failed(reason),
    }
}

/// The platform's error as the client's `Failed`.
fn failed(error: &connetto_peer_apple::Error) -> BluetoothError {
    BluetoothError::Failed(error.to_string())
}

impl ReadinessBackend for AppleBluetoothBackend {
    fn state(&self) -> BluetoothState {
        state(apple::state())
    }

    fn missing_permissions(&self) -> Vec<String> {
        match apple::state() {
            apple::State::NotPermitted => vec![BLUETOOTH_PERMISSION.to_owned()],
            _ => Vec::new(),
        }
    }

    fn prompt(&self) -> Result<(), BluetoothError> {
        apple::prompt().map_err(|error| failed(&error))
    }

    fn prompt_outcome(&self) -> Option<PromptOutcome> {
        apple::prompt_outcome().map(outcome)
    }
}

impl PeripheralBackend for AppleBluetoothBackend {
    fn start(&self, _beacon: [u8; 9]) -> Result<(), BluetoothError> {
        // The advert carries the service's UUID alone, so the beacon's bytes
        // stand out of it (R76 decision 25).
        apple::start().map_err(|error| failed(&error))
    }

    fn stop(&self) {
        let _ = apple::stop();
    }

    fn poll(&self) -> Vec<PeripheralEvent> {
        apple::poll().into_iter().map(event).collect()
    }

    fn notify(&self, device: u64, bytes: &[u8]) -> Result<(), BluetoothError> {
        let sent = apple::notify(device, bytes).map_err(|error| failed(&error));
        tracing::debug!(
            device,
            len = bytes.len(),
            ok = sent.is_ok(),
            "the service notified"
        );
        sent
    }

    fn disconnect(&self, device: u64) {
        apple::disconnect(device);
    }
}
