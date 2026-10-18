//! The Windows Bluetooth readiness, over the `Radios` API (R76 slice 9d).
//!
//! The radio's standing stands on the shared standing a thread of its own
//! re-reads, the machine's polled calls reading it without waiting.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use windows::Devices::Radios::{Radio, RadioKind, RadioState};
use windows::core::Error;

use super::{BluetoothError, BluetoothState, PromptOutcome, ReadinessBackend};

/// The pace of the radio's re-read, between the machine's own looks.
const REREAD: Duration = Duration::from_millis(1000);

/// The radio's standing, as the machine's polled calls read it.
type Standing = Arc<Mutex<Option<BluetoothState>>>;

/// The prompt's outcome, as the machine's polled calls read it.
type PromptStanding = Arc<Mutex<Option<PromptOutcome>>>;

/// The Windows Bluetooth readiness (R76 decision 21).
pub(crate) struct WindowsBluetoothReadiness {
    standing: Standing,
    prompt: PromptStanding,
    /// The thread's stop, set when the backend drops.
    stop: Arc<AtomicBool>,
}

impl WindowsBluetoothReadiness {
    /// The readiness, its thread re-reading the radio on its own pace.
    pub(crate) fn new() -> Self {
        let standing: Standing = Arc::new(Mutex::new(None));
        let prompt: PromptStanding = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let drive = Arc::clone(&standing);
        let drive_stop = Arc::clone(&stop);
        if let Err(err) = std::thread::Builder::new()
            .name("connetto-windows-radio".into())
            .spawn(move || Self::read_loop(&drive, &drive_stop))
        {
            tracing::error!("the Windows radio's thread did not start: {err}");
        }
        Self {
            standing,
            prompt,
            stop,
        }
    }

    /// The thread's loop, the radio's re-read on its pace, until the
    /// backend drops.
    fn read_loop(standing: &Standing, stop: &AtomicBool) {
        loop {
            match read_radio() {
                Ok(radio) => *standing.lock() = radio,
                Err(err) => tracing::debug!(%err, "the radio's standing will not re-read"),
            }
            if stop.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(REREAD);
        }
    }
}

/// The system's Bluetooth radio, its standing where it stands, or its
/// absence where the system carries no radio. The thread blocks on the
/// system's answer, which reading the radio's list never waits on a user for.
fn read_radio() -> Result<Option<BluetoothState>, Error> {
    let radios = Radio::GetRadiosAsync()?.join()?;
    let count = radios.Size()?;
    for index in 0..count {
        let radio = radios.GetAt(index)?;
        if radio.Kind()? == RadioKind::Bluetooth {
            let standing = match radio.State()? {
                RadioState::On => BluetoothState::Ready,
                // `Off`, `Disabled` and `Unknown` all keep the radio off,
                // which the settings pane can turn back on.
                _ => BluetoothState::Off,
            };
            return Ok(Some(standing));
        }
    }
    Ok(None)
}

impl ReadinessBackend for WindowsBluetoothReadiness {
    fn state(&self) -> BluetoothState {
        // `None` stands until the first read and where the system carries
        // no radio, which the platform reports as no Bluetooth.
        let standing = *self.standing.lock();
        standing.unwrap_or(BluetoothState::Unsupported)
    }

    fn missing_permissions(&self) -> Vec<String> {
        // Windows grants the radio to every app.
        Vec::new()
    }

    fn prompt(&self) -> Result<(), BluetoothError> {
        *self.prompt.lock() = None;
        open::that("ms-settings:bluetooth").map_err(|err| {
            BluetoothError::Failed(format!("the Bluetooth settings will not open: {err}"))
        })?;
        *self.prompt.lock() = Some(PromptOutcome::SentToSettings);
        Ok(())
    }

    fn prompt_outcome(&self) -> Option<PromptOutcome> {
        *self.prompt.lock()
    }
}

impl Drop for WindowsBluetoothReadiness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
