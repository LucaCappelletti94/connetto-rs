//! Location Services access, which macOS asks of a process before it joins a
//! network by name (R76 slice 9c).

use std::cell::RefCell;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use dispatch2::DispatchQueue;
use objc2::MainThreadMarker;
use objc2::rc::Retained;
use objc2_core_location::{CLAuthorizationStatus, CLLocationManager};

use crate::hotspot::LocationAccess;

thread_local! {
    /// The one manager, kept on the main thread. The prompt closes when its
    /// manager goes, and a fresh manager reads `NotDetermined` until
    /// locationd answers it, so every read and request goes through this
    /// one (measured 2026-10-14).
    static MANAGER: RefCell<Option<Retained<CLLocationManager>>> = const { RefCell::new(None) };
}

/// When the main thread's manager was made, since its first reads answer
/// `NotDetermined` until locationd registers it (measured 2026-10-14).
static MADE_AT: LazyLock<parking_lot::Mutex<Option<Instant>>> =
    LazyLock::new(|| parking_lot::Mutex::new(None));

/// How long a fresh manager's `NotDetermined` stands unsettled.
const SETTLE_BOUND: Duration = Duration::from_secs(2);

/// The pause between two reads while a fresh manager settles.
const SETTLE_PAUSE: Duration = Duration::from_millis(100);

/// The process's standing with Location Services.
///
/// Off the main thread, a `NotAsked` from a manager younger than
/// [`SETTLE_BOUND`] is read again until it settles or the bound runs out.
pub(crate) fn access() -> LocationAccess {
    if MainThreadMarker::new().is_some() {
        return read();
    }
    loop {
        let mut access = LocationAccess::NotAsked;
        DispatchQueue::main().exec_sync(|| access = read());
        let settling = MADE_AT
            .lock()
            .is_some_and(|made| made.elapsed() < SETTLE_BOUND);
        if access != LocationAccess::NotAsked || !settling {
            return access;
        }
        std::thread::sleep(SETTLE_PAUSE);
    }
}

/// Ask the user for location access on the main queue.
pub(crate) fn request() {
    DispatchQueue::main().exec_async(|| {
        with_manager(|manager| {
            // SAFETY: the request takes nothing and answers nothing.
            unsafe { manager.requestWhenInUseAuthorization() };
        });
    });
}

/// The standing the main thread's manager reads.
fn read() -> LocationAccess {
    with_manager(|manager| {
        // SAFETY: the read answers the process's authorization as a plain
        // value.
        let status = unsafe { manager.authorizationStatus() };
        match status {
            CLAuthorizationStatus::NotDetermined => LocationAccess::NotAsked,
            CLAuthorizationStatus::AuthorizedAlways
            | CLAuthorizationStatus::AuthorizedWhenInUse => LocationAccess::Granted,
            _ => LocationAccess::Denied,
        }
    })
}

/// Run `body` on the main thread's manager, made on its first use.
fn with_manager<T>(body: impl FnOnce(&CLLocationManager) -> T) -> T {
    MANAGER.with(|slot| {
        let mut slot = slot.borrow_mut();
        let manager = slot.get_or_insert_with(|| {
            *MADE_AT.lock() = Some(Instant::now());
            // SAFETY: the init answers a manager the caller owns, made on
            // the main thread its prompt needs.
            unsafe { CLLocationManager::new() }
        });
        body(manager)
    })
}
