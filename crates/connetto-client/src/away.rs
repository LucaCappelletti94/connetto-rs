//! The away and return re-check, the one input that tells the client the
//! application went away and came back, and the re-check it drives.
//!
//! Time away is the larger of a sleep-counting monotonic clock and the wall
//! clock (decision 19): `Instant` stops during device sleep on Apple and on
//! Linux and Android, so a phone asleep for an hour would read as minutes
//! away. The sleep-counting reading is `CLOCK_BOOTTIME` on Linux and Android,
//! `CLOCK_MONOTONIC` on Apple, and `performance.now()` in the browser. A wall
//! clock stepped back cannot shorten time away below the monotonic reading,
//! and one stepped forward costs at most one extra prompt.
//!
//! The client never reads a clock itself. The caller (connetto-dioxus, the
//! browser worker, or an application) reads the clocks into a [`Moment`] and
//! hands it to the [`GateController`] that owns the re-check, the
//! [`ConnettoClient`](crate::ConnettoClient)'s own or the browser relay hub's. Tests inject a
//! [`Clock`] to control the readings.

use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::sync::{Arc, Mutex as StdMutex};

/// A moment the application went away or came back, a sleep-counting
/// monotonic reading beside a wall reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Moment {
    /// The sleep-counting monotonic reading, which keeps counting through
    /// device sleep.
    monotonic: Duration,
    /// The wall reading, which can be stepped forward or back.
    wall: Duration,
}

impl Moment {
    /// The moment the application went away or came back, read from `clock`.
    #[must_use]
    pub fn now<C: Clock>(clock: &C) -> Self {
        Self {
            monotonic: clock.monotonic(),
            wall: clock.wall(),
        }
    }

    /// The time away between this moment and `back`, as the larger of the
    /// monotonic and wall deltas, a negative delta read as zero.
    ///
    /// A wall clock stepped back gives a negative wall delta (read as zero), so
    /// the time away falls back to the monotonic reading, which cannot be
    /// stepped. A wall clock stepped forward gives a larger wall delta, so the
    /// time away is at most one extra prompt.
    #[must_use]
    pub fn away_duration(self, back: Moment) -> Duration {
        back.monotonic
            .saturating_sub(self.monotonic)
            .max(back.wall.saturating_sub(self.wall))
    }
}

/// The two clocks a [`Moment`] reads, a sleep-counting monotonic and a wall.
///
/// The system clocks are [`SystemClock`], and tests inject a deterministic one.
pub trait Clock {
    /// The sleep-counting monotonic reading, which keeps counting through
    /// device sleep.
    fn monotonic(&self) -> Duration;
    /// The wall reading, which can be stepped forward or back.
    fn wall(&self) -> Duration;
}

/// The platform's real clocks.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn monotonic(&self) -> Duration {
        monotonic()
    }

    fn wall(&self) -> Duration {
        wall()
    }
}

/// The sleep-counting monotonic reading, by platform.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn monotonic() -> Duration {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // CLOCK_BOOTTIME keeps counting through suspend.
        match rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Boottime) {
            Ok(timespec) => Duration::try_from(timespec).unwrap_or_else(|_| instant_monotonic()),
            Err(_) => instant_monotonic(),
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        // Darwin's CLOCK_MONOTONIC keeps counting through sleep.
        Duration::try_from(rustix::time::clock_gettime(
            rustix::time::ClockId::Monotonic,
        ))
        .unwrap_or_else(|_| instant_monotonic())
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        // Windows and other native targets read std's steady clock, which on
        // Windows is the QueryPerformanceCounter-backed Instant.
        instant_monotonic()
    }
}

/// The wall reading, by platform.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn wall() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

/// The steady-clock fallback reading, seconds since a fixed process reference.
///
/// Used when the platform's sleep-counting syscall is unavailable, and as the
/// only source on native targets without a named sleep-counting clock.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn instant_monotonic() -> Duration {
    static REFERENCE: std::sync::LazyLock<std::time::Instant> =
        std::sync::LazyLock::new(std::time::Instant::now);
    std::time::Instant::now().duration_since(*REFERENCE)
}

/// The sleep-counting monotonic reading on the browser, in milliseconds since
/// the page's time origin.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
fn monotonic() -> Duration {
    let millis = web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0);
    // Millis since the time origin, a non-negative integer-valued float within
    // u64, so the truncating cast loses nothing.
    debug_assert!(
        millis.is_finite() && millis >= 0.0,
        "performance.now is not a valid reading"
    );
    Duration::from_millis(millis as u64)
}

/// The wall reading on the browser, in milliseconds since the epoch.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
fn wall() -> Duration {
    let millis = js_sys::Date::now();
    // Millis since the epoch, a non-negative integer-valued float within u64,
    // so the truncating cast loses nothing.
    debug_assert!(
        millis.is_finite() && millis >= 0.0,
        "Date.now is not a valid reading"
    );
    Duration::from_millis(millis as u64)
}

/// How the gate's prompt resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateAskOutcome {
    /// The user approved, and the mechanism resumed access.
    Approved,
    /// The user dismissed the prompt, and the mechanism stays locked.
    Dismissed,
}

/// The gate prompt's future, owned so the client's pump can hold it across
/// iterations and drive it alongside the frame wait.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub type GateAskFuture = Pin<Box<dyn Future<Output = GateAskOutcome> + Send + 'static>>;
/// The wasm form of the gate prompt's future, unconstrained because the
/// runtime is single threaded. See the native docs.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub type GateAskFuture = Pin<Box<dyn Future<Output = GateAskOutcome> + 'static>>;

/// What locks and re-asks the secret the gate protects.
///
/// The mechanism is platform-specific. The browser implements it over the tab's
/// unlock ceremony, and the native keyring over the Apple keychain's and the
/// Android Keystore's own verification (R51, R52). The client calls
/// [`lock`](Self::lock) the moment a re-check fires (it locks the protected
/// secret) and drives [`ask`](Self::ask) to completion, and on
/// [`GateAskOutcome::Approved`] the mechanism resumes access.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub trait GateMechanism: Send + Sync {
    /// Lock the protected secret. Application access is refused until the next
    /// approval.
    fn lock(&self);
    /// Ask the platform's prompt. The returned future resolves to
    /// [`GateAskOutcome::Approved`] (and the mechanism resumes access) or
    /// [`GateAskOutcome::Dismissed`] (and the mechanism stays locked).
    fn ask(&self) -> GateAskFuture;
    /// Whether the platform already verified the user this launch, so the
    /// gate starts open rather than asking. False unless the mechanism knows.
    fn is_open(&self) -> bool {
        false
    }
}

/// The wasm form of [`GateMechanism`], unconstrained because the runtime is
/// single threaded. See the native docs.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub trait GateMechanism {
    /// Lock the protected secret. Application access is refused until the next
    /// approval.
    fn lock(&self);
    /// Ask the platform's prompt. The returned future resolves to
    /// [`GateAskOutcome::Approved`] (and the mechanism resumes access) or
    /// [`GateAskOutcome::Dismissed`] (and the mechanism stays locked).
    fn ask(&self) -> GateAskFuture;
    /// Whether the platform already verified the user this launch, so the
    /// gate starts open rather than asking. False unless the mechanism knows.
    fn is_open(&self) -> bool {
        false
    }
}

/// Receives the gate's transitions the moment they happen.
///
/// The owner supplies one sink to [`GateController`], which emits each
/// transition at the moment the state changes. The client maps them onto
/// its event stream, and the browser's relay hub onto the state it forwards
/// to its tabs.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub trait GateSink: Send + Sync {
    /// The gate locked, because a prompt started or a relay-driven lock applied.
    fn locked(&self);
    /// The gate unlocked, because an approval or a relay-driven unlock
    /// applied.
    fn unlocked(&self);
    /// A prompt was dismissed, so the gate stays locked.
    fn unlock_dismissed(&self);
}

/// The wasm form of [`GateSink`], unconstrained because the runtime is
/// single threaded. See the native docs.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub trait GateSink {
    /// The gate locked, because a prompt started or a relay-driven lock applied.
    fn locked(&self);
    /// The gate unlocked, because an approval or a relay-driven unlock
    /// applied.
    fn unlocked(&self);
    /// A prompt was dismissed, so the gate stays locked.
    fn unlock_dismissed(&self);
}

/// The gate's re-check state, the grace, the mechanism and the current lock.
#[derive(Default)]
struct GateState {
    /// The re-check grace: `None` re-checks once per launch (never on a
    /// return), `Some(zero)` re-checks every return, and `Some(d)` re-checks
    /// a return whose time away exceeds `d`.
    recheck: Option<Duration>,
    /// The mechanism that locks and re-asks the protected secret, present
    /// when the gate is on.
    mechanism: Option<Arc<dyn GateMechanism>>,
    /// Whether application access is refused.
    locked: bool,
    /// Whether a prompt is in flight.
    prompting: bool,
    /// The pending away moment, absent until one is kept.
    pending_away: Option<Moment>,
}

/// The gate's re-check state machine over the grace, the mechanism, the
/// current lock, the prompt in flight and the pending away moment.
///
/// Platform-neutral, so the client's pump and the browser's relay hub run
/// the same machine. The owner feeds it the moments the application went
/// away and came back through [`away`](Self::away) and [`back`](Self::back),
/// checks [`is_locked`](Self::is_locked) before it grants application
/// access, and drives the prompt's future it
/// [`take_ask`](Self::take_ask)ed to completion, applying the outcome with
/// [`apply_outcome`](Self::apply_outcome). Every transition is emitted
/// through the sink the owner supplied.
///
/// A controller with no mechanism ignores every input and never locks, so
/// an owner with no gate can hold one always.
pub struct GateController {
    sink: Arc<dyn GateSink>,
    state: StdMutex<GateState>,
    /// The prompt's future, driven by the owner. Absent when no prompt is in
    /// flight, and outside the state lock so the owner can drive it without
    /// holding the lock.
    ask: StdMutex<Option<GateAskFuture>>,
}

impl GateController {
    /// A controller with no gate armed.
    #[must_use]
    pub fn new(sink: Arc<dyn GateSink>) -> Self {
        Self {
            sink,
            state: StdMutex::new(GateState::default()),
            ask: StdMutex::new(None),
        }
    }

    /// Whether a gate is armed.
    ///
    /// # Panics
    ///
    /// When the state lock is poisoned.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.state
            .lock()
            .expect("the gate state lock")
            .mechanism
            .is_some()
    }

    /// Whether application access is refused.
    ///
    /// # Panics
    ///
    /// When the state lock is poisoned.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.state.lock().expect("the gate state lock").locked
    }

    /// Arm the re-check.
    ///
    /// A gated launch starts locked, so the first access asks, unless the
    /// mechanism reports the platform verified the user already.
    ///
    /// # Panics
    ///
    /// When the state lock is poisoned.
    pub fn enable(&self, recheck: Option<Duration>, mechanism: Arc<dyn GateMechanism>) {
        // A gated launch starts locked, so the first access asks, unless the
        // platform verified the user already this launch.
        let locked = !mechanism.is_open();
        self.arm(recheck, mechanism, locked);
    }

    /// Arm the re-check open, for a launch whose prompt was approved.
    ///
    /// # Panics
    ///
    /// When the state lock is poisoned.
    pub(crate) fn enable_verified(
        &self,
        recheck: Option<Duration>,
        mechanism: Arc<dyn GateMechanism>,
    ) {
        self.arm(recheck, mechanism, false);
    }

    fn arm(&self, recheck: Option<Duration>, mechanism: Arc<dyn GateMechanism>, locked: bool) {
        tracing::debug!(?recheck, locked, "the gate armed");
        let mut state = self.state.lock().expect("the gate state lock");
        state.recheck = recheck;
        state.locked = locked;
        state.mechanism = Some(mechanism);
        state.prompting = false;
        state.pending_away = None;
    }

    /// The application went away at `at`.
    ///
    /// Only an armed, open controller keeps the moment, and only when a
    /// grace is set. A controller with no mechanism or a locked one ignores
    /// it.
    ///
    /// # Panics
    ///
    /// When the state lock is poisoned.
    pub fn away(&self, at: Moment) {
        let mut state = self.state.lock().expect("the gate state lock");
        tracing::debug!(
            ?at,
            armed = state.mechanism.is_some(),
            locked = state.locked,
            prompting = state.prompting,
            pending = ?state.pending_away,
            "the gate heard an away"
        );
        if state.mechanism.is_none() || state.locked {
            return;
        }
        if state.recheck.is_some() {
            state.pending_away = Some(at);
        }
    }

    /// The application came back at `at`.
    ///
    /// A locked controller re-asks the mechanism when no prompt is pending.
    /// An armed, open controller clears the pending moment and re-checks
    /// when the time away exceeds the grace, or on every return with a zero
    /// grace. Returns true when a prompt started.
    ///
    /// # Panics
    ///
    /// When the state lock is poisoned.
    pub fn back(&self, at: Moment) -> bool {
        let mut state = self.state.lock().expect("the gate state lock");
        tracing::debug!(
            ?at,
            armed = state.mechanism.is_some(),
            locked = state.locked,
            prompting = state.prompting,
            pending = ?state.pending_away,
            "the gate heard a return"
        );
        let mechanism = match state.mechanism.as_ref() {
            Some(m) => Arc::clone(m),
            None => return false,
        };
        if state.locked {
            if state.prompting {
                return false;
            }
            self.start_prompt(&mut state, &mechanism);
            return true;
        }
        let Some(pending) = state.pending_away.take() else {
            return false;
        };
        let Some(grace) = state.recheck else {
            return false;
        };
        if grace.is_zero() || pending.away_duration(at) > grace {
            self.start_prompt(&mut state, &mechanism);
            true
        } else {
            false
        }
    }

    /// The application asks the gate to unlock, a retry after a dismissed
    /// prompt. Asks the mechanism when the gate is locked and no prompt is
    /// pending, and does nothing when the gate is open or a prompt is
    /// pending. Returns true when a prompt started.
    ///
    /// # Panics
    ///
    /// When the state lock is poisoned.
    pub fn unlock(&self) -> bool {
        let mut state = self.state.lock().expect("the gate state lock");
        let mechanism = match state.mechanism.as_ref() {
            Some(m) => Arc::clone(m),
            None => return false,
        };
        if state.locked && !state.prompting {
            self.start_prompt(&mut state, &mechanism);
            true
        } else {
            false
        }
    }

    /// Set the gate locked or unlocked, relay-driven.
    ///
    /// A tab has no mechanism of its own. The worker aggregates the gate
    /// and forwards the lock state to every tab. This applies that state
    /// directly, emitting through the sink, and refusing or resuming
    /// application access. Returns true when the state changed.
    ///
    /// # Panics
    ///
    /// When the state lock is poisoned.
    pub fn set_locked(&self, locked: bool) -> bool {
        let mut state = self.state.lock().expect("the gate state lock");
        if state.locked == locked {
            return false;
        }
        state.locked = locked;
        state.prompting = false;
        state.pending_away = None;
        if locked {
            self.sink.locked();
        } else {
            self.sink.unlocked();
        }
        true
    }

    /// Take the in-flight prompt's future, if any, for the owner to drive.
    ///
    /// # Panics
    ///
    /// When the prompt lock is poisoned.
    #[must_use]
    pub fn take_ask(&self) -> Option<GateAskFuture> {
        self.ask.lock().expect("the prompt lock").take()
    }

    /// Give back a prompt's future the owner has not resolved.
    ///
    /// # Panics
    ///
    /// When the prompt lock is poisoned.
    pub fn restore_ask(&self, ask: GateAskFuture) {
        *self.ask.lock().expect("the prompt lock") = Some(ask);
    }

    /// Apply a resolved prompt.
    ///
    /// Clears `ask` on an outcome and emits through the sink. Approval
    /// unlocks, and a dismissal stays locked for the next return or unlock
    /// call.
    ///
    /// # Panics
    ///
    /// When the state lock is poisoned.
    pub fn apply_outcome(&self, ask: &mut Option<GateAskFuture>, outcome: Option<GateAskOutcome>) {
        let Some(outcome) = outcome else {
            return;
        };
        *ask = None;
        let mut state = self.state.lock().expect("the gate state lock");
        tracing::debug!(?outcome, "the gate prompt answered");
        state.prompting = false;
        if outcome == GateAskOutcome::Approved {
            state.locked = false;
            self.sink.unlocked();
        } else {
            self.sink.unlock_dismissed();
        }
    }

    /// Lock the gate and start a prompt, which locks the mechanism, emits
    /// through the sink, and stores the ask's future for the owner to drive. Called
    /// while holding the state lock.
    fn start_prompt(&self, state: &mut GateState, mechanism: &Arc<dyn GateMechanism>) {
        tracing::debug!("the gate locked and started a prompt");
        state.locked = true;
        state.prompting = true;
        mechanism.lock();
        let ask = mechanism.ask();
        *self.ask.lock().expect("the prompt lock") = Some(ask);
        self.sink.locked();
    }
}
