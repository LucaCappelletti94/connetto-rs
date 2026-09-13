use core::future::Future;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{BroadcastChannel, MessageEvent};

use connetto_core::custody::{Custody, NoGate};

use crate::RelayHub;
use crate::frames::{MessageTransport, MessageTransportError};

/// Deadline for all hello-channel exchanges.
const HELLO_TIMEOUT_MS: f64 = 15_000.0;

/// The transport a tab rides to the DB worker.
pub type TabWire = MessageTransport<BroadcastChannel>;

enum HelloReady {
    Waiting,
    Up,
    Failed(String),
}

/// Failure surfaced by the page-side hello-channel functions.
#[derive(Debug, thiserror::Error)]
pub enum IntakeError {
    /// the hello channel could not be opened
    #[error("{operation}: {detail}")]
    ChannelOpen {
        /// the operation that failed
        operation: &'static str,
        /// the browser exception text
        detail: String,
    },
    /// the db worker reported a boot failure
    #[error("db worker boot failed: {detail}")]
    BootFailed {
        /// the detail the worker sent
        detail: String,
    },
    /// the db worker did not answer within the readiness deadline
    #[error("db worker did not answer within {deadline_ms:.0} ms")]
    Timeout {
        /// the deadline that expired, in milliseconds
        deadline_ms: f64,
    },
}

impl From<IntakeError> for JsValue {
    fn from(value: IntakeError) -> Self {
        JsValue::from_str(&value.to_string())
    }
}

async fn poll_hello_channel(
    channel: &BroadcastChannel,
    state: &Rc<RefCell<HelloReady>>,
    deadline_ms: f64,
) -> Result<(), IntakeError> {
    const POLL_MS: i32 = 50;
    let started = js_sys::Date::now();
    loop {
        match &*state.borrow() {
            HelloReady::Up => return Ok(()),
            HelloReady::Failed(detail) => {
                let detail = detail.clone();
                return Err(IntakeError::BootFailed { detail });
            }
            HelloReady::Waiting => {}
        }
        if js_sys::Date::now() - started >= deadline_ms {
            return Err(IntakeError::Timeout { deadline_ms });
        }
        let _ = channel.post_message(&JsValue::from_str("ask"));
        sleep_ms(POLL_MS).await;
    }
}

thread_local! {
    /// The boot this context spawned most recently, answering for it while it is in flight.
    static CURRENT_BOOT: RefCell<Option<BootAnnouncer>> = const { RefCell::new(None) };
}

/// Announces the boot this context has just spawned, replacing the announcement before it.
///
/// A reconnect attempt is handed no identity, and the boot it waits for is by construction the
/// newest one this context spawned, so one slot is all a context needs.
pub(super) fn announce_current_boot(identity: &super::boot::BootIdentity) {
    let announcer = announce_boot(identity);
    CURRENT_BOOT.with_borrow_mut(|current| *current = announcer);
}

/// The boot this context spawned, while a failure for it can still arrive.
fn current_boot_in_flight() -> Option<super::boot::BootIdentity> {
    CURRENT_BOOT.with_borrow(|current| {
        current
            .as_ref()
            .filter(|announcer| announcer.in_flight())
            .map(BootAnnouncer::identity)
    })
}

/// Keeps a boot's identity obtainable while the boot is in flight.
///
/// The announcement is posted once and a broadcast is not replayed, so a waiter that joins
/// later would have nothing to attribute a failure to. This answers `ask` with the identity for
/// as long as the boot has neither reported ready nor failed, which is the window a failure can
/// still arrive in. Dropping it stops answering.
pub struct BootAnnouncer {
    channel: BroadcastChannel,
    identity: super::boot::BootIdentity,
    in_flight: Rc<Cell<bool>>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
}

impl BootAnnouncer {
    /// The boot being announced.
    #[must_use]
    pub fn identity(&self) -> super::boot::BootIdentity {
        self.identity.clone()
    }

    /// Whether a failure for this boot can still arrive, which it cannot once the worker
    /// reported ready or the boot reported its failure.
    #[must_use]
    pub fn in_flight(&self) -> bool {
        self.in_flight.get()
    }
}

impl Drop for BootAnnouncer {
    fn drop(&mut self) {
        self.channel.set_onmessage(None);
        self.channel.close();
    }
}

/// Announces a boot and keeps answering for it, or `None` when the channel cannot be opened.
///
/// A caller that cannot announce still boots, because the announcement only makes a failure
/// attributable to a context that did not spawn it.
#[must_use]
pub(super) fn announce_boot(identity: &super::boot::BootIdentity) -> Option<BootAnnouncer> {
    let channel = BroadcastChannel::new(super::HELLO_CHANNEL).ok()?;
    let message = format!("booting:{identity}");
    let in_flight = Rc::new(Cell::new(true));
    let on_message = {
        let channel = channel.clone();
        let failure = format!("failed:{identity}:");
        let answer = message.clone();
        let in_flight = Rc::clone(&in_flight);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(heard) = event.data().as_string() else {
                return;
            };
            if heard == "ready" || heard.starts_with(failure.as_str()) {
                in_flight.set(false);
            } else if heard == "ask" && in_flight.get() {
                let _ = channel.post_message(&JsValue::from_str(&answer));
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let _ = channel.post_message(&JsValue::from_str(&message));
    Some(BootAnnouncer {
        channel,
        identity: identity.clone(),
        in_flight,
        _on_message: on_message,
    })
}

/// Page side: resolve once the DB worker's intake answers on the hello channel.
///
/// `known` lists boot identities this caller may act on; a failure whose identity is not among
/// them is ignored. A caller that knows no identity, and spawned no boot in this context, learns
/// one from a `booting:<identity>` announcement or from another waiter's answer to its `ask`,
/// because the origin hosts one worker topology and that announcement is its boot. A caller that
/// does know one stays with it.
///
/// # Errors
///
/// [`IntakeError::ChannelOpen`] when the hello channel cannot be opened,
/// [`IntakeError::BootFailed`] when the worker reported a failure for a known identity, or
/// [`IntakeError::Timeout`] when the deadline expires.
pub async fn await_db_worker_ready(known: &[super::boot::BootIdentity]) -> Result<(), IntakeError> {
    await_db_worker_ready_bounded(known, HELLO_TIMEOUT_MS).await
}

/// Waits for readiness under `deadline_ms`, so a test proves the ignoring of a foreign failure
/// in milliseconds rather than over the shipped deadline.
pub(super) async fn await_db_worker_ready_bounded(
    known: &[super::boot::BootIdentity],
    deadline_ms: f64,
) -> Result<(), IntakeError> {
    let channel =
        BroadcastChannel::new(super::HELLO_CHANNEL).map_err(|err| IntakeError::ChannelOpen {
            operation: "hello channel",
            detail: format!("{err:?}"),
        })?;
    let state = Rc::new(RefCell::new(HelloReady::Waiting));
    let mut initial = known.to_vec();
    if initial.is_empty() {
        // Only a caller that named nothing falls back to this context's boot, because a caller
        // that named one is scoped to it and a newer spawn is not what it is waiting for.
        initial.extend(current_boot_in_flight());
    }
    let known_ids = Rc::new(RefCell::new(initial));
    // A waiter that knows which boot it waits for has no business adopting another one, and a
    // waiter that knows none has only the announcement to go on.
    let trusts_announcements = known_ids.borrow().is_empty();
    let on_message = {
        let state = Rc::clone(&state);
        let known_ids = Rc::clone(&known_ids);
        let sender = channel.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(message) = event.data().as_string() else {
                return;
            };
            if message == "ready" {
                *state.borrow_mut() = HelloReady::Up;
            } else if message == "ask" {
                // A waiter that joins after the announcement gets it from whoever heard it,
                // because a broadcast is not replayed.
                for identity in known_ids.borrow().iter() {
                    let _ = sender.post_message(&JsValue::from_str(&format!("booting:{identity}")));
                }
            } else if let Some(id) = message.strip_prefix("booting:") {
                let heard = super::boot::BootIdentity::from_wire(id);
                let mut known_ids = known_ids.borrow_mut();
                if trusts_announcements && !known_ids.contains(&heard) {
                    known_ids.push(heard);
                }
            } else if let Some(rest) = message.strip_prefix("failed:")
                && let Some((id, detail)) = rest.split_once(':')
                && known_ids.borrow().iter().any(|known| known.matches_str(id))
            {
                *state.borrow_mut() = HelloReady::Failed(detail.to_owned());
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let result = poll_hello_channel(&channel, &state, deadline_ms).await;
    channel.set_onmessage(None);
    channel.close();
    result
}

/// Page side: announce a tab's wire channel and wait for the worker's attachment ack.
///
/// # Errors
///
/// [`IntakeError::ChannelOpen`] when the hello channel cannot be opened, or
/// [`IntakeError::Timeout`] when the worker does not acknowledge within the deadline.
pub async fn announce_tab(wire: &str) -> Result<(), IntakeError> {
    let channel =
        BroadcastChannel::new(super::HELLO_CHANNEL).map_err(|err| IntakeError::ChannelOpen {
            operation: "hello channel",
            detail: format!("{err:?}"),
        })?;
    let expected = format!("attached:{wire}");
    let attached = Rc::new(Cell::new(false));
    let on_message = {
        let attached = Rc::clone(&attached);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if event.data().as_string().as_deref() == Some(expected.as_str()) {
                attached.set(true);
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let _ = channel.post_message(&JsValue::from_str(&format!("tab:{wire}")));
    let started = js_sys::Date::now();
    while !attached.get() {
        if js_sys::Date::now() - started >= HELLO_TIMEOUT_MS {
            channel.set_onmessage(None);
            channel.close();
            return Err(IntakeError::Timeout {
                deadline_ms: HELLO_TIMEOUT_MS,
            });
        }
        sleep_ms(10).await;
    }
    channel.set_onmessage(None);
    channel.close();
    Ok(())
}

/// A transport factory for a reconnecting tab client.
///
/// Every attempt waits for a ready DB worker, announces a fresh wire channel, and returns a
/// transport watching the worker's alive lock.
pub fn tab_wire_factory(
    client_id: String,
) -> impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = Result<TabWire, MessageTransportError>>>>
{
    let mut attempt: u64 = 0;
    move || {
        attempt += 1;
        let wire = format!(
            "connetto-wire-{client_id}-{attempt}-{}",
            js_sys::Date::now()
        );
        Box::pin(async move {
            await_db_worker_ready(&[])
                .await
                .map_err(|err| MessageTransportError::Sink(err.to_string()))?;
            announce_tab(&wire)
                .await
                .map_err(|err| MessageTransportError::Sink(err.to_string()))?;
            MessageTransport::<BroadcastChannel>::with_peer_liveness(&wire, super::DB_ALIVE_LOCK)
        })
    }
}

/// Resolve after roughly `duration` in a window or worker context.
pub async fn sleep(duration: core::time::Duration) {
    let ms = i32::try_from(duration.as_millis()).unwrap_or(i32::MAX);
    sleep_ms(ms).await;
}

fn decode_custody_reply(data: &JsValue) -> Option<Custody> {
    let text = data.as_string()?;
    let encoded = text.strip_prefix("custody:")?;
    decode_custody(encoded)
}

/// Page side: ask the worker for the current custody level over the hello channel.
///
/// # Errors
///
/// [`IntakeError::ChannelOpen`] when the hello channel cannot be opened, or
/// [`IntakeError::Timeout`] when the worker does not answer within the deadline.
pub async fn request_custody() -> Result<Custody, IntakeError> {
    let channel =
        BroadcastChannel::new(super::HELLO_CHANNEL).map_err(|err| IntakeError::ChannelOpen {
            operation: "hello channel",
            detail: format!("{err:?}"),
        })?;
    let result: Rc<Cell<Option<Custody>>> = Rc::new(Cell::new(None));
    let on_message = {
        let result = Rc::clone(&result);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if let Some(custody) = decode_custody_reply(&event.data()) {
                result.set(Some(custody));
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let started = js_sys::Date::now();
    let mut answered = result.get();
    while answered.is_none() {
        if js_sys::Date::now() - started >= HELLO_TIMEOUT_MS {
            channel.set_onmessage(None);
            channel.close();
            drop(on_message);
            return Err(IntakeError::Timeout {
                deadline_ms: HELLO_TIMEOUT_MS,
            });
        }
        // Asks posted before the intake existed are lost, so this repeats the ask.
        let _ = channel.post_message(&JsValue::from_str("custody?"));
        sleep_ms(10).await;
        answered = result.get();
    }
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    Ok(answered.unwrap_or(Custody::Ephemeral))
}

/// Open the hello channel and broadcast the initial `ready`.
pub(super) fn install_hello_intake(hub: RelayHub) -> Result<(), IntakeError> {
    let hello =
        BroadcastChannel::new(super::HELLO_CHANNEL).map_err(|err| IntakeError::ChannelOpen {
            operation: "hello channel",
            detail: format!("{err:?}"),
        })?;
    let intake = {
        let hello = hello.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(message) = event.data().as_string() else {
                return;
            };
            if message == "ask" {
                let _ = hello.post_message(&JsValue::from_str("ready"));
            } else if message == "custody?" {
                let encoded = encode_custody(crate::unlock::custody());
                let _ = hello.post_message(&JsValue::from_str(&format!("custody:{encoded}")));
            } else if let Some(wire) = message.strip_prefix("tab:") {
                match MessageTransport::<BroadcastChannel>::new(wire) {
                    Ok(transport) => {
                        hub.attach(transport);
                        let _ = hello.post_message(&JsValue::from_str(&format!("attached:{wire}")));
                    }
                    Err(err) => {
                        tracing::error!(wire = %wire, error = %err, "tab wire channel failed");
                    }
                }
            }
        })
    };
    hello.set_onmessage(Some(intake.as_ref().unchecked_ref()));
    intake.forget();
    let _ = hello.post_message(&JsValue::from_str("ready"));
    Ok(())
}

/// Encode a [`Custody`] as a compact ASCII string for the hello-channel wire.
///
/// Decode with [`decode_custody`]; these two must stay adjacent so they cannot drift.
fn encode_custody(c: Custody) -> &'static str {
    match c {
        Custody::Verified => "v",
        Custody::Ephemeral => "e",
        Custody::Unverified(NoGate::Unsupported) => "u:us",
        Custody::Unverified(NoGate::Offerable) => "u:off",
        Custody::Unverified(NoGate::Declined) => "u:dec",
    }
}

/// Decode a custody string produced by [`encode_custody`], refusing unknown strings.
fn decode_custody(s: &str) -> Option<Custody> {
    match s {
        "v" => Some(Custody::Verified),
        "e" => Some(Custody::Ephemeral),
        "u:us" => Some(Custody::Unverified(NoGate::Unsupported)),
        "u:off" => Some(Custody::Unverified(NoGate::Offerable)),
        "u:dec" => Some(Custody::Unverified(NoGate::Declined)),
        _ => None,
    }
}

use super::helpers::sleep_ms;
