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
    /// The deadline runs.
    Counting,
    /// The boot waits on the user, so the deadline does not run.
    AtUser,
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
    started: &Rc<Cell<f64>>,
    deadline_ms: f64,
) -> Result<(), IntakeError> {
    const POLL_MS: i32 = 50;
    loop {
        match &*state.borrow() {
            HelloReady::Up => return Ok(()),
            HelloReady::Failed(detail) => {
                let detail = detail.clone();
                return Err(IntakeError::BootFailed { detail });
            }
            HelloReady::Counting => {
                if js_sys::Date::now() - started.get() >= deadline_ms {
                    return Err(IntakeError::Timeout { deadline_ms });
                }
            }
            HelloReady::AtUser => {}
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

/// What an announced boot has come to, which is what a later `ask` is answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BootOutcome {
    /// A failure for this boot can still arrive.
    Pending,
    /// As [`Pending`](Self::Pending), with the boot waiting on the user in the numbered step.
    AtUser(u64),
    /// The boot failed, and the reason is still worth telling a waiter that joins now.
    Failed(String),
    /// The worker is up, or a newer boot has been announced, so this one has nothing to say.
    Spent,
}

/// The highest user step a listener has taken, so a replayed announcement of a step that has
/// already resumed pauses nothing. Replays and the worker's own announcements come from
/// different senders, and a channel orders messages per sender only.
#[derive(Debug, Default)]
struct UserSteps {
    step: u64,
}

impl UserSteps {
    /// Whether `waiting` for `step` is news, taking it if so.
    fn waiting(&mut self, step: u64) -> bool {
        let news = step > self.step;
        if news {
            self.step = step;
        }
        news
    }

    /// Whether `resumed` for `step` is current, taking it if so.
    fn resumed(&mut self, step: u64) -> bool {
        let current = step >= self.step;
        if current {
            self.step = step;
        }
        current
    }
}

/// The boot identity and step number of a `waiting:` or `resumed:` message.
fn user_step<'a>(message: &'a str, prefix: &str) -> Option<(&'a str, u64)> {
    let (id, step) = message.strip_prefix(prefix)?.split_once(':')?;
    Some((id, step.parse().ok()?))
}

/// Keeps a boot's identity and its outcome obtainable for as long as they explain anything.
///
/// Both the announcement and the failure are single broadcasts and a broadcast is not replayed,
/// so a waiter that joins later would have nothing to attribute a failure to, and one that
/// joins after the failure would have no failure either. This answers `ask` with the
/// announcement while the boot is pending, followed by the boot's wait on the user while it has
/// one and by the failure once it has failed, until a newer boot is announced or the worker
/// reports ready. Dropping it stops answering.
pub struct BootAnnouncer {
    channel: BroadcastChannel,
    identity: super::boot::BootIdentity,
    outcome: Rc<RefCell<BootOutcome>>,
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
        matches!(
            *self.outcome.borrow(),
            BootOutcome::Pending | BootOutcome::AtUser(_)
        )
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
    announce_boot_on(super::HELLO_CHANNEL, identity)
}

/// Announces a boot on `channel_name`, so a test speaks on a channel of its own.
#[must_use]
pub(super) fn announce_boot_on(
    channel_name: &str,
    identity: &super::boot::BootIdentity,
) -> Option<BootAnnouncer> {
    let channel = BroadcastChannel::new(channel_name).ok()?;
    let announcement = format!("booting:{identity}");
    let outcome = Rc::new(RefCell::new(BootOutcome::Pending));
    let on_message = {
        let channel = channel.clone();
        let failure = format!("failed:{identity}:");
        // Readiness carries no identity for the waiters, so only the tagged form retires this
        // announcer: an outgoing worker's queued readiness must not spend the boot replacing it.
        let readiness = format!("ready:{identity}");
        let own = identity.clone();
        let mut steps = UserSteps::default();
        let announcement = announcement.clone();
        let outcome = Rc::clone(&outcome);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(heard) = event.data().as_string() else {
                return;
            };
            let mut outcome = outcome.borrow_mut();
            if heard == readiness {
                *outcome = BootOutcome::Spent;
            } else if let Some(detail) = heard.strip_prefix(failure.as_str()) {
                // Only a pending boot can fail: a worker that has reported ready booted, and an
                // error it throws later is not this boot's outcome.
                if matches!(*outcome, BootOutcome::Pending | BootOutcome::AtUser(_)) {
                    *outcome = BootOutcome::Failed(detail.to_owned());
                }
            } else if heard.starts_with("booting:") && heard != announcement {
                // A newer boot is the one a waiter should hear about now.
                *outcome = BootOutcome::Spent;
            } else if let Some((id, step)) = user_step(&heard, "waiting:")
                && own.matches_str(id)
            {
                if matches!(*outcome, BootOutcome::Pending | BootOutcome::AtUser(_))
                    && steps.waiting(step)
                {
                    *outcome = BootOutcome::AtUser(step);
                }
            } else if let Some((id, step)) = user_step(&heard, "resumed:")
                && own.matches_str(id)
            {
                if steps.resumed(step) && matches!(*outcome, BootOutcome::AtUser(_)) {
                    *outcome = BootOutcome::Pending;
                }
            } else if heard == "ask" {
                let follow_up = match &*outcome {
                    BootOutcome::Pending => None,
                    BootOutcome::AtUser(step) => Some(format!("waiting:{own}:{step}")),
                    BootOutcome::Failed(detail) => Some(format!("{failure}{detail}")),
                    BootOutcome::Spent => return,
                };
                // The identity goes first, because a waiter acts on a failure or a wait on the
                // user only for an identity it knows.
                let _ = channel.post_message(&JsValue::from_str(&announcement));
                if let Some(follow_up) = follow_up {
                    let _ = channel.post_message(&JsValue::from_str(&follow_up));
                }
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let _ = channel.post_message(&JsValue::from_str(&announcement));
    Some(BootAnnouncer {
        channel,
        identity: identity.clone(),
        outcome,
        _on_message: on_message,
    })
}

/// Page side: resolve once the DB worker's intake answers on the hello channel.
///
/// `known` lists boot identities this caller may act on; a failure whose identity is not among
/// them is ignored. A caller that knows no identity, and spawned no boot in this context, learns
/// one from the `booting:<identity>` a spawn announces or answers with, because the origin hosts
/// one worker topology and that announcement is its boot. A caller that does know one stays with
/// it.
///
/// # Errors
///
/// [`IntakeError::ChannelOpen`] when the hello channel cannot be opened,
/// [`IntakeError::BootFailed`] when the worker reported a failure for a known identity, or
/// [`IntakeError::Timeout`] when the deadline expires.
pub async fn await_db_worker_ready(known: &[super::boot::BootIdentity]) -> Result<(), IntakeError> {
    await_db_worker_ready_bounded(super::HELLO_CHANNEL, known, HELLO_TIMEOUT_MS).await
}

/// Waits for readiness on `channel_name` under `deadline_ms`, so a test proves a boundary in
/// milliseconds rather than over the shipped deadline, on a channel of its own rather than on
/// the one every other waiter in the context is listening to.
pub(super) async fn await_db_worker_ready_bounded(
    channel_name: &str,
    known: &[super::boot::BootIdentity],
    deadline_ms: f64,
) -> Result<(), IntakeError> {
    let channel = BroadcastChannel::new(channel_name).map_err(|err| IntakeError::ChannelOpen {
        operation: "hello channel",
        detail: format!("{err:?}"),
    })?;
    let state = Rc::new(RefCell::new(HelloReady::Counting));
    let started = Rc::new(Cell::new(js_sys::Date::now()));
    let mut initial = known.to_vec();
    if initial.is_empty() && channel_name == super::HELLO_CHANNEL {
        // Only a caller that named nothing falls back to this context's boot, because a caller
        // that named one is scoped to it and a newer spawn is not what it is waiting for. A boot
        // is remembered for the channel it was announced on and explains nothing on another.
        initial.extend(current_boot_in_flight());
    }
    let known_ids = Rc::new(RefCell::new(initial));
    // A waiter that knows which boot it waits for has no business adopting another one, and a
    // waiter that knows none has only the announcement to go on.
    let trusts_announcements = known_ids.borrow().is_empty();
    let on_message = {
        let state = Rc::clone(&state);
        let started = Rc::clone(&started);
        let known_ids = Rc::clone(&known_ids);
        let mut steps = UserSteps::default();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(message) = event.data().as_string() else {
                return;
            };
            let is_known = |id: &str| known_ids.borrow().iter().any(|known| known.matches_str(id));
            let mut state = state.borrow_mut();
            // Readiness and failure are terminal: a worker that answered this wait booted, and
            // what it throws afterwards is not this wait's outcome.
            if matches!(*state, HelloReady::Up | HelloReady::Failed(_)) {
                return;
            }
            if message == "ready" || message.starts_with("ready:") {
                *state = HelloReady::Up;
            } else if let Some(id) = message.strip_prefix("booting:") {
                // Only a spawn announces, so the newest announcement names the boot that will
                // serve this waiter, and the one before it has been replaced: its failure no
                // longer says anything about whether a worker is coming, and neither does its
                // wait on the user.
                if trusts_announcements && !is_known(id) {
                    *known_ids.borrow_mut() = vec![super::boot::BootIdentity::from_wire(id)];
                    // A new boot is a new worker, which numbers its user steps from 1 again.
                    steps = UserSteps::default();
                    if matches!(*state, HelloReady::AtUser) {
                        *state = HelloReady::Counting;
                        started.set(js_sys::Date::now());
                    }
                }
            } else if let Some(rest) = message.strip_prefix("failed:")
                && let Some((id, detail)) = rest.split_once(':')
                && is_known(id)
            {
                *state = HelloReady::Failed(detail.to_owned());
            } else if let Some((id, step)) = user_step(&message, "waiting:")
                && is_known(id)
            {
                if steps.waiting(step) {
                    *state = HelloReady::AtUser;
                }
            } else if let Some((id, step)) = user_step(&message, "resumed:")
                && is_known(id)
                && steps.resumed(step)
                && matches!(*state, HelloReady::AtUser)
            {
                *state = HelloReady::Counting;
                started.set(js_sys::Date::now());
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let result = poll_hello_channel(&channel, &state, &started, deadline_ms).await;
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
    request_custody_bounded(HELLO_TIMEOUT_MS).await
}

/// Asks for custody under `deadline_ms`, so a test proves the expiry in milliseconds rather
/// than waiting out the shipped deadline.
pub(super) async fn request_custody_bounded(deadline_ms: f64) -> Result<Custody, IntakeError> {
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
        if js_sys::Date::now() - started >= deadline_ms {
            channel.set_onmessage(None);
            channel.close();
            drop(on_message);
            return Err(IntakeError::Timeout { deadline_ms });
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

thread_local! {
    /// The user steps this worker has announced, numbering the next one.
    static USER_STEPS: Cell<u64> = const { Cell::new(0) };
}

/// Worker side: run `step`, a boot step that waits on the user, announced on the hello channel
/// so a page waiting for this boot pauses its deadline for as long as the user takes.
pub(crate) async fn awaiting_user<F: Future>(step: F) -> F::Output {
    awaiting_user_on(
        super::HELLO_CHANNEL,
        super::boot::boot_identity_from_location(),
        step,
    )
    .await
}

/// [`awaiting_user`] on `channel_name` for the boot `identity`, so a test speaks on a channel of
/// its own. A boot with no identity announces nothing, since no waiter could attribute it.
pub(super) async fn awaiting_user_on<F: Future>(
    channel_name: &str,
    identity: Option<String>,
    step: F,
) -> F::Output {
    let announcing = identity.and_then(|identity| {
        let channel = BroadcastChannel::new(channel_name).ok()?;
        let step = USER_STEPS.with(|taken| {
            taken.set(taken.get() + 1);
            taken.get()
        });
        let _ = channel.post_message(&JsValue::from_str(&format!("waiting:{identity}:{step}")));
        Some((channel, identity, step))
    });
    let output = step.await;
    if let Some((channel, identity, step)) = announcing {
        let _ = channel.post_message(&JsValue::from_str(&format!("resumed:{identity}:{step}")));
        channel.close();
    }
    output
}

/// Open the hello channel and broadcast the initial `ready`.
pub(super) fn install_hello_intake(hub: RelayHub) -> Result<(), IntakeError> {
    let hello =
        BroadcastChannel::new(super::HELLO_CHANNEL).map_err(|err| IntakeError::ChannelOpen {
            operation: "hello channel",
            detail: format!("{err:?}"),
        })?;
    // Readiness stays untagged for the waiters, and names the boot as well so the spawning
    // context can tell its own boot's readiness from a message an outgoing worker left behind.
    let ready = super::boot::boot_identity_from_location()
        .map(|identity| format!("ready:{identity}"))
        .unwrap_or_default();
    let intake = {
        let hello = hello.clone();
        let ready = ready.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(message) = event.data().as_string() else {
                return;
            };
            if message == "ask" {
                let _ = hello.post_message(&JsValue::from_str("ready"));
                if !ready.is_empty() {
                    let _ = hello.post_message(&JsValue::from_str(&ready));
                }
            } else if message == "custody?" {
                let encoded = encode_custody(crate::unlock::custody());
                let _ = hello.post_message(&JsValue::from_str(&format!("custody:{encoded}")));
            } else if let Some(wire) = message.strip_prefix("tab:") {
                match MessageTransport::<BroadcastChannel>::new(wire) {
                    Ok(transport) => {
                        hub.attach_with_content(transport);
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
    if !ready.is_empty() {
        let _ = hello.post_message(&JsValue::from_str(&ready));
    }
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
