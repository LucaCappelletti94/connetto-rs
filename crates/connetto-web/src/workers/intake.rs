use core::future::Future;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use web_sys::{BroadcastChannel, MessageEvent};

use connetto_core::custody::{Custody, NoGate};

use crate::RelayHub;
use crate::frames::{MessageTransport, MessageTransportError};

use super::helpers::sleep_ms;

/// Deadline for all hello-channel exchanges.
const HELLO_TIMEOUT_MS: f64 = 15_000.0;

/// The transport a tab rides to the DB worker.
pub type TabWire = MessageTransport<BroadcastChannel>;

enum HelloReady {
    Waiting,
    Up,
    Failed(String),
}

async fn poll_hello_channel(
    channel: &BroadcastChannel,
    state: &Rc<RefCell<HelloReady>>,
) -> Result<(), JsValue> {
    const POLL_MS: i32 = 50;
    let started = js_sys::Date::now();
    loop {
        match &*state.borrow() {
            HelloReady::Up => return Ok(()),
            HelloReady::Failed(detail) => {
                let detail = detail.clone();
                return Err(JsValue::from_str(&format!(
                    "db worker boot failed: {detail}"
                )));
            }
            HelloReady::Waiting => {}
        }
        if js_sys::Date::now() - started >= HELLO_TIMEOUT_MS {
            return Err(JsValue::from_str("db worker did not answer readiness"));
        }
        let _ = channel.post_message(&JsValue::from_str("ask"));
        sleep_ms(POLL_MS).await;
    }
}

/// Page side: resolve once the DB worker's intake answers on the hello channel.
///
/// # Errors
///
/// A boot-failure string if the worker reported one, or a timeout string.
pub async fn await_db_worker_ready() -> Result<(), JsValue> {
    let channel = BroadcastChannel::new(super::HELLO_CHANNEL)
        .map_err(|err| JsValue::from_str(&format!("hello channel: {err:?}")))?;
    let state = Rc::new(RefCell::new(HelloReady::Waiting));
    let on_message = {
        let state = Rc::clone(&state);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(message) = event.data().as_string() else {
                return;
            };
            if message == "ready" {
                *state.borrow_mut() = HelloReady::Up;
            } else if let Some(detail) = message.strip_prefix("failed:") {
                *state.borrow_mut() = HelloReady::Failed(detail.to_owned());
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let result = poll_hello_channel(&channel, &state).await;
    channel.set_onmessage(None);
    channel.close();
    result
}

/// Page side: announce a tab's wire channel and wait for the worker's attachment ack.
///
/// # Errors
///
/// A timeout string when the worker does not acknowledge within the readiness deadline.
pub async fn announce_tab(wire: &str) -> Result<(), JsValue> {
    let channel = BroadcastChannel::new(super::HELLO_CHANNEL)
        .map_err(|err| JsValue::from_str(&format!("hello channel: {err:?}")))?;
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
            return Err(JsValue::from_str("db worker did not acknowledge the tab"));
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
            await_db_worker_ready()
                .await
                .map_err(|err| MessageTransportError::Sink(format!("{err:?}")))?;
            announce_tab(&wire)
                .await
                .map_err(|err| MessageTransportError::Sink(format!("{err:?}")))?;
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
/// A timeout string when the worker does not answer within the readiness deadline.
pub async fn request_custody() -> Result<Custody, JsValue> {
    let channel = BroadcastChannel::new(super::HELLO_CHANNEL)
        .map_err(|err| JsValue::from_str(&format!("hello channel: {err:?}")))?;
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
            return Err(JsValue::from_str("db worker did not answer custody"));
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
pub(super) fn install_hello_intake(hub: RelayHub) -> Result<(), JsValue> {
    let hello = BroadcastChannel::new(super::HELLO_CHANNEL)
        .map_err(|err| JsValue::from_str(&format!("hello channel: {err:?}")))?;
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
