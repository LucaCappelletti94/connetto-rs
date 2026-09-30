//! Tab visibility aggregation for the worker's away-and-return input.
//!
//! The browser application is away when no tab of the origin is visible, and
//! back when any tab becomes visible, a closing tab counting as hidden. Each
//! tab posts its `visibilitychange` and page hide on a plain
//! `BroadcastChannel` with the tab's identity, the client id it declares to
//! the hub and that also names its liveness lock. The worker aggregates the
//! reports into one `away` moment and one `back` moment for the worker's
//! gate controller per transition, reading them from the system clock at the
//! instant the transition happens.
//!
//! Visibility is not a secret, so a channel shared with other same-origin
//! scripts is fine. The worker's private port carries nothing of this kind,
//! because it is the only channel a non-extractable key may cross.

use std::collections::HashSet;
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::JsValue;
use wasm_bindgen_futures::spawn_local;
use web_sys::{BroadcastChannel, Event, MessageEvent, VisibilityState};

use connetto_client::away::GateController;
use connetto_client::{Moment, SystemClock};

/// The channel carrying tab visibility reports.
pub const VISIBILITY_CHANNEL: &str = "connetto-visibility";

/// One report the worker's visibility tracker receives.
enum Report {
    /// A tab reported its own visibility, which also registers the tab.
    State {
        /// The reporting tab's client id.
        tab: String,
        /// Whether the tab is visible.
        visible: bool,
    },
    /// The tab's liveness lock was released, so the tab is gone and counts
    /// as hidden.
    Dead {
        /// The vanished tab's client id.
        tab: String,
    },
}

/// Decode one visibility report.
fn decode(message: &str) -> Option<(String, bool)> {
    let rest = message.strip_prefix("vis:")?;
    let (tab, state) = rest.rsplit_once(':')?;
    let visible = match state {
        "v" => true,
        "h" => false,
        _ => return None,
    };
    Some((tab.to_owned(), visible))
}

/// Report this tab's visibility to the worker under `client_id`, tab side.
///
/// The current state posts at once, so a tab that installs late still counts,
/// and each `visibilitychange` and page hide posts the new state. A closing
/// tab counts as hidden through the same report, and when it cannot report at
/// all, through the worker's watch of the tab's liveness lock.
pub fn report_visibility(client_id: impl Into<String>) {
    let id: String = client_id.into();
    let Some(window) = web_sys::window() else {
        tracing::warn!("visibility: no window to report from");
        return;
    };
    let Ok(channel) = BroadcastChannel::new(VISIBILITY_CHANNEL) else {
        tracing::error!("visibility: the visibility channel could not be opened");
        return;
    };
    let Some(document) = window.document() else {
        tracing::warn!("visibility: no document to report from");
        return;
    };
    // The current state posts before a listener can fire, so the worker sees
    // the tab from its first moment.
    let visible = document.visibility_state() != VisibilityState::Hidden;
    let message = format!("vis:{id}:{}", if visible { "v" } else { "h" });
    let _ = channel.post_message(&JsValue::from_str(&message));
    // Each listener closure owns its channel and its copy of the id, so both
    // stay open for the page's life.
    let on_change = {
        let channel = channel.clone();
        let id = id.clone();
        let document = document.clone();
        Closure::<dyn FnMut(Event)>::new(move |_event: Event| {
            let visible = document.visibility_state() != VisibilityState::Hidden;
            let message = format!("vis:{id}:{}", if visible { "v" } else { "h" });
            let _ = channel.post_message(&JsValue::from_str(&message));
        })
    };
    let on_hide = {
        let channel = channel.clone();
        let id = id.clone();
        Closure::<dyn FnMut(Event)>::new(move |_event: Event| {
            let _ = channel.post_message(&JsValue::from_str(&format!("vis:{id}:h")));
        })
    };
    let _ = document
        .add_event_listener_with_callback("visibilitychange", on_change.as_ref().unchecked_ref());
    let _ = window.add_event_listener_with_callback("pagehide", on_hide.as_ref().unchecked_ref());
    on_change.forget();
    on_hide.forget();
}

/// Aggregate the tabs' visibility into away-and-back moments for the
/// worker's client, worker side.
///
/// The application is away when no tab of the origin is visible and back when
/// any tab becomes visible, a closing tab counting as hidden. Each
/// transition feeds the client one `away` moment and one `back` moment, read
/// at the instant it happens. A tab's death is learned from its liveness lock
/// freeing, so a tab that cannot report its own close still counts as
/// hidden.
pub fn track_visibility(gate: Rc<GateController>) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Report>();
    let Ok(channel) = BroadcastChannel::new(VISIBILITY_CHANNEL) else {
        tracing::error!("visibility: the visibility channel could not be opened");
        return;
    };
    let on_message = {
        let tx = tx.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(message) = event.data().as_string() else {
                return;
            };
            if let Some((tab, visible)) = decode(&message) {
                let _ = tx.send(Report::State { tab, visible });
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
    let watch_tx = tx.clone();
    spawn_local(async move {
        let mut visible: HashSet<String> = HashSet::new();
        let mut known: HashSet<String> = HashSet::new();
        while let Some(report) = rx.recv().await {
            match report {
                Report::State {
                    tab,
                    visible: is_visible,
                } => {
                    // A tab's first report registers its liveness watch. A
                    // tab that opted out of liveness holds no lock and is
                    // never watched.
                    if known.insert(tab.clone()) {
                        watch_liveness(tab.clone(), watch_tx.clone());
                    }
                    set_visibility(&gate, &mut visible, &tab, is_visible);
                }
                // A closing tab counts as hidden.
                Report::Dead { tab } => {
                    set_visibility(&gate, &mut visible, &tab, false);
                }
            }
        }
    });
    // The tracker lives for the worker's whole life, so the channel is not
    // dropped.
    std::mem::forget(channel);
}

/// Watch a tab's liveness lock and report the tab as dead when the browser
/// releases it.
fn watch_liveness(tab: String, tx: tokio::sync::mpsc::UnboundedSender<Report>) {
    spawn_local(async move {
        let name = crate::locks::tab_lock_name(&tab);
        if crate::locks::lock_is_held(&name).await {
            crate::locks::wait_until_free(&name).await;
            let _ = tx.send(Report::Dead { tab });
        }
    });
}

/// Apply one visibility change, feeding the client the away-and-back
/// transition moments.
fn set_visibility(
    gate: &GateController,
    visible: &mut HashSet<String>,
    tab: &str,
    is_visible: bool,
) {
    let was_away = visible.is_empty();
    if is_visible {
        visible.insert(tab.to_owned());
    } else {
        visible.remove(tab);
    }
    let is_away = visible.is_empty();
    if was_away && !is_away {
        gate.back(Moment::now(&SystemClock));
    } else if !was_away && is_away {
        gate.away(Moment::now(&SystemClock));
    }
}
