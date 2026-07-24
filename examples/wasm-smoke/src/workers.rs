//! Entry points and page-side glue for the leader topology.
//!
//! One tab wins the leader lock and spawns the dedicated DB worker, the
//! only browsing context kind with OPFS sync access handles. The worker
//! owns the durable replica (sahpool), the server connection, and the relay
//! hub, and reaps dead tabs through their liveness locks. Every tab,
//! leader included, speaks the wire protocol to it over its own uniquely
//! named `BroadcastChannel`, which crosses unrelated same-origin contexts
//! with no broker.
//!
//! The intake rendezvous rides the shared hello channel and is ack-based,
//! because a `BroadcastChannel` never buffers for future subscribers: the
//! worker answers `ask` with `ready` once its intake exists, a tab then
//! announces `tab:{wire}` and waits for `attached:{wire}` before connecting,
//! so the handshake cannot outrun the worker's end of the wire channel.
//!
//! The DB worker holds an alive lock for its whole life, so tab transports
//! detect its death (a broadcast peer dies silently) and a reconnecting
//! tab's factory finds the replacement worker through the same ready
//! handshake. Multi-page leader election lives in [`crate::leader`]: a page
//! that wins the leader lock spawns the worker through [`spawn_db_worker`].

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use js_sys::Promise;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{BroadcastChannel, MessageEvent, Worker, WorkerOptions, WorkerType};

use crate::relay::HubReconnect;
use crate::{BroadcastTransport, BrowserSocket, HubNotice, RelayHub, locks};
use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection};
use connetto_core::messages::SubscriptionSpec;

/// The demo server every smoke context connects to.
pub const DEMO_WS_URL: &str = "ws://127.0.0.1:7777/";
/// The replica schema: `orders` is the server-synced table, `notes` exists
/// only in the replica tiers.
pub const DEMO_SQLITE_DDL: &str = "\
CREATE TABLE orders (id INTEGER PRIMARY KEY NOT NULL, quantity INTEGER) STRICT;\
CREATE TABLE notes (id INTEGER PRIMARY KEY NOT NULL, body TEXT) STRICT;";
/// The upstream subscription the DB worker registers.
pub const DEMO_QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";
/// The OPFS file holding the DB worker's durable replica.
pub const DB_NAME: &str = "connetto-relay.sqlite";
/// The shared rendezvous channel for worker readiness and tab announcements.
pub const HELLO_CHANNEL: &str = "connetto-hello";
/// The web lock the DB worker holds for its whole life. Tab transports
/// watch it for dead-worker detection.
pub const DB_ALIVE_LOCK: &str = "connetto-db-alive";

thread_local! {
    /// The DB worker's alive lock, held until the worker context dies.
    static DB_ALIVE: RefCell<Option<locks::HeldLock>> = const { RefCell::new(None) };
}

/// Page side, leader only: spawn the dedicated DB worker.
///
/// The worker URL resolves against the glue URL, never the page location,
/// so it also works when a harness runs the page under a wrapper URL.
///
/// # Errors
///
/// The URL or `Worker` constructor's error when the worker cannot be
/// created.
pub fn spawn_db_worker(glue_url: &str) -> Result<Worker, JsValue> {
    let options = WorkerOptions::new();
    options.set_type(WorkerType::Module);
    options.set_name("connetto-db");
    let base = web_sys::Url::new_with_base("db-worker.js", glue_url)?;
    let encoded = String::from(js_sys::encode_uri_component(glue_url));
    Worker::new_with_options(&format!("{}?glue={encoded}", base.href()), &options)
}

/// Page side: resolve once the DB worker's intake answers on the hello
/// channel. Asks repeatedly, since asks posted before the worker's boot
/// finished are lost, not queued.
pub async fn await_db_worker_ready() {
    let channel = BroadcastChannel::new(HELLO_CHANNEL).expect("hello channel");
    let ready = Rc::new(Cell::new(false));
    let on_message = {
        let ready = Rc::clone(&ready);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if event.data().as_string().as_deref() == Some("ready") {
                ready.set(true);
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    while !ready.get() {
        let _ = channel.post_message(&JsValue::from_str("ask"));
        sleep_ms(50).await;
    }
    channel.set_onmessage(None);
    channel.close();
}

/// Page side: announce a tab's wire channel and wait for the worker's
/// attachment ack, after which the wire channel's far end exists and the
/// client handshake cannot be lost.
pub async fn announce_tab(wire: &str) {
    let channel = BroadcastChannel::new(HELLO_CHANNEL).expect("hello channel");
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
    while !attached.get() {
        sleep_ms(10).await;
    }
    channel.set_onmessage(None);
    channel.close();
}

/// DB worker context: install the OPFS VFS, open the durable replica
/// (resuming an existing one from its persisted cursor), connect upstream,
/// wait for the subscription to be fully served, hold the alive lock,
/// start the relay hub with upstream reconnect, wire dead-tab reaping, and
/// open the hello channel intake. `db-worker.js` awaits this.
///
/// # Errors
///
/// A string describing the VFS, upstream connect, or subscribe failure.
#[wasm_bindgen]
pub async fn db_worker_boot() -> Result<(), JsValue> {
    let util = sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    .map_err(|err| JsValue::from_str(&format!("install sahpool: {err:?}")))?;

    let transport = BrowserSocket::connect(DEMO_WS_URL).await.map_err(to_js)?;
    let config = ClientConfig {
        client_id: format!("db-worker-{}", js_sys::Date::now()),
        auth_token: "token".to_owned(),
    };
    // A replica left by a previous worker generation resumes: the persisted
    // cursor rides the handshake and the subscription below catches up from
    // the server oplog instead of re-snapshotting.
    let existing = util.exists(DB_NAME).unwrap_or(false);
    let mut worker = if existing {
        ConnettoConnection::connect_existing(transport, DB_NAME, &config, None)
            .await
            .map_err(to_js)?
    } else {
        ConnettoConnection::connect(transport, DB_NAME, DEMO_SQLITE_DDL, &config, None)
            .await
            .map_err(to_js)?
    };
    web_sys::console::log_1(
        &format!(
            "db worker: {} replica",
            if existing {
                "resuming the existing"
            } else {
                "creating a fresh"
            }
        )
        .into(),
    );
    worker
        .subscribe("db-upstream", DEMO_QUERY)
        .await
        .map_err(to_js)?;
    // Ping fence instead of waiting for a snapshot end: a resumed
    // subscription catches up with plain live patches and never sends one.
    // Control frames are processed in order, so the pong proves the
    // subscription is fully served either way.
    worker.ping(1).await.map_err(to_js)?;
    loop {
        match worker.pump_one().await.map_err(to_js)? {
            ClientEvent::Pong { nonce: 1 } => break,
            ClientEvent::Closed => {
                return Err(JsValue::from_str("server closed during the upstream boot"));
            }
            _ => {}
        }
    }

    // Held for the worker's whole life: tab transports watch this lock to
    // detect a dead worker, and the browser releases it with the context.
    let alive = locks::hold_lock(DB_ALIVE_LOCK).await;
    DB_ALIVE.with(|cell| cell.borrow_mut().replace(alive));

    let reconnect = HubReconnect {
        factory: || async {
            BrowserSocket::connect(DEMO_WS_URL)
                .await
                .map_err(|err| err.to_string())
        },
        sleeper: sleep,
        policy: ReconnectPolicy::default(),
        upstream: vec![("db-upstream".to_owned(), SubscriptionSpec::new(DEMO_QUERY))],
    };
    let (hub, pump, mut notices) =
        RelayHub::with_reconnect(worker, "connetto-hub-meta.sqlite", reconnect)
            .map_err(|err| JsValue::from_str(&format!("hub meta: {err}")))?;
    spawn_local(async move {
        if let Err(err) = pump.await {
            web_sys::console::error_1(&format!("relay hub ended: {err}").into());
        }
    });

    // Dead-tab reaping: each handshake names a liveness lock. A tab that
    // holds it is watched, and the lock coming free means the tab is gone.
    // A tab that never held it (it must acquire BEFORE connecting) opted
    // out and is never reaped.
    {
        let hub = hub.clone();
        spawn_local(async move {
            while let Some(HubNotice::Handshake { tab, client_id }) = notices.recv().await {
                let hub = hub.clone();
                spawn_local(async move {
                    let name = locks::tab_lock_name(&client_id);
                    if !locks::lock_is_held(&name).await {
                        return;
                    }
                    locks::wait_until_free(&name).await;
                    hub.kill(tab);
                });
            }
        });
    }

    // The hello channel intake: answer readiness asks and attach a wire
    // transport per tab announcement, acking each attachment.
    let hello = BroadcastChannel::new(HELLO_CHANNEL)
        .map_err(|err| JsValue::from_str(&format!("hello channel: {err:?}")))?;
    let intake = {
        let hello = hello.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(message) = event.data().as_string() else {
                return;
            };
            if message == "ask" {
                let _ = hello.post_message(&JsValue::from_str("ready"));
            } else if let Some(wire) = message.strip_prefix("tab:") {
                match BroadcastTransport::new(wire) {
                    Ok(transport) => {
                        hub.attach(transport);
                        let _ = hello.post_message(&JsValue::from_str(&format!("attached:{wire}")));
                    }
                    Err(err) => {
                        web_sys::console::error_1(
                            &format!("tab wire channel {wire} failed: {err}").into(),
                        );
                    }
                }
            }
        })
    };
    hello.set_onmessage(Some(intake.as_ref().unchecked_ref()));
    // The intake handler lives for the worker's whole life.
    intake.forget();
    let _ = hello.post_message(&JsValue::from_str("ready"));
    Ok(())
}

/// A transport factory for a reconnecting tab client: every attempt waits
/// for a ready DB worker, announces a fresh wire channel, and returns a
/// transport watching the worker's alive lock, so a dead worker surfaces
/// as a clean close instead of silence. Pass it to
/// `ConnettoClient::with_reconnect` together with [`sleep`] as the sleeper.
pub fn tab_wire_factory(
    client_id: String,
) -> impl FnMut() -> std::pin::Pin<
    Box<dyn Future<Output = Result<crate::BroadcastTransport, crate::BroadcastTransportError>>>,
> {
    let mut attempt: u64 = 0;
    move || {
        attempt += 1;
        let wire = format!(
            "connetto-wire-{client_id}-{attempt}-{}",
            js_sys::Date::now()
        );
        Box::pin(async move {
            await_db_worker_ready().await;
            announce_tab(&wire).await;
            BroadcastTransport::with_peer_liveness(&wire, DB_ALIVE_LOCK)
        })
    }
}

/// Resolve after roughly `duration`, in a window or a worker context. Also
/// the browser [`Sleeper`](connetto_client::reconnect::Sleeper) for the
/// reconnect drivers.
pub async fn sleep(duration: core::time::Duration) {
    let ms = i32::try_from(duration.as_millis()).unwrap_or(i32::MAX);
    sleep_ms(ms).await;
}

/// Resolve after `ms` milliseconds, in a window or a worker context.
async fn sleep_ms(ms: i32) {
    let promise = Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        let set_timeout = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
            .ok()
            .and_then(|f| f.dyn_into::<js_sys::Function>().ok());
        if let Some(set_timeout) = set_timeout {
            let _ = set_timeout.call2(&global, &resolve, &JsValue::from_f64(f64::from(ms)));
        }
    });
    let _ = JsFuture::from(promise).await;
}

/// Fold any displayable error into a JS string error.
fn to_js(err: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&err.to_string())
}
