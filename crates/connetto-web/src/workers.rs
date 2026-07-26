//! DB worker orchestration and page-side glue for the leader topology.
//!
//! One tab wins the leader lock and spawns the dedicated DB worker, the
//! only browsing context kind with OPFS sync access handles. The worker
//! owns the durable replica and the local tier file (sahpool), the server
//! connection, and the relay hub, and reaps dead tabs through their
//! liveness locks. Every tab,
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
//!
//! The application supplies the demo-specific pieces (server URL, replica
//! and tier schema, upstream query, database names, baked tier template)
//! through [`DbWorkerConfig`], so this crate bakes nothing application
//! specific: the consumer's `#[wasm_bindgen]` entry point calls
//! [`boot_db_worker`] with its own config.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use js_sys::Promise;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{BroadcastChannel, MessageEvent, Worker, WorkerOptions, WorkerType};

use crate::relay::{HubReconnect, LocalTier};
use crate::{BroadcastTransport, BrowserSocket, HubNotice, RelayHub, locks};
use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection};
use connetto_core::messages::SubscriptionSpec;
use diesel::{Connection, SqliteConnection};

/// The shared rendezvous channel for worker readiness and tab announcements.
pub const HELLO_CHANNEL: &str = "connetto-hello";
/// The web lock the DB worker holds for its whole life. Tab transports
/// watch it for dead-worker detection.
pub const DB_ALIVE_LOCK: &str = "connetto-db-alive";

thread_local! {
    /// The DB worker's alive lock, held until the worker context dies.
    static DB_ALIVE: RefCell<Option<locks::HeldLock>> = const { RefCell::new(None) };
}

/// The application-specific inputs [`boot_db_worker`] needs: this crate ships
/// no demo schema, server URL, or baked template, so the consumer passes them
/// here. The consumer's `#[wasm_bindgen] db_worker_boot` builds one of these
/// from its own constants and awaits [`boot_db_worker`].
pub struct DbWorkerConfig {
    /// The server WebSocket URL the worker connects upstream to.
    pub ws_url: &'static str,
    /// The OPFS file holding the durable synced replica.
    pub replica_db_name: &'static str,
    /// The synced replica DDL, applied only on a first boot (a resumed
    /// replica keeps its schema and its persisted cursor).
    pub replica_ddl: &'static str,
    /// The OPFS file holding the durable local tier (device-private tables,
    /// never synced).
    pub frontend_db_name: &'static str,
    /// The baked local tier template, imported on a first boot.
    pub frontend_template: &'static [u8],
    /// The subscription id the worker registers upstream.
    pub upstream_sub_id: &'static str,
    /// The subscription query the worker registers upstream.
    pub upstream_query: &'static str,
    /// The attached database file holding the hub's own durable state.
    pub hub_meta_name: &'static str,
    /// The prefix of the worker's client id (a timestamp is appended).
    pub client_id_prefix: &'static str,
    /// The schema version this app build was compiled against. The worker
    /// presents it to the server at handshake (a mismatch is a stale build)
    /// and the hub forwards the server's version to tabs for the same check.
    pub schema_version: connetto_core::SchemaVersion,
}

/// The worker's SQLite storage backend. OPFS through the sahpool VFS is the
/// durable default. When OPFS is unavailable (a Firefox private window
/// refuses `getDirectory` with a `SecurityError`, for one), the worker falls
/// back to the in-memory VFS so the app still boots instead of dying: this
/// session gets no persistence and no cross-window OPFS sharing, but the live
/// topology over `BroadcastChannel` and Web Locks stays intact.
enum WorkerStorage {
    Opfs(sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil),
    Memory(sqlite_wasm_rs::MemVfsUtil<sqlite_wasm_rs::WasmOsCallback>),
}

impl WorkerStorage {
    /// Install OPFS if the browser allows it, otherwise the in-memory VFS
    /// (already registered as the default VFS at SQLite init, so plain file
    /// names resolve to it once sahpool declines to take over the default).
    async fn install() -> Self {
        match sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
            &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
            true,
        )
        .await
        {
            Ok(util) => Self::Opfs(util),
            Err(err) => {
                web_sys::console::warn_1(
                    &format!(
                        "db worker: OPFS unavailable ({err:?}), using an in-memory replica: no persistence and no cross-window OPFS sharing this session"
                    )
                    .into(),
                );
                Self::Memory(sqlite_wasm_rs::MemVfsUtil::new())
            }
        }
    }

    /// Whether a database file of this name already exists in the backend.
    fn exists(&self, name: &str) -> bool {
        match self {
            Self::Opfs(util) => util.exists(name).unwrap_or(false),
            Self::Memory(util) => util.exists(name),
        }
    }

    /// Import baked template bytes as a new database file.
    fn import_db(&self, name: &str, bytes: &[u8]) -> Result<(), JsValue> {
        let result = match self {
            Self::Opfs(util) => util
                .import_db(name, bytes)
                .map_err(|err| format!("{err:?}")),
            Self::Memory(util) => util
                .import_db(name, bytes)
                .map_err(|err| format!("{err:?}")),
        };
        result.map_err(|err| JsValue::from_str(&format!("import {name}: {err}")))
    }
}

/// How the leader launches the dedicated DB worker, which differs only by how
/// the app's wasm-bindgen glue initializes.
pub enum WorkerBootstrap {
    /// The glue auto-initializes on import and runs `main` (a bundler such as
    /// dx). The worker is the glue module itself, so `main` boots the DB tier
    /// in its no-`Window` branch with no extra script.
    Glue,
    /// A separately served bootstrap script that imports the glue named by an
    /// appended `glue` query parameter. The `String` is that script's URL.
    Script(String),
    /// A connetto-generated bootstrap: a blob module that imports the glue and
    /// initializes the wasm (URL derived from the glue URL by swapping the
    /// `.js` suffix for `_bg.wasm`), letting `init` run `main`, which boots the
    /// DB tier. For bundlers whose glue does not self-initialize (trunk), so
    /// the consumer ships no worker JS of its own.
    Generated,
}

/// Page side, leader only: spawn the dedicated DB worker from `glue_url`
/// according to `bootstrap`.
///
/// # Errors
///
/// The `Worker` constructor's error, or a blob-URL failure for
/// [`WorkerBootstrap::Generated`].
pub fn spawn_db_worker(glue_url: &str, bootstrap: &WorkerBootstrap) -> Result<Worker, JsValue> {
    let options = WorkerOptions::new();
    options.set_type(WorkerType::Module);
    options.set_name("connetto-db");
    match bootstrap {
        WorkerBootstrap::Glue => Worker::new_with_options(glue_url, &options),
        WorkerBootstrap::Script(script_url) => {
            let encoded = String::from(js_sys::encode_uri_component(glue_url));
            let separator = if script_url.contains('?') { '&' } else { '?' };
            Worker::new_with_options(&format!("{script_url}{separator}glue={encoded}"), &options)
        }
        WorkerBootstrap::Generated => {
            let object_url = generated_bootstrap_url(glue_url)?;
            let worker = Worker::new_with_options(&object_url, &options);
            // The worker takes its reference to the blob during construction,
            // so the object URL can be released regardless of the outcome.
            let _ = web_sys::Url::revoke_object_url(&object_url);
            worker
        }
    }
}

/// Build the blob-module bootstrap for [`WorkerBootstrap::Generated`] and
/// return its object URL. The module imports the glue and initializes the wasm
/// with the derived binary URL (the stock wasm-bindgen web glue does not
/// self-initialize, and its built-in default fetches the un-hashed name);
/// `init` runs `main`, which boots the DB tier in its no-`Window` branch.
fn generated_bootstrap_url(glue_url: &str) -> Result<String, JsValue> {
    let wasm_url = glue_url.strip_suffix(".js").map_or_else(
        || format!("{glue_url}_bg.wasm"),
        |base| format!("{base}_bg.wasm"),
    );
    let source = format!(
        "try {{\n  const mod = await import({glue});\n  await mod.default({{ module_or_path: {wasm} }});\n}} catch (err) {{\n  new BroadcastChannel(\"connetto-debug\").postMessage(\"db worker bootstrap FAILED: \" + err);\n  throw err;\n}}\n",
        glue = js_string_literal(glue_url),
        wasm = js_string_literal(&wasm_url),
    );
    let parts = js_sys::Array::of1(&JsValue::from_str(&source));
    let options = web_sys::BlobPropertyBag::new();
    options.set_type("text/javascript");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &options)?;
    web_sys::Url::create_object_url_with_blob(&blob)
}

/// Encode a string as a JS double-quoted string literal for generated source.
fn js_string_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
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
/// open the hello channel intake. The consumer's `db-worker.js` awaits the
/// `#[wasm_bindgen]` wrapper that calls this.
///
/// # Errors
///
/// A string describing the VFS, upstream connect, or subscribe failure.
#[allow(clippy::too_many_lines)]
pub async fn boot_db_worker(config: &DbWorkerConfig) -> Result<(), JsValue> {
    let storage = WorkerStorage::install().await;

    let transport = BrowserSocket::connect(config.ws_url).await.map_err(to_js)?;
    let client_config = ClientConfig {
        client_id: format!("{}-{}", config.client_id_prefix, js_sys::Date::now()),
        auth_token: "token".to_owned(),
        schema_version: Some(config.schema_version.clone()),
    };
    // A replica left by a previous worker generation resumes: the persisted
    // cursor rides the handshake and the subscription below catches up from
    // the server oplog instead of re-snapshotting.
    let existing = storage.exists(config.replica_db_name);
    let mut worker = if existing {
        ConnettoConnection::connect_existing(
            transport,
            config.replica_db_name,
            &client_config,
            None,
        )
        .await
        .map_err(to_js)?
    } else {
        ConnettoConnection::connect(
            transport,
            config.replica_db_name,
            config.replica_ddl,
            &client_config,
            None,
        )
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
    // The local tier: first boot imports the baked frontend template. The
    // hub serves these tables from a second connection whose main schema
    // IS the tier file, because a changeset apply always targets main.
    // The worker replica never contains them, so a note can never ride an
    // upstream mutation.
    if !storage.exists(config.frontend_db_name) {
        storage.import_db(config.frontend_db_name, config.frontend_template)?;
    }
    let frontend = SqliteConnection::establish(config.frontend_db_name)
        .map_err(|err| JsValue::from_str(&format!("open the frontend tier: {err}")))?;
    let local = LocalTier::new(frontend).map_err(to_js)?;
    worker
        .subscribe(config.upstream_sub_id, config.upstream_query)
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

    let ws_url = config.ws_url;
    let reconnect = HubReconnect {
        factory: move || async move {
            BrowserSocket::connect(ws_url)
                .await
                .map_err(|err| err.to_string())
        },
        sleeper: sleep,
        policy: ReconnectPolicy::default(),
        upstream: vec![(
            config.upstream_sub_id.to_owned(),
            SubscriptionSpec::new(config.upstream_query),
        )],
    };
    let (hub, pump, mut notices) =
        RelayHub::with_reconnect(worker, config.hub_meta_name, Some(local), reconnect)
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
