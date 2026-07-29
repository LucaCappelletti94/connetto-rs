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
use connetto_client::{ClientConfig, ClientEvent, ConnettoConnection, Replica};
use connetto_core::messages::SubscriptionSpec;
use diesel::connection::SimpleConnection;
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
    /// The base name of the OPFS file holding the durable synced replica.
    /// With `auth` set the worker appends the authenticated identity, so each
    /// identity owns its own replica file and an account switch opens a
    /// different one. With `auth` unset this is the file name verbatim.
    pub replica_db_prefix: &'static str,
    /// The synced replica DDL, applied only on a first boot (a resumed
    /// replica keeps its schema and its persisted cursor).
    pub replica_ddl: &'static str,
    /// The OPFS file holding the durable local tier (device-private tables,
    /// never synced).
    pub frontend_db_name: &'static str,
    /// The local tier DDL, applied only on a first boot, exactly like
    /// `replica_ddl`.
    ///
    /// The tier used to first-boot from a baked byte-image template, and cannot
    /// any more: a template is a plaintext database, the per-replica key does not
    /// exist at build time, and neither page codec offers a
    /// plaintext-to-encrypted transform that works on both backends. DDL is the
    /// route that works whether the tier is encrypted or not, and the replica
    /// already took it.
    pub frontend_ddl: &'static str,
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
    /// Custom SQLite functions connetto registers on every connection the
    /// worker opens (the synced replica and the local tier alike), before any
    /// DDL or insert. Empty by default. A synced schema whose key column has a
    /// function-backed `DEFAULT` supplies the matching installer here.
    pub sql_functions: connetto_client::SqlFunctions,
    /// Browser OAuth acquisition. `None` uses a placeholder token (dev and the
    /// pre-auth loops). `Some` makes the worker acquire connetto's own token
    /// before connecting: silently from the OPFS-stored refresh token on a cold
    /// start or leader failover, or through an interactive tab login otherwise.
    pub auth: Option<crate::auth::WorkerAuthConfig>,
    /// The OPFS database holding the worker-only refresh token, used only when
    /// `auth` is set.
    pub auth_db_name: &'static str,
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

/// Acquire connetto's own session in the worker: silently refresh from the
/// OPFS-stored refresh token, or drive an interactive tab login when there is
/// none. Returns the access token plus the typed identity and session deadline
/// the worker needs to select the replica file and to warn before an offline
/// session lapses. The worker holds the tokens throughout; a tab only ever
/// sees the login URL and returns the authorization code.
///
/// The refresh store is encrypted under this device's own key, which is minted on
/// first use. A store that does not open under it is a store from before the key
/// existed, or one whose key was destroyed: either way the credential inside is
/// unreachable and the only recovery is a fresh login, so it is discarded rather
/// than reported as a boot failure.
async fn acquire_session<Id: serde::de::DeserializeOwned>(
    auth: &crate::auth::WorkerAuthConfig,
    auth_db_name: &str,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::ReplicaKeyStore,
) -> Result<crate::auth::BrowserSession<Id>, JsValue> {
    let device_key = crate::storage::device_key(key_store).await.map_err(to_js)?;
    let auth_db_url = storage.db_url(auth_db_name, true);
    let store = match crate::auth::RefreshStore::open(&auth_db_url, &device_key) {
        Ok(store) => store,
        Err(crate::auth::AuthError::Undecryptable(detail)) => {
            web_sys::console::warn_1(
                &format!(
                    "db worker: the refresh store does not decrypt ({detail}), discarding it and requiring a fresh login"
                )
                .into(),
            );
            storage.delete_db(auth_db_name).map_err(to_js)?;
            crate::auth::RefreshStore::open(&auth_db_url, &device_key).map_err(to_js)?
        }
        Err(err) => return Err(to_js(err)),
    };
    let authenticator = crate::auth::BrowserAuthenticator::new(auth.clone());
    match authenticator.acquire(&store).await.map_err(to_js)? {
        crate::auth::Acquired::Access(session) => Ok(session),
        crate::auth::Acquired::NeedLogin(pending) => {
            let (code, state) = crate::auth::await_login_code(&pending.login_url)
                .await
                .map_err(to_js)?;
            authenticator
                .complete(&pending, &code, &state, &store)
                .await
                .map_err(to_js)
        }
    }
}

/// DB worker context: install the OPFS VFS, acquire connetto's session, open
/// the replica that identity owns (resuming an existing one from its persisted
/// cursor), connect upstream, wait for the subscription to be fully served,
/// hold the alive lock, start the relay hub with upstream reconnect, wire
/// dead-tab reaping, and open the hello channel intake. The consumer's
/// `db-worker.js` awaits the `#[wasm_bindgen]` wrapper that calls this.
///
/// `Id` is the deployment's typed user id, the one connetto-server mints into
/// its token responses. It names the replica file, so it must be given even
/// when `config.auth` is `None`, where no identity is ever acquired and the
/// replica keeps `config.replica_db_prefix` verbatim.
///
/// # Errors
///
/// A string describing the VFS, acquisition, upstream connect, or subscribe
/// failure.
#[allow(clippy::too_many_lines)]
pub async fn boot_db_worker<Id>(config: &DbWorkerConfig) -> Result<(), JsValue>
where
    Id: serde::Serialize + serde::de::DeserializeOwned,
{
    let storage = crate::storage::ReplicaStorage::install().await;

    // Acquire connetto's own access token when auth is configured: a silent
    // refresh from the OPFS-stored token on a cold start or leader failover,
    // or an interactive tab login otherwise. The worker holds the tokens; the
    // tab only ever sees the login URL and hands back the code.
    //
    // This runs before any transport exists, because the authenticated
    // identity decides which replica file to open. Connecting first and
    // checking identity afterwards would resume the previous identity's
    // replica over the wire under the new user's token.
    //
    // One key store serves the whole boot: this device's own key, which unlocks
    // the refresh store, and the per-replica key both live in it, and opening
    // IndexedDB twice buys nothing.
    let key_store = match &config.auth {
        Some(_) => Some(crate::auth::ReplicaKeyStore::open().await.map_err(to_js)?),
        None => None,
    };

    // Every wipe the application asked for is carried out here, before the login
    // and before anything is opened.
    //
    // Two reasons for this position, both learned the hard way. Nothing holds the
    // replica yet: once the hub's pump owns the connection it holds it for this
    // worker's whole life, and the OPFS delete cannot run against a live one. And
    // it is ahead of acquisition, because acquisition blocks on an interactive
    // login when the credential was cleared, which is exactly what logging out
    // does. A wipe behind that wait would only happen once somebody logged in
    // again, and only if it were the same somebody, so a user who asked to have
    // their data deleted and never came back would keep it.
    //
    // Each record names its own replica, so no identity is needed to act on it.
    // The unsynced guard ran when the record was written, which is the one moment
    // the queued writes could still have been uploaded, so this is unconditional.
    // A failure is fatal to the boot rather than logged past: the record is already
    // taken, so continuing would open a replica the user asked to destroy.
    if let Some(keys) = &key_store {
        for name in crate::storage::take_pending_wipes().await.map_err(to_js)? {
            crate::storage::wipe_replica(&storage, keys, &name, &[], true)
                .await
                .map_err(to_js)?;
            web_sys::console::log_1(
                &format!("db worker: carried out the pending data wipe of {name}").into(),
            );
        }
    }

    let session = match (&config.auth, &key_store) {
        (Some(auth_config), Some(keys)) => {
            Some(acquire_session::<Id>(auth_config, config.auth_db_name, &storage, keys).await?)
        }
        _ => None,
    };
    // Identity continuity by file selection: each identity owns the replica
    // named from its own id, so an account switch opens a different file and
    // can neither adopt the previous identity's rows nor upload its pending
    // mutations. The identity that just left keeps its replica: switching back
    // resumes from its persisted cursor instead of re-snapshotting, and any
    // mutation it never got to upload is still there to replay. Destroying a
    // replica is an explicit data wipe, never a side effect of someone else
    // signing in.
    let replica_db_name = match &session {
        Some(session) => {
            connetto_client::replica_db_name(config.replica_db_prefix, &session.user_id)
                .map_err(to_js)?
        }
        None => config.replica_db_prefix.to_owned(),
    };
    // A replica left by a previous worker generation of the SAME identity
    // resumes: the persisted cursor rides the handshake and the subscription
    // below catches up from the server oplog instead of re-snapshotting.
    let existing = storage.exists(&replica_db_name);

    // Provision-once custody of the per-replica encryption key, minted on this
    // device. It resolves here rather than inside acquisition because the record
    // is addressed by the replica name, which only exists once the identity
    // does. A fresh replica mints its key and caches it. An existing one reads
    // the cache and nothing else: minting for it would return a key that
    // decrypts nothing, and would fill the record that restoring a backed-up
    // key still could, so an absent record refuses in `Replica::encrypted_file`
    // instead.
    let replica_key = match &key_store {
        Some(keys) => {
            if existing {
                keys.load(&replica_db_name).await.map_err(to_js)?
            } else {
                Some(
                    crate::auth::provision_replica_key(keys, &replica_db_name)
                        .await
                        .map_err(to_js)?,
                )
            }
        }
        None => None,
    };
    // Encrypted whenever authentication is configured, because that is exactly
    // when an identity, and so a key store record addressed by it, exists. With
    // auth unset there is no identity to name a record after, so the replica is
    // plaintext and says so. The refusal for "auth configured but the key store
    // no longer holds this replica's key" lives in `Replica::encrypted_file`, so
    // a native application gets the same behaviour rather than a second
    // implementation of it here.
    let encrypted = config.auth.is_some();

    let auth_token = session
        .as_ref()
        .map_or_else(|| "token".to_owned(), |s| s.access_token.clone());
    let client_config = ClientConfig {
        client_id: format!("{}-{}", config.client_id_prefix, js_sys::Date::now()),
        auth_token,
        schema_version: Some(config.schema_version.clone()),
        sql_functions: config.sql_functions.clone(),
    };
    let transport = BrowserSocket::connect(config.ws_url).await.map_err(to_js)?;
    let replica_url = storage.db_url(&replica_db_name, encrypted);
    // Always a durable file here: OPFS, or the in-memory VFS's named file when
    // OPFS is unavailable. Never `Ephemeral`, which is the tab's case.
    let replica = if encrypted {
        Replica::encrypted_file(&replica_url, replica_key).map_err(to_js)?
    } else {
        Replica::PlaintextFile { path: &replica_url }
    };
    let mut worker = if existing {
        ConnettoConnection::connect_existing(transport, &replica, &client_config, None)
            .await
            .map_err(to_js)?
    } else {
        ConnettoConnection::connect(
            transport,
            &replica,
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
    // The local tier is a second connection whose main schema IS the tier file,
    // because a changeset apply always targets main. The worker replica never
    // contains these tables, so a note can never ride an upstream mutation.
    //
    // Being its own main database, it carries its own key salt and is unlocked
    // independently, unlike the native tier which is attached to the replica and
    // inherits from it. Same key either way: one device, one key.
    let tier_is_new = !storage.exists(config.frontend_db_name);
    let mut frontend =
        SqliteConnection::establish(&storage.db_url(config.frontend_db_name, encrypted))
            .map_err(|err| JsValue::from_str(&format!("open the frontend tier: {err}")))?;
    if let Some(key) = replica.key() {
        connetto_client::cipher::unlock(&mut frontend, key)
            .map_err(|err| JsValue::from_str(&format!("unlock the frontend tier: {err}")))?;
    }
    // Same registrar set as the replica: connetto installs it on every
    // connection it opens, before any DDL or insert, even where the tier
    // schema does not call a registered function.
    config
        .sql_functions
        .install(&mut frontend)
        .map_err(|err| JsValue::from_str(&format!("register sql functions on the tier: {err}")))?;
    if tier_is_new {
        frontend
            .batch_execute(config.frontend_ddl)
            .map_err(|err| JsValue::from_str(&format!("apply the frontend tier schema: {err}")))?;
    }
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
