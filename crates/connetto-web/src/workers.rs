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

use core::fmt::Display;
use core::future::Future;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use connetto_file_client::{BrowserStore, BrowserStoreError, ContentArchive};
use js_sys::Promise;
use sha2::{Digest, Sha256};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{BroadcastChannel, File, MessageEvent, Worker, WorkerOptions, WorkerType};

use crate::frames::{MessageTransport, MessageTransportError};
use crate::relay::HubReconnect;
use crate::{BrowserSocket, HubNotice, RelayHub, locks};
use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::reconnect::{Sleeper, TransportFactory};
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoConnection, ExportScope, Grant, ImportOutcome, Replica,
    ReplicaStorage as StorageKind, Tier,
};
use connetto_core::custody::{Custody, NoGate};
use connetto_core::messages::SubscriptionSpec;
use connetto_core::traits::{RefreshTokenStore, ReplicaKeyStore as _};
use tokio::sync::mpsc::UnboundedReceiver;

/// The shared rendezvous channel for worker readiness and tab announcements.
pub const HELLO_CHANNEL: &str = "connetto-hello";
/// The web lock the DB worker holds for its whole life. Tab transports
/// watch it for dead-worker detection.
pub const DB_ALIVE_LOCK: &str = "connetto-db-alive";
/// The channel a tab asks for a local-data export on. Its own channel rather
/// than the hello channel because the reply carries an archive, and the hello
/// channel is a string protocol every tab already listens to.
pub const EXPORT_CHANNEL: &str = "connetto-export";
/// The channel a tab asks for a local-data import on.
pub const IMPORT_CHANNEL: &str = "connetto-import";
/// Storage-pool slots [`boot_db_worker`] reserves: the four databases it opens
/// (the replica, the device-private database beside it, the refresh store and
/// the hub's own state) and a rollback journal for each, which the pool counts
/// as a file of its own and which a write cannot proceed without.
const BOOT_SLOTS: u32 = 8;

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
    ws_url: &'static str,
    /// The base name of the OPFS file holding the durable synced replica.
    /// With `auth` set the worker appends the authenticated identity, so each
    /// identity owns its own replica file and an account switch opens a
    /// different one. With `auth` unset this is the file name verbatim.
    replica_db_prefix: &'static str,
    /// The synced replica DDL, applied only on a first boot (a resumed
    /// replica keeps its schema and its persisted cursor).
    replica_ddl: &'static str,
    /// The local tier DDL, applied only on a first boot, exactly like
    /// `replica_ddl`. Its file is not named here: the worker derives it from
    /// the replica's own name through
    /// [`tier_db_name`](crate::storage::tier_db_name), so the file and the key
    /// it opens under belong to the same identity.
    ///
    /// The tier used to first-boot from a baked byte-image template, and cannot
    /// any more: a template is a plaintext database, the per-replica key does not
    /// exist at build time, and neither page codec offers a
    /// plaintext-to-encrypted transform that works on both backends. DDL is the
    /// route that works whether the tier is encrypted or not, and the replica
    /// already took it.
    frontend_ddl: &'static str,
    /// The subscription id the worker registers upstream.
    upstream_sub_id: &'static str,
    /// The subscription query the worker registers upstream.
    upstream_query: &'static str,
    /// The attached database file holding the hub's own durable state.
    hub_meta_name: &'static str,
    /// Seed for account-isolated browser content storage and archive handling.
    content_namespace: Option<&'static str>,
    // The tab's own id is not configurable: it is a fresh UUID per worker,
    // because the hub keys a durable write counter and a lock on it.
    /// The schema version this app build was compiled against. The worker
    /// presents it to the server at handshake (a mismatch is a stale build)
    /// and the hub forwards the server's version to tabs for the same check.
    schema_version: connetto_core::SchemaVersion,
    /// Custom SQLite functions connetto registers on every connection the
    /// worker opens (the synced replica and the local tier alike), before any
    /// DDL or insert. Empty by default. A synced schema whose key column has a
    /// function-backed `DEFAULT` supplies the matching installer here.
    sql_functions: connetto_client::SqlFunctions,
    /// The tables the synced replica's row-level-security translation split,
    /// from the same build that produced `replica_ddl`. Empty by default,
    /// which is right for a schema with no policies and renames nothing.
    policy_tables: connetto_client::PolicyTables,
    /// The SQLite function name a translated policy calls for the caller, from
    /// the build's `with_session_variable` mapping. Empty when no policy names
    /// the caller. The worker fills the value from the identity it signed in
    /// as, which is the same identity the replica is named from.
    caller_function: &'static str,
    /// Browser OAuth acquisition. `None` uses a placeholder token (dev and the
    /// pre-auth loops). `Some` makes the worker acquire connetto's own token
    /// before connecting: silently from the OPFS-stored refresh token on a cold
    /// start or leader failover, or through an interactive tab login otherwise.
    auth: Option<crate::auth::WorkerAuthConfig>,
    /// The OPFS database holding the worker-only refresh token, used only when
    /// `auth` is set.
    auth_db_name: &'static str,
    /// Whether to serve the passkey unlock protocol. Defaults to `false`.
    ///
    /// When `false` the worker never posts to the tab, mints or reads the
    /// stored KEK, and reports `Custody::Unverified(NoGate::Offerable)`.
    /// Every existing consumer keeps this default and needs no change.
    ///
    /// When `true` the worker installs the private-port handler, asks the tab
    /// to unlock an enrolled profile before reading anything, and asks the tab
    /// to enrol on a fresh profile after the session is acquired. The tab must
    /// call [`crate::unlock::serve_unlock`] before the worker boots.
    unlock: bool,
    /// Whether to ask the tab which account to sign in as. Defaults to `false`.
    ///
    /// When `false` the boot takes the last-used account, which is what an
    /// application with one account per person wants and needs no code.
    ///
    /// When `true` the worker offers the stored accounts to the tab after the
    /// gate and signs in as whichever one it names. The tab registers the answer
    /// with [`crate::unlock::serve_account_choice`]. Nothing registered takes the
    /// default, so this cannot strand a boot on a missing picker.
    pick_account: bool,
}

impl DbWorkerConfig {
    /// Builds with `schema_version` set and all other fields at empty or absent defaults.
    ///
    /// Supply the remaining fields with the `with_*` setters in declaration order.
    #[must_use]
    pub fn new(schema_version: connetto_core::SchemaVersion) -> Self {
        Self {
            ws_url: "",
            replica_db_prefix: "",
            replica_ddl: "",
            frontend_ddl: "",
            upstream_sub_id: "",
            upstream_query: "",
            hub_meta_name: "",
            content_namespace: None,
            schema_version,
            sql_functions: connetto_client::SqlFunctions::default(),
            policy_tables: connetto_client::PolicyTables::new(),
            caller_function: "",
            auth: None,
            auth_db_name: "",
            unlock: false,
            pick_account: false,
        }
    }

    /// The server WebSocket URL the worker connects upstream to.
    #[must_use]
    pub fn with_ws_url(mut self, ws_url: &'static str) -> Self {
        self.ws_url = ws_url;
        self
    }

    /// The base name of the OPFS file holding the durable synced replica.
    /// With `auth` set the worker appends the authenticated identity. With
    /// `auth` unset this is the file name verbatim.
    #[must_use]
    pub fn with_replica_db_prefix(mut self, replica_db_prefix: &'static str) -> Self {
        self.replica_db_prefix = replica_db_prefix;
        self
    }

    /// The synced replica DDL, applied only on a first boot.
    #[must_use]
    pub fn with_replica_ddl(mut self, replica_ddl: &'static str) -> Self {
        self.replica_ddl = replica_ddl;
        self
    }

    /// The local tier DDL, applied only on a first boot.
    #[must_use]
    pub fn with_frontend_ddl(mut self, frontend_ddl: &'static str) -> Self {
        self.frontend_ddl = frontend_ddl;
        self
    }

    /// The subscription id the worker registers upstream.
    #[must_use]
    pub fn with_upstream_sub_id(mut self, upstream_sub_id: &'static str) -> Self {
        self.upstream_sub_id = upstream_sub_id;
        self
    }

    /// The subscription query the worker registers upstream.
    #[must_use]
    pub fn with_upstream_query(mut self, upstream_query: &'static str) -> Self {
        self.upstream_query = upstream_query;
        self
    }

    /// The attached database file holding the hub's own durable state.
    #[must_use]
    pub fn with_hub_meta_name(mut self, hub_meta_name: &'static str) -> Self {
        self.hub_meta_name = hub_meta_name;
        self
    }

    /// Enables worker-owned browser content storage and attachment-aware archives.
    #[must_use]
    pub fn with_content_namespace(mut self, namespace: &'static str) -> Self {
        self.content_namespace = Some(namespace);
        self
    }

    /// Custom SQLite functions connetto registers on every connection the
    /// worker opens, before any DDL or insert.
    #[must_use]
    pub fn with_sql_functions(mut self, sql_functions: connetto_client::SqlFunctions) -> Self {
        self.sql_functions = sql_functions;
        self
    }

    /// The tables the synced replica's translation split, from the build that
    /// produced the replica DDL.
    #[must_use]
    pub fn with_policy_tables(mut self, policy_tables: connetto_client::PolicyTables) -> Self {
        self.policy_tables = policy_tables;
        self
    }

    /// The SQLite function name a translated policy calls for the caller.
    ///
    /// The worker supplies the value itself, from the identity it authenticated
    /// as, so a policy comparing against `current_setting('app.user_id')` on the
    /// server compares against the same person here.
    #[must_use]
    pub fn with_caller_function(mut self, caller_function: &'static str) -> Self {
        self.caller_function = caller_function;
        self
    }

    /// Browser OAuth acquisition.
    #[must_use]
    pub fn with_auth(mut self, auth: Option<crate::auth::WorkerAuthConfig>) -> Self {
        self.auth = auth;
        self
    }

    /// The OPFS database holding the worker-only refresh token, used only when
    /// `auth` is set.
    #[must_use]
    pub fn with_auth_db_name(mut self, auth_db_name: &'static str) -> Self {
        self.auth_db_name = auth_db_name;
        self
    }

    /// Enable the passkey unlock protocol.
    ///
    /// Set to `true` only when the tab calls
    /// [`crate::unlock::serve_unlock`] before the worker boots, otherwise the
    /// worker blocks indefinitely waiting for a tab answer.
    ///
    /// Consumers that do not call this leave the default `false` and behave
    /// exactly as before: stored KEK, no tab interaction, and
    /// `Custody::Unverified(NoGate::Offerable)` reported.
    #[must_use]
    pub fn with_unlock(mut self, unlock: bool) -> Self {
        self.unlock = unlock;
        self
    }

    /// Ask the tab which account to sign in as, rather than taking the last-used
    /// one.
    ///
    /// The list of stored accounts only exists after the gate has run, so the
    /// question is asked there: one gesture to unlock the device, then a choice of
    /// who. Register the answer with
    /// [`crate::unlock::serve_account_choice`] before the worker boots.
    #[must_use]
    pub fn with_pick_account(mut self, pick_account: bool) -> Self {
        self.pick_account = pick_account;
        self
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
        r#"try {{
  const mod = await import({glue});
  await mod.default({{ module_or_path: {wasm} }});
}} catch (err) {{
  new BroadcastChannel("connetto-debug").postMessage("db worker bootstrap FAILED: " + err);
  new BroadcastChannel("connetto-hello").postMessage("failed:" + err);
  throw err;
}}
"#,
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
/// channel.
///
/// The worker reports boot failures on the same channel. A stale or absent
/// stack therefore fails here by name rather than spinning until the browser
/// runner kills the test.
///
/// # Errors
///
/// Returns `Err(JsValue)` with a message beginning `"hello channel:"` if the browser's `BroadcastChannel` constructor fails.
/// Returns `Err(JsValue)` with a message of the form `"db worker boot failed: <detail>"` if the worker sends a failure report on the hello channel.
/// Returns `Err(JsValue)` with `"db worker did not answer readiness"` if the 15-second timeout elapses before the worker signals readiness.
pub async fn await_db_worker_ready() -> Result<(), JsValue> {
    const POLL_MS: i32 = 50;
    const TIMEOUT_MS: f64 = 15_000.0;

    enum Ready {
        Waiting,
        Up,
        Failed(String),
    }

    let channel = BroadcastChannel::new(HELLO_CHANNEL)
        .map_err(|err| JsValue::from_str(&format!("hello channel: {err:?}")))?;
    let state = Rc::new(RefCell::new(Ready::Waiting));
    let on_message = {
        let state = Rc::clone(&state);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(message) = event.data().as_string() else {
                return;
            };
            if message == "ready" {
                *state.borrow_mut() = Ready::Up;
            } else if let Some(detail) = message.strip_prefix("failed:") {
                *state.borrow_mut() = Ready::Failed(detail.to_owned());
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let started = js_sys::Date::now();
    loop {
        match &*state.borrow() {
            Ready::Up => break,
            Ready::Failed(detail) => {
                let detail = detail.clone();
                channel.set_onmessage(None);
                channel.close();
                return Err(JsValue::from_str(&format!(
                    "db worker boot failed: {detail}"
                )));
            }
            Ready::Waiting => {}
        }
        if js_sys::Date::now() - started >= TIMEOUT_MS {
            channel.set_onmessage(None);
            channel.close();
            return Err(JsValue::from_str("db worker did not answer readiness"));
        }
        let _ = channel.post_message(&JsValue::from_str("ask"));
        sleep_ms(POLL_MS).await;
    }
    channel.set_onmessage(None);
    channel.close();
    Ok(())
}

/// Page side: announce a tab's wire channel and wait for the worker's
/// attachment ack, after which the wire channel's far end exists and the
/// client handshake cannot be lost.
///
/// # Panics
///
/// Panics if the browser's `BroadcastChannel` constructor fails for the hello channel, which cannot occur in any conforming browser environment.
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
async fn acquire_session<Id: serde::de::DeserializeOwned + serde::Serialize>(
    auth: &crate::auth::WorkerAuthConfig,
    auth_db_name: &str,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
    pick_account: bool,
) -> Result<crate::auth::BrowserSession<Id>, JsValue> {
    let store = open_refresh_store(auth_db_name, storage, key_store).await?;
    let account = choose_account(&store, pick_account).await?;
    drive_acquisition(auth, &store, account).await
}

/// Which account this boot signs in as: the one the tab named, or the one this
/// device last used, or nobody.
///
/// Nobody means an interactive login, which is a first run, a profile whose
/// accounts were all signed out, and a marker naming an account whose credential
/// is gone or refused. Falling back to another stored account is deliberately not
/// done: it would open one identity's data when the user expected another's.
///
/// Asked here rather than earlier because the list comes out of the credential
/// store, and that store does not open until the gate has run.
async fn choose_account(
    store: &crate::auth::RefreshStore,
    pick_account: bool,
) -> Result<Option<String>, JsValue> {
    let remembered = crate::auth::remembered_account(store).map_err(to_js)?;
    if !pick_account {
        return Ok(remembered);
    }
    let accounts = RefreshTokenStore::accounts(store).map_err(to_js)?;
    if accounts.is_empty() && remembered.is_none() {
        // Nothing stored and nothing remembered, so there is nothing to choose
        // between and asking would put a picker in front of somebody who has no
        // account to pick.
        return Ok(None);
    }
    match crate::unlock::ask_account(&accounts).await.map_err(to_js)? {
        crate::unlock::TabAnswer::Account(crate::unlock::AccountChoice::Named(chosen)) => {
            // A name that was never offered is a caller bug, not a stale
            // credential, so it is refused rather than answered with a login.
            if !accounts.contains(&chosen) {
                return Err(to_js(crate::auth::AuthError::Context(
                    "the tab named an account that was not offered".into(),
                )));
            }
            Ok(Some(chosen))
        }
        // The application declined to override, so the default applies.
        crate::unlock::TabAnswer::Account(crate::unlock::AccountChoice::LastUsed) => Ok(remembered),
        // Somebody new, so no stored credential is addressed and the acquisition
        // runs an interactive login. Every credential already stored is left
        // alone, which is what makes this the second account rather than a
        // replacement for the first.
        crate::unlock::TabAnswer::Account(crate::unlock::AccountChoice::New) => Ok(None),
        other => Err(to_js(crate::auth::AuthError::Context(format!(
            "the tab answered the account question with {}",
            crate::unlock::answer_kind(&other)
        )))),
    }
}

/// Acquire without persisting anything, for a first run that has not settled its
/// gate yet. See [`crate::auth::DeferredRefreshStore`] for why the write cannot
/// simply happen first and be re-wrapped afterwards.
async fn acquire_deferred<Id: serde::de::DeserializeOwned + serde::Serialize>(
    auth: &crate::auth::WorkerAuthConfig,
) -> Result<
    (
        crate::auth::BrowserSession<Id>,
        crate::auth::DeferredRefreshStore,
    ),
    JsValue,
> {
    let deferred = crate::auth::DeferredRefreshStore::default();
    // A first run has no store, so there is nothing stored to try and nothing to
    // offer a picker.
    let session = drive_acquisition(auth, &deferred, None).await?;
    Ok((session, deferred))
}

/// Write a deferred acquisition through to the real store, now that the gate has
/// settled and the device key resolves under whichever key-encryption key won.
async fn persist_deferred(
    deferred: &crate::auth::DeferredRefreshStore,
    auth_db_name: &str,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
) -> Result<(), JsValue> {
    let store = open_refresh_store(auth_db_name, storage, key_store).await?;
    for (account, token) in deferred.take() {
        RefreshTokenStore::store(&store, &account, &token).map_err(to_js)?;
    }
    Ok(())
}

/// Open the refresh store under this device's own key.
async fn open_refresh_store(
    auth_db_name: &str,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
) -> Result<crate::auth::RefreshStore, JsValue> {
    let device_key = crate::storage::device_key(key_store).await.map_err(to_js)?;
    let auth_db_url = storage.db_url(auth_db_name);
    match crate::auth::RefreshStore::open(&auth_db_url, &device_key) {
        Ok(store) => Ok(store),
        Err(crate::auth::AuthError::Undecryptable(detail)) => {
            tracing::warn!(
                detail = %detail,
                "db worker: the refresh store does not decrypt, discarding it and requiring a \
                 fresh login"
            );
            storage.delete_db(auth_db_name).map_err(to_js)?;
            crate::auth::RefreshStore::open(&auth_db_url, &device_key).map_err(to_js)
        }
        Err(err) => Err(to_js(err)),
    }
}

/// Drive the authenticator against `store`: a silent refresh from whatever it
/// holds, or an interactive tab login when it holds nothing.
async fn drive_acquisition<Id, S>(
    auth: &crate::auth::WorkerAuthConfig,
    store: &S,
    account: Option<String>,
) -> Result<crate::auth::BrowserSession<Id>, JsValue>
where
    Id: serde::de::DeserializeOwned + serde::Serialize,
    S: RefreshTokenStore<Error = crate::auth::AuthError>,
{
    let authenticator = crate::auth::BrowserAuthenticator::new(auth.clone(), account);
    match authenticator.acquire(store).await.map_err(to_js)? {
        crate::auth::Acquired::Access(session) => Ok(session),
        crate::auth::Acquired::NeedLogin(pending) => {
            let (code, state) = crate::auth::await_login_code(&pending.login_url)
                .await
                .map_err(to_js)?;
            authenticator
                .complete(&pending, &code, &state, store)
                .await
                .map_err(to_js)
        }
    }
}

/// What a boot resolved about the session it opened.
///
/// One value rather than three returns, because they arrive together from one
/// token response and an application showing who is signed in usually wants the
/// rest of it too. All three are absent together when no authentication was
/// configured, which is the anonymous run that keeps nothing durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootedSession<Id> {
    /// The identity the session was acquired for.
    pub identity: Option<Id>,
    /// Unix seconds when the local session lapses if it is never refreshed again.
    ///
    /// What an application needs to warn somebody before an offline session
    /// lapses, through
    /// [`expiry_warning`](connetto_client::teardown::expiry_warning). The worker
    /// refreshes silently while it can reach the server, so this moves outward on
    /// every acquisition and a warning is only ever about a device that has been
    /// offline a long time.
    pub session_expires_at: Option<u64>,
    /// The credential-store key this identity's account is addressed by.
    ///
    /// The same value the last-used marker holds. An application offering an
    /// account picker needs it to say which of the stored accounts is the live
    /// one, and it is already computed here, so recomputing it in the application
    /// would be a second encoding of one fact.
    pub account: Option<String>,
    /// Whether configured content storage is durable, or `None` when content is disabled.
    pub content_persistent: Option<bool>,
}

async fn apply_pending_wipes(
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
) -> Result<(), JsValue> {
    for pending in crate::storage::pending_wipes().await.map_err(to_js)? {
        apply_pending_wipe(storage, key_store, &pending).await?;
    }
    Ok(())
}

async fn apply_pending_wipe(
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
    pending: &crate::storage::PendingWipe,
) -> Result<(), JsValue> {
    let content_removed = remove_pending_content(pending).await?;
    if !pending.replica_deleted() {
        crate::storage::wipe_replica(
            storage,
            key_store,
            &pending.replica,
            &crate::auth::PendingWork::default(),
            true,
        )
        .await
        .map_err(to_js)?;
    }
    match (content_removed, pending.replica_deleted()) {
        (true, _) => crate::storage::acknowledge_pending_wipe(pending)
            .await
            .map_err(to_js)?,
        (false, false) => crate::storage::defer_pending_content_wipe(pending)
            .await
            .map_err(to_js)?,
        (false, true) => {}
    }
    tracing::info!(replica = %pending.replica, "db worker: advanced a pending data wipe");
    Ok(())
}

async fn remove_pending_content(pending: &crate::storage::PendingWipe) -> Result<bool, JsValue> {
    let Some(namespace) = &pending.content_namespace else {
        return Ok(true);
    };
    let scope: web_sys::DedicatedWorkerGlobalScope =
        js_sys::global()
            .dyn_into()
            .map_err(|value: js_sys::Object| {
                JsValue::from_str(&format!("db worker scope: {value:?}"))
            })?;
    match BrowserStore::remove(&scope, namespace).await {
        Ok(()) => Ok(true),
        Err(error @ BrowserStoreError::InvalidNamespace { .. }) => Err(to_js(error)),
        Err(error) => {
            tracing::warn!(
                replica = %pending.replica,
                error = %error,
                "db worker: content wipe deferred while browser storage is unavailable"
            );
            Ok(false)
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
/// Returns what the boot resolved about the session it opened, or a
/// [`BootedSession`] carrying nothing when `config.auth` is unset. An application
/// wants all three: without them the only way to learn any of them is to acquire a
/// second session alongside this one, which duplicates the acquisition and rotates
/// the refresh token twice per boot.
///
/// # Errors
///
/// A string describing the VFS, acquisition, upstream connect, or subscribe
/// failure.

pub async fn boot_db_worker<Id>(config: &DbWorkerConfig) -> Result<BootedSession<Id>, JsValue>
where
    // `Display` because the server binds this identity as the row-level
    // security setting through the same rendering, so a policy comparing
    // against it must see the same string on both ends.
    Id: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Display,
{
    let storage = crate::storage::ReplicaStorage::install().await;
    // Encrypted regardless of auth, and the per-replica key also lives here.
    let key_store = Rc::new(crate::auth::IdbKeyStore::open().await.map_err(to_js)?);
    let was_enrolled = setup_custody(config, &key_store).await?;
    apply_pending_wipes(&storage, &key_store).await?;
    // After wipes (which free slots) and before login (which opens the refresh store).
    storage.reserve(BOOT_SLOTS).await.map_err(to_js)?;
    let session = acquire_boot_session::<Id>(config, &storage, &key_store, was_enrolled).await?;
    let mut spec = BootReplicaSpec::from_session(config, session, &storage)?;
    // Addressed by replica name, which exists only after identity resolves.
    let replica_key =
        provision_or_load_key(&key_store, &spec.replica_db_name, spec.existing).await?;
    let content_root_key = replica_key.as_ref().map(|key| *key.as_bytes());
    let login = spec.login.take();
    let client_config = build_boot_client_config(config, login, &spec);
    // Offline at boot is valid; the hub reconnects when a transport is available.
    let transport = try_connect_upstream(config.ws_url).await;
    let mut worker =
        open_boot_replica(transport, &spec, config, &client_config, replica_key).await?;
    subscribe_and_boot(&mut worker, config).await?;
    // Released by the browser when this worker context dies.
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
    let (content, content_persistent, content_wipe_namespace) = setup_content_store(
        config,
        spec.identified,
        &spec.replica_db_name,
        content_root_key,
    )
    .await?;
    let (hub, notices) = start_relay_hub(worker, config.hub_meta_name, reconnect, content)?;
    install_dead_tab_reaper(hub.clone(), notices);
    install_tab_services(
        config,
        &hub,
        &spec.replica_db_name,
        content_wipe_namespace,
        spec.active_account.as_deref(),
    )?;
    install_hello_intake(hub)?;
    Ok(BootedSession {
        identity: spec.identity,
        session_expires_at: spec.session_expires_at,
        account: spec.active_account,
        content_persistent,
    })
}

/// Boot state resolved from the session: replica paths, account key, and session fields.
struct BootReplicaSpec<Id> {
    replica_db_name: String,
    tier_db_name: String,
    replica_url: String,
    active_account: Option<String>,
    identified: bool,
    existing: bool,
    identity: Option<Id>,
    session_expires_at: Option<u64>,
    login: Option<Grant>,
}

impl<Id: serde::Serialize + core::fmt::Display> BootReplicaSpec<Id> {
    fn from_session(
        config: &DbWorkerConfig,
        session: Option<crate::auth::BrowserSession<Id>>,
        storage: &crate::storage::ReplicaStorage,
    ) -> Result<Self, JsValue> {
        // Each identity owns its own replica file; switching accounts opens a different one.
        let replica_db_name = match &session {
            Some(session) => {
                connetto_client::replica_db_name(config.replica_db_prefix, &session.user_id)
                    .map_err(to_js)?
            }
            None => config.replica_db_prefix.to_owned(),
        };
        // Keyed the same way as the credential row and the last-used marker.
        let active_account = match &session {
            Some(session) => {
                Some(connetto_client::encode_identity(&session.user_id).map_err(to_js)?)
            }
            None => None,
        };
        // A prior generation of this identity resumes from the persisted cursor.
        let existing = storage.exists(&replica_db_name);
        // Derived from the replica name so both belong to the same identity.
        let tier_db_name = crate::storage::tier_db_name(&replica_db_name);
        let replica_url = storage.db_url(&replica_db_name);
        let identified = session.is_some();
        let session_expires_at = session.as_ref().map(|s| s.session_expires_at);
        // None here means the server gets no grant and keeps everything in memory.
        let login = session.as_ref().map(|s| Grant::new(s.access_token.clone()));
        let identity = session.map(|s| s.user_id);
        Ok(Self {
            replica_db_name,
            tier_db_name,
            replica_url,
            active_account,
            identified,
            existing,
            identity,
            session_expires_at,
            login,
        })
    }
}

/// Install the unlock handler, initialise custody, and run the enrolment
/// ceremony if credentials are already on disk. Returns whether a credential
/// was enrolled.
async fn setup_custody(
    config: &DbWorkerConfig,
    key_store: &Rc<crate::auth::IdbKeyStore>,
) -> Result<bool, JsValue> {
    // Thread-local must be valid even when unlock is disabled.
    if config.unlock {
        crate::unlock::install_worker_handler()?;
    }
    // Overwritten below on enrolment or for an ephemeral session.
    crate::unlock::init_worker(Rc::clone(key_store), Custody::Unverified(NoGate::Offerable));
    let enrolled_ids = key_store.enrolled().await.map_err(to_js)?;
    let was_enrolled = !enrolled_ids.is_empty();
    // Enrolled profiles need the protocol to derive the KEK; refusing is safer than silently falling back.
    if was_enrolled && !config.unlock {
        return Err(to_js(crate::auth::AuthError::Locked {
            detail: "a credential is enrolled but this build did not enable the unlock \
                     protocol, so nothing here can derive the key"
                .into(),
        }));
    }
    if was_enrolled {
        match crate::unlock::ask_unlock(enrolled_ids)
            .await
            .map_err(to_js)?
        {
            crate::unlock::TabAnswer::Key { credential_id, key } => {
                key_store
                    .use_derived(key, &credential_id)
                    .await
                    .map_err(to_js)?;
                crate::unlock::set_custody(Custody::Verified);
            }
            // Recovery via wipe request, not here.
            crate::unlock::TabAnswer::Declined => {
                return Err(to_js(crate::auth::AuthError::Locked {
                    detail: "the ceremony was dismissed or the credential is gone".into(),
                }));
            }
            crate::unlock::TabAnswer::Unsupported => {
                return Err(to_js(crate::auth::AuthError::Locked {
                    detail: "this browsing context cannot run the ceremony that enrolled this \
                             profile"
                        .into(),
                }));
            }
            crate::unlock::TabAnswer::Failed { detail } => {
                return Err(to_js(crate::auth::AuthError::Locked { detail }));
            }
            // Wrong answer type is a handler bug, not a platform failure.
            other @ crate::unlock::TabAnswer::Account(_) => {
                return Err(to_js(crate::auth::AuthError::Context(format!(
                    "the unlock request was answered with {}",
                    crate::unlock::answer_kind(&other)
                ))));
            }
        }
    }
    Ok(was_enrolled)
}

/// Acquire the session (deferred or direct), run the optional enrolment
/// ceremony, and persist the deferred credential once the gate has settled.
async fn acquire_boot_session<Id: serde::Serialize + serde::de::DeserializeOwned>(
    config: &DbWorkerConfig,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
    was_enrolled: bool,
) -> Result<Option<crate::auth::BrowserSession<Id>>, JsValue> {
    // Identity decides the replica file, so acquire before connecting.
    // Deferred when the gate has not settled yet, to avoid minting a KEK before enrolment.
    let defer = config.unlock
        && !was_enrolled
        && config.auth.is_some()
        && !storage.exists(config.auth_db_name);
    let (session, deferred) = match &config.auth {
        Some(auth_config) if defer => {
            let (session, deferred) = acquire_deferred::<Id>(auth_config).await?;
            (Some(session), Some(deferred))
        }
        Some(auth_config) => (
            Some(
                acquire_session::<Id>(
                    auth_config,
                    config.auth_db_name,
                    storage,
                    key_store,
                    config.pick_account,
                )
                .await?,
            ),
            None,
        ),
        None => {
            // Nothing durable: the replica is in memory and there is no key.
            crate::unlock::set_custody(Custody::Ephemeral);
            (None, None)
        }
    };
    // Unenrolled with unlock enabled: enrol now that someone is signed in.
    if config.unlock && !was_enrolled && session.is_some() {
        match crate::unlock::ask_enrol().await.map_err(to_js)? {
            crate::unlock::TabAnswer::Key { credential_id, key } => {
                key_store
                    .adopt_derived(key, &credential_id)
                    .await
                    .map_err(to_js)?;
                crate::unlock::set_custody(Custody::Verified);
            }
            crate::unlock::TabAnswer::Declined => {
                crate::unlock::set_custody(Custody::Unverified(NoGate::Declined));
            }
            crate::unlock::TabAnswer::Unsupported => {
                crate::unlock::set_custody(Custody::Unverified(NoGate::Unsupported));
            }
            // A fault is a bug, not a platform limitation; failing prevents a silent ungated profile.
            crate::unlock::TabAnswer::Failed { detail } => {
                return Err(to_js(crate::auth::AuthError::Context(format!(
                    "the enrolment ceremony failed: {detail}"
                ))));
            }
            other @ crate::unlock::TabAnswer::Account(_) => {
                return Err(to_js(crate::auth::AuthError::Context(format!(
                    "the enrolment request was answered with {}",
                    crate::unlock::answer_kind(&other)
                ))));
            }
        }
    }
    // Gate settled, so the KEK resolves under the winning key.
    if let Some(deferred) = &deferred {
        persist_deferred(deferred, config.auth_db_name, storage, key_store).await?;
    }
    Ok(session)
}

/// Load the existing replica key or mint and cache a fresh one.
async fn provision_or_load_key(
    key_store: &crate::auth::IdbKeyStore,
    replica_db_name: &str,
    existing: bool,
) -> Result<Option<connetto_core::ReplicaKey>, JsValue> {
    if existing {
        key_store.load(replica_db_name).await.map_err(to_js)
    } else {
        crate::auth::provision_replica_key(key_store, replica_db_name)
            .await
            .map_err(to_js)
            .map(Some)
    }
}

/// Build the [`ClientConfig`] from the worker config and resolved session spec.
fn build_boot_client_config<Id: core::fmt::Display>(
    config: &DbWorkerConfig,
    login: Option<Grant>,
    spec: &BootReplicaSpec<Id>,
) -> ClientConfig {
    let mut client_config = ClientConfig::new(rosetta_uuid::Uuid::new_v4().to_string())
        .with_login(login)
        .with_schema_version(Some(config.schema_version.clone()))
        .with_sql_functions(config.sql_functions.clone())
        .with_policy_tables(config.policy_tables.clone());
    if !config.caller_function.is_empty() {
        // Empty string means no owner match, hiding every row, matching server behaviour.
        client_config = client_config.with_caller(
            config.caller_function,
            spec.identity
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
        );
    }
    client_config
}

/// Attempt an upstream connection, logging a warning and returning `None` on failure.
async fn try_connect_upstream(ws_url: &str) -> Option<BrowserSocket> {
    match BrowserSocket::connect(ws_url).await {
        Ok(transport) => Some(transport),
        Err(err) => {
            tracing::warn!(
                error = %err,
                url = ws_url,
                "db worker: no server reachable, starting offline"
            );
            None
        }
    }
}

/// Build and open the correct replica variant (durable or in-memory) and log the result.
async fn open_boot_replica<Id>(
    transport: Option<BrowserSocket>,
    spec: &BootReplicaSpec<Id>,
    config: &DbWorkerConfig,
    client_config: &ClientConfig,
    replica_key: Option<connetto_core::ReplicaKey>,
) -> Result<ConnettoConnection<BrowserSocket>, JsValue> {
    // Identified runs get a durable pair; anonymous runs stay in-memory to avoid unkeyed files.
    let worker = if spec.identified {
        let replica = Replica::encrypted_file(&spec.replica_url, replica_key)
            .map_err(to_js)?
            .with_tier(&spec.tier_db_name, config.frontend_ddl);
        open_replica(transport, &replica, spec.existing, config, client_config).await?
    } else {
        let replica = Replica::in_memory().with_tier(config.frontend_ddl);
        open_replica(transport, &replica, false, config, client_config).await?
    };
    tracing::info!(
        replica = %spec.replica_db_name,
        resumed = spec.existing,
        durable = spec.identified,
        connected = worker.is_connected(),
        "db worker: replica open"
    );
    Ok(worker)
}

/// Declare the upstream subscription and pump until the pong proves it is served.
async fn subscribe_and_boot(
    worker: &mut ConnettoConnection<BrowserSocket>,
    config: &DbWorkerConfig,
) -> Result<(), JsValue> {
    // Offline: the hub declares the subscription on first reconnect instead.
    if !worker.is_connected() {
        return Ok(());
    }
    worker
        .subscribe(config.upstream_sub_id, config.upstream_query)
        .await
        .map_err(to_js)?;
    // Pong arrives after any pending snapshot, proving the subscription is fully served.
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
    Ok(())
}

/// Set up the browser content store and archive. Returns the archive, a
/// persistence flag, and the wipe namespace (when configured and identified).
async fn setup_content_store(
    config: &DbWorkerConfig,
    identified: bool,
    replica_db_name: &str,
    content_root_key: Option<[u8; 32]>,
) -> Result<
    (
        Option<ContentArchive<BrowserStore>>,
        Option<bool>,
        Option<String>,
    ),
    JsValue,
> {
    let Some(seed) = config.content_namespace else {
        return Ok((None, None, None));
    };
    let namespace = content_store_namespace(seed, replica_db_name);
    let (store, root_key) = if identified {
        let root_key = content_root_key
            .ok_or_else(|| JsValue::from_str("browser content key is unavailable"))?;
        let scope: web_sys::DedicatedWorkerGlobalScope =
            js_sys::global()
                .dyn_into()
                .map_err(|value: js_sys::Object| {
                    JsValue::from_str(&format!("db worker scope: {value:?}"))
                })?;
        let store = BrowserStore::install(&scope, &namespace)
            .await
            .map_err(|err| JsValue::from_str(&format!("browser content store: {err}")))?;
        (store, root_key)
    } else {
        (
            BrowserStore::ephemeral(),
            content_root_key.unwrap_or([0; 32]),
        )
    };
    let persistent = store.is_persistent();
    let wipe_namespace = identified.then_some(namespace);
    Ok((
        Some(ContentArchive::new(store, root_key)),
        Some(persistent),
        wipe_namespace,
    ))
}

/// Construct the relay hub, spawn its pump task, and return the hub and notice channel.
fn start_relay_hub<F, S>(
    worker: ConnettoConnection<BrowserSocket>,
    hub_meta_name: &'static str,
    reconnect: HubReconnect<F, S>,
    content: Option<ContentArchive<BrowserStore>>,
) -> Result<(RelayHub, UnboundedReceiver<HubNotice>), JsValue>
where
    F: TransportFactory<Transport = BrowserSocket> + 'static,
    F::Error: core::fmt::Display,
    S: Sleeper + Clone + 'static,
{
    let (hub, pump, notices) =
        RelayHub::with_reconnect_archive(worker, hub_meta_name, reconnect, content)
            .map_err(|err| JsValue::from_str(&format!("hub meta: {err}")))?;
    spawn_local(async move {
        if let Err(err) = pump.await {
            tracing::error!(error = %err, "relay hub ended");
        }
    });
    Ok((hub, notices))
}

/// Spawn the task that kills a tab in the hub when its liveness lock is released.
fn install_dead_tab_reaper(hub: RelayHub, mut notices: UnboundedReceiver<HubNotice>) {
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

/// Install the logout, export, and import channel handlers.
fn install_tab_services(
    config: &DbWorkerConfig,
    hub: &RelayHub,
    replica_db_name: &str,
    content_wipe_namespace: Option<String>,
    active_account: Option<&str>,
) -> Result<(), JsValue> {
    // A tab that can start a session must be able to end it.
    if let Some(auth_config) = &config.auth {
        serve_logout_requests(
            auth_config.clone(),
            config.auth_db_name,
            replica_db_name,
            content_wipe_namespace,
            active_account.map(ToOwned::to_owned),
            hub.clone(),
        )?;
    }
    // Export and import run unconditionally; anonymous sessions still hold data.
    serve_export_requests(hub.clone())?;
    serve_import_requests(hub.clone())?;
    Ok(())
}

/// Open the hello channel, install the message handler, and broadcast the initial `ready`.
fn install_hello_intake(hub: RelayHub) -> Result<(), JsValue> {
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
    // Handler lives for the worker's whole life.
    intake.forget();
    let _ = hello.post_message(&JsValue::from_str("ready"));
    Ok(())
}

/// Serve [`LOGOUT_CHANNEL`](crate::auth::LOGOUT_CHANNEL) for this worker's life,
/// answering unsynced-count questions and carrying out logouts a tab asks for.
///
/// [`boot_db_worker`] calls this itself whenever logins are configured, so an
/// application built on it needs nothing here. Call it directly when assembling a
/// worker by hand, since a [`RelayHub`] built without `boot_db_worker` would
/// otherwise have no way to offer logout.
///
/// The storage and key-store handles are opened per request rather than captured:
/// installing the VFS again hands back another handle over the same pool, and the
/// refresh store is only needed for the moment it takes to revoke, so nothing here
/// holds an encrypted database open waiting for a logout that may never come.
///
/// # Errors
///
/// The `BroadcastChannel` error when the channel cannot be opened.
pub fn serve_logout_requests(
    auth: crate::auth::WorkerAuthConfig,
    auth_db_name: &str,
    replica_db_name: &str,
    content_namespace: Option<String>,
    account: Option<String>,
    hub: crate::relay::RelayHub,
) -> Result<(), JsValue> {
    let auth_db_name = auth_db_name.to_owned();
    let replica_db_name = replica_db_name.to_owned();
    let channel = BroadcastChannel::new(crate::auth::LOGOUT_CHANNEL)
        .map_err(|err| JsValue::from_str(&format!("logout channel: {err:?}")))?;
    let listener = {
        let channel = channel.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(text) = event.data().as_string() else {
                return;
            };
            let Ok(request) = serde_json::from_str::<crate::auth::LogoutMessage>(&text) else {
                return;
            };
            let channel = channel.clone();
            let hub = hub.clone();
            let auth = auth.clone();
            let auth_db_name = auth_db_name.clone();
            let replica_db_name = replica_db_name.clone();
            let content_namespace = content_namespace.clone();
            let account = account.clone();
            spawn_local(async move {
                if let Some(reply) = serve_logout(
                    &request,
                    &hub,
                    &auth,
                    &auth_db_name,
                    &replica_db_name,
                    content_namespace.as_deref(),
                    account.as_deref(),
                )
                .await
                {
                    match serde_json::to_string(&reply) {
                        Ok(encoded) => {
                            let _ = channel.post_message(&JsValue::from_str(&encoded));
                        }
                        Err(err) => {
                            tracing::error!(error = %err, "db worker: encoding a logout reply failed");
                        }
                    }
                }
            });
        })
    };
    channel.set_onmessage(Some(listener.as_ref().unchecked_ref()));
    // The listener lives for the worker's whole life, like the hello intake.
    listener.forget();
    Ok(())
}

/// Serve [`EXPORT_CHANNEL`] for this worker's life, answering a tab's request
/// for an archive of the local tiers.
///
/// [`boot_db_worker`] calls this itself, so an application built on it needs
/// nothing here. Call it directly when assembling a worker by hand.
///
/// The reply carries bytes, so it is a structured-clone object rather than the
/// JSON strings the other channels use: base64 through a string would inflate
/// every archive by a third to say the same thing.
///
/// # Errors
///
/// The `BroadcastChannel` error when the channel cannot be opened.
pub fn serve_export_requests(hub: crate::relay::RelayHub) -> Result<(), JsValue> {
    serve_exports(move |scope| {
        let hub = hub.clone();
        async move { hub.export_local_data(scope).await }
    })
}

fn serve_exports<F, Fut, E>(export: F) -> Result<(), JsValue>
where
    F: Fn(ExportScope) -> Fut + 'static,
    Fut: Future<Output = Result<Vec<u8>, E>> + 'static,
    E: Display + 'static,
{
    let channel = BroadcastChannel::new(EXPORT_CHANNEL)
        .map_err(|err| JsValue::from_str(&format!("export channel: {err:?}")))?;
    let generation = Rc::new(rosetta_uuid::Uuid::new_v4().to_string());
    let export = Rc::new(export);
    let listener = {
        let channel = channel.clone();
        let generation = Rc::clone(&generation);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if is_export_generation_request(&event.data()) {
                if let Ok(reply) = export_generation_reply(&generation) {
                    let _ = channel.post_message(&reply);
                }
                return;
            }
            let Some((tag, scope)) = decode_export_request(&event.data()) else {
                return;
            };
            if tag.generation != *generation {
                return;
            }
            let channel = channel.clone();
            let export = Rc::clone(&export);
            spawn_local(async move {
                let reply = match export(scope).await {
                    Ok(bytes) => export_reply_ok(&tag, &bytes),
                    Err(err) => export_reply_failed(&tag, &err.to_string()),
                };
                match reply {
                    Ok(reply) => {
                        let _ = channel.post_message(&reply);
                    }
                    Err(err) => {
                        tracing::error!(error = ?err, "db worker: building an export reply failed");
                    }
                }
            });
        })
    };
    channel.set_onmessage(Some(listener.as_ref().unchecked_ref()));
    listener.forget();
    Ok(())
}

/// Serve [`IMPORT_CHANNEL`] for this worker's life, reading a `File` the page
/// hands over, applying the archive inside it, and replying with the outcome.
///
/// [`boot_db_worker`] calls this itself. Call it directly when assembling a
/// worker by hand, alongside [`serve_export_requests`].
///
/// The request is a [`web_sys::File`] object, not a string: the page posts the
/// file handle directly so the worker reads the bytes inside the worker and the
/// archive is never held twice.
///
/// # Errors
///
/// The `BroadcastChannel` error when the channel cannot be opened.
pub fn serve_import_requests(hub: crate::relay::RelayHub) -> Result<(), JsValue> {
    serve_imports(move |bytes| {
        let hub = hub.clone();
        async move { hub.import_local_data(bytes).await }
    })
}

fn serve_imports<F, Fut, E>(import: F) -> Result<(), JsValue>
where
    F: Fn(Vec<u8>) -> Fut + 'static,
    Fut: Future<Output = Result<(ImportOutcome, usize), E>> + 'static,
    E: Display + 'static,
{
    let channel = BroadcastChannel::new(IMPORT_CHANNEL)
        .map_err(|err| JsValue::from_str(&format!("import channel: {err:?}")))?;
    let import = Rc::new(import);
    let listener = {
        let channel = channel.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Ok(file) = event.data().dyn_into::<File>() else {
                return;
            };
            let channel = channel.clone();
            let import = Rc::clone(&import);
            spawn_local(async move {
                let buffer = match JsFuture::from(file.array_buffer()).await {
                    Ok(buffer) => buffer,
                    Err(err) => {
                        tracing::error!(error = ?err, "db worker: reading import file failed");
                        return;
                    }
                };
                let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
                let reply = match import(bytes).await {
                    Ok((outcome, collisions)) => import_reply_ok(&outcome, collisions),
                    Err(err) => import_reply_failed(&err.to_string()),
                };
                match reply {
                    Ok(reply) => {
                        let _ = channel.post_message(&reply);
                    }
                    Err(err) => {
                        tracing::error!(error = ?err, "db worker: building an import reply failed");
                    }
                }
            });
        })
    };
    channel.set_onmessage(Some(listener.as_ref().unchecked_ref()));
    listener.forget();
    Ok(())
}

/// `kind` of a reply carrying an archive.
const EXPORT_REPLY_OK: &str = "export";
/// `kind` of a reply carrying an export failure.
const EXPORT_REPLY_FAILED: &str = "export-failed";
/// `kind` of a worker-generation reply.
const EXPORT_GENERATION_REPLY: &str = "export-generation";
/// `kind` of a reply carrying import counts.
const IMPORT_REPLY_OK: &str = "import";
/// `kind` of a reply carrying an import failure.
const IMPORT_REPLY_FAILED: &str = "import-failed";

/// Build the worker-generation reply.
fn export_generation_reply(generation: &str) -> Result<JsValue, JsValue> {
    let reply = js_sys::Object::new();
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("kind"),
        &JsValue::from_str(EXPORT_GENERATION_REPLY),
    )?;
    set_export_generation(&reply, generation)?;
    Ok(reply.into())
}

fn set_export_generation(reply: &js_sys::Object, generation: &str) -> Result<bool, JsValue> {
    js_sys::Reflect::set(
        reply,
        &JsValue::from_str("generation"),
        &JsValue::from_str(generation),
    )
}

/// Build the export success reply.
fn export_reply_ok(tag: &ExportTag, bytes: &[u8]) -> Result<JsValue, JsValue> {
    let reply = js_sys::Object::new();
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("kind"),
        &JsValue::from_str(EXPORT_REPLY_OK),
    )?;
    tag.write(&reply)?;
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("bytes"),
        &js_sys::Uint8Array::from(bytes),
    )?;
    Ok(reply.into())
}

/// Build the export failure reply.
fn export_reply_failed(tag: &ExportTag, error: &str) -> Result<JsValue, JsValue> {
    let reply = js_sys::Object::new();
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("kind"),
        &JsValue::from_str(EXPORT_REPLY_FAILED),
    )?;
    tag.write(&reply)?;
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("error"),
        &JsValue::from_str(error),
    )?;
    Ok(reply.into())
}

/// Build the import success reply: counts as JS numbers.
fn import_reply_ok(outcome: &ImportOutcome, collisions: usize) -> Result<JsValue, JsValue> {
    let reply = js_sys::Object::new();
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("kind"),
        &JsValue::from_str(IMPORT_REPLY_OK),
    )?;
    // Row counts are device-database quantities: u32::MAX is effectively
    // unlimited, so truncating here is equivalent to saturating at max.
    let set = |key: &str, count: usize| -> Result<bool, JsValue> {
        js_sys::Reflect::set(
            &reply,
            &JsValue::from_str(key),
            &JsValue::from(u32::try_from(count).unwrap_or(u32::MAX)),
        )
    };
    set("rows_restored", outcome.rows_restored)?;
    set("rows_kept", outcome.rows_kept)?;
    set("writes_restored", outcome.writes_restored)?;
    set("collisions", collisions)?;
    Ok(reply.into())
}

/// Build the import failure reply: `{ kind: "import-failed", error: String }`.
fn import_reply_failed(error: &str) -> Result<JsValue, JsValue> {
    let reply = js_sys::Object::new();
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("kind"),
        &JsValue::from_str(IMPORT_REPLY_FAILED),
    )?;
    js_sys::Reflect::set(
        &reply,
        &JsValue::from_str("error"),
        &JsValue::from_str(error),
    )?;
    Ok(reply.into())
}

/// One export reply: the archive, or the reason there is none.
type ExportReply = Result<Vec<u8>, String>;

/// Where the channel listener leaves the reply for the awaiting caller.
#[derive(Default)]
struct ExportWait {
    generation: Option<String>,
    replaced: bool,
    result: Option<ExportReply>,
}

/// Where the channel listener records the worker generation and reply.
type ExportSlot = Rc<RefCell<ExportWait>>;
/// One import reply: the outcome counts and collision total, or an error.
type ImportReply = Result<(ImportOutcome, usize), String>;

/// Where the import channel listener leaves the reply for the awaiting caller.
type ImportSlot = Rc<RefCell<Option<ImportReply>>>;

/// Poll step while waiting for a channel reply.
const POLL_MS: i32 = 25;

/// Page side: ask the DB worker for a zip archive of this device's local data.
///
/// `scope` selects what the archive carries: [`ExportScope::Everything`] for a
/// full copy, [`ExportScope::Unsynced`] for the device-private tier and queued
/// writes only.
///
/// Call after [`await_db_worker_ready`]. The request is posted once and not
/// repeated, unlike [`request_custody`]: an export reads the whole replica, so
/// a repeated ask would run it again rather than hurry the first one along.
///
/// A tab cannot export its own mirror instead. That mirror is in memory and
/// holds only what its subscriptions cover, so it is neither the durable copy
/// nor the whole one.
///
/// # Errors
///
/// [`ExportRefused::Gone`](crate::relay::ExportRefused::Gone) when no DB worker is running,
/// [`ExportRefused::Failed`](crate::relay::ExportRefused::Failed) when one
/// answered without an archive.
pub async fn request_export(scope: ExportScope) -> Result<Vec<u8>, crate::relay::ExportRefused> {
    let channel = BroadcastChannel::new(EXPORT_CHANNEL)
        .map_err(|err| crate::relay::ExportRefused::Failed(format!("export channel: {err:?}")))?;
    let state: ExportSlot = Rc::new(RefCell::new(ExportWait::default()));
    // This caller's own id, so a reply to a concurrent caller's request on the
    // same channel is not mistaken for this one's archive.
    let request = rosetta_uuid::Uuid::new_v4().to_string();
    let on_message = {
        let state = Rc::clone(&state);
        let request = request.clone();
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if let Some(generation) = decode_export_generation(&event.data()) {
                let mut state = state.borrow_mut();
                match &state.generation {
                    Some(expected) if expected != &generation => state.replaced = true,
                    None => state.generation = Some(generation),
                    Some(_) => {}
                }
                return;
            }
            let Some((tag, reply)) = decode_export_reply(&event.data()) else {
                return;
            };
            let mut state = state.borrow_mut();
            if tag.request == request
                && state.generation.as_deref() == Some(tag.generation.as_str())
            {
                state.result.get_or_insert(reply);
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let generation_request = build_export_generation_request();
    let mut posted = channel.post_message(&generation_request);
    while posted.is_ok()
        && state.borrow().generation.is_none()
        && !state.borrow().replaced
        && crate::locks::lock_is_held(DB_ALIVE_LOCK).await
    {
        sleep_ms(POLL_MS).await;
        if state.borrow().generation.is_none() {
            posted = channel.post_message(&generation_request);
        }
    }
    let generation = state.borrow().generation.clone();
    if let Some(generation) = generation
        && !state.borrow().replaced
    {
        let tag = ExportTag {
            generation,
            request,
        };
        posted = channel.post_message(&build_export_request(scope, &tag));
        while posted.is_ok()
            && state.borrow().result.is_none()
            && !state.borrow().replaced
            && crate::locks::lock_is_held(DB_ALIVE_LOCK).await
        {
            let _ = channel.post_message(&generation_request);
            sleep_ms(POLL_MS).await;
        }
    }
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    let mut state = state.borrow_mut();
    match state.result.take() {
        Some(Ok(bytes)) if !state.replaced => Ok(bytes),
        Some(Err(err)) if !state.replaced => Err(crate::relay::ExportRefused::Failed(err)),
        _ => Err(crate::relay::ExportRefused::Gone(crate::relay::HubGone)),
    }
}

/// Page side: hand the DB worker a `File` to import and wait for the outcome.
///
/// The file is posted on [`IMPORT_CHANNEL`] as a structured-clone object: the
/// worker reads the bytes inside the worker so the archive is never held twice
/// and the size ceiling is the database being written rather than what the
/// message passing layer would impose.
///
/// All collisions are resolved in the file's favor, matching
/// [`ImportChoices::keeping_the_file`](connetto_client::ImportChoices::keeping_the_file).
/// The returned `usize` is the number of rows that clashed, so the caller can
/// tell the person how many of their local values were overwritten.
///
/// Absence of the DB worker is detected through the liveness lock it holds for
/// its whole life ([`DB_ALIVE_LOCK`]). When the lock is released before a reply
/// arrives, this function returns
/// [`ImportRefused::Gone`](crate::relay::ImportRefused::Gone).
///
/// # Errors
///
/// [`ImportRefused::Gone`](crate::relay::ImportRefused::Gone) when no DB
/// worker is running, [`ImportRefused::Failed`](crate::relay::ImportRefused::Failed)
/// when one answered with a refusal.
pub async fn request_import(
    file: File,
) -> Result<(ImportOutcome, usize), crate::relay::ImportRefused> {
    let channel = BroadcastChannel::new(IMPORT_CHANNEL)
        .map_err(|err| crate::relay::ImportRefused::Failed(format!("import channel: {err:?}")))?;
    let result: ImportSlot = Rc::new(RefCell::new(None));
    let on_message = {
        let result = Rc::clone(&result);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if let Some(reply) = decode_import_reply(&event.data()) {
                result.borrow_mut().get_or_insert(reply);
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let posted = channel.post_message(file.as_ref());
    while posted.is_ok()
        && result.borrow().is_none()
        && crate::locks::lock_is_held(DB_ALIVE_LOCK).await
    {
        sleep_ms(POLL_MS).await;
    }
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    match result.borrow_mut().take() {
        Some(Ok((outcome, collisions))) => Ok((outcome, collisions)),
        Some(Err(err)) => Err(crate::relay::ImportRefused::Failed(err)),
        None => Err(crate::relay::ImportRefused::Gone(crate::relay::HubGone)),
    }
}

fn export_message_kind(data: &JsValue) -> Option<String> {
    js_sys::Reflect::get(data, &JsValue::from_str("kind"))
        .ok()?
        .as_string()
}

fn export_message_field(data: &JsValue, key: &str) -> Option<String> {
    js_sys::Reflect::get(data, &JsValue::from_str(key))
        .ok()?
        .as_string()
}

fn export_message_generation(data: &JsValue) -> Option<String> {
    export_message_field(data, "generation")
}

/// Addresses one export exchange: the worker generation that answers it, and
/// which caller asked. The generation alone cannot tell two concurrent
/// callers' replies apart.
#[derive(Clone, PartialEq, Eq)]
struct ExportTag {
    generation: String,
    request: String,
}

impl ExportTag {
    fn read(data: &JsValue) -> Option<Self> {
        Some(Self {
            generation: export_message_field(data, "generation")?,
            request: export_message_field(data, "request")?,
        })
    }

    fn write(&self, message: &js_sys::Object) -> Result<(), JsValue> {
        set_export_generation(message, &self.generation)?;
        js_sys::Reflect::set(
            message,
            &JsValue::from_str("request"),
            &JsValue::from_str(&self.request),
        )?;
        Ok(())
    }
}

fn is_export_generation_request(data: &JsValue) -> bool {
    export_message_kind(data).as_deref() == Some("generation?")
}

fn decode_export_generation(data: &JsValue) -> Option<String> {
    (export_message_kind(data).as_deref() == Some(EXPORT_GENERATION_REPLY))
        .then(|| export_message_generation(data))
        .flatten()
}

fn build_export_generation_request() -> JsValue {
    let request = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &request,
        &JsValue::from_str("kind"),
        &JsValue::from_str("generation?"),
    );
    request.into()
}

fn decode_export_request(data: &JsValue) -> Option<(ExportTag, ExportScope)> {
    if export_message_kind(data).as_deref() != Some("export?") {
        return None;
    }
    let tag = ExportTag::read(data)?;
    let scope = match export_message_field(data, "scope")?.as_str() {
        "everything" => ExportScope::Everything,
        "unsynced" => ExportScope::Unsynced,
        _ => return None,
    };
    Some((tag, scope))
}

fn build_export_request(scope: ExportScope, tag: &ExportTag) -> JsValue {
    let request = js_sys::Object::new();
    let scope = match scope {
        ExportScope::Everything => "everything",
        ExportScope::Unsynced => "unsynced",
    };
    let _ = js_sys::Reflect::set(
        &request,
        &JsValue::from_str("kind"),
        &JsValue::from_str("export?"),
    );
    let _ = tag.write(&request);
    let _ = js_sys::Reflect::set(
        &request,
        &JsValue::from_str("scope"),
        &JsValue::from_str(scope),
    );
    request.into()
}

fn decode_export_reply(data: &JsValue) -> Option<(ExportTag, ExportReply)> {
    let tag = ExportTag::read(data)?;
    let reply = match export_message_kind(data)?.as_str() {
        EXPORT_REPLY_OK => {
            let bytes = js_sys::Reflect::get(data, &JsValue::from_str("bytes")).ok()?;
            Ok(js_sys::Uint8Array::new(&bytes).to_vec())
        }
        EXPORT_REPLY_FAILED => {
            let error = js_sys::Reflect::get(data, &JsValue::from_str("error"))
                .ok()
                .and_then(|value| value.as_string())
                .unwrap_or_else(|| "the worker gave no reason".to_owned());
            Err(error)
        }
        _ => return None,
    };
    Some((tag, reply))
}

/// One count carried as a JS number, or `None` when the value is not a whole
/// number a count can be.
///
/// A JS number is an `f64`, and the counts the worker sends are `usize`
/// values that fit `u32` on every wasm target, so anything outside that is a
/// reply this build did not write.
fn count_from_js(value: &JsValue) -> Option<usize> {
    let number = value.as_f64()?;
    if !number.is_finite() || number < 0.0 || number.fract() != 0.0 || number > f64::from(u32::MAX)
    {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "std offers no fallible conversion from f64 and the guard above proves a whole number inside u32"
    )]
    let count = number as u32;
    usize::try_from(count).ok()
}

/// Read one [`IMPORT_CHANNEL`] message as an import reply, or `None`.
fn decode_import_reply(data: &JsValue) -> Option<ImportReply> {
    let kind = js_sys::Reflect::get(data, &JsValue::from_str("kind"))
        .ok()?
        .as_string()?;
    match kind.as_str() {
        IMPORT_REPLY_OK => {
            let get_count = |key: &str| -> Option<usize> {
                let v = js_sys::Reflect::get(data, &JsValue::from_str(key)).ok()?;
                count_from_js(&v)
            };
            let outcome = ImportOutcome {
                rows_restored: get_count("rows_restored")?,
                rows_kept: get_count("rows_kept")?,
                writes_restored: get_count("writes_restored")?,
            };
            let collisions = get_count("collisions")?;
            Some(Ok((outcome, collisions)))
        }
        IMPORT_REPLY_FAILED => {
            let error = js_sys::Reflect::get(data, &JsValue::from_str("error"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_else(|| "the worker gave no reason".to_owned());
            Some(Err(error))
        }
        _ => None,
    }
}

/// Asks the hub for local work at risk, returning `None` when it cannot answer.
async fn ask_unsynced(hub: &crate::relay::RelayHub) -> Option<crate::auth::PendingWork> {
    match hub.unsynced().await {
        Ok(pending) => Some(pending),
        Err(err) => {
            tracing::error!(error = %err, "db worker: the hub cannot report unsynced work");
            None
        }
    }
}

/// Reads one hex file identity, or `None` when it is not one this build wrote.
fn file_id_from_hex(text: &str) -> Option<connetto_file_client::FileId> {
    if text.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
        let digits = core::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(digits, 16).ok()?;
    }
    Some(connetto_file_client::FileId::from_bytes(bytes))
}

/// Carry out one logout-channel request, returning the reply to broadcast, or
/// `None` for traffic that is not a request (this worker's own replies).
async fn serve_logout(
    request: &crate::auth::LogoutMessage,
    hub: &crate::relay::RelayHub,
    auth: &crate::auth::WorkerAuthConfig,
    auth_db_name: &str,
    replica_db_name: &str,
    content_namespace: Option<&str>,
    account: Option<&str>,
) -> Option<crate::auth::LogoutMessage> {
    use crate::auth::LogoutMessage;

    let (delete, force) = match request {
        LogoutMessage::Unsynced => {
            let pending = ask_unsynced(hub).await?;
            return Some(LogoutMessage::Pending { pending });
        }
        LogoutMessage::Logout { delete, force } => (*delete, *force),
        LogoutMessage::ForgetRetired { files } => {
            // All or nothing: the reply names what was forgotten, so a request
            // carrying an identity this build cannot read is refused whole.
            let refusal = |detail: &str| {
                Some(LogoutMessage::ForgetFailed {
                    files: files.clone(),
                    detail: detail.to_owned(),
                })
            };
            let Some(retired) = files
                .iter()
                .map(|file| file_id_from_hex(file))
                .collect::<Option<Vec<_>>>()
            else {
                return refusal("a file identity was not readable");
            };
            return match hub.forget_retired_content(retired).await {
                Ok(()) => Some(LogoutMessage::Forgot {
                    files: files.clone(),
                }),
                Err(err) => refusal(&err.to_string()),
            };
        }
        LogoutMessage::Pending { .. }
        | LogoutMessage::Done { .. }
        | LogoutMessage::Refused { .. }
        | LogoutMessage::Forgot { .. }
        | LogoutMessage::ForgetFailed { .. } => {
            return None;
        }
    };

    // The guard runs before the revoke, so a refused delete leaves the session
    // whole. Revoking first would answer a refusal to a tab that is already
    // logged out, and the retry with `force` would then be a bare delete against
    // a half-torn-down session.
    //
    // The replica is only marked here. It is destroyed at the next startup,
    // because this worker holds it open for its whole life and OPFS cannot
    // delete a live file.
    if delete {
        let pending = ask_unsynced(hub).await?;
        let wipe = crate::storage::PendingWipe::new(
            replica_db_name,
            content_namespace.map(ToOwned::to_owned),
        );
        if let Err(err) = crate::storage::mark_wipe_pending(&wipe, &pending, force).await {
            return match err {
                crate::storage::WipeError::Unsynced(pending) => {
                    Some(LogoutMessage::Refused { pending })
                }
                other => {
                    tracing::error!(error = %other, "db worker: marking the replica for deletion failed");
                    None
                }
            };
        }
    }

    // The credential is gone locally either way. A failed revoke leaves the
    // session alive on the server until it expires, which is worth logging but
    // does not make this tab any less logged out.
    match logout_locally(auth, auth_db_name, account).await {
        Ok(()) => {}
        Err(err) => tracing::warn!(
            error = %err,
            "db worker: the session revoke failed, local state cleared anyway"
        ),
    }
    Some(LogoutMessage::Done { deleted: delete })
}

/// Revoke the session and clear the stored credential of one account.
///
/// Uses the worker's own key store rather than opening a second one. The derived
/// key-encryption key lives on the instance, so a fresh store is locked on an
/// enrolled profile: opening one here left the credential in place while the tab
/// was told it had logged out.
async fn logout_locally(
    auth: &crate::auth::WorkerAuthConfig,
    auth_db_name: &str,
    account: Option<&str>,
) -> Result<(), crate::auth::AuthError> {
    let storage = crate::storage::ReplicaStorage::install().await;
    let keys = match crate::unlock::worker_key_store() {
        Some(keys) => keys,
        // No worker store registered means no gate was ever installed, so a
        // freshly opened one holds everything it needs.
        None => std::rc::Rc::new(crate::auth::IdbKeyStore::open().await?),
    };
    let device = crate::storage::device_key(&*keys).await?;
    let store = crate::auth::RefreshStore::open(&storage.db_url(auth_db_name), &device)?;
    crate::auth::BrowserAuthenticator::new(auth.clone(), account.map(ToOwned::to_owned))
        .logout(&store)
        .await
}

/// The transport a tab rides to the DB worker: one end of a uniquely named
/// broadcast channel.
pub type TabWire = MessageTransport<BroadcastChannel>;

/// A transport factory for a reconnecting tab client: every attempt waits
/// for a ready DB worker, announces a fresh wire channel, and returns a
/// transport watching the worker's alive lock, so a dead worker surfaces
/// as a clean close instead of silence. Pass it to
/// `ConnettoClient::with_reconnect` together with [`sleep`] as the sleeper.
///
/// # Panics
///
/// Each call to the returned factory closure panics if `await_db_worker_ready` returns an error, that is, if the DB worker does not become ready within 15 seconds or reports a boot failure.
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
            await_db_worker_ready().await.expect("db worker ready");
            announce_tab(&wire).await;
            MessageTransport::<BroadcastChannel>::with_peer_liveness(&wire, DB_ALIVE_LOCK)
        })
    }
}

/// Resolve after roughly `duration`, in a window or a worker context. Also
/// the browser [`Sleeper`] for the
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

/// Open the replica, with the device-private database attached beside it.
///
/// One connection holds both. `ConnettoConnection::connect` attaches whatever
/// tier the replica names, which is also what applies its schema on a first
/// boot, and the relay serves those tables through the same connection. The
/// worker used to open that file a second time as its own main database, and
/// could not: the browser's storage pool gives two connections to one file a
/// single underlying handle and two page caches. Both tiers therefore share
/// one key and one salt, which is what an attached database inherits anyway.
fn content_store_namespace(seed: &str, replica_db_name: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(seed.as_bytes());
    digest.update([0]);
    digest.update(replica_db_name.as_bytes());
    format!("{:x}", digest.finalize())
}
async fn open_replica<S: StorageKind>(
    transport: Option<BrowserSocket>,
    replica: &Replica<'_, S>,
    existing: bool,
    config: &DbWorkerConfig,
    client_config: &ClientConfig,
) -> Result<ConnettoConnection<BrowserSocket>, JsValue> {
    if matches!(replica.tier(), Tier::None) {
        // Both callers name one, so this is a programming error here rather
        // than a configuration one.
        return Err(JsValue::from_str(
            "the db worker named no device-private database",
        ));
    }
    // Opened first and greeted second, always, so the replica is serving reads
    // whether or not the greeting can happen at all.
    let mut worker = if existing {
        ConnettoConnection::open_existing(replica, client_config, None).map_err(to_js)?
    } else {
        ConnettoConnection::open(replica, config.replica_ddl, client_config, None).map_err(to_js)?
    };
    if let Some(transport) = transport {
        worker.attach(transport).await.map_err(to_js)?;
    }
    Ok(worker)
}

fn to_js(err: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&err.to_string())
}

/// Encode a [`Custody`] value as a compact, stable ASCII string for the
/// hello-channel wire. Decode with [`decode_custody`]; encode and decode must
/// stay adjacent so they cannot drift.
///
/// Encoding:
/// - `"v"` = `Verified`
/// - `"e"` = `Ephemeral`
/// - `"u:us"` = `Unverified(Unsupported)`
/// - `"u:off"` = `Unverified(Offerable)`
/// - `"u:dec"` = `Unverified(Declined)`
fn encode_custody(c: Custody) -> &'static str {
    match c {
        Custody::Verified => "v",
        Custody::Ephemeral => "e",
        Custody::Unverified(NoGate::Unsupported) => "u:us",
        Custody::Unverified(NoGate::Offerable) => "u:off",
        Custody::Unverified(NoGate::Declined) => "u:dec",
    }
}

/// Decode a custody string produced by [`encode_custody`], or `None` when the
/// value is not one this build knows.
///
/// It refuses to guess rather than defaulting: a level connetto cannot vouch for
/// is worse than no answer, and the only caller is waiting for a reply anyway,
/// so an unrecognised string simply is not one.
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

/// Page side: ask the worker for the current custody level over the hello
/// channel. Follows the [`await_db_worker_ready`] / [`announce_tab`] pattern:
/// posts `"custody?"` and waits for `"custody:<encoding>"`.
///
/// The answer reflects the state at the moment the worker processes the
/// message, so call this after [`await_db_worker_ready`] to be sure boot has
/// settled.
///
/// # Panics
///
/// Panics if the browser's `BroadcastChannel` constructor fails for the hello channel, which cannot occur in any conforming browser environment.
pub async fn request_custody() -> Custody {
    let channel = BroadcastChannel::new(HELLO_CHANNEL).expect("hello channel");
    let result: Rc<Cell<Option<Custody>>> = Rc::new(Cell::new(None));
    let on_message = {
        let result = Rc::clone(&result);
        Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            if let Some(text) = event.data().as_string()
                && let Some(encoded) = text.strip_prefix("custody:")
                && let Some(custody) = decode_custody(encoded)
            {
                result.set(Some(custody));
            }
        })
    };
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    let mut answered = result.get();
    while answered.is_none() {
        // Asks posted before the intake existed are lost rather than queued,
        // exactly as `await_db_worker_ready` found, so this repeats the ask.
        let _ = channel.post_message(&JsValue::from_str("custody?"));
        sleep_ms(10).await;
        answered = result.get();
    }
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    answered.unwrap_or(Custody::Ephemeral)
}

#[cfg(test)]
mod tests;
