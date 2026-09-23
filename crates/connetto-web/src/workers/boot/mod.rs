use core::fmt;
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;
use web_sys::{Worker, WorkerOptions, WorkerType};

mod replica;
mod services;

/// The query parameter a spawned worker reads its boot identity from.
const BOOT_PARAM: &str = "boot";

/// The query parameter a bootstrap script reads the glue URL from.
const GLUE_PARAM: &str = "glue";

/// The global a generated bootstrap leaves its boot identity in, because a blob worker's own
/// location carries no query.
const BOOT_GLOBAL: &str = "connettoBoot";

/// Storage-pool slots reserved by [`boot_db_worker`]: 4 databases plus a rollback journal each.
const BOOT_SLOTS: u32 = 8;

/// An opaque identifier minted when a DB worker is spawned.
///
/// The spawning tab announces it as `booting:<identity>` on the hello channel, and the
/// generated bootstrap posts it as `failed:<identity>:<detail>` when the worker cannot start.
/// Cloning increments an `Rc` reference count rather than copying the string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BootIdentity(Rc<str>);

impl fmt::Display for BootIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl BootIdentity {
    /// Mints a fresh identity for one boot attempt.
    #[must_use]
    pub fn mint() -> Self {
        Self(rosetta_uuid::Uuid::new_v4().to_string().into())
    }

    /// Whether a wire string names this boot.
    pub(crate) fn matches_str(&self, wire: &str) -> bool {
        &*self.0 == wire
    }

    /// Takes an identity from a hello-channel message.
    pub(crate) fn from_wire(wire: &str) -> Self {
        Self(Rc::from(wire))
    }
}

/// Failure of the DB worker boot sequence or worker spawn.
#[derive(Debug, thiserror::Error)]
pub enum BootError {
    /// The credential key store could not be opened, queried, or the enrolled credential is
    /// unusable in this context.
    #[error("key store: {0}")]
    KeyStore(crate::auth::AuthError),
    /// The passkey unlock or custody ceremony failed.
    #[error("unlock: {0}")]
    Unlock(#[from] crate::unlock::UnlockError),
    /// A pending data wipe could not be applied.
    #[error("pending wipe: {0}")]
    PendingWipe(#[from] crate::storage::WipeError),
    /// Database slot reservation failed.
    #[error("slot reservation: {0}")]
    SlotReservation(crate::auth::AuthError),
    /// Session acquisition or refresh-token persistence failed.
    #[error("session acquisition: {0}")]
    SessionAcquisition(crate::auth::AuthError),
    /// The replica could not be opened or its session-derived name could not be encoded.
    #[error("replica open: {0}")]
    ReplicaOpen(connetto_client::ClientError),
    /// No device-private database was configured alongside the replica.
    #[error("no device-private database configured")]
    NoTierConfigured,
    /// The upstream subscription or boot-handshake ping failed.
    #[error("upstream subscription: {0}")]
    Subscribe(connetto_client::ClientError),
    /// No server frame arrived within the inactivity deadline during the upstream boot.
    #[error("upstream boot handshake stalled: no frame for {deadline_ms:.0} ms")]
    BootTimeout {
        /// The inactivity window that elapsed, in milliseconds.
        deadline_ms: f64,
    },
    /// The server closed the connection during the upstream boot.
    #[error("server closed during upstream boot")]
    BootClosed,
    /// An identified session has no content root key for the content store.
    #[error("content key unavailable")]
    ContentKey,
    /// The global is not a `DedicatedWorkerGlobalScope` or lacks a required browser API.
    #[error("worker scope error: {0}")]
    NotWorkerScope(String),
    /// The browser content store could not be installed or removed.
    #[error("content store: {0}")]
    ContentStore(#[from] connetto_file_client::BrowserStoreError),
    /// The relay hub could not start.
    #[error("relay hub: {0}")]
    RelayHub(#[from] crate::relay::RelayError),
    /// A tab-service channel handler could not be installed.
    #[error("tab service: {0}")]
    TabService(#[from] super::ChannelError),
    /// The hello-channel intake handler could not be installed.
    #[error("intake: {0}")]
    Intake(#[from] super::IntakeError),
    /// The bootstrap script or blob URL could not be constructed from the glue URL.
    #[error("bootstrap URL: {0}")]
    BootstrapUrl(String),
    /// Spawning the browser worker failed.
    #[error("worker spawn: {0}")]
    WorkerSpawn(String),
}

impl From<BootError> for JsValue {
    fn from(value: BootError) -> Self {
        JsValue::from_str(&value.to_string())
    }
}

/// Application-specific inputs for [`boot_db_worker`].
pub struct DbWorkerConfig {
    /// The server WebSocket URL the worker connects upstream to.
    pub(crate) ws_url: &'static str,
    /// Base name of the OPFS replica file; identity is appended when `auth` is set.
    pub(crate) replica_db_prefix: &'static str,
    /// Synced replica DDL, applied only on first boot.
    pub(crate) replica_ddl: &'static str,
    /// Local tier DDL, applied only on first boot.
    ///
    /// The tier used to first-boot from a baked byte-image template, and cannot
    /// any more: a template is a plaintext database, the per-replica key does not
    /// exist at build time, and neither page codec offers a
    /// plaintext-to-encrypted transform that works on both backends. DDL is the
    /// route that works whether the tier is encrypted or not, and the replica
    /// already took it.
    pub(crate) frontend_ddl: &'static str,
    /// The subscription id the worker registers upstream.
    pub(crate) upstream_sub_id: &'static str,
    /// The subscription query the worker registers upstream.
    pub(crate) upstream_query: &'static str,
    /// Additional upstream subscriptions the worker keeps live.
    pub(crate) extra_upstream: Vec<(&'static str, &'static str)>,
    /// Attached database file holding the hub's own durable state.
    pub(crate) hub_meta_name: &'static str,
    /// Seed for account-isolated browser content storage.
    pub(crate) content_namespace: Option<&'static str>,
    /// The transport every content transfer runs under, carrying the idle bound.
    pub(crate) content_http: connetto_file_client::BrowserHttp,
    /// Broadcast channel opening the first upstream connect attempt.
    pub(crate) connect_gate: Option<&'static str>,
    /// Schema version presented to the server at handshake.
    pub(crate) schema_version: connetto_core::SchemaVersion,
    /// Custom SQLite functions registered on every connection before any DDL.
    pub(crate) sql_functions: connetto_client::SqlFunctions,
    /// Tables the synced replica's row-level-security translation split.
    pub(crate) policy_tables: connetto_client::PolicyTables,
    /// SQLite function name a translated policy calls for the caller identity.
    pub(crate) caller_function: &'static str,
    /// SQLite function name a translated policy calls for the caller's keys.
    pub(crate) subjects_function: &'static str,
    /// Share keys this boot holds, each a signed grant and the subject it
    /// names. A deployment obtains them however its own sharing works, a link
    /// a user opened being the usual way, and hands them here.
    pub(crate) share_keys: Vec<(String, String)>,
    /// Browser OAuth acquisition config; `None` uses a placeholder token.
    pub(crate) auth: Option<crate::auth::WorkerAuthConfig>,
    /// OPFS database holding the account index and last-used marker.
    pub(crate) auth_db_name: &'static str,
    /// Whether to serve the passkey unlock protocol.
    ///
    /// When `false` the worker never posts to the tab, mints or reads the
    /// stored KEK, and reports `Custody::Unverified(NoGate::Offerable)`.
    /// Every existing consumer keeps this default and needs no change.
    ///
    /// When `true` the worker installs the private-port handler, asks the tab
    /// to unlock an enrolled profile before reading anything, and asks the tab
    /// to enrol on a fresh profile after the session is acquired. The tab must
    /// call [`crate::unlock::serve_unlock`] before the worker boots.
    pub(crate) unlock: bool,
    /// Whether to ask the tab which account to sign in as.
    ///
    /// When `false` the boot takes the last-used account.
    ///
    /// When `true` the worker offers the stored accounts to the tab after the
    /// gate and signs in as whichever one it names. Register the answer with
    /// [`crate::unlock::serve_account_choice`] before the worker boots.
    pub(crate) pick_account: bool,
}

impl DbWorkerConfig {
    /// Build with `schema_version` set and all other fields at empty or absent defaults.
    #[must_use]
    pub fn new(schema_version: connetto_core::SchemaVersion) -> Self {
        Self {
            ws_url: "",
            replica_db_prefix: "",
            replica_ddl: "",
            frontend_ddl: "",
            upstream_sub_id: "",
            upstream_query: "",
            extra_upstream: Vec::new(),
            hub_meta_name: "",
            content_namespace: None,
            content_http: connetto_file_client::BrowserHttp::new(),
            connect_gate: None,
            schema_version,
            sql_functions: connetto_client::SqlFunctions::default(),
            policy_tables: connetto_client::PolicyTables::new(),
            caller_function: "",
            subjects_function: "",
            share_keys: Vec::new(),
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

    /// Base name of the OPFS replica file; identity is appended when `auth` is set.
    #[must_use]
    pub fn with_replica_db_prefix(mut self, replica_db_prefix: &'static str) -> Self {
        self.replica_db_prefix = replica_db_prefix;
        self
    }

    /// Synced replica DDL, applied only on first boot.
    #[must_use]
    pub fn with_replica_ddl(mut self, replica_ddl: &'static str) -> Self {
        self.replica_ddl = replica_ddl;
        self
    }

    /// Local tier DDL, applied only on first boot.
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
    /// Register one more upstream subscription alongside the primary one.
    #[must_use]
    pub fn with_extra_upstream(mut self, sub_id: &'static str, query: &'static str) -> Self {
        self.extra_upstream.push((sub_id, query));
        self
    }

    /// Attached database file holding the hub's own durable state.
    #[must_use]
    pub fn with_hub_meta_name(mut self, hub_meta_name: &'static str) -> Self {
        self.hub_meta_name = hub_meta_name;
        self
    }

    /// Enable worker-owned browser content storage and attachment-aware archives.
    #[must_use]
    pub fn with_content_namespace(mut self, namespace: &'static str) -> Self {
        self.content_namespace = Some(namespace);
        self
    }

    /// Hold the worker offline until this channel receives any message.
    #[must_use]
    pub fn with_connect_gate(mut self, connect_gate: &'static str) -> Self {
        self.connect_gate = Some(connect_gate);
        self
    }

    /// How long a content transfer may stay silent before it is aborted.
    ///
    /// The bound covers every phase of a request on this device, and a
    /// deployment whose commit verification is slow raises it rather than
    /// gaining a second number. Thirty seconds by default.
    #[must_use]
    pub fn with_transfer_idle_bound(mut self, idle_bound: core::time::Duration) -> Self {
        self.content_http = self.content_http.with_idle_bound(idle_bound);
        self
    }

    /// Custom SQLite functions registered on every connection before any DDL.
    #[must_use]
    pub fn with_sql_functions(mut self, sql_functions: connetto_client::SqlFunctions) -> Self {
        self.sql_functions = sql_functions;
        self
    }

    /// Tables the synced replica's translation split, from the build that produced the replica DDL.
    #[must_use]
    pub fn with_policy_tables(mut self, policy_tables: connetto_client::PolicyTables) -> Self {
        self.policy_tables = policy_tables;
        self
    }

    /// SQLite function name a translated policy calls for the caller.
    #[must_use]
    pub fn with_caller_function(mut self, caller_function: &'static str) -> Self {
        self.caller_function = caller_function;
        self
    }

    /// SQLite function name a translated policy calls for the share keys the
    /// caller holds.
    ///
    /// A deployment whose policies carry a membership arm MUST name it, or
    /// the replica's first read fails on the missing function. A boot holding
    /// no key answers NULL, so the arm admits nothing, which is what the
    /// server's own binding answers for the same caller.
    #[must_use]
    pub fn with_subjects_function(mut self, subjects_function: &'static str) -> Self {
        self.subjects_function = subjects_function;
        self
    }

    /// The share keys this boot holds, each the signed grant and the subject
    /// it names.
    ///
    /// The grant is what the handshake presents, so the server reads the key
    /// into the caller it binds. The subject is what the replica answers its
    /// own membership arms with, so the same rows are admitted locally. Both
    /// halves are needed: a grant alone leaves the replica blind to the rows
    /// the server sends, and a subject alone claims a key the server never
    /// checked.
    #[must_use]
    pub fn with_share_keys(
        mut self,
        share_keys: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        self.share_keys = share_keys.into_iter().collect();
        self
    }

    /// Browser OAuth acquisition config.
    #[must_use]
    pub fn with_auth(mut self, auth: Option<crate::auth::WorkerAuthConfig>) -> Self {
        self.auth = auth;
        self
    }

    /// OPFS database holding the account index and last-used marker.
    #[must_use]
    pub fn with_auth_db_name(mut self, auth_db_name: &'static str) -> Self {
        self.auth_db_name = auth_db_name;
        self
    }

    /// Enable the passkey unlock protocol.
    ///
    /// Set to `true` only when the tab calls [`crate::unlock::serve_unlock`] before the worker
    /// boots, otherwise the worker blocks indefinitely.
    #[must_use]
    pub fn with_unlock(mut self, unlock: bool) -> Self {
        self.unlock = unlock;
        self
    }

    /// Ask the tab which account to sign in as, rather than taking the last-used one.
    #[must_use]
    pub fn with_pick_account(mut self, pick_account: bool) -> Self {
        self.pick_account = pick_account;
        self
    }

    pub(crate) fn upstream_subscriptions(
        &self,
    ) -> impl Iterator<Item = (&'static str, &'static str)> + '_ {
        std::iter::once((self.upstream_sub_id, self.upstream_query))
            .chain(self.extra_upstream.iter().copied())
    }
}

/// How the leader launches the dedicated DB worker.
pub enum WorkerBootstrap {
    /// The glue auto-initializes on import and runs `main` (bundlers such as dx).
    Glue,
    /// A separately served bootstrap script at this URL that imports the glue.
    Script(String),
    /// A connetto-generated bootstrap blob for bundlers whose glue does not self-initialize.
    Generated,
}

/// Page side, leader only: spawn the dedicated DB worker from `glue_url`.
///
/// # Errors
///
/// [`BootError::BootstrapUrl`] when a URL cannot be parsed, [`BootError::WorkerSpawn`] when the
/// `Worker` constructor fails.
pub fn spawn_db_worker(
    glue_url: &str,
    bootstrap: &WorkerBootstrap,
) -> Result<(Worker, BootIdentity), BootError> {
    let identity = BootIdentity::mint();
    let options = WorkerOptions::new();
    options.set_type(WorkerType::Module);
    options.set_name("connetto-db");
    let worker = match bootstrap {
        WorkerBootstrap::Glue => {
            let url = boot_tagged_url(glue_url, &identity)?;
            Worker::new_with_options(&url, &options)
                .map_err(|e| BootError::WorkerSpawn(format!("{e:?}")))?
        }
        WorkerBootstrap::Script(script_url) => {
            let base = current_location_href()?;
            let url = web_sys::Url::new_with_base(script_url, &base)
                .map_err(|e| BootError::BootstrapUrl(format!("{e:?}")))?;
            let params = url.search_params();
            params.set(GLUE_PARAM, glue_url);
            params.set(BOOT_PARAM, &identity.to_string());
            Worker::new_with_options(&url.href(), &options)
                .map_err(|e| BootError::WorkerSpawn(format!("{e:?}")))?
        }
        WorkerBootstrap::Generated => {
            let object_url = generated_bootstrap_url(glue_url, &identity)?;
            let worker = Worker::new_with_options(&object_url, &options)
                .map_err(|e| BootError::WorkerSpawn(format!("{e:?}")));
            // The worker takes its reference to the blob during construction.
            let _ = web_sys::Url::revoke_object_url(&object_url);
            worker?
        }
    };
    report_worker_errors(&worker, &identity);
    // Announced last, because a boot that never got a worker has nothing to announce and would
    // stand in for the boot that replaces it.
    super::intake::announce_current_boot(&identity);
    Ok((worker, identity))
}

/// Reports an error the worker never got to handle, naming the boot it belongs to.
///
/// A module that cannot be fetched, or one that throws while initializing, fails before any
/// Rust code runs, and only the spawning context can name that boot, so the failure is posted
/// from here rather than from inside the worker.
///
/// This listens rather than assigning `onerror`, because a caller installs its own handler and
/// the last assignment would win, and it reports only until the boot is over: a worker that has
/// reported ready booted, and an exception it throws hours later is not a boot failure for the
/// tab that asks next.
fn report_worker_errors(worker: &Worker, identity: &BootIdentity) {
    let message = format!("failed:{identity}:");
    let pending = Rc::new(std::cell::Cell::new(true));
    watch_boot_outcome(identity, &pending);
    let handler = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
        if !pending.replace(false) {
            return;
        }
        if let Ok(hello) = web_sys::BroadcastChannel::new(super::HELLO_CHANNEL) {
            // A module that fails to fetch fires a plain event, so the message may be absent.
            let detail = js_sys::Reflect::get(&event, &JsValue::from_str("message"))
                .ok()
                .and_then(|value| value.as_string())
                .filter(|detail| !detail.is_empty())
                .unwrap_or_else(|| "the worker could not start".to_owned());
            let _ = hello.post_message(&JsValue::from_str(&format!("{message}{detail}")));
            hello.close();
        }
    });
    let _ = worker.add_event_listener_with_callback("error", handler.as_ref().unchecked_ref());
    handler.forget();
}

/// Clears `pending` once this boot has reported its readiness or its failure.
fn watch_boot_outcome(identity: &BootIdentity, pending: &Rc<std::cell::Cell<bool>>) {
    let Ok(hello) = web_sys::BroadcastChannel::new(super::HELLO_CHANNEL) else {
        return;
    };
    let readiness = format!("ready:{identity}");
    let failure = format!("failed:{identity}:");
    let pending = Rc::clone(pending);
    let watcher = {
        let hello = hello.clone();
        Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |event: web_sys::MessageEvent| {
            let Some(heard) = event.data().as_string() else {
                return;
            };
            if heard == readiness || heard.starts_with(failure.as_str()) {
                pending.set(false);
                // This boot has settled, so the listener would only keep reading other boots'
                // traffic, one retained channel per worker the page ever replaced.
                hello.set_onmessage(None);
                hello.close();
            }
        })
    };
    hello.set_onmessage(Some(watcher.as_ref().unchecked_ref()));
    watcher.forget();
}

/// The URL a worker is spawned from, carrying the boot identity as a query parameter.
///
/// A reserved parameter already present is replaced, because the worker reads the first
/// value of the name and a second one would name a boot nobody is waiting for.
///
/// The worker reads it back from its own location, which is how a boot failure after the
/// import names the boot it belongs to.
pub(super) fn boot_tagged_url(url: &str, identity: &BootIdentity) -> Result<String, BootError> {
    tagged_url_against(&current_base_href()?, url, identity)
}

/// Tags `url` resolved against `base`, which is what makes the resolution testable.
pub(super) fn tagged_url_against(
    base: &str,
    url: &str,
    identity: &BootIdentity,
) -> Result<String, BootError> {
    let tagged = web_sys::Url::new_with_base(url, base)
        .map_err(|e| BootError::BootstrapUrl(format!("{e:?}")))?;
    tagged
        .search_params()
        .set(BOOT_PARAM, &identity.to_string());
    Ok(tagged.href())
}

fn generated_bootstrap_url(glue_url: &str, identity: &BootIdentity) -> Result<String, BootError> {
    let source = generated_bootstrap_source(glue_url, identity)?;
    let parts = js_sys::Array::of1(&JsValue::from_str(&source));
    let options = web_sys::BlobPropertyBag::new();
    options.set_type("text/javascript");
    let blob = web_sys::Blob::new_with_str_sequence_and_options(&parts, &options)
        .map_err(|e| BootError::WorkerSpawn(format!("{e:?}")))?;
    web_sys::Url::create_object_url_with_blob(&blob)
        .map_err(|e| BootError::WorkerSpawn(format!("{e:?}")))
}

/// Build the module source that imports the glue and initializes it against its wasm file.
pub(super) fn generated_bootstrap_source(
    glue_url: &str,
    identity: &BootIdentity,
) -> Result<String, BootError> {
    let base = current_location_href()?;
    let url = web_sys::Url::new_with_base(glue_url, &base)
        .map_err(|e| BootError::BootstrapUrl(format!("{e:?}")))?;
    // A blob module resolves a relative specifier against blob:, so the import needs the
    // absolute URL captured before the pathname is rewritten.
    let resolved_glue = url.href();
    let path = url.pathname();
    let wasm_path = path.strip_suffix(".js").map_or_else(
        || format!("{path}_bg.wasm"),
        |base| format!("{base}_bg.wasm"),
    );
    url.set_pathname(&wasm_path);
    // A fragment is not meaningful for a resource fetch.
    url.set_hash("");
    let wasm_url = url.href();
    Ok(format!(
        r#"self.{param} = {id_literal};
try {{
  const mod = await import({glue});
  await mod.default({{ module_or_path: {wasm} }});
}} catch (err) {{
  new BroadcastChannel("connetto-debug").postMessage("db worker bootstrap FAILED: " + err);
  new BroadcastChannel("connetto-hello").postMessage("failed:{id}:" + err);
  throw err;
}}
"#,
        param = BOOT_GLOBAL,
        id_literal = js_string_literal(&identity.to_string()),
        glue = js_string_literal(&resolved_glue),
        wasm = js_string_literal(&wasm_url),
        id = identity,
    ))
}

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

/// The base a relative worker URL resolves against.
///
/// A page can move that base with `<base href>`, and the `Worker` constructor honours it, so
/// tagging a relative URL has to resolve against the same base or the module is fetched from
/// somewhere the deployment never served it.
fn current_base_href() -> Result<String, BootError> {
    if let Ok(window) = js_sys::global().dyn_into::<web_sys::Window>()
        && let Some(document) = window.document()
    {
        return Ok(document.base_uri().ok().flatten().unwrap_or(
            window
                .location()
                .href()
                .map_err(|e| BootError::BootstrapUrl(format!("{e:?}")))?,
        ));
    }
    current_location_href()
}

/// Resolve the current document or worker location to an absolute URL string.
fn current_location_href() -> Result<String, BootError> {
    match js_sys::global().dyn_into::<web_sys::Window>() {
        Ok(window) => window
            .location()
            .href()
            .map_err(|e| BootError::BootstrapUrl(format!("{e:?}"))),
        Err(global) => match global.dyn_into::<web_sys::WorkerGlobalScope>() {
            Ok(worker) => Ok(worker.location().href()),
            Err(_) => Err(BootError::BootstrapUrl(
                "cannot determine current location".into(),
            )),
        },
    }
}

/// What the boot resolved about the session it opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootedSession<Id> {
    /// The identity the session was acquired for.
    pub identity: Option<Id>,
    /// Unix seconds when the local session lapses if it is never refreshed again.
    pub session_expires_at: Option<u64>,
    /// Credential-store key this identity's account is addressed by.
    pub account: Option<String>,
    /// Whether configured content storage is durable, or `None` when content is disabled.
    pub content_persistent: Option<bool>,
}

/// Boot the DB worker context: install VFS, acquire session, open replica, connect upstream,
/// and start services.
///
/// # Errors
///
/// [`BootError`] describing the VFS, acquisition, upstream connect, or subscribe failure.
pub async fn boot_db_worker<Id>(config: &DbWorkerConfig) -> Result<BootedSession<Id>, BootError>
where
    Id: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Display,
{
    let booted = boot_session(config).await;
    if let Err(error) = &booted {
        report_boot_failure(&error.to_string());
    }
    booted
}

/// Tells the waiting page why this boot failed, naming the boot it was spawned as.
///
/// The identity arrives on this worker's own URL, which the page sets for every bootstrap
/// kind, so a page waiting on readiness hears the reason instead of waiting out its deadline.
/// A worker spawned without one stays silent, which is what a deployment's own bootstrap
/// does when it does not forward the parameter.
fn report_boot_failure(detail: &str) {
    let Some(identity) = boot_identity_from_location() else {
        return;
    };
    if let Ok(hello) = web_sys::BroadcastChannel::new(super::HELLO_CHANNEL) {
        let _ = hello.post_message(&JsValue::from_str(&format!("failed:{identity}:{detail}")));
        hello.close();
    }
}

/// The boot identity this worker was spawned with, from its own URL or from the global a
/// generated bootstrap leaves behind.
pub(super) fn boot_identity_from_location() -> Option<String> {
    let global = js_sys::global();
    if let Ok(scope) = global.clone().dyn_into::<web_sys::WorkerGlobalScope>()
        && let Ok(url) = web_sys::Url::new(&scope.location().href())
        && let Some(value) = url.search_params().get(BOOT_PARAM)
        && !value.is_empty()
    {
        return Some(value);
    }
    js_sys::Reflect::get(&global, &JsValue::from_str(BOOT_GLOBAL))
        .ok()
        .and_then(|value| value.as_string())
        .filter(|value| !value.is_empty())
}

async fn boot_session<Id>(config: &DbWorkerConfig) -> Result<BootedSession<Id>, BootError>
where
    Id: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Display,
{
    let (storage, key_store, was_enrolled) = services::prepare_boot_storage(config).await?;
    let mut spec =
        replica::resolve_replica_spec::<Id>(config, &storage, &key_store, was_enrolled).await?;
    let replica_key = replica::resolve_replica_key(&key_store, &spec).await?;
    let login = spec.login.take();
    let client_config = replica::build_boot_client_config(config, login, &spec);
    let transport = match config.connect_gate {
        Some(_) => None,
        None => replica::try_connect_upstream(config.ws_url).await,
    };
    let (mut worker, content_root_key) =
        replica::open_boot_replica(transport, &spec, config, &client_config, replica_key).await?;
    replica::subscribe_and_boot(&mut worker, config).await?;
    services::hold_alive_lock().await;
    let content_persistent =
        services::start_boot_services(config, &spec, worker, content_root_key).await?;
    Ok(BootedSession {
        identity: spec.identity,
        session_expires_at: spec.session_expires_at,
        account: spec.active_account,
        content_persistent,
    })
}
