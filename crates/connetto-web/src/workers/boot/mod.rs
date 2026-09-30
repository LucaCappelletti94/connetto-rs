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
pub(crate) async fn boot_db_worker<Id>(
    build: crate::builder::WebBuild,
) -> Result<BootedSession<Id>, BootError>
where
    Id: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Display,
{
    let booted = boot_session(build).await;
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

async fn boot_session<Id>(build: crate::builder::WebBuild) -> Result<BootedSession<Id>, BootError>
where
    Id: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Display,
{
    let crate::builder::WebBuild { core, web: config } = build;
    let (storage, key_store, was_enrolled) = services::prepare_boot_storage(&config).await?;
    let resolved =
        replica::resolve_boot_sign_in::<Id>(&config, &storage, &key_store, was_enrolled).await?;
    let (spec, mut worker, content_root_key) =
        replica::open_worker(core, &config, resolved, &storage, &key_store).await?;
    if config.connect_gate.is_none() {
        replica::try_connect_upstream(&mut worker, config.ws_url).await?;
    }
    replica::subscribe_and_boot(&mut worker, &config).await?;
    services::hold_alive_lock().await;
    let (hub, content_persistent) =
        services::start_boot_services(&config, &spec, worker, content_root_key).await?;
    // The re-check guards what the gate protects, so it runs once the key
    // actually came from the user's own verification.
    let gated = crate::unlock::custody() == connetto_core::custody::Custody::Verified;
    crate::gate::install_worker_gate(&hub, key_store, config.gate, gated);
    Ok(BootedSession {
        identity: spec.identity,
        session_expires_at: spec.session_expires_at,
        account: spec.active_account,
        content_persistent,
    })
}
