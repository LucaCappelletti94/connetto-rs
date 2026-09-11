use std::cell::RefCell;
use std::rc::Rc;

use connetto_file_client::{BrowserStore, BrowserStoreError, ContentArchive};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::{Worker, WorkerOptions, WorkerType};

use crate::relay::HubReconnect;
use crate::{BrowserSocket, HubNotice, RelayHub, locks};
use connetto_client::reconnect::{ReconnectPolicy, Sleeper, TransportFactory};
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoConnection, Grant, Replica, ReplicaStorage as StorageKind,
    Tier,
};
use connetto_core::custody::{Custody, NoGate};
use connetto_core::messages::SubscriptionSpec;
use connetto_core::traits::ReplicaKeyStore as _;
use tokio::sync::mpsc::UnboundedReceiver;

use super::helpers::{content_store_namespace, to_js};
use super::session::{acquire_deferred, acquire_session, persist_deferred};

/// Storage-pool slots reserved by [`boot_db_worker`]: 4 databases plus a rollback journal each.
const BOOT_SLOTS: u32 = 8;

thread_local! {
    static DB_ALIVE: RefCell<Option<locks::HeldLock>> = const { RefCell::new(None) };
}

/// Application-specific inputs for [`boot_db_worker`].
pub struct DbWorkerConfig {
    /// The server WebSocket URL the worker connects upstream to.
    ws_url: &'static str,
    /// Base name of the OPFS replica file; identity is appended when `auth` is set.
    replica_db_prefix: &'static str,
    /// Synced replica DDL, applied only on first boot.
    replica_ddl: &'static str,
    /// Local tier DDL, applied only on first boot.
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
    /// Attached database file holding the hub's own durable state.
    hub_meta_name: &'static str,
    /// Seed for account-isolated browser content storage.
    content_namespace: Option<&'static str>,
    /// Schema version presented to the server at handshake.
    schema_version: connetto_core::SchemaVersion,
    /// Custom SQLite functions registered on every connection before any DDL.
    sql_functions: connetto_client::SqlFunctions,
    /// Tables the synced replica's row-level-security translation split.
    policy_tables: connetto_client::PolicyTables,
    /// SQLite function name a translated policy calls for the caller identity.
    caller_function: &'static str,
    /// Browser OAuth acquisition config; `None` uses a placeholder token.
    auth: Option<crate::auth::WorkerAuthConfig>,
    /// OPFS database holding the worker-only refresh token.
    auth_db_name: &'static str,
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
    unlock: bool,
    /// Whether to ask the tab which account to sign in as.
    ///
    /// When `false` the boot takes the last-used account.
    ///
    /// When `true` the worker offers the stored accounts to the tab after the
    /// gate and signs in as whichever one it names. Register the answer with
    /// [`crate::unlock::serve_account_choice`] before the worker boots.
    pick_account: bool,
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

    /// Browser OAuth acquisition config.
    #[must_use]
    pub fn with_auth(mut self, auth: Option<crate::auth::WorkerAuthConfig>) -> Self {
        self.auth = auth;
        self
    }

    /// OPFS database holding the worker-only refresh token.
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
/// The `Worker` constructor's error, or a blob-URL failure for [`WorkerBootstrap::Generated`].
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
            // The worker takes its reference to the blob during construction.
            let _ = web_sys::Url::revoke_object_url(&object_url);
            worker
        }
    }
}

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
/// A string describing the VFS, acquisition, upstream connect, or subscribe failure.
pub async fn boot_db_worker<Id>(config: &DbWorkerConfig) -> Result<BootedSession<Id>, JsValue>
where
    Id: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Display,
{
    let storage = crate::storage::ReplicaStorage::install().await;
    let key_store = Rc::new(crate::auth::IdbKeyStore::open().await.map_err(to_js)?);
    let was_enrolled = setup_custody(config, &key_store).await?;
    apply_pending_wipes(&storage, &key_store).await?;
    storage.reserve(BOOT_SLOTS).await.map_err(to_js)?;
    let session = acquire_boot_session::<Id>(config, &storage, &key_store, was_enrolled).await?;
    let mut spec = BootReplicaSpec::from_session(config, session, &storage)?;
    let replica_key =
        provision_or_load_key(&key_store, &spec.replica_db_name, spec.existing).await?;
    let content_root_key = replica_key.as_ref().map(|key| *key.as_bytes());
    let login = spec.login.take();
    let client_config = build_boot_client_config(config, login, &spec);
    let transport = try_connect_upstream(config.ws_url).await;
    let mut worker =
        open_boot_replica(transport, &spec, config, &client_config, replica_key).await?;
    subscribe_and_boot(&mut worker, config).await?;
    hold_alive_lock().await;
    let content_persistent = start_boot_services(config, &spec, worker, content_root_key).await?;
    Ok(BootedSession {
        identity: spec.identity,
        session_expires_at: spec.session_expires_at,
        account: spec.active_account,
        content_persistent,
    })
}

async fn hold_alive_lock() {
    let alive = locks::hold_lock(super::DB_ALIVE_LOCK).await;
    DB_ALIVE.with(|cell| cell.borrow_mut().replace(alive));
}

async fn start_boot_services<Id>(
    config: &DbWorkerConfig,
    spec: &BootReplicaSpec<Id>,
    worker: ConnettoConnection<BrowserSocket>,
    content_root_key: Option<[u8; 32]>,
) -> Result<Option<bool>, JsValue> {
    let ws_url = config.ws_url;
    let reconnect = HubReconnect {
        factory: move || async move {
            BrowserSocket::connect(ws_url)
                .await
                .map_err(|err| err.to_string())
        },
        sleeper: super::intake::sleep,
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
    super::intake::install_hello_intake(hub)?;
    Ok(content_persistent)
}

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
        let replica_db_name = match &session {
            Some(session) => {
                connetto_client::replica_db_name(config.replica_db_prefix, &session.user_id)
                    .map_err(to_js)?
            }
            None => config.replica_db_prefix.to_owned(),
        };
        let active_account = match &session {
            Some(session) => {
                Some(connetto_client::encode_identity(&session.user_id).map_err(to_js)?)
            }
            None => None,
        };
        let existing = storage.exists(&replica_db_name);
        let tier_db_name = crate::storage::tier_db_name(&replica_db_name);
        let replica_url = storage.db_url(&replica_db_name);
        let identified = session.is_some();
        let session_expires_at = session.as_ref().map(|s| s.session_expires_at);
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

async fn run_unlock_ceremony(
    enrolled_ids: Vec<Vec<u8>>,
    key_store: &crate::auth::IdbKeyStore,
) -> Result<(), JsValue> {
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
        other @ crate::unlock::TabAnswer::Account(_) => {
            return Err(to_js(crate::auth::AuthError::Context(format!(
                "the unlock request was answered with {}",
                crate::unlock::answer_kind(&other)
            ))));
        }
    }
    Ok(())
}

async fn setup_custody(
    config: &DbWorkerConfig,
    key_store: &Rc<crate::auth::IdbKeyStore>,
) -> Result<bool, JsValue> {
    if config.unlock {
        crate::unlock::install_worker_handler()?;
    }
    crate::unlock::init_worker(Rc::clone(key_store), Custody::Unverified(NoGate::Offerable));
    let enrolled_ids = key_store.enrolled().await.map_err(to_js)?;
    let was_enrolled = !enrolled_ids.is_empty();
    if was_enrolled && !config.unlock {
        return Err(to_js(crate::auth::AuthError::Locked {
            detail: "a credential is enrolled but this build did not enable the unlock \
                     protocol, so nothing here can derive the key"
                .into(),
        }));
    }
    if was_enrolled {
        run_unlock_ceremony(enrolled_ids, key_store).await?;
    }
    Ok(was_enrolled)
}

async fn acquire_or_defer_session<Id: serde::Serialize + serde::de::DeserializeOwned>(
    config: &DbWorkerConfig,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
    was_enrolled: bool,
) -> Result<
    (
        Option<crate::auth::BrowserSession<Id>>,
        Option<crate::auth::DeferredRefreshStore>,
    ),
    JsValue,
> {
    let defer = config.unlock
        && !was_enrolled
        && config.auth.is_some()
        && !storage.exists(config.auth_db_name);
    match &config.auth {
        Some(auth_config) if defer => {
            let (session, deferred) = acquire_deferred::<Id>(auth_config).await?;
            Ok((Some(session), Some(deferred)))
        }
        Some(auth_config) => Ok((
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
        )),
        None => {
            crate::unlock::set_custody(Custody::Ephemeral);
            Ok((None, None))
        }
    }
}

async fn run_enrol_ceremony(key_store: &crate::auth::IdbKeyStore) -> Result<(), JsValue> {
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
    Ok(())
}

async fn acquire_boot_session<Id: serde::Serialize + serde::de::DeserializeOwned>(
    config: &DbWorkerConfig,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
    was_enrolled: bool,
) -> Result<Option<crate::auth::BrowserSession<Id>>, JsValue> {
    let (session, deferred) =
        acquire_or_defer_session::<Id>(config, storage, key_store, was_enrolled).await?;
    if config.unlock && !was_enrolled && session.is_some() {
        run_enrol_ceremony(key_store).await?;
    }
    if let Some(deferred) = &deferred {
        persist_deferred(deferred, config.auth_db_name, storage, key_store).await?;
    }
    Ok(session)
}

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

async fn open_boot_replica<Id>(
    transport: Option<BrowserSocket>,
    spec: &BootReplicaSpec<Id>,
    config: &DbWorkerConfig,
    client_config: &ClientConfig,
    replica_key: Option<connetto_core::ReplicaKey>,
) -> Result<ConnettoConnection<BrowserSocket>, JsValue> {
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

async fn subscribe_and_boot(
    worker: &mut ConnettoConnection<BrowserSocket>,
    config: &DbWorkerConfig,
) -> Result<(), JsValue> {
    if !worker.is_connected() {
        return Ok(());
    }
    worker
        .subscribe(config.upstream_sub_id, config.upstream_query)
        .await
        .map_err(to_js)?;
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

fn install_tab_services(
    config: &DbWorkerConfig,
    hub: &RelayHub,
    replica_db_name: &str,
    content_wipe_namespace: Option<String>,
    active_account: Option<&str>,
) -> Result<(), JsValue> {
    if let Some(auth_config) = &config.auth {
        super::logout::serve_logout_requests(
            auth_config.clone(),
            config.auth_db_name,
            replica_db_name,
            content_wipe_namespace,
            active_account.map(ToOwned::to_owned),
            hub.clone(),
        )?;
    }
    super::archive_channel::serve_export_requests(hub.clone())?;
    super::archive_channel::serve_import_requests(hub.clone())?;
    Ok(())
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

/// Open the replica with the device-private database attached beside it.
async fn open_replica<S: StorageKind>(
    transport: Option<BrowserSocket>,
    replica: &Replica<'_, S>,
    existing: bool,
    config: &DbWorkerConfig,
    client_config: &ClientConfig,
) -> Result<ConnettoConnection<BrowserSocket>, JsValue> {
    if matches!(replica.tier(), Tier::None) {
        return Err(JsValue::from_str(
            "the db worker named no device-private database",
        ));
    }
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
