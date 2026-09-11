use wasm_bindgen::JsValue;
use web_sys::{Worker, WorkerOptions, WorkerType};

mod replica;
mod services;

/// Storage-pool slots reserved by [`boot_db_worker`]: 4 databases plus a rollback journal each.
const BOOT_SLOTS: u32 = 8;

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
    /// Attached database file holding the hub's own durable state.
    pub(crate) hub_meta_name: &'static str,
    /// Seed for account-isolated browser content storage.
    pub(crate) content_namespace: Option<&'static str>,
    /// Schema version presented to the server at handshake.
    pub(crate) schema_version: connetto_core::SchemaVersion,
    /// Custom SQLite functions registered on every connection before any DDL.
    pub(crate) sql_functions: connetto_client::SqlFunctions,
    /// Tables the synced replica's row-level-security translation split.
    pub(crate) policy_tables: connetto_client::PolicyTables,
    /// SQLite function name a translated policy calls for the caller identity.
    pub(crate) caller_function: &'static str,
    /// Browser OAuth acquisition config; `None` uses a placeholder token.
    pub(crate) auth: Option<crate::auth::WorkerAuthConfig>,
    /// OPFS database holding the worker-only refresh token.
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
    let (storage, key_store, was_enrolled) = services::prepare_boot_storage(config).await?;
    let mut spec =
        replica::resolve_replica_spec::<Id>(config, &storage, &key_store, was_enrolled).await?;
    let replica_key =
        replica::provision_or_load_key(&key_store, &spec.replica_db_name, spec.existing).await?;
    let login = spec.login.take();
    let client_config = replica::build_boot_client_config(config, login, &spec);
    let transport = replica::try_connect_upstream(config.ws_url).await;
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
