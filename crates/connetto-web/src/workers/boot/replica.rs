use std::rc::Rc;

use connetto_client::{
    ClientConfig, ClientEvent, ConnettoConnection, Grant, Replica, ReplicaStorage as StorageKind,
    Tier,
};
use connetto_core::custody::{Custody, NoGate};
use connetto_core::traits::ReplicaKeyStore as _;
use wasm_bindgen::JsValue;

use super::super::helpers::{sleep_ms, to_js};

use super::super::session::{
    RefreshStoreHandle, acquire_deferred, acquire_session, persist_deferred,
};
use super::DbWorkerConfig;
use crate::BrowserSocket;

pub(crate) struct BootReplicaSpec<Id> {
    pub(crate) replica_db_name: String,
    pub(crate) tier_db_name: String,
    pub(crate) replica_url: String,
    pub(crate) active_account: Option<String>,
    pub(crate) identified: bool,
    pub(crate) existing: bool,
    pub(crate) identity: Option<Id>,
    pub(crate) session_expires_at: Option<u64>,
    pub(crate) login: Option<Grant>,
}

impl<Id: serde::Serialize + core::fmt::Display> BootReplicaSpec<Id> {
    pub(super) fn from_session(
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

/// Combine session acquisition and spec construction into one step.
pub(super) async fn resolve_replica_spec<Id>(
    config: &DbWorkerConfig,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
    was_enrolled: bool,
) -> Result<BootReplicaSpec<Id>, JsValue>
where
    Id: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Display,
{
    let session = acquire_boot_session::<Id>(config, storage, key_store, was_enrolled).await?;
    BootReplicaSpec::from_session(config, session, storage)
}

pub(super) async fn setup_custody(
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
        Some(auth_config) => {
            let store = RefreshStoreHandle {
                db_name: config.auth_db_name,
                storage,
                key_store,
            };
            Ok((
                Some(acquire_session::<Id>(auth_config, &store, config.pick_account).await?),
                None,
            ))
        }
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
        let store = RefreshStoreHandle {
            db_name: config.auth_db_name,
            storage,
            key_store,
        };
        persist_deferred(deferred, &store).await?;
    }
    Ok(session)
}

pub(super) async fn provision_or_load_key(
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

pub(super) fn build_boot_client_config<Id: core::fmt::Display>(
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

pub(super) async fn try_connect_upstream(ws_url: &str) -> Option<BrowserSocket> {
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

/// Open the boot replica; the replica key is consumed here and its derived content root key
/// is returned alongside the connection.
pub(super) async fn open_boot_replica<Id>(
    transport: Option<BrowserSocket>,
    spec: &BootReplicaSpec<Id>,
    config: &DbWorkerConfig,
    client_config: &ClientConfig,
    replica_key: Option<connetto_core::ReplicaKey>,
) -> Result<(ConnettoConnection<BrowserSocket>, Option<[u8; 32]>), JsValue> {
    let content_root_key = replica_key.as_ref().map(|key| *key.as_bytes());
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
    Ok((worker, content_root_key))
}

pub(super) async fn subscribe_and_boot(
    worker: &mut ConnettoConnection<BrowserSocket>,
    config: &DbWorkerConfig,
) -> Result<(), JsValue> {
    // Matches the hello-channel TIMEOUT_MS in intake.rs so the tab and the worker give up
    // at the same wall-clock moment: both sides wait at most 15 s for the worker to be ready.
    const BOOT_TIMEOUT_MS: f64 = 15_000.0;
    if !worker.is_connected() {
        return Ok(());
    }
    worker
        .subscribe(config.upstream_sub_id, config.upstream_query)
        .await
        .map_err(to_js)?;
    worker.ping(1).await.map_err(to_js)?;
    let started = js_sys::Date::now();
    loop {
        let elapsed = js_sys::Date::now() - started;
        if elapsed >= BOOT_TIMEOUT_MS {
            return Err(JsValue::from_str(
                "upstream did not complete the boot handshake within the deadline",
            ));
        }
        let remaining = BOOT_TIMEOUT_MS - elapsed;
        // Provably in i32 range: remaining <= BOOT_TIMEOUT_MS = 15_000.
        debug_assert!(remaining > 0.0 && remaining <= BOOT_TIMEOUT_MS);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "remaining <= BOOT_TIMEOUT_MS = 15_000; sub-ms truncation is deliberate"
        )]
        let cancel = sleep_ms(remaining as i32);
        match worker.pump_one_or(cancel).await.map_err(to_js)? {
            Some(ClientEvent::Pong { nonce: 1 }) => break,
            Some(ClientEvent::Closed) => {
                return Err(JsValue::from_str("server closed during the upstream boot"));
            }
            Some(_) | None => {}
        }
    }
    Ok(())
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
