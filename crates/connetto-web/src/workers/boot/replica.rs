use std::rc::Rc;

use wasm_bindgen::JsCast;

use connetto_client::{
    ClientConfig, ClientEvent, ConnettoConnection, Grant, Replica, ReplicaStorage as StorageKind,
    Tier,
};
use connetto_core::custody::{Custody, NoGate};
use connetto_core::traits::ReplicaKeyStore as _;

use super::super::helpers::sleep_ms;
use super::super::session::{AccountStoreHandle, acquire_session};
use super::BootError;
use super::DbWorkerConfig;
use crate::BrowserSocket;

pub(crate) struct BootReplicaSpec<Id> {
    pub(crate) replica_db_name: String,
    pub(crate) replica_url: String,
    pub(crate) active_account: Option<String>,
    pub(crate) identified: bool,
    pub(crate) existing: bool,
    pub(crate) identity: Option<Id>,
    pub(crate) session_expires_at: Option<u64>,
    pub(crate) login: Option<Grant>,
    /// The share keys this boot holds, each the signed grant and the subject
    /// it names. Empty when the deployment named none, and the replica then
    /// admits nothing through a key, exactly as the server does for that same
    /// caller.
    pub(crate) share_keys: Vec<(String, String)>,
}

impl<Id: serde::Serialize + core::fmt::Display> BootReplicaSpec<Id> {
    pub(super) fn from_session(
        config: &DbWorkerConfig,
        session: Option<crate::auth::BrowserSession<Id>>,
        storage: &crate::storage::ReplicaStorage,
    ) -> Result<Self, BootError> {
        let replica_db_name = match &session {
            Some(session) => {
                connetto_client::replica_db_name(config.replica_db_prefix, &session.user_id)
                    .map_err(BootError::ReplicaOpen)?
            }
            None => config.replica_db_prefix.to_owned(),
        };
        let active_account = match &session {
            Some(session) => Some(
                connetto_client::encode_identity(&session.user_id)
                    .map_err(BootError::ReplicaOpen)?,
            ),
            None => None,
        };
        let existing = storage.exists(&replica_db_name);
        let replica_url = storage.db_url(&replica_db_name);
        let identified = session.is_some();
        let session_expires_at = session.as_ref().map(|s| s.session_expires_at);
        let login = session.as_ref().map(|s| Grant::new(s.access_token.clone()));
        let identity = session.map(|s| s.user_id);
        Ok(Self {
            replica_db_name,
            replica_url,
            active_account,
            identified,
            existing,
            identity,
            session_expires_at,
            login,
            share_keys: config.share_keys.clone(),
        })
    }
}

/// Combine session acquisition and spec construction into one step.
pub(super) async fn resolve_replica_spec<Id>(
    config: &DbWorkerConfig,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
    was_enrolled: bool,
) -> Result<BootReplicaSpec<Id>, BootError>
where
    Id: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Display,
{
    let session = acquire_boot_session::<Id>(config, storage, key_store, was_enrolled).await?;
    BootReplicaSpec::from_session(config, session, storage)
}

pub(super) async fn setup_custody(
    config: &DbWorkerConfig,
    key_store: &Rc<crate::auth::IdbKeyStore>,
) -> Result<bool, BootError> {
    if config.unlock {
        crate::unlock::install_worker_handler()?;
    }
    crate::unlock::init_worker(Rc::clone(key_store), Custody::Unverified(NoGate::Offerable));
    let enrolled_ids = key_store.enrolled().await.map_err(BootError::KeyStore)?;
    let was_enrolled = !enrolled_ids.is_empty();
    if was_enrolled && !config.unlock {
        return Err(BootError::KeyStore(crate::auth::AuthError::Locked {
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
) -> Result<(), BootError> {
    match crate::unlock::ask_unlock(enrolled_ids)
        .await
        .map_err(BootError::KeyStore)?
    {
        crate::unlock::TabAnswer::Key { credential_id, key } => {
            key_store
                .use_derived(key, &credential_id)
                .await
                .map_err(BootError::KeyStore)?;
            crate::unlock::set_custody(Custody::Verified);
        }
        crate::unlock::TabAnswer::Declined => {
            return Err(BootError::KeyStore(crate::auth::AuthError::Locked {
                detail: "the ceremony was dismissed or the credential is gone".into(),
            }));
        }
        crate::unlock::TabAnswer::Unsupported => {
            return Err(BootError::KeyStore(crate::auth::AuthError::Locked {
                detail: "this browsing context cannot run the ceremony that enrolled this \
                         profile"
                    .into(),
            }));
        }
        crate::unlock::TabAnswer::Failed { detail } => {
            return Err(BootError::KeyStore(crate::auth::AuthError::Locked {
                detail,
            }));
        }
        other @ crate::unlock::TabAnswer::Account(_) => {
            return Err(BootError::KeyStore(crate::auth::AuthError::Context(
                format!(
                    "the unlock request was answered with {}",
                    crate::unlock::answer_kind(&other)
                ),
            )));
        }
    }
    Ok(())
}

async fn acquire_boot_session<Id: serde::Serialize + serde::de::DeserializeOwned>(
    config: &DbWorkerConfig,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
    was_enrolled: bool,
) -> Result<Option<crate::auth::BrowserSession<Id>>, BootError> {
    let Some(auth_config) = &config.auth else {
        crate::unlock::set_custody(Custody::Ephemeral);
        return Ok(None);
    };
    let store = AccountStoreHandle {
        db_name: config.auth_db_name,
        storage,
    };
    let session = acquire_session::<Id>(auth_config, &store, config.pick_account)
        .await
        .map_err(BootError::SessionAcquisition)?;
    // A first run on an unlocking build enrols only after the login resolved an
    // account, so the user enrols a profile that exists rather than an empty
    // one.
    if config.unlock && !was_enrolled {
        run_enrol_ceremony(key_store).await?;
    }
    Ok(Some(session))
}

async fn run_enrol_ceremony(key_store: &crate::auth::IdbKeyStore) -> Result<(), BootError> {
    match crate::unlock::ask_enrol()
        .await
        .map_err(BootError::KeyStore)?
    {
        crate::unlock::TabAnswer::Key { credential_id, key } => {
            key_store
                .adopt_derived(key, &credential_id)
                .await
                .map_err(BootError::KeyStore)?;
            crate::unlock::set_custody(Custody::Verified);
        }
        crate::unlock::TabAnswer::Declined => {
            crate::unlock::set_custody(Custody::Unverified(NoGate::Declined));
        }
        crate::unlock::TabAnswer::Unsupported => {
            crate::unlock::set_custody(Custody::Unverified(NoGate::Unsupported));
        }
        crate::unlock::TabAnswer::Failed { detail } => {
            return Err(BootError::KeyStore(crate::auth::AuthError::Context(
                format!("enrolment ceremony failed: {detail}"),
            )));
        }
        other @ crate::unlock::TabAnswer::Account(_) => {
            return Err(BootError::KeyStore(crate::auth::AuthError::Context(
                format!(
                    "enrolment request was answered with {}",
                    crate::unlock::answer_kind(&other)
                ),
            )));
        }
    }
    Ok(())
}

pub(super) async fn provision_or_load_key(
    key_store: &crate::auth::IdbKeyStore,
    replica_db_name: &str,
    existing: bool,
) -> Result<Option<connetto_core::ReplicaKey>, BootError> {
    if existing {
        key_store
            .load(replica_db_name)
            .await
            .map_err(BootError::KeyStore)
    } else {
        crate::auth::provision_replica_key(key_store, replica_db_name)
            .await
            .map_err(BootError::KeyStore)
            .map(Some)
    }
}

/// Clear any replica key an earlier anonymous boot stored under the bare prefix.
///
/// An anonymous boot provisions no key, so a record left by a boot from before
/// this decision would sit under the bare prefix with nothing to ever remove it.
/// The clear is idempotent, so a boot that finds none is unaffected.
pub(super) async fn clear_anonymous_key(
    key_store: &crate::auth::IdbKeyStore,
    replica_db_name: &str,
) -> Result<(), BootError> {
    key_store
        .clear(replica_db_name)
        .await
        .map_err(BootError::KeyStore)
}

/// Resolve this boot's replica key, provisioning only for an identified boot.
///
/// An anonymous boot has no durable file to open, so it provisions no key and
/// instead clears any record a past anonymous boot left under the bare prefix.
pub(super) async fn resolve_replica_key<Id>(
    key_store: &crate::auth::IdbKeyStore,
    spec: &BootReplicaSpec<Id>,
) -> Result<Option<connetto_core::ReplicaKey>, BootError> {
    if spec.identified {
        provision_or_load_key(key_store, &spec.replica_db_name, spec.existing).await
    } else {
        clear_anonymous_key(key_store, &spec.replica_db_name).await?;
        Ok(None)
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
        client_config = client_config.with_caller(
            config.caller_function,
            spec.identity.as_ref().map(ToString::to_string),
        );
    }
    if !config.subjects_function.is_empty() {
        // Pairs rather than two lists: the client renders the set from the
        // grants that are still alive and presents those same grants, so an
        // expired key cannot linger in a durable replica's own answer.
        client_config = client_config.with_share_keys::<String>(
            config.subjects_function,
            spec.share_keys.iter().cloned().map(|(grant, subject)| {
                (
                    Grant::new(grant),
                    connetto_core::auth::CapabilitySubject::new(subject),
                )
            }),
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

/// Open the boot replica and return the content root key beside the connection.
///
/// For an identified boot the content root key is the replica key. For an
/// anonymous boot the replica key is `None`, so a fresh content root key is
/// minted for this worker when a content namespace is configured.
pub(super) async fn open_boot_replica<Id>(
    transport: Option<BrowserSocket>,
    spec: &BootReplicaSpec<Id>,
    config: &DbWorkerConfig,
    client_config: &ClientConfig,
    replica_key: Option<connetto_core::ReplicaKey>,
) -> Result<(ConnettoConnection<BrowserSocket>, Option<[u8; 32]>), BootError> {
    let (worker, content_root_key) = if spec.identified {
        let content_root_key = replica_key.as_ref().map(|key| *key.as_bytes());
        let replica = Replica::encrypted_file(&spec.replica_url, replica_key)
            .map_err(BootError::ReplicaOpen)?
            .with_tier(config.frontend_ddl);
        let worker =
            open_replica(transport, &replica, spec.existing, config, client_config).await?;
        (worker, content_root_key)
    } else {
        // An anonymous content store is worker-lifetime memory, so its root key is
        // minted for this worker and never stored, and only when a content
        // namespace is configured at all.
        let content_root_key = if config.content_namespace.is_some() {
            Some(crate::auth::mint_content_root_key().map_err(BootError::KeyStore)?)
        } else {
            None
        };
        let replica = Replica::in_memory().with_tier(config.frontend_ddl);
        let worker = open_replica(transport, &replica, false, config, client_config).await?;
        (worker, content_root_key)
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
) -> Result<(), BootError> {
    // Matches the hello-channel HELLO_TIMEOUT_MS so a silent server is detected
    // as fast as the tab's own wait expires.
    const BOOT_TIMEOUT_MS: f64 = 15_000.0;
    if !worker.is_connected() {
        return Ok(());
    }
    for (sub_id, query) in config.upstream_subscriptions() {
        worker
            .subscribe(sub_id, query)
            .await
            .map_err(BootError::Subscribe)?;
    }
    worker.ping(1).await.map_err(BootError::Subscribe)?;
    // Performance::now() is monotonic so a backward wall-clock step cannot extend the wait.
    let performance = js_sys::global()
        .dyn_into::<web_sys::DedicatedWorkerGlobalScope>()
        .map_err(|v: js_sys::Object| BootError::NotWorkerScope(format!("{v:?}")))?
        .performance()
        .ok_or_else(|| BootError::NotWorkerScope("no Performance API in worker scope".into()))?;
    let mut last_activity = performance.now();
    loop {
        let elapsed = performance.now() - last_activity;
        if elapsed >= BOOT_TIMEOUT_MS {
            return Err(BootError::BootTimeout {
                deadline_ms: BOOT_TIMEOUT_MS,
            });
        }
        let remaining = BOOT_TIMEOUT_MS - elapsed;
        // Provably in i32 range because remaining is at most BOOT_TIMEOUT_MS of 15_000.
        debug_assert!(remaining > 0.0 && remaining <= BOOT_TIMEOUT_MS);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "remaining <= BOOT_TIMEOUT_MS = 15_000; sub-ms truncation is deliberate"
        )]
        let cancel = sleep_ms(remaining as i32);
        match worker
            .pump_one_or(cancel)
            .await
            .map_err(BootError::Subscribe)?
        {
            Some(ClientEvent::Pong { nonce: 1 }) => break,
            Some(ClientEvent::Closed) => {
                return Err(BootError::BootClosed);
            }
            // Any non-Pong frame resets the inactivity timer; the sync is progressing.
            Some(_) => {
                last_activity = performance.now();
            }
            None => {}
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
) -> Result<ConnettoConnection<BrowserSocket>, BootError> {
    if matches!(replica.tier(), Tier::None) {
        return Err(BootError::NoTierConfigured);
    }
    let mut worker = if existing {
        ConnettoConnection::open_existing(replica, client_config, None)
            .map_err(BootError::ReplicaOpen)?
    } else {
        ConnettoConnection::open(replica, config.replica_ddl, client_config, None)
            .map_err(BootError::ReplicaOpen)?
    };
    if let Some(transport) = transport {
        worker
            .attach(transport)
            .await
            .map_err(BootError::ReplicaOpen)?;
    }
    Ok(worker)
}

#[cfg(test)]
mod tests {
    use super::{BootReplicaSpec, resolve_replica_key};
    use connetto_core::traits::ReplicaKeyStore as _;
    use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_dedicated_worker);

    /// An anonymous spec, whose replica name is the bare prefix a run with no
    /// identity opens under.
    fn anonymous_spec(prefix: &str) -> BootReplicaSpec<String> {
        BootReplicaSpec {
            replica_db_name: prefix.to_owned(),
            replica_url: String::new(),
            active_account: None,
            identified: false,
            existing: false,
            identity: None,
            session_expires_at: None,
            login: None,
            share_keys: Vec::new(),
        }
    }

    /// An anonymous boot provisions no key, and clears any record a boot from
    /// before this decision left under the bare prefix.
    #[wasm_bindgen_test]
    async fn an_anonymous_boot_writes_no_key_and_clears_a_leftover() {
        let key_store = crate::auth::IdbKeyStore::open()
            .await
            .expect("open the key store");

        // A leftover record under the bare prefix, as a past anonymous boot wrote.
        let leftover = "boot-anon-leftover.sqlite";
        crate::auth::provision_replica_key(&key_store, leftover)
            .await
            .expect("seed a leftover key");
        assert!(
            key_store.load(leftover).await.expect("load").is_some(),
            "the leftover record is present before the boot"
        );

        let resolved = resolve_replica_key(&key_store, &anonymous_spec(leftover))
            .await
            .expect("resolve the anonymous key");
        assert!(resolved.is_none(), "an anonymous boot provisions no key");
        assert_eq!(
            key_store.load(leftover).await.expect("load"),
            None,
            "and it clears the leftover record under the bare prefix"
        );

        // With nothing present, an anonymous boot writes no record at all.
        let fresh = "boot-anon-fresh.sqlite";
        key_store.clear(fresh).await.expect("start from nothing");
        let resolved = resolve_replica_key(&key_store, &anonymous_spec(fresh))
            .await
            .expect("resolve the anonymous key");
        assert!(resolved.is_none());
        assert_eq!(
            key_store.load(fresh).await.expect("load"),
            None,
            "an anonymous boot leaves no key-store record behind"
        );
    }
}
