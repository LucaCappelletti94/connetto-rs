use std::cell::RefCell;

use connetto_client::ConnettoConnection;
use connetto_client::reconnect::{ReconnectPolicy, Sleeper, TransportFactory};
use connetto_core::messages::SubscriptionSpec;
use connetto_file_client::{BrowserStore, BrowserStoreError, ContentArchive};
use tokio::sync::mpsc::UnboundedReceiver;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use super::super::helpers::content_store_namespace;
use super::BootError;
use super::DbWorkerConfig;
use super::replica::BootReplicaSpec;
use crate::relay::HubReconnect;
use crate::{BrowserSocket, HubNotice, RelayHub, locks};

thread_local! {
    static DB_ALIVE: RefCell<Option<locks::HeldLock>> = const { RefCell::new(None) };
}

/// Install storage and custody, carry out any outstanding data wipe, and
/// reserve this boot's database slots.
///
/// Returns the storage handle, the key store, and whether a credential was
/// already enrolled.
pub(super) async fn prepare_boot_storage(
    config: &DbWorkerConfig,
) -> Result<
    (
        crate::storage::ReplicaStorage,
        std::rc::Rc<crate::auth::IdbKeyStore>,
        bool,
    ),
    BootError,
> {
    let storage = crate::storage::ReplicaStorage::install().await;
    // Encrypted regardless of auth, and the per-replica key also lives here.
    let key_store = std::rc::Rc::new(
        crate::auth::IdbKeyStore::open()
            .await
            .map_err(BootError::KeyStore)?,
    );
    let was_enrolled = super::replica::setup_custody(config, &key_store).await?;
    apply_pending_wipes(&storage, &key_store).await?;
    // After wipes (which free slots) and before login (which opens the refresh store).
    storage
        .reserve(super::BOOT_SLOTS)
        .await
        .map_err(BootError::SlotReservation)?;
    Ok((storage, key_store, was_enrolled))
}

pub(super) async fn apply_pending_wipes(
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
) -> Result<(), BootError> {
    for pending in crate::storage::pending_wipes()
        .await
        .map_err(BootError::KeyStore)?
    {
        apply_pending_wipe(storage, key_store, &pending).await?;
    }
    Ok(())
}

async fn apply_pending_wipe(
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
    pending: &crate::storage::PendingWipe,
) -> Result<(), BootError> {
    let content_removed = remove_pending_content(pending).await?;
    if !pending.replica_deleted() {
        crate::storage::wipe_replica(
            storage,
            key_store,
            &pending.replica,
            &crate::auth::PendingWork::default(),
            true,
        )
        .await?;
    }
    match (content_removed, pending.replica_deleted()) {
        (true, _) => crate::storage::acknowledge_pending_wipe(pending)
            .await
            .map_err(BootError::KeyStore)?,
        (false, false) => crate::storage::defer_pending_content_wipe(pending)
            .await
            .map_err(BootError::KeyStore)?,
        (false, true) => {}
    }
    tracing::info!(replica = %pending.replica, "db worker: advanced a pending data wipe");
    Ok(())
}

async fn remove_pending_content(pending: &crate::storage::PendingWipe) -> Result<bool, BootError> {
    let Some(namespace) = &pending.content_namespace else {
        return Ok(true);
    };
    let scope: web_sys::DedicatedWorkerGlobalScope = js_sys::global()
        .dyn_into()
        .map_err(|value: js_sys::Object| BootError::NotWorkerScope(format!("{value:?}")))?;
    match BrowserStore::remove(&scope, namespace).await {
        Ok(()) => Ok(true),
        Err(error @ BrowserStoreError::InvalidNamespace { .. }) => {
            Err(BootError::ContentStore(error))
        }
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

pub(super) async fn hold_alive_lock() {
    let alive = locks::hold_lock(super::super::DB_ALIVE_LOCK).await;
    DB_ALIVE.with(|cell| cell.borrow_mut().replace(alive));
}

pub(super) async fn start_boot_services<Id>(
    config: &DbWorkerConfig,
    spec: &BootReplicaSpec<Id>,
    worker: ConnettoConnection<BrowserSocket>,
    content_root_key: Option<[u8; 32]>,
) -> Result<Option<bool>, BootError> {
    let ws_url = config.ws_url;
    let reconnect = HubReconnect {
        factory: move || async move {
            BrowserSocket::connect(ws_url)
                .await
                .map_err(|err| err.to_string())
        },
        sleeper: super::super::intake::sleep,
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
    super::super::intake::install_hello_intake(hub)?;
    Ok(content_persistent)
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
    BootError,
> {
    let Some(seed) = config.content_namespace else {
        return Ok((None, None, None));
    };
    let namespace = content_store_namespace(seed, replica_db_name);
    let (store, root_key) = if identified {
        let root_key = content_root_key.ok_or(BootError::ContentKey)?;
        let scope: web_sys::DedicatedWorkerGlobalScope = js_sys::global()
            .dyn_into()
            .map_err(|value: js_sys::Object| BootError::NotWorkerScope(format!("{value:?}")))?;
        let store = BrowserStore::install(&scope, &namespace).await?;
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
) -> Result<(RelayHub, UnboundedReceiver<HubNotice>), BootError>
where
    F: TransportFactory<Transport = BrowserSocket> + 'static,
    F::Error: core::fmt::Display,
    S: Sleeper + Clone + 'static,
{
    let (hub, pump, notices) =
        RelayHub::with_reconnect_archive(worker, hub_meta_name, reconnect, content)?;
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
) -> Result<(), BootError> {
    if let Some(auth_config) = &config.auth {
        super::super::logout::serve_logout_requests(
            super::super::logout::LogoutConfig {
                auth: auth_config.clone(),
                auth_db_name: config.auth_db_name.to_owned(),
                replica_db_name: replica_db_name.to_owned(),
                content_namespace: content_wipe_namespace,
                account: active_account.map(ToOwned::to_owned),
            },
            hub.clone(),
        )?;
    }
    super::super::archive_channel::serve_export_requests(hub.clone())?;
    super::super::archive_channel::serve_import_requests(hub.clone())?;
    Ok(())
}
