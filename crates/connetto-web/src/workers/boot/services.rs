use std::cell::{Cell, RefCell};
use std::rc::Rc;

use connetto_client::ConnettoConnection;
use connetto_client::reconnect::{ReconnectPolicy, Sleeper, TransportFactory};
use connetto_core::messages::SubscriptionSpec;
use connetto_file_client::{BrowserStore, ContentArchive};
use tokio::sync::mpsc::UnboundedReceiver;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::spawn_local;
use web_sys::{BroadcastChannel, MessageEvent};

use super::super::helpers::content_store_namespace;
use super::BootError;
use super::DbWorkerConfig;
use super::replica::BootReplicaSpec;
use crate::relay::HubReconnect;
use crate::{BrowserSocket, HubNotice, RelayHub, locks};

thread_local! {
    static DB_ALIVE: RefCell<Option<locks::HeldLock>> = const { RefCell::new(None) };
}

struct ConnectGate {
    open: Rc<Cell<bool>>,
    _channel: BroadcastChannel,
    _listener: Closure<dyn FnMut(MessageEvent)>,
}

fn install_connect_gate(name: &'static str) -> Result<Rc<ConnectGate>, BootError> {
    let channel =
        BroadcastChannel::new(name).map_err(|err| super::super::IntakeError::ChannelOpen {
            operation: "connect gate",
            detail: format!("{err:?}"),
        })?;
    let open = Rc::new(Cell::new(false));
    let listener = {
        let open = Rc::clone(&open);
        Closure::<dyn FnMut(MessageEvent)>::new(move |_event: MessageEvent| {
            open.set(true);
        })
    };
    channel.set_onmessage(Some(listener.as_ref().unchecked_ref()));
    Ok(Rc::new(ConnectGate {
        open,
        _channel: channel,
        _listener: listener,
    }))
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
    // Wipes run before custody so a pending deletion applies even when the unlock is refused or unconfigured.
    apply_pending_wipes(&storage, &key_store).await?;
    let was_enrolled = super::replica::setup_custody(config, &key_store).await?;
    // After wipes (which free slots) and before login (which reads the account index).
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
    let progress = if pending.replica_deleted() {
        // The replica and key went on an earlier boot, and a fresh login may
        // already own the name, so only the orphaned content is retried here.
        match pending.content_namespace.as_deref() {
            Some(namespace) => crate::storage::remove_content_namespace(namespace).await?,
            None => crate::storage::WipeProgress::Complete,
        }
    } else {
        crate::storage::wipe_replica(
            storage,
            key_store,
            &pending.replica,
            pending.content_namespace.as_deref(),
            &crate::auth::PendingWork::default(),
            true,
        )
        .await?
    };
    match (progress, pending.replica_deleted()) {
        (crate::storage::WipeProgress::Complete, _) => {
            crate::storage::acknowledge_pending_wipe(pending)
                .await
                .map_err(BootError::KeyStore)?;
        }
        (crate::storage::WipeProgress::ContentPending, false) => {
            crate::storage::defer_pending_content_wipe(pending)
                .await
                .map_err(BootError::KeyStore)?;
        }
        (crate::storage::WipeProgress::ContentPending, true) => {}
    }
    tracing::info!(replica = %pending.replica, "db worker: advanced a pending data wipe");
    Ok(())
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
    let connect_gate = match config.connect_gate {
        Some(name) => Some(install_connect_gate(name)?),
        None => None,
    };
    let reconnect = HubReconnect {
        factory: move || {
            let connect_gate = connect_gate.clone();
            async move {
                if connect_gate.as_ref().is_some_and(|gate| !gate.open.get()) {
                    return Err("connect gate closed".to_owned());
                }
                BrowserSocket::connect(ws_url)
                    .await
                    .map_err(|err| err.to_string())
            }
        },
        sleeper: super::super::intake::sleep,
        policy: ReconnectPolicy::default(),
        upstream: config
            .upstream_subscriptions()
            .map(|(sub_id, query)| (sub_id.to_owned(), SubscriptionSpec::new(query)))
            .collect(),
    };
    let (content, content_persistent, content_wipe_namespace) = setup_content_store(
        config,
        spec.identified,
        &spec.replica_db_name,
        content_root_key,
    )
    .await?;
    let (hub, notices) = start_relay_hub(
        worker,
        config.hub_meta_name,
        reconnect,
        content,
        config.content_http,
    )?;
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
    let root_key = content_root_key.ok_or(BootError::ContentKey)?;
    let store = if identified {
        let scope: web_sys::DedicatedWorkerGlobalScope = js_sys::global()
            .dyn_into()
            .map_err(|value: js_sys::Object| BootError::NotWorkerScope(format!("{value:?}")))?;
        BrowserStore::install(&scope, &namespace).await?
    } else {
        BrowserStore::ephemeral()
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
    content_http: connetto_file_client::BrowserHttp,
) -> Result<(RelayHub, UnboundedReceiver<HubNotice>), BootError>
where
    F: TransportFactory<Transport = BrowserSocket> + 'static,
    F::Error: core::fmt::Display,
    S: Sleeper + Clone + 'static,
{
    let (hub, pump, notices) =
        RelayHub::with_reconnect_archive(worker, hub_meta_name, reconnect, content, content_http)?;
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
