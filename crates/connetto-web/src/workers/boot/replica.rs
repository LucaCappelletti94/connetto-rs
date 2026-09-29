use std::rc::Rc;

use wasm_bindgen::JsCast;

use connetto_client::{
    ClientError, ClientEvent, ConnettoConnection, ContentPlace, Located, ReplicaPlace,
};
use connetto_core::custody::{Custody, NoGate};
use connetto_core::traits::ReplicaKeyStore as _;

use super::super::helpers::sleep_ms;
use super::super::session::{AccountStoreHandle, ResolvedSignIn, resolve_sign_in};
use super::BootError;
use crate::BrowserSocket;
use crate::builder::{CoreBuild, WebConfig};

/// What the boot resolved about its replica, which the services and the
/// booted session report read.
pub(crate) struct BootReplicaSpec<Id> {
    /// The replica's name in the pool, the bare prefix for an anonymous boot.
    pub(crate) replica_db_name: String,
    /// The account key the identity is addressed by.
    pub(crate) active_account: Option<String>,
    /// Whether the replica is durable, which only a signed-in boot is.
    pub(crate) identified: bool,
    /// Whether the replica was already in the pool.
    pub(crate) existing: bool,
    /// The identity a provider login established.
    pub(crate) identity: Option<Id>,
    /// Unix seconds when the local session lapses.
    pub(crate) session_expires_at: Option<u64>,
}

/// The OPFS pool, the browser's place for a durable replica.
///
/// Each replica is named under the application's prefix, and its key record
/// takes the same name, because the key store is shared by the whole
/// origin while the prefix separates the applications on it.
pub(crate) struct OpfsPlace<'a> {
    pub(crate) storage: &'a crate::storage::ReplicaStorage,
    pub(crate) prefix: &'static str,
}

impl ReplicaPlace for OpfsPlace<'_> {
    fn locate(&self, name: &str) -> Result<Located, ClientError> {
        let db = crate::storage::replica_entry(self.prefix, name);
        let url = self.storage.db_url(&db);
        let exists = self.storage.exists(&db);
        Ok(Located::new(db, url, exists, ContentPlace::InMemory))
    }
}

pub(super) async fn setup_custody(
    config: &WebConfig,
    key_store: &Rc<crate::auth::IdbKeyStore>,
) -> Result<bool, BootError> {
    if config.gate.on() {
        crate::unlock::install_worker_handler()?;
    }
    crate::unlock::init_worker(Rc::clone(key_store), Custody::Unverified(NoGate::Offerable));
    let enrolled_ids = key_store.enrolled().await.map_err(BootError::KeyStore)?;
    let was_enrolled = !enrolled_ids.is_empty();
    if was_enrolled && !config.gate.on() {
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
    match crate::workers::intake::awaiting_user(crate::unlock::ask_unlock(enrolled_ids))
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

/// Resolve the sign-in, enrolling the gate after a first login when the
/// build keeps it on and nothing was enrolled before.
pub(super) async fn resolve_boot_sign_in<Id>(
    config: &WebConfig,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
    was_enrolled: bool,
) -> Result<Option<ResolvedSignIn<Id>>, BootError>
where
    Id: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Display,
{
    let Some(kind) = config.sign_in.clone() else {
        crate::unlock::set_custody(Custody::Ephemeral);
        return Ok(None);
    };
    let store = AccountStoreHandle {
        db_name: config.auth_db_name,
        storage,
    };
    let resolved = resolve_sign_in::<Id>(kind, &store, config.redirect_uri.as_deref())
        .await
        .map_err(BootError::SessionAcquisition)?;
    // A first run on a gated build enrols only after the login resolved an
    // account, so the user enrols a profile that exists rather than an empty
    // one.
    if config.gate.on() && !was_enrolled {
        run_enrol_ceremony(key_store).await?;
    }
    Ok(Some(resolved))
}

async fn run_enrol_ceremony(key_store: &crate::auth::IdbKeyStore) -> Result<(), BootError> {
    match crate::workers::intake::awaiting_user(crate::unlock::ask_enrol())
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

/// Open the worker's replica through the core build, with no transport, and
/// return it beside the spec and the content root key.
///
/// A signed-in boot opens the durable replica its credential names under the
/// application's prefix, provisioning the key of a fresh one first, since
/// only the browser mints keys here. An anonymous boot opens in memory, and
/// its content root key is minted for this worker and never stored.
pub(super) async fn open_worker<Id>(
    core: CoreBuild,
    config: &WebConfig,
    resolved: Option<ResolvedSignIn<Id>>,
    storage: &crate::storage::ReplicaStorage,
    key_store: &Rc<crate::auth::IdbKeyStore>,
) -> Result<
    (
        BootReplicaSpec<Id>,
        ConnettoConnection<BrowserSocket>,
        Option<[u8; 32]>,
    ),
    BootError,
> {
    let (Some(resolved), Some(prefix)) = (resolved, config.replica_db_prefix) else {
        let content_root_key = if config.content_namespace.is_some() {
            Some(crate::auth::mint_content_root_key().map_err(BootError::KeyStore)?)
        } else {
            None
        };
        let worker = core
            .with_client_id(rosetta_uuid::Uuid::new_v4().to_string())
            .open_driven()
            .map_err(BootError::ReplicaOpen)?;
        let spec = BootReplicaSpec {
            replica_db_name: connetto_client::REPLICA_PREFIX.to_owned(),
            active_account: None,
            identified: false,
            existing: false,
            identity: None,
            session_expires_at: None,
        };
        return Ok((spec, worker, content_root_key));
    };
    let place = OpfsPlace { storage, prefix };
    let located = place
        .locate(resolved.credential.replica_name())
        .map_err(BootError::ReplicaOpen)?;
    let key = if located.exists() {
        key_store
            .load(located.record())
            .await
            .map_err(BootError::KeyStore)?
    } else {
        Some(
            crate::auth::provision_replica_key(key_store.as_ref(), located.record())
                .await
                .map_err(BootError::KeyStore)?,
        )
    };
    let content_root_key = key.as_ref().map(|key| *key.as_bytes());
    let worker = core
        .signed_in(resolved.credential)
        .durable(
            place,
            crate::auth::BuilderKeyStore::new(Rc::clone(key_store)),
        )
        .open_driven()
        .await
        .map_err(BootError::ReplicaOpen)?;
    let spec = BootReplicaSpec {
        replica_db_name: located.record().to_owned(),
        active_account: resolved.account,
        identified: true,
        existing: located.exists(),
        identity: resolved.identity,
        session_expires_at: resolved.session_expires_at,
    };
    tracing::info!(
        replica = %spec.replica_db_name,
        resumed = spec.existing,
        "db worker: replica open"
    );
    Ok((spec, worker, content_root_key))
}

/// Attach the worker to the server at boot, or leave it offline for the
/// reconnect loop when no server answers.
pub(super) async fn try_connect_upstream(
    worker: &mut ConnettoConnection<BrowserSocket>,
    ws_url: &str,
) -> Result<(), BootError> {
    match BrowserSocket::connect(ws_url).await {
        Ok(transport) => worker
            .attach(transport)
            .await
            .map_err(BootError::ReplicaOpen),
        Err(err) => {
            tracing::warn!(
                error = %err,
                url = ws_url,
                "db worker: no server reachable, starting offline"
            );
            Ok(())
        }
    }
}

pub(super) async fn subscribe_and_boot(
    worker: &mut ConnettoConnection<BrowserSocket>,
    config: &WebConfig,
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
