use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use web_sys::{BroadcastChannel, MessageEvent};

/// Serve [`crate::auth::LOGOUT_CHANNEL`] for this worker's life.
///
/// [`super::boot_db_worker`] calls this itself; call directly when assembling a worker by hand.
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
    listener.forget();
    Ok(())
}

async fn ask_unsynced(hub: &crate::relay::RelayHub) -> Option<crate::auth::PendingWork> {
    match hub.unsynced().await {
        Ok(pending) => Some(pending),
        Err(err) => {
            tracing::error!(error = %err, "db worker: the hub cannot report unsynced work");
            None
        }
    }
}

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

async fn handle_forget_retired(
    files: &[String],
    hub: &crate::relay::RelayHub,
) -> Option<crate::auth::LogoutMessage> {
    use crate::auth::LogoutMessage;
    let Some(retired) = files
        .iter()
        .map(|file| file_id_from_hex(file))
        .collect::<Option<Vec<_>>>()
    else {
        return Some(LogoutMessage::ForgetFailed {
            files: files.to_vec(),
            detail: "a file identity was not readable".to_owned(),
        });
    };
    match hub.forget_retired_content(retired).await {
        Ok(()) => Some(LogoutMessage::Forgot {
            files: files.to_vec(),
        }),
        Err(err) => Some(LogoutMessage::ForgetFailed {
            files: files.to_vec(),
            detail: err.to_string(),
        }),
    }
}

async fn guard_replica_deletion(
    replica_db_name: &str,
    content_namespace: Option<&str>,
    hub: &crate::relay::RelayHub,
    force: bool,
) -> Result<(), Option<crate::auth::LogoutMessage>> {
    let Some(pending) = ask_unsynced(hub).await else {
        return Err(None);
    };
    let wipe =
        crate::storage::PendingWipe::new(replica_db_name, content_namespace.map(ToOwned::to_owned));
    crate::storage::mark_wipe_pending(&wipe, &pending, force)
        .await
        .map_err(|err| match err {
            crate::storage::WipeError::Unsynced(pending) => {
                Some(crate::auth::LogoutMessage::Refused { pending })
            }
            other => {
                tracing::error!(error = %other, "db worker: marking the replica for deletion failed");
                None
            }
        })
}

/// Handle one logout-channel request, returning the reply or `None` for non-request traffic.
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
            return handle_forget_retired(files, hub).await;
        }
        LogoutMessage::Pending { .. }
        | LogoutMessage::Done { .. }
        | LogoutMessage::Refused { .. }
        | LogoutMessage::Forgot { .. }
        | LogoutMessage::ForgetFailed { .. } => {
            return None;
        }
    };
    // Guard before revoke: a refused delete must leave the session intact.
    if delete
        && let Err(reply) =
            guard_replica_deletion(replica_db_name, content_namespace, hub, force).await
    {
        return reply;
    }
    match logout_locally(auth, auth_db_name, account).await {
        Ok(()) => {}
        Err(err) => tracing::warn!(
            error = %err,
            "db worker: the session revoke failed, local state cleared anyway"
        ),
    }
    Some(LogoutMessage::Done { deleted: delete })
}

/// Revoke the session and clear the stored credential.
///
/// Uses the worker's own key store because a fresh store is locked on an enrolled profile.
async fn logout_locally(
    auth: &crate::auth::WorkerAuthConfig,
    auth_db_name: &str,
    account: Option<&str>,
) -> Result<(), crate::auth::AuthError> {
    let storage = crate::storage::ReplicaStorage::install().await;
    let keys = match crate::unlock::worker_key_store() {
        Some(keys) => keys,
        None => std::rc::Rc::new(crate::auth::IdbKeyStore::open().await?),
    };
    let device = crate::storage::device_key(&*keys).await?;
    let store = crate::auth::RefreshStore::open(&storage.db_url(auth_db_name), &device)?;
    crate::auth::BrowserAuthenticator::new(auth.clone(), account.map(ToOwned::to_owned))
        .logout(&store)
        .await
}
