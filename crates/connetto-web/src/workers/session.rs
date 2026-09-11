use wasm_bindgen::JsValue;

use connetto_core::traits::RefreshTokenStore;

use super::helpers::to_js;

/// Acquire a session, refreshing silently or driving an interactive login.
pub(super) async fn acquire_session<Id: serde::de::DeserializeOwned + serde::Serialize>(
    auth: &crate::auth::WorkerAuthConfig,
    auth_db_name: &str,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
    pick_account: bool,
) -> Result<crate::auth::BrowserSession<Id>, JsValue> {
    let store = open_refresh_store(auth_db_name, storage, key_store).await?;
    let account = choose_account(&store, pick_account).await?;
    drive_acquisition(auth, &store, account).await
}

/// Select which account to sign in as, or `None` for an interactive login.
async fn choose_account(
    store: &crate::auth::RefreshStore,
    pick_account: bool,
) -> Result<Option<String>, JsValue> {
    let remembered = crate::auth::remembered_account(store).map_err(to_js)?;
    if !pick_account {
        return Ok(remembered);
    }
    let accounts = RefreshTokenStore::accounts(store).map_err(to_js)?;
    if accounts.is_empty() && remembered.is_none() {
        return Ok(None);
    }
    match crate::unlock::ask_account(&accounts).await.map_err(to_js)? {
        crate::unlock::TabAnswer::Account(crate::unlock::AccountChoice::Named(chosen)) => {
            if !accounts.contains(&chosen) {
                return Err(to_js(crate::auth::AuthError::Context(
                    "the tab named an account that was not offered".into(),
                )));
            }
            Ok(Some(chosen))
        }
        crate::unlock::TabAnswer::Account(crate::unlock::AccountChoice::LastUsed) => Ok(remembered),
        crate::unlock::TabAnswer::Account(crate::unlock::AccountChoice::New) => Ok(None),
        other => Err(to_js(crate::auth::AuthError::Context(format!(
            "the tab answered the account question with {}",
            crate::unlock::answer_kind(&other)
        )))),
    }
}

/// Acquire without persisting anything, for a first run whose gate has not settled yet.
pub(super) async fn acquire_deferred<Id: serde::de::DeserializeOwned + serde::Serialize>(
    auth: &crate::auth::WorkerAuthConfig,
) -> Result<
    (
        crate::auth::BrowserSession<Id>,
        crate::auth::DeferredRefreshStore,
    ),
    JsValue,
> {
    let deferred = crate::auth::DeferredRefreshStore::default();
    let session = drive_acquisition(auth, &deferred, None).await?;
    Ok((session, deferred))
}

/// Write a deferred acquisition through to the real store once the gate has settled.
pub(super) async fn persist_deferred(
    deferred: &crate::auth::DeferredRefreshStore,
    auth_db_name: &str,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
) -> Result<(), JsValue> {
    let store = open_refresh_store(auth_db_name, storage, key_store).await?;
    for (account, token) in deferred.take() {
        RefreshTokenStore::store(&store, &account, &token).map_err(to_js)?;
    }
    Ok(())
}

/// Open the refresh store under this device's own key.
async fn open_refresh_store(
    auth_db_name: &str,
    storage: &crate::storage::ReplicaStorage,
    key_store: &crate::auth::IdbKeyStore,
) -> Result<crate::auth::RefreshStore, JsValue> {
    let device_key = crate::storage::device_key(key_store).await.map_err(to_js)?;
    let auth_db_url = storage.db_url(auth_db_name);
    match crate::auth::RefreshStore::open(&auth_db_url, &device_key) {
        Ok(store) => Ok(store),
        Err(crate::auth::AuthError::Undecryptable(detail)) => {
            tracing::warn!(
                detail = %detail,
                "db worker: the refresh store does not decrypt, discarding it and requiring a \
                 fresh login"
            );
            storage.delete_db(auth_db_name).map_err(to_js)?;
            crate::auth::RefreshStore::open(&auth_db_url, &device_key).map_err(to_js)
        }
        Err(err) => Err(to_js(err)),
    }
}

/// Silently refresh from whatever `store` holds, or drive an interactive login when empty.
async fn drive_acquisition<Id, S>(
    auth: &crate::auth::WorkerAuthConfig,
    store: &S,
    account: Option<String>,
) -> Result<crate::auth::BrowserSession<Id>, JsValue>
where
    Id: serde::de::DeserializeOwned + serde::Serialize,
    S: RefreshTokenStore<Error = crate::auth::AuthError>,
{
    let authenticator = crate::auth::BrowserAuthenticator::new(auth.clone(), account);
    match authenticator.acquire(store).await.map_err(to_js)? {
        crate::auth::Acquired::Access(session) => Ok(session),
        crate::auth::Acquired::NeedLogin(pending) => {
            let (code, state) = crate::auth::await_login_code(&pending.login_url)
                .await
                .map_err(to_js)?;
            authenticator
                .complete(&pending, &code, &state, store)
                .await
                .map_err(to_js)
        }
    }
}
