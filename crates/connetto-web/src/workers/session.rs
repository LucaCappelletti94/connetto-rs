use connetto_core::traits::RefreshTokenStore;

use crate::auth::AuthError;

/// Bundled storage context for session acquisition and token persistence.
pub(crate) struct RefreshStoreHandle<'a> {
    pub(crate) db_name: &'a str,
    pub(crate) storage: &'a crate::storage::ReplicaStorage,
    pub(crate) key_store: &'a crate::auth::IdbKeyStore,
}

/// Acquire a session, refreshing silently or driving an interactive login.
pub(crate) async fn acquire_session<Id: serde::de::DeserializeOwned + serde::Serialize>(
    auth: &crate::auth::WorkerAuthConfig,
    store: &RefreshStoreHandle<'_>,
    pick_account: bool,
) -> Result<crate::auth::BrowserSession<Id>, AuthError> {
    let refresh = open_refresh_store(store).await?;
    let account = choose_account(&refresh, pick_account).await?;
    drive_acquisition(auth, &refresh, account).await
}

/// Select which account to sign in as, or `None` for an interactive login.
async fn choose_account(
    store: &crate::auth::RefreshStore,
    pick_account: bool,
) -> Result<Option<String>, AuthError> {
    let remembered = crate::auth::remembered_account(store)?;
    if !pick_account {
        return Ok(remembered);
    }
    let accounts = RefreshTokenStore::accounts(store)?;
    if accounts.is_empty() && remembered.is_none() {
        return Ok(None);
    }
    match crate::unlock::ask_account(&accounts).await? {
        crate::unlock::TabAnswer::Account(crate::unlock::AccountChoice::Named(chosen)) => {
            if !accounts.contains(&chosen) {
                return Err(AuthError::Context(
                    "the tab named an account that was not offered".into(),
                ));
            }
            Ok(Some(chosen))
        }
        crate::unlock::TabAnswer::Account(crate::unlock::AccountChoice::LastUsed) => Ok(remembered),
        crate::unlock::TabAnswer::Account(crate::unlock::AccountChoice::New) => Ok(None),
        other => Err(AuthError::Context(format!(
            "the tab answered the account question with {}",
            crate::unlock::answer_kind(&other)
        ))),
    }
}

/// Acquire without persisting anything, for a first run whose gate has not settled yet.
pub(crate) async fn acquire_deferred<Id: serde::de::DeserializeOwned + serde::Serialize>(
    auth: &crate::auth::WorkerAuthConfig,
) -> Result<
    (
        crate::auth::BrowserSession<Id>,
        crate::auth::DeferredRefreshStore,
    ),
    AuthError,
> {
    let deferred = crate::auth::DeferredRefreshStore::default();
    let session = drive_acquisition(auth, &deferred, None).await?;
    Ok((session, deferred))
}

/// Write a deferred acquisition through to the real store once the gate has settled.
pub(crate) async fn persist_deferred(
    deferred: &crate::auth::DeferredRefreshStore,
    store: &RefreshStoreHandle<'_>,
) -> Result<(), AuthError> {
    let refresh = open_refresh_store(store).await?;
    for (account, token) in deferred.take() {
        RefreshTokenStore::store(&refresh, &account, &token)?;
    }
    Ok(())
}

/// Open the refresh store under this device's own key.
async fn open_refresh_store(
    ctx: &RefreshStoreHandle<'_>,
) -> Result<crate::auth::RefreshStore, AuthError> {
    let device_key = crate::storage::device_key(ctx.key_store).await?;
    let auth_db_url = ctx.storage.db_url(ctx.db_name);
    match crate::auth::RefreshStore::open(&auth_db_url, &device_key) {
        Ok(store) => Ok(store),
        Err(AuthError::Undecryptable(detail)) => {
            tracing::warn!(
                detail = %detail,
                "db worker: the refresh store does not decrypt, discarding it and requiring a \
                 fresh login"
            );
            ctx.storage.delete_db(ctx.db_name)?;
            crate::auth::RefreshStore::open(&auth_db_url, &device_key)
        }
        Err(err) => Err(err),
    }
}

/// Silently refresh from whatever `store` holds, or drive an interactive login when empty.
async fn drive_acquisition<Id, S>(
    auth: &crate::auth::WorkerAuthConfig,
    store: &S,
    account: Option<String>,
) -> Result<crate::auth::BrowserSession<Id>, AuthError>
where
    Id: serde::de::DeserializeOwned + serde::Serialize,
    S: RefreshTokenStore<Error = crate::auth::AuthError>,
{
    let authenticator = crate::auth::BrowserAuthenticator::new(auth.clone(), account);
    match authenticator.acquire(store).await? {
        crate::auth::Acquired::Access(session) => Ok(session),
        crate::auth::Acquired::NeedLogin(pending) => {
            let (code, state) = crate::auth::await_login_code(&pending.login_url).await?;
            authenticator.complete(&pending, &code, &state, store).await
        }
    }
}
