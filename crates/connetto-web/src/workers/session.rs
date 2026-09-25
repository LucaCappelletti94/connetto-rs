use crate::auth::AuthError;

/// Bundled storage context for session acquisition and account persistence.
pub(crate) struct AccountStoreHandle<'a> {
    pub(crate) db_name: &'a str,
    pub(crate) storage: &'a crate::storage::ReplicaStorage,
}

/// Acquire a session, refreshing silently or driving an interactive login.
pub(crate) async fn acquire_session<Id: serde::de::DeserializeOwned + serde::Serialize>(
    auth: &crate::auth::WorkerAuthConfig,
    store: &AccountStoreHandle<'_>,
    pick_account: bool,
) -> Result<crate::auth::BrowserSession<Id>, AuthError> {
    let store = open_account_store(store)?;
    let account = choose_account(&store, pick_account).await?;
    drive_acquisition(auth, &store, account).await
}

/// Select which account to sign in as, or `None` for an interactive login.
async fn choose_account(
    store: &crate::auth::AccountStore,
    pick_account: bool,
) -> Result<Option<String>, AuthError> {
    let remembered = crate::auth::remembered_account(store)?;
    if !pick_account {
        return Ok(remembered);
    }
    let accounts = store.accounts()?;
    if accounts.is_empty() && remembered.is_none() {
        return Ok(None);
    }
    match super::intake::awaiting_user(crate::unlock::ask_account(&accounts)).await? {
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

/// Open the account index, discarding a file an earlier build encrypted and
/// propagating every other failure, which a discard would only turn into lost
/// accounts.
///
/// The name is the one the encrypted refresh store used. Such a database
/// cannot open as the plain index, and discarding it is right rather than a
/// loss: its credential belongs to the pre-cookie contract and cannot refresh
/// anymore, so the boot needs a fresh login either way.
pub(crate) fn open_account_store(
    ctx: &AccountStoreHandle<'_>,
) -> Result<crate::auth::AccountStore, AuthError> {
    let db_url = ctx.storage.db_url(ctx.db_name);
    match crate::auth::AccountStore::open(&db_url) {
        Ok(store) => Ok(store),
        Err(err @ AuthError::Undecryptable(_)) => {
            tracing::warn!(
                error = %err,
                "db worker: the account index is not a readable database, discarding it and \
                 requiring a fresh login"
            );
            ctx.storage.delete_db(ctx.db_name)?;
            crate::auth::AccountStore::open(&db_url)
        }
        Err(err) => Err(err),
    }
}

/// Silently refresh from the cookie the browser holds, or drive an interactive
/// login when the account is absent or refused.
async fn drive_acquisition<Id>(
    auth: &crate::auth::WorkerAuthConfig,
    store: &crate::auth::AccountStore,
    account: Option<String>,
) -> Result<crate::auth::BrowserSession<Id>, AuthError>
where
    Id: serde::de::DeserializeOwned + serde::Serialize,
{
    let authenticator = crate::auth::BrowserAuthenticator::new(auth.clone(), account);
    match authenticator.acquire(store).await? {
        crate::auth::Acquired::Access(session) => Ok(session),
        crate::auth::Acquired::NeedLogin(pending) => {
            let (code, state) =
                super::intake::awaiting_user(crate::auth::await_login_code(&pending.login_url))
                    .await?;
            authenticator.complete(&pending, &code, &state, store).await
        }
    }
}
