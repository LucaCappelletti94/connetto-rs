use connetto_client::builder::sign_in::{AccountChoice, HeldCredential, SignInKind};
use connetto_client::{AccessTokenSource, ClientError};

use crate::auth::AuthError;

/// Bundled storage context for session acquisition and account persistence.
pub(crate) struct AccountStoreHandle<'a> {
    pub(crate) db_name: &'a str,
    pub(crate) storage: &'a crate::storage::ReplicaStorage,
}

/// The provider fields a sign-in names, or an error for a held credential,
/// which does not drive a provider login.
fn provider_parts(
    kind: &SignInKind,
) -> Result<(&str, Option<&str>, &str, AccountChoice), AuthError> {
    match kind {
        SignInKind::Provider {
            origin,
            login_origin,
            provider,
            account,
            ..
        } => Ok((
            origin.as_str(),
            login_origin.as_deref(),
            provider.as_str(),
            account.clone(),
        )),
        SignInKind::Held(_) => Err(AuthError::Context(
            "a held credential does not drive a provider login".into(),
        )),
    }
}

/// Acquire a session, refreshing silently or driving an interactive login.
pub(crate) async fn acquire_session<Id: serde::de::DeserializeOwned + serde::Serialize>(
    kind: &SignInKind,
    store: &AccountStoreHandle<'_>,
    redirect_uri: Option<&str>,
) -> Result<crate::auth::BrowserSession<Id>, AuthError> {
    let (origin, login_origin, provider, account_choice) = provider_parts(kind)?;
    let store = open_account_store(store)?;
    let account = choose_account(&store, account_choice).await?;
    drive_acquisition(
        origin,
        login_origin,
        provider,
        redirect_uri,
        &store,
        account,
    )
    .await
}

/// What a resolved sign-in established for the boot.
pub(crate) struct ResolvedSignIn<Id> {
    /// The credential the boot hands the core builder.
    pub(crate) credential: HeldCredential,
    /// The identity the session was acquired for, when a provider login
    /// established one.
    pub(crate) identity: Option<Id>,
    /// Unix seconds when the local session lapses, when a provider login
    /// established one.
    pub(crate) session_expires_at: Option<u64>,
    /// The credential-store key the account is addressed by, when a
    /// provider login established one.
    pub(crate) account: Option<String>,
}

/// Resolve the sign-in to the credential the boot hands the core builder.
///
/// The provider sign-in drives the provider login and seals the acquired
/// session into a credential backed by a cookie token source. The held
/// sign-in hands its credential through, which the application sealed.
///
/// # Errors
///
/// [`AuthError`] on a store, account, or provider failure.
pub(crate) async fn resolve_sign_in<Id>(
    kind: SignInKind,
    store: &AccountStoreHandle<'_>,
    redirect_uri: Option<&str>,
) -> Result<ResolvedSignIn<Id>, AuthError>
where
    Id: serde::de::DeserializeOwned + serde::Serialize + core::fmt::Display,
{
    let provider = match kind {
        SignInKind::Held(credential) => {
            return Ok(ResolvedSignIn {
                credential,
                identity: None,
                session_expires_at: None,
                account: None,
            });
        }
        provider @ SignInKind::Provider { .. } => provider,
    };
    let (origin, ..) = provider_parts(&provider)?;
    let origin = origin.to_owned();
    let session = acquire_session::<Id>(&provider, store, redirect_uri).await?;
    let account = connetto_client::encode_identity(&session.user_id)
        .map_err(|err| AuthError::Context(err.to_string()))?;
    let body = serde_json::json!({ "user_id": &session.user_id }).to_string();
    let credential = HeldCredential::new(
        connetto_client::Grant::new(session.access_token),
        &session.user_id,
    )
    .map_err(|err| AuthError::Context(err.to_string()))?
    .with_token_source(refresh_source(&origin, body));
    Ok(ResolvedSignIn {
        credential,
        identity: Some(session.user_id),
        session_expires_at: Some(session.session_expires_at),
        account: Some(account),
    })
}

/// The token source a provider boot attaches to its credential.
///
/// Every reconnect renews the access token through the cookie the browser
/// holds, and a refused refresh fails the resume, which the reconnect
/// policy then retries.
fn refresh_source(origin: &str, body: String) -> AccessTokenSource {
    let url: std::sync::Arc<str> = format!("{origin}/auth/refresh").into();
    let body: std::sync::Arc<str> = body.into();
    AccessTokenSource::new(move || {
        let url = std::sync::Arc::clone(&url);
        let body = std::sync::Arc::clone(&body);
        // A browser fetch holds JavaScript handles, and this target has one thread.
        send_wrapper::SendWrapper::new(async move {
            let text = crate::auth::post_json(&url, &body)
                .await
                .map_err(|err| ClientError::Auth(err.to_string()))?;
            let refreshed: Refreshed = serde_json::from_str(&text)
                .map_err(|_| ClientError::Auth("the refresh response was not a token".into()))?;
            Ok(refreshed.access_token)
        })
    })
}

/// The one field a token source reads off a refresh response.
#[derive(serde::Deserialize)]
struct Refreshed {
    access_token: String,
}

/// Select which account to sign in as, or `None` for an interactive login.
async fn choose_account(
    store: &crate::auth::AccountStore,
    choice: AccountChoice,
) -> Result<Option<String>, AuthError> {
    let remembered = crate::auth::remembered_account(store)?;
    match choice {
        AccountChoice::LastUsed => Ok(remembered),
        AccountChoice::Account(name) => {
            let accounts = store.accounts()?;
            if !accounts.contains(&name) {
                return Err(AuthError::Context(
                    "the named account was not offered by the store".into(),
                ));
            }
            Ok(Some(name))
        }
        AccountChoice::New => Ok(None),
        AccountChoice::Ask => {
            let accounts = store.accounts()?;
            if accounts.is_empty() && remembered.is_none() {
                return Ok(None);
            }
            match super::intake::awaiting_user(crate::unlock::ask_account(&accounts)).await? {
                crate::unlock::TabAnswer::Account(choice) => match choice {
                    AccountChoice::Account(chosen) => {
                        if !accounts.contains(&chosen) {
                            return Err(AuthError::Context(
                                "the tab named an account that was not offered".into(),
                            ));
                        }
                        Ok(Some(chosen))
                    }
                    AccountChoice::LastUsed => Ok(remembered),
                    AccountChoice::New => Ok(None),
                    AccountChoice::Ask => Err(AuthError::Context(
                        "the tab answered the account question with an ask".into(),
                    )),
                },
                other => Err(AuthError::Context(format!(
                    "the tab answered the account question with {}",
                    crate::unlock::answer_kind(&other)
                ))),
            }
        }
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
    origin: &str,
    login_origin: Option<&str>,
    provider: &str,
    redirect_uri: Option<&str>,
    store: &crate::auth::AccountStore,
    account: Option<String>,
) -> Result<crate::auth::BrowserSession<Id>, AuthError>
where
    Id: serde::de::DeserializeOwned + serde::Serialize,
{
    let auth = connetto_client::Auth::new(origin, provider)
        .with_login_origin(login_origin.map(str::to_owned));
    let authenticator =
        crate::auth::BrowserAuthenticator::new(&auth, redirect_uri.unwrap_or_default(), account);
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
