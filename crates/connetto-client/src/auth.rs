//! Native OAuth acquisition: loopback redirect, system browser, OS secure
//! storage, and silent refresh.
//!
//! connetto-server is the OAuth client (Backend-For-Frontend); this native
//! client treats connetto-server as its own authorization server and runs
//! Authorization Code plus PKCE against it over a `127.0.0.1` loopback listener
//! and the system browser. connetto's refresh token is stored in OS secure
//! storage and the short-lived access token lives in memory, regenerated from
//! the refresh token as needed. See `docs/architecture/11-authentication.md`.
//!
//! [`NativeAuthenticator::token_source`] yields an [`AccessTokenSource`] for
//! [`ConnettoConnection::with_token_source`](crate::ConnettoConnection::with_token_source),
//! so a reconnect silently refreshes with no user interaction.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connetto_core::ReplicaKey;
use connetto_core::percent::{percent_decode, percent_encode};
use connetto_core::traits::{RefreshTokenStore, ReplicaKeyStore};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zeroize::{Zeroize, Zeroizing};

use crate::{AccessTokenSource, ClientError, IDENTITY_RECORD, encode_identity};

fn ensure_keyring_store() -> Result<(), ClientError> {
    static STORE: OnceLock<Result<(), Arc<str>>> = OnceLock::new();
    STORE
        .get_or_init(|| install_keyring_store().map_err(|err| Arc::<str>::from(err.to_string())))
        .as_ref()
        .copied()
        .map_err(|err| ClientError::Auth(format!("keyring setup: {err}")))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn install_keyring_store() -> keyring_core::Result<()> {
    keyring_core::set_default_store(apple_native_keyring_store::keychain::Store::new()?);
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_keyring_store() -> keyring_core::Result<()> {
    keyring_core::set_default_store(linux_keyutils_keyring_store::Store::new()?);
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_keyring_store() -> keyring_core::Result<()> {
    keyring_core::set_default_store(windows_native_keyring_store::Store::new()?);
    Ok(())
}

#[cfg(not(any(
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "windows"
)))]
fn install_keyring_store() -> keyring_core::Result<()> {
    Err(keyring_core::Error::Invalid(
        "platform".to_owned(),
        "native auth has no keyring store for this platform".to_owned(),
    ))
}

/// The keyring sequence both secret stores here perform.
///
/// One service holds one entry per name, so the sequence lives here once.
struct Keyring {
    service: String,
}

impl Keyring {
    fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// The keyring entry for `name`.
    fn entry(&self, name: &str) -> Result<keyring_core::Entry, ClientError> {
        ensure_keyring_store()?;
        keyring_core::Entry::new(&self.service, name)
            .map_err(|err| ClientError::Auth(format!("keyring open: {err}")))
    }

    /// The secret stored under `name`, or `None` when none was stored.
    fn read(&self, name: &str) -> Result<Option<String>, ClientError> {
        let entry = self.entry(name)?;
        match entry.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(err) => Err(ClientError::Auth(format!("keyring load: {err}"))),
        }
    }

    /// Persist `secret` under `name`, replacing any prior one.
    fn write(&self, name: &str, secret: &str) -> Result<(), ClientError> {
        self.entry(name)?
            .set_password(secret)
            .map_err(|err| ClientError::Auth(format!("keyring store: {err}")))
    }

    /// Remove the entry stored under `name`, if any.
    fn clear(&self, name: &str) -> Result<(), ClientError> {
        let entry = self.entry(name)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => Err(ClientError::Auth(format!("keyring clear: {err}"))),
        }
    }
}

/// OS secure storage for the refresh token: Keychain on Apple platforms,
/// Credential Manager on Windows, and keyutils on Linux.
///
/// One service holds one entry per account, exactly as [`KeyringKeyStore`]
/// holds one per replica record.
pub struct KeyringStore {
    keyring: Keyring,
}

impl KeyringStore {
    /// Store refresh tokens under `service` in the OS keyring.
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            keyring: Keyring::new(service),
        }
    }

    /// The indexed accounts, empty when nothing was ever stored.
    ///
    /// An index that does not parse is treated as absent rather than fatal: it is
    /// a hint about what to offer, and refusing to open the store over it would
    /// turn a listing problem into a lockout. The credentials themselves are
    /// untouched, and the next sign-in rewrites it.
    fn index(&self) -> Result<Vec<String>, ClientError> {
        let Some(raw) = self.keyring.read(crate::replica::ACCOUNTS_RECORD)? else {
            return Ok(Vec::new());
        };
        Ok(serde_json::from_str(&raw).unwrap_or_default())
    }

    fn write_index(&self, accounts: &[String]) -> Result<(), ClientError> {
        let encoded = serde_json::to_string(accounts)
            .map_err(|err| ClientError::Auth(format!("encoding the account index: {err}")))?;
        self.keyring
            .write(crate::replica::ACCOUNTS_RECORD, &encoded)
    }
}

/// `known` with `account` added, or `None` when the index already says what it
/// needs to and no write is worth its round trip.
///
/// A reserved record is never indexed: it shares the key namespace with the
/// accounts, and offering one as somebody to sign in as would put a credential
/// nobody owns in front of a user.
fn indexed_with(known: &[String], account: &str) -> Option<Vec<String>> {
    if crate::is_reserved_record(account) || known.iter().any(|name| name == account) {
        return None;
    }
    let mut updated = known.to_vec();
    updated.push(account.to_owned());
    Some(updated)
}

/// `known` with `account` removed, or `None` when it was not there.
fn indexed_without(known: &[String], account: &str) -> Option<Vec<String>> {
    if crate::is_reserved_record(account) || !known.iter().any(|name| name == account) {
        return None;
    }
    Some(
        known
            .iter()
            .filter(|name| *name != account)
            .cloned()
            .collect(),
    )
}

impl RefreshTokenStore for KeyringStore {
    type Error = ClientError;

    fn load(&self, account: &str) -> Result<Option<String>, ClientError> {
        self.keyring.read(account)
    }

    /// Writes the entry, then records the account in the index so
    /// [`accounts`](Self::accounts) can answer at all.
    ///
    /// The index is maintained here rather than by the authenticator so that no
    /// caller can write a credential without it being listable. A reserved
    /// record is not an account and is not indexed.
    fn store(&self, account: &str, token: &str) -> Result<(), ClientError> {
        self.keyring.write(account, token)?;
        match indexed_with(&self.index()?, account) {
            Some(updated) => self.write_index(&updated),
            None => Ok(()),
        }
    }

    /// Removes the entry and drops the account from the index.
    ///
    /// The entry goes first, so an interruption leaves a listed account with no
    /// credential, which costs an interactive login. The other order would leave
    /// a credential nothing can list, which is a secret the user cannot see or
    /// reach.
    fn clear(&self, account: &str) -> Result<(), ClientError> {
        self.keyring.clear(account)?;
        match indexed_without(&self.index()?, account) {
            Some(updated) => self.write_index(&updated),
            None => Ok(()),
        }
    }

    fn accounts(&self) -> Result<Vec<String>, ClientError> {
        self.index()
    }
}

/// An in-memory refresh-token store, for tests and ephemeral sessions.
#[derive(Default)]
pub struct MemoryRefreshStore {
    inner: Mutex<std::collections::HashMap<String, String>>,
}

impl RefreshTokenStore for MemoryRefreshStore {
    type Error = ClientError;

    fn load(&self, account: &str) -> Result<Option<String>, ClientError> {
        Ok(self
            .inner
            .lock()
            .expect("refresh store lock")
            .get(account)
            .cloned())
    }

    fn store(&self, account: &str, token: &str) -> Result<(), ClientError> {
        self.inner
            .lock()
            .expect("refresh store lock")
            .insert(account.to_owned(), token.to_owned());
        Ok(())
    }

    fn clear(&self, account: &str) -> Result<(), ClientError> {
        self.inner
            .lock()
            .expect("refresh store lock")
            .remove(account);
        Ok(())
    }

    /// Enumerated from the map itself, so it cannot disagree with what is stored.
    fn accounts(&self) -> Result<Vec<String>, ClientError> {
        Ok(self
            .inner
            .lock()
            .expect("refresh store lock")
            .keys()
            .filter(|name| !crate::is_reserved_record(name))
            .cloned()
            .collect())
    }
}

/// The account key this device last signed in under, if it ever did.
///
/// This is what a start reads to know which stored credential to try, and it is
/// also what makes a start with no network possible at all: the replica file is
/// named from the account, and the account otherwise only arrives inside a token
/// response, which needs the network to fetch.
///
/// Decode it into the deployment's own id type with
/// [`decode_identity`](crate::decode_identity) when the caller wants to show who
/// it is rather than address a record.
///
/// # Errors
///
/// [`ClientError`] if the store cannot be read.
pub fn remembered_account<S>(store: &S) -> Result<Option<String>, ClientError>
where
    S: RefreshTokenStore<Error = ClientError> + ?Sized,
{
    store.load(IDENTITY_RECORD)
}

/// The effective key for the replica `name`, minting one when this device has
/// none cached.
///
/// Provision-once in one function: a key already cached on this device always
/// wins and is never overwritten, so a second login cannot silently re-key a
/// replica and strand its contents. Only when nothing is cached is a fresh key
/// minted, and it is written through before it is returned.
///
/// The key is minted here, on the device, from the same platform RNG that mints
/// the PKCE verifier and the CSRF state. No key material crosses the wire and
/// the server never holds any. The scope the plan locked is unchanged: one key
/// per replica per device, cached locally, usable with no credential and no
/// network.
///
/// It stays once per target rather than moving to `connetto-core` beside the
/// trait, because minting needs an entropy source and `ReplicaKey` deliberately
/// carries none, which is what keeps the browser build free of one.
///
/// **Call this only for a replica that does not exist yet.** For one already on
/// disk, read the cache with [`ReplicaKeyStore::load`] and hand the result to
/// [`Replica::encrypted_file`](crate::Replica::encrypted_file). Minting for an
/// existing replica would return a key that decrypts nothing, and it would fill
/// the record that restoring a backed-up key still could, where the refusal
/// ([`ClientError::ReplicaKeyMissing`])
/// leaves both the ciphertext and that recovery intact.
///
/// # Errors
///
/// [`ClientError::Auth`] if the store cannot be read or written, or if the
/// platform RNG fails.
pub async fn provision_replica_key<S: ReplicaKeyStore<Error = ClientError>>(
    store: &S,
    name: &str,
) -> Result<ReplicaKey, ClientError> {
    if let Some(cached) = store.load(name).await? {
        return Ok(cached);
    }
    let minted = mint_replica_key()?;
    store.store(name, &minted).await?;
    Ok(minted)
}

/// A fresh key from the platform RNG.
///
/// The staging array is key material until it is wiped, and a plain fill would
/// be elidable where `zeroize` is not.
fn mint_replica_key() -> Result<ReplicaKey, ClientError> {
    let mut bytes = [0u8; ReplicaKey::LEN];
    getrandom::fill(&mut bytes)
        .map_err(|err| ClientError::Auth(format!("replica key mint: {err}")))?;
    let key = ReplicaKey::from_bytes(bytes);
    bytes.zeroize();
    Ok(key)
}

/// OS secure storage for the per-replica encryption keys, using the same
/// keyring backend as [`KeyringStore`].
///
/// The keyring account is the record name, so one service holds one entry per
/// identity.
pub struct KeyringKeyStore {
    keyring: Keyring,
}

impl KeyringKeyStore {
    /// Store replica keys under `service` in the OS keyring.
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            keyring: Keyring::new(service),
        }
    }
}

// Every method here returns before it yields, which is the cost decision 2 of
// R41 accepted: the trait awaits because the browser must, and the keychain
// call blocks whoever polls it. Bounded, since key custody runs at open and at
// logout rather than per change.
#[allow(clippy::unused_async_trait_impl)]
impl ReplicaKeyStore for KeyringKeyStore {
    type Error = ClientError;

    async fn load(&self, name: &str) -> Result<Option<ReplicaKey>, ClientError> {
        self.keyring
            .read(name)?
            // The keyring hands back an owned hex string, which is key
            // material until it is wiped, hence the `Zeroizing` wrapper.
            .map(|hex| {
                Zeroizing::new(hex)
                    .parse::<ReplicaKey>()
                    .map_err(|err| ClientError::Auth(format!("keyring key parse: {err}")))
            })
            .transpose()
    }

    async fn store(&self, name: &str, key: &ReplicaKey) -> Result<(), ClientError> {
        let mut hex = Zeroizing::new(String::with_capacity(ReplicaKey::LEN * 2));
        for byte in key.as_bytes() {
            let _ = write!(&mut *hex, "{byte:02x}");
        }
        self.keyring.write(name, &hex)
    }

    async fn clear(&self, name: &str) -> Result<(), ClientError> {
        self.keyring.clear(name)
    }
}

/// An in-memory replica-key store, for tests and ephemeral sessions.
#[derive(Default)]
pub struct MemoryKeyStore {
    inner: Mutex<std::collections::HashMap<String, ReplicaKey>>,
}

#[allow(clippy::unused_async_trait_impl)]
impl ReplicaKeyStore for MemoryKeyStore {
    type Error = ClientError;

    async fn load(&self, name: &str) -> Result<Option<ReplicaKey>, ClientError> {
        Ok(self
            .inner
            .lock()
            .expect("key store lock")
            .get(name)
            .cloned())
    }

    async fn store(&self, name: &str, key: &ReplicaKey) -> Result<(), ClientError> {
        self.inner
            .lock()
            .expect("key store lock")
            .insert(name.to_owned(), key.clone());
        Ok(())
    }

    async fn clear(&self, name: &str) -> Result<(), ClientError> {
        self.inner.lock().expect("key store lock").remove(name);
        Ok(())
    }
}

/// Opens a URL in the user's browser. Fire-and-forget: it returns immediately.
pub type BrowserOpener = Arc<dyn Fn(&str) -> Result<(), ClientError> + Send + Sync>;

/// The real opener, launching a detached system browser.
#[must_use]
pub fn system_browser_opener() -> BrowserOpener {
    Arc::new(|url: &str| {
        open::that_detached(url).map_err(|err| ClientError::Auth(format!("open browser: {err}")))
    })
}

/// The token pair connetto-server returns from its token and refresh endpoints.
#[derive(Debug, Deserialize)]
struct TokenResponse<Id> {
    access_token: String,
    refresh_token: String,
    user_id: Id,
    session_expires_at: u64,
}

/// The outcome of an acquisition: the access token for the handshake plus the
/// identity and session deadline the client needs to select its replica file
/// and to warn before an offline session lapses with unsynced data.
///
/// No key material rides this: the replica's encryption key is minted on the
/// device. Derive the replica name from
/// [`user_id`](Self::user_id) and pass it to [`provision_replica_key`] for a
/// fresh replica, or to [`ReplicaKeyStore::load`] for one already on disk.
#[derive(Debug, Clone)]
pub struct AcquiredSession<Id> {
    /// connetto's short-lived access token, presented as one grant on the handshake.
    pub access_token: String,
    /// The typed `user_id` this session belongs to. It selects the replica
    /// file through
    /// [`replica_db_name`](crate::replica::replica_db_name), so a
    /// re-authentication that resolves to a different identity opens a
    /// different file instead of resuming onto this one's data.
    pub user_id: Id,
    /// When the local session lapses if never refreshed again.
    pub session_expires_at: SystemTime,
}

impl<Id> From<TokenResponse<Id>> for AcquiredSession<Id> {
    fn from(response: TokenResponse<Id>) -> Self {
        Self {
            access_token: response.access_token,
            user_id: response.user_id,
            session_expires_at: UNIX_EPOCH + Duration::from_secs(response.session_expires_at),
        }
    }
}

/// Acquires and refreshes connetto's own tokens for a native client, driving the
/// loopback Authorization Code plus PKCE flow against connetto-server.
///
/// It holds the account whose stored credential it should try, rather than
/// passing one at each call, so no two call sites can disagree about which
/// credential this is.
pub struct NativeAuthenticator {
    server_base: String,
    provider: String,
    store: Arc<dyn RefreshTokenStore<Error = ClientError> + Send + Sync>,
    account: Option<String>,
    opener: BrowserOpener,
    http: reqwest::Client,
}

impl NativeAuthenticator {
    /// Build over connetto-server's auth base URL (for example
    /// `http://127.0.0.1:8081`), the provider name to log in with, a refresh
    /// token store, and the account whose stored credential to try. Uses the
    /// system browser.
    ///
    /// `account` is `None` when there is nothing to try, which is a first run and
    /// any start where nothing was remembered. It is not a placeholder for an
    /// unknown account: the token is what reveals the account, so a run with none
    /// skips the silent attempt rather than addressing a literal. Read the
    /// remembered one with [`remembered_account`].
    #[must_use]
    pub fn new(
        server_base: impl Into<String>,
        provider: impl Into<String>,
        store: Arc<dyn RefreshTokenStore<Error = ClientError> + Send + Sync>,
        account: Option<String>,
    ) -> Self {
        Self {
            server_base: server_base.into(),
            provider: provider.into(),
            store,
            account,
            opener: system_browser_opener(),
            http: reqwest::Client::new(),
        }
    }

    /// Replace the browser opener. Tests inject a fake that drives the loopback.
    #[must_use]
    pub fn with_browser_opener(mut self, opener: BrowserOpener) -> Self {
        self.opener = opener;
        self
    }

    /// Obtain an access token: silently refresh when a refresh token is stored,
    /// otherwise run the interactive loopback login.
    ///
    /// `Id` is the deployment's typed user id, deserialized straight from the
    /// token response. It never round-trips through text.
    ///
    /// # Errors
    ///
    /// [`ClientError::Auth`] if both refresh and login fail.
    pub async fn acquire<Id: DeserializeOwned + serde::Serialize>(
        &self,
    ) -> Result<AcquiredSession<Id>, ClientError> {
        if let Some(account) = self.account.as_deref()
            && self.store.load(account)?.is_some()
            && let Ok(session) = self.refresh_access().await
        {
            return Ok(session);
        }
        let session = self.login().await?;
        Ok(session)
    }

    /// Silently refresh the access token from the stored refresh token, rotating
    /// and re-storing it. Never opens a browser.
    ///
    /// # Errors
    ///
    /// [`ClientError::Auth`] if no refresh token is stored or the refresh fails.
    pub async fn refresh_access<Id: DeserializeOwned + serde::Serialize>(
        &self,
    ) -> Result<AcquiredSession<Id>, ClientError> {
        let response = self.refresh_tokens::<Id>().await?;
        self.remember(&response.user_id)?;
        Ok(response.into())
    }

    /// The refresh exchange itself: present the stored token, take the rotated
    /// one, and persist it.
    ///
    /// Separate from [`refresh_access`](Self::refresh_access) because
    /// [`token_source`](Self::token_source) wants only a fresh access token and
    /// has no id type to decode into, so it must not be forced to name one it
    /// could then write to the identity record.
    async fn refresh_tokens<Id: DeserializeOwned>(&self) -> Result<TokenResponse<Id>, ClientError> {
        let account = self
            .account
            .as_deref()
            .ok_or_else(|| ClientError::Auth("no account to refresh".to_owned()))?;
        let refresh = self
            .store
            .load(account)?
            .ok_or_else(|| ClientError::Auth("no stored refresh token".to_owned()))?;
        let response: TokenResponse<Id> = self
            .post_json(
                &format!("{}/auth/refresh", self.server_base),
                &serde_json::json!({ "refresh_token": refresh }),
            )
            .await?;
        self.store.store(account, &response.refresh_token)?;
        Ok(response)
    }

    /// Run the interactive loopback login: bind a `127.0.0.1` listener, open the
    /// system browser at connetto-server's login endpoint, catch the redirected
    /// code, exchange it with the PKCE verifier, and store the refresh token.
    ///
    /// # Errors
    ///
    /// [`ClientError::Auth`] on any loopback, browser, or exchange failure.
    pub async fn login<Id: DeserializeOwned + serde::Serialize>(
        &self,
    ) -> Result<AcquiredSession<Id>, ClientError> {
        let verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = random_token();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|err| ClientError::Auth(format!("loopback bind: {err}")))?;
        let port = listener
            .local_addr()
            .map_err(|err| ClientError::Auth(format!("loopback addr: {err}")))?
            .port();
        let redirect_uri = format!("http://127.0.0.1:{port}/callback");
        let url = format!(
            "{}/auth/login?provider={}&redirect_uri={}&code_challenge={}&state={}",
            self.server_base,
            percent_encode(&self.provider),
            percent_encode(&redirect_uri),
            percent_encode(&challenge),
            percent_encode(&state),
        );
        (self.opener)(&url)?;

        let (code, returned_state) = accept_loopback_code(&listener).await?;
        if returned_state != state {
            return Err(ClientError::Auth("loopback state mismatch".to_owned()));
        }
        let response: TokenResponse<Id> = self
            .post_json(
                &format!("{}/auth/token", self.server_base),
                &serde_json::json!({ "code": code, "code_verifier": verifier }),
            )
            .await?;
        // Keyed off the response, because a first login has no account to key on
        // and learns it here. The marker's value is the same encoding, so it is
        // literally the key of the record it points at.
        self.store.store(
            &encode_identity(&response.user_id)?,
            &response.refresh_token,
        )?;
        self.remember(&response.user_id)?;
        Ok(response.into())
    }

    /// Write which account this device signed in as, beside its credential.
    ///
    /// Both token paths call it, because either can be the one that establishes
    /// who this device is: a silent refresh on a start, or an interactive login
    /// on a first run or after the credential lapsed.
    fn remember<Id: serde::Serialize>(&self, user_id: &Id) -> Result<(), ClientError> {
        self.store
            .store(IDENTITY_RECORD, &encode_identity(user_id)?)
    }

    /// A silent-refresh [`AccessTokenSource`] for
    /// [`ConnettoConnection::with_token_source`](crate::ConnettoConnection::with_token_source).
    /// It only refreshes (never opens a browser), so a reconnect whose refresh
    /// token is gone surfaces an error rather than a surprise browser window.
    ///
    /// A resume needs only the access token, and the replica file was already
    /// selected from the identity at acquisition, so the response's `user_id`
    /// is discarded here rather than deserialized into a type this seam would
    /// otherwise have to name.
    #[must_use]
    pub fn token_source(self: &Arc<Self>) -> AccessTokenSource {
        let authenticator = Arc::clone(self);
        AccessTokenSource::new(move || {
            let authenticator = Arc::clone(&authenticator);
            async move {
                authenticator
                    .refresh_tokens::<serde::de::IgnoredAny>()
                    .await
                    .map(|session| session.access_token)
            }
        })
    }

    /// Credential teardown: revoke the session server-side and clear the stored
    /// refresh token, so re-authentication is required.
    ///
    /// This is one half of the logout grid. It touches no data: the replica and
    /// its key survive, which is what lets a returning user resume from their
    /// persisted cursor instead of re-syncing. For the other half see
    /// [`wipe_replica`](crate::teardown::wipe_replica), and for both under one
    /// guard see [`forget_device`](crate::teardown::forget_device).
    ///
    /// The revoke is awaited, and **the local clear happens either way**. A
    /// device with no connectivity must still be able to log out, so a failed
    /// revoke is reported rather than allowed to keep the credential on disk.
    /// The caller can therefore distinguish the two outcomes: `Ok` means the
    /// session is refused at the next handshake, and an error means local state
    /// is gone but the session stays live server-side until it expires on its
    /// own. Queueing the revoke for later is not an option, since after the
    /// clear there is no credential left to authenticate it with.
    ///
    /// Revocation is liveness, not expiry: any access token already minted stays
    /// signature-valid until its own short TTL runs out.
    ///
    /// Idempotent. With no refresh token stored there is nothing to revoke and
    /// nothing to clear, and it returns `Ok`.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] or [`ClientError::Auth`] if the revoke fails,
    /// after the local clear. [`ClientError::Auth`] if the store cannot be read
    /// or cleared.
    pub async fn logout(&self) -> Result<(), ClientError> {
        // Signing out is per account: any other stored credential survives, and
        // the marker is left naming an account with none, which the next start
        // answers with an interactive login rather than by picking somebody else.
        let Some(account) = self.account.as_deref() else {
            return Ok(());
        };
        let Some(refresh) = self.store.load(account)? else {
            return Ok(());
        };
        let revoked = self
            .post(
                &format!("{}/auth/logout", self.server_base),
                &serde_json::json!({ "refresh_token": refresh }),
            )
            .await;
        self.store.clear(account)?;
        revoked.map(drop)
    }

    async fn post_json<R: DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<R, ClientError> {
        let response = self.post(url, body).await?;
        // A decode failure on a success response is a protocol mismatch.
        response
            .json()
            .await
            .map_err(|err| ClientError::Protocol(format!("decoding {url}: {err}")))
    }

    /// POST `body` and classify the status, leaving the response body to the
    /// caller (the logout endpoint answers `204` with none at all).
    async fn post(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<reqwest::Response, ClientError> {
        // A send failure is a transport condition, retryable on reconnect, not a
        // rejected credential, so it must not route to a terminal re-login.
        let response = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|err| ClientError::Transport(format!("request to {url}: {err}")))?;
        let status = response.status();
        if !status.is_success() {
            // A 5xx is a transient server fault (retry). A 4xx is a genuine
            // credential failure (the refresh token is gone), which is terminal.
            return Err(if status.is_server_error() {
                ClientError::Transport(format!("{url} returned {status}"))
            } else {
                ClientError::Auth(format!("{url} returned {status}"))
            });
        }
        Ok(response)
    }
}

/// A 256-bit random token as URL-safe base64, for the PKCE verifier and the
/// CSRF state.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("platform RNG");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Accept one loopback connection, read the GET request, reply with a small
/// page, and return the `code` and `state` from its query.
async fn accept_loopback_code(listener: &TcpListener) -> Result<(String, String), ClientError> {
    let (mut stream, _) = listener
        .accept()
        .await
        .map_err(|err| ClientError::Auth(format!("loopback accept: {err}")))?;
    let mut buf = [0u8; 4096];
    let read = stream
        .read(&mut buf)
        .await
        .map_err(|err| ClientError::Auth(format!("loopback read: {err}")))?;
    let request = String::from_utf8_lossy(&buf[..read]);
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("");
    let query = target.split_once('?').map_or("", |(_, query)| query);

    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("code=") {
            code = Some(percent_decode(value));
        } else if let Some(value) = pair.strip_prefix("state=") {
            state = Some(percent_decode(value));
        }
    }

    let page =
        "<!doctype html><html><body>Login complete. You may close this window.</body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
        page.len(),
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;

    let code = code.ok_or_else(|| ClientError::Auth("loopback callback had no code".to_owned()))?;
    let state =
        state.ok_or_else(|| ClientError::Auth("loopback callback had no state".to_owned()))?;
    Ok((code, state))
}

#[cfg(test)]
mod tests {
    use connetto_core::ReplicaKey;

    use super::{MemoryKeyStore, indexed_with, indexed_without, provision_replica_key};
    use connetto_core::traits::ReplicaKeyStore as _;

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    /// R42: the native account index, which is the only thing that can answer
    /// what the OS keyring holds. `keyring` 3.6.3 exposes no enumeration on any
    /// backend, so a wrong answer here is a picker offering accounts that are not
    /// there or hiding ones that are.
    ///
    /// The integration twin against the real keyring is
    /// `the_keyring_refresh_store_lists_every_account_it_holds`, which a headless
    /// or locked session cannot run. This half needs no secure storage.
    #[test]
    fn the_account_index_records_each_account_once() {
        assert_eq!(
            indexed_with(&[], "\"alice\"").as_deref(),
            Some(names(&["\"alice\""]).as_slice()),
            "a first account enters the index"
        );
        assert_eq!(
            indexed_with(&names(&["\"alice\""]), "\"bob\"").as_deref(),
            Some(names(&["\"alice\"", "\"bob\""]).as_slice()),
            "and a second joins it rather than replacing it, which is the phase"
        );
        assert_eq!(
            indexed_with(&names(&["\"alice\""]), "\"alice\""),
            None,
            "a rotation re-stores the same account, and must not duplicate it"
        );
    }

    /// Connetto's own records share the key namespace with the accounts, so the
    /// marker must never reach the index. It is written on every single token
    /// acquisition, so getting this wrong offers it to every picker.
    #[test]
    fn the_account_index_refuses_connettos_own_records() {
        assert_eq!(
            indexed_with(&[], crate::IDENTITY_RECORD),
            None,
            "the last-used marker is not somebody to sign in as"
        );
        assert_eq!(
            indexed_with(&[], super::super::replica::ACCOUNTS_RECORD),
            None,
            "and neither is the index itself"
        );
    }

    /// Signing one account out leaves the others listed, which is what makes the
    /// remaining ones still signed in.
    #[test]
    fn the_account_index_drops_only_the_account_signed_out() {
        assert_eq!(
            indexed_without(&names(&["\"alice\"", "\"bob\""]), "\"alice\"").as_deref(),
            Some(names(&["\"bob\""]).as_slice()),
            "the other account stays signed in"
        );
        assert_eq!(
            indexed_without(&names(&["\"bob\""]), "\"alice\""),
            None,
            "clearing an account that was never there writes nothing"
        );
        assert_eq!(
            indexed_without(&names(&["\"bob\""]), crate::IDENTITY_RECORD),
            None,
            "and clearing the marker leaves the accounts alone"
        );
    }

    fn key_from_byte(b: u8) -> ReplicaKey {
        ReplicaKey::from_bytes([b; ReplicaKey::LEN])
    }

    /// Provision-once: a key already cached for this replica is handed straight
    /// back and nothing is minted. Without this a second login would silently
    /// re-key the replica and strand everything already written under the old
    /// key.
    #[tokio::test]
    async fn a_cached_key_wins_over_minting_a_fresh_one() {
        let store = MemoryKeyStore::default();
        store
            .store("replica-a", &key_from_byte(0xaa))
            .await
            .unwrap();

        let effective = provision_replica_key(&store, "replica-a")
            .await
            .expect("a cached key resolves");

        assert_eq!(effective, key_from_byte(0xaa));
        assert_eq!(
            store.load("replica-a").await.unwrap(),
            Some(key_from_byte(0xaa)),
            "provisioning must not overwrite the cache"
        );
    }

    /// First sight of a replica on a device: nothing is cached, so a key is
    /// minted locally and written through before it is handed back. Two
    /// different replicas mint independently, which is what makes the key per
    /// replica rather than per device.
    #[tokio::test]
    async fn a_key_is_minted_and_cached_when_nothing_is_stored() {
        let store = MemoryKeyStore::default();

        let minted = provision_replica_key(&store, "replica-a")
            .await
            .expect("a key is minted");
        assert_eq!(store.load("replica-a").await.unwrap(), Some(minted.clone()));
        assert_eq!(
            provision_replica_key(&store, "replica-a").await.unwrap(),
            minted,
            "the minted key is stable across calls"
        );

        let other = provision_replica_key(&store, "replica-b")
            .await
            .expect("a second key is minted");
        assert_ne!(other, minted, "each replica mints its own key");
    }

    /// The mint draws on the platform RNG rather than any fixed or derived
    /// value, so no two replicas and no two devices share a key.
    #[tokio::test]
    async fn a_minted_key_is_neither_constant_nor_derived_from_the_name() {
        let first = MemoryKeyStore::default();
        let second = MemoryKeyStore::default();

        let a = provision_replica_key(&first, "replica-a").await.unwrap();
        let b = provision_replica_key(&second, "replica-a").await.unwrap();

        assert_ne!(a, b, "the same name on two devices mints two keys");
        assert_ne!(
            a,
            key_from_byte(0),
            "an all-zero key would mean the fill never ran"
        );
    }

    /// Two identities signed in on one device keep separate keys, which is
    /// what makes the key per replica rather than per user. A single-slot
    /// store would collide here and hand one identity the other's key.
    #[tokio::test]
    async fn keys_are_isolated_per_replica_name() {
        let store = MemoryKeyStore::default();
        store
            .store("replica-a", &key_from_byte(0x11))
            .await
            .unwrap();
        store
            .store("replica-b", &key_from_byte(0x22))
            .await
            .unwrap();

        assert_eq!(
            store.load("replica-a").await.unwrap(),
            Some(key_from_byte(0x11))
        );
        assert_eq!(
            store.load("replica-b").await.unwrap(),
            Some(key_from_byte(0x22))
        );

        // Crypto-shredding one replica leaves the other readable.
        store.clear("replica-a").await.unwrap();
        assert_eq!(store.load("replica-a").await.unwrap(), None);
        assert_eq!(
            store.load("replica-b").await.unwrap(),
            Some(key_from_byte(0x22))
        );
    }
}
