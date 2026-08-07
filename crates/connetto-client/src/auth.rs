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
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use connetto_core::ReplicaKey;
use connetto_core::traits::{RefreshTokenStore, ReplicaKeyStore};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{AccessTokenSource, ClientError};

/// OS secure storage for the refresh token: Keychain on macOS, Credential
/// Manager on Windows, and the kernel keyutils keyring on Linux (daemon-free,
/// session-scoped by default).
///
/// One service holds one entry per account, exactly as [`KeyringKeyStore`]
/// holds one per replica record.
pub struct KeyringStore {
    service: String,
}

impl KeyringStore {
    /// Store refresh tokens under `service` in the OS keyring.
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// The keyring entry for `account`, or `None` when this platform's backend
    /// reports that no such entry exists.
    ///
    /// Some backends resolve the credential when the entry is constructed rather
    /// than when it is read, so "not stored yet" can surface here instead of from
    /// [`get_password`](keyring::Entry::get_password). Reporting that as an error
    /// would make a first run fatal, when it only means there is nothing to load.
    fn entry(&self, account: &str) -> Result<Option<keyring::Entry>, ClientError> {
        match keyring::Entry::new(&self.service, account) {
            Ok(entry) => Ok(Some(entry)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(ClientError::Auth(format!("keyring open: {err}"))),
        }
    }
}

impl RefreshTokenStore for KeyringStore {
    type Error = ClientError;

    fn load(&self, account: &str) -> Result<Option<String>, ClientError> {
        let Some(entry) = self.entry(account)? else {
            return Ok(None);
        };
        match entry.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(ClientError::Auth(format!("keyring load: {err}"))),
        }
    }

    fn store(&self, account: &str, token: &str) -> Result<(), ClientError> {
        // A backend that reports no entry before one is written still has to accept
        // the write, so this asks for the entry again rather than reusing `entry`.
        keyring::Entry::new(&self.service, account)
            .map_err(|err| ClientError::Auth(format!("keyring open: {err}")))?
            .set_password(token)
            .map_err(|err| ClientError::Auth(format!("keyring store: {err}")))
    }

    fn clear(&self, account: &str) -> Result<(), ClientError> {
        let Some(entry) = self.entry(account)? else {
            return Ok(());
        };
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(ClientError::Auth(format!("keyring clear: {err}"))),
        }
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
    service: String,
}

impl KeyringKeyStore {
    /// Store replica keys under `service` in the OS keyring.
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// The keyring entry for `name`, or `None` when this platform's backend
    /// reports that no such entry exists. See [`KeyringStore::entry`] for why a
    /// missing entry can surface here rather than from the read.
    fn entry(&self, name: &str) -> Result<Option<keyring::Entry>, ClientError> {
        match keyring::Entry::new(&self.service, name) {
            Ok(entry) => Ok(Some(entry)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(ClientError::Auth(format!("keyring open: {err}"))),
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
        let Some(entry) = self.entry(name)? else {
            return Ok(None);
        };
        match entry.get_password() {
            // The keyring hands back an owned hex string, which is key
            // material until it is wiped, hence the `Zeroizing` wrapper.
            Ok(hex) => Zeroizing::new(hex)
                .parse::<ReplicaKey>()
                .map(Some)
                .map_err(|err| ClientError::Auth(format!("keyring key parse: {err}"))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(ClientError::Auth(format!("keyring load: {err}"))),
        }
    }

    async fn store(&self, name: &str, key: &ReplicaKey) -> Result<(), ClientError> {
        let mut hex = Zeroizing::new(String::with_capacity(ReplicaKey::LEN * 2));
        for byte in key.as_bytes() {
            let _ = write!(&mut *hex, "{byte:02x}");
        }
        // A backend that reports no entry before one is written still has to accept
        // the write, so this asks for the entry again rather than reusing `entry`.
        keyring::Entry::new(&self.service, name)
            .map_err(|err| ClientError::Auth(format!("keyring open: {err}")))?
            .set_password(&hex)
            .map_err(|err| ClientError::Auth(format!("keyring store: {err}")))
    }

    async fn clear(&self, name: &str) -> Result<(), ClientError> {
        let Some(entry) = self.entry(name)? else {
            return Ok(());
        };
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(ClientError::Auth(format!("keyring clear: {err}"))),
        }
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
/// It holds the account whose record it reads and writes, rather than passing
/// one at each call, so every method addresses the same record by construction
/// and no two call sites can disagree about which credential this is.
pub struct NativeAuthenticator {
    server_base: String,
    provider: String,
    store: Arc<dyn RefreshTokenStore<Error = ClientError> + Send + Sync>,
    account: String,
    opener: BrowserOpener,
    http: reqwest::Client,
}

impl NativeAuthenticator {
    /// Build over connetto-server's auth base URL (for example
    /// `http://127.0.0.1:8081`), the provider name to log in with, a refresh
    /// token store, and the account naming this credential's record in it.
    /// Uses the system browser.
    #[must_use]
    pub fn new(
        server_base: impl Into<String>,
        provider: impl Into<String>,
        store: Arc<dyn RefreshTokenStore<Error = ClientError> + Send + Sync>,
        account: impl Into<String>,
    ) -> Self {
        Self {
            server_base: server_base.into(),
            provider: provider.into(),
            store,
            account: account.into(),
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
    pub async fn acquire<Id: DeserializeOwned>(&self) -> Result<AcquiredSession<Id>, ClientError> {
        if self.store.load(&self.account)?.is_some()
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
    pub async fn refresh_access<Id: DeserializeOwned>(
        &self,
    ) -> Result<AcquiredSession<Id>, ClientError> {
        let refresh = self
            .store
            .load(&self.account)?
            .ok_or_else(|| ClientError::Auth("no stored refresh token".to_owned()))?;
        let response: TokenResponse<Id> = self
            .post_json(
                &format!("{}/auth/refresh", self.server_base),
                &serde_json::json!({ "refresh_token": refresh }),
            )
            .await?;
        self.store.store(&self.account, &response.refresh_token)?;
        Ok(response.into())
    }

    /// Run the interactive loopback login: bind a `127.0.0.1` listener, open the
    /// system browser at connetto-server's login endpoint, catch the redirected
    /// code, exchange it with the PKCE verifier, and store the refresh token.
    ///
    /// # Errors
    ///
    /// [`ClientError::Auth`] on any loopback, browser, or exchange failure.
    pub async fn login<Id: DeserializeOwned>(&self) -> Result<AcquiredSession<Id>, ClientError> {
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
        self.store.store(&self.account, &response.refresh_token)?;
        Ok(response.into())
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
                    .refresh_access::<serde::de::IgnoredAny>()
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
        let Some(refresh) = self.store.load(&self.account)? else {
            return Ok(());
        };
        let revoked = self
            .post(
                &format!("{}/auth/logout", self.server_base),
                &serde_json::json!({ "refresh_token": refresh }),
            )
            .await;
        self.store.clear(&self.account)?;
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

/// A 256-bit random token as hex, for the PKCE verifier and the CSRF state.
fn random_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
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

/// Percent-encode the reserved set for a query-string value.
fn percent_encode(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

/// Decode a percent-encoded query value. Bytes we cannot decode pass through.
fn percent_decode(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let hi = bytes.next();
            let lo = bytes.next();
            if let (Some(hi), Some(lo)) = (hi, lo)
                && let (Some(hi), Some(lo)) =
                    (char::from(hi).to_digit(16), char::from(lo).to_digit(16))
            {
                // Both nibbles are in 0..16, so the byte fits.
                out.push(u8::try_from(hi * 16 + lo).expect("nibble byte fits u8"));
                continue;
            }
            out.push(b'%');
        } else {
            out.push(byte);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use connetto_core::ReplicaKey;

    use super::{MemoryKeyStore, provision_replica_key};
    use connetto_core::traits::ReplicaKeyStore as _;

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
