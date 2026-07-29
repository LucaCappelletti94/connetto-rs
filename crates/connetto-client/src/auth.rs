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
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{AccessTokenSource, ClientError};

/// Where a native client persists its rotating refresh token between runs.
pub trait RefreshTokenStore: Send + Sync {
    /// The stored refresh token, or `None` when none was stored.
    ///
    /// # Errors
    ///
    /// [`ClientError::Auth`] if the backing store cannot be read.
    fn load(&self) -> Result<Option<String>, ClientError>;

    /// Persist `token`, replacing any prior one.
    ///
    /// # Errors
    ///
    /// [`ClientError::Auth`] if the backing store cannot be written.
    fn store(&self, token: &str) -> Result<(), ClientError>;

    /// Remove the stored token, if any.
    ///
    /// # Errors
    ///
    /// [`ClientError::Auth`] if the backing store cannot be cleared.
    fn clear(&self) -> Result<(), ClientError>;
}

/// OS secure storage for the refresh token: Keychain on macOS, Credential
/// Manager on Windows, and the kernel keyutils keyring on Linux (daemon-free,
/// session-scoped by default).
pub struct KeyringStore {
    service: String,
    user: String,
}

impl KeyringStore {
    /// Store the refresh token under `service` and `user` in the OS keyring.
    #[must_use]
    pub fn new(service: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            user: user.into(),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, ClientError> {
        keyring::Entry::new(&self.service, &self.user)
            .map_err(|err| ClientError::Auth(format!("keyring open: {err}")))
    }
}

impl RefreshTokenStore for KeyringStore {
    fn load(&self) -> Result<Option<String>, ClientError> {
        match self.entry()?.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(ClientError::Auth(format!("keyring load: {err}"))),
        }
    }

    fn store(&self, token: &str) -> Result<(), ClientError> {
        self.entry()?
            .set_password(token)
            .map_err(|err| ClientError::Auth(format!("keyring store: {err}")))
    }

    fn clear(&self) -> Result<(), ClientError> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(ClientError::Auth(format!("keyring clear: {err}"))),
        }
    }
}

/// An in-memory refresh-token store, for tests and ephemeral sessions.
#[derive(Default)]
pub struct MemoryRefreshStore {
    inner: Mutex<Option<String>>,
}

impl RefreshTokenStore for MemoryRefreshStore {
    fn load(&self) -> Result<Option<String>, ClientError> {
        Ok(self.inner.lock().expect("refresh store lock").clone())
    }

    fn store(&self, token: &str) -> Result<(), ClientError> {
        *self.inner.lock().expect("refresh store lock") = Some(token.to_owned());
        Ok(())
    }

    fn clear(&self) -> Result<(), ClientError> {
        *self.inner.lock().expect("refresh store lock") = None;
        Ok(())
    }
}

/// Where a native client caches its per-replica encryption keys between runs.
///
/// Every method takes a `name`, the per-identity record this device holds for
/// one replica. Pass the same value
/// [`replica_db_name`](crate::replica::replica_db_name) produced for the
/// replica file, so two identities signed in on one device keep separate keys
/// and a wipe of one cannot reach the other.
///
/// A name is only knowable once login has resolved the identity, which is why
/// the store is not consulted during acquisition. Resolve afterwards with
/// [`resolve_replica_key`].
pub trait ReplicaKeyStore: Send + Sync {
    /// The cached key for `name`, or `None` when none was ever stored here.
    ///
    /// # Errors
    ///
    /// [`ClientError::Auth`] if the backing store cannot be read.
    fn load(&self, name: &str) -> Result<Option<ReplicaKey>, ClientError>;

    /// Persist `key` under `name`, replacing any prior value.
    ///
    /// # Errors
    ///
    /// [`ClientError::Auth`] if the backing store cannot be written.
    fn store(&self, name: &str, key: &ReplicaKey) -> Result<(), ClientError>;

    /// Remove the cached key for `name`, if any. This is the crypto-shred half
    /// of a data wipe: without the key the replica ciphertext is inert.
    ///
    /// # Errors
    ///
    /// [`ClientError::Auth`] if the backing store cannot be cleared.
    fn clear(&self, name: &str) -> Result<(), ClientError>;
}

/// The effective key for the replica `name`, given whatever the login response
/// carried in `wire`.
///
/// Provision-once in one function: a key already cached on this device always
/// wins and is never overwritten, so a re-login cannot silently re-key a
/// replica and strand its contents. Only when nothing is cached is a freshly
/// provisioned key adopted, and it is written through before it is returned.
///
/// # Errors
///
/// [`ClientError::Auth`] if the store cannot be read or written.
pub fn resolve_replica_key(
    store: &dyn ReplicaKeyStore,
    name: &str,
    wire: Option<ReplicaKey>,
) -> Result<Option<ReplicaKey>, ClientError> {
    if let Some(cached) = store.load(name)? {
        return Ok(Some(cached));
    }
    match wire {
        Some(fresh) => {
            store.store(name, &fresh)?;
            Ok(Some(fresh))
        }
        None => Ok(None),
    }
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

    fn entry(&self, name: &str) -> Result<keyring::Entry, ClientError> {
        keyring::Entry::new(&self.service, name)
            .map_err(|err| ClientError::Auth(format!("keyring open: {err}")))
    }
}

impl ReplicaKeyStore for KeyringKeyStore {
    fn load(&self, name: &str) -> Result<Option<ReplicaKey>, ClientError> {
        match self.entry(name)?.get_password() {
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

    fn store(&self, name: &str, key: &ReplicaKey) -> Result<(), ClientError> {
        let mut hex = Zeroizing::new(String::with_capacity(ReplicaKey::LEN * 2));
        for byte in key.as_bytes() {
            let _ = write!(&mut *hex, "{byte:02x}");
        }
        self.entry(name)?
            .set_password(&hex)
            .map_err(|err| ClientError::Auth(format!("keyring store: {err}")))
    }

    fn clear(&self, name: &str) -> Result<(), ClientError> {
        match self.entry(name)?.delete_credential() {
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

impl ReplicaKeyStore for MemoryKeyStore {
    fn load(&self, name: &str) -> Result<Option<ReplicaKey>, ClientError> {
        Ok(self
            .inner
            .lock()
            .expect("key store lock")
            .get(name)
            .cloned())
    }

    fn store(&self, name: &str, key: &ReplicaKey) -> Result<(), ClientError> {
        self.inner
            .lock()
            .expect("key store lock")
            .insert(name.to_owned(), key.clone());
        Ok(())
    }

    fn clear(&self, name: &str) -> Result<(), ClientError> {
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
    #[serde(default)]
    replica_key: Option<ReplicaKey>,
}

/// The outcome of an acquisition: the access token for the handshake plus the
/// identity and session deadline the client needs to select its replica file
/// and to warn before an offline session lapses with unsynced data.
#[derive(Debug, Clone)]
pub struct AcquiredSession<Id> {
    /// connetto's short-lived access token, carried in `Handshake.auth_token`.
    pub access_token: String,
    /// The typed `user_id` this session belongs to. It selects the replica
    /// file through
    /// [`replica_db_name`](crate::replica::replica_db_name), so a
    /// re-authentication that resolves to a different identity opens a
    /// different file instead of resuming onto this one's data.
    pub user_id: Id,
    /// When the local session lapses if never refreshed again.
    pub session_expires_at: SystemTime,
    /// The freshly provisioned per-replica encryption key, exactly as the
    /// login response carried it. `Some` on a login, `None` on a refresh.
    ///
    /// This is the raw wire value, not the key to use. The identity is only
    /// known once this response arrives, and the key store is addressed per
    /// identity, so pass this to
    /// [`resolve_replica_key`] together with the replica name derived from
    /// [`user_id`](Self::user_id) to get the effective key. A device that
    /// already cached a key keeps it and discards this one.
    pub replica_key: Option<ReplicaKey>,
}

impl<Id> From<TokenResponse<Id>> for AcquiredSession<Id> {
    fn from(response: TokenResponse<Id>) -> Self {
        Self {
            access_token: response.access_token,
            user_id: response.user_id,
            session_expires_at: UNIX_EPOCH + Duration::from_secs(response.session_expires_at),
            replica_key: response.replica_key,
        }
    }
}

/// Acquires and refreshes connetto's own tokens for a native client, driving the
/// loopback Authorization Code plus PKCE flow against connetto-server.
pub struct NativeAuthenticator {
    server_base: String,
    provider: String,
    store: Arc<dyn RefreshTokenStore>,
    opener: BrowserOpener,
    http: reqwest::Client,
}

impl NativeAuthenticator {
    /// Build over connetto-server's auth base URL (for example
    /// `http://127.0.0.1:8081`), the provider name to log in with, and a refresh
    /// token store. Uses the system browser.
    #[must_use]
    pub fn new(
        server_base: impl Into<String>,
        provider: impl Into<String>,
        store: Arc<dyn RefreshTokenStore>,
    ) -> Self {
        Self {
            server_base: server_base.into(),
            provider: provider.into(),
            store,
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
        if self.store.load()?.is_some()
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
            .load()?
            .ok_or_else(|| ClientError::Auth("no stored refresh token".to_owned()))?;
        let response: TokenResponse<Id> = self
            .post_json(
                &format!("{}/auth/refresh", self.server_base),
                &serde_json::json!({ "refresh_token": refresh }),
            )
            .await?;
        self.store.store(&response.refresh_token)?;
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
        self.store.store(&response.refresh_token)?;
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

    async fn post_json<R: DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<R, ClientError> {
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
        // A decode failure on a success response is a protocol mismatch.
        response
            .json()
            .await
            .map_err(|err| ClientError::Protocol(format!("decoding {url}: {err}")))
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

    use super::{MemoryKeyStore, ReplicaKeyStore as _, resolve_replica_key};

    fn key_from_byte(b: u8) -> ReplicaKey {
        ReplicaKey::from_bytes([b; ReplicaKey::LEN])
    }

    /// Provision-once: a key already cached for this replica wins over
    /// whatever a later login response carries, and the cache is left alone.
    /// Without this a re-login would silently re-key the replica and strand
    /// everything already written under the old key.
    #[test]
    fn a_cached_key_wins_over_a_freshly_provisioned_one() {
        let store = MemoryKeyStore::default();
        store.store("replica-a", &key_from_byte(0xaa)).unwrap();

        let effective = resolve_replica_key(&store, "replica-a", Some(key_from_byte(0xbb)))
            .unwrap()
            .expect("a cached key resolves");

        assert_eq!(effective, key_from_byte(0xaa));
        assert_eq!(
            store.load("replica-a").unwrap(),
            Some(key_from_byte(0xaa)),
            "the wire key must not overwrite the cache"
        );
    }

    /// First login on a device: nothing is cached, so the provisioned key is
    /// adopted and written through before it is handed back.
    #[test]
    fn a_provisioned_key_is_cached_when_nothing_is_stored() {
        let store = MemoryKeyStore::default();

        let effective = resolve_replica_key(&store, "replica-a", Some(key_from_byte(0xcc)))
            .unwrap()
            .expect("the wire key resolves");

        assert_eq!(effective, key_from_byte(0xcc));
        assert_eq!(store.load("replica-a").unwrap(), Some(key_from_byte(0xcc)));
    }

    /// A refresh response carries no key, and with nothing cached there is
    /// nothing to resolve. Notably this must not invent or persist a key.
    #[test]
    fn no_cached_and_no_wire_key_resolves_to_nothing() {
        let store = MemoryKeyStore::default();
        assert_eq!(
            resolve_replica_key(&store, "replica-a", None).unwrap(),
            None
        );
        assert_eq!(store.load("replica-a").unwrap(), None);
    }

    /// Two identities signed in on one device keep separate keys, which is
    /// what makes the key per replica rather than per user. A single-slot
    /// store would collide here and hand one identity the other's key.
    #[test]
    fn keys_are_isolated_per_replica_name() {
        let store = MemoryKeyStore::default();
        store.store("replica-a", &key_from_byte(0x11)).unwrap();
        store.store("replica-b", &key_from_byte(0x22)).unwrap();

        assert_eq!(store.load("replica-a").unwrap(), Some(key_from_byte(0x11)));
        assert_eq!(store.load("replica-b").unwrap(), Some(key_from_byte(0x22)));

        // Crypto-shredding one replica leaves the other readable.
        store.clear("replica-a").unwrap();
        assert_eq!(store.load("replica-a").unwrap(), None);
        assert_eq!(store.load("replica-b").unwrap(), Some(key_from_byte(0x22)));
    }
}
