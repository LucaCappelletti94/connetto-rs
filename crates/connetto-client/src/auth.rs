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

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

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
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    user_id: String,
    session_expires_at: u64,
}

/// The outcome of an acquisition: the access token for the handshake plus the
/// identity and session deadline the client needs to enforce identity
/// continuity and to warn before an offline session lapses with unsynced data.
#[derive(Debug, Clone)]
pub struct AcquiredSession {
    /// connetto's short-lived access token, carried in `Handshake.auth_token`.
    pub access_token: String,
    /// The `user_id` this session belongs to, for
    /// [`bind_identity`](crate::ConnettoConnection::bind_identity).
    pub user_id: String,
    /// When the local session lapses if never refreshed again.
    pub session_expires_at: SystemTime,
}

impl From<TokenResponse> for AcquiredSession {
    fn from(response: TokenResponse) -> Self {
        Self {
            access_token: response.access_token,
            user_id: response.user_id,
            session_expires_at: UNIX_EPOCH + Duration::from_secs(response.session_expires_at),
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
    /// # Errors
    ///
    /// [`ClientError::Auth`] if both refresh and login fail.
    pub async fn acquire(&self) -> Result<AcquiredSession, ClientError> {
        if self.store.load()?.is_some()
            && let Ok(session) = self.refresh_access().await
        {
            return Ok(session);
        }
        self.login().await
    }

    /// Silently refresh the access token from the stored refresh token, rotating
    /// and re-storing it. Never opens a browser.
    ///
    /// # Errors
    ///
    /// [`ClientError::Auth`] if no refresh token is stored or the refresh fails.
    pub async fn refresh_access(&self) -> Result<AcquiredSession, ClientError> {
        let refresh = self
            .store
            .load()?
            .ok_or_else(|| ClientError::Auth("no stored refresh token".to_owned()))?;
        let response: TokenResponse = self
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
    pub async fn login(&self) -> Result<AcquiredSession, ClientError> {
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
        let response: TokenResponse = self
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
    #[must_use]
    pub fn token_source(self: &Arc<Self>) -> AccessTokenSource {
        let authenticator = Arc::clone(self);
        AccessTokenSource::new(move || {
            let authenticator = Arc::clone(&authenticator);
            async move { authenticator.refresh_access().await.map(|s| s.access_token) }
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
