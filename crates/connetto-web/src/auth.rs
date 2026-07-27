//! Browser OAuth acquisition, worker-side.
//!
//! connetto-server is the OAuth client (Backend-For-Frontend). In the browser
//! the dedicated DB worker owns the single server connection and the only OPFS
//! access, but a worker cannot navigate, so interactive login happens in a tab.
//! The worker holds connetto's tokens and the tab never does: the worker mints
//! the PKCE verifier, hands the tab only a login URL, and the tab hands back
//! only the authorization code. The worker exchanges the code for tokens, keeps
//! the access token in memory, and persists the refresh token worker-only in
//! OPFS so a cold start or a leader failover silently refreshes and resumes.
//! See `docs/architecture/11-authentication.md`.
//!
//! The enforced invariant: [`LoginMessage`] has no variant that carries a token,
//! so nothing the worker broadcasts on the login channel can leak one to a tab.

use std::cell::RefCell;
use std::rc::Rc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::{Connection, SqliteConnection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    BroadcastChannel, Headers, MessageEvent, Request, RequestInit, Response, WorkerGlobalScope,
};

/// The `BroadcastChannel` the worker and tabs use to coordinate interactive
/// login. It carries only [`LoginMessage`], which cannot hold a token.
pub const LOGIN_CHANNEL: &str = "connetto-login";

/// Failure of a browser acquisition step.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The refresh-token store could not be opened, read, or written.
    #[error("refresh store: {0}")]
    Store(String),
    /// A `fetch` to connetto-server failed or returned a non-success status.
    #[error("auth request failed: {0}")]
    Request(String),
    /// A transient `fetch` failure or a 5xx from connetto-server, retryable
    /// rather than a rejected credential.
    #[error("auth request transient failure: {0}")]
    Transient(String),
    /// The endpoint response could not be decoded.
    #[error("auth response decode failed")]
    Decode,
    /// The login callback state did not match the one the worker issued.
    #[error("login state mismatch")]
    StateMismatch,
    /// The interactive login was abandoned before a code arrived.
    #[error("login cancelled")]
    Cancelled,
    /// A browser API was unavailable in this context.
    #[error("browser context error: {0}")]
    Context(String),
}

fn js_error(context: &str, value: &JsValue) -> AuthError {
    AuthError::Request(format!("{context}: {value:?}"))
}

/// Worker-side confidential-client configuration for the browser flow.
#[derive(Debug, Clone)]
pub struct WorkerAuthConfig {
    /// connetto-server's auth base URL, for example `https://app.example/auth`
    /// stripped of the trailing `/auth`, i.e. the origin the endpoints hang off
    /// (`{base}/auth/login`, `{base}/auth/token`, `{base}/auth/refresh`).
    pub auth_base_url: String,
    /// The provider name to log in with.
    pub provider: String,
    /// The app page the login redirect returns to, which posts the code back to
    /// the worker with [`deliver_login_code`].
    pub redirect_uri: String,
}

/// The rotating refresh token, persisted worker-only in an OPFS-backed SQLite
/// database so a cold start or leader failover can silently refresh. When OPFS
/// is unavailable the same code runs against the in-memory VFS, so the session
/// works but does not survive a worker restart.
pub struct RefreshStore {
    conn: RefCell<SqliteConnection>,
}

diesel::table! {
    connetto_refresh (id) {
        id -> diesel::sql_types::Integer,
        token -> diesel::sql_types::Text,
    }
}

impl RefreshStore {
    /// Open (creating if needed) the refresh store in `db_name`, which resolves
    /// through whichever VFS the worker installed.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the database cannot be opened or initialized.
    pub fn open(db_name: &str) -> Result<Self, AuthError> {
        let mut conn = SqliteConnection::establish(db_name)
            .map_err(|err| AuthError::Store(format!("open {db_name}: {err}")))?;
        conn.batch_execute(
            "CREATE TABLE IF NOT EXISTS connetto_refresh (id INTEGER PRIMARY KEY, token TEXT NOT NULL)",
        )
        .map_err(|err| AuthError::Store(format!("init: {err}")))?;
        Ok(Self {
            conn: RefCell::new(conn),
        })
    }

    /// The stored refresh token, or `None`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the read fails.
    pub fn load(&self) -> Result<Option<String>, AuthError> {
        connetto_refresh::table
            .filter(connetto_refresh::id.eq(1))
            .select(connetto_refresh::token)
            .first::<String>(&mut *self.conn.borrow_mut())
            .optional()
            .map_err(|err| AuthError::Store(format!("load: {err}")))
    }

    /// Persist `token`, replacing any prior one.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the write fails.
    pub fn save(&self, token: &str) -> Result<(), AuthError> {
        diesel::insert_into(connetto_refresh::table)
            .values((
                connetto_refresh::id.eq(1),
                connetto_refresh::token.eq(token),
            ))
            .on_conflict(connetto_refresh::id)
            .do_update()
            .set(connetto_refresh::token.eq(token))
            .execute(&mut *self.conn.borrow_mut())
            .map_err(|err| AuthError::Store(format!("save: {err}")))?;
        Ok(())
    }

    /// Remove the stored token, if any.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the delete fails.
    pub fn clear(&self) -> Result<(), AuthError> {
        diesel::delete(connetto_refresh::table)
            .execute(&mut *self.conn.borrow_mut())
            .map_err(|err| AuthError::Store(format!("clear: {err}")))?;
        Ok(())
    }
}

/// A login message on [`LOGIN_CHANNEL`]. Deliberately tokenless: the worker
/// sends [`LoginMessage::Request`] with only a URL, and a tab replies with
/// [`LoginMessage::Code`] carrying only the authorization code and state. No
/// variant can carry an access or refresh token, so the worker's token custody
/// is a real boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LoginMessage {
    /// Worker to tabs: navigate to this login URL.
    Request {
        /// The login URL (carries the PKCE challenge and state, never a token).
        url: String,
    },
    /// Tab to worker: the authorization code and state from the callback.
    Code {
        /// The one-time connetto authorization code.
        code: String,
        /// The CSRF state echoed by the callback.
        state: String,
    },
}

/// The tokens plus session metadata connetto-server returns from its token and
/// refresh endpoints.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    user_id: String,
    session_expires_at: u64,
}

/// A completed acquisition: the access token the worker sets on its handshake,
/// plus the identity and session deadline the worker needs to enforce identity
/// continuity (a re-auth to a different `user_id` is an account switch) and to
/// warn before an offline session lapses with unsynced data.
#[derive(Debug, Clone)]
pub struct BrowserSession {
    /// connetto's short-lived access token, held only in the worker.
    pub access_token: String,
    /// The `user_id` this session belongs to, bound onto the worker replica.
    pub user_id: String,
    /// Unix seconds when the local session lapses if never refreshed again.
    pub session_expires_at: u64,
}

impl From<TokenResponse> for BrowserSession {
    fn from(response: TokenResponse) -> Self {
        Self {
            access_token: response.access_token,
            user_id: response.user_id,
            session_expires_at: response.session_expires_at,
        }
    }
}

/// The outcome of an acquisition attempt.
pub enum Acquired {
    /// A ready session (silent refresh succeeded).
    Access(BrowserSession),
    /// Interactive login is required. Drive it with
    /// [`await_login_code`] then [`BrowserAuthenticator::complete`].
    NeedLogin(PendingLogin),
}

/// An in-flight interactive login: the URL to send a tab to, plus the secrets
/// the worker keeps to complete the exchange.
pub struct PendingLogin {
    /// The login URL to broadcast to a tab.
    pub login_url: String,
    verifier: String,
    state: String,
}

/// Acquires and refreshes connetto's own tokens in the worker.
pub struct BrowserAuthenticator {
    config: WorkerAuthConfig,
}

impl BrowserAuthenticator {
    /// Build over the worker auth configuration.
    #[must_use]
    pub fn new(config: WorkerAuthConfig) -> Self {
        Self { config }
    }

    /// Try a silent refresh from the stored token; on failure or absence,
    /// produce a [`PendingLogin`] for interactive login.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the store cannot be read.
    pub async fn acquire(&self, store: &RefreshStore) -> Result<Acquired, AuthError> {
        if let Some(refresh) = store.load()? {
            match self.refresh_tokens(&refresh).await {
                Ok(tokens) => {
                    store.save(&tokens.refresh_token)?;
                    return Ok(Acquired::Access(tokens.into()));
                }
                // A transient refresh fault must not force an interactive login:
                // propagate it so the worker boot can retry silently.
                Err(err @ AuthError::Transient(_)) => return Err(err),
                // A rejected or expired refresh token falls through to login.
                Err(_) => {}
            }
        }
        let verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let state = random_token();
        let login_url = format!(
            "{}/auth/login?provider={}&redirect_uri={}&code_challenge={}&state={}",
            self.config.auth_base_url,
            percent_encode(&self.config.provider),
            percent_encode(&self.config.redirect_uri),
            percent_encode(&challenge),
            percent_encode(&state),
        );
        Ok(Acquired::NeedLogin(PendingLogin {
            login_url,
            verifier,
            state,
        }))
    }

    /// Complete an interactive login: verify the returned state, exchange the
    /// code for tokens, persist the refresh token, and return the access token.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a state mismatch, a failed exchange, or a store write.
    pub async fn complete(
        &self,
        pending: &PendingLogin,
        code: &str,
        state: &str,
        store: &RefreshStore,
    ) -> Result<BrowserSession, AuthError> {
        if state != pending.state {
            return Err(AuthError::StateMismatch);
        }
        let tokens = self.exchange_code(code, &pending.verifier).await?;
        store.save(&tokens.refresh_token)?;
        Ok(tokens.into())
    }

    async fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenResponse, AuthError> {
        let body = serde_json::json!({ "refresh_token": refresh_token }).to_string();
        let text = post_json(
            &format!("{}/auth/refresh", self.config.auth_base_url),
            &body,
        )
        .await?;
        serde_json::from_str(&text).map_err(|_| AuthError::Decode)
    }

    async fn exchange_code(&self, code: &str, verifier: &str) -> Result<TokenResponse, AuthError> {
        let body = serde_json::json!({ "code": code, "code_verifier": verifier }).to_string();
        let text = post_json(&format!("{}/auth/token", self.config.auth_base_url), &body).await?;
        serde_json::from_str(&text).map_err(|_| AuthError::Decode)
    }
}

/// Worker-side: broadcast the login request to tabs and resolve once one posts
/// the authorization code back.
///
/// # Errors
///
/// [`AuthError`] if the channel cannot be opened or the login is cancelled.
pub async fn await_login_code(login_url: &str) -> Result<(String, String), AuthError> {
    let channel = BroadcastChannel::new(LOGIN_CHANNEL)
        .map_err(|err| AuthError::Context(format!("login channel: {err:?}")))?;
    let (sender, receiver) = futures_channel::oneshot::channel::<(String, String)>();
    let sender = Rc::new(RefCell::new(Some(sender)));
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new({
        let sender = Rc::clone(&sender);
        move |event: MessageEvent| {
            let Some(text) = event.data().as_string() else {
                return;
            };
            if let Ok(LoginMessage::Code { code, state }) = serde_json::from_str(&text)
                && let Some(sender) = sender.borrow_mut().take()
            {
                let _ = sender.send((code, state));
            }
        }
    });
    channel.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    let request = serde_json::to_string(&LoginMessage::Request {
        url: login_url.to_owned(),
    })
    .map_err(|_| AuthError::Decode)?;
    channel
        .post_message(&JsValue::from_str(&request))
        .map_err(|err| js_error("broadcast login request", &err))?;

    let outcome = receiver.await.map_err(|_| AuthError::Cancelled);
    channel.set_onmessage(None);
    channel.close();
    drop(on_message);
    outcome
}

/// Page-side: post the authorization code and state from the login callback
/// back to the worker. A callback route calls this after reading `?code` and
/// `?state` from its URL.
///
/// # Errors
///
/// The `BroadcastChannel` error if the channel cannot be opened or posted to.
pub fn deliver_login_code(code: &str, state: &str) -> Result<(), JsValue> {
    let channel = BroadcastChannel::new(LOGIN_CHANNEL)?;
    let message = serde_json::to_string(&LoginMessage::Code {
        code: code.to_owned(),
        state: state.to_owned(),
    })
    .map_err(|err| JsValue::from_str(&err.to_string()))?;
    channel.post_message(&JsValue::from_str(&message))?;
    channel.close();
    Ok(())
}

/// A 256-bit random token as URL-safe base64, for the PKCE verifier and state.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("platform RNG");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// POST `body` as JSON to `url` from the worker and return the response body.
async fn post_json(url: &str, body: &str) -> Result<String, AuthError> {
    let options = RequestInit::new();
    options.set_method("POST");
    options.set_body(&JsValue::from_str(body));
    let headers = Headers::new().map_err(|err| AuthError::Context(format!("headers: {err:?}")))?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|err| AuthError::Context(format!("header set: {err:?}")))?;
    options.set_headers(headers.as_ref());
    let request = Request::new_with_str_and_init(url, &options)
        .map_err(|err| js_error("build request", &err))?;

    let global: WorkerGlobalScope = js_sys::global()
        .dyn_into()
        .map_err(|_| AuthError::Context("not a worker global scope".to_owned()))?;
    let response_value = JsFuture::from(global.fetch_with_request(&request))
        .await
        .map_err(|err| AuthError::Transient(format!("fetch {url}: {err:?}")))?;
    let response: Response = response_value
        .dyn_into()
        .map_err(|err| js_error("response cast", &err))?;
    if !response.ok() {
        let status = response.status();
        return Err(if (500..600).contains(&status) {
            AuthError::Transient(format!("{url} returned {status}"))
        } else {
            AuthError::Request(format!("{url} returned {status}"))
        });
    }
    let text_promise = response
        .text()
        .map_err(|err| js_error("response text", &err))?;
    let text_value = JsFuture::from(text_promise)
        .await
        .map_err(|err| js_error("read body", &err))?;
    text_value.as_string().ok_or(AuthError::Decode)
}

/// Percent-encode the reserved set for a query-string value.
fn percent_encode(value: &str) -> String {
    use core::fmt::Write as _;
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
