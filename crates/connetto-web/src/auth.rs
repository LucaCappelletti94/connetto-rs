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
use connetto_core::ReplicaKey;
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::{Connection, SqliteConnection};
use indexed_db_futures::database::Database as IdbDatabase;
use indexed_db_futures::prelude::*;
use indexed_db_futures::query_source::QuerySource;
use indexed_db_futures::transaction::TransactionMode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    BroadcastChannel, Headers, MessageEvent, Request, RequestInit, Response, WorkerGlobalScope,
};
use zeroize::Zeroize;

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
///
/// This database is **not** encrypted at rest, and the blocker is structural
/// rather than a matter of effort. It is read to learn the identity, while the
/// per-replica key that phase E2 applies everywhere else is addressed by
/// `replica_db_name`, which is derived from that identity. So the refresh store
/// must be readable strictly before any per-replica key can be resolved, and it
/// cannot be encrypted under one. Covering it needs a device-scoped key with its
/// own custody and its own lifetime, which is a second key concept the
/// at-rest-encryption plan has not settled: it locked exactly one key, per
/// replica. That decision belongs with the logout and key-lifecycle primitives.
///
/// The exposure this leaves is bounded by what the token is: a rotating
/// credential, revocable server-side, and useless once a logout revokes the
/// session. It is not the user's data, which is what E2 encrypts.
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
struct TokenResponse<Id> {
    access_token: String,
    refresh_token: String,
    user_id: Id,
    session_expires_at: u64,
    #[serde(default)]
    replica_key: Option<ReplicaKey>,
}

/// A completed acquisition: the access token the worker sets on its handshake,
/// plus the identity and session deadline the worker needs to select the
/// replica file this identity owns and to warn before an offline session
/// lapses with unsynced data.
#[derive(Debug, Clone)]
pub struct BrowserSession<Id> {
    /// connetto's short-lived access token, held only in the worker.
    pub access_token: String,
    /// The typed `user_id` this session belongs to. The worker names its
    /// replica file from it before opening any transport, so an account switch
    /// opens a different file rather than resuming the previous identity's.
    pub user_id: Id,
    /// Unix seconds when the local session lapses if never refreshed again.
    pub session_expires_at: u64,
    /// The effective per-replica encryption key for this identity on this
    /// device. Populated by [`ReplicaKeyStore`] logic in
    /// [`BrowserAuthenticator::complete`]: a cached key always wins over the
    /// wire value, so this is stable across logins and never reset by a
    /// later server response. `None` when no key has been provisioned yet.
    pub replica_key: Option<ReplicaKey>,
}

impl<Id> From<TokenResponse<Id>> for BrowserSession<Id> {
    fn from(response: TokenResponse<Id>) -> Self {
        Self {
            access_token: response.access_token,
            user_id: response.user_id,
            session_expires_at: response.session_expires_at,
            replica_key: response.replica_key,
        }
    }
}

/// `IndexedDB` database name for the key store.
const KEY_STORE_DB: &str = "connetto-key-store";
/// Object store holding the non-extractable KEK.
const STORE_KEK: &str = "kek";
/// Object store holding per-identity IV-plus-ciphertext records.
const STORE_WRAPPED: &str = "wrapped";
/// Fixed record key for the sole KEK entry.
const KEK_KEY: u32 = 1;
/// AES-GCM IV length in bytes. Used for slice operations.
const AES_GCM_IV_LEN: usize = 12;

/// Wraps and unwraps per-identity replica keys in `IndexedDB` using a
/// non-extractable AES-GCM-256 key-encryption key (KEK).
///
/// The KEK is generated once per browser profile, stored as a
/// structured-cloneable `CryptoKey` value in `IndexedDB`, and marked
/// non-extractable so its raw bytes cannot be read by script. Each replica
/// key is stored as a record keyed by the caller-supplied identity name,
/// containing a 12-byte random IV followed by the AES-GCM ciphertext.
///
/// This design defends against two specific threats: script-level
/// exfiltration of the raw key bytes (the KEK is non-extractable, so
/// reading the IDB store yields only opaque ciphertext), and an off-device
/// copy of the `IndexedDB` contents alone (without the KEK the ciphertext is
/// inert). It does not defend against a resident attacker who can call
/// `load` directly through this store, and it does not necessarily defend
/// against an attacker who has access to the full browser profile directory,
/// which includes both the IDB files and the backing storage for
/// non-extractable keys.
pub struct ReplicaKeyStore {
    db: IdbDatabase,
}

impl ReplicaKeyStore {
    /// Open (creating if needed) the key-store `IndexedDB` database.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the database cannot be opened.
    pub async fn open() -> Result<Self, AuthError> {
        let db = IdbDatabase::open(KEY_STORE_DB)
            .with_version(1u8)
            .with_on_upgrade_needed(|_event, db| {
                db.create_object_store(STORE_KEK).build()?;
                db.create_object_store(STORE_WRAPPED).build()?;
                Ok(())
            })
            .await
            .map_err(|e| AuthError::Store(format!("open key store: {e}")))?;
        Ok(Self { db })
    }

    /// Load the replica key for `name`, or `None` if no key has been saved.
    ///
    /// `name` is the caller-supplied record key, typically the value returned
    /// by `connetto_client::replica_db_name`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] on any IDB or `SubtleCrypto` failure.
    pub async fn load(&self, name: &str) -> Result<Option<ReplicaKey>, AuthError> {
        let Some(kek) = self.load_kek().await? else {
            return Ok(None);
        };
        let tx = self
            .db
            .transaction(STORE_WRAPPED)
            .build()
            .map_err(|e| AuthError::Store(format!("load tx: {e}")))?;
        let store = tx
            .object_store(STORE_WRAPPED)
            .map_err(|e| AuthError::Store(format!("load store: {e}")))?;
        let record: Option<JsValue> = store
            .get(name)
            .primitive()
            .map_err(|e| AuthError::Store(format!("load get: {e}")))?
            .await
            .map_err(|e| AuthError::Store(format!("load get await: {e}")))?;
        let Some(record) = record else {
            return Ok(None);
        };
        let buf = js_sys::Uint8Array::new(&record).to_vec();
        if buf.len() <= AES_GCM_IV_LEN {
            return Err(AuthError::Store("key record truncated".into()));
        }
        let (iv_bytes, ct_bytes) = buf.split_at(AES_GCM_IV_LEN);
        let iv = js_sys::Uint8Array::from(iv_bytes);
        let params = aes_gcm_params(&iv);
        let ct_buf = ct_bytes.to_vec();
        let plain_js = JsFuture::from(
            subtle()?
                .decrypt_with_object_and_u8_array(&params, &kek, &ct_buf)
                .map_err(|e| AuthError::Store(format!("decrypt: {e:?}")))?,
        )
        .await
        .map_err(|e| AuthError::Store(format!("decrypt await: {e:?}")))?;
        let plain = js_sys::Uint8Array::new(&plain_js).to_vec();
        if plain.len() != ReplicaKey::LEN {
            return Err(AuthError::Store("decrypted key has wrong length".into()));
        }
        let mut arr = [0u8; ReplicaKey::LEN];
        arr.copy_from_slice(&plain);
        Ok(Some(ReplicaKey::from_bytes(arr)))
    }

    /// Save `key` for `name`, overwriting any prior value.
    ///
    /// `name` is the caller-supplied record key, typically the value returned
    /// by `connetto_client::replica_db_name`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] on any IDB or `SubtleCrypto` failure.
    pub async fn save(&self, name: &str, key: &ReplicaKey) -> Result<(), AuthError> {
        let kek = self.get_or_create_kek().await?;
        let iv_bytes = random_iv();
        let iv = js_sys::Uint8Array::from(iv_bytes.as_ref());
        let params = aes_gcm_params(&iv);
        // Copy key bytes into a mutable buffer for the SubtleCrypto API.
        let mut key_buf = *key.as_bytes();
        let ct_js = JsFuture::from(
            subtle()?
                .encrypt_with_object_and_u8_array(&params, &kek, &key_buf)
                .map_err(|e| AuthError::Store(format!("encrypt: {e:?}")))?,
        )
        .await
        .map_err(|e| AuthError::Store(format!("encrypt await: {e:?}")))?;
        // The plaintext copy handed to WebCrypto is key material, so it does
        // not outlive the call. A plain fill would be elidable, zeroize is not.
        key_buf.zeroize();
        let ct = js_sys::Uint8Array::new(&ct_js);
        // Store IV (12 bytes) followed by ciphertext in one Uint8Array.
        let record = js_sys::Uint8Array::new_with_length(12u32 + ct.length());
        record.set(&iv, 0);
        record.set(&ct, 12u32);
        let tx = self
            .db
            .transaction(STORE_WRAPPED)
            .with_mode(TransactionMode::Readwrite)
            .build()
            .map_err(|e| AuthError::Store(format!("save tx: {e}")))?;
        let store = tx
            .object_store(STORE_WRAPPED)
            .map_err(|e| AuthError::Store(format!("save store: {e}")))?;
        let record_val: JsValue = record.into();
        store
            .put(record_val)
            .with_key(name)
            .primitive()
            .map_err(|e| AuthError::Store(format!("save put: {e}")))?
            .await
            .map_err(|e| AuthError::Store(format!("save put await: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| AuthError::Store(format!("save commit: {e}")))?;
        Ok(())
    }

    /// Remove the wrapped key for `name`.
    ///
    /// E3 calls this during a data-wipe cycle. It is a no-op when no record
    /// exists for `name`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] on any IDB failure.
    pub async fn clear(&self, name: &str) -> Result<(), AuthError> {
        let tx = self
            .db
            .transaction(STORE_WRAPPED)
            .with_mode(TransactionMode::Readwrite)
            .build()
            .map_err(|e| AuthError::Store(format!("clear tx: {e}")))?;
        let store = tx
            .object_store(STORE_WRAPPED)
            .map_err(|e| AuthError::Store(format!("clear store: {e}")))?;
        store
            .delete(name)
            .primitive()
            .map_err(|e| AuthError::Store(format!("clear delete: {e}")))?
            .await
            .map_err(|e| AuthError::Store(format!("clear delete await: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| AuthError::Store(format!("clear commit: {e}")))?;
        Ok(())
    }
    async fn load_kek(&self) -> Result<Option<web_sys::CryptoKey>, AuthError> {
        let tx = self
            .db
            .transaction(STORE_KEK)
            .build()
            .map_err(|e| AuthError::Store(format!("kek read tx: {e}")))?;
        let store = tx
            .object_store(STORE_KEK)
            .map_err(|e| AuthError::Store(format!("kek store: {e}")))?;
        let kek_js: Option<JsValue> = store
            .get(KEK_KEY)
            .primitive()
            .map_err(|e| AuthError::Store(format!("kek get: {e}")))?
            .await
            .map_err(|e| AuthError::Store(format!("kek get await: {e}")))?;
        Ok(kek_js.map(wasm_bindgen::JsCast::unchecked_into::<web_sys::CryptoKey>))
    }

    async fn get_or_create_kek(&self) -> Result<web_sys::CryptoKey, AuthError> {
        if let Some(kek) = self.load_kek().await? {
            return Ok(kek);
        }
        let params = aes_key_gen_params();
        let usages = js_sys::Array::new();
        usages.push(&JsValue::from_str("encrypt"));
        usages.push(&JsValue::from_str("decrypt"));
        // extractable = false: the KEK bytes can never be exported by script.
        let kek_js = JsFuture::from(
            subtle()?
                .generate_key_with_object(&params, false, &usages)
                .map_err(|e| AuthError::Store(format!("generate kek: {e:?}")))?,
        )
        .await
        .map_err(|e| AuthError::Store(format!("generate kek await: {e:?}")))?;
        let tx = self
            .db
            .transaction(STORE_KEK)
            .with_mode(TransactionMode::Readwrite)
            .build()
            .map_err(|e| AuthError::Store(format!("kek write tx: {e}")))?;
        let store = tx
            .object_store(STORE_KEK)
            .map_err(|e| AuthError::Store(format!("kek store: {e}")))?;
        store
            .put(kek_js.clone())
            .with_key(KEK_KEY)
            .primitive()
            .map_err(|e| AuthError::Store(format!("kek put: {e}")))?
            .await
            .map_err(|e| AuthError::Store(format!("kek put await: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| AuthError::Store(format!("kek commit: {e}")))?;
        Ok(kek_js.unchecked_into::<web_sys::CryptoKey>())
    }
}

/// The effective key for the replica `name`, given whatever the login response
/// carried in `wire`.
///
/// Provision-once, and the browser mirror of
/// `connetto_client::auth::resolve_replica_key`: a key already cached on this
/// device always wins and is never overwritten, so a re-login cannot silently
/// re-key a replica and strand its contents. Only when nothing is cached is a
/// freshly provisioned key adopted, and it is written through first.
///
/// Call this after acquisition, because `name` is derived from the identity
/// the token response resolves.
///
/// # Errors
///
/// [`AuthError::Store`] if the key store cannot be read or written.
pub async fn resolve_replica_key(
    store: &ReplicaKeyStore,
    name: &str,
    wire: Option<ReplicaKey>,
) -> Result<Option<ReplicaKey>, AuthError> {
    if let Some(cached) = store.load(name).await? {
        return Ok(Some(cached));
    }
    match wire {
        Some(fresh) => {
            store.save(name, &fresh).await?;
            Ok(Some(fresh))
        }
        None => Ok(None),
    }
}

/// The outcome of an acquisition attempt.
pub enum Acquired<Id> {
    /// A ready session (silent refresh succeeded).
    Access(BrowserSession<Id>),
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

    /// Try a silent refresh from the stored token, on failure or absence
    /// produce a [`PendingLogin`] for interactive login.
    ///
    /// The returned session's `replica_key` is the raw wire value, which a
    /// refresh never carries. Resolve the effective key afterwards with
    /// [`resolve_replica_key`], once the identity is known.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the refresh store cannot be read.
    pub async fn acquire<Id: serde::de::DeserializeOwned>(
        &self,
        store: &RefreshStore,
    ) -> Result<Acquired<Id>, AuthError> {
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
    /// code for tokens, and persist the refresh token.
    ///
    /// The returned session's `replica_key` is the raw wire value the server
    /// just provisioned. Resolve the effective key with
    /// [`resolve_replica_key`], which applies provision-once against the
    /// per-identity record.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a state mismatch, a failed exchange, or a store write.
    pub async fn complete<Id: serde::de::DeserializeOwned>(
        &self,
        pending: &PendingLogin,
        code: &str,
        state: &str,
        store: &RefreshStore,
    ) -> Result<BrowserSession<Id>, AuthError> {
        if state != pending.state {
            return Err(AuthError::StateMismatch);
        }
        let tokens = self.exchange_code(code, &pending.verifier).await?;
        store.save(&tokens.refresh_token)?;
        Ok(tokens.into())
    }

    async fn refresh_tokens<Id: serde::de::DeserializeOwned>(
        &self,
        refresh_token: &str,
    ) -> Result<TokenResponse<Id>, AuthError> {
        let body = serde_json::json!({ "refresh_token": refresh_token }).to_string();
        let text = post_json(
            &format!("{}/auth/refresh", self.config.auth_base_url),
            &body,
        )
        .await?;
        serde_json::from_str(&text).map_err(|_| AuthError::Decode)
    }

    async fn exchange_code<Id: serde::de::DeserializeOwned>(
        &self,
        code: &str,
        verifier: &str,
    ) -> Result<TokenResponse<Id>, AuthError> {
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

/// Return the `SubtleCrypto` interface from the current worker global scope.
fn subtle() -> Result<web_sys::SubtleCrypto, AuthError> {
    let scope: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let crypto = scope
        .crypto()
        .map_err(|e| AuthError::Context(format!("crypto: {e:?}")))?;
    Ok(crypto.subtle())
}

/// Build an `AES-GCM` algorithm parameter object with the given IV.
fn aes_gcm_params(iv: &js_sys::Uint8Array) -> js_sys::Object {
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &JsValue::from("name"), &JsValue::from("AES-GCM")).unwrap_throw();
    js_sys::Reflect::set(&obj, &JsValue::from("iv"), iv.as_ref()).unwrap_throw();
    obj
}

/// Build an `AES-GCM` key-generation parameter object requesting a 256-bit key.
fn aes_key_gen_params() -> js_sys::Object {
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &JsValue::from("name"), &JsValue::from("AES-GCM")).unwrap_throw();
    js_sys::Reflect::set(&obj, &JsValue::from("length"), &JsValue::from(256u32)).unwrap_throw();
    obj
}

/// Generate a fresh 12-byte random IV for AES-GCM.
fn random_iv() -> [u8; AES_GCM_IV_LEN] {
    let mut iv = [0u8; AES_GCM_IV_LEN];
    getrandom::getrandom(&mut iv).unwrap_throw();
    iv
}
