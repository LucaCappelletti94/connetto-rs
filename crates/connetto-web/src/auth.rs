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
use connetto_core::percent::percent_encode;
use connetto_core::traits::{RefreshTokenStore, ReplicaKeyStore};
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

/// The `BroadcastChannel` a tab uses to ask the worker to log out, and to ask
/// how much local work is still unsynced before offering to destroy it. It
/// carries only [`LogoutMessage`], which cannot hold a token either.
///
/// The worker owns the refresh token, the replica, and its key, so a tab cannot
/// log out by itself. What a tab owns is the button and the wording, which is
/// why the destructive choice travels as a request rather than as an action.
pub const LOGOUT_CHANNEL: &str = "connetto-logout";

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
    /// An existing database did not decrypt under the key supplied. A wrong key
    /// and a corrupt file are indistinguishable to the page codec.
    #[error("the database does not decrypt under the key supplied: {0}")]
    Undecryptable(String),
    /// A key operation was refused because a credential is enrolled but no
    /// derived key-encryption key is held, or because this build cannot reach
    /// the one that would unlock it. The detail names which.
    ///
    /// The message always begins with [`LOCKED_MESSAGE`], so a caller can
    /// recognise the refusal without parsing the rest.
    #[error("{LOCKED_MESSAGE}: {detail}")]
    Locked {
        /// Which of the two refusals this is.
        detail: String,
    },
}

/// The error string a JS caller receives when the key store is locked.
///
/// The refusal message always starts with this, so a caller recognises it by
/// prefix and the detail after it stays free to change.
pub const LOCKED_MESSAGE: &str = "connetto-locked";

/// Fixed PRF extension input for the at-rest key. Never per-identity, because
/// the refresh store opens before any identity is known.
pub const AT_REST_PRF_INPUT: &[u8] = b"connetto/at-rest/v1";

/// HKDF label for the key-encryption key derived from the PRF output.
pub const AT_REST_KEK_LABEL: &[u8] = b"connetto kek v1";

fn js_error(context: &str, value: &JsValue) -> AuthError {
    AuthError::Request(format!("{context}: {value:?}"))
}

/// Worker-side confidential-client configuration for the browser flow.
#[derive(Debug, Clone)]
pub struct WorkerAuthConfig {
    /// The origin the worker's `fetch` calls go to, for `{base}/auth/token`,
    /// `{base}/auth/refresh`, and `{base}/auth/logout`. These carry no CORS
    /// headers from connetto, so this is the application's own origin whenever the
    /// deployment puts the auth endpoints behind its own reverse proxy.
    auth_base_url: String,
    /// The origin the login navigation goes to, when it is not
    /// [`auth_base_url`](Self::auth_base_url).
    ///
    /// A login is a navigation the browser follows, so it needs no CORS and only
    /// needs an origin that actually serves the auth router. That is usually the
    /// same one, and `None` means exactly that. It differs when the application is
    /// served by a dev server whose proxy does not forward navigations, in which
    /// case the navigation goes straight to the auth origin while the `fetch` calls
    /// keep going through the proxy.
    login_base_url: Option<String>,
    /// The provider name to log in with.
    provider: String,
    /// The app page the login redirect returns to, which posts the code back to
    /// the worker with [`deliver_login_code`].
    redirect_uri: String,
}

impl WorkerAuthConfig {
    /// Builds with the given auth origin, provider name, and callback URI.
    #[must_use]
    pub fn new(
        auth_base_url: impl Into<String>,
        provider: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            auth_base_url: auth_base_url.into(),
            login_base_url: None,
            provider: provider.into(),
            redirect_uri: redirect_uri.into(),
        }
    }

    /// The origin the login navigation goes to, when it is not the auth origin.
    ///
    /// A login is a navigation the browser follows, so it needs no CORS and only
    /// needs an origin that actually serves the auth router. That is usually the
    /// same one, and `None` means exactly that. It differs when the application is
    /// served by a dev server whose proxy does not forward navigations, in which
    /// case the navigation goes straight to the auth origin while the `fetch` calls
    /// keep going through the proxy.
    #[must_use]
    pub fn with_login_base_url(mut self, login_base_url: Option<String>) -> Self {
        self.login_base_url = login_base_url;
        self
    }
}

/// The rotating refresh token, persisted worker-only in an OPFS-backed SQLite
/// database so a cold start or leader failover can silently refresh. When OPFS
/// is unavailable the same code runs against the in-memory VFS, so the session
/// works but does not survive a worker restart.
///
/// Encrypted at rest under [`device_key`](crate::storage::device_key) rather than
/// under a per-replica key, and the distinction is structural. This store is read
/// to learn the identity, while a per-replica key is addressed by
/// `replica_db_name`, which is derived from that identity, so the store must be
/// readable strictly before any per-replica key exists. A device-scoped key has
/// no such ordering problem: it is named by a literal, minted locally on first
/// use, and wrapped in the same non-extractable [`IdbKeyStore`] the replica
/// keys live in.
///
/// What that protects is bounded by what the token is: a rotating credential,
/// revocable server-side, and useless once a logout revokes the session. The
/// user's data is the replica's business, not this store's.
pub struct RefreshStore {
    conn: RefCell<SqliteConnection>,
}

diesel::table! {
    /// Encrypted refresh token storage, one row per account
    connetto_refresh (account) {
        /// The account this record belongs to, which every call addresses
        account -> diesel::sql_types::Text,
        /// Encrypted refresh token value
        token -> diesel::sql_types::Text,
    }
}

impl RefreshStore {
    /// Open (creating if needed) the refresh store at `db_url`, encrypted under
    /// `key`.
    ///
    /// `db_url` is the codec URL
    /// [`ReplicaStorage::db_url`](crate::storage::ReplicaStorage::db_url)
    /// composes over the installed VFS, because the codec intercepts as a VFS
    /// shim and a bare name would leave it out of the stack. `key` is
    /// [`device_key`](crate::storage::device_key), not a per-replica key: this
    /// store is read before any identity is known, so nothing addressed by an
    /// identity can protect it.
    ///
    /// Opening is the only asymmetry with the native store, and it is why the
    /// trait covers the three accessors and not construction: the key this needs
    /// comes from the key store, so a browser refresh store is reached through an
    /// await while a keyring entry is not.
    ///
    /// # Errors
    ///
    /// [`AuthError::Undecryptable`] if a store already exists and `key` does not
    /// open it, or [`AuthError::Store`] if the database cannot be opened or
    /// initialized.
    pub fn open(db_url: &str, key: &ReplicaKey) -> Result<Self, AuthError> {
        let mut conn = SqliteConnection::establish(db_url)
            .map_err(|err| AuthError::Store(format!("open {db_url}: {err}")))?;
        // Before any statement that reads a page: the CREATE TABLE below would
        // otherwise read the header and fail on ciphertext.
        connetto_client::cipher::unlock(&mut conn, key).map_err(|err| match err {
            connetto_client::UnlockError::WrongKey(detail) => {
                AuthError::Undecryptable(detail.to_string())
            }
            other => AuthError::Store(format!("unlock the refresh store: {other}")),
        })?;
        conn.batch_execute(
            "CREATE TABLE IF NOT EXISTS connetto_refresh (account TEXT PRIMARY KEY NOT NULL, token TEXT NOT NULL)",
        )
        .map_err(|err| AuthError::Store(format!("init: {err}")))?;
        Ok(Self {
            conn: RefCell::new(conn),
        })
    }
}

impl RefreshTokenStore for RefreshStore {
    type Error = AuthError;

    fn load(&self, account: &str) -> Result<Option<String>, AuthError> {
        connetto_refresh::table
            .filter(connetto_refresh::account.eq(account))
            .select(connetto_refresh::token)
            .first::<String>(&mut *self.conn.borrow_mut())
            .optional()
            .map_err(|err| AuthError::Store(format!("load: {err}")))
    }

    fn store(&self, account: &str, token: &str) -> Result<(), AuthError> {
        diesel::insert_into(connetto_refresh::table)
            .values((
                connetto_refresh::account.eq(account),
                connetto_refresh::token.eq(token),
            ))
            .on_conflict(connetto_refresh::account)
            .do_update()
            .set(connetto_refresh::token.eq(token))
            .execute(&mut *self.conn.borrow_mut())
            .map_err(|err| AuthError::Store(format!("save: {err}")))?;
        Ok(())
    }

    fn clear(&self, account: &str) -> Result<(), AuthError> {
        diesel::delete(connetto_refresh::table.filter(connetto_refresh::account.eq(account)))
            .execute(&mut *self.conn.borrow_mut())
            .map_err(|err| AuthError::Store(format!("clear: {err}")))?;
        Ok(())
    }

    /// Enumerated from the rows the tokens live in, so it cannot disagree with
    /// what is stored. No index is kept here, and none is needed.
    fn accounts(&self) -> Result<Vec<String>, AuthError> {
        let names = connetto_refresh::table
            .select(connetto_refresh::account)
            .load::<String>(&mut *self.conn.borrow_mut())
            .map_err(|err| AuthError::Store(format!("accounts: {err}")))?;
        Ok(names
            .into_iter()
            .filter(|name| !connetto_client::is_reserved_record(name))
            .collect())
    }
}

/// A refresh store that writes nowhere, for the one boot where there is nothing
/// yet to write under.
///
/// A first run cannot persist its credential before the gate resolves. The
/// device key that encrypts [`RefreshStore`] is a record in [`IdbKeyStore`], so
/// writing it before enrolment would mint a stored key-encryption key, and
/// enrolment could then only delete that record, which does not erase the bytes
/// underneath. A snapshot of the profile taken in between would hold the stored
/// key and therefore the replica key. So acquisition runs against this, and
/// [`take`](Self::take) hands the rows to the real store once the gate is
/// settled and the device key resolves under whichever key-encryption key won.
///
/// Only a run that finds no existing store uses it. With a store already on
/// disk a stored key already exists, so deferring buys nothing and reading the
/// credential that is there saves the user an interactive login.
#[derive(Default)]
pub(crate) struct DeferredRefreshStore {
    rows: RefCell<Vec<(String, String)>>,
}

impl DeferredRefreshStore {
    /// Every row written, in write order, leaving this store empty.
    pub(crate) fn take(&self) -> Vec<(String, String)> {
        self.rows.take()
    }
}

impl RefreshTokenStore for DeferredRefreshStore {
    type Error = AuthError;

    fn load(&self, account: &str) -> Result<Option<String>, AuthError> {
        Ok(self
            .rows
            .borrow()
            .iter()
            .rev()
            .find(|(name, _)| name == account)
            .map(|(_, value)| value.clone()))
    }

    fn store(&self, account: &str, token: &str) -> Result<(), AuthError> {
        let mut rows = self.rows.borrow_mut();
        match rows.iter_mut().find(|(name, _)| name == account) {
            Some(row) => token.clone_into(&mut row.1),
            None => rows.push((account.to_owned(), token.to_owned())),
        }
        Ok(())
    }

    fn clear(&self, account: &str) -> Result<(), AuthError> {
        self.rows.borrow_mut().retain(|(name, _)| name != account);
        Ok(())
    }

    /// The pending rows, which is every account this boot has written so far.
    fn accounts(&self) -> Result<Vec<String>, AuthError> {
        Ok(self
            .rows
            .borrow()
            .iter()
            .map(|(name, _)| name.clone())
            .filter(|name| !connetto_client::is_reserved_record(name))
            .collect())
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

/// A logout message on [`LOGOUT_CHANNEL`], tokenless for the same reason
/// [`LoginMessage`] is: no variant can carry a credential, so a tab still cannot
/// reach the worker's token custody by speaking on this channel.
///
/// A tab sends [`Unsynced`](LogoutMessage::Unsynced) or
/// [`Logout`](LogoutMessage::Logout). The worker answers with
/// [`Pending`](LogoutMessage::Pending), [`Done`](LogoutMessage::Done), or
/// [`Refused`](LogoutMessage::Refused).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum LogoutMessage {
    /// Tab to worker: how much local work has not reached the server? Asking
    /// changes nothing, so a tab can offer an honest prompt before the user
    /// commits to anything.
    Unsynced,
    /// Worker to tabs: the seqs behind, whose length is the count to show. A
    /// snapshot, since the worker keeps syncing after answering.
    Pending {
        /// Mutations applied locally and queued but not yet acknowledged.
        seqs: Vec<u64>,
    },
    /// Tab to worker: revoke the session and clear the stored credential. With
    /// `delete` set, also destroy the replica, which needs `force` when work is
    /// still queued, because that work dies with the file.
    Logout {
        /// Destroy the replica rather than leaving it for the next login.
        delete: bool,
        /// Destroy it even though queued work would be lost with it.
        force: bool,
    },
    /// Worker to tabs: the logout is done. A tab reacts by showing a signed-out
    /// screen, since its own connection is about to be refused.
    Done {
        /// Whether the replica was marked for destruction.
        deleted: bool,
    },
    /// Worker to tabs: the delete was refused because work is still queued and
    /// `force` was not set. Reachable even after
    /// [`Pending`](LogoutMessage::Pending) answered zero, because a write can
    /// land between the question and the request.
    Refused {
        /// The queued seqs that would have been lost.
        seqs: Vec<u64>,
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
}

/// A completed acquisition: the access token the worker sets on its handshake,
/// plus the identity and session deadline the worker needs to select the
/// replica file this identity owns and to warn before an offline session
/// lapses with unsynced data.
///
/// No key material rides this: the replica's encryption key is minted in the
/// worker. Derive the replica name from [`user_id`](Self::user_id) and pass it
/// to [`provision_replica_key`] for a fresh replica, or to
/// [`IdbKeyStore::load`] for one already in storage.
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
}

impl<Id> From<TokenResponse<Id>> for BrowserSession<Id> {
    fn from(response: TokenResponse<Id>) -> Self {
        Self {
            access_token: response.access_token,
            user_id: response.user_id,
            session_expires_at: response.session_expires_at,
        }
    }
}

/// `IndexedDB` database name for the key store.
const KEY_STORE_DB: &str = "connetto-key-store";
/// Object store holding the non-extractable KEK for the ungated rung.
const STORE_KEK: &str = "kek";
/// Object store holding per-identity IV-plus-ciphertext records.
///
/// Record keys are `"{name}#{holder}"` where `holder` is the base64url-no-pad
/// credential id for enrolled profiles, or the empty string for the ungated rung.
const STORE_WRAPPED: &str = "wrapped";
/// Object store holding enrolled credential ids in the clear.
const STORE_CREDENTIALS: &str = "credentials";
/// Fixed record key for the sole ungated KEK entry in `STORE_KEK`.
const KEK_KEY: u32 = 1;
/// AES-GCM IV length in bytes.
const AES_GCM_IV_LEN: usize = 12;

/// Wraps and unwraps per-identity replica keys in `IndexedDB`.
///
/// Two rungs exist: an ungated rung backed by a stored non-extractable AES-GCM
/// key in `kek`, used while nobody has enrolled, and a passkey-derived rung
/// where the key-encryption key comes from a PRF assertion and is held only in
/// memory. Calling [`use_derived`](Self::use_derived) or
/// [`adopt_derived`](Self::adopt_derived) sets the in-memory derived key and
/// switches all subsequent reads and writes to it.
///
/// While `derived` is set, the `kek` store is irrelevant and nothing writes to
/// it. While it is absent and the `credentials` store is empty, the ungated kek
/// is used and minted on first write. Once credentials are enrolled and no
/// derived key is held, reads and writes return [`AuthError::Locked`]: the
/// caller must unlock before proceeding.
///
/// It deliberately reports no custody level. Telling a gate nobody has set up
/// from a platform that has none needs to know whether this browser can run the
/// ceremony at all, which is a tab property no key store can see, so any answer
/// here would over-claim. See [`connetto_core::NoGate`].
/// The single authority is [`crate::unlock::custody`], written by whoever asked
/// the tab, and [`enrolled`](Self::enrolled) is the storage half a caller
/// composes with.
pub struct IdbKeyStore {
    db: IdbDatabase,
    /// The derived key-encryption key, held only in memory. Populated by
    /// [`use_derived`](Self::use_derived) or [`adopt_derived`](Self::adopt_derived).
    /// The second element is the credential id whose PRF output it came from.
    derived: RefCell<Option<(web_sys::CryptoKey, Vec<u8>)>>,
}

impl IdbKeyStore {
    /// Open (creating if needed) the key-store database at version 2.
    ///
    /// Upgrading from version 1 drops and recreates `kek` and `wrapped` (the
    /// old shapes carried no holder suffix and cannot be unlocked) and creates
    /// `credentials`. The development profile therefore starts clean rather
    /// than carrying records nothing can unwrap.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the database cannot be opened or upgraded.
    pub async fn open() -> Result<Self, AuthError> {
        let db = IdbDatabase::open(KEY_STORE_DB)
            .with_version(2u8)
            .with_on_upgrade_needed(|_event, db| {
                // Drop old stores if present so no legacy records survive.
                let _ = db.delete_object_store(STORE_KEK);
                let _ = db.delete_object_store(STORE_WRAPPED);
                db.create_object_store(STORE_KEK).build()?;
                db.create_object_store(STORE_WRAPPED).build()?;
                db.create_object_store(STORE_CREDENTIALS).build()?;
                Ok(())
            })
            .await
            .map_err(|e| AuthError::Store(format!("open key store: {e}")))?;
        Ok(Self {
            db,
            derived: RefCell::new(None),
        })
    }

    /// The credential ids enrolled on this profile, in store order.
    ///
    /// An empty result means nobody has enrolled: the ungated rung is in use.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] on any IDB failure.
    pub async fn enrolled(&self) -> Result<Vec<Vec<u8>>, AuthError> {
        let tx = self
            .db
            .transaction(STORE_CREDENTIALS)
            .build()
            .map_err(|e| AuthError::Store(format!("enrolled tx: {e}")))?;
        let store = tx
            .object_store(STORE_CREDENTIALS)
            .map_err(|e| AuthError::Store(format!("enrolled store: {e}")))?;
        let keys: Vec<String> = store
            .get_all_keys::<String>()
            .primitive()
            .map_err(|e| AuthError::Store(format!("enrolled keys: {e}")))?
            .await
            .map_err(|e| AuthError::Store(format!("enrolled keys await: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuthError::Store(format!("enrolled decode: {e}")))?;
        keys.into_iter()
            .map(|k| {
                URL_SAFE_NO_PAD
                    .decode(k.as_bytes())
                    .map_err(|e| AuthError::Store(format!("enrolled id decode: {e}")))
            })
            .collect()
    }

    /// Derive the key-encryption key for this handle from `hkdf` without
    /// touching storage. Subsequent reads and writes use the derived key.
    ///
    /// Call this on the unlock path when a profile is already enrolled.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the HKDF derivation or AES-GCM import fails.
    pub async fn use_derived(
        &self,
        hkdf: web_sys::CryptoKey,
        credential_id: &[u8],
    ) -> Result<(), AuthError> {
        let kek = derive_kek(&hkdf).await?;
        self.derived.replace(Some((kek, credential_id.to_vec())));
        Ok(())
    }

    /// Derive the key-encryption key, re-wrap every existing record under it,
    /// record the credential id, and delete the stored ungated KEK.
    ///
    /// Serves both a first enrolment and a later one. After this call,
    /// `custody()` returns `Custody::Verified`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] on any IDB or `SubtleCrypto` failure.
    pub async fn adopt_derived(
        &self,
        hkdf: web_sys::CryptoKey,
        credential_id: &[u8],
    ) -> Result<(), AuthError> {
        // One holder per replica, a recorded out-of-scope decision: every copy
        // lives in this same store and is lost together. Refusing here also
        // keeps the re-wrap below total, since it walks the ungated records and
        // a second credential would orphan the first one's.
        if !self.enrolled().await?.is_empty() {
            return Err(AuthError::Store(
                "a credential is already enrolled on this profile".into(),
            ));
        }
        let derived_kek = derive_kek(&hkdf).await?;
        let holder_b64 = URL_SAFE_NO_PAD.encode(credential_id);
        self.rewrap_ungated_under(&derived_kek, &holder_b64).await?;
        self.forget_stored_kek().await?;
        self.record_credential(&holder_b64).await?;
        self.derived
            .replace(Some((derived_kek, credential_id.to_vec())));
        Ok(())
    }

    /// Move every ungated record onto `derived_kek` under the `holder` suffix.
    ///
    /// The decrypt and encrypt happen outside any open transaction, because
    /// `SubtleCrypto` awaits and an `IndexedDB` transaction closes the moment
    /// the event loop turns without pending work on it.
    async fn rewrap_ungated_under(
        &self,
        derived_kek: &web_sys::CryptoKey,
        holder: &str,
    ) -> Result<(), AuthError> {
        let stored_kek = self.load_kek().await?;
        let all_keys = self.wrapped_keys().await?;

        // For each ungated record (key ends with `#`): load, decrypt, re-encrypt.
        // WebCrypto runs outside any open IDB transaction.
        let mut rewrapped: Vec<(String, String, Vec<u8>)> = Vec::new();
        for old_key in &all_keys {
            if !old_key.ends_with('#') {
                continue;
            }
            let base = old_key.trim_end_matches('#');
            let raw = {
                let tx = self
                    .db
                    .transaction(STORE_WRAPPED)
                    .build()
                    .map_err(|e| AuthError::Store(format!("adopt read tx: {e}")))?;
                let store = tx
                    .object_store(STORE_WRAPPED)
                    .map_err(|e| AuthError::Store(format!("adopt read store: {e}")))?;
                store
                    .get(old_key.as_str())
                    .primitive()
                    .map_err(|e| AuthError::Store(format!("adopt get: {e}")))?
                    .await
                    .map_err(|e| AuthError::Store(format!("adopt get await: {e}")))?
            };
            let Some(raw) = raw else {
                continue;
            };
            let buf = js_sys::Uint8Array::new(&raw).to_vec();
            if buf.len() <= AES_GCM_IV_LEN {
                return Err(AuthError::Store("adopt: record truncated".into()));
            }
            let stored_kek_ref = stored_kek
                .as_ref()
                .ok_or_else(|| AuthError::Store("adopt: no stored kek to re-wrap".into()))?;
            let (iv_bytes, ct_bytes) = buf.split_at(AES_GCM_IV_LEN);
            let iv = js_sys::Uint8Array::from(iv_bytes);
            let params = aes_gcm_params(&iv);
            let ct_buf = ct_bytes.to_vec();
            let plain_js = JsFuture::from(
                subtle()?
                    .decrypt_with_object_and_u8_array(&params, stored_kek_ref, &ct_buf)
                    .map_err(|e| AuthError::Store(format!("adopt decrypt: {e:?}")))?,
            )
            .await
            .map_err(|e| AuthError::Store(format!("adopt decrypt await: {e:?}")))?;
            let plain = js_sys::Uint8Array::new(&plain_js).to_vec();
            let new_record = encrypt_with_kek(derived_kek, &plain).await?;
            rewrapped.push((old_key.clone(), format!("{base}#{holder}"), new_record));
        }
        if rewrapped.is_empty() {
            return Ok(());
        }
        let tx = self
            .db
            .transaction(STORE_WRAPPED)
            .with_mode(TransactionMode::Readwrite)
            .build()
            .map_err(|e| AuthError::Store(format!("adopt write tx: {e}")))?;
        let store = tx
            .object_store(STORE_WRAPPED)
            .map_err(|e| AuthError::Store(format!("adopt write store: {e}")))?;
        for (old_key, new_key, record_bytes) in &rewrapped {
            let arr = js_sys::Uint8Array::from(record_bytes.as_slice());
            let val: JsValue = arr.into();
            store
                .put(val)
                .with_key(new_key.as_str())
                .primitive()
                .map_err(|e| AuthError::Store(format!("adopt put: {e}")))?
                .await
                .map_err(|e| AuthError::Store(format!("adopt put await: {e}")))?;
            store
                .delete(old_key.as_str())
                .primitive()
                .map_err(|e| AuthError::Store(format!("adopt del: {e}")))?
                .await
                .map_err(|e| AuthError::Store(format!("adopt del await: {e}")))?;
        }
        tx.commit()
            .await
            .map_err(|e| AuthError::Store(format!("adopt write commit: {e}")))
    }

    /// Every key in the `wrapped` store.
    async fn wrapped_keys(&self) -> Result<Vec<String>, AuthError> {
        let tx = self
            .db
            .transaction(STORE_WRAPPED)
            .build()
            .map_err(|e| AuthError::Store(format!("wrapped list tx: {e}")))?;
        let store = tx
            .object_store(STORE_WRAPPED)
            .map_err(|e| AuthError::Store(format!("wrapped list store: {e}")))?;
        store
            .get_all_keys::<String>()
            .primitive()
            .map_err(|e| AuthError::Store(format!("wrapped list keys: {e}")))?
            .await
            .map_err(|e| AuthError::Store(format!("wrapped list keys await: {e}")))?
            .collect::<Result<Vec<String>, _>>()
            .map_err(|e| AuthError::Store(format!("wrapped list decode: {e}")))
    }

    /// Destroy the stored key-encryption key, which is what makes an enrolled
    /// profile hold nothing that opens the replica.
    async fn forget_stored_kek(&self) -> Result<(), AuthError> {
        let tx = self
            .db
            .transaction(STORE_KEK)
            .with_mode(TransactionMode::Readwrite)
            .build()
            .map_err(|e| AuthError::Store(format!("adopt kek del tx: {e}")))?;
        let store = tx
            .object_store(STORE_KEK)
            .map_err(|e| AuthError::Store(format!("adopt kek store: {e}")))?;
        store
            .delete(KEK_KEY)
            .primitive()
            .map_err(|e| AuthError::Store(format!("adopt kek del: {e}")))?
            .await
            .map_err(|e| AuthError::Store(format!("adopt kek del await: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| AuthError::Store(format!("adopt kek commit: {e}")))
    }

    /// Note the credential id in the clear. It is not secret, and an assertion
    /// has to be scoped to it on the next boot.
    async fn record_credential(&self, holder: &str) -> Result<(), AuthError> {
        let tx = self
            .db
            .transaction(STORE_CREDENTIALS)
            .with_mode(TransactionMode::Readwrite)
            .build()
            .map_err(|e| AuthError::Store(format!("adopt cred tx: {e}")))?;
        let store = tx
            .object_store(STORE_CREDENTIALS)
            .map_err(|e| AuthError::Store(format!("adopt cred store: {e}")))?;
        // The id is the key, so the value only has to exist.
        store
            .put(JsValue::TRUE)
            .with_key(holder)
            .primitive()
            .map_err(|e| AuthError::Store(format!("adopt cred put: {e}")))?
            .await
            .map_err(|e| AuthError::Store(format!("adopt cred put await: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| AuthError::Store(format!("adopt cred commit: {e}")))
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

    /// Resolve the kek and record key for a `load` or `store` call.
    async fn resolve_kek_for_read(
        &self,
        name: &str,
    ) -> Result<Option<(web_sys::CryptoKey, String)>, AuthError> {
        if let Some((kek, cred_id)) = self.derived.borrow().clone() {
            let holder = URL_SAFE_NO_PAD.encode(&cred_id);
            return Ok(Some((kek, format!("{name}#{holder}"))));
        }
        // No derived key. An enrolled profile is LOCKED, which is not the same
        // as holding no key, and the difference matters: `None` tells a boot
        // that nothing was ever cached, so it would mint a fresh key and strand
        // the replica this one still opens.
        if !self.enrolled().await?.is_empty() {
            return Err(AuthError::Locked {
                detail: "a credential is enrolled and no derived key is held, unlock first".into(),
            });
        }
        let Some(kek) = self.load_kek().await? else {
            return Ok(None);
        };
        Ok(Some((kek, format!("{name}#"))))
    }

    /// Resolve the kek and record key for a `store` call, refusing when enrolled
    /// but no derived key is held.
    async fn resolve_kek_for_write(
        &self,
        name: &str,
    ) -> Result<(web_sys::CryptoKey, String), AuthError> {
        if let Some((kek, cred_id)) = self.derived.borrow().clone() {
            let holder = URL_SAFE_NO_PAD.encode(&cred_id);
            return Ok((kek, format!("{name}#{holder}")));
        }
        // No derived key. If enrolled, refuse rather than mint a stored kek.
        if !self.enrolled().await?.is_empty() {
            return Err(AuthError::Locked {
                detail: "a credential is enrolled and no derived key is held, unlock first".into(),
            });
        }
        let kek = self.get_or_create_kek().await?;
        Ok((kek, format!("{name}#")))
    }
}

impl ReplicaKeyStore for IdbKeyStore {
    type Error = AuthError;

    /// Load the replica key for `name`, or `None` if no key has been saved.
    ///
    /// Uses the derived key-encryption key when one is held in memory (enrolled
    /// and unlocked), otherwise the stored ungated KEK. Returns `None` when no
    /// KEK is available rather than an error.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] on any IDB or `SubtleCrypto` failure.
    /// [`AuthError::Locked`] when credentials are enrolled but no derived key
    /// is held.
    async fn load(&self, name: &str) -> Result<Option<ReplicaKey>, AuthError> {
        let Some((kek, record_key)) = self.resolve_kek_for_read(name).await? else {
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
            .get(record_key.as_str())
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

    /// Persist `key` for `name`, overwriting any prior value.
    ///
    /// Uses the derived key-encryption key when one is held in memory.
    /// Otherwise uses the stored ungated KEK, minting it on first use, unless a
    /// credential is enrolled in which case it returns [`AuthError::Locked`].
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] on any IDB or `SubtleCrypto` failure.
    /// [`AuthError::Locked`] when enrolled but no derived key is held.
    async fn store(&self, name: &str, key: &ReplicaKey) -> Result<(), AuthError> {
        let (kek, record_key) = self.resolve_kek_for_write(name).await?;
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
            .with_key(record_key.as_str())
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
    /// Enumerates the `wrapped` store to find whichever holder suffix the
    /// record carries, since the caller knows only the base name. No-op when no
    /// record for `name` exists under any holder.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] on any IDB failure.
    async fn clear(&self, name: &str) -> Result<(), AuthError> {
        let prefix = format!("{name}#");
        // Read all keys, then delete matching ones in a write tx.
        let all_keys: Vec<String> = {
            let tx = self
                .db
                .transaction(STORE_WRAPPED)
                .build()
                .map_err(|e| AuthError::Store(format!("clear list tx: {e}")))?;
            let store = tx
                .object_store(STORE_WRAPPED)
                .map_err(|e| AuthError::Store(format!("clear list store: {e}")))?;
            store
                .get_all_keys::<String>()
                .primitive()
                .map_err(|e| AuthError::Store(format!("clear list keys: {e}")))?
                .await
                .map_err(|e| AuthError::Store(format!("clear list keys await: {e}")))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| AuthError::Store(format!("clear list decode: {e}")))?
        };
        let to_delete: Vec<&str> = all_keys
            .iter()
            .filter(|k| k.starts_with(&prefix))
            .map(String::as_str)
            .collect();
        if to_delete.is_empty() {
            return Ok(());
        }
        let tx = self
            .db
            .transaction(STORE_WRAPPED)
            .with_mode(TransactionMode::Readwrite)
            .build()
            .map_err(|e| AuthError::Store(format!("clear tx: {e}")))?;
        let store = tx
            .object_store(STORE_WRAPPED)
            .map_err(|e| AuthError::Store(format!("clear store: {e}")))?;
        for key in to_delete {
            store
                .delete(key)
                .primitive()
                .map_err(|e| AuthError::Store(format!("clear delete: {e}")))?
                .await
                .map_err(|e| AuthError::Store(format!("clear delete await: {e}")))?;
        }
        tx.commit()
            .await
            .map_err(|e| AuthError::Store(format!("clear commit: {e}")))?;
        Ok(())
    }
}

/// The effective key for the replica `name`, minting one when this device has
/// none cached.
///
/// Provision-once, and the browser mirror of
/// `connetto_client::auth::provision_replica_key`: a key already cached on this
/// device always wins and is never overwritten, so a second login cannot
/// silently re-key a replica and strand its contents. Only when nothing is
/// cached is a fresh key minted, and it is written through first.
///
/// The key is minted here, in the worker, from the same platform RNG that mints
/// the PKCE verifier and the AES-GCM IV this very key is wrapped under. No key
/// material crosses the wire and the server never holds any.
///
/// Call this after acquisition, because `name` is derived from the identity the
/// token response resolves, and **only for a replica that does not exist yet**.
/// For one already in storage read [`ReplicaKeyStore::load`]: minting for an
/// existing replica would return a key that decrypts nothing.
///
/// It stays once per target rather than moving to `connetto-core` beside the
/// trait, because minting needs an entropy source and `ReplicaKey` deliberately
/// carries none, which is what keeps this build's entropy choice its own.
///
/// # Errors
///
/// [`AuthError::Store`] if the key store cannot be read or written, or
/// [`AuthError::Context`] if the platform RNG fails.
pub async fn provision_replica_key<S: ReplicaKeyStore<Error = AuthError>>(
    store: &S,
    name: &str,
) -> Result<ReplicaKey, AuthError> {
    if let Some(cached) = store.load(name).await? {
        return Ok(cached);
    }
    let minted = mint_replica_key()?;
    store.store(name, &minted).await?;
    Ok(minted)
}

/// Persist what a token response established: the credential under the account
/// it belongs to, and that same account as the last-used marker.
///
/// Keyed off the response rather than off whatever the caller was told to try,
/// because a first login has no account to key on and learns it here. One
/// encoding serves both records, so the marker's value is literally the key of
/// the row it points at.
///
/// The browser mirror of the same write on `NativeAuthenticator`. Both token
/// paths do it, because either can be the one that establishes who this device
/// is: a silent refresh on a start, or an interactive login on a first run.
///
/// # Errors
///
/// [`AuthError::Store`] if the account cannot be encoded or either record
/// written.
fn persist_session<Id: serde::Serialize, S: RefreshTokenStore<Error = AuthError>>(
    store: &S,
    user_id: &Id,
    refresh_token: &str,
) -> Result<(), AuthError> {
    let account = connetto_client::encode_identity(user_id)
        .map_err(|err| AuthError::Store(err.to_string()))?;
    store.store(&account, refresh_token)?;
    store.store(connetto_client::IDENTITY_RECORD, &account)
}

/// The account this device last signed in as, if it ever did.
///
/// This is what makes a start with no network possible at all: the replica file
/// is named from the account, and the account otherwise only ever arrives
/// inside a token response, which needs the network to fetch.
///
/// # Errors
///
/// [`AuthError::Store`] if the record cannot be read, or if it does not decode
/// as this build's id type, which means a build whose id type differed wrote
/// it. The recovery is a fresh login, which rewrites it.
pub fn remembered_identity<
    Id: serde::de::DeserializeOwned,
    S: RefreshTokenStore<Error = AuthError>,
>(
    store: &S,
) -> Result<Option<Id>, AuthError> {
    let Some(record) = store.load(connetto_client::IDENTITY_RECORD)? else {
        return Ok(None);
    };
    connetto_client::decode_identity(&record)
        .map(Some)
        .map_err(|err| AuthError::Store(err.to_string()))
}

/// The account key this device last signed in under, if it ever did.
///
/// The same record [`remembered_identity`] decodes, read raw, because a boot
/// needs the store key rather than the typed id: it is what addresses the
/// credential to try. Kept apart from the typed read so a boot never has to
/// decode an id only to re-encode it.
///
/// # Errors
///
/// [`AuthError::Store`] if the record cannot be read.
pub fn remembered_account<S: RefreshTokenStore<Error = AuthError>>(
    store: &S,
) -> Result<Option<String>, AuthError> {
    store.load(connetto_client::IDENTITY_RECORD)
}

/// A fresh key from the platform RNG.
///
/// The staging array is key material until it is wiped, and a plain fill would
/// be elidable where `zeroize` is not.
fn mint_replica_key() -> Result<ReplicaKey, AuthError> {
    let mut bytes = [0u8; ReplicaKey::LEN];
    getrandom::fill(&mut bytes)
        .map_err(|err| AuthError::Context(format!("replica key mint: {err}")))?;
    let key = ReplicaKey::from_bytes(bytes);
    bytes.zeroize();
    Ok(key)
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
///
/// It holds the account whose stored credential it should try, rather than
/// passing one at each call, so no two call sites can disagree about which
/// credential this is.
pub struct BrowserAuthenticator {
    config: WorkerAuthConfig,
    account: Option<String>,
}

impl BrowserAuthenticator {
    /// Build over the worker auth configuration and the account whose stored
    /// credential to try.
    ///
    /// `None` means there is nothing to try, which is a first run and any boot
    /// where no account was chosen and none was ever remembered. It is not a
    /// placeholder for an unknown account: the token is what reveals the account,
    /// so a run with no account skips the silent attempt entirely rather than
    /// addressing a literal.
    #[must_use]
    pub fn new(config: WorkerAuthConfig, account: Option<String>) -> Self {
        Self { config, account }
    }

    /// Try a silent refresh from the stored token, on failure or absence
    /// produce a [`PendingLogin`] for interactive login.
    ///
    /// The replica key is not part of this exchange: see
    /// [`complete`](Self::complete).
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the refresh store cannot be read.
    pub async fn acquire<
        Id: serde::de::DeserializeOwned + serde::Serialize,
        S: RefreshTokenStore<Error = AuthError>,
    >(
        &self,
        store: &S,
    ) -> Result<Acquired<Id>, AuthError> {
        if let Some(account) = self.account.as_deref()
            && let Some(refresh) = store.load(account)?
        {
            match self.refresh_tokens(&refresh).await {
                Ok(tokens) => {
                    persist_session(store, &tokens.user_id, &tokens.refresh_token)?;
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
            self.config
                .login_base_url
                .as_ref()
                .unwrap_or(&self.config.auth_base_url),
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
    /// The replica key is not part of this exchange. Resolve it afterwards from
    /// the identity this returns, with [`provision_replica_key`] for a fresh
    /// replica or [`ReplicaKeyStore::load`] for one already in storage.
    ///
    /// # Errors
    ///
    /// [`AuthError`] on a state mismatch, a failed exchange, or a store write.
    pub async fn complete<
        Id: serde::de::DeserializeOwned + serde::Serialize,
        S: RefreshTokenStore<Error = AuthError>,
    >(
        &self,
        pending: &PendingLogin,
        code: &str,
        state: &str,
        store: &S,
    ) -> Result<BrowserSession<Id>, AuthError> {
        if state != pending.state {
            return Err(AuthError::StateMismatch);
        }
        let tokens = self.exchange_code(code, &pending.verifier).await?;
        persist_session(store, &tokens.user_id, &tokens.refresh_token)?;
        Ok(tokens.into())
    }

    /// Credential teardown: revoke the session server-side and clear the stored
    /// refresh token, so re-authentication is required.
    ///
    /// One half of the logout grid. It touches no data: the replica and its key
    /// survive, which is what lets a returning user resume from their persisted
    /// cursor instead of re-syncing. For the other half see
    /// [`wipe_replica`](crate::storage::wipe_replica).
    ///
    /// The revoke is awaited, and **the local clear happens either way**. A tab
    /// with no connectivity must still be able to log out, so a failed revoke is
    /// reported rather than allowed to keep the credential in OPFS. `Ok` means the
    /// session is refused at the next handshake, and an error means local state is
    /// gone but the session stays live server-side until it expires on its own.
    /// Queueing the revoke is not an option, since after the clear there is no
    /// credential left to authenticate it with.
    ///
    /// Revocation is liveness, not expiry: the access token the worker still holds
    /// in memory stays signature-valid until its own short TTL runs out, so drop
    /// the connection rather than trusting the server to refuse it.
    ///
    /// Idempotent: with no refresh token stored there is nothing to revoke.
    ///
    /// # Errors
    ///
    /// [`AuthError::Transient`] or [`AuthError::Request`] if the revoke fails,
    /// after the local clear, or [`AuthError::Store`] if the store cannot be read
    /// or cleared.
    pub async fn logout(&self, store: &RefreshStore) -> Result<(), AuthError> {
        // Signing out is per account: the others keep their credentials, and the
        // marker is left pointing at an account with none, which the next boot
        // answers with an interactive login rather than by picking somebody else.
        let Some(account) = self.account.as_deref() else {
            return Ok(());
        };
        let Some(refresh) = store.load(account)? else {
            return Ok(());
        };
        let body = serde_json::json!({ "refresh_token": refresh }).to_string();
        let revoked = post_json(&format!("{}/auth/logout", self.config.auth_base_url), &body).await;
        store.clear(account)?;
        revoked.map(drop)
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
    ask(
        LOGIN_CHANNEL,
        &LoginMessage::Request {
            url: login_url.to_owned(),
        },
        |message| match message {
            LoginMessage::Code { code, state } => Some((code, state)),
            LoginMessage::Request { .. } => None,
        },
    )
    .await
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

/// What a [`request_logout`] call ended in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogoutOutcome {
    /// Logged out, replica left in place for the next login by this identity.
    Kept,
    /// Logged out, replica marked for destruction at the next startup.
    Deleted,
    /// Still logged in: the delete would have destroyed queued work and `force`
    /// was not set.
    Refused {
        /// The queued seqs that would have been lost.
        seqs: Vec<u64>,
    },
}

/// Broadcast `request` on `channel` and wait for the reply that `reply`
/// recognises. Other traffic on the channel is ignored, including this
/// context's own request, which a `BroadcastChannel` never echoes to its
/// sender.
async fn ask<M, T>(
    channel: &str,
    request: &M,
    reply: impl Fn(M) -> Option<T> + 'static,
) -> Result<T, AuthError>
where
    M: Serialize + serde::de::DeserializeOwned + 'static,
    T: 'static,
{
    let broadcast = BroadcastChannel::new(channel)
        .map_err(|err| AuthError::Context(format!("{channel} channel: {err:?}")))?;
    let (sender, receiver) = futures_channel::oneshot::channel::<T>();
    let sender = Rc::new(RefCell::new(Some(sender)));
    let on_message = Closure::<dyn FnMut(MessageEvent)>::new({
        let sender = Rc::clone(&sender);
        move |event: MessageEvent| {
            let Some(text) = event.data().as_string() else {
                return;
            };
            if let Ok(message) = serde_json::from_str::<M>(&text)
                && let Some(value) = reply(message)
                && let Some(sender) = sender.borrow_mut().take()
            {
                let _ = sender.send(value);
            }
        }
    });
    broadcast.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

    let encoded = serde_json::to_string(request).map_err(|_| AuthError::Decode)?;
    broadcast
        .post_message(&JsValue::from_str(&encoded))
        .map_err(|err| js_error(&format!("broadcast on {channel}"), &err))?;

    let outcome = receiver.await.map_err(|_| AuthError::Cancelled);
    broadcast.set_onmessage(None);
    broadcast.close();
    drop(on_message);
    outcome
}

/// Page-side: how many local writes have not reached the server yet.
///
/// Ask before offering to delete, so the prompt can name the number instead of
/// warning vaguely. The answer is a snapshot: the worker keeps syncing, so by the
/// time a user confirms, the true count may be lower, or higher if another tab
/// wrote meanwhile.
///
/// # Errors
///
/// [`AuthError::Cancelled`] when no worker answers, which is what a dead or
/// still-booting DB worker looks like from a tab.
pub async fn request_unsynced() -> Result<Vec<u64>, AuthError> {
    ask(
        LOGOUT_CHANNEL,
        &LogoutMessage::Unsynced,
        |message| match message {
            LogoutMessage::Pending { seqs } => Some(seqs),
            _ => None,
        },
    )
    .await
}

/// Page-side: ask the worker to log out, optionally destroying the replica.
///
/// `delete` without `force` is refused while writes are queued, and the refusal
/// carries them, so a tab that skipped [`request_unsynced`] still cannot destroy
/// unsynced work by accident. The replica is destroyed at the next startup rather
/// than now, because the worker holds it open for its whole life.
///
/// # Errors
///
/// [`AuthError::Cancelled`] when no worker answers.
pub async fn request_logout(delete: bool, force: bool) -> Result<LogoutOutcome, AuthError> {
    ask(
        LOGOUT_CHANNEL,
        &LogoutMessage::Logout { delete, force },
        |message| match message {
            LogoutMessage::Done { deleted } => Some(if deleted {
                LogoutOutcome::Deleted
            } else {
                LogoutOutcome::Kept
            }),
            LogoutMessage::Refused { seqs } => Some(LogoutOutcome::Refused { seqs }),
            _ => None,
        },
    )
    .await
}

/// A 256-bit random token as URL-safe base64, for the PKCE verifier and state.
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("platform RNG");
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
    getrandom::fill(&mut iv).unwrap_throw();
    iv
}

/// Derive the AES-GCM-256 key-encryption key from an HKDF `CryptoKey`.
///
/// The HKDF key carries the PRF extension output (32 uniformly random bytes)
/// imported by the tab as `importKey("raw", ..., "HKDF", false, ["deriveBits"])`.
/// Derivation uses a zero-length salt (the extension output is already
/// uniformly random) and [`AT_REST_KEK_LABEL`] as the purpose label.
pub(crate) async fn derive_kek(hkdf: &web_sys::CryptoKey) -> Result<web_sys::CryptoKey, AuthError> {
    let params = js_sys::Object::new();
    js_sys::Reflect::set(&params, &JsValue::from("name"), &JsValue::from("HKDF")).unwrap_throw();
    js_sys::Reflect::set(&params, &JsValue::from("hash"), &JsValue::from("SHA-256")).unwrap_throw();
    js_sys::Reflect::set(
        &params,
        &JsValue::from("salt"),
        &js_sys::Uint8Array::new_with_length(0),
    )
    .unwrap_throw();
    js_sys::Reflect::set(
        &params,
        &JsValue::from("info"),
        &js_sys::Uint8Array::from(AT_REST_KEK_LABEL),
    )
    .unwrap_throw();
    let bits_js = JsFuture::from(
        subtle()?
            .derive_bits_with_object(&params, hkdf, 256u32)
            .map_err(|e| AuthError::Store(format!("derive bits: {e:?}")))?,
    )
    .await
    .map_err(|e| AuthError::Store(format!("derive bits await: {e:?}")))?;
    let bits_u8 = js_sys::Uint8Array::new(&bits_js);
    let aes_params = aes_key_gen_params();
    let usages = js_sys::Array::new();
    usages.push(&JsValue::from_str("encrypt"));
    usages.push(&JsValue::from_str("decrypt"));
    let kek_js = JsFuture::from(
        subtle()?
            .import_key_with_object(
                "raw",
                bits_u8.unchecked_ref::<js_sys::Object>(),
                &aes_params,
                false,
                &usages,
            )
            .map_err(|e| AuthError::Store(format!("import kek: {e:?}")))?,
    )
    .await
    .map_err(|e| AuthError::Store(format!("import kek await: {e:?}")))?;
    Ok(kek_js.unchecked_into::<web_sys::CryptoKey>())
}

/// Encrypt `plaintext` with `kek` under a fresh random IV and return the
/// `IV || ciphertext` byte vector.
pub(crate) async fn encrypt_with_kek(
    kek: &web_sys::CryptoKey,
    plaintext: &[u8],
) -> Result<Vec<u8>, AuthError> {
    let iv_bytes = random_iv();
    let iv = js_sys::Uint8Array::from(iv_bytes.as_ref());
    let params = aes_gcm_params(&iv);
    let mut buf = plaintext.to_vec();
    let ct_js = JsFuture::from(
        subtle()?
            .encrypt_with_object_and_u8_array(&params, kek, &buf)
            .map_err(|e| AuthError::Store(format!("encrypt: {e:?}")))?,
    )
    .await
    .map_err(|e| AuthError::Store(format!("encrypt await: {e:?}")))?;
    buf.zeroize();
    let ct = js_sys::Uint8Array::new(&ct_js);
    let ct_len = usize::try_from(ct.length())
        .map_err(|e| AuthError::Store(format!("encrypt ct len: {e}")))?;
    let mut out = Vec::with_capacity(AES_GCM_IV_LEN + ct_len);
    out.extend_from_slice(&iv_bytes);
    out.extend(ct.to_vec());
    Ok(out)
}
