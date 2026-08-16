//! connetto-client: the native local-first sync client.
//!
//! A transparent sync layer over a `connetto-server`. The application runs
//! ordinary diesel queries against a managed local SQLite connection; the client
//! does the rest.
//!
//! * **Local writes** are captured by a SQLite session hooked onto the
//!   application's connection ([`SqliteSessionExt`]). [`ConnettoConnection::push`] drains
//!   that session into a changeset (which carries the old row image, so the
//!   server's conflict check works), compresses it, and uploads it as a
//!   `MutationHeader` plus `MutationPatch`.
//! * **Server patches** (the initial snapshot and live updates) apply on the
//!   same connection with capture suspended: the session's recording is
//!   switched off around the apply (`sqlite3session_enable`), so
//!   server-originated changes are never re-uploaded (no echo loop). One
//!   connection serves both directions, which is also the only topology
//!   `sqlite-wasm-rs` supports on wasm (no multiple connections per
//!   database), so native and wasm share it.
//!
//! The server produces its patches with `sqlite-diff-rs`, whose output is the
//! native SQLite session patchset format, so the client applies them directly
//! with [`SqliteSessionExt::apply_patchset`]. No catalog or `subql` engine lives
//! on the client.
//!
//! The client is single-threaded ([`diesel_sqlite_session::Session`] holds a raw
//! SQLite handle and is `!Send`): drive it from one task with
//! [`ConnettoConnection::pump_one`], interleaving [`ConnettoConnection::push`] after local
//! writes.

pub use connetto_core::messages::{FullResyncReason, Grant, PauseCause, SyncStatus};

use connetto_core::messages::{
    AckCredits, BulkMessage, ConflictRow, ControlMessage, FatalErrorReason, Handshake,
    MutationHeader, MutationPatch, Ping, Subscribe, SubscriptionSpec, Unsubscribe,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION, SchemaVersion, quote_ident};
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use diesel::connection::SimpleConnection;
use diesel::connection::{
    AnsiTransactionManager, CacheSize, ConnectionSealed, DefaultLoadingMode, Instrumentation,
    LoadConnection,
};
use diesel::expression::QueryMetadata;
use diesel::query_builder::{Query, QueryFragment, QueryId};
use diesel::result::{ConnectionError, ConnectionResult, QueryResult};
use diesel::sqlite::{
    CommitDecision, Sqlite, SqliteChangeOps, SqliteFunctionBehavior, SqliteUpdateRouter,
};
use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SqliteConnection};
use diesel_sqlite_session::{
    ConflictAction, ConflictType, Session, SqliteSessionExt, invert_changeset,
};
use sqlite_diff_rs::{
    DiffOps, DynTable, ParsedDiffSet, PatchDelete, PatchSet, PatchsetOp, SchemaWithPK, TableSchema,
    Value,
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

#[cfg(feature = "native-auth")]
pub mod auth;
pub mod cipher;
mod clock;
pub mod dsl;
mod grant_expiry;
pub mod live;
pub mod reconnect;
pub mod replica;
mod subscriptions;

pub use subscriptions::{DEFAULT_GRACE, MAX_GRACE};
pub mod teardown;

#[cfg(feature = "native-auth")]
pub use auth::{
    AcquiredSession, BrowserOpener, KeyringKeyStore, KeyringStore, MemoryKeyStore,
    MemoryRefreshStore, NativeAuthenticator, provision_replica_key, system_browser_opener,
};
pub use cipher::{ReplicaKey, UnlockError};
pub use dsl::Watchable;
pub use live::{
    ConnettoClient, LiveHandle, LiveQuery, LiveValue, subscription_is_aggregate,
    subscription_tables,
};
#[cfg(feature = "native-transport")]
pub use reconnect::TokioSleeper;
pub use reconnect::{ReconnectPolicy, Sleeper, TransportFactory};
pub use replica::{
    Encrypted, IDENTITY_RECORD, InMemory, Replica, ReplicaStorage, Tier, decode_identity,
    encode_identity, replica_db_name,
};

/// Zstd level for outbound mutation payloads. Level 3 is the library default.
const ZSTD_LEVEL: i32 = 3;

/// Failure surfaced by the client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The underlying transport failed.
    #[error("transport error: {0}")]
    Transport(String),
    /// The server violated the expected wire sequence.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// The SQLite capture session failed.
    #[error("session error: {0}")]
    Session(String),
    /// Applying a server patch to the local replica failed.
    #[error("apply error: {0}")]
    Apply(String),
    /// A local database operation failed.
    #[error(transparent)]
    Db(#[from] diesel::result::Error),
    /// Connecting the local database failed.
    #[error("database connection error: {0}")]
    Connect(String),
    /// Zstd compression or decompression failed.
    #[error(transparent)]
    Compression(#[from] std::io::Error),
    /// The server advertised a schema version this client build does not match
    /// (either a different version or none at all), so this build is stale and
    /// the app must reload. connetto never migrates schemas at runtime.
    #[error(
        "schema outdated: client built for {}, server advertises {server}",
        .client.as_ref().map_or_else(|| "none".to_owned(), ToString::to_string)
    )]
    SchemaOutdated {
        /// The version this client build was compiled against, or `None` when
        /// it declared none.
        client: Option<SchemaVersion>,
        /// The version the server advertised in the handshake ack.
        server: SchemaVersion,
    },
    /// The operation needs a server and this connection has none.
    ///
    /// Raised by everything that speaks to the server on a connection that was
    /// opened offline and never attached, or whose transport dropped. Local
    /// reads, local writes and the pending queue are unaffected: a caller that
    /// meets this keeps working and retries when a transport arrives.
    #[error("not connected: this operation needs a server")]
    NotConnected,
    /// Acquiring or refreshing the access token failed.
    #[error("authentication error: {0}")]
    Auth(String),
    /// The local database exists but does not decrypt under the key given at
    /// connect.
    ///
    /// A wrong key and a corrupt file are indistinguishable to the page codec.
    /// The benign cause is a device whose key store was cleared while its
    /// replica file survived, which the next login re-keys, so the recovery is
    /// discard and re-sync rather than a corruption report.
    ///
    /// There is no unsynced-mutation guard on that discard, and there cannot be
    /// one: the pending mutations live inside the file this key will not open,
    /// so they are unreadable and therefore already lost. Delete the replica
    /// with [`purge_replica`](teardown::purge_replica) and `force` set, then
    /// connect afresh to re-sync the synced tables from the server. The
    /// device-local tier does not come back, which is the cost the plan states
    /// for provision-once custody.
    #[error("the local database does not decrypt under the key supplied: {0}")]
    ReplicaUndecryptable(String),
    /// Applying the replica cipher failed before any page was read: this build
    /// links a SQLite with no page codec, or a cipher pragma was rejected.
    #[error("replica cipher: {0}")]
    Cipher(String),
    /// An encrypted replica was asked for and no key resolved: the login carried
    /// none and none was cached.
    ///
    /// Raised by [`Replica::encrypted_file`], which is where the refusal lives so
    /// that no caller can turn a missing key into a readable file instead. The
    /// reachable cause is a device whose key store was cleared while its replica
    /// survived. Recover with a fresh interactive login, which provisions a key,
    /// or with an explicit data wipe.
    #[error("no replica key was provisioned or cached, so the replica cannot be opened encrypted")]
    ReplicaKeyMissing,
    /// The replica's schema and the policy-table map disagree about which
    /// tables the row-level-security translation split.
    ///
    /// The map is a build artifact of the same translation that emitted the
    /// DDL, so a disagreement means the two came from different builds, or
    /// that the application never passed the map
    /// ([`ClientConfig::with_policy_tables`]). Either way the sync boundaries
    /// would rename the wrong set of names, and the resulting loss is silent:
    /// a patch applied against a policy view reports success and delivers
    /// nothing. Rebuild the client against the current schema.
    #[error(
        "the replica's policy views and the compiled-in table map disagree: {}",
        .unmapped.join(", ")
    )]
    PolicyTablesStale {
        /// The disagreeing names, each said as which side is missing it.
        unmapped: Vec<String>,
    },
}

/// Why a sign-in switch was refused.
///
/// Nothing has changed when this is returned: the run is still the one it was,
/// and the caller may retry once the connection is healthy enough to drain.
#[derive(Debug, thiserror::Error)]
pub enum SignInRefused {
    /// Writes are still queued after the push, so switching would strand them
    /// under a handle nobody presents again.
    #[error("sign-in blocked: {} write(s) are still queued", .0.len())]
    Unsent(Vec<u64>),
    /// Draining the queue failed, so whether anything is still unsent is
    /// unknown and the switch is refused rather than guessed at.
    #[error("sign-in blocked, the queued writes could not be sent: {0}")]
    Push(String),
    /// No server has been reached, so there is no handle to hand over. A run
    /// that has never connected has written nothing the server attributed to
    /// it, so there is nothing for the incoming account to adopt.
    #[error("sign-in blocked: this run has no server handle to hand over")]
    NotConnected,
}

/// Split a cipher failure by what the caller can do about it: a key that does
/// not decrypt is recoverable by discarding the replica, everything else is a
/// build or configuration fault.
impl From<UnlockError> for ClientError {
    fn from(error: UnlockError) -> Self {
        match error {
            UnlockError::WrongKey(_) => Self::ReplicaUndecryptable(error.to_string()),
            UnlockError::CodecMissing | UnlockError::Pragma(_) => Self::Cipher(error.to_string()),
        }
    }
}

/// The boxed future a token factory returns.
type TokenFuture = std::pin::Pin<Box<dyn Future<Output = Result<String, ClientError>> + Send>>;

/// The token factory behind an [`AccessTokenSource`].
type TokenFactory = dyn Fn() -> TokenFuture + Send + Sync;

/// A source of fresh connetto access tokens for the handshake.
///
/// A [`ConnettoConnection`] set with one (see
/// [`with_token_source`](ConnettoConnection::with_token_source)) calls it on
/// every resume, so a native client silently refreshes its access token on
/// reconnect. Debug-opaque and `Clone` like [`SqlFunctions`], so it can live in
/// a `Send + Sync` connection on every target.
#[derive(Clone)]
pub struct AccessTokenSource(Arc<TokenFactory>);

impl AccessTokenSource {
    /// Build a source from an async token factory.
    pub fn new<F, Fut>(factory: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, ClientError>> + Send + 'static,
    {
        Self(Arc::new(move || Box::pin(factory())))
    }

    /// Obtain a fresh access token.
    ///
    /// # Errors
    ///
    /// Whatever the factory returns, typically [`ClientError::Auth`].
    pub async fn token(&self) -> Result<String, ClientError> {
        (self.0)().await
    }
}

impl std::fmt::Debug for AccessTokenSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AccessTokenSource(..)")
    }
}

/// A closure that registers custom SQLite functions on a replica connection
/// connetto opens. connetto runs every installer right after opening a
/// connection and before any DDL or insert, so a column `DEFAULT` that calls a
/// registered function fires on the very first write.
///
/// `Send + Sync` on every target, wasm included: [`ConnettoConnection`]
/// embeds [`ClientConfig`] and implements `diesel::Connection`, whose `Send`
/// supertrait forces the whole connection (so the whole config) to be `Send`
/// even in the wasm build. `Arc<dyn Fn>` is `Send` only when the `dyn` is
/// `Send + Sync`, hence both bounds. In practice a registrar closes over
/// global clock and PRNG functions, never a `JsValue`, so the bound holds.
pub type SqlFunctionInstaller = Arc<dyn Fn(&mut SqliteConnection) -> QueryResult<()> + Send + Sync>;

/// The custom SQLite functions connetto registers on every replica connection
/// it opens. Empty by default: connetto ships no built-in functions, so each
/// app registers the functions its schema names (a `uuidv7` key generator, for
/// instance) through [`with`](SqlFunctions::with).
#[derive(Clone, Default)]
pub struct SqlFunctions(Vec<SqlFunctionInstaller>);

impl SqlFunctions {
    /// An empty registrar list.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Add one installer, returning the extended list.
    #[must_use]
    pub fn with(mut self, installer: SqlFunctionInstaller) -> Self {
        self.0.push(installer);
        self
    }

    /// Run every installer against `conn`. connetto calls this at each
    /// connection seam, right after `establish`, before DDL or the first
    /// insert.
    ///
    /// # Errors
    ///
    /// The first installer's error, so a failed registration surfaces at
    /// connect rather than as a "no such function" at insert time.
    pub fn install(&self, conn: &mut SqliteConnection) -> QueryResult<()> {
        for installer in &self.0 {
            installer(conn)?;
        }
        Ok(())
    }

    /// The number of registered installers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no installer is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SqlFunctions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The closures are opaque, so report only how many are registered.
        f.debug_struct("SqlFunctions")
            .field("count", &self.0.len())
            .finish()
    }
}

/// The tables the replica's row-level-security translation split, mapping each
/// logical Postgres name to the physical table holding its rows.
///
/// `pg2sqlite` turns a policy-bearing table into three objects: a suffixed
/// backing table with the rows, a view carrying the original name, and
/// `INSTEAD OF` triggers enforcing the policy. That split exists only here.
/// Postgres enforces its own row-level security and never splits anything, so
/// the wire speaks logical names in both directions and the client rewrites
/// them at its two sync boundaries.
///
/// **Empty is the correct value for a schema with no policies**, which is
/// every schema until one is written, and it renames nothing.
///
/// Build it from the same translation run that emitted the DDL: the
/// `(logical, physical)` pairs come from `Pg2Sqlite::translation_manifest`,
/// and the view names from the throwaway database the build applies the
/// translation to. Pass it to [`ClientConfig::with_policy_tables`]. Deriving
/// it instead from the replica's own schema by looking for the suffix would
/// bake that suffix into connetto, and a suffix that changed upstream would
/// leave the client matching nothing, renaming nothing, and going silently
/// empty.
///
/// The view list is separate from the pairs and is wider than them, because a
/// translation emits views of its own beside the one carrying the logical
/// name. Reading it from the built database rather than deducing it keeps
/// connetto ignorant of how upstream names those, which is the same argument
/// again.
///
/// ```
/// use connetto_client::PolicyTables;
///
/// let tables = PolicyTables::from_translation(
///     [("orders", "orders_rls")],
///     ["orders", "orders_rls_violations"],
/// );
/// assert_eq!(tables.physical("orders"), Some("orders_rls"));
/// assert_eq!(tables.logical("orders_rls"), Some("orders"));
/// assert_eq!(tables.physical("notes"), None, "an unsplit table is absent");
/// ```
#[derive(Debug, Clone, Default)]
pub struct PolicyTables {
    /// Logical to physical, and its exact inverse. Both directions are held
    /// rather than one being searched, because each is on a per-patch path.
    to_physical: HashMap<String, String>,
    to_logical: HashMap<String, String>,
    /// Every view the translation emitted, which is what the replica's own
    /// catalogue is checked against at open.
    views: HashSet<String>,
}

impl PolicyTables {
    /// No split table, which renames nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from the translation's `(logical, physical)` pairs and the views
    /// it emitted.
    ///
    /// Everything is held lowercased, because a name arrives here from three
    /// places that do not agree on case: the Postgres catalog folds an
    /// unquoted identifier down, the parsed DDL keeps what the document wrote,
    /// and SQLite compares identifiers case-insensitively anyway.
    #[must_use]
    pub fn from_translation<I, L, P, V, N>(pairs: I, views: V) -> Self
    where
        I: IntoIterator<Item = (L, P)>,
        L: Into<String>,
        P: Into<String>,
        V: IntoIterator<Item = N>,
        N: Into<String>,
    {
        let mut tables = Self::default();
        for (logical, physical) in pairs {
            let logical = logical.into().to_lowercase();
            let physical = physical.into().to_lowercase();
            tables.to_logical.insert(physical.clone(), logical.clone());
            tables.to_physical.insert(logical, physical);
        }
        tables.views = views
            .into_iter()
            .map(|name| name.into().to_lowercase())
            .collect();
        tables
    }

    /// The physical table holding `logical`'s rows, or `None` when it was not
    /// split.
    #[must_use]
    pub fn physical(&self, logical: &str) -> Option<&str> {
        lookup(&self.to_physical, logical)
    }

    /// The logical name `physical` backs, or `None` when it is not a backing
    /// table.
    #[must_use]
    pub fn logical(&self, physical: &str) -> Option<&str> {
        lookup(&self.to_logical, physical)
    }

    /// Whether no table was split.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.to_physical.is_empty()
    }

    /// The views the translation emitted.
    fn views(&self) -> &HashSet<String> {
        &self.views
    }
}

/// A case-insensitive lookup that allocates only when the caller's name was
/// not already lowercase, which on the patch path it always is.
fn lookup<'map>(map: &'map HashMap<String, String>, key: &str) -> Option<&'map str> {
    map.get(key)
        .or_else(|| map.get(&key.to_lowercase()))
        .map(String::as_str)
}

/// What the client presents at the handshake.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Stable client id, echoed for logging and correlation. Never a trust
    /// input on the server.
    client_id: String,
    /// The login grant, when somebody is signed in. `None` is a caller with no
    /// identity, which the server accepts: it reads whatever the deployment's
    /// policy shows such a caller and writes only where a capability says it
    /// may.
    ///
    /// It is separate from [`capabilities`](Self::capabilities) because only
    /// this one refreshes: a token source, when set, replaces it on every
    /// reconnect. On the wire the two are one undifferentiated list.
    login: Option<Grant>,
    /// Capability grants, for example share keys, presented alongside the
    /// login. Each is checked on its own, and one that fails changes nothing
    /// except what the caller can see.
    capabilities: Vec<Grant>,
    /// The schema version this client build was compiled against, for staleness
    /// detection, or `None` to opt out. When both this and the server's ack
    /// carry a version and they differ, [`ConnettoConnection::connect`] fails
    /// with [`ClientError::SchemaOutdated`] so the app can reload. Either side
    /// being `None` skips the check.
    schema_version: Option<SchemaVersion>,
    /// Custom SQLite functions connetto registers on the replica connection it
    /// opens for this client, before any DDL or insert. Empty by default. A
    /// schema whose column `DEFAULT` calls a function (a `uuidv7` key
    /// generator, say) supplies the matching installer here.
    sql_functions: SqlFunctions,
    /// The tables the replica's row-level-security translation split, from the
    /// same build that produced the DDL. Empty by default, which is right for
    /// a schema with no policies and renames nothing.
    policy_tables: PolicyTables,
    /// What a translated policy means by the caller: the SQLite function name
    /// the deployment mapped `current_setting` onto, and the value it returns.
    ///
    /// `None` when no policy names the caller, which is every schema until one
    /// does. Fixed for the life of the connection, because a replica belongs
    /// to the identity it was named from.
    caller: Option<(String, String)>,
}

impl ClientConfig {
    /// Build a config for a client with the given id, no login, no capabilities,
    /// no schema version, no custom SQL functions, and no split tables.
    #[must_use]
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            login: None,
            capabilities: Vec::new(),
            schema_version: None,
            sql_functions: SqlFunctions::default(),
            policy_tables: PolicyTables::default(),
            caller: None,
        }
    }

    /// The login grant, when somebody is signed in.
    #[must_use]
    pub fn with_login(mut self, login: Option<Grant>) -> Self {
        self.login = login;
        self
    }

    /// What the replica's translated policies mean by the caller.
    ///
    /// `function` is the SQLite function name the build mapped
    /// `current_setting('app.user_id')` onto through pg2sqlite's
    /// `with_session_variable`, and `identity` is what it returns: the same
    /// value the server binds as that setting, so both ends of the policy
    /// compare against one identity. connetto registers it on the replica
    /// connection beside the application's own functions, because the
    /// generated view and its three `INSTEAD OF` triggers call it and would
    /// otherwise fail to resolve on the first read.
    #[must_use]
    pub fn with_caller(mut self, function: impl Into<String>, identity: impl Into<String>) -> Self {
        self.caller = Some((function.into(), identity.into()));
        self
    }

    /// Capability grants presented alongside the login.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: impl IntoIterator<Item = Grant>) -> Self {
        self.capabilities = capabilities.into_iter().collect();
        self
    }

    /// Schema version for staleness detection, or `None` to opt out.
    #[must_use]
    pub fn with_schema_version(mut self, schema_version: Option<SchemaVersion>) -> Self {
        self.schema_version = schema_version;
        self
    }

    /// The tables the replica's row-level-security translation split.
    ///
    /// Build it from `Pg2Sqlite::translation_manifest` in the same build step
    /// that emits the replica DDL. Opening a replica whose views disagree with
    /// this map fails with [`ClientError::PolicyTablesStale`] rather than
    /// syncing into nothing.
    #[must_use]
    pub fn with_policy_tables(mut self, policy_tables: PolicyTables) -> Self {
        self.policy_tables = policy_tables;
        self
    }

    /// Custom SQLite functions registered before any DDL or insert.
    #[must_use]
    pub fn with_sql_functions(mut self, sql_functions: SqlFunctions) -> Self {
        self.sql_functions = sql_functions;
        self
    }
}

/// One observable outcome of [`ConnettoConnection::pump_one`].
#[derive(Debug, Clone, PartialEq)]
pub enum ClientEvent {
    /// Whether this connection can reach a server changed, or is being stated
    /// for the first time.
    ///
    /// The only thing that carries connection state. It arrives when a
    /// connection is opened with no server, when one is attached, and whenever
    /// a transport fails, so an application reading this stream always knows
    /// whether what it is showing is current.
    SyncStatus(SyncStatus),
    /// The server began an initial snapshot for a subscription.
    SnapshotBegin {
        /// Subscription id.
        sub_id: String,
    },
    /// A snapshot chunk was applied to the local replica.
    SnapshotApplied {
        /// Subscription id.
        sub_id: String,
    },
    /// The server finished the initial snapshot; the resume cursor advanced.
    SnapshotEnd {
        /// Subscription id.
        sub_id: String,
    },
    /// A live patch was applied; the resume cursor advanced to `cursor`.
    LivePatch {
        /// Subscription id.
        sub_id: String,
        /// New resume cursor persisted after applying this patch.
        cursor: Cursor,
        /// The compressed patchset exactly as applied, shared cheaply so a
        /// relay can forward it to downstream replicas (the browser tab
        /// mirrors) without re-encoding.
        patchset_zstd: Arc<[u8]>,
    },
    /// An aggregate result update, mirroring the wire
    /// [`AggregateUpdate`](connetto_core::messages::AggregateUpdate) field for
    /// field so a relay can rebuild a faithful frame for a downstream tab.
    Aggregate {
        /// Subscription id.
        sub_id: String,
        /// JSON-encoded aggregate value.
        result_json: String,
        /// Opaque group key, or `None` for a single-group aggregate.
        group_key: Option<Vec<u8>>,
        /// Whether this update replaces the entire result set or upserts a
        /// single group.
        is_full_result: bool,
    },
    /// The server requires a full resync for this subscription.
    FullResync {
        /// Subscription id.
        sub_id: String,
        /// Why the rows had to be replaced, carried so a relay tells its own
        /// consumers the truth rather than restating one cause as another.
        reason: FullResyncReason,
    },
    /// The server reported a non-fatal error attached to a request, most
    /// commonly a rejected subscription. The session stays open.
    NonFatal {
        /// The request or subscription id the error refers to, when the server
        /// attributed it.
        related_to: Option<String>,
        /// Human-readable detail.
        detail: String,
    },
    /// The server refused this request because the caller asked too often.
    ///
    /// The session stays alive and the caller may retry after the stated delay.
    /// This is not a permanent refusal: an honest client backs off and retries.
    RateLimited {
        /// The request or subscription id this refusal refers to, when the server
        /// correlated it to a specific request.
        related_to: Option<String>,
        /// How long to wait before retrying, in milliseconds.
        retry_after_ms: u64,
    },
    /// The server confirmed a mutation as durably applied. Its pending
    /// record is retired, so it will never replay.
    MutationApplied {
        /// The applied mutation's sequence number.
        client_seq: u64,
    },
    /// The server rejected a prior mutation.
    MutationRejected {
        /// The rejected mutation's sequence number.
        client_seq: u64,
        /// Rows the rejected write touched, rolled back locally.
        rows: Vec<AffectedRow>,
    },
    /// The server reported a conflict on a prior mutation.
    MutationConflict {
        /// The conflicting mutation's sequence number.
        client_seq: u64,
        /// Rows the conflicting write touched, rolled back locally.
        rows: Vec<AffectedRow>,
        /// The server's copy of the row the write collided with, absent when
        /// the row is gone. Deserialise `row_json` into the app's row type to
        /// show what the other writer left, or to merge against it.
        server_row: Option<ConflictRow>,
    },
    /// A keepalive reply.
    Pong {
        /// Echoed nonce.
        nonce: u64,
    },
    /// The reconnect driver lost the transport and is about to try again.
    Reconnecting {
        /// 1-based attempt counter since the drop.
        attempt: u32,
    },
    /// The reconnect driver resumed the session and re-declared every live
    /// subscription. Missed changes stream in as ordinary live patches (or a
    /// full resync when the cursor fell out of the server's retention).
    Reconnected,
    /// The server closed the session deliberately, and said why.
    ///
    /// Distinct from [`Closed`](Self::Closed), which is the transport simply
    /// ending. The reconnect driver treats this as a lost connection and backs
    /// off, so a server going away is not hammered with immediate retries. The
    /// reason is what lets an app tell a restart from a sign-out.
    ServerClosed {
        /// Why the server closed the session.
        reason: FatalErrorReason,
    },
    /// The connection closed.
    Closed,
    /// The credential was rejected and refresh could not recover it, so the
    /// local session is over. The reconnect driver stops rather than spinning:
    /// the app must re-authenticate interactively, then either resume (same
    /// `user_id`) or purge and start fresh (an account switch). Terminal, like
    /// [`Closed`](Self::Closed).
    AuthenticationRequired,
    /// Live delivery is temporarily paused. No new rows will arrive until
    /// [`DeliveryResumed`](Self::DeliveryResumed).
    DeliveryPaused {
        /// Why delivery is paused.
        cause: PauseCause,
    },
    /// Live delivery has resumed after a pause.
    DeliveryResumed,
}

/// A primary-key column value carried on a mutation event.
#[derive(Debug, Clone, PartialEq)]
pub enum KeyValue {
    /// SQL NULL.
    Null,
    /// Integer key column.
    Int(i64),
    /// Real key column.
    Real(f64),
    /// Text key column.
    Text(String),
    /// Blob key column.
    Blob(Vec<u8>),
}

impl From<Value<String, Vec<u8>>> for KeyValue {
    fn from(value: Value<String, Vec<u8>>) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Integer(int) => Self::Int(int),
            Value::Real(real) => Self::Real(real),
            Value::Text(text) => Self::Text(text),
            Value::Blob(blob) => Self::Blob(blob),
        }
    }
}

/// A row a mutation touched, identified by table and primary key. Reported when
/// the server rejects or conflicts the mutation and the client rolls it back.
#[derive(Debug, Clone, PartialEq)]
pub struct AffectedRow {
    /// Table containing the row.
    pub table: String,
    /// The row's primary-key column values, in key order.
    pub key: Vec<KeyValue>,
}

/// The outcome of one [`ConnettoConnection::next_event`]: the observed event and
/// the local tables whose rows changed while producing it, so the app knows what
/// to re-query.
#[derive(Debug, Clone)]
pub struct Reactive {
    /// The event pumped from the server.
    pub event: ClientEvent,
    /// Sorted, de-duplicated names of tables whose rows changed.
    pub changed_tables: Vec<String>,
}

/// Conflict resolution for applying authoritative server patches: the server
/// wins on a data or version conflict, and a missing target is skipped so a
/// replayed delete or update is idempotent.
fn server_wins(conflict: ConflictType) -> ConflictAction {
    match conflict {
        ConflictType::Data | ConflictType::Conflict => ConflictAction::Replace,
        _ => ConflictAction::Omit,
    }
}

/// Maximum number of pushed mutations retained for rollback. A server rejection
/// arrives well within this window, so the changeset to invert is still held.
const PENDING_CAP: usize = 256;

/// Conflict resolution for a rollback: a row a concurrent server patch already
/// changed is left as the server left it, so only a cleanly-matching optimistic
/// write is reverted.
fn rollback_omit(_conflict: ConflictType) -> ConflictAction {
    ConflictAction::Omit
}

/// Suspends the capture session for the duration of a server-originated
/// apply (a patch or a rollback), so the session never records what the
/// server already knows. Re-enables on drop, so no exit path can leave
/// capture switched off. `set_enabled` is a plain setter and cannot panic.
struct SuspendedCapture<'s> {
    session: &'s mut Session,
}

impl<'s> SuspendedCapture<'s> {
    fn new(session: &'s mut Session) -> Self {
        session.set_enabled(false);
        Self { session }
    }
}

impl Drop for SuspendedCapture<'_> {
    fn drop(&mut self) {
        self.session.set_enabled(true);
    }
}

/// Rewrite the table names in a diffset, returning the original bytes when
/// nothing matched so an unaffected payload costs no re-encode.
///
/// One parse per renamed payload is the price of the split, and callers skip
/// this entirely when no table was split.
fn rename_diffset(
    bytes: Vec<u8>,
    mut rename: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<u8>, ClientError> {
    let mut parsed = ParsedDiffSet::parse(&bytes)
        .map_err(|err| ClientError::Apply(format!("parsing a diffset to rename it: {err:?}")))?;
    if parsed.rename_tables(&mut rename) == 0 {
        return Ok(bytes);
    }
    Ok(parsed.into())
}

/// Decode a pushed changeset into the rows it touched, each as its table and
/// primary key, for reporting on a rejected or conflicting mutation.
///
/// `tables` maps a split table's backing name back to the logical one the
/// application wrote against, because a capture records what SQLite actually
/// changed and the `INSTEAD OF` triggers change the backing table.
fn affected_rows(changeset: &[u8], tables: &PolicyTables) -> Result<Vec<AffectedRow>, ClientError> {
    let parsed = ParsedDiffSet::parse(changeset)
        .map_err(|err| ClientError::Apply(format!("parsing pushed changeset: {err:?}")))?;
    let named = |physical: &str| tables.logical(physical).unwrap_or(physical).to_owned();
    let rows = match parsed {
        ParsedDiffSet::Changeset(diff) => diff
            .iter()
            .map(|op| AffectedRow {
                table: named(op.table().name()),
                key: op.primary_key().into_iter().map(KeyValue::from).collect(),
            })
            .collect(),
        ParsedDiffSet::Patchset(diff) => diff
            .iter()
            .map(|op| AffectedRow {
                table: named(op.table().name()),
                key: op.primary_key().into_iter().map(KeyValue::from).collect(),
            })
            .collect(),
    };
    Ok(rows)
}

/// Count the ops in a captured changeset for the advisory `MutationHeader`.
fn count_ops(changeset: &[u8]) -> u32 {
    match sqlite_diff_rs::ParsedDiffSet::parse(changeset) {
        Ok(sqlite_diff_rs::ParsedDiffSet::Changeset(diff)) => {
            u32::try_from(diff.iter().count()).unwrap_or(u32::MAX)
        }
        Ok(sqlite_diff_rs::ParsedDiffSet::Patchset(diff)) => {
            u32::try_from(diff.iter().count()).unwrap_or(u32::MAX)
        }
        Err(_) => 0,
    }
}

/// DDL for the replica-local metadata: the persisted resume cursor and the
/// pending mutation records awaiting a durable-apply acknowledgement. Both
/// written only under capture suspension, so they never ride a mutation
/// upload.
const META_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_meta \
    (id INTEGER PRIMARY KEY CHECK (id = 1), cursor BLOB NOT NULL); \
    CREATE TABLE IF NOT EXISTS _connetto_pending \
    (seq INTEGER PRIMARY KEY, changeset BLOB NOT NULL)";

/// The attach name of the local tier database. An internal constant: authored
/// SQL never names it, since bare table names resolve across attached
/// databases and duplicate names across tiers are a generation-time error.
const LOCAL_SCHEMA: &str = "connetto_local";

/// A table name row from an attached schema's catalog.
#[derive(diesel::QueryableByName)]
struct SchemaTableRow {
    /// The table name.
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}

/// The lowercased names of every application table in the attached local tier.
///
/// connetto's own bookkeeping tables are excluded. The relay keeps a per-tab
/// write counter in this database, and a caller subscribing to it or routing a
/// live query at it would be reading connetto's internals as though they were
/// application data. `sqlite_schema` of an attached database has no `table!` to
/// query through, which is why this one stays a catalogue read.
fn local_tier_tables(db: &mut SqliteConnection) -> Result<HashSet<String>, ClientError> {
    let rows: Vec<SchemaTableRow> = diesel::sql_query(format!(
        "SELECT name FROM {LOCAL_SCHEMA}.sqlite_schema WHERE type = 'table' \
         AND name NOT LIKE 'sqlite_%' AND name NOT GLOB '_connetto*'"
    ))
    .load(db)?;
    Ok(rows
        .into_iter()
        .map(|row| row.name.to_lowercase())
        .collect())
}

diesel::table! {
    /// SQLite's own catalogue of the main database, typed for the one question
    /// connetto asks it: which objects are views rather than tables. The
    /// attached local tier needs a schema-qualified name, which `table!`
    /// cannot express, so `local_tier_tables` stays a raw read and this
    /// serves `main` only.
    #[sql_name = "sqlite_schema"]
    sqlite_catalog (name) {
        /// The object kind: `table`, `view`, `index` or `trigger`.
        #[sql_name = "type"]
        kind -> diesel::sql_types::Text,
        /// The object name.
        name -> diesel::sql_types::Text,
    }
}

/// Refuse to open when the replica's views and the translation's disagree.
///
/// A translation that split a table emits a view carrying the logical name,
/// plus views of its own beside it, and the artifact lists all of them. So the
/// two sets must be equal, and either direction of a difference means the map
/// and the DDL came from different builds. Both are silent if allowed
/// through: a view the map does not name is applied into directly, reports
/// success and drops every row, and a mapped name with no view renames a patch
/// onto a table that is not there.
fn check_policy_tables(
    db: &mut SqliteConnection,
    tables: &PolicyTables,
) -> Result<(), ClientError> {
    let present: HashSet<String> = sqlite_catalog::table
        .select(sqlite_catalog::name)
        .filter(sqlite_catalog::kind.eq("view"))
        .load::<String>(db)?
        .into_iter()
        .map(|name| name.to_lowercase())
        .collect();
    let declared = tables.views();
    if &present == declared {
        return Ok(());
    }
    let mut unmapped: Vec<String> =
        present
            .difference(declared)
            .map(|name| format!("{name} is a view the build's translation does not account for"))
            .chain(declared.difference(&present).map(|name| {
                format!("{name} is in the build's translation but not in this replica")
            }))
            .collect();
    unmapped.sort();
    Err(ClientError::PolicyTablesStale { unmapped })
}

/// Register the SQLite function a translated policy calls for the caller's
/// identity, returning `identity` for the life of the connection.
///
/// The name is the deployment's, chosen when it told pg2sqlite what
/// `current_setting('app.user_id')` means locally, so it cannot be a function
/// declared here: it is registered under whatever the build mapped. Marked
/// deterministic because it is, being a constant per replica, which lets
/// SQLite hoist it out of the policy predicate that otherwise runs per row,
/// and innocuous because the generated view and triggers are exactly the
/// schema objects it has to be callable from.
fn register_caller(
    db: &mut SqliteConnection,
    function: &str,
    identity: String,
) -> Result<(), ClientError> {
    db.register_noarg_sql_function::<diesel::sql_types::Text, _, _>(
        function,
        SqliteFunctionBehavior::DETERMINISTIC | SqliteFunctionBehavior::INNOCUOUS,
        move || identity.clone(),
    )
    .map_err(|e| ClientError::Session(format!("registering the caller function: {e}")))
}

/// Whether `name` is SQLite's or connetto's own, rather than the application's.
///
/// The Rust counterpart of the exclusion [`local_tier_tables`] writes in SQL,
/// down to the case rules the two operators have: `LIKE 'sqlite_%'` is
/// ASCII-case-insensitive with `_` standing for one character, so a table named
/// exactly `sqlite` is the application's, and `GLOB '_connetto*'` is
/// case-sensitive with `_` a literal.
fn is_internal_table(name: &str) -> bool {
    let sqlite_own = name.len() > 6
        && name
            .get(..6)
            .is_some_and(|head| head.eq_ignore_ascii_case("sqlite"));
    sqlite_own || name.starts_with("_connetto")
}

/// `s` without `prefix`, matched case-insensitively, or `None`. Byte-indexed
/// through `get` so a multibyte character at the boundary cannot panic.
fn strip_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    s.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &s[prefix.len()..])
}

/// Requalify one `CREATE TABLE` statement into the local tier schema, so an
/// unqualified DDL document lands in the attached database instead of `main`.
fn qualify_create_table(statement: &str) -> Result<String, ClientError> {
    let rest = strip_ci(statement, "CREATE TABLE").ok_or_else(|| {
        ClientError::Session(format!(
            "local tier DDL supports only CREATE TABLE statements, got: {statement}"
        ))
    })?;
    let (if_not_exists, name_part) = match strip_ci(rest.trim_start(), "IF NOT EXISTS") {
        Some(after) => ("IF NOT EXISTS ", after.trim_start()),
        None => ("", rest.trim_start()),
    };
    Ok(format!(
        "CREATE TABLE {if_not_exists}{LOCAL_SCHEMA}.{name_part}"
    ))
}

/// A one-column existence probe, for asking whether a row is still covered.
#[derive(diesel::QueryableByName)]
struct Present {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    #[allow(dead_code)]
    present: i32,
}

/// The primary-key column positions of `table`, in key order.
fn pk_ordinals(table: &TableSchema<String>) -> Vec<usize> {
    let mut ordinals: Vec<(usize, usize)> = (0..table.number_of_columns())
        .filter_map(|col| table.primary_key_index(col).map(|pos| (pos, col)))
        .collect();
    ordinals.sort_unstable();
    ordinals.into_iter().map(|(_, col)| col).collect()
}

/// The replica's own column names for `table`, in ordinal order.
fn replica_columns(db: &mut SqliteConnection, table: &str) -> Result<Vec<String>, ClientError> {
    #[derive(diesel::QueryableByName)]
    struct Column {
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
    }
    let quoted = table.replace('\'', "''");
    let rows: Vec<Column> = diesel::sql_query(format!(
        "SELECT name FROM pragma_table_info('{quoted}') ORDER BY cid"
    ))
    .load(db)?;
    Ok(rows.into_iter().map(|row| row.name).collect())
}

/// Record `cursor` in the replica's metadata table.
///
/// **Invariant: a resume position is never recorded for data this replica has
/// not applied.** A resume position is a promise that everything up to it is
/// already here, and the next attach asks the server only for what follows, so
/// recording one early loses the rows in between with nothing on either side
/// able to notice.
///
/// Two callers hold it two ways. `apply_patch` writes the rows and the cursor
/// in one transaction, so a crash cannot separate them. The `SnapshotEnd` arm
/// of `handle_control` has no rows of its own to bind to and relies on the
/// server having sent the snapshot first, which it does because the completion
/// frame shares the delivery queue with the rows it completes (R33). Asserted
/// by `no_resume_position_is_persisted_for_rows_that_never_arrived`.
fn persist_cursor(db: &mut SqliteConnection, cursor: &Cursor) -> Result<(), ClientError> {
    diesel::sql_query(
        "INSERT INTO _connetto_meta (id, cursor) VALUES (1, ?) \
         ON CONFLICT (id) DO UPDATE SET cursor = excluded.cursor",
    )
    .bind::<diesel::sql_types::Binary, _>(cursor.as_bytes())
    .execute(db)?;
    Ok(())
}

/// The cursor persisted by a previous run against this replica, if any.
fn load_cursor(db: &mut SqliteConnection) -> Option<Cursor> {
    #[derive(diesel::QueryableByName)]
    struct MetaRow {
        #[diesel(sql_type = diesel::sql_types::Binary)]
        cursor: Vec<u8>,
    }
    let rows: Vec<MetaRow> = diesel::sql_query("SELECT cursor FROM _connetto_meta WHERE id = 1")
        .load(db)
        .ok()?;
    rows.into_iter()
        .next()
        .map(|row| Cursor::new(row.cursor))
        .filter(|cursor| !cursor.is_empty())
}

/// The client sequence as the storage integer.
fn seq_storage(seq: u64) -> Result<i64, ClientError> {
    i64::try_from(seq).map_err(|_| ClientError::Session("sequence overflows storage".to_owned()))
}

/// Record a pushed mutation's changeset durably, so a restart can replay it
/// until the server acknowledges the durable apply.
fn persist_pending(
    db: &mut SqliteConnection,
    seq: u64,
    changeset: &[u8],
) -> Result<(), ClientError> {
    diesel::sql_query("INSERT OR REPLACE INTO _connetto_pending (seq, changeset) VALUES (?, ?)")
        .bind::<diesel::sql_types::BigInt, _>(seq_storage(seq)?)
        .bind::<diesel::sql_types::Binary, _>(changeset)
        .execute(db)?;
    Ok(())
}

/// Retire a pending mutation record: acknowledged, rejected, or rolled back.
fn delete_pending(db: &mut SqliteConnection, seq: u64) -> Result<(), ClientError> {
    diesel::sql_query("DELETE FROM _connetto_pending WHERE seq = ?")
        .bind::<diesel::sql_types::BigInt, _>(seq_storage(seq)?)
        .execute(db)?;
    Ok(())
}

/// The pending mutations persisted by a previous run against this replica.
fn load_pending(db: &mut SqliteConnection) -> Result<BTreeMap<u64, Vec<u8>>, ClientError> {
    #[derive(diesel::QueryableByName)]
    struct PendingRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        seq: i64,
        #[diesel(sql_type = diesel::sql_types::Binary)]
        changeset: Vec<u8>,
    }
    let rows: Vec<PendingRow> =
        diesel::sql_query("SELECT seq, changeset FROM _connetto_pending ORDER BY seq").load(db)?;
    Ok(rows
        .into_iter()
        .filter_map(|row| u64::try_from(row.seq).ok().map(|seq| (seq, row.changeset)))
        .collect())
}

/// What a completed handshake told the client.
struct HandshakeOk {
    connection_id: String,
    session_handle: String,
    resume_token: String,
    watermark: Option<u64>,
    schema_version: Option<SchemaVersion>,
}

/// Run the opening handshake over `transport`: send the hello (carrying the
/// grants, the resume cursor and, on a resume, the credential proving the
/// previous run's handle) and read the ack.
///
/// `now` is the epoch second the replica's clock reports, used to drop a share
/// key whose expiry has already passed.
///
/// Shared by the first connect and every resume.
async fn exchange_handshake<T>(
    transport: &mut T,
    config: &ClientConfig,
    token_source: Option<&AccessTokenSource>,
    resume: Option<&Cursor>,
    resume_token: Option<&str>,
    now: i64,
) -> Result<HandshakeOk, ClientError>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    let mut grants = Vec::with_capacity(1 + config.capabilities.len());
    match token_source {
        Some(source) => grants.push(Grant::new(source.token().await?)),
        None => grants.extend(config.login.clone()),
    }
    // A dead share key can only draw a refusal, and the refusal is the one
    // honest source of the signal R36 counts, so it is worth not sending. The
    // login grant is not filtered: its refresh is `token_source`'s job, and a
    // client with no fresh token still has to present what it has and be told.
    grants.extend(
        config
            .capabilities
            .iter()
            .filter(|grant| !grant_expiry::has_expired(grant, now))
            .cloned(),
    );
    let mut handshake =
        Handshake::new(PROTOCOL_VERSION, config.client_id.clone()).with_grants(grants);
    if let Some(cursor) = resume {
        handshake = handshake.with_cursor(cursor.clone());
    }
    // The credential proving the previous run's handle is this caller's. The
    // server refuses one it did not sign, and an identified run takes its
    // handle from the login grant instead.
    if let Some(token) = resume_token {
        handshake = handshake.with_resume_token(token.to_owned());
    }
    transport
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .map_err(|e| ClientError::Transport(e.to_string()))?;
    match transport
        .recv()
        .await
        .map_err(|e| ClientError::Transport(e.to_string()))?
    {
        Some(IncomingFrame::Control(ControlMessage::HandshakeAck(ack))) => {
            // Server-gated staleness detection: when the server advertises a
            // schema version, the client must declare the same one. A client
            // that declares none is stale against a versioned server, so a
            // build that forgot to bake its version fails loudly instead of
            // mis-parsing. A server that declares none opts out and skips the
            // check. This runs before any pending replay, so a stale build
            // never pushes old-schema changesets to a new-schema server.
            match ack.schema_version.as_ref() {
                Some(server) if config.schema_version.as_ref() != Some(server) => {
                    return Err(ClientError::SchemaOutdated {
                        client: config.schema_version.clone(),
                        server: server.clone(),
                    });
                }
                _ => {}
            }
            Ok(HandshakeOk {
                connection_id: ack.connection_id,
                session_handle: ack.session_token,
                resume_token: ack.resume_token,
                watermark: ack.last_applied_seq,
                schema_version: ack.schema_version,
            })
        }
        Some(_) => Err(ClientError::Protocol("expected handshake ack".into())),
        None => Err(ClientError::Protocol("connection closed before ack".into())),
    }
}

/// Install an update hook recording the name of every table whose rows change on
/// `conn` into the shared `changed` set. Feeds the reactivity signal that tells
/// the app which tables to re-query.
fn install_change_tracker(conn: &mut SqliteConnection, changed: &Arc<Mutex<HashSet<String>>>) {
    let sink = Arc::clone(changed);
    conn.on_update(
        SqliteUpdateRouter::new().on_any(SqliteChangeOps::ALL, move |event| {
            if let Ok(mut tables) = sink.lock() {
                tables.insert(event.table_name.to_owned());
            }
        }),
    );
}

/// What a dropped transport does not touch: the run the server attributed this
/// caller's work to.
///
/// Separate from [`Wire`] because these three deliberately outlive a socket.
/// The handle survives a reconnect by design, and the resume credential exists
/// precisely to be presented again so the run continues rather than starting
/// over, so emptying them when a transport dies would silently turn every
/// reconnect into a new session.
struct Run {
    /// The durable handle of this run, in the clear, for the application to
    /// read: a synced row written before anybody signed in is attributed to it.
    session_handle: String,
    /// The credential proving that handle is this caller's, presented again on
    /// every later attach so the run's operational state (its per-subscription
    /// cursors and pending buffer) continues rather than starting over. A
    /// bearer secret, so it never goes into the replica.
    resume_token: String,
    /// The server's schema version from the handshake ack, kept so a relay can
    /// forward it verbatim to its tabs and a stale build can be detected
    /// against the baked schema.
    schema_version: Option<SchemaVersion>,
}

/// One live socket and the label the server gave it.
///
/// Present exactly while this connection can reach a server. Absent before the
/// first [`ConnettoConnection::attach`] and again the moment a transport
/// fails, which is what makes the offline half of
/// [`SyncStatus`] something the connection itself can state rather than
/// something each layer above has to infer.
struct Wire<T> {
    transport: T,
    connection_id: String,
}

/// A sync client bound to one local SQLite database, with or without a server.
///
/// It exists before any transport does. Opening the replica, serving reads from
/// it and capturing writes into the pending queue all work with nothing to talk
/// to, and [`attach`](Self::attach) is what later gives it a server. That is
/// what lets an application start with no network and sync when one appears.
pub struct ConnettoConnection<T: Transport> {
    /// The live socket, absent when no server is reachable.
    wire: Option<Wire<T>>,
    /// The run this caller's work belongs to, absent until a first handshake
    /// and kept across every later drop.
    run: Option<Run>,
    /// State changes waiting to be handed to the application, drained ahead of
    /// the transport so an offline connection can still report itself.
    notices: VecDeque<ClientEvent>,
    // `session` is declared before `db` so it drops first: it holds a raw
    // pointer into the connection's SQLite handle and must not outlive it.
    session: Session,
    db: SqliteConnection,
    last_cursor: Option<Cursor>,
    next_seq: u64,
    /// Set by the commit hook whenever a write commits, so the driver knows
    /// to look for a captured mutation to flush. Server patch applies trip it
    /// too, harmlessly: an empty capture session never uploads.
    dirty: Arc<AtomicBool>,
    /// Names of tables whose rows changed since the last drain, from the
    /// connection's update hook (local writes and server patches alike).
    changed: Arc<Mutex<HashSet<String>>>,
    /// Transaction bookkeeping for the diesel `Connection` impl. The manager
    /// issues `BEGIN`/`COMMIT` through this connection, which delegate to `db`.
    transaction_state: AnsiTransactionManager,
    /// Changesets of pushed mutations awaiting resolution, keyed by `client_seq`,
    /// so a server rejection can be inverted and rolled back locally. Bounded by
    /// `PENDING_CAP`.
    pending: BTreeMap<u64, Vec<u8>>,
    /// Identity presented at handshake, kept for re-handshakes on resume.
    config: ClientConfig,
    /// Optional source of fresh access tokens, consulted on every resume so a
    /// reconnect silently refreshes. `None` reuses `config.login`.
    token_source: Option<AccessTokenSource>,
    /// Lowercased names of the tables in the device-private database the
    /// replica named, empty when it named none. Live
    /// queries dispatch on it: a local table never reaches the wire.
    local_tables: HashSet<String>,
}

impl<T> ConnettoConnection<T>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    /// Connect: open the local replica, hook the capture session, and run the
    /// handshake.
    ///
    /// `replica` says where the replica lives, whether its pages are encrypted,
    /// and what device-private database sits beside it, as one value, so a
    /// connection cannot exist without its opener having stated all three and
    /// cannot pair a durable device-private database with storage that has no
    /// key. `sqlite_ddl` creates the local schema. Pass `resume` to continue
    /// from a persisted cursor on reconnect.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a database, cipher, session, transport, or handshake
    /// failure. [`ClientError::ReplicaUndecryptable`] when an existing replica
    /// does not open under the key given.
    pub async fn connect<S: ReplicaStorage>(
        transport: T,
        replica: &Replica<'_, S>,
        sqlite_ddl: &str,
        config: &ClientConfig,
        resume: Option<Cursor>,
    ) -> Result<Self, ClientError> {
        let mut conn = Self::open_inner(replica, Some(sqlite_ddl), config, resume)?;
        conn.attach(transport).await?;
        Ok(conn)
    }

    /// Connect to a replica that already carries its schema, executing no
    /// DDL: a previous run's replica on reconnect.
    ///
    /// `replica` must describe the replica as it was created. See
    /// [`connect`](Self::connect) for why it is stated rather than inferred.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a database, cipher, session, transport, or handshake
    /// failure. [`ClientError::ReplicaUndecryptable`] when the replica does not
    /// open under the key given.
    pub async fn connect_existing<S: ReplicaStorage>(
        transport: T,
        replica: &Replica<'_, S>,
        config: &ClientConfig,
        resume: Option<Cursor>,
    ) -> Result<Self, ClientError> {
        let mut conn = Self::open_inner(replica, None, config, resume)?;
        conn.attach(transport).await?;
        Ok(conn)
    }

    /// Open the replica with no server, serving local reads at once.
    ///
    /// The connection exists and works before anything is reachable: reads
    /// answer from the replica, writes capture into the pending queue, and
    /// [`attach`](Self::attach) later hands it a transport, which replays
    /// whatever queued up. This is what lets an application start offline.
    ///
    /// `sqlite_ddl` creates the local schema on a first boot. See
    /// [`connect`](Self::connect) for why `replica` states all three of where
    /// it lives, whether it is encrypted, and what sits beside it.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a database, cipher or session failure.
    /// [`ClientError::ReplicaUndecryptable`] when an existing replica does not
    /// open under the key given.
    pub fn open<S: ReplicaStorage>(
        replica: &Replica<'_, S>,
        sqlite_ddl: &str,
        config: &ClientConfig,
        resume: Option<Cursor>,
    ) -> Result<Self, ClientError> {
        let mut conn = Self::open_inner(replica, Some(sqlite_ddl), config, resume)?;
        conn.notices
            .push_back(ClientEvent::SyncStatus(SyncStatus::Offline));
        Ok(conn)
    }

    /// Open a replica that already carries its schema, with no server.
    ///
    /// [`open`](Self::open) for a replica a previous run created.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a database, cipher or session failure.
    /// [`ClientError::ReplicaUndecryptable`] when the replica does not open
    /// under the key given.
    pub fn open_existing<S: ReplicaStorage>(
        replica: &Replica<'_, S>,
        config: &ClientConfig,
        resume: Option<Cursor>,
    ) -> Result<Self, ClientError> {
        let mut conn = Self::open_inner(replica, None, config, resume)?;
        conn.notices
            .push_back(ClientEvent::SyncStatus(SyncStatus::Offline));
        Ok(conn)
    }

    /// Shared open body: open the database, unlock the page codec, apply the
    /// schema when it arrives as DDL, and hook the capture session. No
    /// handshake happens here, which is the whole point.
    fn open_inner<S: ReplicaStorage>(
        replica: &Replica<'_, S>,
        sqlite_ddl: Option<&str>,
        config: &ClientConfig,
        resume: Option<Cursor>,
    ) -> Result<Self, ClientError> {
        let mut db = SqliteConnection::establish(replica.path())
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        // First, ahead of everything: setting the journal mode reads the
        // database header, which is ciphertext until the codec is keyed. Every
        // database later attached to this connection inherits the key from an
        // `ATTACH` with no `KEY` clause, so the local tier and the relay hub's
        // own state are covered by this one call.
        if let Some(key) = replica.key() {
            cipher::unlock(&mut db, key)?;
        }
        db.batch_execute("PRAGMA journal_mode=WAL")?;
        // Register app-supplied functions before any DDL or insert, so a
        // column DEFAULT that calls one fires on the first write.
        config
            .sql_functions
            .install(&mut db)
            .map_err(|e| ClientError::Session(e.to_string()))?;
        if let Some((function, identity)) = &config.caller {
            register_caller(&mut db, function, identity.clone())?;
        }
        if let Some(ddl) = sqlite_ddl {
            db.batch_execute(ddl)?;
        }
        // After the schema exists, whether this open created it or a previous
        // run did: the views are what the map has to agree with.
        check_policy_tables(&mut db, &config.policy_tables)?;
        db.batch_execute(META_DDL)?;
        db.batch_execute(subscriptions::SUBSCRIPTION_DDL)?;
        // Once per open, before anything can re-claim: a watch the previous run
        // died still holding gets its countdown from now, so the UI has this
        // run to re-claim it and an abandoned one retires. Ahead of the capture
        // session, which does not exist yet, so nothing has to be suspended.
        subscriptions::anchor_launch(&mut db)?;
        // An explicit resume cursor wins. Otherwise the replica remembers
        // its own resume point, so reopening a persisted replica (a file, an
        // OPFS import) continues where the previous run stopped. Pending
        // mutations persisted by a previous run come along for replay.
        let resume = resume.or_else(|| load_cursor(&mut db));
        let pending = load_pending(&mut db)?;
        let changed: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let dirty = Arc::new(AtomicBool::new(false));
        install_change_tracker(&mut db, &changed);
        {
            let dirty = Arc::clone(&dirty);
            db.on_commit(move || {
                dirty.store(true, Ordering::Relaxed);
                CommitDecision::Proceed
            });
        }
        let mut session = db
            .create_session()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        session
            .attach_all()
            .map_err(|e| ClientError::Session(e.to_string()))?;

        let next_seq = pending.last_key_value().map_or(0, |(seq, _)| seq + 1);
        let mut conn = Self {
            wire: None,
            run: None,
            notices: VecDeque::new(),
            session,
            db,
            last_cursor: resume,
            next_seq,
            dirty,
            changed,
            transaction_state: AnsiTransactionManager::default(),
            pending,
            config: config.clone(),
            token_source: None,
            local_tables: HashSet::new(),
        };
        conn.attach_tier(replica.tier())?;
        Ok(conn)
    }

    /// Attach the device-private database the replica named, if any.
    ///
    /// Driven from `connect` rather than exposed, because which one is legal
    /// depends on what the replica keeps at rest and only the replica knows
    /// that. The capture session is bound to `main`, so writes to these tables
    /// are physically incapable of being uploaded, rejected, or rolled back,
    /// and live queries over them are served locally with no subscription.
    ///
    /// The tier shares the replica's cipher, always: SQLite gives an attached
    /// database the connection's VFS and the page codec gives it the main
    /// database's derived key. One device, one key, because two would double the
    /// lost-key failure modes and isolate nothing, since both entries would sit
    /// in the same key store behind the same wrap.
    fn attach_tier(&mut self, tier: &Tier<'_>) -> Result<(), ClientError> {
        match tier {
            Tier::None => Ok(()),
            Tier::Existing { path } => {
                let create_was_enabled = self.db.is_attach_create_enabled()?;
                if create_was_enabled {
                    self.db.set_attach_create_enabled(false)?;
                }
                let attached = self.db.attach_database(path, LOCAL_SCHEMA);
                if create_was_enabled {
                    self.db.set_attach_create_enabled(true)?;
                }
                attached?;
                self.local_tables = local_tier_tables(&mut self.db)?;
                Ok(())
            }
            Tier::Create { path, ddl } => {
                self.db.attach_database(path, LOCAL_SCHEMA)?;
                // An attached database with no tables is a fresh one, on every
                // target and with no filesystem probe, which wasm does not have.
                if local_tier_tables(&mut self.db)?.is_empty() {
                    for statement in ddl.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                        self.db.batch_execute(&qualify_create_table(statement)?)?;
                    }
                }
                self.local_tables = local_tier_tables(&mut self.db)?;
                Ok(())
            }
        }
    }

    /// Attach a source of fresh access tokens, consulted on every
    /// [`attach`](Self::attach) so a reconnect silently refreshes the access
    /// token from the stored refresh token with no user interaction. The first
    /// connect used `config.login`, so a native client sets that to a token it
    /// acquired interactively and this to its silent-refresh source.
    #[must_use]
    pub fn with_token_source(mut self, source: AccessTokenSource) -> Self {
        self.token_source = Some(source);
        self
    }

    /// Give this connection a transport: greet the server with the highest
    /// applied cursor and keep every piece of local state (replica, capture
    /// session, pending mutations, sequence counter).
    ///
    /// One method for both arrivals, because they are one operation. A
    /// connection opened offline reaching a server for the first time and a
    /// live connection replacing a dropped transport differ only in whether a
    /// resume credential exists to present, and the server settles the rest.
    ///
    /// The ack's durable watermark retires every pending mutation the server
    /// already applied and the rest are replayed, so the upload path stays
    /// exactly-once across the gap, however long it was. The dirty flag is
    /// forced so writes captured but never pushed re-flush. A re-declared
    /// subscription replays what the server retained past the cursor, or
    /// full-resyncs.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a transport or handshake failure. The connection
    /// keeps whatever it had, so a caller can try again with another
    /// transport, and one that had nothing stays usable for local reads.
    pub async fn attach(&mut self, mut transport: T) -> Result<(), ClientError> {
        let now = clock::now_secs(&mut self.db)?;
        let ack = exchange_handshake(
            &mut transport,
            &self.config,
            self.token_source.as_ref(),
            self.last_cursor.as_ref(),
            self.run.as_ref().map(|run| run.resume_token.as_str()),
            now,
        )
        .await?;
        let watermark = ack.watermark;
        self.run = Some(Run {
            session_handle: ack.session_handle,
            resume_token: ack.resume_token,
            schema_version: ack.schema_version,
        });
        self.wire = Some(Wire {
            transport,
            connection_id: ack.connection_id,
        });
        self.notices
            .push_back(ClientEvent::SyncStatus(SyncStatus::Connected));
        // Relaxed: same-task flag, no ordering dependency.
        self.dirty.store(true, Ordering::Relaxed);
        self.reconcile_pending(watermark).await?;
        self.replay_subscriptions().await?;
        Ok(())
    }

    /// Bring the pending mutations in line with the server's durable
    /// watermark after a handshake: retire everything at or below it (those
    /// applied, so the optimistic local rows are correct), replay the rest
    /// in order, and keep the sequence counter above every number the server
    /// has seen. The server's watermark makes a duplicated replay idempotent.
    async fn reconcile_pending(&mut self, watermark: Option<u64>) -> Result<(), ClientError> {
        if let Some(watermark) = watermark {
            let retired: Vec<u64> = self
                .pending
                .range(..=watermark)
                .map(|(seq, _)| *seq)
                .collect();
            if !retired.is_empty() {
                let _suspended = SuspendedCapture::new(&mut self.session);
                for seq in retired {
                    self.pending.remove(&seq);
                    delete_pending(&mut self.db, seq)?;
                }
            }
            self.next_seq = self.next_seq.max(watermark.saturating_add(1));
        }
        let replays: Vec<(u64, Vec<u8>)> = self
            .pending
            .iter()
            .map(|(seq, changeset)| (*seq, changeset.clone()))
            .collect();
        for (seq, changeset) in replays {
            self.send_mutation(seq, &changeset).await?;
        }
        Ok(())
    }

    /// The live socket, or the not-connected refusal.
    ///
    /// Every method that speaks to the server goes through this, so the offline
    /// case is stated once rather than at each of them.
    fn wire(&mut self) -> Result<&mut Wire<T>, ClientError> {
        self.wire.as_mut().ok_or(ClientError::NotConnected)
    }

    /// Judge one transport result: a failure means this socket is gone, so the
    /// wire is dropped and the change is announced before the error surfaces.
    ///
    /// The run is deliberately kept, because the next attach presents its
    /// resume credential to continue rather than start over.
    fn judge<V, E: core::fmt::Display>(&mut self, result: Result<V, E>) -> Result<V, ClientError> {
        result.map_err(|err| {
            self.disconnected();
            ClientError::Transport(err.to_string())
        })
    }

    /// Drop the live socket and announce it, once.
    fn disconnected(&mut self) {
        if self.wire.take().is_some() {
            self.notices
                .push_back(ClientEvent::SyncStatus(SyncStatus::Offline));
        }
    }

    /// Whether a handshake currently stands.
    ///
    /// False before the first [`attach`](Self::attach) and after a transport
    /// drops. Local reads and writes work either way.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.wire.is_some()
    }

    /// The per-connection routing label from the handshake ack, or `None` while
    /// no server has been reached. This is not identity and must not be treated
    /// as such.
    #[must_use]
    pub fn connection_id(&self) -> Option<&str> {
        self.wire.as_ref().map(|wire| wire.connection_id.as_str())
    }

    /// The durable session handle from the handshake ack, or `None` while no
    /// server has been reached.
    ///
    /// One unbroken run of one caller, and the key the server's resume, its
    /// per-subscription cursors, and the exactly-once watermark all address.
    /// Unlike [`connection_id`](Self::connection_id), it survives a reconnect.
    #[must_use]
    pub fn session_handle(&self) -> Option<&str> {
        self.run.as_ref().map(|run| run.session_handle.as_str())
    }

    /// End this run because somebody is signing in, handing back the handle it
    /// wrote under.
    ///
    /// Pushes whatever is queued first and refuses the switch when anything is
    /// still unsent, because signing in mints a new handle and the old run's
    /// queued writes would be stranded under one nobody presents again. This is
    /// the unsynced guard the teardown primitives already apply, moved to the
    /// one other moment where writes can still be uploaded.
    ///
    /// Nothing is carried across. Synced rows are discarded and re-snapshotted
    /// under the new identity, and the local copy is changing from in memory to
    /// identity-named at the same moment, so a fresh snapshot happens anyway.
    /// The caller therefore opens a new connection against the identity's own
    /// replica rather than mutating this one, which is why no adoption
    /// primitive exists.
    ///
    /// What connetto hands over is the handle, and it performs no merge. A row
    /// the run wrote before anybody signed in, a shopping cart being the
    /// canonical one, is attributed to this handle on the server, and only the
    /// application knows which of its tables hold such rows, what to do when
    /// one already exists for the incoming user, and what a cart even is.
    ///
    /// # Errors
    ///
    /// [`SignInRefused::Unsent`] when writes remain queued after the push, in
    /// which case nothing has changed and the caller may retry once the
    /// connection is healthy. [`SignInRefused::Push`] when the push itself
    /// failed.
    pub async fn end_run_for_sign_in(&mut self) -> Result<String, SignInRefused> {
        self.push()
            .await
            .map_err(|err| SignInRefused::Push(err.to_string()))?;
        let unsent = self.unsynced();
        if !unsent.is_empty() {
            return Err(SignInRefused::Unsent(unsent));
        }
        self.session_handle()
            .map(ToOwned::to_owned)
            .ok_or(SignInRefused::NotConnected)
    }

    /// The server's schema version from the handshake ack, or `None` when no
    /// server has been reached or the server declared none.
    #[must_use]
    pub fn schema_version(&self) -> Option<&SchemaVersion> {
        self.run
            .as_ref()
            .and_then(|run| run.schema_version.as_ref())
    }

    /// The application's local connection, for ordinary diesel reads and writes.
    /// Writes here are captured for upload on the next [`push`](Self::push).
    pub const fn conn(&mut self) -> &mut SqliteConnection {
        &mut self.db
    }

    /// The highest resume cursor applied so far, if any.
    #[must_use]
    pub const fn cursor(&self) -> Option<&Cursor> {
        self.last_cursor.as_ref()
    }

    /// Whether this replica has ever received data from a server.
    ///
    /// False on a first run that has never reached one. An empty read then
    /// means the rows were never fetched, not that there are none, and only
    /// the application knows which of those two sentences to show. Device
    /// private tables are unaffected: their rows are authoritative with or
    /// without a server.
    #[must_use]
    pub const fn has_ever_synced(&self) -> bool {
        self.last_cursor.is_some()
    }

    /// The sequence numbers of mutations captured locally but not yet
    /// confirmed durable by the server. Non-empty means a teardown would lose
    /// data, so logout and expiry surface these before purging the replica.
    #[must_use]
    pub fn unsynced(&self) -> Vec<u64> {
        self.pending.keys().copied().collect()
    }

    /// The lowercased names of the tables in the attached local tier, empty
    /// when no tier is attached.
    #[must_use]
    pub const fn local_tables(&self) -> &HashSet<String> {
        &self.local_tables
    }

    /// Declare a subscription from a SQLite-dialect `SELECT`, the same dialect
    /// used against the local replica. The server reverse-translates it to
    /// Postgres and classifies it: a row projection streams patchsets into the
    /// local replica (observe [`ClientEvent::LivePatch`] and read rows with
    /// diesel), while a single scalar aggregate pushes each value as a
    /// [`ClientEvent::Aggregate`] and leaves the replica untouched. A query that
    /// cannot be translated or that `subql` rejects surfaces as a
    /// [`ClientEvent::NonFatal`] with the session intact.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the subscribe frame cannot be sent.
    pub async fn subscribe(&mut self, sub_id: &str, query: &str) -> Result<(), ClientError> {
        self.subscribe_spec(sub_id, SubscriptionSpec::new(query))
            .await
    }

    /// Declare a subscription from a full [`SubscriptionSpec`], carrying the
    /// query's `?` placeholder bind values alongside the SQLite-dialect SQL.
    /// [`subscribe`](Self::subscribe) is the plain-string form of this.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the subscribe frame cannot be sent.
    pub async fn subscribe_spec(
        &mut self,
        sub_id: &str,
        spec: SubscriptionSpec,
    ) -> Result<(), ClientError> {
        self.subscribe_spec_with_grace(sub_id, spec, subscriptions::DEFAULT_GRACE)
            .await
    }

    /// Declare a subscription that outlives its last handle by `grace` rather
    /// than by the default.
    ///
    /// Clamped to [`MAX_GRACE`]: wanting to outlive
    /// the cap is by definition a pin, and the cap is what enforces that
    /// boundary mechanically rather than by documentation.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the subscribe frame cannot be sent.
    pub async fn subscribe_spec_with_grace(
        &mut self,
        sub_id: &str,
        spec: SubscriptionSpec,
        grace: Duration,
    ) -> Result<(), ClientError> {
        // Recorded before it is sent, and recorded whether or not it can be
        // sent. A subscription declared with no server reachable is a
        // declaration, not a failure, and it takes effect on the first
        // connection.
        {
            let _suspended = SuspendedCapture::new(&mut self.session);
            subscriptions::remember(&mut self.db, sub_id, &spec, grace)?;
        }
        if self.is_connected() {
            self.send_subscribe(sub_id, spec).await?;
        }
        Ok(())
    }

    /// Put one `Subscribe` frame on the wire.
    async fn send_subscribe(
        &mut self,
        sub_id: &str,
        spec: SubscriptionSpec,
    ) -> Result<(), ClientError> {
        self.wire()?
            .transport
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: sub_id.to_owned(),
                spec,
            }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// Record `sub_id` as a pin under the application's `name`.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica rejects the write.
    pub fn pin_subscription(
        &mut self,
        name: &str,
        sub_id: &str,
        spec: &SubscriptionSpec,
    ) -> Result<(), ClientError> {
        let _suspended = SuspendedCapture::new(&mut self.session);
        subscriptions::pin(&mut self.db, name, sub_id, spec)
    }

    /// End the pin under `name`, leaving its subscription on the ordinary
    /// grace path. Unknown names are a no-op.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica rejects the write.
    pub fn unpin_subscription(&mut self, name: &str) -> Result<(), ClientError> {
        let _suspended = SuspendedCapture::new(&mut self.session);
        subscriptions::unpin(&mut self.db, name)
    }

    /// Every pin, as name and query, in name order.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica cannot be read.
    pub fn pins(&mut self) -> Result<Vec<(String, String)>, ClientError> {
        subscriptions::pins(&mut self.db)
    }

    /// Start the grace countdown on `sub_id`, because its last handle dropped.
    /// The subscription stays declared and stays on the wire until the grace
    /// runs out, so re-watching the same query inside the window costs no
    /// fresh snapshot.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica rejects the write.
    pub fn release_subscription(&mut self, sub_id: &str) -> Result<(), ClientError> {
        let _suspended = SuspendedCapture::new(&mut self.session);
        subscriptions::release(&mut self.db, sub_id)
    }

    /// Stop the grace countdown on `sub_id`, because a handle holds it again.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica rejects the write.
    pub fn hold_subscription(&mut self, sub_id: &str) -> Result<(), ClientError> {
        let _suspended = SuspendedCapture::new(&mut self.session);
        subscriptions::hold(&mut self.db, sub_id)
    }

    /// Every subscription whose grace has run out. Reading this ends nothing:
    /// the caller unsubscribes each and drops its record.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica cannot be read.
    pub fn expired_subscriptions(&mut self) -> Result<Vec<String>, ClientError> {
        subscriptions::expired(&mut self.db)
    }

    /// Every subscription this replica has declared and not dropped, whether
    /// or not a server has ever seen them.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica cannot be read.
    pub fn declared_subscriptions(
        &mut self,
    ) -> Result<Vec<(String, SubscriptionSpec)>, ClientError> {
        Ok(subscriptions::declared(&mut self.db)?
            .into_iter()
            .map(|record| (record.sub_id, record.spec))
            .collect())
    }

    /// Declare every persisted subscription on a freshly attached transport.
    ///
    /// One rule covers both cases the set can hold: subscriptions this run
    /// declared while alone, and subscriptions a previous run declared and
    /// never dropped. `docs/architecture/15-replica-retention.md` decides that
    /// the second kind is live at launch and re-claimed as screens mount, so
    /// there is no second case to write here.
    async fn replay_subscriptions(&mut self) -> Result<(), ClientError> {
        for record in subscriptions::declared(&mut self.db)? {
            if record.live {
                self.send_subscribe(&record.sub_id, record.spec).await?;
            } else {
                // Past its grace, so it is ended rather than re-declared and
                // its rows become evictable. The server never saw it on this
                // connection, so there is nothing to unsubscribe.
                let _suspended = SuspendedCapture::new(&mut self.session);
                subscriptions::forget(&mut self.db, &record.sub_id)?;
            }
        }
        Ok(())
    }

    /// Cancel a subscription (row or aggregate) by its client-assigned id. The
    /// server tolerates an unknown id silently.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the unsubscribe frame cannot be sent.
    pub async fn unsubscribe(&mut self, sub_id: &str) -> Result<(), ClientError> {
        // Dropped from the record first, so a cancellation made offline is not
        // replayed as a subscription by the next attach.
        {
            let _suspended = SuspendedCapture::new(&mut self.session);
            subscriptions::forget(&mut self.db, sub_id)?;
        }
        if self.is_connected() {
            self.wire()?
                .transport
                .send_control(ControlMessage::Unsubscribe(Unsubscribe {
                    sub_id: sub_id.to_owned(),
                }))
                .await
                .map_err(|e| ClientError::Transport(e.to_string()))?;
        }
        Ok(())
    }

    /// Read one inbound frame, apply it if it is a patch, and report what
    /// happened. Applying a bulk patch replenishes one delivery credit.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a transport, apply, or protocol failure.
    pub async fn pump_one(&mut self) -> Result<ClientEvent, ClientError> {
        if let Some(notice) = self.notices.pop_front() {
            return Ok(notice);
        }
        let frame = self.wire()?.transport.recv().await;
        let frame = self.judge(frame)?;
        self.handle_frame(frame).await
    }

    /// Like [`pump_one`](Self::pump_one), but abandons the idle wait when
    /// `cancel` resolves first, returning `None`. The underlying receive is
    /// cancel-safe, so an abandoned wait loses no frame. This is the pump step
    /// a shared driver uses so it never parks on the transport while holding
    /// the connection lock.
    ///
    /// # Errors
    ///
    /// Same as [`pump_one`](Self::pump_one).
    pub async fn pump_one_or(
        &mut self,
        cancel: impl core::future::Future<Output = ()>,
    ) -> Result<Option<ClientEvent>, ClientError> {
        // Ahead of the transport, and ahead of the cancel, because a state
        // change already happened and holding it back would leave a caller
        // showing stale data with nothing to tell it otherwise.
        if let Some(notice) = self.notices.pop_front() {
            return Ok(Some(notice));
        }
        let Some(wire) = self.wire.as_mut() else {
            // No socket is not a failure here. It is a connection with nothing
            // to say, exactly like an idle one, and treating it as an error
            // would end a pump that still has local work to do.
            cancel.await;
            return Ok(None);
        };
        let frame = tokio::select! {
            biased;
            () = cancel => return Ok(None),
            frame = wire.transport.recv() => frame,
        };
        let frame = self.judge(frame)?;
        self.handle_frame(frame).await.map(Some)
    }

    /// Apply one received frame: bulk patches mutate the replica and advance
    /// flow control, control frames map onto their [`ClientEvent`]s.
    async fn handle_frame(
        &mut self,
        frame: Option<IncomingFrame>,
    ) -> Result<ClientEvent, ClientError> {
        match frame {
            // A peer that closed cleanly is as gone as one that failed, so the
            // wire goes and the change is announced behind this event.
            None => {
                self.disconnected();
                Ok(ClientEvent::Closed)
            }
            Some(IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch))) => {
                self.apply_patch(&patch.patchset_zstd, None, Some(&patch.sub_id))?;
                self.ack_one().await?;
                Ok(ClientEvent::SnapshotApplied {
                    sub_id: patch.sub_id,
                })
            }
            Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch))) => {
                self.apply_patch(
                    &patch.patchset_zstd,
                    Some(&patch.cursor),
                    Some(&patch.sub_id),
                )?;
                self.last_cursor = Some(patch.cursor.clone());
                self.ack_one().await?;
                Ok(ClientEvent::LivePatch {
                    sub_id: patch.sub_id,
                    cursor: patch.cursor,
                    patchset_zstd: patch.patchset_zstd.into(),
                })
            }
            Some(IncomingFrame::Bulk(_)) => Err(ClientError::Protocol(
                "unexpected bulk frame from server".into(),
            )),
            Some(IncomingFrame::Control(msg)) => self.handle_control(msg),
        }
    }

    /// Send a keepalive probe. The matching [`ClientEvent::Pong`] from a later
    /// [`pump_one`](Self::pump_one) doubles as a barrier: the server processes
    /// frames in order, so a pong proves every preceding frame was handled.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the ping cannot be sent.
    pub async fn ping(&mut self, nonce: u64) -> Result<(), ClientError> {
        self.wire()?
            .transport
            .send_control(ControlMessage::Ping(Ping { nonce }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// Upload local writes captured since the last push as one mutation.
    ///
    /// Returns the assigned `client_seq`, or `None` when there was nothing to
    /// send. The pending record is persisted and the capture session reset
    /// BEFORE the frames leave, so from that point the pending table is the
    /// single owner of this mutation: a send failure replays it on the next
    /// resume instead of re-capturing it, and a process death replays it on
    /// the next boot of the same replica.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a session, compression, or transport failure.
    pub async fn push(&mut self) -> Result<Option<u64>, ClientError> {
        let changeset = self
            .session
            .changeset()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        if changeset.is_empty() {
            return Ok(None);
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        {
            let _suspended = SuspendedCapture::new(&mut self.session);
            persist_pending(&mut self.db, seq, &changeset)?;
            // The cap is a safety valve against a server that never
            // acknowledges: evicting a record gives up its replay.
            if self.pending.len() >= PENDING_CAP
                && let Some((&oldest, _)) = self.pending.first_key_value()
            {
                self.pending.pop_first();
                delete_pending(&mut self.db, oldest)?;
            }
        }
        // Reset capture: a fresh session records only writes after this push.
        let mut fresh = self
            .db
            .create_session()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        fresh
            .attach_all()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        self.session = fresh;
        self.pending.insert(seq, changeset.clone());
        // With no server the write stays queued, which is the designed offline
        // state rather than a failure: it is already durable in
        // `_connetto_pending` above, and `attach` replays it. Returning an
        // error here would make every caller treat working offline as a fault.
        // A caller that needs to know asks `unsynced`, or reads the
        // connection-state event.
        if self.is_connected() {
            self.send_mutation(seq, &changeset).await?;
        }
        Ok(Some(seq))
    }

    /// Send one mutation as its header and patchset frame pair. Shared by
    /// [`push`](Self::push) and the replay in
    /// [`reconcile_pending`](Self::reconcile_pending).
    ///
    /// This is the one place a captured changeset leaves for the server, so it
    /// is where a split table's backing name goes back to the logical Postgres
    /// name the wire speaks. The durable pending record keeps the physical
    /// names it was captured under, because that is what a rollback has to
    /// apply locally, and a replay renames again on its way out.
    async fn send_mutation(&mut self, seq: u64, changeset: &[u8]) -> Result<(), ClientError> {
        let logical = self.to_logical(changeset.to_vec())?;
        let op_count = count_ops(&logical);
        let payload = zstd::encode_all(logical.as_slice(), ZSTD_LEVEL)?;
        self.wire()?
            .transport
            .send_control(ControlMessage::MutationHeader(MutationHeader::new(
                seq, op_count,
            )))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        self.wire()?
            .transport
            .send_bulk(BulkMessage::MutationPatch(MutationPatch::new(seq, payload)))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        Ok(())
    }

    /// Roll back the optimistic local write for `client_seq` after the server
    /// rejected or conflicted it: decode the touched rows for the event, invert
    /// the captured changeset, and apply the inverse with capture suspended,
    /// so the rollback is never re-uploaded. A row a concurrent server patch
    /// already changed is left alone. Returns the touched rows, empty when
    /// the changeset is gone.
    fn rollback(&mut self, client_seq: u64) -> Result<Vec<AffectedRow>, ClientError> {
        let Some(changeset) = self.pending.remove(&client_seq) else {
            return Ok(Vec::new());
        };
        let rows = affected_rows(&changeset, &self.config.policy_tables)?;
        let inverse = invert_changeset(&changeset)
            .map_err(|err| ClientError::Apply(format!("inverting rejected changeset: {err}")))?;
        let _suspended = SuspendedCapture::new(&mut self.session);
        delete_pending(&mut self.db, client_seq)?;
        self.db
            .apply_changeset(&inverse, rollback_omit)
            .map_err(|err| ClientError::Apply(err.to_string()))?;
        Ok(rows)
    }

    /// Flush locally captured writes as one mutation when the capture session
    /// recorded a committed change since the last flush.
    ///
    /// Returns the assigned `client_seq`, or `None` when nothing was pending.
    /// This is the automatic submit: writes made on [`conn`](Self::conn) are
    /// uploaded here without an explicit [`push`](Self::push).
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a session, compression, or transport failure.
    pub async fn flush(&mut self) -> Result<Option<u64>, ClientError> {
        if self.dirty.swap(false, Ordering::Relaxed) {
            self.push().await
        } else {
            Ok(None)
        }
    }

    /// Drive one step of the sync loop: flush pending local writes, apply one
    /// inbound server frame, and report the event with the tables that changed.
    ///
    /// This is the app-facing driver. The application writes ordinary diesel
    /// queries on [`conn`](Self::conn) and awaits `next_event` in a loop, using
    /// [`Reactive::changed_tables`] to re-query what changed.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a transport, apply, or protocol failure.
    pub async fn next_event(&mut self) -> Result<Reactive, ClientError> {
        self.flush().await?;
        let event = self.pump_one().await?;
        Ok(Reactive {
            event,
            changed_tables: self.take_changed(),
        })
    }

    /// Drain the set of tables whose rows changed since the last call, sorted.
    ///
    /// connetto's own bookkeeping is dropped here rather than at the update
    /// hook, so the tracker stays a plain record of what the connection wrote
    /// and this one boundary decides what counts as an application table for
    /// both consumers, [`Reactive::changed_tables`] and the live-query refresh.
    ///
    /// A split table is reported under its logical name for the same reason.
    /// SQLite's update hook never fires for a view, so a write through the
    /// `INSTEAD OF` triggers and a server patch applied underneath them both
    /// report the backing table, while a live query names the table its own SQL
    /// names. Reporting the physical name would leave every live query over a
    /// policy-bearing table never refreshing, silently.
    pub fn take_changed(&mut self) -> Vec<String> {
        let tables = &self.config.policy_tables;
        let mut named: Vec<String> = self
            .changed
            .lock()
            .map(|mut set| {
                set.drain()
                    .filter(|name| !is_internal_table(name))
                    .map(|name| match tables.logical(&name) {
                        Some(logical) => logical.to_owned(),
                        None => name,
                    })
                    .collect()
            })
            .unwrap_or_default();
        named.sort();
        named.dedup();
        named
    }

    /// Close the transport.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the close fails.
    pub async fn close(&mut self) -> Result<(), ClientError> {
        self.wire()?
            .transport
            .close()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    fn handle_control(&mut self, msg: ControlMessage) -> Result<ClientEvent, ClientError> {
        match msg {
            ControlMessage::SnapshotBegin(begin) => Ok(ClientEvent::SnapshotBegin {
                sub_id: begin.sub_id,
            }),
            ControlMessage::SnapshotEnd(end) => {
                // This records a resume position for rows delivered on the
                // other plane, so it depends on the server having sent them
                // first: see the invariant on `persist_cursor`.
                //
                // An empty cursor carries no resume information: never let
                // it regress a real one, in memory or in the replica.
                if !end.cursor.is_empty() {
                    let _suspended = SuspendedCapture::new(&mut self.session);
                    persist_cursor(&mut self.db, &end.cursor)?;
                    self.last_cursor = Some(end.cursor);
                }
                Ok(ClientEvent::SnapshotEnd { sub_id: end.sub_id })
            }
            ControlMessage::AggregateUpdate(update) => Ok(ClientEvent::Aggregate {
                sub_id: update.sub_id,
                result_json: update.result_json,
                group_key: update.group_key,
                is_full_result: update.is_full_result,
            }),
            ControlMessage::FullResyncRequired(resync) => {
                self.clear_subscription_rows(&resync.sub_id)?;
                Ok(ClientEvent::FullResync {
                    sub_id: resync.sub_id,
                    reason: resync.reason,
                })
            }
            ControlMessage::MutationApplied(ack) => {
                if self.pending.remove(&ack.client_seq).is_some() {
                    let _suspended = SuspendedCapture::new(&mut self.session);
                    delete_pending(&mut self.db, ack.client_seq)?;
                }
                Ok(ClientEvent::MutationApplied {
                    client_seq: ack.client_seq,
                })
            }
            ControlMessage::MutationReject(reject) => {
                let rows = self.rollback(reject.client_seq)?;
                Ok(ClientEvent::MutationRejected {
                    client_seq: reject.client_seq,
                    rows,
                })
            }
            ControlMessage::MutationConflict(conflict) => {
                let rows = self.rollback(conflict.client_seq)?;
                Ok(ClientEvent::MutationConflict {
                    client_seq: conflict.client_seq,
                    rows,
                    server_row: conflict.server_row,
                })
            }
            ControlMessage::Pong(pong) => Ok(ClientEvent::Pong { nonce: pong.nonce }),
            ControlMessage::NonFatalError(err) => Ok(ClientEvent::NonFatal {
                related_to: err.related_to,
                detail: err.detail,
            }),
            ControlMessage::RateLimited(limited) => Ok(ClientEvent::RateLimited {
                related_to: limited.related_to,
                retry_after_ms: limited.retry_after_ms,
            }),
            // A relay saying whether IT can reach the server. For a tab that is
            // the answer that matters, because a tab whose own link is fine
            // still cannot sync while the relay cannot, so it rides the same
            // event as this connection's own state.
            ControlMessage::SyncStatus(status) => Ok(ClientEvent::SyncStatus(status)),
            // The server says why it is closing. Surfaced rather than treated
            // as a violation: the server behaved exactly as the protocol says.
            ControlMessage::FatalError(fatal) => Ok(ClientEvent::ServerClosed {
                reason: fatal.reason,
            }),
            ControlMessage::DeliveryPaused { cause } => Ok(ClientEvent::DeliveryPaused { cause }),
            ControlMessage::DeliveryResumed => Ok(ClientEvent::DeliveryResumed),
            other => Err(ClientError::Protocol(format!(
                "unexpected control frame from server: {other:?}"
            ))),
        }
    }

    /// Drop the replica rows of a row subscription's tables ahead of a
    /// full-resync snapshot, sparing every row a sibling subscription still
    /// covers.
    ///
    /// The fresh snapshot carries only the resyncing subscription's currently
    /// authorized rows, so the insert-only apply would leave rows deleted
    /// during the outage behind. Deleting the whole table instead destroys a
    /// sibling's rows over that table, which nothing then restores, so the
    /// statement deletes the complement of what the survivors want. Dropping a
    /// subscription never names it: it simply stops contributing a clause.
    ///
    /// Capture is suspended so the deletes are never re-uploaded as a local
    /// mutation. An unknown or aggregate sub id is a no-op.
    fn clear_subscription_rows(&mut self, sub_id: &str) -> Result<(), ClientError> {
        let declared = subscriptions::declared(&mut self.db)?;
        let Some(resyncing) = declared
            .iter()
            .find(|record| record.sub_id == sub_id)
            .and_then(|record| crate::live::coverage_of(&record.spec).transpose())
            .transpose()?
        else {
            return Ok(());
        };

        // Every other subscription's claim on those tables, as SQL. A survivor
        // with no predicate wants the whole table, so nothing there may go.
        let mut clauses: HashMap<&str, Vec<String>> = HashMap::new();
        let mut untouchable: HashSet<&str> = HashSet::new();
        for record in &declared {
            // A subscription past its grace no longer wants anything, so it
            // contributes no clause and its rows are the pass's to remove.
            if record.sub_id == sub_id || !record.live {
                continue;
            }
            let Some(coverage) = crate::live::coverage_of(&record.spec)? else {
                continue;
            };
            for table in resyncing
                .tables
                .iter()
                .filter(|t| coverage.tables.contains(*t))
            {
                match &coverage.predicate {
                    Some(predicate) => clauses
                        .entry(table.as_str())
                        .or_default()
                        .push(predicate.clone()),
                    None => {
                        untouchable.insert(table.as_str());
                    }
                }
            }
        }

        let _suspended = SuspendedCapture::new(&mut self.session);
        let tables = self.config.policy_tables.clone();
        self.db.transaction::<_, ClientError, _>(|conn| {
            for table in &resyncing.tables {
                if untouchable.contains(table.as_str()) {
                    continue;
                }
                // A split table is cleared at its backing table, not through
                // the policy view, for the reason the apply path writes there:
                // the server decides what this replica may hold, and the view
                // yields only rows the local policy admits, so deleting
                // through it would strand every row the policy hides where
                // nothing ever removes it. The predicates name plain columns
                // of the logical table and the backing table carries the same
                // columns in the same order, so they are unaffected.
                let target = tables.physical(table).unwrap_or(table);
                // The table and the predicates are chosen at runtime from the
                // subscriptions' own parsed queries, so diesel's compile-time
                // DSL cannot name them: this is the one raw statement here.
                let quoted = quote_ident(target);
                let statement = match clauses.get(table.as_str()) {
                    Some(surviving) if !surviving.is_empty() => {
                        let kept = surviving
                            .iter()
                            .map(|clause| format!("({clause})"))
                            .collect::<Vec<_>>()
                            .join(" OR ");
                        format!("DELETE FROM {quoted} WHERE NOT ({kept})")
                    }
                    _ => format!("DELETE FROM {quoted}"),
                };
                diesel::sql_query(statement).execute(conn)?;
            }
            Ok(())
        })
    }

    /// Apply one compressed server patchset to the replica, recording
    /// `cursor` in the same transaction when one accompanies it, so a crash
    /// never separates an applied change from its resume point. Capture is
    /// suspended throughout: the session never records what the server
    /// already knows.
    ///
    /// The wire speaks logical Postgres names, so a split table's rows are
    /// rewritten onto its backing table before the apply. Applying them to the
    /// view instead is silent loss rather than an error:
    /// `sqlite3changeset_apply` resolves the view, synthesizes an implicit
    /// rowid key because a view declares no primary key, passes its shape
    /// checks, and then fails every row as a per-row `Constraint` conflict,
    /// which `server_wins` maps to Omit. Server data is authoritative, so it
    /// lands underneath the policy triggers rather than through them.
    fn apply_patch(
        &mut self,
        payload_zstd: &[u8],
        cursor: Option<&Cursor>,
        addressed_to: Option<&str>,
    ) -> Result<(), ClientError> {
        let bytes = zstd::decode_all(payload_zstd)?;
        // Departure filtering weighs the wire's logical names against what the
        // subscriptions cover, which is also logical, so the rename follows it.
        let apply = self
            .honour_departures(&bytes, addressed_to)?
            .map(|bytes| self.to_physical(bytes))
            .transpose()?;
        let _suspended = SuspendedCapture::new(&mut self.session);
        self.db.transaction::<_, ClientError, _>(|conn| {
            // The cursor advances even when every op was withheld. A departure
            // this replica declined to act on is still an event it has seen,
            // and not recording it would replay the same decision for ever.
            if let Some(bytes) = apply.as_deref() {
                conn.apply_patchset(bytes, server_wins)
                    .map_err(|e| ClientError::Apply(e.to_string()))?;
            }
            if let Some(cursor) = cursor {
                persist_cursor(conn, cursor)?;
            }
            Ok(())
        })
    }

    /// Rewrite a payload from the wire's logical names onto the replica's
    /// physical ones. A schema with no split table skips the parse entirely.
    fn to_physical(&self, bytes: Vec<u8>) -> Result<Vec<u8>, ClientError> {
        let tables = &self.config.policy_tables;
        if tables.is_empty() {
            return Ok(bytes);
        }
        rename_diffset(bytes, |name| tables.physical(name).map(str::to_owned))
    }

    /// Rewrite a captured payload from the replica's physical names back onto
    /// the logical ones the wire and Postgres use.
    fn to_logical(&self, bytes: Vec<u8>) -> Result<Vec<u8>, ClientError> {
        let tables = &self.config.policy_tables;
        if tables.is_empty() {
            return Ok(bytes);
        }
        rename_diffset(bytes, |name| tables.logical(name).map(str::to_owned))
    }

    /// What of `bytes` should actually be applied, once departure notices are
    /// weighed against what other subscriptions still want.
    ///
    /// A server-synthesized indirect delete means the row left the addressed
    /// subscription's window rather than being removed, so it applies only
    /// when no surviving subscription still covers the row. Everything else,
    /// including a genuine delete, applies unconditionally: on a real removal
    /// the server sends one to every covering subscription, and holding each
    /// back on the others would leave the row for ever.
    ///
    /// Returns `None` when the payload should be applied unchanged, which is
    /// every ordinary patch and costs one parse.
    fn honour_departures(
        &mut self,
        bytes: &[u8],
        addressed_to: Option<&str>,
    ) -> Result<Option<Vec<u8>>, ClientError> {
        let Ok(ParsedDiffSet::Patchset(set)) = ParsedDiffSet::parse(bytes) else {
            return Ok(Some(bytes.to_vec()));
        };
        // The server sends a departure as a patchset of indirect deletes and
        // nothing else, so a payload carrying anything further is an ordinary
        // one and is not inspected further.
        let mut departures = Vec::new();
        for op in set.iter() {
            match op {
                PatchsetOp::Delete { .. } if op.indirect() => {
                    departures.push((op.table().clone(), op.primary_key()));
                }
                _ => return Ok(Some(bytes.to_vec())),
            }
        }
        if departures.is_empty() {
            return Ok(Some(bytes.to_vec()));
        }

        let mut kept = PatchSet::<TableSchema<String>, String, Vec<u8>>::new();
        let mut any = false;
        for (table, pk) in departures {
            if self.still_covered(&table, &pk, addressed_to)? {
                continue;
            }
            any = true;
            kept = kept.delete(PatchDelete::new(table, pk));
        }
        Ok(any.then(|| kept.build()))
    }

    /// Whether some subscription other than `addressed_to` still wants the row
    /// `pk` identifies in `table`.
    ///
    /// `table` is the wire's logical name, so the subscription match below is
    /// on that, while the row itself is read from the backing table when the
    /// table was split: the question is what this replica holds for other
    /// subscriptions, and the view would answer only for the rows the local
    /// policy admits.
    fn still_covered(
        &mut self,
        table: &TableSchema<String>,
        pk: &[sqlite_diff_rs::Value<String, Vec<u8>>],
        addressed_to: Option<&str>,
    ) -> Result<bool, ClientError> {
        let name = table.name().to_lowercase();
        let mut clauses = Vec::new();
        for record in subscriptions::declared(&mut self.db)? {
            if !record.live || addressed_to.is_some_and(|id| id == record.sub_id) {
                continue;
            }
            let Some(coverage) = crate::live::coverage_of(&record.spec)? else {
                continue;
            };
            if !coverage.tables.contains(&name) {
                continue;
            }
            match coverage.predicate {
                // A survivor with no predicate wants the whole table, so the
                // row is covered and no further clause can change that.
                None => return Ok(true),
                Some(predicate) => clauses.push(format!("({predicate})")),
            }
        }
        if clauses.is_empty() {
            return Ok(false);
        }

        // The key is matched by ordinal, because the wire format carries a
        // primary key's positions and never its column names. The replica's own
        // catalog supplies the names for those positions.
        let physical = self
            .config
            .policy_tables
            .physical(&name)
            .unwrap_or(table.name())
            .to_owned();
        let columns = replica_columns(&mut self.db, &physical)?;
        let mut wheres = Vec::with_capacity(pk.len());
        for (position, value) in pk_ordinals(table).into_iter().zip(pk) {
            let column = columns.get(position).ok_or_else(|| {
                ClientError::Session(format!(
                    "a patch names column {position} of {name}, which the replica does not have"
                ))
            })?;
            wheres.push(format!(
                "{} IS {}",
                quote_ident(column),
                crate::live::bind_literal_of(value)?
            ));
        }
        let sql = format!(
            "SELECT 1 AS present FROM {} WHERE {} AND ({}) LIMIT 1",
            quote_ident(&physical),
            wheres.join(" AND "),
            clauses.join(" OR ")
        );
        let rows: Vec<Present> = diesel::sql_query(sql).load(&mut self.db)?;
        Ok(!rows.is_empty())
    }

    async fn ack_one(&mut self) -> Result<(), ClientError> {
        self.wire()?
            .transport
            .send_control(ControlMessage::AckCredits(AckCredits { credits: 1 }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))
    }
}

impl<T: Transport> SimpleConnection for ConnettoConnection<T> {
    fn batch_execute(&mut self, query: &str) -> QueryResult<()> {
        self.db.batch_execute(query)
    }
}

impl<T: Transport> ConnectionSealed for ConnettoConnection<T> {}

/// `ConnettoConnection` is a diesel `Connection` over the managed local SQLite,
/// so applications run ordinary diesel queries on `&mut conn`. Execution
/// delegates to the captured connection `db`, so local writes are recorded and
/// auto-submitted by the driver. `establish` is unsupported: build the
/// connection with [`ConnettoConnection::connect`], which owns the transport and
/// handshake. diesel's query methods never call `establish`.
impl<T: Transport + Send> Connection for ConnettoConnection<T> {
    type Backend = Sqlite;
    type TransactionManager = AnsiTransactionManager;

    fn establish(_database_url: &str) -> ConnectionResult<Self> {
        Err(ConnectionError::BadConnection(
            "ConnettoConnection is built with ConnettoConnection::connect, not establish"
                .to_owned(),
        ))
    }

    fn execute_returning_count<Q>(&mut self, source: &Q) -> QueryResult<usize>
    where
        Q: QueryFragment<Self::Backend> + QueryId,
    {
        self.db.execute_returning_count(source)
    }

    fn transaction_state(&mut self) -> &mut AnsiTransactionManager {
        &mut self.transaction_state
    }

    fn instrumentation(&mut self) -> &mut dyn Instrumentation {
        self.db.instrumentation()
    }

    fn set_instrumentation(&mut self, instrumentation: impl Instrumentation) {
        self.db.set_instrumentation(instrumentation);
    }

    fn set_prepared_statement_cache_size(&mut self, size: CacheSize) {
        self.db.set_prepared_statement_cache_size(size);
    }
}

impl<T: Transport + Send> LoadConnection<DefaultLoadingMode> for ConnettoConnection<T> {
    type Cursor<'conn, 'query>
        = <SqliteConnection as LoadConnection<DefaultLoadingMode>>::Cursor<'conn, 'query>
    where
        T: 'conn;
    type Row<'conn, 'query>
        = <SqliteConnection as LoadConnection<DefaultLoadingMode>>::Row<'conn, 'query>
    where
        T: 'conn;

    fn load<'conn, 'query, Q>(
        &'conn mut self,
        source: Q,
    ) -> QueryResult<Self::Cursor<'conn, 'query>>
    where
        Q: Query + QueryFragment<Self::Backend> + QueryId + 'query,
        Self::Backend: QueryMetadata<Q::SqlType>,
    {
        self.db.load(source)
    }
}
