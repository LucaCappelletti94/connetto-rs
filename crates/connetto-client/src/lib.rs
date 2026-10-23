#![doc = include_str!("../README.md")]

pub use connetto_core::messages::{
    FullResyncReason, Grant, PauseCause, SyncStatus, WriterGrant, WriterRef, WriterRequest,
};
pub use connetto_core::{Custody, NoGate};
/// The peer link's close reasons, dial errors and chain refusals (R76).
#[cfg(feature = "peer")]
pub use connetto_peer::{CloseReason, LinkError, Refusal};
use share_keys::ShareKeyPersistence;
pub use share_keys::{ShareKeyFuture, ShareKeySet, ShareKeyStore};

use connetto_core::SUBJECTS_FUNCTION;
use connetto_core::auth::{CapabilityKey, CapabilitySubject};
use connetto_core::chain::{GENESIS, entry_hash};
#[cfg(feature = "peer")]
use connetto_core::device_cert::DeviceIdentity;
#[cfg(feature = "device-identity")]
use connetto_core::device_cert::DeviceKey;
use connetto_core::messages::{
    AckCredits, BindValue, BulkMessage, ConflictRow, ContentTicketRequest, ContentVerb,
    ControlMessage, FatalErrorReason, GateState, Handshake, MutationHeader, MutationPatch,
    MutationReject, MutationRejectReason, Ping, Provenance, ReplaceShareKeys, RetireWriter,
    ShareKeyChange, Subscribe, SubscriptionSpec, TabIdentity, TabShareKeyAnswer, TabShareKeyChange,
    TabShareKeyOutcome, Unsubscribe, WriterAnswer,
};
#[cfg(feature = "device-identity")]
use connetto_core::messages::{BindDevice, WriterOutcome, writer_bind_message};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Backoff, Cursor, PROTOCOL_VERSION, RetryPolicy, SchemaVersion, quote_ident};
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
    AutoVacuumMode, CommitDecision, Sqlite, SqliteChangeOps, SqliteFunctionBehavior,
    SqliteUpdateRouter, WalCheckpointMode,
};
use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SqliteConnection};
use diesel_sqlite_session::{
    ConflictAction, ConflictType, Session, SqliteSessionExt, invert_changeset,
};
use sqlite_diff_rs::{
    DiffOps, DynTable, ParsedDiffSet, PatchDelete, PatchSet, PatchsetOp, SchemaWithPK, TableSchema,
    Value,
};
use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
#[cfg(feature = "peer")]
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

mod aggregates;
pub mod archive;
#[cfg(feature = "native-auth")]
pub mod auth;
pub mod away;
#[cfg(feature = "peer")]
mod bluetooth;
#[cfg(feature = "bot")]
pub mod bot;
pub mod bots;
pub mod builder;
pub mod cipher;
mod clock;
#[cfg(feature = "device-identity")]
pub mod device_key;
pub mod dsl;
#[cfg(feature = "device-identity")]
mod enrolment;
mod grant_expiry;
pub mod harden;
#[cfg(feature = "peer")]
mod hotspot;
#[cfg(feature = "native-auth")]
mod keyring;
pub mod live;
mod memory_stores;
#[cfg(all(feature = "peer", target_os = "android"))]
mod multicast;
pub mod reconnect;
pub mod replica;
pub mod share_keys;
mod shared_replay;
mod subscriptions;

#[cfg(feature = "peer")]
pub use bluetooth::{
    BeaconState, BluetoothError, BluetoothState, HostId, Hosted, JoinNearbyError, NearbyHost,
    PromptOutcome,
};
#[cfg(feature = "device-identity")]
pub use enrolment::{CertificateError, DeviceEntry};
#[cfg(feature = "peer")]
pub use hotspot::{HotspotError, HotspotOffer, HotspotSecurity, JoinError, WifiPayloadError};
pub use subscriptions::{DEFAULT_GRACE, MAX_GRACE};
pub mod teardown;

pub use archive::{
    ArchiveAttachment, Cell, Collision, Difference, ExportScope, ImportChoices, ImportOutcome,
    ImportPlan, Keep, LocalDataExport, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENTS_BYTES,
};
#[cfg(feature = "native-auth")]
pub use auth::{
    AcquiredSession, AuthorizationSession, BrowserOpener, KeyringKeyStore, KeyringStore,
    NativeAuthenticator, SessionFuture, system_browser_opener,
};
pub use away::{
    Clock, GateAskFuture, GateAskOutcome, GateController, GateMechanism, GateSink, Moment,
    SystemClock,
};
#[cfg(feature = "native-auth")]
pub use builder::native::NativeSession;
#[cfg(feature = "native-transport")]
pub use builder::native::{
    DataDir, NativeClient, NativeClientBuilder, NativeDurable, NativeSignedIn, NativeTransport,
};
pub use builder::sign_in::{AccountChoice, Auth, HeldCredential, WebSignIn};
#[cfg(feature = "native-auth")]
pub use builder::sign_in::{AccountChooser, Keyring, KeyringAuth, StoredAuth};
#[cfg(feature = "native-transport")]
pub use builder::sign_in::{NativeSignIn, NoKeyring};
pub use builder::{
    AttachContent, ClientBuilder, ContentPlace, CoreClient, CoreDurable, CorePump, CoreSignedIn,
    Gate, Located, REPLICA_PREFIX, ReplicaPlace, SyncSchema, SyncTuning,
};
pub use cipher::{ReplicaKey, UnlockError};
pub use dsl::Watchable;
#[cfg(all(feature = "native-auth", target_os = "android"))]
pub use keyring::KeystorePrompt;
#[cfg(feature = "native-auth")]
pub use keyring::SecretStoreError;
#[cfg(all(feature = "native-auth", target_os = "linux"))]
pub use keyring::{Backend, KeyFile, LinuxStore};
#[cfg(all(feature = "native-auth", target_os = "windows"))]
pub use keyring::{HelloCancellation, HelloOwner, HelloWindow};
pub use live::{
    ConnettoClient, LiveGroups, LiveHandle, LiveQuery, LiveRows, LiveValue,
    subscription_is_aggregate, subscription_tables,
};
pub use memory_stores::{MemoryKeyStore, MemoryRefreshStore};
#[cfg(feature = "native-transport")]
pub use reconnect::TokioSleeper;
pub use reconnect::{FirstThen, ReconnectPolicy, Sleeper, TransportFactory};
#[cfg(feature = "native-transport")]
pub use replica::provision_replica_key;
pub use replica::{
    Encrypted, IDENTITY_RECORD, InMemory, Replica, ReplicaStorage, Tier, decode_identity,
    device_key_record, encode_identity, is_reserved_record, replica_db_name, shared_store_name,
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
    /// The peer refused the handshake and said why: a server on another
    /// protocol version, a newer connection on the same handle, a shutdown, or
    /// a browser relay hub rejecting a malformed tab.
    #[error("handshake refused: {reason:?}")]
    Refused {
        /// The refusal the peer sent.
        reason: FatalErrorReason,
    },
    /// The bot's registration was refused (R91). The refusal is the wire's
    /// `RegistrationRefused` frame, after which the connection carries on with
    /// a fresh challenge, so there is no close reason to carry.
    #[error("the registration was refused")]
    RegistrationRefused,
    /// The install's own validation refused the add before a row was written
    /// (R91), so the app's transaction rolls back whole and nothing uploads.
    #[error("the install was refused: {0}")]
    InstallRefused(String),
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
    /// Writing the local data export failed.
    #[error("export error: {0}")]
    Export(String),
    /// Reading or applying a local data archive failed, or the archive was
    /// refused: a schema, an account or a queue this replica cannot take. Every
    /// refusal says which by name, because an import that fails has to tell the
    /// person something they can act on.
    #[error("import error: {0}")]
    Import(String),
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
    /// The client's pump stopped on a fault no reconnect can cure, named here.
    #[error("the client stopped: {0}")]
    Stopped(String),
    /// Acquiring or refreshing the access token failed.
    #[error("authentication error: {0}")]
    Auth(String),
    /// An OS secret store refused.
    #[cfg(feature = "native-auth")]
    #[error("secret store: {0}")]
    SecretStore(keyring::SecretStoreError),
    /// No device key could be made (R74).
    #[cfg(feature = "device-identity")]
    #[error(transparent)]
    DeviceKey(#[from] device_key::DeviceKeyStoreError),
    /// The security chip refused to hold or use a device key (R74).
    #[cfg(feature = "device-identity")]
    #[error(transparent)]
    DeviceChip(device_key::ChipError),
    /// The device descriptor cannot be sent, since it does not serialize or
    /// is over the 4096 bytes the server accepts (R74).
    #[cfg(feature = "device-identity")]
    #[error("the device descriptor cannot be sent: {0}")]
    DeviceDescriptor(String),
    /// An Android build with a device identity connected without the JNI
    /// access its key needs, which `NativeDurable::with_java_access` hands in
    /// (R74 decision 20).
    #[cfg(all(feature = "device-identity", target_os = "android"))]
    #[error("the device key needs JNI access: call NativeDurable::with_java_access")]
    MissingJavaAccess,
    /// A build with a device identity connected without naming the roots its
    /// certificates and revocation lists are checked against (R74 decision 23).
    #[cfg(feature = "device-identity")]
    #[error(
        "the device identity needs its deployment roots: call NativeDurable::with_deployment_roots"
    )]
    MissingDeploymentRoots,
    /// A deployment root the application named is not a certificate holding
    /// a key.
    #[cfg(feature = "device-identity")]
    #[error("deployment root {index} is not a certificate holding a key")]
    InvalidDeploymentRoot {
        /// The root's position among the roots given to `with_deployment_roots`.
        index: usize,
    },
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
    /// Another connection held the local database locked for longer than the
    /// open waits, so the file and the key are untouched and a later open succeeds.
    #[error("another connection holds the local database locked: {0}")]
    ReplicaBusy(String),
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
    /// The platform destroyed every key it held behind the user's
    /// verification, as Android does when the screen lock is removed. A
    /// durable build answers it by wiping the replica and starting a fresh one
    /// the server resyncs, since nothing can open the old one again.
    #[error("the platform lost the replica key, so the replica can never be opened again")]
    ReplicaKeyLost,
    /// The replica's schema and the policy-table map disagree about which
    /// tables the row-level-security translation split.
    ///
    /// The map is a build artifact of the same translation that emitted the
    /// DDL, so a disagreement means the two came from different builds, or
    /// that the schema was bundled without it
    /// ([`SyncSchema`]). Either way the sync boundaries
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
    /// A table connetto cannot record changes to, so writes to it would be
    /// lost without a word.
    ///
    /// SQLite records nothing for a table whose only key is the implicit
    /// `rowid`, and two mechanisms depend on that record: the capture session
    /// bound to `main`, so a synced table is never uploaded, and the session
    /// diff the browser relay serves a tab from, so a table of either
    /// database is never read by a sibling tab. `CREATE TABLE prefs (name
    /// TEXT, value TEXT)` is a keyed table by SQL's standards, so this
    /// requirement is connetto's own and the refusal names the fix.
    ///
    /// A table listed in
    /// [`SyncSchema::with_unrecorded_tables`](crate::SyncSchema::with_unrecorded_tables) that does
    /// declare a key is refused here too: the list and the schema then say
    /// opposite things, and the table would sync while the application
    /// believed it did not.
    #[error("connetto cannot record changes to some tables: {}", .tables.join(", "))]
    WritesNotRecorded {
        /// One sentence per table, naming which database holds it and what to
        /// change.
        tables: Vec<String>,
    },
    /// A plain `ws` URL named a host that is not loopback, refused before
    /// any socket opens.
    #[error("insecure websocket: {host} is not a loopback host")]
    InsecureWebSocket {
        /// The host the URL named.
        host: String,
    },
    /// The content layer failed to build its client.
    #[error("content error: {0}")]
    Content(String),
    /// The gate is locked, so application access is refused. The pump keeps
    /// applying inbound patches and reconnecting. This is a typed refusal the
    /// application distinguishes from a transport failure and retries after
    /// [`ConnettoClient::unlock`](crate::live::ConnettoClient::unlock) or the
    /// next approved re-check.
    #[error("locked: the gate is locked and application access is refused")]
    Locked,
}

/// Why a peer link could not be opened (R76).
#[cfg(feature = "peer")]
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    /// No device key, no certificate, or a build without a device identity.
    #[error("the device has no identity to link")]
    NoIdentity,
    /// The device's certificate passed its expiry plus the tolerance, which
    /// also raises `ClientEvent::CertificateExpired`.
    #[error("the device certificate is expired")]
    CertificateExpired,
    /// The local clock puts the device's certificate outside its window.
    #[error("the device clock is outside the certificate window")]
    ClockOutsideWindow,
    /// The dial failed.
    #[error(transparent)]
    Link(#[from] LinkError),
}

/// One queued write awaiting its final answer, named by the writer and the
/// sequence it is the writer's.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnsyncedWrite {
    /// The writer the entry is queued under.
    pub writer: WriterRef,
    /// The entry's sequence in that writer's queue.
    pub seq: u64,
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
    Unsent(Vec<UnsyncedWrite>),
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
/// not decrypt is recoverable by discarding the replica, a busy file by opening
/// again, and everything else is a build or configuration fault.
impl From<UnlockError> for ClientError {
    fn from(error: UnlockError) -> Self {
        match error {
            UnlockError::WrongKey(_) => Self::ReplicaUndecryptable(error.to_string()),
            UnlockError::Busy(_) => Self::ReplicaBusy(error.to_string()),
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
/// a `Send + Sync` connection on every target, which diesel's `Connection`
/// requires. A browser factory whose future holds browser handles wraps it
/// in `send_wrapper::SendWrapper`, which is sound on a target with one thread.
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
/// `Send + Sync` on every target, wasm included, because [`ConnettoConnection`]
/// embeds the client configuration and implements `diesel::Connection`, whose `Send`
/// supertrait forces the whole connection (so the whole config) to be `Send`
/// even in the wasm build. `Arc<dyn Fn>` is `Send` only when the `dyn` is
/// `Send + Sync`, hence both bounds. In practice a registrar closes over
/// global clock and PRNG functions, never a `JsValue`, so the bound holds.
pub type SqlFunctionInstaller = Arc<dyn Fn(&mut SqliteConnection) -> QueryResult<()> + Send + Sync>;

/// The custom SQLite functions connetto registers on every replica connection
/// it opens. Empty by default: connetto ships no built-in functions, so each
/// app registers the functions its schema names (a `uuidv7` key generator, for
/// instance) through [`with`](SqlFunctions::with).
///
/// A replica connection runs with trusted schema off (see
/// [`crate::harden`]), so a function a schema object reaches (a column
/// `DEFAULT`, a view, a trigger, a `CHECK`, a generated column, an expression
/// index) must be registered with `SqliteFunctionBehavior::INNOCUOUS`, through
/// `register_impl_with_behavior` rather than `register_impl` or
/// `register_nondeterministic_impl`. Without it SQLite refuses the call as
/// "unsafe use of `f()`" when the schema object runs, not when the function is
/// registered.
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

    /// Combine this list with `other`, `other`'s installers last.
    #[must_use]
    pub fn merged(mut self, other: SqlFunctions) -> Self {
        self.0.extend(other.0);
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
/// translation to, which is what [`SyncSchema`] carries. Deriving
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

/// Default percentage of the replica's pages that must sit on the freelist
/// before the trimming pass reclaims any. A file with little slack is left
/// alone rather than vacuumed for nothing (R15).
pub const DEFAULT_TRIM_THRESHOLD: u8 = 25;

/// Default number of pages one `incremental_vacuum` call reclaims, so a large
/// freelist is returned to the filesystem in bounded steps rather than one
/// stalling pass (R15).
pub const DEFAULT_TRIM_BUDGET: u32 = 1000;

/// Default cap on the number of distinct rested statistics (one query plus
/// binds, however many group rows it holds) the resting table keeps. Past it,
/// the statistic updated longest ago that no handle currently watches is
/// evicted, so the last N statistics you watched survive a restart (R83).
pub const DEFAULT_RESTED_STATISTICS_CAP: usize = 256;

/// Default number of applied rows, summed across tables, at which the
/// residual pass and its crossing event arm (R60 decision 4). A pass over a
/// replica this size costs well under a second on any target device.
pub const DEFAULT_RESIDUAL_THRESHOLD: u64 = 10_000;

/// Who runs the residual eviction pass when the applied-rows measure crosses
/// its threshold (R60 decision 3). The crossing event is delivered either
/// way: connetto supplies the signal, this decides who acts on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResidualPass {
    /// The connection runs [`ConnettoConnection::tidy`] itself at the
    /// crossing, then resets the measure. The default.
    #[default]
    Automatic,
    /// The application supplants the default: it observes
    /// [`ClientEvent::TidyDue`] and calls [`ConnettoConnection::tidy`] at a
    /// moment of its own choosing.
    Manual,
}

/// The accumulation measure behind the residual pass (R60 decision 4),
/// queryable at any time through
/// [`ConnettoConnection::residual_pressure`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualPressure {
    /// Rows applied per table since the last `tidy`, sorted by table name.
    pub rows_applied: Vec<(String, u64)>,
    /// Percentage of the replica's pages sitting on the freelist, the same
    /// ratio the trim gate reads.
    pub freelist_percent: u8,
}

/// The subject set a replica answers its membership arms with.
///
/// Holds the grants beside their subjects so the rendering can drop a key
/// whose grant has died, which is what keeps the replica from admitting rows
/// the server refuses.
#[derive(Debug, Clone)]
struct SubjectSource {
    function: String,
    set: ShareKeySet,
}

impl SubjectSource {
    /// The live subjects at `now`, sorted and deduplicated.
    fn live_subjects(&self, now: i64) -> Vec<&str> {
        let mut alive: Vec<&str> = self
            .set
            .keys
            .iter()
            .filter(|(grant, _)| !grant_expiry::has_expired(grant, now))
            .map(|(_, subject)| subject.as_str())
            .collect();
        alive.sort_unstable();
        alive.dedup();
        alive
    }

    /// The value the registered function answers at `now`, or `None` when the
    /// caller holds no key that is still alive.
    ///
    /// Sorted and deduplicated, so one holder renders one value whatever order
    /// its keys arrived in, and joined by the deployment's own separator, which
    /// no single key may contain.
    fn rendered(&self, now: i64) -> Option<String> {
        let alive = self.live_subjects(now);
        (!alive.is_empty()).then(|| alive.join(&self.set.separator.to_string()))
    }

    /// Every grant the handshake should present for these keys.
    fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.set.keys.iter().map(|(grant, _)| grant)
    }
}

/// What the client presents at the handshake.
#[derive(Debug, Clone)]
pub(crate) struct ClientConfig {
    /// Stable client id, echoed for logging and correlation. Never a trust
    /// input on the server.
    client_id: String,
    /// The login grant, when somebody is signed in. `None` is a caller with no
    /// identity, which the server accepts: it reads whatever the deployment's
    /// policy shows such a caller and writes only where a capability says it
    /// may.
    ///
    /// It is separate from the share keys' grants because only this one
    /// refreshes, a token source, when set, replacing it on every reconnect.
    /// On the wire they are one undifferentiated list.
    login: Option<Grant>,
    /// The schema version this client build was compiled against, for staleness
    /// detection, or `None` to opt out. When both this and the server's ack
    /// carry a version and they differ, the handshake fails
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
    /// Tables whose missing primary key is intentional, so connetto records
    /// nothing for them and the application accepted that. Empty by default,
    /// and every other unkeyed table is refused
    /// ([`ClientError::WritesNotRecorded`]). Lowercased, since SQLite table
    /// names are ASCII-case-insensitive.
    unrecorded_tables: HashSet<String>,
    /// What a translated policy means by the caller: the SQLite function name
    /// the deployment mapped `current_setting` onto, and the value it returns.
    ///
    /// `None` when no policy names the caller, which is every schema until one
    /// does. Fixed for the life of the connection, because a replica belongs
    /// to the identity it was named from.
    caller: Option<(String, String)>,
    /// What a translated policy means by the caller's subject set: the SQLite
    /// function name the deployment mapped its subjects setting onto, the
    /// separator it joins the set with, and each key the caller holds as the
    /// grant that proves it beside the subject it renders as.
    ///
    /// The pair travels rather than the rendering alone, because the two
    /// halves answer different ends and may not disagree: the grant is what
    /// the handshake presents, so the server reads the key into the setting it
    /// binds, and the subject is what the replica compares locally. Registering
    /// a subject whose grant has died would leave a durable replica serving
    /// rows the server refuses, so the set is rendered from the same live
    /// grants the handshake presents.
    ///
    /// `None` when no policy names the set.
    subjects: Option<SubjectSource>,
    /// The local tuning levers, the trim pass, the resting cap, the residual
    /// pass and the watch grace. Never a handshake input.
    tuning: SyncTuning,
    /// How the key protecting this connection is held. The default is honest
    /// for every native target today: no native gate exists until R51 and R52
    /// land, so reporting anything stronger would claim protection connetto
    /// does not yet provide.
    custody: Custody,
    shared_layout: Option<Arc<connetto_core::schema::SharedLayout>>,
    shared_tables: HashSet<String>,
    connection_ddl: Option<Arc<str>>,
    /// Whether this connection mirrors a relay's worker, which holds the share
    /// keys, so a key change travels to the relay instead of committing here.
    relay_mirror: bool,
}

impl ClientConfig {
    /// Build a config for a client with the given id, no login, no share keys,
    /// no schema version, no custom SQL functions, and no split tables.
    #[must_use]
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            login: None,
            schema_version: None,
            sql_functions: SqlFunctions::default(),
            policy_tables: PolicyTables::default(),
            unrecorded_tables: HashSet::new(),
            caller: None,
            subjects: None,
            tuning: SyncTuning::default(),
            custody: Custody::Unverified(NoGate::Unsupported),
            shared_layout: None,
            shared_tables: HashSet::new(),
            connection_ddl: None,
            relay_mirror: false,
        }
    }

    /// Fold the device's storage layout into the open configuration.
    fn with_storage_schema(mut self, schema: &SyncSchema) -> Self {
        self.shared_layout = schema.shared_layout().cloned().map(Arc::new);
        if self.shared_layout.is_some() {
            self.shared_tables = schema.shared_tables().map(str::to_lowercase).collect();
        }
        self.connection_ddl =
            (!schema.connection_ddl().is_empty()).then(|| Arc::from(schema.connection_ddl()));
        self
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
    /// `with_session_variable`, and `identity` is who the caller is, or `None`
    /// when nobody is signed in. connetto registers the function on the
    /// replica connection beside the application's own functions, because the
    /// generated view and its three `INSTEAD OF` triggers call it and would
    /// otherwise fail to resolve on the first read.
    ///
    /// An unheld identity renders as [`absent_marker`], the same shape the
    /// server binds, rather than as `""`. An empty string is a real identity
    /// that a row can carry, so a replica answering `""` would show its holder
    /// rows the server hides.
    ///
    /// [`absent_marker`]: connetto_core::auth::absent_marker
    #[must_use]
    pub fn with_caller(
        mut self,
        function: impl Into<String>,
        identity: Option<impl Into<String>>,
    ) -> Self {
        let identity = identity.map_or_else(
            || connetto_core::auth::absent_marker().to_owned(),
            Into::into,
        );
        self.caller = Some((function.into(), identity));
        self
    }

    /// What the replica's translated policies mean by the caller's subject
    /// set, the share keys it holds, each as the grant that proves it beside
    /// the subject it names, rendered to subject strings through the
    /// deployment's `CapabilityKey` separator. Applied on every platform by
    /// the builders.
    ///
    /// Both halves of a key travel together because they answer different
    /// ends. The grant is what the handshake presents, so the server reads the
    /// key into the setting it binds, and the subject is what the replica
    /// compares locally. A subject whose grant has died is left out of the
    /// rendering, so a durable replica serves only what the server still
    /// admits.
    #[must_use]
    pub(crate) fn with_share_keys_rendered(
        mut self,
        separator: char,
        keys: Vec<(Grant, String)>,
    ) -> Self {
        self.subjects = Some(SubjectSource {
            function: SUBJECTS_FUNCTION.to_owned(),
            set: ShareKeySet::rendered(separator, keys),
        });
        self
    }

    /// Mark the connection as a relay tab's mirror (R95 decision 17).
    #[must_use]
    pub(crate) fn with_relay_mirror(mut self, relay_mirror: bool) -> Self {
        self.relay_mirror = relay_mirror;
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

    /// Tables whose missing primary key is intentional, accepting that
    /// connetto records nothing for them.
    ///
    /// A settings singleton, a rebuilt cache or a log ordered by `rowid` has no
    /// natural key, and naming one here is how an application says so. Every
    /// unkeyed table not named is refused when the replica opens, or at the
    /// next write when the application created it later, and so is a name here
    /// that does declare a key, since the two would then disagree
    /// ([`ClientError::WritesNotRecorded`]).
    ///
    /// An unrecorded table stays readable and writable locally on native,
    /// where a live query re-reads it after SQLite's update hook reports the
    /// write. In a browser it does not: the worker holds the database and a tab
    /// reads through the relay, which builds a tab's copy as a session diff,
    /// so a tab sees an unrecorded table as empty.
    #[must_use]
    pub fn with_unrecorded_tables(
        mut self,
        tables: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.unrecorded_tables = tables
            .into_iter()
            .map(|table| table.into().to_lowercase())
            .collect();
        self
    }

    /// Custom SQLite functions registered before any DDL or insert.
    #[must_use]
    pub fn with_sql_functions(mut self, sql_functions: SqlFunctions) -> Self {
        self.sql_functions = sql_functions;
        self
    }

    /// The local tuning levers the build carries.
    #[must_use]
    pub fn with_tuning(mut self, tuning: SyncTuning) -> Self {
        self.tuning = tuning;
        self
    }

    /// The custody level to report for this connection.
    ///
    /// The right value to pass here is the one the platform's key-management
    /// layer can honestly claim. Passing [`Custody::Verified`] without a real
    /// user-verified gate in place would report protection connetto does not
    /// provide. The default, `Custody::Unverified(NoGate::Unsupported)`, is
    /// the honest value for every native target until R51 and R52 land.
    #[must_use]
    pub fn with_custody(mut self, custody: Custody) -> Self {
        self.custody = custody;
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
        /// JSON-encoded aggregate value, or `None` when this key was removed
        /// from the result set (the group or keyed row departed).
        result_json: Option<String>,
        /// Opaque group key, or `None` for a single-group aggregate.
        group_key: Option<Vec<u8>>,
        /// The decoded group values as a JSON array in `GROUP BY` order,
        /// present exactly when `group_key` is. A typed keyed handle decodes
        /// its public map key from these, never from the key bytes (R84).
        group_values_json: Option<String>,
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
    /// The server opened a membership subscription on this client's behalf
    /// (R27): a filter narrowing through a membership table needs that
    /// table's rows on the replica for the offline answer and for the policy
    /// view. Its table stays out of [`Reactive::changed_tables`], and the
    /// server owns its lifecycle, so nothing needs doing with this event.
    MembershipOpened {
        /// The hidden subscription's server-chosen label.
        sub_id: String,
        /// The membership table it reads.
        member_table: String,
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
    /// The server refused a mutation and the client rolled it back locally.
    MutationRejected {
        /// The rejected mutation's sequence number.
        client_seq: u64,
        /// The server's reason for refusing the write.
        reason: MutationRejectReason,
        /// Rows the rejected write touched, rolled back locally.
        rows: Vec<AffectedRow>,
    },
    /// The server could not settle a prior mutation yet, so it stays pending
    /// on the replica, rows and all, and is sent again. A later
    /// [`MutationApplied`](Self::MutationApplied),
    /// [`MutationRejected`](Self::MutationRejected) or
    /// [`MutationConflict`](Self::MutationConflict) for the same sequence
    /// settles it.
    MutationDeferred {
        /// The deferred mutation's sequence number.
        client_seq: u64,
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
    /// The server granted a content ticket: an address to fetch or upload the
    /// named file's bytes at, the ticket already inside it. Correlated to the
    /// request by `request_id`, and a refusal of the same request arrives as
    /// [`NonFatal`](Self::NonFatal) or [`RateLimited`](Self::RateLimited)
    /// carrying that id in `related_to`.
    ContentTicket {
        /// The correlation token the request chose.
        request_id: String,
        /// Where to send the request, ticket included.
        url: String,
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
    /// The pump stopped on a fault no reconnect can cure, and said which.
    /// [`Closed`](Self::Closed) follows, and every live handle's `changed`
    /// returns [`ClientError::Stopped`] from then on.
    Stopped {
        /// The fault, as text.
        detail: String,
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
    /// The applied-rows measure crossed the configured residual threshold
    /// (R60): enough rows have arrived since the last `tidy` that a pass is
    /// worth running. Fires once per crossing and re-arms when a pass resets
    /// the measure. Under [`ResidualPass::Automatic`] the connection has
    /// already run the pass, successfully, by the time this is observed: a
    /// failed pass surfaces as the pump error instead and retries at the
    /// next apply. Under [`ResidualPass::Manual`] it is the application's
    /// cue.
    TidyDue {
        /// Rows applied across all tables since the last pass, at the
        /// crossing. The per-table breakdown is
        /// [`ConnettoConnection::residual_pressure`].
        rows_applied: u64,
    },
    /// The gate is locked. Application reads, writes, and new watches are
    /// refused with [`ClientError::Locked`], and live-handle refreshes are
    /// held. The replica connection and sync keep running.
    Locked,
    /// The gate is unlocked. Application access resumes, held live-handle
    /// refreshes are flushed, and each affected handle wakes once.
    Unlocked,
    /// The gate's prompt was dismissed or failed, so the gate stays locked.
    /// The next return or [`ConnettoClient::unlock`] asks again, which is
    /// what an application offers a retry through.
    UnlockDismissed,
    /// A relay stated who its worker is signed in as, and this tab's mirror
    /// now answers its policy views as that caller. Every live query over
    /// the replica refreshes.
    IdentityStated,
    /// A renewal asked for a certificate lifetime over the server's ceiling,
    /// which its operator lowered, and was granted at the ceiling (R74).
    CertificateLifetimeCapped {
        /// The lifetime asked for.
        requested: Duration,
        /// The ceiling granted instead, which later renewals ask for.
        ceiling: Duration,
    },
    /// The server refused this device's key as revoked, so the key and its
    /// certificate are deleted and the device holds no identity (R74).
    DeviceRevoked,
    /// The root revoked the issuer of this device's certificate, so peers
    /// refuse it. The certificate is deleted, the key kept, and the device
    /// enrols the key again on its next connection (R74 decision 24).
    CertificateWithdrawn,
    /// The local clock puts this device's certificate outside its validity
    /// window, so peers will refuse it until the clock is set right (R74
    /// decision 29). Raised once on entering the state, when a certificate the
    /// server just granted is already outside its window or one held at open
    /// is not yet valid. `ahead` is whether the clock runs ahead of the
    /// server's.
    ClockOutsideWindow {
        /// Whether the local clock is ahead, so the certificate looks expired,
        /// rather than behind, so it looks not yet valid.
        ahead: bool,
    },
    /// The deployment's accepted attestation levels exclude this device's, so
    /// its enrolment is refused. A device holding a certificate keeps it
    /// until it expires, and the device asks again only on its next
    /// connection, since its level cannot change (R74 decision 33).
    AttestationRequired,
    /// A peer device is now linked (R76).
    #[cfg(feature = "peer")]
    PeerLinked {
        /// The peer the link reached.
        peer: DeviceIdentity,
    },
    /// A peer link closed, with the reason (R76).
    #[cfg(feature = "peer")]
    PeerUnlinked {
        /// The peer the link fell from.
        peer: DeviceIdentity,
        /// Why the link closed.
        reason: CloseReason,
    },
    /// The device's certificate passed its expiry plus the tolerance, so
    /// `link_peer` refuses until the device renews (R76).
    #[cfg(feature = "peer")]
    CertificateExpired,
    /// The peer listener could not bind, so the device dials but does not
    /// serve until the next standing change (R76).
    #[cfg(feature = "peer")]
    PeerListenFailed {
        /// The address the listener could not bind.
        address: SocketAddr,
        /// Why the bind failed.
        error: String,
    },
    /// Discovery found a peer instance at `address` (R76).
    #[cfg(feature = "peer")]
    PeerFound {
        /// The resolved address to dial.
        address: SocketAddr,
        /// The instance's leaf fingerprint.
        fingerprint: connetto_peer::Fingerprint,
    },
    /// Discovery lost a peer instance (R76).
    #[cfg(feature = "peer")]
    PeerGone {
        /// The instance's leaf fingerprint.
        fingerprint: connetto_peer::Fingerprint,
    },
    /// The hotspot stopped, on a system stop (R76).
    #[cfg(feature = "peer")]
    HotspotStopped,
    /// The personal hotspot's offer was handed out but no device landed on
    /// the network within its bound (R76 decision 26).
    #[cfg(feature = "peer")]
    HotspotUnreached,
    /// The joined network was left (R76).
    #[cfg(feature = "peer")]
    HotspotLeft,
    /// The redial to its joined hotspot's gateway passed its bound with no
    /// link standing, so it stopped (R76).
    #[cfg(feature = "peer")]
    JoinedHostUnreached,
    /// A VPN on this device that apps cannot bypass refused the joined
    /// hotspot's dial, so the redial stopped and only peers that connect to
    /// this device over the hotspot can link with it (R76).
    #[cfg(feature = "peer")]
    JoinedNetworkBlockedByVpn,
    /// The platform's Bluetooth standing changed (R76 decision 21).
    #[cfg(feature = "peer")]
    BluetoothChanged {
        /// The standing the platform reports.
        state: crate::bluetooth::BluetoothState,
    },
    /// A nearby host's beacon was seen, or its beacon changed (R76
    /// decisions 19 and 25).
    #[cfg(feature = "peer")]
    HostNearby {
        /// The host's device.
        host: crate::bluetooth::HostId,
        /// The beacon's prefix, where the beacon carries one (R76 decision
        /// 25).
        prefix: Option<[u8; 8]>,
        /// The signal the beacon carried.
        rssi: Option<i16>,
    },
    /// A nearby host's beacon was not seen for its bound (R76 decision 19).
    #[cfg(feature = "peer")]
    HostGone {
        /// The host's device.
        host: crate::bluetooth::HostId,
    },
    /// The server accepted a share-key replacement and queued its authorization resends.
    ShareKeysReplaced {
        /// The correlation token the swap it answers carried.
        request_id: String,
    },
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

/// The schedule a deferred write is sent again on. Uncapped, because a write
/// the server could not settle is kept like an offline one.
static RESEND_POLICY: std::sync::LazyLock<RetryPolicy> = std::sync::LazyLock::new(RetryPolicy::new);

/// Where sending the deferred writes again stands.
enum Resend {
    /// Nothing is deferred.
    Idle,
    /// Every pending write goes out again once `timer` elapses.
    Waiting {
        episode: Backoff<'static>,
        timer: ResendTimer,
    },
    /// Every pending write went out again, and no answer has settled the deferral yet.
    Resent { episode: Backoff<'static> },
}

/// One armed resend of the writes the server deferred, for whoever drives the
/// pump to sleep on before calling [`ConnettoConnection::resend_deferred`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResendTimer {
    armed: u64,
    wait: Duration,
}

impl ResendTimer {
    /// How long to wait before sending the deferred writes again.
    #[must_use]
    pub const fn wait(&self) -> Duration {
        self.wait
    }
}

/// Computed declarations awaiting a correlated server-processing fence.
#[derive(Debug, Clone)]
struct DeclarationFence {
    /// The nonce the pong must carry, drawn from the high-bit namespace so it
    /// cannot collide with the application's own pings.
    nonce: u64,
    /// The instant the answer bound expires.
    deadline: Duration,
    /// The declarations counted when the fence went out.
    count: u64,
    /// The computed `sub_id`s declared before the fence, dropped on the pong.
    sub_ids: Vec<String>,
}

/// A share-key replacement awaiting its correlated answer.
#[derive(Debug, Clone)]
struct ShareKeyRequest {
    /// The correlation token the answer quotes.
    request_id: String,
    /// The generation the swap carried.
    generation: u64,
    /// The instant the answer bound expires.
    deadline: Duration,
}

/// A tab's share-key change awaiting its relay's answer.
#[derive(Debug)]
struct RelayShareKeyWait {
    /// Where the outcome goes.
    answer: tokio::sync::oneshot::Sender<Result<(), ClientError>>,
    /// The instant the answer bound expires.
    deadline: Duration,
}

/// The next share-key wake for a pump driver.
#[derive(Debug, Clone, Copy)]
pub struct ShareKeyTimer {
    /// How many times the timer was armed, so a pump tells a fresh one from the
    /// one it sleeps on.
    armed: u64,
    /// The instant the next share-key work is due.
    deadline: Duration,
}

impl ShareKeyTimer {
    /// How long to wait before the next share-key work.
    #[must_use]
    pub fn wait(&self) -> Duration {
        self.deadline
            .saturating_sub(crate::away::SystemClock.monotonic())
    }
}

impl PartialEq for ShareKeyTimer {
    fn eq(&self, other: &Self) -> bool {
        self.armed == other.armed
    }
}

impl Eq for ShareKeyTimer {}

/// Conflict resolution for a rollback: a row a concurrent server patch already
/// changed is left as the server left it, so only a cleanly-matching optimistic
/// write is reverted.
fn rollback_omit(_conflict: ConflictType) -> ConflictAction {
    ConflictAction::Omit
}

/// Suspends the capture session for the duration of a server-originated
/// apply (a patch or a rollback), so the session never records what the
/// server already knows, and holds the write exemption true for the same
/// span, so the translated schema's fail-closed guards admit the write (the
/// policy already judged it where it was authored). Re-enables capture and
/// drops the exemption on drop, so no exit path can leave either switched.
/// `set_enabled` is a plain setter and cannot panic.
struct SuspendedCapture<'s> {
    session: &'s mut Session,
    exempt: Arc<AtomicBool>,
}

impl<'s> SuspendedCapture<'s> {
    fn new(session: &'s mut Session, exempt: &Arc<AtomicBool>) -> Self {
        session.set_enabled(false);
        exempt.store(true, Ordering::Relaxed);
        Self {
            session,
            exempt: Arc::clone(exempt),
        }
    }
}

impl Drop for SuspendedCapture<'_> {
    fn drop(&mut self) {
        self.exempt.store(false, Ordering::Relaxed);
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

/// DDL for the replica-local metadata, written only under capture suspension.
const META_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_meta \
    (id INTEGER PRIMARY KEY CHECK (id = 1), cursor BLOB NOT NULL, cursor_subjects BLOB); \
    CREATE TABLE IF NOT EXISTS _connetto_writers \
    (id TEXT NOT NULL PRIMARY KEY, next_seq INTEGER NOT NULL, head BLOB NOT NULL); \
    CREATE TABLE IF NOT EXISTS _connetto_pending \
    (writer TEXT NOT NULL, seq INTEGER NOT NULL, changeset BLOB NOT NULL, \
     entry_hash BLOB NOT NULL, position INTEGER NOT NULL, \
     prov_writer TEXT, prov_seq INTEGER, \
     PRIMARY KEY (writer, seq)); \
    CREATE TABLE IF NOT EXISTS _connetto_retire \
    (writer TEXT NOT NULL PRIMARY KEY); \
    CREATE TABLE IF NOT EXISTS _connetto_retired_keys \
    (key_id BLOB NOT NULL PRIMARY KEY)";

/// The attach name of the local tier database. An internal constant: authored
/// SQL never names it, since bare table names resolve across attached
/// databases and duplicate names across tiers are a generation-time error.
const LOCAL_SCHEMA: &str = "connetto_local";
const SHARED_SCHEMA: &str = "connetto_shared";

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
/// application data. `sqlite_master` of an attached database has no `table!` to
/// query through, which is why this one stays a catalogue read.
fn local_tier_tables(db: &mut SqliteConnection) -> Result<HashSet<String>, ClientError> {
    let rows: Vec<SchemaTableRow> = diesel::sql_query(format!(
        "SELECT name FROM {LOCAL_SCHEMA}.sqlite_master WHERE type = 'table' \
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
    #[sql_name = "sqlite_master"]
    sqlite_catalog (name) {
        /// The object kind: `table`, `view`, `index` or `trigger`.
        #[sql_name = "type"]
        kind -> diesel::sql_types::Text,
        /// The object name.
        name -> diesel::sql_types::Text,
    }
}

diesel::table! {
    /// Durable writer frontiers.
    _connetto_writers (id) {
        /// The writer identity.
        id -> diesel::sql_types::Text,
        /// The next sequence to append.
        next_seq -> diesel::sql_types::BigInt,
        /// The last appended entry hash.
        head -> diesel::sql_types::Binary,
    }
}

diesel::table! {
    /// Outstanding entries ordered across writers by append position.
    _connetto_pending (writer, seq) {
        /// The current writer identity.
        writer -> diesel::sql_types::Text,
        /// The sequence under the current writer.
        seq -> diesel::sql_types::BigInt,
        /// The captured physical changeset.
        changeset -> diesel::sql_types::Binary,
        /// The logical changeset's chain hash.
        entry_hash -> diesel::sql_types::Binary,
        /// The replica-wide append position.
        position -> diesel::sql_types::BigInt,
        /// The original writer identity.
        prov_writer -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
        /// The original writer's sequence.
        prov_seq -> diesel::sql_types::Nullable<diesel::sql_types::BigInt>,
    }
}

diesel::table! {
    /// The writers owed a retirement on the next connection.
    _connetto_retire (writer) {
        /// The writer awaiting retirement.
        writer -> diesel::sql_types::Text,
    }
}

diesel::table! {
    /// Keys durably excluded from writer selection.
    _connetto_retired_keys (key_id) {
        /// The retired device key.
        key_id -> diesel::sql_types::Binary,
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
    let rows: Vec<SchemaTableRow> = diesel::sql_query(
        "SELECT name FROM main.sqlite_master WHERE type = 'view' \
         UNION SELECT name FROM temp.sqlite_master WHERE type = 'view'",
    )
    .load(db)?;
    let present: HashSet<String> = rows
        .into_iter()
        .map(|row| row.name.to_lowercase())
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

/// Register the no-argument function a translated policy calls for the
/// caller's subject set.
///
/// It answers the packed set rather than one value, because that is what the
/// server binds into the setting and what the membership test the policy
/// compiles unpacks. `NULL` for a caller holding no key, which is what makes
/// an absent capability fail closed: a comparison against `NULL` is `NULL`
/// rather than true.
fn register_subjects(
    db: &mut SqliteConnection,
    function: &str,
    packed: Option<String>,
) -> Result<(), ClientError> {
    db.register_noarg_sql_function::<diesel::sql_types::Nullable<diesel::sql_types::Text>, _, _>(
        function,
        SqliteFunctionBehavior::DETERMINISTIC | SqliteFunctionBehavior::INNOCUOUS,
        move || packed.clone(),
    )
    .map_err(|e| ClientError::Session(format!("registering the subjects function: {e}")))
}

/// Register the no-argument function a translated cap policy calls for the
/// caller's bot list, so the replica holds a caller to the same list
/// Postgres holds it to.
fn register_bot_list(db: &mut SqliteConnection, list: String) -> Result<(), ClientError> {
    db.register_noarg_sql_function::<diesel::sql_types::Text, _, _>(
        connetto_core::BOT_LIST_FUNCTION,
        SqliteFunctionBehavior::DETERMINISTIC | SqliteFunctionBehavior::INNOCUOUS,
        move || list.clone(),
    )
    .map_err(|e| ClientError::Session(format!("registering the bot list function: {e}")))
}

/// The SQLite function a translated schema's write guards call to let
/// connetto's own writes land underneath the policy triggers.
///
/// pg2sqlite's write guards are fail-closed: a translation built with
/// `with_write_exemption_function` names one function, and a backing-table
/// write is admitted only while that function returns true. connetto holds it
/// true exactly while its capture session is suspended, which is every write
/// connetto authors itself: applying server-authoritative patches, rolling a
/// refused mutation back, evicting uncovered rows, and its own bookkeeping.
/// The application's writes always see it false, so the policy judges them.
/// Register [`connetto_core::WRITE_EXEMPTION_FUNCTION`] backed by `flag`.
///
/// A build that translates its schema with policies passes the same name to
/// `Pg2SqliteOptions::with_write_exemption_function`. connetto registers the
/// function on every replica connection it opens, whether or not the schema
/// names it.
///
/// Nondeterministic on purpose: its value changes between statements (the
/// suspension guard flips it), so SQLite must not hoist or cache it the way
/// the caller function invites. Innocuous because the generated triggers are
/// exactly the schema objects it has to be callable from.
fn register_write_exemption(
    db: &mut SqliteConnection,
    flag: &Arc<AtomicBool>,
) -> Result<(), ClientError> {
    let flag = Arc::clone(flag);
    db.register_noarg_sql_function::<diesel::sql_types::Bool, _, _>(
        connetto_core::WRITE_EXEMPTION_FUNCTION,
        SqliteFunctionBehavior::INNOCUOUS,
        move || flag.load(Ordering::Relaxed),
    )
    .map_err(|e| ClientError::Session(format!("registering the write exemption function: {e}")))
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

/// The schema an export's empty twins live under while the row patchset is
/// taken. Its own name because the relay attaches a `blank` of its own to this
/// same connection, and two attachments cannot share one name.
const EXPORT_BLANK_SCHEMA: &str = "connetto_export_blank";

#[derive(diesel::QueryableByName)]
struct SchemaDdlRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    sql: Option<String>,
}

/// One exported table: its name on the replica and its stored DDL, which the
/// empty twin the rows are diffed against is built from.
///
/// Names travel verbatim, backing name and all: both ends of an archive run
/// the same build, which the schema fingerprint enforces, so renaming a
/// policy-split table to its logical name would only be a step to undo on the
/// way back in (R56 decision 10).
struct ExportTable {
    name: String,
    ddl: String,
}
#[derive(diesel::QueryableByName)]
struct ExportKeyRow {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    key_columns: i64,
}

/// Every row of one schema, as the change record an import applies.
///
/// The rows are diffed against empty twins, which is what the relay does to
/// build a tab's snapshot, and the record travels as it comes out: `R26`
/// replayed it into a second database and serialized that, which is the half
/// `R56` decision 10 deleted.
fn export_rows(
    source: &mut SqliteConnection,
    source_schema: &str,
    include: Option<&HashSet<String>>,
    hidden: &HashSet<String>,
    accepted: &HashSet<String>,
) -> Result<Vec<u8>, ClientError> {
    let rows = schema_ddl_rows(source, source_schema)?;
    let mut tables = Vec::new();
    for row in &rows {
        if !export_table_allowed(&row.name, include, hidden) {
            continue;
        }
        let Some(ddl) = row.sql.as_ref() else {
            continue;
        };
        // A table with no primary key cannot be attached to a session, so its
        // rows would be absent from the record. One the application declared
        // unrecorded is skipped, which is what the declaration means, and any
        // other is refused: that beats handing over an archive whose tables
        // are all present and one of them empty.
        if key_columns(source, source_schema, &row.name)? == 0 {
            if accepted.contains(&row.name.to_lowercase()) {
                continue;
            }
            return Err(ClientError::Export(format!(
                "table {} has no primary key, so its rows cannot be exported",
                row.name
            )));
        }
        tables.push(ExportTable {
            name: row.name.clone(),
            ddl: ddl.clone(),
        });
    }
    if tables.is_empty() {
        return Ok(Vec::new());
    }
    // An in-memory database needs no creation permit, only the write one: the
    // twins are created inside it.
    harden::attach_in_window(
        source,
        ":memory:",
        EXPORT_BLANK_SCHEMA,
        harden::AttachPermits::Write,
    )?;
    let patchset = export_patchset(source, source_schema, &tables);
    let detached = source
        .batch_execute(&format!(
            "DETACH DATABASE {}",
            quote_ident(EXPORT_BLANK_SCHEMA)
        ))
        .map_err(ClientError::from)
        .and_then(|()| harden::seal_attaches(source).map_err(ClientError::from));
    let patchset = patchset?;
    detached?;
    Ok(patchset)
}

/// The patchset holding every row of `tables`, taken against empty twins in
/// the already-attached blank schema.
fn export_patchset(
    source: &mut SqliteConnection,
    source_schema: &str,
    tables: &[ExportTable],
) -> Result<Vec<u8>, ClientError> {
    for table in tables {
        let twin = rename_create_table(
            &table.ddl,
            &format!(
                "{}.{}",
                quote_ident(EXPORT_BLANK_SCHEMA),
                quote_ident(&table.name)
            ),
        )?;
        source.batch_execute(&twin)?;
    }
    let mut session = source
        .create_session_on(source_schema)
        .map_err(|err| ClientError::Export(format!("opening the export session: {err}")))?;
    for table in tables {
        session
            .attach_by_name(&table.name)
            .map_err(|err| ClientError::Export(format!("reading {}: {err}", table.name)))?;
        session
            .diff(EXPORT_BLANK_SCHEMA, &table.name)
            .map_err(|err| ClientError::Export(format!("reading {}: {err}", table.name)))?;
    }
    session
        .patchset()
        .map_err(|err| ClientError::Export(format!("encoding the exported rows: {err}")))
}

/// How many columns make up `table`'s primary key, zero for a rowid table
/// that declared none.
fn key_columns(
    source: &mut SqliteConnection,
    source_schema: &str,
    table: &str,
) -> Result<i64, ClientError> {
    let rows: Vec<ExportKeyRow> = diesel::sql_query(format!(
        "SELECT count(*) AS key_columns FROM {}.pragma_table_info(?) WHERE pk > 0",
        quote_ident(source_schema)
    ))
    .bind::<diesel::sql_types::Text, _>(table)
    .load(source)?;
    Ok(rows.first().map_or(0, |row| row.key_columns))
}

/// The tables of one schema, in creation order, each with the DDL SQLite kept.
fn schema_ddl_rows(
    db: &mut SqliteConnection,
    source_schema: &str,
) -> Result<Vec<SchemaDdlRow>, ClientError> {
    diesel::sql_query(format!(
        "SELECT name, sql FROM {}.sqlite_master \
         WHERE type = 'table' AND sql IS NOT NULL ORDER BY rowid",
        quote_ident(source_schema)
    ))
    .load(db)
    .map_err(ClientError::from)
}

/// What a refusal calls the database holding the table, since a refused write
/// over a device-private table never travelled anywhere.
fn schema_label(schema: &str) -> &'static str {
    if schema == LOCAL_SCHEMA {
        "device-private"
    } else {
        "synced"
    }
}

/// Refuse the tables of `schema` whose changes connetto cannot record.
///
/// SQLite records nothing for a table whose only key is the implicit `rowid`,
/// so a write to one is never uploaded and never reaches a sibling browser
/// tab, and nothing else notices. `accepted` names the tables whose missing
/// key the application declared intentional, and a name in it that does
/// declare a key is refused for the opposite reason (R62).
fn check_recorded_tables(
    db: &mut SqliteConnection,
    schema: &str,
    accepted: &HashSet<String>,
) -> Result<(), ClientError> {
    let where_it_is = schema_label(schema);
    let mut tables = Vec::new();
    for row in schema_ddl_rows(db, schema)? {
        if is_internal_table(&row.name) {
            continue;
        }
        let keyed = key_columns(db, schema, &row.name)? > 0;
        match (keyed, accepted.contains(&row.name.to_lowercase())) {
            (false, false) => tables.push(format!(
                "{} in the {where_it_is} database declares no primary key, so SQLite records \
                 nothing for it and writes to it are lost: declare one (a single-row table wants \
                 id INTEGER PRIMARY KEY CHECK (id = 1)), or accept the loss with \
                 SyncSchema::with_unrecorded_tables",
                row.name
            )),
            (true, true) => tables.push(format!(
                "{} in the {where_it_is} database declares a primary key and is named in \
                 SyncSchema::with_unrecorded_tables, so the two disagree: drop the name to sync \
                 it, or drop the key to keep it local",
                row.name
            )),
            _ => {}
        }
    }
    if tables.is_empty() {
        return Ok(());
    }
    tables.sort();
    Err(ClientError::WritesNotRecorded { tables })
}

#[derive(diesel::QueryableByName)]
struct SchemaCookie {
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    schema_version: i64,
}

/// SQLite's schema cookie for one database, which changes on any DDL. One
/// integer read, so the write path can tell whether the key check has anything
/// new to look at.
fn schema_cookie(db: &mut SqliteConnection, schema: &str) -> Result<i64, ClientError> {
    let rows: Vec<SchemaCookie> =
        diesel::sql_query(format!("PRAGMA {}.schema_version", quote_ident(schema))).load(db)?;
    Ok(rows.first().map_or(0, |row| row.schema_version))
}

pub(crate) fn export_table_allowed(
    name: &str,
    include: Option<&HashSet<String>>,
    hidden: &HashSet<String>,
) -> bool {
    let lower = name.to_lowercase();
    !is_internal_table(name)
        && !hidden.contains(&lower)
        && include.is_none_or(|tables| tables.contains(&lower))
}

/// Refuse a restored write naming a table this build does not have.
///
/// SQLite skips a table absent from the target rather than reporting it, so
/// without this a queued write would be restored, replayed, and quietly apply
/// nothing (R56 decision 6).
fn pending_tables(
    changeset: &[u8],
    known: &HashMap<String, Vec<String>>,
) -> Result<(), ClientError> {
    let parsed = ParsedDiffSet::parse(changeset)
        .map_err(|err| ClientError::Import(format!("a restored write does not parse: {err}")))?;
    let named: Vec<String> = match &parsed {
        ParsedDiffSet::Changeset(set) => {
            set.iter().map(|op| op.table().name().to_owned()).collect()
        }
        ParsedDiffSet::Patchset(set) => set.iter().map(|op| op.table().name().to_owned()).collect(),
    };
    for table in named {
        if !known.contains_key(&table.to_lowercase()) {
            return Err(ClientError::Import(format!(
                "a queued write names table {table}, which this build does not have"
            )));
        }
    }
    Ok(())
}

type ColumnMap = HashMap<String, Vec<String>>;

fn validate_archive_compat(
    archive: &archive::Incoming,
    fingerprint: &str,
    account: Option<&str>,
) -> Result<(), ClientError> {
    if archive.fingerprint != fingerprint {
        return Err(ClientError::Import(
            "the archive was made under a different schema than this build runs, so it cannot be restored here"
                .to_owned(),
        ));
    }
    if archive.account.as_deref() != account {
        return Err(ClientError::Import(
            "the archive belongs to another account, and an import only ever restores into the account that made it"
                .to_owned(),
        ));
    }
    Ok(())
}

fn resolve_import_columns(
    db: &mut SqliteConnection,
    local_tables: &HashSet<String>,
    hidden: &HashSet<String>,
) -> Result<(ColumnMap, ColumnMap), ClientError> {
    let local_columns = if local_tables.is_empty() {
        HashMap::new()
    } else {
        archive::schema_columns(db, LOCAL_SCHEMA, Some(local_tables), &HashSet::new())?
    };
    let main_columns = archive::schema_columns(db, "main", None, hidden)?;
    Ok((local_columns, main_columns))
}

fn build_import_index(
    db: &mut SqliteConnection,
    archive: &archive::Incoming,
    local_columns: &ColumnMap,
    local_tables: &HashSet<String>,
    unrecorded: &HashSet<String>,
) -> Result<(Vec<archive::rows::IncomingRow>, archive::rows::RowIndex), ClientError> {
    let incoming = match &archive.local_rows {
        Some(rows) => archive::read_rows(rows, local_columns)?,
        None => Vec::new(),
    };
    let held = if local_tables.is_empty() {
        archive::index_rows(&[], local_columns)?
    } else {
        let current = export_rows(
            db,
            LOCAL_SCHEMA,
            Some(local_tables),
            &HashSet::new(),
            unrecorded,
        )?;
        archive::index_rows(&current, local_columns)?
    };
    Ok((incoming, held))
}

fn plan_import_rows(
    incoming: Vec<archive::rows::IncomingRow>,
    held: &archive::rows::RowIndex,
) -> (Vec<archive::PlannedRow>, Vec<Collision>) {
    let mut rows = Vec::with_capacity(incoming.len());
    let mut collisions = Vec::new();
    for row in incoming {
        let collision = match held.get(&(row.table.clone(), row.key.clone())) {
            Some(mine) if *mine != row.values => {
                collisions.push(Collision {
                    table: row.table.clone(),
                    key: row.key.clone(),
                    columns: row.columns.clone(),
                    mine: mine.clone(),
                    theirs: row.values.clone(),
                });
                Some(collisions.len() - 1)
            }
            _ => None,
        };
        rows.push(archive::PlannedRow {
            table: row.table,
            columns: row.columns,
            key_columns: row.key_columns,
            values: row.values,
            collision,
        });
    }
    (rows, collisions)
}

/// Rewrite a stored `CREATE TABLE` statement to name `target`, which is an
/// already-quoted path: a bare name for the archive database, or a qualified
/// one for a twin in the blank schema. Column definitions travel verbatim, so
/// types, defaults and constraints survive.
fn rename_create_table(sql: &str, target: &str) -> Result<String, ClientError> {
    let mut pos = after_keyword(sql, "CREATE TABLE")
        .ok_or_else(|| ClientError::Export(format!("unsupported table DDL: {sql}")))?;
    pos = skip_ws(sql, pos);
    if starts_ci(&sql[pos..], "IF NOT EXISTS") {
        pos += "IF NOT EXISTS".len();
        pos = skip_ws(sql, pos);
    }
    let range = object_path_range(sql, pos)
        .ok_or_else(|| ClientError::Export(format!("unsupported table DDL: {sql}")))?;
    Ok(replace_range(sql, range, target))
}

fn replace_range(sql: &str, range: std::ops::Range<usize>, replacement: &str) -> String {
    let mut renamed = String::with_capacity(sql.len() + replacement.len());
    renamed.push_str(&sql[..range.start]);
    renamed.push_str(replacement);
    renamed.push_str(&sql[range.end..]);
    renamed
}

fn after_keyword(sql: &str, keyword: &str) -> Option<usize> {
    let start = skip_ws(sql, 0);
    starts_ci(&sql[start..], keyword).then_some(start + keyword.len())
}

fn starts_ci(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn skip_ws(value: &str, pos: usize) -> usize {
    value[pos..]
        .char_indices()
        .find_map(|(offset, ch)| (!ch.is_whitespace()).then_some(pos + offset))
        .unwrap_or(value.len())
}

fn object_path_range(sql: &str, pos: usize) -> Option<std::ops::Range<usize>> {
    let start = pos;
    let first = identifier_end(sql, pos)?;
    let after_first = skip_ws(sql, first);
    if sql.as_bytes().get(after_first) != Some(&b'.') {
        return Some(start..first);
    }
    let second_start = skip_ws(sql, after_first + 1);
    let second = identifier_end(sql, second_start)?;
    Some(start..second)
}

fn identifier_end(sql: &str, pos: usize) -> Option<usize> {
    let bytes = sql.as_bytes();
    match *bytes.get(pos)? {
        b'"' | b'\'' | b'`' => quoted_identifier_end(bytes, pos, bytes[pos]),
        b'[' => bracket_identifier_end(bytes, pos),
        _ => unquoted_identifier_end(sql, pos),
    }
}

fn quoted_identifier_end(bytes: &[u8], pos: usize, quote: u8) -> Option<usize> {
    let mut i = pos + 1;
    while i < bytes.len() {
        if bytes[i] == quote {
            if bytes.get(i + 1) == Some(&quote) {
                i += 2;
            } else {
                return Some(i + 1);
            }
        } else {
            i += 1;
        }
    }
    None
}

fn bracket_identifier_end(bytes: &[u8], pos: usize) -> Option<usize> {
    bytes[pos + 1..]
        .iter()
        .position(|byte| *byte == b']')
        .map(|offset| pos + 1 + offset + 1)
}

fn unquoted_identifier_end(sql: &str, pos: usize) -> Option<usize> {
    sql[pos..]
        .char_indices()
        .find_map(|(offset, ch)| {
            (ch.is_whitespace() || ch == '(' || ch == '.').then_some(pos + offset)
        })
        .filter(|end| *end > pos)
        .or(Some(sql.len()))
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
/// A `PRAGMA` names no table and passes through as connection state.
fn qualify_tier_statement(statement: &str) -> Result<String, ClientError> {
    if strip_ci(statement, "PRAGMA").is_some() {
        return Ok(statement.to_owned());
    }
    let rest = strip_ci(statement, "CREATE TABLE").ok_or_else(|| {
        ClientError::Session(format!(
            "local tier DDL supports only CREATE TABLE and PRAGMA statements, got: {statement}"
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
    #[expect(
        dead_code,
        reason = "diesel reads the column through QueryableByName and no Rust code names the field"
    )]
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

mod cursor_metadata {
    diesel::table! {
        _connetto_meta (id) {
            id -> Integer,
            cursor -> Binary,
            cursor_subjects -> Nullable<Binary>,
        }
    }
}

use cursor_metadata::_connetto_meta;

/// Persist coverage with the cursor only after its data has been applied.
fn persist_cursor_and_subjects(
    db: &mut SqliteConnection,
    cursor: &Cursor,
    subjects: Option<&[String]>,
) -> Result<(), ClientError> {
    let cursor = cursor.as_bytes();
    let subjects = subjects
        .map(|subjects| serde_json::to_vec(subjects).expect("compact JSON of subject names"));
    diesel::insert_into(_connetto_meta::table)
        .values((
            _connetto_meta::id.eq(1),
            _connetto_meta::cursor.eq(cursor),
            _connetto_meta::cursor_subjects.eq(subjects.as_deref()),
        ))
        .on_conflict(_connetto_meta::id)
        .do_update()
        .set((
            _connetto_meta::cursor.eq(cursor),
            _connetto_meta::cursor_subjects.eq(subjects.as_deref()),
        ))
        .execute(db)
        .map_err(|_| ClientError::Protocol("durable cursor write".into()))?;
    Ok(())
}

/// The cursor the server had when the last applied patch arrived, with the
/// coverage that was applied at that cursor, or `None` before the first
/// applied patch.
fn load_cursor_and_subjects(db: &mut SqliteConnection) -> Option<(Cursor, Option<Vec<String>>)> {
    let (bytes, subjects) = _connetto_meta::table
        .find(1)
        .select((_connetto_meta::cursor, _connetto_meta::cursor_subjects))
        .first::<(Vec<u8>, Option<Vec<u8>>)>(&mut *db)
        .ok()?;
    let subjects = subjects.and_then(|subjects| serde_json::from_slice(&subjects).ok());
    Some((Cursor::new(bytes), subjects)).filter(|(cursor, _)| !cursor.is_empty())
}

/// The client sequence as the storage integer.
fn seq_storage(seq: u64) -> Result<i64, ClientError> {
    i64::try_from(seq).map_err(|_| ClientError::Session("sequence overflows storage".to_owned()))
}

/// A number writer's identity before the server issues a number, so a write
/// made before the first handshake stays queued under a name the server can
/// never grant, and no connection ever presents it.
const UNISSUED_NUMBER: u64 = 0;

/// The writer a write awaiting its number is queued under.
const fn unissued() -> WriterRef {
    WriterRef::Number(UNISSUED_NUMBER)
}

/// A writer the server could have settled under, so it owes a retirement and
/// its entries carry its provenance. The unissued identity is not one.
fn is_real_writer(writer: &WriterRef) -> bool {
    !matches!(writer, WriterRef::Number(number) if *number == UNISSUED_NUMBER)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// A writer's storage identity, the replica's own spelling of the wire name.
fn writer_id(writer: &WriterRef) -> String {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    match writer {
        WriterRef::Number(number) => format!("number:{number}"),
        WriterRef::Device(id) => {
            let mut out = String::with_capacity(9 + id.len() * 2);
            out.push_str("device:");
            for byte in id {
                out.push(char::from(HEX[(byte >> 4) as usize]));
                out.push(char::from(HEX[(byte & 0xf) as usize]));
            }
            out
        }
    }
}

/// Parse a storage identity the previous run wrote.
fn writer_from_id(id: &str) -> Option<WriterRef> {
    let (kind, rest) = id.split_once(':')?;
    match kind {
        "number" => Some(WriterRef::Number(rest.parse().ok()?)),
        "device" if rest.len() == 64 => {
            let bytes = (0..32)
                .map(|i| {
                    let hi = hex_digit(rest.as_bytes()[i * 2])?;
                    let lo = hex_digit(rest.as_bytes()[i * 2 + 1])?;
                    Some(hi * 16 + lo)
                })
                .collect::<Option<Vec<u8>>>()?;
            Some(WriterRef::Device(bytes.try_into().ok()?))
        }
        _ => None,
    }
}

/// One queued write of one writer.
#[derive(Debug, Clone)]
struct PendingEntry {
    /// The captured changeset, the physical table names a rollback applies.
    changeset: Vec<u8>,
    /// This entry's chain hash, over the logical upload bytes and every
    /// entry queued before it.
    hash: [u8; 32],
    /// The replica-wide order the entry was queued in, ahead of every writer
    /// sequence, so a restart and a reapply replay it where it was made.
    position: u64,
    /// The writer and sequence this entry was first written under, set when
    /// the entry was imported or carried to a fresh writer.
    provenance: Option<Provenance>,
}

struct CarriedEntry {
    source: WriterRef,
    original_seq: u64,
    position: u64,
    seq: u64,
    hash: [u8; 32],
}

/// One writer's queue, the client half of the (writer, sequence) identity.
#[derive(Debug, Clone)]
struct WriterQueue {
    /// The sequence a new entry of this writer takes.
    next_seq: u64,
    /// The chain head, the last queued entry's hash or the genesis.
    head: [u8; 32],
    /// The queued entries, in sequence order.
    pending: BTreeMap<u64, PendingEntry>,
}

impl WriterQueue {
    /// A queue for a writer nothing has written yet.
    fn fresh() -> Self {
        Self {
            next_seq: 1,
            head: GENESIS,
            pending: BTreeMap::new(),
        }
    }
}

/// Record a writer's queue state, its next sequence and chain head.
fn persist_writer_state(
    db: &mut SqliteConnection,
    writer: &WriterRef,
    next_seq: u64,
    head: &[u8; 32],
) -> Result<(), ClientError> {
    let id = writer_id(writer);
    diesel::replace_into(_connetto_writers::table)
        .values((
            _connetto_writers::id.eq(&id),
            _connetto_writers::next_seq.eq(seq_storage(next_seq)?),
            _connetto_writers::head.eq(*head),
        ))
        .execute(db)?;
    Ok(())
}

/// Drop a writer's queue state and its records, the writer moving on.
fn drop_writer_state(db: &mut SqliteConnection, writer: &WriterRef) -> Result<(), ClientError> {
    let id = writer_id(writer);
    diesel::delete(_connetto_writers::table.filter(_connetto_writers::id.eq(&id))).execute(db)?;
    delete_writer_pending(db, writer)?;
    Ok(())
}

/// The queue state of every writer a previous run left behind.
fn load_writer_states(
    db: &mut SqliteConnection,
) -> Result<BTreeMap<WriterRef, (u64, [u8; 32])>, ClientError> {
    let rows: Vec<(String, i64, Vec<u8>)> = _connetto_writers::table
        .select((
            _connetto_writers::id,
            _connetto_writers::next_seq,
            _connetto_writers::head,
        ))
        .load(db)?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, next_seq, head)| {
            Some((
                writer_from_id(&id)?,
                (u64::try_from(next_seq).ok()?, head.try_into().ok()?),
            ))
        })
        .collect())
}

/// Record a queued entry durably, with its chain hash, append position and
/// provenance, so a restart can replay it where it was made.
fn persist_pending(
    db: &mut SqliteConnection,
    writer: &WriterRef,
    seq: u64,
    changeset: &[u8],
    hash: [u8; 32],
    provenance: Option<Provenance>,
    position: u64,
) -> Result<(), ClientError> {
    let (prov_writer, prov_seq) = match &provenance {
        Some(prov) => (Some(writer_id(&prov.writer)), Some(seq_storage(prov.seq)?)),
        None => (None, None),
    };
    let id = writer_id(writer);
    diesel::replace_into(_connetto_pending::table)
        .values((
            _connetto_pending::writer.eq(&id),
            _connetto_pending::seq.eq(seq_storage(seq)?),
            _connetto_pending::changeset.eq(changeset),
            _connetto_pending::entry_hash.eq(hash),
            _connetto_pending::position.eq(seq_storage(position)?),
            _connetto_pending::prov_writer.eq(&prov_writer),
            _connetto_pending::prov_seq.eq(&prov_seq),
        ))
        .execute(db)?;
    Ok(())
}

/// Retire one queued entry, acknowledged, rejected, or rolled back.
fn delete_pending(
    db: &mut SqliteConnection,
    writer: &WriterRef,
    seq: u64,
) -> Result<(), ClientError> {
    let id = writer_id(writer);
    diesel::delete(
        _connetto_pending::table
            .filter(_connetto_pending::writer.eq(&id))
            .filter(_connetto_pending::seq.eq(seq_storage(seq)?)),
    )
    .execute(db)?;
    Ok(())
}

/// Retire every queued entry of one writer, it moving to a fresh writer.
fn delete_writer_pending(db: &mut SqliteConnection, writer: &WriterRef) -> Result<(), ClientError> {
    let id = writer_id(writer);
    diesel::delete(_connetto_pending::table.filter(_connetto_pending::writer.eq(&id)))
        .execute(db)?;
    Ok(())
}

/// Re-key a writer's pending rows and queue state onto another writer, the
/// unissued number taking its issued one.
fn rekey_writer(
    db: &mut SqliteConnection,
    from: &WriterRef,
    to: &WriterRef,
) -> Result<(), ClientError> {
    let from_id = writer_id(from);
    let to_id = writer_id(to);
    diesel::update(_connetto_pending::table.filter(_connetto_pending::writer.eq(&from_id)))
        .set(_connetto_pending::writer.eq(&to_id))
        .execute(db)?;
    diesel::update(_connetto_writers::table.filter(_connetto_writers::id.eq(&from_id)))
        .set(_connetto_writers::id.eq(&to_id))
        .execute(db)?;
    Ok(())
}

/// A queued entry as the bookkeeping stores it, sequence, changeset, chain
/// hash, append position and provenance.
struct LoadedEntry {
    seq: u64,
    changeset: Vec<u8>,
    hash: [u8; 32],
    position: u64,
    provenance: Option<Provenance>,
}

/// Every queued entry a previous run left, per writer in writer then
/// sequence order.
fn load_pending(
    db: &mut SqliteConnection,
) -> Result<BTreeMap<WriterRef, Vec<LoadedEntry>>, ClientError> {
    #[derive(diesel::Queryable)]
    struct PendingRow {
        writer: String,
        seq: i64,
        changeset: Vec<u8>,
        entry_hash: Vec<u8>,
        position: i64,
        prov_writer: Option<String>,
        prov_seq: Option<i64>,
    }
    let rows: Vec<PendingRow> = _connetto_pending::table
        .select((
            _connetto_pending::writer,
            _connetto_pending::seq,
            _connetto_pending::changeset,
            _connetto_pending::entry_hash,
            _connetto_pending::position,
            _connetto_pending::prov_writer,
            _connetto_pending::prov_seq,
        ))
        .order((
            _connetto_pending::writer.asc(),
            _connetto_pending::seq.asc(),
        ))
        .load(db)?;
    let mut queues = BTreeMap::new();
    for row in rows {
        let Some(writer) = writer_from_id(&row.writer) else {
            continue;
        };
        let Ok(seq) = u64::try_from(row.seq) else {
            continue;
        };
        let Ok(hash) = row.entry_hash.try_into() else {
            continue;
        };
        let Ok(position) = u64::try_from(row.position) else {
            continue;
        };
        let provenance = row
            .prov_writer
            .as_deref()
            .zip(row.prov_seq)
            .and_then(|(writer, seq)| Some((writer_from_id(writer)?, u64::try_from(seq).ok()?)))
            .map(|(writer, seq)| Provenance { writer, seq });
        queues
            .entry(writer)
            .or_insert_with(Vec::new)
            .push(LoadedEntry {
                seq,
                changeset: row.changeset,
                hash,
                position,
                provenance,
            });
    }
    Ok(queues)
}

/// Remember a writer to retire on the next connection.
fn persist_retire(db: &mut SqliteConnection, writer: &WriterRef) -> Result<(), ClientError> {
    let id = writer_id(writer);
    diesel::insert_into(_connetto_retire::table)
        .values(_connetto_retire::writer.eq(&id))
        .on_conflict_do_nothing()
        .execute(db)?;
    Ok(())
}

/// The writers owed a retirement, in writer order.
fn load_retires(db: &mut SqliteConnection) -> Result<Vec<WriterRef>, ClientError> {
    let rows: Vec<String> = _connetto_retire::table
        .select(_connetto_retire::writer)
        .order(_connetto_retire::writer.asc())
        .load(db)?;
    Ok(rows
        .into_iter()
        .filter_map(|writer| writer_from_id(&writer))
        .collect())
}

/// Drop a writer's retirement obligation, its answer arrived.
fn clear_retire(db: &mut SqliteConnection, writer: &WriterRef) -> Result<(), ClientError> {
    let id = writer_id(writer);
    diesel::delete(_connetto_retire::table.filter(_connetto_retire::writer.eq(&id))).execute(db)?;
    Ok(())
}

/// Durably exclude a retired device key from writer selection, so a
/// certificate the enrolment task has not yet cleared cannot take new writes
/// and a fresh one cannot reactivate the retired writer.
#[cfg(feature = "device-identity")]
fn persist_retired_key(db: &mut SqliteConnection, key_id: [u8; 32]) -> Result<(), ClientError> {
    diesel::insert_into(_connetto_retired_keys::table)
        .values(_connetto_retired_keys::key_id.eq(key_id))
        .on_conflict_do_nothing()
        .execute(db)?;
    Ok(())
}

/// The device keys a completed retirement excluded, in key order.
#[cfg(feature = "device-identity")]
fn load_retired_keys(db: &mut SqliteConnection) -> Result<HashSet<[u8; 32]>, ClientError> {
    let rows: Vec<Vec<u8>> = _connetto_retired_keys::table
        .select(_connetto_retired_keys::key_id)
        .load(db)?;
    Ok(rows
        .into_iter()
        .filter_map(|key| key.try_into().ok())
        .collect())
}

/// Every writer queue a previous run left, beside the position the next
/// queued entry takes: the highest durable position plus one, restarting at
/// one when no entry stands, settled history not ordered by the counter.
fn load_writer_queues(
    db: &mut SqliteConnection,
) -> Result<(BTreeMap<WriterRef, WriterQueue>, u64), ClientError> {
    let states = load_writer_states(db)?;
    let pending = load_pending(db)?;
    let mut queues = BTreeMap::new();
    for (writer, (next_seq, head)) in states {
        queues.insert(
            writer,
            WriterQueue {
                next_seq,
                head,
                pending: BTreeMap::new(),
            },
        );
    }
    for (writer, entries) in pending {
        let queue = queues.entry(writer).or_insert_with(WriterQueue::fresh);
        let mut last_hash: Option<[u8; 32]> = None;
        for entry in entries {
            last_hash = Some(entry.hash);
            queue.pending.insert(
                entry.seq,
                PendingEntry {
                    changeset: entry.changeset,
                    hash: entry.hash,
                    position: entry.position,
                    provenance: entry.provenance,
                },
            );
        }
        if let Some(last) = last_hash {
            queue.head = last;
            if let Some(max_seq) = queue.pending.keys().next_back() {
                queue.next_seq = queue.next_seq.max(max_seq + 1);
            }
        }
    }
    let next_position = queues
        .values()
        .flat_map(|queue| queue.pending.values())
        .map(|entry| entry.position)
        .max()
        .map_or(1, |position| position + 1);
    Ok((queues, next_position))
}

/// What a completed handshake told the client.
struct HandshakeOk {
    connection_id: String,
    session_handle: String,
    resume_token: String,
    writer: Option<WriterGrant>,
    schema_version: Option<SchemaVersion>,
    #[cfg(feature = "device-identity")]
    challenge: Option<[u8; 32]>,
}

/// The handshake exchange's inputs, the transport alone apart.
struct HandshakeInput<'a> {
    config: &'a ClientConfig,
    token_source: Option<&'a AccessTokenSource>,
    resume: Option<&'a Cursor>,
    resume_token: Option<&'a str>,
    writer: WriterRequest,
    settled_through: Option<u64>,
    /// The replica's clock, used to drop a share key whose expiry passed.
    now: i64,
    /// The coverage last applied at the resume cursor, presented with it.
    cursor_subjects: Option<&'a [String]>,
}

/// Run the opening handshake and read the ack, shared by the first connect
/// and every resume.
#[expect(
    clippy::too_many_lines,
    reason = "The opening exchange keeps its ordered protocol checks together."
)]
async fn exchange_handshake<T>(
    transport: &mut T,
    input: HandshakeInput<'_>,
) -> Result<HandshakeOk, ClientError>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    let HandshakeInput {
        config,
        token_source,
        resume,
        resume_token,
        writer,
        settled_through,
        now,
        cursor_subjects,
    } = input;
    let mut grants = Vec::with_capacity(
        1 + config
            .subjects
            .as_ref()
            .map_or(0, |subjects| subjects.set.keys.len()),
    );
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
            .subjects
            .iter()
            .flat_map(SubjectSource::grants)
            .filter(|grant| !grant_expiry::has_expired(grant, now))
            .cloned(),
    );
    let mut handshake = Handshake::new(PROTOCOL_VERSION, config.client_id.clone())
        .with_grants(grants)
        .with_writer(writer);
    if let Some(seq) = settled_through {
        handshake = handshake.with_settled_through(seq);
    }
    if let Some(cursor) = resume {
        handshake = handshake.with_cursor(cursor.clone());
        if let Some(subjects) = cursor_subjects {
            handshake = handshake.with_cursor_subjects(subjects.iter().cloned());
        }
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
    // The server opens every connection with a challenge (R91) the handshake answers nothing with.
    #[cfg(feature = "device-identity")]
    let mut challenge: Option<[u8; 32]> = None;
    let frame = transport
        .recv()
        .await
        .map_err(|e| ClientError::Transport(e.to_string()))?;
    let frame = match frame {
        Some(IncomingFrame::Control(ControlMessage::Challenge(challenge_frame))) => {
            #[cfg(feature = "device-identity")]
            {
                challenge = Some(challenge_frame.nonce);
            }
            #[cfg(not(feature = "device-identity"))]
            {
                let _ = challenge_frame;
            }
            transport
                .recv()
                .await
                .map_err(|e| ClientError::Transport(e.to_string()))?
        }
        other => other,
    };
    match frame {
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
                writer: ack.writer,
                schema_version: ack.schema_version,
                #[cfg(feature = "device-identity")]
                challenge,
            })
        }
        Some(IncomingFrame::Control(ControlMessage::FatalError(fatal))) => {
            Err(ClientError::Refused {
                reason: fatal.reason,
            })
        }
        Some(_) => Err(ClientError::Protocol("expected handshake ack".into())),
        None => Err(ClientError::Protocol("connection closed before ack".into())),
    }
}

/// Install an update hook recording the name of every table whose rows change on
/// `conn` into the shared `changed` set. Feeds the reactivity signal that tells
/// the app which tables to re-query.
///
/// The same hook maintains the residual measure (R60 decision 4): while
/// `counting` is set, which is exactly while a server patch is being applied,
/// each changed row of an application table adds one to its table's entry in
/// `staging`. `apply_patch` merges staging into `applied_rows` only after the
/// transaction commits, so a rolled-back apply leaves no phantom counts.
/// One atomic load and one map bump per row, the O(1) the decision asked for.
fn install_change_tracker(
    conn: &mut SqliteConnection,
    changed: &Arc<Mutex<HashSet<String>>>,
    staging: &Arc<Mutex<HashMap<String, u64>>>,
    counting: &Arc<AtomicBool>,
) {
    let sink = Arc::clone(changed);
    let rows = Arc::clone(staging);
    let gate = Arc::clone(counting);
    conn.on_update(
        SqliteUpdateRouter::new().on_any(SqliteChangeOps::ALL, move |event| {
            if let Ok(mut tables) = sink.lock() {
                tables.insert(event.table_name.to_owned());
            }
            if gate.load(Ordering::Relaxed)
                && !is_internal_table(event.table_name)
                && let Ok(mut counts) = rows.lock()
            {
                *counts.entry(event.table_name.to_owned()).or_insert(0) += 1;
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

/// The bound a share-key swap or a declaration fence waits on its answer for.
const SHARE_KEY_REQUEST_WAIT: Duration = Duration::from_secs(30);

static NEXT_SHARE_KEY_REQUEST: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

/// A fresh request id for a share-key swap this connection will send.
fn share_key_request_id() -> String {
    format!(
        "share-key-{}",
        NEXT_SHARE_KEY_REQUEST.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    )
}

static NEXT_DECLARATION_FENCE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

/// A fresh declaration-fence nonce in the high-bit namespace, disjoint from
/// the nonces an application hands its own pings.
fn declaration_fence_nonce() -> u64 {
    (1u64 << 63) | NEXT_DECLARATION_FENCE.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
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
    /// The connection's challenge nonce, the device bind signs it.
    #[cfg(feature = "device-identity")]
    challenge: Option<[u8; 32]>,
    /// Which of the connection's handshakes attached this wire.
    #[cfg(feature = "device-identity")]
    number: ConnectionNumber,
}

/// Which handshake of a [`ConnettoConnection`] a wire came from, counted from
/// one, so no two wires of the same connection share a number.
#[cfg(feature = "device-identity")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectionNumber(u64);

#[cfg(all(test, feature = "device-identity"))]
impl ConnectionNumber {
    /// The number `n`, for a fake link standing on its own connections.
    pub(crate) const fn new(n: u64) -> Self {
        Self(n)
    }
}

/// The bind or retirement a connection sent and has not been answered for.
#[derive(Debug, Clone)]
struct WriterTask {
    /// What was sent.
    kind: WriterTaskKind,
    /// The id this connection gave it, so the answer matches it.
    request_id: String,
    /// The monotonic deadline the answer is owed by.
    deadline: Duration,
}

/// What a [`WriterTask`] asked the server to do.
#[derive(Debug, Clone)]
enum WriterTaskKind {
    #[cfg(feature = "device-identity")]
    /// A device bind, the identity the answer binds.
    Bind {
        key_id: [u8; 32],
        signature: Vec<u8>,
    },
    /// A writer retirement.
    Retire(WriterRef),
}

/// How long a bind or retirement waits for its `WriterAnswer` before the
/// connection drops and the pump redials. R74's enrolment uses the same bound.
const WRITER_ANSWER_WAIT: Duration = Duration::from_secs(30);

static NEXT_WRITER_REQUEST: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// A fresh request id for a bind or retirement this connection will send.
fn writer_request_id() -> String {
    format!(
        "writer-{}",
        NEXT_WRITER_REQUEST.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    )
}

#[derive(Clone, Copy)]
enum AttachReplay {
    Idle,
    /// The bound writer's queue is resent, the frontier raised first.
    Pending {
        frontier: Option<u64>,
    },
}

/// The label prefix the server gives a hidden membership subscription (R27).
const MEMBERSHIP_LABEL_PREFIX: &str = "connetto-membership:";

/// Which scoped tables a clear empties whatever a sibling subscription still claims.
enum Stale {
    /// None, so each sibling keeps what its filter claims.
    Nothing,
    /// The one table a truncate emptied, lowercased (R48).
    Table(String),
    /// Every scoped table, because the whole session resyncs past where its timeline ended (R73).
    Everything,
}

impl Stale {
    fn covers(&self, table: &str) -> bool {
        match self {
            Self::Nothing => false,
            Self::Table(emptied) => *emptied == table.to_lowercase(),
            Self::Everything => true,
        }
    }
}

/// A sync client bound to one local SQLite database, with or without a server.
///
/// It exists before any transport does. Opening the replica, serving reads from
/// it and capturing writes into the pending queue all work with nothing to talk
/// to, and [`attach`](Self::attach) is what later gives it a server. That is
/// what lets an application start with no network and sync when one appears.
#[expect(
    clippy::struct_excessive_bools,
    reason = "Independent capture, replay and persistence obligations can overlap."
)]
pub struct ConnettoConnection<T: Transport> {
    /// The live socket, absent when no server is reachable.
    wire: Option<Wire<T>>,
    /// The run this caller's work belongs to, absent until a first handshake
    /// and kept across every later drop.
    run: Option<Run>,
    /// Post-handshake replay progress retained across a local interruption.
    attach_replay: AttachReplay,
    /// State changes waiting to be handed to the application, drained ahead of
    /// the transport so an offline connection can still report itself.
    notices: VecDeque<ClientEvent>,
    /// How many handshakes this connection has completed.
    #[cfg(feature = "device-identity")]
    handshakes: u64,
    // `session` is declared before `db` so it drops first: it holds a raw
    // pointer into the connection's SQLite handle and must not outlive it.
    session: Session,
    db: SqliteConnection,
    last_cursor: Option<Cursor>,
    /// The queues of the writers this replica has queued writes under.
    writers: BTreeMap<WriterRef, WriterQueue>,
    /// The position the next queued entry takes, rebuilt at open from the
    /// durable entries and advanced only after one commits, so the order of
    /// outstanding entries outlives every writer sequence.
    next_position: u64,
    /// The writer this connection writes as, absent on a device connection
    /// until its bind is answered.
    bound_writer: Option<WriterRef>,
    /// The binds and retirements queued to send, in order.
    writer_tasks: VecDeque<WriterTask>,
    /// The bind or retirement sent and awaited, at most one at a time.
    writer_in_flight: Option<WriterTask>,
    /// A device bind signed and held, sent once the number's tail settles.
    #[cfg(feature = "device-identity")]
    pending_bind: Option<WriterTask>,
    /// The device key opened to sign a bind, device identity only.
    #[cfg(feature = "device-identity")]
    opened_key: Option<Arc<dyn DeviceKey>>,
    /// Steers the enrolment task to a fresh key, device identity only.
    #[cfg(feature = "device-identity")]
    writer_retired: Option<tokio::sync::mpsc::UnboundedSender<crate::enrolment::Command>>,
    /// The device's keys, opened at a bind to sign it, device identity only.
    #[cfg(feature = "device-identity")]
    writer_keys: Option<Arc<dyn crate::enrolment::DeviceKeys>>,
    /// The device keys a completed retirement excluded from writer
    /// selection, held so a not-yet-cleared certificate cannot take new
    /// writes and a fresh one cannot reactivate the retired writer.
    #[cfg(feature = "device-identity")]
    retired_keys: HashSet<[u8; 32]>,
    /// Set by the commit hook whenever a write commits, so the driver knows
    /// to look for a captured mutation to flush. Server patch applies trip it
    /// too, harmlessly: an empty capture session never uploads.
    dirty: Arc<AtomicBool>,
    /// True while [`SuspendedCapture`] holds it, read by the registered
    /// [`connetto_core::WRITE_EXEMPTION_FUNCTION`], so the translated schema's fail-closed
    /// write guards admit connetto's own writes and nobody else's.
    write_exempt: Arc<AtomicBool>,
    /// Names of tables whose rows changed since the last drain, from the
    /// connection's update hook (local writes and server patches alike).
    changed: Arc<Mutex<HashSet<String>>>,
    /// Rows applied per application table since the last residual pass, the
    /// R60 measure. Accumulated via `apply_staging` during each apply and
    /// merged here only after the transaction commits.
    applied_rows: Arc<Mutex<HashMap<String, u64>>>,
    /// Raised for the duration of a server-patch apply, so the hook tallies
    /// rows into `apply_staging` and never into `applied_rows` directly.
    apply_counting: Arc<AtomicBool>,
    /// Staging accumulator for the residual measure: rows are tallied here
    /// while `apply_counting` is up and merged into `applied_rows` only after
    /// the transaction commits. Cleared on rollback to leave no phantom counts.
    apply_staging: Arc<Mutex<HashMap<String, u64>>>,
    /// Whether [`ClientEvent::TidyDue`] has fired since the measure last
    /// reset, so a crossing fires once rather than once per frame.
    residual_warned: bool,
    /// Transaction bookkeeping for the diesel `Connection` impl. The manager
    /// issues `BEGIN`/`COMMIT` through this connection, which delegate to `db`.
    transaction_state: AnsiTransactionManager,
    /// Where sending the writes the server deferred again stands.
    resend: Resend,
    /// How many resends were ever armed, so a pump tells a fresh timer from the one it sleeps on.
    resends_armed: u64,
    /// Identity presented at handshake, kept for re-handshakes on resume.
    config: ClientConfig,
    /// Optional source of fresh access tokens, consulted on every resume so a
    /// reconnect silently refreshes. `None` reuses `config.login`.
    token_source: Option<AccessTokenSource>,
    /// Lowercased names of the tables in the device-private database the
    /// replica named, empty when it named none. Live
    /// queries dispatch on it: a local table never reaches the wire.
    local_tables: HashSet<String>,
    /// Lowercased names of membership tables served by server-opened hidden
    /// subscriptions (R27). Kept out of the application-facing changed-tables
    /// signal, unconditionally, while the live-query refresh still sees them.
    hidden_tables: HashSet<String>,
    /// Subscriptions whose replacement snapshot has not ended yet, so the
    /// pending writes their clear took off the replica are still owed a
    /// re-apply (R48 decision 3). Held per subscription because two can be
    /// replaced at once, and cleared when each one's `SnapshotEnd` lands.
    resyncing: HashSet<String>,
    /// Whether this connection already emptied every subscribed table for a
    /// cursor past where its timeline ended (R73).
    history_cleared: bool,
    /// Subjects durably covering the cursor, or `None` while coverage is unknown.
    cursor_subjects: Option<Vec<String>>,
    /// Row declarations and deliveries awaiting their ordered completion.
    open_snapshots: HashSet<String>,
    /// Tables already emptied by the current attach or key-replacement batch.
    authorization_cleared: Option<HashSet<String>>,
    /// Computed declarations awaiting a successful fence or retirement.
    unfenced_computed: HashSet<String>,
    /// Declarations awaiting an ordered server-processing fence.
    unfenced_count: u64,
    /// The correlated declaration-processing fence in flight.
    declaration_fence: Option<DeclarationFence>,
    /// Generation advanced by accepted additions, removals and expiry.
    share_key_generation: u64,
    /// Latest key generation accepted by a handshake or replacement.
    share_key_settled: u64,
    /// The share-key swap sent and awaiting its answer, at most one at a time.
    share_key_request: Option<ShareKeyRequest>,
    /// When a rate-limited swap may go out again, absent when none owes a
    /// delay.
    share_key_retry_at: Option<Duration>,
    /// The durable share-key set's persistence, present on a store-backed
    /// connection.
    share_key_persistence: Option<ShareKeyPersistence>,
    /// A changed share-key set still owed its save to the store.
    share_key_save_pending: bool,
    /// A relay mirror's share-key changes awaiting their answers, by request id.
    relay_share_key_waits: HashMap<String, RelayShareKeyWait>,
    /// The earliest parsed expiry of a held key, refreshed at every set
    /// change, so an unrelated frame never parses a grant.
    share_key_expiry: Option<i64>,
    /// Earliest expiry, retry or correlated-answer deadline.
    share_key_deadline: Option<Duration>,
    /// How many times the share-key timer was armed, so a pump tells a fresh
    /// one from the one it sleeps on.
    share_key_armed: u64,
    /// Whether the durable share-key set is already loaded into the subject
    /// source this connection, so a reconnect re-attach skips it.
    share_key_loaded: bool,
    /// Whether the replica is backed by a file rather than `:memory:`. An
    /// in-memory replica has no durable key, so `custody()` overrides the
    /// configured level to `Ephemeral` whenever this is false.
    durable: bool,
    /// The schema cookie of `main` at its last key check, and of the tier when
    /// one is attached. The write path re-checks a schema only when its cookie
    /// moved, which is one integer read per schema (R62 decisions 1 and 4).
    main_schema: i64,
    tier_schema: Option<i64>,
    /// Enrolment requests awaiting their answer, by the `request_id` it quotes.
    /// Emptied on disconnect, which ends every wait at once.
    #[cfg(feature = "device-identity")]
    enrol_waiters: HashMap<String, tokio::sync::oneshot::Sender<enrolment::Answer>>,
    /// Where pushed revocation lists go, the enrolment task's inbox.
    #[cfg(feature = "device-identity")]
    list_sink: Option<tokio::sync::mpsc::UnboundedSender<Vec<connetto_core::messages::SignedList>>>,
}

/// Attach the shared store when the build shares tables, then run the program
/// for the files this open finds fresh, or the reopen program when neither is.
fn install_storage_layout<S: ReplicaStorage>(
    db: &mut SqliteConnection,
    replica: &Replica<'_, S>,
    sqlite_ddl: Option<&str>,
    config: &ClientConfig,
) -> Result<(), ClientError> {
    use diesel::OptionalExtension as _;
    let Some(layout) = &config.shared_layout else {
        // One transaction, because committing each of a replica schema's statements on its own
        // takes seconds on the browser's OPFS storage.
        if let Some(ddl) = sqlite_ddl.or(config.connection_ddl.as_deref()) {
            db.transaction::<_, ClientError, _>(|db| Ok(db.batch_execute(ddl)?))?;
        }
        return Ok(());
    };
    match (replica.shared_store(), replica.key()) {
        (Some((path, key)), _) => harden::attach_keyed_in_window(
            db,
            path,
            SHARED_SCHEMA,
            harden::AttachPermits::CreateAndWrite,
            key,
        )?,
        // Nothing at rest, so the shared store lives as long as the connection.
        (None, None) => {
            harden::attach_in_window(db, ":memory:", SHARED_SCHEMA, harden::AttachPermits::Write)?;
        }
        (None, Some(_)) => return Err(ClientError::ReplicaKeyMissing),
    }
    let fresh_shared = diesel::sql_query(
        "SELECT 1 AS present FROM connetto_shared.sqlite_master WHERE type = 'table' LIMIT 1",
    )
    .get_result::<Present>(db)
    .optional()?
    .is_none();
    if fresh_shared {
        db.set_auto_vacuum(Some(SHARED_SCHEMA), AutoVacuumMode::Incremental)?;
    }
    db.transaction::<_, ClientError, _>(|db| {
        db.batch_execute(layout.sql(sqlite_ddl.is_some(), fresh_shared))?;
        Ok(())
    })?;
    check_recorded_tables(db, SHARED_SCHEMA, &config.unrecorded_tables)
}

/// The schema and metadata tables an open installs, in dependency order.
#[deny(clippy::ref_patterns)]
fn install_replica_schema(
    db: &mut SqliteConnection,
    config: &ClientConfig,
) -> Result<(), ClientError> {
    // The views are what the map has to agree with.
    check_policy_tables(db, &config.policy_tables)?;
    // A rowid-only table records nothing, so a write to one uploads nothing and reports success (R62).
    check_recorded_tables(db, "main", &config.unrecorded_tables)?;
    db.batch_execute(META_DDL)?;
    match db.batch_execute("ALTER TABLE _connetto_meta ADD COLUMN cursor_subjects BLOB") {
        Ok(()) => {}
        Err(diesel::result::Error::DatabaseError(_, info))
            if info.message().contains("duplicate column name") => {}
        Err(error) => return Err(error.into()),
    }
    db.batch_execute(subscriptions::SUBSCRIPTION_DDL)?;
    // After the subscription tables, since it references `_connetto_query`.
    db.batch_execute(aggregates::AGGREGATE_DDL)?;
    #[cfg(feature = "device-identity")]
    db.batch_execute(enrolment::CERTIFICATE_DDL)?;
    // A watch the previous run died still holding counts down from now.
    subscriptions::anchor_launch(db)?;
    Ok(())
}

impl<T> ConnettoConnection<T>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    /// Open the replica with no server, serving local reads at once.
    ///
    /// The connection exists and works before anything is reachable: reads
    /// answer from the replica, writes capture into the pending queue, and
    /// [`attach`](Self::attach) later hands it a transport, which replays
    /// whatever queued up. This is what lets an application start offline.
    ///
    /// `sqlite_ddl` creates the local schema on a first boot. `replica` states
    /// where the replica lives, whether its pages are encrypted, and what
    /// device-private database sits beside it, as one value, so a connection
    /// cannot exist without its opener having stated all three.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a database, cipher or session failure.
    /// [`ClientError::ReplicaUndecryptable`] when an existing replica does not
    /// open under the key given.
    pub(crate) fn open<S: ReplicaStorage>(
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
    pub(crate) fn open_existing<S: ReplicaStorage>(
        replica: &Replica<'_, S>,
        config: &ClientConfig,
        resume: Option<Cursor>,
    ) -> Result<Self, ClientError> {
        let mut conn = Self::open_inner(replica, None, config, resume)?;
        conn.notices
            .push_back(ClientEvent::SyncStatus(SyncStatus::Offline));
        Ok(conn)
    }

    /// An empty in-memory connection carrying this one's identity, which takes
    /// its place once its replica file is to be deleted, so no handle keeps
    /// the file open.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the in-memory database cannot be opened.
    #[cfg(feature = "native-auth")]
    pub(crate) fn emptied(&self) -> Result<Self, ClientError> {
        // The stand-in has no schema, so the build's policy views are absent by design.
        let mut config = self
            .config
            .clone()
            .with_policy_tables(PolicyTables::default());
        config.shared_layout = None;
        config.shared_tables.clear();
        config.connection_ddl = None;
        Self::open(&Replica::in_memory(), "", &config, None)
    }

    /// Shared open body: open the database, unlock the page codec, apply the
    /// schema when it arrives as DDL, and hook the capture session. No
    /// handshake happens here, which is the whole point.
    #[expect(
        clippy::too_many_lines,
        reason = "Replica initialization establishes the connection's state together."
    )]
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
        // The translated schema expects Postgres's case-sensitive LIKE, and the
        // pragma is connection state, so the DDL's own copy covers a first boot alone.
        db.batch_execute("PRAGMA case_sensitive_like = 1")?;
        // Incremental auto-vacuum keeps the freelist bookkeeping current at
        // every commit so the trimming pass can later hand pages back to the
        // filesystem. The mode is stored in the file and fixed at the first
        // table, so it is set on the create path alone: an existing replica
        // already carries it, and setting it after the first table is a silent
        // no-op (R15).
        if sqlite_ddl.is_some() {
            db.set_auto_vacuum(None, AutoVacuumMode::Incremental)?;
        }
        // Before any statement carrying outside input, and before the first
        // attach: R18's hardening surface, one helper for both open paths.
        harden::harden_replica_connection(&mut db)?;
        // Connection state, so every open sets it. Native SQLite enforces by
        // compile default and the browser build does not, and the tier's
        // references have no enforcer but this one (R92 decision 2).
        db.set_foreign_keys_enabled(true)?;
        // Register app-supplied functions before any DDL or insert, so a
        // column DEFAULT that calls one fires on the first write.
        config
            .sql_functions
            .install(&mut db)
            .map_err(|e| ClientError::Session(e.to_string()))?;
        if let Some((function, identity)) = &config.caller {
            register_caller(&mut db, function, identity.clone())?;
        }
        if let Some(subjects) = &config.subjects {
            // Rendered against the replica's own clock, the one this crate
            // reads, so a key whose grant has died is left out here exactly as
            // the handshake leaves it out of what it presents.
            let now = crate::clock::now_secs(&mut db)?;
            register_subjects(&mut db, &subjects.function, subjects.rendered(now))?;
        }
        // Beside the caller function and for the same reach: the generated
        // write guards call it, so it exists before any trigger can run. A
        // schema that never names it pays nothing.
        let write_exempt = Arc::new(AtomicBool::new(false));
        register_write_exemption(&mut db, &write_exempt)?;
        // A person carries the wildcard, and a bot login reads its list here (R99).
        register_bot_list(&mut db, connetto_core::BOT_LIST_WILDCARD.to_owned())?;
        install_storage_layout(&mut db, replica, sqlite_ddl, config)?;
        db.transaction(|db| install_replica_schema(db, config))?;
        // An explicit resume cursor wins. Otherwise the replica remembers
        // its own resume point, so reopening a persisted replica (a file, an
        // OPFS import) continues where the previous run stopped. The writer
        // queues a previous run left, entries and all, come along for replay.
        let stored = if resume.is_none() {
            load_cursor_and_subjects(&mut db)
        } else {
            None
        };
        let (resume, cursor_subjects) = match (resume, stored) {
            (Some(resume), _) => (Some(resume), None),
            (None, Some((cursor, subjects))) => (Some(cursor), subjects),
            (None, None) => (None, None),
        };
        let (writers, next_position) = load_writer_queues(&mut db)?;
        #[cfg(feature = "device-identity")]
        let retired_keys = load_retired_keys(&mut db)?;
        let changed: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let applied_rows: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
        let apply_staging: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
        let apply_counting = Arc::new(AtomicBool::new(false));
        let dirty = Arc::new(AtomicBool::new(false));
        install_change_tracker(&mut db, &changed, &apply_staging, &apply_counting);
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

        // Read after every statement this open applies, so the first write
        // re-checks only what the application changed since.
        let main_schema = schema_cookie(&mut db, "main")?;

        let mut conn = Self {
            wire: None,
            run: None,
            attach_replay: AttachReplay::Idle,
            notices: VecDeque::new(),
            #[cfg(feature = "device-identity")]
            handshakes: 0,
            session,
            db,
            last_cursor: resume,
            writers,
            next_position,
            bound_writer: None,
            writer_tasks: VecDeque::new(),
            writer_in_flight: None,
            #[cfg(feature = "device-identity")]
            pending_bind: None,
            #[cfg(feature = "device-identity")]
            opened_key: None,
            #[cfg(feature = "device-identity")]
            writer_retired: None,
            #[cfg(feature = "device-identity")]
            writer_keys: None,
            #[cfg(feature = "device-identity")]
            retired_keys,
            dirty,
            write_exempt,
            changed,
            applied_rows,
            apply_counting,
            apply_staging,
            residual_warned: false,
            transaction_state: AnsiTransactionManager::default(),
            resend: Resend::Idle,
            resends_armed: 0,
            config: config.clone(),
            token_source: None,
            local_tables: HashSet::new(),
            hidden_tables: HashSet::new(),
            resyncing: HashSet::new(),
            history_cleared: false,
            cursor_subjects,
            open_snapshots: HashSet::new(),
            authorization_cleared: None,
            unfenced_computed: HashSet::new(),
            unfenced_count: 0,
            declaration_fence: None,
            share_key_generation: 0,
            share_key_settled: 0,
            share_key_request: None,
            share_key_retry_at: None,
            share_key_persistence: None,
            share_key_save_pending: false,
            relay_share_key_waits: HashMap::new(),
            share_key_expiry: None,
            share_key_deadline: None,
            share_key_armed: 0,
            share_key_loaded: false,
            // A key is what custody is about, so the absence of one is the
            // signal rather than the path: `Replica::in_memory` is the only
            // constructor that carries none, and `encrypted_file` refuses
            // without one.
            durable: replica.key().is_some(),
            main_schema,
            tier_schema: None,
            #[cfg(feature = "device-identity")]
            enrol_waiters: HashMap::new(),
            #[cfg(feature = "device-identity")]
            list_sink: None,
        };
        conn.attach_tier(replica.tier())?;
        conn.refresh_share_key_expiry();
        conn.recompute_share_key_deadline();
        Ok(conn)
    }

    /// Attach the device-private database the replica named, if any.
    ///
    /// Driven from `open` rather than exposed, because which one is legal
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
            Tier::None => return Ok(()),
            Tier::Existing { path } => {
                // Write allowed so the tier stays writable, creation refused so
                // a missing tier file fails instead of starting an empty one.
                harden::attach_in_window(
                    &mut self.db,
                    path,
                    LOCAL_SCHEMA,
                    harden::AttachPermits::Write,
                )?;
            }
            Tier::Create { path, ddl } => {
                harden::attach_in_window(
                    &mut self.db,
                    path,
                    LOCAL_SCHEMA,
                    harden::AttachPermits::CreateAndWrite,
                )?;
                // An attached database with no tables is a fresh one, on every
                // target and with no filesystem probe, which wasm does not have.
                if local_tier_tables(&mut self.db)?.is_empty() {
                    for statement in ddl.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                        self.db.batch_execute(&qualify_tier_statement(statement)?)?;
                    }
                }
            }
        }
        self.local_tables = local_tier_tables(&mut self.db)?;
        // The tier needs keys as much as the replica does: a browser tab reads
        // a tier table through a session diff the relay takes, so an unkeyed
        // one delivers nothing to a sibling tab (R62).
        check_recorded_tables(&mut self.db, LOCAL_SCHEMA, &self.config.unrecorded_tables)?;
        self.tier_schema = Some(schema_cookie(&mut self.db, LOCAL_SCHEMA)?);
        Ok(())
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

    /// Give this connection the device's keys and the enrolment task's
    /// retirement steering, device identity only. A restarted device reached
    /// its server before the keys were handed over, so the bind it owed at the
    /// handshake arms here, on the live wire, once they arrive.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the deferred bind cannot be signed or sent.
    #[cfg(feature = "device-identity")]
    pub(crate) async fn with_device_writer(
        &mut self,
        keys: Arc<dyn crate::enrolment::DeviceKeys>,
        retired: tokio::sync::mpsc::UnboundedSender<crate::enrolment::Command>,
    ) -> Result<(), ClientError> {
        self.writer_keys = Some(keys);
        self.writer_retired = Some(retired);
        if self.wire.is_some() {
            self.plan_bind().await?;
            self.flush_writer_tasks().await?;
        }
        Ok(())
    }

    /// Give this connection a transport: greet the server with the highest
    /// applied cursor and the writer this run writes as, and keep every piece
    /// of local state (replica, capture session, the writer queues, the
    /// sequence counters).
    ///
    /// One method for both arrivals, because they are one operation. A
    /// connection opened offline reaching a server for the first time and a
    /// live connection replacing a dropped transport differ only in whether a
    /// resume credential exists to present, and the server settles the rest.
    ///
    /// The ack's frontier retires nothing locally: the bound writer's whole
    /// queue is resent in order, and the server re-answers the entries at or
    /// below its frontier from its settled record, so a refusal the client
    /// never saw still rolls back, and the upload path stays exactly-once
    /// across the gap, however long it was. The dirty flag is forced so
    /// writes captured but never pushed re-flush. A re-declared subscription
    /// replays what the server retained past the cursor, or full-resyncs.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a transport or handshake failure. The connection
    /// keeps whatever it had, so a caller can try again with another
    /// transport, and one that had nothing stays usable for local reads.
    pub async fn attach(&mut self, mut transport: T) -> Result<(), ClientError> {
        let now = clock::now_secs(&mut self.db)?;
        // Durable authorization is loaded before the first handshake.
        self.prepare_share_keys().await?;
        let (writer, settled_through) = self.writer_handshake()?;
        let ack = match exchange_handshake(
            &mut transport,
            HandshakeInput {
                config: &self.config,
                token_source: self.token_source.as_ref(),
                resume: self.last_cursor.as_ref(),
                cursor_subjects: self.cursor_subjects.as_deref(),
                resume_token: self.run.as_ref().map(|run| run.resume_token.as_str()),
                writer,
                settled_through,
                now,
            },
        )
        .await
        {
            Err(
                error @ ClientError::Refused {
                    reason: FatalErrorReason::WriterUnknown | FatalErrorReason::WriterRetired,
                },
            ) => {
                if let WriterRequest::Number(number) = writer {
                    self.carry_to_live(WriterRef::Number(number));
                }
                return Err(error);
            }
            Ok(ack) => ack,
            Err(err) => return Err(err),
        };
        let bound = self.apply_writer_grant(writer, ack.writer)?;
        let frontier = match bound {
            Some(WriterRef::Number(_)) => ack.writer.map(|grant| grant.frontier),
            _ => None,
        };
        self.run = Some(Run {
            session_handle: ack.session_handle,
            resume_token: ack.resume_token,
            schema_version: ack.schema_version,
        });
        #[cfg(feature = "device-identity")]
        {
            self.handshakes += 1;
        }
        self.wire = Some(Wire {
            transport,
            connection_id: ack.connection_id,
            #[cfg(feature = "device-identity")]
            challenge: ack.challenge,
            #[cfg(feature = "device-identity")]
            number: ConnectionNumber(self.handshakes),
        });
        self.history_cleared = false;
        self.bound_writer = bound;
        self.share_key_settled = self.share_key_generation;
        self.authorization_cleared = Some(HashSet::new());
        self.attach_replay = AttachReplay::Pending { frontier };
        self.notices
            .push_back(ClientEvent::SyncStatus(SyncStatus::Connected));
        // Relaxed: same-task flag, no ordering dependency.
        self.dirty.store(true, Ordering::Relaxed);
        #[cfg(feature = "device-identity")]
        self.plan_bind().await?;
        // A retirement owed before the last connection is re-sent here, queued
        // behind any bind so the connection is bound before it retires.
        for writer in load_retires(&mut self.db)? {
            self.writer_tasks.push_back(WriterTask {
                kind: WriterTaskKind::Retire(writer),
                request_id: writer_request_id(),
                deadline: crate::away::SystemClock.monotonic() + WRITER_ANSWER_WAIT,
            });
        }
        self.flush_writer_tasks().await?;
        self.resume_attach().await
    }

    /// Finishes post-handshake replay after an outer operation temporarily
    /// yielded the connection for local work.
    ///
    /// Calling this after a completed attach is a no-op.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when pending mutation or subscription replay fails.
    pub async fn resume_attach(&mut self) -> Result<(), ClientError> {
        let AttachReplay::Pending { frontier } = self.attach_replay else {
            return Ok(());
        };
        self.reconcile_pending(frontier).await?;
        self.replay_subscriptions().await?;
        self.attach_replay = AttachReplay::Idle;
        Ok(())
    }

    /// Raise the bound writer's next sequence to the frontier the handshake
    /// reported and replay the queue in order, nothing at or below the
    /// frontier retired locally, the server re-answering it from its record.
    async fn reconcile_pending(&mut self, frontier: Option<u64>) -> Result<(), ClientError> {
        if let (Some(writer), Some(frontier)) = (self.bound_writer, frontier)
            && let Some(queue) = self.writers.get_mut(&writer)
        {
            let raised = frontier.saturating_add(1).max(queue.next_seq);
            if raised != queue.next_seq {
                queue.next_seq = raised;
                persist_writer_state(&mut self.db, &writer, queue.next_seq, &queue.head)?;
            }
        }
        self.replay_pending().await
    }

    /// Replays the bound writer's unacknowledged entries on the current
    /// transport, each carrying its writer, its sequence and its provenance.
    ///
    /// Calling this while offline leaves the durable queues untouched.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when encoding or sending a queued entry fails.
    pub async fn replay_pending(&mut self) -> Result<(), ClientError> {
        if !self.is_connected() {
            return Ok(());
        }
        let Some((writer, queue)) = self
            .bound_writer
            .and_then(|writer| self.writers.get(&writer).map(|queue| (writer, queue)))
        else {
            return Ok(());
        };
        let replays: Vec<(u64, Vec<u8>, Option<Provenance>)> = queue
            .pending
            .iter()
            .map(|(seq, entry)| (*seq, entry.changeset.clone(), entry.provenance))
            .collect();
        for (seq, changeset, provenance) in replays {
            self.send_mutation(writer, seq, &changeset, provenance.as_ref())
                .await?;
        }
        Ok(())
    }

    /// The writer to present at the next handshake, with how much of it the
    /// server has already settled. A number's unsent tail outlives a device's
    /// bind, and an unissued tail takes its fresh number first, so a fresh
    /// number is asked whenever any writer's tail waits.
    fn writer_handshake(&mut self) -> Result<(WriterRequest, Option<u64>), ClientError> {
        let number = self.number_identity();
        let number_tail = number.is_some_and(|number| {
            self.writers
                .get(&WriterRef::Number(number))
                .is_some_and(|queue| !queue.pending.is_empty())
        });
        if number_tail {
            let number = number.expect("a tail names its writer");
            let writer = WriterRef::Number(number);
            return Ok((
                WriterRequest::Number(number),
                Some(self.settled_through(&writer)),
            ));
        }
        // An unissued tail settles under its own fresh number first, or a
        // device handshake would queue it behind the device's later entries.
        let unissued_tail = self
            .writers
            .get(&unissued())
            .is_some_and(|queue| !queue.pending.is_empty());
        if unissued_tail {
            return Ok((WriterRequest::Issue, None));
        }
        if self.device_bindable()? {
            return Ok((WriterRequest::Device, None));
        }
        match number {
            Some(number) => {
                let writer = WriterRef::Number(number);
                Ok((
                    WriterRequest::Number(number),
                    Some(self.settled_through(&writer)),
                ))
            }
            None => Ok((WriterRequest::Issue, None)),
        }
    }

    /// The number writer this replica holds, if any, the unissued one
    /// held back, it waits for the server to issue its number.
    fn number_identity(&self) -> Option<u64> {
        self.writers.keys().find_map(|writer| match writer {
            WriterRef::Number(number) if *number != UNISSUED_NUMBER => Some(*number),
            _ => None,
        })
    }

    /// How much of one writer the server has settled, the retired prefix of
    /// its queue, contiguous from sequence one, or the whole queue when it
    /// holds nothing.
    fn settled_through(&self, writer: &WriterRef) -> u64 {
        match self.writers.get(writer) {
            Some(queue) => queue
                .pending
                .keys()
                .next()
                .copied()
                .map_or(queue.next_seq.saturating_sub(1), |seq| {
                    seq.saturating_sub(1)
                }),
            None => 0,
        }
    }

    /// Whether a device handshake would be answered `Bound`, device identity only.
    #[cfg_attr(
        not(feature = "device-identity"),
        expect(
            clippy::unused_self,
            clippy::unnecessary_wraps,
            reason = "the device-only body is the only user of self and the only error source"
        )
    )]
    fn device_bindable(&mut self) -> Result<bool, ClientError> {
        #[cfg(not(feature = "device-identity"))]
        {
            Ok(false)
        }
        #[cfg(feature = "device-identity")]
        {
            let device_holds = self
                .writers
                .keys()
                .any(|writer| matches!(writer, WriterRef::Device(_)));
            if !device_holds {
                return Ok(false);
            }
            let Some(held) = self.device_certificate()? else {
                return Ok(false);
            };
            // A completed retirement excludes the key before the enrolment
            // task's cleanup runs, so a not-yet-cleared certificate does not
            // make it bindable.
            let key_id = *held.leaf.identity().key().as_bytes();
            if self.retired_keys.contains(&key_id) {
                return Ok(false);
            }
            Ok(matches!(
                crate::enrolment::Standing::of(Some(&held), std::time::SystemTime::now()),
                crate::enrolment::Standing::Fresh | crate::enrolment::Standing::Aging
            ))
        }
    }

    /// Fold the ack's grant into the writer state, moving the unissued
    /// queue to the issued number, and return the writer the connection now
    /// writes as, absent until a device bind is answered.
    fn apply_writer_grant(
        &mut self,
        request: WriterRequest,
        granted: Option<WriterGrant>,
    ) -> Result<Option<WriterRef>, ClientError> {
        match request {
            WriterRequest::Issue => {
                let grant = granted.ok_or_else(|| {
                    ClientError::Protocol("the server issued no writer to an issue".to_owned())
                })?;
                if grant.number == UNISSUED_NUMBER {
                    return Err(ClientError::Protocol(
                        "the server issued the unissued number".to_owned(),
                    ));
                }
                if grant.frontier != 0 {
                    return Err(ClientError::Protocol(
                        "a fresh number arrived with a frontier".to_owned(),
                    ));
                }
                let number = WriterRef::Number(grant.number);
                {
                    let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
                    let queue = self.writers.get(&unissued());
                    self.db.transaction::<(), ClientError, _>(|db| {
                        let (next_seq, head) = if let Some(queue) = queue {
                            rekey_writer(db, &unissued(), &number)?;
                            (queue.next_seq, &queue.head)
                        } else {
                            (1, &GENESIS)
                        };
                        persist_writer_state(db, &number, next_seq, head)
                    })?;
                }
                let queue = self
                    .writers
                    .remove(&unissued())
                    .unwrap_or_else(WriterQueue::fresh);
                self.writers.insert(number, queue);
                Ok(Some(number))
            }
            WriterRequest::Number(number) => {
                let grant = granted.ok_or_else(|| {
                    ClientError::Protocol("the server answered a number without a grant".to_owned())
                })?;
                if grant.number != number {
                    return Err(ClientError::Protocol(
                        "the server confirmed another number than the handshake named".to_owned(),
                    ));
                }
                let writer = WriterRef::Number(number);
                if let Entry::Vacant(entry) = self.writers.entry(writer) {
                    {
                        let _suspended =
                            SuspendedCapture::new(&mut self.session, &self.write_exempt);
                        persist_writer_state(&mut self.db, &writer, 1, &GENESIS)?;
                    }
                    entry.insert(WriterQueue::fresh());
                }
                Ok(Some(writer))
            }
            WriterRequest::Device => {
                if granted.is_some() {
                    return Err(ClientError::Protocol(
                        "the server answered a device handshake with a grant".to_owned(),
                    ));
                }
                // The unissued queue holds this replica's own writes awaiting a
                // writer, so it joins the device's queue, without provenance,
                // since it never sat under a writer the server knows.
                #[cfg(feature = "device-identity")]
                if let Ok(Some(held)) = self.device_certificate() {
                    let key_id = *held.leaf.identity().key().as_bytes();
                    self.carry_writers(&[unissued()], &WriterRef::Device(key_id))?;
                }
                Ok(None)
            }
        }
    }

    /// Sign the device's bind for this connection's challenge and queue it,
    /// sent at once for a device handshake and held for the number's tail to
    /// settle otherwise, device identity only.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the device key cannot be opened or will not sign.
    #[cfg(feature = "device-identity")]
    async fn plan_bind(&mut self) -> Result<(), ClientError> {
        if !self.device_bindable()? {
            return Ok(());
        }
        // Already bound as the device, so the bind stands and no new one is owed.
        if matches!(self.bound_writer, Some(WriterRef::Device(_))) {
            return Ok(());
        }
        // The build hands the device's keys over after the handshake on a
        // restarted device, so a bind that cannot be signed yet defers to the
        // keys arriving, not a failure.
        if self.writer_keys.is_none() {
            return Ok(());
        }
        let task = self.bind_task().await?;
        // A bind owed for this key supersedes any queued bind for another,
        // the selected writer having moved, so the stale one drops rather
        // than sending for a writer the replica no longer writes as.
        if let WriterTaskKind::Bind { key_id, .. } = &task.kind {
            self.writer_tasks.retain(|queued| {
                !matches!(
                    &queued.kind,
                    WriterTaskKind::Bind { key_id: other, .. } if other != key_id
                )
            });
        }
        if self.bound_writer.is_none() {
            self.writer_tasks.push_back(task);
        } else {
            self.pending_bind = Some(task);
        }
        Ok(())
    }

    /// The bind this connection would send, signed against the challenge it
    /// opened with.
    #[cfg(feature = "device-identity")]
    async fn bind_task(&mut self) -> Result<WriterTask, ClientError> {
        let challenge = self
            .wire
            .as_ref()
            .and_then(|wire| wire.challenge)
            .ok_or_else(|| {
                ClientError::Protocol("the connection opened without a challenge".to_owned())
            })?;
        let keys = self.writer_keys.as_ref().ok_or_else(|| {
            ClientError::Protocol("the device holds no keys to bind with".to_owned())
        })?;
        let opened = keys.open().await?;
        let key: Arc<dyn DeviceKey> = Arc::from(opened.key);
        self.opened_key = Some(Arc::clone(&key));
        let key_id = *connetto_core::device_cert::key_id(&*key).as_bytes();
        let signature = key.sign(&writer_bind_message(&challenge)).map_err(|err| {
            ClientError::DeviceChip(crate::device_key::ChipError::Failed(Box::new(err)))
        })?;
        let queue = self
            .writers
            .entry(WriterRef::Device(key_id))
            .or_insert_with(WriterQueue::fresh);
        {
            let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
            persist_writer_state(
                &mut self.db,
                &WriterRef::Device(key_id),
                queue.next_seq,
                &queue.head,
            )?;
        }
        Ok(WriterTask {
            kind: WriterTaskKind::Bind { key_id, signature },
            request_id: writer_request_id(),
            deadline: crate::away::SystemClock.monotonic() + WRITER_ANSWER_WAIT,
        })
    }

    /// Send the front queued bind or retirement, one in flight at a time.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the send fails.
    async fn flush_writer_tasks(&mut self) -> Result<(), ClientError> {
        if self.writer_in_flight.is_some() {
            return Ok(());
        }
        let Some(wire) = self.wire.as_mut() else {
            return Ok(());
        };
        let Some(task) = self.writer_tasks.pop_front() else {
            return Ok(());
        };
        let message = match &task.kind {
            #[cfg(feature = "device-identity")]
            WriterTaskKind::Bind { key_id, signature } => ControlMessage::BindDevice(BindDevice {
                request_id: task.request_id.clone(),
                key_id: *key_id,
                signature: signature.clone(),
            }),
            WriterTaskKind::Retire(writer) => ControlMessage::RetireWriter(RetireWriter {
                request_id: task.request_id.clone(),
                writer: *writer,
            }),
        };
        wire.transport
            .send_control(message)
            .await
            .map_err(|err| ClientError::Transport(err.to_string()))?;
        self.writer_in_flight = Some(task);
        Ok(())
    }

    /// Drop the connection when its writer answer overran the bound, the
    /// pump redials and the next connection re-sends the bind or retirement.
    fn check_writer_deadlines(&mut self) {
        if self
            .writer_in_flight
            .as_ref()
            .is_some_and(|task| crate::away::SystemClock.monotonic() >= task.deadline)
        {
            tracing::warn!("the writer answer overran its bound, dropping the connection");
            self.disconnected();
        }
    }

    /// Settle a `WriterAnswer` for a bind or retirement this connection sent.
    async fn settle_writer_task(
        &mut self,
        answer: &WriterAnswer,
    ) -> Result<ClientEvent, ClientError> {
        let Some(task) = self.writer_in_flight.take() else {
            return Err(ClientError::Protocol(
                "a writer answer arrived with nothing in flight".to_owned(),
            ));
        };
        if task.request_id != answer.request_id {
            self.writer_in_flight = Some(task);
            return Err(ClientError::Protocol(
                "the writer answer names a foreign request".to_owned(),
            ));
        }
        match task.kind {
            #[cfg(feature = "device-identity")]
            WriterTaskKind::Bind { key_id, .. } => {
                self.answer_bind(key_id, answer.request_id.clone(), answer.outcome)
                    .await
            }
            WriterTaskKind::Retire(writer) => {
                {
                    let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
                    clear_retire(&mut self.db, &writer)?;
                }
                self.flush_writer_tasks().await?;
                Ok(ClientEvent::NonFatal {
                    related_to: Some(answer.request_id.clone()),
                    detail: "a writer retirement was answered".to_owned(),
                })
            }
        }
    }

    #[cfg(feature = "device-identity")]
    /// Apply a bind's answer to the writer state.
    async fn answer_bind(
        &mut self,
        key_id: [u8; 32],
        request_id: String,
        outcome: WriterOutcome,
    ) -> Result<ClientEvent, ClientError> {
        let writer = WriterRef::Device(key_id);
        match outcome {
            WriterOutcome::Bound { frontier } => {
                // A completed retirement excludes the key before its answer
                // can arrive, so a late `Bound` cannot reactivate it.
                if self.retired_keys.contains(&key_id) {
                    tracing::warn!("a bind answer named a retired device key, dropping it");
                    self.flush_writer_tasks().await?;
                    return Ok(ClientEvent::NonFatal {
                        related_to: Some(request_id),
                        detail: "a stale bind answer for a retired key dropped".to_owned(),
                    });
                }
                let queue = self
                    .writers
                    .entry(writer)
                    .or_insert_with(WriterQueue::fresh);
                let raised = frontier.saturating_add(1).max(queue.next_seq);
                if raised != queue.next_seq {
                    queue.next_seq = raised;
                }
                {
                    let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
                    persist_writer_state(&mut self.db, &writer, queue.next_seq, &queue.head)?;
                }
                self.bound_writer = Some(writer);
                // A retirement re-enrols under a fresh key, and the tail the
                // retired device carried to a number re-queues under the
                // newly bound device, provenance intact.
                let stale: Vec<WriterRef> = self
                    .writers
                    .keys()
                    .filter(|w| !matches!(w, WriterRef::Device(_)))
                    .copied()
                    .collect();
                self.carry_writers(&stale, &writer)?;
                self.flush_writer_tasks().await?;
                self.replay_pending().await?;
                Ok(ClientEvent::NonFatal {
                    related_to: Some(request_id),
                    detail: "the device writer bind was answered".to_owned(),
                })
            }
            WriterOutcome::Retired | WriterOutcome::NotEnrolled | WriterOutcome::Unknown => {
                // The key is retired or not a live enrolment, so the tail
                // travels under a fresh number and the device enrols fresh.
                self.retire_device()
            }
        }
    }

    #[cfg(feature = "device-identity")]
    /// Retire the number writer whose tail settled, its entries all answered,
    /// and drop its state, so the next handshake does not present it again.
    fn retire_number(&mut self, number: WriterRef) -> Result<(), ClientError> {
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        persist_retire(&mut self.db, &number)?;
        drop_writer_state(&mut self.db, &number)?;
        self.writer_tasks.push_back(WriterTask {
            kind: WriterTaskKind::Retire(number),
            request_id: writer_request_id(),
            deadline: crate::away::SystemClock.monotonic() + WRITER_ANSWER_WAIT,
        });
        self.writers.remove(&number);
        Ok(())
    }

    /// Send the held device bind once the number's tail has settled out,
    /// retiring the number behind the bind, so the device becomes the writer.
    #[cfg(feature = "device-identity")]
    async fn finish_number_tail(&mut self) -> Result<(), ClientError> {
        let Some(writer) = self.bound_writer else {
            return Ok(());
        };
        if !matches!(writer, WriterRef::Number(_)) {
            return Ok(());
        }
        let Some(queue) = self.writers.get(&writer) else {
            return Ok(());
        };
        if !queue.pending.is_empty() {
            return Ok(());
        }
        if let Some(bind) = self.pending_bind.take() {
            self.writer_tasks.push_back(bind);
            self.retire_number(writer)?;
            self.flush_writer_tasks().await?;
        }
        Ok(())
    }

    /// Atomically carries tails in append order and excludes retired device keys.
    fn carry_writers(&mut self, dead: &[WriterRef], target: &WriterRef) -> Result<(), ClientError> {
        debug_assert!(!dead.contains(target));
        let capacity = dead
            .iter()
            .filter_map(|writer| self.writers.get(writer))
            .map(|queue| queue.pending.len())
            .sum();
        let mut plan = Vec::with_capacity(capacity);
        for source in dead {
            if let Some(queue) = self.writers.get(source) {
                for (original_seq, entry) in &queue.pending {
                    plan.push(CarriedEntry {
                        source: *source,
                        original_seq: *original_seq,
                        position: entry.position,
                        seq: 0,
                        hash: GENESIS,
                    });
                }
            }
        }
        plan.sort_unstable_by_key(|entry| entry.position);
        let (mut next_seq, mut head) = self
            .writers
            .get(target)
            .map_or((1, GENESIS), |queue| (queue.next_seq, queue.head));
        for placement in &mut plan {
            let entry = &self.writers[&placement.source].pending[&placement.original_seq];
            placement.seq = next_seq;
            placement.hash = entry_hash(&head, next_seq, &self.logical_for(&entry.changeset)?);
            next_seq += 1;
            head = placement.hash;
        }
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        self.db.transaction::<(), ClientError, _>(|db| {
            for placement in &plan {
                let entry = &self.writers[&placement.source].pending[&placement.original_seq];
                let provenance = entry.provenance.or_else(|| {
                    is_real_writer(&placement.source).then_some(Provenance {
                        writer: placement.source,
                        seq: placement.original_seq,
                    })
                });
                persist_pending(
                    db,
                    target,
                    placement.seq,
                    &entry.changeset,
                    placement.hash,
                    provenance,
                    entry.position,
                )?;
            }
            if !plan.is_empty() {
                persist_writer_state(db, target, next_seq, &head)?;
            }
            for writer in dead {
                #[cfg(feature = "device-identity")]
                if let WriterRef::Device(key) = writer {
                    persist_retired_key(db, *key)?;
                }
                drop_writer_state(db, writer)?;
            }
            Ok(())
        })?;
        if !plan.is_empty() {
            let mut queue = self
                .writers
                .remove(target)
                .unwrap_or_else(WriterQueue::fresh);
            queue.next_seq = next_seq;
            queue.head = head;
            for placement in plan {
                let mut entry = self
                    .writers
                    .get_mut(&placement.source)
                    .expect("the planned source exists")
                    .pending
                    .remove(&placement.original_seq)
                    .expect("the planned entry exists");
                entry.hash = placement.hash;
                entry.provenance = entry.provenance.or_else(|| {
                    is_real_writer(&placement.source).then_some(Provenance {
                        writer: placement.source,
                        seq: placement.original_seq,
                    })
                });
                queue.pending.insert(placement.seq, entry);
            }
            self.writers.insert(*target, queue);
        }
        for writer in dead {
            self.writers.remove(writer);
            #[cfg(feature = "device-identity")]
            if let WriterRef::Device(key) = writer {
                self.retired_keys.insert(*key);
            }
        }
        Ok(())
    }

    /// The writer a tail travels to when its writer dies: a live number when
    /// one holds, the unissued one until the server issues it, never a
    /// device queue, which would join the tail behind its own later entries,
    /// and never the dead writer itself.
    fn tail_target(&self, dead: &WriterRef) -> WriterRef {
        match self.number_identity() {
            Some(number) if WriterRef::Number(number) != *dead => WriterRef::Number(number),
            _ => unissued(),
        }
    }

    /// Carry a dead writer's tail to the live writer, tolerating the database
    /// the same way the fatal that drove the carry does.
    fn carry_to_live(&mut self, dead: WriterRef) {
        let target = self.tail_target(&dead);
        if let Err(err) = self.carry_writers(&[dead], &target) {
            tracing::warn!(error = %err, "the tail could not be re-queued");
        }
    }

    /// Atomically appends an entry, its position and its writer frontier.
    fn append_entry(
        &mut self,
        writer: &WriterRef,
        changeset: &[u8],
        provenance: Option<Provenance>,
    ) -> Result<u64, ClientError> {
        let position = self.next_position;
        let (seq, head) = match self.writers.get(writer) {
            Some(queue) => (queue.next_seq, queue.head),
            None => (1, GENESIS),
        };
        let hash = entry_hash(&head, seq, &self.logical_for(changeset)?);
        let entry = PendingEntry {
            changeset: changeset.to_vec(),
            hash,
            position,
            provenance,
        };
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        self.db.transaction::<(), ClientError, _>(|db| {
            persist_writer_state(db, writer, seq + 1, &hash)?;
            persist_pending(
                db,
                writer,
                seq,
                &entry.changeset,
                entry.hash,
                entry.provenance,
                position,
            )?;
            Ok(())
        })?;
        let queue = self
            .writers
            .entry(*writer)
            .or_insert_with(WriterQueue::fresh);
        queue.next_seq = seq + 1;
        queue.head = hash;
        queue.pending.insert(seq, entry);
        self.next_position = position + 1;
        Ok(seq)
    }

    /// Every device writer this replica still holds, in id order.
    fn device_writers(&self) -> Vec<WriterRef> {
        self.writers
            .keys()
            .filter(|writer| matches!(writer, WriterRef::Device(_)))
            .copied()
            .collect()
    }

    /// Durably retires device queues before requesting fresh enrolment.
    ///
    /// # Errors
    ///
    /// [`ClientError`] if the carry and key exclusion cannot commit together.
    fn retire_device(&mut self) -> Result<ClientEvent, ClientError> {
        self.exclude_device_writers()?;
        #[cfg(feature = "device-identity")]
        if let Some(sender) = &self.writer_retired {
            let _ = sender.send(crate::enrolment::Command::WriterRetired);
        }
        Ok(ClientEvent::NonFatal {
            related_to: None,
            detail: "the device's writer retired, a fresh key enrolls".to_owned(),
        })
    }

    /// Durably excludes held device keys and carries their tails.
    ///
    /// # Errors
    ///
    /// [`ClientError`] if the carry and key exclusion cannot commit together.
    fn exclude_device_writers(&mut self) -> Result<(), ClientError> {
        let writers = self.device_writers();
        #[cfg(feature = "device-identity")]
        let writers = {
            let mut writers = writers;
            if writers.is_empty()
                && let Some(held) = self.device_certificate()?
            {
                writers.push(WriterRef::Device(*held.leaf.identity().key().as_bytes()));
            }
            writers
        };
        let target = self
            .number_identity()
            .map_or_else(unissued, WriterRef::Number);
        self.carry_writers(&writers, &target)?;
        #[cfg(feature = "device-identity")]
        {
            self.pending_bind = None;
            self.writer_tasks.retain(|task| {
                !matches!(
                    &task.kind,
                    WriterTaskKind::Bind { key_id, .. }
                        if self.retired_keys.contains(key_id)
                )
            });
        }
        if self
            .bound_writer
            .is_some_and(|writer| matches!(writer, WriterRef::Device(_)))
        {
            self.bound_writer = Some(target);
        }
        Ok(())
    }

    /// The armed resend of writes the server deferred, when there is one.
    ///
    /// A pump that owns a timer sleeps for [`ResendTimer::wait`] and then calls
    /// [`resend_deferred`](Self::resend_deferred). One that does not leaves the
    /// writes pending until the next reconnect or [`replay_pending`](Self::replay_pending).
    #[must_use]
    pub const fn resend_timer(&self) -> Option<ResendTimer> {
        match &self.resend {
            Resend::Waiting { timer, .. } => Some(*timer),
            Resend::Idle | Resend::Resent { .. } => None,
        }
    }

    /// Send every pending write again, in order, when `timer` is still the armed resend.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when encoding or sending a queued mutation fails.
    pub async fn resend_deferred(&mut self, timer: ResendTimer) -> Result<(), ClientError> {
        match core::mem::replace(&mut self.resend, Resend::Idle) {
            Resend::Waiting {
                episode,
                timer: armed,
            } if armed == timer && self.is_connected() => {
                self.resend = Resend::Resent { episode };
                self.replay_pending().await
            }
            unchanged => {
                self.resend = unchanged;
                Ok(())
            }
        }
    }

    /// Arm a resend after the server deferred a pending write, `asked` being the wait it named.
    ///
    /// An armed resend stands, because it already sends every pending write.
    fn defer_pending(&mut self, asked: Option<Duration>) {
        let mut episode = match core::mem::replace(&mut self.resend, Resend::Idle) {
            waiting @ Resend::Waiting { .. } => {
                self.resend = waiting;
                return;
            }
            Resend::Resent { episode } => episode,
            Resend::Idle => RESEND_POLICY.start(),
        };
        let backoff = episode
            .next_wait()
            .unwrap_or_else(|| RESEND_POLICY.max_backoff());
        self.resends_armed += 1;
        self.resend = Resend::Waiting {
            episode,
            timer: ResendTimer {
                armed: self.resends_armed,
                wait: asked.unwrap_or(backoff),
            },
        };
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
        self.attach_replay = AttachReplay::Idle;
        // A fresh transport replays every pending write, so no resend stays owed.
        self.resend = Resend::Idle;
        // The writer identity a connection bound to is per-connection; a fresh
        // handshake rebinds, and a held bind re-signs against the fresh nonce.
        self.bound_writer = None;
        self.writer_tasks.clear();
        self.writer_in_flight = None;
        #[cfg(feature = "device-identity")]
        {
            self.pending_bind = None;
        }
        #[cfg(feature = "device-identity")]
        self.enrol_waiters.clear();
        // A relay answer can no longer arrive, so each waiting tab call fails now.
        self.relay_share_key_waits.clear();
        // Desired keys and durable coverage survive a transport failure.
        self.share_key_request = None;
        self.declaration_fence = None;
        self.share_key_retry_at = None;
        self.open_snapshots.clear();
        self.authorization_cleared = None;
        self.unfenced_computed.clear();
        self.unfenced_count = 0;
        self.recompute_share_key_deadline();
        if self.wire.take().is_some() {
            self.notices
                .push_back(ClientEvent::SyncStatus(SyncStatus::Offline));
        }
    }

    /// Drop the current transport while preserving the resumable session.
    pub fn disconnect(&mut self) {
        self.disconnected();
    }

    /// Run due share-key work, deferring secret writes while `persist` is `false`.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when checkpoint or secret persistence fails.
    pub async fn process_share_keys(&mut self, persist: bool) -> Result<bool, ClientError> {
        self.check_share_key_deadlines();
        let due = self
            .share_key_deadline
            .is_some_and(|at| crate::away::SystemClock.monotonic() >= at);
        let changed = if due {
            self.expire_share_keys(persist).await?
        } else {
            false
        };
        if persist
            && self.share_key_save_pending
            && let Some(store) = &self.share_key_persistence
        {
            let set = self.share_key_set();
            store.save(set).await?;
            self.share_key_save_pending = false;
        }
        Ok(changed)
    }

    /// The next share-key wake, if any, for a driver to sleep on and rerun
    /// [`process_share_keys`](Self::process_share_keys) when it lands.
    #[must_use]
    pub fn share_key_timer(&self) -> Option<ShareKeyTimer> {
        self.share_key_deadline.map(|deadline| ShareKeyTimer {
            armed: self.share_key_armed,
            deadline,
        })
    }

    /// Set the secret store before preparing the durable connection.
    pub(crate) fn initialize_share_key_store(&mut self, store: ShareKeyPersistence) {
        self.share_key_persistence = Some(store);
    }

    /// Merge stored and builder keys before exposing a durable replica.
    pub(crate) async fn prepare_share_keys(&mut self) -> Result<(), ClientError> {
        if self.share_key_loaded {
            return Ok(());
        }
        let now = clock::now_secs(&mut self.db)?;
        self.load_share_key_store(now).await?;
        self.share_key_loaded = true;
        Ok(())
    }

    /// The share keys this connection holds, as the durable set renders them.
    fn share_key_set(&self) -> &ShareKeySet {
        static EMPTY: ShareKeySet = ShareKeySet {
            separator: ' ',
            keys: Vec::new(),
        };
        self.config
            .subjects
            .as_ref()
            .map_or(&EMPTY, |source| &source.set)
    }

    /// Refresh the cached earliest expiry of a held key, at a set change
    /// alone, so an unrelated frame never parses a grant.
    fn refresh_share_key_expiry(&mut self) {
        self.share_key_expiry = self
            .config
            .subjects
            .iter()
            .flat_map(|subjects| subjects.set.keys.iter().map(|(grant, _)| grant))
            .filter_map(grant_expiry::expiry_of)
            .min();
    }

    /// Recompute the instant the next share-key work is due, arming the timer
    /// when it moves.
    fn recompute_share_key_deadline(&mut self) {
        let now = crate::away::SystemClock.monotonic();
        let mut deadline = self.share_key_retry_at.filter(|at| *at > now);
        if let Some(expiry) = self.share_key_expiry {
            let remaining = if expiry <= 0 {
                Duration::ZERO
            } else {
                Duration::from_secs(u64::try_from(expiry).expect("a positive i64 fits a u64"))
                    .saturating_sub(crate::away::SystemClock.wall())
            };
            deadline = Some(match deadline {
                Some(armed) => armed.min(now + remaining),
                None => now + remaining,
            });
        }
        if let Some(request) = &self.share_key_request {
            deadline = match deadline {
                Some(armed) => Some(armed.min(request.deadline)),
                None => Some(request.deadline),
            };
        }
        if let Some(fence) = &self.declaration_fence {
            deadline = match deadline {
                Some(armed) => Some(armed.min(fence.deadline)),
                None => Some(fence.deadline),
            };
        }
        if let Some(relay) = self
            .relay_share_key_waits
            .values()
            .map(|wait| wait.deadline)
            .min()
        {
            deadline = Some(deadline.map_or(relay, |armed| armed.min(relay)));
        }
        if deadline != self.share_key_deadline {
            self.share_key_deadline = deadline;
            self.share_key_armed += 1;
        }
    }

    /// Drop the connection when a share-key answer overran its bound, and end
    /// every relay wait past its own bound with an unknown outcome.
    fn check_share_key_deadlines(&mut self) {
        let now = crate::away::SystemClock.monotonic();
        let overdue: Vec<String> = self
            .relay_share_key_waits
            .iter()
            .filter(|(_, wait)| now >= wait.deadline)
            .map(|(id, _)| id.clone())
            .collect();
        let expired = !overdue.is_empty();
        for id in overdue {
            if let Some(wait) = self.relay_share_key_waits.remove(&id) {
                let _ = wait.answer.send(Err(ClientError::Transport(
                    "the relay did not answer the share-key change in time, so its outcome is unknown"
                        .to_owned(),
                )));
            }
        }
        if self
            .share_key_request
            .as_ref()
            .is_some_and(|request| now >= request.deadline)
            || self
                .declaration_fence
                .as_ref()
                .is_some_and(|fence| now >= fence.deadline)
        {
            tracing::warn!("a share-key answer overran its bound, dropping the connection");
            self.disconnected();
        } else if expired {
            self.recompute_share_key_deadline();
        }
    }

    /// Persist unknown coverage before authorization changes.
    fn invalidate_coverage(&mut self) -> Result<(), ClientError> {
        if self.cursor_subjects.is_some() {
            if let Some(cursor) = &self.last_cursor {
                let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
                persist_cursor_and_subjects(&mut self.db, cursor, None)?;
            }
            self.cursor_subjects = None;
        }
        Ok(())
    }

    /// Publish the durable coverage now that every frame before the cursor is
    /// owed by the server, so the cursor may be claimed on a resume.
    fn publish_coverage(&mut self) -> Result<(), ClientError> {
        if self.cursor_subjects.is_some()
            || self.share_key_request.is_some()
            || self.declaration_fence.is_some()
            || self.unfenced_count != 0
            || !self.unfenced_computed.is_empty()
            || self.share_key_generation != self.share_key_settled
            || !self.resyncing.is_empty()
            || !self.open_snapshots.is_empty()
        {
            return Ok(());
        }
        let Some(cursor) = &self.last_cursor else {
            return Ok(());
        };
        let subjects = if let Some(source) = &self.config.subjects {
            source
                .live_subjects(clock::now_secs(&mut self.db)?)
                .into_iter()
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        };
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        persist_cursor_and_subjects(&mut self.db, cursor, Some(&subjects))?;
        self.cursor_subjects = Some(subjects);
        self.authorization_cleared = None;
        Ok(())
    }

    /// Hide expired grants before attempting secret persistence.
    async fn expire_share_keys(&mut self, persist: bool) -> Result<bool, ClientError> {
        let now = clock::now_secs(&mut self.db)?;
        if self.config.subjects.as_ref().is_none_or(|subjects| {
            !subjects
                .set
                .keys
                .iter()
                .any(|(grant, _)| grant_expiry::has_expired(grant, now))
        }) {
            self.recompute_share_key_deadline();
            return Ok(false);
        }
        self.invalidate_coverage()?;
        if let Some(source) = &mut self.config.subjects {
            source
                .set
                .keys
                .retain(|(grant, _)| !grant_expiry::has_expired(grant, now));
        }
        self.share_key_generation += 1;
        self.refresh_share_key_expiry();
        self.rerender_subjects()?;
        self.recompute_share_key_deadline();
        if let Some(store) = &self.share_key_persistence {
            if persist {
                let set = self.share_key_set();
                if let Err(error) = store.save(set).await {
                    self.share_key_save_pending = true;
                    return Err(error);
                }
                self.share_key_save_pending = false;
            } else {
                self.share_key_save_pending = true;
            }
        }
        Ok(true)
    }

    /// Re-register the subjects function against the replica's clock and mark
    /// every table changed, so a query filtered on the keys re-runs.
    fn rerender_subjects(&mut self) -> Result<(), ClientError> {
        let Some(source) = &self.config.subjects else {
            return Ok(());
        };
        let rendered = source.rendered(clock::now_secs(&mut self.db)?);
        register_subjects(&mut self.db, &source.function, rendered)?;
        let tables: Vec<String> = sqlite_catalog::table
            .select(sqlite_catalog::name)
            .filter(sqlite_catalog::kind.eq_any(["table", "view"]))
            .load(&mut self.db)?;
        self.changed
            .lock()
            .expect("the changed-tables lock")
            .extend(tables);
        Ok(())
    }

    /// Persist and install an accepted key change before advancing its generation.
    async fn commit_share_key_change(&mut self) -> Result<(), ClientError> {
        self.invalidate_coverage()?;
        if let Some(store) = &self.share_key_persistence {
            let set = self.share_key_set();
            store.save(set).await?;
            self.share_key_save_pending = false;
        }
        self.rerender_subjects()?;
        self.share_key_generation += 1;
        self.refresh_share_key_expiry();
        self.recompute_share_key_deadline();
        Ok(())
    }

    /// Add `grant` for `subject` to the durable share-key set.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica rejects the write or this
    /// connection is a relay tab's mirror, which changes keys through
    /// [`ConnettoClient`], and [`ClientError::Auth`]
    /// when the store refuses the save. A failed change leaves the held set
    /// unchanged.
    pub async fn add_share_key<K: CapabilityKey>(
        &mut self,
        grant: &Grant,
        subject: &CapabilitySubject<K>,
    ) -> Result<(), ClientError> {
        self.refuse_relay_mirror_change()?;
        self.add_rendered_share_key(grant, subject.key().to_string())
            .await
            .map(drop)
    }

    /// Drop every key `subject` renders as from the durable share-key set.
    ///
    /// # Errors
    ///
    /// As [`add_share_key`](Self::add_share_key).
    pub async fn remove_share_key<K: CapabilityKey>(
        &mut self,
        subject: &CapabilitySubject<K>,
    ) -> Result<(), ClientError> {
        self.refuse_relay_mirror_change()?;
        self.remove_rendered_share_key(&subject.key().to_string())
            .await
            .map(drop)
    }

    /// Apply a relay tab's change to the keys this worker holds, reporting
    /// whether the subjects its replica answers moved.
    ///
    /// # Errors
    ///
    /// As [`add_share_key`](Self::add_share_key).
    pub async fn apply_relay_share_key_change(
        &mut self,
        change: &ShareKeyChange,
    ) -> Result<bool, ClientError> {
        self.refuse_relay_mirror_change()?;
        match change {
            ShareKeyChange::Add { grant, subject } => {
                self.add_rendered_share_key(grant, subject.clone()).await
            }
            ShareKeyChange::Remove { subject } => self.remove_rendered_share_key(subject).await,
        }
    }

    /// A count that moves whenever the held share-key set changes, so a relay
    /// restates its identity to its tabs only after it moved.
    #[must_use]
    pub fn share_key_generation(&self) -> u64 {
        self.share_key_generation
    }

    /// Whether this connection mirrors a relay's worker.
    pub(crate) fn is_relay_mirror(&self) -> bool {
        self.config.relay_mirror
    }

    fn refuse_relay_mirror_change(&self) -> Result<(), ClientError> {
        if self.config.relay_mirror {
            return Err(ClientError::Session(
                "a relay tab changes share keys through its ConnettoClient".to_owned(),
            ));
        }
        Ok(())
    }

    async fn add_rendered_share_key(
        &mut self,
        grant: &Grant,
        rendered: String,
    ) -> Result<bool, ClientError> {
        let changed = match &mut self.config.subjects {
            Some(source) => {
                if source
                    .set
                    .keys
                    .iter()
                    .any(|(held, subject_held)| held == grant && subject_held == &rendered)
                {
                    false
                } else {
                    source.set.keys.push((grant.clone(), rendered));
                    true
                }
            }
            None => false,
        };
        if !changed {
            return Ok(false);
        }
        if let Err(error) = self.commit_share_key_change().await {
            if let Some(source) = &mut self.config.subjects {
                source.set.keys.pop();
            }
            return Err(error);
        }
        Ok(true)
    }

    async fn remove_rendered_share_key(&mut self, rendered: &str) -> Result<bool, ClientError> {
        let removed: Vec<(Grant, String)> = match &mut self.config.subjects {
            Some(source) => source
                .set
                .keys
                .extract_if(.., |(_, subject_held)| subject_held == rendered)
                .collect(),
            None => Vec::new(),
        };
        if removed.is_empty() {
            return Ok(false);
        }
        if let Err(error) = self.commit_share_key_change().await {
            if let Some(source) = &mut self.config.subjects {
                source.set.keys.extend(removed);
            }
            return Err(error);
        }
        Ok(true)
    }

    /// Send a relay tab's change to its worker and the receiver its outcome
    /// arrives on, within [`SHARE_KEY_REQUEST_WAIT`].
    ///
    /// The receiver fails at once when the connection drops.
    pub(crate) async fn ask_relay_share_key(
        &mut self,
        change: ShareKeyChange,
    ) -> Result<tokio::sync::oneshot::Receiver<Result<(), ClientError>>, ClientError> {
        let request_id = share_key_request_id();
        self.wire()?
            .transport
            .send_control(ControlMessage::TabShareKeyChange(TabShareKeyChange {
                request_id: request_id.clone(),
                change,
            }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let (answer, receiver) = tokio::sync::oneshot::channel();
        self.relay_share_key_waits.insert(
            request_id,
            RelayShareKeyWait {
                answer,
                deadline: crate::away::SystemClock.monotonic() + SHARE_KEY_REQUEST_WAIT,
            },
        );
        self.recompute_share_key_deadline();
        Ok(receiver)
    }

    /// Hand a relay's answer to the change waiting on it. An answer nobody
    /// waits for arrived after its wait ended, and is dropped.
    fn settle_relay_share_key(&mut self, answer: TabShareKeyAnswer) {
        let Some(wait) = self.relay_share_key_waits.remove(&answer.request_id) else {
            tracing::debug!(request_id = %answer.request_id, "a share-key answer arrived after its wait");
            return;
        };
        let outcome = match answer.outcome {
            TabShareKeyOutcome::Changed => Ok(()),
            TabShareKeyOutcome::Locked => Err(ClientError::Locked),
            TabShareKeyOutcome::StoreRefused(detail) => Err(ClientError::Auth(detail)),
            TabShareKeyOutcome::ReplicaRefused(detail) => Err(ClientError::Session(detail)),
        };
        let _ = wait.answer.send(outcome);
        self.recompute_share_key_deadline();
    }

    /// Send the swap carrying every live held key, one in flight at a time.
    async fn send_share_key_replacement(&mut self) -> Result<(), ClientError> {
        let now = clock::now_secs(&mut self.db)?;
        let keys = self
            .config
            .subjects
            .iter()
            .flat_map(|subjects| subjects.set.keys.iter().map(|(grant, _)| grant.clone()))
            .filter(|grant| !grant_expiry::has_expired(grant, now))
            .collect();
        let request_id = share_key_request_id();
        let generation = self.share_key_generation;
        self.wire()?
            .transport
            .send_control(ControlMessage::ReplaceShareKeys(ReplaceShareKeys {
                request_id: request_id.clone(),
                keys,
            }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        self.authorization_cleared = Some(HashSet::new());
        self.share_key_request = Some(ShareKeyRequest {
            request_id,
            generation,
            deadline: crate::away::SystemClock.monotonic() + SHARE_KEY_REQUEST_WAIT,
        });
        self.share_key_retry_at = None;
        self.recompute_share_key_deadline();
        Ok(())
    }

    /// Fence every declaration preceding a correlated ping.
    async fn declare_fence(&mut self) -> Result<(), ClientError> {
        let nonce = declaration_fence_nonce();
        let sub_ids: Vec<String> = self.unfenced_computed.iter().cloned().collect();
        self.wire()?
            .transport
            .send_control(ControlMessage::Ping(Ping { nonce }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        self.declaration_fence = Some(DeclarationFence {
            nonce,
            deadline: crate::away::SystemClock.monotonic() + SHARE_KEY_REQUEST_WAIT,
            count: self.unfenced_count,
            sub_ids,
        });
        self.recompute_share_key_deadline();
        Ok(())
    }

    /// Drive replacements, declaration fences, expiry and checkpoint publication.
    async fn step_share_keys(&mut self) -> Result<(), ClientError> {
        if self.wire.is_some() && matches!(self.attach_replay, AttachReplay::Idle) {
            if self.share_key_request.is_none()
                && self.share_key_generation > self.share_key_settled
                && self.unfenced_count == 0
                && self
                    .share_key_retry_at
                    .is_none_or(|at| crate::away::SystemClock.monotonic() >= at)
            {
                self.send_share_key_replacement().await?;
            } else if self.declaration_fence.is_none()
                && self.cursor_subjects.is_none()
                && self.unfenced_count > 0
            {
                self.declare_fence().await?;
            }
        }
        if self
            .share_key_deadline
            .is_some_and(|at| crate::away::SystemClock.monotonic() >= at)
        {
            self.expire_share_keys(false).await?;
        }
        self.publish_coverage()?;
        Ok(())
    }

    /// Settle only the key generation carried by this replacement.
    fn settle_share_key_replacement(&mut self, request_id: &str) -> Result<(), ClientError> {
        let Some(request) = self.share_key_request.take() else {
            return Err(ClientError::Protocol(
                "a share-key answer arrived with nothing in flight".to_owned(),
            ));
        };
        if request.request_id != request_id {
            self.share_key_request = Some(request);
            return Err(ClientError::Protocol(
                "the share-key answer names a foreign request".to_owned(),
            ));
        }
        self.share_key_settled = request.generation;
        self.recompute_share_key_deadline();
        self.publish_coverage()?;
        Ok(())
    }

    /// Merge stored and builder keys before exposing the durable replica.
    async fn load_share_key_store(&mut self, now: i64) -> Result<(), ClientError> {
        let Some(store) = &self.share_key_persistence else {
            return Ok(());
        };
        let stored = store.load().await?;
        let mut set = match (&self.config.subjects, &stored) {
            (None, Some(stored)) => ShareKeySet::rendered(stored.separator(), Vec::new()),
            _ => self.share_key_set().clone(),
        };
        if let Some(stored) = &stored {
            set.union(stored.pairs());
        }
        set.remove_expired(now);
        if stored.as_ref() != Some(&set) {
            self.invalidate_coverage()?;
            self.share_key_persistence
                .as_ref()
                .expect("a durable store was loaded")
                .save(&set)
                .await?;
            self.share_key_save_pending = false;
        }
        let function = self.config.subjects.take().map_or_else(
            || connetto_core::SUBJECTS_FUNCTION.to_owned(),
            |source| source.function,
        );
        self.config.subjects = Some(SubjectSource { function, set });
        self.refresh_share_key_expiry();
        self.rerender_subjects()?;
        self.recompute_share_key_deadline();
        Ok(())
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

    /// The number of the handshake that attached the live wire, or `None`
    /// while no server is reachable.
    #[cfg(feature = "device-identity")]
    pub(crate) fn connection_number(&self) -> Option<ConnectionNumber> {
        self.wire.as_ref().map(|wire| wire.number)
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

    /// The logical-to-physical table map this connection renames with.
    ///
    /// An embedder that serves other consumers from this replica (the relay
    /// hub) must read a split table through the same map the connection
    /// applies with, or the two disagree silently.
    #[must_use]
    pub fn policy_tables(&self) -> &PolicyTables {
        &self.config.policy_tables
    }

    /// The physical tables held in the device-wide public store.
    #[must_use]
    pub fn shared_tables(&self) -> &HashSet<String> {
        &self.config.shared_tables
    }

    /// Who this connection answers its policy views as, which a relay states
    /// to each tab so the tab's mirror answers them the same way.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the replica's clock cannot be read to decide
    /// which share keys are still alive.
    pub fn relay_identity(&mut self) -> Result<TabIdentity, ClientError> {
        let caller = self
            .config
            .caller
            .as_ref()
            .map(|(_, identity)| identity.clone());
        let subjects = match &self.config.subjects {
            Some(subjects) => subjects.rendered(crate::clock::now_secs(&mut self.db)?),
            None => None,
        };
        Ok(TabIdentity { caller, subjects })
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

    /// The (writer, sequence) pairs of entries captured locally but not yet
    /// confirmed durable by the server. Non-empty means a teardown would lose
    /// data, so logout and expiry surface these before purging the replica.
    #[must_use]
    pub fn unsynced(&self) -> Vec<UnsyncedWrite> {
        self.writers
            .iter()
            .flat_map(|(writer, queue)| {
                queue.pending.keys().map(move |seq| UnsyncedWrite {
                    writer: *writer,
                    seq: *seq,
                })
            })
            .collect()
    }

    /// The lowercased names of the tables in the attached local tier, empty
    /// when no tier is attached.
    #[must_use]
    pub const fn local_tables(&self) -> &HashSet<String> {
        &self.local_tables
    }

    /// Write an archive of this device's local data into `sink`, which
    /// [`import_local_data`](Self::import_local_data) reads back.
    ///
    /// The archive is written through as it is made, so a file sink costs a
    /// file and no copy of it. The sink comes back, which is how a caller
    /// reaches a buffer it passed in.
    ///
    /// `scope` decides how much travels: [`ExportScope::Everything`] carries
    /// the synced replica and the device-private tier, and
    /// [`ExportScope::Unsynced`] carries only what an import restores, which is
    /// the device-private tier and the writes that never reached the server.
    /// Authentication state and sync cursors are never exported.
    ///
    /// Rows use connetto's SQLite change-record format, while optional client layers may add declared attachments.
    ///
    /// **The archive is not encrypted.** It holds every row this device can
    /// read, in the clear, so it is a bearer document: whoever holds the file
    /// holds the data. That is deliberate, and it is why this is the only place
    /// that says so. Put it somewhere you would put the data itself.
    ///
    /// # Errors
    ///
    /// [`ClientError::Export`] when a table has no declared primary key and
    /// was not named in
    /// [`SyncSchema::with_unrecorded_tables`](crate::SyncSchema::with_unrecorded_tables), since SQLite
    /// records no changes for one and its rows would be silently absent. A
    /// named one is skipped, which is what the declaration means. Also when
    /// the sink refuses a write.
    pub fn export_local_data<W: std::io::Write>(
        &mut self,
        scope: ExportScope,
        sink: W,
    ) -> Result<W, ClientError> {
        self.export_local_data_with_attachments(scope, &[], sink)?
            .finish()
    }

    /// Starts a local-data archive that declares `attachments` at their relative paths.
    ///
    /// The returned export owes one
    /// [`write_attachment`](LocalDataExport::write_attachment) per declaration
    /// and is closed by [`finish`](LocalDataExport::finish), so the caller
    /// holds one attachment at a time and the archive is never assembled in
    /// memory.
    ///
    /// # Errors
    ///
    /// Returns the errors from [`Self::export_local_data`] and refuses unsafe
    /// or repeated attachment paths, one declaration above the per-entry
    /// ceiling, or declarations above the aggregate ceiling.
    pub fn export_local_data_with_attachments<W: std::io::Write>(
        &mut self,
        scope: ExportScope,
        attachments: &[ArchiveAttachment],
        sink: W,
    ) -> Result<LocalDataExport<W>, ClientError> {
        let synced_rows = match scope {
            ExportScope::Everything => Some(export_rows(
                &mut self.db,
                "main",
                None,
                &self.hidden_tables,
                &self.config.unrecorded_tables,
            )?),
            ExportScope::Unsynced => None,
        };
        let local_rows = if self.local_tables.is_empty() {
            None
        } else {
            Some(export_rows(
                &mut self.db,
                LOCAL_SCHEMA,
                Some(&self.local_tables),
                &HashSet::new(),
                &self.config.unrecorded_tables,
            )?)
        };
        archive::start(
            sink,
            &archive::Archive {
                scope,
                fingerprint: self.schema_fingerprint()?,
                account: self.account(),
                synced_rows,
                local_rows,
                pending: {
                    let mut queued: Vec<_> = self
                        .writers
                        .iter()
                        .flat_map(|(writer, queue)| {
                            queue.pending.iter().map(move |(seq, entry)| {
                                (
                                    entry.position,
                                    archive::ArchivedEntry {
                                        writer: *writer,
                                        seq: *seq,
                                        hash: entry.hash,
                                        changeset: entry.changeset.clone(),
                                        provenance: entry.provenance,
                                    },
                                )
                            })
                        })
                        .collect();
                    queued.sort_unstable_by_key(|(position, _)| *position);
                    queued.into_iter().map(|(_, entry)| entry).collect()
                },
                attachments,
            },
        )
    }

    /// The fingerprint of the schema this replica runs, over both tiers.
    fn schema_fingerprint(&mut self) -> Result<String, ClientError> {
        let local = if self.local_tables.is_empty() {
            None
        } else {
            Some(self.local_tables.clone())
        };
        let schemas: Vec<(&str, Option<&HashSet<String>>)> = match &local {
            Some(tables) => vec![("main", None), (LOCAL_SCHEMA, Some(tables))],
            None => vec![("main", None)],
        };
        archive::fingerprint(&mut self.db, &schemas, &self.hidden_tables)
    }

    /// The account this replica is signed in as, as the deployment's own policy
    /// names it, or [`None`] when the deployment names no caller.
    ///
    /// The caller value is the one thing on the device that says whose rows
    /// these are: it is what the server binds as the row-level-security
    /// identity, so an archive and the replica it is imported into agree on it
    /// or the import refuses. A deployment with no policy has no such value and
    /// also nothing owning its rows, so the check has nothing to protect there.
    fn account(&self) -> Option<String> {
        self.config
            .caller
            .as_ref()
            .map(|(_, identity)| identity.clone())
    }

    /// Read an archive from a seekable `source`, check it against this replica,
    /// and report what applying it would overwrite. Nothing is written.
    ///
    /// The plan holds `source` open, because the attachments it names are read
    /// from it one at a time rather than carried, so a `2 GiB` archive costs
    /// the largest attachment in it and never the whole file.
    ///
    /// Only what the server does not have is ever restored: the device-private
    /// tier and the writes that never reached it. The cache of rows the server
    /// already holds is skipped even when the archive carries it, because the
    /// server sends those again and writing them back would have them deleted
    /// without warning at the next refresh.
    ///
    /// Answer the plan's collisions with [`ImportChoices`] and hand both to
    /// [`apply_import`](Self::apply_import). The file wins by default, and
    /// never silently: the clashes are in the plan before anything is
    /// overwritten.
    ///
    /// # Errors
    ///
    /// [`ClientError::Import`] naming the refusal: an archive of another
    /// format or version, one made under a different schema, one belonging to
    /// another account, a queue longer than this build holds, or a table this
    /// build does not have.
    pub fn import_local_data<R: std::io::Read + std::io::Seek>(
        &mut self,
        source: R,
    ) -> Result<ImportPlan<R>, ClientError> {
        let (archive, reader) = archive::open(source)?;
        validate_archive_compat(
            &archive,
            &self.schema_fingerprint()?,
            self.account().as_deref(),
        )?;
        let (local_columns, main_columns) =
            resolve_import_columns(&mut self.db, &self.local_tables, &self.hidden_tables)?;
        for entry in &archive.pending {
            pending_tables(&entry.changeset, &main_columns)?;
        }
        let (incoming, held) = build_import_index(
            &mut self.db,
            &archive,
            &local_columns,
            &self.local_tables,
            &self.config.unrecorded_tables,
        )?;
        let (rows, collisions) = plan_import_rows(incoming, &held);
        Ok(ImportPlan {
            archive,
            rows,
            collisions,
            reader,
        })
    }

    /// Apply a plan, honouring `choices` for every clash it reported.
    ///
    /// The device-private rows land in this build's schema, and each restored
    /// write is applied locally **and** put back in the queue, which is the
    /// pair an offline write already produces, so the replica ends where it
    /// would have been had those writes been made here. The next connection
    /// replays them through the ordinary path.
    ///
    /// The restored writes are numbered above this replica's own. A number
    /// means something only inside one durable session handle and an archive
    /// arrives under a different one, so the file's numbers would collide here
    /// and say nothing to the server.
    ///
    /// The whole apply is one transaction, so an import is all or nothing.
    /// SQLite rolls back a single failed apply on its own, measured in
    /// `tests/apply_behaviour.rs`, but an import is a sequence of them and a
    /// half-restored replica is exactly what this phase exists to avoid.
    ///
    /// # Errors
    ///
    /// [`ClientError::Import`] when rows, queued writes, or attachment handling fail, and [`ClientError::Db`] on a local database failure.
    pub fn apply_import<R>(
        &mut self,
        plan: &ImportPlan<R>,
        choices: &ImportChoices,
    ) -> Result<ImportOutcome, ClientError> {
        if !plan.attachments().is_empty() {
            return Err(ClientError::Import(
                "the archive carries attachments that require an attachment-aware importer"
                    .to_owned(),
            ));
        }
        self.apply_import_with_bookkeeping(plan, choices, |_| Ok(()))
    }

    /// Applies imported rows and writes before running `bookkeeping` in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns the errors from [`Self::apply_import`] or `bookkeeping`.
    pub fn apply_import_with_bookkeeping<R, F>(
        &mut self,
        plan: &ImportPlan<R>,
        choices: &ImportChoices,
        bookkeeping: F,
    ) -> Result<ImportOutcome, ClientError>
    where
        F: FnOnce(&mut SqliteConnection) -> Result<(), ClientError>,
    {
        let mut outcome = ImportOutcome::default();
        {
            // Suspended for the whole apply, so restoring a write does not
            // capture a second write of the same rows.
            let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
            self.db.transaction::<(), ClientError, _>(|db| {
                // Checked at the commit, so neither table order nor row order
                // inside a self-referencing table can refuse a whole archive,
                // and an orphan still aborts the import (R92 decision 3).
                db.batch_execute("PRAGMA defer_foreign_keys = ON")?;
                for row in &plan.rows {
                    if choices.answer(row.collision) == Keep::Mine {
                        outcome.rows_kept += 1;
                        continue;
                    }
                    archive::write_row(
                        db,
                        &archive::rows::RowWrite {
                            schema: LOCAL_SCHEMA,
                            table: &row.table,
                            columns: &row.columns,
                            key_columns: &row.key_columns,
                            values: &row.values,
                        },
                    )?;
                    outcome.rows_restored += 1;
                }
                for entry in &plan.archive.pending {
                    // A row this changeset updates or deletes that the replica
                    // never held is omitted rather than failing: the cache is
                    // not imported, so it may not be here, and the server
                    // settles the write when it goes up.
                    db.apply_changeset(&entry.changeset, |_| ConflictAction::Omit)
                        .map_err(|err| {
                            ClientError::Import(format!("applying a restored write: {err}"))
                        })?;
                    outcome.writes_restored += 1;
                }
                bookkeeping(db)?;
                Ok(())
            })?;
        }
        let restored = self.restore_archived_writes(&plan.archive.pending)?;
        debug_assert_eq!(outcome.writes_restored, restored);
        Ok(outcome)
    }

    /// Re-queue archived writes in causal order while retaining their original identities.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a local database failure while persisting the queue.
    fn restore_archived_writes(
        &mut self,
        entries: &[archive::ArchivedEntry],
    ) -> Result<usize, ClientError> {
        if entries.is_empty() {
            return Ok(0);
        }
        let current = self.choose_writer();
        let archived: std::collections::BTreeSet<WriterRef> = entries
            .iter()
            .map(|entry| entry.writer)
            .filter(is_real_writer)
            .collect();
        {
            let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
            for writer in &archived {
                persist_retire(&mut self.db, writer)?;
            }
        }
        let target = if archived.contains(&current) {
            // The archived writer is this replica's own, so it is retired and
            // its tail, restored entries included, travels to the live writer.
            let live = self.tail_target(&current);
            self.carry_writers(&[current], &live)?;
            #[cfg(feature = "device-identity")]
            if matches!(current, WriterRef::Device(_))
                && let Some(sender) = &self.writer_retired
            {
                let _ = sender.send(crate::enrolment::Command::WriterRetired);
            }
            live
        } else {
            current
        };
        let mut restored = 0;
        for entry in entries {
            let provenance = entry.provenance.or_else(|| {
                is_real_writer(&entry.writer).then_some(Provenance {
                    writer: entry.writer,
                    seq: entry.seq,
                })
            });
            self.append_entry(&target, &entry.changeset, provenance)?;
            restored += 1;
        }
        Ok(restored)
    }

    /// How the key protecting this replica is held.
    ///
    /// Returns [`Custody::Ephemeral`] whenever the replica is in-memory,
    /// regardless of what was configured, because an in-memory replica has no
    /// durable key by construction.
    #[must_use]
    pub const fn custody(&self) -> Custody {
        if self.durable {
            self.config.custody
        } else {
            Custody::Ephemeral
        }
    }

    /// The grace a watcher may outlive this connection, from the config.
    #[must_use]
    pub(crate) const fn watch_grace(&self) -> Duration {
        self.config.tuning.watch_grace()
    }

    /// Update the custody level, for example after a gate is enrolled while the
    /// process runs. Has no effect on an in-memory replica: `custody()` still
    /// reports `Ephemeral` for one, because no durable key was ever written.
    pub fn set_custody(&mut self, custody: Custody) {
        self.config.custody = custody;
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
            let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
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
        // A computed declaration carries no coverage to prove it, so it owes
        // its replay until a fence or a swap settles it (R95).
        let computed = crate::live::coverage_of(&spec).is_ok_and(|coverage| coverage.is_none());
        self.invalidate_coverage()?;
        if computed {
            if self.unfenced_computed.insert(sub_id.to_owned()) {
                self.unfenced_count += 1;
            }
        } else {
            self.open_snapshots.insert(sub_id.to_owned());
        }
        self.wire()?
            .transport
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: sub_id.to_owned(),
                spec,
            }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        Ok(())
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
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        subscriptions::pin(&mut self.db, name, sub_id, spec)
    }

    /// End the pin under `name`, leaving its subscription on the ordinary
    /// grace path. Unknown names are a no-op.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica rejects the write.
    pub fn unpin_subscription(&mut self, name: &str) -> Result<(), ClientError> {
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
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
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        subscriptions::release(&mut self.db, sub_id)
    }

    /// Stop the grace countdown on `sub_id`, because a handle holds it again.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica rejects the write.
    pub fn hold_subscription(&mut self, sub_id: &str) -> Result<(), ClientError> {
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        subscriptions::hold(&mut self.db, sub_id)
    }

    /// Every subscription whose grace has run out. Reading this ends nothing:
    /// the caller unsubscribes each and drops its record.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica cannot be read or written.
    pub fn expired_subscriptions(&mut self) -> Result<Vec<String>, ClientError> {
        self.reanchor_subscriptions()?;
        subscriptions::expired(&mut self.db)
    }

    /// Re-anchor every stop moment a stepped-back wall clock left ahead of the
    /// replica clock, with capture suspended so the write never rides an upload.
    fn reanchor_subscriptions(&mut self) -> Result<(), ClientError> {
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        subscriptions::reanchor_ahead(&mut self.db)
    }

    /// The current wall time in seconds since the epoch, from the replica's
    /// own clock, so the resting table's as-of stamps and the expiry
    /// comparisons agree on one clock.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica cannot be read.
    pub(crate) fn now_secs(&mut self) -> Result<i64, ClientError> {
        clock::now_secs(&mut self.db)
    }

    /// Rest one server aggregate frame in `_connetto_aggregates`, then evict
    /// down to the configured cap.
    ///
    /// The frame carries only its run-local subscription id, so the query
    /// identity that keys the rested row (query text and binds) is resolved
    /// from the persisted subscription record that same id names. A frame
    /// whose subscription is not on record rests nothing: there is no identity
    /// to key it on, and a live frame always has one. The write is a
    /// `_connetto_*` write, so it runs under capture suspension and never rides
    /// a mutation upload.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica rejects the write.
    fn rest_aggregate(
        &mut self,
        sub_id: &str,
        frame: &aggregates::AggregateFrame<'_>,
    ) -> Result<(), ClientError> {
        let Some((query_id, binds)) = subscriptions::identity_of(&mut self.db, sub_id)? else {
            return Ok(());
        };
        let now = clock::now_secs(&mut self.db)?;
        // The statistics still on record are the ones a handle still watches,
        // so the cap never evicts a value in use.
        let protected = subscriptions::live_identities(&mut self.db)?;
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        aggregates::apply_frame(&mut self.db, query_id, &binds, frame, now)?;
        // A removal cannot add a statistic, so only a write needs the cap.
        if frame.result_json.is_some() {
            aggregates::enforce_cap(
                &mut self.db,
                self.config.tuning.rested_statistics_cap(),
                &protected,
            )?;
        }
        Ok(())
    }

    /// The rested scalar value and its as-of time for a subscription's query
    /// and binds, or `None` when none rests. The scalar watch bootstraps from
    /// this on an offline restart, and a relay answers a tab's aggregate watch
    /// from it while its worker is offline.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica cannot be read.
    pub fn rested_scalar(
        &mut self,
        query: &str,
        binds: &[BindValue],
    ) -> Result<Option<(String, i64)>, ClientError> {
        aggregates::lookup_scalar(&mut self.db, query, binds)
    }

    /// Every rested group row for a subscription's query and binds, the
    /// scalar row excluded, in stored-key order. A keyed or row-shaped handle
    /// bootstraps from these on an offline restart and a late join, whichever
    /// resting shape it finds (R84).
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica cannot be read.
    pub(crate) fn rested_groups(
        &mut self,
        query: &str,
        binds: &[BindValue],
    ) -> Result<Vec<aggregates::RestedGroup>, ClientError> {
        aggregates::lookup_groups(&mut self.db, query, binds)
    }

    /// Every subscription this replica has declared and not dropped, whether
    /// or not a server has ever seen them.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica cannot be read or written.
    pub fn declared_subscriptions(
        &mut self,
    ) -> Result<Vec<(String, SubscriptionSpec)>, ClientError> {
        self.reanchor_subscriptions()?;
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
        self.reanchor_subscriptions()?;
        for record in subscriptions::declared(&mut self.db)? {
            if record.live {
                self.send_subscribe(&record.sub_id, record.spec).await?;
            } else {
                // Past its grace, so it is ended rather than re-declared. Its
                // rows are evicted here, the first connected moment that can
                // honour the transport-down guard, before the record goes (R15
                // D3). The server never saw it on this connection, so there is
                // nothing to unsubscribe.
                self.evict_subscription_rows(&record.sub_id)?;
                let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
                subscriptions::forget(&mut self.db, &record.sub_id)?;
            }
        }
        Ok(())
    }

    /// Cancel a subscription (row or aggregate) by its client-assigned id. The
    /// server tolerates an unknown id silently.
    ///
    /// Connected, the rows the subscription synced are evicted before the
    /// record goes, the live teardown's order, because a forgotten record
    /// takes its table out of every later pass's scope and would strand the
    /// rows for ever. Offline, eviction is barred (a row discarded offline
    /// cannot be re-fetched, R15 D3), so the record is ended rather than
    /// forgotten: the next connected attach evicts and then forgets it, and an
    /// ended record is never replayed as a subscription.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the unsubscribe frame cannot be sent.
    pub async fn unsubscribe(&mut self, sub_id: &str) -> Result<(), ClientError> {
        if self.is_connected() {
            self.evict_subscription_rows(sub_id)?;
            {
                let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
                subscriptions::forget(&mut self.db, sub_id)?;
            }
            self.wire()?
                .transport
                .send_control(ControlMessage::Unsubscribe(Unsubscribe {
                    sub_id: sub_id.to_owned(),
                }))
                .await
                .map_err(|e| ClientError::Transport(e.to_string()))?;
        } else {
            let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
            subscriptions::end(&mut self.db, sub_id)?;
        }
        self.open_snapshots.remove(sub_id);
        self.resyncing.remove(sub_id);
        self.unfenced_computed.remove(sub_id);
        Ok(())
    }

    /// Read one inbound frame, apply it if it is a patch, and report what
    /// happened. Applying a bulk patch replenishes one delivery credit.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a transport, apply, or protocol failure.
    pub async fn pump_one(&mut self) -> Result<ClientEvent, ClientError> {
        loop {
            self.check_share_key_deadlines();
            self.step_share_keys().await?;
            self.check_writer_deadlines();
            if let Some(notice) = self.notices.pop_front() {
                return Ok(notice);
            }
            let frame = self.wire()?.transport.recv().await;
            let frame = self.judge(frame)?;
            if let Some(event) = self.handle_frame(frame).await? {
                return Ok(event);
            }
        }
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
        // A writer answer that overran its bound drops the connection before
        // the next frame is waited on, so the pump redials without stalling.
        self.check_writer_deadlines();
        self.check_share_key_deadlines();
        self.step_share_keys().await?;
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
        self.handle_frame(frame).await
    }

    /// Apply one received frame: bulk patches mutate the replica and advance
    /// flow control, control frames map onto their [`ClientEvent`]s, and an
    /// enrolment answer goes to its waiter with nothing to report.
    async fn handle_frame(
        &mut self,
        frame: Option<IncomingFrame>,
    ) -> Result<Option<ClientEvent>, ClientError> {
        let event = match frame {
            // A peer that closed cleanly is as gone as one that failed, so the
            // wire goes and the change is announced behind this event.
            None => {
                self.disconnected();
                ClientEvent::Closed
            }
            Some(IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch))) => {
                self.apply_patch(&patch.patchset_zstd, None, Some(&patch.sub_id))?;
                self.ack_one().await?;
                ClientEvent::SnapshotApplied {
                    sub_id: patch.sub_id,
                }
            }
            Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch))) => {
                self.apply_patch(
                    &patch.patchset_zstd,
                    Some(&patch.cursor),
                    Some(&patch.sub_id),
                )?;
                self.last_cursor = Some(patch.cursor.clone());
                self.ack_one().await?;
                ClientEvent::LivePatch {
                    sub_id: patch.sub_id,
                    cursor: patch.cursor,
                    patchset_zstd: patch.patchset_zstd.into(),
                }
            }
            Some(IncomingFrame::Bulk(_)) => {
                return Err(ClientError::Protocol(
                    "unexpected bulk frame from server".into(),
                ));
            }
            // Lists a server with device certificates pushes. A build without a
            // device identity has nothing to check them with.
            Some(IncomingFrame::Control(ControlMessage::RevocationUpdate(update))) => {
                #[cfg(feature = "device-identity")]
                self.push_revocations(update.lists);
                #[cfg(not(feature = "device-identity"))]
                drop(update);
                return Ok(None);
            }
            Some(IncomingFrame::Control(ControlMessage::TabShareKeyAnswer(answer))) => {
                self.settle_relay_share_key(answer);
                return Ok(None);
            }
            Some(IncomingFrame::Control(msg)) => {
                #[cfg(feature = "device-identity")]
                if enrolment::Answer::is_answer(&msg) {
                    if let Some((request_id, answer)) = enrolment::Answer::of(msg) {
                        self.answer_enrolment(&request_id, answer);
                    }
                    return Ok(None);
                }
                self.handle_control(msg).await?
            }
        };
        Ok(Some(event))
    }

    /// Send a lower-63-bit keepalive whose matching [`ClientEvent::Pong`] fences preceding requests.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the ping cannot be sent and
    /// [`ClientError::Protocol`] when its nonce uses the reserved high bit.
    pub async fn ping(&mut self, nonce: u64) -> Result<(), ClientError> {
        let wire = self.wire()?;
        if nonce & (1_u64 << 63) != 0 {
            return Err(ClientError::Protocol(
                "the ping nonce uses the reserved high bit".to_owned(),
            ));
        }
        wire.transport
            .send_control(ControlMessage::Ping(Ping { nonce }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// Ask the server for a content ticket naming one file and one verb.
    ///
    /// The answer arrives on a later [`pump_one`](Self::pump_one) as
    /// [`ClientEvent::ContentTicket`] carrying `request_id`, or as a refusal
    /// ([`ClientEvent::NonFatal`], [`ClientEvent::RateLimited`]) carrying it
    /// in `related_to`. The caller owns the id and its uniqueness.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the request cannot be sent, which
    /// includes having no transport at all: a ticket is the server's to grant
    /// and there is nothing to queue offline.
    pub async fn request_content_ticket(
        &mut self,
        request_id: String,
        file_id: [u8; 32],
        verb: ContentVerb,
    ) -> Result<(), ClientError> {
        self.wire()?
            .transport
            .send_control(ControlMessage::ContentTicketRequest(ContentTicketRequest {
                request_id,
                file_id,
                verb,
            }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// Commit connetto's own bookkeeping and the application's writes as one
    /// transaction, where only the second is uploaded.
    ///
    /// `bookkeeping` runs with capture suspended, so its writes to the
    /// `_connetto_` tables never enter a changeset, and `app` runs with
    /// capture live, so its writes upload as an ordinary mutation. Both are
    /// inside one SQLite transaction on one file, which is what makes a
    /// bookkeeping record and the row that depends on it survive or vanish
    /// together rather than by convention. Suspension is orthogonal to the
    /// transaction: switching the session off does not end it.
    ///
    /// The pair exists because the alternative cannot be enforced. A caller
    /// writing its own record and then the row, or handed a recorder to call
    /// inside a transaction it opens itself, has a happy path that works and
    /// a crash that leaves a row pointing at a record that was never written.
    ///
    /// Both closures return a value, so a pass whose whole result is
    /// bookkeeping (a sweep counting what it evicted) uses the same primitive
    /// as a write whose result is the application's, with `()` on the side it
    /// does not use.
    ///
    /// # Errors
    ///
    /// Whatever either closure returns, with the transaction rolled back, and
    /// [`ClientError::Session`] when the transaction itself fails.
    pub fn transact_with_bookkeeping<B, A, P, O, E>(
        &mut self,
        bookkeeping: B,
        app: A,
    ) -> Result<(P, O), E>
    where
        B: FnOnce(&mut SqliteConnection) -> Result<P, E>,
        A: FnOnce(&mut SqliteConnection) -> Result<O, E>,
        E: From<diesel::result::Error>,
    {
        // Prepared here so the closure below captures these two fields rather
        // than all of `self`, which `db` is borrowed out of for the duration.
        let session = &mut self.session;
        let exempt = &self.write_exempt;
        self.db.transaction(|conn| {
            let private = {
                let _suspended = SuspendedCapture::new(session, exempt);
                bookkeeping(conn)?
            };
            Ok((private, app(conn)?))
        })
    }

    /// Re-run the key check for a schema whose DDL moved since the last look.
    ///
    /// The capture session covers tables created after it exists, so a table
    /// the application creates mid-run would otherwise lose every write to it
    /// until the next restart. The gate is one integer read per schema, and
    /// the tier is read too even though nothing there uploads, because a tier
    /// table nobody records is invisible to every sibling browser tab (R62
    /// decisions 1 and 4).
    fn recheck_changed_schemas(&mut self) -> Result<(), ClientError> {
        let main = schema_cookie(&mut self.db, "main")?;
        if main != self.main_schema {
            check_recorded_tables(&mut self.db, "main", &self.config.unrecorded_tables)?;
            self.main_schema = main;
        }
        if let Some(seen) = self.tier_schema {
            let tier = schema_cookie(&mut self.db, LOCAL_SCHEMA)?;
            if tier != seen {
                check_recorded_tables(&mut self.db, LOCAL_SCHEMA, &self.config.unrecorded_tables)?;
                self.tier_schema = Some(tier);
            }
        }
        Ok(())
    }

    /// Upload local writes captured since the last push as one mutation
    /// under the writer this run writes as.
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
    /// [`ClientError`] on a session, compression, or transport failure, and
    /// [`ClientError::WritesNotRecorded`] when the application created a table
    /// connetto cannot record changes to since the last write.
    pub async fn push(&mut self) -> Result<Option<u64>, ClientError> {
        self.recheck_changed_schemas()?;
        let changeset = self
            .session
            .changeset()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        if changeset.is_empty() {
            return Ok(None);
        }
        let writer = self.choose_writer();
        let seq = self.append_entry(&writer, &changeset, None)?;
        // Reset capture: a fresh session records only writes after this push.
        let mut fresh = self
            .db
            .create_session()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        fresh
            .attach_all()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        self.session = fresh;
        // With no server the write stays queued, which is the designed offline
        // state rather than a failure: it is already durable in
        // `_connetto_pending` above, and `attach` replays it. Returning an
        // error here would make every caller treat working offline as a fault.
        // A caller that needs to know asks `unsynced`, or reads the
        // connection-state event. A write under a writer the connection is
        // not bound to waits for the connection to bind it, the replay sends
        // it then.
        if self.is_connected() && self.bound_writer == Some(writer) {
            self.send_mutation(writer, seq, &changeset, None).await?;
        }
        Ok(Some(seq))
    }

    /// The writer a new local write queues under: the enrolled device's key
    /// when the device holds a certificate a completed retirement has not
    /// excluded, the number otherwise, the unissued one until the server
    /// issues it.
    fn choose_writer(&mut self) -> WriterRef {
        #[cfg(feature = "device-identity")]
        if let Ok(Some(held)) = self.device_certificate() {
            let key_id = *held.leaf.identity().key().as_bytes();
            if !self.retired_keys.contains(&key_id) {
                return WriterRef::Device(key_id);
            }
        }
        match self.number_identity() {
            Some(number) => WriterRef::Number(number),
            None => unissued(),
        }
    }

    /// Send one mutation as its header and patchset frame pair, as `writer`'s
    /// sequence `seq`. Shared by [`push`](Self::push) and the replay in
    /// [`replay_pending`](Self::replay_pending).
    ///
    /// This is the one place a captured changeset leaves for the server, so it
    /// is where a split table's backing name goes back to the logical Postgres
    /// name the wire speaks. The durable pending record keeps the physical
    /// names it was captured under, because that is what a rollback has to
    /// apply locally, and a replay renames again on its way out.
    async fn send_mutation(
        &mut self,
        writer: WriterRef,
        seq: u64,
        changeset: &[u8],
        provenance: Option<&Provenance>,
    ) -> Result<(), ClientError> {
        if self.bound_writer != Some(writer) {
            return Err(ClientError::Protocol(
                "a mutation left for a writer the connection is not bound to".to_owned(),
            ));
        }
        let logical = self.to_logical(changeset.to_vec())?;
        let op_count = count_ops(&logical);
        let payload = zstd::encode_all(logical.as_slice(), ZSTD_LEVEL)?;
        let mut header = MutationHeader::new(seq, op_count);
        if let Some(provenance) = provenance {
            header = header.with_provenance(*provenance);
        }
        self.wire()?
            .transport
            .send_control(ControlMessage::MutationHeader(header))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        self.wire()?
            .transport
            .send_bulk(BulkMessage::MutationPatch(MutationPatch::new(seq, payload)))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        Ok(())
    }

    /// Roll back the optimistic local write for `writer`'s `client_seq` after
    /// the server rejected or conflicted it: decode the touched rows for the
    /// event, invert the captured changeset, and apply the inverse with
    /// capture suspended, so the rollback is never re-uploaded. A row a
    /// concurrent server patch already changed is left alone. Returns the
    /// touched rows, empty when the changeset is gone.
    fn rollback(
        &mut self,
        writer: WriterRef,
        client_seq: u64,
    ) -> Result<Vec<AffectedRow>, ClientError> {
        let Some(queue) = self.writers.get_mut(&writer) else {
            return Ok(Vec::new());
        };
        let Some(entry) = queue.pending.remove(&client_seq) else {
            return Ok(Vec::new());
        };
        let changeset = entry.changeset;
        let rows = affected_rows(&changeset, &self.config.policy_tables)?;
        let inverse = invert_changeset(&changeset)
            .map_err(|err| ClientError::Apply(format!("inverting rejected changeset: {err}")))?;
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        delete_pending(&mut self.db, &writer, client_seq)?;
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
        let mut named = self.take_changed_unfiltered();
        // R27 decisions 4 and 7: a membership table served by a hidden
        // subscription stays out of the application-facing signal,
        // unconditionally, even when the application also subscribed to it.
        named.retain(|name| !self.hidden_tables.contains(&name.to_lowercase()));
        named
    }

    /// Answer the caller and subjects functions with a relay's worker's
    /// values, and mark every table changed so each live query re-reads
    /// through the views they filter.
    fn adopt_relay_identity(&mut self, identity: TabIdentity) -> Result<(), ClientError> {
        register_caller(
            &mut self.db,
            connetto_core::CALLER_FUNCTION,
            identity
                .caller
                .unwrap_or_else(|| connetto_core::auth::absent_marker().to_owned()),
        )?;
        register_subjects(&mut self.db, SUBJECTS_FUNCTION, identity.subjects)?;
        let tables: Vec<String> = sqlite_catalog::table
            .select(sqlite_catalog::name)
            .filter(sqlite_catalog::kind.eq_any(["table", "view"]))
            .load(&mut self.db)?;
        self.changed
            .lock()
            .expect("the changed-tables lock")
            .extend(tables);
        Ok(())
    }

    /// [`take_changed`](Self::take_changed) without the hidden-table filter,
    /// for the live-query refresh: a query narrowed through a membership
    /// still has to re-run when the membership moves (R27).
    pub(crate) fn take_changed_unfiltered(&mut self) -> Vec<String> {
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

    fn refuse_declaration(&mut self, related_to: Option<&str>) {
        if let (Some(related_to), Some(fence)) = (related_to, &mut self.declaration_fence) {
            fence.sub_ids.retain(|sub_id| sub_id != related_to);
        }
    }

    /// A server throttle, deferring the pending write it names.
    fn rate_limited(&mut self, limited: connetto_core::messages::RateLimited) -> ClientEvent {
        self.refuse_declaration(limited.related_to.as_deref());
        // A mutation is correlated by its sequence, and one still pending waits for its resend.
        let throttled_write = limited
            .related_to
            .as_deref()
            .and_then(|related| related.parse::<u64>().ok())
            .is_some_and(|seq| {
                self.writers
                    .values()
                    .any(|queue| queue.pending.contains_key(&seq))
            });
        if throttled_write {
            self.defer_pending(Some(Duration::from_millis(limited.retry_after_ms)));
        }
        // A swap its limit refused is deferred by the server's bound, not
        // dropped.
        if limited.related_to.as_deref().is_some_and(|related| {
            self.share_key_request
                .as_ref()
                .is_some_and(|request| request.request_id == related)
        }) {
            self.share_key_request = None;
            self.share_key_retry_at = Some(
                crate::away::SystemClock.monotonic()
                    + Duration::from_millis(limited.retry_after_ms),
            );
            self.recompute_share_key_deadline();
        }
        ClientEvent::RateLimited {
            related_to: limited.related_to,
            retry_after_ms: limited.retry_after_ms,
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Each control frame has one explicit protocol dispatch arm."
    )]
    async fn handle_control(&mut self, msg: ControlMessage) -> Result<ClientEvent, ClientError> {
        match msg {
            ControlMessage::SnapshotBegin(begin) => {
                self.open_snapshots.insert(begin.sub_id.clone());
                Ok(ClientEvent::SnapshotBegin {
                    sub_id: begin.sub_id,
                })
            }
            ControlMessage::SnapshotEnd(end) => {
                // This records a resume position for rows delivered on the
                // other plane, so it depends on the server having sent them
                // first: see the invariant on `persist_cursor`.
                //
                // An empty cursor carries no resume information: never let
                // it regress a real one, in memory or in the replica.
                if !end.cursor.is_empty() {
                    let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
                    let coverage = self.cursor_subjects.as_deref();
                    persist_cursor_and_subjects(&mut self.db, &end.cursor, coverage)?;
                    self.last_cursor = Some(end.cursor);
                }
                self.open_snapshots.remove(&end.sub_id);
                if self.resyncing.remove(&end.sub_id) {
                    self.reapply_pending()?;
                }
                self.publish_coverage()?;
                Ok(ClientEvent::SnapshotEnd { sub_id: end.sub_id })
            }
            ControlMessage::AggregateUpdate(update) => {
                // Resting is a durable consequence of receiving a server frame,
                // the same class as the cursor and patch writes above, so it
                // happens here on the one frame-application path every pump
                // driver shares, not in a driver's own loop (R83).
                self.rest_aggregate(
                    &update.sub_id,
                    &aggregates::AggregateFrame {
                        group_key: update.group_key.as_deref(),
                        group_values_json: update.group_values_json.as_deref(),
                        result_json: update.result_json.as_deref(),
                        is_full_result: update.is_full_result,
                    },
                )?;
                Ok(ClientEvent::Aggregate {
                    sub_id: update.sub_id,
                    result_json: update.result_json,
                    group_key: update.group_key,
                    group_values_json: update.group_values_json,
                    is_full_result: update.is_full_result,
                })
            }
            ControlMessage::FullResyncRequired(resync) => {
                if resync.reason == FullResyncReason::AuthorizationChange {
                    // The swap re-renders the coverage, so the durable claim
                    // is unknown again before the clear runs.
                    self.invalidate_coverage()?;
                }
                let aggregate = self.clear_subscription_rows(&resync.sub_id, &resync.reason)?;
                // The replacement snapshot lands after this, so the pending writes
                // this clear took off the replica go back on its `SnapshotEnd`, not
                // now: a snapshot row under `server_wins` would take a local edit off
                // screen (R48 decision 3). An aggregate names no snapshot.
                if !aggregate {
                    self.resyncing.insert(resync.sub_id.clone());
                }
                Ok(ClientEvent::FullResync {
                    sub_id: resync.sub_id,
                    reason: resync.reason,
                })
            }
            ControlMessage::MutationApplied(ack) => self.mutation_applied(ack.client_seq).await,
            ControlMessage::MutationReject(reject) => self.mutation_rejected(&reject).await,
            ControlMessage::MutationConflict(conflict) => {
                self.settle_resend();
                let writer = self
                    .bound_writer
                    .expect("a conflict arrives for the bound writer");
                let rows = self.rollback(writer, conflict.client_seq)?;
                #[cfg(feature = "device-identity")]
                self.finish_number_tail().await?;
                Ok(ClientEvent::MutationConflict {
                    client_seq: conflict.client_seq,
                    rows,
                    server_row: conflict.server_row,
                })
            }
            ControlMessage::WriterAnswer(answer) => self.settle_writer_task(&answer).await,
            ControlMessage::Pong(pong) => {
                let fence = if self
                    .declaration_fence
                    .as_ref()
                    .is_some_and(|fence| fence.nonce == pong.nonce)
                {
                    self.declaration_fence.take()
                } else {
                    None
                };
                if let Some(fence) = fence {
                    // Refused declarations remain outstanding after this fence.
                    self.unfenced_count = self.unfenced_count.saturating_sub(fence.count);
                    self.unfenced_computed
                        .retain(|sub_id| !fence.sub_ids.contains(sub_id));
                    self.recompute_share_key_deadline();
                    self.publish_coverage()?;
                }
                Ok(ClientEvent::Pong { nonce: pong.nonce })
            }
            ControlMessage::ContentTicketGrant(grant) => Ok(ClientEvent::ContentTicket {
                request_id: grant.request_id,
                url: grant.url,
            }),
            ControlMessage::NonFatalError(err) => {
                self.refuse_declaration(err.related_to.as_deref());
                Ok(ClientEvent::NonFatal {
                    related_to: err.related_to,
                    detail: err.detail,
                })
            }
            ControlMessage::RateLimited(limited) => Ok(self.rate_limited(limited)),
            // A relay saying whether IT can reach the server. For a tab that is
            // the answer that matters, because a tab whose own link is fine
            // still cannot sync while the relay cannot, so it rides the same
            // event as this connection's own state.
            ControlMessage::SyncStatus(status) => Ok(ClientEvent::SyncStatus(status)),
            // A relay stating the worker's gate state. For a tab that is the
            // answer its application acts on, so it rides the same event as
            // the client's own gate.
            ControlMessage::GateState(state) => Ok(match state {
                GateState::Locked => ClientEvent::Locked,
                GateState::Unlocked => ClientEvent::Unlocked,
                GateState::UnlockDismissed => ClientEvent::UnlockDismissed,
            }),
            // A relay stating who its worker is. The tab's mirror runs the
            // worker's translated schema, whose views filter on both values.
            ControlMessage::TabIdentity(identity) => {
                self.adopt_relay_identity(identity)?;
                Ok(ClientEvent::IdentityStated)
            }
            // The server says why it is closing. Surfaced rather than treated
            // as a violation: the server behaved exactly as the protocol says.
            ControlMessage::FatalError(fatal) => self.server_closed(fatal.reason),
            ControlMessage::DeliveryPaused { cause } => Ok(ClientEvent::DeliveryPaused { cause }),
            ControlMessage::DeliveryResumed => Ok(ClientEvent::DeliveryResumed),
            ControlMessage::MembershipOpened(opened) => {
                // R27 decisions 3, 4 and 7: the server opened a membership
                // subscription on this client's behalf. Its data frames apply
                // like any other subscription's, while the table stays out of
                // the application-facing changed-tables signal. The server
                // owns its lifecycle, so nothing is declared or re-declared
                // here.
                self.hidden_tables
                    .insert(opened.member_table.to_lowercase());
                Ok(ClientEvent::MembershipOpened {
                    sub_id: opened.sub_id,
                    member_table: opened.member_table,
                })
            }
            ControlMessage::ShareKeysReplaced(ack) => {
                self.settle_share_key_replacement(&ack.request_id)?;
                Ok(ClientEvent::ShareKeysReplaced {
                    request_id: ack.request_id,
                })
            }
            other => Err(ClientError::Protocol(format!(
                "unexpected control frame from server: {other:?}"
            ))),
        }
    }

    /// Apply the writer-state change a writer fatal carries, then surface the
    /// close, the pump redialing under the fresh writer.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when a device retirement cannot be made durable; the
    /// queues then stand as they did before the transition.
    fn server_closed(&mut self, reason: FatalErrorReason) -> Result<ClientEvent, ClientError> {
        match reason {
            FatalErrorReason::WriterRetired | FatalErrorReason::WriterUnknown => {
                match self.bound_writer {
                    Some(WriterRef::Device(_)) => {
                        // The device's writer is gone, so its tails travel
                        // under a number, the key is excluded before the
                        // cleanup runs, and a fresh key enrols.
                        self.retire_device()?;
                    }
                    Some(writer) => {
                        // A number died, so its tail travels to the live
                        // writer, the key untouched.
                        self.carry_to_live(writer);
                    }
                    None => {}
                }
            }
            FatalErrorReason::DeviceRevoked => {
                self.exclude_device_writers()?;
            }
            _ => {}
        }
        Ok(ClientEvent::ServerClosed { reason })
    }

    /// Retire an entry the server applied durably, under the bound writer.
    #[cfg_attr(
        not(feature = "device-identity"),
        expect(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "the device build awaits the number's bind release here"
        )
    )]
    async fn mutation_applied(&mut self, client_seq: u64) -> Result<ClientEvent, ClientError> {
        let writer = self.bound_writer;
        if let Some(writer) = writer {
            let removed = self
                .writers
                .get_mut(&writer)
                .and_then(|queue| queue.pending.remove(&client_seq))
                .is_some();
            if removed {
                let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
                delete_pending(&mut self.db, &writer, client_seq)?;
            }
        }
        self.settle_resend();
        #[cfg(feature = "device-identity")]
        self.finish_number_tail().await?;
        Ok(ClientEvent::MutationApplied { client_seq })
    }

    /// Roll back an entry the server refused, or keep it for a resend when the
    /// server could not settle it, under the bound writer.
    #[cfg_attr(
        not(feature = "device-identity"),
        expect(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "the device build awaits the number's bind release here"
        )
    )]
    async fn mutation_rejected(
        &mut self,
        reject: &MutationReject,
    ) -> Result<ClientEvent, ClientError> {
        let client_seq = reject.client_seq;
        let writer = self.bound_writer;
        // Rolling back a write the server could not settle would lose it for good.
        if reject.reason == MutationRejectReason::Indeterminate {
            let held = writer
                .and_then(|writer| {
                    self.writers
                        .get(&writer)
                        .map(|queue| queue.pending.contains_key(&client_seq))
                })
                .unwrap_or(false);
            if held {
                self.defer_pending(None);
            }
            return Ok(ClientEvent::MutationDeferred { client_seq });
        }
        self.settle_resend();
        let rows = match writer {
            Some(writer) => self.rollback(writer, client_seq)?,
            None => Vec::new(),
        };
        #[cfg(feature = "device-identity")]
        self.finish_number_tail().await?;
        Ok(ClientEvent::MutationRejected {
            client_seq,
            reason: reject.reason.clone(),
            rows,
        })
    }

    /// The server gave a resent write a final answer, so whatever deferred it has passed and the next deferral starts its schedule afresh.
    fn settle_resend(&mut self) {
        if matches!(self.resend, Resend::Resent { .. }) {
            self.resend = Resend::Idle;
        }
    }

    /// Drop the replica rows a full-resync snapshot will replace, or, for a
    /// named aggregate, its whole resting answer (R95). Returns whether the
    /// notice named an aggregate, so the caller keeps its label out of
    /// `resyncing`.
    fn clear_subscription_rows(
        &mut self,
        sub_id: &str,
        reason: &FullResyncReason,
    ) -> Result<bool, ClientError> {
        let declared = subscriptions::declared(&mut self.db)?;
        let beyond_history = *reason == FullResyncReason::CursorBeyondHistory;
        // A hidden membership subscription has no declared record to take its tables from.
        let membership = sub_id
            .strip_prefix(MEMBERSHIP_LABEL_PREFIX)
            .filter(|_| beyond_history)
            .map(str::to_lowercase);
        // Every row subscription resyncs, so the first notice empties all their tables and later ones spare fresh replacements.
        if beyond_history && !self.history_cleared {
            self.history_cleared = true;
            let mut scope: HashSet<String> = membership.into_iter().collect();
            for record in &declared {
                if let Some(coverage) = crate::live::coverage_of(&record.spec)? {
                    scope.extend(coverage.tables);
                }
            }
            self.delete_uncovered(&scope, None, &Stale::Everything, &HashMap::new())?;
            return Ok(false);
        }
        if let Some(table) = membership {
            let scope = HashSet::from([table]);
            self.delete_uncovered(&scope, None, &Stale::Nothing, &HashMap::new())?;
            return Ok(false);
        }
        let Some(record) = declared.iter().find(|record| record.sub_id == sub_id) else {
            return Ok(false);
        };
        match crate::live::coverage_of(&record.spec)? {
            // A named aggregate has no replica rows to clear.
            None => {
                self.clear_aggregate_resting(sub_id)?;
                Ok(true)
            }
            Some(mut resyncing) => {
                if *reason == FullResyncReason::AuthorizationChange
                    && let Some(cleared) = &self.authorization_cleared
                {
                    resyncing.tables.retain(|table| !cleared.contains(table));
                    self.delete_uncovered(
                        &resyncing.tables,
                        None,
                        &Stale::Everything,
                        &HashMap::new(),
                    )?;
                    self.authorization_cleared
                        .as_mut()
                        .expect("an authorization batch is active")
                        .extend(resyncing.tables);
                    return Ok(false);
                }
                let stale = match reason {
                    // Compared case-insensitively because the server names it from the
                    // catalog and a subscription names it as its query spelled it.
                    FullResyncReason::TableTruncated { table } => {
                        Stale::Table(table.to_lowercase())
                    }
                    FullResyncReason::CursorOutsideRetention
                    | FullResyncReason::AuthorizationChange
                    | FullResyncReason::SnapshotInterrupted
                    | FullResyncReason::CursorBeyondHistory => Stale::Nothing,
                };
                self.delete_uncovered(&resyncing.tables, Some(sub_id), &stale, &HashMap::new())?;
                Ok(false)
            }
        }
    }

    /// Drop every row of the aggregate `sub_id` names, under the query identity
    /// its frames rest under (R95). A notice with no subscription on record
    /// clears nothing.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] when the replica cannot be read or written.
    fn clear_aggregate_resting(&mut self, sub_id: &str) -> Result<(), ClientError> {
        let Some((query_id, binds)) = subscriptions::identity_of(&mut self.db, sub_id)? else {
            return Ok(());
        };
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        aggregates::clear(&mut self.db, query_id, &binds)?;
        Ok(())
    }

    /// The complement-of-union delete a resync clear and an eviction run share.
    ///
    /// Over the `scope` tables, delete every row no live subscription other than
    /// `exclude` still covers. A subscription is never named: it stops
    /// contributing a clause, so a row another subscription still wants matches
    /// that clause and survives, and a table no survivor claims takes the whole
    /// delete. `spare` holds extra keep-clauses per physical table (the eviction
    /// pass passes its pending-write keys, a resync passes none). `stale` names
    /// the tables that delete whole regardless of a survivor's filter, because
    /// their every row may be gone upstream (R48, R73). Returns the rows removed.
    ///
    /// Capture is suspended so the deletes are never re-uploaded as a local
    /// mutation.
    fn delete_uncovered(
        &mut self,
        scope: &HashSet<String>,
        exclude: Option<&str>,
        stale: &Stale,
        spare: &HashMap<String, Vec<String>>,
    ) -> Result<usize, ClientError> {
        // Every surviving subscription's claim on the scoped tables, as SQL. A
        // survivor with no predicate wants the whole table, so nothing there may
        // go. A subscription past its grace no longer wants anything.
        let declared = subscriptions::declared(&mut self.db)?;
        let mut clauses: HashMap<&str, Vec<String>> = HashMap::new();
        let mut untouchable: HashSet<&str> = HashSet::new();
        for record in &declared {
            if exclude == Some(record.sub_id.as_str()) || !record.live {
                continue;
            }
            let Some(coverage) = crate::live::coverage_of(&record.spec)? else {
                continue;
            };
            for table in scope.iter().filter(|t| coverage.tables.contains(*t)) {
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

        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        let tables = self.config.policy_tables.clone();
        self.db.transaction::<_, ClientError, _>(|conn| {
            let mut removed = 0usize;
            for table in scope {
                let truncated = stale.covers(table);
                if untouchable.contains(table.as_str()) && !truncated {
                    continue;
                }
                // A split table is cleared at its backing table, not through the
                // policy view: the view yields only rows the local policy admits,
                // so deleting through it would strand every row the policy hides.
                // The predicates name plain columns of the logical table and the
                // backing table carries the same columns in the same order.
                let target = tables.physical(table).unwrap_or(table);
                let quoted = quote_ident(target);
                // Survivor predicates plus any spared pending-write keys: a row
                // matching any of them stays. A truncate ignores both, since
                // every row of an emptied table is stale.
                let mut kept: Vec<String> = Vec::new();
                if !truncated {
                    if let Some(surviving) = clauses.get(table.as_str()) {
                        kept.extend(surviving.iter().map(|clause| format!("({clause})")));
                    }
                    if let Some(spared) = spare.get(&target.to_lowercase()) {
                        kept.extend(spared.iter().cloned());
                    }
                }
                // The table and the predicates are chosen at runtime from the
                // subscriptions' own parsed queries, so diesel's compile-time
                // DSL cannot name them: this is the one raw statement here.
                let statement = if kept.is_empty() {
                    format!("DELETE FROM {quoted}")
                } else {
                    format!("DELETE FROM {quoted} WHERE NOT ({})", kept.join(" OR "))
                };
                removed += diesel::sql_query(statement).execute(conn)?;
            }
            Ok(removed)
        })
    }

    /// The pending, un-acknowledged writes as per-table primary-key match
    /// clauses, so the eviction pass spares a row this client has written but
    /// not yet had the server acknowledge.
    ///
    /// Keyed by the lowercased physical table the delete runs against, each
    /// value a list of `(col IS literal AND ...)` clauses. Decoded from
    /// `self.pending` the same way [`affected_rows`] reads a changeset's touched
    /// keys, so the protection is bounded by the queue's cap and clears itself
    /// when an ack retires the mutation. A captured mutation is a changeset,
    /// whose op carries the backing table's own schema, so the primary-key
    /// columns and ordinals come straight from it.
    fn pending_spare(&mut self) -> Result<HashMap<String, Vec<String>>, ClientError> {
        let mut spare: HashMap<String, Vec<String>> = HashMap::new();
        let changesets: Vec<Vec<u8>> = self
            .writers
            .values()
            .flat_map(|queue| queue.pending.values())
            .map(|entry| entry.changeset.clone())
            .collect();
        for changeset in &changesets {
            let ParsedDiffSet::Changeset(diff) =
                ParsedDiffSet::parse(changeset).map_err(|err| {
                    ClientError::Apply(format!("parsing a pending changeset: {err:?}"))
                })?
            else {
                continue;
            };
            for op in diff.iter() {
                let table = op.table();
                let physical = table.name().to_lowercase();
                let columns = replica_columns(&mut self.db, &physical)?;
                let ordinals = pk_ordinals(table);
                let pk = op.primary_key();
                let mut wheres = Vec::with_capacity(ordinals.len());
                let mut complete = !ordinals.is_empty();
                for (position, value) in ordinals.into_iter().zip(&pk) {
                    let Some(column) = columns.get(position) else {
                        complete = false;
                        break;
                    };
                    wheres.push(format!(
                        "{} IS {}",
                        quote_ident(column),
                        crate::live::bind_literal_of(value)?
                    ));
                }
                if complete {
                    spare
                        .entry(physical)
                        .or_default()
                        .push(format!("({})", wheres.join(" AND ")));
                }
            }
        }
        Ok(spare)
    }

    /// Return freelist pages to the filesystem: reclaim in
    /// bounded `incremental_vacuum` steps once the freelist is a large enough
    /// fraction of the file (D1), then truncate the write-ahead log so the pages
    /// leave the file rather than reappearing inside a grown WAL.
    ///
    /// Self-gates on the freelist ratio, so calling it after a pass that freed
    /// little costs two pragma reads. Runs outside any transaction, since
    /// `wal_checkpoint` fails inside one. A checkpoint a reader blocks reports
    /// busy and is left for the next pass rather than spun on.
    fn trim_replica(&mut self) -> Result<(), ClientError> {
        let total = self.db.page_count(None)?;
        if total == 0 {
            return Ok(());
        }
        let free = self.db.freelist_count(None)?;
        if free.saturating_mul(100)
            < i64::from(self.config.tuning.trim_threshold()).saturating_mul(total)
        {
            return Ok(());
        }
        // Each call frees up to the budget and runs to completion for that
        // bound, so a large freelist drains over several calls without one
        // stalling step. Stop when the freelist stops shrinking, which also ends
        // the loop if a page cannot be reclaimed.
        let budget = self.config.tuning.trim_budget();
        loop {
            let before = self.db.freelist_count(None)?;
            if before == 0 {
                break;
            }
            self.db
                .incremental_vacuum(None, (budget > 0).then_some(budget))?;
            let after = self.db.freelist_count(None)?;
            if after >= before {
                break;
            }
        }
        // Move the reclaimed pages out of the WAL and shrink it to zero so the
        // file actually contracts. Busy means a reader held it, which the next
        // pass retries, so it is not treated as an error here.
        let _ = self.db.wal_checkpoint(None, WalCheckpointMode::Truncate)?;
        Ok(())
    }

    /// Evict the replica rows of a subscription that has ended, sparing every
    /// row a surviving subscription still covers and every row a pending write
    /// awaits an ack for, then trim the pages the delete freed.
    ///
    /// The transport-down guard lives here: a row discarded offline could not be
    /// re-fetched, so the pass is a no-op until connectivity returns, and the
    /// ended record is left in place for the next connected pass (D3).
    pub(crate) fn evict_subscription_rows(&mut self, sub_id: &str) -> Result<(), ClientError> {
        if !self.is_connected() {
            return Ok(());
        }
        let declared = subscriptions::declared(&mut self.db)?;
        let Some(coverage) = declared
            .iter()
            .find(|record| record.sub_id == sub_id)
            .and_then(|record| crate::live::coverage_of(&record.spec).transpose())
            .transpose()?
        else {
            return Ok(());
        };
        let spare = self.pending_spare()?;
        let removed =
            self.delete_uncovered(&coverage.tables, Some(sub_id), &Stale::Nothing, &spare)?;
        if removed > 0 {
            self.trim_replica()?;
        }
        Ok(())
    }

    /// The callable free-up-space pass: evict every uncovered row across every
    /// table any declared subscription names, then trim the freelist.
    ///
    /// The trim runs whether or not the eviction removed a row, so pages an
    /// application freed by deleting covered rows are returned to the filesystem
    /// too, not only pages an eviction freed. The trim keeps its own ratio gate,
    /// reclaiming only once the freelist is a large enough fraction of the file.
    ///
    /// Only the eviction waits on the transport, because a row discarded offline
    /// cannot be re-fetched. Trimming discards nothing and reclaims local pages,
    /// so it runs whether or not a server is reachable. Every pending write is
    /// spared.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a replica read or write failure.
    pub fn tidy(&mut self) -> Result<(), ClientError> {
        if self.is_connected() {
            let declared = subscriptions::declared(&mut self.db)?;
            let mut scope: HashSet<String> = HashSet::new();
            for record in &declared {
                if let Some(coverage) = crate::live::coverage_of(&record.spec)? {
                    scope.extend(coverage.tables);
                }
            }
            let spare = self.pending_spare()?;
            self.delete_uncovered(&scope, None, &Stale::Nothing, &spare)?;
        }
        self.trim_replica()?;
        // The pass is the residual measure's reset point (R60 decision 4):
        // counters cleared, crossing event re-armed.
        if let Ok(mut counts) = self.applied_rows.lock() {
            counts.clear();
        }
        self.residual_warned = false;
        Ok(())
    }

    /// The accumulation measure (R60 decision 4): rows applied per table
    /// since the last `tidy`, and the freelist's share of the file the trim
    /// gate reads. Queryable at any time; [`ClientEvent::TidyDue`] fires when
    /// the row sum crosses the configured threshold.
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the replica's page statistics cannot be read.
    pub fn residual_pressure(&mut self) -> Result<ResidualPressure, ClientError> {
        let mut rows_applied: Vec<(String, u64)> = self.applied_rows.lock().map_or_else(
            |_| Vec::new(),
            |counts| counts.iter().map(|(t, n)| (t.clone(), *n)).collect(),
        );
        rows_applied.sort();
        let total = self.db.page_count(None)?;
        let free = self.db.freelist_count(None)?;
        let freelist_percent = if total > 0 {
            u8::try_from(free.saturating_mul(100) / total).unwrap_or(100)
        } else {
            0
        };
        Ok(ResidualPressure {
            rows_applied,
            freelist_percent,
        })
    }

    /// Put this replica's own unacknowledged writes back after a replacement
    /// snapshot has landed, in append-position order across every writer.
    ///
    /// **The clear ahead of a resync deletes rows the server has never seen.**
    /// A local insert that is still queued lives in the replica and in
    /// `_connetto_pending`, and the replacement snapshot cannot carry it back
    /// because the server does not have it yet, so without this the user watches
    /// their own unsaved work vanish and it returns only if and when the write is
    /// acknowledged. This is R15's un-acked rule, which until R48 was written
    /// down and not enforced.
    ///
    /// **After the snapshot ends rather than right after the clear**, or a
    /// snapshot row for the same key lands on top under `server_wins` and takes
    /// the local edit off the screen again. An emptied table's snapshot is empty
    /// so the order would not show there, which is exactly why this belongs on
    /// the resync path rather than on the truncate branch (R48 decision 3), where
    /// it also repairs the same loss under `CursorOutsideRetention` and
    /// `AuthorizationChange`.
    ///
    /// A queued update or delete whose row the resync did not restore applies to
    /// nothing and is omitted, which is correct: there is no row left to change,
    /// and the server refuses the upload for the same reason. Capture stays
    /// suspended so re-applying does not queue the writes a second time.
    fn reapply_pending(&mut self) -> Result<(), ClientError> {
        let mut queued: Vec<(u64, Vec<u8>)> = self
            .writers
            .values()
            .flat_map(|queue| queue.pending.values())
            .map(|entry| (entry.position, entry.changeset.clone()))
            .collect();
        queued.sort_unstable_by_key(|(position, _)| *position);
        let queued: Vec<Vec<u8>> = queued.into_iter().map(|(_, changeset)| changeset).collect();
        if queued.is_empty() {
            return Ok(());
        }
        let _suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        self.db.transaction::<_, ClientError, _>(|conn| {
            for changeset in &queued {
                conn.apply_changeset(changeset, server_wins)
                    .map_err(|err| ClientError::Apply(err.to_string()))?;
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
        let suspended = SuspendedCapture::new(&mut self.session, &self.write_exempt);
        // The counting gate makes the update hook tally each row into
        // `apply_staging` (R60 decision 4). Cleared before any error propagates
        // so a failed apply never leaves the gate up. The staging map merges
        // into `applied_rows` only after the transaction commits and is cleared
        // on rollback, so a failed apply leaves no phantom counts.
        self.apply_counting.store(true, Ordering::Relaxed);
        // The coverage the cursor carries, materialized before the closure so
        // the pair writes in the same statement as the cursor.
        let coverage = self.cursor_subjects.as_deref();
        let shared = &self.config.shared_tables;
        let applied = self.db.transaction::<_, ClientError, _>(|conn| {
            // The cursor advances even when every op was withheld. A departure
            // this replica declined to act on is still an event it has seen,
            // and not recording it would replay the same decision for ever.
            if let Some(bytes) = apply.as_deref() {
                conn.apply_patchset(bytes, server_wins)
                    .map_err(|e| ClientError::Apply(e.to_string()))?;
                // The native apply reaches `main` only.
                if !shared.is_empty() {
                    shared_replay::apply(conn, bytes, shared)?;
                }
            }
            if let Some(cursor) = cursor {
                persist_cursor_and_subjects(conn, cursor, coverage)?;
            }
            Ok(())
        });
        self.apply_counting.store(false, Ordering::Relaxed);
        drop(suspended);
        if applied.is_ok() {
            if let (Ok(mut stage), Ok(mut rows)) =
                (self.apply_staging.lock(), self.applied_rows.lock())
            {
                for (table, n) in stage.drain() {
                    *rows.entry(table).or_insert(0) += n;
                }
            }
        } else if let Ok(mut stage) = self.apply_staging.lock() {
            stage.clear();
        }
        applied?;
        self.residual_check()
    }

    /// After a server patch lands: run the pass under
    /// [`ResidualPass::Automatic`] when the applied-rows sum crosses the
    /// configured threshold, then fire [`ClientEvent::TidyDue`], once per
    /// crossing (R60 decision 3). A failed automatic pass queues nothing and
    /// re-arms, so the event never claims a pass that did not happen and the
    /// next apply retries. `tidy` resets the measure and re-arms the event,
    /// whoever calls it.
    fn residual_check(&mut self) -> Result<(), ClientError> {
        if self.residual_warned {
            return Ok(());
        }
        let total: u64 = self
            .applied_rows
            .lock()
            .map_or(0, |counts| counts.values().sum());
        if total < self.config.tuning.residual_threshold() {
            return Ok(());
        }
        self.residual_warned = true;
        if self.config.tuning.residual_pass() == ResidualPass::Automatic
            && let Err(err) = self.tidy()
        {
            self.residual_warned = false;
            return Err(err);
        }
        self.notices.push_back(ClientEvent::TidyDue {
            rows_applied: total,
        });
        Ok(())
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

    /// The canonical bytes the queue chain hashes a payload under, the
    /// logical table names the wire uploads. A payload no split table
    /// touches borrows its captured bytes, only the split path re-encodes.
    fn logical_for<'a>(&'a self, changeset: &'a [u8]) -> Result<Cow<'a, [u8]>, ClientError> {
        let tables = &self.config.policy_tables;
        if tables.is_empty() {
            return Ok(Cow::Borrowed(changeset));
        }
        let mut parsed = ParsedDiffSet::parse(changeset)
            .map_err(|err| ClientError::Apply(format!("parsing a diffset to hash it: {err:?}")))?;
        let rename = |name: &str| tables.logical(name).map(str::to_owned);
        if parsed.rename_tables(rename) == 0 {
            return Ok(Cow::Borrowed(changeset));
        }
        Ok(Cow::Owned(parsed.into()))
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
/// auto-submitted by the driver. `establish` is unsupported, since a client
/// builder owns the transport and handshake, and diesel's query methods never
/// call `establish`.
impl<T: Transport + Send> Connection for ConnettoConnection<T> {
    type Backend = Sqlite;
    type TransactionManager = AnsiTransactionManager;

    fn establish(_database_url: &str) -> ConnectionResult<Self> {
        Err(ConnectionError::BadConnection(
            "ConnettoConnection is built with a client builder, not establish".to_owned(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use connetto_core::test_support::FakeTransport;

    const DDL: &str = "CREATE TABLE t (id INTEGER PRIMARY KEY)";

    #[test]
    fn writer_id_round_trips_through_writer_from_id() {
        let device = [0xab; 32];
        let spelled = writer_id(&WriterRef::Device(device));
        assert_eq!(spelled, format!("device:{}", "ab".repeat(32)));
        assert_eq!(writer_from_id(&spelled), Some(WriterRef::Device(device)));
        assert_eq!(
            writer_from_id(&writer_id(&WriterRef::Number(7))),
            Some(WriterRef::Number(7))
        );
    }

    #[test]
    fn writer_from_id_refuses_ids_it_cannot_parse() {
        assert_eq!(writer_from_id("garbage"), None);
        assert_eq!(writer_from_id("number:x"), None);
        assert_eq!(writer_from_id("device:ab"), None);
        let bad = format!("device:{}", "a".repeat(63));
        assert_eq!(writer_from_id(&bad), None);
        let bad = format!("device:g{}", "a".repeat(63));
        assert_eq!(writer_from_id(&bad), None);
    }

    #[test]
    fn in_memory_replica_is_always_ephemeral() {
        // Even when the config explicitly asks for Verified, an in-memory
        // replica reports Ephemeral: nothing durable is ever written.
        let config = ClientConfig::new("custody-test").with_custody(Custody::Verified);
        let conn =
            ConnettoConnection::<FakeTransport>::open(&Replica::in_memory(), DDL, &config, None)
                .expect("open in-memory replica");
        assert_eq!(conn.custody(), Custody::Ephemeral);
    }

    #[test]
    fn durable_replica_reports_configured_custody_and_respects_set_custody() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("custody.db");
        let path_str = path.to_str().expect("path is utf-8");
        let key = ReplicaKey::from_bytes([0x42; ReplicaKey::LEN]);
        let replica = Replica::encrypted_file(path_str, Some(key)).expect("replica");
        let config =
            ClientConfig::new("custody-test").with_custody(Custody::Unverified(NoGate::Offerable));
        let mut conn = ConnettoConnection::<FakeTransport>::open(&replica, DDL, &config, None)
            .expect("open durable replica");
        assert_eq!(conn.custody(), Custody::Unverified(NoGate::Offerable));
        conn.set_custody(Custody::Verified);
        assert_eq!(conn.custody(), Custody::Verified);
    }

    /// A first boot whose schema fails partway leaves none of its earlier tables in the file.
    #[test]
    fn a_schema_failing_partway_leaves_no_table_behind() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("partial.db");
        let path_str = path.to_str().expect("path is utf-8");
        let key = || ReplicaKey::from_bytes([0x42; ReplicaKey::LEN]);
        let replica = Replica::encrypted_file(path_str, Some(key())).expect("replica");
        let failing = "CREATE TABLE first (id INTEGER PRIMARY KEY);
             CREATE TABLE first (id INTEGER PRIMARY KEY);";
        let config = ClientConfig::new("partial-test");
        assert!(
            ConnettoConnection::<FakeTransport>::open(&replica, failing, &config, None).is_err(),
            "a schema naming one table twice fails the open"
        );
        let mut db = SqliteConnection::establish(path_str).expect("reopen the file");
        cipher::unlock(&mut db, &key()).expect("unlock");
        let left = sqlite_catalog::table
            .filter(sqlite_catalog::name.eq("first"))
            .count()
            .get_result::<i64>(&mut db)
            .expect("read the catalogue");
        assert_eq!(
            left, 0,
            "the first statement was rolled back with the second"
        );
    }

    /// A resent write the server refuses settles the deferral, so the next outage starts its resend from the first wait.
    #[tokio::test]
    async fn a_settled_resend_restarts_the_next_deferral_from_the_first_wait() {
        let config = ClientConfig::new("resend-test");
        let mut conn =
            ConnettoConnection::<FakeTransport>::open(&Replica::in_memory(), DDL, &config, None)
                .expect("open in-memory replica");
        conn.attach(FakeTransport::accepting())
            .await
            .expect("attach");
        let writer = conn
            .bound_writer
            .expect("the handshake bound the issued number");
        conn.db
            .batch_execute("INSERT INTO t (id) VALUES (1)")
            .expect("local write");
        let changeset = conn.session.changeset().expect("capture the write");
        let first = conn
            .append_entry(&writer, &changeset, None)
            .expect("queue the write");
        conn.db
            .batch_execute("INSERT INTO t (id) VALUES (2)")
            .expect("second local write");
        let changeset = conn.session.changeset().expect("capture the second write");
        let second = conn
            .append_entry(&writer, &changeset, None)
            .expect("queue the second write");
        // A deferral whose writes went out again after its schedule had grown.
        let mut episode = RESEND_POLICY.start();
        for _ in 0..6 {
            let _ = episode.next_wait();
        }
        conn.resend = Resend::Resent { episode };

        conn.handle_control(ControlMessage::MutationReject(MutationReject {
            client_seq: first,
            reason: MutationRejectReason::Unauthorized,
        }))
        .await
        .expect("the refusal settles");
        conn.handle_control(ControlMessage::MutationReject(MutationReject {
            client_seq: second,
            reason: MutationRejectReason::Indeterminate,
        }))
        .await
        .expect("the next outage defers");
        let wait = conn.resend_timer().expect("a resend is armed").wait();
        assert!(
            wait <= RESEND_POLICY.initial_backoff(),
            "the new deferral starts from the first wait"
        );
    }

    /// A device with a device-private tier, for the two refusals an honest
    /// export of the same build cannot produce.
    fn tiered_connection(dir: &tempfile::TempDir) -> ConnettoConnection<FakeTransport> {
        let replica_path = dir.path().join("replica.db");
        let replica = Replica::encrypted_file(
            replica_path.to_str().expect("path is utf-8"),
            Some(ReplicaKey::from_bytes([0x11; ReplicaKey::LEN])),
        )
        .expect("replica")
        .with_tier("CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)");
        ConnettoConnection::<FakeTransport>::open(
            &replica,
            DDL,
            &ClientConfig::new("refusal-test"),
            None,
        )
        .expect("open replica")
    }

    /// An archive naming a table this build does not have is refused.
    ///
    /// It cannot arrive from an honest export of the same build, because the
    /// schema fingerprint would differ first, so the archive is built here.
    /// The check stays because the file is not authenticated and SQLite skips
    /// an absent table in silence rather than reporting it.
    #[test]
    fn an_archive_naming_an_unknown_table_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut conn = tiered_connection(&dir);
        let fingerprint = conn.schema_fingerprint().expect("fingerprint");
        let rows = {
            // A record naming a table that exists nowhere, built the way the
            // export builds one.
            let mut other = SqliteConnection::establish(":memory:").expect("scratch");
            other
                .batch_execute(
                    "CREATE TABLE ghosts (id INTEGER PRIMARY KEY, body TEXT);
                     INSERT INTO ghosts (id, body) VALUES (1, 'boo');",
                )
                .expect("scratch schema");
            export_rows(&mut other, "main", None, &HashSet::new(), &HashSet::new()).expect("record")
        };
        let bytes = archive_bytes(&archive::Archive {
            scope: ExportScope::Unsynced,
            fingerprint,
            account: None,
            synced_rows: None,
            local_rows: Some(rows),
            pending: Vec::new(),
            attachments: &[],
        });
        match conn.import_local_data(std::io::Cursor::new(&bytes)) {
            Err(ClientError::Import(message)) => {
                assert!(
                    message.contains("ghosts"),
                    "the refusal names it: {message}"
                );
            }
            other => panic!("expected a refusal, got {}", other.is_ok()),
        }
    }

    /// One archive in a buffer, for the refusal cases that build a file by hand.
    fn archive_bytes(archive: &archive::Archive<'_>) -> Vec<u8> {
        archive::start(Vec::new(), archive)
            .expect("start archive")
            .finish()
            .expect("finish archive")
    }
}
