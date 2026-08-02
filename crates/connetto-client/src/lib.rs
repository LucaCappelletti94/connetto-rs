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

use connetto_core::messages::{
    AckCredits, BulkMessage, ControlMessage, FatalError, FatalErrorReason, Handshake,
    MutationHeader, MutationPatch, Ping, Subscribe, SubscriptionSpec, Unsubscribe,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION, SchemaVersion};
use core::sync::atomic::{AtomicBool, Ordering};
use diesel::connection::SimpleConnection;
use diesel::connection::{
    AnsiTransactionManager, CacheSize, ConnectionSealed, DefaultLoadingMode, Instrumentation,
    LoadConnection,
};
use diesel::expression::QueryMetadata;
use diesel::query_builder::{Query, QueryFragment, QueryId};
use diesel::result::{ConnectionError, ConnectionResult, QueryResult};
use diesel::sqlite::{CommitDecision, Sqlite, SqliteChangeOps, SqliteUpdateRouter};
use diesel::{Connection, RunQueryDsl, SqliteConnection};
use diesel_sqlite_session::{
    ConflictAction, ConflictType, Session, SqliteSessionExt, invert_changeset,
};
use sqlite_diff_rs::{ParsedDiffSet, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[cfg(feature = "native-auth")]
pub mod auth;
pub mod cipher;
pub mod dsl;
pub mod live;
pub mod reconnect;
pub mod replica;
pub mod teardown;

#[cfg(feature = "native-auth")]
pub use auth::{
    AcquiredSession, BrowserOpener, KeyringKeyStore, KeyringStore, MemoryKeyStore,
    MemoryRefreshStore, NativeAuthenticator, RefreshTokenStore, ReplicaKeyStore,
    provision_replica_key, system_browser_opener,
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
pub use replica::{Replica, replica_db_name};

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

/// Client identity presented at handshake.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Stable client id, echoed for logging and correlation.
    pub client_id: String,
    /// Opaque auth token validated by the server at connect.
    pub auth_token: String,
    /// The schema version this client build was compiled against, for staleness
    /// detection, or `None` to opt out. When both this and the server's ack
    /// carry a version and they differ, [`ConnettoConnection::connect`] fails
    /// with [`ClientError::SchemaOutdated`] so the app can reload. Either side
    /// being `None` skips the check.
    pub schema_version: Option<SchemaVersion>,
    /// Custom SQLite functions connetto registers on the replica connection it
    /// opens for this client, before any DDL or insert. Empty by default. A
    /// schema whose column `DEFAULT` calls a function (a `uuidv7` key
    /// generator, say) supplies the matching installer here.
    pub sql_functions: SqlFunctions,
}

/// One observable outcome of [`ConnettoConnection::pump_one`].
#[derive(Debug, Clone, PartialEq)]
pub enum ClientEvent {
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
    /// The connection closed.
    Closed,
    /// The credential was rejected and refresh could not recover it, so the
    /// local session is over. The reconnect driver stops rather than spinning:
    /// the app must re-authenticate interactively, then either resume (same
    /// `user_id`) or purge and start fresh (an account switch). Terminal, like
    /// [`Closed`](Self::Closed).
    AuthenticationRequired,
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

/// Decode a pushed changeset into the rows it touched, each as its table and
/// primary key, for reporting on a rejected or conflicting mutation.
fn affected_rows(changeset: &[u8]) -> Result<Vec<AffectedRow>, ClientError> {
    let parsed = ParsedDiffSet::parse(changeset)
        .map_err(|err| ClientError::Apply(format!("parsing pushed changeset: {err:?}")))?;
    let rows = match parsed {
        ParsedDiffSet::Changeset(diff) => diff
            .iter()
            .map(|op| AffectedRow {
                table: op.table().name().to_owned(),
                key: op.primary_key().into_iter().map(KeyValue::from).collect(),
            })
            .collect(),
        ParsedDiffSet::Patchset(diff) => diff
            .iter()
            .map(|op| AffectedRow {
                table: op.table().name().to_owned(),
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

/// The lowercased names of every table in the attached local tier.
fn local_tier_tables(db: &mut SqliteConnection) -> Result<HashSet<String>, ClientError> {
    let rows: Vec<SchemaTableRow> = diesel::sql_query(format!(
        "SELECT name FROM {LOCAL_SCHEMA}.sqlite_schema WHERE type = 'table'"
    ))
    .load(db)?;
    Ok(rows
        .into_iter()
        .map(|row| row.name.to_lowercase())
        .collect())
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

/// Record `cursor` in the replica's metadata table. Callers wrap this in the
/// same transaction as the patch apply it belongs to, so a crash never
/// separates a row change from its resume point.
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

/// Run the opening handshake over `transport`: send the hello (carrying the
/// resume cursor and, on a resume, the durable session handle) and read the
/// ack. Returns the server-assigned connection id, the durable session handle
/// the server minted, the server's durable mutation watermark, and the
/// server's schema version.
/// Shared by the first connect and every resume.
async fn exchange_handshake<T>(
    transport: &mut T,
    config: &ClientConfig,
    token_source: Option<&AccessTokenSource>,
    resume: Option<&Cursor>,
    session_handle: Option<&str>,
) -> Result<(String, String, Option<u64>, Option<SchemaVersion>), ClientError>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    let mut handshake = Handshake::new(
        PROTOCOL_VERSION,
        config.client_id.clone(),
        match token_source {
            Some(source) => source.token().await?,
            None => config.auth_token.clone(),
        },
    );
    if let Some(cursor) = resume {
        handshake = handshake.with_cursor(cursor.clone());
    }
    // The durable handle from a previous run of this session. The server
    // derives the authoritative handle from the verified credential, so this
    // is the client's continuity claim rather than a trust input.
    if let Some(handle) = session_handle {
        handshake = handshake.with_session_token(handle.to_owned());
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
            Ok((
                ack.connection_id,
                ack.session_token,
                ack.last_applied_seq,
                ack.schema_version,
            ))
        }
        // A rejected credential is fatal for this attempt and routes to
        // re-login, not a generic reconnect that would spin forever.
        Some(IncomingFrame::Control(ControlMessage::FatalError(FatalError {
            reason: FatalErrorReason::AuthenticationFailed,
        }))) => Err(ClientError::Auth("credential rejected at handshake".into())),
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

/// A native sync client bound to one transport and one local SQLite database.
pub struct ConnettoConnection<T: Transport> {
    transport: T,
    // `session` is declared before `db` so it drops first: it holds a raw
    // pointer into the connection's SQLite handle and must not outlive it.
    session: Session,
    db: SqliteConnection,
    last_cursor: Option<Cursor>,
    next_seq: u64,
    connection_id: String,
    /// The durable session handle the server minted at handshake, presented
    /// again on every resume so the session's operational state (its
    /// per-subscription cursors and pending buffer) continues rather than
    /// starting over.
    session_handle: String,
    /// The server's schema version from the handshake ack, kept so a relay can
    /// forward it verbatim to its tabs and (Phase 7) a stale build can be
    /// detected against the baked schema.
    schema_version: Option<SchemaVersion>,
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
    /// reconnect silently refreshes. `None` reuses `config.auth_token`.
    token_source: Option<AccessTokenSource>,
    /// Lowercased names of the tables in the attached local tier, empty until
    /// [`attach_local_tier`](Self::attach_local_tier) or
    /// [`attach_local_tier_ddl`](Self::attach_local_tier_ddl) runs. Live
    /// queries dispatch on it: a local table never reaches the wire.
    local_tables: HashSet<String>,
    /// Lowercased tables backing each row subscription, keyed by sub id, so a
    /// `FullResyncRequired` can drop the subscription's stale replica rows
    /// before the fresh snapshot repopulates. Aggregate subscriptions hold no
    /// replica rows, so they are never recorded here.
    sub_tables: HashMap<String, HashSet<String>>,
}

impl<T> ConnettoConnection<T>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    /// Connect: open the local replica, hook the capture session, and run the
    /// handshake.
    ///
    /// `replica` says where the replica lives and whether its pages are
    /// encrypted, as one value, so a connection cannot exist without its opener
    /// having stated both and cannot claim a key over storage that has nothing
    /// at rest. `sqlite_ddl` creates the local schema. Pass `resume` to continue
    /// from a persisted cursor on reconnect.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a database, cipher, session, transport, or handshake
    /// failure. [`ClientError::ReplicaUndecryptable`] when an existing replica
    /// does not open under the key given.
    pub async fn connect(
        transport: T,
        replica: &Replica<'_>,
        sqlite_ddl: &str,
        config: &ClientConfig,
        resume: Option<Cursor>,
    ) -> Result<Self, ClientError> {
        Self::connect_inner(transport, replica, Some(sqlite_ddl), config, resume).await
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
    pub async fn connect_existing(
        transport: T,
        replica: &Replica<'_>,
        config: &ClientConfig,
        resume: Option<Cursor>,
    ) -> Result<Self, ClientError> {
        Self::connect_inner(transport, replica, None, config, resume).await
    }

    /// Shared connect body: open the connection, unlock the page codec, apply
    /// the schema when it arrives as DDL, hook the capture session, and run the
    /// handshake.
    async fn connect_inner(
        mut transport: T,
        replica: &Replica<'_>,
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
        match replica {
            Replica::Ephemeral => {}
            Replica::EncryptedFile { key, .. } => cipher::unlock(&mut db, key)?,
        }
        db.batch_execute("PRAGMA journal_mode=WAL")?;
        // Register app-supplied functions before any DDL or insert, so a
        // column DEFAULT that calls one fires on the first write.
        config
            .sql_functions
            .install(&mut db)
            .map_err(|e| ClientError::Session(e.to_string()))?;
        if let Some(ddl) = sqlite_ddl {
            db.batch_execute(ddl)?;
        }
        db.batch_execute(META_DDL)?;
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

        let (connection_id, session_handle, watermark, schema_version) =
            exchange_handshake(&mut transport, config, None, resume.as_ref(), None).await?;

        let next_seq = pending.last_key_value().map_or(0, |(seq, _)| seq + 1);
        let mut conn = Self {
            transport,
            session,
            db,
            last_cursor: resume,
            next_seq,
            connection_id,
            session_handle,
            schema_version,
            dirty,
            changed,
            transaction_state: AnsiTransactionManager::default(),
            pending,
            config: config.clone(),
            token_source: None,
            local_tables: HashSet::new(),
            sub_tables: HashMap::new(),
        };
        conn.reconcile_pending(watermark).await?;
        Ok(conn)
    }

    /// Attach a source of fresh access tokens, consulted on every
    /// [`resume`](Self::resume) so a reconnect silently refreshes the access
    /// token from the stored refresh token with no user interaction. The first
    /// connect used `config.auth_token`, so a native client sets that to a
    /// token it acquired interactively and this to its silent-refresh source.
    #[must_use]
    pub fn with_token_source(mut self, source: AccessTokenSource) -> Self {
        self.token_source = Some(source);
        self
    }

    /// Swap in a fresh transport after a drop: re-handshake with the highest
    /// applied cursor and keep every piece of local state (replica, capture
    /// session, pending mutations, sequence counter).
    ///
    /// The ack's durable watermark retires every pending mutation the server
    /// already applied and the rest are replayed, so the upload path stays
    /// exactly-once across the drop. The dirty flag is forced so writes that
    /// were captured but never pushed re-flush. A re-declared subscription
    /// replays what the server retained past the cursor, or full-resyncs.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a transport or handshake failure. The connection
    /// keeps its previous (dead) transport in that case, so a caller can try
    /// again with another one.
    pub async fn resume(&mut self, mut transport: T) -> Result<(), ClientError> {
        let (connection_id, session_handle, watermark, schema_version) = exchange_handshake(
            &mut transport,
            &self.config,
            self.token_source.as_ref(),
            self.last_cursor.as_ref(),
            Some(self.session_handle.as_str()),
        )
        .await?;
        self.transport = transport;
        self.connection_id = connection_id;
        self.session_handle = session_handle;
        self.schema_version = schema_version;
        // Relaxed: same-task flag, no ordering dependency.
        self.dirty.store(true, Ordering::Relaxed);
        self.reconcile_pending(watermark).await?;
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

    /// The per-connection routing label from the handshake ack. This is not
    /// identity and must not be treated as such.
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// The durable session handle from the handshake ack.
    ///
    /// One unbroken run of one caller, and the key the server's resume, its
    /// per-subscription cursors, and the exactly-once watermark all address.
    /// Unlike [`connection_id`](Self::connection_id), it survives a reconnect.
    #[must_use]
    pub fn session_handle(&self) -> &str {
        &self.session_handle
    }

    /// The server's schema version from the handshake ack, or `None` when the
    /// server declared none.
    #[must_use]
    pub fn schema_version(&self) -> &Option<SchemaVersion> {
        &self.schema_version
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

    /// The sequence numbers of mutations captured locally but not yet
    /// confirmed durable by the server. Non-empty means a teardown would lose
    /// data, so logout and expiry surface these before purging the replica.
    #[must_use]
    pub fn unsynced(&self) -> Vec<u64> {
        self.pending.keys().copied().collect()
    }

    /// Attach the local tier database at `path`: device-private tables that
    /// never sync. The capture session is bound to `main`, so writes to these
    /// tables are physically incapable of being uploaded, rejected, or rolled
    /// back, and live queries over them are served locally without a server
    /// subscription.
    ///
    /// The file must already exist (a baked template written by the app or
    /// imported through the VFS): attach-create is disabled around the
    /// attach, so a missing file fails loudly instead of materializing as an
    /// empty database. Attach before creating live queries, since tier
    /// dispatch happens at registration.
    ///
    /// The tier shares the replica's cipher, always: SQLite gives an attached
    /// database the connection's VFS and the page codec gives it the main
    /// database's derived key. One device, one key, because two would double the
    /// lost-key failure modes and isolate nothing, since both entries would sit
    /// in the same key store behind the same wrap.
    ///
    /// Under an encrypted replica the tier file must have been created through a
    /// connection keyed the same way, which in practice means a previous run's
    /// [`attach_local_tier_ddl`](Self::attach_local_tier_ddl). A file created
    /// elsewhere carries its own key salt and will not decrypt here, and a
    /// plaintext baked template will not either. Both fail loudly with
    /// [`ClientError::Db`] rather than leaving the tier in the clear.
    ///
    /// # Errors
    ///
    /// [`ClientError::Db`] when the file is missing, is not a database, or a
    /// tier is already attached.
    pub fn attach_local_tier(&mut self, path: &str) -> Result<(), ClientError> {
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

    /// Attach the local tier at `path`, creating it and applying `ddl` when it
    /// is empty. `":memory:"` gives the ephemeral tier a `:memory:` replica
    /// wants (a tab's mirror, tests), a file path gives a durable one, and
    /// either way a second run over an already populated tier re-attaches it
    /// untouched.
    ///
    /// This is the only way to first-boot a durable tier under an encrypted
    /// replica, and the reason is a property of the page codec rather than a
    /// preference. A database created through an `ATTACH` on a keyed connection
    /// inherits the main database's key salt, and an `ATTACH` of an existing
    /// database applies the main database's derived key regardless of any `KEY`
    /// clause, so a tier file created by some other connection carries a
    /// different salt and will not decrypt here. Creating it through the replica
    /// connection is what makes the salts agree, which is also why
    /// [`attach_local_tier`](Self::attach_local_tier) works on every later run.
    /// This is measured behaviour: see
    /// `crates/connetto-client/tests/encrypted_replica.rs`.
    ///
    /// `ddl` must consist of `CREATE TABLE` statements only: each is
    /// requalified into the attached schema, since an unqualified `CREATE
    /// TABLE` would land in `main` and sync.
    ///
    /// # Errors
    ///
    /// [`ClientError::Session`] on a non-`CREATE TABLE` statement,
    /// [`ClientError::Db`] when a statement fails or a tier is already
    /// attached.
    pub fn attach_local_tier_ddl(&mut self, path: &str, ddl: &str) -> Result<(), ClientError> {
        self.db.attach_database(path, LOCAL_SCHEMA)?;
        // An attached database with no tables is a fresh one, on every target
        // and with no filesystem probe, which wasm does not have.
        if local_tier_tables(&mut self.db)?.is_empty() {
            for statement in ddl.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                self.db.batch_execute(&qualify_create_table(statement)?)?;
            }
        }
        self.local_tables = local_tier_tables(&mut self.db)?;
        Ok(())
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
        self.transport
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: sub_id.to_owned(),
                spec: SubscriptionSpec::new(query),
            }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        self.record_row_subscription(sub_id, query);
        Ok(())
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
        let query = spec.query.clone();
        self.transport
            .send_control(ControlMessage::Subscribe(Subscribe {
                sub_id: sub_id.to_owned(),
                spec,
            }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        self.record_row_subscription(sub_id, &query);
        Ok(())
    }

    /// Cancel a subscription (row or aggregate) by its client-assigned id. The
    /// server tolerates an unknown id silently.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the unsubscribe frame cannot be sent.
    pub async fn unsubscribe(&mut self, sub_id: &str) -> Result<(), ClientError> {
        self.transport
            .send_control(ControlMessage::Unsubscribe(Unsubscribe {
                sub_id: sub_id.to_owned(),
            }))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        self.sub_tables.remove(sub_id);
        Ok(())
    }

    /// Record the lowercased replica tables a row subscription reads, so a
    /// later `FullResyncRequired` drops its stale rows before the fresh
    /// snapshot repopulates. Best-effort: an aggregate or an unparsable query
    /// records nothing (and clears any prior mapping under this id), because it
    /// holds no replica rows to reset.
    fn record_row_subscription(&mut self, sub_id: &str, query: &str) {
        if let Ok(false) = subscription_is_aggregate(query)
            && let Ok(tables) = subscription_tables(query)
        {
            self.sub_tables.insert(sub_id.to_owned(), tables);
        } else {
            self.sub_tables.remove(sub_id);
        }
    }

    /// Read one inbound frame, apply it if it is a patch, and report what
    /// happened. Applying a bulk patch replenishes one delivery credit.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a transport, apply, or protocol failure.
    pub async fn pump_one(&mut self) -> Result<ClientEvent, ClientError> {
        let frame = self
            .transport
            .recv()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
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
        let frame = tokio::select! {
            biased;
            () = cancel => return Ok(None),
            frame = self.transport.recv() => {
                frame.map_err(|e| ClientError::Transport(e.to_string()))?
            }
        };
        self.handle_frame(frame).await.map(Some)
    }

    /// Apply one received frame: bulk patches mutate the replica and advance
    /// flow control, control frames map onto their [`ClientEvent`]s.
    async fn handle_frame(
        &mut self,
        frame: Option<IncomingFrame>,
    ) -> Result<ClientEvent, ClientError> {
        match frame {
            None => Ok(ClientEvent::Closed),
            Some(IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch))) => {
                self.apply_patch(&patch.patchset_zstd, None)?;
                self.ack_one().await?;
                Ok(ClientEvent::SnapshotApplied {
                    sub_id: patch.sub_id,
                })
            }
            Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch))) => {
                self.apply_patch(&patch.patchset_zstd, Some(&patch.cursor))?;
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
        self.transport
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
        self.send_mutation(seq, &changeset).await?;
        Ok(Some(seq))
    }

    /// Send one mutation as its header and patchset frame pair. Shared by
    /// [`push`](Self::push) and the replay in
    /// [`reconcile_pending`](Self::reconcile_pending).
    async fn send_mutation(&mut self, seq: u64, changeset: &[u8]) -> Result<(), ClientError> {
        let op_count = count_ops(changeset);
        let payload = zstd::encode_all(changeset, ZSTD_LEVEL)?;
        self.transport
            .send_control(ControlMessage::MutationHeader(MutationHeader::new(
                seq, op_count,
            )))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        self.transport
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
        let rows = affected_rows(&changeset)?;
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
    pub fn take_changed(&mut self) -> Vec<String> {
        let mut tables: Vec<String> = self
            .changed
            .lock()
            .map(|mut set| set.drain().collect())
            .unwrap_or_default();
        tables.sort();
        tables
    }

    /// Close the transport.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when the close fails.
    pub async fn close(&mut self) -> Result<(), ClientError> {
        self.transport
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
                })
            }
            ControlMessage::Pong(pong) => Ok(ClientEvent::Pong { nonce: pong.nonce }),
            ControlMessage::NonFatalError(err) => Ok(ClientEvent::NonFatal {
                related_to: err.related_to,
                detail: err.detail,
            }),
            other => Err(ClientError::Protocol(format!(
                "unexpected control frame from server: {other:?}"
            ))),
        }
    }

    /// Drop every replica row of a row subscription's tables ahead of a
    /// full-resync snapshot. The fresh snapshot carries only the currently
    /// authorized rows, so the insert-only apply would leave rows deleted
    /// during the outage behind. Capture is suspended so the deletes are never
    /// re-uploaded as a local mutation. An unknown or aggregate sub id (no
    /// recorded tables) is a no-op.
    fn clear_subscription_rows(&mut self, sub_id: &str) -> Result<(), ClientError> {
        let Some(tables) = self.sub_tables.get(sub_id).cloned() else {
            return Ok(());
        };
        let _suspended = SuspendedCapture::new(&mut self.session);
        self.db.transaction::<_, ClientError, _>(|conn| {
            for table in &tables {
                // The table is chosen at runtime from the subscription's parsed
                // query, so diesel's compile-time table DSL cannot name it: a
                // quoted-identifier DELETE is the one raw statement here.
                diesel::sql_query(format!("DELETE FROM \"{table}\"")).execute(conn)?;
            }
            Ok(())
        })
    }

    /// Apply one compressed server patchset to the replica, recording
    /// `cursor` in the same transaction when one accompanies it, so a crash
    /// never separates an applied change from its resume point. Capture is
    /// suspended throughout: the session never records what the server
    /// already knows.
    fn apply_patch(
        &mut self,
        payload_zstd: &[u8],
        cursor: Option<&Cursor>,
    ) -> Result<(), ClientError> {
        let bytes = zstd::decode_all(payload_zstd)?;
        let _suspended = SuspendedCapture::new(&mut self.session);
        self.db.transaction::<_, ClientError, _>(|conn| {
            conn.apply_patchset(&bytes, server_wins)
                .map_err(|e| ClientError::Apply(e.to_string()))?;
            if let Some(cursor) = cursor {
                persist_cursor(conn, cursor)?;
            }
            Ok(())
        })
    }

    async fn ack_one(&mut self) -> Result<(), ClientError> {
        self.transport
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
