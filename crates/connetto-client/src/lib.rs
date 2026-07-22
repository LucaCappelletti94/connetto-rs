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
//! * **Server patches** (the initial snapshot and live updates) apply to a
//!   sibling connection to the same database file. A session tracks only writes
//!   made on the connection it is attached to, so applying on the sibling
//!   bypasses the capture session and server-originated changes are never
//!   re-uploaded (no echo loop). The application's connection sees them through
//!   SQLite WAL.
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
    AckCredits, BulkMessage, ControlMessage, Handshake, MutationHeader, MutationPatch, Ping,
    Subscribe, SubscriptionSpec, Unsubscribe,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
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
use diesel::{Connection, SqliteConnection};
use diesel_sqlite_session::{
    ConflictAction, ConflictType, Session, SqliteSessionExt, invert_changeset,
};
use sqlite_diff_rs::{ParsedDiffSet, Value};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

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
}

/// Client identity presented at handshake.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Stable client id, echoed for logging and correlation.
    pub client_id: String,
    /// Opaque auth token validated by the server at connect.
    pub auth_token: String,
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
    },
    /// An aggregate result update.
    Aggregate {
        /// Subscription id.
        sub_id: String,
        /// JSON-encoded aggregate value.
        result_json: String,
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
    /// The connection closed.
    Closed,
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
    // `session` is declared before `dev` so it drops first: it holds a raw
    // pointer into the connection's SQLite handle and must not outlive it.
    session: Session,
    dev: SqliteConnection,
    apply: SqliteConnection,
    last_cursor: Option<Cursor>,
    next_seq: u64,
    session_id: String,
    /// Set by the commit hook on `dev` whenever a local write commits, so the
    /// driver knows there is a captured mutation to flush.
    dirty: Arc<AtomicBool>,
    /// Names of tables whose rows changed since the last drain, from the update
    /// hooks on both `dev` (local writes) and `apply` (server patches).
    changed: Arc<Mutex<HashSet<String>>>,
    /// Transaction bookkeeping for the diesel `Connection` impl. The manager
    /// issues `BEGIN`/`COMMIT` through this connection, which delegate to `dev`.
    transaction_state: AnsiTransactionManager,
    /// Changesets of pushed mutations awaiting resolution, keyed by `client_seq`,
    /// so a server rejection can be inverted and rolled back locally. Bounded by
    /// `PENDING_CAP`.
    pending: BTreeMap<u64, Vec<u8>>,
}

impl<T> ConnettoConnection<T>
where
    T: Transport,
    T::Error: core::fmt::Display,
{
    /// Connect: open the local database, hook the capture session, and run the
    /// handshake.
    ///
    /// `db_path` must be a real file path (not `:memory:`) so the capture and
    /// apply connections share it. `sqlite_ddl` creates the local schema. Pass
    /// `resume` to continue from a persisted cursor on reconnect.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a database, session, transport, or handshake failure.
    pub async fn connect(
        mut transport: T,
        db_path: &str,
        sqlite_ddl: &str,
        config: &ClientConfig,
        resume: Option<Cursor>,
    ) -> Result<Self, ClientError> {
        let mut apply = SqliteConnection::establish(db_path)
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        apply.batch_execute("PRAGMA journal_mode=WAL")?;
        apply.batch_execute(sqlite_ddl)?;
        let changed: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        install_change_tracker(&mut apply, &changed);

        let mut dev = SqliteConnection::establish(db_path)
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        dev.batch_execute("PRAGMA journal_mode=WAL")?;
        let dirty = Arc::new(AtomicBool::new(false));
        install_change_tracker(&mut dev, &changed);
        {
            let dirty = Arc::clone(&dirty);
            dev.on_commit(move || {
                dirty.store(true, Ordering::Relaxed);
                CommitDecision::Proceed
            });
        }
        let mut session = dev
            .create_session()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        session
            .attach_all()
            .map_err(|e| ClientError::Session(e.to_string()))?;

        let mut handshake = Handshake::new(
            PROTOCOL_VERSION,
            config.client_id.clone(),
            config.auth_token.clone(),
        );
        if let Some(cursor) = resume.clone() {
            handshake = handshake.with_cursor(cursor);
        }
        transport
            .send_control(ControlMessage::Handshake(handshake))
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let session_id = match transport
            .recv()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?
        {
            Some(IncomingFrame::Control(ControlMessage::HandshakeAck(ack))) => ack.session_id,
            Some(_) => return Err(ClientError::Protocol("expected handshake ack".into())),
            None => return Err(ClientError::Protocol("connection closed before ack".into())),
        };

        Ok(Self {
            transport,
            session,
            dev,
            apply,
            last_cursor: resume,
            next_seq: 0,
            session_id,
            dirty,
            changed,
            transaction_state: AnsiTransactionManager::default(),
            pending: BTreeMap::new(),
        })
    }

    /// The server-assigned session id from the handshake ack.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The application's local connection, for ordinary diesel reads and writes.
    /// Writes here are captured for upload on the next [`push`](Self::push).
    pub const fn conn(&mut self) -> &mut SqliteConnection {
        &mut self.dev
    }

    /// The highest resume cursor applied so far, if any.
    #[must_use]
    pub const fn cursor(&self) -> Option<&Cursor> {
        self.last_cursor.as_ref()
    }

    /// Declare a subscription from a `SELECT`. The server classifies it from the
    /// SQL: a row projection streams patchsets into the local replica (observe
    /// [`ClientEvent::LivePatch`] and read rows with diesel), while a single
    /// scalar aggregate pushes each value as a [`ClientEvent::Aggregate`] and
    /// leaves the replica untouched. `subql` rejects unsupported syntax, which
    /// surfaces as a [`ClientEvent::NonFatal`] with the session intact.
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
            .map_err(|e| ClientError::Transport(e.to_string()))
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
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// Read one inbound frame, apply it if it is a patch, and report what
    /// happened. Applying a bulk patch replenishes one delivery credit.
    ///
    /// # Errors
    ///
    /// [`ClientError`] on a transport, apply, or protocol failure.
    pub async fn pump_one(&mut self) -> Result<ClientEvent, ClientError> {
        match self
            .transport
            .recv()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?
        {
            None => Ok(ClientEvent::Closed),
            Some(IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch))) => {
                self.apply_patch(&patch.patchset_zstd)?;
                self.ack_one().await?;
                Ok(ClientEvent::SnapshotApplied {
                    sub_id: patch.sub_id,
                })
            }
            Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch))) => {
                self.apply_patch(&patch.patchset_zstd)?;
                self.last_cursor = Some(patch.cursor.clone());
                self.ack_one().await?;
                Ok(ClientEvent::LivePatch {
                    sub_id: patch.sub_id,
                    cursor: patch.cursor,
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
    /// send. The capture session is reset afterward so the next push sees only
    /// subsequent writes.
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
        let op_count = count_ops(&changeset);
        let seq = self.next_seq;
        self.next_seq += 1;
        let payload = zstd::encode_all(changeset.as_slice(), ZSTD_LEVEL)?;
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
        self.pending.insert(seq, changeset);
        if self.pending.len() > PENDING_CAP {
            self.pending.pop_first();
        }
        // Reset capture: a fresh session records only writes after this push.
        let mut fresh = self
            .dev
            .create_session()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        fresh
            .attach_all()
            .map_err(|e| ClientError::Session(e.to_string()))?;
        self.session = fresh;
        Ok(Some(seq))
    }

    /// Roll back the optimistic local write for `client_seq` after the server
    /// rejected or conflicted it: decode the touched rows for the event, invert
    /// the captured changeset, and apply the inverse on the apply connection,
    /// which the capture session does not observe, so the rollback is never
    /// re-uploaded. A row a concurrent server patch already changed is left
    /// alone. Returns the touched rows, empty when the changeset is gone.
    fn rollback(&mut self, client_seq: u64) -> Result<Vec<AffectedRow>, ClientError> {
        let Some(changeset) = self.pending.remove(&client_seq) else {
            return Ok(Vec::new());
        };
        let rows = affected_rows(&changeset)?;
        let inverse = invert_changeset(&changeset)
            .map_err(|err| ClientError::Apply(format!("inverting rejected changeset: {err}")))?;
        self.apply
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
                self.last_cursor = Some(end.cursor);
                Ok(ClientEvent::SnapshotEnd { sub_id: end.sub_id })
            }
            ControlMessage::AggregateUpdate(update) => Ok(ClientEvent::Aggregate {
                sub_id: update.sub_id,
                result_json: update.result_json,
            }),
            ControlMessage::FullResyncRequired(resync) => Ok(ClientEvent::FullResync {
                sub_id: resync.sub_id,
            }),
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

    fn apply_patch(&mut self, payload_zstd: &[u8]) -> Result<(), ClientError> {
        let bytes = zstd::decode_all(payload_zstd)?;
        self.apply
            .apply_patchset(&bytes, server_wins)
            .map_err(|e| ClientError::Apply(e.to_string()))
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
        self.dev.batch_execute(query)
    }
}

impl<T: Transport> ConnectionSealed for ConnettoConnection<T> {}

/// `ConnettoConnection` is a diesel `Connection` over the managed local SQLite,
/// so applications run ordinary diesel queries on `&mut conn`. Execution
/// delegates to the capture connection `dev`, so local writes are recorded and
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
        self.dev.execute_returning_count(source)
    }

    fn transaction_state(&mut self) -> &mut AnsiTransactionManager {
        &mut self.transaction_state
    }

    fn instrumentation(&mut self) -> &mut dyn Instrumentation {
        self.dev.instrumentation()
    }

    fn set_instrumentation(&mut self, instrumentation: impl Instrumentation) {
        self.dev.set_instrumentation(instrumentation);
    }

    fn set_prepared_statement_cache_size(&mut self, size: CacheSize) {
        self.dev.set_prepared_statement_cache_size(size);
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
        self.dev.load(source)
    }
}
