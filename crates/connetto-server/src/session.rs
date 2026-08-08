//! Session manager, per-session state machine, the snapshot seam, and the
//! write path.
//!
//! One [`SessionManager`] fronts a shared [`Materializer`], a routing table, a
//! visibility policy, and the server's write target. Each connection is driven
//! by [`SessionManager::serve`], which runs the handshake, then a select loop
//! over inbound control frames and outbound live patches. CDC events reach
//! subscribed sessions through [`SessionManager::dispatch_event`].
//!
//! Flow control charges a credit only to bulk-plane frames
//! (`LivePatch`/`SnapshotPatch`), never to control frames, so keepalive can
//! never deadlock on an empty credit window. See
//! `docs/architecture/10-subscription-materializer.md` and `02-protocol.md`.
//!
//! The write path pairs a `MutationHeader` with the `MutationPatch` that follows
//! it, authorizes every op, detects stale-version conflicts, applies the whole
//! changeset in one transaction, and replies on every outcome: `MutationApplied`
//! on a durable apply, `MutationReject` or `MutationConflict` otherwise. The
//! write applies to the source Postgres under the caller's RLS context.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use connetto_core::auth::{Principal, Subject};
use connetto_core::messages::{
    AggregateUpdate, BindValue, BulkMessage, ControlMessage, FatalError, FatalErrorReason,
    FullResyncReason, FullResyncRequired, Handshake, HandshakeAck, LivePatch, MutationApplied,
    MutationConflict, MutationHeader, MutationPatch, MutationReject, MutationRejectReason,
    NonFatalError, Pong, RateLimited, SUBSCRIPTION_REFUSED, SnapshotBegin, SnapshotEnd,
    SnapshotPatch, Subscribe,
};
use connetto_core::traits::{HandshakeAuthority, IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION, SchemaVersion, SessionId};
use subql::backend::{CdcEvent, Postgres, ScalarKind, Value as PgValue};
use subql::reexec::{AsyncConnector, Snapshot as ConnectorRead};
use subql::visibility::{EventRow, Verdict, VisibilityPolicy};
use subql::{AggAccumulator, CdcSource, ChangeEvent, ParserDB, PgLsn, SubscriptionId};
use tokio::sync::{Mutex, mpsc};
use tracing::Instrument;

use crate::abuse::{Caller, Reaction};
use crate::capability::CapabilityKey;
use crate::counters;
use crate::guard::RequestGuard;
use crate::materializer::{
    DeltaAggregateCapture, Materializer, MaterializerError, Registration, SqliteRegistration,
    agg_value_to_json, compress, value_to_json,
};
use crate::oplog::{CatchupDecision, InMemoryOplog, Oplog, catchup_decision};
use crate::row_view::ValuesRow;
use crate::throttle::Tier;
use crate::watermark_schema::ConnettoWatermarkSchema;
use crate::write_target::{PgWriteTarget, WriteError, WriteOutcome};

/// Initial rows for a subscription, produced by a [`SnapshotSource`].
pub struct Snapshot {
    /// Raw (uncompressed) insert-patchset bytes for the initial rows.
    pub patchset: Vec<u8>,
    /// Cursor at which the snapshot was read. Live updates strictly greater
    /// than this apply on top on the client.
    pub cursor: Cursor,
}

/// Produces a subscription's initial snapshot for a given identity.
///
/// Phase 4 implements it over the re-exec `Connector`: run the subscription's
/// `SELECT` against Postgres at a snapshot LSN and encode the rows into an
/// insert-patchset with `sqlite-diff-rs`. No SQLite lives on the backend. The
/// `caller` lets the implementation run the read under the requesting
/// principal's Row-Level Security so the snapshot already excludes rows it
/// cannot see.
#[allow(async_fn_in_trait)]
pub trait SnapshotSource<Id = String, Key = String>: Send + Sync {
    /// Snapshot-source error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// Produce the initial snapshot for `select_sql`, authorized as `caller`.
    ///
    /// `select_sql` is the Postgres translation of the subscription query,
    /// never the client dialect, with `$N` placeholders paired to `binds` in
    /// order.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backend read or encoding failure.
    async fn snapshot(
        &self,
        select_sql: &str,
        binds: &[BindValue],
        caller: &Principal<Id, Key>,
    ) -> Result<Snapshot, Self::Error>;
}

/// The products of registering one row subscription, as its delivery needs
/// them: the engine ids plus the Postgres translation of the query, which
/// the snapshot read uses instead of the client dialect.
struct RowRegistration {
    /// The engine consumer bound to this subscription.
    consumer_id: u64,
    /// The engine subscription id.
    sub_id: SubscriptionId,
    /// The subscription query reverse translated to Postgres.
    pg_sql: String,
}

/// Per-session server configuration.
///
/// Limits and abuse thresholds live on [`RequestGuard`] rather than here,
/// because one instance of it is shared with the auth service and this type is
/// cloned per manager.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Delivery credits granted to the server at handshake.
    pub initial_credits: u32,
    /// Schema version advertised in the handshake ack, or `None` to declare no
    /// version (staleness detection off for every client).
    pub schema_version: Option<SchemaVersion>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            initial_credits: 64,
            schema_version: None,
        }
    }
}

/// Backoff policy for reconnecting a dropped CDC stream.
///
/// [`SessionManager::ingest_with_reconnect`] reconnects the source after the
/// stream fails, resuming from the replication slot's confirmed position.
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    /// Backoff before the first retry.
    pub initial_backoff: Duration,
    /// Ceiling for the exponential backoff.
    pub max_backoff: Duration,
    /// Give up after this many consecutive failed attempts. `None` retries
    /// forever, which is what a long-running server wants.
    pub max_attempts: Option<u32>,
    /// A connection that stayed up at least this long is treated as healthy, so
    /// the backoff resets after it drops.
    pub healthy_after: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(30),
            max_attempts: None,
            healthy_after: Duration::from_secs(10),
        }
    }
}

impl ReconnectPolicy {
    /// Backoff before the `attempt`-th retry (1-based): exponential from
    /// `initial_backoff`, capped at `max_backoff`.
    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2u128.saturating_pow(attempt.saturating_sub(1));
        let millis = self
            .initial_backoff
            .as_millis()
            .saturating_mul(factor)
            .min(self.max_backoff.as_millis());
        Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
    }
}

/// An event from [`SessionManager::ingest_with_reconnect`], for logging or
/// metrics. The loop is otherwise silent, so a caller wanting visibility into
/// reconnect churn observes it here.
#[derive(Debug)]
pub enum ReconnectEvent<'a> {
    /// The CDC stream failed; the loop retries after `backoff`.
    Retrying {
        /// Consecutive failed-attempt count (1-based).
        attempt: u32,
        /// Delay before the next connect.
        backoff: Duration,
        /// The failure that triggered the retry.
        error: &'a str,
    },
    /// The policy's `max_attempts` was reached; the loop stops.
    GaveUp {
        /// Total attempts made.
        attempts: u32,
        /// The last failure.
        error: &'a str,
    },
}

/// Failure surfaced by the session layer.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The underlying transport failed.
    #[error("transport error: {0}")]
    Transport(String),
    /// The snapshot source failed.
    #[error("snapshot error: {0}")]
    Snapshot(String),
    /// The oplog backing store failed.
    #[error("oplog error: {0}")]
    Oplog(String),
    /// A materializer operation failed.
    #[error(transparent)]
    Materializer(#[from] MaterializerError),
    /// The peer violated the wire protocol.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// Compressing a bulk payload failed.
    #[error(transparent)]
    Compression(#[from] std::io::Error),
    /// The write target failed outside a mutation commit (the watermark read
    /// at handshake).
    #[error("write target error: {0}")]
    WriteTarget(String),
    /// The ban list could not be read, so the handshake failed closed rather
    /// than admitting a caller whose ban might not have been seen.
    #[error("ban list error: {0}")]
    BanList(String),
    /// The resume credential could not be minted.
    #[error("resume credential: {0}")]
    Handle(String),
}

fn transport_err<E: core::fmt::Display>(err: E) -> SessionError {
    SessionError::Transport(err.to_string())
}

fn oplog_err<E: core::fmt::Display>(err: E) -> SessionError {
    SessionError::Oplog(err.to_string())
}

/// Decode a resume cursor into an LSN. The cursor is an 8-byte big-endian LSN;
/// anything else (empty, absent, or malformed) is a client that never synced,
/// which maps to LSN 0 and takes the full-resync path.
fn resume_lsn_from_cursor(cursor: Option<&Cursor>) -> u64 {
    match cursor.map(Cursor::as_bytes) {
        Some(bytes) if bytes.len() == 8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(bytes);
            u64::from_be_bytes(buf)
        }
        _ => 0,
    }
}

/// The word for a checked subject in the log, so a refusal can be counted and
/// filtered by kind without parsing a sentence.
const fn subject_kind<Id, Key>(subject: &Subject<Id, Key>) -> &'static str {
    match subject {
        Subject::Identity(_) => "user",
        Subject::Capability(_) => "key",
    }
}

/// Map a materializer failure to the reason sent back on the wire.
fn reject_reason(err: &MaterializerError) -> MutationRejectReason {
    match err {
        MaterializerError::Parse(detail) => MutationRejectReason::Malformed {
            detail: detail.clone(),
        },
        MaterializerError::NotWritable(_) | MaterializerError::SchemaMismatch(_) => {
            MutationRejectReason::SchemaMismatch
        }
        MaterializerError::Apply(inner) => MutationRejectReason::Constraint {
            detail: inner.to_string(),
        },
        other => MutationRejectReason::Other {
            detail: other.to_string(),
        },
    }
}

/// A frame queued for a session's outbound path.
enum Outbound {
    /// A live row patch (bulk plane, credit-gated).
    Live(LivePatch),
    /// An aggregate value update (control plane, never credit-gated).
    Aggregate(AggregateUpdate),
    /// A fatal close: the pump sends it as a control frame and ends the
    /// session (revocation and supersession arrive this way).
    Fatal(FatalError),
    /// End the session without sending anything. A ban tells the caller
    /// nothing, so it draws no frame and no reason.
    Drop,
}

/// Route from a `subql` consumer id back to the owning session's outbound
/// channel.
#[derive(Clone)]
struct Route<Id, Key> {
    /// The durable handle folded to the `u64` subql keys this session's
    /// per-subscription cursors on, stable across reconnects.
    session_key: u64,
    sub_id: SubscriptionId,
    label: String,
    tx: mpsc::UnboundedSender<Outbound>,
    /// The subscribing session's caller, consulted per event for the read
    /// filter before a live patch is delivered. Shared rather than copied,
    /// because the fan-out clones one route per subscriber per event.
    principal: Arc<Principal<Id, Key>>,
}

/// Route from an aggregate subscription (re-execution query or delta aggregate)
/// to its session's outbound channel.
#[derive(Clone)]
struct AggRoute {
    label: String,
    tx: mpsc::UnboundedSender<Outbound>,
}

/// A live connection in the session registry: the socket counter that owns
/// the entry, the outbound channel a close is delivered on, and who holds it.
struct LiveSession {
    connection_num: u64,
    tx: mpsc::UnboundedSender<Outbound>,
    /// The identity's rendering, absent for a caller with no identity, so a ban
    /// can find every connection one person holds.
    user: Option<String>,
}

/// What a completed handshake establishes for the run loop.
struct HandshakeOutcome<Id, Key> {
    connection_num: u64,
    principal: Arc<Principal<Id, Key>>,
    resume_lsn: u64,
    applied_watermark: Option<u64>,
    /// How many grants were refused, tallied for abuse once the run is
    /// registered so a crossing can close the connection it happened on.
    refused_grants: u32,
    /// The logging context, opened as soon as the run has a handle so that a
    /// refused grant is recorded inside it.
    span: tracing::Span,
}

/// Mutable per-session state carried through the run loop.
struct SessionState<Id, Key> {
    credits: u32,
    pending: VecDeque<BulkMessage>,
    subs: HashMap<String, (u64, SubscriptionId)>,
    agg_subs: HashMap<String, u64>,
    /// Delta aggregate subscriptions by client label: consumer id and engine
    /// subscription id, both needed to tear the subscription down.
    delta_agg_subs: HashMap<String, (u64, SubscriptionId)>,
    outbound: mpsc::UnboundedSender<Outbound>,
    /// The caller, established at handshake and consulted per read and write.
    principal: Arc<Principal<Id, Key>>,
    /// The `MutationHeader` awaiting its paired `MutationPatch`.
    pending_header: Option<MutationHeader>,
    /// The connetto-minted session id from the verified token. The durable
    /// watermark keys on it, so a reconnect reusing the same session dedupes.
    session_id: SessionId,
    /// Highest `client_seq` durably applied for this client identity, from
    /// the write target at handshake and advanced per commit. A replayed
    /// sequence at or below it is re-acknowledged, never re-applied.
    applied_watermark: Option<u64>,
    /// Resume LSN decoded from the handshake cursor. 0 means a fresh session, so
    /// every re-declared subscription replays from here on reconnect.
    resume_lsn: u64,
    /// Set when a per-connection abuse threshold crossed, so the run loop ends
    /// after the frame that crossed it. A caller with no identity has no name
    /// to ban, so closing the socket is the whole outcome.
    closing: bool,
}

/// An [`AsyncConnector`] that fails every call: the default when a manager runs
/// no re-execution backend, appropriate when no aggregate subscriptions exist.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoConnector;

#[allow(clippy::manual_async_fn)]
impl AsyncConnector for NoConnector {
    type AuthContext = ();
    type Error = std::io::Error;
    type Checkpoint = PgLsn;
    type Backend = Postgres;

    fn execute_scalar(
        &self,
        _sql: &str,
        _kind: ScalarKind,
        _auth: &(),
    ) -> impl core::future::Future<
        Output = Result<(PgValue<Postgres>, Option<PgLsn>), std::io::Error>,
    > + Send {
        async {
            Err(std::io::Error::other(
                "no re-execution connector configured",
            ))
        }
    }

    fn execute_rows(
        &self,
        _sql: &str,
        _auth: &(),
    ) -> impl core::future::Future<
        Output = Result<ConnectorRead<Vec<Vec<PgValue<Postgres>>>, PgLsn>, std::io::Error>,
    > + Send {
        async {
            Err(std::io::Error::other(
                "no re-execution connector configured",
            ))
        }
    }
}

/// Fronts a shared [`Materializer`], routes CDC output to sessions, and runs the
/// write path against a visibility policy, the Postgres write target, and a
/// re-execution connector for aggregate subscriptions.
pub struct SessionManager<
    Snap,
    Auth,
    W,
    C = NoConnector,
    O = InMemoryOplog,
    Id = String,
    Key = String,
> where
    Snap: SnapshotSource<Id, Key>,
    Auth: VisibilityPolicy<Watcher = Arc<Principal<Id, Key>>, Backend = Postgres>,
    C: AsyncConnector<Backend = Postgres, Checkpoint = PgLsn, AuthContext = ()> + Send + Sync,
    O: Oplog,
    W: ConnettoWatermarkSchema<Id = Id>,
{
    materializer: Arc<Mutex<Materializer>>,
    /// The parsed catalog, cloned out of the materializer at construction.
    /// The visibility question holds a row view across an await, so it cannot
    /// borrow one through the materializer's mutex.
    catalog: Arc<ParserDB>,
    routes: Mutex<HashMap<u64, Route<Id, Key>>>,
    agg_routes: Mutex<HashMap<u64, AggRoute>>,
    /// Delta aggregate routes keyed by consumer id. Kept separate from
    /// `agg_routes` (keyed by re-execution query id) because the two u64
    /// keyspaces are distinct and could otherwise collide.
    delta_agg_routes: Mutex<HashMap<u64, AggRoute>>,
    /// Live connections keyed by the durable session handle, for revocation
    /// and supersession. The per-subscription route map cannot serve either,
    /// because a session with no subscriptions has no route.
    sessions: Mutex<HashMap<SessionId, LiveSession>>,
    snapshot_source: Snap,
    auth: Auth,
    /// Checks the grants a handshake presents and signs the resume credential
    /// it hands back. A runtime trait object so a deployment configures
    /// identity without changing the manager's type. Required at construction
    /// with no default, because the deleted trusting default was itself the
    /// spoofing hole (R2).
    authority: Arc<dyn HandshakeAuthority<Id, Key>>,
    connector: C,
    oplog: O,
    target: PgWriteTarget<W>,
    next_session: AtomicU64,
    next_consumer: AtomicU64,
    config: SessionConfig,
    /// Every counter connetto keeps about a caller, shared with the auth
    /// service so the four abuse signals are defined once each.
    guard: Arc<RequestGuard<Id>>,
}

impl<Snap, Auth, W> SessionManager<Snap, Auth, W, NoConnector, InMemoryOplog>
where
    Snap: SnapshotSource,
    Auth: VisibilityPolicy<Watcher = Arc<Principal>, Backend = Postgres>,
    W: ConnettoWatermarkSchema<Id = String>,
{
    /// Build a manager with no re-execution connector and a default in-memory
    /// oplog.
    ///
    /// The `authority` is required: nothing installs one by default, so a
    /// deployment chooses its identity story explicitly. Aggregate
    /// subscriptions need a connector; use
    /// [`with_connector`](Self::with_connector) to supply one. Reconnect uses a
    /// default [`InMemoryOplog`]; use [`with_oplog`](Self::with_oplog) for another.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        materializer: Materializer,
        snapshot_source: Snap,
        auth: Auth,
        authority: Arc<dyn HandshakeAuthority>,
        target: PgWriteTarget<W>,
        guard: Arc<RequestGuard<String>>,
        config: SessionConfig,
    ) -> Arc<Self> {
        Self::with_oplog(
            materializer,
            snapshot_source,
            auth,
            authority,
            NoConnector,
            InMemoryOplog::default(),
            target,
            guard,
            config,
        )
    }
}

impl<Snap, Auth, C, W> SessionManager<Snap, Auth, W, C, InMemoryOplog>
where
    Snap: SnapshotSource,
    Auth: VisibilityPolicy<Watcher = Arc<Principal>, Backend = Postgres>,
    C: AsyncConnector<Backend = Postgres, Checkpoint = PgLsn, AuthContext = ()> + Send + Sync,
    C::Error: core::fmt::Display,
    W: ConnettoWatermarkSchema<Id = String>,
{
    /// Build a manager with a re-execution connector and a default in-memory
    /// oplog. Use [`with_oplog`](Self::with_oplog) to supply another oplog.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn with_connector(
        materializer: Materializer,
        snapshot_source: Snap,
        auth: Auth,
        authority: Arc<dyn HandshakeAuthority>,
        connector: C,
        target: PgWriteTarget<W>,
        guard: Arc<RequestGuard<String>>,
        config: SessionConfig,
    ) -> Arc<Self> {
        Self::with_oplog(
            materializer,
            snapshot_source,
            auth,
            authority,
            connector,
            InMemoryOplog::default(),
            target,
            guard,
            config,
        )
    }
}

impl<Snap, Auth, C, O, W> SessionManager<Snap, Auth, W, C, O>
where
    Snap: SnapshotSource,
    Auth: VisibilityPolicy<Watcher = Arc<Principal>, Backend = Postgres>,
    C: AsyncConnector<Backend = Postgres, Checkpoint = PgLsn, AuthContext = ()> + Send + Sync,
    C::Error: core::fmt::Display,
    O: Oplog,
    W: ConnettoWatermarkSchema<Id = String>,
{
    /// Build a manager with an explicit re-execution connector and oplog.
    // Every collaborator the manager owns arrives here explicitly. The other
    // two constructors delegate to it with defaults, so this is the one place
    // the full set is named, and grouping it into a config struct would only
    // move the same arity behind another type.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn with_oplog(
        materializer: Materializer,
        snapshot_source: Snap,
        auth: Auth,
        authority: Arc<dyn HandshakeAuthority>,
        connector: C,
        oplog: O,
        target: PgWriteTarget<W>,
        guard: Arc<RequestGuard<String>>,
        config: SessionConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            catalog: Arc::new(materializer.catalog().clone()),
            materializer: Arc::new(Mutex::new(materializer)),
            routes: Mutex::new(HashMap::new()),
            agg_routes: Mutex::new(HashMap::new()),
            delta_agg_routes: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            snapshot_source,
            auth,
            authority,
            connector,
            oplog,
            target,
            next_session: AtomicU64::new(1),
            next_consumer: AtomicU64::new(1),
            config,
            guard,
        })
    }
}

impl<Snap, Auth, C, O, Id, Key, W> SessionManager<Snap, Auth, W, C, O, Id, Key>
where
    Snap: SnapshotSource<Id, Key>,
    Auth: VisibilityPolicy<Watcher = Arc<Principal<Id, Key>>, Backend = Postgres>,
    C: AsyncConnector<Backend = Postgres, Checkpoint = PgLsn, AuthContext = ()> + Send + Sync,
    C::Error: core::fmt::Display,
    O: Oplog,
    Id: core::fmt::Display + Clone + Send + Sync + 'static,
    Key: CapabilityKey,
    W: ConnettoWatermarkSchema<Id = Id>,
{
    fn next_connection_num(&self) -> u64 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }

    fn next_consumer_id(&self) -> u64 {
        self.next_consumer.fetch_add(1, Ordering::Relaxed)
    }

    /// Map a principal to its throttle tier.
    fn principal_tier(principal: &Principal<Id, Key>) -> Tier {
        if principal.identity().is_some() {
            Tier::Identified
        } else {
            Tier::Anonymous
        }
    }

    /// Who a signal is attributed to: the handle for the rate limit, the person
    /// for the abuse tally.
    fn caller(principal: &Principal<Id, Key>) -> Caller<'_, Id> {
        Caller {
            session: principal.session_id(),
            user: principal.identity().map(|identity| &identity.user_id),
        }
    }

    /// Close `session_id`'s live connection, if one exists, sending `reason`
    /// as a fatal frame first. Returns whether a live connection was found.
    ///
    /// The revocation path (`FatalErrorReason::SessionRevoked`): revoking a
    /// session closes its live connection rather than only refusing its next
    /// handshake.
    pub async fn close_session(&self, session_id: SessionId, reason: FatalErrorReason) -> bool {
        let live = { self.sessions.lock().await.remove(&session_id) };
        match live {
            Some(live) => {
                tracing::info!(session = %session_id, reason = ?reason, "closing a live connection");
                let _ = live.tx.send(Outbound::Fatal(FatalError::new(reason)));
                true
            }
            None => false,
        }
    }

    /// Close every live connection the identity rendering as `user` holds,
    /// telling them nothing, and report how many. A person may hold one per
    /// device, so a ban that closed only the connection it was detected on
    /// would leave the others streaming.
    ///
    /// The registry is small and a ban is rare, so this scans rather than
    /// keeping a second index to fall out of step.
    pub async fn close_person(&self, user: &str) -> usize {
        let closing: Vec<_> = {
            let mut sessions = self.sessions.lock().await;
            let handles: Vec<SessionId> = sessions
                .iter()
                .filter(|(_, live)| live.user.as_deref() == Some(user))
                .map(|(handle, _)| *handle)
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| sessions.remove(&handle))
                .collect()
        };
        for live in &closing {
            let _ = live.tx.send(Outbound::Drop);
        }
        if !closing.is_empty() {
            tracing::info!(
                closed = closing.len(),
                "closing a banned identity's connections"
            );
        }
        closing.len()
    }

    /// Close every live connection with
    /// [`FatalErrorReason::ServerShuttingDown`], returning how many were told.
    ///
    /// A client that learns the server is going away backs off instead of
    /// reconnecting immediately into a dying process. The registry is drained,
    /// so a handshake racing the shutdown registers into an empty map and is
    /// closed by the listener stopping rather than by a second frame.
    pub async fn shutdown(&self) -> usize {
        let live: Vec<_> = {
            let mut sessions = self.sessions.lock().await;
            sessions.drain().map(|(_, live)| live.tx).collect()
        };
        for tx in &live {
            let _ = tx.send(Outbound::Fatal(FatalError::new(
                FatalErrorReason::ServerShuttingDown,
            )));
        }
        live.len()
    }

    /// Claim `session_id` for this connection, superseding whatever held it.
    ///
    /// One live connection per durable handle, newer wins. Two connections
    /// must not share a handle, because the handle keys the per-subscription
    /// cursors and the pending buffer, and two readers would each consume the
    /// other's changes. Last-wins also makes a reconnect racing its own
    /// half-dead socket self-heal.
    async fn register_connection(
        &self,
        session_id: SessionId,
        connection_num: u64,
        user: Option<String>,
        tx: &mpsc::UnboundedSender<Outbound>,
    ) {
        let superseded = {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(
                session_id,
                LiveSession {
                    connection_num,
                    tx: tx.clone(),
                    user,
                },
            )
        };
        if let Some(old) = superseded {
            tracing::warn!(
                session = %session_id,
                superseded = old.connection_num,
                "a newer connection claimed this session handle"
            );
            let _ = old.tx.send(Outbound::Fatal(FatalError::new(
                FatalErrorReason::ConnectionSuperseded,
            )));
        }
    }

    /// Drop the registry entry only if this connection still owns it: a
    /// superseded connection's cleanup must not evict its successor.
    async fn unregister_connection(&self, session_id: SessionId, connection_num: u64) {
        let mut sessions = self.sessions.lock().await;
        if sessions
            .get(&session_id)
            .is_some_and(|live| live.connection_num == connection_num)
        {
            sessions.remove(&session_id);
        }
    }

    async fn add_route(&self, consumer_id: u64, route: Route<Id, Key>) {
        self.routes.lock().await.insert(consumer_id, route);
    }

    async fn remove_route(&self, consumer_id: u64) {
        self.routes.lock().await.remove(&consumer_id);
    }

    async fn add_agg_route(&self, query_id: u64, route: AggRoute) {
        self.agg_routes.lock().await.insert(query_id, route);
    }

    async fn remove_agg_route(&self, query_id: u64) {
        self.agg_routes.lock().await.remove(&query_id);
    }

    async fn add_delta_agg_route(&self, consumer_id: u64, route: AggRoute) {
        self.delta_agg_routes
            .lock()
            .await
            .insert(consumer_id, route);
    }

    async fn remove_delta_agg_route(&self, consumer_id: u64) {
        self.delta_agg_routes.lock().await.remove(&consumer_id);
    }

    /// Dispatch one CDC event: fan row patches to sessions, deliver in-process
    /// aggregate changes, and service re-execution triggers through the
    /// connector.
    ///
    /// Locks the materializer only for the synchronous engine calls, never
    /// across a channel send or a connector await.
    ///
    /// # Errors
    ///
    /// [`SessionError`] when dispatch, a cursor advance, an install, or the
    /// oplog append fails.
    pub async fn dispatch_event(&self, event: &ChangeEvent) -> Result<(), SessionError> {
        let dispatched = {
            counters::timed_lock(&self.materializer)
                .await
                .dispatch(event)?
        };

        // Record the event in the oplog before fan-out. The append is per event,
        // not per consumer, since reconnect catchup re-filters per client.
        let record = {
            counters::timed_lock(&self.materializer)
                .await
                .oplog_record(event)
        };
        if let Some(record) = record {
            self.oplog.append(record).await.map_err(oplog_err)?;
        }

        // Every patch this event produced, paired with the route it goes to.
        // Collected before the visibility question because that question names
        // every watcher at once.
        let mut deliveries = Vec::with_capacity(dispatched.patches.len());
        for patch in dispatched.patches {
            let route = { self.routes.lock().await.get(&patch.consumer_id).cloned() };
            let Some(route) = route else { continue };
            counters::add(&counters::FANOUT_ROUTE_CLONES, 1);
            deliveries.push((patch, route));
        }

        // Read filter: deliver only rows a session may see. A delete or a
        // truncate carries no post-image, which is what `EventRow::current`
        // reports by answering `None`, and those replay regardless so a client
        // drops a row it may still hold locally even after it can no longer see
        // it.
        let mut verdicts = Vec::new();
        if let Some(row) = EventRow::current(event, self.catalog.as_ref()) {
            let watchers: Vec<_> = deliveries
                .iter()
                .map(|(_, route)| Arc::clone(&route.principal))
                .collect();
            Verdict::reset(&mut verdicts, watchers.len());
            // The buffer arrived pre-filled with denials, so whatever the
            // policy could not reach stays denied.
            let _ = self.auth.may_see(&row, &watchers, &mut verdicts).await;
        } else {
            // Nothing to ask about, so nothing is filtered.
            verdicts.resize(deliveries.len(), Verdict::Allow);
        }

        for ((patch, route), verdict) in deliveries.into_iter().zip(verdicts) {
            if !verdict.allowed() {
                continue;
            }
            {
                counters::timed_lock(&self.materializer)
                    .await
                    .advance_cursor(route.session_key, route.sub_id, &patch.cursor)?;
            }
            let live = LivePatch::new(route.label, Cursor::new(patch.cursor), patch.payload_zstd);
            // A dropped session receiver just means the client is gone.
            let _ = route.tx.send(Outbound::Live(live));
        }

        for change in dispatched.aggregates {
            self.deliver_aggregate(change.query_id, change.result_json)
                .await;
        }

        for trigger in dispatched.triggers {
            let Ok((value, _lsn)) = self
                .connector
                .execute_scalar(&trigger.sql, trigger.kind, &())
                .await
            else {
                // Re-execution failure: bounded retry and SyncFailure surfacing
                // land in Phase 6. Skip for now.
                continue;
            };
            let result_json = value_to_json(&value);
            {
                self.materializer
                    .lock()
                    .await
                    .install_scalar(trigger.query_id, value);
            }
            self.deliver_aggregate(trigger.query_id, result_json).await;
        }

        // Delta aggregates are global by construction (subql rejects aggregators
        // on RLS tables), so no per-row read filter applies: deliver each folded
        // value unconditionally to its owning session.
        for change in dispatched.delta_aggregates {
            self.deliver_delta_aggregate(change.consumer_id, change.result_json)
                .await;
        }
        Ok(())
    }

    /// Drive a CDC source to completion, dispatching every event and acking its
    /// checkpoint so the upstream can recycle its log.
    ///
    /// This is the standing ingestor: one per server, fanning out to every
    /// session. It is generic over the [`CdcSource`], so it runs the same way
    /// against the SQLite emulator (Docker-free) and a real
    /// `PgStreamingCdcSource`. Reconnect on a transient source error lands in
    /// Phase 6; for now an error ends the loop.
    ///
    /// # Errors
    ///
    /// [`SessionError`] when a dispatch fails or the source errors.
    pub async fn ingest<S>(&self, source: &mut S) -> Result<(), SessionError>
    where
        S: CdcSource<Event = ChangeEvent>,
        S::Error: core::fmt::Display,
    {
        loop {
            match source.next_event().await {
                Ok(Some(event)) => {
                    self.dispatch_event(&event).await?;
                    if let Some(lsn) = event.checkpoint() {
                        source
                            .ack(lsn)
                            .await
                            .map_err(|err| SessionError::Transport(err.to_string()))?;
                    }
                }
                // A clean source shutdown ends ingestion.
                Ok(None) => return Ok(()),
                Err(err) => return Err(SessionError::Transport(err.to_string())),
            }
        }
    }

    /// Ingest CDC events, reconnecting the source with backoff when the stream
    /// fails.
    ///
    /// `connect` produces a fresh source each time, resuming from the
    /// replication slot's confirmed position, so a dropped connection loses no
    /// events. `on_event` observes each retry and the final give-up, for logging
    /// or metrics. Returns `Ok(())` when a source signals a clean shutdown, or
    /// an error only once `policy` exhausts its attempts (a policy with no
    /// `max_attempts` retries forever).
    ///
    /// # Errors
    ///
    /// [`SessionError`] when the reconnect policy gives up, or when a dispatch
    /// fails.
    pub async fn ingest_with_reconnect<S, Connect, F, E>(
        &self,
        mut connect: Connect,
        policy: &ReconnectPolicy,
        mut on_event: impl FnMut(ReconnectEvent<'_>),
    ) -> Result<(), SessionError>
    where
        S: CdcSource<Event = ChangeEvent>,
        S::Error: core::fmt::Display,
        Connect: FnMut() -> F,
        F: core::future::Future<Output = Result<S, E>>,
        E: core::fmt::Display,
    {
        let mut attempt: u32 = 0;
        loop {
            let error = match connect().await {
                Ok(mut source) => {
                    let started = Instant::now();
                    match self.ingest(&mut source).await {
                        Ok(()) => return Ok(()),
                        Err(err) => {
                            if started.elapsed() >= policy.healthy_after {
                                attempt = 0;
                            }
                            err.to_string()
                        }
                    }
                }
                Err(err) => err.to_string(),
            };
            attempt = attempt.saturating_add(1);
            if let Some(max) = policy.max_attempts
                && attempt >= max
            {
                on_event(ReconnectEvent::GaveUp {
                    attempts: attempt,
                    error: &error,
                });
                return Err(SessionError::Transport(format!(
                    "cdc ingest gave up after {attempt} attempts: {error}"
                )));
            }
            let backoff = policy.backoff(attempt);
            on_event(ReconnectEvent::Retrying {
                attempt,
                backoff,
                error: &error,
            });
            tokio::time::sleep(backoff).await;
        }
    }

    /// Send an aggregate result to the session owning `query_id`, if routed.
    async fn deliver_aggregate(&self, query_id: u64, result_json: String) {
        let route = { self.agg_routes.lock().await.get(&query_id).cloned() };
        let Some(route) = route else { return };
        let update = AggregateUpdate {
            sub_id: route.label,
            group_key: None,
            result_json,
            is_full_result: true,
        };
        let _ = route.tx.send(Outbound::Aggregate(update));
    }

    /// Send a folded delta aggregate value to the session owning `consumer_id`,
    /// if routed.
    async fn deliver_delta_aggregate(&self, consumer_id: u64, result_json: String) {
        let route = {
            self.delta_agg_routes
                .lock()
                .await
                .get(&consumer_id)
                .cloned()
        };
        let Some(route) = route else { return };
        let update = AggregateUpdate {
            sub_id: route.label,
            group_key: None,
            result_json,
            is_full_result: true,
        };
        let _ = route.tx.send(Outbound::Aggregate(update));
    }

    /// Receive and validate the handshake, decode the resume cursor, read the
    /// client's durable mutation watermark, and reply with the ack carrying
    /// both the server's current cursor and that watermark.
    ///
    /// Returns the session identity, or `None` when the peer closed before
    /// sending a handshake.
    async fn run_handshake<T: Transport>(
        &self,
        transport: &mut T,
    ) -> Result<Option<HandshakeOutcome<Id, Key>>, SessionError> {
        let handshake = match transport.recv().await.map_err(transport_err)? {
            Some(IncomingFrame::Control(ControlMessage::Handshake(hs))) => hs,
            Some(_) => return Err(SessionError::Protocol("expected handshake first".into())),
            None => return Ok(None),
        };
        if handshake.protocol_version != PROTOCOL_VERSION {
            // Outside any connection context on purpose: no session exists yet,
            // so the handle is absent rather than a stand-in.
            tracing::warn!(
                client_id = %handshake.client_id,
                expected = PROTOCOL_VERSION,
                got = handshake.protocol_version,
                "handshake refused, protocol version mismatch"
            );
            let _ = transport
                .send_control(ControlMessage::FatalError(FatalError::new(
                    FatalErrorReason::ProtocolVersionMismatch {
                        expected: PROTOCOL_VERSION,
                        got: handshake.protocol_version,
                    },
                )))
                .await;
            return Err(SessionError::Protocol(format!(
                "protocol version mismatch: server {PROTOCOL_VERSION}, client {}",
                handshake.protocol_version
            )));
        }

        let connection_num = self.next_connection_num();
        // The handle comes before the grants on purpose: a run has one whether
        // or not anybody is signed in, and having it first is what lets the
        // logging context cover the grant checks below. Identity is resolved
        // only from checked grants, never from the client-supplied `client_id`,
        // which stays a pure correlation label.
        let handle = self.resume_handle(handshake.resume_token.as_deref(), &handshake.client_id);
        // A span attaches its values only when its own level passes the filter,
        // so the context has to be at least as severe as the least verbose
        // event that must carry it. That event is a refused grant, at warn, and
        // it is the one line where losing the handle would matter most: an
        // operator who quiets this process to warn would otherwise keep exactly
        // the security-relevant line and lose the run it belongs to.
        let span = tracing::warn_span!(
            "connection",
            session = %handle,
            user = tracing::field::Empty,
            connection = connection_num,
        );
        let (principal, refused_grants, grant_wait) = self
            .resolve_grants(handle, &handshake)
            .instrument(span.clone())
            .await;
        if let Some(identity) = principal.identity() {
            span.record("user", tracing::field::display(&identity.user_id));
        }
        let session_id = principal.session_id();
        let tier = Self::principal_tier(&principal);
        if self
            .refuse_over_limit(transport, session_id, tier, grant_wait, &span)
            .await
        {
            // The refusals still count. A rate limit caps how fast a signal can
            // accumulate and must never erase what it already saw, or the caller
            // spraying keys fast enough to trip it would be the one caller this
            // phase cannot see. The reaction is ignored because this connection
            // is ending either way, and a ban that lands closes the caller's
            // other connections through the hook.
            //
            // This and the announcement in `run_session` are the two ends of one
            // count and are mutually exclusive. The ban refusal below needs
            // neither: that caller is already banned, so tallying more would only
            // re-ask the application about a decision it has taken.
            let _ = span.in_scope(|| {
                self.guard
                    .refused_grants(Self::caller(&principal), refused_grants)
            });
            // None: no session to run, so `serve` completes cleanly.
            return Ok(None);
        }

        if self.refuse_if_banned(&principal, &span).await? {
            return Ok(None);
        }

        // Decode the resume cursor and read the server watermark for the ack. An
        // 8-byte cursor is the client's resume LSN; anything else is a fresh
        // client (LSN 0), which takes the full-resync path on subscribe.
        let resume_lsn = resume_lsn_from_cursor(handshake.last_cursor.as_ref());
        let current_cursor = match self.oplog.current_lsn().await.map_err(oplog_err)? {
            Some(lsn) => Cursor::new(lsn.to_be_bytes().to_vec()),
            None => Cursor::new(Vec::new()),
        };
        // The durable mutation watermark: the client retires pending records
        // at or below it and replays the rest.
        let applied_watermark = self
            .target
            .last_applied(session_id)
            .await
            .map_err(|err| SessionError::WriteTarget(err.detail()))?;
        let resume_token = self
            .authority
            .mint_handle(session_id)
            .map_err(|err| SessionError::Handle(err.to_string()))?;

        transport
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: format!("connection-{connection_num}"),
                session_token: session_id.to_string(),
                resume_token,
                current_cursor,
                schema_version: self.config.schema_version.clone(),
                initial_credits: self.config.initial_credits,
                last_applied_seq: applied_watermark,
            }))
            .await
            .map_err(transport_err)?;
        Ok(Some(HandshakeOutcome {
            connection_num,
            principal: Arc::new(principal),
            resume_lsn,
            applied_watermark,
            refused_grants,
            span,
        }))
    }
    /// Refuse a caller that is over a rate limit, reporting whether it was.
    ///
    /// The credential count short-circuits the connection one, so a caller
    /// already being turned away for it does not also spend a connection, and
    /// the check runs before any store work.
    async fn refuse_over_limit<T: Transport>(
        &self,
        transport: &mut T,
        session_id: SessionId,
        tier: Tier,
        grant_wait: Option<Duration>,
        span: &tracing::Span,
    ) -> bool {
        let refused = grant_wait
            .map(|wait| ("credential refusal limit", wait))
            .or_else(|| {
                self.guard
                    .connection(session_id, tier)
                    .map(|wait| ("connection limit", wait))
            });
        let Some((limit, wait)) = refused else {
            return false;
        };
        let retry_after_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        // Inside the connection context, so the line names the handle it
        // refused. Unlike a version mismatch, a run exists here.
        span.in_scope(|| {
            tracing::warn!(
                retry_after_ms,
                limit,
                "connection refused, rate limit reached"
            );
        });
        let _ = transport
            .send_control(ControlMessage::FatalError(FatalError::new(
                FatalErrorReason::RateLimited { retry_after_ms },
            )))
            .await;
        true
    }

    /// Whether the caller is banned, checked one frame after the grant that
    /// named them because nothing identifies a caller earlier and a browser
    /// cannot read the status of a refused upgrade anyway.
    ///
    /// A banned caller is told nothing: no frame and no reason, with the ban
    /// going to the structured log. A ban list that cannot be read refuses the
    /// connection, so a ban never lapses because a table was briefly unreadable
    /// and an attacker who can cause an outage cannot suspend their own ban.
    async fn refuse_if_banned(
        &self,
        principal: &Principal<Id, Key>,
        span: &tracing::Span,
    ) -> Result<bool, SessionError> {
        let Some(identity) = principal.identity() else {
            return Ok(false);
        };
        let ban = span
            .in_scope(|| self.guard.banned(&identity.user_id))
            .await
            .map_err(|err| SessionError::BanList(err.detail().to_owned()))?;
        let Some(ban) = ban else {
            return Ok(false);
        };
        span.in_scope(|| {
            tracing::warn!(
                reason = %ban.reason,
                permanent = ban.expires_at.is_none(),
                "handshake refused, identity banned"
            );
        });
        Ok(true)
    }

    /// The handle this run continues on: the one inside a resume credential
    /// this server signed, or a fresh one when there is none or it does not
    /// check out. An identified run replaces it with its login grant's handle.
    ///
    /// Refusing an unsigned credential is what stops a caller choosing the key
    /// to its own server-side state, or resuming as a visitor whose handle it
    /// obtained.
    fn resume_handle(&self, presented: Option<&str>, client_id: &str) -> SessionId {
        let Some(blob) = presented else {
            return SessionId::from_uuid(uuid::Uuid::new_v4());
        };
        self.authority.read_handle(blob).unwrap_or_else(|err| {
            tracing::warn!(
                client_id = %client_id,
                error = %err,
                "resume credential refused, starting a fresh run"
            );
            SessionId::from_uuid(uuid::Uuid::new_v4())
        })
    }

    /// Check every grant on its own and fold what resolved into the caller,
    /// returning how many were refused and the wait the rate limit imposed.
    ///
    /// A refusal is recorded here and nowhere else. It does not end the
    /// connection and the reply says nothing about it, so this log line is the
    /// entire visibility story: without it a checker that refuses everything
    /// and one that accepts everything look identical from the client.
    ///
    /// The count travels rather than being tallied here, because a login grant
    /// may follow a bad key in the list, so who to attribute the refusals to is
    /// not known until the loop finishes.
    ///
    /// Tripping the refusal limit stops the loop. One handshake carries as many
    /// grants as fit in a frame, so continuing would buy the caller every
    /// remaining signature check after the limit already said no, and the
    /// connection is closed on the returned wait regardless.
    async fn resolve_grants(
        &self,
        handle: SessionId,
        handshake: &Handshake,
    ) -> (Principal<Id, Key>, u32, Option<Duration>) {
        let mut principal = Principal::unidentified(handle);
        let mut refusal_wait: Option<Duration> = None;
        let mut refusals: u32 = 0;
        for (position, grant) in handshake.grants.iter().enumerate() {
            let position = u64::try_from(position).unwrap_or(u64::MAX);
            let refused = match self.authority.check_grant(grant).await {
                Ok(subject) => {
                    let kind = subject_kind(&subject);
                    let ambiguous = principal.accept(subject).is_err();
                    if ambiguous {
                        tracing::warn!(
                            client_id = %handshake.client_id,
                            grant = position,
                            kind,
                            reason = "ambiguous",
                            "grant refused"
                        );
                    }
                    ambiguous
                }
                Err(refusal) => {
                    tracing::warn!(
                        client_id = %handshake.client_id,
                        grant = position,
                        reason = refusal.reason(),
                        detail = %refusal,
                        "grant refused"
                    );
                    true
                }
            };
            if !refused {
                continue;
            }
            refusals = refusals.saturating_add(1);
            // A refused grant never establishes an identity, so the refusal is
            // metered at the tier that has not proved one.
            if let Some(wait) = self.guard.credential_refusal(handle, Tier::Anonymous) {
                refusal_wait = Some(wait);
                break;
            }
        }
        (principal, refusals, refusal_wait)
    }

    /// Serve one connection to completion: handshake, then the run loop, then
    /// cleanup on disconnect.
    ///
    /// # Errors
    ///
    /// [`SessionError`] on a transport failure, a protocol violation, a
    /// snapshot failure, or a materializer error.
    pub async fn serve<T: Transport>(
        self: Arc<Self>,
        mut transport: T,
    ) -> Result<(), SessionError> {
        let Some(outcome) = self.run_handshake(&mut transport).await? else {
            return Ok(());
        };
        let span = outcome.span.clone();
        self.run_session(transport, outcome).instrument(span).await
    }

    /// The run loop and its teardown, inside the connection's logging context.
    async fn run_session<T: Transport>(
        self: Arc<Self>,
        mut transport: T,
        outcome: HandshakeOutcome<Id, Key>,
    ) -> Result<(), SessionError> {
        let HandshakeOutcome {
            connection_num,
            principal,
            resume_lsn,
            applied_watermark,
            refused_grants,
            span: _,
        } = outcome;
        let session_id = principal.session_id();
        tracing::info!(resume_lsn, "connection established");

        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Outbound>();
        self.register_connection(
            session_id,
            connection_num,
            principal
                .identity()
                .map(|identity| identity.user_id.to_string()),
            &outbound_tx,
        )
        .await;
        // The refusals the handshake collected are tallied here rather than as
        // they happened, because only now is the caller resolved, and only now
        // is the connection registered so a ban can close it.
        let refused = self
            .guard
            .refused_grants(Self::caller(&principal), refused_grants);
        let mut state = SessionState {
            credits: self.config.initial_credits,
            pending: VecDeque::new(),
            subs: HashMap::new(),
            agg_subs: HashMap::new(),
            delta_agg_subs: HashMap::new(),
            outbound: outbound_tx,
            principal,
            pending_header: None,
            session_id,
            applied_watermark,
            resume_lsn,
            closing: refused == Reaction::Close,
        };

        while !state.closing {
            // One task, two arms. The transport arm awaits a whole subscribe,
            // snapshot included, so the outbound arm cannot interleave a live
            // patch into it and a client never sees one before SnapshotEnd.
            // Moving either arm onto its own task breaks that silently.
            tokio::select! {
                incoming = transport.recv() => {
                    match incoming.map_err(transport_err)? {
                        None => break,
                        Some(IncomingFrame::Control(msg)) => {
                            self.handle_control(&mut transport, msg, &mut state).await?;
                        }
                        Some(IncomingFrame::Bulk(BulkMessage::MutationPatch(patch))) => {
                            self.handle_mutation(&mut transport, patch, &mut state).await?;
                        }
                        Some(IncomingFrame::Bulk(_)) => {
                            return Err(SessionError::Protocol(
                                "unexpected bulk frame from client".into(),
                            ));
                        }
                    }
                }
                outbound = outbound_rx.recv() => {
                    let Some(outbound) = outbound else { break };
                    match outbound {
                        Outbound::Live(patch) => {
                            enqueue_and_flush(
                                &mut transport,
                                &mut state.credits,
                                &mut state.pending,
                                BulkMessage::LivePatch(patch),
                            )
                            .await
                            .map_err(transport_err)?;
                        }
                        Outbound::Aggregate(update) => {
                            transport
                                .send_control(ControlMessage::AggregateUpdate(update))
                                .await
                                .map_err(transport_err)?;
                        }
                        Outbound::Fatal(fatal) => {
                            let _ = transport
                                .send_control(ControlMessage::FatalError(fatal))
                                .await;
                            break;
                        }
                        Outbound::Drop => break,
                    }
                }
            }
        }

        self.unregister_connection(session_id, connection_num).await;
        // The connection is the window for a caller with no identity, so its
        // tallies die here and nothing else expires them.
        self.guard.forget_connection(session_id);

        self.unsubscribe_all(state).await;
        tracing::info!("connection closed");
        Ok(())
    }

    /// Drop every route and registration this connection held.
    async fn unsubscribe_all(&self, state: SessionState<Id, Key>) {
        for (consumer_id, sub_id) in state.subs.into_values() {
            self.remove_route(consumer_id).await;
            self.materializer.lock().await.unregister(sub_id);
        }
        for query_id in state.agg_subs.into_values() {
            self.remove_agg_route(query_id).await;
            self.materializer
                .lock()
                .await
                .unregister_aggregate(query_id);
        }
        for (consumer_id, sub_id) in state.delta_agg_subs.into_values() {
            self.remove_delta_agg_route(consumer_id).await;
            self.materializer
                .lock()
                .await
                .unregister_delta_aggregate(consumer_id, sub_id);
        }
    }

    async fn handle_control<T: Transport>(
        &self,
        transport: &mut T,
        msg: ControlMessage,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        match msg {
            ControlMessage::Subscribe(sub) => self.handle_subscribe(transport, sub, state).await,
            ControlMessage::Unsubscribe(unsub) => {
                if let Some((consumer_id, sub_id)) = state.subs.remove(&unsub.sub_id) {
                    self.remove_route(consumer_id).await;
                    self.materializer.lock().await.unregister(sub_id);
                }
                if let Some(query_id) = state.agg_subs.remove(&unsub.sub_id) {
                    self.remove_agg_route(query_id).await;
                    self.materializer
                        .lock()
                        .await
                        .unregister_aggregate(query_id);
                }
                if let Some((consumer_id, sub_id)) = state.delta_agg_subs.remove(&unsub.sub_id) {
                    self.remove_delta_agg_route(consumer_id).await;
                    self.materializer
                        .lock()
                        .await
                        .unregister_delta_aggregate(consumer_id, sub_id);
                }
                Ok(())
            }
            ControlMessage::Ping(ping) => transport
                .send_control(ControlMessage::Pong(Pong { nonce: ping.nonce }))
                .await
                .map_err(transport_err),
            ControlMessage::AckCredits(ack) => {
                state.credits = state.credits.saturating_add(ack.credits);
                flush(transport, &mut state.credits, &mut state.pending)
                    .await
                    .map_err(transport_err)
            }
            ControlMessage::Handshake(_) => {
                let _ = transport
                    .send_control(ControlMessage::FatalError(FatalError::new(
                        FatalErrorReason::ProtocolViolation {
                            detail: "duplicate handshake".into(),
                        },
                    )))
                    .await;
                Err(SessionError::Protocol("duplicate handshake".into()))
            }
            // Announce a mutation upload. The paired patch follows on the bulk
            // channel and completes the write path.
            ControlMessage::MutationHeader(header) => {
                state.pending_header = Some(header);
                Ok(())
            }
            // Server-origin frames received from a client are ignored.
            _ => Ok(()),
        }
    }

    /// Pair a `MutationPatch` with its header, authorize, conflict-check, and
    /// apply. A durable apply (and any replay of one) is confirmed with
    /// [`MutationApplied`], failures reply with their dedicated messages, and
    /// the data itself flows back as the CDC echo.
    async fn handle_mutation<T: Transport>(
        &self,
        transport: &mut T,
        patch: MutationPatch,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let client_seq = patch.client_seq;
        let Some(header) = state.pending_header.take() else {
            return Err(SessionError::Protocol(
                "mutation patch arrived without a preceding header".into(),
            ));
        };
        if header.client_seq != client_seq {
            return self
                .reject(
                    transport,
                    client_seq,
                    MutationRejectReason::Other {
                        detail: "mutation header and patch client_seq disagree".into(),
                    },
                )
                .await;
        }
        // Exactly-once: a sequence at or below the durable watermark was
        // already applied (this session or an earlier one). Re-acknowledge
        // so the replaying client retires its pending record.
        if state
            .applied_watermark
            .is_some_and(|watermark| client_seq <= watermark)
        {
            return self.ack(transport, client_seq).await;
        }

        // Parse and classify against the catalog.
        let plan = match self
            .materializer
            .lock()
            .await
            .plan_write(&patch.patchset_zstd)
        {
            Ok(plan) => plan,
            Err(err) => {
                return self
                    .reject(transport, client_seq, reject_reason(&err))
                    .await;
            }
        };

        // Authorize every op, fail closed on a denial or an auth error.
        for op in &plan.ops {
            let row = ValuesRow::new(op.table_id, &op.row);
            let allowed = self
                .auth
                .may_write(&row, &state.principal, op.op)
                .await
                .is_ok_and(Verdict::allowed);
            if !allowed {
                return self.reject_unauthorized(transport, client_seq, state).await;
            }
        }

        // Probe conflicts and apply through the write target, which owns the
        // backend specifics: the Postgres target applies under the user's RLS
        // context so the database gates the write.
        match self
            .target
            .commit(
                &state.principal,
                &plan,
                &patch.patchset_zstd,
                state.session_id,
                client_seq,
            )
            .await
        {
            Ok(WriteOutcome::Applied) => {
                state.applied_watermark = Some(client_seq);
                self.ack(transport, client_seq).await
            }
            Ok(WriteOutcome::Conflict { table, server_row }) => {
                transport
                    .send_control(ControlMessage::MutationConflict(MutationConflict {
                        client_seq,
                        table,
                        server_row,
                    }))
                    .await
                    .map_err(transport_err)?;
                Ok(())
            }
            Err(WriteError::Unauthorized) => {
                self.reject_unauthorized(transport, client_seq, state).await
            }
            Err(WriteError::Materializer(err)) => {
                self.reject(transport, client_seq, reject_reason(&err))
                    .await
            }
            Err(WriteError::Backend(detail)) => {
                self.reject(
                    transport,
                    client_seq,
                    MutationRejectReason::Other { detail },
                )
                .await
            }
        }
    }

    /// Refuse one write the policy rejected, and report it as an abuse signal.
    ///
    /// Naming a row and being told no is the phase's definition of a signal.
    /// This is the one signal no rate limit sits above, so its threshold does
    /// all its own work.
    async fn reject_unauthorized<T: Transport>(
        &self,
        transport: &mut T,
        client_seq: u64,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let reaction = self.guard.rejected_write(Self::caller(&state.principal));
        if reaction == Reaction::Close {
            state.closing = true;
        }
        self.reject(transport, client_seq, MutationRejectReason::Unauthorized)
            .await
    }

    async fn reject<T: Transport>(
        &self,
        transport: &mut T,
        client_seq: u64,
        reason: MutationRejectReason,
    ) -> Result<(), SessionError> {
        transport
            .send_control(ControlMessage::MutationReject(MutationReject {
                client_seq,
                reason,
            }))
            .await
            .map_err(transport_err)
    }

    /// Confirm a durably applied sequence, so the client retires the pending
    /// record it would otherwise replay on the next resume.
    async fn ack<T: Transport>(
        &self,
        transport: &mut T,
        client_seq: u64,
    ) -> Result<(), SessionError> {
        transport
            .send_control(ControlMessage::MutationApplied(MutationApplied {
                client_seq,
            }))
            .await
            .map_err(transport_err)
    }

    async fn handle_subscribe<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let tier = Self::principal_tier(&state.principal);
        if let Some(wait) = self.guard.subscription(state.session_id, tier) {
            let retry_after_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
            tracing::warn!(
                sub_id = %sub.sub_id,
                retry_after_ms,
                "subscription refused, rate limit reached"
            );
            transport
                .send_control(ControlMessage::RateLimited(RateLimited {
                    related_to: Some(sub.sub_id),
                    retry_after_ms,
                }))
                .await
                .map_err(transport_err)?;
            return Ok(());
        }
        let consumer_id = self.next_consumer_id();
        let SqliteRegistration {
            registration,
            pg_sql,
        } = match self.materializer.lock().await.register_sqlite(
            consumer_id,
            &sub.spec.query,
            &sub.spec.binds,
        ) {
            Ok(registration) => registration,
            Err(err) => {
                tracing::warn!(sub_id = %sub.sub_id, error = %err, "subscription registration refused");
                // Naming something that does not resolve is one of the four
                // abuse signals. The snapshot failure below is not: there the
                // table exists and the read failed, which says nothing about
                // what the caller named.
                let reaction = self
                    .guard
                    .unresolvable_subscription(Self::caller(&state.principal));
                if reaction == Reaction::Close {
                    state.closing = true;
                }
                transport
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(sub.sub_id),
                        detail: SUBSCRIPTION_REFUSED.to_owned(),
                    }))
                    .await
                    .map_err(transport_err)?;
                return Ok(());
            }
        };

        match registration {
            Registration::Row(sub_id) => {
                let sub_label = sub.sub_id.clone();
                let reg = RowRegistration {
                    consumer_id,
                    sub_id,
                    pg_sql,
                };
                match self.subscribe_row(transport, sub, state, reg).await {
                    // A snapshot failure is scoped to this one subscription:
                    // the registration is rolled back and the session (with
                    // every sibling subscription) stays alive. Transport and
                    // oplog failures stay fatal.
                    Err(SessionError::Snapshot(detail)) => {
                        tracing::warn!(sub_id = %sub_label, error = %detail, "snapshot failed");
                        state.subs.remove(&sub_label);
                        self.remove_route(consumer_id).await;
                        self.materializer.lock().await.unregister(sub_id);
                        transport
                            .send_control(ControlMessage::NonFatalError(NonFatalError {
                                related_to: Some(sub_label),
                                detail: SUBSCRIPTION_REFUSED.to_owned(),
                            }))
                            .await
                            .map_err(transport_err)?;
                        Ok(())
                    }
                    other => other,
                }
            }
            Registration::Aggregate(capture) => {
                self.subscribe_aggregate(transport, sub, state, capture)
                    .await
            }
            Registration::DeltaAggregate(capture) => {
                self.subscribe_delta_aggregate(transport, sub, state, capture)
                    .await
            }
        }
    }

    /// Deliver a row subscription, by snapshot or by oplog catchup.
    ///
    /// A fresh session snapshots. A resuming session (nonzero `resume_lsn`)
    /// whose cursor is still inside the retained window catches up from the
    /// oplog instead of re-snapshotting. One outside the window snapshots
    /// afresh, and the resync notice goes out with the new data rather than
    /// here, so a failing read reads like any other refusal and costs the
    /// client nothing.
    async fn subscribe_row<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
        reg: RowRegistration,
    ) -> Result<(), SessionError> {
        let mut resync = None;
        if state.resume_lsn != 0 {
            let min = self.oplog.min_lsn().await.map_err(oplog_err)?;
            let current = self.oplog.current_lsn().await.map_err(oplog_err)?;
            match catchup_decision(state.resume_lsn, min, current) {
                CatchupDecision::Catchup => {
                    return self.catch_up_row(transport, sub, state, &reg).await;
                }
                CatchupDecision::FullResync => {
                    resync = Some(FullResyncReason::CursorOutsideRetention);
                }
            }
        }
        self.snapshot_row(transport, sub, state, &reg, resync).await
    }

    /// Install the live route and record the subscription, so `dispatch_event`
    /// starts delivering to this consumer.
    ///
    /// Both row paths call this before reading anything. Until the route
    /// exists every patch produced for the consumer is discarded, and the
    /// snapshot read plus its bulk transfer is long enough to lose commits.
    async fn attach_row_route(
        &self,
        sub_label: &str,
        state: &mut SessionState<Id, Key>,
        reg: &RowRegistration,
    ) {
        self.add_route(
            reg.consumer_id,
            Route {
                session_key: state.session_id.as_u64_key(),
                sub_id: reg.sub_id,
                label: sub_label.to_owned(),
                tx: state.outbound.clone(),
                principal: Arc::clone(&state.principal),
            },
        )
        .await;
        state
            .subs
            .insert(sub_label.to_owned(), (reg.consumer_id, reg.sub_id));
    }

    /// Snapshot a row subscription: route first, then read, then resync
    /// notice, begin, patch, end.
    ///
    /// Live delivery runs throughout the snapshot, so a change committed while
    /// it is in flight reaches the client as a patch queued behind
    /// `SnapshotEnd`. Such a patch may repeat a row the snapshot already
    /// carries, which is harmless: patches arrive in commit order, so the last
    /// one applied for a row is that row's current value. Filtering the
    /// overlap by LSN was considered and rejected, see `04-subscriptions.md`.
    ///
    /// No frame goes out until the read succeeds. A `SnapshotBegin` or a
    /// `FullResyncRequired` ahead of a failing read would mark the refusal as
    /// one that passed registration, and a refusal must not vary by cause.
    /// The resync notice is also what makes the client discard the rows it
    /// holds, so it must not go out before the replacement data exists.
    async fn snapshot_row<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
        reg: &RowRegistration,
        resync: Option<FullResyncReason>,
    ) -> Result<(), SessionError> {
        self.attach_row_route(&sub.sub_id, state, reg).await;
        let snapshot = self
            .snapshot_source
            .snapshot(&reg.pg_sql, &sub.spec.binds, &state.principal)
            .await
            .map_err(|err| SessionError::Snapshot(err.to_string()))?;
        if let Some(reason) = resync {
            transport
                .send_control(ControlMessage::FullResyncRequired(FullResyncRequired {
                    sub_id: sub.sub_id.clone(),
                    reason,
                }))
                .await
                .map_err(transport_err)?;
        }
        transport
            .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                sub_id: sub.sub_id.clone(),
                priority: sub.spec.priority,
            }))
            .await
            .map_err(transport_err)?;
        let payload = compress(&snapshot.patchset)?;
        enqueue_and_flush(
            transport,
            &mut state.credits,
            &mut state.pending,
            BulkMessage::SnapshotPatch(SnapshotPatch::new(sub.sub_id.clone(), payload)),
        )
        .await
        .map_err(transport_err)?;
        transport
            .send_control(ControlMessage::SnapshotEnd(SnapshotEnd {
                sub_id: sub.sub_id,
                cursor: snapshot.cursor,
            }))
            .await
            .map_err(transport_err)?;
        Ok(())
    }

    /// Catch a resuming row subscription up from the oplog.
    ///
    /// Registers the route first, so live events for LSNs past the watermark
    /// queue behind the catchup (the run loop is blocked here until this
    /// returns, so nothing is delivered meanwhile), then replays each retained
    /// entry the subscription matches as a `LivePatch` carrying that entry's
    /// cursor, in the live-path format. Entries past the pre-catchup watermark
    /// are skipped because the live path will deliver them, so replay and live
    /// delivery never double up. The auth read filter runs per client, but a
    /// delete tombstone replays regardless so a client drops a row it may still
    /// hold locally.
    async fn catch_up_row<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
        reg: &RowRegistration,
    ) -> Result<(), SessionError> {
        self.attach_row_route(&sub.sub_id, state, reg).await;

        // Watermark just after the route exists. An entry at or below it was
        // appended before this consumer could receive live delivery, so
        // replaying it cannot duplicate a live patch.
        let ceiling = self
            .oplog
            .current_lsn()
            .await
            .map_err(oplog_err)?
            .unwrap_or(0);
        let entries = self
            .oplog
            .entries_since(state.resume_lsn)
            .await
            .map_err(oplog_err)?;
        // One watcher, this session's caller, so the buffer is one verdict and
        // is reused across the whole replay.
        let watchers = [Arc::clone(&state.principal)];
        let mut verdicts = Vec::new();
        for record in entries {
            if record.lsn() > ceiling {
                continue;
            }
            let matched = {
                self.materializer
                    .lock()
                    .await
                    .match_row_consumers(record.event())?
                    .contains(&reg.consumer_id)
            };
            if !matched {
                continue;
            }
            // A delete or a truncate has no post-image and so no question, and
            // replays regardless, which is what lets a client drop a row it may
            // still hold.
            if let Some(row) = EventRow::current(record.event(), self.catalog.as_ref()) {
                Verdict::reset(&mut verdicts, watchers.len());
                let _ = self.auth.may_see(&row, &watchers, &mut verdicts).await;
                if !verdicts.first().copied().unwrap_or_default().allowed() {
                    continue;
                }
            }
            let payload = {
                self.materializer
                    .lock()
                    .await
                    .encode_patch(record.event())?
            };
            let cursor = record.lsn().to_be_bytes().to_vec();
            {
                self.materializer.lock().await.advance_cursor(
                    state.session_id.as_u64_key(),
                    reg.sub_id,
                    &cursor,
                )?;
            }
            let live = LivePatch::new(sub.sub_id.clone(), Cursor::new(cursor), payload);
            enqueue_and_flush(
                transport,
                &mut state.credits,
                &mut state.pending,
                BulkMessage::LivePatch(live),
            )
            .await
            .map_err(transport_err)?;
        }
        Ok(())
    }

    /// Bootstrap a captured aggregate through the connector, deliver its initial
    /// value, and route future updates.
    async fn subscribe_aggregate<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
        capture: crate::materializer::AggregateCapture,
    ) -> Result<(), SessionError> {
        let value = match self
            .connector
            .execute_scalar(&capture.sql, capture.kind, &())
            .await
        {
            Ok((value, _lsn)) => value,
            Err(err) => {
                tracing::warn!(sub_id = %sub.sub_id, error = %err, "aggregate bootstrap failed");
                self.materializer
                    .lock()
                    .await
                    .unregister_aggregate(capture.query_id);
                transport
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(sub.sub_id),
                        detail: SUBSCRIPTION_REFUSED.to_owned(),
                    }))
                    .await
                    .map_err(transport_err)?;
                return Ok(());
            }
        };
        let result_json = value_to_json(&value);
        {
            self.materializer
                .lock()
                .await
                .install_scalar(capture.query_id, value);
        }

        self.add_agg_route(
            capture.query_id,
            AggRoute {
                label: sub.sub_id.clone(),
                tx: state.outbound.clone(),
            },
        )
        .await;
        state.agg_subs.insert(sub.sub_id.clone(), capture.query_id);
        transport
            .send_control(ControlMessage::AggregateUpdate(AggregateUpdate {
                sub_id: sub.sub_id,
                group_key: None,
                result_json,
                is_full_result: true,
            }))
            .await
            .map_err(transport_err)?;
        Ok(())
    }

    /// Seed a delta aggregate through the connector, deliver its initial value,
    /// and route future folded updates keyed by consumer id.
    async fn subscribe_delta_aggregate<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
        capture: DeltaAggregateCapture,
    ) -> Result<(), SessionError> {
        let row = match self
            .connector
            .execute_scalar_row(&capture.bootstrap.sql, &capture.bootstrap.kinds, &())
            .await
        {
            Ok((row, _lsn)) => row,
            Err(err) => {
                tracing::warn!(sub_id = %sub.sub_id, error = %err, "delta aggregate bootstrap failed");
                self.materializer
                    .lock()
                    .await
                    .unregister_delta_aggregate(capture.consumer_id, capture.subscription_id);
                transport
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(sub.sub_id),
                        detail: SUBSCRIPTION_REFUSED.to_owned(),
                    }))
                    .await
                    .map_err(transport_err)?;
                return Ok(());
            }
        };
        let acc = AggAccumulator::seed_from_row(&capture.spec, &row);
        let result_json = agg_value_to_json(acc.value());
        {
            self.materializer.lock().await.install_aggregate(
                capture.consumer_id,
                capture.spec,
                acc,
            );
        }

        self.add_delta_agg_route(
            capture.consumer_id,
            AggRoute {
                label: sub.sub_id.clone(),
                tx: state.outbound.clone(),
            },
        )
        .await;
        state.delta_agg_subs.insert(
            sub.sub_id.clone(),
            (capture.consumer_id, capture.subscription_id),
        );
        transport
            .send_control(ControlMessage::AggregateUpdate(AggregateUpdate {
                sub_id: sub.sub_id,
                group_key: None,
                result_json,
                is_full_result: true,
            }))
            .await
            .map_err(transport_err)?;
        Ok(())
    }
}

/// Send `msg` under flow control: enqueue then drain what the credit window
/// allows, preserving FIFO order.
async fn enqueue_and_flush<T: Transport>(
    transport: &mut T,
    credits: &mut u32,
    pending: &mut VecDeque<BulkMessage>,
    msg: BulkMessage,
) -> Result<(), T::Error> {
    pending.push_back(msg);
    flush(transport, credits, pending).await
}

/// Drain queued bulk frames while credits remain.
async fn flush<T: Transport>(
    transport: &mut T,
    credits: &mut u32,
    pending: &mut VecDeque<BulkMessage>,
) -> Result<(), T::Error> {
    while *credits > 0 {
        let Some(msg) = pending.pop_front() else {
            break;
        };
        transport.send_bulk(msg).await?;
        *credits -= 1;
    }
    Ok(())
}
