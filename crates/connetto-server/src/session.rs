//! Session manager, per-session state machine, the snapshot seam, and the
//! write path.
//!
//! One [`SessionManager`] fronts a shared [`Materializer`], a routing table, an
//! [`AuthPolicy`], and the server's write target. Each connection is driven by
//! [`SessionManager::serve`], which runs the handshake, then a select loop over
//! inbound control frames and outbound live patches. CDC events reach
//! subscribed sessions through [`SessionManager::dispatch_event`].
//!
//! Flow control charges a credit only to bulk-plane frames
//! (`LivePatch`/`SnapshotPatch`), never to control frames, so keepalive can
//! never deadlock on an empty credit window. See
//! `docs/architecture/10-subscription-materializer.md` and `02-protocol.md`.
//!
//! The write path pairs a `MutationHeader` with the `MutationPatch` that follows
//! it, authorizes every op, detects stale-version conflicts, applies the whole
//! changeset in one transaction, and replies only on failure. Success is the CDC
//! echo, so there is no dedicated ack. The Docker-free target is a synchronous
//! SQLite connection; the async Postgres apply lives on the materializer behind
//! the `pg-async` feature.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use connetto_core::auth::AuthContext;
use connetto_core::messages::{
    AggregateUpdate, BindValue, BulkMessage, ControlMessage, FatalError, FatalErrorReason,
    FullResyncReason, FullResyncRequired, HandshakeAck, LivePatch, MutationApplied,
    MutationConflict, MutationHeader, MutationPatch, MutationReject, MutationRejectReason,
    NonFatalError, Pong, SnapshotBegin, SnapshotEnd, SnapshotPatch, Subscribe,
};
use connetto_core::traits::{AuthPolicy, IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION, SchemaVersion};
use subql::backend::{CdcEvent, Postgres, ScalarKind, Value as PgValue};
use subql::reexec::{AsyncConnector, Snapshot as ConnectorRead};
use subql::{AggAccumulator, CdcSource, ChangeEvent, PgLsn, SubscriptionId};
use tokio::sync::{Mutex, mpsc};

use crate::materializer::{
    DeltaAggregateCapture, Materializer, MaterializerError, Registration, SqliteRegistration,
    agg_value_to_json, compress, value_to_json,
};
use crate::oplog::{CatchupDecision, InMemoryOplog, Oplog, catchup_decision};
use crate::write_target::{WriteError, WriteOutcome, WriteTarget};

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
/// `auth` context lets the implementation run the read under the requesting
/// user's Row-Level Security so the snapshot already excludes rows the user
/// cannot see.
#[allow(async_fn_in_trait)]
pub trait SnapshotSource: Send + Sync {
    /// Snapshot-source error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// Produce the initial snapshot for `select_sql`, authorized as `auth`.
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
        auth: &AuthContext,
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
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Delivery credits granted to the server at handshake.
    pub initial_credits: u32,
    /// Schema version advertised in the handshake ack.
    pub schema_version: SchemaVersion,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            initial_credits: 64,
            schema_version: SchemaVersion::default(),
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
}

/// Route from a `subql` consumer id back to the owning session's outbound
/// channel.
#[derive(Clone)]
struct Route {
    session_id: u64,
    sub_id: SubscriptionId,
    label: String,
    tx: mpsc::UnboundedSender<Outbound>,
    /// The subscribing session's identity, consulted per event for the read
    /// filter before a live patch is delivered.
    auth_ctx: AuthContext,
}

/// Route from an aggregate subscription (re-execution query or delta aggregate)
/// to its session's outbound channel.
#[derive(Clone)]
struct AggRoute {
    label: String,
    tx: mpsc::UnboundedSender<Outbound>,
}

/// What a completed handshake establishes for the run loop.
struct HandshakeOutcome {
    session_num: u64,
    auth_ctx: AuthContext,
    resume_lsn: u64,
    client_id: String,
    applied_watermark: Option<u64>,
}

/// Mutable per-session state carried through the run loop.
struct SessionState {
    credits: u32,
    pending: VecDeque<BulkMessage>,
    subs: HashMap<String, (u64, SubscriptionId)>,
    agg_subs: HashMap<String, u64>,
    /// Delta aggregate subscriptions by client label: consumer id and engine
    /// subscription id, both needed to tear the subscription down.
    delta_agg_subs: HashMap<String, (u64, SubscriptionId)>,
    outbound: mpsc::UnboundedSender<Outbound>,
    /// Session identity, established at handshake and consulted per write.
    auth_ctx: AuthContext,
    /// The `MutationHeader` awaiting its paired `MutationPatch`.
    pending_header: Option<MutationHeader>,
    /// The client id from the handshake, keying the durable mutation
    /// watermark together with the auth identity.
    client_id: String,
    /// Highest `client_seq` durably applied for this client identity, from
    /// the write target at handshake and advanced per commit. A replayed
    /// sequence at or below it is re-acknowledged, never re-applied.
    applied_watermark: Option<u64>,
    /// Resume LSN decoded from the handshake cursor. 0 means a fresh session, so
    /// every re-declared subscription replays from here on reconnect.
    resume_lsn: u64,
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
/// write path against an [`AuthPolicy`], a SQLite write target, and a
/// re-execution connector for aggregate subscriptions.
pub struct SessionManager<Snap, Auth, C = NoConnector, O = InMemoryOplog>
where
    Snap: SnapshotSource,
    Auth: AuthPolicy + Send + Sync,
    C: AsyncConnector<Backend = Postgres, Checkpoint = PgLsn, AuthContext = ()> + Send + Sync,
    O: Oplog,
{
    materializer: Arc<Mutex<Materializer>>,
    routes: Mutex<HashMap<u64, Route>>,
    agg_routes: Mutex<HashMap<u64, AggRoute>>,
    /// Delta aggregate routes keyed by consumer id. Kept separate from
    /// `agg_routes` (keyed by re-execution query id) because the two u64
    /// keyspaces are distinct and could otherwise collide.
    delta_agg_routes: Mutex<HashMap<u64, AggRoute>>,
    snapshot_source: Snap,
    auth: Auth,
    connector: C,
    oplog: O,
    target: WriteTarget,
    next_session: AtomicU64,
    next_consumer: AtomicU64,
    config: SessionConfig,
}

impl<Snap, Auth> SessionManager<Snap, Auth, NoConnector, InMemoryOplog>
where
    Snap: SnapshotSource,
    Auth: AuthPolicy + Send + Sync,
{
    /// Build a manager with no re-execution connector and a default in-memory
    /// oplog.
    ///
    /// Aggregate subscriptions need a connector; use
    /// [`with_connector`](Self::with_connector) to supply one. Reconnect uses a
    /// default [`InMemoryOplog`]; use [`with_oplog`](Self::with_oplog) for another.
    #[must_use]
    pub fn new(
        materializer: Materializer,
        snapshot_source: Snap,
        auth: Auth,
        target: impl Into<WriteTarget>,
        config: SessionConfig,
    ) -> Arc<Self> {
        Self::with_oplog(
            materializer,
            snapshot_source,
            auth,
            NoConnector,
            InMemoryOplog::default(),
            target,
            config,
        )
    }
}

impl<Snap, Auth, C> SessionManager<Snap, Auth, C, InMemoryOplog>
where
    Snap: SnapshotSource,
    Auth: AuthPolicy + Send + Sync,
    C: AsyncConnector<Backend = Postgres, Checkpoint = PgLsn, AuthContext = ()> + Send + Sync,
    C::Error: core::fmt::Display,
{
    /// Build a manager with a re-execution connector and a default in-memory
    /// oplog. Use [`with_oplog`](Self::with_oplog) to supply another oplog.
    #[must_use]
    pub fn with_connector(
        materializer: Materializer,
        snapshot_source: Snap,
        auth: Auth,
        connector: C,
        target: impl Into<WriteTarget>,
        config: SessionConfig,
    ) -> Arc<Self> {
        Self::with_oplog(
            materializer,
            snapshot_source,
            auth,
            connector,
            InMemoryOplog::default(),
            target,
            config,
        )
    }
}

impl<Snap, Auth, C, O> SessionManager<Snap, Auth, C, O>
where
    Snap: SnapshotSource,
    Auth: AuthPolicy + Send + Sync,
    C: AsyncConnector<Backend = Postgres, Checkpoint = PgLsn, AuthContext = ()> + Send + Sync,
    C::Error: core::fmt::Display,
    O: Oplog,
{
    /// Build a manager with an explicit re-execution connector and oplog.
    #[must_use]
    pub fn with_oplog(
        materializer: Materializer,
        snapshot_source: Snap,
        auth: Auth,
        connector: C,
        oplog: O,
        target: impl Into<WriteTarget>,
        config: SessionConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            materializer: Arc::new(Mutex::new(materializer)),
            routes: Mutex::new(HashMap::new()),
            agg_routes: Mutex::new(HashMap::new()),
            delta_agg_routes: Mutex::new(HashMap::new()),
            snapshot_source,
            auth,
            connector,
            oplog,
            target: target.into(),
            next_session: AtomicU64::new(1),
            next_consumer: AtomicU64::new(1),
            config,
        })
    }

    fn next_session_id(&self) -> u64 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }

    fn next_consumer_id(&self) -> u64 {
        self.next_consumer.fetch_add(1, Ordering::Relaxed)
    }

    async fn add_route(&self, consumer_id: u64, route: Route) {
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
        let dispatched = { self.materializer.lock().await.dispatch(event)? };

        // Record the event in the oplog before fan-out. The append is per event,
        // not per consumer, since reconnect catchup re-filters per client.
        let record = { self.materializer.lock().await.oplog_record(event) };
        // The event's (table, primary key, is-delete) for the per-consumer read
        // filter below.
        let identity = record
            .as_ref()
            .map(|r| (r.table().to_owned(), r.pk().to_vec(), r.is_tombstone()));
        if let Some(record) = record {
            self.oplog.append(record).await.map_err(oplog_err)?;
        }

        for patch in dispatched.patches {
            let route = { self.routes.lock().await.get(&patch.consumer_id).cloned() };
            let Some(route) = route else { continue };
            // Read filter: deliver only rows the session may see. A delete
            // replays regardless (a tombstone), so a client drops a row it may
            // still hold locally even after it can no longer see it.
            if let Some((table, pk, is_delete)) = identity.as_ref()
                && !is_delete
                && !self
                    .auth
                    .can_read(&route.auth_ctx, table, pk)
                    .await
                    .unwrap_or(false)
            {
                continue;
            }
            {
                self.materializer.lock().await.advance_cursor(
                    route.session_id,
                    route.sub_id,
                    &patch.cursor,
                )?;
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
    ) -> Result<Option<HandshakeOutcome>, SessionError> {
        let handshake = match transport.recv().await.map_err(transport_err)? {
            Some(IncomingFrame::Control(ControlMessage::Handshake(hs))) => hs,
            Some(_) => return Err(SessionError::Protocol("expected handshake first".into())),
            None => return Ok(None),
        };
        if handshake.protocol_version != PROTOCOL_VERSION {
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

        // Identity for this session. Token validation (JWT decode or session
        // lookup) lands with `OpenFGA` and `rls2fga`; for now the client id is the
        // identity carried into the auth policy.
        let auth_ctx = AuthContext::new(handshake.client_id.clone());

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
            .last_applied(&auth_ctx, &handshake.client_id)
            .await
            .map_err(|err| SessionError::WriteTarget(err.detail()))?;

        let session_num = self.next_session_id();
        transport
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                session_id: format!("session-{session_num}"),
                session_token: format!("token-{session_num}"),
                current_cursor,
                schema_version: self.config.schema_version.clone(),
                initial_credits: self.config.initial_credits,
                last_applied_seq: applied_watermark,
            }))
            .await
            .map_err(transport_err)?;
        Ok(Some(HandshakeOutcome {
            session_num,
            auth_ctx,
            resume_lsn,
            client_id: handshake.client_id,
            applied_watermark,
        }))
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
        let Some(HandshakeOutcome {
            session_num,
            auth_ctx,
            resume_lsn,
            client_id,
            applied_watermark,
        }) = self.run_handshake(&mut transport).await?
        else {
            return Ok(());
        };

        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Outbound>();
        let mut state = SessionState {
            credits: self.config.initial_credits,
            pending: VecDeque::new(),
            subs: HashMap::new(),
            agg_subs: HashMap::new(),
            delta_agg_subs: HashMap::new(),
            outbound: outbound_tx,
            auth_ctx,
            pending_header: None,
            client_id,
            applied_watermark,
            resume_lsn,
        };

        loop {
            tokio::select! {
                incoming = transport.recv() => {
                    match incoming.map_err(transport_err)? {
                        None => break,
                        Some(IncomingFrame::Control(msg)) => {
                            self.handle_control(&mut transport, msg, &mut state, session_num).await?;
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
                    }
                }
            }
        }

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
        Ok(())
    }

    async fn handle_control<T: Transport>(
        &self,
        transport: &mut T,
        msg: ControlMessage,
        state: &mut SessionState,
        session_num: u64,
    ) -> Result<(), SessionError> {
        match msg {
            ControlMessage::Subscribe(sub) => {
                self.handle_subscribe(transport, sub, state, session_num)
                    .await
            }
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
        state: &mut SessionState,
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
            let allowed = self
                .auth
                .can_write(&state.auth_ctx, &op.table, &op.pk, op.op)
                .await
                .unwrap_or(false);
            if !allowed {
                return self
                    .reject(transport, client_seq, MutationRejectReason::Unauthorized)
                    .await;
            }
        }

        // Probe conflicts and apply through the write target, which owns the
        // backend specifics: the Postgres target applies under the user's RLS
        // context so the database gates the write.
        match self
            .target
            .commit(
                &self.materializer,
                &state.auth_ctx,
                &plan,
                &patch.patchset_zstd,
                &state.client_id,
                client_seq,
            )
            .await
        {
            Ok(WriteOutcome::Applied) => {
                state.applied_watermark = Some(client_seq);
                self.ack(transport, client_seq).await
            }
            Ok(WriteOutcome::Conflict {
                table,
                server_updated_at,
                server_row_json,
            }) => {
                transport
                    .send_control(ControlMessage::MutationConflict(MutationConflict {
                        client_seq,
                        table,
                        server_updated_at,
                        server_row_json,
                    }))
                    .await
                    .map_err(transport_err)?;
                Ok(())
            }
            Err(WriteError::Unauthorized) => {
                self.reject(transport, client_seq, MutationRejectReason::Unauthorized)
                    .await
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
        state: &mut SessionState,
        session_num: u64,
    ) -> Result<(), SessionError> {
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
                transport
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(sub.sub_id),
                        detail: format!("subscription rejected: {err}"),
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
                match self
                    .subscribe_row(transport, sub, state, session_num, reg)
                    .await
                {
                    // A snapshot failure is scoped to this one subscription:
                    // the registration is rolled back and the session (with
                    // every sibling subscription) stays alive. Transport and
                    // oplog failures stay fatal.
                    Err(SessionError::Snapshot(detail)) => {
                        self.remove_route(consumer_id).await;
                        self.materializer.lock().await.unregister(sub_id);
                        transport
                            .send_control(ControlMessage::NonFatalError(NonFatalError {
                                related_to: Some(sub_label),
                                detail: format!("snapshot failed: {detail}"),
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
    /// oplog instead of re-snapshotting; one outside the window is told to
    /// full-resync and then snapshots.
    async fn subscribe_row<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState,
        session_num: u64,
        reg: RowRegistration,
    ) -> Result<(), SessionError> {
        if state.resume_lsn != 0 {
            let min = self.oplog.min_lsn().await.map_err(oplog_err)?;
            let current = self.oplog.current_lsn().await.map_err(oplog_err)?;
            match catchup_decision(state.resume_lsn, min, current) {
                CatchupDecision::Catchup => {
                    return self
                        .catch_up_row(transport, sub, state, session_num, &reg)
                        .await;
                }
                CatchupDecision::FullResync => {
                    transport
                        .send_control(ControlMessage::FullResyncRequired(FullResyncRequired {
                            sub_id: sub.sub_id.clone(),
                            reason: FullResyncReason::CursorOutsideRetention,
                        }))
                        .await
                        .map_err(transport_err)?;
                }
            }
        }
        self.snapshot_row(transport, sub, state, session_num, &reg)
            .await
    }

    /// Snapshot a row subscription: begin, patch, end, then route live patches.
    async fn snapshot_row<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState,
        session_num: u64,
        reg: &RowRegistration,
    ) -> Result<(), SessionError> {
        transport
            .send_control(ControlMessage::SnapshotBegin(SnapshotBegin {
                sub_id: sub.sub_id.clone(),
                priority: sub.spec.priority,
            }))
            .await
            .map_err(transport_err)?;
        let snapshot = self
            .snapshot_source
            .snapshot(&reg.pg_sql, &sub.spec.binds, &state.auth_ctx)
            .await
            .map_err(|err| SessionError::Snapshot(err.to_string()))?;
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
                sub_id: sub.sub_id.clone(),
                cursor: snapshot.cursor,
            }))
            .await
            .map_err(transport_err)?;

        self.add_route(
            reg.consumer_id,
            Route {
                session_id: session_num,
                sub_id: reg.sub_id,
                label: sub.sub_id.clone(),
                tx: state.outbound.clone(),
                auth_ctx: state.auth_ctx.clone(),
            },
        )
        .await;
        state.subs.insert(sub.sub_id, (reg.consumer_id, reg.sub_id));
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
        state: &mut SessionState,
        session_num: u64,
        reg: &RowRegistration,
    ) -> Result<(), SessionError> {
        self.add_route(
            reg.consumer_id,
            Route {
                session_id: session_num,
                sub_id: reg.sub_id,
                label: sub.sub_id.clone(),
                tx: state.outbound.clone(),
                auth_ctx: state.auth_ctx.clone(),
            },
        )
        .await;
        state
            .subs
            .insert(sub.sub_id.clone(), (reg.consumer_id, reg.sub_id));

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
            if !record.is_tombstone() {
                let allowed = self
                    .auth
                    .can_read(&state.auth_ctx, record.table(), record.pk())
                    .await
                    .unwrap_or(false);
                if !allowed {
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
                self.materializer
                    .lock()
                    .await
                    .advance_cursor(session_num, reg.sub_id, &cursor)?;
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
        state: &mut SessionState,
        capture: crate::materializer::AggregateCapture,
    ) -> Result<(), SessionError> {
        let value = match self
            .connector
            .execute_scalar(&capture.sql, capture.kind, &())
            .await
        {
            Ok((value, _lsn)) => value,
            Err(err) => {
                self.materializer
                    .lock()
                    .await
                    .unregister_aggregate(capture.query_id);
                transport
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(sub.sub_id),
                        detail: format!("aggregate bootstrap failed: {err}"),
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
        state: &mut SessionState,
        capture: DeltaAggregateCapture,
    ) -> Result<(), SessionError> {
        let row = match self
            .connector
            .execute_scalar_row(&capture.bootstrap.sql, &capture.bootstrap.kinds, &())
            .await
        {
            Ok((row, _lsn)) => row,
            Err(err) => {
                self.materializer
                    .lock()
                    .await
                    .unregister_delta_aggregate(capture.consumer_id, capture.subscription_id);
                transport
                    .send_control(ControlMessage::NonFatalError(NonFatalError {
                        related_to: Some(sub.sub_id),
                        detail: format!("aggregate bootstrap failed: {err}"),
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
