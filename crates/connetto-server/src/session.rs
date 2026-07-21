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

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use connetto_core::auth::AuthContext;
use connetto_core::messages::{
    AggregateUpdate, BulkMessage, ControlMessage, FatalError, FatalErrorReason, HandshakeAck,
    LivePatch, MutationConflict, MutationHeader, MutationPatch, MutationReject,
    MutationRejectReason, NonFatalError, Pong, SnapshotBegin, SnapshotEnd, SnapshotPatch,
    Subscribe,
};
use connetto_core::traits::{AuthPolicy, IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION, SchemaVersion};
use diesel::SqliteConnection;
use subql::backend::{Postgres, ScalarKind, Value as PgValue};
use subql::reexec::{AsyncConnector, Snapshot as ConnectorRead};
use subql::{ChangeEvent, PgLsn, SubscriptionId};
use tokio::sync::{Mutex, mpsc};

use crate::materializer::{
    ConflictProbe, Materializer, MaterializerError, Registration, compress, probe_conflict_sqlite,
    value_to_json,
};

/// Initial rows for a subscription, produced by a [`SnapshotSource`].
pub struct Snapshot {
    /// Raw (uncompressed) insert-patchset bytes for the initial rows.
    pub patchset: Vec<u8>,
    /// Cursor at which the snapshot was read. Live updates strictly greater
    /// than this apply on top on the client.
    pub cursor: Cursor,
}

/// Produces a subscription's initial snapshot.
///
/// Phase 2 delivers whatever this yields. Phase 4 implements it over the
/// re-exec `Connector`: run the subscription's `SELECT` against Postgres at a
/// snapshot LSN and encode the rows into an insert-patchset with
/// `sqlite-diff-rs`. No SQLite lives on the backend in either case.
#[allow(async_fn_in_trait)]
pub trait SnapshotSource: Send + Sync {
    /// Snapshot-source error.
    type Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static;

    /// Produce the initial snapshot for the subscription's `select_sql`.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backend read or encoding failure.
    async fn snapshot(&self, select_sql: &str) -> Result<Snapshot, Self::Error>;
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
            schema_version: SchemaVersion::new("v0", Vec::new()),
        }
    }
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
    /// A materializer operation failed.
    #[error(transparent)]
    Materializer(#[from] MaterializerError),
    /// The peer violated the wire protocol.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// Compressing a bulk payload failed.
    #[error(transparent)]
    Compression(#[from] std::io::Error),
}

fn transport_err<E: core::fmt::Display>(err: E) -> SessionError {
    SessionError::Transport(err.to_string())
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
}

/// Route from a captured aggregate query to its session's outbound channel.
#[derive(Clone)]
struct AggRoute {
    label: String,
    tx: mpsc::UnboundedSender<Outbound>,
}

/// Mutable per-session state carried through the run loop.
struct SessionState {
    credits: u32,
    pending: VecDeque<BulkMessage>,
    subs: HashMap<String, (u64, SubscriptionId)>,
    agg_subs: HashMap<String, u64>,
    outbound: mpsc::UnboundedSender<Outbound>,
    /// Session identity, established at handshake and consulted per write.
    auth_ctx: AuthContext,
    /// The `MutationHeader` awaiting its paired `MutationPatch`.
    pending_header: Option<MutationHeader>,
    /// Sequence numbers already applied, so a replayed upload applies once.
    applied_seqs: HashSet<u64>,
}

/// A shared, synchronous SQLite write target. The server applies mutations and
/// reads current rows for conflict detection through it. `SQLite` stays
/// synchronous; the async Postgres apply lives on the materializer. The lock is
/// never held across an `.await`.
pub type SqliteWriteTarget = Arc<parking_lot::Mutex<SqliteConnection>>;

/// Wrap a SQLite connection as a shared [`SqliteWriteTarget`].
#[must_use]
pub fn sqlite_write_target(conn: SqliteConnection) -> SqliteWriteTarget {
    Arc::new(parking_lot::Mutex::new(conn))
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
pub struct SessionManager<Snap, Auth, C = NoConnector>
where
    Snap: SnapshotSource,
    Auth: AuthPolicy + Send + Sync,
    C: AsyncConnector<Backend = Postgres, Checkpoint = PgLsn, AuthContext = ()> + Send + Sync,
{
    materializer: Arc<Mutex<Materializer>>,
    routes: Mutex<HashMap<u64, Route>>,
    agg_routes: Mutex<HashMap<u64, AggRoute>>,
    snapshot_source: Snap,
    auth: Auth,
    connector: C,
    target: SqliteWriteTarget,
    next_session: AtomicU64,
    next_consumer: AtomicU64,
    config: SessionConfig,
}

impl<Snap, Auth> SessionManager<Snap, Auth, NoConnector>
where
    Snap: SnapshotSource,
    Auth: AuthPolicy + Send + Sync,
{
    /// Build a manager with no re-execution connector.
    ///
    /// Aggregate subscriptions need a connector; use
    /// [`with_connector`](Self::with_connector) to supply one.
    #[must_use]
    pub fn new(
        materializer: Materializer,
        snapshot_source: Snap,
        auth: Auth,
        target: SqliteWriteTarget,
        config: SessionConfig,
    ) -> Arc<Self> {
        Self::with_connector(
            materializer,
            snapshot_source,
            auth,
            NoConnector,
            target,
            config,
        )
    }
}

impl<Snap, Auth, C> SessionManager<Snap, Auth, C>
where
    Snap: SnapshotSource,
    Auth: AuthPolicy + Send + Sync,
    C: AsyncConnector<Backend = Postgres, Checkpoint = PgLsn, AuthContext = ()> + Send + Sync,
    C::Error: core::fmt::Display,
{
    /// Build a manager with a re-execution connector for aggregate subscriptions.
    #[must_use]
    pub fn with_connector(
        materializer: Materializer,
        snapshot_source: Snap,
        auth: Auth,
        connector: C,
        target: SqliteWriteTarget,
        config: SessionConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            materializer: Arc::new(Mutex::new(materializer)),
            routes: Mutex::new(HashMap::new()),
            agg_routes: Mutex::new(HashMap::new()),
            snapshot_source,
            auth,
            connector,
            target,
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

    /// Dispatch one CDC event: fan row patches to sessions, deliver in-process
    /// aggregate changes, and service re-execution triggers through the
    /// connector.
    ///
    /// Locks the materializer only for the synchronous engine calls, never
    /// across a channel send or a connector await.
    ///
    /// # Errors
    ///
    /// [`MaterializerError`] when dispatch, a cursor advance, or an install
    /// fails.
    pub async fn dispatch_event(&self, event: &ChangeEvent) -> Result<(), MaterializerError> {
        let dispatched = { self.materializer.lock().await.dispatch(event)? };

        for patch in dispatched.patches {
            let route = { self.routes.lock().await.get(&patch.consumer_id).cloned() };
            let Some(route) = route else { continue };
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
        Ok(())
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
        let handshake = match transport.recv().await.map_err(transport_err)? {
            Some(IncomingFrame::Control(ControlMessage::Handshake(hs))) => hs,
            Some(_) => return Err(SessionError::Protocol("expected handshake first".into())),
            None => return Ok(()),
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

        let session_num = self.next_session_id();
        transport
            .send_control(ControlMessage::HandshakeAck(HandshakeAck {
                session_id: format!("session-{session_num}"),
                session_token: format!("token-{session_num}"),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: self.config.schema_version.clone(),
                initial_credits: self.config.initial_credits,
            }))
            .await
            .map_err(transport_err)?;

        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Outbound>();
        let mut state = SessionState {
            credits: self.config.initial_credits,
            pending: VecDeque::new(),
            subs: HashMap::new(),
            agg_subs: HashMap::new(),
            outbound: outbound_tx,
            auth_ctx,
            pending_header: None,
            applied_seqs: HashSet::new(),
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
    /// apply. Replies only on failure; success is the CDC echo.
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
        // Idempotency: a replayed sequence is acknowledged silently, not
        // reapplied.
        if state.applied_seqs.contains(&client_seq) {
            return Ok(());
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

        // Conflict-check every version-bearing op against the current server row.
        for op in &plan.ops {
            let Some(conflict) = &op.conflict else {
                continue;
            };
            let probe = {
                let mut conn = self.target.lock();
                probe_conflict_sqlite(conflict, &mut conn)
            };
            match probe {
                Ok(ConflictProbe::Clear) => {}
                Ok(ConflictProbe::Stale(row)) => {
                    let (server_updated_at, server_row_json) = row.map_or_else(
                        || (String::new(), "null".to_owned()),
                        |row| (row.version, row.row_json),
                    );
                    transport
                        .send_control(ControlMessage::MutationConflict(MutationConflict {
                            client_seq,
                            table: conflict.table.clone(),
                            server_updated_at,
                            server_row_json,
                        }))
                        .await
                        .map_err(transport_err)?;
                    return Ok(());
                }
                Err(err) => {
                    return self
                        .reject(transport, client_seq, reject_reason(&err))
                        .await;
                }
            }
        }

        // Apply the whole changeset in one transaction.
        let applied = {
            let materializer = self.materializer.lock().await;
            let mut conn = self.target.lock();
            materializer.apply_diffset(&patch.patchset_zstd, &mut conn)
        };
        match applied {
            Ok(_) => {
                state.applied_seqs.insert(client_seq);
                Ok(())
            }
            Err(err) => {
                self.reject(transport, client_seq, reject_reason(&err))
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

    async fn handle_subscribe<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState,
        session_num: u64,
    ) -> Result<(), SessionError> {
        let consumer_id = self.next_consumer_id();
        let registration = match self
            .materializer
            .lock()
            .await
            .register(consumer_id, &sub.spec.query)
        {
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
                self.subscribe_row(transport, sub, state, session_num, consumer_id, sub_id)
                    .await
            }
            Registration::Aggregate(capture) => {
                self.subscribe_aggregate(transport, sub, state, capture)
                    .await
            }
        }
    }

    /// Deliver a row subscription's snapshot and route its live patches.
    async fn subscribe_row<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState,
        session_num: u64,
        consumer_id: u64,
        sub_id: SubscriptionId,
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
            .snapshot(&sub.spec.query)
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
            consumer_id,
            Route {
                session_id: session_num,
                sub_id,
                label: sub.sub_id.clone(),
                tx: state.outbound.clone(),
            },
        )
        .await;
        state.subs.insert(sub.sub_id, (consumer_id, sub_id));
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
