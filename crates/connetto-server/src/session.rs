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
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use connetto_core::auth::{Principal, Subject};
use connetto_core::messages::{
    AggregateUpdate, BindValue, BulkMessage, ControlMessage, FatalError, FatalErrorReason,
    FullResyncReason, FullResyncRequired, Handshake, HandshakeAck, LivePatch, MembershipOpened,
    MutationApplied, MutationConflict, MutationHeader, MutationPatch, MutationReject,
    MutationRejectReason, NonFatalError, PauseCause, Pong, RateLimited, SUBSCRIPTION_REFUSED,
    SnapshotBegin, SnapshotEnd, SnapshotPatch, Subscribe, SubscriptionSpec,
};
use connetto_core::traits::{HandshakeAuthority, IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION, RetryPolicy, SchemaVersion, SessionId};
use sqlite_diff_rs::{
    DiffOps, Indirect, ParsedDiffSet, PatchDelete, PatchSet, PatchsetOp, TableSchema,
};
use subql::backend::{CdcEvent, Postgres, ScalarKind, Value as PgValue};
use subql::reexec::{AsyncConnector, Snapshot as ConnectorRead};
use subql::visibility::transition::{Transition, TransitionError, Transitions, transitions};
use subql::visibility::{EventRow, RowWrite, Verdict, VisibilityPolicy};
use subql::{
    AggAccumulator, CdcSource, ChangeEvent, DatabaseLike, EventKind, ParserDB, PgLsn,
    SubscriptionId, TableLike,
};
use tokio::sync::{Mutex, mpsc};
use tracing::Instrument;

use crate::abuse::{Caller, Reaction};
use crate::audit::{AuthEvent, AuthOp};
use crate::capability::CapabilityKey;
use crate::counters;
use crate::guard::RequestGuard;
use crate::materializer::{
    DeltaAggregateCapture, MatchedPatch, Materializer, MaterializerError, PlannedWrite,
    Registration, SqliteRegistration, TermMove, TermSeed, agg_value_to_json, compress,
    narrowed_sql, typed_subscriber, value_to_json,
};
use crate::openfga::{GrantHolder, GrantMove};
use crate::oplog::{CatchupDecision, InMemoryOplog, Oplog, catchup_decision};
use crate::reserve::ReaderPermit;
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

/// The caller's own membership rows for a term at registration, read by a
/// [`SnapshotSource`] that can run the seed under the caller's own binding.
pub struct TermSeedRead {
    /// Full membership rows in catalog column order, decoded the same way the
    /// snapshot decodes, so the seed and the snapshot agree by construction.
    pub rows: Vec<Vec<PgValue<Postgres>>>,
    /// Whether the membership table is carried by the publication this source
    /// was configured with, or `None` when it has none to check against.
    pub published: Option<bool>,
}

/// Why a subscription was not registered, beyond the materializer's own
/// refusals. Every cause is answered on the wire with the one fixed
/// `SUBSCRIPTION_REFUSED` detail (R38), so this exists for the structured log.
#[derive(Debug, thiserror::Error)]
enum SubscribeRefusal {
    /// Translation or registration was refused.
    #[error(transparent)]
    Materializer(#[from] MaterializerError),
    /// The seed read failed.
    #[error("the membership seed read failed: {0}")]
    Seed(String),
    /// A membership term filters for a caller, and this one has no identity.
    #[error("a membership term needs an identified caller")]
    Anonymous,
    /// The identity cannot be read at the membership column's kind. A
    /// mistyped subscriber would admit nobody in silence, so it refuses.
    #[error("the caller's identity cannot be read at the membership column's kind")]
    Mistyped,
    /// The membership table is not replicated, so no membership change would
    /// ever move rows and the term would go stale silently.
    #[error(
        "membership table {0} is not carried by the publication, so a membership change would never move rows"
    )]
    Unpublished(String),
    /// The snapshot source has no publication to verify against.
    #[error(
        "no publication is configured on the snapshot source, so a membership table cannot be verified as replicated"
    )]
    NoPublication,
    /// The snapshot source cannot run a seed read.
    #[error("this snapshot source cannot seed a membership term")]
    Unseedable,
}

/// The server-chosen label of the membership subscription over `member_table`
/// (R27 decision 7). Deterministic, so a term registering again on the same
/// session finds the one already open instead of opening a second, and the
/// prefix is a reserved wire namespace the client can classify by.
fn membership_label(member_table: &str) -> String {
    format!("connetto-membership:{member_table}")
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

    /// Read the caller's own membership rows for a term at registration:
    /// `seed_sql` run as `caller` under the same binding the snapshot uses,
    /// plus whether `member_table` is carried by the configured publication.
    ///
    /// The default cannot seed and returns `Ok(None)`, which refuses the
    /// registration: a term served without its seed admits nobody in silence,
    /// and a membership table outside the publication never narrows.
    ///
    /// # Errors
    ///
    /// Implementation-defined: a backend read or decode failure.
    async fn term_seed(
        &self,
        seed_sql: &str,
        member_table: &str,
        caller: &Principal<Id, Key>,
    ) -> Result<Option<TermSeedRead>, Self::Error> {
        let _ = (seed_sql, member_table, caller);
        Ok(None)
    }
}

/// The products of registering one row subscription, as its delivery needs
/// them: the engine ids plus the Postgres translation of the query, which
/// the snapshot read uses instead of the client dialect.
#[derive(Clone)]
struct RowRegistration {
    /// The engine consumer bound to this subscription.
    consumer_id: u64,
    /// The engine subscription id.
    sub_id: SubscriptionId,
    /// The subscription query reverse translated to Postgres.
    pg_sql: String,
    /// The membership tables the subscription's terms watch, empty for a
    /// filter naming none (R27).
    member_tables: std::sync::Arc<[(String, String)]>,
}

/// Per-session server configuration.
///
/// Limits and abuse thresholds live on [`RequestGuard`] rather than here,
/// because one instance of it is shared with the auth service and this type is
/// cloned per manager.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Delivery credits granted to the server at handshake.
    initial_credits: u32,
    /// Schema version advertised in the handshake ack, or `None` to declare no
    /// version (staleness detection off for every client).
    schema_version: Option<SchemaVersion>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            initial_credits: 64,
            schema_version: None,
        }
    }
}

impl SessionConfig {
    /// Returns the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the delivery credits granted at handshake.
    #[must_use]
    pub const fn with_initial_credits(mut self, initial_credits: u32) -> Self {
        self.initial_credits = initial_credits;
        self
    }

    /// Sets the schema version advertised in the handshake ack.
    #[must_use]
    pub fn with_schema_version(mut self, schema_version: Option<SchemaVersion>) -> Self {
        self.schema_version = schema_version;
        self
    }

    /// Delivery credits granted at handshake.
    #[must_use]
    pub fn initial_credits(&self) -> u32 {
        self.initial_credits
    }
}

/// Backoff policy for reconnecting a dropped CDC stream.
///
/// [`SessionManager::ingest_with_reconnect`] reconnects the source after the
/// stream fails, resuming from the replication slot's confirmed position.
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    /// Shared exponential backoff parameters.
    retry: connetto_core::RetryPolicy,
    /// A connection that stayed up at least this long is treated as healthy, so
    /// the backoff resets after it drops.
    healthy_after: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            retry: connetto_core::RetryPolicy::new().with_max_backoff(Duration::from_secs(30)),
            healthy_after: Duration::from_secs(10),
        }
    }
}

impl ReconnectPolicy {
    /// Returns the defaults: 200 ms initial backoff, 30 s ceiling, retry forever,
    /// 10 s healthy threshold.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the backoff before the first retry.
    #[must_use]
    pub fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.retry = self.retry.with_initial_backoff(initial_backoff);
        self
    }

    /// Sets the ceiling for the exponential backoff.
    #[must_use]
    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.retry = self.retry.with_max_backoff(max_backoff);
        self
    }

    /// Sets the attempt limit. `None` retries forever.
    #[must_use]
    pub fn with_max_attempts(mut self, max_attempts: Option<u32>) -> Self {
        self.retry = self.retry.with_max_attempts(max_attempts);
        self
    }

    /// Sets the minimum uptime for a connection to be treated as healthy.
    #[must_use]
    pub const fn with_healthy_after(mut self, healthy_after: Duration) -> Self {
        self.healthy_after = healthy_after;
        self
    }

    /// Attempt limit. `None` retries forever.
    #[must_use]
    pub fn max_attempts(&self) -> Option<u32> {
        self.retry.max_attempts()
    }

    /// Backoff before the `attempt`-th retry (1-based), delegating to
    /// [`RetryPolicy::backoff`](connetto_core::RetryPolicy::backoff).
    fn backoff(&self, attempt: u32) -> Duration {
        self.retry.backoff(attempt)
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
    /// The authorization service was unreachable for one event, so the ingest
    /// loop retries after `backoff` without reconnecting the change stream.
    AuthRetrying {
        /// Consecutive failed-attempt count (1-based) for this event.
        attempt: u32,
        /// Delay before the next authorization attempt.
        backoff: Duration,
        /// The error from the authorization service.
        error: &'a str,
    },
}

/// What the write question answered for a whole mutation.
///
/// Three answers rather than a boolean, because a refusal and a failure to
/// reach an answer reach the client as different reasons. Telling a client it
/// lacks permission when the truth is that the server cannot tell makes it stop
/// retrying and possibly discard the write, which turns a transient outage into
/// permanent loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteVerdict {
    /// Every op is allowed.
    Allowed,
    /// The policy refused one.
    Denied,
    /// The policy could not be reached, so no answer exists yet.
    Undetermined,
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
    /// The authorization service was unreachable while answering a visibility
    /// question. The ingest loop retries the same event rather than advancing
    /// past it.
    #[error("auth service unreachable: {0}")]
    AuthUnavailable(String),
    /// The change stream cannot answer what a row looked like before it
    /// changed, for the table named.
    ///
    /// Either the table does not record the previous image (`REPLICA IDENTITY`
    /// is not `FULL`) or the catalog does not know it. **Neither clears by
    /// itself**, so the ingest loop must not hold the event and retry: the
    /// server refuses to serve instead, and the restart meets the startup
    /// refusal naming the table (R6 decision 4).
    #[error(
        "the change stream cannot report the previous version of a row in {0}, so \
         a row that leaves a caller's reach cannot be taken back from them. Run \
         ALTER TABLE {0} REPLICA IDENTITY FULL"
    )]
    ChangeStreamUnusable(String),
}

fn transport_err<E: core::fmt::Display>(err: E) -> SessionError {
    SessionError::Transport(err.to_string())
}

fn oplog_err<E: core::fmt::Display>(err: E) -> SessionError {
    SessionError::Oplog(err.to_string())
}

/// A refusal's wait as the wire's milliseconds, saturating.
fn retry_ms(wait: Duration) -> u64 {
    u64::try_from(wait.as_millis()).unwrap_or(u64::MAX)
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
    /// A non-fatal control frame delivered immediately, bypassing the bulk
    /// queue. Used for session-wide notifications such as delivery paused or
    /// resumed.
    Control(ControlMessage),
    /// Re-read one row subscription and replace what the client holds, because
    /// a grant reaching its table moved (R7). Carried as an instruction rather
    /// than as frames because only this session's own task holds the transport,
    /// and the notice and its replacement must stay one ordered pair.
    Resnapshot {
        /// The client-facing label of the subscription to replace.
        sub_id: String,
    },
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
    /// The table this subscription reads, absent when the translated SQL names
    /// none the parser recognises. What a moved grant is matched against (R7).
    table: Option<String>,
    /// The subscription's Postgres SQL, for the move-in read a membership
    /// narrowing triggers (R27). Shared, because the fan-out clones one route
    /// per subscriber per event.
    pg_sql: std::sync::Arc<str>,
    /// The subscription's bind values, paired with `pg_sql`'s placeholders.
    binds: std::sync::Arc<[BindValue]>,
    /// The membership tables this subscription's terms watch, empty for a
    /// filter naming none. A grant moved by a change to one of these tables is
    /// served incrementally by the term's own move (R27 decision 2), so the
    /// R7 resend is suppressed for exactly these tables.
    member_tables: std::sync::Arc<[(String, String)]>,
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

/// One item waiting on the outbound queue.
///
/// Whether a frame is rationed and whether it is ordered against the data are
/// two separate questions, and the queue answers both. [`Rows`](Self::Rows)
/// costs a credit, because flow control exists to bound bulk. `SnapshotEnd`
/// costs nothing but must still travel behind the rows it completes, so it
/// waits in line and leaves free.
///
/// The set is closed on purpose. A control frame that must **not** be held
/// behind data, a `Pong` above all, has no variant here and cannot be queued
/// by accident: it goes straight out through `send_control`.
enum Deliverable {
    /// A bulk frame. Costs one credit.
    Rows(BulkMessage),
    /// The frame closing a snapshot. Ordered, never charged.
    SnapshotComplete(SnapshotEnd),
}

impl Deliverable {
    /// Whether sending this spends one of the client's delivery credits.
    const fn costs_credit(&self) -> bool {
        matches!(self, Self::Rows(_))
    }
}

/// One live row subscription, as the session has to remember it.
///
/// The request is kept because a resync re-reads the same set from the server
/// side: the client is told to discard what it holds and is handed a
/// replacement, so nothing asks it to describe the subscription again.
struct RowSub {
    reg: RowRegistration,
    sub: Subscribe,
}

/// Mutable per-session state carried through the run loop.
struct SessionState<Id, Key> {
    credits: u32,
    pending: VecDeque<Deliverable>,
    /// Row subscriptions by client label, each keeping the request that made it
    /// so the server can re-read the same set without asking the client again
    /// (R7).
    subs: HashMap<String, RowSub>,
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
    /// Backoff for the authorization-service unreachable path on the change
    /// pipeline. When `may_see` or `may_write` returns an error, the ingest
    /// loop retries the same event using this schedule before moving on.
    auth_retry: RetryPolicy,
    /// Brings the authorization store level with each changed row before that
    /// row reaches anybody.
    ///
    /// Optional because most policies keep no store: row-level security reads
    /// the live table and has nothing to maintain. A manager that holds one
    /// waits for it, because a patch delivered before the store catches up is
    /// answered from facts the change already invalidated, and in the allow
    /// direction no later correction takes the row back.
    upkeep: OnceLock<Arc<dyn crate::openfga::StoreUpkeep>>,
    /// A second executor asked about the row as it is now, alongside the one
    /// that delivers, so a divergence between them fails a run.
    ///
    /// Optional and off by default: it costs one Postgres round trip per watcher
    /// per changed row, which is the whole cost R5b removed.
    second_opinion: OnceLock<Arc<dyn crate::parity::SecondOpinion<Id, Key>>>,
    /// Reads the rows a membership move-out withdraws, on the privileged pool
    /// (R27 decision 6): when a membership ends, the policy that made those
    /// rows visible is exactly what ended, so a read as the caller comes back
    /// empty precisely when there is something to withdraw.
    ///
    /// Optional like the upkeep. Without one, a move-out escalates to the R7
    /// replace instead of withdrawing incrementally.
    withdrawal_source: OnceLock<Snap>,
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
            auth_retry: RetryPolicy::new(),
            upkeep: OnceLock::new(),
            second_opinion: OnceLock::new(),
            withdrawal_source: OnceLock::new(),
        })
    }
}

impl<Snap, Auth, C, O, Id, Key, W> SessionManager<Snap, Auth, W, C, O, Id, Key>
where
    Snap: SnapshotSource<Id, Key>,
    Auth: VisibilityPolicy<Watcher = Arc<Principal<Id, Key>>, Backend = Postgres>,
    Auth::Error: core::fmt::Display,
    C: AsyncConnector<Backend = Postgres, Checkpoint = PgLsn, AuthContext = ()> + Send + Sync,
    C::Error: core::fmt::Display,
    O: Oplog,
    Id: core::fmt::Display + Clone + Send + Sync + 'static,
    Key: CapabilityKey,
    W: ConnettoWatermarkSchema<Id = Id>,
{
    /// Maintain the authorization store from the change stream.
    ///
    /// Set once, after construction, because the upkeep is built from the
    /// executor this manager already holds and so cannot be assembled before
    /// it. A second call is refused rather than allowed to replace a live
    /// collaborator, which would leave events either side of the swap
    /// answered against two different stores.
    ///
    /// # Errors
    ///
    /// The upkeep handed over, when one is already installed.
    pub fn install_store_upkeep(
        &self,
        upkeep: Arc<dyn crate::openfga::StoreUpkeep>,
    ) -> Result<(), Arc<dyn crate::openfga::StoreUpkeep>> {
        self.upkeep.set(upkeep)
    }

    /// Ask a second executor about every current row alongside the one that
    /// delivers, so a divergence between them is counted and named.
    ///
    /// Set once, for the same reason the upkeep is: replacing a live one would
    /// compare events either side of the swap against two different executors.
    /// Off by default, because it costs one Postgres round trip per watcher per
    /// changed row.
    ///
    /// # Errors
    ///
    /// The executor handed over, when one is already installed.
    pub fn install_second_opinion(
        &self,
        second: Arc<dyn crate::parity::SecondOpinion<Id, Key>>,
    ) -> Result<(), Arc<dyn crate::parity::SecondOpinion<Id, Key>>> {
        self.second_opinion.set(second)
    }

    /// Read move-out withdrawals on the privileged pool (R27 decision 6).
    ///
    /// Set once, after construction, like the store upkeep. The source's pool
    /// is what makes it privileged: the caller binding is inert where
    /// row-level security does not apply, and nothing read through it is sent
    /// as data, only denied keys as indirect deletes.
    ///
    /// # Errors
    ///
    /// The source handed over, when one is already installed.
    pub fn install_withdrawal_source(&self, source: Snap) -> Result<(), Snap> {
        self.withdrawal_source.set(source)
    }

    /// Which refusal a transition failure is.
    ///
    /// A policy that could not answer is the transient case the ingest loop
    /// holds the event for. The other two do not clear by themselves: a table
    /// that does not record its previous row image produces the same failure on
    /// every later change, and so does one the catalog does not know, so the
    /// server refuses to serve rather than retrying for ever (R6 decision 4).
    fn transition_refusal(
        &self,
        event: &ChangeEvent,
        err: TransitionError<Auth::Error>,
    ) -> SessionError {
        match err {
            TransitionError::Policy(err) => SessionError::AuthUnavailable(err.to_string()),
            // `NotARowEvent` is unreachable, because a truncate is answered
            // before the question is put. Refusing is the direction to fail in
            // if that ever stops being true.
            TransitionError::IncompletePreviousImage
            | TransitionError::UnknownTable
            | TransitionError::NotARowEvent => {
                SessionError::ChangeStreamUnusable(self.event_table(event))
            }
        }
    }

    /// The event's table, for a message a person has to act on.
    fn event_table(&self, event: &ChangeEvent) -> String {
        let catalog = self.catalog.as_ref();
        let id = event.table_id(catalog);
        usize::try_from(id)
            .ok()
            .and_then(|index| catalog.table_by_id(index))
            .map_or_else(
                || format!("table {id}"),
                |table| table.table_name().to_owned(),
            )
    }

    /// The changed row's primary key, as connetto observed it on the event.
    ///
    /// Empty when the event carries no readable image, which an audit row
    /// records as a change naming no row rather than as a wrong one.
    fn event_key(&self, event: &ChangeEvent) -> Vec<subql::backend::Value<Postgres>> {
        let catalog = self.catalog.as_ref();
        let Some(row) =
            EventRow::current(event, catalog).or_else(|| EventRow::previous(event, catalog))
        else {
            return Vec::new();
        };
        event
            .pk_columns(catalog)
            .into_iter()
            .map_while(|column| subql::visibility::RowView::value_at(&row, column).ok())
            .collect()
    }

    /// Ask the second opinion about the row as it is now, when one is installed.
    ///
    /// Only the current row, and only when the event has one: row-level security
    /// reads the live table, so it cannot answer about a previous version and
    /// answers no for everyone about a deleted row. A watcher was told to deliver
    /// exactly when the shipped executor allowed the current row, which is what
    /// makes the comparison recoverable here without asking twice.
    async fn ask_second_opinion(
        &self,
        event: &ChangeEvent,
        watchers: &[Arc<Principal<Id, Key>>],
        verdicts: &[Transition],
    ) {
        let Some(second) = self.second_opinion.get() else {
            return;
        };
        let Some(row) = EventRow::current(event, self.catalog.as_ref()) else {
            return;
        };
        let shipped: Vec<Verdict> = verdicts
            .iter()
            .map(|verdict| {
                if *verdict == Transition::Deliver {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                }
            })
            .collect();
        second.compare(&row, watchers, &shipped).await;
    }

    fn next_connection_num(&self) -> u64 {
        self.next_session.fetch_add(1, Ordering::Relaxed)
    }

    fn next_consumer_id(&self) -> u64 {
        self.next_consumer.fetch_add(1, Ordering::Relaxed)
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
        self.close_all(FatalErrorReason::ServerShuttingDown).await
    }

    /// Reconcile the change feed's resume position against what the log holds,
    /// declaring a resync epoch when the feed skipped a stretch.
    ///
    /// Called before each connect with the position the stream is about to
    /// resume from. Everything the feed delivered was appended to the log
    /// before being acknowledged, so in ordinary operation the resume position
    /// is at or behind the log's own high-water mark and this does nothing. A
    /// resume position **ahead** of it means changes happened that the feed
    /// never delivered: an invalidated slot the deployment recreated, a
    /// database restored from a backup, or a slot dropped under a running
    /// server. Detecting the hole rather than the cause is deliberate, since
    /// no layer here distinguishes an invalidation from an ordinary
    /// disconnection and matching on an error string would pin this to one
    /// Postgres version and to the causes somebody enumerated (R32).
    ///
    /// **The boundary reported is the resume position, not the last record
    /// ingested, and today nothing turns on that.** Trimming through either
    /// deletes the same rows, because the last record ingested is by definition
    /// the highest the log holds. The resume position is the honest number to
    /// name because it is where the epoch actually starts, and the difference
    /// would matter the moment a boundary were stored and compared rather than
    /// applied: a client's cursor can sit above the last record without being
    /// current, since a snapshot's cursor is the write-ahead position when it
    /// was read and that advances for reasons other than changes.
    ///
    /// Two things follow, and both are needed. The log forgets everything
    /// through the boundary, so every later handshake is judged against what
    /// can still be proven. And every live connection is closed, because a
    /// connection never asks that question again: reconnecting re-declares its
    /// subscriptions through the ordinary path, which rebuilds a running total
    /// from its source rather than repairing one that accumulated across the
    /// hole.
    ///
    /// Returns the boundary when an epoch was declared.
    ///
    /// # Errors
    ///
    /// [`SessionError`] when the log could not be read or trimmed. The caller
    /// must not begin streaming on an error: an undeclared gap is the silence
    /// this exists to remove.
    pub async fn reconcile_stream(&self, resume_lsn: u64) -> Result<Option<u64>, SessionError> {
        let Some(ingested) = self.oplog.current_lsn().await.map_err(oplog_err)? else {
            // Nothing recorded, so there is nothing to be past. A log in that
            // state already resyncs every client that presents a cursor.
            return Ok(None);
        };
        if resume_lsn <= ingested {
            return Ok(None);
        }
        self.oplog
            .forget_through(resume_lsn)
            .await
            .map_err(oplog_err)?;
        let closed = self.close_all(FatalErrorReason::ChangeStreamGap).await;
        tracing::error!(
            ingested,
            resume_lsn,
            missing_bytes = resume_lsn.saturating_sub(ingested),
            closed,
            "change feed resumed past what it delivered, so a stretch of changes \
             was never seen: the reconnect log is trimmed to the resume point and \
             every client will resynchronise"
        );
        Ok(Some(resume_lsn))
    }

    /// Close every live connection with `reason`, returning how many were told.
    async fn close_all(&self, reason: FatalErrorReason) -> usize {
        let live: Vec<_> = {
            let mut sessions = self.sessions.lock().await;
            sessions.drain().map(|(_, live)| live.tx).collect()
        };
        for tx in &live {
            let _ = tx.send(Outbound::Fatal(FatalError::new(reason.clone())));
        }
        live.len()
    }

    /// Send a control frame to every currently live session without removing
    /// any entry from the session registry.
    async fn broadcast_control(&self, msg: ControlMessage) {
        let txs: Vec<_> = {
            self.sessions
                .lock()
                .await
                .values()
                .map(|live| live.tx.clone())
                .collect()
        };
        for tx in txs {
            let _ = tx.send(Outbound::Control(msg.clone()));
        }
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
        self.dispatch_with_grants(event, &[]).await
    }

    /// [`dispatch_event`](Self::dispatch_event) with this event's grant moves,
    /// as the ingest loop computed them before dispatching: a membership
    /// move-out may withdraw rows only when the same event moved a grant
    /// reaching the subscribed table for that watcher, because only then did
    /// policy visibility of held rows flip (see `move_out`).
    async fn dispatch_with_grants(
        &self,
        event: &ChangeEvent,
        grant_moves: &[GrantMove],
    ) -> Result<(), SessionError> {
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
        self.fan_out_rows(event, deliveries).await?;
        self.fan_out_moves(event, dispatched.narrowings, grant_moves)
            .await;

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

    /// Decide what one event does to every matched caller's copy of the row, and
    /// send it (R6, the two-check form).
    ///
    /// `Deliver` sends the patch this event produced, `Withdraw` sends a plain
    /// delete that takes the row back, and `Nothing` sends nothing at all, which
    /// is what stops a deleted row's key reaching a caller who could never see
    /// it.
    ///
    /// # Errors
    ///
    /// [`SessionError::AuthUnavailable`] when the policy could not answer, so the
    /// ingest loop holds the event, [`SessionError::ChangeStreamUnusable`] when
    /// the stream cannot report the previous version at all, and
    /// [`SessionError::Materializer`] when a cursor advance fails.
    async fn fan_out_rows(
        &self,
        event: &ChangeEvent,
        deliveries: Vec<(MatchedPatch, Route<Id, Key>)>,
    ) -> Result<(), SessionError> {
        let watchers: Vec<_> = deliveries
            .iter()
            .map(|(_, route)| Arc::clone(&route.principal))
            .collect();
        // A truncate names no row, so neither version exists and no question can
        // be put. It also folds to a patchset with no operations, so replaying it
        // discloses nothing. R48 owns making it empty the replica.
        let truncate = event.kind() == EventKind::Truncate;
        let mut verdicts = Transitions::new();
        verdicts.reset(watchers.len());
        if !truncate && !watchers.is_empty() {
            transitions(
                &self.auth,
                event,
                self.catalog.as_ref(),
                &watchers,
                &mut verdicts,
            )
            .await
            .map_err(|err| self.transition_refusal(event, err))?;
            self.ask_second_opinion(event, &watchers, verdicts.get())
                .await;
        }

        // What a caller who may no longer see the row receives. **A delete's own
        // patch already is exactly that**, one unmarked delete keyed by the image
        // the caller holds, so only an update needs a second fold: its own patch
        // carries the new row values the caller has just lost the right to read.
        // Built once per event when it is needed at all, exactly as the departure
        // notice is, because the bytes carry a table and a key and nothing
        // caller-specific.
        let withdrawal = if event.kind() == EventKind::Delete
            || !verdicts.get().contains(&Transition::Withdraw)
        {
            None
        } else {
            let built = counters::timed_lock(&self.materializer)
                .await
                .withdrawal_patch(event)?;
            Some(built.ok_or_else(|| {
                MaterializerError::Emit(
                    "a row has to be taken back from a caller and the event folded to no \
                     operation to take it back with"
                        .to_owned(),
                )
            })?)
        };

        for ((patch, route), verdict) in deliveries.into_iter().zip(verdicts.get().iter().copied())
        {
            // R44's departure notice is no longer exempt from the visibility
            // question, and retiring that exemption is R6's decision 6. The
            // exemption existed because a denied subscriber would otherwise be
            // told nothing and keep the row for ever, which the withdrawal above
            // now answers properly. What it cost was the notice carrying a key to
            // a caller who could never see the row.
            let payload = if truncate {
                patch.payload_zstd
            } else {
                match verdict {
                    Transition::Nothing => continue,
                    Transition::Deliver => patch.payload_zstd,
                    Transition::Withdraw => withdrawal.clone().unwrap_or(patch.payload_zstd),
                }
            };
            {
                counters::timed_lock(&self.materializer)
                    .await
                    .advance_cursor(route.session_key, route.sub_id, &patch.cursor)?;
            }
            let live = LivePatch::new(route.label, Cursor::new(patch.cursor), payload);
            // A dropped session receiver just means the client is gone.
            let _ = route.tx.send(Outbound::Live(live));
        }
        Ok(())
    }

    /// How many times a membership move read retries in place before the
    /// subscription is replaced through the R7 machinery instead.
    const MOVE_ATTEMPTS: u32 = 3;

    /// Serve the rows one membership move affects (R27 step 4): a value that
    /// entered a subscription's set is answered with the subscription's own
    /// SELECT narrowed to that value, and a value that left with an indirect
    /// delete per key the policy no longer grants.
    ///
    /// A failure never fails the event and never skips silently: the engine's
    /// membership set has already moved, so a redispatched event would re-fire
    /// no narrowing, and instead the subscription is replaced whole through
    /// the same ordered notice-and-replacement instruction a moved grant uses
    /// (R7). The healthy path stays incremental, which is what the phase's
    /// proof asserts.
    async fn fan_out_moves(
        &self,
        event: &ChangeEvent,
        moves: Vec<TermMove>,
        grant_moves: &[GrantMove],
    ) {
        if moves.is_empty() {
            return;
        }
        let cursor = event
            .checkpoint()
            .map(|lsn| lsn.0.to_be_bytes().to_vec())
            .unwrap_or_default();
        for term_move in moves {
            let route = {
                self.routes
                    .lock()
                    .await
                    .values()
                    .find(|route| route.sub_id == term_move.sub_id)
                    .cloned()
            };
            let Some(route) = route else { continue };
            let served = if term_move.entered {
                self.move_in(&route, &term_move, &cursor).await
            } else {
                self.move_out(&route, &term_move, &cursor, grant_moves)
                    .await
            };
            if !served {
                let _ = route.tx.send(Outbound::Resnapshot {
                    sub_id: route.label.clone(),
                });
            }
        }
    }

    /// Deliver the rows a value entering the set admits: the subscription's
    /// own SELECT narrowed to the value, read as the caller under row-level
    /// security, which is the snapshot-time visibility question, so a row the
    /// policy forbids never arrives however much the term admits it. Returns
    /// whether the move was served.
    async fn move_in(&self, route: &Route<Id, Key>, term_move: &TermMove, cursor: &[u8]) -> bool {
        let Some(sql) = narrowed_sql(&route.pg_sql, &term_move.column, &term_move.value) else {
            return false;
        };
        let mut attempt: u32 = 0;
        let snapshot = loop {
            match self
                .snapshot_source
                .snapshot(&sql, &route.binds, &route.principal)
                .await
            {
                Ok(snapshot) => break snapshot,
                Err(err) => {
                    attempt = attempt.saturating_add(1);
                    if attempt >= Self::MOVE_ATTEMPTS {
                        tracing::warn!(
                            sub_id = %route.label,
                            error = %err,
                            "a move-in read kept failing, replacing the subscription"
                        );
                        return false;
                    }
                    tokio::time::sleep(self.auth_retry.backoff(attempt)).await;
                }
            }
        };
        let has_rows = matches!(
            ParsedDiffSet::parse(&snapshot.patchset),
            Ok(ParsedDiffSet::Patchset(set)) if set.iter().next().is_some()
        );
        if !has_rows {
            // The policy admitted nothing under this value. Delivering an
            // empty patch would say something moved when nothing did.
            return true;
        }
        let Ok(payload) = compress(&snapshot.patchset) else {
            return false;
        };
        self.send_move(route, cursor, payload).await
    }

    /// Withdraw what a value leaving the set no longer shows: the rows under
    /// the moved value, read on the privileged pool per decision 6, because
    /// the policy that made them visible is exactly what ended and a read as
    /// the caller finds nothing precisely when there is something to
    /// withdraw. Each row still goes through the change-path executor, and
    /// only what is denied is sent, keys only, as indirect deletes: a row the
    /// policy still admits through something other than the term stays put,
    /// and the replica's own membership copy answers the local query. Returns
    /// whether the move was served.
    async fn move_out(
        &self,
        route: &Route<Id, Key>,
        term_move: &TermMove,
        cursor: &[u8],
        grant_moves: &[GrantMove],
    ) -> bool {
        // Only an event that moved a grant reaching the subscribed table for
        // this watcher can have flipped the policy's answer for rows the
        // client held. Any other membership exit is interest-only: nothing is
        // sent, and the replica's own membership copy stops the local query
        // matching. The deny-now set under a parent also contains keys the
        // caller never held, and a delete for a never-held key is the
        // disclosure R6 forbids, which is what this gate closes.
        let policy_moved = grant_moves.iter().any(|moved| {
            route
                .table
                .as_deref()
                .is_some_and(|table| moved.tables.iter().any(|reached| reached == table))
                && Self::concerns(&route.principal, &moved.holder)
        });
        if !policy_moved {
            return true;
        }
        let Some(source) = self.withdrawal_source.get() else {
            return false;
        };
        let base = format!(
            "SELECT * FROM {}",
            connetto_core::quote_ident(&term_move.table)
        );
        let Some(sql) = narrowed_sql(&base, &term_move.column, &term_move.value) else {
            return false;
        };
        let mut attempt: u32 = 0;
        let snapshot = loop {
            match source.snapshot(&sql, &[], &route.principal).await {
                Ok(snapshot) => break snapshot,
                Err(err) => {
                    attempt = attempt.saturating_add(1);
                    if attempt >= Self::MOVE_ATTEMPTS {
                        tracing::warn!(
                            sub_id = %route.label,
                            error = %err,
                            "a move-out read kept failing, replacing the subscription"
                        );
                        return false;
                    }
                    tokio::time::sleep(self.auth_retry.backoff(attempt)).await;
                }
            }
        };
        let Ok(ParsedDiffSet::Patchset(set)) = ParsedDiffSet::parse(&snapshot.patchset) else {
            return false;
        };
        let Some(table_id) =
            subql::catalog_helpers::table_id(self.catalog.as_ref(), &term_move.table)
        else {
            return false;
        };
        let mut deletes = PatchSet::<TableSchema<String>, String, Vec<u8>>::new();
        let mut any = false;
        for op in set.iter() {
            let PatchsetOp::Insert { values, .. } = &op else {
                continue;
            };
            let row: Vec<PgValue<Postgres>> = values.iter().map(crate::pk::from_wire).collect();
            let view = ValuesRow::new(table_id, &row);
            let watchers = [Arc::clone(&route.principal)];
            let mut verdicts = Vec::new();
            let mut asked: u32 = 0;
            let allowed = loop {
                Verdict::reset(&mut verdicts, watchers.len());
                match self.auth.may_see(&view, &watchers, &mut verdicts).await {
                    Ok(()) => break matches!(verdicts.as_slice(), [Verdict::Allow, ..]),
                    Err(err) => {
                        asked = asked.saturating_add(1);
                        if asked >= Self::MOVE_ATTEMPTS {
                            tracing::warn!(
                                sub_id = %route.label,
                                error = %err,
                                "a move-out visibility question kept failing, replacing the subscription"
                            );
                            return false;
                        }
                        tokio::time::sleep(self.auth_retry.backoff(asked)).await;
                    }
                }
            };
            if allowed {
                continue;
            }
            deletes = deletes
                .delete(PatchDelete::new(op.table().clone(), op.primary_key()).indirect(true));
            any = true;
        }
        if !any {
            return true;
        }
        let Ok(payload) = compress(&deletes.build()) else {
            return false;
        };
        self.send_move(route, cursor, payload).await
    }

    /// Advance the subscription's cursor to the causing event and queue one
    /// live patch for it. Returns whether it was queued.
    async fn send_move(&self, route: &Route<Id, Key>, cursor: &[u8], payload: Vec<u8>) -> bool {
        let advanced = {
            counters::timed_lock(&self.materializer)
                .await
                .advance_cursor(route.session_key, route.sub_id, cursor)
        };
        if advanced.is_err() {
            return false;
        }
        let live = LivePatch::new(route.label.clone(), Cursor::new(cursor.to_vec()), payload);
        // A dropped session receiver just means the client is gone.
        let _ = route.tx.send(Outbound::Live(live));
        true
    }

    /// Bring the authorization store level with `event`, if one is maintained.
    ///
    /// **Called once per event, before it is dispatched, and deliberately not
    /// from `dispatch_event`.** Until the store holds what the row moved, every
    /// question about a row those facts reach is answered from a world that has
    /// moved. But a difference is applied once: an event held through an
    /// outage is dispatched again when the answer comes back, and re-applying a
    /// difference already in the store writes facts that are already there,
    /// which the service refuses. Reached through the ingest loop, which holds
    /// the event, so the retry retries the question and not the write.
    ///
    /// Catchup does not call it, and must not: it replays history whose
    /// differences were applied when those events were live.
    ///
    /// # Errors
    ///
    /// [`SessionError::AuthUnavailable`], because a store that could not be
    /// brought level is the same class of unknown as an unreachable service and
    /// takes the same path.
    async fn keep_store_current(
        &self,
        event: &ChangeEvent,
    ) -> Result<Vec<GrantMove>, SessionError> {
        match self.upkeep.get() {
            Some(upkeep) => upkeep
                .keep_current(event)
                .await
                .map_err(|err| SessionError::AuthUnavailable(err.to_string())),
            None => Ok(Vec::new()),
        }
    }

    /// Tell every live subscription a moved grant reaches to replace its rows.
    ///
    /// The instruction goes on the session's own outbound queue, so the notice
    /// and its replacement are produced by the task that holds the transport.
    /// A dropped receiver just means the client has gone.
    ///
    /// One audit row per connection told, which is connetto's own act: a
    /// permission change nobody is connected for records nothing here, and the
    /// grant row itself is the application's to keep (R7 decision 8).
    async fn announce_grant_moves(&self, event: &ChangeEvent, moves: &[GrantMove]) {
        if moves.is_empty() {
            return;
        }
        let moved_table = self.event_table(event);
        let told: Vec<(SessionId, Option<Id>, String)> = {
            let routes = self.routes.lock().await;
            routes
                .values()
                .filter_map(|route| {
                    let table = route.table.as_deref()?;
                    let concerned = moves.iter().any(|moved| {
                        moved.tables.iter().any(|reached| reached == table)
                            && Self::concerns(&route.principal, &moved.holder)
                    });
                    if !concerned {
                        return None;
                    }
                    // A subscription whose own term watches the moved grant's
                    // table is served incrementally by the membership move
                    // this same event produces (R27 decision 2). The resend
                    // would double-deliver what the move already sends, and
                    // the phase's proof asserts its absence.
                    if route
                        .member_tables
                        .iter()
                        .any(|(member, _)| member == &moved_table)
                    {
                        return None;
                    }
                    let sent = route.tx.send(Outbound::Resnapshot {
                        sub_id: route.label.clone(),
                    });
                    sent.is_ok().then(|| {
                        (
                            route.principal.session_id(),
                            route
                                .principal
                                .identity()
                                .map(|identity| identity.user_id.clone()),
                            route.label.clone(),
                        )
                    })
                })
                .collect()
        };
        let grant_row = self.event_table(event);
        let grant_key = self.event_key(event);
        for (session, user_id, label) in told {
            tracing::info!(
                sub_id = %label,
                grant_table = %grant_row,
                "a permission change reached this subscription, replacing its rows"
            );
            self.guard.record(
                AuthEvent::new(session, user_id, AuthOp::PermissionChange)
                    .about_row(grant_row.clone(), grant_key.clone()),
            );
        }
    }

    /// Whether a moved grant concerns this caller.
    fn concerns(principal: &Principal<Id, Key>, holder: &GrantHolder) -> bool {
        match holder {
            GrantHolder::Everybody => true,
            GrantHolder::Person(person) => principal
                .identity()
                .is_some_and(|identity| identity.user_id.to_string() == *person),
        }
    }

    /// Drive a CDC source to completion, dispatching every event and acking its
    /// checkpoint so the upstream can recycle its log.
    ///
    /// When `dispatch_event` returns [`SessionError::AuthUnavailable`] the loop
    /// holds the event, broadcasts [`ControlMessage::DeliveryPaused`] to every
    /// live session (once per outage, not per retry), and retries after
    /// its own retry backoff. On recovery it broadcasts
    /// [`ControlMessage::DeliveryResumed`] and moves on. The source checkpoint
    /// is not acknowledged until dispatch succeeds, so the replication slot never
    /// advances past an unanswered event.
    ///
    /// # Errors
    ///
    /// [`SessionError`] when a non-auth dispatch fails or the source errors.
    pub async fn ingest<S>(
        &self,
        source: &mut S,
        on_event: &mut impl FnMut(ReconnectEvent<'_>),
    ) -> Result<(), SessionError>
    where
        S: CdcSource<Event = ChangeEvent>,
        S::Error: core::fmt::Display,
    {
        loop {
            match source.next_event().await {
                Ok(Some(event)) => {
                    let mut auth_attempt: u32 = 0;
                    let mut paused = false;
                    // Applied once, then only the question is retried. See
                    // `keep_store_current` for why re-applying is refused.
                    let mut levelled = false;
                    // Remembered across auth retries: the store is levelled
                    // once, so the moves exist only on the first attempt, and
                    // a retried dispatch still owes the withdrawal they gate.
                    let mut grant_moves: Vec<GrantMove> = Vec::new();
                    loop {
                        let attempt = async {
                            if !levelled {
                                // Announced here rather than after dispatch, so
                                // the notice cannot be produced twice by the
                                // retry that re-asks the question, and so the
                                // replacement is read against a level store.
                                let moved = self.keep_store_current(&event).await?;
                                levelled = true;
                                self.announce_grant_moves(&event, &moved).await;
                                grant_moves = moved;
                            }
                            self.dispatch_with_grants(&event, &grant_moves).await
                        };
                        match attempt.await {
                            Ok(()) => {
                                if paused {
                                    self.broadcast_control(ControlMessage::DeliveryResumed)
                                        .await;
                                }
                                break;
                            }
                            Err(SessionError::AuthUnavailable(err)) => {
                                auth_attempt = auth_attempt.saturating_add(1);
                                if !paused {
                                    self.broadcast_control(ControlMessage::DeliveryPaused {
                                        cause: PauseCause::AuthServiceUnreachable,
                                    })
                                    .await;
                                    paused = true;
                                }
                                let backoff = self.auth_retry.backoff(auth_attempt);
                                on_event(ReconnectEvent::AuthRetrying {
                                    attempt: auth_attempt,
                                    backoff,
                                    error: &err,
                                });
                                tokio::time::sleep(backoff).await;
                            }
                            Err(other) => return Err(other),
                        }
                    }
                    if let Some(lsn) = event.checkpoint() {
                        source
                            .ack(lsn)
                            .await
                            .map_err(|err| SessionError::Transport(err.to_string()))?;
                    }
                }
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
                    match self.ingest(&mut source, &mut on_event).await {
                        Ok(()) => return Ok(()),
                        // Reconnecting cannot help: the same table produces the
                        // same refusal on the next event, so retrying it would
                        // spin for ever against a deployment that has to be
                        // fixed (R6 decision 4).
                        Err(err @ SessionError::ChangeStreamUnusable(_)) => return Err(err),
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
            if let Some(max) = policy.max_attempts()
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
        let tier = Tier::of(&principal);
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
        // at or below it and replays the rest. Its read is the handshake's one
        // reader-pool checkout, so an unidentified caller takes a share permit
        // for it (R39) and draws R19's fatal refusal when the share stays full.
        let applied_watermark = {
            let Some(_reader_permit) = self
                .handshake_reader_permit(transport, tier, &principal, refused_grants, &span)
                .await
            else {
                return Ok(None);
            };
            self.target
                .last_applied(session_id)
                .await
                .map_err(|err| SessionError::WriteTarget(err.detail()))?
        };
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
        let retry_after_ms = retry_ms(wait);
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

    /// Take the handshake's reader-share permit (R39), or refuse the caller
    /// in R19's fatal shape and report [`None`].
    ///
    /// The refusals still count on this exit, exactly as on the rate-limit
    /// one: the tally here and the announcement in `run_session` are two ends
    /// of one count.
    async fn handshake_reader_permit<T: Transport>(
        &self,
        transport: &mut T,
        tier: Tier,
        principal: &Principal<Id, Key>,
        refused_grants: u32,
        span: &tracing::Span,
    ) -> Option<ReaderPermit> {
        match self.guard.reader_permit(tier).await {
            Ok(permit) => Some(permit),
            Err(wait) => {
                let retry_after_ms = retry_ms(wait);
                span.in_scope(|| {
                    tracing::warn!(
                        retry_after_ms,
                        "connection refused, the unreserved reader share is full"
                    );
                });
                let _ = transport
                    .send_control(ControlMessage::FatalError(FatalError::new(
                        FatalErrorReason::RateLimited { retry_after_ms },
                    )))
                    .await;
                let _ = span.in_scope(|| {
                    self.guard
                        .refused_grants(Self::caller(principal), refused_grants)
                });
                None
            }
        }
    }

    /// Take the mutation's reader-share permit (R39), or defer the mutation
    /// in R19's shape and report [`None`].
    ///
    /// The refusal is correlated by the `client_seq` rendered as a string,
    /// exactly as `NonFatalError` correlates. The mutation is neither applied
    /// nor acknowledged, so it stays pending on the client and replays on
    /// reconnect.
    async fn mutation_reader_permit<T: Transport>(
        &self,
        transport: &mut T,
        client_seq: u64,
        state: &SessionState<Id, Key>,
    ) -> Result<Option<ReaderPermit>, SessionError> {
        match self.guard.reader_permit(Tier::of(&state.principal)).await {
            Ok(permit) => Ok(Some(permit)),
            Err(wait) => {
                let retry_after_ms = retry_ms(wait);
                tracing::warn!(
                    client_seq,
                    retry_after_ms,
                    "mutation deferred, the unreserved reader share is full"
                );
                transport
                    .send_control(ControlMessage::RateLimited(RateLimited {
                        related_to: Some(client_seq.to_string()),
                        retry_after_ms,
                    }))
                    .await
                    .map_err(transport_err)?;
                Ok(None)
            }
        }
    }

    /// Take a row subscription's reader-share permit (R39), or refuse it in
    /// R19's nonfatal shape and report [`None`], unwinding the registration.
    /// The route is not attached and the label not recorded at this point, so
    /// the registration is the one thing to unwind.
    async fn subscribe_reader_permit<T: Transport>(
        &self,
        transport: &mut T,
        tier: Tier,
        sub_id: &str,
        registered: SubscriptionId,
    ) -> Result<Option<ReaderPermit>, SessionError> {
        match self.guard.reader_permit(tier).await {
            Ok(permit) => Ok(Some(permit)),
            Err(wait) => {
                let retry_after_ms = retry_ms(wait);
                tracing::warn!(
                    sub_id = %sub_id,
                    retry_after_ms,
                    "subscription refused, the unreserved reader share is full"
                );
                self.materializer.lock().await.unregister(registered);
                transport
                    .send_control(ControlMessage::RateLimited(RateLimited {
                        related_to: Some(sub_id.to_owned()),
                        retry_after_ms,
                    }))
                    .await
                    .map_err(transport_err)?;
                Ok(None)
            }
        }
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
                                Deliverable::Rows(BulkMessage::LivePatch(patch)),
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
                        Outbound::Control(msg) => {
                            // Non-fatal control frame: send immediately, ignore
                            // a closed transport (the session may have moved on).
                            let _ = transport.send_control(msg).await;
                        }
                        Outbound::Resnapshot { sub_id } => {
                            // In this arm rather than a task of its own, so the
                            // select cannot interleave it into a subscribe, and
                            // the notice with its replacement is one ordered
                            // pair on the task that holds the transport (R7).
                            self.resnapshot_row(&mut transport, &mut state, &sub_id)
                                .await?;
                        }
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
        for row in state.subs.into_values() {
            let (consumer_id, sub_id) = (row.reg.consumer_id, row.reg.sub_id);
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
                if let Some(row) = state.subs.remove(&unsub.sub_id) {
                    self.remove_route(row.reg.consumer_id).await;
                    self.materializer.lock().await.unregister(row.reg.sub_id);
                    // R27 decision 7: a membership subscription is torn down
                    // with the last term subscription that needed it.
                    for (member_table, _) in row.reg.member_tables.iter() {
                        let still_needed = state.subs.values().any(|sibling| {
                            sibling
                                .reg
                                .member_tables
                                .iter()
                                .any(|(table, _)| table == member_table)
                        });
                        if still_needed {
                            continue;
                        }
                        if let Some(hidden) = state.subs.remove(&membership_label(member_table)) {
                            self.remove_route(hidden.reg.consumer_id).await;
                            self.materializer.lock().await.unregister(hidden.reg.sub_id);
                        }
                    }
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

    /// Ask the write question about every op in `plan`, stopping at the first
    /// answer that is not an allow.
    ///
    /// The question carries the row versions its verb is judged on, so a
    /// replacement is asked about both rather than about one image standing in
    /// for two. Judging a replacement on the resulting row alone asks whether
    /// the **new** owner is the caller, which grants a caller who holds nothing
    /// and writes itself in.
    async fn every_op_authorized(
        &self,
        plan: &crate::materializer::WritePlan,
        caller: &Arc<Principal<Id, Key>>,
    ) -> WriteVerdict {
        for op in &plan.ops {
            let answer = match &op.write {
                PlannedWrite::Insert { new } => {
                    let new = ValuesRow::new(op.table_id, new);
                    self.auth
                        .may_write(RowWrite::Insert { new: &new }, caller)
                        .await
                }
                PlannedWrite::Update { old, new } => {
                    let old = ValuesRow::new(op.table_id, old);
                    let new = ValuesRow::new(op.table_id, new);
                    self.auth
                        .may_write(
                            RowWrite::Update {
                                old: &old,
                                new: &new,
                            },
                            caller,
                        )
                        .await
                }
                PlannedWrite::Delete { old } => {
                    let old = ValuesRow::new(op.table_id, old);
                    self.auth
                        .may_write(RowWrite::Delete { old: &old }, caller)
                        .await
                }
            };
            match answer {
                Ok(verdict) if verdict.allowed() => {}
                Ok(_) => return WriteVerdict::Denied,
                Err(_) => return WriteVerdict::Undetermined,
            }
        }
        WriteVerdict::Allowed
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

        match self.every_op_authorized(&plan, &state.principal).await {
            WriteVerdict::Allowed => {}
            // Genuine denial: the caller may not perform this operation.
            WriteVerdict::Denied => {
                return self.reject_unauthorized(transport, client_seq, state).await;
            }
            // The service could not be reached, so whether the caller may
            // write is unknown. The client must retry rather than discard.
            WriteVerdict::Undetermined => {
                return self.reject_indeterminate(transport, client_seq).await;
            }
        }

        // Probe conflicts and apply through the write target, which owns the
        // backend specifics: the Postgres target applies under the user's RLS
        // context so the database gates the write. The apply is the mutation's
        // one reader-pool checkout, so a share permit spans it (R39).
        let outcome = {
            let Some(_reader_permit) = self
                .mutation_reader_permit(transport, client_seq, state)
                .await?
            else {
                return Ok(());
            };
            self.target
                .commit(
                    &state.principal,
                    &plan,
                    &patch.patchset_zstd,
                    state.session_id,
                    client_seq,
                )
                .await
        };
        match outcome {
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

    /// Refuse one write the authorization service could not answer.
    ///
    /// The client MUST retry rather than discard its pending record: the
    /// server could not determine whether the write is permitted, so discarding
    /// it would turn a transient outage into permanent loss.
    async fn reject_indeterminate<T: Transport>(
        &self,
        transport: &mut T,
        client_seq: u64,
    ) -> Result<(), SessionError> {
        self.reject(transport, client_seq, MutationRejectReason::Indeterminate)
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

    /// Translate and register one subscription, seeding a membership term.
    ///
    /// A filter naming no term registers as before. A term is seeded per R27:
    /// the subscriber typed at `member_subject`'s own catalog kind and the
    /// values read from the membership table as the caller. The materializer
    /// lock is held across the seed read and the register (decision 11), so
    /// no dispatch lands between the seed's snapshot and the engine watching,
    /// which would silently lose that membership change for good. The
    /// lock-then-connection order cannot deadlock: no other path holds this
    /// lock and a pooled connection at once, verified against
    /// `dispatch_event` and `handle_mutation`.
    async fn register_subscription(
        &self,
        consumer_id: u64,
        sub: &Subscribe,
        state: &SessionState<Id, Key>,
    ) -> Result<(SqliteRegistration, std::sync::Arc<[(String, String)]>), SubscribeRefusal> {
        let mut materializer = self.materializer.lock().await;
        let pg_sql = materializer.translate_subscription_sql(&sub.spec.query)?;
        let terms = materializer.membership_terms(&pg_sql);
        let seed = match terms.as_slice() {
            [] => None,
            [first, rest @ ..] => {
                let identity = state
                    .principal
                    .identity()
                    .ok_or(SubscribeRefusal::Anonymous)?;
                if rest
                    .iter()
                    .any(|term| term.subject_kind != first.subject_kind)
                {
                    return Err(SubscribeRefusal::Mistyped);
                }
                let subscriber =
                    typed_subscriber(&identity.user_id.to_string(), first.subject_kind)
                        .ok_or(SubscribeRefusal::Mistyped)?;
                let mut term_values = Vec::with_capacity(terms.len());
                for term in &terms {
                    let read = self
                        .snapshot_source
                        .term_seed(&term.seed_sql, &term.member_table, &state.principal)
                        .await
                        .map_err(|err| SubscribeRefusal::Seed(err.to_string()))?
                        .ok_or(SubscribeRefusal::Unseedable)?;
                    match read.published {
                        Some(true) => {}
                        Some(false) => {
                            return Err(SubscribeRefusal::Unpublished(term.member_table.clone()));
                        }
                        None => return Err(SubscribeRefusal::NoPublication),
                    }
                    let values: Vec<PgValue<Postgres>> = read
                        .rows
                        .iter()
                        .filter_map(|row| row.get(term.member_key_ordinal))
                        .filter(|value| !matches!(value, PgValue::Missing | PgValue::Null))
                        .cloned()
                        .collect();
                    term_values.push((term.column.clone(), values));
                }
                Some(TermSeed {
                    subscriber,
                    term_values,
                })
            }
        };
        let member_tables: std::sync::Arc<[(String, String)]> = terms
            .iter()
            .map(|term| (term.member_table.clone(), term.member_subject.clone()))
            .collect::<Vec<_>>()
            .into();
        let registration =
            materializer.register_translated(consumer_id, &pg_sql, &sub.spec.binds, seed)?;
        Ok((
            SqliteRegistration {
                registration,
                pg_sql,
            },
            member_tables,
        ))
    }

    async fn handle_subscribe<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
    ) -> Result<(), SessionError> {
        let tier = Tier::of(&state.principal);
        if let Some(wait) = self.guard.subscription(state.session_id, tier) {
            let retry_after_ms = retry_ms(wait);
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
        let (registration, member_tables) = match self
            .register_subscription(consumer_id, &sub, state)
            .await
        {
            Ok(pair) => pair,
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
        let SqliteRegistration {
            registration,
            pg_sql,
        } = registration;

        match registration {
            Registration::Row(sub_id) => {
                let reg = RowRegistration {
                    consumer_id,
                    sub_id,
                    pg_sql,
                    member_tables,
                };
                self.serve_term_row(transport, sub, state, tier, reg).await
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

    /// Serve one registered row subscription: the R39 reader permit, the R27
    /// allowance pre-charge for the membership subscription a term needs, the
    /// snapshot or catchup, and the membership open behind it.
    async fn serve_term_row<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
        tier: Tier,
        reg: RowRegistration,
    ) -> Result<(), SessionError> {
        // One share permit spans the whole row delivery (R39): the snapshot
        // read or the catchup replay's visibility questions, which check out
        // reader connections one at a time, so an unidentified caller counts
        // once for the operation however many checkouts it makes. Aggregates
        // bootstrap through the re-execution connector on the owner pool and
        // take none.
        let Some(_reader_permit) = self
            .subscribe_reader_permit(transport, tier, &sub.sub_id, reg.sub_id)
            .await?
        else {
            return Ok(());
        };
        let sub_label = sub.sub_id.clone();
        let (consumer_id, sub_id) = (reg.consumer_id, reg.sub_id);
        // R27 decisions 4 and 7: the membership subscription this term needs
        // is counted against the same allowance before anything is served, so
        // a caller at its ceiling is refused as a unit rather than served
        // half.
        for (member_table, _) in reg.member_tables.iter() {
            if state.subs.contains_key(&membership_label(member_table)) {
                continue;
            }
            if let Some(wait) = self.guard.subscription(state.session_id, tier) {
                let retry_after_ms = retry_ms(wait);
                self.materializer.lock().await.unregister(sub_id);
                transport
                    .send_control(ControlMessage::RateLimited(RateLimited {
                        related_to: Some(sub_label),
                        retry_after_ms,
                    }))
                    .await
                    .map_err(transport_err)?;
                return Ok(());
            }
        }
        let members = std::sync::Arc::clone(&reg.member_tables);
        match self.subscribe_row(transport, sub, state, reg).await {
            // A snapshot failure is scoped to this one subscription: the
            // registration is rolled back and the session (with every sibling
            // subscription) stays alive. Transport and oplog failures stay
            // fatal.
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
            Ok(()) => {
                // R27 decision 7: the server opens the membership
                // subscription the term needs, after the term's own frames so
                // the announce precedes the hidden subscription's snapshot.
                for (member_table, member_subject) in members.iter() {
                    self.open_membership_subscription(
                        transport,
                        state,
                        tier,
                        member_table,
                        member_subject,
                    )
                    .await?;
                }
                Ok(())
            }
            other => other,
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

    /// Open the membership subscription a term needs, on the client's behalf
    /// (R27 decisions 3, 4, 7 and 12): the caller's own membership rows and
    /// nothing wider, announced ahead of its snapshot, hidden from the
    /// changed-tables signal by the client, and torn down with the last term
    /// subscription that needs it. Idempotent per session through the
    /// deterministic label, which also covers a reconnect registering the
    /// same term again.
    async fn open_membership_subscription<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
        tier: Tier,
        member_table: &str,
        member_subject: &str,
    ) -> Result<(), SessionError> {
        let label = membership_label(member_table);
        if state.subs.contains_key(&label) {
            return Ok(());
        }
        // `register_subscription` requires an identified caller for any term,
        // so the membership subscription always has an identity to filter by.
        let Some(identity) = state.principal.identity() else {
            return Err(SessionError::Snapshot(
                "a membership subscription needs an identified caller".to_owned(),
            ));
        };
        // The caller's own rows only (decision 12): a membership table
        // typically carries no policy of its own, so an unfiltered read would
        // snapshot every tenant's membership rows to every client. The
        // identity rides as a bind rather than as the caller function,
        // because a filter naming the caller directly is itself a term to
        // subql and would ask for a seed of its own, while a bound literal is
        // an ordinary predicate. The requirement, never the spelling, is what
        // decision 12 fixed.
        let query = format!(
            "SELECT * FROM {} WHERE {} = ?",
            connetto_core::quote_ident(member_table),
            connetto_core::quote_ident(member_subject),
        );
        let hidden = Subscribe {
            sub_id: label.clone(),
            spec: SubscriptionSpec::new(query)
                .with_binds(vec![BindValue::Text(identity.user_id.to_string())]),
        };
        transport
            .send_control(ControlMessage::MembershipOpened(MembershipOpened {
                sub_id: label.clone(),
                member_table: member_table.to_owned(),
            }))
            .await
            .map_err(transport_err)?;
        let consumer_id = self.next_consumer_id();
        let registration = match self
            .register_subscription(consumer_id, &hidden, state)
            .await
        {
            Ok((registration, _)) => registration,
            // The query is the server's own rendering over its own catalog,
            // so a refusal here is a server-side defect, never something the
            // caller sent, and it fails loudly rather than serving the term
            // without the rows its local answer needs.
            Err(err) => return Err(SessionError::Snapshot(err.to_string())),
        };
        let SqliteRegistration {
            registration,
            pg_sql,
        } = registration;
        let Registration::Row(sub_id) = registration else {
            return Err(SessionError::Snapshot(
                "a membership subscription registered as something other than rows".to_owned(),
            ));
        };
        let Some(_reader_permit) = self
            .subscribe_reader_permit(transport, tier, &label, sub_id)
            .await?
        else {
            return Ok(());
        };
        let reg = RowRegistration {
            consumer_id,
            sub_id,
            pg_sql,
            member_tables: std::sync::Arc::from(Vec::new()),
        };
        self.subscribe_row(transport, hidden, state, reg).await
    }

    /// Install the live route and record the subscription, so `dispatch_event`
    /// starts delivering to this consumer.
    ///
    /// Both row paths call this before reading anything. Until the route
    /// exists every patch produced for the consumer is discarded, and the
    /// snapshot read plus its bulk transfer is long enough to lose commits.
    ///
    /// The route also records the table the subscription reads, taken from the
    /// translated SQL rather than from the client's text, because that is what
    /// a moved grant is matched against (R7).
    async fn attach_row_route(
        &self,
        sub: &Subscribe,
        state: &mut SessionState<Id, Key>,
        reg: &RowRegistration,
    ) {
        self.add_route(
            reg.consumer_id,
            Route {
                session_key: state.session_id.as_u64_key(),
                sub_id: reg.sub_id,
                label: sub.sub_id.clone(),
                tx: state.outbound.clone(),
                principal: Arc::clone(&state.principal),
                table: crate::snapshot::table_from_select(&reg.pg_sql).ok(),
                pg_sql: reg.pg_sql.as_str().into(),
                binds: sub.spec.binds.clone().into(),
                member_tables: reg.member_tables.clone(),
            },
        )
        .await;
        state.subs.insert(
            sub.sub_id.clone(),
            RowSub {
                reg: reg.clone(),
                sub: sub.clone(),
            },
        );
    }

    /// Replace what one subscription holds, because a grant reaching its table
    /// moved (R7).
    ///
    /// The read comes first and the notice second, which `snapshot_row`
    /// guarantees, so a failed read leaves the client holding what it had and
    /// nothing is discarded on a promise. That is also why a failure is retried
    /// rather than reported: the rows are still there, wrongly, until the
    /// replacement lands. The backoff is the one the ingest loop uses when the
    /// authorization service is unreachable, because a read failing here is the
    /// same class of outage.
    async fn resnapshot_row<T: Transport>(
        &self,
        transport: &mut T,
        state: &mut SessionState<Id, Key>,
        sub_label: &str,
    ) -> Result<(), SessionError> {
        let mut attempt: u32 = 0;
        loop {
            // Read afresh each time: an unsubscribe may have landed between
            // attempts, and then there is nothing left to replace.
            let Some(row) = state.subs.get(sub_label) else {
                return Ok(());
            };
            let (sub, reg) = (row.sub.clone(), row.reg.clone());
            match self
                .snapshot_row(
                    transport,
                    sub,
                    state,
                    &reg,
                    Some(FullResyncReason::AuthorizationChange),
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(SessionError::Snapshot(detail)) => {
                    attempt = attempt.saturating_add(1);
                    let backoff = self.auth_retry.backoff(attempt);
                    tracing::warn!(
                        sub_id = %sub_label,
                        attempt,
                        error = %detail,
                        "replacing a subscription after a permission change failed, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                }
                Err(other) => return Err(other),
            }
        }
    }

    /// Snapshot a row subscription: route first, then read, then resync
    /// notice, begin, patch, end.
    ///
    /// The patch and the end share one queue, so the end cannot overtake the
    /// rows it completes however far behind the client has fallen. Only the
    /// patch spends a credit.
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
        self.attach_row_route(&sub, state, reg).await;
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
            Deliverable::Rows(BulkMessage::SnapshotPatch(SnapshotPatch::new(
                sub.sub_id.clone(),
                payload,
            ))),
        )
        .await
        .map_err(transport_err)?;
        // Queued rather than sent, so it cannot overtake the rows it completes
        // when the credit window is shut. It costs no credit: it waits its
        // turn, it is not rationed. Sending it here instead would tell the
        // client to record a resume position for rows still in `pending`
        // (R33).
        enqueue_and_flush(
            transport,
            &mut state.credits,
            &mut state.pending,
            Deliverable::SnapshotComplete(SnapshotEnd {
                sub_id: sub.sub_id,
                cursor: snapshot.cursor,
            }),
        )
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
    /// hold locally. The two-check form runs per client, so a row this caller may
    /// no longer see replays as the plain delete that takes it back, and a
    /// deleted row this caller could never see replays as nothing at all (R6).
    async fn catch_up_row<T: Transport>(
        &self,
        transport: &mut T,
        sub: Subscribe,
        state: &mut SessionState<Id, Key>,
        reg: &RowRegistration,
    ) -> Result<(), SessionError> {
        self.attach_row_route(&sub, state, reg).await;

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
        // One watcher, this session's caller, so the buffers hold one verdict
        // each and are reused across the whole replay.
        let watchers = [Arc::clone(&state.principal)];
        let mut verdicts = Transitions::new();
        for record in entries {
            if record.lsn() > ceiling {
                continue;
            }
            let replayed = {
                self.materializer
                    .lock()
                    .await
                    .replay_patch(record.event(), reg.consumer_id)?
            };
            let Some((payload, _departure)) = replayed else {
                continue;
            };
            let Some(payload) = self
                .replay_payload(transport, record.event(), &watchers, &mut verdicts, payload)
                .await?
            else {
                continue;
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
                Deliverable::Rows(BulkMessage::LivePatch(live)),
            )
            .await
            .map_err(transport_err)?;
        }
        Ok(())
    }

    /// What one replayed event delivers to this caller, or [`None`] when it
    /// delivers nothing (R6, the two-check form on the catchup path).
    ///
    /// `built` is the payload the materializer folded for this record, which is
    /// R44's marked departure notice when the row left this subscription's
    /// window.
    ///
    /// # Errors
    ///
    /// [`SessionError::ChangeStreamUnusable`] when the stream cannot report the
    /// previous version at all, and [`SessionError::Materializer`] when the
    /// withdrawal cannot be folded.
    async fn replay_payload<T: Transport>(
        &self,
        transport: &mut T,
        event: &ChangeEvent,
        watchers: &[Arc<Principal<Id, Key>>],
        verdicts: &mut Transitions,
        built: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, SessionError> {
        // A truncate carries no row, so no question can be put and it replays as
        // it stands, exactly as on the live path.
        if event.kind() == EventKind::Truncate {
            return Ok(Some(built));
        }
        // Retry the authorization question on error instead of silently skipping
        // the record: a skip followed by delivering later records would advance
        // the cursor past this one, making it permanently unreplayable from the
        // oplog.
        let mut auth_attempt: u32 = 0;
        let mut paused = false;
        loop {
            verdicts.reset(watchers.len());
            match transitions(&self.auth, event, self.catalog.as_ref(), watchers, verdicts).await {
                Ok(()) => {
                    if paused {
                        let _ = transport
                            .send_control(ControlMessage::DeliveryResumed)
                            .await;
                    }
                    break;
                }
                // Not transient, so retrying it would replay one record for ever.
                // The live path refuses on the same condition and for the same
                // reason.
                Err(
                    err @ (TransitionError::IncompletePreviousImage
                    | TransitionError::UnknownTable
                    | TransitionError::NotARowEvent),
                ) => return Err(self.transition_refusal(event, err)),
                Err(TransitionError::Policy(err)) => {
                    auth_attempt = auth_attempt.saturating_add(1);
                    if !paused {
                        let _ = transport
                            .send_control(ControlMessage::DeliveryPaused {
                                cause: PauseCause::AuthServiceUnreachable,
                            })
                            .await;
                        paused = true;
                    }
                    let backoff = self.auth_retry.backoff(auth_attempt);
                    tracing::warn!(
                        attempt = auth_attempt,
                        backoff_ms = backoff.as_millis(),
                        error = %err,
                        "auth service unreachable during catchup replay, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
        self.ask_second_opinion(event, watchers, verdicts.get())
            .await;
        // R44's departure notice takes the same three-way answer as the live
        // path: still visible and out of the window keeps the marked notice, out
        // of reach becomes the plain delete, and never in reach becomes silence
        // (R6 decision 6).
        match verdicts.get().first().copied().unwrap_or_default() {
            Transition::Nothing => Ok(None),
            Transition::Deliver => Ok(Some(built)),
            // A replayed delete's own patch already is the withdrawal, as on the
            // live path, so only an update pays a second fold.
            Transition::Withdraw if event.kind() == EventKind::Delete => Ok(Some(built)),
            Transition::Withdraw => {
                let withdrawal = { self.materializer.lock().await.withdrawal_patch(event)? };
                let withdrawal = withdrawal.ok_or_else(|| {
                    MaterializerError::Emit(
                        "a replayed row has to be taken back from a caller and the event folded \
                         to no operation to take it back with"
                            .to_owned(),
                    )
                })?;
                Ok(Some(withdrawal))
            }
        }
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
        // Announce the seed before reading it, so a change dispatched while the
        // connector is in flight is held and applied on top rather than folded
        // into an accumulator that does not exist yet (R28 part B).
        self.materializer
            .lock()
            .await
            .expect_aggregate(capture.consumer_id);
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

/// Queue `msg` then drain what the credit window allows, preserving FIFO order.
async fn enqueue_and_flush<T: Transport>(
    transport: &mut T,
    credits: &mut u32,
    pending: &mut VecDeque<Deliverable>,
    msg: Deliverable,
) -> Result<(), T::Error> {
    pending.push_back(msg);
    flush(transport, credits, pending).await
}

/// Drain the outbound queue in order, stopping at the first bulk frame the
/// credit window cannot pay for.
///
/// A free item behind a bulk frame the window cannot afford stays queued, and
/// that is the point: it is queued precisely because it describes data the
/// client has not received.
async fn flush<T: Transport>(
    transport: &mut T,
    credits: &mut u32,
    pending: &mut VecDeque<Deliverable>,
) -> Result<(), T::Error> {
    loop {
        if *credits == 0 && pending.front().is_some_and(Deliverable::costs_credit) {
            return Ok(());
        }
        let Some(next) = pending.pop_front() else {
            return Ok(());
        };
        match next {
            Deliverable::Rows(msg) => {
                transport.send_bulk(msg).await?;
                *credits -= 1;
            }
            Deliverable::SnapshotComplete(end) => {
                transport
                    .send_control(ControlMessage::SnapshotEnd(end))
                    .await?;
            }
        }
    }
}
