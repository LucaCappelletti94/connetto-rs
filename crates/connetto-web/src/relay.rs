//! Multi-tab relay hub, increment 3 of the browser relay topology.
//!
//! One worker-held [`ConnettoConnection`] owns the durable replica and the
//! server session, and any number of tabs speak the ordinary connetto wire
//! protocol to it over their own [`Transport`]s (an in-memory loopback, or a
//! [`MessageTransport`] over a `MessageChannel`
//! port). The hub is a single-task core fed by channels: each attached tab
//! gets a shovel task that owns its transport and exchanges frames with the
//! core, so the core never selects over a dynamic set of transports and sends
//! toward tabs never block it.
//!
//! Snapshots are generic: a throwaway capture session diffs each subscribed
//! table against an empty twin in an attached blank database, so values of
//! every storage class survive verbatim with no per-schema code. Live
//! patches are routed by table and forwarded at most once per tab. Tab
//! writes are applied to the worker replica with capture active, re-uploaded
//! by the worker connection, and an upstream verdict maps back to the owning
//! tab's own sequence number: a rejection as a `MutationReject` and a
//! conflict as a `MutationConflict`, so the tab draws the same distinction a
//! direct client would. A tab-level protocol violation closes that tab
//! alone, the hub and its other tabs keep running.
//!
//! A hub can also serve a device-local tier: tables living in their own
//! database file, never in the worker replica or on the server. A tab
//! mutation touching only those tables commits into the tier connection
//! (whose main schema IS the tier file, because a changeset apply always
//! targets main), is acknowledged by the hub itself as the terminal
//! authority, and fans out to every tab with a subscription reading a
//! touched table. A mutation spanning both tiers is rejected, because the
//! local half could not ride the rollback of an upstream rejection.
//!
//! Aggregate subscriptions are served by multiplexing a private upstream
//! subscription onto the worker connection per tab aggregate and demuxing the
//! server's pushes back to the owning tab, so a tab `watch_value` resolves
//! through the hub exactly as on a direct socket.
//!
//! A full resync propagates too. When the upstream cannot resume a subscription
//! incrementally it sends `FullResyncRequired` and a fresh snapshot, which the
//! worker's own client applies after clearing its stale replica rows. Once that
//! snapshot lands the hub fans a `FullResyncRequired` plus a fresh snapshot out
//! to every tab subscription reading the affected tables, so a tab drops rows
//! deleted during the outage exactly as a direct client would.
//!
//! Non-fatal errors stay scoped, so the relay never turns a recoverable per
//! request failure into a teardown. A tab subscription the hub cannot serve (an
//! unparsable or unservable query, a failed snapshot) draws a `NonFatalError`
//! correlated to that sub id, leaving the tab and its sibling subscriptions
//! alive, and the worker's own `NonFatal` for an aggregate or row upstream maps
//! back to the owning tab subscriptions the same way. Only a genuine protocol
//! violation closes a tab.
//!
//! Flow control matches the server: each tab has a delivery-credit window, so
//! bulk frames (`LivePatch`, `SnapshotPatch`) queue once credits reach zero and
//! drain on `AckCredits`. No control frame consumes a credit, so keepalive and
//! acknowledgements cannot deadlock behind a full window. `SnapshotEnd` is the
//! one control frame that still waits its turn in the queue, because it
//! describes rows the tab has not received yet.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::auth::PendingWork;
use crate::content_wire::{ContentFrame, WireResolve, mime_from_code};
use crate::frames::{
    InternalInbound, InternalLane, MessageSink, MessageTransport, MessageTransportError,
};
use crate::workers::blob_io::BlobSource;
use crate::workers::helpers::sleep_ms;
use connetto_client::reconnect::{ReconnectPolicy, Sleeper, TransportFactory};
use connetto_client::{
    AffectedRow, ClientError, ClientEvent, ConnettoConnection, ExportScope, ImportChoices,
    ImportOutcome, PolicyTables, subscription_is_aggregate, subscription_tables,
};
use connetto_core::messages::{
    AggregateUpdate, BulkMessage, ConflictRow, ControlMessage, FullResyncReason,
    FullResyncRequired, HandshakeAck, LivePatch, MutationApplied, MutationConflict, MutationReject,
    MutationRejectReason, NonFatalError, Pong, RateLimited, SUBSCRIPTION_REFUSED, SnapshotBegin,
    SnapshotEnd, SnapshotPatch, Subscribe, SubscriptionPriority, SubscriptionSpec, SyncStatus,
};
use connetto_core::traits::MaybeSend;
use connetto_core::{Cursor, IncomingFrame, Transport, quote_ident};
use connetto_file_client::{
    BrowserHttp, BrowserStore, ChunkScan, ContentArchive, ContentError, ContentFlush,
    ContentFlushStart, ContentFlushState, ContentUpload, FileId, PendingConnectionResolve,
    ResolveRoute, ResolveStart, Resolved, ScanStep, StageCommitError,
};
use diesel::SqliteConnection;
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::query_builder::{BoxedSqlQuery, SqlQuery};
use diesel::sql_query;
use diesel::sqlite::Sqlite;
use diesel_sqlite_session::{ConflictAction, SqliteSessionExt};
use futures_util::StreamExt;
use sqlite_diff_rs::{ChangesetOp, ParsedDiffSet, TableSchema, Value};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
/// Zstd level for relayed snapshot payloads, matching the client library default.
const ZSTD_LEVEL: i32 = 3;

/// Staged content older than this lost its mutation at the hub; the blob is
/// dropped when the tab next stages or writes.
const STALE_CONTENT_MS: f64 = 15_000.0;

/// Staged blobs a single tab may hold at once, oldest dropped first.
const MAX_STAGED_CONTENT: usize = 8;

/// Longest a tab's resolve question waits on a ticket round trip before the
/// hub answers `Unavailable`.
const RESOLVE_WAIT_MS: i32 = 15_000;

/// Upstream sequence numbers retained for mapping rejections back to a tab.
/// A rejection arrives well within this window, mirroring the client's own
/// pending cap.
const SEQ_MAP_CAP: usize = 256;

/// The delivery-credit window the hub advertises and enforces per tab,
/// matching the server's `initial_credits`. Only bulk frames (`LivePatch`,
/// `SnapshotPatch`) consume credits, so keepalive and acknowledgements cannot
/// deadlock behind a full window.
const INITIAL_CREDITS: u32 = 64;

/// Identifies one attached tab for the hub's lifetime.
pub type TabId = u64;

/// Failure surfaced by the hub pump. Tab-level faults never appear here,
/// they close the offending tab and the pump keeps running.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// The worker-held upstream connection failed.
    #[error("worker client: {0}")]
    Worker(#[from] ClientError),
    /// A statement against the worker replica failed.
    #[error("replica: {0}")]
    Replica(#[from] diesel::result::Error),
    /// The snapshot capture session failed.
    #[error("snapshot session: {0}")]
    Session(String),
    /// The blank schema twin for a subscribed table could not be built.
    #[error("snapshot schema: {0}")]
    Snapshot(String),
    /// An upstream patchset could not be parsed for routing.
    #[error("patch routing: {0}")]
    Patch(String),
    /// Compressing or decompressing a payload failed.
    #[error("compress: {0}")]
    Compress(#[from] std::io::Error),
    /// Browser content bookkeeping could not be installed.
    #[error(transparent)]
    Content(#[from] ContentError),
}

#[derive(Debug, thiserror::Error)]
enum ArchiveServiceError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Content(#[from] ContentError),
    #[error(
        "the {bytes} bytes of unsent content are above the {ceiling} bytes an archive may carry as attachments"
    )]
    ContentTooLarge { bytes: u64, ceiling: u64 },
    #[error(transparent)]
    Blob(#[from] crate::workers::BlobError),
}

/// The hub core has ended, so it can no longer answer.
#[derive(Debug, thiserror::Error)]
#[error("the relay hub core has ended")]
pub struct HubGone;

/// Why an export request came back without an archive.
#[derive(Debug, thiserror::Error)]
pub enum ExportRefused {
    /// Nobody answered: the hub core has ended, or from a page's side of the
    /// channel, no DB worker is listening.
    #[error(transparent)]
    Gone(#[from] HubGone),
    /// Somebody answered, and no archive came of it.
    #[error("export: {0}")]
    Failed(String),
}

/// Why an import request came back without an outcome.
#[derive(Debug, thiserror::Error)]
pub enum ImportRefused {
    /// Nobody answered: the hub core has ended.
    #[error(transparent)]
    Gone(#[from] HubGone),
    /// The core answered and the import was refused or failed.
    #[error("import: {0}")]
    Failed(String),
}

/// Why acknowledging lost content files did not take effect.
#[derive(Debug, thiserror::Error)]
pub enum ForgetRefused {
    /// Nobody answered: the hub core has ended.
    #[error(transparent)]
    Gone(#[from] HubGone),
    /// The core answered and the replica write failed.
    #[error("forget retired content: {0}")]
    Failed(String),
}

/// Why listing refused content did not return results.
#[derive(Debug, thiserror::Error)]
pub enum RefusedContentRefused {
    /// Nobody answered: the hub core has ended.
    #[error(transparent)]
    Gone(#[from] HubGone),
    /// The core answered and the replica read failed.
    #[error("refused content: {0}")]
    Failed(String),
}

/// Why clearing a content refusal did not take effect.
#[derive(Debug, thiserror::Error)]
pub enum RetryRefusalRefused {
    /// Nobody answered: the hub core has ended.
    #[error(transparent)]
    Gone(#[from] HubGone),
    /// The core answered and the replica write failed.
    #[error("retry refused: {0}")]
    Failed(String),
}

/// Something the hub tells its owner about, so platform glue can react
/// without living inside the core (the DB worker registers a liveness
/// watcher per handshake, for example).
#[derive(Debug)]
pub enum HubNotice {
    /// A tab completed its handshake.
    Handshake {
        /// The hub-assigned tab id.
        tab: TabId,
        /// The client id the tab declared, which names its liveness lock.
        client_id: String,
    },
}

/// What a shovel or a hub handle feeds into the core.
enum HubEvent {
    /// A new tab: registered before its shovel can emit any frame.
    Attached(TabId, UnboundedSender<TabOut>),
    /// One inbound frame from a tab.
    Frame(TabId, IncomingFrame),
    /// The tab's shovel ended (transport closed or failed).
    Gone(TabId),
    /// The owner wants this tab disconnected (a liveness watcher fired).
    Kill(TabId),
    /// Report local work that has not reached the server.
    Unsynced(futures_channel::oneshot::Sender<PendingWork>),
    /// Export the worker's local tiers as an archive. Same reason as
    /// [`Unsynced`](Self::Unsynced): only the core can reach the connection.
    Export(
        ExportScope,
        futures_channel::oneshot::Sender<Result<web_sys::Blob, ArchiveServiceError>>,
    ),
    /// Acknowledge lost content files, so they stop being reported. Same
    /// reason: only the core can reach the connection.
    ForgetRetired(
        Vec<FileId>,
        futures_channel::oneshot::Sender<Result<(), ArchiveServiceError>>,
    ),
    /// Import an archive: device-private rows and queued writes. Same reason.
    Import(
        web_sys::Blob,
        futures_channel::oneshot::Sender<Result<(ImportOutcome, usize), ArchiveServiceError>>,
    ),
    /// Query every refused outbox entry with its detail, answered from the
    /// replica. Same reason: only the core can reach the connection.
    RefusedContent(
        futures_channel::oneshot::Sender<Result<Vec<(FileId, String)>, ArchiveServiceError>>,
    ),
    /// Clear the refusal mark on one outbox entry, answered from the replica.
    /// Same reason: only the core can reach the connection.
    RetryRefused(
        FileId,
        futures_channel::oneshot::Sender<Result<(), ArchiveServiceError>>,
    ),
    /// One content-protocol message from a tab's internal lane. A `Stage`
    /// arrives with its blob; the other frames carry none.
    Internal(TabId, ContentFrame, Option<web_sys::Blob>),
}

/// One outbound frame toward a tab. Dropping a tab's sender closes it: the
/// shovel answers the closed channel by closing the transport.
enum TabOut {
    Control(ControlMessage),
    Bulk(BulkMessage),
    /// One content-protocol reply toward a tab, with the blob a `Local`
    /// resolution carries. Only transports attached with an internal lane
    /// can receive these.
    Internal(Vec<u8>, Option<web_sys::Blob>),
}

/// A fault while handling one tab's frame: either close that tab, or a
/// hub-fatal error.
enum TabFault {
    /// Close the offending tab, with the reason logged for debugging.
    Close(String),
    /// The hub itself failed.
    Hub(RelayError),
}

impl From<RelayError> for TabFault {
    fn from(err: RelayError) -> Self {
        Self::Hub(err)
    }
}

/// Per-tab state held by the core.
struct TabState {
    out: UnboundedSender<TabOut>,
    handshaken: bool,
    subs: Vec<TabSub>,
    /// Sequence number announced by a `MutationHeader`, awaiting its bulk
    /// patchset frame.
    pending_write: Option<u64>,
    /// The tab's own id, set by its handshake, keying its durable mutation
    /// watermark. Absent until the handshake, never a stand-in value.
    client_id: Option<rosetta_uuid::Uuid>,
    /// Highest tab sequence applied to the worker replica for this client
    /// id, from the hub meta schema at handshake and advanced per apply. A
    /// replayed sequence at or below it is re-acknowledged, never
    /// re-applied.
    applied_watermark: Option<u64>,
    /// Highest tab sequence applied to the local tier for this client id,
    /// the tier side sibling of `applied_watermark`.
    local_watermark: Option<u64>,
    /// Delivery credits remaining for this tab's bulk frames. A bulk send
    /// decrements it, an `AckCredits` frame replenishes it. Starts at
    /// `INITIAL_CREDITS`, mirroring the server's per-session window.
    credits: u32,
    /// Frames queued toward this tab, drained in FIFO order as credits return.
    pending: VecDeque<TabDeliverable>,
    /// Content blobs this tab has staged and not yet paired with a mutation,
    /// oldest first.
    staged: VecDeque<StagedContent>,
}

/// One staged blob awaiting the mutation that names it. The mutation pairs
/// by the declared identity, and content nothing paired by the time it goes
/// stale is dropped.
struct StagedContent {
    file_id: FileId,
    mime: connetto_file_core::MimeClass,
    blob: web_sys::Blob,
    /// `Date::now()` at arrival, milliseconds.
    taken: f64,
}

/// One item waiting on a tab's outbound queue.
///
/// Mirrors the server's `Deliverable`: whether a frame is rationed and whether
/// it is ordered against the data are two separate questions.
/// [`Rows`](Self::Rows) costs a credit, `SnapshotEnd` costs nothing but must
/// still travel behind the rows it completes.
///
/// The set is closed on purpose. A control frame that must **not** be held
/// behind data, a `Pong` above all, has no variant here and cannot be queued
/// by accident.
enum TabDeliverable {
    /// A bulk frame. Costs one credit.
    Rows(BulkMessage),
    /// The frame closing a snapshot. Ordered, never charged.
    SnapshotComplete(SnapshotEnd),
}

impl TabDeliverable {
    /// Whether sending this spends one of the tab's delivery credits.
    const fn costs_credit(&self) -> bool {
        matches!(self, Self::Rows(_))
    }
}

/// A failure inside the tab-mutation apply transaction.
#[derive(Debug)]
enum TabApplyError {
    /// The changeset failed to apply: rejected back to the tab.
    Apply(String),
    /// The replica or watermark storage failed: hub-fatal.
    Db(diesel::result::Error),
}

impl From<diesel::result::Error> for TabApplyError {
    fn from(err: diesel::result::Error) -> Self {
        Self::Db(err)
    }
}

/// DDL for the hub's durable per-tab mutation watermark. It lives in an
/// ATTACHED schema: the worker's capture session tracks only `main`, so
/// watermark writes never ride the worker's own uploads.
const HUB_META_DDL: &str = "CREATE TABLE IF NOT EXISTS connetto_hub._tab_mutations \
    (client_id BLOB NOT NULL PRIMARY KEY, last_seq BIGINT NOT NULL)";

/// DDL for the local tier's durable per-tab mutation watermark. It lives
/// in the tier database itself so it advances in the same transaction as
/// the apply, mirroring the server's `_connetto_mutations` design.
///
/// Qualified, because `CREATE TABLE` with a bare name would land in `main`.
/// Every later read and write of it is unqualified and typed, since a bare
/// name resolves across attached databases and `local_tier_tables` keeps
/// connetto's own tables out of the set a caller can name.
const LOCAL_META_DDL: &str = "CREATE TABLE IF NOT EXISTS connetto_local._connetto_tab_mutations \
    (client_id BLOB NOT NULL PRIMARY KEY, last_seq BIGINT NOT NULL)";

/// Typed schema for the local tier watermark table, which lives in the
/// ATTACHED `connetto_local` database. The declaration names no schema and
/// does not need to: a bare table name resolves across attached databases,
/// and the replica never holds a table of this name. The hub meta watermark
/// cannot do the same, because `connetto_hub._tab_mutations` collides with
/// nothing but is created under a schema `diesel::table!` will not model, so
/// those queries stay `sql_query`.
mod local_schema {
    diesel::table! {
        /// Per-tab durable write counter, the browser mirror of the server's
        /// mutation watermark.
        _connetto_tab_mutations (client_id) {
            /// Which tab the counter belongs to.
            client_id -> rosetta_uuid::sql_types::Uuid,
            /// The highest sequence that tab has durably uploaded.
            last_seq -> diesel::sql_types::BigInt,
        }
    }
}

/// One registered tab subscription and the tables its query reads.
struct TabSub {
    sub_id: String,
    tables: HashSet<String>,
    /// Delivery tier from the tab's Subscribe, replayed on a resync
    /// re-snapshot so the tab's `SnapshotBegin` matches the original.
    priority: SubscriptionPriority,
}

/// One aggregate subscription multiplexed onto the worker connection.
///
/// The worker replica holds only authorized rows, so a global aggregate
/// cannot be computed from it: the hub registers a private upstream
/// subscription on the worker connection and demultiplexes each pushed
/// [`AggregateUpdate`] back to the owning tab under its own sub id. The spec
/// is retained so [`hub_recover`] re-declares the upstream after a resume.
struct AggRoute {
    tab: TabId,
    tab_sub: String,
    spec: SubscriptionSpec,
}

/// The blank twin database used for generic snapshots.
#[derive(Default)]
struct BlankState {
    /// Whether the blank database is attached to the worker connection yet.
    attached: bool,
    /// Tables whose empty twin already exists in the blank schema.
    tables: HashSet<String>,
}

/// The attach name of the device-private tier on the worker connection. It is
/// the client's own `ATTACH` alias, and the hub reads and writes those tables
/// through the worker connection rather than opening the file a second time:
/// the browser's storage pool gives two connections to one file a single
/// underlying handle and two page caches, which is not a thing SQLite can be
/// asked to survive.
const LOCAL_SCHEMA: &str = "connetto_local";

/// The name of a connection's own database, which is where the synced replica
/// lives. Named so a snapshot reads the same way for either tier.
const MAIN_SCHEMA: &str = "main";

/// The schema the hub's own durable state is attached under.
const HUB_SCHEMA: &str = "connetto_hub";

/// Core state threaded through the hub loop.
#[derive(Default)]
struct HubState {
    tabs: HashMap<TabId, TabState>,
    /// Upstream push sequence to the owning tab and its sequence, for
    /// mapping rejections back. Entries of accepted mutations linger
    /// (acceptance has no reply), so the map is pruned oldest-first past
    /// [`SEQ_MAP_CAP`].
    seq_map: BTreeMap<u64, (TabId, u64)>,
    blank: BlankState,
    /// Lowercased names of the device-private tables the worker connection has
    /// attached, empty when this run serves no tier. Writes to them commit on
    /// the worker connection and can never reach the server, because the
    /// capture session is bound to `main` and these tables are not in it.
    local_tables: HashSet<String>,
    /// Whether the hub can currently reach the server, so a tab arriving later
    /// is told the current answer rather than having to wait for the next
    /// change, which may never come.
    sync_status: SyncStatus,
    /// Aggregate subscriptions multiplexed onto the worker connection,
    /// keyed by the private upstream sub id the hub registered
    /// (`agg-{tab}-{sub}`). Each entry demuxes the worker's
    /// [`AggregateUpdate`] back to the owning tab.
    agg_routes: HashMap<String, AggRoute>,
    /// Tables backing each row upstream subscription, keyed by the worker's
    /// upstream sub id, from the reconnect specs. Used to fan an upstream
    /// [`ClientEvent::FullResync`] out to the tab subscriptions reading those
    /// tables.
    resync_tables: HashMap<String, HashSet<String>>,
    /// Worker upstream subs currently between an upstream `FullResync` and the
    /// fresh snapshot's end, each with the reason it arrived with. Their
    /// `SnapshotEnd` triggers the tab re-snapshot, which carries that reason on
    /// rather than restating one cause as another.
    resyncing: HashMap<String, FullResyncReason>,

    /// Resolves waiting on a server ticket answer, each with the tab and
    /// request to answer and the `Date::now` instant its wait ends.
    pending_resolve: Vec<PendingHubResolve>,
}

/// One resolve whose ticket request is in flight, kept in the hub state so
/// the wait costs a slot rather than the event loop.
struct PendingHubResolve {
    tab: TabId,
    request_id: u64,
    ticket: PendingConnectionResolve,
    /// `Date::now` milliseconds by which the tab hears at the latest.
    deadline: f64,
}

/// Handle for attaching tabs to a running hub. Cloneable, and every clone
/// plus every live shovel keeps the hub pump alive.
#[derive(Clone)]
pub struct RelayHub {
    events: UnboundedSender<HubEvent>,
    next_tab: Arc<AtomicU64>,
}

/// Upstream reconnect wiring for a hub: how to make fresh server
/// connections, how to wait between attempts, when to give up, and which
/// upstream subscriptions to re-declare after a resume.
pub struct HubReconnect<F, S> {
    /// Makes fresh transports toward the server.
    pub factory: F,
    /// Waits between attempts.
    pub sleeper: S,
    /// Backoff and retry budget.
    pub policy: ReconnectPolicy,
    /// The hub's own upstream subscriptions, re-declared after every
    /// resume so the server streams retained changes from the cursor.
    pub upstream: Vec<(String, SubscriptionSpec)>,
}

/// Factory type for hubs configured without reconnect. Never invoked.
struct NoFactory<U>(core::marker::PhantomData<fn() -> U>);

impl<U> TransportFactory for NoFactory<U>
where
    U: Transport + MaybeSend + 'static,
{
    type Transport = U;
    type Error = core::convert::Infallible;

    fn connect(
        &mut self,
    ) -> impl Future<Output = Result<Self::Transport, Self::Error>> + MaybeSend {
        core::future::pending()
    }
}

/// Sleeper type for hubs configured without reconnect. Never invoked.
struct NoSleep;

impl Sleeper for NoSleep {
    fn sleep(&mut self, _duration: core::time::Duration) -> impl Future<Output = ()> + MaybeSend {
        core::future::ready(())
    }
}

impl RelayHub {
    /// Build a hub around a connected, subscribed worker connection.
    ///
    /// `hub_meta` is the database attached for the hub's own durable state
    /// (the per-tab mutation watermarks): a sahpool-backed file name in the
    /// DB worker, `:memory:` in tests. `local` is the device-local tier the
    /// hub serves alongside the worker replica, `None` when there are no
    /// local tables. Returns the handle, the pump future to spawn (it runs
    /// until the upstream session closes, the upstream fails, or every
    /// handle and shovel is gone), and the notice stream. Dropping the
    /// notice receiver is fine when the owner has no platform glue to run.
    ///
    /// # Errors
    ///
    /// [`RelayError::Replica`] when attaching the hub meta database fails.
    #[expect(
        clippy::type_complexity,
        reason = "the tuple is the constructor contract"
    )]
    pub fn new<U>(
        worker: ConnettoConnection<U>,
        hub_meta: &str,
    ) -> Result<
        (
            Self,
            impl Future<Output = Result<(), RelayError>>,
            UnboundedReceiver<HubNotice>,
        ),
        RelayError,
    >
    where
        U: Transport + MaybeSend + 'static,
        U::Error: core::fmt::Display,
    {
        Self::build(
            worker,
            hub_meta,
            None::<HubReconnect<NoFactory<U>, NoSleep>>,
            None,
            None::<NoSleep>,
        )
    }

    /// Like [`new`](Self::new), but the hub survives upstream transport
    /// drops: it backs off per the policy, obtains a fresh connection,
    /// resumes the session with the highest applied cursor, and re-declares
    /// its upstream subscriptions. Tabs keep reading the replica during the
    /// outage and their queued frames are served after the resume.
    ///
    /// # Errors
    ///
    /// [`RelayError::Replica`] when attaching the hub meta database fails.
    #[expect(
        clippy::type_complexity,
        reason = "the tuple is the constructor contract"
    )]
    pub fn with_reconnect<U, F, S>(
        worker: ConnettoConnection<U>,
        hub_meta: &str,
        reconnect: HubReconnect<F, S>,
    ) -> Result<
        (
            Self,
            impl Future<Output = Result<(), RelayError>>,
            UnboundedReceiver<HubNotice>,
        ),
        RelayError,
    >
    where
        U: Transport + MaybeSend + 'static,
        U::Error: core::fmt::Display,
        F: TransportFactory<Transport = U>,
        S: Sleeper,
    {
        Self::build(worker, hub_meta, Some(reconnect), None, None::<NoSleep>)
    }

    /// Builds a content-aware reconnecting hub whose transfers run under
    /// `content_http`, which carries the deployment's idle bound.
    ///
    /// # Errors
    ///
    /// [`RelayError::Content`] when content setup fails or [`RelayError::Replica`] when hub metadata cannot attach.
    #[expect(
        clippy::type_complexity,
        reason = "the tuple is the constructor contract"
    )]
    pub fn with_reconnect_and_content<U, F, S>(
        worker: ConnettoConnection<U>,
        hub_meta: &str,
        reconnect: HubReconnect<F, S>,
        content: ContentArchive<BrowserStore>,
        content_http: BrowserHttp,
    ) -> Result<
        (
            Self,
            impl Future<Output = Result<(), RelayError>>,
            UnboundedReceiver<HubNotice>,
        ),
        RelayError,
    >
    where
        U: Transport + MaybeSend + 'static,
        U::Error: core::fmt::Display,
        F: TransportFactory<Transport = U>,
        S: Sleeper + Clone,
    {
        let content_sleeper = reconnect.sleeper.clone();
        Self::build(
            worker,
            hub_meta,
            Some(reconnect),
            Some(HubContent {
                archive: content,
                http: content_http,
            }),
            Some(content_sleeper),
        )
    }

    #[expect(
        clippy::type_complexity,
        reason = "the tuple is the constructor contract"
    )]
    pub(crate) fn with_reconnect_archive<U, F, S>(
        worker: ConnettoConnection<U>,
        hub_meta: &str,
        reconnect: HubReconnect<F, S>,
        content: Option<ContentArchive<BrowserStore>>,
        content_http: BrowserHttp,
    ) -> Result<
        (
            Self,
            impl Future<Output = Result<(), RelayError>>,
            UnboundedReceiver<HubNotice>,
        ),
        RelayError,
    >
    where
        U: Transport + MaybeSend + 'static,
        U::Error: core::fmt::Display,
        F: TransportFactory<Transport = U>,
        S: Sleeper + Clone,
    {
        let content_sleeper = content.as_ref().map(|_| reconnect.sleeper.clone());
        let content = content.map(|archive| HubContent {
            archive,
            http: content_http,
        });
        Self::build(worker, hub_meta, Some(reconnect), content, content_sleeper)
    }

    /// Shared constructor body behind the two hub flavors: attach the hub
    /// meta database and ensure its schema, ensure the device-private tier's
    /// watermark table when this run has one, then assemble the channels.
    #[expect(
        clippy::type_complexity,
        reason = "the tuple is the constructor contract"
    )]
    fn build<U, F, S, CS>(
        mut worker: ConnettoConnection<U>,
        hub_meta: &str,
        reconnect: Option<HubReconnect<F, S>>,
        content: Option<HubContent>,
        content_sleeper: Option<CS>,
    ) -> Result<
        (
            Self,
            impl Future<Output = Result<(), RelayError>>,
            UnboundedReceiver<HubNotice>,
        ),
        RelayError,
    >
    where
        U: Transport + MaybeSend + 'static,
        U::Error: core::fmt::Display,
        F: TransportFactory<Transport = U>,
        S: Sleeper,
        CS: Sleeper,
    {
        let local_tables = prepare_hub_worker(
            &mut worker,
            hub_meta,
            content.as_ref().map(HubContent::archive),
        )?;
        let (events_tx, events_rx) = unbounded_channel();
        let (notices_tx, notices_rx) = unbounded_channel();
        let hub = Self {
            events: events_tx,
            next_tab: Arc::new(AtomicU64::new(0)),
        };
        Ok((
            hub,
            run_hub(
                worker,
                local_tables,
                events_rx,
                notices_tx,
                reconnect,
                content,
                content_sleeper,
            ),
            notices_rx,
        ))
    }

    /// Attach one tab transport and spawn its shovel task.
    pub fn attach<D>(&self, tab: D) -> TabId
    where
        D: Transport + 'static,
        D::Error: core::fmt::Display,
    {
        self.spawn_tab(tab, None, None)
    }

    /// Attach one message transport together with its internal lane, so the
    /// tab can stage content and ask resolution questions alongside its
    /// sync frames.
    pub fn attach_with_content<S>(&self, mut tab: MessageTransport<S>) -> TabId
    where
        S: MessageSink + Clone + 'static,
    {
        let internal_rx = tab.take_internal_inbox();
        let replier: Box<dyn InternalReplier> = Box::new(InternalLaneReplier(tab.internal_lane()));
        self.spawn_tab(tab, internal_rx, Some(replier))
    }

    fn spawn_tab<D>(
        &self,
        tab: D,
        internal_rx: Option<futures_channel::mpsc::UnboundedReceiver<InternalInbound>>,
        replier: Option<Box<dyn InternalReplier>>,
    ) -> TabId
    where
        D: Transport + 'static,
        D::Error: core::fmt::Display,
    {
        // Relaxed: pure id allocation, nothing orders against it.
        let id = self.next_tab.fetch_add(1, Ordering::Relaxed);
        let (out_tx, out_rx) = unbounded_channel();
        // Queued before the shovel exists, so the core learns the tab
        // before its first frame can possibly arrive on the same channel.
        let _ = self.events.send(HubEvent::Attached(id, out_tx));
        wasm_bindgen_futures::spawn_local(shovel(
            id,
            tab,
            out_rx,
            internal_rx,
            replier,
            self.events.clone(),
        ));
        id
    }

    /// Disconnect one tab, as when its liveness lock reports it dead. The
    /// core drops the tab's state, which closes its transport politely.
    pub fn kill(&self, tab: TabId) {
        let _ = self.events.send(HubEvent::Kill(tab));
    }

    /// Returns a snapshot of mutations and content files not yet acknowledged.
    ///
    /// # Errors
    ///
    /// [`HubGone`] when the core has ended, so no answer will come.
    pub async fn unsynced(&self) -> Result<PendingWork, HubGone> {
        self.ask(HubEvent::Unsynced).await
    }

    /// A zip archive of the worker's local data, scoped as requested.
    ///
    /// The worker connection is the only durable copy in this topology.
    ///
    /// # Errors
    ///
    /// [`ExportRefused::Gone`] when the core has ended.
    /// [`ExportRefused::Failed`] when the core answered and the export failed.
    pub async fn export_local_data(
        &self,
        scope: ExportScope,
    ) -> Result<web_sys::Blob, ExportRefused> {
        self.ask(|reply| HubEvent::Export(scope, reply))
            .await?
            .map_err(|err| ExportRefused::Failed(err.to_string()))
    }

    /// Apply an archive to the worker connection: device-private rows and
    /// queued writes. Every clash resolves in the file's favour.
    ///
    /// Returns the outcome and the number of rows where the file won over a
    /// locally held version.
    ///
    /// # Errors
    ///
    /// [`ImportRefused::Gone`] when the core has ended.
    /// [`ImportRefused::Failed`] when the plan or apply step is refused.
    pub async fn import_local_data(
        &self,
        archive: web_sys::Blob,
    ) -> Result<(ImportOutcome, usize), ImportRefused> {
        self.ask(|reply| HubEvent::Import(archive, reply))
            .await?
            .map_err(|err| ImportRefused::Failed(err.to_string()))
    }

    /// Acknowledge lost content files, so pending-work answers stop naming them.
    ///
    /// # Errors
    ///
    /// [`ForgetRefused::Gone`] when the core has ended.
    /// [`ForgetRefused::Failed`] when the replica write failed.
    pub async fn forget_retired_content(&self, files: Vec<FileId>) -> Result<(), ForgetRefused> {
        self.ask(|reply| HubEvent::ForgetRetired(files, reply))
            .await?
            .map_err(|err| ForgetRefused::Failed(err.to_string()))
    }

    /// Every refused outbox entry with its permanent refusal detail.
    ///
    /// Answered from the replica, so it is served while the connection is idle
    /// and interrupts an attach, the same class as [`forget_retired_content`](Self::forget_retired_content).
    ///
    /// # Errors
    ///
    /// [`RefusedContentRefused::Gone`] when the core has ended.
    /// [`RefusedContentRefused::Failed`] when the replica read failed.
    pub async fn refused_content(&self) -> Result<Vec<(FileId, String)>, RefusedContentRefused> {
        self.ask(HubEvent::RefusedContent)
            .await?
            .map_err(|err| RefusedContentRefused::Failed(err.to_string()))
    }

    /// Clears the refusal mark on one outbox entry so the next walk attempts it.
    ///
    /// Answered from the replica and wakes the outbox driver wherever the
    /// request was served, so neither a reconnect nor an import is needed.
    ///
    /// # Errors
    ///
    /// [`RetryRefusalRefused::Gone`] when the core has ended.
    /// [`RetryRefusalRefused::Failed`] when the replica write failed.
    pub async fn retry_refused(&self, file_id: FileId) -> Result<(), RetryRefusalRefused> {
        self.ask(|reply| HubEvent::RetryRefused(file_id, reply))
            .await?
            .map_err(|err| RetryRefusalRefused::Failed(err.to_string()))
    }

    /// Queue one request the core answers on its own channel, and wait for it.
    async fn ask<T>(
        &self,
        request: impl FnOnce(futures_channel::oneshot::Sender<T>) -> HubEvent,
    ) -> Result<T, HubGone> {
        let (reply, answer) = futures_channel::oneshot::channel();
        self.events.send(request(reply)).map_err(|_| HubGone)?;
        answer.await.map_err(|_| HubGone)
    }
}

/// A hub's content wiring: the archive it walks and the transport its
/// transfers run under, which carries the deployment's idle bound.
struct HubContent {
    archive: ContentArchive<BrowserStore>,
    http: BrowserHttp,
}

impl HubContent {
    /// The archive every content read and write goes through.
    const fn archive(&self) -> &ContentArchive<BrowserStore> {
        &self.archive
    }
}

fn prepare_hub_worker<U: Transport>(
    worker: &mut ConnettoConnection<U>,
    hub_meta: &str,
    content: Option<&ContentArchive<BrowserStore>>,
) -> Result<HashSet<String>, RelayError> {
    if let Some(content) = content {
        content.install(worker)?;
    }
    // Hub metadata must share the replica codec and key salt.
    connetto_client::harden::attach_in_window(
        worker.conn(),
        hub_meta,
        HUB_SCHEMA,
        connetto_client::harden::AttachPermits::CreateAndWrite,
    )?;
    worker.conn().batch_execute(HUB_META_DDL)?;
    let local_tables = worker.local_tables().clone();
    if !local_tables.is_empty() {
        worker.conn().batch_execute(LOCAL_META_DDL)?;
    }
    Ok(local_tables)
}

/// The reply leg of an attached tab's internal lane, boxed shape for the
/// shovel so the lane's sink type stays private to the attach call.
trait InternalReplier {
    /// Post one internal message to the tab.
    ///
    /// # Errors
    ///
    /// [`MessageTransportError::Sink`] when the browser refuses the post.
    fn post(&self, json: &[u8], blob: Option<&web_sys::Blob>) -> Result<(), MessageTransportError>;
}

struct InternalLaneReplier<S: MessageSink>(InternalLane<S>);

impl<S: MessageSink> InternalReplier for InternalLaneReplier<S> {
    fn post(&self, json: &[u8], blob: Option<&web_sys::Blob>) -> Result<(), MessageTransportError> {
        self.0.post_internal(json, blob)
    }
}

/// The per-tab I/O task: owns the transport, feeds inbound frames and
/// internal messages to the core, writes outbound frames and internal
/// replies, and closes the transport when the core drops the tab.
async fn shovel<D>(
    id: TabId,
    mut tab: D,
    mut out_rx: UnboundedReceiver<TabOut>,
    mut internal_rx: Option<futures_channel::mpsc::UnboundedReceiver<InternalInbound>>,
    replier: Option<Box<dyn InternalReplier>>,
    events: UnboundedSender<HubEvent>,
) where
    D: Transport,
    D::Error: core::fmt::Display,
{
    loop {
        // Cancel safety: every leg parks on an mpsc backed receive, which
        // loses nothing when dropped, and sends on the transports this hub
        // runs over (loopback and message ports) complete in one poll, so a
        // losing branch is only ever dropped while parked.
        //
        // Biased on purpose: the content lane and the codec frames share one
        // message port, so a staged blob is posted before the mutation that
        // names it, and poll order here is the only thing that keeps that
        // order at the hub. A fair select could deliver the mutation first
        // and lose the pairing. The handshake needs no such guard: a tab
        // stages only after its ack round trip, which the hub already
        // answered.
        tokio::select! {
            biased;
            inbound = async {
                match internal_rx.as_mut() {
                    Some(rx) => rx.next().await,
                    None => std::future::pending::<Option<InternalInbound>>().await,
                }
            } => match inbound {
                Some(inbound) => match ContentFrame::from_json(&inbound.json) {
                    Some(frame) => {
                        if events
                            .send(HubEvent::Internal(id, frame, inbound.blob))
                            .is_err()
                        {
                            break;
                        }
                    }
                    None => {
                        tracing::warn!(tab = %id, "relay hub dropped an undecodable internal frame");
                    }
                },
                // The lane ended with its transport; parking on a closed
                // channel would spin until the frame leg catches up.
                None => break,
            },
            frame = tab.recv() => match frame {
                Ok(Some(frame)) => {
                    if events.send(HubEvent::Frame(id, frame)).is_err() {
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            },
            out = out_rx.recv() => match out {
                Some(TabOut::Control(message)) => {
                    if tab.send_control(message).await.is_err() {
                        break;
                    }
                }
                Some(TabOut::Bulk(message)) => {
                    if tab.send_bulk(message).await.is_err() {
                        break;
                    }
                }
                Some(TabOut::Internal(json, blob)) => {
                    // Only core replies reach this arm, and only tabs
                    // attached with a lane receive them.
                    if let Some(replier) = &replier {
                        let _ = replier.post(&json, blob.as_ref());
                    }
                }
                None => {
                    let _ = tab.close().await;
                    break;
                }
            },
        }
    }
    let _ = events.send(HubEvent::Gone(id));
}

fn initial_hub_state<U, F, S>(
    worker: &ConnettoConnection<U>,
    reconnect: Option<&HubReconnect<F, S>>,
    local_tables: HashSet<String>,
) -> HubState
where
    U: Transport,
{
    let mut state = HubState {
        local_tables,
        sync_status: if worker.is_connected() {
            SyncStatus::Connected
        } else {
            SyncStatus::Offline
        },
        ..HubState::default()
    };
    if let Some(driver) = reconnect {
        for (sub_id, spec) in &driver.upstream {
            if let Ok(false) = subscription_is_aggregate(&spec.query)
                && let Ok(tables) = subscription_tables(&spec.query)
            {
                state.resync_tables.insert(sub_id.clone(), tables);
            }
        }
    }
    state
}

#[derive(Default)]
struct ContentRetry {
    policy: ReconnectPolicy,
    attempt: u32,
    delay: Option<core::time::Duration>,
    flush: ContentFlushState,
}
impl ContentRetry {
    fn schedule(&mut self, queued: bool, progressed: bool) {
        match (queued, progressed) {
            (false, _) => self.attempt = 0,
            (true, true) => {
                self.attempt = 0;
                self.delay = Some(core::time::Duration::ZERO);
            }
            (true, false) => {
                self.attempt = self.attempt.saturating_add(1);
                self.delay = Some(self.policy.backoff(self.attempt));
            }
        }
    }
}

enum ContentWalk {
    Complete { queued: bool, progressed: bool },
    Interrupted(Option<HubEvent>),
}

/// Everything one hub task owns: the worker connection, tab state, the notice
/// channel, the optional content archive and the transport its transfers run
/// under, the event intake and the content retry schedule.
struct HubRuntime<U: Transport> {
    worker: ConnettoConnection<U>,
    state: HubState,
    notices: UnboundedSender<HubNotice>,
    content: Option<HubContent>,
    events: UnboundedReceiver<HubEvent>,
    retry: ContentRetry,
    walk: WalkState,
}

/// What the content integrity walk still owes this run.
#[derive(Default)]
struct WalkState {
    /// Outbox files still to be checked for readable bytes.
    unverified: VecDeque<connetto_file_client::FileId>,
    /// Position of the scan over the head file's chunks.
    scan: ChunkScan,
    /// Whether the orphan sweep owes a turn, set at the start and by every import.
    unswept: bool,
    /// Whether a failed sweep is waiting for the content retry timer.
    sweep_waiting: bool,
    /// Orphaned chunks the sweep has listed and not yet deleted.
    orphans: VecDeque<connetto_file_client::ChunkHash>,
    /// Whether a commit has queued work the outbox driver has not been told about.
    outbox_wake: bool,
}

/// Chunks read per integrity turn, small enough that a turn cannot hold the cycle.
const VERIFY_CHUNK_BUDGET: usize = 8;

/// Orphaned chunks deleted per turn, for the same reason.
const DISCARD_BUDGET: usize = 8;

/// Why one hub cycle woke.
enum Wake {
    /// The content retry timer elapsed.
    Content,
    /// A tab or application request arrived.
    Local(Option<HubEvent>),
    /// The worker connection produced an event.
    Upstream(Result<ClientEvent, ClientError>),
    /// The content integrity walk has a file left to check.
    Verify,
    /// A resolve's ticket wait ran out while the hub served everything else.
    Resolve,
}

impl<U> HubRuntime<U>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    /// Serve hub events until the intake closes or the connection is beyond recovery.
    async fn run<F, S, CS>(
        mut self,
        mut reconnect: Option<HubReconnect<F, S>>,
        mut sleeper: Option<CS>,
    ) -> Result<(), RelayError>
    where
        U: MaybeSend + 'static,
        F: TransportFactory<Transport = U>,
        S: Sleeper,
        CS: Sleeper,
    {
        self.load_unverified();
        while self.cycle(reconnect.as_mut(), sleeper.as_mut()).await? {}
        Ok(())
    }

    async fn cycle<F, S, CS>(
        &mut self,
        reconnect: Option<&mut HubReconnect<F, S>>,
        sleeper: Option<&mut CS>,
    ) -> Result<bool, RelayError>
    where
        U: MaybeSend + 'static,
        F: TransportFactory<Transport = U>,
        S: Sleeper,
        CS: Sleeper,
    {
        if self.walk.outbox_wake {
            // An import commits restored writes and files wherever it was served, so the
            // driver is told here rather than by whichever path served it.
            self.walk.outbox_wake = false;
            self.wake_content()?;
        }
        let unverified = walk_owes(&self.walk);
        let delay = self.retry.delay;
        let content_wait = async {
            match (delay, sleeper) {
                (Some(delay), Some(sleeper)) => sleeper.sleep(delay).await,
                _ => core::future::pending().await,
            }
        };
        tokio::pin!(content_wait);
        // The resolve waits ride a timer here rather than parking a handler:
        // when one fires, the sweep answers only the waits that have truly
        // elapsed and the loop keeps serving everything else in between.
        let resolve_ms = resolve_deadline_ms(&self.state.pending_resolve);
        let resolve_wait = async {
            match resolve_ms {
                Some(ms) => sleep_ms(ms).await,
                None => core::future::pending().await,
            }
        };
        tokio::pin!(resolve_wait);
        // Each arm only names its wake reason, so a losing branch leaves
        // nothing half applied: every mpsc receive loses nothing when dropped.
        let wake = {
            let Self {
                worker,
                events,
                retry,
                ..
            } = self;
            tokio::select! {
                () = &mut content_wait => Wake::Content,
                event = events.recv() => Wake::Local(event),
                event = worker.pump_one(), if !retry.flush.is_waiting() => Wake::Upstream(event),
                // Always ready, so the walk shares the cycle with every other source
                // rather than holding it or being starved by it.
                () = core::future::ready(()), if unverified => Wake::Verify,
                () = &mut resolve_wait, if resolve_ms.is_some() => Wake::Resolve,
            }
        };
        match wake {
            Wake::Content => self.drive_content(reconnect).await,
            Wake::Local(event) => self.serve_local(event).await,
            Wake::Upstream(event) => self.serve_upstream(reconnect, event).await,
            Wake::Verify => self.verify_turn().await,
            Wake::Resolve => {
                expire_resolves(&mut self.state);
                Ok(true)
            }
        }
    }

    async fn serve(&mut self, event: HubEvent) -> Result<(), RelayError> {
        handle_hub_event(
            &mut self.worker,
            &mut self.state,
            &self.notices,
            self.content.as_ref().map(HubContent::archive),
            &mut self.walk,
            event,
        )
        .await
    }

    async fn serve_local(&mut self, event: Option<HubEvent>) -> Result<bool, RelayError> {
        let Some(event) = event else {
            return Ok(false);
        };
        self.serve(event).await?;
        Ok(true)
    }

    async fn serve_upstream<F, S>(
        &mut self,
        reconnect: Option<&mut HubReconnect<F, S>>,
        event: Result<ClientEvent, ClientError>,
    ) -> Result<bool, RelayError>
    where
        U: MaybeSend + 'static,
        F: TransportFactory<Transport = U>,
        S: Sleeper,
    {
        match event {
            Ok(ClientEvent::Closed | ClientEvent::ServerClosed { .. })
            | Err(ClientError::Transport(_) | ClientError::NotConnected) => {
                self.retry.delay = None;
                let Some(driver) = reconnect else {
                    return Ok(false);
                };
                if !self.recover(driver).await? {
                    return Ok(false);
                }
                self.wake_content()?;
                Ok(true)
            }
            Ok(event) => {
                let wake_content = matches!(
                    &event,
                    ClientEvent::Reconnected
                        | ClientEvent::SyncStatus(SyncStatus::Connected)
                        | ClientEvent::MutationApplied { .. }
                );
                handle_worker_event(&mut self.worker, &mut self.state, event)?;
                if wake_content {
                    self.wake_content()?;
                }
                Ok(true)
            }
            Err(err) => Err(err.into()),
        }
    }

    async fn recover<F, S>(&mut self, driver: &mut HubReconnect<F, S>) -> Result<bool, RelayError>
    where
        U: MaybeSend + 'static,
        F: TransportFactory<Transport = U>,
        S: Sleeper,
    {
        hub_recover(
            &mut self.worker,
            driver,
            &mut self.state,
            &self.notices,
            self.content.as_ref().map(HubContent::archive),
            &mut self.events,
            &mut self.walk,
        )
        .await
    }

    /// Walk the content outbox once, then reschedule the driver from what the walk left.
    async fn drive_content<F, S>(
        &mut self,
        reconnect: Option<&mut HubReconnect<F, S>>,
    ) -> Result<bool, RelayError>
    where
        U: MaybeSend + 'static,
        F: TransportFactory<Transport = U>,
        S: Sleeper,
    {
        self.retry.delay = None;
        self.walk.sweep_waiting = false;
        if self.content.is_none() {
            return Ok(true);
        }
        let (queued, progressed) = match self.flush_content().await? {
            ContentWalk::Complete { queued, progressed } => (queued, progressed),
            ContentWalk::Interrupted(Some(event)) => {
                self.serve(event).await?;
                self.retry.schedule(true, true);
                return Ok(true);
            }
            ContentWalk::Interrupted(None) => return Ok(false),
        };
        if progressed {
            // An uploaded file is no longer unsent, so retention can release it.
            self.walk.unswept = true;
            self.walk.sweep_waiting = false;
        }
        if !self.worker.is_connected() {
            let Some(driver) = reconnect else {
                return Ok(false);
            };
            if !self.recover(driver).await? {
                return Ok(false);
            }
            self.retry.schedule(queued, true);
            return Ok(true);
        }
        self.retry.schedule(queued, progressed);
        Ok(true)
    }

    /// One outbox attempt, serving local events across its HTTP transfer.
    async fn flush_content(&mut self) -> Result<ContentWalk, RelayError> {
        let Self {
            worker,
            state,
            notices,
            content,
            events,
            retry,
            walk,
        } = self;
        let Some(content) = content.as_ref() else {
            return Ok(ContentWalk::Complete {
                queued: false,
                progressed: false,
            });
        };
        let mut interrupted = None;
        let cancel = async {
            interrupted = Some(events.recv().await);
        };
        let (start, observed) = content
            .archive()
            .begin_flush_next_or(worker, &mut retry.flush, cancel)
            .await;
        for event in observed {
            handle_worker_event(worker, state, event)?;
        }
        let flush = match start {
            Ok(ContentFlushStart::Complete(ContentFlush::Interrupted)) => {
                return Ok(ContentWalk::Interrupted(interrupted.unwrap_or(None)));
            }
            Ok(ContentFlushStart::Complete(flush)) => flush,
            Ok(ContentFlushStart::Upload(upload)) => {
                finish_content_upload(worker, state, notices, content, events, walk, &upload)
                    .await?
            }
            Err(err) => {
                tracing::warn!(error = %err, "content outbox walk failed");
                ContentFlush::Deferred
            }
        };
        Ok(ContentWalk::Complete {
            queued: content.archive().sendable_files(worker)? > 0,
            progressed: flush == ContentFlush::Progressed,
        })
    }

    /// Queue the outbox for the integrity walk, which runs one file per turn.
    fn load_unverified(&mut self) {
        let Some(content) = self.content.as_ref() else {
            return;
        };
        match content.archive().unsent_files(&mut self.worker) {
            Ok(files) => self.walk.unverified = files.into(),
            Err(err) => tracing::warn!(error = %err, "content integrity pass failed"),
        }
    }

    /// Take one turn of the content integrity walk.
    ///
    /// The turn is bounded, and a failure asks for the upload retry's own backoff rather
    /// than the next cycle, so a store that keeps failing is not walked in a loop.
    async fn verify_turn(&mut self) -> Result<bool, RelayError> {
        let Self {
            worker,
            content,
            walk,
            retry,
            ..
        } = self;
        if walk_turn(worker, content.as_ref().map(HubContent::archive), walk).await
            == WalkTurn::Deferred
        {
            retry.schedule(true, false);
            return Ok(true);
        }
        if walk_owes(&self.walk) {
            return Ok(true);
        }
        self.wake_content()?;
        Ok(true)
    }

    fn wake_content(&mut self) -> Result<(), RelayError> {
        if content_sendable_files(
            &mut self.worker,
            self.content.as_ref().map(HubContent::archive),
        )? > 0
        {
            self.retry.schedule(true, true);
        }
        Ok(())
    }
}

/// Whether the content integrity walk still owes this run a turn.
fn walk_owes(walk: &WalkState) -> bool {
    !walk.unverified.is_empty() || !walk.orphans.is_empty() || (walk.unswept && !walk.sweep_waiting)
}

/// What one walk turn left behind.
#[derive(PartialEq, Eq)]
enum WalkTurn {
    /// The turn ran, and the walk may owe more.
    Taken,
    /// The store failed, so the rest waits for the retry timer.
    Deferred,
}

/// One bounded turn of the integrity walk: eight chunks of the head file, or the sweep
/// listing, or eight of the listed deletions.
///
/// Driven from the connected cycle and from the recovery waits that leave the connection
/// idle, because the walk reads only the replica and the chunk store.
async fn walk_turn<U>(
    worker: &mut ConnettoConnection<U>,
    content: Option<&ContentArchive<BrowserStore>>,
    walk: &mut WalkState,
) -> WalkTurn
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let Some(content) = content else {
        walk.unverified.clear();
        walk.orphans.clear();
        walk.unswept = false;
        return WalkTurn::Taken;
    };
    if !walk.orphans.is_empty() {
        return discard_turn(worker, content, walk).await;
    }
    let Some(&file_id) = walk.unverified.front() else {
        // The files are settled, so the bytes none of them name can go.
        if list_orphans(worker, content, walk).await {
            walk.unswept = false;
            return WalkTurn::Taken;
        }
        walk.sweep_waiting = true;
        return WalkTurn::Deferred;
    };
    match content
        .scan_unsent_file(worker, file_id, walk.scan, VERIFY_CHUNK_BUDGET)
        .await
    {
        Ok(ScanStep::More(scan)) => {
            walk.scan = scan;
            return WalkTurn::Taken;
        }
        // The identity is durable in the replica until acknowledged, so a pending-work
        // query reports it rather than this line.
        Ok(ScanStep::Retired) => {
            tracing::warn!(%file_id, "content integrity pass retired unreadable file");
        }
        Ok(ScanStep::Intact) => {}
        Err(err) => tracing::warn!(error = %err, "content integrity pass failed"),
    }
    walk.unverified.pop_front();
    walk.scan = ChunkScan::default();
    WalkTurn::Taken
}

/// Drop the manifests nothing covers, then list the chunks that leaves behind along with
/// those an interrupted import or stage left, reporting whether the listing succeeded.
async fn list_orphans<U>(
    worker: &mut ConnettoConnection<U>,
    content: &ContentArchive<BrowserStore>,
    walk: &mut WalkState,
) -> bool
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    match content.evict_uncovered(worker) {
        Ok(0) => {}
        Ok(evicted) => tracing::info!(evicted, "evicted uncovered content manifests"),
        Err(err) => tracing::warn!(error = %err, "evicting uncovered manifests failed"),
    }
    match content.orphan_chunks(worker).await {
        Ok(orphans) => {
            if !orphans.is_empty() {
                tracing::info!(
                    orphans = orphans.len(),
                    "reclaiming orphaned content chunks"
                );
            }
            walk.orphans = orphans.into();
            true
        }
        Err(err) => {
            tracing::warn!(error = %err, "listing orphaned chunks failed");
            false
        }
    }
}

/// Delete a bounded number of the listed orphans.
async fn discard_turn<U>(
    worker: &mut ConnettoConnection<U>,
    content: &ContentArchive<BrowserStore>,
    walk: &mut WalkState,
) -> WalkTurn
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    for _ in 0..DISCARD_BUDGET {
        let Some(hash) = walk.orphans.pop_front() else {
            break;
        };
        if let Err(err) = content.discard_chunk(worker, &hash).await {
            tracing::warn!(error = %err, "discarding an orphaned chunk failed");
            walk.orphans.clear();
            walk.sweep_waiting = true;
            walk.unswept = true;
            return WalkTurn::Deferred;
        }
    }
    WalkTurn::Taken
}

/// The hub core: one task owning the worker connection and every tab's
/// state, fed exclusively by channels. With reconnect wiring, an upstream
/// transport drop is recovered in place: tabs stay attached and their
/// queued frames are served after the resume.
async fn run_hub<U, F, S, CS>(
    worker: ConnettoConnection<U>,
    local_tables: HashSet<String>,
    events: UnboundedReceiver<HubEvent>,
    notices: UnboundedSender<HubNotice>,
    reconnect: Option<HubReconnect<F, S>>,
    content: Option<HubContent>,
    content_sleeper: Option<CS>,
) -> Result<(), RelayError>
where
    U: Transport + MaybeSend + 'static,
    U::Error: core::fmt::Display,
    F: TransportFactory<Transport = U>,
    S: Sleeper,
    CS: Sleeper,
{
    let state = initial_hub_state(&worker, reconnect.as_ref(), local_tables);
    HubRuntime {
        worker,
        state,
        notices,
        content,
        events,
        retry: ContentRetry::default(),
        walk: WalkState {
            unswept: true,
            ..WalkState::default()
        },
    }
    .run(reconnect, content_sleeper)
    .await
}

/// One granted upload, run to completion while local events keep being served.
async fn finish_content_upload<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
    notices: &UnboundedSender<HubNotice>,
    content: &HubContent,
    events: &mut UnboundedReceiver<HubEvent>,
    walk: &mut WalkState,
    upload: &ContentUpload<BrowserStore>,
) -> Result<ContentFlush, RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let transfer = upload.transfer(&content.http);
    tokio::pin!(transfer);
    let mut serving = true;
    let mut event_error = None;
    // A started upload is never cancelled: a failing local event only stops
    // the service loop, and the transfer plus its bookkeeping still finish.
    let result = loop {
        match transfer_step(&mut transfer, events, serving).await {
            TransferStep::Done(result) => break result,
            TransferStep::Event(None) => serving = false,
            TransferStep::Event(Some(event)) => {
                if let Err(error) =
                    handle_hub_event(worker, state, notices, Some(content.archive()), walk, event)
                        .await
                {
                    event_error = Some(error);
                    serving = false;
                }
            }
        }
    };
    let flush = content
        .archive()
        .finish_upload(worker, upload, result)
        .await?;
    match event_error {
        Some(error) => Err(error),
        None => Ok(flush),
    }
}

/// What happened first: the transfer finished, or a local request arrived.
enum TransferStep {
    Done(Result<(), ContentError>),
    Event(Option<HubEvent>),
}

/// Serves a queued local event before the transfer, or the transfer alone once local
/// events are no longer being served.
///
/// The select is biased to the event queue, so completion is reported only when no event
/// is waiting, and an import that restores a chunk is applied before a loss is finalized.
async fn transfer_step(
    transfer: &mut core::pin::Pin<&mut impl Future<Output = Result<(), ContentError>>>,
    events: &mut UnboundedReceiver<HubEvent>,
    serving: bool,
) -> TransferStep {
    if !serving {
        return TransferStep::Done(transfer.as_mut().await);
    }
    tokio::select! {
        biased;
        event = events.recv() => TransferStep::Event(event),
        result = transfer.as_mut() => TransferStep::Done(result),
    }
}

/// Content files this device still owes the server, zero when content is disabled.
fn content_pending_files<U>(
    worker: &mut ConnettoConnection<U>,
    content: Option<&ContentArchive<BrowserStore>>,
) -> Result<u64, RelayError>
where
    U: Transport,
{
    match content {
        Some(content) => Ok(content.pending_files(worker)?),
        None => Ok(0),
    }
}

/// Sendable content files (outbox entries without a refusal mark), zero when content is disabled.
///
/// The outbox driver schedules from this count so a refused file never wakes
/// the driver. Pending work reports every outbox row through `content_pending_files`.
fn content_sendable_files<U>(
    worker: &mut ConnettoConnection<U>,
    content: Option<&ContentArchive<BrowserStore>>,
) -> Result<u64, RelayError>
where
    U: Transport,
{
    match content {
        Some(content) => Ok(content.sendable_files(worker)?),
        None => Ok(0),
    }
}

/// Files whose unsent bytes were lost and remain unacknowledged, none when
/// content is disabled.
fn retired_content<U>(
    worker: &mut ConnettoConnection<U>,
    content: Option<&ContentArchive<BrowserStore>>,
) -> Result<Vec<FileId>, RelayError>
where
    U: Transport,
{
    match content {
        Some(content) => Ok(content.retired_content(worker)?),
        None => Ok(Vec::new()),
    }
}

async fn handle_hub_event<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
    notices: &UnboundedSender<HubNotice>,
    content: Option<&ContentArchive<BrowserStore>>,
    walk: &mut WalkState,
    event: HubEvent,
) -> Result<(), RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    match event {
        HubEvent::Attached(id, out) => attach_tab(state, id, out),
        HubEvent::Frame(id, frame) => {
            handle_tab_frame(worker, state, notices, content, walk, id, frame).await?;
        }
        HubEvent::Internal(id, frame, blob) => {
            handle_tab_internal(worker, state, content, id, frame, blob).await?;
        }
        HubEvent::Unsynced(reply) => {
            let pending = PendingWork {
                mutation_seqs: worker.unsynced(),
                content_files: content_pending_files(worker, content)?,
                retired_files: retired_content(worker, content)?
                    .iter()
                    .map(FileId::to_string)
                    .collect(),
            };
            let _ = reply.send(pending);
        }
        HubEvent::ForgetRetired(files, reply) => {
            let answer = match content {
                Some(content) => content
                    .forget_retired_content(worker, &files)
                    .map_err(ArchiveServiceError::from),
                None => Ok(()),
            };
            let _ = reply.send(answer);
        }
        HubEvent::Export(scope, reply) => {
            let _ = reply.send(export_archive(worker, content, scope).await);
        }
        HubEvent::Import(blob, reply) => {
            let _ = reply.send(import_archive(worker, content, blob).await);
            // An import can restore the chunks a scan in progress has already missed, and
            // can leave its own behind when it fails part way.
            walk.scan = ChunkScan::default();
            walk.unswept = true;
            walk.sweep_waiting = false;
            // A listed orphan can be exactly what this import restored, so the list is
            // taken again rather than trusted.
            walk.orphans.clear();
            walk.outbox_wake = true;
        }
        HubEvent::RefusedContent(reply) => {
            let answer = match content {
                Some(content) => content
                    .refused_content(worker)
                    .map_err(ArchiveServiceError::from),
                None => Ok(Vec::new()),
            };
            let _ = reply.send(answer);
        }
        HubEvent::RetryRefused(file_id, reply) => {
            let answer = match content {
                Some(content) => content
                    .retry_refused(worker, file_id)
                    .map_err(ArchiveServiceError::from),
                None => Ok(()),
            };
            let succeeded = answer.is_ok();
            let _ = reply.send(answer);
            // Wake the outbox driver wherever this request was served, so
            // neither a reconnect nor an import is needed to attempt the entry.
            if succeeded {
                walk.outbox_wake = true;
            }
        }
        HubEvent::Gone(id) | HubEvent::Kill(id) => remove_tab(worker, state, id).await,
    }
    Ok(())
}

fn attach_tab(state: &mut HubState, id: TabId, out: UnboundedSender<TabOut>) {
    state.tabs.insert(
        id,
        TabState {
            out,
            handshaken: false,
            subs: Vec::new(),
            pending_write: None,
            client_id: None,
            applied_watermark: None,
            local_watermark: None,
            credits: INITIAL_CREDITS,
            pending: VecDeque::new(),
            staged: VecDeque::new(),
        },
    );
}

async fn export_archive<U>(
    worker: &mut ConnettoConnection<U>,
    content: Option<&ContentArchive<BrowserStore>>,
    scope: ExportScope,
) -> Result<web_sys::Blob, ArchiveServiceError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    if let Some(content) = content {
        let bytes = content.unsent_content_bytes(worker)?;
        if bytes > connetto_client::MAX_ATTACHMENTS_BYTES {
            return Err(ArchiveServiceError::ContentTooLarge {
                bytes,
                ceiling: connetto_client::MAX_ATTACHMENTS_BYTES,
            });
        }
        let sink = content
            .export_local_data(worker, scope, crate::workers::BlobSink::new())
            .await?;
        Ok(sink.into_blob()?)
    } else {
        let sink = worker.export_local_data(scope, crate::workers::BlobSink::new())?;
        Ok(sink.into_blob()?)
    }
}

async fn import_archive<U>(
    worker: &mut ConnettoConnection<U>,
    content: Option<&ContentArchive<BrowserStore>>,
    blob: web_sys::Blob,
) -> Result<(ImportOutcome, usize), ArchiveServiceError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let source = crate::workers::BlobSource::new(blob)?;
    let mut reader = std::io::BufReader::new(source);
    if let Some(content) = content {
        content
            .import_local_data(worker, &mut reader)
            .await
            .map_err(ArchiveServiceError::from)
    } else {
        let plan = worker.import_local_data(&mut reader)?;
        let collisions = plan.collisions().len();
        let outcome = worker.apply_import(&plan, &ImportChoices::keeping_the_file())?;
        // The import is committed, so a failed replay is left to the outbox driver.
        let _ = worker.replay_pending().await;
        Ok((outcome, collisions))
    }
}

async fn remove_tab<U>(worker: &mut ConnettoConnection<U>, state: &mut HubState, id: TabId)
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    state.tabs.remove(&id);
    state.pending_resolve.retain(|resolve| resolve.tab != id);
    let upstreams: Vec<String> = state
        .agg_routes
        .iter()
        .filter(|(_, route)| route.tab == id)
        .map(|(upstream_id, _)| upstream_id.clone())
        .collect();
    for upstream_id in upstreams {
        state.agg_routes.remove(&upstream_id);
        let _ = worker.unsubscribe(&upstream_id).await;
    }
}

/// Reconnects upstream while continuing to serve replica-only commands.
enum RecoveryAttempt {
    Connected,
    Failed,
    Interrupted(HubEvent),
    Closed,
}

enum RecoveryCycle {
    Connected,
    Failed,
    Closed,
}

enum ConnectAttempt<U> {
    Connected(U),
    Failed,
    Closed,
}

struct RecoveryContext<'a, U>
where
    U: Transport,
{
    worker: &'a mut ConnettoConnection<U>,
    state: &'a mut HubState,
    notices: &'a UnboundedSender<HubNotice>,
    content: Option<&'a ContentArchive<BrowserStore>>,
    events: &'a mut UnboundedReceiver<HubEvent>,
    deferred: &'a mut VecDeque<HubEvent>,
    walk: &'a mut WalkState,
}

async fn hub_recover<U, F, S>(
    worker: &mut ConnettoConnection<U>,
    driver: &mut HubReconnect<F, S>,
    state: &mut HubState,
    notices: &UnboundedSender<HubNotice>,
    content: Option<&ContentArchive<BrowserStore>>,
    events: &mut UnboundedReceiver<HubEvent>,
    walk: &mut WalkState,
) -> Result<bool, RelayError>
where
    U: Transport + MaybeSend + 'static,
    U::Error: core::fmt::Display,
    F: TransportFactory<Transport = U>,
    S: Sleeper,
{
    let mut backoff = driver.policy.initial_backoff();
    let mut attempt: u32 = 0;
    let mut deferred = VecDeque::new();
    let mut recovery_io = RecoveryContext {
        worker,
        state,
        notices,
        content,
        events,
        deferred: &mut deferred,
        walk,
    };
    loop {
        attempt = attempt.saturating_add(1);
        if driver
            .policy
            .max_attempts()
            .is_some_and(|max| attempt > max)
        {
            return Ok(false);
        }
        tracing::warn!(attempt, "relay hub upstream reconnecting");
        if !wait_recovery_backoff(&mut recovery_io, &mut driver.sleeper, backoff).await? {
            return Ok(false);
        }
        backoff = backoff.saturating_mul(2).min(driver.policy.max_backoff());
        match finish_recovery(&mut recovery_io, &mut driver.factory, &driver.upstream).await? {
            RecoveryCycle::Connected => return Ok(true),
            RecoveryCycle::Failed => {}
            RecoveryCycle::Closed => return Ok(false),
        }
    }
}

async fn finish_recovery<U, F>(
    context: &mut RecoveryContext<'_, U>,
    factory: &mut F,
    upstream: &[(String, SubscriptionSpec)],
) -> Result<RecoveryCycle, RelayError>
where
    U: Transport + MaybeSend + 'static,
    U::Error: core::fmt::Display,
    F: TransportFactory<Transport = U>,
{
    let mut attempt = recovery_attempt(context, factory, upstream).await?;
    loop {
        match attempt {
            RecoveryAttempt::Connected => {
                handle_deferred_events(context).await?;
                return Ok(RecoveryCycle::Connected);
            }
            RecoveryAttempt::Failed => {
                context.worker.disconnect();
                return Ok(RecoveryCycle::Failed);
            }
            RecoveryAttempt::Interrupted(event) => {
                if !context.worker.is_connected() {
                    context.worker.disconnect();
                }
                handle_hub_event(
                    context.worker,
                    context.state,
                    context.notices,
                    context.content,
                    context.walk,
                    event,
                )
                .await?;
                attempt = if context.worker.is_connected() {
                    finish_attached_during_recovery(context, upstream).await
                } else {
                    recovery_attempt(context, factory, upstream).await?
                };
            }
            RecoveryAttempt::Closed => return Ok(RecoveryCycle::Closed),
        }
    }
}

async fn finish_attached_during_recovery<U>(
    context: &mut RecoveryContext<'_, U>,
    upstream: &[(String, SubscriptionSpec)],
) -> RecoveryAttempt
where
    U: Transport + MaybeSend + 'static,
    U::Error: core::fmt::Display,
{
    let subscriptions = recovery_subscriptions(context.state, upstream);
    let worker = &mut *context.worker;
    let state = &mut *context.state;
    let events = &mut *context.events;
    let deferred = &mut *context.deferred;
    let recovery = async {
        worker.resume_attach().await?;
        restore_recovery_subscriptions(worker, &subscriptions).await
    };
    tokio::pin!(recovery);
    loop {
        tokio::select! {
            result = &mut recovery => {
                return match result {
                    Ok(()) => RecoveryAttempt::Connected,
                    Err(_) => RecoveryAttempt::Failed,
                };
            }
            event = events.recv() => match event {
                Some(event) => {
                    if let Some(local) = attach_during_recovery(state, deferred, event) {
                        return RecoveryAttempt::Interrupted(local);
                    }
                }
                None => return RecoveryAttempt::Closed,
            },
        }
    }
}

async fn wait_recovery_backoff<U, S>(
    context: &mut RecoveryContext<'_, U>,
    sleeper: &mut S,
    backoff: core::time::Duration,
) -> Result<bool, RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
    S: Sleeper,
{
    let sleep = sleeper.sleep(backoff);
    tokio::pin!(sleep);
    loop {
        let owes = walk_owes(context.walk);
        let wake = {
            let events = &mut *context.events;
            tokio::select! {
                () = &mut sleep => return Ok(true),
                event = events.recv() => IdleWake::Event(event),
                // The walk reads only the replica and the chunk store, so the sleep is
                // where it belongs rather than a pause until the server returns.
                () = core::future::ready(()), if owes => IdleWake::Walk,
            }
        };
        match wake {
            IdleWake::Event(Some(event)) => handle_recovery_event(context, event).await?,
            IdleWake::Event(None) => return Ok(false),
            IdleWake::Walk => {
                walk_recovery_turn(context).await;
            }
        }
    }
}

/// Why one idle recovery wait woke.
enum IdleWake {
    /// A request arrived, or the intake closed.
    Event(Option<HubEvent>),
    /// The content integrity walk owes a turn.
    Walk,
}

/// One walk turn while the connection is idle.
///
/// A deferred turn waits for the connected cycle's retry timer, which is the schedule the
/// walk already uses, so a failing store is not walked in a loop here either.
async fn walk_recovery_turn<U>(context: &mut RecoveryContext<'_, U>)
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let _ = walk_turn(context.worker, context.content, context.walk).await;
}

async fn recovery_attempt<U, F>(
    context: &mut RecoveryContext<'_, U>,
    factory: &mut F,
    upstream: &[(String, SubscriptionSpec)],
) -> Result<RecoveryAttempt, RelayError>
where
    U: Transport + MaybeSend + 'static,
    U::Error: core::fmt::Display,
    F: TransportFactory<Transport = U>,
{
    match connect_during_recovery(context, factory).await? {
        ConnectAttempt::Connected(transport) => {
            Ok(resume_during_recovery(context, transport, upstream).await)
        }
        ConnectAttempt::Failed => Ok(RecoveryAttempt::Failed),
        ConnectAttempt::Closed => Ok(RecoveryAttempt::Closed),
    }
}

async fn connect_during_recovery<U, F>(
    context: &mut RecoveryContext<'_, U>,
    factory: &mut F,
) -> Result<ConnectAttempt<U>, RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
    F: TransportFactory<Transport = U>,
{
    let connect = factory.connect();
    tokio::pin!(connect);
    loop {
        let owes = walk_owes(context.walk);
        let wake = {
            let events = &mut *context.events;
            tokio::select! {
                result = &mut connect => {
                    return Ok(match result {
                        Ok(transport) => ConnectAttempt::Connected(transport),
                        Err(_) => ConnectAttempt::Failed,
                    });
                }
                event = events.recv() => IdleWake::Event(event),
                () = core::future::ready(()), if owes => IdleWake::Walk,
            }
        };
        match wake {
            IdleWake::Event(Some(event)) => handle_recovery_event(context, event).await?,
            IdleWake::Event(None) => return Ok(ConnectAttempt::Closed),
            IdleWake::Walk => {
                walk_recovery_turn(context).await;
            }
        }
    }
}

async fn resume_during_recovery<U>(
    context: &mut RecoveryContext<'_, U>,
    transport: U,
    upstream: &[(String, SubscriptionSpec)],
) -> RecoveryAttempt
where
    U: Transport + MaybeSend + 'static,
    U::Error: core::fmt::Display,
{
    let subscriptions = recovery_subscriptions(context.state, upstream);
    let worker = &mut *context.worker;
    let state = &mut *context.state;
    let events = &mut *context.events;
    let deferred = &mut *context.deferred;
    let recovery = async {
        worker.attach(transport).await?;
        restore_recovery_subscriptions(worker, &subscriptions).await
    };
    tokio::pin!(recovery);
    loop {
        tokio::select! {
            result = &mut recovery => {
                return match result {
                    Ok(()) => RecoveryAttempt::Connected,
                    Err(_) => RecoveryAttempt::Failed,
                };
            }
            event = events.recv() => match event {
                Some(event) => {
                    if let Some(local) = attach_during_recovery(state, deferred, event) {
                        return RecoveryAttempt::Interrupted(local);
                    }
                }
                None => return RecoveryAttempt::Closed,
            },
        }
    }
}

/// Registers a tab where it arrives, because that writes hub state and touches neither the
/// connection the attach owns nor the replica.
///
/// The tab's own announce gives up after fifteen seconds, so holding it for the length of
/// a reconnect fails a healthy tab. Everything else follows chapter 18's attach column.
fn attach_during_recovery(
    state: &mut HubState,
    deferred: &mut VecDeque<HubEvent>,
    event: HubEvent,
) -> Option<HubEvent> {
    if deferred.is_empty()
        && let HubEvent::Attached(id, out) = event
    {
        attach_tab(state, id, out);
        return None;
    }
    schedule_recovery_event(deferred, event, recovery_interrupts_attach)
}

/// Every subscription the replay puts back, taken before the attach starts so the attach
/// borrows no hub state and a tab can be registered while it runs.
fn recovery_subscriptions(
    state: &HubState,
    upstream: &[(String, SubscriptionSpec)],
) -> Vec<(String, SubscriptionSpec)> {
    upstream
        .iter()
        .map(|(sub_id, spec)| (sub_id.clone(), spec.clone()))
        .chain(
            state
                .agg_routes
                .iter()
                .map(|(upstream_id, route)| (upstream_id.clone(), route.spec.clone())),
        )
        .collect()
}

async fn restore_recovery_subscriptions<U>(
    worker: &mut ConnettoConnection<U>,
    subscriptions: &[(String, SubscriptionSpec)],
) -> Result<(), ClientError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    for (sub_id, spec) in subscriptions {
        worker.subscribe_spec(sub_id, spec.clone()).await?;
    }
    Ok(())
}

async fn handle_recovery_event<U>(
    context: &mut RecoveryContext<'_, U>,
    event: HubEvent,
) -> Result<(), RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let Some(local) = schedule_recovery_event(context.deferred, event, recovery_serves_idle) else {
        return Ok(());
    };
    handle_hub_event(
        context.worker,
        context.state,
        context.notices,
        context.content,
        context.walk,
        local,
    )
    .await
}

/// Queues `event` unless it is served where it arrives, which chapter 18's table decides
/// per situation through `served`.
///
/// One order rule covers every served cell: anything older already queued keeps its place,
/// so a kill can never overtake a frame of the tab it kills.
fn schedule_recovery_event(
    deferred: &mut VecDeque<HubEvent>,
    event: HubEvent,
    served: fn(&HubEvent) -> bool,
) -> Option<HubEvent> {
    if deferred.is_empty() && served(&event) {
        Some(event)
    } else {
        deferred.push_back(event);
        None
    }
}

/// What the recovery loop serves while the connection sits idle, in the retry sleep and
/// during the connect.
///
/// Tab work that the replica or the hub can answer stays live offline, so a tab can boot,
/// subscribe, mutate and ask content questions before the worker reaches the server.
fn recovery_serves_idle(event: &HubEvent) -> bool {
    matches!(
        event,
        HubEvent::Attached(_, _)
            | HubEvent::Gone(_)
            | HubEvent::Kill(_)
            | HubEvent::Unsynced(_)
            | HubEvent::Export(_, _)
            | HubEvent::Import(_, _)
            | HubEvent::ForgetRetired(_, _)
            | HubEvent::RefusedContent(_)
            | HubEvent::RetryRefused(_, _)
            | HubEvent::Frame(_, _)
            | HubEvent::Internal(_, _, _)
    )
}

/// What interrupts an attach or a subscription replay rather than waiting for it.
///
/// Every request answered from the replica, because a caller waits on each. A departure
/// and a kill unsubscribe through the connection the attach owns and nothing waits on
/// them, so they keep their place in the queue instead.
fn recovery_interrupts_attach(event: &HubEvent) -> bool {
    matches!(
        event,
        HubEvent::Unsynced(_)
            | HubEvent::Export(_, _)
            | HubEvent::Import(_, _)
            | HubEvent::ForgetRetired(_, _)
            | HubEvent::RefusedContent(_)
            | HubEvent::RetryRefused(_, _)
            | HubEvent::Internal(_, ContentFrame::Resolve { .. }, _)
    )
}

async fn handle_deferred_events<U>(context: &mut RecoveryContext<'_, U>) -> Result<(), RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    while let Some(event) = context.deferred.pop_front() {
        handle_hub_event(
            context.worker,
            context.state,
            context.notices,
            context.content,
            context.walk,
            event,
        )
        .await?;
    }
    Ok(())
}

/// Handle one frame from a tab, downgrading tab-level faults to closing
/// that tab so one misbehaving client never poisons its siblings.
async fn handle_tab_frame<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
    notices: &UnboundedSender<HubNotice>,
    content: Option<&ContentArchive<BrowserStore>>,
    walk: &mut WalkState,
    id: TabId,
    frame: IncomingFrame,
) -> Result<(), RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let outcome = match frame {
        IncomingFrame::Control(message) => {
            handle_tab_control(worker, state, notices, id, message).await
        }
        IncomingFrame::Bulk(bulk) => handle_tab_bulk(worker, state, content, walk, id, bulk).await,
    };
    match outcome {
        Ok(()) => Ok(()),
        Err(TabFault::Close(reason)) => {
            tracing::warn!(tab = %id, reason = %reason, "relay hub closed a tab");
            state.tabs.remove(&id);
            state.pending_resolve.retain(|resolve| resolve.tab != id);
            Ok(())
        }
        Err(TabFault::Hub(err)) => Err(err),
    }
}

/// Multiplex a tab aggregate subscription onto the worker connection.
///
/// The replica holds only this device's authorized rows and cannot answer a
/// global aggregate, so the hub registers a private upstream subscription
/// (`agg-{tab}-{sub}`) and records the route so [`handle_worker_event`]
/// demuxes the server's pushes back to this tab. No row snapshot is served.
async fn register_tab_aggregate<U>(
    worker: &mut ConnettoConnection<U>,
    agg_routes: &mut HashMap<String, AggRoute>,
    tab: &mut TabState,
    id: TabId,
    subscribe: Subscribe,
) -> Result<(), TabFault>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let upstream_id = format!("agg-{id}-{}", subscribe.sub_id);
    worker
        .subscribe_spec(&upstream_id, subscribe.spec.clone())
        .await
        .map_err(RelayError::from)?;
    // While the worker is offline the server sends no bootstrap, so a tab would
    // otherwise show nothing until the worker connects. Answer the watch from
    // the resting table the worker keeps, synthesizing the scalar frame the
    // server would have sent. The worker's next connect delivers the
    // authoritative value and overwrites it (R83 decision 7).
    if !worker.is_connected()
        && let Some((result_json, _)) = worker
            .rested_scalar(&subscribe.spec.query, &subscribe.spec.binds)
            .map_err(RelayError::from)?
    {
        let _ = tab
            .out
            .send(TabOut::Control(ControlMessage::AggregateUpdate(
                AggregateUpdate {
                    sub_id: subscribe.sub_id.clone(),
                    group_key: None,
                    group_values_json: None,
                    result_json: Some(result_json),
                    is_full_result: true,
                },
            )));
    }
    agg_routes.insert(
        upstream_id,
        AggRoute {
            tab: id,
            tab_sub: subscribe.sub_id,
            spec: subscribe.spec,
        },
    );
    Ok(())
}

/// Tear down a tab's multiplexed aggregate upstream by its tab sub id, if this
/// sub was an aggregate. A row unsubscribe finds no route and is a no-op.
async fn drop_tab_aggregate<U>(
    worker: &mut ConnettoConnection<U>,
    agg_routes: &mut HashMap<String, AggRoute>,
    id: TabId,
    tab_sub: &str,
) -> Result<(), TabFault>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let upstream = agg_routes
        .iter()
        .find(|(_, route)| route.tab == id && route.tab_sub == tab_sub)
        .map(|(upstream_id, _)| upstream_id.clone());
    if let Some(upstream_id) = upstream {
        agg_routes.remove(&upstream_id);
        worker
            .unsubscribe(&upstream_id)
            .await
            .map_err(RelayError::from)?;
    }
    Ok(())
}

/// Serve one tab row or aggregate subscription, or scope its failure.
///
/// A query the hub cannot parse or serve draws a `NonFatalError` correlated to
/// its sub id, leaving the tab and its siblings alive, mirroring the direct
/// server. An aggregate registers a private upstream sub. A row subscription is
/// answered from the worker replica and its tables recorded for later routing.
async fn handle_tab_subscribe<U>(
    worker: &mut ConnettoConnection<U>,
    agg_routes: &mut HashMap<String, AggRoute>,
    blank: &mut BlankState,
    local_tables: &HashSet<String>,
    tab: &mut TabState,
    id: TabId,
    subscribe: Subscribe,
) -> Result<(), TabFault>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    match subscription_is_aggregate(&subscribe.spec.query) {
        Err(err) => {
            tracing::warn!(tab = %id, sub_id = %subscribe.sub_id, error = %err, "tab subscription refused");
            send_tab_nonfatal(tab, &subscribe.sub_id, SUBSCRIPTION_REFUSED);
            Ok(())
        }
        Ok(true) => register_tab_aggregate(worker, agg_routes, tab, id, subscribe).await,
        Ok(false) => {
            let tables = match subscription_tables(&subscribe.spec.query) {
                Ok(tables) => tables,
                Err(err) => {
                    tracing::warn!(tab = %id, sub_id = %subscribe.sub_id, error = %err, "tab subscription refused");
                    send_tab_nonfatal(tab, &subscribe.sub_id, SUBSCRIPTION_REFUSED);
                    return Ok(());
                }
            };
            if let Err(err) = serve_snapshot(
                worker,
                blank,
                local_tables,
                tab,
                &subscribe.sub_id,
                subscribe.spec.priority,
                &tables,
            ) {
                tracing::warn!(tab = %id, sub_id = %subscribe.sub_id, error = %err, "tab snapshot failed");
                send_tab_nonfatal(tab, &subscribe.sub_id, SUBSCRIPTION_REFUSED);
                return Ok(());
            }
            tab.subs.retain(|sub| sub.sub_id != subscribe.sub_id);
            tab.subs.push(TabSub {
                sub_id: subscribe.sub_id,
                tables,
                priority: subscribe.spec.priority,
            });
            Ok(())
        }
    }
}

/// Handle one control frame from a tab.
async fn handle_tab_control<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
    notices: &UnboundedSender<HubNotice>,
    id: TabId,
    message: ControlMessage,
) -> Result<(), TabFault>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let Some(tab) = state.tabs.get_mut(&id) else {
        return Ok(());
    };
    match message {
        ControlMessage::Handshake(handshake) => {
            if tab.handshaken {
                return Err(TabFault::Close("second handshake".to_owned()));
            }
            let client_uuid = handshake
                .client_id
                .parse::<rosetta_uuid::Uuid>()
                .map_err(|_| TabFault::Close("client_id is not a valid UUID".to_owned()))?;
            tab.handshaken = true;
            tab.client_id = Some(client_uuid);
            tab.applied_watermark = tab_watermark(worker, client_uuid)?;
            tab.local_watermark = if state.local_tables.is_empty() {
                None
            } else {
                local_tab_watermark(worker, client_uuid)?
            };
            // The hub handles a tab's mutations in order and each lands in
            // exactly one tier, so every sequence at or below the higher of
            // the two watermarks was already applied or rejected.
            let last_applied = match (tab.applied_watermark, tab.local_watermark) {
                (Some(synced), Some(local)) => Some(synced.max(local)),
                (synced, local) => synced.or(local),
            };
            // The hub owns the one upstream run, so a tab has neither a
            // handle of its own nor anything to resume on: both are named for
            // the relay and the tab does not act on either. The watermark is
            // load-bearing: the tab retires pending mutations at or below it
            // and replays the rest.
            let _ = tab.out.send(TabOut::Control(ControlMessage::HandshakeAck(
                HandshakeAck {
                    connection_id: format!("relay-{}", handshake.client_id),
                    session_token: "relay".to_owned(),
                    resume_token: "relay".to_owned(),
                    current_cursor: relay_cursor(worker),
                    schema_version: worker.schema_version().cloned(),
                    initial_credits: INITIAL_CREDITS,
                    last_applied_seq: last_applied,
                },
            )));
            // Right after its own ack, so a tab knows from its first moment
            // whether what it is about to read is current. Waiting for the next
            // change would leave a tab that attached during an outage showing
            // stale rows with nothing saying so.
            let _ = tab.out.send(TabOut::Control(ControlMessage::SyncStatus(
                state.sync_status,
            )));
            let _ = notices.send(HubNotice::Handshake {
                tab: id,
                client_id: handshake.client_id,
            });
            Ok(())
        }
        ControlMessage::Subscribe(subscribe) if tab.handshaken => {
            handle_tab_subscribe(
                worker,
                &mut state.agg_routes,
                &mut state.blank,
                &state.local_tables,
                tab,
                id,
                subscribe,
            )
            .await
        }
        ControlMessage::Unsubscribe(unsubscribe) if tab.handshaken => {
            tab.subs.retain(|sub| sub.sub_id != unsubscribe.sub_id);
            drop_tab_aggregate(worker, &mut state.agg_routes, id, &unsubscribe.sub_id).await
        }
        ControlMessage::Ping(ping) if tab.handshaken => {
            let _ = tab.out.send(TabOut::Control(ControlMessage::Pong(Pong {
                nonce: ping.nonce,
            })));
            Ok(())
        }
        ControlMessage::MutationHeader(header) if tab.handshaken => {
            if tab.pending_write.replace(header.client_seq).is_some() {
                return Err(TabFault::Close(
                    "mutation header while another mutation is in flight".to_owned(),
                ));
            }
            Ok(())
        }
        ControlMessage::AckCredits(ack) if tab.handshaken => {
            tab.credits = tab.credits.saturating_add(ack.credits);
            flush_tab_bulk(tab);
            Ok(())
        }
        other => Err(TabFault::Close(format!(
            "unsupported tab frame in this increment: {other:?}"
        ))),
    }
}

/// Handle one bulk frame from a tab: the patchset of an announced
/// mutation. The changeset is decoded, classified by the tables it
/// touches, and dispatched to its tier. A mutation spanning both tiers is
/// rejected: applying it would tear on an upstream rejection, because the
/// rollback inverts the tab's whole changeset while the local half stays
/// committed everywhere else.
async fn handle_tab_bulk<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
    content: Option<&ContentArchive<BrowserStore>>,
    walk: &mut WalkState,
    id: TabId,
    bulk: BulkMessage,
) -> Result<(), TabFault>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let patch = match bulk {
        BulkMessage::MutationPatch(patch) => patch,
        other => {
            return Err(TabFault::Close(format!(
                "unexpected bulk frame from the tab: {other:?}"
            )));
        }
    };
    let (tab_seq, out) = {
        let Some(tab) = state.tabs.get_mut(&id) else {
            return Ok(());
        };
        let Some(tab_seq) = tab.pending_write.take() else {
            return Err(TabFault::Close(
                "mutation patchset without a preceding header".to_owned(),
            ));
        };
        if patch.client_seq != tab_seq {
            return Err(TabFault::Close(format!(
                "mutation patchset seq {} does not match header seq {tab_seq}",
                patch.client_seq
            )));
        }
        (tab_seq, tab.out.clone())
    };
    let Ok(changeset) = zstd::decode_all(patch.patchset_zstd.as_slice()) else {
        return Err(TabFault::Close("undecodable mutation patchset".to_owned()));
    };
    let Ok(tables) = changeset_tables(&changeset) else {
        return Err(TabFault::Close("unparsable mutation changeset".to_owned()));
    };
    let local_hit = tables.intersection(&state.local_tables).count();
    if local_hit > 0 && local_hit < tables.len() {
        let _ = out.send(TabOut::Control(ControlMessage::MutationReject(
            MutationReject {
                client_seq: tab_seq,
                reason: MutationRejectReason::Other {
                    detail: "a mutation must not span the synced and local tiers, \
                             commit each tier in its own transaction"
                        .to_owned(),
                },
            },
        )));
        return Ok(());
    }
    if local_hit > 0 {
        return handle_local_mutation(
            worker,
            state,
            id,
            tab_seq,
            &changeset,
            &tables,
            &patch.patchset_zstd,
        );
    }
    // Content rides a mutation that names it: a changeset carrying a staged
    // file's identity commits the manifest, the upload queue entry and the
    // rows together. A changeset naming nothing staged is an ordinary
    // mutation, and staged content it never names ages out.
    let staged = take_staged(state, id, &changeset);
    handle_synced_mutation(
        worker, state, id, tab_seq, &changeset, staged, content, walk,
    )
    .await
}

/// Bind one changeset value at its own SQLite storage class.
///
/// `Value::Null` never reaches here: a null is written into the predicate as
/// `IS NULL` and into an assignment as the literal, because a bind has no
/// type to carry.
fn bind_value<'a>(
    query: BoxedSqlQuery<'a, Sqlite, SqlQuery>,
    value: &Value<String, Vec<u8>>,
) -> BoxedSqlQuery<'a, Sqlite, SqlQuery> {
    match value {
        Value::Null => query,
        Value::Integer(v) => query.bind::<diesel::sql_types::BigInt, _>(*v),
        Value::Real(v) => query.bind::<diesel::sql_types::Double, _>(*v),
        Value::Text(v) => query.bind::<diesel::sql_types::Text, _>(v.clone()),
        Value::Blob(v) => query.bind::<diesel::sql_types::Binary, _>(v.clone()),
    }
}

/// Column names of one device-private table, in the order a changeset records
/// them, which is the table's own column order.
///
/// `PRAGMA table_info` is a vendor pragma with no typed form, and it takes no
/// bind parameter for the table, so the name is quoted into it. Every name
/// reaching here came from `local_tables`, which connetto read out of the
/// attached catalogue itself.
fn tier_columns(conn: &mut SqliteConnection, table: &str) -> Result<Vec<String>, TabApplyError> {
    #[derive(QueryableByName)]
    struct ColumnRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
    }
    let rows: Vec<ColumnRow> =
        sql_query(format!("PRAGMA table_info({})", quote_ident(table))).load(conn)?;
    if rows.is_empty() {
        return Err(TabApplyError::Apply(format!("no such table: {table}")));
    }
    Ok(rows.into_iter().map(|row| row.name).collect())
}

/// Replay one changeset into the attached device-private tables.
///
/// SQLite's own `sqlite3changeset_apply` takes a connection and no schema, so
/// it can only ever write into `main`, which here is the synced replica. These
/// tables live in an attached database on that same connection, so the change
/// list is replayed as ordinary statements instead. Table names are written
/// bare on purpose: a bare name resolves across attached databases, and a name
/// shared between the two tiers is a generation-time error.
///
/// **The conflict rule is `ConflictAction::Abort`'s, kept exactly.** Every
/// column the changeset carries an old value for goes into the predicate, so
/// one affected row means the row was there and still held what the writer
/// saw. Anything else is a conflict, which covers both a row that has gone and
/// a row somebody else has changed underneath, and both abort the whole
/// transaction exactly as they do today. An insert onto an occupied key raises
/// a constraint error, which is the same refusal by another route.
fn apply_local_changeset(
    conn: &mut SqliteConnection,
    changeset: &[u8],
) -> Result<(), TabApplyError> {
    let parsed = ParsedDiffSet::parse(changeset)
        .map_err(|err| TabApplyError::Apply(format!("unparsable changeset: {err:?}")))?;
    let ParsedDiffSet::Changeset(diff) = parsed else {
        // A patchset carries no old values, so it cannot be replayed under the
        // conflict rule above. Tabs capture with `changeset()`, so this is a
        // client that is not connetto's.
        return Err(TabApplyError::Apply(
            "a local tier mutation must be a changeset, not a patchset".to_owned(),
        ));
    };
    let mut columns: HashMap<String, Vec<String>> = HashMap::new();
    for op in diff.iter() {
        let table = op.table().name().to_owned();
        if !columns.contains_key(&table) {
            let names = tier_columns(conn, &table)?;
            columns.insert(table.clone(), names);
        }
        let names = &columns[&table];
        let (sql, binds) = render_local_op(&op, &table, names)?;
        let mut query = sql_query(sql).into_boxed::<Sqlite>();
        for value in &binds {
            query = bind_value(query, value);
        }
        let affected = query
            .execute(conn)
            .map_err(|err| TabApplyError::Apply(err.to_string()))?;
        if affected != 1 {
            return Err(TabApplyError::Apply(format!(
                "conflict on {table}: the row was not there or no longer held what the writer saw"
            )));
        }
    }
    Ok(())
}

/// One rendered statement and the values to bind, in order.
type RenderedOp = (String, Vec<Value<String, Vec<u8>>>);

/// One `column IS ?` term, or `column IS NULL` when the value is null. A null
/// is written rather than bound, because a bind carries no type to compare.
fn predicate_term(
    terms: &mut Vec<String>,
    binds: &mut Vec<Value<String, Vec<u8>>>,
    column: &str,
    value: &Value<String, Vec<u8>>,
) {
    if matches!(value, Value::Null) {
        terms.push(format!("{} IS NULL", quote_ident(column)));
    } else {
        terms.push(format!("{} IS ?", quote_ident(column)));
        binds.push(value.clone());
    }
}

/// The column a changeset names at `index`, or a refusal when the changeset
/// and the table disagree about the table's width.
fn column_at<'a>(
    columns: &'a [String],
    index: usize,
    table: &str,
) -> Result<&'a str, TabApplyError> {
    columns.get(index).map(String::as_str).ok_or_else(|| {
        TabApplyError::Apply(format!(
            "{table}: the changeset names column {index} and the table has {}",
            columns.len()
        ))
    })
}

/// Render one changeset operation as SQL plus the values to bind, in order.
fn render_local_op(
    op: &ChangesetOp<'_, TableSchema<String>, String, Vec<u8>>,
    table: &str,
    columns: &[String],
) -> Result<RenderedOp, TabApplyError> {
    match op {
        ChangesetOp::Insert { values, .. } => render_insert(values, table, columns),
        ChangesetOp::Update { values, .. } => render_update(values, table, columns),
        ChangesetOp::Delete { old_values, .. } => render_delete(old_values, table, columns),
    }
}

fn render_insert(
    values: &[Value<String, Vec<u8>>],
    table: &str,
    columns: &[String],
) -> Result<RenderedOp, TabApplyError> {
    if values.len() != columns.len() {
        return Err(TabApplyError::Apply(format!(
            "{table}: the changeset has {} columns and the table has {}",
            values.len(),
            columns.len()
        )));
    }
    let mut binds: Vec<Value<String, Vec<u8>>> = Vec::new();
    let names = columns
        .iter()
        .map(|column| quote_ident(column))
        .collect::<Vec<_>>();
    let slots = values
        .iter()
        .map(|value| {
            if matches!(value, Value::Null) {
                "NULL".to_owned()
            } else {
                binds.push(value.clone());
                "?".to_owned()
            }
        })
        .collect::<Vec<_>>();
    Ok((
        format!(
            "INSERT INTO {} ({}) VALUES ({})",
            quote_ident(table),
            names.join(", "),
            slots.join(", ")
        ),
        binds,
    ))
}

fn render_update(
    values: &[sqlite_diff_rs::ChangesetUpdatePair<String, Vec<u8>>],
    table: &str,
    columns: &[String],
) -> Result<RenderedOp, TabApplyError> {
    let mut binds: Vec<Value<String, Vec<u8>>> = Vec::new();
    let mut assignments: Vec<String> = Vec::new();
    let mut terms: Vec<String> = Vec::new();
    let mut predicate_binds: Vec<Value<String, Vec<u8>>> = Vec::new();
    for (index, pair) in values.iter().enumerate() {
        let column = column_at(columns, index, table)?;
        if let Some(new) = pair.1.as_ref() {
            if matches!(new, Value::Null) {
                assignments.push(format!("{} = NULL", quote_ident(column)));
            } else {
                assignments.push(format!("{} = ?", quote_ident(column)));
                binds.push(new.clone());
            }
        }
        if let Some(old) = pair.0.as_ref() {
            predicate_term(&mut terms, &mut predicate_binds, column, old);
        }
    }
    if assignments.is_empty() || terms.is_empty() {
        return Err(TabApplyError::Apply(format!(
            "{table}: an update with nothing to set or nothing to match"
        )));
    }
    binds.extend(predicate_binds);
    Ok((
        format!(
            "UPDATE {} SET {} WHERE {}",
            quote_ident(table),
            assignments.join(", "),
            terms.join(" AND ")
        ),
        binds,
    ))
}

fn render_delete(
    old_values: &[Value<String, Vec<u8>>],
    table: &str,
    columns: &[String],
) -> Result<RenderedOp, TabApplyError> {
    let mut binds: Vec<Value<String, Vec<u8>>> = Vec::new();
    let mut terms: Vec<String> = Vec::new();
    for (index, value) in old_values.iter().enumerate() {
        let column = column_at(columns, index, table)?;
        predicate_term(&mut terms, &mut binds, column, value);
    }
    if terms.is_empty() {
        return Err(TabApplyError::Apply(format!(
            "{table}: a delete with nothing to match"
        )));
    }
    Ok((
        format!(
            "DELETE FROM {} WHERE {}",
            quote_ident(table),
            terms.join(" AND ")
        ),
        binds,
    ))
}

/// Apply one pure local tier mutation and fan it out.
///
/// The changeset commits into the attached device-private tables together
/// with the tab's durable watermark, in one transaction on the worker
/// connection. The hub is the terminal authority for this tier (there is no
/// upstream leg), so its own durable apply is the acknowledgement. Nothing
/// here can ride an upload: the capture session is bound to `main` and these
/// tables are not in it.
///
/// The payload then fans out to every tab with a subscription reading a
/// touched table, the originator included: its re-apply is idempotent under
/// the client's conflict policy and converges every mirror on the hub's
/// serialization order.
fn handle_local_mutation<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
    id: TabId,
    tab_seq: u64,
    changeset: &[u8],
    tables: &HashSet<String>,
    payload: &[u8],
) -> Result<(), TabFault>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let (client_id, out, watermark) = {
        let Some(tab) = state.tabs.get(&id) else {
            return Ok(());
        };
        // A mutation frame is only accepted after the handshake, which is what
        // sets the id, so no id means a tab that cannot be keyed.
        let Some(client_id) = tab.client_id else {
            return Ok(());
        };
        (client_id, tab.out.clone(), tab.local_watermark)
    };
    if watermark.is_some_and(|watermark| tab_seq <= watermark) {
        // Already applied to the tier by an earlier delivery. The hub is
        // the authority, so a plain re-acknowledgement is complete here.
        let _ = out.send(TabOut::Control(ControlMessage::MutationApplied(
            MutationApplied {
                client_seq: tab_seq,
            },
        )));
        return Ok(());
    }
    let Ok(seq) = i64::try_from(tab_seq) else {
        return Err(TabFault::Close("sequence overflows storage".to_owned()));
    };
    if state.local_tables.is_empty() {
        return Ok(());
    }
    let applied = worker.conn().transaction::<_, TabApplyError, _>(|conn| {
        apply_local_changeset(conn, changeset)?;
        {
            use local_schema::_connetto_tab_mutations::dsl as wm;
            // MAX(a, b) as a 2-arg scalar is not in diesel's aggregate DSL;
            // raw fragment used only for that one update expression.
            diesel::insert_into(wm::_connetto_tab_mutations)
                .values((wm::client_id.eq(client_id), wm::last_seq.eq(seq)))
                .on_conflict(wm::client_id)
                .do_update()
                .set(
                    wm::last_seq.eq(diesel::dsl::sql::<diesel::sql_types::BigInt>(
                        "MAX(last_seq, excluded.last_seq)",
                    )),
                )
                .execute(conn)?;
        }
        Ok(())
    });
    match applied {
        Ok(()) => {}
        Err(TabApplyError::Apply(detail)) => {
            let _ = out.send(TabOut::Control(ControlMessage::MutationReject(
                MutationReject {
                    client_seq: tab_seq,
                    reason: MutationRejectReason::Other {
                        detail: format!("local tier apply failed: {detail}"),
                    },
                },
            )));
            return Ok(());
        }
        Err(TabApplyError::Db(err)) => return Err(RelayError::from(err).into()),
    }
    if let Some(tab) = state.tabs.get_mut(&id) {
        tab.local_watermark = Some(tab_seq);
    }
    let _ = out.send(TabOut::Control(ControlMessage::MutationApplied(
        MutationApplied {
            client_seq: tab_seq,
        },
    )));
    // The worker's own cursor stamps the fan-out. Read here rather than passed
    // in, because this tier has no upstream leg that could advance it.
    let cursor = relay_cursor(worker);
    for tab in state.tabs.values_mut() {
        let Some(sub) = tab.subs.iter().find(|sub| !sub.tables.is_disjoint(tables)) else {
            continue;
        };
        let msg = BulkMessage::LivePatch(LivePatch::new(
            sub.sub_id.clone(),
            cursor.clone(),
            payload.to_vec(),
        ));
        enqueue_tab_frame(tab, TabDeliverable::Rows(msg));
    }
    Ok(())
}

/// Apply one synced tier mutation to the worker replica.
///
/// The changeset is applied with capture ACTIVE (so the worker's own
/// session records it and the following push re-uploads it), and the
/// tab's durable watermark advances in the same transaction. A replayed
/// sequence at or below the watermark is re-acknowledged, never
/// re-applied. The end-to-end acknowledgement the tab retires its pending
/// record on arrives separately, when the SERVER confirms the forwarded
/// mutation. An apply failure rejects the mutation back to the tab and
/// leaves the replica untouched, since the abort policy rolls the whole
/// apply back.
///
/// When the changeset paired with staged content, the file is chunked into
/// the encrypted store and its manifest and upload entry commit in the same
/// transaction as the rows, with the declared identity checked against what
/// the bytes actually hash to. A chunking, identity or apply failure all
/// reject the mutation with nothing committed.
#[expect(
    clippy::too_many_arguments,
    reason = "the mutation needs its tab, its content archive and the walk to wake, none of which belongs on another's struct"
)]
async fn handle_synced_mutation<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
    id: TabId,
    tab_seq: u64,
    changeset: &[u8],
    staged: Option<StagedContent>,
    content: Option<&ContentArchive<BrowserStore>>,
    walk: &mut WalkState,
) -> Result<(), TabFault>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let (client_id, out, watermark) = {
        let Some(tab) = state.tabs.get(&id) else {
            return Ok(());
        };
        let Some(client_id) = tab.client_id else {
            return Ok(());
        };
        (client_id, tab.out.clone(), tab.applied_watermark)
    };
    if watermark.is_some_and(|watermark| tab_seq <= watermark) {
        // Already applied to the replica by an earlier delivery. The worker
        // replays its own pending record upstream independently, so a plain
        // re-acknowledgement is correct here.
        let _ = out.send(TabOut::Control(ControlMessage::MutationApplied(
            MutationApplied {
                client_seq: tab_seq,
            },
        )));
        return Ok(());
    }
    // The tab sent this under logical names, exactly as it would to the
    // server, because its own send path renames split tables back. Applying
    // raw would hit a split table's view, which the changeset apply refuses
    // row by row. Rename to the physical backing tables first, mirroring the
    // client's own apply direction.
    let map = worker.policy_tables().clone();
    let changeset = rename_to_physical(changeset, &map)?;
    let Ok(seq) = i64::try_from(tab_seq) else {
        return Err(TabFault::Close("sequence overflows storage".to_owned()));
    };
    if let Some(staged) = staged {
        match commit_staged_mutation(worker, content, staged, &changeset, client_id, seq).await {
            Ok(()) => {
                // The commit left an outbox entry the driver has not been
                // told about, and no upstream event may arrive to tell it.
                walk.outbox_wake = true;
            }
            Err(detail) => {
                reject_mutation(&out, tab_seq, detail);
                return Ok(());
            }
        }
    } else {
        let applied = worker.conn().transaction::<_, TabApplyError, _>(|conn| {
            conn.apply_changeset(&changeset, |_conflict| ConflictAction::Abort)
                .map_err(|err| TabApplyError::Apply(err.to_string()))?;
            record_tab_watermark(conn, client_id, seq)?;
            Ok(())
        });
        match applied {
            Ok(()) => {}
            Err(TabApplyError::Apply(detail)) => {
                reject_mutation(
                    &out,
                    tab_seq,
                    format!("worker replica apply failed: {detail}"),
                );
                return Ok(());
            }
            Err(TabApplyError::Db(err)) => return Err(RelayError::from(err).into()),
        }
    }
    if let Some(tab) = state.tabs.get_mut(&id) {
        tab.applied_watermark = Some(tab_seq);
    }
    if let Some(worker_seq) = worker.push().await.map_err(RelayError::from)? {
        state.seq_map.insert(worker_seq, (id, tab_seq));
        if state.seq_map.len() > SEQ_MAP_CAP {
            state.seq_map.pop_first();
        }
    }
    Ok(())
}

/// Chunk a staged blob and commit its manifest, outbox entry, watermark and
/// row change in one transaction.
///
/// The error is the refusal detail for the tab, never a hub fault.
async fn commit_staged_mutation<U>(
    worker: &mut ConnettoConnection<U>,
    content: Option<&ContentArchive<BrowserStore>>,
    staged: StagedContent,
    changeset: &[u8],
    client_id: rosetta_uuid::Uuid,
    seq: i64,
) -> Result<(), String>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let Some(content) = content else {
        return Err("this worker holds no content archive".to_owned());
    };
    let Ok(reader) = BlobSource::new(staged.blob) else {
        return Err("staged content could not be opened for reading".to_owned());
    };
    // Chunking runs outside the transaction: a large blob must not hold the
    // write lock, and bytes chunked for a commit that never lands are orphans
    // the next sweep collects, exactly as with the native client's staging.
    let manifest = content
        .chunk_file(reader, staged.mime)
        .await
        .map_err(|err| format!("staged content could not be chunked: {err}"))?;
    let declared = staged.file_id;
    content
        .commit_staged(worker, &manifest, |conn, worker_id| {
            if worker_id != declared {
                return Err(StageCommitError::Row(format!(
                    "staged bytes hash to {worker_id}, the mutation names {declared}"
                )));
            }
            conn.apply_changeset(changeset, |_conflict| ConflictAction::Abort)
                .map_err(|err| {
                    StageCommitError::Row(format!("worker replica apply failed: {err}"))
                })?;
            record_tab_watermark(conn, client_id, seq)?;
            Ok(())
        })
        .map_err(|err| match err {
            StageCommitError::Row(detail) => detail,
            StageCommitError::Bookkeeping(err) => {
                format!("the worker could not record the staged file: {err}")
            }
        })
}

/// Answer a mutation with a refusal the tab can surface.
fn reject_mutation(out: &UnboundedSender<TabOut>, tab_seq: u64, detail: String) {
    let _ = out.send(TabOut::Control(ControlMessage::MutationReject(
        MutationReject {
            client_seq: tab_seq,
            reason: MutationRejectReason::Other { detail },
        },
    )));
}

/// Advance one tab's durable mutation watermark inside the transaction that
/// applied its mutation.
///
/// `sql_query` is kept because `connetto_hub`._`tab_mutations` is in an ATTACHED
/// schema that diesel's table! macro does not model for SQLite.
fn record_tab_watermark(
    conn: &mut SqliteConnection,
    client_id: rosetta_uuid::Uuid,
    seq: i64,
) -> Result<(), diesel::result::Error> {
    diesel::sql_query(
        "INSERT INTO connetto_hub._tab_mutations (client_id, last_seq) VALUES (?, ?) \
         ON CONFLICT (client_id) DO UPDATE SET \
         last_seq = MAX(last_seq, excluded.last_seq)",
    )
    .bind::<rosetta_uuid::diesel_impls::Uuid, _>(client_id)
    .bind::<diesel::sql_types::BigInt, _>(seq)
    .execute(conn)?;
    Ok(())
}

/// Take the staged blob a synced changeset names, if this tab holds one,
/// dropping entries that went stale waiting for a mutation that never came.
fn take_staged(state: &mut HubState, id: TabId, changeset: &[u8]) -> Option<StagedContent> {
    let tab = state.tabs.get_mut(&id)?;
    if tab.staged.is_empty() {
        return None;
    }
    let now = js_sys::Date::now();
    tab.staged
        .retain(|staged| now - staged.taken < STALE_CONTENT_MS);
    let named = changeset_blob_values(changeset);
    if named.is_empty() {
        return None;
    }
    let index = tab
        .staged
        .iter()
        .position(|staged| named.contains(&staged.file_id))?;
    tab.staged.remove(index)
}

/// The file identities a changeset could be naming: every 32-byte blob value
/// it writes, which is where staged content declares itself. Old images are
/// never scanned: a row's previous identity names content the hub holds
/// already, not content this mutation uploaded.
///
/// Only changesets are scanned. A tab's own capture produces changesets, and
/// a patchset from a foreign tab is applied without content either way.
fn changeset_blob_values(bytes: &[u8]) -> Vec<FileId> {
    fn named(value: &Value<String, Vec<u8>>) -> Option<FileId> {
        let Value::Blob(blob) = value else {
            return None;
        };
        <[u8; 32]>::try_from(blob.as_slice())
            .ok()
            .map(FileId::from_bytes)
    }
    let Ok(parsed) = ParsedDiffSet::parse(bytes) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if let ParsedDiffSet::Changeset(diff) = parsed {
        for op in diff.iter() {
            match op {
                ChangesetOp::Insert { values, .. } => {
                    found.extend(values.iter().filter_map(named));
                }
                ChangesetOp::Update { values, .. } => {
                    found.extend(values.iter().filter_map(|pair| named(pair.1.as_ref()?)));
                }
                ChangesetOp::Delete { .. } => {}
            }
        }
    }
    found
}

/// cannot hold the hub. Both serve wherever they arrive, like `Attached`:
/// they write hub state or read the replica, never the server on the
/// critical path a resolve cannot wait out.
async fn handle_tab_internal<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
    content: Option<&ContentArchive<BrowserStore>>,
    id: TabId,
    frame: ContentFrame,
    blob: Option<web_sys::Blob>,
) -> Result<(), RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    if !state.tabs.get(&id).is_some_and(|tab| tab.handshaken) {
        return Ok(());
    }
    match frame {
        ContentFrame::Stage { file_id, mime } => {
            let Some(tab) = state.tabs.get_mut(&id) else {
                return Ok(());
            };
            let Some(blob) = blob else {
                tracing::warn!(tab = %id, "a stage message carried no blob");
                return Ok(());
            };
            let now = js_sys::Date::now();
            tab.staged
                .retain(|staged| now - staged.taken < STALE_CONTENT_MS);
            if tab.staged.len() >= MAX_STAGED_CONTENT {
                tracing::warn!(
                    tab = %id,
                    "the tab already holds the maximum unpaired stages, refusing another; \
                     content it announces from here on will not ride its mutation"
                );
                return Ok(());
            }
            tab.staged.push_back(StagedContent {
                file_id: FileId::from_bytes(file_id),
                mime: mime_from_code(mime),
                blob,
                taken: now,
            });
            Ok(())
        }
        ContentFrame::Resolve {
            request_id,
            file_id,
        } => {
            let start = match content {
                Some(content) => {
                    match content
                        .start_resolve_connection(worker, FileId::from_bytes(file_id))
                        .await
                    {
                        Ok(start) => Some(start),
                        Err(err) => {
                            tracing::warn!(
                                tab = %id,
                                ?err,
                                "the resolve's ticket request could not go out"
                            );
                            None
                        }
                    }
                }
                None => None,
            };
            match start {
                Some(ResolveStart::Waiting(ticket)) => {
                    state.pending_resolve.push(PendingHubResolve {
                        tab: id,
                        request_id,
                        ticket,
                        deadline: js_sys::Date::now() + f64::from(RESOLVE_WAIT_MS),
                    });
                }
                Some(ResolveStart::Answered(Resolved::Remote { url })) => {
                    answer_resolve(state, id, request_id, WireResolve::Remote { url }, None);
                }
                Some(ResolveStart::Answered(Resolved::Local { bytes, .. })) => {
                    answer_resolve(state, id, request_id, WireResolve::Local, Some(bytes));
                }
                Some(ResolveStart::Answered(Resolved::Unavailable)) | None => {
                    answer_resolve(state, id, request_id, WireResolve::Unavailable, None);
                }
            }
            Ok(())
        }
        ContentFrame::ResolveReply { .. } => Ok(()),
    }
}

/// Answers a tab's resolve on its content lane. A `Local` answer attaches its
/// bytes as the reply's blob; a tab that has detached loses the answer with
/// the lane.
fn answer_resolve(
    state: &mut HubState,
    tab: TabId,
    request_id: u64,
    answer: WireResolve,
    bytes: Option<Vec<u8>>,
) {
    let reply = ContentFrame::ResolveReply { request_id, answer };
    let blob = bytes.and_then(|bytes| {
        let parts = js_sys::Array::of1(&js_sys::Uint8Array::from(bytes.as_slice()));
        match web_sys::Blob::new_with_u8_array_sequence(&parts) {
            Ok(blob) => Some(blob),
            Err(err) => {
                tracing::warn!(
                    tab = %tab,
                    error = ?err,
                    "the browser refused a resolve reply blob"
                );
                None
            }
        }
    });
    if let Some(entry) = state.tabs.get(&tab) {
        let _ = entry.out.send(TabOut::Internal(reply.to_json(), blob));
    }
}

/// Runs one upstream event past the resolves waiting on tickets, answering
/// every tab whose wait it settles. The event goes on to the ordinary
/// handling: a grant is news the rest of the hub ignores, a refusal detail
/// names a request no tab write knows, and a closed link is news every
/// handler needs.
fn route_resolves(state: &mut HubState, event: &ClientEvent) {
    if state.pending_resolve.is_empty() {
        return;
    }
    let mut settled = Vec::new();
    let mut waiting = Vec::new();
    for resolve in std::mem::take(&mut state.pending_resolve) {
        match resolve.ticket.route(event) {
            ResolveRoute::Settled(result) => {
                settled.push((resolve.tab, resolve.request_id, result));
            }
            ResolveRoute::Other => waiting.push(resolve),
        }
    }
    state.pending_resolve = waiting;
    for (tab, request_id, result) in settled {
        let answer = match result {
            Ok(url) => WireResolve::Remote { url },
            Err(err) => {
                tracing::warn!(tab = %tab, ?err, "the content ticket request did not reach a grant");
                WireResolve::Unavailable
            }
        };
        answer_resolve(state, tab, request_id, answer, None);
    }
}

/// Milliseconds until the earliest resolve wait must answer, `None` when no
/// resolve waits. Never zero, so a cycle never busy-spins on an elapsed
/// deadline the sweep has not yet collected.
fn resolve_deadline_ms(pending: &[PendingHubResolve]) -> Option<i32> {
    let now = js_sys::Date::now();
    // The floor is 1 ms and the ceiling is RESOLVE_WAIT_MS, the widest wait
    // this file ever queues, so the value is always in i32 range.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "clamped to [1.0, RESOLVE_WAIT_MS = 15_000]; sub-ms rounding is deliberate"
    )]
    let ms = pending
        .iter()
        .map(|resolve| {
            (resolve.deadline - now)
                .clamp(1.0, f64::from(RESOLVE_WAIT_MS))
                .ceil() as i32
        })
        .min();
    ms
}

/// Answers `Unavailable` to every resolve whose wait ran out.
fn expire_resolves(state: &mut HubState) {
    if state.pending_resolve.is_empty() {
        return;
    }
    let now = js_sys::Date::now();
    let mut settled = Vec::new();
    let mut waiting = Vec::new();
    for resolve in std::mem::take(&mut state.pending_resolve) {
        if now >= resolve.deadline {
            settled.push((resolve.tab, resolve.request_id));
        } else {
            waiting.push(resolve);
        }
    }
    state.pending_resolve = waiting;
    for (tab, request_id) in settled {
        tracing::warn!(tab = %tab, request_id, "the content ticket did not answer in time");
        answer_resolve(state, tab, request_id, WireResolve::Unavailable, None);
    }
}

/// Rewrite a tab's logical-named changeset onto the physical backing tables,
/// returning the bytes unchanged when no table was split.
fn rename_to_physical(changeset: &[u8], map: &PolicyTables) -> Result<Vec<u8>, RelayError> {
    if map.is_empty() {
        return Ok(changeset.to_vec());
    }
    let mut parsed = ParsedDiffSet::parse(changeset)
        .map_err(|err| RelayError::Patch(format!("renaming a tab mutation: {err:?}")))?;
    if parsed.rename_tables(&mut |table: &str| map.physical(table).map(str::to_owned)) == 0 {
        return Ok(changeset.to_vec());
    }
    Ok(parsed.into())
}

/// Demux one worker aggregate push to the tab that owns its multiplexed
/// subscription, rebuilding the frame under the tab's own id.
fn forward_aggregate(
    state: &HubState,
    sub_id: &str,
    group_key: Option<Vec<u8>>,
    group_values_json: Option<String>,
    result_json: Option<String>,
    is_full_result: bool,
) {
    let Some(route) = state.agg_routes.get(sub_id) else {
        return;
    };
    if let Some(tab) = state.tabs.get(&route.tab) {
        let _ = tab
            .out
            .send(TabOut::Control(ControlMessage::AggregateUpdate(
                AggregateUpdate {
                    sub_id: route.tab_sub.clone(),
                    group_key,
                    group_values_json,
                    result_json,
                    is_full_result,
                },
            )));
    }
}

/// Handle one upstream event from the worker connection.
fn handle_worker_event<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
    event: ClientEvent,
) -> Result<(), RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    route_resolves(state, &event);
    match event {
        ClientEvent::LivePatch {
            cursor,
            patchset_zstd,
            ..
        } => {
            let tables = patch_tables(&patchset_zstd)?;
            // Each tab holds ONE replica, so a patch is forwarded at most
            // once per tab, under the first subscription reading a touched
            // table. The tab's own update hook refreshes every affected
            // handle.
            for tab in state.tabs.values_mut() {
                let Some(sub) = tab.subs.iter().find(|sub| !sub.tables.is_disjoint(&tables)) else {
                    continue;
                };
                let msg = BulkMessage::LivePatch(LivePatch::new(
                    sub.sub_id.clone(),
                    cursor.clone(),
                    patchset_zstd.to_vec(),
                ));
                enqueue_tab_frame(tab, TabDeliverable::Rows(msg));
            }
            Ok(())
        }
        ClientEvent::MutationApplied { client_seq } => {
            // The server's durable confirmation for a forwarded tab write:
            // map it back so the tab retires its pending record.
            let Some((tab_id, tab_seq)) = state.seq_map.remove(&client_seq) else {
                return Ok(());
            };
            if let Some(tab) = state.tabs.get(&tab_id) {
                let _ = tab
                    .out
                    .send(TabOut::Control(ControlMessage::MutationApplied(
                        MutationApplied {
                            client_seq: tab_seq,
                        },
                    )));
            }
            Ok(())
        }
        ClientEvent::MutationRejected { client_seq, .. } => reject_tab_mutation(
            state,
            client_seq,
            "the upstream server rejected the forwarded mutation",
        ),
        ClientEvent::MutationConflict {
            client_seq,
            rows,
            server_row,
        } => conflict_tab_mutation(state, client_seq, &rows, server_row),
        ClientEvent::Aggregate {
            sub_id,
            result_json,
            group_key,
            group_values_json,
            is_full_result,
        } => {
            forward_aggregate(
                state,
                &sub_id,
                group_key,
                group_values_json,
                result_json,
                is_full_result,
            );
            Ok(())
        }
        ClientEvent::FullResync { sub_id, reason } => {
            // The worker's own client clears its replica on this frame and
            // repopulates from the fresh snapshot that follows. Defer the tab
            // fan-out to the matching SnapshotEnd, when that replica is whole.
            state.resyncing.insert(sub_id, reason);
            Ok(())
        }
        ClientEvent::SnapshotEnd { sub_id } => {
            if let Some(reason) = state.resyncing.remove(&sub_id) {
                resnapshot_after_resync(worker, state, &sub_id, &reason)?;
            }
            Ok(())
        }
        ClientEvent::NonFatal { related_to, detail } => {
            forward_worker_nonfatal(state, related_to.as_deref(), &detail);
            Ok(())
        }
        ClientEvent::RateLimited {
            related_to,
            retry_after_ms,
        } => {
            forward_worker_rate_limited(state, related_to.as_deref(), retry_after_ms);
            Ok(())
        }
        // Whether the hub can reach the server is the answer every tab needs,
        // because a tab whose own link to the hub is perfect still cannot sync
        // while the hub cannot. It goes to every tab rather than to the readers
        // of some subscription, since it is about the connection and not about
        // any one query.
        ClientEvent::SyncStatus(status) => {
            state.sync_status = status;
            // Only tabs that have finished their own handshake: a control frame
            // ahead of a tab's ack is a protocol violation to that tab, and it
            // learns the current state as part of handshaking anyway.
            for tab in state.tabs.values().filter(|tab| tab.handshaken) {
                let _ = tab
                    .out
                    .send(TabOut::Control(ControlMessage::SyncStatus(status)));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Re-snapshot every tab subscription reading a table of a just-resynced
/// upstream sub. The worker replica has already applied the fresh snapshot
/// (its own client cleared the stale rows on `FullResyncRequired`), so each
/// tab receives its own `FullResyncRequired` followed by a fresh snapshot: it
/// clears its mirror and repopulates it exactly as a direct client would,
/// dropping rows deleted during the outage.
fn resnapshot_after_resync<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
    worker_sub: &str,
    reason: &FullResyncReason,
) -> Result<(), RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let Some(worker_tables) = state.resync_tables.get(worker_sub).cloned() else {
        return Ok(());
    };
    let targets: Vec<(TabId, String, SubscriptionPriority, HashSet<String>)> = state
        .tabs
        .iter()
        .flat_map(|(id, tab)| {
            tab.subs
                .iter()
                .filter(|sub| !sub.tables.is_disjoint(&worker_tables))
                .map(move |sub| (*id, sub.sub_id.clone(), sub.priority, sub.tables.clone()))
        })
        .collect();
    for (tab_id, tab_sub, priority, tab_tables) in targets {
        let Some(tab) = state.tabs.get_mut(&tab_id) else {
            continue;
        };
        let _ = tab
            .out
            .send(TabOut::Control(ControlMessage::FullResyncRequired(
                FullResyncRequired {
                    sub_id: tab_sub.clone(),
                    reason: reason.clone(),
                },
            )));
        serve_snapshot(
            worker,
            &mut state.blank,
            &state.local_tables,
            tab,
            &tab_sub,
            priority,
            &tab_tables,
        )?;
    }
    Ok(())
}

/// Map an upstream rejection back to the owning tab's sequence number.
///
/// The worker client already rolled the change back out of its replica. The
/// reject tells the tab to do the same to its mirror, so both converge.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the event dispatch calls every handler through the same fallible signature"
)]
fn reject_tab_mutation(
    state: &mut HubState,
    worker_seq: u64,
    detail: &str,
) -> Result<(), RelayError> {
    let Some((tab_id, tab_seq)) = state.seq_map.remove(&worker_seq) else {
        return Ok(());
    };
    if let Some(tab) = state.tabs.get(&tab_id) {
        let _ = tab.out.send(TabOut::Control(ControlMessage::MutationReject(
            MutationReject {
                client_seq: tab_seq,
                reason: MutationRejectReason::Other {
                    detail: detail.to_owned(),
                },
            },
        )));
    }
    Ok(())
}

/// Map an upstream conflict back to the owning tab's sequence number, as a
/// `MutationConflict` rather than a plain reject, so a relay tab draws the
/// same distinction a direct client does.
///
/// The server's copy of the conflicting row travels through the worker client
/// untouched, so the tab sees exactly what a direct client would. The table
/// name comes from the locally rolled-back rows, which the worker client
/// carries alongside it.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the event dispatch calls every handler through the same fallible signature"
)]
fn conflict_tab_mutation(
    state: &mut HubState,
    worker_seq: u64,
    rows: &[AffectedRow],
    server_row: Option<ConflictRow>,
) -> Result<(), RelayError> {
    let Some((tab_id, tab_seq)) = state.seq_map.remove(&worker_seq) else {
        return Ok(());
    };
    if let Some(tab) = state.tabs.get(&tab_id) {
        let table = rows
            .first()
            .map(|row| row.table.clone())
            .unwrap_or_default();
        let _ = tab
            .out
            .send(TabOut::Control(ControlMessage::MutationConflict(
                MutationConflict {
                    client_seq: tab_seq,
                    table,
                    server_row,
                },
            )));
    }
    Ok(())
}

/// Send a scoped non-fatal error to one tab, leaving its session and every
/// sibling subscription intact, exactly as the direct server does for a
/// rejected or unservable request.
fn send_tab_nonfatal(tab: &TabState, related_to: &str, detail: &str) {
    let _ = tab.out.send(TabOut::Control(ControlMessage::NonFatalError(
        NonFatalError {
            related_to: Some(related_to.to_owned()),
            detail: detail.to_owned(),
        },
    )));
}

/// Send a rate-limit refusal to one tab, correlated to the tab's own sub id.
///
/// The session stays alive. The tab may retry after `retry_after_ms`.
fn send_tab_rate_limited(tab: &TabState, related_to: &str, retry_after_ms: u64) {
    let _ = tab
        .out
        .send(TabOut::Control(ControlMessage::RateLimited(RateLimited {
            related_to: Some(related_to.to_owned()),
            retry_after_ms,
        })));
}

/// Forward the worker's own non-fatal error to the tab subscriptions it
/// concerns. An aggregate upstream (`agg-{tab}-{sub}`) maps to its one owning
/// tab subscription. A row upstream maps to every tab subscription reading one
/// of its tables, mirroring the resync fan-out, so a rejected replica feed
/// surfaces on each affected tab rather than vanishing. An error the hub cannot
/// correlate to a tab is dropped.
fn forward_worker_nonfatal(state: &HubState, related_to: Option<&str>, detail: &str) {
    let Some(upstream) = related_to else {
        return;
    };
    if let Some(route) = state.agg_routes.get(upstream) {
        if let Some(tab) = state.tabs.get(&route.tab) {
            send_tab_nonfatal(tab, &route.tab_sub, detail);
        }
        return;
    }
    let Some(tables) = state.resync_tables.get(upstream) else {
        return;
    };
    for tab in state.tabs.values() {
        for sub in &tab.subs {
            if !sub.tables.is_disjoint(tables) {
                send_tab_nonfatal(tab, &sub.sub_id, detail);
            }
        }
    }
}

/// Forward the worker's own rate-limit refusal to the tab subscriptions it
/// concerns, mirroring the logic of [`forward_worker_nonfatal`]. An aggregate
/// upstream maps to its one owning tab subscription. A row upstream maps to
/// every tab subscription reading one of its tables. An uncorrelated refusal
/// is dropped.
fn forward_worker_rate_limited(state: &HubState, related_to: Option<&str>, retry_after_ms: u64) {
    let Some(upstream) = related_to else {
        return;
    };
    if let Some(route) = state.agg_routes.get(upstream) {
        if let Some(tab) = state.tabs.get(&route.tab) {
            send_tab_rate_limited(tab, &route.tab_sub, retry_after_ms);
        }
        return;
    }
    let Some(tables) = state.resync_tables.get(upstream) else {
        return;
    };
    for tab in state.tabs.values() {
        for sub in &tab.subs {
            if !sub.tables.is_disjoint(tables) {
                send_tab_rate_limited(tab, &sub.sub_id, retry_after_ms);
            }
        }
    }
}

/// Answer one tab subscription: a snapshot from the worker replica for synced
/// tables and from the attached device-private tables for the rest, both over
/// the one connection and between one begin and end pair.
///
/// Both payloads are built and compressed before any frame goes out. A begin
/// ahead of a failing read would mark the refusal as one that got as far as
/// the replica, and a refusal must not vary by cause.
fn serve_snapshot<U>(
    worker: &mut ConnettoConnection<U>,
    blank: &mut BlankState,
    tier_tables: &HashSet<String>,
    tab: &mut TabState,
    sub_id: &str,
    priority: SubscriptionPriority,
    tables: &HashSet<String>,
) -> Result<(), RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let local_tables: HashSet<String> = tables.intersection(tier_tables).cloned().collect();
    let synced: HashSet<String> = tables.difference(&local_tables).cloned().collect();
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    if !synced.is_empty() {
        let map = worker.policy_tables().clone();
        let patchset = synced_snapshot(worker.conn(), &map, &synced, blank)?;
        if !patchset.is_empty() {
            payloads.push(zstd::encode_all(&patchset[..], ZSTD_LEVEL)?);
        }
    }
    if !local_tables.is_empty() {
        let patchset = snapshot_patchset(worker.conn(), LOCAL_SCHEMA, &local_tables, blank)?;
        if !patchset.is_empty() {
            payloads.push(zstd::encode_all(&patchset[..], ZSTD_LEVEL)?);
        }
    }
    let _ = tab.out.send(TabOut::Control(ControlMessage::SnapshotBegin(
        SnapshotBegin {
            sub_id: sub_id.to_owned(),
            priority,
        },
    )));
    for payload in payloads {
        enqueue_tab_frame(
            tab,
            TabDeliverable::Rows(BulkMessage::SnapshotPatch(SnapshotPatch::new(
                sub_id.to_owned(),
                payload,
            ))),
        );
    }
    // Queued rather than sent, so it cannot overtake the rows it completes
    // when the tab's credit window is shut. It costs no credit: it waits its
    // turn, it is not rationed (R33).
    enqueue_tab_frame(
        tab,
        TabDeliverable::SnapshotComplete(SnapshotEnd {
            sub_id: sub_id.to_owned(),
            cursor: relay_cursor(worker),
        }),
    );
    Ok(())
}

/// Queue one frame toward a tab under its credit window, then drain what the
/// credits allow in FIFO order. Mirrors the server's `enqueue_and_flush`.
fn enqueue_tab_frame(tab: &mut TabState, msg: TabDeliverable) {
    tab.pending.push_back(msg);
    flush_tab_bulk(tab);
}

/// Drain a tab's queue in order, stopping at the first bulk frame the credit
/// window cannot pay for. A dropped `out` means the tab is gone, so sends stay
/// best effort.
///
/// A free item behind a bulk frame the window cannot afford stays queued, and
/// that is the point: it is queued precisely because it describes data the tab
/// has not received.
fn flush_tab_bulk(tab: &mut TabState) {
    loop {
        if tab.credits == 0
            && tab
                .pending
                .front()
                .is_some_and(TabDeliverable::costs_credit)
        {
            return;
        }
        let Some(next) = tab.pending.pop_front() else {
            return;
        };
        match next {
            TabDeliverable::Rows(msg) => {
                let _ = tab.out.send(TabOut::Bulk(msg));
                tab.credits -= 1;
            }
            TabDeliverable::SnapshotComplete(end) => {
                let _ = tab
                    .out
                    .send(TabOut::Control(ControlMessage::SnapshotEnd(end)));
            }
        }
    }
}

/// Build the synced-tier snapshot for `tables` (logical names), reading each
/// policy-split table through its physical backing table and renaming the
/// patchset back, so the tab-facing payload speaks logical names exactly like
/// the server does.
///
/// The logical name of a split table is a view in the replica, which a
/// session cannot diff, and the plain read used to match nothing and serve an
/// empty snapshot silently.
fn synced_snapshot(
    conn: &mut SqliteConnection,
    map: &PolicyTables,
    tables: &HashSet<String>,
    blank: &mut BlankState,
) -> Result<Vec<u8>, RelayError> {
    let mut read = HashSet::with_capacity(tables.len());
    let mut back: HashMap<String, String> = HashMap::new();
    for name in tables {
        match map.physical(name) {
            Some(physical) => {
                read.insert(physical.to_owned());
                back.insert(physical.to_owned(), name.clone());
            }
            None => {
                read.insert(name.clone());
            }
        }
    }
    let patchset = snapshot_patchset(conn, MAIN_SCHEMA, &read, blank)?;
    if back.is_empty() || patchset.is_empty() {
        return Ok(patchset);
    }
    let mut parsed = ParsedDiffSet::parse(&patchset)
        .map_err(|err| RelayError::Patch(format!("renaming a split snapshot: {err:?}")))?;
    if parsed.rename_tables(&mut |table: &str| back.get(&table.to_lowercase()).cloned()) == 0 {
        return Ok(patchset);
    }
    Ok(parsed.into())
}

/// Build one insert patchset holding every current row of the requested
/// tables in `schema`, by diffing them against empty twins in an attached
/// blank database.
///
/// `sqlite3session_diff` requires the twin to live on the same connection
/// under the same table name, so the blank database is attached once and each
/// requested table's stored DDL is replayed into it with a schema qualifier
/// spliced in. The throwaway session never sees a write, it only loads the
/// diff, so any capture session on the connection is unaffected.
///
/// `schema` is what lets one connection serve both tiers. A session binds to
/// one database for its whole life, so the device-private tables need a
/// session opened on their attached name rather than on `main`. One blank
/// database serves both, because its twins are keyed by table name and a name
/// shared between the two tiers is a generation-time error.
fn snapshot_patchset(
    conn: &mut SqliteConnection,
    schema: &str,
    tables: &HashSet<String>,
    blank: &mut BlankState,
) -> Result<Vec<u8>, RelayError> {
    #[derive(QueryableByName)]
    struct SchemaRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        sql: Option<String>,
    }
    let rows: Vec<SchemaRow> = sql_query(format!(
        "SELECT name, sql FROM {schema}.sqlite_schema \
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ))
    .load(&mut *conn)?;
    let matching: Vec<SchemaRow> = rows
        .into_iter()
        .filter(|row| tables.contains(&row.name.to_lowercase()))
        .collect();
    if matching.is_empty() {
        return Ok(Vec::new());
    }
    if !blank.attached {
        // An in-memory database needs no creation permit, only the write one:
        // the twins below are created inside it.
        connetto_client::harden::attach_in_window(
            conn,
            ":memory:",
            "blank",
            connetto_client::harden::AttachPermits::Write,
        )?;
        blank.attached = true;
    }
    for row in &matching {
        if blank.tables.contains(&row.name) {
            continue;
        }
        let ddl = row
            .sql
            .as_deref()
            .ok_or_else(|| RelayError::Snapshot(format!("table {} has no stored DDL", row.name)))?;
        let twin = qualify_ddl(ddl, &row.name).ok_or_else(|| {
            RelayError::Snapshot(format!("cannot qualify the DDL of table {}", row.name))
        })?;
        conn.batch_execute(&twin)?;
        blank.tables.insert(row.name.clone());
    }
    let mut session = conn.create_session_on(schema).map_err(session_err)?;
    for row in &matching {
        session.attach_by_name(&row.name).map_err(session_err)?;
        session.diff("blank", &row.name).map_err(session_err)?;
    }
    session.patchset().map_err(session_err)
}

/// Splice the `blank` schema qualifier onto the table name of a stored
/// `CREATE TABLE` statement, so replaying it builds the empty twin inside the
/// attached database.
///
/// `sqlite_schema` stores the original DDL text, so the name token follows
/// `CREATE TABLE` in one of the four SQLite quoting forms or bare. Returns
/// `None` when the text does not match that shape.
fn qualify_ddl(ddl: &str, table: &str) -> Option<String> {
    let after_create = strip_ci(ddl.trim_start(), "CREATE")?;
    let after_table = strip_ci(after_create.trim_start(), "TABLE")?;
    let name_and_body = after_table.trim_start();
    for quoted in [
        format!("\"{table}\""),
        format!("`{table}`"),
        format!("[{table}]"),
        table.to_owned(),
    ] {
        let matches_token = name_and_body
            .get(..quoted.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(&quoted));
        if matches_token {
            return Some(format!("CREATE TABLE blank.{name_and_body}"));
        }
    }
    None
}

/// Case-insensitive prefix strip over ASCII keywords.
fn strip_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// The lowercased set of tables a compressed patchset touches.
fn patch_tables(patchset_zstd: &[u8]) -> Result<HashSet<String>, RelayError> {
    let bytes = zstd::decode_all(patchset_zstd)?;
    changeset_tables(&bytes)
}

/// The lowercased set of tables an uncompressed changeset or patchset
/// touches.
fn changeset_tables(bytes: &[u8]) -> Result<HashSet<String>, RelayError> {
    let parsed =
        ParsedDiffSet::parse(bytes).map_err(|err| RelayError::Patch(format!("{err:?}")))?;
    let mut tables = HashSet::new();
    match parsed {
        ParsedDiffSet::Changeset(diff) => {
            for op in diff.iter() {
                tables.insert(op.table().name().to_lowercase());
            }
        }
        ParsedDiffSet::Patchset(diff) => {
            for op in diff.iter() {
                tables.insert(op.table().name().to_lowercase());
            }
        }
    }
    Ok(tables)
}

/// The hub's durable watermark for one tab client id, if any, from the
/// attached hub meta schema.
fn tab_watermark<U>(
    worker: &mut ConnettoConnection<U>,
    client_id: rosetta_uuid::Uuid,
) -> Result<Option<u64>, RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    // sql_query is kept here because connetto_hub._tab_mutations lives in an
    // ATTACHED schema that diesel's table! macro does not model for SQLite.
    #[derive(diesel::QueryableByName)]
    struct WatermarkRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        last_seq: i64,
    }
    let rows: Vec<WatermarkRow> =
        diesel::sql_query("SELECT last_seq FROM connetto_hub._tab_mutations WHERE client_id = ?")
            .bind::<rosetta_uuid::diesel_impls::Uuid, _>(client_id)
            .load(worker.conn())?;
    Ok(rows
        .into_iter()
        .next()
        .and_then(|row| u64::try_from(row.last_seq).ok()))
}

/// The local tier's durable watermark for one tab client id, if any.
fn local_tab_watermark<U>(
    worker: &mut ConnettoConnection<U>,
    client_id: rosetta_uuid::Uuid,
) -> Result<Option<u64>, RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    use local_schema::_connetto_tab_mutations::dsl as wm;
    let result = wm::_connetto_tab_mutations
        .filter(wm::client_id.eq(client_id))
        .select(wm::last_seq)
        .first::<i64>(worker.conn())
        .optional()?;
    Ok(result.and_then(|v| u64::try_from(v).ok()))
}

/// The worker's resume cursor, or an empty placeholder before the first
/// upstream snapshot end arrives.
fn relay_cursor<U>(worker: &ConnettoConnection<U>) -> Cursor
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    worker
        .cursor()
        .cloned()
        .unwrap_or_else(|| Cursor::new(Vec::new()))
}

/// Fold a session extension error into [`RelayError::Session`].
fn session_err<E: core::fmt::Display>(err: E) -> RelayError {
    RelayError::Session(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        BrowserHttp, ContentFrame, HubContent, HubEvent, TabApplyError, apply_local_changeset,
        changeset_blob_values, recovery_interrupts_attach, recovery_serves_idle,
        schedule_recovery_event,
    };
    use connetto_file_core::FileId;
    use diesel::connection::SimpleConnection;
    use diesel::{Connection, RunQueryDsl, SqliteConnection};
    use diesel_sqlite_session::SqliteSessionExt;
    use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_dedicated_worker);

    const DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)";

    #[wasm_bindgen_test]
    fn a_local_recovery_request_cannot_overtake_an_ordinary_event() {
        let mut deferred = std::collections::VecDeque::new();
        deferred.push_back(HubEvent::Kill(7));
        let (reply, _answer) = futures_channel::oneshot::channel();

        assert!(
            schedule_recovery_event(
                &mut deferred,
                HubEvent::Unsynced(reply),
                recovery_serves_idle
            )
            .is_none()
        );
        assert!(matches!(deferred.pop_front(), Some(HubEvent::Kill(7))));
        assert!(matches!(deferred.pop_front(), Some(HubEvent::Unsynced(_))));
    }

    #[wasm_bindgen_test]
    fn a_local_recovery_request_is_serviceable_at_the_queue_head() {
        let mut deferred = std::collections::VecDeque::new();
        let (reply, _answer) = futures_channel::oneshot::channel();

        assert!(matches!(
            schedule_recovery_event(
                &mut deferred,
                HubEvent::Unsynced(reply),
                recovery_serves_idle
            ),
            Some(HubEvent::Unsynced(_))
        ));
        assert!(deferred.is_empty());
    }

    /// Acknowledging a retirement only writes the replica, so it is served during recovery
    /// rather than queued behind an upstream that may never come back.
    #[wasm_bindgen_test]
    fn a_retirement_acknowledgement_is_serviceable_during_recovery() {
        let mut deferred = std::collections::VecDeque::new();
        let (reply, _answer) = futures_channel::oneshot::channel();

        assert!(matches!(
            schedule_recovery_event(
                &mut deferred,
                HubEvent::ForgetRetired(Vec::new(), reply),
                recovery_serves_idle,
            ),
            Some(HubEvent::ForgetRetired(_, _))
        ));
        assert!(deferred.is_empty());
    }

    /// Chapter 18's idle column (amended R69-F): every event that can be answered from
    /// local state is served where it arrives during idle recovery, including Frames. A
    /// tab mutation commits to durable pending and replays exactly once on attach under
    /// the R67 watermark, mirroring the native client's offline behaviour. The only events
    /// that wait for the upstream are those in `recovery_interrupts_attach` not in this
    /// predicate, because the attach phase owns the connection for replay.
    #[wasm_bindgen_test]
    fn a_frame_is_served_into_pending_during_idle_recovery() {
        use connetto_core::messages::{ControlMessage, Ping};
        use connetto_core::traits::IncomingFrame;
        use tokio::sync::mpsc::unbounded_channel;

        let mut deferred = std::collections::VecDeque::new();
        let (out, _out_rx) = unbounded_channel();
        assert!(
            matches!(
                schedule_recovery_event(
                    &mut deferred,
                    HubEvent::Attached(1, out),
                    recovery_serves_idle
                ),
                Some(HubEvent::Attached(_, _))
            ),
            "a tab attach writes hub state and is served"
        );
        assert!(matches!(
            schedule_recovery_event(&mut deferred, HubEvent::Gone(1), recovery_serves_idle),
            Some(HubEvent::Gone(1))
        ));
        assert!(matches!(
            schedule_recovery_event(&mut deferred, HubEvent::Kill(1), recovery_serves_idle),
            Some(HubEvent::Kill(1))
        ));
        // Frames are now served during idle recovery: a tab mutation that arrives while
        // the upstream is down commits to the replica and to _connetto_pending, then
        // replays exactly once when the upstream attaches, the same contract as native.
        assert!(
            matches!(
                schedule_recovery_event(
                    &mut deferred,
                    HubEvent::Frame(
                        1,
                        IncomingFrame::Control(ControlMessage::Ping(Ping { nonce: 1 })),
                    ),
                    recovery_serves_idle,
                ),
                Some(HubEvent::Frame(_, _))
            ),
            "a frame is served from local state during idle recovery"
        );
        assert_eq!(
            deferred.len(),
            0,
            "nothing is queued while the deque was empty"
        );
    }

    /// Chapter 18's attach column: a departure or a kill unsubscribes through the
    /// connection the attach owns, so it keeps its place instead of interrupting.
    #[wasm_bindgen_test]
    fn a_departure_does_not_interrupt_an_attach() {
        let mut deferred = std::collections::VecDeque::new();
        assert!(
            schedule_recovery_event(&mut deferred, HubEvent::Gone(1), recovery_interrupts_attach)
                .is_none()
        );
        let (reply, _answer) = futures_channel::oneshot::channel();
        assert!(
            schedule_recovery_event(
                &mut deferred,
                HubEvent::Unsynced(reply),
                recovery_interrupts_attach,
            )
            .is_none(),
            "and the request behind it keeps the arrival order"
        );
        assert_eq!(deferred.len(), 2);
    }

    /// A staged blob only writes hub state, and a resolve is answered from
    /// the replica or the chunk store, so both are served wherever they
    /// arrive. A resolve has a tab waiting on the answer, so it interrupts a
    /// replay. A stage waits on nobody and keeps its queue place.
    #[wasm_bindgen_test]
    fn internal_content_frames_follow_the_recovery_columns() {
        let stage = HubEvent::Internal(
            1,
            ContentFrame::Stage {
                file_id: [1; 32],
                mime: 0,
            },
            None,
        );
        let resolve = HubEvent::Internal(
            1,
            ContentFrame::Resolve {
                request_id: 7,
                file_id: [2; 32],
            },
            None,
        );
        assert!(
            recovery_serves_idle(&stage),
            "a stage writes hub state only"
        );
        assert!(
            recovery_serves_idle(&resolve),
            "a resolve never needs the server"
        );
        assert!(
            recovery_interrupts_attach(&resolve),
            "a tab waits on its resolve, so it overtakes a replay"
        );
        assert!(
            !recovery_interrupts_attach(&stage),
            "nothing waits on a stage, so it keeps its place"
        );
    }

    /// Pairing reads the declared identity straight out of the tab's
    /// changeset: every 32-byte blob an insert writes or an update names in
    /// its new values. Old images name nothing, and a delete writes nothing.
    #[wasm_bindgen_test]
    fn a_changeset_names_its_thirty_two_byte_blobs() {
        let mut conn = SqliteConnection::establish(":memory:").expect("open");
        conn.batch_execute(
            "CREATE TABLE photos (id INTEGER PRIMARY KEY, content_id BLOB NOT NULL)",
        )
        .expect("schema");
        let mut session = conn.create_session().expect("session");
        session.attach_all().expect("attach");
        conn.batch_execute("INSERT INTO photos VALUES (1, x'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')")
            .expect("insert");
        let changeset = session.changeset().expect("changeset");
        assert_eq!(
            changeset_blob_values(&changeset),
            vec![FileId::from_bytes([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f
            ])],
            "an insert names its content"
        );

        conn.batch_execute("UPDATE photos SET content_id = x'202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' WHERE id = 1")
            .expect("update");
        let changeset = session.changeset().expect("changeset");
        let named = changeset_blob_values(&changeset);
        assert!(
            named.contains(&FileId::from_bytes([
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
                0x3c, 0x3d, 0x3e, 0x3f
            ])),
            "an update names its new content, got {named:?}"
        );
        assert!(
            !named.contains(&FileId::from_bytes([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f
            ])),
            "the old image a column sheds names nothing, got {named:?}"
        );

        conn.batch_execute("DELETE FROM photos WHERE id = 1")
            .expect("delete");
        let changeset = session.changeset().expect("changeset");
        assert!(
            changeset_blob_values(&changeset).is_empty(),
            "a delete writes no content and stages nothing"
        );
    }

    /// Thirty-one bytes is data, not an identity, and a blob value longer
    /// than a hash is nobody's file.
    #[wasm_bindgen_test]
    fn only_a_thirty_two_byte_blob_names_a_file() {
        let mut conn = SqliteConnection::establish(":memory:").expect("open");
        conn.batch_execute(
            "CREATE TABLE photos (id INTEGER PRIMARY KEY, content_id BLOB NOT NULL)",
        )
        .expect("schema");
        let mut session = conn.create_session().expect("session");
        session.attach_all().expect("attach");
        conn.batch_execute("INSERT INTO photos VALUES (1, x'010203')")
            .expect("short blob");
        let changeset = session.changeset().expect("changeset");
        assert!(
            changeset_blob_values(&changeset).is_empty(),
            "a short blob is not an identity"
        );
        assert!(
            changeset_blob_values(b"not even a changeset").is_empty(),
            "undecodable bytes name nothing"
        );
    }

    /// Chapter 18's job table: the walk owes a turn through the retry sleep and the
    /// connect, where the connection is idle.
    #[wasm_bindgen_test]
    fn the_walk_owes_a_turn_while_the_connection_is_idle() {
        use connetto_file_core::FileId;

        let settled = super::WalkState::default();
        assert!(
            !super::walk_owes(&settled),
            "a settled walk asks for no turn"
        );
        let mut owing = super::WalkState::default();
        owing.unverified.push_back(FileId::from_bytes([1; 32]));
        assert!(super::walk_owes(&owing), "a queued file owes a turn");
        let mut swept = super::WalkState {
            unswept: true,
            ..super::WalkState::default()
        };
        assert!(super::walk_owes(&swept), "an owed sweep owes a turn");
        swept.sweep_waiting = true;
        assert!(
            !super::walk_owes(&swept),
            "and a sweep waiting for the retry timer does not"
        );
    }

    /// A database holding `drafts` with one row, in memory.
    fn seeded(body: &str) -> SqliteConnection {
        let mut conn = SqliteConnection::establish(":memory:").expect("open");
        conn.batch_execute(DDL).expect("schema");
        conn.batch_execute(&format!("INSERT INTO drafts VALUES (1, '{body}')"))
            .expect("seed");
        conn
    }

    /// Capture the changeset a tab would ship for `statement`, against a row
    /// that starts at `from`.
    fn captured(from: &str, statement: &str) -> Vec<u8> {
        let mut conn = seeded(from);
        let mut session = conn.create_session().expect("session");
        session.attach_all().expect("attach");
        conn.batch_execute(statement).expect("write");
        session.changeset().expect("changeset")
    }

    fn body(conn: &mut SqliteConnection) -> Option<String> {
        #[derive(diesel::QueryableByName)]
        struct Row {
            #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
            body: Option<String>,
        }
        diesel::sql_query("SELECT body FROM drafts WHERE id = 1")
            .load::<Row>(conn)
            .expect("read")
            .into_iter()
            .next()
            .and_then(|row| row.body)
    }

    /// The rule `ConflictAction::Abort` gave and the replay has to keep: a
    /// write lands only onto the row the writer actually saw.
    #[wasm_bindgen_test]
    fn an_update_lands_when_the_row_still_holds_what_the_writer_saw() {
        let changeset = captured("first", "UPDATE drafts SET body = 'second' WHERE id = 1");
        let mut target = seeded("first");
        apply_local_changeset(&mut target, &changeset).expect("the update applies");
        assert_eq!(body(&mut target).as_deref(), Some("second"));
    }

    /// The case that separates a changeset replay from a blind key match: the
    /// row is there, its key matches, and somebody else has changed it.
    #[wasm_bindgen_test]
    fn an_update_onto_a_row_somebody_else_changed_is_refused() {
        let changeset = captured("first", "UPDATE drafts SET body = 'second' WHERE id = 1");
        let mut target = seeded("somebody-elses-edit");
        let outcome = apply_local_changeset(&mut target, &changeset);
        assert!(
            matches!(outcome, Err(TabApplyError::Apply(_))),
            "a stale update must be refused, got {outcome:?}"
        );
        assert_eq!(
            body(&mut target).as_deref(),
            Some("somebody-elses-edit"),
            "and must leave the row alone"
        );
    }

    #[wasm_bindgen_test]
    fn a_delete_of_a_row_that_has_gone_is_refused() {
        let changeset = captured("first", "DELETE FROM drafts WHERE id = 1");
        let mut target = SqliteConnection::establish(":memory:").expect("open");
        target.batch_execute(DDL).expect("schema");
        let outcome = apply_local_changeset(&mut target, &changeset);
        assert!(
            matches!(outcome, Err(TabApplyError::Apply(_))),
            "a delete of a vanished row must be refused, got {outcome:?}"
        );
    }

    #[wasm_bindgen_test]
    fn an_insert_onto_an_occupied_key_is_refused() {
        let mut source = SqliteConnection::establish(":memory:").expect("open");
        source.batch_execute(DDL).expect("schema");
        let mut session = source.create_session().expect("session");
        session.attach_all().expect("attach");
        source
            .batch_execute("INSERT INTO drafts VALUES (1, 'mine')")
            .expect("write");
        let changeset = session.changeset().expect("changeset");

        let mut target = seeded("already-here");
        let outcome = apply_local_changeset(&mut target, &changeset);
        assert!(
            matches!(outcome, Err(TabApplyError::Apply(_))),
            "an insert onto an occupied key must be refused, got {outcome:?}"
        );
    }

    /// A null is written into the predicate rather than bound, so a row whose
    /// old value was null still has to match exactly.
    #[wasm_bindgen_test]
    fn a_null_old_value_matches_only_a_null() {
        let changeset = captured_null();
        let mut holds_null = SqliteConnection::establish(":memory:").expect("open");
        holds_null.batch_execute(DDL).expect("schema");
        holds_null
            .batch_execute("INSERT INTO drafts VALUES (1, NULL)")
            .expect("seed");
        apply_local_changeset(&mut holds_null, &changeset).expect("the update applies");
        assert_eq!(body(&mut holds_null).as_deref(), Some("filled"));

        let mut holds_text = seeded("not-null");
        let outcome = apply_local_changeset(&mut holds_text, &changeset);
        assert!(
            matches!(outcome, Err(TabApplyError::Apply(_))),
            "a null old value must not match a row holding text, got {outcome:?}"
        );
    }

    /// The changeset for filling a null column.
    fn captured_null() -> Vec<u8> {
        let mut conn = SqliteConnection::establish(":memory:").expect("open");
        conn.batch_execute(DDL).expect("schema");
        conn.batch_execute("INSERT INTO drafts VALUES (1, NULL)")
            .expect("seed");
        let mut session = conn.create_session().expect("session");
        session.attach_all().expect("attach");
        conn.batch_execute("UPDATE drafts SET body = 'filled' WHERE id = 1")
            .expect("write");
        session.changeset().expect("changeset")
    }

    /// R18: the generic snapshot's scratch database still attaches, even though
    /// the replica connection refuses every attach at rest.
    ///
    /// The hub's own meta database is covered by the `logout_refusal` suite,
    /// which builds a real hub. This one is the mid-session attach, which no
    /// suite reaches through a tab.
    #[wasm_bindgen_test]
    fn the_snapshot_scratch_database_attaches_through_a_window() {
        let mut conn = seeded("under lockdown");
        connetto_client::harden::harden_replica_connection(&mut conn).expect("harden");
        assert_eq!(
            conn.get_limit(diesel::sqlite::SqliteLimit::Attached),
            0,
            "nothing is attached, so nothing may be"
        );

        let mut blank = super::BlankState::default();
        let tables: std::collections::HashSet<String> =
            core::iter::once("drafts".to_owned()).collect();
        let patchset = super::snapshot_patchset(&mut conn, super::MAIN_SCHEMA, &tables, &mut blank)
            .expect("the snapshot attaches its scratch database and diffs against it");
        assert!(
            !patchset.is_empty(),
            "the seeded row has to appear in the patchset"
        );
        assert_eq!(
            conn.get_limit(diesel::sqlite::SqliteLimit::Attached),
            1,
            "the ceiling followed the scratch attach and closed behind it"
        );
    }

    /// The hub's snapshot must see a policy-split table: the logical name is
    /// a view, the rows live under the backing table, and the served patchset
    /// has to come back under the logical name. This served an empty snapshot
    /// silently before the worker's map was threaded through.
    #[wasm_bindgen_test]
    fn a_split_table_snapshot_reads_the_backing_table_and_speaks_logically() {
        let mut conn = SqliteConnection::establish(":memory:").expect("open");
        conn.batch_execute(
            "CREATE TABLE orders_rls (id INTEGER PRIMARY KEY, owner_id TEXT NOT NULL);
             CREATE VIEW orders AS SELECT id, owner_id FROM orders_rls;
             INSERT INTO orders_rls VALUES (7, 'alice');",
        )
        .expect("split schema");
        let map =
            connetto_client::PolicyTables::from_translation([("orders", "orders_rls")], ["orders"]);
        let tables: std::collections::HashSet<String> =
            core::iter::once("orders".to_owned()).collect();
        let mut blank = super::BlankState::default();
        let patchset =
            super::synced_snapshot(&mut conn, &map, &tables, &mut blank).expect("snapshot");
        assert!(
            !patchset.is_empty(),
            "the seeded backing-table row has to appear in the patchset"
        );
        let sqlite_diff_rs::ParsedDiffSet::Patchset(set) =
            sqlite_diff_rs::ParsedDiffSet::parse(&patchset).expect("parse")
        else {
            panic!("a session patchset parses as a patchset");
        };
        let names: Vec<String> = set.iter().map(|op| op.table().name().clone()).collect();
        assert_eq!(names, ["orders"], "one insert, under the logical name");
    }

    /// R83 browser done-when: a tab's aggregate watch is answered from the
    /// resting table while the worker is offline, so the tab shows the last
    /// synced value through the DB worker rather than nothing.
    ///
    /// The worker rests the value on the connection's own frame path, the same
    /// path the native client uses, which is what lets the hub answer with no
    /// server: it reads the rested scalar and synthesizes the bootstrap frame
    /// the server would have sent.
    #[wasm_bindgen_test]
    async fn a_tab_aggregate_watch_is_answered_from_rest_while_offline() {
        use connetto_client::{ClientConfig, ConnettoConnection, Grant, Replica};
        use connetto_core::messages::{
            AggregateUpdate, ControlMessage, Subscribe, SubscriptionSpec,
        };
        use connetto_core::test_support::FakeTransport;
        use connetto_core::traits::IncomingFrame;
        use std::collections::{HashMap, VecDeque};
        use tokio::sync::mpsc::unbounded_channel;

        const AGG_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, quantity INTEGER)";
        let query = "SELECT COUNT(*) FROM orders";
        let spec = SubscriptionSpec::new(query);
        let config = ClientConfig::new("worker").with_login(Some(Grant::new("user:token")));

        // A fake server that acks the handshake, delivers one scalar bootstrap
        // for the worker's upstream subscription, then drains so the worker
        // goes offline with the value on record.
        let transport = FakeTransport::accepting_then_delivering([IncomingFrame::Control(
            ControlMessage::AggregateUpdate(AggregateUpdate {
                sub_id: "wire-0".to_owned(),
                group_key: None,
                group_values_json: None,
                result_json: Some("7".to_owned()),
                is_full_result: true,
            }),
        )]);
        // Subscribe offline first, so the frame's sub id resolves to a query
        // identity the instant it lands, then attach the fake server and pump
        // until it drains, which drains the connect notice, rests the
        // bootstrap, and takes the close.
        let mut worker = ConnettoConnection::<FakeTransport>::open(
            &Replica::in_memory(),
            AGG_DDL,
            &config,
            None,
        )
        .expect("worker opens offline");
        worker
            .subscribe_spec("wire-0", spec.clone())
            .await
            .expect("worker records its upstream subscription");
        worker.attach(transport).await.expect("worker attaches");
        while worker.is_connected() {
            if worker.pump_one().await.is_err() {
                break;
            }
        }
        assert!(!worker.is_connected(), "the worker is offline for the test");

        // A tab subscribes the same aggregate through the hub while offline.
        let (out_tx, mut out_rx) = unbounded_channel();
        let mut tab = super::TabState {
            out: out_tx,
            handshaken: true,
            subs: Vec::new(),
            pending_write: None,
            client_id: None,
            applied_watermark: None,
            local_watermark: None,
            credits: super::INITIAL_CREDITS,
            pending: VecDeque::new(),
            staged: VecDeque::new(),
        };
        let mut agg_routes: HashMap<String, super::AggRoute> = HashMap::new();
        let subscribe = Subscribe {
            sub_id: "s1".to_owned(),
            spec,
        };
        if super::register_tab_aggregate(&mut worker, &mut agg_routes, &mut tab, 1, subscribe)
            .await
            .is_err()
        {
            panic!("the hub failed to answer the tab from rest");
        }

        match out_rx
            .try_recv()
            .expect("a synthesized frame reaches the tab")
        {
            super::TabOut::Control(ControlMessage::AggregateUpdate(update)) => {
                assert_eq!(update.sub_id, "s1", "under the tab's own sub id");
                assert_eq!(
                    update.result_json.as_deref(),
                    Some("7"),
                    "the last synced value, from rest"
                );
                assert_eq!(update.group_key, None, "a scalar answer addresses no group");
                assert!(update.is_full_result, "a bootstrap is a full result");
            }
            _ => panic!("expected a synthesized aggregate frame toward the tab"),
        }
    }

    /// A committed import stays a success when the post-commit replay fails, because the
    /// rows are durable and the outbox driver retries the upload.
    #[wasm_bindgen_test]
    async fn a_committed_import_survives_a_failing_replay() {
        use connetto_client::{ClientConfig, ConnettoConnection, ExportScope, Grant, Replica};
        use connetto_core::test_support::FakeTransport;

        let config = ClientConfig::new("worker").with_login(Some(Grant::new("user:token")));
        let mut source =
            ConnettoConnection::<FakeTransport>::open(&Replica::in_memory(), DDL, &config, None)
                .expect("source opens offline");
        source
            .conn()
            .batch_execute("INSERT INTO drafts VALUES (1, 'restored')")
            .expect("the source writes one row");
        source
            .push()
            .await
            .expect("the write queues while the source is offline");
        let archive = source
            .export_local_data(ExportScope::Everything, crate::workers::BlobSink::new())
            .expect("the source exports")
            .into_blob()
            .expect("the sink closes into one blob");

        let mut target =
            ConnettoConnection::<FakeTransport>::open(&Replica::in_memory(), DDL, &config, None)
                .expect("target opens offline");
        target
            .attach(FakeTransport::accepting_but_failing_bulk())
            .await
            .expect("the target attaches");

        let (outcome, _collisions) = super::import_archive(&mut target, None, archive)
            .await
            .expect("a committed import must survive a failing replay");
        assert!(
            outcome.writes_restored > 0,
            "the restored writes must be reported, got {outcome:?}"
        );
        assert_eq!(
            body(target.conn()).as_deref(),
            Some("restored"),
            "the rows are committed before the replay is attempted"
        );
    }

    /// An import schedules the orphan sweep again, because an import that fails part way
    /// leaves chunks no manifest names.
    #[wasm_bindgen_test]
    async fn an_import_schedules_the_orphan_sweep() {
        use connetto_client::{ClientConfig, ConnettoConnection, ExportScope, Replica};
        use connetto_core::test_support::FakeTransport;
        use tokio::sync::mpsc::unbounded_channel;

        let config = ClientConfig::new("worker");
        let mut source =
            ConnettoConnection::<FakeTransport>::open(&Replica::in_memory(), DDL, &config, None)
                .expect("the source opens offline");
        source
            .conn()
            .batch_execute("INSERT INTO drafts VALUES (1, 'swept')")
            .expect("the source writes one row");
        let archive = source
            .export_local_data(ExportScope::Everything, crate::workers::BlobSink::new())
            .expect("the source exports")
            .into_blob()
            .expect("the sink closes into one blob");

        let worker =
            ConnettoConnection::<FakeTransport>::open(&Replica::in_memory(), DDL, &config, None)
                .expect("the worker opens offline");
        let (notices, _notice_rx) = unbounded_channel();
        let (_events, event_rx) = unbounded_channel();
        let mut runtime = super::HubRuntime {
            worker,
            state: super::HubState::default(),
            notices,
            content: None,
            events: event_rx,
            retry: super::ContentRetry::default(),
            walk: super::WalkState::default(),
        };

        let (reply, answer) = futures_channel::oneshot::channel();
        runtime
            .serve_local(Some(HubEvent::Import(archive, reply)))
            .await
            .expect("the import is served");
        answer
            .await
            .expect("the caller is answered")
            .expect("the import applies");
        assert!(
            runtime.walk.unswept,
            "an import must leave the orphan sweep owed a turn"
        );
    }

    /// The integrity walk checks one outbox file per turn, so the cycle it shares with
    /// tab attachments and upstream frames is never held by a long outbox.
    #[wasm_bindgen_test]
    async fn the_content_integrity_walk_checks_one_file_per_turn() {
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_client::{BrowserStore, ContentArchive};
        use connetto_file_core::FileId;
        use std::collections::VecDeque;
        use tokio::sync::mpsc::unbounded_channel;

        let config = ClientConfig::new("worker");
        let mut worker =
            ConnettoConnection::<FakeTransport>::open(&Replica::in_memory(), DDL, &config, None)
                .expect("the worker opens offline");
        let content = ContentArchive::new(BrowserStore::ephemeral(), [5; 32]);
        content.install(&mut worker).expect("content tables");
        let (notices, _notice_rx) = unbounded_channel();
        let (_events, event_rx) = unbounded_channel();
        let mut runtime = super::HubRuntime {
            worker,
            state: super::HubState::default(),
            notices,
            content: Some(super::HubContent {
                archive: content,
                http: BrowserHttp::new(),
            }),
            events: event_rx,
            retry: super::ContentRetry::default(),
            walk: super::WalkState {
                unverified: VecDeque::from([
                    FileId::from_bytes([7; 32]),
                    FileId::from_bytes([9; 32]),
                ]),
                ..super::WalkState::default()
            },
        };

        assert!(
            runtime.verify_turn().await.expect("the turn serves"),
            "the hub keeps running"
        );
        assert_eq!(
            runtime.walk.unverified.len(),
            1,
            "one turn checks exactly one file, leaving the cycle free for everything else"
        );
        assert!(
            runtime.verify_turn().await.expect("the turn serves"),
            "the hub keeps running"
        );
        assert!(
            runtime.walk.unverified.is_empty(),
            "and the walk finishes file by file"
        );
    }

    /// A hub request answers the refusals with their details, and a hub retry clears the
    /// mark and wakes the outbox driver.
    #[wasm_bindgen_test]
    async fn a_hub_request_answers_refusals_and_a_hub_retry_clears_the_mark() {
        use super::{ContentRetry, HubEvent, HubRuntime, HubState, WalkState};
        use connetto_client::{ClientConfig, ConnettoConnection, Replica};
        use connetto_core::test_support::FakeTransport;
        use connetto_file_client::{BrowserStore, ContentArchive};
        use connetto_file_core::FileId;
        use tokio::sync::mpsc::unbounded_channel;

        let config = ClientConfig::new("worker");
        let mut worker =
            ConnettoConnection::<FakeTransport>::open(&Replica::in_memory(), DDL, &config, None)
                .expect("the worker opens offline");
        let content = ContentArchive::new(BrowserStore::ephemeral(), [5; 32]);
        content.install(&mut worker).expect("content tables");

        // Insert a refused outbox entry via raw SQL; connetto-file-client's db
        // module is private from here.
        let file_id = FileId::from_bytes([0xAA; 32]);
        let mut hex_id = String::with_capacity(64);
        for b in file_id.as_bytes() {
            use core::fmt::Write;
            write!(hex_id, "{b:02X}").expect("writing to a String cannot fail");
        }
        worker
            .conn()
            .batch_execute(&format!(
                "INSERT INTO _connetto_content_outbox (file_id, refused) \
                 VALUES (X'{hex_id}', 'over the ceiling')"
            ))
            .expect("insert refused entry");

        let (notices, _notice_rx) = unbounded_channel();
        let (_events, event_rx) = unbounded_channel();
        let mut runtime = HubRuntime {
            worker,
            state: HubState::default(),
            notices,
            content: Some(HubContent {
                archive: content,
                http: BrowserHttp::new(),
            }),
            events: event_rx,
            retry: ContentRetry::default(),
            walk: WalkState::default(),
        };

        // Serve a RefusedContent request and verify the reply lists the refused entry.
        let (reply, answer) = futures_channel::oneshot::channel();
        runtime
            .serve_local(Some(HubEvent::RefusedContent(reply)))
            .await
            .expect("the request is served");
        let refusals = answer
            .await
            .expect("the caller is answered")
            .expect("the read succeeds");
        assert_eq!(refusals.len(), 1, "one refused entry must appear");
        assert_eq!(refusals[0].0, file_id, "the refused entry names the file");
        assert!(
            !refusals[0].1.is_empty(),
            "the refused entry carries a non-empty detail"
        );

        // Serve a RetryRefused request and verify the mark is cleared and the walk wakes.
        let (retry_reply, retry_answer) = futures_channel::oneshot::channel();
        runtime
            .serve_local(Some(HubEvent::RetryRefused(file_id, retry_reply)))
            .await
            .expect("the retry request is served");
        retry_answer
            .await
            .expect("the caller is answered")
            .expect("the clear succeeds");
        assert!(
            runtime.walk.outbox_wake,
            "clearing a refusal must schedule the outbox driver"
        );

        // A second RefusedContent request must find an empty list.
        let (reply2, answer2) = futures_channel::oneshot::channel();
        runtime
            .serve_local(Some(HubEvent::RefusedContent(reply2)))
            .await
            .expect("the second request is served");
        let after = answer2
            .await
            .expect("the caller is answered")
            .expect("the read succeeds");
        assert!(
            after.is_empty(),
            "no refused entries must remain after the mark is cleared"
        );
    }

    /// Both new requests are served while the connection is idle and interrupt an attach,
    /// asserted through the recovery predicates.
    #[wasm_bindgen_test]
    fn both_refusal_requests_are_served_during_recovery_and_interrupt_an_attach() {
        use connetto_core::messages::{ControlMessage, Ping};
        use connetto_core::traits::IncomingFrame;
        use connetto_file_core::FileId;

        let mut deferred = std::collections::VecDeque::new();
        let (reply_a, _) = futures_channel::oneshot::channel();
        let (reply_b, _) = futures_channel::oneshot::channel();

        assert!(
            matches!(
                schedule_recovery_event(
                    &mut deferred,
                    HubEvent::RefusedContent(reply_a),
                    recovery_serves_idle,
                ),
                Some(HubEvent::RefusedContent(_))
            ),
            "RefusedContent must be served while the connection is idle"
        );
        assert!(
            matches!(
                schedule_recovery_event(
                    &mut deferred,
                    HubEvent::RetryRefused(FileId::from_bytes([1; 32]), reply_b),
                    recovery_serves_idle,
                ),
                Some(HubEvent::RetryRefused(_, _))
            ),
            "RetryRefused must be served while the connection is idle"
        );

        // A held request is queued first, because a served one leaves the queue empty and
        // the order rule only bites behind something already waiting.
        let mut deferred = std::collections::VecDeque::new();
        assert!(
            schedule_recovery_event(
                &mut deferred,
                HubEvent::Frame(
                    1,
                    IncomingFrame::Control(ControlMessage::Ping(Ping { nonce: 1 }))
                ),
                recovery_interrupts_attach,
            )
            .is_none(),
            "a frame waits for the upstream"
        );
        let (reply_c, _) = futures_channel::oneshot::channel();
        let (reply_d, _) = futures_channel::oneshot::channel();
        assert!(
            schedule_recovery_event(
                &mut deferred,
                HubEvent::RefusedContent(reply_c),
                recovery_interrupts_attach,
            )
            .is_none(),
            "RefusedContent behind a queued event must not overtake it"
        );
        assert!(
            schedule_recovery_event(
                &mut deferred,
                HubEvent::RetryRefused(FileId::from_bytes([2; 32]), reply_d),
                recovery_interrupts_attach,
            )
            .is_none(),
            "RetryRefused behind a queued event must not overtake it"
        );

        let (reply_e, _) = futures_channel::oneshot::channel();
        let (reply_f, _) = futures_channel::oneshot::channel();
        let mut empty = std::collections::VecDeque::new();
        assert!(
            matches!(
                schedule_recovery_event(
                    &mut empty,
                    HubEvent::RefusedContent(reply_e),
                    recovery_interrupts_attach,
                ),
                Some(HubEvent::RefusedContent(_))
            ),
            "RefusedContent at the queue head must interrupt an attach"
        );
        assert!(
            matches!(
                schedule_recovery_event(
                    &mut empty,
                    HubEvent::RetryRefused(FileId::from_bytes([3; 32]), reply_f),
                    recovery_interrupts_attach,
                ),
                Some(HubEvent::RetryRefused(_, _))
            ),
            "RetryRefused at the queue head must interrupt an attach"
        );
    }

    /// A queued event is served before a transfer that is also ready, so an import waiting
    /// in the channel is applied before an upload's loss is finalized.
    #[wasm_bindgen_test]
    async fn transfer_step_serves_a_queued_event_before_a_ready_transfer() {
        use super::{TransferStep, transfer_step};
        use connetto_file_client::ContentError;
        use tokio::sync::mpsc::unbounded_channel;

        let (tx, mut rx) = unbounded_channel();
        tx.send(HubEvent::Kill(9)).expect("queue an event");
        let transfer =
            async { Err::<(), ContentError>(ContentError::Transport("done".to_owned())) };
        tokio::pin!(transfer);
        let step = transfer_step(&mut transfer, &mut rx, true).await;
        assert!(
            matches!(step, TransferStep::Event(Some(HubEvent::Kill(9)))),
            "a queued event must be served before a transfer that is also ready"
        );
    }
}
