//! Multi-tab relay hub, increment 3 of the browser relay topology.
//!
//! One worker-held [`ConnettoConnection`] owns the durable replica and the
//! server session, and any number of tabs speak the ordinary connetto wire
//! protocol to it over their own [`Transport`]s (an in-memory loopback, or a
//! [`PortTransport`](crate::PortTransport) over a `MessageChannel` or
//! `SharedWorker` port). The hub is a single-task core fed by channels: each
//! attached tab gets a shovel task that owns its transport and exchanges
//! frames with the core, so the core never selects over a dynamic set of
//! transports and sends toward tabs never block it.
//!
//! Snapshots are generic: a throwaway capture session diffs each subscribed
//! table against an empty twin in an attached blank database, so values of
//! every storage class survive verbatim with no per-schema code. Live
//! patches are routed by table and forwarded at most once per tab. Tab
//! writes are applied to the worker replica with capture active, re-uploaded
//! by the worker connection, and an upstream rejection maps back to the
//! owning tab's own sequence number. A tab-level protocol violation closes
//! that tab alone, the hub and its other tabs keep running.
//!
//! Remaining limits, lifted by later increments: aggregate subscriptions are
//! not served, flow control credits are ignored, and an upstream conflict
//! reaches the tab as a plain rejection, because the worker client surfaces
//! only the sequence number of a conflicted mutation.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use connetto_client::reconnect::{ReconnectPolicy, Sleeper, TransportFactory};
use connetto_client::{ClientError, ClientEvent, ConnettoConnection, subscription_tables};
use connetto_core::messages::{
    BulkMessage, ControlMessage, HandshakeAck, LivePatch, MutationApplied, MutationReject,
    MutationRejectReason, Pong, SnapshotBegin, SnapshotEnd, SnapshotPatch, Subscribe,
    SubscriptionSpec,
};
use connetto_core::traits::MaybeSend;
use connetto_core::{Cursor, IncomingFrame, SchemaVersion, Transport};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::sql_query;
use diesel_sqlite_session::{ConflictAction, SqliteSessionExt};
use sqlite_diff_rs::ParsedDiffSet;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// Zstd level for relayed snapshot payloads, matching the client library default.
const ZSTD_LEVEL: i32 = 3;

/// Upstream sequence numbers retained for mapping rejections back to a tab.
/// A rejection arrives well within this window, mirroring the client's own
/// pending cap.
const SEQ_MAP_CAP: usize = 256;

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
}

/// One outbound frame toward a tab. Dropping a tab's sender closes it: the
/// shovel answers the closed channel by closing the transport.
enum TabOut {
    Control(ControlMessage),
    Bulk(BulkMessage),
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
    /// The client id from the tab's handshake, keying its durable mutation
    /// watermark in the hub meta schema.
    client_id: String,
    /// Highest tab sequence applied to the worker replica for this client
    /// id, from the hub meta schema at handshake and advanced per apply. A
    /// replayed sequence at or below it is re-acknowledged, never
    /// re-applied.
    applied_watermark: Option<u64>,
}

/// A failure inside the tab-mutation apply transaction.
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
    (client_id TEXT NOT NULL PRIMARY KEY, last_seq BIGINT NOT NULL)";

/// One registered tab subscription and the tables its query reads.
struct TabSub {
    sub_id: String,
    tables: HashSet<String>,
}

/// The blank twin database used for generic snapshots.
#[derive(Default)]
struct BlankState {
    /// Whether the blank database is attached to the worker connection yet.
    attached: bool,
    /// Tables whose empty twin already exists in the blank schema.
    tables: HashSet<String>,
}

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
    /// DB worker, `:memory:` in tests. Returns the handle, the pump future
    /// to spawn (it runs until the upstream session closes, the upstream
    /// fails, or every handle and shovel is gone), and the notice stream.
    /// Dropping the notice receiver is fine when the owner has no platform
    /// glue to run.
    ///
    /// # Errors
    ///
    /// [`RelayError::Replica`] when attaching the hub meta database fails.
    #[allow(
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
    #[allow(
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
        Self::build(worker, hub_meta, Some(reconnect))
    }

    /// Shared constructor body behind the two hub flavors: attach the hub
    /// meta database and ensure its schema, then assemble the channels.
    #[allow(
        clippy::type_complexity,
        reason = "the tuple is the constructor contract"
    )]
    fn build<U, F, S>(
        mut worker: ConnettoConnection<U>,
        hub_meta: &str,
        reconnect: Option<HubReconnect<F, S>>,
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
        worker
            .conn()
            .batch_execute(&format!("ATTACH DATABASE '{hub_meta}' AS connetto_hub"))?;
        worker.conn().batch_execute(HUB_META_DDL)?;
        let (events_tx, events_rx) = unbounded_channel();
        let (notices_tx, notices_rx) = unbounded_channel();
        let hub = Self {
            events: events_tx,
            next_tab: Arc::new(AtomicU64::new(0)),
        };
        Ok((
            hub,
            run_hub(worker, events_rx, notices_tx, reconnect),
            notices_rx,
        ))
    }

    /// Attach one tab transport and spawn its shovel task.
    pub fn attach<D>(&self, tab: D) -> TabId
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
        wasm_bindgen_futures::spawn_local(shovel(id, tab, out_rx, self.events.clone()));
        id
    }

    /// Disconnect one tab, as when its liveness lock reports it dead. The
    /// core drops the tab's state, which closes its transport politely.
    pub fn kill(&self, tab: TabId) {
        let _ = self.events.send(HubEvent::Kill(tab));
    }
}

/// The per-tab I/O task: owns the transport, feeds inbound frames to the
/// core, writes outbound frames, and closes the transport when the core
/// drops the tab.
async fn shovel<D>(
    id: TabId,
    mut tab: D,
    mut out_rx: UnboundedReceiver<TabOut>,
    events: UnboundedSender<HubEvent>,
) where
    D: Transport,
    D::Error: core::fmt::Display,
{
    loop {
        // Cancel safety: both legs park on an mpsc backed receive, which
        // loses nothing when dropped, and sends on the transports this hub
        // runs over (loopback and message ports) complete in one poll, so a
        // losing branch is only ever dropped while parked.
        tokio::select! {
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
                None => {
                    let _ = tab.close().await;
                    break;
                }
            },
        }
    }
    let _ = events.send(HubEvent::Gone(id));
}

/// The hub core: one task owning the worker connection and every tab's
/// state, fed exclusively by channels. With reconnect wiring, an upstream
/// transport drop is recovered in place: tabs stay attached and their
/// queued frames are served after the resume.
async fn run_hub<U, F, S>(
    mut worker: ConnettoConnection<U>,
    mut events: UnboundedReceiver<HubEvent>,
    notices: UnboundedSender<HubNotice>,
    mut reconnect: Option<HubReconnect<F, S>>,
) -> Result<(), RelayError>
where
    U: Transport + MaybeSend + 'static,
    U::Error: core::fmt::Display,
    F: TransportFactory<Transport = U>,
    S: Sleeper,
{
    let mut state = HubState::default();
    loop {
        // Cancel safety: the events leg is an mpsc receive, and the worker
        // leg completes in one poll once its frame lands (browser socket
        // sends resolve immediately), so a losing branch is only ever
        // dropped while parked.
        tokio::select! {
            event = events.recv() => match event {
                // Every handle and every shovel is gone.
                None => break,
                Some(HubEvent::Attached(id, out)) => {
                    state.tabs.insert(id, TabState {
                        out,
                        handshaken: false,
                        subs: Vec::new(),
                        pending_write: None,
                        client_id: String::new(),
                        applied_watermark: None,
                    });
                }
                Some(HubEvent::Frame(id, frame)) => {
                    handle_tab_frame(&mut worker, &mut state, &notices, id, frame).await?;
                }
                // Removing the state drops the tab's sender, and the shovel
                // answers the closed channel by closing the transport.
                Some(HubEvent::Gone(id) | HubEvent::Kill(id)) => {
                    state.tabs.remove(&id);
                }
            },
            event = worker.pump_one() => match event {
                Ok(ClientEvent::Closed) | Err(ClientError::Transport(_)) => {
                    let Some(driver) = reconnect.as_mut() else {
                        break;
                    };
                    if !hub_recover(&mut worker, driver).await {
                        break;
                    }
                }
                Ok(event) => handle_worker_event(&mut state, event)?,
                Err(err) => return Err(err.into()),
            },
        }
    }
    Ok(())
}

/// Recover the hub's upstream: backoff, fresh transport, session resume,
/// re-declared upstream subscriptions. Returns whether the upstream is live
/// again, `false` meaning the policy is exhausted.
async fn hub_recover<U, F, S>(
    worker: &mut ConnettoConnection<U>,
    driver: &mut HubReconnect<F, S>,
) -> bool
where
    U: Transport + MaybeSend + 'static,
    U::Error: core::fmt::Display,
    F: TransportFactory<Transport = U>,
    S: Sleeper,
{
    let mut backoff = driver.policy.initial_backoff;
    let mut attempt: u32 = 0;
    loop {
        attempt = attempt.saturating_add(1);
        if driver.policy.max_attempts.is_some_and(|max| attempt > max) {
            return false;
        }
        web_sys::console::warn_1(&format!("relay hub upstream reconnect attempt {attempt}").into());
        driver.sleeper.sleep(backoff).await;
        backoff = backoff.saturating_mul(2).min(driver.policy.max_backoff);

        let Ok(transport) = driver.factory.connect().await else {
            continue;
        };
        if worker.resume(transport).await.is_err() {
            continue;
        }
        let mut redeclared = true;
        for (sub_id, spec) in &driver.upstream {
            if worker.subscribe_spec(sub_id, spec.clone()).await.is_err() {
                redeclared = false;
                break;
            }
        }
        if redeclared {
            return true;
        }
    }
}

/// Handle one frame from a tab, downgrading tab-level faults to closing
/// that tab so one misbehaving client never poisons its siblings.
async fn handle_tab_frame<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
    notices: &UnboundedSender<HubNotice>,
    id: TabId,
    frame: IncomingFrame,
) -> Result<(), RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let outcome = match frame {
        IncomingFrame::Control(message) => handle_tab_control(worker, state, notices, id, message),
        IncomingFrame::Bulk(bulk) => handle_tab_bulk(worker, state, id, bulk).await,
    };
    match outcome {
        Ok(()) => Ok(()),
        Err(TabFault::Close(reason)) => {
            web_sys::console::warn_1(&format!("relay hub closed tab {id}: {reason}").into());
            state.tabs.remove(&id);
            Ok(())
        }
        Err(TabFault::Hub(err)) => Err(err),
    }
}

/// Handle one control frame from a tab.
fn handle_tab_control<U>(
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
            tab.handshaken = true;
            tab.client_id = handshake.client_id.clone();
            tab.applied_watermark = tab_watermark(worker, &handshake.client_id)?;
            // The session naming is a placeholder the client does not act
            // on today. The watermark is load-bearing: the tab retires
            // pending mutations at or below it and replays the rest.
            let _ = tab.out.send(TabOut::Control(ControlMessage::HandshakeAck(
                HandshakeAck {
                    session_id: format!("relay-{}", handshake.client_id),
                    session_token: "relay".to_owned(),
                    current_cursor: relay_cursor(worker),
                    schema_version: SchemaVersion::new("relay", Vec::new()),
                    initial_credits: 64,
                    last_applied_seq: tab.applied_watermark,
                },
            )));
            let _ = notices.send(HubNotice::Handshake {
                tab: id,
                client_id: handshake.client_id,
            });
            Ok(())
        }
        ControlMessage::Subscribe(subscribe) if tab.handshaken => {
            let tables = subscription_tables(&subscribe.spec.query)
                .map_err(|err| TabFault::Close(format!("unparsable subscription query: {err}")))?;
            serve_snapshot(worker, &mut state.blank, tab, &subscribe, &tables)?;
            tab.subs.retain(|sub| sub.sub_id != subscribe.sub_id);
            tab.subs.push(TabSub {
                sub_id: subscribe.sub_id,
                tables,
            });
            Ok(())
        }
        ControlMessage::Unsubscribe(unsubscribe) if tab.handshaken => {
            tab.subs.retain(|sub| sub.sub_id != unsubscribe.sub_id);
            Ok(())
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
        // Flow control is not enforced here: patches are pushed as they
        // arrive and the credit window is ignored.
        ControlMessage::AckCredits(_) if tab.handshaken => Ok(()),
        other => Err(TabFault::Close(format!(
            "unsupported tab frame in this increment: {other:?}"
        ))),
    }
}

/// Handle one bulk frame from a tab: the patchset of an announced mutation.
///
/// The changeset is applied to the worker replica with capture ACTIVE (so
/// the worker's own session records it and the following push re-uploads
/// it), and the tab's durable watermark advances in the same transaction. A
/// replayed sequence at or below the watermark is re-acknowledged, never
/// re-applied. The end-to-end acknowledgement the tab retires its pending
/// record on arrives separately, when the SERVER confirms the forwarded
/// mutation. An apply failure rejects the mutation back to the tab and
/// leaves the replica untouched, since the abort policy rolls the whole
/// apply back.
async fn handle_tab_bulk<U>(
    worker: &mut ConnettoConnection<U>,
    state: &mut HubState,
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
    let (tab_seq, client_id, out, watermark) = {
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
        (
            tab_seq,
            tab.client_id.clone(),
            tab.out.clone(),
            tab.applied_watermark,
        )
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
    let Ok(changeset) = zstd::decode_all(patch.patchset_zstd.as_slice()) else {
        return Err(TabFault::Close("undecodable mutation patchset".to_owned()));
    };
    let Ok(seq) = i64::try_from(tab_seq) else {
        return Err(TabFault::Close("sequence overflows storage".to_owned()));
    };
    let applied = worker.conn().transaction::<_, TabApplyError, _>(|conn| {
        conn.apply_changeset(&changeset, |_conflict| ConflictAction::Abort)
            .map_err(|err| TabApplyError::Apply(err.to_string()))?;
        diesel::sql_query(
            "INSERT INTO connetto_hub._tab_mutations (client_id, last_seq) VALUES (?, ?) \
             ON CONFLICT (client_id) DO UPDATE SET \
             last_seq = MAX(last_seq, excluded.last_seq)",
        )
        .bind::<diesel::sql_types::Text, _>(&client_id)
        .bind::<diesel::sql_types::BigInt, _>(seq)
        .execute(conn)?;
        Ok(())
    });
    match applied {
        Ok(()) => {}
        Err(TabApplyError::Apply(detail)) => {
            let _ = out.send(TabOut::Control(ControlMessage::MutationReject(
                MutationReject {
                    client_seq: tab_seq,
                    reason: MutationRejectReason::Other {
                        detail: format!("worker replica apply failed: {detail}"),
                    },
                },
            )));
            return Ok(());
        }
        Err(TabApplyError::Db(err)) => return Err(RelayError::from(err).into()),
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

/// Handle one upstream event from the worker connection.
fn handle_worker_event(state: &mut HubState, event: ClientEvent) -> Result<(), RelayError> {
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
            for tab in state.tabs.values() {
                let Some(sub) = tab.subs.iter().find(|sub| !sub.tables.is_disjoint(&tables)) else {
                    continue;
                };
                let _ = tab
                    .out
                    .send(TabOut::Bulk(BulkMessage::LivePatch(LivePatch::new(
                        sub.sub_id.clone(),
                        cursor.clone(),
                        patchset_zstd.to_vec(),
                    ))));
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
        ClientEvent::MutationConflict { client_seq, .. } => reject_tab_mutation(
            state,
            client_seq,
            "the upstream server conflicted the forwarded mutation",
        ),
        _ => Ok(()),
    }
}

/// Map an upstream rejection back to the owning tab's sequence number.
///
/// The worker client already rolled the change back out of its replica. The
/// reject tells the tab to do the same to its mirror, so both converge.
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

/// Answer one tab subscription from the worker replica.
fn serve_snapshot<U>(
    worker: &mut ConnettoConnection<U>,
    blank: &mut BlankState,
    tab: &TabState,
    subscribe: &Subscribe,
    tables: &HashSet<String>,
) -> Result<(), RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    let _ = tab.out.send(TabOut::Control(ControlMessage::SnapshotBegin(
        SnapshotBegin {
            sub_id: subscribe.sub_id.clone(),
            priority: subscribe.spec.priority,
        },
    )));
    let patchset = snapshot_patchset(worker, tables, blank)?;
    if !patchset.is_empty() {
        let payload = zstd::encode_all(patchset.as_slice(), ZSTD_LEVEL)?;
        let _ = tab.out.send(TabOut::Bulk(BulkMessage::SnapshotPatch(
            SnapshotPatch::new(subscribe.sub_id.clone(), payload),
        )));
    }
    let _ = tab
        .out
        .send(TabOut::Control(ControlMessage::SnapshotEnd(SnapshotEnd {
            sub_id: subscribe.sub_id.clone(),
            cursor: relay_cursor(worker),
        })));
    Ok(())
}

/// Build one insert patchset holding every current row of the subscribed
/// tables, by diffing the worker replica against empty twins in an attached
/// blank database.
///
/// `sqlite3session_diff` requires the twin to live on the same connection
/// under the same table name and schema, so the blank database is attached
/// once and each subscribed table's stored DDL is replayed into it with a
/// schema qualifier spliced in. The throwaway session never sees a write, it
/// only loads the diff, so the worker's own capture session is unaffected.
fn snapshot_patchset<U>(
    worker: &mut ConnettoConnection<U>,
    tables: &HashSet<String>,
    blank: &mut BlankState,
) -> Result<Vec<u8>, RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    #[derive(QueryableByName)]
    struct SchemaRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        sql: Option<String>,
    }
    let rows: Vec<SchemaRow> = sql_query(
        "SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .load(worker.conn())?;
    let matching: Vec<SchemaRow> = rows
        .into_iter()
        .filter(|row| tables.contains(&row.name.to_lowercase()))
        .collect();
    if matching.is_empty() {
        return Ok(Vec::new());
    }
    if !blank.attached {
        worker
            .conn()
            .batch_execute("ATTACH DATABASE ':memory:' AS blank")?;
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
        worker.conn().batch_execute(&twin)?;
        blank.tables.insert(row.name.clone());
    }
    let mut session = worker.conn().create_session().map_err(session_err)?;
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
    let parsed =
        ParsedDiffSet::parse(&bytes).map_err(|err| RelayError::Patch(format!("{err:?}")))?;
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
    client_id: &str,
) -> Result<Option<u64>, RelayError>
where
    U: Transport,
    U::Error: core::fmt::Display,
{
    #[derive(diesel::QueryableByName)]
    struct WatermarkRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        last_seq: i64,
    }
    let rows: Vec<WatermarkRow> =
        diesel::sql_query("SELECT last_seq FROM connetto_hub._tab_mutations WHERE client_id = ?")
            .bind::<diesel::sql_types::Text, _>(client_id)
            .load(worker.conn())?;
    Ok(rows
        .into_iter()
        .next()
        .and_then(|row| u64::try_from(row.last_seq).ok()))
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
