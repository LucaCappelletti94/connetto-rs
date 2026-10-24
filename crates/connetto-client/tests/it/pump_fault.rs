//! A pump that stops on a fault it cannot recover from says why and releases
//! everything waiting on it.

use connetto_client::{
    ClientBuilder, ClientError, ClientEvent, ConnettoClient, DataDir, MemoryRefreshStore,
};
use connetto_core::messages::{
    BulkMessage, ControlMessage, FatalError, FatalErrorReason, LivePatch,
};
use connetto_core::traits::{IncomingFrame, Transport};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::future::ready;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tempfile::tempdir;

use super::support::handshake_ack as ack;

const DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const BOUND: Duration = Duration::from_secs(5);

diesel::table! {
    /// Synced test table.
    items (id) {
        /// Item identifier, the primary key
        id -> Integer,
        /// Optional item label
        label -> Nullable<Text>,
    }
}

#[derive(Debug, Clone, PartialEq, Queryable)]
struct Item {
    id: i32,
    label: Option<String>,
}

/// A transport handing out queued frames, idling when none are queued, and
/// recording the subscriptions it was sent and whether it was closed. Once
/// told to drop, every send fails the way a dead socket does.
#[derive(Clone, Default)]
struct Script {
    frames: Arc<Mutex<VecDeque<IncomingFrame>>>,
    subscribed: Arc<Mutex<Vec<String>>>,
    closed: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

/// The failure a send reports once the socket is gone.
#[derive(Debug, thiserror::Error)]
#[error("the socket is gone")]
struct Gone;

impl Script {
    fn say(&self, frame: IncomingFrame) {
        self.frames.lock().push_back(frame);
    }

    fn last_subscribed(&self) -> String {
        self.subscribed
            .lock()
            .last()
            .cloned()
            .expect("the client subscribed")
    }

    /// A send fails once the socket is dropped or closed, as a real one does.
    fn sent(&self) -> Result<(), Gone> {
        if self.dropped.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            Err(Gone)
        } else {
            Ok(())
        }
    }
}

impl Transport for Script {
    type Error = Gone;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        if let ControlMessage::Subscribe(subscribe) = message {
            self.subscribed.lock().push(subscribe.sub_id);
        }
        ready(self.sent())
    }

    fn send_bulk(
        &mut self,
        _message: BulkMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        ready(self.sent())
    }

    fn recv(&mut self) -> impl Future<Output = Result<Option<IncomingFrame>, Self::Error>> {
        let frames = Arc::clone(&self.frames);
        async move {
            loop {
                if let Some(frame) = frames.lock().pop_front() {
                    return Ok(Some(frame));
                }
                tokio::task::yield_now().await;
            }
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        self.closed.store(true, Ordering::Release);
        ready(Ok(()))
    }
}

async fn client() -> (
    ConnettoClient<Script>,
    Script,
    tempfile::TempDir,
    tokio::task::JoinHandle<()>,
) {
    let dir = tempdir().expect("temp dir");
    let script = Script::default();
    script.say(ack());
    let credential = super::support::held("tester");
    let key_store = super::support::key_store(&credential).await;
    let (running, pump) = ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::Once::new(script.clone()),
    )
    .signed_in(credential)
    .durable(
        DataDir::new(dir.path().to_path_buf()),
        key_store,
        MemoryRefreshStore::default(),
    )
    .connect_with_pump()
    .await
    .expect("the builder connects");
    let pump = tokio::spawn(pump);
    (running.client().clone(), script, dir, pump)
}

/// A client built with no reconnect driver, so its pump ends at once when
/// the server closes the session.
async fn client_no_driver() -> (
    ConnettoClient<Script>,
    Script,
    tempfile::TempDir,
    tokio::task::JoinHandle<()>,
) {
    let dir = tempdir().expect("temp dir");
    let script = Script::default();
    script.say(ack());
    let credential = super::support::held("tester");
    let key_store = super::support::key_store(&credential).await;
    let probe = script.clone();
    let mut conn = ClientBuilder::new(
        super::support::bundle(DDL),
        super::support::Once::new(script.clone()),
    )
    .signed_in(credential)
    .durable(
        DataDir::new(dir.path().to_path_buf()),
        key_store,
        MemoryRefreshStore::default(),
    )
    .open_driven()
    .await
    .expect("the builder opens the replica");
    conn.attach(script).await.expect("the handshake completes");
    let (running, pump) = ConnettoClient::with_pump(conn);
    let pump = tokio::spawn(pump);
    (running, probe, dir, pump)
}

/// Every event up to and including `Closed`.
async fn until_closed(
    events: &mut tokio::sync::broadcast::Receiver<ClientEvent>,
) -> Vec<ClientEvent> {
    let mut seen = Vec::new();
    loop {
        let event = tokio::time::timeout(BOUND, events.recv())
            .await
            .expect("the pump announces its end in time")
            .expect("the event stream stays open");
        let closed = event == ClientEvent::Closed;
        seen.push(event);
        if closed {
            return seen;
        }
    }
}

/// A live patch whose bytes are not zstd fails to apply, a local fault no
/// reconnect can cure, so the pump ends. It announces why before `Closed`,
/// closes the transport, and a handle waiting for its next change is told,
/// as is one opened after the stop.
#[tokio::test]
async fn a_fault_that_stops_the_pump_is_announced_and_releases_waiting_handles() {
    let (client, script, _dir, _pump) = client().await;
    let mut events = client.events();
    let mut query = client
        .watch::<_, Item>(items::table.order(items::id))
        .await
        .expect("watch the synced table");
    let waiting = tokio::spawn(async move { query.changed().await });
    tokio::task::yield_now().await;
    assert!(
        !waiting.is_finished(),
        "the handle is waiting before the fault"
    );

    script.say(IncomingFrame::Bulk(BulkMessage::LivePatch(LivePatch::new(
        script.last_subscribed(),
        connetto_core::Cursor::from(vec![0, 0, 0, 0, 0, 0, 1, 0]),
        b"not a zstd frame".to_vec(),
    ))));

    let seen = until_closed(&mut events).await;
    let stopped = seen
        .iter()
        .position(|event| matches!(event, ClientEvent::Stopped { .. }));
    assert_eq!(
        stopped,
        Some(seen.len() - 2),
        "the cause is announced right before Closed, saw {seen:?}"
    );

    let outcome = tokio::time::timeout(BOUND, waiting)
        .await
        .expect("the waiting handle is released in time")
        .expect("the waiting task completes");
    assert!(
        matches!(outcome, Err(ClientError::Stopped(_))),
        "the waiter learns the pump stopped, got {outcome:?}"
    );
    assert!(
        script.closed.load(Ordering::Acquire),
        "the transport is closed"
    );

    // A query the server never saw, so nothing already on the wire serves it.
    let mut late = client
        .watch::<_, Item>(items::table.filter(items::id.gt(0)).order(items::id))
        .await
        .expect("a watch after the stop still answers locally");
    let late_outcome = tokio::time::timeout(BOUND, late.changed())
        .await
        .expect("a handle opened after the stop is told at once");
    assert!(
        matches!(late_outcome, Err(ClientError::Stopped(_))),
        "got {late_outcome:?}"
    );
    tokio::time::timeout(BOUND, client.close())
        .await
        .expect("close returns at once after the stop");
}

/// A table without a primary key is created mid-run, so the next auto-submit
/// refuses to upload anything. The fault is caught on the drain side, before
/// the pump step, and still announces the stop, closes the transport, and
/// releases the live handle.
#[tokio::test]
async fn a_local_fault_on_the_drain_side_stops_the_pump_the_same_way() {
    let (client, script, _dir, _pump) = client().await;
    let mut events = client.events();
    let mut query = client
        .watch::<_, Item>(items::table.order(items::id))
        .await
        .expect("watch the synced table");

    client
        .with_conn(|conn| {
            diesel::insert_into(items::table)
                .values((items::id.eq(1), items::label.eq("seeded")))
                .execute(conn.conn())
                .expect("write the row")
        })
        .await
        .expect("the write lands locally");
    client
        .with_conn(|conn| {
            SimpleConnection::batch_execute(conn.conn(), "CREATE TABLE loose (label TEXT)")
                .expect("the application creates its own table");
        })
        .await
        .expect("the table lands locally");

    let seen = until_closed(&mut events).await;
    let stopped = seen
        .iter()
        .position(|event| matches!(event, ClientEvent::Stopped { .. }))
        .unwrap_or_else(|| panic!("the fault is announced, saw {seen:?}"));
    assert_eq!(
        stopped,
        seen.len() - 2,
        "the cause is announced right before Closed, saw {seen:?}"
    );
    let detail = match &seen[stopped] {
        ClientEvent::Stopped { detail } => detail.clone(),
        _ => unreachable!("the position was matched above"),
    };
    assert!(
        detail.contains("loose"),
        "the refusal names the table, got {detail}"
    );

    let outcome = tokio::time::timeout(BOUND, query.changed())
        .await
        .expect("the handle is released in time")
        .expect_err("the handle learns the pump stopped");
    assert!(
        matches!(outcome, ClientError::Stopped(_)),
        "got {outcome:?}"
    );
    assert!(
        script.closed.load(Ordering::Acquire),
        "the transport is closed"
    );
    let rows: Vec<Item> = client
        .with_conn(|conn| {
            items::table
                .order(items::id)
                .load(conn.conn())
                .expect("the replica answers")
        })
        .await
        .expect("the replica keeps serving the offline half");
    assert_eq!(rows.len(), 1, "the last rows stay readable");
    tokio::time::timeout(BOUND, client.close())
        .await
        .expect("close returns at once after the stop");
}

/// Every event up to the driver's first redial, refusing a stop on the way.
async fn until_reconnecting(events: &mut tokio::sync::broadcast::Receiver<ClientEvent>) {
    let mut seen = Vec::new();
    loop {
        let event = tokio::time::timeout(BOUND, events.recv())
            .await
            .unwrap_or_else(|_| panic!("the driver redials in time, saw {seen:?}"))
            .expect("the event stream stays open");
        assert!(
            !matches!(event, ClientEvent::Stopped { .. } | ClientEvent::Closed),
            "a lost socket is recovered, never a stop, saw {seen:?} then {event:?}"
        );
        if matches!(event, ClientEvent::Reconnecting { .. }) {
            return;
        }
        seen.push(event);
    }
}

/// The socket dies as a local write is uploaded. That is a transport to go
/// and find, so the driver redials and the pump never announces a stop.
#[tokio::test]
async fn a_socket_lost_while_uploading_a_write_is_recovered() {
    let (client, script, _dir, _pump) = client().await;
    let mut events = client.events();
    script.dropped.store(true, Ordering::Release);
    client
        .with_conn(|conn| {
            diesel::insert_into(items::table)
                .values((items::id.eq(1), items::label.eq("offline")))
                .execute(conn.conn())
                .expect("write the row")
        })
        .await
        .expect("the write lands locally");
    until_reconnecting(&mut events).await;
}

/// The server ends the session with no reconnect driver to resume it, so the
/// pump queues the last writes and ends without announcing a fault. The
/// replica stays readable, and the end is signalled to `close`.
#[tokio::test]
async fn a_server_close_with_no_driver_ends_the_pump_and_keeps_the_replica_readable() {
    let (client, script, _dir, _pump) = client_no_driver().await;
    let mut events = client.events();
    client
        .with_conn(|conn| {
            diesel::insert_into(items::table)
                .values((items::id.eq(1), items::label.eq("kept")))
                .execute(conn.conn())
                .expect("write the row")
        })
        .await
        .expect("the write lands locally");

    script.say(IncomingFrame::Control(ControlMessage::FatalError(
        FatalError::new(FatalErrorReason::ServerShuttingDown),
    )));

    let seen = until_closed(&mut events).await;
    assert!(
        seen.iter()
            .all(|event| !matches!(event, ClientEvent::Stopped { .. })),
        "a server close is not a fault, saw {seen:?}"
    );
    assert!(
        matches!(
            seen[seen.len() - 2],
            ClientEvent::ServerClosed {
                reason: FatalErrorReason::ServerShuttingDown
            }
        ),
        "the reason comes right before Closed, saw {seen:?}"
    );
    tokio::time::timeout(BOUND, client.close())
        .await
        .expect("the pump's end is signalled to close");
    let rows: Vec<Item> = client
        .with_conn(|conn| {
            items::table
                .order(items::id)
                .load(conn.conn())
                .expect("the replica answers")
        })
        .await
        .expect("the replica keeps serving the offline half");
    assert_eq!(rows.len(), 1, "the last rows stay readable");
}

/// Dropping every client clone ends the pump with a graceful close, no
/// fault, so a handle that outlives them learns about it through the watch
/// sender going away, not through the fault record.
#[tokio::test]
async fn a_handle_outliving_every_clone_falls_back_to_the_driver_stop() {
    let (client, script, _dir, pump) = client().await;
    let mut events = client.events();
    let mut query = client
        .watch::<_, Item>(items::table.order(items::id))
        .await
        .expect("watch the synced table");
    client
        .with_conn(|conn| {
            diesel::insert_into(items::table)
                .values((items::id.eq(1), items::label.eq("kept")))
                .execute(conn.conn())
                .expect("write the row")
        })
        .await
        .expect("the write lands locally");
    // The local write refreshes the watch before the clones go, so the
    // handle rests on the row when the pump ends.
    tokio::time::timeout(BOUND, query.changed())
        .await
        .expect("the local write refreshes the watch in time")
        .expect("the refresh signals the handle");

    drop(client);
    pump.await.expect("the pump task ends");

    let seen = until_closed(&mut events).await;
    assert!(
        seen.iter()
            .all(|event| !matches!(event, ClientEvent::Stopped { .. })),
        "a graceful close announces no fault, saw {seen:?}"
    );
    let outcome = query.changed().await;
    assert!(
        matches!(
            &outcome,
            Err(ClientError::Transport(detail)) if detail == "live query driver stopped"
        ),
        "a faultless end reports the driver stop, got {outcome:?}"
    );
    assert_eq!(query.rows().len(), 1, "the last rows stay readable");
    assert!(
        script.closed.load(Ordering::Acquire),
        "the transport is closed"
    );
}
