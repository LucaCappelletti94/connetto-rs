//! A pump that stops on a fault it cannot recover from says why and releases
//! everything waiting on it.

use connetto_client::{ClientBuilder, ClientError, ClientEvent, ConnettoClient, DataDir};
use connetto_core::messages::{BulkMessage, ControlMessage, HandshakeAck, LivePatch};
use connetto_core::traits::{IncomingFrame, Transport};
use diesel::prelude::*;
use std::collections::VecDeque;
use std::future::ready;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;

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
/// recording the subscriptions it was sent and whether it was closed.
#[derive(Clone, Default)]
struct Script {
    frames: Arc<Mutex<VecDeque<IncomingFrame>>>,
    subscribed: Arc<Mutex<Vec<String>>>,
    closed: Arc<AtomicBool>,
}

impl Script {
    fn say(&self, frame: IncomingFrame) {
        self.frames.lock().expect("script lock").push_back(frame);
    }

    fn last_subscribed(&self) -> String {
        self.subscribed
            .lock()
            .expect("script lock")
            .last()
            .cloned()
            .expect("the client subscribed")
    }
}

impl Transport for Script {
    type Error = std::convert::Infallible;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        if let ControlMessage::Subscribe(subscribe) = message {
            self.subscribed
                .lock()
                .expect("script lock")
                .push(subscribe.sub_id);
        }
        ready(Ok(()))
    }

    fn send_bulk(
        &mut self,
        _message: BulkMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }

    fn recv(&mut self) -> impl Future<Output = Result<Option<IncomingFrame>, Self::Error>> {
        let frames = Arc::clone(&self.frames);
        async move {
            loop {
                if let Some(frame) = frames.lock().expect("script lock").pop_front() {
                    return Ok(Some(frame));
                }
                tokio::task::yield_now().await;
            }
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        self.closed.store(true, Ordering::Relaxed);
        ready(Ok(()))
    }
}

fn ack() -> IncomingFrame {
    IncomingFrame::Control(ControlMessage::HandshakeAck(HandshakeAck {
        connection_id: "script".to_owned(),
        session_token: "script".to_owned(),
        resume_token: "script".to_owned(),
        current_cursor: connetto_core::Cursor::from(Vec::new()),
        schema_version: None,
        initial_credits: 64,
        last_applied_seq: None,
    }))
}

async fn client() -> (ConnettoClient<Script>, Script, tempfile::TempDir) {
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
    .durable(DataDir::new(dir.path().to_path_buf()), key_store)
    .connect_with_pump()
    .await
    .expect("the builder connects");
    tokio::spawn(pump);
    (running.client().clone(), script, dir)
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
    let (client, script, _dir) = client().await;
    let mut events = client.events();
    let mut query = client
        .watch::<_, Item>(items::table.order(items::id))
        .await
        .expect("watch the synced table");
    let waiting = tokio::spawn(async move { query.changed().await });

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
        script.closed.load(Ordering::Relaxed),
        "the transport is closed"
    );

    let mut late = client
        .watch::<_, Item>(items::table.order(items::id))
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
