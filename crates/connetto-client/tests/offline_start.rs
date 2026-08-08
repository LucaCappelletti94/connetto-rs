//! R20 steps 1 and 2: a connection exists before a server does.
//!
//! The first two parts of the phase's proof. Start with a populated replica and
//! nothing listening, and reads answer from the replica while the process stays
//! up. Then hand the same connection a transport, and the writes it queued
//! while alone go up without the application restarting.
//!
//! Then declare a query with nothing listening, and the declaration survives
//! both the missing socket and the process, reaching the server on the first
//! connection that happens.
//!
//! Native and offline by construction: the point is that no server is involved
//! until the second half, and the transport used there answers a handshake and
//! records what it is sent.

use std::future::{Future, ready};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use connetto_client::{
    ClientConfig, ClientError, ClientEvent, ConnettoConnection, Grant, Replica, SqlFunctions,
    SyncStatus,
};
use connetto_core::Cursor;
use connetto_core::messages::{BulkMessage, ControlMessage, HandshakeAck, SubscriptionSpec};
use connetto_core::traits::{IncomingFrame, Transport};
use diesel::prelude::*;
use tempfile::tempdir;

const DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";

diesel::table! {
    /// Synced test table.
    items (id) {
        /// Item identifier, the primary key
        id -> Integer,
        /// Optional item label
        label -> Nullable<Text>,
    }
}

/// A transport that completes the handshake and remembers the mutation
/// sequences it was handed, so a replay is observed rather than assumed.
///
/// The shared fake discards what it is sent, and the harness that watches a
/// real server replay is Docker-gated and starts already connected, so neither
/// can see the thing this phase adds: a connection that had no transport at
/// all being given one.
#[derive(Clone, Default)]
struct Recorder {
    greeted: Arc<AtomicBool>,
    uploads: Arc<Mutex<Vec<u64>>>,
    subscribes: Arc<Mutex<Vec<(String, String)>>>,
}

impl Transport for Recorder {
    type Error = std::convert::Infallible;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        match message {
            ControlMessage::MutationHeader(header) => {
                self.uploads
                    .lock()
                    .expect("uploads lock")
                    .push(header.client_seq);
            }
            ControlMessage::Subscribe(subscribe) => {
                self.subscribes
                    .lock()
                    .expect("subscribes lock")
                    .push((subscribe.sub_id, subscribe.spec.query));
            }
            _ => {}
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
        if self.greeted.swap(true, Ordering::Relaxed) {
            // Nothing further to say, and the connection stays usable.
            return ready(Ok(None));
        }
        ready(Ok(Some(IncomingFrame::Control(
            ControlMessage::HandshakeAck(HandshakeAck {
                connection_id: "recorder".to_owned(),
                session_token: "recorder".to_owned(),
                resume_token: "recorder".to_owned(),
                current_cursor: Cursor::new(Vec::new()),
                schema_version: None,
                initial_credits: 64,
                last_applied_seq: None,
            }),
        ))))
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> {
        ready(Ok(()))
    }
}

fn config() -> ClientConfig {
    ClientConfig {
        client_id: "r20-offline".to_owned(),
        login: Some(Grant::new("user:tester")),
        capabilities: Vec::new(),
        schema_version: None,
        sql_functions: SqlFunctions::new(),
    }
}

fn labels(conn: &mut ConnettoConnection<Recorder>) -> Vec<Option<String>> {
    items::table
        .order(items::id)
        .select(items::label)
        .load(conn.conn())
        .expect("read the replica")
}

/// Part one: no server, and the connection is still a working local database.
#[tokio::test]
async fn a_connection_opens_and_serves_reads_with_no_server() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("offline.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");

    let mut conn = ConnettoConnection::<Recorder>::open(&replica, DDL, &config(), None)
        .expect("open with no server");
    assert!(
        !conn.is_connected(),
        "nothing was attached, so nothing is connected"
    );
    assert_eq!(
        conn.session_handle(),
        None,
        "a run that has never reached a server holds no handle from one"
    );

    diesel::insert_into(items::table)
        .values((items::id.eq(1), items::label.eq("written-offline")))
        .execute(conn.conn())
        .expect("write with no server");
    assert_eq!(labels(&mut conn), vec![Some("written-offline".to_owned())]);

    // The write queues durably rather than failing, which is the designed
    // offline state: chapter 11 says local writes never depend on reaching
    // anybody.
    let seq = conn.push().await.expect("queue the write").expect("a seq");
    assert_eq!(
        conn.unsynced(),
        vec![seq],
        "the write is queued and visibly unsent"
    );

    // And anything that genuinely needs a server says so rather than pretending.
    assert!(matches!(conn.ping(1).await, Err(ClientError::NotConnected)));
}

/// Part two: the same connection, handed a transport, sends what it queued.
#[tokio::test]
async fn attaching_a_transport_later_replays_what_was_queued() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("later.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");

    let mut conn = ConnettoConnection::<Recorder>::open(&replica, DDL, &config(), None)
        .expect("open with no server");
    diesel::insert_into(items::table)
        .values((items::id.eq(1), items::label.eq("queued")))
        .execute(conn.conn())
        .expect("write");
    let seq = conn.push().await.expect("queue").expect("a seq");

    // The server arrives. No restart, no second connection, no reopening the
    // replica: the same value gains a transport.
    let recorder = Recorder::default();
    assert!(
        recorder.uploads.lock().expect("uploads lock").is_empty(),
        "nothing has been sent yet, because there was nothing to send it through"
    );
    conn.attach(recorder.clone())
        .await
        .expect("attach a transport to a live connection");
    assert!(conn.is_connected());
    assert!(
        conn.session_handle().is_some(),
        "the handshake gave this run a handle"
    );

    // The queued write went up on attach, through the same exactly-once replay
    // a reconnect uses. Observed on the wire rather than inferred.
    assert_eq!(
        *recorder.uploads.lock().expect("uploads lock"),
        vec![seq],
        "attaching replayed exactly the write that was queued while alone"
    );
    assert_eq!(labels(&mut conn), vec![Some("queued".to_owned())]);
    assert!(
        conn.unsynced().contains(&seq),
        "and it stays pending until the server acknowledges it, which this \
         transport never does"
    );
}

/// The third part of the phase's proof: nothing synced and nothing to sync to
/// is an empty answer, and the connection can say it has never synced rather
/// than leaving the caller to guess.
#[tokio::test]
async fn a_first_run_with_no_data_and_no_server_reports_empty_and_never_synced() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("fresh.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");

    let mut conn = ConnettoConnection::<Recorder>::open(&replica, DDL, &config(), None)
        .expect("open with no server");
    assert!(
        labels(&mut conn).is_empty(),
        "nothing has ever been fetched"
    );
    assert_eq!(
        conn.cursor(),
        None,
        "and the run can tell that apart from a dataset that is genuinely empty"
    );
}

/// R20 step 3: the connection says which state it is in, on the one stream the
/// application already reads.
///
/// A value handed back once cannot report a server arriving later, which is why
/// this is an event and not a return.
#[tokio::test]
async fn the_connection_reports_going_offline_and_coming_back() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("status.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");

    let mut conn = ConnettoConnection::<Recorder>::open(&replica, DDL, &config(), None)
        .expect("open with no server");

    // The state it came up in, stated rather than left to be guessed.
    assert_eq!(
        conn.pump_one().await.expect("the opening state"),
        ClientEvent::SyncStatus(SyncStatus::Offline)
    );

    conn.attach(Recorder::default()).await.expect("attach");
    assert_eq!(
        conn.pump_one().await.expect("the change"),
        ClientEvent::SyncStatus(SyncStatus::Connected)
    );

    // The recorder says nothing further and reports end of stream, which is a
    // transport that has gone. The connection notices, drops the wire, and says
    // so rather than leaving the caller showing data it can no longer refresh.
    assert_eq!(
        conn.pump_one().await.expect("the peer closing"),
        ClientEvent::Closed
    );
    assert!(
        !conn.is_connected(),
        "a peer that has gone leaves no server to reach"
    );
    assert_eq!(
        conn.pump_one().await.expect("the drop is announced"),
        ClientEvent::SyncStatus(SyncStatus::Offline)
    );

    // The run survived the drop, which is what lets the next attach continue it
    // rather than start a new one.
    assert!(
        conn.session_handle().is_some(),
        "the run outlives the socket, so a reconnect resumes rather than restarts"
    );
}

/// Part three: a subscription declared with no server reaches the first one
/// that turns up, and survives a restart on the way.
///
/// The restart is the half that needs the record on disk. Without it the
/// declaration lives in the process that made it, and an application that
/// subscribes at startup while offline, then restarts before a server appears,
/// is subscribed to nothing at all with no error anywhere to say so.
#[tokio::test]
async fn a_subscription_declared_alone_reaches_the_first_server() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("declared.sqlite");
    let key = connetto_core::test_support::replica_key();
    let replica = Replica::encrypted_file(path.to_str().expect("utf-8 path"), Some(key.clone()))
        .expect("a resolved key");

    // No server, and a query is declared anyway.
    let mut conn = ConnettoConnection::<Recorder>::open(&replica, DDL, &config(), None)
        .expect("open with no server");
    conn.subscribe_spec("wire-1", SubscriptionSpec::new("SELECT * FROM items"))
        .await
        .expect("declaring a subscription does not need a server");
    assert_eq!(
        conn.declared_subscriptions()
            .expect("read the declared set")
            .len(),
        1,
        "it is recorded even though nothing could be sent"
    );
    drop(conn);

    // The process ends and starts again, still with no server. The declaration
    // is read back off disk, not remembered.
    let reopened = Replica::encrypted_file(path.to_str().expect("utf-8 path"), Some(key))
        .expect("a resolved key");
    let mut conn = ConnettoConnection::<Recorder>::open_existing(&reopened, &config(), None)
        .expect("reopen with no server");
    assert_eq!(
        conn.declared_subscriptions()
            .expect("read the declared set"),
        vec![(
            "wire-1".to_owned(),
            SubscriptionSpec::new("SELECT * FROM items")
        )],
        "the declaration outlived the process that made it"
    );

    // A server finally turns up, and hears about the query without the
    // application declaring it again.
    let recorder = Recorder::default();
    conn.attach(recorder.clone()).await.expect("attach");
    assert_eq!(
        *recorder.subscribes.lock().expect("subscribes lock"),
        vec![("wire-1".to_owned(), "SELECT * FROM items".to_owned())],
        "the first connection carried the subscription declared two runs ago"
    );

    // And cancelling it offline is equally durable: the next attach must not
    // resurrect it.
    conn.unsubscribe("wire-1").await.expect("unsubscribe");
    assert!(
        conn.declared_subscriptions()
            .expect("read the declared set")
            .is_empty(),
        "the record goes with the cancellation"
    );
}
