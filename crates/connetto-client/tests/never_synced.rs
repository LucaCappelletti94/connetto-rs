//! R20 step 4: an empty result says which kind of empty it is.
//!
//! A replica that has never reached a server cannot serve rows nobody has ever
//! fetched, and returning an empty list for that is indistinguishable from a
//! dataset that really is empty. The application has to tell "you have no
//! items" from "we could not load your items", so the live handle carries the
//! difference.
//!
//! The discriminating case is a first sync that delivers no rows at all.
//! Nothing refreshes, because no watched table changed, so a caller would be
//! told "never fetched" forever about a set that was fetched and found empty.

use std::collections::VecDeque;
use std::future::{Future, ready};
use std::sync::{Arc, Mutex};

use connetto_client::reconnect::ReconnectPolicy;
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Grant, Replica, SqlFunctions,
};
use connetto_core::messages::{
    BulkMessage, ControlMessage, HandshakeAck, SnapshotBegin, SnapshotEnd, SubscriptionSpec,
};
use connetto_core::traits::{IncomingFrame, Transport};
use diesel::prelude::*;
use tempfile::tempdir;

const DDL: &str = "CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)";
const TIER_DDL: &str = "CREATE TABLE drafts (id INTEGER PRIMARY KEY, body TEXT)";

diesel::table! {
    /// Synced test table.
    items (id) {
        /// Item identifier, the primary key
        id -> Integer,
        /// Optional item label
        label -> Nullable<Text>,
    }
}

diesel::table! {
    /// Device-private test table, never synced by design.
    drafts (id) {
        /// Draft identifier, the primary key
        id -> Integer,
        /// Draft text
        body -> Nullable<Text>,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = drafts)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Draft {
    id: i32,
    body: Option<String>,
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = items)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Item {
    id: i32,
    label: Option<String>,
}

/// A transport handing out a scripted sequence of frames, then going quiet
/// without closing.
///
/// Going quiet matters: a transport that reports end of stream is a closed
/// one, which would drop the wire and end the run. A real idle socket simply
/// has nothing to say yet, so this one stays pending until the script grows.
#[derive(Clone, Default)]
struct Script {
    frames: Arc<Mutex<VecDeque<IncomingFrame>>>,
    subscribes: Arc<Mutex<Vec<String>>>,
}

impl Script {
    fn with(frames: Vec<IncomingFrame>) -> Self {
        Self {
            frames: Arc::new(Mutex::new(frames.into())),
            subscribes: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn say(&self, frame: IncomingFrame) {
        self.frames.lock().expect("script lock").push_back(frame);
    }
}

impl Transport for Script {
    type Error = std::convert::Infallible;

    fn send_control(
        &mut self,
        message: ControlMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        if let ControlMessage::Subscribe(subscribe) = message {
            self.subscribes
                .lock()
                .expect("subscribes lock")
                .push(subscribe.spec.query);
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

fn config() -> ClientConfig {
    ClientConfig {
        client_id: "r20-never-synced".to_owned(),
        login: Some(Grant::new("user:tester")),
        capabilities: Vec::new(),
        schema_version: None,
        sql_functions: SqlFunctions::new(),
    }
}

/// Wait for the pump to report the named event, so the assertions that follow
/// read state the pump has finished writing.
async fn until(events: &mut tokio::sync::broadcast::Receiver<ClientEvent>, sub: &str) {
    loop {
        match events.recv().await.expect("events") {
            ClientEvent::SnapshotEnd { sub_id } if sub_id == sub => return,
            _ => {}
        }
    }
}

/// A first sync that finds nothing still ends the "never fetched" state.
///
/// Both halves are load-bearing. Before the snapshot the empty list means the
/// rows were never fetched, and after it the identical empty list means there
/// are none.
#[tokio::test]
async fn an_empty_first_sync_still_counts_as_having_synced() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("fresh.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");

    let script = Script::with(vec![ack()]);
    let mut conn = ConnettoConnection::<Script>::open(&replica, DDL, &config(), None)
        .expect("open the replica");
    conn.attach(script.clone())
        .await
        .expect("attach the script");
    assert!(
        !conn.has_ever_synced(),
        "a handshake is not data: nothing has been fetched yet"
    );

    let (client, pump) = ConnettoClient::with_pump(conn);
    tokio::spawn(pump);
    let mut events = client.events();

    let query = client
        .watch::<_, Item>(items::table.order(items::id))
        .await
        .expect("watch the synced table");
    assert!(
        query.rows().is_empty(),
        "nothing has arrived, so there is nothing to show"
    );
    assert!(
        query.never_synced(),
        "empty here means the rows were never fetched"
    );

    // The server answers, and finds nothing. No patch, so no watched table
    // changes and no live query refreshes: only the cursor moves.
    script.say(IncomingFrame::Control(ControlMessage::SnapshotBegin(
        SnapshotBegin {
            sub_id: query.sub_id().to_owned(),
            priority: connetto_core::messages::SubscriptionPriority::default(),
        },
    )));
    script.say(IncomingFrame::Control(ControlMessage::SnapshotEnd(
        SnapshotEnd {
            sub_id: query.sub_id().to_owned(),
            cursor: connetto_core::Cursor::from(vec![0, 0, 0, 0, 0, 0, 0, 9]),
        },
    )));
    until(&mut events, query.sub_id()).await;
    // The event is broadcast from inside the pump's state lock, so taking that
    // lock is the barrier proving the whole iteration finished. Without it the
    // assertions below race the rest of the step.
    client.with_conn(|_| ()).await;

    assert!(
        query.rows().is_empty(),
        "the server had nothing, so the rows are still empty"
    );
    assert!(
        !query.never_synced(),
        "but this empty list was fetched, and the application can now say so"
    );
}

/// A query over device-private tables alone never reports never-synced,
/// because its rows never came from a server and never will.
///
/// Without this, every draft an offline user typed would be presented as
/// possibly-missing data, which is the opposite of what a device-private table
/// is for.
#[tokio::test]
async fn device_private_rows_do_not_wait_on_a_server() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("local.sqlite");
    let tier = dir.path().join("local-tier.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key")
    .with_tier(tier.to_str().expect("utf-8 path"), TIER_DDL);

    let mut conn = ConnettoConnection::<Script>::open(&replica, DDL, &config(), None)
        .expect("open the replica");
    assert!(!conn.has_ever_synced(), "no server was ever reached");
    diesel::insert_into(drafts::table)
        .values((drafts::id.eq(1), drafts::body.eq("typed offline")))
        .execute(conn.conn())
        .expect("write a draft with no server");

    let (client, pump) = ConnettoClient::with_pump(conn);
    tokio::spawn(pump);

    let query = client
        .watch::<_, Draft>(drafts::table.order(drafts::id))
        .await
        .expect("watch the device-private table");
    assert_eq!(
        query.rows(),
        vec![Draft {
            id: 1,
            body: Some("typed offline".to_owned()),
        }],
        "the draft is there, server or no server"
    );
    assert!(
        !query.never_synced(),
        "these rows never depended on a server, so nothing about them is unfetched"
    );
}

/// A device-private app with no server and no way to reach one keeps working:
/// a later local write still refreshes the live query.
///
/// The pump is what refreshes, and with nothing to read and no transport to
/// find it would be easy to let it end. Then the first screen would render and
/// nothing would ever update again, which is the failure mode an offline-first
/// application would notice last.
#[tokio::test]
async fn local_writes_keep_refreshing_with_no_server_and_no_way_to_get_one() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("local-only.sqlite");
    let tier = dir.path().join("local-only-tier.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key")
    .with_tier(tier.to_str().expect("utf-8 path"), TIER_DDL);

    let conn = ConnettoConnection::<Script>::open(&replica, DDL, &config(), None)
        .expect("open the replica");
    // No reconnect driver: nothing can ever attach a transport to this client.
    let (client, pump) = ConnettoClient::with_pump(conn);
    tokio::spawn(pump);

    let mut query = client
        .watch::<_, Draft>(drafts::table.order(drafts::id))
        .await
        .expect("watch");
    assert!(query.rows().is_empty());

    // Wait until the pump has run a full step and reported where it stands, so
    // the write below lands on a settled pump rather than racing its first
    // iteration. Without this the test passes even when the pump ends, because
    // one refresh happens before it does.
    let mut events = client.events();
    loop {
        if matches!(
            events.recv().await.expect("events"),
            ClientEvent::SyncStatus(_)
        ) {
            break;
        }
    }

    client
        .with_conn(|conn| {
            diesel::insert_into(drafts::table)
                .values((drafts::id.eq(1), drafts::body.eq("written later")))
                .execute(conn.conn())
                .expect("write a draft");
        })
        .await;

    tokio::time::timeout(core::time::Duration::from_secs(5), query.changed())
        .await
        .expect("the pump is still running and noticed the write")
        .expect("changed");
    assert_eq!(
        query.rows(),
        vec![Draft {
            id: 1,
            body: Some("written later".to_owned()),
        }]
    );
}

/// Watching a synced table with no server reachable answers from the replica,
/// says the rows may be incomplete, and reaches the server when one arrives.
///
/// This is the whole offline story in one place. Before step 5 the call itself
/// failed, because declaring a subscription put a frame on a socket that did
/// not exist, so an application whose first screen mounts a query could not
/// start at all without a server.
#[tokio::test]
async fn a_query_watched_with_no_server_answers_and_then_subscribes() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("watch-offline.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");

    let mut conn = ConnettoConnection::<Script>::open(&replica, DDL, &config(), None)
        .expect("open with no server");
    diesel::insert_into(items::table)
        .values((items::id.eq(1), items::label.eq("from a previous run")))
        .execute(conn.conn())
        .expect("seed the replica");

    let (client, pump) = ConnettoClient::with_pump(conn);
    tokio::spawn(pump);

    let query = client
        .watch::<_, Item>(items::table.order(items::id))
        .await
        .expect("watching a synced table must not need a server");
    assert_eq!(
        query.rows(),
        vec![Item {
            id: 1,
            label: Some("from a previous run".to_owned()),
        }],
        "the replica answers on its own"
    );
    assert!(
        query.never_synced(),
        "and says the answer may be missing rows this device never fetched"
    );

    drop(query);
    drop(client);
}

/// The same declaration, carried onto the first transport the reconnect driver
/// finds. A run that starts before its server ends up subscribed without the
/// application declaring anything twice.
#[tokio::test]
async fn a_run_that_starts_before_its_server_ends_up_subscribed() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("late-server.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");

    let conn = ConnettoConnection::<Script>::open(&replica, DDL, &config(), None)
        .expect("open with no server");
    let script = Script::with(vec![ack()]);
    let factory = {
        let script = script.clone();
        move || {
            let script = script.clone();
            async move { Ok::<_, core::convert::Infallible>(script) }
        }
    };
    let (client, pump) = ConnettoClient::with_reconnect(
        conn,
        factory,
        |d| tokio::time::sleep(d),
        ReconnectPolicy {
            initial_backoff: core::time::Duration::from_millis(5),
            max_backoff: core::time::Duration::from_millis(20),
            max_attempts: Some(20),
        },
    );
    tokio::spawn(pump);
    let mut events = client.events();

    let query = client
        .watch::<_, Item>(items::table.order(items::id))
        .await
        .expect("watching must not need a server");
    assert!(query.never_synced(), "no server has answered yet");

    // The driver finds the transport on its own, and the declaration rides it.
    loop {
        if matches!(
            events.recv().await.expect("events"),
            ClientEvent::Reconnected
        ) {
            break;
        }
    }
    assert_eq!(
        *script.subscribes.lock().expect("subscribes lock"),
        vec!["SELECT `items`.`id`, `items`.`label` FROM `items` ORDER BY `items`.`id`".to_owned()],
        "the query declared before the server existed reached it unprompted"
    );
}

/// Dropping the last handle starts a countdown instead of unsubscribing, so
/// navigating away and back inside the grace pays no fresh snapshot.
///
/// The subscription staying declared is the observable: before this, the last
/// drop unsubscribed at once and the record went with it.
#[tokio::test]
async fn a_dropped_watch_keeps_its_subscription_for_the_grace() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("grace.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");

    let conn = ConnettoConnection::<Script>::open(&replica, DDL, &config(), None)
        .expect("open with no server");
    let (client, pump) = ConnettoClient::with_pump(conn);
    tokio::spawn(pump);

    let query = client
        .watch::<_, Item>(items::table.order(items::id))
        .await
        .expect("watch");
    // A second, differently shaped query over the same table. It holds its own
    // subscription, so dropping the first genuinely releases one, and its
    // refresh is the barrier proving the pump finished the drop pass.
    let mut probe = client
        .watch::<_, Item>(items::table.filter(items::id.gt(0)))
        .await
        .expect("probe");
    assert_eq!(
        client
            .with_conn(|conn| conn.declared_subscriptions().expect("declared"))
            .await
            .len(),
        2
    );
    drop(query);

    client
        .with_conn(|conn| {
            diesel::insert_into(items::table)
                .values((items::id.eq(1), items::label.eq("wake the pump")))
                .execute(conn.conn())
                .expect("write");
        })
        .await;
    tokio::time::timeout(core::time::Duration::from_secs(5), probe.changed())
        .await
        .expect("the pump completed an iteration")
        .expect("changed");

    assert_eq!(
        client
            .with_conn(|conn| conn.declared_subscriptions().expect("declared"))
            .await
            .len(),
        2,
        "the dropped handle's subscription outlives it for the grace"
    );

    // And re-watching it finds the same subscription rather than minting a
    // second one for the same query.
    let again = client
        .watch::<_, Item>(items::table.order(items::id))
        .await
        .expect("re-watch");
    assert_eq!(
        client
            .with_conn(|conn| conn.declared_subscriptions().expect("declared"))
            .await
            .len(),
        2,
        "re-watching re-claims rather than declaring a second time"
    );
    drop(again);
    drop(probe);
}

/// A pin survives closing and reopening the application, with no server ever
/// involved, which is the case it exists for.
#[tokio::test]
async fn a_pin_survives_a_restart_with_no_server() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("pinned.sqlite");
    let key = connetto_core::test_support::replica_key();
    let replica = Replica::encrypted_file(path.to_str().expect("utf-8 path"), Some(key.clone()))
        .expect("a resolved key");

    {
        let conn = ConnettoConnection::<Script>::open(&replica, DDL, &config(), None)
            .expect("open with no server");
        let (client, pump) = ConnettoClient::with_pump(conn);
        tokio::spawn(pump);
        client
            .pin("offline-pack", "SELECT * FROM items")
            .await
            .expect("pinning must not need a server");
        assert_eq!(
            client.pins().await.expect("pins"),
            vec![("offline-pack".to_owned(), "SELECT * FROM items".to_owned())]
        );
    }

    // The process ends. A pin has no handle and no clock, so it is still there.
    let reopened = Replica::encrypted_file(path.to_str().expect("utf-8 path"), Some(key))
        .expect("a resolved key");
    let mut conn =
        ConnettoConnection::<Script>::open_existing(&reopened, &config(), None).expect("reopen");
    assert_eq!(
        conn.pins().expect("pins"),
        vec![("offline-pack".to_owned(), "SELECT * FROM items".to_owned())],
        "the pin outlived the process that made it"
    );

    // And it is what the first connection re-declares.
    let script = Script::with(vec![ack()]);
    conn.attach(script.clone()).await.expect("attach");
    assert_eq!(
        *script.subscribes.lock().expect("subscribes lock"),
        vec!["SELECT * FROM items".to_owned()],
        "the pin reached the first server that turned up"
    );

    conn.unpin_subscription("offline-pack").expect("unpin");
    assert!(conn.pins().expect("pins").is_empty());
}

/// A subscription past its grace is not re-declared on the next connection,
/// and one still live beside it is.
///
/// Both halves matter. Sending nothing at all would pass a test that only
/// checked the expired one, so a live sibling has to travel in the same
/// attach. The expired record is reached through the public surface: unpinning
/// ends a pin at once rather than starting a countdown, which leaves exactly
/// the past-grace state a watch reaches five minutes after its last handle.
#[tokio::test]
async fn a_subscription_past_its_grace_is_not_re_declared() {
    let dir = tempdir().expect("temp dir");
    let path = dir.path().join("grace-attach.sqlite");
    let replica = Replica::encrypted_file(
        path.to_str().expect("utf-8 path"),
        Some(connetto_core::test_support::replica_key()),
    )
    .expect("a resolved key");

    let mut conn = ConnettoConnection::<Script>::open(&replica, DDL, &config(), None)
        .expect("open with no server");

    let ended = SubscriptionSpec::new("SELECT * FROM items WHERE id = 1");
    let live = SubscriptionSpec::new("SELECT * FROM items WHERE id = 2");
    conn.subscribe_spec("wire-1", ended.clone())
        .await
        .expect("declare the one that will end");
    conn.subscribe_spec("wire-2", live.clone())
        .await
        .expect("declare the one that stays");

    // Pinning then unpinning ends `wire-1` immediately, which is the same
    // record state as a watch whose grace has run out.
    conn.pin_subscription("temporary", "wire-1", &ended)
        .expect("pin");
    conn.unpin_subscription("temporary").expect("unpin");
    assert_eq!(
        conn.declared_subscriptions().expect("declared").len(),
        2,
        "both are still recorded until the next attach reads them"
    );

    let script = Script::with(vec![ack()]);
    conn.attach(script.clone()).await.expect("attach");

    assert_eq!(
        *script.subscribes.lock().expect("subscribes lock"),
        vec![live.query.clone()],
        "only the live subscription reached the server"
    );
    assert_eq!(
        conn.declared_subscriptions().expect("declared"),
        vec![("wire-2".to_owned(), live)],
        "and the ended one is gone rather than lingering"
    );
}
