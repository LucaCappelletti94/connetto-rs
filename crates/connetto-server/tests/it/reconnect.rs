//! Reconnect and oplog end-to-end tests (Phase 5).
//!
//! Drives a sequence of CDC events through the manager (which records them in an
//! in-memory oplog), then reconnects a client whose resume cursor sits at a
//! chosen point and asserts the catchup-versus-full-resync behaviour:
//!
//! * within the retained window: the client receives exactly the entries after
//!   its cursor as `LivePatch`, and its replica reaches row parity;
//! * a catchup completion follows all rows and carries their ceiling.
//! * outside the window (after a prune): the client receives
//!   `FullResyncRequired { CursorOutsideRetention }` followed by a fresh
//!   snapshot;
//! * a delete replays as a tombstone so the client drops the row;
//! * after a restart, the feed re-delivering rows a caught-up client already
//!   holds keeps running and sends that client only what it lacks;
//! * a transaction a snapshot missed, flushed before its read but not yet
//!   visible to it, reaches the client right after the snapshot, through
//!   catchup from the fenced cursor the snapshot issued, or live below that
//!   cursor.
//!
//! Reads and seeds go through typed diesel queries, matching the other tests;
//! DML against the emulated backend stays as SQL strings.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{
    AckCredits, BulkMessage, ControlMessage, FullResyncReason, Handshake, Ping, Subscribe,
    SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{HandshakeAuthority, IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    ChangeRecord, InMemoryOplog, LoopbackTransport, ManagerBuilder, Materializer, NoConnector,
    Oplog, OplogConfig, PageSpec, PgOplog, Position, ReadFence, SessionConfig, SessionManager,
    SnapshotEstimate, SnapshotPage, SnapshotSource, TimelineHistory, Unseen, loopback,
    pg_write_target,
};
use connetto_test_harness::{ConnettoDefaults, Fixture, RosterAuth, WITHHELD_ID};
use diesel::prelude::*;
use diesel::sql_query;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use subql::backend::{CdcEvent, Postgres};
use subql::visibility::VisibilityPolicy;
use subql::{
    CdcSource, PgChangeEvent, PgCommit, PgCommitPosition, PgLsn, PgSqliteEmuSource, PgXid,
    SourceItem,
};

mod failures;
const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

fn test_verifier() -> std::sync::Arc<dyn HandshakeAuthority> {
    std::sync::Arc::new(TestGrantChecker)
}

/// A snapshot source returning one seed row. Only the full-resync path delivers
/// it, and that test asserts the frame sequence rather than applying it.
struct SeedSnapshot;

impl SnapshotSource for SeedSnapshot {
    type Error = std::convert::Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &connetto_core::Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        Ok(SnapshotEstimate {
            rows: 0.0,
            width: 0,
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the trait method is async and this body finishes without awaiting"
    )]
    async fn snapshot_page(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        let table = SimpleTable::new("orders", &["id", "price", "quantity", "status"], &[0]);
        let insert = Insert::<_, String, Vec<u8>>::from(table)
            .set(0, Value::Integer(1))
            .expect("set id")
            .set(1, Value::Real(1.0))
            .expect("set price")
            .set(2, Value::Integer(3))
            .expect("set quantity")
            .set(3, Value::Text("seed".to_owned()))
            .expect("set status");
        let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new()
            .insert(insert)
            .build();
        Ok(SnapshotPage {
            patchset,
            cursor: Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: 0,
            rows: 0,
            bytes: 0,
        })
    }
}

diesel::table! {
    /// Row from the orders test fixture.
    orders (id) {
        /// Order identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Unit price.
        price -> diesel::sql_types::Double,
        /// Number of units.
        quantity -> diesel::sql_types::BigInt,
        /// Order status.
        status -> diesel::sql_types::Text,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    price: f64,
    quantity: i64,
    status: String,
}

fn order(id: i64, price: f64, quantity: i64, status: &str) -> Order {
    Order {
        id,
        price,
        quantity,
        status: status.to_owned(),
    }
}

fn orders(conn: &mut SqliteConnection) -> Vec<Order> {
    orders::table
        .order(orders::id)
        .select(Order::as_select())
        .load(conn)
        .expect("read orders")
}

fn client_replica() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    conn
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

async fn next_bulk<T: Transport>(transport: &mut T) -> BulkMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Bulk(msg)) => msg,
        other => panic!("expected bulk frame, got {other:?}"),
    }
}

/// Assert no frame arrives within a short window.
async fn expect_idle<T: Transport>(transport: &mut T) {
    let outcome = tokio::time::timeout(Duration::from_millis(150), transport.recv()).await;
    assert!(outcome.is_err(), "expected no frame, got {outcome:?}");
}

/// The next frame in wire order, giving up after a bound so a frame the server
/// never sends fails the test instead of hanging it.
async fn next_frame_bounded<T: Transport>(transport: &mut T) -> IncomingFrame {
    tokio::time::timeout(Duration::from_secs(5), transport.recv())
        .await
        .expect("a frame within five seconds")
        .expect("recv")
        .expect("connection open")
}

/// The next control frame under the bound above.
async fn next_control_bounded<T: Transport>(transport: &mut T) -> ControlMessage {
    let frame = next_frame_bounded(transport).await;
    let IncomingFrame::Control(msg) = frame else {
        panic!("expected a control frame, got {frame:?}");
    };
    msg
}

/// Every frame between the call and the pong for `nonce`, in wire order.
///
/// The run loop handles frames one at a time, so the pong proves everything
/// produced before it is already in the transport.
async fn barrier<T: Transport>(client: &mut T, nonce: u64) -> Vec<IncomingFrame> {
    client
        .send_control(ControlMessage::Ping(Ping { nonce }))
        .await
        .expect("send barrier ping");
    let mut seen = Vec::new();
    loop {
        let frame = next_frame_bounded(client).await;
        if let IncomingFrame::Control(ControlMessage::Pong(pong)) = &frame {
            assert_eq!(pong.nonce, nonce, "the barrier's own pong");
            return seen;
        }
        seen.push(frame);
    }
}

/// Execute `sql` against the emulated backend, route every resulting event
/// through the manager (which appends to the oplog), and return the events.
/// The emulator stamps monotonic LSNs, which the LSN-keyed oplog relies on.
async fn drive<A, O>(
    source: &mut PgSqliteEmuSource,
    manager: &SessionManager<SeedSnapshot, A, ConnettoDefaults, NoConnector, O>,
    sql: &str,
) -> Vec<PgChangeEvent>
where
    A: VisibilityPolicy<Watcher = Arc<connetto_core::auth::Principal>, Backend = Postgres>,
    A::Error: core::fmt::Display + connetto_server::FailedAuthorization,
    O: Oplog,
{
    source.execute_sql(sql).expect("execute dml");
    let mut events = Vec::new();
    while let Some(item) = source.next_item().await.expect("poll source") {
        let SourceItem::Event(event) = item else {
            continue;
        };
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
        events.push(event);
    }
    events
}

/// The resume cursor a client would persist after applying `event`, on the
/// first timeline of a database never promoted.
fn cursor_of(event: &PgChangeEvent) -> Cursor {
    let at = event.checkpoint().expect("row event carries a checkpoint");
    Cursor::new(
        Position {
            system: TimelineHistory::default().system(),
            timeline: 1,
            at,
        }
        .to_cursor_bytes(),
    )
}

/// Open a session on `manager`, send the handshake carrying `resume`, and read
/// the ack. Returns the client half and the server task handle.
async fn open_session<A>(
    manager: &Arc<SessionManager<SeedSnapshot, A, ConnettoDefaults>>,
    client_id: &str,
    resume: Option<Cursor>,
) -> (LoopbackTransport, tokio::task::JoinHandle<()>)
where
    A: VisibilityPolicy<Watcher = Arc<connetto_core::auth::Principal>, Backend = Postgres>
        + Send
        + Sync
        + 'static,
    A::Error: core::fmt::Display + Send + connetto_server::FailedAuthorization,
{
    let (server_transport, mut client) = loopback();
    let server = manager.clone();
    let handle = tokio::spawn(async move {
        server.serve(server_transport).await.expect("session ok");
    });
    let mut handshake = Handshake::new(PROTOCOL_VERSION, client_id).with_grant(
        connetto_core::messages::Grant::new(format!("user:{client_id}")),
    );
    if let Some(cursor) = resume {
        handshake = handshake
            .with_cursor(cursor)
            .with_cursor_subjects(core::iter::empty::<&str>());
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    // The server leads every connection with a challenge a person ignores (R91).
    let ControlMessage::Challenge(_) = next_control(&mut client).await else {
        panic!("expected the leading challenge");
    };
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };
    (client, handle)
}

/// Subscribe to `QUERY` over `client`.
async fn subscribe<T: Transport>(client: &mut T) {
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::new(QUERY),
        }))
        .await
        .expect("send subscribe");
}

#[expect(
    clippy::too_many_lines,
    reason = "The snapshot, missed changes and completed catchup form one scenario."
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catchup_within_window_streams_missed_ops() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::builder(PG_DDL)
        .build()
        .expect("build materializer");
    let manager = ManagerBuilder::new(
        materializer,
        SeedSnapshot,
        RosterAuth::granting("client-a").withholding(WITHHELD_ID),
        test_verifier(),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    )
    .build();

    // Drive a stream: two inserts (the synced prefix), then update, insert,
    // delete (the events the client will miss and catch up on).
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");

    let mut events = Vec::new();
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (1, 9.5, 3, 'paid')",
        )
        .await,
    );
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (2, 4.0, 5, 'new')",
        )
        .await,
    );
    events.extend(
        drive(
            &mut source,
            &manager,
            "UPDATE orders SET quantity = 7 WHERE id = 1",
        )
        .await,
    );
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (3, 2.0, 2, 'later')",
        )
        .await,
    );
    events.extend(drive(&mut source, &manager, "DELETE FROM orders WHERE id = 2").await);
    // Drive the withheld row into the oplog while the client is disconnected.
    // quantity=1 matches the subscription predicate, so its absence after
    // reconnect proves the policy suppresses it on the catchup path.
    let withheld = drive(
        &mut source,
        &manager,
        &format!("INSERT INTO orders (id, price, quantity, status) VALUES ({WITHHELD_ID}, 1.0, 1, 'withheld')"),
    )
    .await;
    assert_eq!(events.len(), 5, "one CDC event per statement");

    // Build the client's replica as of the second event (the synced prefix).
    let applier = Materializer::builder(PG_DDL)
        .build()
        .expect("build applier");
    let mut replica = client_replica();
    for event in &events[..2] {
        let patch = applier.encode_patch(event).expect("encode prefix patch");
        applier
            .apply_diffset(&patch, &mut replica)
            .expect("apply prefix patch");
    }
    assert_eq!(
        orders(&mut replica),
        vec![order(1, 9.5, 3, "paid"), order(2, 4.0, 5, "new")],
        "prefix replica synced through event 2",
    );

    // Reconnect from the second event's cursor.
    let resume = cursor_of(&events[1]);
    let (mut client, server) = open_session(&manager, "client-a", Some(resume)).await;
    subscribe(&mut client).await;

    // Catchup delivers exactly the three events after the resume cursor, as
    // LivePatch, with no snapshot frames.
    for event in &events[2..] {
        let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
            panic!("expected a catchup live patch");
        };
        assert_eq!(live.sub_id, "orders");
        assert_eq!(
            live.cursor,
            cursor_of(event),
            "patch carries the event cursor"
        );
        applier
            .apply_diffset(&live.patchset_zstd, &mut replica)
            .expect("apply catchup patch");
    }
    // The replay ends with its completion, carrying the ceiling the replay read.
    let ControlMessage::SnapshotEnd(end) = next_control_bounded(&mut client).await else {
        panic!("expected the catchup completion");
    };
    assert_eq!(end.sub_id, "orders");
    assert_eq!(
        end.cursor,
        cursor_of(&withheld[0]),
        "the ceiling names the newest row in the log, withheld rows included"
    );
    expect_idle(&mut client).await;

    // The replica reached parity with the server's matching rows.
    assert_eq!(
        orders(&mut replica),
        vec![order(1, 9.5, 7, "paid"), order(3, 2.0, 2, "later")],
        "catchup brought the replica to current state",
    );

    client.close().await.expect("close client");
    server.await.expect("join server");
}

/// An ordinary row catchup ends with a completion frame carrying the ceiling the replay read, so a client resuming from that cursor replays nothing it has not applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ordinary_catchup_ends_with_a_completion_at_the_ceiling() {
    let fixture = Fixture::acquire().await;
    let manager = ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .build()
            .expect("build materializer"),
        SeedSnapshot,
        RosterAuth::granting("client-a").withholding(WITHHELD_ID),
        test_verifier(),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    )
    .build();

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    let mut events = Vec::new();
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (1, 9.5, 3, 'paid')",
        )
        .await,
    );
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (2, 4.0, 5, 'new')",
        )
        .await,
    );
    events.extend(
        drive(
            &mut source,
            &manager,
            "UPDATE orders SET quantity = 7 WHERE id = 1",
        )
        .await,
    );
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (3, 2.0, 2, 'later')",
        )
        .await,
    );
    events.extend(drive(&mut source, &manager, "DELETE FROM orders WHERE id = 2").await);
    assert_eq!(events.len(), 5, "one CDC event per statement");

    let resume = cursor_of(&events[1]);
    let (mut client, server) = open_session(&manager, "client-a", Some(resume)).await;
    subscribe(&mut client).await;

    for event in &events[2..] {
        let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
            panic!("expected a catchup live patch");
        };
        assert_eq!(live.sub_id, "orders");
        assert_eq!(
            live.cursor,
            cursor_of(event),
            "patch carries the event cursor"
        );
    }

    let ControlMessage::SnapshotEnd(end) = next_control_bounded(&mut client).await else {
        panic!("expected the catchup completion");
    };
    assert_eq!(end.sub_id, "orders");
    assert_eq!(
        end.cursor,
        cursor_of(&events[4]),
        "the completion names the ceiling the replay read"
    );
    expect_idle(&mut client).await;

    client.close().await.expect("close client");
    server.await.expect("join server");
}

/// With the credit window shut, an ordinary catchup's completion waits behind the rows it completes until the last credit releases them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credit_starved_catchup_holds_its_completion_behind_its_rows() {
    let fixture = Fixture::acquire().await;
    let (manager, _script, events, _source) =
        scripted(&fixture, SessionConfig::new().with_initial_credits(0)).await;
    let mut client = open_scripted(&manager, cursor_of(&events[0])).await;
    subscribe(&mut client).await;

    assert!(
        barrier(&mut client, 1).await.is_empty(),
        "with no credits the replayed rows cannot leave, so their completion may not either"
    );

    client
        .send_control(ControlMessage::AckCredits(AckCredits { credits: 1 }))
        .await
        .expect("credit one row");
    let released = barrier(&mut client, 2).await;
    assert_eq!(
        released.len(),
        1,
        "one credit releases exactly one row, and nothing else"
    );
    let IncomingFrame::Bulk(BulkMessage::LivePatch(live)) = &released[0] else {
        panic!("the released frame is the first row, got {released:?}");
    };
    assert_eq!(live.sub_id, "orders");
    assert_eq!(
        live.cursor,
        cursor_of(&events[1]),
        "the first missed row, in log order"
    );

    client
        .send_control(ControlMessage::AckCredits(AckCredits { credits: 1 }))
        .await
        .expect("credit the last row");
    let released = barrier(&mut client, 3).await;
    assert_eq!(
        released.len(),
        2,
        "the final row and, behind it, the completion"
    );
    let IncomingFrame::Bulk(BulkMessage::LivePatch(live)) = &released[0] else {
        panic!("the last released row leads, got {released:?}");
    };
    assert_eq!(live.cursor, cursor_of(&events[2]), "the last missed row");
    let IncomingFrame::Control(ControlMessage::SnapshotEnd(end)) = &released[1] else {
        panic!("the completion follows the rows it completes, got {released:?}");
    };
    assert_eq!(end.sub_id, "orders");
    assert_eq!(
        end.cursor,
        cursor_of(&events[2]),
        "the completion names the ceiling"
    );
    expect_idle(&mut client).await;
}

/// Resuming at the ceiling replays no rows, but the catchup still completes, and the completion carries the cursor the resume presented.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_catchup_still_sends_its_completion() {
    let fixture = Fixture::acquire().await;
    let (manager, _script, events, _source) = scripted(&fixture, SessionConfig::default()).await;
    let mut client = open_scripted(&manager, cursor_of(&events[2])).await;
    subscribe(&mut client).await;

    let ControlMessage::SnapshotEnd(end) = next_control_bounded(&mut client).await else {
        panic!("expected the empty catchup's completion");
    };
    assert_eq!(end.sub_id, "orders");
    assert_eq!(
        end.cursor,
        cursor_of(&events[2]),
        "with nothing to replay the ceiling is the resume cursor"
    );
    expect_idle(&mut client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cursor_outside_window_forces_full_resync() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::builder(PG_DDL)
        .build()
        .expect("build materializer");
    // A tiny window: after four inserts the oldest two are pruned.
    let oplog = InMemoryOplog::new(
        OplogConfig::new()
            .with_max_entries(2)
            .with_max_age(Duration::from_hours(72)),
    );
    let manager = ManagerBuilder::new(
        materializer,
        SeedSnapshot,
        RosterAuth::granting("client-a").withholding(WITHHELD_ID),
        test_verifier(),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    )
    .with_oplog(oplog)
    .build();

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");

    let mut events = Vec::new();
    for id in 1..=4 {
        let sql = format!(
            "INSERT INTO orders (id, price, quantity, status) VALUES ({id}, 1.0, {id}, 'row')"
        );
        events.extend(drive(&mut source, &manager, &sql).await);
    }
    assert_eq!(events.len(), 4);

    // Resume from the first event, which the prune dropped from the window.
    let resume = cursor_of(&events[0]);
    let (mut client, server) = open_session(&manager, "client-a", Some(resume)).await;
    subscribe(&mut client).await;

    // The server signals a full resync, then delivers a fresh snapshot.
    let ControlMessage::FullResyncRequired(resync) = next_control(&mut client).await else {
        panic!("expected a full-resync signal");
    };
    assert_eq!(resync.sub_id, "orders");
    assert_eq!(resync.reason, FullResyncReason::CursorOutsideRetention);

    let ControlMessage::SnapshotBegin(begin) = next_control(&mut client).await else {
        panic!("expected snapshot begin after resync");
    };
    assert_eq!(begin.sub_id, "orders");
    let BulkMessage::SnapshotPatch(patch) = next_bulk(&mut client).await else {
        panic!("expected snapshot patch");
    };
    assert_eq!(patch.sub_id, "orders");
    let ControlMessage::SnapshotEnd(end) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };
    assert_eq!(end.sub_id, "orders");
    expect_idle(&mut client).await;

    // Drive the withheld row through the live change path after the resync.
    // quantity=1 matches the subscription predicate, so absence proves the policy.
    drive(
        &mut source,
        &manager,
        &format!("INSERT INTO orders (id, price, quantity, status) VALUES ({WITHHELD_ID}, 1.0, 1, 'withheld')"),
    )
    .await;
    expect_idle(&mut client).await;

    client.close().await.expect("close client");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tombstone_replays_the_delete() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::builder(PG_DDL)
        .build()
        .expect("build materializer");
    let manager = ManagerBuilder::new(
        materializer,
        SeedSnapshot,
        RosterAuth::granting("client-a").withholding(WITHHELD_ID),
        test_verifier(),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    )
    .build();

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");

    let mut events = Vec::new();
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (1, 9.5, 3, 'paid')",
        )
        .await,
    );
    events.extend(drive(&mut source, &manager, "DELETE FROM orders WHERE id = 1").await);
    // Drive the withheld row into the oplog before reconnect so it falls in the
    // catchup window. quantity=1 matches the subscription predicate, so its
    // absence after reconnect proves the policy suppresses it on the catchup path.
    let withheld = drive(
        &mut source,
        &manager,
        &format!("INSERT INTO orders (id, price, quantity, status) VALUES ({WITHHELD_ID}, 1.0, 1, 'withheld')"),
    )
    .await;
    assert_eq!(events.len(), 2);

    // The client synced through the insert and holds the row locally.
    let applier = Materializer::builder(PG_DDL)
        .build()
        .expect("build applier");
    let mut replica = client_replica();
    let insert_patch = applier.encode_patch(&events[0]).expect("encode insert");
    applier
        .apply_diffset(&insert_patch, &mut replica)
        .expect("apply insert");
    assert_eq!(orders(&mut replica), vec![order(1, 9.5, 3, "paid")]);

    // Reconnect from just before the delete: the delete replays as a tombstone.
    let resume = cursor_of(&events[0]);
    let (mut client, server) = open_session(&manager, "client-a", Some(resume)).await;
    subscribe(&mut client).await;

    let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
        panic!("expected the delete replayed as a live patch");
    };
    assert_eq!(live.cursor, cursor_of(&events[1]));
    applier
        .apply_diffset(&live.patchset_zstd, &mut replica)
        .expect("apply tombstone patch");
    let ControlMessage::SnapshotEnd(end) = next_control_bounded(&mut client).await else {
        panic!("expected the catchup completion");
    };
    assert_eq!(end.sub_id, "orders");
    assert_eq!(end.cursor, cursor_of(&withheld[0]));
    expect_idle(&mut client).await;

    assert!(
        orders(&mut replica).is_empty(),
        "the replayed delete dropped the row from the replica",
    );

    client.close().await.expect("close client");
    server.await.expect("join server");
}

/// What the scripted log refuses and records.
#[derive(Default)]
struct Script {
    /// The reads to refuse, each once, in the order they are expected.
    refuse: std::collections::VecDeque<&'static str>,
    /// Whether a refusal is one a later read may get past.
    transient: bool,
    /// Where to prune the log, once, when the first refusal happens.
    prune_through: Option<PgCommitPosition>,
    /// Every read asked for since the script was armed.
    reads: Vec<&'static str>,
    armed: bool,
    /// Blocks entries reads in queue order, pruning through the optional position before each hold.
    holds: std::collections::VecDeque<(
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Notify>,
        Option<PgCommitPosition>,
    )>,
    current_reads: std::collections::HashMap<tokio::task::Id, usize>,
    panic_next_page: bool,
}

/// An in-memory reconnect log that refuses scripted reads, as a database does while it is cut off.
struct ScriptedOplog {
    inner: InMemoryOplog,
    script: Arc<std::sync::Mutex<Script>>,
}

/// A read the scripted log refused.
#[derive(Debug)]
struct Refused {
    transient: bool,
}

impl core::fmt::Display for Refused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the reconnect log refused a read (transient: {})",
            self.transient
        )
    }
}

impl ScriptedOplog {
    /// Record `read`, refusing it when it is the next scripted refusal.
    async fn gate(&self, read: &'static str) -> Result<(), Refused> {
        let (refused, prune) = {
            let mut script = self.script.lock().expect("script");
            if !script.armed {
                return Ok(());
            }
            script.reads.push(read);
            if read == "current_position"
                && let Some(task) = tokio::task::try_id()
            {
                *script.current_reads.entry(task).or_default() += 1;
            }
            if script.refuse.front() == Some(&read) {
                script.refuse.pop_front();
                (
                    Some(Refused {
                        transient: script.transient,
                    }),
                    script.prune_through.take(),
                )
            } else {
                (None, None)
            }
        };
        if let Some(through) = prune {
            self.inner
                .forget_through(through)
                .await
                .unwrap_or_else(|never| match never {});
        }
        refused.map_or(Ok(()), Err)
    }
}

impl Oplog for ScriptedOplog {
    type Error = Refused;

    fn is_transient(err: &Refused) -> bool {
        err.transient
    }

    async fn append(&self, record: ChangeRecord) -> Result<(), Refused> {
        self.inner
            .append(record)
            .await
            .map_err(|never| match never {})
    }

    async fn entries_since(&self, after: PgCommitPosition) -> Result<Vec<ChangeRecord>, Refused> {
        let hold = self.script.lock().expect("script").holds.pop_front();
        if let Some((arrived, release, prune)) = hold {
            if let Some(through) = prune {
                self.inner
                    .forget_through(through)
                    .await
                    .unwrap_or_else(|never| match never {});
            }
            arrived.notify_one();
            tokio::time::timeout(Duration::from_secs(15), release.notified())
                .await
                .expect("held page released before deadline");
        }
        let panic = {
            let mut script = self.script.lock().expect("script");
            std::mem::take(&mut script.panic_next_page)
        };
        assert!(!panic, "scripted catch-up walker panic");
        self.gate("entries_since").await?;
        self.inner
            .entries_since(after)
            .await
            .map_err(|never| match never {})
    }

    async fn entries_of(&self, unseen: &Unseen) -> Result<Vec<ChangeRecord>, Refused> {
        self.gate("entries_of").await?;
        self.inner
            .entries_of(unseen)
            .await
            .map_err(|never| match never {})
    }

    async fn min_position(&self) -> Result<Option<PgCommitPosition>, Refused> {
        self.gate("min_position").await?;
        self.inner
            .min_position()
            .await
            .map_err(|never| match never {})
    }

    async fn current_position(&self) -> Result<Option<PgCommitPosition>, Refused> {
        self.gate("current_position").await?;
        self.inner
            .current_position()
            .await
            .map_err(|never| match never {})
    }

    async fn forget_through(&self, through: PgCommitPosition) -> Result<(), Refused> {
        self.inner
            .forget_through(through)
            .await
            .map_err(|never| match never {})
    }

    async fn record_commit(&self, commit: PgCommit) -> Result<(), Refused> {
        self.inner
            .record_commit(commit)
            .await
            .map_err(|never| match never {})
    }

    async fn last_commit(&self) -> Result<Option<PgCommit>, Refused> {
        self.inner
            .last_commit()
            .await
            .map_err(|never| match never {})
    }
}

type ScriptedManager<A = RosterAuth> =
    SessionManager<SeedSnapshot, A, ConnettoDefaults, NoConnector, ScriptedOplog>;

/// Open a session on the scripted manager, printing the error it ends with, and read the ack.
async fn open_scripted(manager: &Arc<ScriptedManager>, resume: Cursor) -> LoopbackTransport {
    open_scripted_as(manager, "client-a", resume).await
}

/// [`open_scripted`] as the caller `name`.
async fn open_scripted_as(
    manager: &Arc<ScriptedManager>,
    name: &str,
    resume: Cursor,
) -> LoopbackTransport {
    let (server_transport, mut client) = loopback();
    let server = Arc::clone(manager);
    tokio::spawn(async move {
        if let Err(err) = server.serve(server_transport).await {
            eprintln!("session ended with an error: {err}");
        }
    });
    let handshake = Handshake::new(PROTOCOL_VERSION, name)
        .with_grant(connetto_core::messages::Grant::new(format!("user:{name}")))
        .with_cursor(resume)
        .with_cursor_subjects(core::iter::empty::<&str>());
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    // The server leads every connection with a challenge a person ignores (R91).
    let ControlMessage::Challenge(_) = next_control(&mut client).await else {
        panic!("expected the leading challenge");
    };
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };
    client
}

/// A manager on a scripted log holding three matching orders, their events, and the source that wrote them.
async fn scripted(
    fixture: &Fixture,
    config: SessionConfig,
) -> (
    Arc<ScriptedManager>,
    Arc<std::sync::Mutex<Script>>,
    Vec<PgChangeEvent>,
    PgSqliteEmuSource,
) {
    scripted_for(fixture, config, &["client-a"]).await
}

/// [`scripted`] granting every caller in `names`.
async fn scripted_for(
    fixture: &Fixture,
    config: SessionConfig,
    names: &[&str],
) -> (
    Arc<ScriptedManager>,
    Arc<std::sync::Mutex<Script>>,
    Vec<PgChangeEvent>,
    PgSqliteEmuSource,
) {
    let roster = names[1..]
        .iter()
        .fold(RosterAuth::granting(names[0]), |roster, name| {
            roster.and(*name)
        });
    scripted_with_auth(fixture, config, roster, PG_DDL).await
}

async fn scripted_with_auth<A>(
    fixture: &Fixture,
    config: SessionConfig,
    auth: A,
    ddl: &str,
) -> (
    Arc<ScriptedManager<A>>,
    Arc<std::sync::Mutex<Script>>,
    Vec<PgChangeEvent>,
    PgSqliteEmuSource,
)
where
    A: VisibilityPolicy<Watcher = Arc<connetto_core::Principal>, Backend = Postgres>
        + Send
        + Sync
        + 'static,
    A::Error: core::fmt::Display + connetto_server::FailedAuthorization,
{
    let script = Arc::new(std::sync::Mutex::new(Script::default()));
    let manager = ManagerBuilder::new(
        Materializer::builder(ddl)
            .build()
            .expect("build materializer"),
        SeedSnapshot,
        auth,
        test_verifier(),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), ddl)
            .expect("build write target"),
    )
    .with_oplog(ScriptedOplog {
        inner: InMemoryOplog::new(OplogConfig::default()),
        script: Arc::clone(&script),
    })
    .with_session(config)
    .build();
    let mut source = PgSqliteEmuSource::open_in_memory(ddl).expect("open emu source");
    let mut events = Vec::new();
    for id in 1..=3 {
        let sql = format!(
            "INSERT INTO orders (id, price, quantity, status) VALUES ({id}, 1.0, {id}, 'row')"
        );
        events.extend(drive(&mut source, &manager, &sql).await);
    }
    (manager, script, events, source)
}

/// Arm `script` to refuse `reads` in order.
fn arm(
    script: &std::sync::Mutex<Script>,
    reads: &[&'static str],
    transient: bool,
    prune_through: Option<PgCommitPosition>,
) {
    let mut script = script.lock().expect("script");
    script.refuse = reads.iter().copied().collect();
    script.transient = transient;
    script.prune_through = prune_through;
    script.reads.clear();
    script.armed = true;
}

/// A database cut off for a moment during a resume, as a promotion does, delays the catchup rather than ending the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_resume_read_that_fails_for_a_moment_is_read_again() {
    let fixture = Fixture::acquire().await;
    let (manager, script, events, _source) = scripted(&fixture, SessionConfig::default()).await;
    let mut client = open_scripted(&manager, cursor_of(&events[0])).await;
    arm(
        &script,
        &[
            "min_position",
            "current_position",
            "current_position",
            "entries_since",
        ],
        true,
        None,
    );
    subscribe(&mut client).await;

    for event in &events[1..] {
        let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
            panic!("expected a catchup live patch");
        };
        assert_eq!(live.cursor, cursor_of(event));
    }
    let script = script.lock().expect("script");
    assert!(script.refuse.is_empty(), "every scripted refusal was met");
    assert_eq!(
        script.reads,
        [
            "min_position",
            "min_position",
            "current_position",
            "current_position",
            "current_position",
            "current_position",
            "entries_since",
            "entries_since",
            "min_position",
        ],
        "the decision's two reads, the replay's ceiling and entries, each read again once, then the retention check"
    );
}

/// Retention moving past the cursor while a read waits turns the catchup into a resync, never a replay with a hole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_catchup_whose_entries_were_pruned_while_it_waited_resyncs() {
    let fixture = Fixture::acquire().await;
    let (manager, script, events, _source) = scripted(&fixture, SessionConfig::default()).await;
    let mut client = open_scripted(&manager, cursor_of(&events[0])).await;
    let second = events[1].checkpoint().expect("a checkpoint");
    arm(&script, &["entries_since"], true, Some(second));
    subscribe(&mut client).await;

    let ControlMessage::FullResyncRequired(resync) = next_control(&mut client).await else {
        panic!("expected a resync rather than a replay with a hole");
    };
    assert_eq!(resync.reason, FullResyncReason::CursorOutsideRetention);
}

/// A session that ends on an error releases its connection like any other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_ended_by_an_error_leaves_no_connection_registered() {
    let fixture = Fixture::acquire().await;
    let (manager, script, events, _source) = scripted(&fixture, SessionConfig::default()).await;
    let mut client = open_scripted(&manager, cursor_of(&events[0])).await;
    assert_eq!(manager.live_connections().await, 1);
    arm(&script, &["min_position"], false, None);
    subscribe(&mut client).await;

    let ended = tokio::time::timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("the session ends");
    assert!(
        matches!(ended, Ok(None)),
        "the transport ends, got {ended:?}"
    );
    assert_eq!(manager.live_connections().await, 0);
}

/// One connection's wait on the reconnect log is bounded however many subscriptions it resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_shares_one_wait_budget_across_its_subscriptions() {
    const BUDGET: Duration = Duration::from_secs(2);
    let fixture = Fixture::acquire().await;
    let config = SessionConfig::default().with_resume_read_budget(BUDGET);
    let (manager, script, events, _source) = scripted(&fixture, config).await;
    let mut client = open_scripted(&manager, cursor_of(&events[0])).await;
    let started = tokio::time::Instant::now();

    // Three jittered waits spend between 0.7 s and 1.4 s of the budget, and the catchup still arrives.
    arm(
        &script,
        &["min_position", "min_position", "min_position"],
        true,
        None,
    );
    subscribe(&mut client).await;
    for event in &events[1..] {
        let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
            panic!("expected a catchup live patch");
        };
        assert_eq!(live.cursor, cursor_of(event));
    }

    // The first catchup's completion left queued behind its rows.
    let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
        panic!("expected the first catchup's completion");
    };

    // The second subscription's reads keep failing, so only what is left of the budget stands before the end.
    arm(&script, &["min_position"; 64], true, None);
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders-again".to_owned(),
            spec: SubscriptionSpec::new(QUERY),
        }))
        .await
        .expect("send the second subscribe");
    let ended = tokio::time::timeout(Duration::from_secs(10), client.recv())
        .await
        .expect("the session ends");
    assert!(
        matches!(ended, Ok(None)),
        "the transport ends, got {ended:?}"
    );
    let waited = started.elapsed();
    assert!(
        waited < BUDGET + Duration::from_millis(500),
        "the connection waited {waited:?} on the log, past its budget of {BUDGET:?}"
    );
}

/// A change that goes live while a resume is still replaying older entries is delivered after them, and the replay does not end the connection for trailing the cursor the live change already moved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_that_goes_live_during_a_replay_follows_it() {
    let fixture = Fixture::acquire().await;
    let (manager, script, events, mut source) = scripted(&fixture, SessionConfig::default()).await;
    let mut client = open_scripted(&manager, cursor_of(&events[0])).await;
    let (arrived, release) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    script.lock().expect("script").holds.push_back((
        Arc::clone(&arrived),
        Arc::clone(&release),
        None,
    ));
    subscribe(&mut client).await;

    // The route stands and the ceiling is read by the time the replay asks for its entries.
    arrived.notified().await;
    let live = drive(
        &mut source,
        &manager,
        "INSERT INTO orders (id, price, quantity, status) VALUES (4, 1.0, 4, 'row')",
    )
    .await;
    release.notify_one();

    for event in &events[1..] {
        let BulkMessage::LivePatch(patch) = next_bulk(&mut client).await else {
            panic!("expected the replay and then the live change");
        };
        assert_eq!(patch.cursor, cursor_of(event));
    }
    // The replay's completion leaves before the queued live change.
    let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
        panic!("expected the replay's completion before the live change");
    };
    let BulkMessage::LivePatch(patch) = next_bulk(&mut client).await else {
        panic!("expected the live change after the replay");
    };
    assert_eq!(patch.cursor, cursor_of(&live[0]));
    expect_idle(&mut client).await;
}

async fn expect_catchup_end<T: Transport>(client: &mut T, sub_id: &str) {
    let ControlMessage::SnapshotEnd(end) = next_control_bounded(client).await else {
        panic!("expected the catchup completion");
    };
    assert_eq!(end.sub_id, sub_id);
}

/// Read the live patches `client` receives for `expected`, in order.
async fn expect_patches(client: &mut LoopbackTransport, expected: &[PgChangeEvent]) {
    for event in expected {
        let BulkMessage::LivePatch(patch) = next_bulk(client).await else {
            panic!("expected a catchup live patch");
        };
        assert_eq!(patch.cursor, cursor_of(event));
    }
    expect_catchup_end(client, "orders").await;
    expect_idle(client).await;
}

/// Resumes that arrive while a catchup walks the log wait for that walk to end and then share one walk of the log, each receiving exactly what it missed, and one of them closing meanwhile leaves the others served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resumes_arriving_during_a_walk_share_the_next_one() {
    let fixture = Fixture::acquire().await;
    let names = ["client-a", "client-b", "client-c", "client-d"];
    let (manager, script, events, _source) =
        scripted_for(&fixture, SessionConfig::default(), &names).await;
    let (arrived, release) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    arm(&script, &[], true, None);
    script.lock().expect("script").holds.push_back((
        Arc::clone(&arrived),
        Arc::clone(&release),
        None,
    ));

    let mut a = open_scripted_as(&manager, "client-a", cursor_of(&events[0])).await;
    subscribe(&mut a).await;
    failures::page_arrived(&arrived).await;

    let mut b = failures::wave_client(&manager, &script, "client-b", cursor_of(&events[0])).await;
    b.subscribe(QUERY).await;
    let mut c = failures::wave_client(&manager, &script, "client-c", cursor_of(&events[1])).await;
    c.subscribe(QUERY).await;
    let mut d = failures::wave_client(&manager, &script, "client-d", cursor_of(&events[0])).await;
    d.subscribe(QUERY).await;
    d.close().await;
    release.notify_one();

    expect_patches(&mut a, &events[1..]).await;
    expect_patches(&mut b.transport, &events[1..]).await;
    expect_patches(&mut c.transport, &events[2..]).await;
    let walks = {
        let script = script.lock().expect("script");
        script
            .reads
            .iter()
            .filter(|read| **read == "entries_since")
            .count()
    };
    assert_eq!(
        walks, 2,
        "the first resume's walk, then one walk shared by the three that arrived during it"
    );
}

/// Retention passing one resume's cursor while it waits for a walk replaces that subscription alone, and the resume sharing its walk still catches up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shared_walk_resyncs_only_the_resume_retention_passed() {
    let fixture = Fixture::acquire().await;
    let names = ["client-a", "client-b", "client-c"];
    let (manager, script, mut events, mut source) =
        scripted_for(&fixture, SessionConfig::default(), &names).await;
    events.extend(
        drive(
            &mut source,
            &manager,
            "INSERT INTO orders (id, price, quantity, status) VALUES (4, 1.0, 4, 'row')",
        )
        .await,
    );
    let (arrived, release) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    // The held walk's read is refused once, and the log is pruned through the second change meanwhile.
    let second = events[1].checkpoint().expect("a checkpoint");
    arm(&script, &["entries_since"], true, Some(second));
    script.lock().expect("script").holds.push_back((
        Arc::clone(&arrived),
        Arc::clone(&release),
        None,
    ));

    let mut a = open_scripted_as(&manager, "client-a", cursor_of(&events[2])).await;
    subscribe(&mut a).await;
    failures::page_arrived(&arrived).await;
    let mut b = failures::wave_client(&manager, &script, "client-b", cursor_of(&events[0])).await;
    b.subscribe(QUERY).await;
    let mut c = failures::wave_client(&manager, &script, "client-c", cursor_of(&events[2])).await;
    c.subscribe(QUERY).await;
    release.notify_one();

    expect_patches(&mut a, &events[3..]).await;
    let ControlMessage::FullResyncRequired(resync) = next_control(&mut b.transport).await else {
        panic!("expected the resume whose changes were pruned to be replaced");
    };
    assert_eq!(resync.reason, FullResyncReason::CursorOutsideRetention);
    expect_patches(&mut c.transport, &events[3..]).await;
}

/// Its own log table, shared by the manager before the restart and the one after it.
const RESTART_OPLOG: &str = "connetto_oplog_restart";

type RestartManager =
    SessionManager<SeedSnapshot, RosterAuth, ConnettoDefaults, NoConnector, PgOplog>;

/// A manager over the existing restart log table, as a restarted process builds it.
fn restarted_manager(fixture: &Fixture) -> Arc<RestartManager> {
    ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .build()
            .expect("build materializer"),
        SeedSnapshot,
        RosterAuth::granting("client-a").withholding(WITHHELD_ID),
        test_verifier(),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    )
    .with_oplog(PgOplog::new(
        fixture.admin().clone(),
        RESTART_OPLOG,
        OplogConfig::default(),
    ))
    .build()
}

/// Open a session on a restart manager resuming at `resume`, returning the client half once the ack arrived.
async fn open_restarted_session(
    manager: &Arc<RestartManager>,
    resume: Cursor,
) -> LoopbackTransport {
    let (server_transport, mut client) = loopback();
    let server = manager.clone();
    tokio::spawn(async move {
        server.serve(server_transport).await.expect("session ok");
    });
    let handshake = Handshake::new(PROTOCOL_VERSION, "client-a")
        .with_grant(connetto_core::messages::Grant::new(
            "user:client-a".to_owned(),
        ))
        .with_cursor(resume)
        .with_cursor_subjects(core::iter::empty::<&str>());
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    // The server leads every connection with a challenge a person ignores (R91).
    let ControlMessage::Challenge(_) = next_control(&mut client).await else {
        panic!("expected the leading challenge");
    };
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };
    client
}

/// After a restart the slot re-delivers rows the durable log already holds. A client that caught up from the log first is past them, and the feed skips them for that client instead of stopping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_feed_replaying_rows_a_caught_up_client_holds_keeps_running() {
    let fixture = Fixture::acquire().await;
    fixture
        .setup(&[
            &format!("DROP TABLE IF EXISTS {RESTART_OPLOG}"),
            &format!(
                "DROP TABLE IF EXISTS {}",
                PgOplog::commit_table(RESTART_OPLOG)
            ),
        ])
        .await;
    PgOplog::new(
        fixture.admin().clone(),
        RESTART_OPLOG,
        OplogConfig::default(),
    )
    .ensure_schema()
    .await
    .expect("provision the log");

    // Four inserts reach the log, and the process stops before any is acknowledged.
    let before = restarted_manager(&fixture);
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    let mut events = Vec::new();
    for id in 1..=4 {
        events.extend(
            drive(
                &mut source,
                &before,
                &format!(
                    "INSERT INTO orders (id, price, quantity, status) VALUES ({id}, 1.0, 2, 'paid')"
                ),
            )
            .await,
        );
    }
    drop(before);

    // A client synced through the second insert reconnects to the restarted process and catches up from the log.
    let after = restarted_manager(&fixture);
    let mut client = open_restarted_session(&after, cursor_of(&events[1])).await;
    subscribe(&mut client).await;
    for event in &events[2..] {
        let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
            panic!("expected a catchup live patch");
        };
        assert_eq!(
            live.cursor,
            cursor_of(event),
            "catchup replays the log in order"
        );
    }
    let held = cursor_of(&events[3]);

    // The log's replay completes before the restarted feed's re-delivery reaches the client.
    let ControlMessage::SnapshotEnd(end) = next_control(&mut client).await else {
        panic!("expected the catchup completion");
    };
    assert_eq!(
        end.cursor, held,
        "the completion names the last row the client holds"
    );

    // The restarted feed re-delivers every unacknowledged insert, then a new one.
    for (index, event) in events.iter().enumerate() {
        after
            .dispatch_event(event)
            .await
            .unwrap_or_else(|err| panic!("re-delivering insert {index} stopped the feed: {err}"));
    }
    let fresh = drive(
        &mut source,
        &after,
        "INSERT INTO orders (id, price, quantity, status) VALUES (5, 1.0, 2, 'paid')",
    )
    .await;
    let fresh = cursor_of(&fresh[0]);

    loop {
        let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
            panic!("expected a live patch");
        };
        assert!(
            live.cursor.as_bytes() >= held.as_bytes(),
            "a row the client already holds came back at {:?}",
            live.cursor
        );
        if live.cursor == fresh {
            break;
        }
    }
    expect_idle(&mut client).await;
}

/// A snapshot source serving the one seed row under a cursor the test sets once it knows the positions.
#[derive(Clone, Default)]
struct FencedSeed {
    cursor: Arc<parking_lot::Mutex<Vec<u8>>>,
}

impl SnapshotSource for FencedSeed {
    type Error = std::convert::Infallible;

    async fn estimate(
        &self,
        select_sql: &str,
        binds: &[connetto_core::messages::BindValue],
        caller: &connetto_core::Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        SeedSnapshot.estimate(select_sql, binds, caller).await
    }

    async fn snapshot_page(
        &self,
        select_sql: &str,
        binds: &[connetto_core::messages::BindValue],
        auth: &connetto_core::Principal,
        page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        let seed = SeedSnapshot
            .snapshot_page(select_sql, binds, auth, page)
            .await?;
        Ok(SnapshotPage {
            cursor: Cursor::new(self.cursor.lock().clone()),
            ..seed
        })
    }
}

type FencedManager = SessionManager<FencedSeed, RosterAuth, ConnettoDefaults>;

fn fenced_manager(fixture: &Fixture, seed: FencedSeed) -> Arc<FencedManager> {
    ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .build()
            .expect("build materializer"),
        seed,
        RosterAuth::granting("client-a").withholding(WITHHELD_ID),
        test_verifier(),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    )
    .build()
}

/// Open a session on a fenced manager, presenting `resume` when given.
async fn open_fenced_session(
    manager: &Arc<FencedManager>,
    resume: Option<Cursor>,
) -> LoopbackTransport {
    let (server_transport, mut client) = loopback();
    let server = manager.clone();
    tokio::spawn(async move {
        server.serve(server_transport).await.expect("session ok");
    });
    let mut handshake = Handshake::new(PROTOCOL_VERSION, "client-a").with_grant(
        connetto_core::messages::Grant::new("user:client-a".to_owned()),
    );
    if let Some(cursor) = resume {
        handshake = handshake
            .with_cursor(cursor)
            .with_cursor_subjects(core::iter::empty::<&str>());
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    // The server leads every connection with a challenge a person ignores (R91).
    let ControlMessage::Challenge(_) = next_control(&mut client).await else {
        panic!("expected the leading challenge");
    };
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };
    client
}

/// `position` stamped the way a never-promoted database's server stamps it, with `fence` after it.
fn fenced_cursor(position: PgCommitPosition, fence: Option<&ReadFence>) -> Cursor {
    Cursor::new(
        Position {
            system: TimelineHistory::default().system(),
            timeline: 1,
            at: position,
        }
        .fenced_cursor_bytes(fence),
    )
}

/// One insert of order `id`, as the emulator stamps it.
async fn insert(source: &mut PgSqliteEmuSource, id: i64) -> PgChangeEvent {
    source
        .execute_sql(&format!(
            "INSERT INTO orders (id, price, quantity, status) VALUES ({id}, 1.0, 2, 'paid')"
        ))
        .expect("execute dml");
    let mut events = Vec::new();
    while let Some(item) = source.next_item().await.expect("poll source") {
        if let SourceItem::Event(event) = item {
            events.push(event);
        }
    }
    let [event] = <[PgChangeEvent; 1]>::try_from(events).expect("one row per insert");
    event
}

/// A transaction flushed before the snapshot's read but not yet visible to it, dispatched before the subscription existed, follows the snapshot under the snapshot's own fenced cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_snapshot_replays_a_transaction_it_missed_that_was_dispatched_before_it() {
    let fixture = Fixture::acquire().await;
    let seed = FencedSeed::default();
    let manager = fenced_manager(&fixture, seed.clone());
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    let held = insert(&mut source, 1).await;
    let missed = insert(&mut source, 2).await;
    manager.dispatch_event(&held).await.expect("dispatch");
    manager.dispatch_event(&missed).await.expect("dispatch");

    // The read sees the first transaction and not the second, which is still running.
    let after = PgLsn(missed.position().commit_lsn().0 + 1);
    let (held_xid, missed_xid) = (held.position().xid().0, missed.position().xid().0);
    let fence = ReadFence::parse(
        &format!("{held_xid}:{}:{missed_xid}", missed_xid + 1),
        after,
    )
    .expect("fence");
    *seed.cursor.lock() =
        connetto_server::snapshot_cursor(PgCommitPosition::before_commit(after), Some(&fence));

    let mut client = open_fenced_session(&manager, None).await;
    subscribe(&mut client).await;
    let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    let mut replica = client_replica();
    let applier = Materializer::builder(PG_DDL)
        .build()
        .expect("build applier");
    let BulkMessage::SnapshotPatch(page) = next_bulk(&mut client).await else {
        panic!("expected the seed page");
    };
    applier
        .apply_diffset(&page.patchset_zstd, &mut replica)
        .expect("apply the seed page");
    let ControlMessage::SnapshotEnd(end) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };
    let snapshot_cursor = fenced_cursor(PgCommitPosition::before_commit(after), Some(&fence));
    assert_eq!(
        end.cursor, snapshot_cursor,
        "the snapshot's cursor names its read and carries its fence"
    );
    let frame = tokio::time::timeout(Duration::from_secs(10), next_bulk(&mut client))
        .await
        .expect("the missed transaction follows the snapshot");
    let BulkMessage::LivePatch(live) = frame else {
        panic!("expected the missed transaction as a live patch");
    };
    assert_eq!(
        live.cursor, snapshot_cursor,
        "under the snapshot's own cursor, so resuming from it replays the row again"
    );
    applier
        .apply_diffset(&live.patchset_zstd, &mut replica)
        .expect("apply the missed transaction");
    assert_eq!(
        orders(&mut replica)
            .iter()
            .map(|row| row.id)
            .collect::<Vec<_>>(),
        vec![1, 2],
        "the missed transaction's row joins the seed"
    );
    expect_idle(&mut client).await;
}

/// A client resuming from a snapshot's fenced cursor catches up on what the snapshot missed and skips what it held, and a missed transaction dispatched later still reaches it below its cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fenced_cursor_catches_up_what_its_snapshot_missed_and_nothing_it_held() {
    let fixture = Fixture::acquire().await;
    let manager = fenced_manager(&fixture, FencedSeed::default());
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    let mut events = Vec::new();
    for id in 1..=5 {
        events.push(insert(&mut source, id).await);
    }
    let [held_below, missed_below, held_above, beyond, late] =
        <[PgChangeEvent; 5]>::try_from(events).expect("five inserts");
    // The fifth insert stands for a transaction the snapshot missed that commits below the fourth.
    let xid = |event: &PgChangeEvent| event.position().xid().0;
    let late = PgChangeEvent::new(
        late.into_change(),
        PgCommitPosition::new(
            PgLsn(held_above.position().commit_lsn().0 + 1),
            PgXid(xid(&beyond) + 1),
            1,
        ),
    );
    for event in [&held_below, &missed_below, &held_above, &beyond] {
        manager.dispatch_event(event).await.expect("dispatch");
    }

    // The read ran between the second and third commits, missing the second and the late one, and its insert position is the fourth commit.
    let read = PgCommitPosition::before_commit(PgLsn(missed_below.position().commit_lsn().0 + 1));
    let fence = ReadFence::parse(
        &format!(
            "{}:{}:{},{}",
            xid(&held_below),
            xid(&beyond) + 2,
            xid(&missed_below),
            xid(&beyond) + 1
        ),
        beyond.position().commit_lsn(),
    )
    .expect("fence");
    let mut client = open_fenced_session(&manager, Some(fenced_cursor(read, Some(&fence)))).await;
    subscribe(&mut client).await;
    for event in [&missed_below, &beyond] {
        let BulkMessage::LivePatch(live) = next_bulk(&mut client).await else {
            panic!("expected a catchup live patch");
        };
        assert_eq!(
            live.cursor,
            cursor_of(event),
            "catchup replays only what the snapshot lacked"
        );
    }
    let ControlMessage::SnapshotEnd(end) = next_control_bounded(&mut client).await else {
        panic!("expected catchup completion");
    };
    assert_eq!(end.sub_id, "orders");
    assert_eq!(end.cursor, cursor_of(&beyond));
    expect_idle(&mut client).await;

    manager
        .dispatch_event(&late)
        .await
        .expect("dispatch the late transaction");
    let late_patch = tokio::time::timeout(Duration::from_secs(10), next_bulk(&mut client))
        .await
        .expect("the late missed transaction is delivered below the cursor");
    let BulkMessage::LivePatch(live) = late_patch else {
        panic!("expected a live patch");
    };
    assert_eq!(live.cursor, cursor_of(&late));
    manager
        .dispatch_event(&held_above)
        .await
        .expect("re-deliver a held transaction");
    expect_idle(&mut client).await;
}
