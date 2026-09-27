//! Reconnect and oplog end-to-end tests (Phase 5).
//!
//! Drives a sequence of CDC events through the manager (which records them in an
//! in-memory oplog), then reconnects a client whose resume cursor sits at a
//! chosen point and asserts the catchup-versus-full-resync behaviour:
//!
//! * within the retained window: the client receives exactly the entries after
//!   its cursor as `LivePatch`, and its replica reaches row parity;
//! * outside the window (after a prune): the client receives
//!   `FullResyncRequired { CursorOutsideRetention }` followed by a fresh
//!   snapshot;
//! * a delete replays as a tombstone so the client drops the row.
//!
//! Reads and seeds go through typed diesel queries, matching the other tests;
//! DML against the emulated backend stays as SQL strings.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{
    BulkMessage, ControlMessage, FullResyncReason, Handshake, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{HandshakeAuthority, IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    ChangeRecord, InMemoryOplog, LoopbackTransport, Materializer, NoConnector, NoSigner, Oplog,
    OplogConfig, PageSpec, Position, RequestGuard, SessionConfig, SessionManager, SnapshotEstimate,
    SnapshotPage, SnapshotSource, TimelineHistory, loopback, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};
use diesel::prelude::*;
use diesel::sql_query;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use subql::backend::{CdcEvent, Postgres};
use subql::visibility::VisibilityPolicy;
use subql::{CdcSource, PgChangeEvent, PgCommit, PgCommitPosition, PgSqliteEmuSource, SourceItem};

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

/// Execute `sql` against the emulated backend, route every resulting event
/// through the manager (which appends to the oplog), and return the events.
/// The emulator stamps monotonic LSNs, which the LSN-keyed oplog relies on.
async fn drive<A, O>(
    source: &mut PgSqliteEmuSource,
    manager: &SessionManager<SeedSnapshot, A, ConnettoWatermark, NoConnector, O>,
    sql: &str,
) -> Vec<PgChangeEvent>
where
    A: VisibilityPolicy<Watcher = Arc<connetto_core::auth::Principal>, Backend = Postgres>,
    A::Error: core::fmt::Display,
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
    manager: &Arc<SessionManager<SeedSnapshot, A, ConnettoWatermark>>,
    client_id: &str,
    resume: Option<Cursor>,
) -> (LoopbackTransport, tokio::task::JoinHandle<()>)
where
    A: VisibilityPolicy<Watcher = Arc<connetto_core::auth::Principal>, Backend = Postgres>
        + Send
        + Sync
        + 'static,
    A::Error: core::fmt::Display + Send,
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
        handshake = handshake.with_cursor(cursor);
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catchup_within_window_streams_missed_ops() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        RosterAuth::granting("client-a").withholding(WITHHELD_ID),
        test_verifier(),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

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
    drive(
        &mut source,
        &manager,
        &format!("INSERT INTO orders (id, price, quantity, status) VALUES ({WITHHELD_ID}, 1.0, 1, 'withheld')"),
    )
    .await;
    assert_eq!(events.len(), 5, "one CDC event per statement");

    // Build the client's replica as of the second event (the synced prefix).
    let applier = Materializer::new(PG_DDL).expect("build applier");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cursor_outside_window_forces_full_resync() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    // A tiny window: after four inserts the oldest two are pruned.
    let oplog = InMemoryOplog::new(
        OplogConfig::new()
            .with_max_entries(2)
            .with_max_age(Duration::from_secs(72 * 60 * 60)),
    );
    let manager = SessionManager::with_oplog(
        materializer,
        SeedSnapshot,
        RosterAuth::granting("client-a").withholding(WITHHELD_ID),
        test_verifier(),
        NoConnector,
        oplog,
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
        None,
        NoSigner,
    );

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
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        SeedSnapshot,
        RosterAuth::granting("client-a").withholding(WITHHELD_ID),
        test_verifier(),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

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
    drive(
        &mut source,
        &manager,
        &format!("INSERT INTO orders (id, price, quantity, status) VALUES ({WITHHELD_ID}, 1.0, 1, 'withheld')"),
    )
    .await;
    assert_eq!(events.len(), 2);

    // The client synced through the insert and holds the row locally.
    let applier = Materializer::new(PG_DDL).expect("build applier");
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
    /// Holds the next entries read until the test releases it, telling the test it arrived.
    hold: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
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
        let hold = self.script.lock().expect("script").hold.take();
        if let Some((arrived, release)) = hold {
            arrived.notify_one();
            release.notified().await;
        }
        self.gate("entries_since").await?;
        self.inner
            .entries_since(after)
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

type ScriptedManager =
    SessionManager<SeedSnapshot, RosterAuth, ConnettoWatermark, NoConnector, ScriptedOplog>;

/// Open a session on the scripted manager, printing the error it ends with, and read the ack.
async fn open_scripted(manager: &Arc<ScriptedManager>, resume: Cursor) -> LoopbackTransport {
    let (server_transport, mut client) = loopback();
    let server = Arc::clone(manager);
    tokio::spawn(async move {
        if let Err(err) = server.serve(server_transport).await {
            eprintln!("session ended with an error: {err}");
        }
    });
    let handshake = Handshake::new(PROTOCOL_VERSION, "client-a")
        .with_grant(connetto_core::messages::Grant::new(
            "user:client-a".to_owned(),
        ))
        .with_cursor(resume);
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
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
    let script = Arc::new(std::sync::Mutex::new(Script::default()));
    let manager = SessionManager::with_oplog(
        Materializer::new(PG_DDL).expect("build materializer"),
        SeedSnapshot,
        RosterAuth::granting("client-a"),
        test_verifier(),
        NoConnector,
        ScriptedOplog {
            inner: InMemoryOplog::new(OplogConfig::default()),
            script: Arc::clone(&script),
        },
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        config,
        None,
        NoSigner,
    );
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
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
    script.lock().expect("script").hold = Some((Arc::clone(&arrived), Arc::clone(&release)));
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

    for event in events[1..].iter().chain(&live) {
        let BulkMessage::LivePatch(patch) = next_bulk(&mut client).await else {
            panic!("expected the replay and then the live change");
        };
        assert_eq!(patch.cursor, cursor_of(event));
    }
    expect_idle(&mut client).await;
}
