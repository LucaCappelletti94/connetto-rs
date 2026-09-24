//! R73: a standby promoted under a running server, seen from its clients.
//!
//! The primary commits rows the cut-off standby never receives, a live client is sent them, then the standby is promoted and the server's address moves to it.
//!
//! Needs Docker. The pair runs Postgres 18.

#![expect(
    clippy::too_many_lines,
    reason = "the test walks one failover in order and a split would hide the sequence"
)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{
    BulkMessage, ControlMessage, FatalErrorReason, FullResyncReason, Grant, Handshake, Subscribe,
    SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    LoopbackTransport, Materializer, NoConnector, NoSigner, Oplog, OplogConfig, PgOplog,
    PgSnapshotSource, Position, ReconnectPolicy, RequestGuard, SessionConfig, SessionManager,
    TimelineHistory, loopback, pg_write_target, timeline,
};
use connetto_test_harness::Fixture;
use connetto_test_harness::standby::{Pair, Switchboard};
use connetto_test_harness::{
    ConnettoWatermark, OPLOG_TABLE, PUBLICATION, RosterAuth, SLOT, WITHHELD_ID, exec, pool_for,
    provision_watermark,
};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use sqlite_diff_rs::{ParsedDiffSet, PatchsetOp, Value};
use sqlparser::dialect::PostgreSqlDialect;
use subql::{ParserDB, PgStreamingCdcSource, PgStreamingConfig};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const QUERY: &str = "SELECT * FROM orders";
const CALLER: &str = "reader";
const SUB: &str = "orders";

/// How long any one expected frame or database state is given.
const WAIT: Duration = Duration::from_secs(120);

type Manager = SessionManager<
    PgSnapshotSource,
    RosterAuth,
    ConnettoWatermark,
    NoConnector,
    PgOplog,
    String,
    String,
    NoSigner,
>;

async fn next_frame(client: &mut LoopbackTransport, what: &str) -> IncomingFrame {
    tokio::time::timeout(WAIT, client.recv())
        .await
        .unwrap_or_else(|_| panic!("no frame within {WAIT:?} while waiting for {what}"))
        .expect("recv")
        .unwrap_or_else(|| panic!("the connection closed while waiting for {what}"))
}

/// The order ids a patch inserts or updates.
fn ids(patchset_zstd: &[u8]) -> BTreeSet<i64> {
    let bytes = zstd::decode_all(patchset_zstd).expect("decompress");
    let Ok(ParsedDiffSet::Patchset(set)) = ParsedDiffSet::parse(&bytes) else {
        return BTreeSet::new();
    };
    set.iter()
        .filter_map(|op| match op {
            PatchsetOp::Insert { values, .. } | PatchsetOp::Update { pk: values, .. } => {
                match values.first() {
                    Some(Value::Integer(id)) => Some(*id),
                    _ => None,
                }
            }
            PatchsetOp::Delete { .. } => None,
        })
        .collect()
}

/// Open a session presenting `cursor` and subscribe to every order.
async fn connect(manager: &Arc<Manager>, cursor: Option<Cursor>) -> LoopbackTransport {
    let (server_end, mut client) = loopback();
    let serving = Arc::clone(manager);
    tokio::spawn(async move {
        let _ = serving.serve(server_end).await;
    });
    let mut handshake =
        Handshake::new(PROTOCOL_VERSION, CALLER).with_grant(Grant::new(format!("user:{CALLER}")));
    if let Some(cursor) = cursor {
        handshake = handshake.with_cursor(cursor);
    }
    client
        .send_control(ControlMessage::Handshake(handshake))
        .await
        .expect("send handshake");
    let IncomingFrame::Control(ControlMessage::HandshakeAck(_)) =
        next_frame(&mut client, "the handshake ack").await
    else {
        panic!("expected a handshake ack");
    };
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: SUB.to_owned(),
            spec: SubscriptionSpec::new(QUERY),
        }))
        .await
        .expect("send subscribe");
    client
}

/// Read one snapshot through its end, returning the resync reason ahead of it and the ids it carried.
async fn snapshot(client: &mut LoopbackTransport) -> (Option<FullResyncReason>, BTreeSet<i64>) {
    let mut reason = None;
    let mut rows = BTreeSet::new();
    loop {
        match next_frame(client, "the snapshot").await {
            IncomingFrame::Control(ControlMessage::FullResyncRequired(resync)) => {
                reason = Some(resync.reason);
            }
            IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch)) => {
                rows.extend(ids(&patch.patchset_zstd));
            }
            IncomingFrame::Control(ControlMessage::SnapshotEnd(_)) => return (reason, rows),
            IncomingFrame::Control(_) => {}
            IncomingFrame::Bulk(other) => panic!("expected a snapshot, got {other:?}"),
        }
    }
}

/// Wait for the live patch carrying order `id`, returning its cursor.
async fn live(client: &mut LoopbackTransport, id: i64) -> Cursor {
    loop {
        match next_frame(client, &format!("the live patch for order {id}")).await {
            IncomingFrame::Bulk(BulkMessage::LivePatch(patch)) => {
                if ids(&patch.patchset_zstd).contains(&id) {
                    return patch.cursor;
                }
            }
            IncomingFrame::Control(
                ControlMessage::FullResyncRequired(_)
                | ControlMessage::SnapshotBegin(_)
                | ControlMessage::SnapshotEnd(_),
            ) => panic!("a resuming cursor inside the window must not resync"),
            IncomingFrame::Control(ControlMessage::FatalError(fatal)) => panic!(
                "the connection closed with {:?} while waiting for order {id}",
                fatal.reason
            ),
            IncomingFrame::Control(_) | IncomingFrame::Bulk(_) => {}
        }
    }
}

/// Wait for the connection to be closed, returning why.
async fn closed(client: &mut LoopbackTransport) -> FatalErrorReason {
    loop {
        if let IncomingFrame::Control(ControlMessage::FatalError(fatal)) =
            next_frame(client, "the connection to close").await
        {
            return fatal.reason;
        }
    }
}

/// The orders table, the watermark and the reconnect log, returning the log's handle.
async fn provision(pool: &Pool<AsyncPgConnection>) -> PgOplog {
    exec(pool, PG_DDL).await;
    exec(pool, "ALTER TABLE orders REPLICA IDENTITY FULL").await;
    provision_watermark(pool).await;
    let oplog = PgOplog::new(pool.clone(), OPLOG_TABLE, OplogConfig::default());
    oplog.ensure_schema().await.expect("provision the oplog");
    oplog
}

fn manager_on(pool: &Pool<AsyncPgConnection>, oplog: PgOplog) -> Arc<Manager> {
    manager_writing_to(pool, pool.clone(), oplog)
}

/// A manager whose watermark reads go through `writes`, so a test can hold that pool.
fn manager_writing_to(
    pool: &Pool<AsyncPgConnection>,
    writes: Pool<AsyncPgConnection>,
    oplog: PgOplog,
) -> Arc<Manager> {
    SessionManager::with_oplog(
        Materializer::new(PG_DDL).expect("build materializer"),
        PgSnapshotSource::from_ddl(pool.clone(), PG_DDL).expect("snapshot source"),
        RosterAuth::granting(CALLER).withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        oplog,
        pg_write_target::<ConnettoWatermark>(writes, PG_DDL).expect("write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
        None,
        NoSigner,
    )
}

/// Timeline 2, which ended timeline 1 at `0/10`.
fn promoted_early() -> TimelineHistory {
    TimelineHistory::parse(
        TimelineHistory::default().system(),
        2,
        "1\t0/10\tno recovery target specified",
    )
    .expect("parse")
}

/// A cursor from before timelines were stamped is judged on the wire as one
/// the server cannot read, so the client is told to clear before the snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cursor_without_a_timeline_resyncs_with_a_clear() {
    let fixture = Fixture::acquire().await;
    let oplog = provision(fixture.admin()).await;
    let manager = manager_on(fixture.admin(), oplog);
    let mut client = connect(&manager, Some(Cursor::new(0x20_u64.to_be_bytes().to_vec()))).await;
    assert_eq!(
        snapshot(&mut client).await,
        (Some(FullResyncReason::CursorBeyondHistory), BTreeSet::new())
    );
}

/// A handshake already under way when the server reads a new history must be
/// judged against that history, since the close that follows the read can
/// run before the handshake registers and so miss it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handshake_under_way_meets_a_history_read_during_it() {
    let fixture = Fixture::acquire().await;
    let oplog = provision(fixture.admin()).await;
    let writes = Pool::builder()
        .max_size(1)
        .build(AsyncDieselConnectionManager::<AsyncPgConnection>::new(
            fixture.admin_url(),
        ))
        .await
        .expect("a one-connection write pool");
    let manager = manager_writing_to(fixture.admin(), writes.clone(), oplog);
    let held = writes.get().await.expect("hold the only write connection");
    let started = writes.state().statistics.get_started;

    let past_the_old_end = Position {
        system: TimelineHistory::default().system(),
        timeline: 1,
        lsn: 0x20,
    };
    let handshake = {
        let manager = Arc::clone(&manager);
        tokio::spawn(async move {
            connect(
                &manager,
                Some(Cursor::new(past_the_old_end.to_cursor_bytes())),
            )
            .await
        })
    };
    while writes.state().statistics.get_started == started {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    manager.reconcile_history(promoted_early()).await;
    drop(held);

    let mut client = handshake.await.expect("the handshake finishes");
    assert_eq!(
        snapshot(&mut client).await.0,
        Some(FullResyncReason::CursorBeyondHistory),
        "a verdict taken before the history read would catch up from a position the database lost"
    );
}

/// The first history a process reads is stored without a close, the same history again changes nothing, and a new timeline closes every live connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_changed_timeline_closes_live_connections() {
    let fixture = Fixture::acquire().await;
    let oplog = provision(fixture.admin()).await;
    let manager = manager_on(fixture.admin(), oplog);
    let mut client = connect(&manager, None).await;
    assert_eq!(snapshot(&mut client).await, (None, BTreeSet::new()));

    manager.reconcile_history(TimelineHistory::default()).await;
    manager.reconcile_history(TimelineHistory::default()).await;
    assert_eq!(
        manager.live_connections().await,
        1,
        "reading the timeline the server already serves closes nothing"
    );

    let promoted = TimelineHistory::parse(
        TimelineHistory::default().system(),
        2,
        "1\t0/3000000\tno recovery target specified",
    )
    .expect("parse");
    manager.reconcile_history(promoted).await;
    assert_eq!(
        closed(&mut client).await,
        FatalErrorReason::DatabaseTimelineChanged
    );
    assert_eq!(manager.live_connections().await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lossy_promotion_resyncs_the_lost_rows_and_resumes_the_rest() {
    let pair = Pair::start().await;
    let board = Switchboard::to(pair.primary_address().await).await;
    let url = board.url();
    let pool = pool_for(&url).await;
    let oplog = provision(&pool).await;
    exec(
        &pool,
        &format!("CREATE PUBLICATION {PUBLICATION} FOR TABLE orders"),
    )
    .await;
    // The fifth argument asks for a failover slot, the one a standby keeps in sync.
    exec(
        &pool,
        &format!(
            "SELECT pg_create_logical_replication_slot('{SLOT}', 'pgoutput', false, false, true)"
        ),
    )
    .await;

    let manager = manager_on(&pool, oplog);
    manager
        .reconcile_history(
            timeline::read_history(&url)
                .await
                .expect("read the timeline"),
        )
        .await;
    let policy = ReconnectPolicy::new()
        .with_initial_backoff(Duration::from_millis(100))
        .with_max_backoff(Duration::from_secs(1))
        .with_max_attempts(None)
        .with_healthy_after(Duration::from_secs(1));
    let ingest = {
        let (manager, url, pool) = (Arc::clone(&manager), url.clone(), pool.clone());
        tokio::spawn(async move {
            let connect = || {
                let (manager, url, pool) = (Arc::clone(&manager), url.clone(), pool.clone());
                async move {
                    let catalog = ParserDB::parse::<PostgreSqlDialect>(PG_DDL)
                        .map_err(|err| format!("{err:?}"))?;
                    manager
                        .reconcile_before_stream(&url, &pool, SLOT)
                        .await
                        .map_err(|err| err.to_string())?;
                    PgStreamingCdcSource::connect(
                        PgStreamingConfig::new(url, SLOT, PUBLICATION),
                        catalog,
                    )
                    .await
                    .map_err(|err| err.to_string())
                }
            };
            let _ = manager
                .ingest_with_reconnect(connect, &policy, |_| {})
                .await;
        })
    };

    let mut watcher = connect(&manager, None).await;
    assert_eq!(snapshot(&mut watcher).await, (None, BTreeSet::new()));

    exec(&pool, "INSERT INTO orders VALUES (1, 1.0, 1, 'replicated')").await;
    let replicated = live(&mut watcher, 1).await;
    // Order rows keep the slot's confirmed position behind the reconnect log, as ordinary traffic does, until the standby keeps a synchronized copy.
    let mut kept = BTreeSet::from([1]);
    let synced = pair.wait_slot_synced(SLOT);
    tokio::pin!(synced);
    for beat in 100.. {
        tokio::select! {
            () = &mut synced => break,
            () = tokio::time::sleep(Duration::from_secs(1)) => {
                exec(&pool, &format!("INSERT INTO orders VALUES ({beat}, 1.0, 1, 'beat')")).await;
                kept.insert(beat);
            }
        }
    }
    // The partition must not cut off a log row for a change the synced slot already covers,
    // or the promoted server rightly declares a gap and closes every connection.
    let last_beat = *kept.last().expect("at least the first order");
    let delivered = Position::from_cursor_bytes(live(&mut watcher, last_beat).await.as_bytes())
        .expect("a stamped cursor")
        .lsn;
    let log = PgOplog::new(pool.clone(), OPLOG_TABLE, OplogConfig::default());
    while log.current_lsn().await.expect("read the log") < Some(delivered) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    pair.wait_replayed(&pair.primary_position().await).await;

    pair.partition_standby().await;
    for id in 2..=4 {
        exec(
            &pool,
            &format!("INSERT INTO orders VALUES ({id}, 1.0, 1, 'lost')"),
        )
        .await;
    }
    let lost = live(&mut watcher, 4).await;

    pair.fail_over().await;
    board.point_at(pair.standby_address().await);

    assert_eq!(
        closed(&mut watcher).await,
        FatalErrorReason::DatabaseTimelineChanged,
        "a connection live through the promotion is closed so its cursor gets judged"
    );
    // Handshakes wait for the feed, so none races the promoted server's gap check.
    pair.wait_slot_active(SLOT).await;

    let mut returning = connect(&manager, Some(lost)).await;
    assert_eq!(
        snapshot(&mut returning).await,
        (Some(FullResyncReason::CursorBeyondHistory), kept),
        "a cursor past where the old timeline ended is replaced by what the promoted database holds"
    );

    let mut resuming = connect(&manager, Some(replicated)).await;
    exec(&pool, "INSERT INTO orders VALUES (5, 1.0, 1, 'after')").await;
    let after = live(&mut resuming, 5).await;
    assert_eq!(
        Position::from_cursor_bytes(after.as_bytes()).map(|position| position.timeline),
        Some(2),
        "the feed continues on the promoted database's timeline"
    );
    assert!(
        pair.slot_was_synced(SLOT).await,
        "the feed resumed from the synchronized slot rather than a recreated one"
    );

    ingest.abort();
}
