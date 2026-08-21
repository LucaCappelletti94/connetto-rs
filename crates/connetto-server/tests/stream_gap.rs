//! R32 step 3: a change feed that resumed past what it delivered declares a
//! resync epoch.
//!
//! Once a deployment caps a replication slot's reservation, the database
//! invalidates the slot rather than letting it fill the disk, and an operator
//! recreates it. The new slot starts at the current write position, so the
//! stretch of changes in between never reaches this server. Nothing downstream
//! can see that hole on its own: the reconnect log simply holds older entries
//! and then newer ones, and the question a returning client asks, whether
//! anything it is missing is still retained, answers yes.
//!
//! So the server compares where the feed is about to resume against how far it
//! had already got. Ahead means a hole, whatever opened it. The log then forgets
//! everything through the resume point, which is what makes that question
//! answer honestly afterwards, and every live connection is closed so it
//! re-declares its subscriptions rather than carrying on across the hole.
//!
//! The invalidation in the second test is real. `max_slot_wal_keep_size` is
//! capped and the write-ahead log is forced past it, so Postgres invalidates the
//! slot itself and the test asserts it did before relying on it.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::{ControlMessage, FatalErrorReason, Handshake};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    CatchupDecision, ChangeRecord, InMemoryOplog, Materializer, Oplog, OplogConfig, PageSpec,
    PgOplog, RequestGuard, SessionConfig, SessionManager, SnapshotEstimate, SnapshotPage,
    SnapshotSource, catchup_decision, loopback, pg_write_target, slot,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};
use subql::{CdcSource, PgSqliteEmuSource};

/// Its own slot and table names, so this never contends with the shared fixture
/// slot the end-to-end suites create and drop.
const SLOT: &str = "connetto_slot_gap";
const OPLOG: &str = "connetto_oplog_gap";
const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";

/// Three real change records, built the way the ingest loop builds them: driven
/// through the emulator and turned into records by the materializer, so their
/// positions are the shape the log actually stores rather than numbers a test
/// invented.
async fn records() -> Vec<ChangeRecord> {
    let mat = Materializer::new(PG_DDL).expect("build materializer");
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    let mut out = Vec::new();
    for id in 1..=3 {
        source
            .execute_sql(&format!(
                "INSERT INTO orders (id, price, quantity, status) VALUES ({id}, 1.0, 1, 'seed')"
            ))
            .expect("insert");
        while let Some(event) = source.next_event().await.expect("poll source") {
            out.push(mat.oplog_record(&event).expect("build oplog record"));
        }
    }
    assert_eq!(out.len(), 3, "one record per statement");
    out
}

/// A snapshot source serving nothing. This suite never reads a snapshot; it
/// only needs a manager that can hold a connection.
struct NoSnapshot;

impl SnapshotSource for NoSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
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

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot_page(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &connetto_core::Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        Ok(SnapshotPage {
            patchset: Vec::new(),
            cursor: Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: 0,
            rows: 0,
            bytes: 0,
        })
    }
}

#[tokio::test]
async fn forgetting_through_the_gap_makes_the_catchup_question_honest() {
    let records = records().await;
    let (first, last) = (records[0].lsn(), records[2].lsn());
    let oplog = InMemoryOplog::new(OplogConfig::default());
    for record in records {
        oplog.append(record).await.expect("append");
    }
    assert_eq!(
        catchup_decision(
            first,
            oplog.min_lsn().await.expect("min"),
            oplog.current_lsn().await.expect("current"),
        ),
        CatchupDecision::Catchup,
        "with no hole, a client inside the window catches up",
    );

    // A hole ending past everything the log holds, which is what a recreated
    // slot looks like.
    let boundary = last + 1_000;
    oplog.forget_through(boundary).await.expect("forget");
    assert!(
        oplog.entries_since(0).await.expect("entries").is_empty(),
        "nothing at or below the boundary survives",
    );
    assert_eq!(
        catchup_decision(
            first,
            oplog.min_lsn().await.expect("min"),
            oplog.current_lsn().await.expect("current"),
        ),
        CatchupDecision::FullResync,
        "and a client whose position predates the resume point can no longer be \
         told it is only missing what the log still holds",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recreated_slot_resumes_past_what_was_delivered() {
    let fixture = Fixture::acquire().await;
    let admin = fixture.admin();
    fixture
        .setup(&[
            &format!(
                "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots \
                 WHERE slot_name = '{SLOT}'"
            ),
            &format!("DROP TABLE IF EXISTS {OPLOG}"),
            "CREATE TABLE IF NOT EXISTS gap_churn (id BIGINT PRIMARY KEY, body TEXT)",
        ])
        .await;
    let oplog = PgOplog::new(admin.clone(), OPLOG, OplogConfig::default());
    oplog.ensure_schema().await.expect("provision the oplog");

    fixture
        .setup(&[&format!(
            "SELECT pg_create_logical_replication_slot('{SLOT}', 'pgoutput')"
        )])
        .await;
    let delivered = slot::resume_position(admin, SLOT)
        .await
        .expect("read the slot")
        .expect("a fresh logical slot has a confirmed position");
    assert_eq!(
        slot::resume_position(admin, SLOT).await.expect("read"),
        Some(delivered),
        "an untouched slot resumes exactly where it was, so an ordinary \
         reconnect is never mistaken for a hole",
    );

    // Cap the reservation and force the log past it, so Postgres invalidates
    // the slot rather than the test asserting that it would.
    fixture
        .setup(&[
            "ALTER SYSTEM SET max_slot_wal_keep_size = '64MB'",
            "SELECT pg_reload_conf()",
        ])
        .await;
    for _ in 0..12 {
        fixture
            .setup(&[
                "INSERT INTO gap_churn \
                 SELECT g, repeat('x', 4000) FROM generate_series(1, 4000) AS g \
                 ON CONFLICT (id) DO UPDATE SET body = excluded.body",
                "SELECT pg_switch_wal()",
                "CHECKPOINT",
            ])
            .await;
        let lag = slot::read_lag(admin, SLOT)
            .await
            .expect("read the slot")
            .expect("the slot exists");
        if lag.wal_status.as_deref() == Some("lost") {
            break;
        }
    }
    let invalidated = slot::read_lag(admin, SLOT)
        .await
        .expect("read the slot")
        .expect("the slot exists");
    assert_eq!(
        invalidated.wal_status.as_deref(),
        Some("lost"),
        "the cap was meant to invalidate the slot and did not, so nothing below \
         would be testing what it claims: {invalidated:?}",
    );

    // What an operator does next, and the moment the hole opens.
    fixture
        .setup(&[
            &format!("SELECT pg_drop_replication_slot('{SLOT}')"),
            &format!("SELECT pg_create_logical_replication_slot('{SLOT}', 'pgoutput')"),
            "ALTER SYSTEM RESET max_slot_wal_keep_size",
            "SELECT pg_reload_conf()",
        ])
        .await;
    let resumed = slot::resume_position(admin, SLOT)
        .await
        .expect("read the slot")
        .expect("the recreated slot has a confirmed position");
    assert!(
        resumed > delivered,
        "the recreated slot must start past what was delivered, which is the \
         hole the step exists to notice: {delivered} then {resumed}",
    );

    fixture
        .setup(&[
            &format!("SELECT pg_drop_replication_slot('{SLOT}')"),
            &format!("DROP TABLE IF EXISTS {OPLOG}"),
            "DROP TABLE IF EXISTS gap_churn",
        ])
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn declaring_an_epoch_trims_the_log_and_closes_every_connection() {
    let fixture = Fixture::acquire().await;
    let admin = fixture.admin();
    fixture
        .setup(&[&format!("DROP TABLE IF EXISTS {OPLOG}")])
        .await;
    // Two handles over one table: the manager owns its own, and the probe is
    // how the test sees what the manager did to it.
    let probe = PgOplog::new(admin.clone(), OPLOG, OplogConfig::default());
    probe.ensure_schema().await.expect("provision the oplog");
    let records = records().await;
    let last = records[2].lsn();
    for record in records {
        probe.append(record).await.expect("append");
    }

    let manager = SessionManager::with_oplog(
        Materializer::new(PG_DDL).expect("build materializer"),
        NoSnapshot,
        // This suite opens no subscription, so the policy is never consulted.
        RosterAuth::granting_nobody().withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        connetto_server::NoConnector,
        PgOplog::new(admin.clone(), OPLOG, OplogConfig::default()),
        pg_write_target::<ConnettoWatermark>(admin.clone(), PG_DDL).expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let (server_end, mut client) = loopback();
    let serve = manager.clone();
    let session = tokio::spawn(async move { serve.serve(server_end).await });
    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "gap-client")
                .with_grant(connetto_core::messages::Grant::new("user:gap-client")),
        ))
        .await
        .expect("send handshake");
    let IncomingFrame::Control(ControlMessage::HandshakeAck(_)) = next_frame(&mut client).await
    else {
        panic!("expected a handshake ack");
    };

    // An ordinary reconnect resumes at or behind what was delivered, and must
    // not be mistaken for a hole.
    assert_eq!(
        manager.reconcile_stream(last).await.expect("reconcile"),
        None,
        "resuming exactly where the feed stopped is not a gap",
    );
    assert_eq!(
        probe.current_lsn().await.expect("current"),
        Some(last),
        "so nothing was forgotten",
    );

    let boundary = last + 1_000;
    assert_eq!(
        manager.reconcile_stream(boundary).await.expect("reconcile"),
        Some(boundary),
        "resuming past what was delivered is a gap, bounded by the resume point",
    );
    assert_eq!(
        probe.current_lsn().await.expect("current"),
        None,
        "the log forgot everything through the boundary",
    );

    let IncomingFrame::Control(ControlMessage::FatalError(fatal)) = next_frame(&mut client).await
    else {
        panic!("the connection must be told, because it never asks again");
    };
    assert_eq!(fatal.reason, FatalErrorReason::ChangeStreamGap);
    assert!(
        client.recv().await.expect("recv").is_none(),
        "and the connection ends, so the client reconnects and re-declares \
         rather than carrying on across the hole",
    );
    session.await.expect("join session").expect("session ok");

    fixture
        .setup(&[&format!("DROP TABLE IF EXISTS {OPLOG}")])
        .await;
}

/// The next frame, whichever plane it came in on.
async fn next_frame<T: Transport>(transport: &mut T) -> IncomingFrame {
    tokio::time::timeout(Duration::from_secs(5), transport.recv())
        .await
        .expect("a frame within five seconds")
        .expect("recv")
        .expect("connection open")
}
