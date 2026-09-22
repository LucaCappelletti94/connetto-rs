//! R89 read-failure classification end-to-end tests.
//!
//! Needs Docker.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use connetto_core::messages::{ControlMessage, PauseCause, SUBSCRIPTION_REFUSED};
use connetto_core::test_support::TestGrantChecker;
use connetto_server::{
    AbuseConfig, Materializer, PgReadConnector, PgSnapshotSource, ReconnectEvent, RequestGuard,
    RuntimeWritableCatalog, SessionConfig, SessionManager, ThrottleConfig, TierLimits, loopback,
    pg_write_target,
};
use connetto_test_harness::{Client, ConnettoWatermark, Fixture, RosterAuth};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use subql::{CdcSource, PgSqliteEmuSource};
use tracing::Instrument;

const DDL: &str = "CREATE TABLE counts (id INT PRIMARY KEY, n INT)";

type Manager = SessionManager<PgSnapshotSource, RosterAuth, ConnettoWatermark, PgReadConnector>;

fn connect_to(manager: &Arc<Manager>) -> Client {
    let (server_end, client_end) = loopback();
    let session = Arc::clone(manager);
    tokio::spawn(
        async move {
            let _ = session.serve(server_end).await;
        }
        .instrument(tracing::Span::current()),
    );
    Client::new(client_end)
}

fn guard(seed: Duration, triggered: Duration) -> Arc<RequestGuard<String>> {
    Arc::new(RequestGuard::new(
        ThrottleConfig::default()
            .with_identified(TierLimits::identified().with_read_timeout(seed))
            .with_reexec_timeout(triggered),
        AbuseConfig::default(),
    ))
}

fn full_manager(
    connector_pool: Pool<AsyncPgConnection>,
    catalog_ddl: &str,
    schema_ddl: &str,
    auth: RosterAuth,
    guard: Arc<RequestGuard<String>>,
    snapshot_pool: Pool<AsyncPgConnection>,
    write_pool: Pool<AsyncPgConnection>,
) -> Arc<Manager> {
    SessionManager::with_connector(
        Materializer::with_read_connector(
            catalog_ddl,
            RuntimeWritableCatalog::default(),
            None,
            None,
            PgReadConnector::with_session_setup(connector_pool.clone()),
        )
        .expect("build materializer"),
        PgSnapshotSource::from_ddl(snapshot_pool, schema_ddl).expect("snapshot source"),
        auth,
        Arc::new(TestGrantChecker),
        PgReadConnector::with_session_setup(connector_pool),
        pg_write_target::<ConnettoWatermark>(write_pool, schema_ddl).expect("build write target"),
        guard,
        SessionConfig::default(),
        None,
    )
}

/// Dropping column n poisons re-execution of SELECT MIN(n): the database returns
/// 42703 which maps to `ReadFailure::Other`. The session refuses the subscription
/// after one retry (attempts=2, class=unknown in the log), while a sibling
/// `SELECT *` subscription receives its live patch from the same event unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_poisoned_computed_read_ends_alone_after_one_retry() {
    crate::logging::with_capture(
        "a_poisoned_computed_read_ends_alone_after_one_retry",
        |logs| async move {
            let fixture = Fixture::acquire().await;
            fixture.exec("DROP TABLE IF EXISTS counts CASCADE").await;
            fixture
                .exec("CREATE TABLE counts (id INT PRIMARY KEY, n INT)")
                .await;
            fixture
                .exec("INSERT INTO counts (id, n) VALUES (10, 10)")
                .await;

            let pool = fixture.admin().clone();
            let manager = full_manager(
                pool.clone(),
                DDL,
                DDL,
                RosterAuth::granting("reader"),
                guard(Duration::from_secs(30), Duration::from_secs(30)),
                pool.clone(),
                pool,
            );

            let mut computed_client = connect_to(&manager);
            computed_client
                .handshake_with("aggregator", "user:aggregator")
                .await;
            computed_client
                .subscribe("cheapest", "SELECT MIN(n) FROM counts")
                .await;
            let ControlMessage::AggregateUpdate(seeded) = computed_client.next_control().await
            else {
                panic!("expected aggregate seed");
            };
            assert_eq!(seeded.result_json.as_deref(), Some("10"));

            let mut row_client = connect_to(&manager);
            row_client.handshake_with("reader", "user:reader").await;
            row_client.subscribe("rows", "SELECT * FROM counts").await;
            row_client.expect_snapshot("rows").await;

            // Drop column n from Postgres; the next connector re-execution of
            // SELECT MIN(n) FROM counts fails with 42703, arriving as
            // `ReadFailure::Other`.
            fixture.exec("ALTER TABLE counts DROP COLUMN n").await;

            let mut source = PgSqliteEmuSource::open_in_memory(DDL).expect("open emu source");
            // Stage the extreme row in the emulator so DELETE can reference it,
            // then discard that CDC event without dispatching it.
            source
                .execute_sql("INSERT INTO counts (id, n) VALUES (10, 10)")
                .expect("seed emu");
            source
                .next_event()
                .await
                .expect("drain emu")
                .expect("insert event");

            // Deleting the tracked extreme forces a re-execution, which now
            // fails because column n is gone from Postgres.
            source
                .execute_sql("DELETE FROM counts WHERE id = 10")
                .expect("execute dml");
            while let Some(event) = source.next_event().await.expect("poll source") {
                manager
                    .dispatch_event(&event)
                    .await
                    .unwrap_or_else(|err| panic!("dispatch failed: {err:?}"));
            }

            let ControlMessage::NonFatalError(refusal) = computed_client.next_control().await
            else {
                panic!("expected refusal of the poisoned subscription");
            };
            assert_eq!(refusal.related_to.as_deref(), Some("cheapest"));
            assert_eq!(refusal.detail, SUBSCRIPTION_REFUSED);

            let log_lines = logs.lines();
            let refused_log = log_lines.iter().any(|line| {
                line["message"]
                    == "a computed subscription's read was refused, ending the subscription"
                    && line["sub_id"] == "cheapest"
                    && line["class"] == "unknown"
                    && line["attempts"].as_u64() == Some(2)
            });
            assert!(
                refused_log,
                "log must record sub_id=cheapest class=unknown attempts=2: {log_lines:?}"
            );

            let live = row_client.wait_for_live(Duration::from_secs(5)).await;
            assert_eq!(live.sub_id, "rows");
        },
    )
    .await;
}

/// A transient connector failure pauses delivery in place and resumes once the
/// database is reachable again, without ending the subscription or touching
/// the change stream.
#[expect(
    clippy::too_many_lines,
    reason = "the test walks setup, hold, pause, assert, release, and resume in order"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transient_read_pause_resumes_delivery_without_ending_anything() {
    let fixture = Fixture::acquire().await;
    fixture.exec("DROP TABLE IF EXISTS counts CASCADE").await;
    fixture
        .exec("CREATE TABLE counts (id INT PRIMARY KEY, n INT)")
        .await;
    fixture
        .exec("INSERT INTO counts (id, n) VALUES (10, 10)")
        .await;

    let tiny_pool = Pool::builder()
        .max_size(1)
        .connection_timeout(Duration::from_millis(150))
        .build(AsyncDieselConnectionManager::<AsyncPgConnection>::new(
            fixture.admin_url().to_owned(),
        ))
        .await
        .expect("build tiny pool");

    let manager = full_manager(
        tiny_pool.clone(),
        DDL,
        DDL,
        RosterAuth::granting_nobody(),
        guard(Duration::from_secs(30), Duration::from_secs(30)),
        fixture.admin().clone(),
        fixture.admin().clone(),
    );

    let mut client = connect_to(&manager);
    client.handshake_with("watcher", "user:watcher").await;
    client
        .subscribe("smallest", "SELECT MIN(n) FROM counts")
        .await;
    let ControlMessage::AggregateUpdate(seeded) = client.next_control().await else {
        panic!("expected aggregate seed");
    };
    assert_eq!(seeded.result_json.as_deref(), Some("10"));

    // Process INSERT before holding the pool so the connector can re-execute.
    let mut source = PgSqliteEmuSource::open_in_memory(DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO counts (id, n) VALUES (1, 1)")
        .expect("stage insert");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch insert");
    }
    let ControlMessage::AggregateUpdate(_) = client.next_control().await else {
        panic!("expected AggregateUpdate from INSERT");
    };

    // Hold the pool's only connection; the DELETE re-execution below times out.
    let held = tiny_pool.get().await.expect("hold the only connection");

    // Stage just the DELETE of the extreme so the next re-execution needs the pool.
    source
        .execute_sql("DELETE FROM counts WHERE id = 1")
        .expect("stage delete");

    let saw_read_retrying = Arc::new(AtomicBool::new(false));
    let saw_stream_retry = Arc::new(AtomicBool::new(false));
    let saw_gave_up = Arc::new(AtomicBool::new(false));
    let r_clone = Arc::clone(&saw_read_retrying);
    let s_clone = Arc::clone(&saw_stream_retry);
    let g_clone = Arc::clone(&saw_gave_up);

    let manager_clone = Arc::clone(&manager);
    let ingest_task = tokio::spawn(async move {
        let _ = manager_clone
            .ingest(&mut source, &mut |event| match event {
                ReconnectEvent::ReadRetrying { .. } => {
                    r_clone.store(true, Ordering::Relaxed);
                }
                ReconnectEvent::Retrying { .. } => {
                    s_clone.store(true, Ordering::Relaxed);
                }
                ReconnectEvent::GaveUp { .. } => {
                    g_clone.store(true, Ordering::Relaxed);
                }
                ReconnectEvent::AuthRetrying { .. } => {}
            })
            .await;
    });

    // DELETE re-execution times out; delivery pauses.
    let paused = tokio::time::timeout(Duration::from_secs(3), client.next_control())
        .await
        .expect("DeliveryPaused within 3 s");
    assert!(
        matches!(
            paused,
            ControlMessage::DeliveryPaused {
                cause: PauseCause::DatabaseUnreachable
            }
        ),
        "expected DeliveryPaused(DatabaseUnreachable), got {paused:?}"
    );

    tokio::time::sleep(Duration::from_millis(400)).await;

    assert!(
        saw_read_retrying.load(Ordering::Relaxed),
        "on_event must observe at least one ReadRetrying while the pool is held"
    );
    assert!(
        !saw_stream_retry.load(Ordering::Relaxed),
        "the change stream must not be reconnected"
    );
    assert!(
        !saw_gave_up.load(Ordering::Relaxed),
        "the ingest loop must not give up"
    );

    drop(held);

    // deliver_computed runs inside dispatch_with_grants; broadcast_control runs
    // after it returns, so AggregateUpdate arrives before DeliveryResumed.
    let reexec = tokio::time::timeout(Duration::from_secs(5), client.next_control())
        .await
        .expect("AggregateUpdate within 5 s");
    let ControlMessage::AggregateUpdate(result) = reexec else {
        panic!("expected AggregateUpdate after resume, got {reexec:?}");
    };
    assert_eq!(result.result_json.as_deref(), Some("10"));

    let resumed = tokio::time::timeout(Duration::from_secs(5), client.next_control())
        .await
        .expect("DeliveryResumed within 5 s");
    assert!(
        matches!(resumed, ControlMessage::DeliveryResumed),
        "expected DeliveryResumed, got {resumed:?}"
    );

    ingest_task.abort();
}
