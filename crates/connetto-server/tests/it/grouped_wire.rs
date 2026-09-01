//! R82: grouped delivery over the wire, end to end.
//!
//! A grouped fold's seeds and deltas reach the client as keyed upserts, a
//! group emptied by a change arrives as a keyed removal, and a subscription
//! whose groups outgrow the fold budget demotes to whole re-reads with the
//! transition in the log and nothing on the wire beyond the answers.
//!
//! Needs Docker: the fixture starts its own Postgres.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::messages::ControlMessage;
use connetto_core::test_support::TestGrantChecker;
use connetto_server::{
    AbuseConfig, Materializer, PgReadConnector, PgSnapshotSource, RequestGuard,
    RuntimeWritableCatalog, SessionConfig, SessionManager, ThrottleConfig, TierLimits, loopback,
    pg_write_target,
};
use connetto_test_harness::{Client, ConnettoWatermark, Fixture, RosterAuth};
use subql::{CdcSource, PgSqliteEmuSource};

const PG_DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, status TEXT);";

/// A manager whose computed subscriptions read through connetto's connector.
type Manager = SessionManager<PgSnapshotSource, RosterAuth, ConnettoWatermark, PgReadConnector>;

fn manager(fixture: &Fixture) -> Arc<Manager> {
    let guard = Arc::new(RequestGuard::new(
        ThrottleConfig::default()
            .with_identified(TierLimits::identified().with_read_timeout(Duration::from_secs(30))),
        AbuseConfig::default(),
    ));
    let pool = fixture.admin().clone();
    SessionManager::with_connector(
        Materializer::with_read_connector(
            PG_DDL,
            RuntimeWritableCatalog::default(),
            None,
            None,
            PgReadConnector::with_session_setup(pool.clone()),
        )
        .expect("build materializer"),
        PgSnapshotSource::from_ddl(pool.clone(), PG_DDL).expect("snapshot source"),
        // A grouped count is global, so the policy never sees it.
        RosterAuth::granting_nobody(),
        Arc::new(TestGrantChecker),
        PgReadConnector::with_session_setup(pool.clone()),
        pg_write_target::<ConnettoWatermark>(pool, PG_DDL).expect("build write target"),
        guard,
        SessionConfig::default(),
    )
}

/// One in-process client on its own session.
fn connect(manager: &Arc<Manager>) -> Client {
    let (server_end, client_end) = loopback();
    let session = Arc::clone(manager);
    tokio::spawn(async move {
        let _ = session.serve(server_end).await;
    });
    Client::new(client_end)
}

/// Pump the client for exactly `n` aggregate frames on `sub_id`.
async fn take_aggregates(
    client: &mut Client,
    sub_id: &str,
    n: usize,
) -> Vec<connetto_core::messages::AggregateUpdate> {
    let mut frames = Vec::with_capacity(n);
    while frames.len() < n {
        let ControlMessage::AggregateUpdate(update) = client.next_control().await else {
            panic!("expected an aggregate frame, {} of {n} seen", frames.len());
        };
        assert_eq!(update.sub_id, sub_id);
        frames.push(update);
    }
    frames
}

/// Run `sql` on the emulated source and dispatch every event it produced.
async fn apply(source: &mut PgSqliteEmuSource, manager: &Arc<Manager>, sql: &str) {
    source.execute_sql(sql).expect("execute dml");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager.dispatch_event(&event).await.expect("dispatch");
    }
}

/// The R82 done-when, first half: seeds and deltas arrive keyed, a group born
/// on the change stream arrives as a new keyed upsert, and emptying it again
/// arrives as a keyed removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grouped_subscription_delivers_per_group_deltas_with_the_key_populated() {
    let fixture = Fixture::acquire().await;
    fixture.exec("DROP TABLE IF EXISTS orders CASCADE").await;
    fixture
        .exec("CREATE TABLE orders (id INT PRIMARY KEY, status TEXT)")
        .await;
    fixture
        .exec("INSERT INTO orders VALUES (1, 'open'), (2, 'open')")
        .await;
    let manager = manager(&fixture);

    let mut client = connect(&manager);
    client.handshake_with("counter", "user:counter").await;
    client
        .subscribe(
            "by-status",
            "SELECT status, COUNT(*) FROM orders GROUP BY status",
        )
        .await;

    // The one seeded group arrives as a keyed upsert.
    let seed = take_aggregates(&mut client, "by-status", 1).await.remove(0);
    assert!(!seed.is_full_result, "a grouped seed is a keyed upsert");
    let open_key = seed.group_key.expect("a grouped seed carries its key");
    assert_eq!(seed.result_json.as_deref(), Some("2"));

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    apply(
        &mut source,
        &manager,
        "INSERT INTO orders VALUES (4, 'open')",
    )
    .await;
    let grew = take_aggregates(&mut client, "by-status", 1).await.remove(0);
    assert_eq!(
        grew.group_key.as_deref(),
        Some(open_key.as_slice()),
        "the delta addresses its group by the seed's own key"
    );
    assert_eq!(grew.result_json.as_deref(), Some("3"));
    assert!(!grew.is_full_result, "a grouped delta is an upsert");

    // A group born on the change stream appears under a new key, and
    // emptying it again is a keyed removal.
    apply(
        &mut source,
        &manager,
        "INSERT INTO orders VALUES (100, 'done')",
    )
    .await;
    let born = take_aggregates(&mut client, "by-status", 1).await.remove(0);
    let done_key = born.group_key.clone().expect("a new group carries its key");
    assert_ne!(done_key.as_slice(), open_key.as_slice());
    assert_eq!(born.result_json.as_deref(), Some("1"));
    assert!(!born.is_full_result);
    apply(&mut source, &manager, "DELETE FROM orders WHERE id = 100").await;
    let removed = take_aggregates(&mut client, "by-status", 1).await.remove(0);
    assert_eq!(
        removed.group_key.as_deref(),
        Some(done_key.as_slice()),
        "the removal addresses the emptied group"
    );
    assert_eq!(removed.result_json, None, "an emptied group is a removal");
    assert!(!removed.is_full_result);
}

/// The R82 done-when, second half: a seed past the group budget demotes at
/// install, the client keeps answering with full results (one row-shaped
/// frame carrying every group, produced by the whole re-read the demotion
/// asked for), and the log carries the transition the client is never told
/// about.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_demoted_subscription_answers_whole_and_logs_the_transition() {
    let logs = logging::install_once();
    let fixture = Fixture::acquire().await;
    fixture.exec("DROP TABLE IF EXISTS orders CASCADE").await;
    fixture
        .exec("CREATE TABLE orders (id INT PRIMARY KEY, status TEXT)")
        .await;
    // One row per group, past the fold budget of 1024 groups.
    fixture
        .exec("INSERT INTO orders SELECT g, 'status-' || g FROM generate_series(1, 1025) AS g")
        .await;
    let manager = manager(&fixture);

    let mut client = connect(&manager);
    client.handshake_with("wide", "user:wide").await;
    client
        .subscribe(
            "by-status",
            "SELECT status, COUNT(*) FROM orders GROUP BY status",
        )
        .await;

    // The demoted first answer is one whole row-shaped frame, not keyed
    // upserts: the fold is gone, the whole re-read is the tier now.
    let whole = take_aggregates(&mut client, "by-status", 1).await.remove(0);
    assert!(
        whole.is_full_result,
        "a demoted subscription answers with full results"
    );
    assert_eq!(whole.group_key, None, "a whole answer addresses no group");
    let rows: serde_json::Value = serde_json::from_str(
        whole
            .result_json
            .as_deref()
            .expect("a whole answer has a body"),
    )
    .expect("the whole answer is JSON rows");
    assert_eq!(
        rows.as_array().map(Vec::len),
        Some(1025),
        "every group is in the whole answer"
    );

    let named = logs
        .lines()
        .into_iter()
        .any(|line| line["message"] == "subscription changed maintenance tier");
    assert!(named, "the log names the transition");
}

/// The process-global log destination, installed once and read back. The
/// transition line is `info`, so this binary listens below `warn`.
mod logging {
    use std::io::Write;
    use std::sync::{Arc, LazyLock, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    pub struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Buffer {
        /// Every line written so far, each parsed as one JSON object.
        pub fn lines(&self) -> Vec<serde_json::Value> {
            String::from_utf8_lossy(&self.0.lock().expect("buffer poisoned"))
                .lines()
                .filter(|line| !line.trim().is_empty())
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect()
        }
    }

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("buffer poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buffer {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// A subscriber is process-global, so it is installed exactly once, on the
    /// first read of the buffer.
    static BUFFER: LazyLock<Buffer> = LazyLock::new(|| {
        let buffer = Buffer::default();
        connetto_core::logging::install(buffer.clone(), "info");
        buffer
    });

    /// Install the destination the first time and hand back the buffer.
    pub fn install_once() -> Buffer {
        BUFFER.clone()
    }
}
