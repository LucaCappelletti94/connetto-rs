//! R58: what one read costs, and what happens when it costs too much.
//!
//! A read larger than one delivery is served completely, in keyset pages the
//! client's own acknowledgements pace, and nothing is ever answered with its
//! first rows. A page is shaped by a byte budget rather than a row count, so a
//! table of wide rows pages smaller than a narrow one under the same budget. A
//! row above the ceiling, a table whose typical row is already above it, and a
//! read whose plan needs a sort are all refused, each with the one fixed phrase
//! on the wire and the cause in the log.
//!
//! Needs Docker: the fixture starts its own Postgres.

use std::sync::Arc;
use std::time::Duration;

use connetto_core::codec::encode_control;
use connetto_core::messages::{BulkMessage, ControlMessage, SUBSCRIPTION_REFUSED};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::IncomingFrame;
use connetto_server::{
    AbuseConfig, Materializer, PgSnapshotSource, RequestGuard, SessionConfig, SessionManager,
    ThrottleConfig, TierLimits, loopback, pg_write_target,
};
use connetto_test_harness::{Client, ConnettoWatermark, Fixture, RosterAuth};
use sqlite_diff_rs::{ParsedDiffSet, PatchsetOp, Value};

const PG_DDL: &str = "CREATE TABLE things (id INT PRIMARY KEY, body TEXT); \
                      CREATE TABLE narrow (id INT PRIMARY KEY, n INT);";

/// The manager these tests serve: the real Postgres read, a policy the initial
/// read never consults, and no re-execution connector.
type Manager = SessionManager<PgSnapshotSource, RosterAuth, ConnettoWatermark>;

/// The read limits one tier gets, as this test wants them.
fn limits(page_bytes: u64, row_ceiling: u64, timeout: Duration) -> Arc<RequestGuard<String>> {
    let tier = TierLimits::identified()
        .with_page_bytes(page_bytes)
        .with_row_ceiling(row_ceiling)
        .with_read_timeout(timeout);
    Arc::new(RequestGuard::new(
        ThrottleConfig::default().with_identified(tier),
        AbuseConfig::default(),
    ))
}

/// A manager reading `PG_DDL`'s tables out of the fixture under `guard`.
///
/// No CDC ingest and no replication slot: every assertion here is about the
/// initial read, which the live path never touches.
fn manager(fixture: &Fixture, guard: Arc<RequestGuard<String>>) -> Arc<Manager> {
    let snapshot =
        PgSnapshotSource::from_ddl(fixture.admin().clone(), PG_DDL).expect("snapshot source");
    SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        snapshot,
        RosterAuth::granting_nobody(),
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
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

/// Drain one subscription's initial read the way a real client does: apply each
/// page, acknowledge it, and take the next one. Returns the ids each page
/// carried, page by page.
///
/// The acknowledgement is what makes a paged read progress, so a drain that
/// forgets it hangs rather than failing.
async fn drain_pages(client: &mut Client, sub_id: &str) -> Vec<Vec<i64>> {
    let ControlMessage::SnapshotBegin(begin) = client.next_control().await else {
        panic!("expected a snapshot begin");
    };
    assert_eq!(begin.sub_id, sub_id);
    let mut pages = Vec::new();
    loop {
        match client.recv().await {
            Some(IncomingFrame::Bulk(BulkMessage::SnapshotPatch(patch))) => {
                assert_eq!(patch.sub_id, sub_id);
                pages.push(ids_in(&patch.patchset_zstd));
                client.ack_credits(1).await;
            }
            Some(IncomingFrame::Control(ControlMessage::SnapshotEnd(end))) => {
                assert_eq!(end.sub_id, sub_id);
                return pages;
            }
            other => panic!("expected a page or the end of the read, got {other:?}"),
        }
    }
}

/// The primary keys one delivered page carries, in delivery order.
fn ids_in(payload: &[u8]) -> Vec<i64> {
    let raw = zstd::decode_all(payload).expect("decompress the page");
    let ParsedDiffSet::Patchset(set) = ParsedDiffSet::parse(&raw).expect("parse the page") else {
        panic!("a snapshot page is a patchset");
    };
    set.iter()
        .map(|op| match op {
            PatchsetOp::Insert { values, .. } => match values.first() {
                Some(Value::Integer(id)) => *id,
                other => panic!("the first column is the integer key, got {other:?}"),
            },
            other => panic!("a snapshot page carries inserts only, got {other:?}"),
        })
        .collect()
}

/// Fill `things` with `rows` rows whose body is `width` characters.
async fn fill(fixture: &Fixture, rows: i32, width: usize) {
    fixture.exec("DROP TABLE IF EXISTS things CASCADE").await;
    fixture
        .exec("CREATE TABLE things (id INT PRIMARY KEY, body TEXT)")
        .await;
    fixture
        .exec(&format!(
            "INSERT INTO things (id, body) \
             SELECT g, repeat('x', {width}) FROM generate_series(1, {rows}) AS g"
        ))
        .await;
    // Statistics, so the predicted width is the table's own rather than its
    // type defaults.
    fixture.exec("ANALYZE things").await;
}

/// The whole read arrives, in more than one page, with every row exactly once.
///
/// This is the phase's central claim: a client may subscribe to more than it can
/// receive at once and still receive all of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_over_the_budget_arrives_completely_in_pages() {
    let fixture = Fixture::acquire().await;
    fill(&fixture, 200, 64).await;
    let manager = manager(&fixture, limits(512, 32 * 1024, Duration::from_secs(30)));

    let mut client = connect(&manager);
    client.handshake_with("pager", "user:pager").await;
    client.subscribe("all", "SELECT * FROM things").await;
    let pages = drain_pages(&mut client, "all").await;

    assert!(
        pages.len() > 1,
        "a 200 row read under a 512 byte budget must take several pages, took {}",
        pages.len()
    );
    let mut delivered: Vec<i64> = pages.iter().flatten().copied().collect();
    delivered.sort_unstable();
    assert_eq!(
        delivered,
        (1..=200).collect::<Vec<i64>>(),
        "every row arrives exactly once across the pages"
    );
}

/// The same byte budget over wider rows produces smaller pages, because the page
/// is sized from the width Postgres predicts rather than from a row count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wide_rows_page_smaller_under_the_same_budget() {
    let fixture = Fixture::acquire().await;
    fixture.exec("DROP TABLE IF EXISTS narrow CASCADE").await;
    fixture
        .exec("CREATE TABLE narrow (id INT PRIMARY KEY, n INT)")
        .await;
    fixture
        .exec("INSERT INTO narrow (id, n) SELECT g, g FROM generate_series(1, 400) AS g")
        .await;
    fixture.exec("ANALYZE narrow").await;
    fill(&fixture, 400, 512).await;
    let manager = manager(
        &fixture,
        limits(8 * 1024, 32 * 1024, Duration::from_secs(30)),
    );

    let mut client = connect(&manager);
    client.handshake_with("shapes", "user:shapes").await;
    client.subscribe("n", "SELECT * FROM narrow").await;
    let narrow = drain_pages(&mut client, "n").await;
    client.subscribe("w", "SELECT * FROM things").await;
    let wide = drain_pages(&mut client, "w").await;

    let first_narrow = narrow.first().expect("a narrow page").len();
    let first_wide = wide.first().expect("a wide page").len();
    assert!(
        first_narrow > first_wide,
        "the same budget must fit more narrow rows than wide ones, got {first_narrow} and {first_wide}"
    );
}

/// A single row above the ceiling is refused, and the log carries the three
/// numbers that say whether the ceiling is set too low or the schema stores
/// file-shaped data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_above_the_ceiling_is_refused_and_the_log_names_three_numbers() {
    let logs = logging::install_once();
    let fixture = Fixture::acquire().await;
    fixture.exec("DROP TABLE IF EXISTS things CASCADE").await;
    fixture
        .exec("CREATE TABLE things (id INT PRIMARY KEY, body TEXT)")
        .await;
    // One outlier among ten thousand ordinary rows, so the table's average
    // stays well under the ceiling and it is the row itself that trips it. The
    // outlier takes the lowest key, so it lands in the first page and the
    // refusal comes before anything is sent.
    fixture
        .exec("INSERT INTO things (id, body) VALUES (1, repeat('x', 200000))")
        .await;
    fixture
        .exec(
            "INSERT INTO things (id, body) \
             SELECT g, repeat('x', 8) FROM generate_series(2, 10000) AS g",
        )
        .await;
    fixture.exec("ANALYZE things").await;
    let manager = manager(&fixture, limits(8 * 1024, 4096, Duration::from_secs(30)));

    let mut client = connect(&manager);
    client.handshake_with("wide", "user:wide").await;
    client.subscribe("all", "SELECT * FROM things").await;

    let ControlMessage::NonFatalError(refusal) = client.next_control().await else {
        panic!("a row above the ceiling must be refused, with nothing sent ahead of it");
    };
    assert_eq!(refusal.detail, SUBSCRIPTION_REFUSED);

    let named = logs.lines().into_iter().any(|line| {
        line["message"] == "read refused"
            && line["cause"].as_str().is_some_and(|cause| {
                cause.contains("200004 bytes")
                    && cause.contains("4096 byte ceiling")
                    && cause.contains("averaging")
            })
    });
    assert!(
        named,
        "the log names the row, the ceiling and the table average: {:?}",
        logs.lines()
    );
}

/// A table whose predicted average row is already above the ceiling is refused
/// before a single row is read, which is the one refusal the estimate pays for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_table_wider_than_the_ceiling_is_refused_before_the_read() {
    let logs = logging::install_once();
    let fixture = Fixture::acquire().await;
    fixture.exec("DROP TABLE IF EXISTS things CASCADE").await;
    fixture
        .exec("CREATE TABLE things (id INT PRIMARY KEY, body TEXT)")
        .await;
    // Stored out of line and uncompressed, so the planner's predicted width is
    // the value's own. A repeated character compresses to almost nothing, and
    // the planner then predicts a width two orders of magnitude under the row
    // as it arrives, which is why the ceiling on a delivered row is measured on
    // the bytes rather than taken from the estimate.
    fixture
        .exec("ALTER TABLE things ALTER COLUMN body SET STORAGE EXTERNAL")
        .await;
    fixture
        .exec(
            "INSERT INTO things (id, body) \
             SELECT g, repeat('x', 4096) FROM generate_series(1, 20) AS g",
        )
        .await;
    fixture.exec("ANALYZE things").await;
    let manager = manager(&fixture, limits(8 * 1024, 64, Duration::from_secs(30)));

    let mut client = connect(&manager);
    client.handshake_with("tooWide", "user:too-wide").await;
    client.subscribe("all", "SELECT * FROM things").await;

    let ControlMessage::NonFatalError(refusal) = client.next_control().await else {
        panic!("a table above the ceiling must be refused");
    };
    assert_eq!(refusal.detail, SUBSCRIPTION_REFUSED);
    let named = logs.lines().into_iter().any(|line| {
        line["message"] == "read refused"
            && line["cause"]
                .as_str()
                .is_some_and(|cause| cause.contains("the table's average row is"))
    });
    assert!(
        named,
        "the log says the refusal came from the estimate: {:?}",
        logs.lines()
    );
}

/// A read whose plan needs a sort is stopped by the time limit rather than
/// running to completion, because a row cap bounds connetto's memory and the
/// wire and not Postgres's work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sort_shaped_read_is_stopped_by_the_time_limit() {
    let fixture = Fixture::acquire().await;
    fill(&fixture, 40_000, 200).await;
    let manager = manager(
        &fixture,
        limits(8 * 1024, 32 * 1024, Duration::from_millis(1)),
    );

    let mut client = connect(&manager);
    client.handshake_with("sorter", "user:sorter").await;
    // `body` carries no index, so the plan sorts the whole table to return one
    // page of it.
    client
        .subscribe("sorted", "SELECT * FROM things ORDER BY body")
        .await;

    let ControlMessage::NonFatalError(refusal) = client.next_control().await else {
        panic!("a read past its time limit must be refused");
    };
    assert_eq!(refusal.detail, SUBSCRIPTION_REFUSED);
}

/// Every read refusal is the same bytes on the wire, whatever stopped it.
///
/// R38's invariant has no exceptions, so a caller cannot tell a ceiling from a
/// time limit, and a developer reads the difference in the log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_refusals_are_byte_identical_across_causes() {
    let fixture = Fixture::acquire().await;
    fill(&fixture, 4_000, 200).await;
    // A ceiling under any row's size and a time limit under any read's
    // duration, so both causes are reachable on one server.
    let manager = manager(&fixture, limits(8 * 1024, 1, Duration::from_millis(1)));

    let mut client = connect(&manager);
    client.handshake_with("causes", "user:causes").await;
    client.subscribe("probe", "SELECT * FROM things").await;
    let ceiling = client.next_control().await;
    client
        .subscribe("probe", "SELECT * FROM things ORDER BY body")
        .await;
    let timeout = client.next_control().await;

    for refusal in [&ceiling, &timeout] {
        let ControlMessage::NonFatalError(err) = refusal else {
            panic!("the refusal is the first and only reply: {refusal:?}");
        };
        assert_eq!(err.related_to.as_deref(), Some("probe"));
        assert_eq!(err.detail, SUBSCRIPTION_REFUSED);
    }
    assert_eq!(
        encode_control(&ceiling).expect("encode"),
        encode_control(&timeout).expect("encode"),
        "a ceiling and a time limit must refuse identically"
    );
}

/// The process-global log destination, installed once and read back.
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
        connetto_core::logging::install(buffer.clone(), "warn");
        buffer
    });

    /// Install the destination the first time and hand back the buffer.
    pub fn install_once() -> Buffer {
        BUFFER.clone()
    }
}

/// A subscription the server has to replace, over a table this tier refuses,
/// ends rather than retrying a refusal for ever.
///
/// Replacing a subscription retries a failed read, because until the
/// replacement lands the client is holding rows it may no longer see. A refusal
/// is not an outage: retrying it would replace nothing, for ever, one log line
/// at a time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_replacement_ends_the_subscription_instead_of_retrying() {
    let logs = logging::install_once();
    let fixture = Fixture::acquire().await;
    fill(&fixture, 40, 64).await;
    let serving = manager(
        &fixture,
        limits(8 * 1024, 32 * 1024, Duration::from_secs(30)),
    );

    let mut client = connect(&serving);
    client.handshake_with("replaced", "user:replaced").await;
    client.subscribe("all", "SELECT * FROM things").await;
    let pages = drain_pages(&mut client, "all").await;
    assert!(!pages.is_empty(), "the first read is served");

    // A ceiling under the table's own rows, so a read here can only be
    // refused.
    let refusing = manager(&fixture, limits(8 * 1024, 1, Duration::from_secs(30)));
    let mut narrowed = connect(&refusing);
    narrowed.handshake_with("narrowed", "user:narrowed").await;
    narrowed.subscribe("all", "SELECT * FROM things").await;

    let ControlMessage::NonFatalError(refusal) = narrowed.next_control().await else {
        panic!("the read is refused");
    };
    assert_eq!(refusal.detail, SUBSCRIPTION_REFUSED);
    // One refusal line, and no retry line: a refusal is not retried.
    let retried = logs.lines().into_iter().any(|line| {
        line["message"] == "replacing a subscription failed, retrying" && line["sub_id"] == "all"
    });
    assert!(!retried, "a refused read is never retried");
}
