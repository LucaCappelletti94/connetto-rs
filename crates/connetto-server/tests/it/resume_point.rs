//! Where a reconnected change feed resumes, and when that position is dropped.
//!
//! A reconnect inside one process starts right after the last row or commit the
//! ingest handled, so a feed that dropped mid-transaction delivers the rest of
//! that transaction and its commit, and nothing twice. A changed timeline or a
//! declared gap drops the position, because resuming after it would skip
//! changes the database never had.
//!
//! Needs Docker: the fixture starts its own Postgres for the write target.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;

use parking_lot::Mutex;

use connetto_core::Cursor;
use connetto_core::auth::Principal;
use connetto_core::messages::BindValue;
use connetto_core::test_support::TestGrantChecker;
use connetto_server::{
    Materializer, NoConnector, NoSigner, Oplog, OplogConfig, PageSpec, PgOplog, ReconnectPolicy,
    RequestGuard, ResumePoint, SessionConfig, SessionManager, SnapshotEstimate, SnapshotPage,
    SnapshotSource, TimelineHistory, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};
use subql::{
    CdcSource, PgChangeEvent, PgCommit, PgCommitPosition, PgLsn, PgSqliteEmuSource, SourceItem,
};

const PG_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);";

/// Its own log table, so this never contends with the shared fixture's.
const OPLOG: &str = "connetto_oplog_resume";

/// The cluster the histories here belong to.
const CLUSTER: u64 = 7;

type Item = SourceItem<PgChangeEvent, PgCommit>;

/// Snapshot that serves nothing, since no subscription is opened.
struct EmptySnapshot;

impl SnapshotSource for EmptySnapshot {
    type Error = std::convert::Infallible;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "test double has no async work to do"
    )]
    async fn estimate(
        &self,
        _sql: &str,
        _binds: &[BindValue],
        _caller: &Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        Ok(SnapshotEstimate {
            rows: 0.0,
            width: 0,
        })
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "test double has no async work to do"
    )]
    async fn snapshot_page(
        &self,
        _sql: &str,
        _binds: &[BindValue],
        _caller: &Principal,
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

/// A source that yields its items, then fails when `fails` is set and ends cleanly otherwise, recording every acknowledgement.
struct Scripted {
    items: VecDeque<Item>,
    fails: bool,
    acks: Arc<Mutex<Vec<PgCommitPosition>>>,
}

impl CdcSource for Scripted {
    type Commit = PgCommit;
    type Event = PgChangeEvent;
    type Error = io::Error;

    fn next_item(&mut self) -> impl Future<Output = Result<Option<Item>, io::Error>> + Send {
        let next = match self.items.pop_front() {
            Some(item) => Ok(Some(item)),
            None if self.fails => Err(io::Error::other("the stream dropped")),
            None => Ok(None),
        };
        async move { next }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "test double has no async work to do"
    )]
    async fn ack(&mut self, upto: PgCommitPosition) -> Result<(), io::Error> {
        self.acks.lock().push(upto);
        Ok(())
    }
}

/// One transaction of two rows and its commit, as the emulator stamps them.
fn two_row_transaction() -> (PgChangeEvent, PgChangeEvent, PgCommit) {
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO notes (id, body) VALUES (1, 'first')")
        .expect("first row");
    source
        .execute_sql("INSERT INTO notes (id, body) VALUES (2, 'second')")
        .expect("second row");
    let mut items = source.drain().expect("drain").into_iter();
    let (
        Some(SourceItem::Event(first)),
        Some(SourceItem::Event(second)),
        Some(SourceItem::Commit(commit)),
        None,
    ) = (items.next(), items.next(), items.next(), items.next())
    else {
        panic!(
            "rows accumulated between two drains form one transaction of two rows and its commit"
        );
    };
    assert_eq!(
        first.position().commit_lsn(),
        second.position().commit_lsn(),
        "both rows belong to one commit"
    );
    (first, second, commit)
}

type Manager = SessionManager<EmptySnapshot, RosterAuth, ConnettoWatermark, NoConnector, PgOplog>;

/// A manager over a fresh log table, and a second handle on that table for the test to read it through.
async fn manager(fixture: &Fixture) -> (Arc<Manager>, PgOplog) {
    fixture
        .setup(&[
            &format!("DROP TABLE IF EXISTS {OPLOG}"),
            &format!("DROP TABLE IF EXISTS {}", PgOplog::commit_table(OPLOG)),
        ])
        .await;
    let probe = PgOplog::new(fixture.admin().clone(), OPLOG, OplogConfig::default());
    probe.ensure_schema().await.expect("provision the log");
    let manager = SessionManager::with_oplog(
        Materializer::new(PG_DDL).expect("build materializer"),
        EmptySnapshot,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        PgOplog::new(fixture.admin().clone(), OPLOG, OplogConfig::default()),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
        None,
        NoSigner,
    );
    (manager, probe)
}

/// What one run of the ingest across a drop in the middle of a transaction saw.
struct Run {
    /// Where each connect was told to start.
    starts: Vec<Option<PgCommitPosition>>,
    /// What each connection's source was acknowledged.
    acks: Vec<Vec<PgCommitPosition>>,
    /// The handle the manager handed to `connect`, read after the run.
    resume: ResumePoint,
}

/// Deliver the first row, drop the stream, then deliver the second row and the commit on the reconnect.
async fn ingest_across_a_drop(manager: &Manager, items: [Item; 3]) -> Run {
    let [first, second, commit] = items;
    let mut scripts = VecDeque::from([
        (VecDeque::from([first]), true),
        (VecDeque::from([second, commit]), false),
    ]);
    let starts = Arc::new(Mutex::new(Vec::new()));
    let acks: Vec<Arc<Mutex<Vec<PgCommitPosition>>>> =
        (0..2).map(|_| Arc::new(Mutex::new(Vec::new()))).collect();
    let handle = Arc::new(Mutex::new(None::<ResumePoint>));
    let connect = {
        let (starts, acks, handle) = (Arc::clone(&starts), acks.clone(), Arc::clone(&handle));
        move |resume: ResumePoint| {
            let mut starts = starts.lock();
            let attempt = starts.len();
            starts.push(resume.get());
            *handle.lock() = Some(resume);
            let (items, fails) = scripts.pop_front().expect("no more than two connects");
            let source = Scripted {
                items,
                fails,
                acks: Arc::clone(&acks[attempt]),
            };
            async move { Ok::<_, io::Error>(source) }
        }
    };
    let policy = ReconnectPolicy::new()
        .with_initial_backoff(std::time::Duration::from_millis(1))
        .with_max_attempts(Some(3));
    manager
        .ingest_with_reconnect(connect, &policy, |_| {})
        .await
        .expect("the second connection ends cleanly");
    let starts = starts.lock().clone();
    let acks = acks.iter().map(|acked| acked.lock().clone()).collect();
    let resume = handle.lock().take().expect("connect ran");
    Run {
        starts,
        acks,
        resume,
    }
}

/// A feed that dropped after a transaction's first row resumes after that row, receives the rest and the commit once, and records the commit before acknowledging it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_feed_dropped_mid_transaction_resumes_after_the_last_row_it_handled() {
    let fixture = Fixture::acquire().await;
    let (manager, probe) = manager(&fixture).await;
    let (first, second, commit) = two_row_transaction();
    let (first_at, second_at) = (first.position(), second.position());

    let run = ingest_across_a_drop(
        &manager,
        [
            SourceItem::Event(first),
            SourceItem::Event(second),
            SourceItem::Commit(commit),
        ],
    )
    .await;

    assert_eq!(
        run.starts,
        vec![None, Some(first_at)],
        "the first connect lets the slot decide and the reconnect starts right after the row already handled"
    );
    assert_eq!(
        run.acks,
        vec![Vec::new(), vec![commit.position()]],
        "a row alone is never acknowledged and the commit is acknowledged once"
    );
    assert_eq!(run.resume.get(), Some(commit.position()));
    assert_eq!(
        probe.last_commit().await.expect("read the log"),
        Some(commit),
        "the commit was recorded before it was acknowledged"
    );
    let logged: Vec<_> = probe
        .entries_since(PgCommitPosition::before_commit(PgLsn(0)))
        .await
        .expect("read the log")
        .iter()
        .map(connetto_server::ChangeRecord::position)
        .collect();
    assert_eq!(logged, vec![first_at, second_at], "each row is logged once");
}

/// A changed timeline drops the resume position, since a position past the switch names changes the new primary never had.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_timeline_drops_the_resume_position() {
    let fixture = Fixture::acquire().await;
    let (manager, _probe) = manager(&fixture).await;
    let (first, second, commit) = two_row_transaction();
    let run = ingest_across_a_drop(
        &manager,
        [
            SourceItem::Event(first),
            SourceItem::Event(second),
            SourceItem::Commit(commit),
        ],
    )
    .await;
    assert_eq!(run.resume.get(), Some(commit.position()));

    manager
        .reconcile_history(TimelineHistory::first(CLUSTER))
        .await;
    assert_eq!(
        run.resume.get(),
        Some(commit.position()),
        "the first history read is not a change and keeps the position"
    );
    manager
        .reconcile_history(TimelineHistory::first(CLUSTER))
        .await;
    assert_eq!(
        run.resume.get(),
        Some(commit.position()),
        "reading the same history again keeps it too"
    );
    manager
        .reconcile_history(TimelineHistory::parse(CLUSTER, 2, "1\t0/10\tpromoted").expect("parse"))
        .await;
    assert_eq!(run.resume.get(), None, "a promotion drops it");
}

/// A declared gap drops the resume position, and an ordinary resume at the recorded commit keeps it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_gap_drops_the_resume_position() {
    let fixture = Fixture::acquire().await;
    let (manager, _probe) = manager(&fixture).await;
    let (first, second, commit) = two_row_transaction();
    let run = ingest_across_a_drop(
        &manager,
        [
            SourceItem::Event(first),
            SourceItem::Event(second),
            SourceItem::Commit(commit),
        ],
    )
    .await;
    let end = commit.end_lsn().0;

    assert_eq!(
        manager.reconcile_stream(end).await.expect("reconcile"),
        None
    );
    assert_eq!(
        run.resume.get(),
        Some(commit.position()),
        "a slot resuming exactly at the recorded end keeps the position"
    );
    assert_eq!(
        manager.reconcile_stream(end + 1).await.expect("reconcile"),
        Some(end + 1)
    );
    assert_eq!(run.resume.get(), None, "a gap drops it");
}
