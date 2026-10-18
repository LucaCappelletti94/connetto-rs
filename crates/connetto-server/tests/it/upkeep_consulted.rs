//! Regression guard for footgun 1: a store upkeep passed at construction must
//! be called for every CDC event, not silently ignored.
//!
//! Before the fix, the upkeep had to be installed separately via
//! `install_store_upkeep`, and forgetting it produced no error. After the fix,
//! it is a constructor parameter; this test drives a CDC event through the
//! manager and asserts the upkeep was invoked.
//!
//! Needs Docker: the fixture starts its own Postgres for the write target.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use connetto_core::Cursor;
use connetto_core::auth::Principal;
use connetto_core::messages::BindValue;
use connetto_core::test_support::TestGrantChecker;
use connetto_server::openfga::{GrantMove, StoreUpkeep, UpkeepError};
use connetto_server::{
    ManagerBuilder, Materializer, NoConnector, PageSpec, SnapshotEstimate, SnapshotPage,
    SnapshotSource, pg_write_target,
};
use connetto_test_harness::{ConnettoDefaults, Fixture, RosterAuth, WITHHELD_ID};
use subql::{CdcSource, PgChangeEvent, PgCommit, PgCommitPosition, PgSqliteEmuSource, SourceItem};

const PG_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);";

/// Upkeep that counts how many times it is consulted.
struct CountingUpkeep(Arc<AtomicU64>);

impl StoreUpkeep for CountingUpkeep {
    fn keep_current<'a>(
        &'a self,
        _event: &'a PgChangeEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<GrantMove>, UpkeepError>> + Send + 'a>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn key_tables(&self) -> &[String] {
        &[]
    }
}

/// Snapshot that serves nothing; the test exercises the live path only.
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

/// A source that yields one event then signals a clean shutdown.
struct OneEvent(Option<PgChangeEvent>);

impl CdcSource for OneEvent {
    type Commit = PgCommit;
    type Event = PgChangeEvent;
    type Error = io::Error;

    fn next_item(
        &mut self,
    ) -> impl Future<Output = Result<Option<SourceItem<PgChangeEvent, PgCommit>>, io::Error>> + Send
    {
        let next = self.0.take();
        async move { Ok(next.map(SourceItem::Event)) }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "test double has no async work to do"
    )]
    async fn ack(&mut self, _upto: PgCommitPosition) -> Result<(), io::Error> {
        Ok(())
    }
}

/// A store upkeep supplied at construction is called for every CDC event.
///
/// Regression guard: before the fix, omitting `install_store_upkeep` left the
/// `OnceLock` empty and `keep_store_current` returned `Ok(vec![])` silently on
/// every event. Now the upkeep is a constructor argument, so the compiled API
/// enforces its presence when one is supplied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_upkeep_passed_at_construction_is_called_on_cdc_event() {
    let fixture = Fixture::acquire().await;
    let count = Arc::new(AtomicU64::new(0));
    let upkeep: Arc<dyn StoreUpkeep> = Arc::new(CountingUpkeep(Arc::clone(&count)));

    let manager = ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .build()
            .expect("build materializer"),
        EmptySnapshot,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    )
    .with_upkeep(upkeep)
    .build();

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO notes (id, body) VALUES (1, 'hello')")
        .expect("execute dml");
    let event = source
        .next_item()
        .await
        .expect("poll source")
        .and_then(subql::SourceItem::into_event)
        .expect("one event");

    manager
        .ingest(&mut OneEvent(Some(event)), &mut |_| {})
        .await
        .expect("ingest completed");

    assert_eq!(
        count.load(Ordering::Relaxed),
        1,
        "the upkeep must be consulted for every CDC event"
    );
}

/// Upkeep whose store write fails, as when the authorization service is down.
struct FailingUpkeep;

impl StoreUpkeep for FailingUpkeep {
    fn keep_current<'a>(
        &'a self,
        _event: &'a PgChangeEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<GrantMove>, UpkeepError>> + Send + 'a>> {
        Box::pin(async move { Err(UpkeepError::Write("the store is unreachable".to_owned())) })
    }

    fn key_tables(&self) -> &[String] {
        &[]
    }
}

/// A store that could not be brought level holds the event as an unavailable answer, so the ingest loop asks again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_store_write_holds_the_event() {
    let fixture = Fixture::acquire().await;
    let manager = ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .build()
            .expect("build materializer"),
        EmptySnapshot,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    )
    .with_upkeep(Arc::new(FailingUpkeep))
    .build();

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO notes (id, body) VALUES (1, 'hello')")
        .expect("execute dml");
    let event = source
        .next_item()
        .await
        .expect("poll source")
        .and_then(subql::SourceItem::into_event)
        .expect("one event");

    let retries = AtomicU64::new(0);
    let ended = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        manager.ingest(&mut OneEvent(Some(event)), &mut |reported| {
            if matches!(
                reported,
                connetto_server::ReconnectEvent::AuthRetrying { .. }
            ) {
                retries.fetch_add(1, Ordering::Relaxed);
            }
        }),
    )
    .await;
    assert!(
        ended.is_err(),
        "the held event is asked again rather than ending ingest, got {ended:?}"
    );
    assert!(
        retries.load(Ordering::Relaxed) >= 1,
        "the failed write is reported as a retry"
    );
}

/// Upkeep that refuses the change the same way however often it is asked.
struct UnanswerableUpkeep;

impl StoreUpkeep for UnanswerableUpkeep {
    fn keep_current<'a>(
        &'a self,
        _event: &'a PgChangeEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<GrantMove>, UpkeepError>> + Send + 'a>> {
        Box::pin(async move {
            Err(UpkeepError::Unanswerable(
                "the store refuses the change for good".to_owned(),
            ))
        })
    }

    fn key_tables(&self) -> &[String] {
        &[]
    }
}

/// A store refusal that cannot clear ends the change stream naming the table,
/// instead of holding the event and retrying without end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_refusal_that_cannot_clear_ends_ingest() {
    use std::sync::atomic::{AtomicU32, Ordering};

    let fixture = Fixture::acquire().await;
    let manager = ManagerBuilder::new(
        Materializer::builder(PG_DDL)
            .build()
            .expect("build materializer"),
        EmptySnapshot,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        pg_write_target::<ConnettoDefaults>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
    )
    .with_upkeep(Arc::new(UnanswerableUpkeep))
    .build();

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO notes (id, body) VALUES (1, 'refused')")
        .expect("execute dml");
    let event = source
        .next_item()
        .await
        .expect("poll source")
        .and_then(subql::SourceItem::into_event)
        .expect("one event");

    let retries = AtomicU32::new(0);
    let ended = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        manager.ingest(&mut OneEvent(Some(event)), &mut |event| {
            if matches!(event, connetto_server::ReconnectEvent::AuthRetrying { .. }) {
                retries.fetch_add(1, Ordering::Relaxed);
            }
        }),
    )
    .await
    .expect("ingest ends on the refusal instead of retrying without end");
    assert!(
        matches!(&ended, Err(connetto_server::SessionError::AuthorizationUnanswerable { table, .. }) if table == "notes"),
        "the refusal ends ingest naming the table, got {ended:?}"
    );
    assert_eq!(
        retries.load(Ordering::Relaxed),
        0,
        "a refusal the store will not clear is never retried"
    );
}
