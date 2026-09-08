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
    InMemoryOplog, Materializer, NoConnector, NoSigner, PageSpec, RequestGuard, SessionConfig,
    SessionManager, SnapshotEstimate, SnapshotPage, SnapshotSource, ThrottleConfig,
    pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};
use subql::{CdcSource, ChangeEvent, PgLsn, PgSqliteEmuSource};

const PG_DDL: &str = "CREATE TABLE notes (id INT PRIMARY KEY, body TEXT);";

/// Upkeep that counts how many times it is consulted.
struct CountingUpkeep(Arc<AtomicU64>);

impl StoreUpkeep for CountingUpkeep {
    fn keep_current<'a>(
        &'a self,
        _event: &'a ChangeEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<GrantMove>, UpkeepError>> + Send + 'a>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move { Ok(Vec::new()) })
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
struct OneEvent(Option<ChangeEvent>);

impl CdcSource for OneEvent {
    type Event = ChangeEvent;
    type Error = io::Error;

    fn next_event(
        &mut self,
    ) -> impl Future<Output = Result<Option<ChangeEvent>, io::Error>> + Send {
        let next = self.0.take();
        async move { Ok(next) }
    }

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "test double has no async work to do"
    )]
    async fn ack(&mut self, _upto: PgLsn) -> Result<(), io::Error> {
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

    let manager = SessionManager::with_oplog(
        Materializer::new(PG_DDL).expect("build materializer"),
        EmptySnapshot,
        RosterAuth::granting("alice").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        NoConnector,
        InMemoryOplog::default(),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
        Some(upkeep),
        NoSigner,
        ThrottleConfig::default(),
    );

    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO notes (id, body) VALUES (1, 'hello')")
        .expect("execute dml");
    let event = source
        .next_event()
        .await
        .expect("poll source")
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
