//! R0 part B: the baseline events-per-second figure and the lock-wait share.
//!
//! **Kept out of the Docker sweep on purpose**, decided with the maintainer on
//! 2026-08-07. It runs for a fixed stretch of wall-clock time at each of two
//! subscriber counts, and a throughput figure taken while the rest of the sweep
//! is hammering the same Postgres is not a baseline a later run can be compared
//! against. So it needs `CONNETTO_LOAD_RUN` as well as `--ignored`, and it wants
//! an otherwise quiet machine:
//!
//! ```text
//! CONNETTO_LOAD_RUN=1 DATABASE_URL=postgres://... \
//!   cargo test --release -p connetto-test-harness --test fanout_load \
//!   -- --ignored --nocapture
//! ```
//!
//! It asserts nothing about the throughput itself, because there is no line to
//! draw yet: today every event still costs one Postgres round trip per
//! subscriber, so tens per second is the expected answer and R5b is what has to
//! move it. What it does assert is the two conditions that make the figure mean
//! anything, since a load run can report a fast number by measuring the wrong
//! thing: the writer must stay ahead of the dispatch loop, and what the
//! dispatch loop fanned out must actually have reached subscribers.

use std::time::Duration;

use connetto_test_harness::Fixture;
use connetto_test_harness::fanout::{RowWidth, fanout_load};

/// The small run's subscriber count, matching the counter test.
const SMALL: u64 = 10;
/// The large run's subscriber count, an order of magnitude above [`SMALL`].
const LARGE: u64 = 100;
/// The measured window per subscriber count.
const WINDOW: Duration = Duration::from_secs(10);
/// How far dispatch may run ahead of delivery before the delivered rate is an
/// understatement rather than a measurement. Patches dispatched just before the
/// window closes arrive just after it, so the gap is never exactly zero.
const DELIVERY_SLACK: f64 = 1.10;
/// How far the writer must stay ahead of the dispatch loop. Merely ahead is the
/// literal condition for a backlog to build, but a run that only just clears it
/// is one slow disk away from reporting the writer's rate instead.
const WRITER_MARGIN: u64 = 2;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "requires a running Postgres with wal_level=logical (Docker) and CONNETTO_LOAD_RUN"]
async fn baseline_throughput_and_lock_wait() {
    if std::env::var_os("CONNETTO_LOAD_RUN").is_none() {
        println!("skipped: set CONNETTO_LOAD_RUN to take a baseline measurement");
        return;
    }

    let fixture = Fixture::acquire().await;
    for width in [RowWidth::Narrow, RowWidth::Wide] {
        for subscribers in [SMALL, LARGE] {
            let run = fanout_load(&fixture, subscribers, WINDOW, width).await;
            println!("{width:?} rows, {run}");

            assert!(
                run.events > 0,
                "no event reached a subscriber at {subscribers} subscribers, {width:?} rows"
            );
            assert!(
                run.writes >= WRITER_MARGIN * run.events,
                "the writer did not stay clear of the dispatch loop at {subscribers} \
                 subscribers, {width:?} rows, so this risks measuring the writer: {} rows \
                 written against {} events delivered",
                run.writes,
                run.events
            );
            let dispatched = run.events_dispatched();
            let ceiling = DELIVERY_SLACK * rounded(run.events);
            assert!(
                rounded(dispatched) <= ceiling,
                "the dispatch loop ran ahead of delivery at {subscribers} subscribers, \
                 {width:?} rows, so frames queued rather than arriving: {dispatched} \
                 dispatched against {} delivered",
                run.events
            );
        }
    }
}

/// A count as a float, for the delivery-gap comparison. These are thousands at
/// most, far below the range `f64` holds exactly.
#[allow(clippy::cast_precision_loss)]
fn rounded(count: u64) -> f64 {
    count as f64
}
