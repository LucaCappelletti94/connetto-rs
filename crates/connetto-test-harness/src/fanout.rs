//! The R0 fan-out load fixture: N subscribers over one table, rows written
//! through Postgres, and the dispatch-path counters read around exactly that
//! window.
//!
//! Two shapes share the fixture. [`fanout_run`] writes a fixed number of rows
//! and returns the counter deltas, which is part A's scaling proof.
//! [`fanout_load`] writes flat out for a fixed stretch of wall-clock time and
//! returns a throughput figure beside the share of that stretch the dispatch
//! path spent blocked on the materializer lock, which is part B's measurement.
//!
//! The run uses the RLS policy so the authorization counter counts real
//! per-subscriber Postgres round trips, which is the cost R5b exists to
//! remove. The reader role sees every row (the table carries no policy), so
//! every subscriber receives every event and the per-event counts are exact.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use connetto_core::messages::BulkMessage;
use connetto_core::traits::IncomingFrame;
use connetto_server::counters::{self, CountersSnapshot};
use connetto_server::{PgSnapshotSource, RlsAuth, SessionConfig};
use diesel::sql_query;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::bb8::Pool;

use crate::{
    Client, Fixture, HarnessAuth, PUBLICATION, Server, ServerConfig, drop_slot, pool_for,
    spawn_server, with_user,
};

/// The one-table catalog the fan-out fixture serves.
pub const FANOUT_PG_DDL: &str = "CREATE TABLE items (id INT PRIMARY KEY, label TEXT);";
/// Every subscriber registers this query, so every event matches every one.
const QUERY: &str = "SELECT * FROM items WHERE id > 0";
/// The non-superuser role the snapshot source and the RLS read checks run as.
const READER: &str = "r0_reader";
/// How long one live patch may take to arrive before the run is declared hung.
const LIVE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to let routes settle after the last snapshot. The route is
/// installed just after `SnapshotEnd` is sent (R28), so an earlier write could
/// miss a not-yet-routed subscriber and the exact per-event counts would drift.
const ROUTE_SETTLE: Duration = Duration::from_millis(300);
/// How long a load consumer blocks on one frame before rechecking whether the
/// run has ended.
const CONSUMER_POLL: Duration = Duration::from_millis(100);
/// How long a load run writes and delivers before its measured window opens, so
/// the writer, the replication stream and the fan-out are all in steady state
/// when counting starts.
const WARMUP: Duration = Duration::from_secs(2);
/// Whether the writer waits for the WAL flush on each row.
///
/// It does not, and that is what keeps the source ahead of the dispatch path.
/// One row per transaction with a durable commit tops out near the disk's
/// commit latency, roughly 280 rows a second here, which at ten subscribers is
/// close enough to the dispatch path's own rate to leave the figure ambiguous.
/// **Concurrent writers were tried instead and destabilised the measurement**:
/// at eight the replication stream reconnected six times inside one window
/// (`logical decoding found consistent point` repeating at one LSN in the
/// Postgres log) and the run reported the backoff rather than the dispatch
/// path. The cause was not chased, because R0 measures and does not fix. One
/// writer keeps transactions serial, which is the shape that stayed stable.
const WRITER_SETUP: &str = "SET synchronous_commit TO off";

/// Counter deltas measured across one fan-out window.
#[derive(Debug, Clone, Copy)]
pub struct FanoutRun {
    /// Rows written inside the measured window, one CDC event each.
    pub events: u64,
    /// Dispatch-path counter deltas bracketing exactly that window.
    pub counters: CountersSnapshot,
}

/// Drive one measured fan-out run: provision the table, reader role,
/// publication, and slot, connect `subscribers` clients with one subscription
/// each, write `events` rows as admin, wait until every client received every
/// patch, and return the counter deltas bracketing exactly the
/// write-and-deliver window. Tears the replication state down afterwards so
/// the next run starts clean under the same [`Fixture`].
pub async fn fanout_run(fixture: &Fixture, subscribers: u64, events: u64) -> FanoutRun {
    let server = provision(fixture).await;
    let mut clients = connect_subscribers(&server, subscribers).await;
    tokio::time::sleep(ROUTE_SETTLE).await;

    let before = counters::snapshot();
    for n in 1..=events {
        fixture
            .exec(&format!("INSERT INTO items VALUES ({n}, 'row-{n}')"))
            .await;
    }
    // The dispatch loop delivers subscribers in order per event, so once the
    // last client holds its last patch, every counted operation has happened.
    for client in &mut clients {
        for _ in 0..events {
            client.wait_for_live(LIVE_TIMEOUT).await;
        }
    }
    let after = counters::snapshot();

    for mut client in clients {
        client.close().await;
    }
    teardown(fixture, server).await;

    FanoutRun {
        events,
        counters: after.since(&before),
    }
}

/// One fixed-duration load run: what got through, and what it cost.
///
/// Two of these fields exist to say whether the throughput figure means
/// anything. [`writes`](Self::writes) well above [`events`](Self::events)
/// proves the writer stayed ahead, so the rate is the dispatch path's ceiling
/// rather than the writer's, and [`events_dispatched`](Self::events_dispatched)
/// close to `events` proves frames reached subscribers instead of queueing
/// behind spent delivery credits.
#[derive(Debug, Clone, Copy)]
pub struct LoadRun {
    /// Subscribers connected for the whole run, one subscription each.
    pub subscribers: u64,
    /// The measured window, wall clock.
    pub elapsed: Duration,
    /// Source events every subscriber received inside the window: live patches
    /// delivered across all subscribers, over the subscriber count.
    pub events: u64,
    /// Rows the writer committed inside the window.
    pub writes: u64,
    /// Dispatch-path counter deltas bracketing exactly the window.
    pub counters: CountersSnapshot,
}

impl LoadRun {
    /// Source events delivered to every subscriber, per second. This is R0's
    /// baseline figure.
    pub fn events_per_second(&self) -> f64 {
        rate(self.events, self.elapsed)
    }

    /// Rows the writer committed per second.
    pub fn writes_per_second(&self) -> f64 {
        rate(self.writes, self.elapsed)
    }

    /// Source events the dispatch loop fanned out, from the per-subscriber
    /// route clone.
    pub fn events_dispatched(&self) -> u64 {
        self.counters.fanout_route_clones / self.subscribers.max(1)
    }

    /// Time the dispatch path spent blocked waiting for the materializer lock.
    pub fn lock_wait(&self) -> Duration {
        Duration::from_nanos(self.counters.materializer_lock_wait_nanos)
    }

    /// That wait as a share of the window, which is the number R14's trigger is
    /// read from. The wait is summed across tasks, so a share above one means
    /// callers were queued behind each other rather than merely waiting.
    pub fn lock_wait_fraction(&self) -> f64 {
        let window = self.elapsed.as_secs_f64();
        if window > 0.0 {
            self.lock_wait().as_secs_f64() / window
        } else {
            0.0
        }
    }
}

impl fmt::Display for LoadRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} subscribers, {:.1?} window",
            self.subscribers, self.elapsed
        )?;
        writeln!(
            f,
            "  events delivered per second  {:.1}",
            self.events_per_second()
        )?;
        writeln!(
            f,
            "  rows written per second      {:.1}",
            self.writes_per_second()
        )?;
        writeln!(
            f,
            "  events dispatched, delivered {}, {}",
            self.events_dispatched(),
            self.events
        )?;
        writeln!(
            f,
            "  materializer lock takes      {}",
            self.counters.materializer_lock_takes
        )?;
        writeln!(
            f,
            "  materializer lock wait       {:.3?}, {:.4} of the window",
            self.lock_wait(),
            self.lock_wait_fraction()
        )?;
        writeln!(
            f,
            "  authorization round trips    {}",
            self.counters.authorization_calls
        )?;
        writeln!(
            f,
            "  route clones                 {}",
            self.counters.fanout_route_clones
        )?;
        write!(
            f,
            "  payload bytes copied         {}",
            self.counters.fanout_payload_bytes
        )
    }
}

/// Drive one fixed-duration load run at `subscribers` subscribers: provision
/// the fixture, connect the subscribers, then write rows as fast as Postgres
/// accepts them while every subscriber consumes what it is sent, and bracket a
/// `duration` window of that steady state with the dispatch-path counters and a
/// wall clock.
///
/// Consuming means acknowledging delivery credits as well as reading frames.
/// Without that the server stops sending after the handshake's credit
/// allowance and queues the rest, and the run would report the rate at which
/// frames pile up in memory instead of the rate at which they arrive.
pub async fn fanout_load(fixture: &Fixture, subscribers: u64, duration: Duration) -> LoadRun {
    let server = provision(fixture).await;
    let clients = connect_subscribers(&server, subscribers).await;
    tokio::time::sleep(ROUTE_SETTLE).await;

    let stop = Arc::new(AtomicBool::new(false));
    let delivered = Arc::new(AtomicU64::new(0));
    let written = Arc::new(AtomicU64::new(0));
    // Half the credit window: often enough that the server never runs dry,
    // rarely enough to avoid a control frame per patch.
    let ack_batch = (SessionConfig::new().initial_credits() / 2).max(1);

    let consumers: Vec<_> = clients
        .into_iter()
        .map(|client| {
            tokio::spawn(consume(
                client,
                Arc::clone(&delivered),
                Arc::clone(&stop),
                ack_batch,
            ))
        })
        .collect();
    let writer = tokio::spawn(write_rows(
        fixture.admin().clone(),
        Arc::clone(&written),
        Arc::clone(&stop),
    ));

    tokio::time::sleep(WARMUP).await;
    let delivered_open = delivered.load(Ordering::Relaxed);
    let written_open = written.load(Ordering::Relaxed);
    let counters_open = counters::snapshot();
    let opened = Instant::now();

    tokio::time::sleep(duration).await;

    let elapsed = opened.elapsed();
    let counters_close = counters::snapshot();
    let delivered_close = delivered.load(Ordering::Relaxed);
    let written_close = written.load(Ordering::Relaxed);

    stop.store(true, Ordering::Relaxed);
    let _ = writer.await;
    for consumer in consumers {
        let _ = consumer.await;
    }
    teardown(fixture, server).await;

    LoadRun {
        subscribers,
        elapsed,
        events: (delivered_close - delivered_open) / subscribers.max(1),
        writes: written_close - written_open,
        counters: counters_close.since(&counters_open),
    }
}

/// Provision the table, reader role, publication and slot, and start a server
/// reading and authorizing through that reader role.
async fn provision(fixture: &Fixture) -> Server {
    // A prior suite in the same full run may have left the shared publication
    // behind (Fixture::acquire only cleans the slot), so drop it first.
    fixture
        .exec(&format!("DROP PUBLICATION IF EXISTS {PUBLICATION}"))
        .await;
    fixture
        .setup(&[
            "DROP TABLE IF EXISTS items CASCADE",
            "CREATE TABLE items (id INT PRIMARY KEY, label TEXT)",
            "ALTER TABLE items REPLICA IDENTITY FULL",
            "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'r0_reader') \
             THEN CREATE ROLE r0_reader LOGIN PASSWORD 'r0_reader'; END IF; END $$",
            "GRANT USAGE ON SCHEMA public TO r0_reader",
            "GRANT SELECT ON items TO r0_reader",
        ])
        .await;
    fixture.start_replication(&["items"]).await;

    let reader_pool = pool_for(&with_user(fixture.admin_url(), READER, READER)).await;
    let snapshot =
        PgSnapshotSource::from_ddl(reader_pool.clone(), FANOUT_PG_DDL).expect("snapshot source");
    let auth = HarnessAuth::rls(RlsAuth::from_ddl(reader_pool, FANOUT_PG_DDL).expect("rls auth"));
    spawn_server(
        ServerConfig::new(FANOUT_PG_DDL, fixture.admin_url()),
        snapshot,
        auth,
        fixture.admin().clone(),
        fixture.admin().clone(),
    )
}

/// Connect `subscribers` clients, each with one subscription over the whole
/// table, and drain each one's initial snapshot.
async fn connect_subscribers(server: &Server, subscribers: u64) -> Vec<Client> {
    let capacity = usize::try_from(subscribers).expect("subscriber count fits usize");
    let mut clients = Vec::with_capacity(capacity);
    for i in 0..subscribers {
        let mut client = server.connect();
        client.handshake(&format!("sub-{i}")).await;
        client.subscribe("fanout", QUERY).await;
        client.expect_snapshot("fanout").await;
        clients.push(client);
    }
    clients
}

/// Drop the server and every piece of replication state it left, so the next
/// run starts clean under the same [`Fixture`].
async fn teardown(fixture: &Fixture, server: Server) {
    drop(server);
    drop_slot(fixture.admin()).await;
    fixture
        .exec(&format!("DROP PUBLICATION IF EXISTS {PUBLICATION}"))
        .await;
    fixture.exec("DROP TABLE IF EXISTS items CASCADE").await;
}

/// Read one subscriber's frames until the run ends, counting live patches and
/// returning delivery credits as they are spent.
async fn consume(mut client: Client, delivered: Arc<AtomicU64>, stop: Arc<AtomicBool>, batch: u32) {
    let mut unacked = 0;
    while !stop.load(Ordering::Relaxed) {
        let Ok(frame) = tokio::time::timeout(CONSUMER_POLL, client.recv()).await else {
            continue;
        };
        match frame {
            Some(IncomingFrame::Bulk(BulkMessage::LivePatch(_))) => {
                delivered.fetch_add(1, Ordering::Relaxed);
                unacked += 1;
                if unacked >= batch {
                    client.ack_credits(unacked).await;
                    unacked = 0;
                }
            }
            Some(_) => {}
            None => return,
        }
    }
    client.close().await;
}

/// Insert rows as admin, one transaction each, until the run ends.
///
/// Holds one connection for the whole run rather than checking one out per
/// row, so [`WRITER_SETUP`] applies to every insert and the pool round trip
/// leaves the writer's rate.
async fn write_rows(pool: Pool<AsyncPgConnection>, written: Arc<AtomicU64>, stop: Arc<AtomicBool>) {
    let mut conn = pool.get().await.expect("writer connection");
    run(&mut conn, WRITER_SETUP.to_owned()).await;
    let mut row: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        row += 1;
        run(
            &mut conn,
            format!("INSERT INTO items VALUES ({row}, 'row-{row}')"),
        )
        .await;
        written.fetch_add(1, Ordering::Relaxed);
    }
}

/// Run one statement on the writer's own connection. The diesel trait is
/// imported here rather than at module scope because its blanket `load` shadows
/// the one on an atomic behind an `Arc`.
async fn run(conn: &mut AsyncPgConnection, sql: String) {
    use diesel_async::RunQueryDsl;

    sql_query(sql)
        .execute(conn)
        .await
        .expect("writer statement");
}

/// A per-second rate. Every count here is far below the range `f64` holds
/// exactly, so the cast loses nothing.
#[allow(clippy::cast_precision_loss)]
fn rate(count: u64, window: Duration) -> f64 {
    let seconds = window.as_secs_f64();
    if seconds > 0.0 {
        count as f64 / seconds
    } else {
        0.0
    }
}
