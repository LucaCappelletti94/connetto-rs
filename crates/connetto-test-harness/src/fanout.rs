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
use connetto_server::openfga::{
    Counted, FgaAuth, ModelSubject, StoreUpkeep, SubjectNaming, Translated,
};
use connetto_server::{PgSnapshotSource, RlsAuth, RuntimeWritableCatalog, SessionConfig};
use diesel::sql_query;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::bb8::Pool;
use openfga_client::client::OpenFgaServiceClient;
use pg2sqlite::prelude::SessionVariableMapping;
use rls2fga::translator::Translator;
use subql::backend::Postgres;
use subql::visibility::openfga::OpenFgaPolicy;

use crate::{
    Client, Fixture, HarnessAuth, PUBLICATION, Server, ServerConfig, drop_slot, pool_for,
    spawn_server, with_user,
};

/// The one-table catalog the fan-out fixture serves.
///
/// It carries an owner column because the executor under measurement answers
/// from the row's own values, and a table with no policy would leave nothing to
/// answer and nothing to count.
pub const FANOUT_PG_DDL: &str =
    "CREATE TABLE items (id INT PRIMARY KEY, owner TEXT NOT NULL, label TEXT);";
/// The policy every connetto table carries: the caller's identity, or a key the
/// caller holds.
///
/// **The measurement depends on this being the shape deployments write**, not a
/// shape chosen to make the number look good. Both arms are read from the
/// changed row, so no watcher costs a round trip, and the counter test asserts
/// exactly zero rather than merely flat.
pub const FANOUT_PG_POLICIES: &str = "ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_p ON items FOR ALL USING (
  owner = current_setting('app.user_id', true)
  OR owner = ANY(string_to_array(current_setting('app.subjects', true), ','))
);";
/// Every subscriber registers this query, so every event matches every one.
const QUERY: &str = "SELECT * FROM items WHERE id > 0";
/// The non-superuser role the snapshot source and the read checks run as.
const READER: &str = "r0_reader";
/// The identity every subscriber authenticates as, and the owner of every row
/// written.
///
/// One identity rather than one per subscriber, so every subscriber may see
/// every row and the per-event delivery counts stay exactly what they were
/// before the policy existed. Distinct identities would change what is
/// delivered as well as what is asked, and the run would measure two things at
/// once.
const OWNER: &str = "fanout-owner";
/// The team every row belongs to under [`PolicyShape::CrossTable`].
const TEAM: i32 = 1;

/// Which policy the fixture serves, and so which half of the criterion the run
/// measures.
///
/// Two shapes rather than one, because the phase claims two different things
/// and a single fixture can only ever defend one of them. Choosing the shape at
/// the call site keeps everything else about the run identical, so a difference
/// in the counters is a difference in the policy and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyShape {
    /// What every connetto table carries: the caller's identity, or a key the
    /// caller holds. Both arms are read from the changed row, so nothing is
    /// asked of the service.
    Row,
    /// A policy that has to look in another table, which one row never settles,
    /// so every watcher becomes a question.
    CrossTable,
    /// The cross-table catalog with a policy that never reads the membership:
    /// items are visible to their owner alone. The membership term expresses
    /// interest through `team_members` while permission ignores it, so the two
    /// can disagree and R27's intersection is observable in both directions.
    OwnerOverTeams,
}

impl PolicyShape {
    /// The statements that create this shape's tables and policy.
    fn setup(self) -> Vec<String> {
        match self {
            Self::Row => vec![
                "CREATE TABLE items (id INT PRIMARY KEY, owner TEXT NOT NULL, label TEXT)".into(),
                "ALTER TABLE items ENABLE ROW LEVEL SECURITY".into(),
                "CREATE POLICY items_p ON items FOR ALL USING (\
                   owner = current_setting('app.user_id', true) \
                   OR owner = ANY(string_to_array(current_setting('app.subjects', true), ',')))"
                    .into(),
            ],
            Self::CrossTable => vec![
                "CREATE TABLE teams (id INT PRIMARY KEY)".into(),
                format!("INSERT INTO teams (id) VALUES ({TEAM})"),
                // `member` is declared first on purpose: the seed projects `team_id`,
                // so a reader that took the first decoded cell instead of the
                // projected one would pass on any table whose key came first.
                "CREATE TABLE team_members (member TEXT NOT NULL, \
                   team_id INT REFERENCES teams(id), PRIMARY KEY (team_id, member))"
                    .into(),
                format!("INSERT INTO team_members (team_id, member) VALUES ({TEAM}, '{OWNER}')"),
                "CREATE TABLE items (id INT PRIMARY KEY, owner TEXT NOT NULL, \
                   team_id INT NOT NULL REFERENCES teams(id), label TEXT)"
                    .into(),
                "ALTER TABLE items ENABLE ROW LEVEL SECURITY".into(),
                "CREATE POLICY items_p ON items FOR SELECT USING (\
                   EXISTS (SELECT 1 FROM team_members \
                           WHERE team_members.team_id = items.team_id \
                             AND team_members.member = current_setting('app.user_id', true)))"
                    .into(),
            ],
            Self::OwnerOverTeams => vec![
                "CREATE TABLE teams (id INT PRIMARY KEY)".into(),
                format!("INSERT INTO teams (id) VALUES ({TEAM})"),
                // `member` is declared first on purpose: the seed projects `team_id`,
                // so a reader that took the first decoded cell instead of the
                // projected one would pass on any table whose key came first.
                "CREATE TABLE team_members (member TEXT NOT NULL, \
                   team_id INT REFERENCES teams(id), PRIMARY KEY (team_id, member))"
                    .into(),
                format!("INSERT INTO team_members (team_id, member) VALUES ({TEAM}, '{OWNER}')"),
                "CREATE TABLE items (id INT PRIMARY KEY, owner TEXT NOT NULL, \
                   team_id INT NOT NULL REFERENCES teams(id), label TEXT)"
                    .into(),
                "ALTER TABLE items ENABLE ROW LEVEL SECURITY".into(),
                "CREATE POLICY items_p ON items FOR SELECT USING (\
                   owner = current_setting('app.user_id', true))"
                    .into(),
            ],
        }
    }

    /// The catalog the materializer and the snapshot source parse.
    fn ddl(self) -> &'static str {
        match self {
            Self::Row => FANOUT_PG_DDL,
            Self::CrossTable | Self::OwnerOverTeams => CROSS_TABLE_PG_DDL,
        }
    }

    /// The policy document the translator reads.
    fn policies(self) -> &'static str {
        match self {
            Self::Row => FANOUT_PG_POLICIES,
            Self::CrossTable => CROSS_TABLE_PG_POLICIES,
            Self::OwnerOverTeams => OWNER_OVER_TEAMS_PG_POLICIES,
        }
    }

    /// One row, written so this shape's policy grants every subscriber, with
    /// `filler` appended to the label so a run chooses how wide the row is.
    fn insert(self, n: u64, filler: &str) -> String {
        match self {
            Self::Row => format!(
                "INSERT INTO items (id, owner, label) VALUES ({n}, '{OWNER}', 'row-{n}{filler}')"
            ),
            Self::CrossTable | Self::OwnerOverTeams => format!(
                "INSERT INTO items (id, owner, team_id, label) \
                 VALUES ({n}, '{OWNER}', {TEAM}, 'row-{n}{filler}')"
            ),
        }
    }

    /// The tables the publication carries.
    fn published(self) -> &'static [&'static str] {
        match self {
            Self::Row => &["items"],
            Self::CrossTable | Self::OwnerOverTeams => &["items", "team_members"],
        }
    }
}

/// How wide the rows a load run writes are, and so how large each event's
/// compressed patch is.
///
/// Two widths because the per-subscriber payload copy scales with patch size as
/// well as with subscriber count, and `docs/architecture/17-fan-out.md` rests
/// the case for sharing the payload on that scaling rather than on the narrow
/// row R0 happened to measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowWidth {
    /// The two-column row R0 measured, whose compressed patch is tens of bytes.
    Narrow,
    /// A row carrying [`WIDE_FILL`] characters of high-entropy text, whose
    /// compressed patch is kilobytes.
    Wide,
}

impl RowWidth {
    /// The text this width appends to every row's label.
    fn filler(self) -> String {
        match self {
            Self::Narrow => String::new(),
            Self::Wide => noise(WIDE_FILL),
        }
    }
}

/// Filler characters [`RowWidth::Wide`] carries. Kilobytes, which is the range a
/// row of a dozen ordinary text columns reaches, rather than a size picked to
/// flatter either reading.
pub const WIDE_FILL: usize = 8192;

/// The catalog the cross-table shape serves.
pub const CROSS_TABLE_PG_DDL: &str = "CREATE TABLE teams (id INT PRIMARY KEY);
CREATE TABLE team_members (member TEXT NOT NULL, team_id INT REFERENCES teams(id), PRIMARY KEY (team_id, member));
CREATE TABLE items (id INT PRIMARY KEY, owner TEXT NOT NULL, team_id INT NOT NULL REFERENCES teams(id), label TEXT);";

/// The cross-table policy: membership of the row's team, which is not in the
/// row.
pub const CROSS_TABLE_PG_POLICIES: &str = "ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_p ON items FOR SELECT USING (
  EXISTS (SELECT 1 FROM team_members
          WHERE team_members.team_id = items.team_id
            AND team_members.member = current_setting('app.user_id', true))
);";

/// An owner-only policy over the cross-table catalog, for the intersection
/// half of R27's proof.
pub const OWNER_OVER_TEAMS_PG_POLICIES: &str = "ALTER TABLE items ENABLE ROW LEVEL SECURITY;
CREATE POLICY items_p ON items FOR SELECT USING (owner = current_setting('app.user_id', true));";
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
pub async fn fanout_run(
    fixture: &Fixture,
    subscribers: u64,
    events: u64,
    shape: PolicyShape,
) -> FanoutRun {
    run_through(fixture, subscribers, events, shape, Executor::Shipped).await
}

/// The same run with both executors answering every question, delivering on the
/// shipped one.
///
/// Its own entry point rather than a flag on the one above, because a parity
/// run asks Postgres once per watcher per event and so cannot also be the run
/// that asserts those round trips are gone.
pub async fn fanout_parity_run(
    fixture: &Fixture,
    subscribers: u64,
    events: u64,
    shape: PolicyShape,
) -> FanoutRun {
    run_through(fixture, subscribers, events, shape, Executor::Both).await
}

async fn run_through(
    fixture: &Fixture,
    subscribers: u64,
    events: u64,
    shape: PolicyShape,
    executor: Executor,
) -> FanoutRun {
    let server = provision_with(fixture, shape, executor, None).await;
    let mut clients = connect_subscribers(&server, subscribers).await;
    tokio::time::sleep(ROUTE_SETTLE).await;

    let before = counters::snapshot();
    for n in 1..=events {
        fixture.exec(&shape.insert(n, "")).await;
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

    /// That wait as a share of the window, which is the number R14's trigger was
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

/// Drive one fixed-duration load run at `subscribers` subscribers over rows of
/// `width`: provision the fixture, connect the subscribers, then write rows as
/// fast as Postgres accepts them while every subscriber consumes what it is
/// sent, and bracket a `duration` window of that steady state with the
/// dispatch-path counters and a wall clock.
///
/// Consuming means acknowledging delivery credits as well as reading frames.
/// Without that the server stops sending after the handshake's credit
/// allowance and queues the rest, and the run would report the rate at which
/// frames pile up in memory instead of the rate at which they arrive.
pub async fn fanout_load(
    fixture: &Fixture,
    subscribers: u64,
    duration: Duration,
    width: RowWidth,
) -> LoadRun {
    let server = provision(fixture, PolicyShape::Row).await;
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
        width.filler(),
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

/// Provision the table, its policy, the reader role, the publication and the
/// slot, put the rules and facts on the authorization service, and start a
/// server answering through the executor the shipped binary answers through.
/// Provision the row-shaped fixture and serve it behind a flag a test lowers
/// to stage an authorization-service outage.
///
/// The flag starts up. Lowering it makes every question fail the way an
/// unreachable service makes it fail, so what a test drives through it is
/// connetto's response rather than the service's failure mode.
pub async fn outage_fixture(fixture: &Fixture) -> (Server, Arc<AtomicBool>) {
    let reachable = Arc::new(AtomicBool::new(true));
    let server = provision_with(
        fixture,
        PolicyShape::Row,
        Executor::Reachable(Arc::clone(&reachable)),
        None,
    )
    .await;
    (server, reachable)
}

/// The row-shaped fixture served through the shipped executor, for a test that
/// drives what visibility delivers rather than measuring what it costs.
///
/// A fan-out run writes every row to one owner so every subscriber sees
/// everything, which is the opposite of what a visibility test needs. This
/// provisions the stack and writes nothing beyond the seed row, leaving the
/// caller to own its rows and their owners.
pub async fn visibility_fixture(fixture: &Fixture) -> Server {
    provision_with(fixture, PolicyShape::Row, Executor::Shipped, None).await
}

/// A server whose policy reads another table: `items` is visible to a member of
/// the row's team, so a grant is a `team_members` row and the rows it decides
/// are in `items`. What R7's teardown needs, because withdrawing a grant here
/// produces no row event on the subscribed table at all.
pub async fn cross_table_visibility_fixture(fixture: &Fixture) -> Server {
    provision_with(fixture, PolicyShape::CrossTable, Executor::Shipped, None).await
}

/// The membership-policy stack with the term enabled end to end: the engine
/// carries the deployment's translator, reverse translation carries the caller
/// pairing, and the snapshot source knows the publication, which is the
/// binary's wiring exactly (R27).
pub async fn membership_term_fixture(fixture: &Fixture) -> Server {
    provision_with(
        fixture,
        PolicyShape::CrossTable,
        Executor::Shipped,
        Some(caller_mapping()),
    )
    .await
}

/// The term over a policy that never reads the membership, so R27's
/// intersection is observable in both directions.
pub async fn term_over_owner_fixture(fixture: &Fixture) -> Server {
    provision_with(
        fixture,
        PolicyShape::OwnerOverTeams,
        Executor::Shipped,
        Some(caller_mapping()),
    )
    .await
}

/// The pairing every example build uses: `current_setting('app.user_id')`
/// spelled `current_app_user()` on the replica.
fn caller_mapping() -> SessionVariableMapping {
    SessionVariableMapping::current_setting(
        connetto_server::capability::DEFAULT_USER_SETTING,
        "current_app_user",
    )
}

async fn provision(fixture: &Fixture, shape: PolicyShape) -> Server {
    provision_with(fixture, shape, Executor::Shipped, None).await
}

/// Which executor a run serves through.
///
/// Separate runs rather than one, because the two measure different things and
/// mixing them makes each number mean less. A parity run asks Postgres once per
/// watcher per event, which is exactly the cost the counter runs exist to
/// assert is gone, so a parity run cannot also be a counter run.
#[derive(Debug, Clone)]
enum Executor {
    /// The shipped one alone, which is what the counters measure.
    Shipped,
    /// Both, delivering on the shipped one, which is what parity measures.
    Both,
    /// The shipped one behind a flag a test lowers, for an outage run.
    Reachable(Arc<AtomicBool>),
}

async fn provision_with(
    fixture: &Fixture,
    shape: PolicyShape,
    executor: Executor,
    caller: Option<SessionVariableMapping>,
) -> Server {
    let mut statements: Vec<String> = vec![
        "DROP TABLE IF EXISTS items CASCADE".into(),
        "DROP TABLE IF EXISTS team_members CASCADE".into(),
        "DROP TABLE IF EXISTS teams CASCADE".into(),
    ];
    statements.extend(shape.setup());
    statements.push(
        "DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'r0_reader') \
         THEN CREATE ROLE r0_reader LOGIN PASSWORD 'r0_reader'; END IF; END $$"
            .into(),
    );
    statements.push("GRANT USAGE ON SCHEMA public TO r0_reader".into());
    statements.push("GRANT SELECT ON ALL TABLES IN SCHEMA public TO r0_reader".into());
    // A row before the store is loaded, so the facts the service answers from
    // exist by the time a subscriber asks.
    statements.push(shape.insert(0, ""));
    let borrowed: Vec<&str> = statements.iter().map(String::as_str).collect();
    fixture.setup(&borrowed).await;
    fixture.start_replication(shape.published()).await;

    let reader_pool = pool_for(&with_user(fixture.admin_url(), READER, READER)).await;
    let snapshot = PgSnapshotSource::from_ddl(reader_pool.clone(), shape.ddl())
        .expect("snapshot source")
        .with_publication(PUBLICATION);
    let (fga, upkeep, translator) = fga_auth(fixture, shape, reader_pool.clone()).await;
    let compared = matches!(executor, Executor::Both);
    let auth = match executor {
        Executor::Shipped | Executor::Both => HarnessAuth::fga(fga),
        // An outage run stages the service going away, so a second opinion that
        // keeps answering would report a disagreement on every held event. It
        // is the one run that compares nothing.
        Executor::Reachable(flag) => HarnessAuth::reachable(flag, fga),
    };
    let server = spawn_server(
        ServerConfig::new(shape.ddl(), fixture.admin_url())
            .with_writable(RuntimeWritableCatalog::builder().writable("items").build())
            .with_translation(translator, caller),
        snapshot,
        auth,
        fixture.admin().clone(),
        fixture.admin().clone(),
    );
    server.install_store_upkeep(upkeep);
    // Since R6 the comparison is asked where the two row versions are still
    // told apart, at the delivery sites, rather than inside the policy: row-level
    // security cannot answer about a previous version at all, so a wrapper over
    // every question would report a difference on each of them.
    if compared {
        server.install_second_opinion(Arc::new(
            RlsAuth::from_ddl(reader_pool, shape.ddl()).expect("second opinion"),
        ));
    }
    server
}

/// Translate the fixture's policy, put it on the service with the facts behind
/// it, and compose the executor the counters are read around.
async fn fga_auth(
    fixture: &Fixture,
    shape: PolicyShape,
    pool: Pool<AsyncPgConnection>,
) -> (crate::HarnessFga, Arc<dyn StoreUpkeep>, Translator) {
    let (channel, store) = fixture.fga_store().await;
    let translated = Translated::of::<String>(
        shape.ddl(),
        shape.policies(),
        connetto_server::capability::DEFAULT_USER_SETTING,
    )
    .expect("the fixture's policy is one rls2fga classifies");
    let mut setup = OpenFgaServiceClient::new(channel.clone());
    let model = translated
        .install_model(&mut setup, &store)
        .await
        .expect("the service accepted the rules");
    let records = translated
        .load_records(fixture.admin())
        .await
        .expect("the generated queries ran");

    let (shapes, translator, reach) = translated.into_parts();
    let naming = Arc::new(SubjectNaming::resolve::<String>(&shapes));
    OpenFgaPolicy::<_, _, ModelSubject<String, String>, Postgres>::new(
        Arc::clone(&shapes),
        setup,
        store.clone(),
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned())
    .write_records(&records)
    .await
    .expect("the facts loaded");

    // The questions go through the counted transport and the setup above does
    // not, so the counter reads change-path round trips alone.
    let delegate = OpenFgaPolicy::new(
        Arc::clone(&shapes),
        OpenFgaServiceClient::new(Counted::new(channel)),
        store,
    )
    .expect("the index carries what the questions need")
    .authorization_model_id(model.id().to_owned());
    let auth = FgaAuth::new(Arc::clone(&shapes), delegate, naming);
    // The store follows the change stream here exactly as it does in the
    // binary, so a row written after the load reaches the service before it
    // reaches a subscriber. Without it a cross-table policy would answer every
    // new row from facts that were never written.
    let upkeep = auth.upkeep(reach, translator.clone(), pool);
    (auth, upkeep, translator)
}

/// Connect `subscribers` clients, each with one subscription over the whole
/// table, and drain each one's initial snapshot.
async fn connect_subscribers(server: &Server, subscribers: u64) -> Vec<Client> {
    let capacity = usize::try_from(subscribers).expect("subscriber count fits usize");
    let mut clients = Vec::with_capacity(capacity);
    for i in 0..subscribers {
        let mut client = server.connect();
        // One identity for every subscriber, so the policy grants each of them
        // every row and the delivery counts stay what they were before it
        // existed. The run suffix is what keeps them apart: the durable session
        // handle is hashed from the whole grant, so without it every connection
        // would supersede the last and only one subscriber would survive.
        client
            .handshake_with(&format!("sub-{i}"), &format!("user:{OWNER}#{i}"))
            .await;
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
async fn write_rows(
    pool: Pool<AsyncPgConnection>,
    written: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    filler: String,
) {
    let mut conn = pool.get().await.expect("writer connection");
    run(&mut conn, WRITER_SETUP.to_owned()).await;
    let mut row: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        row += 1;
        run(&mut conn, PolicyShape::Row.insert(row, &filler)).await;
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

/// Pseudo-random lowercase alphanumerics, `count` of them, from a fixed seed.
///
/// High entropy on purpose: repetitive filler compresses away, so a run would
/// pay a wide row's write cost and still measure a narrow patch. Alphanumeric
/// on purpose too, since the writer interpolates it into a SQL literal.
fn noise(count: usize) -> String {
    const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let index = usize::try_from(state % 36).expect("a value below 36 fits a usize");
        out.push(ALPHABET[index]);
    }
    String::from_utf8(out).expect("the alphabet is ASCII")
}
