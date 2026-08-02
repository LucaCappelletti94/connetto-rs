//! The R0 fan-out load fixture: N subscribers over one table, M rows written
//! through Postgres, and the dispatch-path counters read around exactly that
//! window.
//!
//! The run uses the RLS policy so the authorization counter counts real
//! per-subscriber Postgres round trips, which is the cost R5b exists to
//! remove. The reader role sees every row (the table carries no policy), so
//! every subscriber receives every event and the per-event counts are exact.

use std::time::Duration;

use connetto_server::counters::{self, CountersSnapshot};
use connetto_server::{PgSnapshotSource, RlsAuth, RuntimeWritableCatalog, SessionConfig};

use crate::{
    Fixture, HarnessAuth, PUBLICATION, ServerConfig, drop_slot, pool_for, spawn_server, with_user,
};

/// The one-table catalog the fan-out fixture serves.
pub const FANOUT_PG_DDL: &str = "CREATE TABLE items (id INT PRIMARY KEY, label TEXT);";
/// Every subscriber registers this query, so every event matches every one.
const QUERY: &str = "SELECT * FROM items WHERE id > 0";
/// The non-superuser role the snapshot source and the RLS read checks run as.
const READER: &str = "r0_reader";
/// How long one live patch may take to arrive before the run is declared hung.
const LIVE_TIMEOUT: Duration = Duration::from_secs(30);

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
    let server = spawn_server(
        ServerConfig {
            pg_ddl: FANOUT_PG_DDL.to_owned(),
            writable: RuntimeWritableCatalog::default(),
            admin_url: fixture.admin_url().to_owned(),
            session: SessionConfig::default(),
        },
        snapshot,
        auth,
        fixture.admin().clone(),
        fixture.admin().clone(),
    );

    let capacity = usize::try_from(subscribers).expect("subscriber count fits usize");
    let mut clients = Vec::with_capacity(capacity);
    for i in 0..subscribers {
        let mut client = server.connect();
        client.handshake(&format!("sub-{i}")).await;
        client.subscribe("fanout", QUERY).await;
        client.expect_snapshot("fanout").await;
        clients.push(client);
    }
    // The route is installed just after SnapshotEnd is sent (R28), so give the
    // server a beat before the first write, or an early event could miss a
    // not-yet-routed subscriber and the exact per-event counts would drift.
    tokio::time::sleep(Duration::from_millis(300)).await;

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
    drop(server);
    drop_slot(fixture.admin()).await;
    fixture
        .exec(&format!("DROP PUBLICATION IF EXISTS {PUBLICATION}"))
        .await;
    fixture.exec("DROP TABLE IF EXISTS items CASCADE").await;

    FanoutRun {
        events,
        counters: after.since(&before),
    }
}
