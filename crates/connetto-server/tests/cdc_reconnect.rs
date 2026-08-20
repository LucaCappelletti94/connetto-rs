//! Docker-gated CDC reconnect test.
//!
//! Drives real Postgres logical replication through `ingest_with_reconnect`,
//! then terminates the walsender mid-stream. The ingest loop must reconnect and
//! resume from the slot's confirmed position, so an insert made after the drop
//! still reaches a subscribed client. This is the Phase 6 reliability contract:
//! a dropped replication connection does not lose events.
//!
//! Needs Docker: the fixture starts its own Postgres.
//!

#![allow(clippy::too_many_lines)]

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use connetto_core::messages::{
    BulkMessage, ControlMessage, Handshake, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    Materializer, ReconnectPolicy, RequestGuard, SessionConfig, SessionManager, Snapshot,
    SnapshotSource, loopback, pg_write_target,
};
use connetto_test_harness::{
    ConnettoWatermark, Fixture, PUBLICATION, RosterAuth, SLOT, WITHHELD_ID,
};
use diesel::prelude::*;
use diesel::sql_query;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::bb8::Pool;
use sqlparser::dialect::PostgreSqlDialect;
use subql::{ParserDB, PgStreamingCdcSource, PgStreamingConfig};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

async fn exec(pool: &Pool<AsyncPgConnection>, sql: &str) {
    let mut conn = pool.get().await.expect("admin connection");
    diesel_async::RunQueryDsl::execute(sql_query(sql), &mut *conn)
        .await
        .unwrap_or_else(|err| panic!("statement failed ({sql}): {err}"));
}

/// A snapshot source with no initial rows; the test observes only live CDC.
struct EmptySnapshot;

impl SnapshotSource for EmptySnapshot {
    type Error = Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &connetto_core::Principal,
    ) -> Result<Snapshot, Self::Error> {
        Ok(Snapshot {
            patchset: Vec::new(),
            cursor: Cursor::new(Vec::new()),
        })
    }
}

diesel::table! {
    /// Row from the orders test fixture.
    orders (id) {
        /// Order identifier, the primary key.
        id -> diesel::sql_types::BigInt,
        /// Unit price.
        price -> diesel::sql_types::Double,
        /// Number of units.
        quantity -> diesel::sql_types::BigInt,
        /// Order status.
        status -> diesel::sql_types::Text,
    }
}

fn client_replica() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    conn
}

/// Read frames until the replica holds `want_id`, applying every patch. Returns
/// false on timeout, a closed transport, or a transport error.
async fn drain_until<T: Transport>(
    client: &mut T,
    applier: &Materializer,
    replica: &mut SqliteConnection,
    want_id: i64,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, client.recv()).await {
            Ok(Ok(Some(IncomingFrame::Bulk(bulk)))) => {
                let zstd = match bulk {
                    BulkMessage::LivePatch(patch) => patch.patchset_zstd,
                    BulkMessage::SnapshotPatch(patch) => patch.patchset_zstd,
                    BulkMessage::MutationPatch(_) => continue,
                };
                // An empty snapshot patch may not parse; that is fine.
                applier.apply_diffset(&zstd, replica).ok();
                let present: Vec<i64> = orders::table
                    .select(orders::id)
                    .load(replica)
                    .expect("read replica");
                if present.contains(&want_id) {
                    return true;
                }
            }
            Ok(Ok(Some(IncomingFrame::Control(_)))) => {}
            _ => return false,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cdc_ingest_reconnects_after_walsender_drop() {
    let fixture = Fixture::acquire().await;
    let admin = fixture.admin().clone();
    fixture
        .setup(&["DROP TABLE IF EXISTS orders CASCADE", PG_DDL])
        .await;
    fixture.start_replication(&["orders"]).await;

    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        EmptySnapshot,
        RosterAuth::granting("reader").withholding(WITHHELD_ID),
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );
    let applier = Materializer::new(PG_DDL).expect("build applier");
    let mut replica = client_replica();

    let (server_transport, mut client) = loopback();
    let _server = tokio::spawn(manager.clone().serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "reader")
                .with_grant(connetto_core::messages::Grant::new("user:reader")),
        ))
        .await
        .expect("send handshake");
    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::new(QUERY),
        }))
        .await
        .expect("send subscribe");

    // Resilient ingest: reconnect the streaming source with a brisk backoff.
    let policy = ReconnectPolicy::new()
        .with_initial_backoff(Duration::from_millis(100))
        .with_max_backoff(Duration::from_secs(2))
        .with_max_attempts(Some(50))
        .with_healthy_after(Duration::from_secs(1));
    let url = fixture.admin_url().to_owned();
    let ingest_manager = manager.clone();
    let _ingest = tokio::spawn(async move {
        let connect = || {
            let url = url.clone();
            async move {
                let catalog = ParserDB::parse::<PostgreSqlDialect>(PG_DDL)
                    .map_err(|err| format!("{err:?}"))?;
                let config = PgStreamingConfig::new(url, SLOT, PUBLICATION);
                PgStreamingCdcSource::connect(config, catalog)
                    .await
                    .map_err(|err| err.to_string())
            }
        };
        ingest_manager
            .ingest_with_reconnect(connect, &policy, |_| {})
            .await
            .expect("ingest");
    });

    // First insert flows over the initial connection.
    exec(
        &admin,
        "INSERT INTO orders (id, price, quantity, status) VALUES (1, 1.0, 3, 'before')",
    )
    .await;
    assert!(
        drain_until(
            &mut client,
            &applier,
            &mut replica,
            1,
            Duration::from_secs(15)
        )
        .await,
        "client did not receive the pre-drop insert"
    );

    // Terminate the walsender holding the slot, simulating a dropped stream.
    exec(
        &admin,
        "SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots \
         WHERE slot_name = 'connetto_slot' AND active_pid IS NOT NULL",
    )
    .await;

    // Wait past the reconnect backoff so the terminated walsender is gone and a
    // fresh one has taken the slot. The next insert can then only arrive over
    // the reconnected stream, not the dying original.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // The withheld row has quantity=1 (matching the predicate quantity > 0).
    // It is inserted before id=2 so that once drain_until confirms id=2 arrived,
    // the WITHHELD_ID event has already been processed and filtered.
    exec(
        &admin,
        &format!(
            "INSERT INTO orders (id, price, quantity, status) VALUES ({WITHHELD_ID}, 3.0, 1, 'withheld')",
        ),
    )
    .await;
    // Second insert must arrive once the ingest loop reconnects and resumes.
    exec(
        &admin,
        "INSERT INTO orders (id, price, quantity, status) VALUES (2, 2.0, 5, 'after')",
    )
    .await;
    assert!(
        drain_until(
            &mut client,
            &applier,
            &mut replica,
            2,
            Duration::from_secs(30)
        )
        .await,
        "client did not receive the post-drop insert, so CDC did not resume"
    );
    // WITHHELD_ID was inserted before id=2 on the reconnected stream. Now that
    // id=2 is in the replica, all prior events (including WITHHELD_ID) have been
    // processed. Assert the policy refused it.
    let ids: Vec<i64> = orders::table
        .select(orders::id)
        .load(&mut replica)
        .expect("read replica");
    assert!(
        !ids.contains(&WITHHELD_ID),
        "withheld row reached the replica, policy was not consulted on the reconnected stream"
    );
}
