//! Docker-gated CDC reconnect test.
//!
//! Drives real Postgres logical replication through `ingest_with_reconnect`,
//! then terminates the walsender mid-stream. The ingest loop must reconnect and
//! resume from the slot's confirmed position, so an insert made after the drop
//! still reaches a subscribed client. This is the Phase 6 reliability contract:
//! a dropped replication connection does not lose events.
//!
//! `#[ignore]` by default. It needs a Postgres started with `wal_level=logical`.
//! Point `DATABASE_URL` at one and run with `--ignored` after explicit approval.
//!
//! The whole file compiles only under the `pg-async` feature.

#![cfg(feature = "pg-async")]
#![allow(clippy::too_many_lines)]

use std::convert::Infallible;
use std::time::{Duration, Instant};

use connetto_core::messages::{
    BulkMessage, ControlMessage, Handshake, Subscribe, SubscriptionSpec,
};
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    Materializer, PermissiveAuth, ReconnectPolicy, SessionConfig, SessionManager, Snapshot,
    SnapshotSource, loopback, sqlite_write_target,
};
use diesel::prelude::*;
use diesel::sql_query;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use sqlparser::dialect::PostgreSqlDialect;
use subql::{ParserDB, PgStreamingCdcSource, PgStreamingConfig};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";
const SLOT: &str = "connetto_slot";
const PUBLICATION: &str = "connetto_pub";
const QUERY: &str = "SELECT * FROM orders WHERE quantity > 0";

fn admin_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_owned())
}

async fn pool_for(url: &str) -> Pool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(url.to_owned());
    Pool::builder().build(manager).await.expect("build pool")
}

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
        _auth: &connetto_core::AuthContext,
    ) -> Result<Snapshot, Self::Error> {
        Ok(Snapshot {
            patchset: Vec::new(),
            cursor: Cursor::new(Vec::new()),
        })
    }
}

diesel::table! {
    orders (id) {
        id -> diesel::sql_types::BigInt,
        price -> diesel::sql_types::Double,
        quantity -> diesel::sql_types::BigInt,
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
                    _ => continue,
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
#[ignore = "requires a running Postgres with wal_level=logical (Docker); run after explicit approval"]
async fn cdc_ingest_reconnects_after_walsender_drop() {
    let admin = pool_for(&admin_url()).await;
    exec(&admin, "DROP TABLE IF EXISTS orders CASCADE").await;
    exec(
        &admin,
        "SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots \
         WHERE slot_name = 'connetto_slot'",
    )
    .await;
    exec(&admin, "DROP PUBLICATION IF EXISTS connetto_pub").await;
    exec(&admin, PG_DDL).await;
    exec(&admin, "ALTER TABLE orders REPLICA IDENTITY FULL").await;
    exec(&admin, "CREATE PUBLICATION connetto_pub FOR TABLE orders").await;
    exec(
        &admin,
        "SELECT pg_create_logical_replication_slot('connetto_slot', 'pgoutput')",
    )
    .await;

    let manager = SessionManager::new(
        Materializer::new(PG_DDL).expect("build materializer"),
        EmptySnapshot,
        PermissiveAuth,
        sqlite_write_target(client_replica()),
        SessionConfig::default(),
    );
    let applier = Materializer::new(PG_DDL).expect("build applier");
    let mut replica = client_replica();

    let (server_transport, mut client) = loopback();
    let _server = tokio::spawn(manager.clone().serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(Handshake::new(
            PROTOCOL_VERSION,
            "reader",
            "token",
        )))
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
    let policy = ReconnectPolicy {
        initial_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_secs(2),
        max_attempts: Some(50),
        healthy_after: Duration::from_secs(1),
    };
    let url = admin_url();
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
}
