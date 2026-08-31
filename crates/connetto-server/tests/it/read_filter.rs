//! Read-filter acceptance test (Docker-free).
//!
//! The live dispatch path must deliver a row to a session only when the
//! session's auth context may see it, and that now includes a delete: a
//! tombstone names the row, so forwarding one for a row the caller could never
//! see discloses that it existed. This drives CDC through a session whose auth
//! policy denies one primary key and asserts that neither the denied insert nor
//! the later delete for that key reaches the client.
//!
//! **Its expectation changed with R6.** Until then every tombstone replayed
//! unconditionally, on the reasoning that a client has to be able to drop a row
//! it may still hold. The two-check form answers that properly: a row the caller
//! could see and can no longer see is withdrawn, and one the caller never saw is
//! not mentioned. The old rule got the first case right by getting the second
//! wrong.

#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use connetto_core::auth::Principal;
use connetto_core::messages::{
    BulkMessage, ControlMessage, Handshake, Subscribe, SubscriptionSpec,
};
use connetto_core::test_support::TestGrantChecker;
use connetto_core::traits::{IncomingFrame, Transport};
use connetto_core::{Cursor, PROTOCOL_VERSION};
use connetto_server::{
    LoopbackTransport, Materializer, PageSpec, ReconnectPolicy, RequestGuard, SessionConfig,
    SessionError, SessionManager, SnapshotEstimate, SnapshotPage, SnapshotSource, loopback,
    pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture};
use diesel::prelude::*;
use diesel::sql_query;
use subql::backend::{Postgres, Value};
use subql::visibility::{RowView, RowWrite, Verdict, VisibilityPolicy};
use subql::{CdcSource, ChangeEvent, PgLsn, PgSqliteEmuSource};

const PG_DDL: &str =
    "CREATE TABLE orders (id INT PRIMARY KEY, price FLOAT, quantity INT, status TEXT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY, price REAL, quantity INTEGER, status TEXT);";

/// Denies reads of the `orders` row whose primary key is id 2, allows the rest,
/// and allows every write. The key is read straight off the row view, which is
/// how the row-level-security policy reads it too.
struct DenyId2;

impl VisibilityPolicy for DenyId2 {
    type Watcher = Arc<Principal>;
    type Error = std::convert::Infallible;
    type Backend = Postgres;

    fn may_see<R>(
        &self,
        row: &R,
        watchers: &[Self::Watcher],
        verdicts: &mut [Verdict],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        let denied = matches!(row.value_at(0), Ok(Value::Int(2)));
        async move {
            if !denied {
                for verdict in verdicts.iter_mut().take(watchers.len()) {
                    *verdict = Verdict::Allow;
                }
            }
            Ok(())
        }
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn may_write<R>(
        &self,
        _write: RowWrite<'_, R>,
        _watcher: &Self::Watcher,
    ) -> Result<Verdict, Self::Error>
    where
        R: RowView<Backend = Postgres> + Sync + ?Sized,
    {
        Ok(Verdict::Allow)
    }
}

/// A snapshot source with no initial rows.
struct EmptySnapshot;

impl SnapshotSource for EmptySnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &Principal,
    ) -> Result<SnapshotEstimate, Self::Error> {
        Ok(SnapshotEstimate {
            rows: 0.0,
            width: 0,
        })
    }

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot_page(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _auth: &Principal,
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

#[derive(Queryable, Selectable, Debug, PartialEq)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    price: f64,
    quantity: i64,
    status: String,
}

fn order(id: i64, price: f64, quantity: i64, status: &str) -> Order {
    Order {
        id,
        price,
        quantity,
        status: status.to_owned(),
    }
}

fn client_replica() -> SqliteConnection {
    let mut conn = SqliteConnection::establish(":memory:").expect("open sqlite");
    sql_query(SQLITE_DDL)
        .execute(&mut conn)
        .expect("create table");
    conn
}

async fn next_control<T: Transport>(transport: &mut T) -> ControlMessage {
    match transport.recv().await.expect("recv frame") {
        Some(IncomingFrame::Control(msg)) => msg,
        other => panic!("expected control frame, got {other:?}"),
    }
}

/// The manager, one connected session with a subscription over the whole table,
/// and the task serving it. Its empty snapshot is drained, so the next frame a
/// caller reads is whatever the change path decided.
type Manager = Arc<SessionManager<EmptySnapshot, DenyId2, ConnettoWatermark>>;

async fn connected_session(
    fixture: &Fixture,
    query: &str,
) -> (
    Manager,
    LoopbackTransport,
    tokio::task::JoinHandle<Result<(), SessionError>>,
) {
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let manager = SessionManager::new(
        materializer,
        EmptySnapshot,
        DenyId2,
        Arc::new(TestGrantChecker),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let (server_transport, mut client) = loopback();
    let server = tokio::spawn(manager.clone().serve(server_transport));

    client
        .send_control(ControlMessage::Handshake(
            Handshake::new(PROTOCOL_VERSION, "client-a")
                .with_grant(connetto_core::messages::Grant::new("user:client-a")),
        ))
        .await
        .expect("send handshake");
    let ControlMessage::HandshakeAck(_) = next_control(&mut client).await else {
        panic!("expected handshake ack");
    };

    client
        .send_control(ControlMessage::Subscribe(Subscribe {
            sub_id: "orders".to_owned(),
            spec: SubscriptionSpec::new(query),
        }))
        .await
        .expect("send subscribe");
    // Drain the empty snapshot (begin, patch, end).
    let ControlMessage::SnapshotBegin(_) = next_control(&mut client).await else {
        panic!("expected snapshot begin");
    };
    let BulkMessage::SnapshotPatch(_) = (match client.recv().await.expect("recv") {
        Some(IncomingFrame::Bulk(msg)) => msg,
        other => panic!("expected snapshot patch, got {other:?}"),
    }) else {
        panic!("expected snapshot patch");
    };
    let ControlMessage::SnapshotEnd(_) = next_control(&mut client).await else {
        panic!("expected snapshot end");
    };
    (manager, client, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_read_filter_withholds_a_denied_row_and_its_tombstone() {
    let fixture = Fixture::acquire().await;
    let applier = Materializer::new(PG_DDL).expect("build applier");
    let mut replica = client_replica();
    let (manager, mut client, server) =
        connected_session(&fixture, "SELECT * FROM orders WHERE quantity > 0").await;

    // Drive three inserts (id 2 is denied) then a delete of the denied id.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    for sql in [
        "INSERT INTO orders (id, price, quantity, status) VALUES (1, 9.5, 3, 'a')",
        "INSERT INTO orders (id, price, quantity, status) VALUES (2, 4.0, 5, 'b')",
        "INSERT INTO orders (id, price, quantity, status) VALUES (3, 2.0, 2, 'c')",
        "DELETE FROM orders WHERE id = 2",
    ] {
        source.execute_sql(sql).expect("execute dml");
        while let Some(event) = source.next_event().await.expect("poll source") {
            manager
                .dispatch_event(&event)
                .await
                .expect("dispatch event");
        }
    }

    // Collect live patches until the stream goes idle. Live patches flow
    // through the session's async outbound queue, so a control-plane ping could
    // overtake them; instead wait out a short idle window for each frame.
    let mut live = 0usize;
    loop {
        match tokio::time::timeout(Duration::from_millis(500), client.recv()).await {
            Ok(Ok(Some(IncomingFrame::Bulk(BulkMessage::LivePatch(patch))))) => {
                applier
                    .apply_diffset(&patch.patchset_zstd, &mut replica)
                    .expect("apply live patch");
                live += 1;
            }
            Ok(Ok(Some(other))) => panic!("unexpected frame: {other:?}"),
            Ok(Err(err)) => panic!("recv failed: {err:?}"),
            Ok(Ok(None)) | Err(_) => break,
        }
    }

    // Two inserts delivered (1 and 3). The denied insert (2) is withheld, and so
    // is the delete of 2, because this caller could see neither version of that
    // row: telling it the row is gone would tell it the row was there.
    assert_eq!(
        live, 2,
        "the denied insert and the tombstone for the same row are both withheld"
    );
    assert_eq!(
        orders(&mut replica),
        vec![order(1, 9.5, 3, "a"), order(3, 2.0, 2, "c")],
        "only authorized rows reached the replica",
    );

    client.close().await.expect("close client");
    server.await.expect("join server").expect("session ok");
}

/// A source that yields one event and then ends cleanly, so what the ingest loop
/// does with that event is the whole of what a run observes.
struct OneEvent(Option<ChangeEvent>);

impl CdcSource for OneEvent {
    type Event = ChangeEvent;
    type Error = std::io::Error;

    fn next_event(
        &mut self,
    ) -> impl Future<Output = Result<Option<ChangeEvent>, std::io::Error>> + Send {
        let next = self.0.take();
        async move { Ok(next) }
    }

    // reason: the trait wants a `Send` future and clippy's other arm wants
    // `async fn`, so one of the two fires whichever form this takes. Matching the
    // form the rest of this file uses.
    #[allow(clippy::unused_async_trait_impl)]
    async fn ack(&mut self, _upto: PgLsn) -> Result<(), std::io::Error> {
        Ok(())
    }
}

/// A change the stream cannot report the previous version of refuses to serve,
/// rather than being held and retried for ever (R6 decision 4).
///
/// The condition is a table definition, so it produces the same failure on every
/// later change to that table. Holding the event would stop the stream for every
/// table with nothing said, and the pause a client would see names the
/// authorization service, which is not what went wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_that_cannot_report_the_old_row_refuses_instead_of_retrying() {
    let fixture = Fixture::acquire().await;
    // No predicate, so the subscription's set is keyed by the primary key alone
    // and a delete carrying only that key still names this consumer. A predicate
    // over a column the event does not carry is undecidable, and what the engine
    // does with that is its own question rather than this one.
    let (manager, mut client, server) = connected_session(&fixture, "SELECT * FROM orders").await;

    // The row has to be in the subscription's set for its deletion to reach a
    // caller at all, so it arrives the ordinary way first.
    let mut seed = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    seed.execute_sql("INSERT INTO orders (id, price, quantity, status) VALUES (1, 9.5, 3, 'a')")
        .expect("execute dml");
    while let Some(event) = seed.next_event().await.expect("poll source") {
        manager
            .dispatch_event(&event)
            .await
            .expect("dispatch event");
    }

    // Exactly what Postgres emits for a delete on a table whose replica identity
    // is not FULL: the key, and no other column.
    let mut old = pg_walstream::RowData::with_capacity(1);
    old.push(Arc::from("id"), pg_walstream::ColumnValue::text("1"));
    let event = ChangeEvent::delete(
        "public",
        "orders",
        0,
        old,
        pg_walstream::ReplicaIdentity::Default,
        vec![Arc::from("id")],
        pg_walstream::Lsn::new(1),
    );

    let refused = manager.dispatch_event(&event).await.expect_err(
        "whether this caller could see the row that has gone is not knowable from \
         the event, so nothing may be delivered for it",
    );
    assert!(
        matches!(&refused, SessionError::ChangeStreamUnusable(table) if table == "orders"),
        "the refusal has to name the table somebody must alter: {refused}"
    );

    // The reconnect loop retries a stream failure for ever by design, so the one
    // thing to prove is that it does not retry this.
    let outcome = tokio::time::timeout(
        Duration::from_secs(5),
        manager.ingest_with_reconnect(
            || {
                let event = event.clone();
                async move { Ok::<_, std::io::Error>(OneEvent(Some(event))) }
            },
            &ReconnectPolicy::default(),
            |_event| {},
        ),
    )
    .await
    .expect("the loop returned rather than retrying a condition that cannot clear")
    .expect_err("and it returned the refusal");
    assert!(
        matches!(outcome, SessionError::ChangeStreamUnusable(_)),
        "reconnecting the stream cannot change a table's definition, so this is \
         the refusal and not a give-up after N attempts: {outcome}"
    );

    client.close().await.expect("close client");
    let _ = server.await.expect("join server");
}

fn orders(conn: &mut SqliteConnection) -> Vec<Order> {
    orders::table
        .order(orders::id)
        .select(Order::as_select())
        .load(conn)
        .expect("read orders")
}
