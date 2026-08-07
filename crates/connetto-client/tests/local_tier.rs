//! Local tier (device-private tables) end to end: placement enforcement and
//! live query tier dispatch against a real in-process server.
//!
//! The tier contract under test: `notes` lives in an attached local database,
//! the capture session is bound to `main`, so a note is physically incapable
//! of riding a mutation upload, and live queries dispatch by tier at
//! registration. Local rows and aggregates are served by local (re-)execution
//! with no server subscription at all, a mixed row query auto-subscribes each
//! synced table whole for the handle's lifetime, and a mixed aggregate is
//! refused. The generation-time half of the contract (a `REFERENCES` crossing
//! the tier boundary fails the template bake) is pinned against pg2sqlite
//! directly.

#![allow(clippy::too_many_lines)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Grant, Replica, Watchable,
};
use connetto_core::{Cursor, test_support::TestGrantChecker, traits::HandshakeAuthority};
use connetto_server::{
    Materializer, PermissiveAuth, RequestGuard, RuntimeWritableCatalog, SessionConfig,
    SessionManager, Snapshot, SnapshotSource, WebSocketTransport, pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture};
use diesel::prelude::*;
use sqlite_diff_rs::{PatchSet, SimpleTable};
use subql::{CdcSource, PgSqliteEmuSource};
use tokio::net::{TcpListener, TcpStream};

const PG_DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, quantity INT);";
const SQLITE_DDL: &str =
    "CREATE TABLE orders (id INTEGER PRIMARY KEY NOT NULL, quantity INTEGER) STRICT;";
/// The local tier schema, attached as an ephemeral in-memory database.
const NOTES_DDL: &str = "CREATE TABLE notes (id INTEGER PRIMARY KEY NOT NULL, body TEXT) STRICT;";

diesel::table! {
    orders (id) {
        id -> diesel::sql_types::BigInt,
        quantity -> diesel::sql_types::BigInt,
    }
}

diesel::table! {
    notes (id) {
        id -> diesel::sql_types::BigInt,
        body -> diesel::sql_types::Text,
    }
}

diesel::allow_tables_to_appear_in_same_query!(orders, notes);

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = notes)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Note {
    id: i64,
    body: String,
}

/// A downstream-style application SQL type: the comma-joined result of a
/// `group_concat`. Only this test crate owns it, so the orphan rule lets it
/// carry its own [`AggregateWire`](connetto_client::dsl::AggregateWire) impl,
/// which is the whole point of the extension seam.
#[derive(diesel::sql_types::SqlType, diesel::query_builder::QueryId)]
#[diesel(sqlite_type(name = "Text"))]
pub struct CsvList;

diesel::define_sql_function! {
    /// The SQLite built-in `group_concat` aggregate, returning the custom
    /// [`CsvList`] type. Its name is absent from connetto's built-in
    /// `AGGREGATE_FUNCTIONS`, so only the typed `live()` path (which reads
    /// diesel's `IsAggregate` marker) classifies it as an aggregate. The
    /// `#[aggregate]` attribute is what sets that marker.
    #[aggregate]
    fn group_concat(body: diesel::sql_types::Text) -> CsvList;
}

impl connetto_client::dsl::AggregateWire for CsvList {
    type Value = Option<String>;

    fn decode(json: &str) -> Result<Option<String>, connetto_client::ClientError> {
        use connetto_client::dsl::wire;
        match wire::json_value(json)? {
            serde_json::Value::Null => Ok(None),
            serde_json::Value::String(s) => Ok(Some(s)),
            other => Err(connetto_client::ClientError::Session(format!(
                "expected a csv string, got {other}"
            ))),
        }
    }
}

/// A snapshot source that records every subscription's `select_sql`, so the
/// tests can assert exactly which queries reached the wire. Serves empty
/// snapshots: the tests drive rows through CDC dispatch instead.
#[derive(Clone, Default)]
struct RecordingSnapshot {
    seen: Arc<Mutex<Vec<String>>>,
}

impl SnapshotSource for RecordingSnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn snapshot(
        &self,
        select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &connetto_core::Principal,
    ) -> Result<Snapshot, Self::Error> {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(select_sql.to_owned());
        }
        Ok(Snapshot {
            patchset: PatchSet::<SimpleTable, String, Vec<u8>>::new().build(),
            cursor: Cursor::new(Vec::new()),
        })
    }
}

fn test_verifier() -> Arc<dyn HandshakeAuthority> {
    Arc::new(TestGrantChecker)
}

/// One in-process server over a localhost WebSocket, serving `sessions`
/// connections. Returns the manager (for CDC dispatch), the recorder's log,
/// the address, and the join handle.
async fn spawn_server(
    fixture: &Fixture,
    sessions: usize,
) -> (
    Arc<SessionManager<RecordingSnapshot, PermissiveAuth, ConnettoWatermark>>,
    Arc<Mutex<Vec<String>>>,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    let writable = RuntimeWritableCatalog::builder().writable("orders").build();
    let materializer =
        Materializer::with_write_catalog(PG_DDL, writable).expect("build materializer");
    let recorder = RecordingSnapshot::default();
    let seen = Arc::clone(&recorder.seen);
    let manager = SessionManager::new(
        materializer,
        recorder,
        PermissiveAuth,
        test_verifier(),
        pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
            .expect("build write target"),
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let serve_manager = manager.clone();
    let server = tokio::spawn(async move {
        for _ in 0..sessions {
            let (stream, _) = listener.accept().await.expect("accept");
            let transport = WebSocketTransport::accept(stream).await.expect("ws accept");
            let session_manager = serve_manager.clone();
            tokio::spawn(async move {
                let _ = session_manager.serve(transport).await;
            });
        }
    });
    (manager, seen, addr, server)
}

/// Connect a raw client with the shared tier schema and an ephemeral local
/// tier holding `notes`.
async fn connect_with_tier(
    addr: std::net::SocketAddr,
    client_id: &str,
) -> ConnettoConnection<WebSocketTransport<TcpStream>> {
    let stream = TcpStream::connect(addr).await.expect("connect");
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .expect("ws connect");
    let config = ClientConfig {
        client_id: client_id.to_owned(),
        login: Some(Grant::new("user:token")),
        capabilities: Vec::new(),
        schema_version: None,
        sql_functions: connetto_client::SqlFunctions::new(),
    };
    ConnettoConnection::connect(
        transport,
        &Replica::in_memory().with_tier(NOTES_DDL),
        SQLITE_DDL,
        &config,
        None,
    )
    .await
    .expect("client connect")
}

/// Pump the broadcast stream until an event matches `pred`, failing fast on
/// any [`ClientEvent::NonFatal`]: the server refuses a subscription it cannot
/// translate that way, so a local table leaking onto the wire cannot pass.
async fn wait_broadcast_strict(
    events: &mut tokio::sync::broadcast::Receiver<ClientEvent>,
    pred: impl Fn(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("event stream timed out")
            .expect("event stream closed");
        assert!(
            !matches!(event, ClientEvent::NonFatal { .. }),
            "the server refused a frame: {event:?}"
        );
        if pred(&event) {
            return event;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn local_write_is_outside_the_capture_session() {
    let fixture = Fixture::acquire().await;
    let (_manager, _seen, addr, server) = spawn_server(&fixture, 1).await;
    let mut client = connect_with_tier(addr, "tier-capture").await;
    assert_eq!(
        client.local_tables(),
        &std::collections::HashSet::from(["notes".to_owned()]),
        "the tier lookup names the attached tables"
    );

    // A note lands in the attached database, readable through the bare name,
    // and the capture session has nothing to upload: push is a no-op.
    diesel::insert_into(notes::table)
        .values((notes::id.eq(1_i64), notes::body.eq("draft")))
        .execute(client.conn())
        .expect("insert note");
    assert_eq!(
        client.push().await.expect("push after a note"),
        None,
        "a local tier write must never produce a mutation"
    );
    let stored: Vec<Note> = notes::table
        .select(Note::as_select())
        .load(client.conn())
        .expect("read notes");
    assert_eq!(stored.len(), 1, "the note is readable by its bare name");

    // The same connection still uploads shared tier writes.
    diesel::insert_into(orders::table)
        .values((orders::id.eq(1_i64), orders::quantity.eq(2_i64)))
        .execute(client.conn())
        .expect("insert order");
    assert!(
        client.push().await.expect("push after an order").is_some(),
        "a shared tier write still uploads"
    );

    client.close().await.expect("close");
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn local_row_watch_registers_no_subscription_and_refreshes() {
    let fixture = Fixture::acquire().await;
    let (_manager, seen, addr, server) = spawn_server(&fixture, 1).await;
    let conn = connect_with_tier(addr, "tier-rows").await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    let mut live: connetto_client::LiveQuery<Note> = notes::table
        .order(notes::id)
        .live(&client)
        .await
        .expect("local live query");
    assert!(live.rows().is_empty(), "the tier starts empty");

    // A local write refreshes the handle through the update hook, with no
    // server round trip anywhere in the path.
    client
        .with_conn(|conn| {
            diesel::insert_into(notes::table)
                .values((notes::id.eq(1_i64), notes::body.eq("draft")))
                .execute(conn.conn())
        })
        .await
        .expect("insert note");
    live.changed().await.expect("local refresh");
    assert_eq!(live.rows().len(), 1);

    // Wire silence, fenced: the pong proves the server processed everything
    // sent since the handshake, and the strict waiter rejects any refusal, so
    // a Subscribe for the local table cannot have been sent. The snapshot
    // recorder agrees.
    client.ping(7).await.expect("ping");
    wait_broadcast_strict(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 7 })).await;
    assert!(
        seen.lock().expect("recorder lock").is_empty(),
        "no subscription may reach the server for a local-only query"
    );

    drop(live);
    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn local_aggregate_recomputes_locally() {
    let fixture = Fixture::acquire().await;
    let (_manager, seen, addr, server) = spawn_server(&fixture, 1).await;
    let conn = connect_with_tier(addr, "tier-agg").await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    // A filtered count, so the rendered query carries a bind that the local
    // probe must inline. Unlike the server-pushed path, the bootstrap answer
    // is immediate: the local tier is complete by definition.
    let mut count = notes::table
        .filter(notes::id.gt(0_i64))
        .count()
        .live(&client)
        .await
        .expect("local live aggregate");
    assert_eq!(count.value(), Some(0), "bootstrap is answered locally");

    client
        .with_conn(|conn| {
            diesel::insert_into(notes::table)
                .values(&vec![
                    (notes::id.eq(1_i64), notes::body.eq("a")),
                    (notes::id.eq(2_i64), notes::body.eq("b")),
                ])
                .execute(conn.conn())
        })
        .await
        .expect("insert notes");
    count.changed().await.expect("local recompute");
    assert_eq!(count.value(), Some(2), "the aggregate re-executed locally");

    // Wire silence, fenced like the row case.
    client.ping(7).await.expect("ping");
    wait_broadcast_strict(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 7 })).await;
    assert!(
        seen.lock().expect("recorder lock").is_empty(),
        "no subscription may reach the server for a local aggregate"
    );

    drop(count);
    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn local_custom_aggregate_decodes_via_extension_seam() {
    // A custom aggregate (group_concat, absent from the built-in
    // AGGREGATE_FUNCTIONS) returning an application-defined SQL type
    // (CsvList). It proves two facets at once: the typed live() path
    // classifies it as an aggregate from diesel's IsAggregate marker rather
    // than the SQL-text name list (a text classifier would misread it as a
    // row query and reject it), and a downstream AggregateWire impl over the
    // app's own SQL type drives live() end to end through the public wire
    // primitives. It runs on the local tier, so the client recomputes it with
    // json_quote and no subscription reaches the server.
    let fixture = Fixture::acquire().await;
    let (_manager, seen, addr, server) = spawn_server(&fixture, 1).await;
    let conn = connect_with_tier(addr, "tier-custom-agg").await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    let mut joined = notes::table
        .select(group_concat(notes::body))
        .live(&client)
        .await
        .expect("local live custom aggregate");
    // The empty set: group_concat is NULL, json_quote renders "null", the
    // app's decoder maps it to None.
    assert_eq!(
        joined.value(),
        Some(None),
        "empty bootstrap decodes to None"
    );

    // First live update: two rows appear, the aggregate recomputes locally and
    // decodes through the seam.
    client
        .with_conn(|conn| {
            diesel::insert_into(notes::table)
                .values(&vec![
                    (notes::id.eq(1_i64), notes::body.eq("a")),
                    (notes::id.eq(2_i64), notes::body.eq("b")),
                ])
                .execute(conn.conn())
        })
        .await
        .expect("insert notes");
    joined.changed().await.expect("local recompute");
    assert_eq!(
        joined.value(),
        Some(Some("a,b".to_owned())),
        "the custom aggregate recomputed locally and decoded through the seam",
    );

    // Second live update: an added row changes the value again, so a live
    // handle tracks more than the first transition.
    client
        .with_conn(|conn| {
            diesel::insert_into(notes::table)
                .values((notes::id.eq(3_i64), notes::body.eq("c")))
                .execute(conn.conn())
        })
        .await
        .expect("insert third note");
    joined.changed().await.expect("second local recompute");
    assert_eq!(
        joined.value(),
        Some(Some("a,b,c".to_owned())),
        "a further change updates the custom aggregate",
    );

    // The nullable round-trip: deleting every row empties the set, group_concat
    // is NULL again, and the seam decoder maps it back to None. This is the
    // corner a nullable custom decoder most often gets wrong.
    client
        .with_conn(|conn| diesel::delete(notes::table).execute(conn.conn()))
        .await
        .expect("delete all notes");
    joined.changed().await.expect("empty recompute");
    assert_eq!(
        joined.value(),
        Some(None),
        "emptying the set returns the custom aggregate to None",
    );

    // Wire silence, fenced like the built-in local aggregate case.
    client.ping(9).await.expect("ping");
    wait_broadcast_strict(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 9 })).await;
    assert!(
        seen.lock().expect("recorder lock").is_empty(),
        "no subscription may reach the server for a local custom aggregate"
    );

    drop(joined);
    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn mixed_tier_aggregate_is_refused_at_registration() {
    let fixture = Fixture::acquire().await;
    let (_manager, _seen, addr, server) = spawn_server(&fixture, 1).await;
    let conn = connect_with_tier(addr, "tier-mixed-agg").await;
    let client = ConnettoClient::start(conn);

    let Err(err) = orders::table
        .inner_join(notes::table.on(notes::id.eq(orders::id)))
        .count()
        .live(&client)
        .await
    else {
        panic!("a mixed-tier aggregate must be refused");
    };
    assert!(
        err.to_string().contains("mixed-tier aggregate"),
        "the refusal names the rule, got: {err}"
    );

    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a running Postgres (Docker); run after explicit approval"]
async fn mixed_row_query_subscribes_synced_tables_whole() {
    let fixture = Fixture::acquire().await;
    let (manager, seen, addr, server) = spawn_server(&fixture, 1).await;
    let conn = connect_with_tier(addr, "tier-mixed-rows").await;
    let client = ConnettoClient::start(conn);
    let mut events = client.events();

    client
        .with_conn(|conn| {
            diesel::insert_into(notes::table)
                .values((notes::id.eq(1_i64), notes::body.eq("attached")))
                .execute(conn.conn())
        })
        .await
        .expect("seed note");

    // A join across the tier boundary: served locally, backed by a
    // whole-table subscription on the synced side only.
    let mut joined: connetto_client::LiveQuery<(i64, String)> = orders::table
        .inner_join(notes::table.on(notes::id.eq(orders::id)))
        .select((orders::id, notes::body))
        .order(orders::id)
        .live(&client)
        .await
        .expect("mixed live query");
    assert!(joined.rows().is_empty(), "no orders yet");

    client.ping(7).await.expect("ping");
    wait_broadcast_strict(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 7 })).await;
    {
        let seen = seen.lock().expect("recorder lock");
        assert_eq!(
            *seen,
            vec!["SELECT * FROM \"orders\"".to_owned()],
            "exactly the synced table is subscribed, whole"
        );
    }

    // A server-side orders row arrives as a live patch through the
    // whole-table subscription and completes the join.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, quantity) VALUES (1, 5)")
        .expect("emu insert");
    while let Some(event) = source.next_event().await.expect("poll event") {
        manager.dispatch_event(&event).await.expect("dispatch");
    }
    loop {
        if joined.rows() == vec![(1_i64, "attached".to_owned())] {
            break;
        }
        joined.changed().await.expect("join refresh");
    }

    // The local side of the join refreshes on a local write.
    client
        .with_conn(|conn| {
            diesel::update(notes::table.find(1_i64))
                .set(notes::body.eq("edited"))
                .execute(conn.conn())
        })
        .await
        .expect("edit note");
    loop {
        if joined.rows() == vec![(1_i64, "edited".to_owned())] {
            break;
        }
        joined.changed().await.expect("local join refresh");
    }

    // Dropping the handle retires its whole-table subscriptions cleanly.
    drop(joined);
    client.ping(8).await.expect("ping");
    wait_broadcast_strict(&mut events, |e| matches!(e, ClientEvent::Pong { nonce: 8 })).await;

    drop(client);
    server.await.expect("join server");
}

/// The generation-time half of the tier contract: the two documents are
/// separate reference universes, so a foreign key crossing the boundary is a
/// dangling reference and fails the template bake (pg2sqlite validates
/// reference closure per document, default on).
#[test]
fn cross_tier_reference_fails_the_template_bake() {
    use pg2sqlite::prelude::{Pg2Sqlite, Pg2SqliteOptions};

    let err = Pg2Sqlite::default()
        .sql("CREATE TABLE drafts (id BIGINT PRIMARY KEY, order_id BIGINT REFERENCES orders(id));")
        .expect("parse the frontend document")
        .translate_to_sql(&Pg2SqliteOptions::default())
        .expect_err("a cross-tier reference must fail the bake");
    assert!(
        err.to_string().contains("orders"),
        "the error names the unresolved target, got: {err}"
    );
}
