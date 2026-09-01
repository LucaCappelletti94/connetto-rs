//! VirtualDom-level verification of `use_live`: a real connetto server over a
//! real WebSocket, a real client pump, and a headless dioxus `VirtualDom`
//! whose rendered markup follows CDC. One hook serves both handle kinds: a
//! row query renders its rows and a COUNT(*) aggregate renders its pushed
//! value, in the same component.
//!
//! Needs Docker: the fixture starts its own Postgres.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use connetto_client::{ClientConfig, ConnettoClient, ConnettoConnection, Grant, Replica};
use connetto_core::{
    Cursor, HandshakeAuthority,
    test_support::{TestGrantChecker, replica_key},
};
use connetto_dioxus::{use_live, use_live_fn};
use connetto_server::{
    ConnettoReadSetup, Materializer, PageSpec, RequestGuard, RuntimeWritableCatalog, SessionConfig,
    SessionManager, SnapshotEstimate, SnapshotPage, SnapshotSource, WebSocketTransport,
    pg_write_target,
};
use connetto_test_harness::{ConnettoWatermark, Fixture, RosterAuth, WITHHELD_ID};
use diesel::prelude::*;
use dioxus::prelude::*;
use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value};
use subql::backend::{BuiltinKind, Postgres, Value as PgValue};
use subql::reexec::{
    AsyncConnector, ReadQuery, RowPage, ScalarRowError, Snapshot as ConnectorRead,
};
use subql::{CdcSource, PgLsn, PgSqliteEmuSource};
use tokio::net::{TcpListener, TcpStream};

fn test_verifier() -> Arc<dyn HandshakeAuthority> {
    Arc::new(TestGrantChecker)
}

const PG_DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, quantity INT);";
const SQLITE_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, quantity INTEGER);";

diesel::table! {
    /// Test table for orders in the fixture.
    orders (id) {
        /// Order identifier, the primary key.
        id -> BigInt,
        /// Quantity ordered.
        quantity -> BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: i64,
    quantity: i64,
}

/// No initial rows: the replica fills from CDC alone in this test.
struct EmptySnapshot;

impl SnapshotSource for EmptySnapshot {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &connetto_core::Principal,
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
        _caller: &connetto_core::Principal,
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

/// Serves one `orders` row (id 1, quantity 3), so the boxed-query test starts
/// from a non-empty replica and its first render proves the subscription is
/// established before the CDC insert.
struct SeedOneOrder;

impl SnapshotSource for SeedOneOrder {
    type Error = std::convert::Infallible;

    #[allow(clippy::unused_async_trait_impl)]
    async fn estimate(
        &self,
        _select_sql: &str,
        _binds: &[connetto_core::messages::BindValue],
        _caller: &connetto_core::Principal,
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
        _caller: &connetto_core::Principal,
        _page: &PageSpec,
    ) -> Result<SnapshotPage, Self::Error> {
        let table = SimpleTable::new("orders", &["id", "quantity"], &[0]);
        let insert = Insert::<_, String, Vec<u8>>::from(table)
            .set(0, Value::Integer(1))
            .expect("set id")
            .set(1, Value::Integer(3))
            .expect("set quantity");
        let patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new()
            .insert(insert)
            .build();
        Ok(SnapshotPage {
            patchset,
            cursor: Cursor::new(Vec::new()),
            next: None,
            filled: false,
            widest_row: 0,
            rows: 0,
            bytes: 0,
        })
    }
}

/// Serves only the multi-column aggregate seed, from a queue of canned rows.
#[derive(Clone)]
struct SeedRows {
    rows: Arc<StdMutex<Vec<Vec<PgValue<Postgres>>>>>,
}

#[allow(clippy::manual_async_fn)]
impl AsyncConnector for SeedRows {
    type AuthContext = ConnettoReadSetup;
    type Error = std::io::Error;
    type Checkpoint = PgLsn;
    type Backend = Postgres;

    fn execute_scalar(
        &self,
        _query: &ReadQuery<'_, Postgres>,
        _kind: BuiltinKind,
        _setup: &ConnettoReadSetup,
    ) -> impl core::future::Future<
        Output = Result<(PgValue<Postgres>, Option<PgLsn>), std::io::Error>,
    > + Send {
        async { Err(std::io::Error::other("not used")) }
    }

    fn read_page(
        &self,
        _query: &ReadQuery<'_, Postgres>,
        _max_bytes: usize,
        _setup: &ConnettoReadSetup,
    ) -> impl core::future::Future<
        Output = Result<ConnectorRead<RowPage<Postgres>, PgLsn>, std::io::Error>,
    > + Send {
        async { Err(std::io::Error::other("not used")) }
    }

    fn execute_scalar_row(
        &self,
        _query: &ReadQuery<'_, Postgres>,
        _kinds: &[BuiltinKind],
        _setup: &ConnettoReadSetup,
    ) -> impl core::future::Future<
        Output = Result<(Vec<PgValue<Postgres>>, Option<PgLsn>), ScalarRowError<std::io::Error>>,
    > + Send {
        let next = self.rows.lock().expect("queue poisoned").pop();
        async move {
            next.map(|row| (row, Some(PgLsn(1)))).ok_or_else(|| {
                ScalarRowError::Connector(std::io::Error::other("no more canned rows"))
            })
        }
    }
}

type Ws = WebSocketTransport<TcpStream>;

/// The component reads the shared client from here: `VirtualDom` components
/// take no test-local captures, and props require `PartialEq`. A clearable
/// slot rather than a `OnceLock`, because the teardown must drop every client
/// clone for the pump to close the connection (RAII teardown is part of what
/// this test verifies).
static CLIENT: StdMutex<Option<ConnettoClient<Ws>>> = StdMutex::new(None);

fn app() -> Element {
    let client = CLIENT
        .lock()
        .expect("client slot poisoned")
        .clone()
        .expect("client installed");
    let rows = use_live::<_, _, Order>(&client, orders::table.order(orders::id));
    let count = use_live(&client, orders::table.count());
    let n = rows.value().read().len();
    let c = *count.value().read();
    rsx! {
        div { "rows:{n} count:{c:?}" }
    }
}

/// A dedicated client slot for the boxed-query test, so the two hook tests do
/// not race over one global.
static CLIENT_FN: StdMutex<Option<ConnettoClient<Ws>>> = StdMutex::new(None);

fn app_fn() -> Element {
    let client = CLIENT_FN
        .lock()
        .expect("client slot poisoned")
        .clone()
        .expect("client installed");
    // A boxed row query: not Clone, so use_live cannot take it. use_live_fn
    // rebuilds it from the closure on every refresh.
    let rows = use_live_fn::<_, _, _, Order>(&client, || {
        orders::table
            .filter(orders::quantity.gt(0))
            .order(orders::id)
            .into_boxed()
    });
    let n = rows.value().read().len();
    rsx! {
        div { "boxed-rows:{n}" }
    }
}

/// Pump the vdom until the rendered markup satisfies `pred`.
async fn render_until(vdom: &mut VirtualDom, pred: impl Fn(&str) -> bool) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let html = dioxus_ssr::render(vdom);
        if pred(&html) {
            return html;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "render timed out, last markup: {html}",
        );
        tokio::select! {
            () = vdom.wait_for_work() => {}
            () = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
        vdom.render_immediate(&mut dioxus_core::NoOpMutations);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn use_live_renders_and_follows_cdc() {
    let fixture = Fixture::acquire().await;
    let connector = SeedRows {
        // COUNT(*) seed over the empty backend.
        rows: Arc::new(StdMutex::new(vec![vec![PgValue::Int(0)]])),
    };
    let materializer = Materializer::with_read_connector(
        PG_DDL,
        RuntimeWritableCatalog::default(),
        None,
        None,
        connector.clone(),
    )
    .expect("build materializer");
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::with_connector(
        materializer,
        EmptySnapshot,
        RosterAuth::granting("dioxus-test").withholding(WITHHELD_ID),
        test_verifier(),
        connector,
        target,
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let serve_manager = manager.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let transport = WebSocketTransport::accept(stream).await.expect("ws accept");
        serve_manager.serve(transport).await.expect("session ok");
    });

    let db = tempfile::Builder::new()
        .suffix(".sqlite")
        .tempfile()
        .expect("temp db");
    let db_path = db.path().to_str().expect("utf8 path").to_owned();
    let stream = TcpStream::connect(addr).await.expect("connect");
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .expect("ws connect");
    let config = ClientConfig::new("dioxus-test").with_login(Some(Grant::new("user:dioxus-test")));
    let replica = Replica::encrypted_file(&db_path, Some(replica_key())).expect("replica key");
    let conn = ConnettoConnection::connect(transport, &replica, SQLITE_DDL, &config, None)
        .await
        .expect("client connect");
    let client = ConnettoClient::start(conn);
    *CLIENT.lock().expect("client slot poisoned") = Some(client.clone());

    let mut vdom = VirtualDom::new(app);
    vdom.rebuild(&mut dioxus_core::NoOpMutations);

    // Both hooks bootstrap: no rows yet, COUNT seeded 0 by the connector.
    render_until(&mut vdom, |html| {
        html.contains("rows:0") && html.contains("count:Some(0)")
    })
    .await;

    // One allowed CDC insert and one withheld one drive the change path. The row
    // hook sees only the allowed row, so rows:1 rather than rows:2 proves the
    // policy is consulted. The aggregate counts both, because connetto delivers an
    // aggregate without asking the policy at all (session.rs, delta aggregates are
    // global by construction since subql refuses an aggregator on a policy-bearing
    // table).
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, quantity) VALUES (1, 5)")
        .expect("emu insert");
    source
        .execute_sql(&format!(
            "INSERT INTO orders (id, quantity) VALUES ({WITHHELD_ID}, 1)",
        ))
        .expect("emu insert withheld");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager.dispatch_event(&event).await.expect("dispatch");
    }
    render_until(&mut vdom, |html| {
        html.contains("rows:1") && html.contains("count:Some(2)")
    })
    .await;

    // Unmount everything: dropping the vdom drops the hook tasks, which drops
    // the handles and queues the unsubscribes through the pump.
    drop(vdom);
    CLIENT.lock().expect("client slot poisoned").take();
    drop(client);
    server.await.expect("join server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn use_live_fn_follows_a_boxed_row_query() {
    let fixture = Fixture::acquire().await;
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let target = pg_write_target::<ConnettoWatermark>(fixture.admin().clone(), PG_DDL)
        .expect("build write target");
    let manager = SessionManager::new(
        materializer,
        SeedOneOrder,
        RosterAuth::granting("dioxus-fn-test").withholding(WITHHELD_ID),
        test_verifier(),
        target,
        Arc::new(RequestGuard::default()),
        SessionConfig::default(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let serve_manager = manager.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let transport = WebSocketTransport::accept(stream).await.expect("ws accept");
        serve_manager.serve(transport).await.expect("session ok");
    });

    let db = tempfile::Builder::new()
        .suffix(".sqlite")
        .tempfile()
        .expect("temp db");
    let db_path = db.path().to_str().expect("utf8 path").to_owned();
    let stream = TcpStream::connect(addr).await.expect("connect");
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .expect("ws connect");
    let config =
        ClientConfig::new("dioxus-fn-test").with_login(Some(Grant::new("user:dioxus-fn-test")));
    let replica = Replica::encrypted_file(&db_path, Some(replica_key())).expect("replica key");
    let conn = ConnettoConnection::connect(transport, &replica, SQLITE_DDL, &config, None)
        .await
        .expect("client connect");
    let client = ConnettoClient::start(conn);
    *CLIENT_FN.lock().expect("client slot poisoned") = Some(client.clone());

    let mut vdom = VirtualDom::new(app_fn);
    vdom.rebuild(&mut dioxus_core::NoOpMutations);

    // The snapshot seed row surfaces, which also proves the subscription is
    // established before the CDC insert below.
    render_until(&mut vdom, |html| html.contains("boxed-rows:1")).await;

    // A second allowed row and one withheld row drive the change path. The
    // withheld row has quantity=1 (matching the filter quantity > 0), so
    // boxed-rows:2 (not boxed-rows:3) proves RosterAuth was consulted.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    diesel::insert_into(orders::table)
        .values((orders::id.eq(2_i64), orders::quantity.eq(5_i64)))
        .execute(source.connection())
        .expect("emu insert");
    diesel::insert_into(orders::table)
        .values((orders::id.eq(WITHHELD_ID), orders::quantity.eq(1_i64)))
        .execute(source.connection())
        .expect("emu insert withheld");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager.dispatch_event(&event).await.expect("dispatch");
    }
    render_until(&mut vdom, |html| html.contains("boxed-rows:2")).await;

    // Unmount: dropping the vdom drops the hook task, the handle, and the sub.
    drop(vdom);
    CLIENT_FN.lock().expect("client slot poisoned").take();
    drop(client);
    server.await.expect("join server");
}
