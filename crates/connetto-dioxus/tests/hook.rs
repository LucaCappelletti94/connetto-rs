//! VirtualDom-level verification of `use_live`: a real connetto server over a
//! real WebSocket, a real client pump, and a headless dioxus `VirtualDom`
//! whose rendered markup follows CDC. One hook serves both handle kinds: a
//! row query renders its rows and a COUNT(*) aggregate renders its pushed
//! value, in the same component.

use std::sync::Mutex as StdMutex;
use std::time::Duration;

use connetto_client::{ClientConfig, ConnettoClient, ConnettoConnection};
use connetto_core::Cursor;
use connetto_dioxus::use_live;
use connetto_server::{
    Materializer, PermissiveAuth, SessionConfig, SessionManager, Snapshot, SnapshotSource,
    WebSocketTransport, sqlite_write_target,
};
use diesel::SqliteConnection;
use diesel::prelude::*;
use dioxus::prelude::*;
use subql::backend::{Postgres, ScalarKind, Value as PgValue};
use subql::reexec::{AsyncConnector, ScalarRowError, Snapshot as ConnectorRead};
use subql::{CdcSource, PgLsn, PgSqliteEmuSource};
use tokio::net::{TcpListener, TcpStream};

const PG_DDL: &str = "CREATE TABLE orders (id INT PRIMARY KEY, quantity INT);";
const SQLITE_DDL: &str = "CREATE TABLE orders (id INTEGER PRIMARY KEY, quantity INTEGER);";

diesel::table! {
    orders (id) {
        id -> BigInt,
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
    async fn snapshot(
        &self,
        _select_sql: &str,
        _auth: &connetto_core::AuthContext,
    ) -> Result<Snapshot, Self::Error> {
        Ok(Snapshot {
            patchset: Vec::new(),
            cursor: Cursor::new(Vec::new()),
        })
    }
}

/// Serves only the multi-column aggregate seed, from a queue of canned rows.
struct SeedRows {
    rows: StdMutex<Vec<Vec<PgValue<Postgres>>>>,
}

#[allow(clippy::manual_async_fn)]
impl AsyncConnector for SeedRows {
    type AuthContext = ();
    type Error = std::io::Error;
    type Checkpoint = PgLsn;
    type Backend = Postgres;

    fn execute_scalar(
        &self,
        _sql: &str,
        _kind: ScalarKind,
        _auth: &(),
    ) -> impl core::future::Future<
        Output = Result<(PgValue<Postgres>, Option<PgLsn>), std::io::Error>,
    > + Send {
        async { Err(std::io::Error::other("not used")) }
    }

    fn execute_rows(
        &self,
        _sql: &str,
        _auth: &(),
    ) -> impl core::future::Future<
        Output = Result<ConnectorRead<Vec<Vec<PgValue<Postgres>>>, PgLsn>, std::io::Error>,
    > + Send {
        async { Err(std::io::Error::other("not used")) }
    }

    fn execute_scalar_row(
        &self,
        _sql: &str,
        _kinds: &[ScalarKind],
        _auth: &(),
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
    let materializer = Materializer::new(PG_DDL).expect("build materializer");
    let connector = SeedRows {
        // COUNT(*) seed over the empty backend.
        rows: StdMutex::new(vec![vec![PgValue::Int(0)]]),
    };
    let target = sqlite_write_target(SqliteConnection::establish(":memory:").expect("open sqlite"));
    let manager = SessionManager::with_connector(
        materializer,
        EmptySnapshot,
        PermissiveAuth,
        connector,
        target,
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
    let config = ClientConfig {
        client_id: "dioxus-test".to_owned(),
        auth_token: "token".to_owned(),
    };
    let conn = ConnettoConnection::connect(transport, &db_path, SQLITE_DDL, &config, None)
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

    // One CDC insert updates both the row query and the aggregate.
    let mut source = PgSqliteEmuSource::open_in_memory(PG_DDL).expect("open emu source");
    source
        .execute_sql("INSERT INTO orders (id, quantity) VALUES (1, 5)")
        .expect("emu insert");
    while let Some(event) = source.next_event().await.expect("poll source") {
        manager.dispatch_event(&event).await.expect("dispatch");
    }
    render_until(&mut vdom, |html| {
        html.contains("rows:1") && html.contains("count:Some(1)")
    })
    .await;

    // Unmount everything: dropping the vdom drops the hook tasks, which drops
    // the handles and queues the unsubscribes through the pump.
    drop(vdom);
    CLIENT.lock().expect("client slot poisoned").take();
    drop(client);
    server.await.expect("join server");
}
