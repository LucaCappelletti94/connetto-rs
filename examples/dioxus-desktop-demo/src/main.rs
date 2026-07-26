//! Windowed desktop demo of connetto live queries in a real Dioxus app,
//! against the real stack end to end.
//!
//! Every window is a plain connetto client of a running `connetto-server`,
//! which streams CDC from a real Postgres over logical replication and
//! applies client mutations to that same Postgres. An applied write echoes
//! back through replication, so every window converges, the COUNT(*)
//! aggregate included.
//!
//! Configuration comes from the environment:
//!
//! - `CONNETTO_DEMO_SERVER`: `host:port` of the connetto-server WebSocket
//!   listener (default `127.0.0.1:7777`).
//! - `CONNETTO_DEMO_PG`: Postgres conninfo for the backend writer buttons,
//!   standing in for any non connetto process mutating the source database
//!   (default `postgres://postgres:postgres@127.0.0.1:55456/postgres`).

use std::sync::Arc;

use connetto_client::{ClientConfig, ConnettoClient, ConnettoConnection, SqlFunctions};
use connetto_core::transport::WebSocketTransport;
use connetto_dioxus::use_live;
use diesel::prelude::*;
use dioxus::prelude::*;
use rosetta_uuid::Uuid;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The replica template baked by build.rs: the Postgres dialect schema in
/// schema.sql, translated through pg2sqlite and applied to a fresh SQLite
/// database. The app ships the schema as bytes and never runs DDL. The
/// connetto-server for this demo must be started with the schema.sql content
/// in CONNETTO_PG_DDL.
const REPLICA_TEMPLATE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/replica-template.sqlite"));
/// The Postgres schema source the demo server must be started with
/// (`CONNETTO_PG_DDL`). Hashing it yields the version the server advertises, so
/// this build presents a matching version at handshake.
const SCHEMA_SQL: &str = include_str!("../schema.sql");

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        quantity -> diesel::sql_types::BigInt,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: Uuid,
    quantity: i64,
}

// The synced key generator: `orders.id` bakes to `DEFAULT (uuidv7())`, so a
// local write omits the id and this registered function mints it.
#[diesel::declare_sql_function]
extern "SQL" {
    /// Client-authored primary key: a 16-byte UUID v7 blob.
    fn uuidv7() -> diesel::sql_types::Binary;
}

/// The registrar connetto installs on the replica connection: `uuidv7()` mints
/// a fresh `rosetta_uuid::Uuid` (the same strongly typed key the `orders`
/// schema uses on SQLite and Postgres). Nondeterministic, so SQLite calls it
/// per row instead of folding the DEFAULT to a constant.
fn uuidv7_functions() -> SqlFunctions {
    SqlFunctions::new().with(Arc::new(|conn: &mut diesel::SqliteConnection| {
        uuidv7_utils::register_nondeterministic_impl(conn, Uuid::utc_v7)
    }))
}

/// A positive demo quantity, varied by the wall clock so successive rows
/// differ. The key is minted separately (the DEFAULT on a local write, an
/// explicit v7 bind in the backend writer), so quantity is never keyed off
/// the id.
fn demo_quantity() -> i64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    i64::try_from(millis % 9).unwrap_or(0) * 5 + 5
}

type Ws = WebSocketTransport<TcpStream>;

/// Commands for the backend writer task, standing in for any non connetto
/// process mutating the source Postgres directly.
enum DemoCmd {
    /// Insert one row into Postgres.
    Insert,
    /// Delete the newest backend inserted row from Postgres.
    DeleteNewest,
}

/// Cloneable handle the UI uses to reach the backend writer task.
#[derive(Clone)]
struct Backend(mpsc::UnboundedSender<DemoCmd>);

fn main() {
    // block_on at the top level sync boundary only: main owns the runtime and
    // the dioxus event loop below never returns, so the runtime and the enter
    // guard live for the whole process on this stack frame.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let (client, backend) = rt.block_on(setup());
    let _guard = rt.enter();
    let title = format!("connetto live demo (pid {})", std::process::id());
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            dioxus::desktop::Config::new().with_window(
                dioxus::desktop::WindowBuilder::new()
                    .with_title(title)
                    .with_inner_size(dioxus::desktop::LogicalSize::new(760.0, 680.0)),
            ),
        )
        .with_context(client)
        .with_context(backend)
        .launch(app);
}

/// Connect this window's client to the server and start the backend writer
/// task on a direct Postgres connection.
async fn setup() -> (ConnettoClient<Ws>, Backend) {
    let server =
        std::env::var("CONNETTO_DEMO_SERVER").unwrap_or_else(|_| "127.0.0.1:7777".to_owned());
    let pg_url = std::env::var("CONNETTO_DEMO_PG")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55456/postgres".to_owned());

    // The replica lives in a per process temp file. The window loop never
    // returns, so no drop would run for it anyway and the OS temp cleaner
    // owns it.
    let db_path = std::env::temp_dir().join(format!(
        "connetto-desktop-demo-{}.sqlite",
        std::process::id()
    ));
    let db_path = db_path.to_str().expect("utf8 temp path").to_owned();
    let stream = TcpStream::connect(&server)
        .await
        .expect("connect to server");
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .expect("ws connect");
    let config = ClientConfig {
        client_id: format!("desktop-demo-{}", std::process::id()),
        auth_token: "token".to_owned(),
        schema_version: Some(connetto_core::SchemaVersion::from_source(SCHEMA_SQL)),
        sql_functions: uuidv7_functions(),
    };
    let conn = ConnettoConnection::connect_with_replica_template(
        transport,
        &db_path,
        REPLICA_TEMPLATE,
        &config,
        None,
    )
    .await
    .expect("client connect");
    let client = ConnettoClient::start(conn);

    // Backend writer: DML straight into Postgres through the SAME typed
    // `orders` schema the frontend live query uses, echoed to every window by
    // the server's logical replication stream. Postgres `gen_random_uuid()` is
    // v4, which would break "delete newest via MAX(id)", so the insert mints an
    // explicit v7 `rosetta_uuid::Uuid`. `on_conflict_do_nothing` keeps
    // concurrent button presses harmless.
    let (tx, mut rx) = mpsc::unbounded_channel::<DemoCmd>();
    tokio::spawn(async move {
        use diesel_async::AsyncConnection;
        let mut pg = diesel_async::AsyncPgConnection::establish(&pg_url)
            .await
            .expect("connect to postgres");
        while let Some(cmd) = rx.recv().await {
            // Fully qualified async RunQueryDsl: diesel's sync RunQueryDsl is
            // also in scope through the prelude, so method syntax is ambiguous.
            let run: diesel::QueryResult<()> = match cmd {
                DemoCmd::Insert => diesel_async::RunQueryDsl::execute(
                    diesel::insert_into(orders::table)
                        .values((
                            orders::id.eq(Uuid::utc_v7()),
                            orders::quantity.eq(demo_quantity()),
                        ))
                        .on_conflict_do_nothing(),
                    &mut pg,
                )
                .await
                .map(|_| ()),
                // The newest row is the one with the greatest v7 id (time-ordered).
                DemoCmd::DeleteNewest => {
                    match diesel_async::RunQueryDsl::get_result::<Option<Uuid>>(
                        orders::table.select(diesel::dsl::max(orders::id)),
                        &mut pg,
                    )
                    .await
                    {
                        Ok(Some(newest)) => diesel_async::RunQueryDsl::execute(
                            diesel::delete(orders::table.filter(orders::id.eq(newest))),
                            &mut pg,
                        )
                        .await
                        .map(|_| ()),
                        Ok(None) => Ok(()),
                        Err(err) => Err(err),
                    }
                }
            };
            if let Err(err) = run {
                eprintln!("backend write failed: {err}");
            }
        }
    });

    (client, Backend(tx))
}

fn app() -> Element {
    let client = use_context::<ConnettoClient<Ws>>();
    let backend = use_context::<Backend>();

    let rows = use_live::<_, _, Order>(&client, orders::table.order(orders::id));
    let count = use_live(&client, orders::table.count());

    let display_rows: Vec<(Uuid, i64)> = rows
        .value()
        .read()
        .iter()
        .map(|row| (row.id, row.quantity))
        .collect();
    let count_text = count
        .value()
        .read()
        .map_or_else(|| "pending".to_owned(), |v| v.to_string());
    let rows_error = rows.error().read().clone();
    let count_error = count.error().read().clone();
    let pid = std::process::id();

    let insert_backend = backend.clone();
    let delete_backend = backend;
    let write_client = client;

    rsx! {
        div {
            style: "font-family: sans-serif; padding: 16px; max-width: 680px;",
            h1 { "connetto live demo" }
            p {
                style: "color: #666;",
                "window pid {pid}, one client of the shared connetto-server"
            }
            p {
                "COUNT(*) pushed by the server: "
                strong { {count_text} }
            }
            div {
                style: "display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap;",
                button {
                    onclick: move |_| {
                        let _ = insert_backend.0.send(DemoCmd::Insert);
                    },
                    "Insert via Postgres (backend writer)"
                }
                button {
                    onclick: move |_| {
                        let _ = delete_backend.0.send(DemoCmd::DeleteNewest);
                    },
                    "Delete newest via Postgres"
                }
                button {
                    onclick: move |_| {
                        let client = write_client.clone();
                        spawn(async move {
                            let quantity = demo_quantity();
                            let result = client
                                .with_conn(move |conn| {
                                    diesel::insert_into(orders::table)
                                        .values(orders::quantity.eq(quantity))
                                        .execute(conn.conn())
                                })
                                .await;
                            if let Err(err) = result {
                                eprintln!("local insert failed: {err}");
                            }
                        });
                    },
                    "Insert locally (client write)"
                }
            }
            if let Some(err) = rows_error {
                p { style: "color: #b00;", "row subscription error: {err}" }
            }
            if let Some(err) = count_error {
                p { style: "color: #b00;", "count subscription error: {err}" }
            }
            h2 { "local replica (live query)" }
            p {
                style: "color: #666; font-size: 0.9em;",
                "Local client writes upload to the server, apply to Postgres, and echo back through logical replication, so every window converges, count included."
            }
            table {
                style: "border-collapse: collapse; min-width: 320px;",
                thead {
                    tr {
                        th { style: "border: 1px solid #999; padding: 4px 12px;", "id" }
                        th { style: "border: 1px solid #999; padding: 4px 12px;", "quantity" }
                    }
                }
                tbody {
                    for (id, quantity) in display_rows {
                        tr { key: "{id}",
                            td { style: "border: 1px solid #ccc; padding: 4px 12px;", "{id}" }
                            td { style: "border: 1px solid #ccc; padding: 4px 12px;", "{quantity}" }
                        }
                    }
                }
            }
        }
    }
}
