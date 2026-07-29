//! Windowed desktop demo of connetto live queries, with optional native auth.
//!
//! Two modes, selected by a flag file at startup:
//!
//! - Anonymous (flag absent): no auth, shared plaintext replica seeded from
//!   the shipped template. Matches the original single-mode behavior.
//! - Authenticated (flag present): acquires a connetto session via the RFC 8252
//!   loopback PKCE flow against `connetto-server`'s auth endpoints, names the
//!   replica from the resolved identity, opens it with an OS-keyring-held
//!   encryption key, and installs a silent-refresh token source for reconnects.
//!
//! The mode flag is a plain file whose presence, not contents, carries the
//! signal. It lives at:
//!   `$XDG_DATA_HOME/connetto-dioxus-demo/signed-in`
//!   (fallback: `$HOME/.local/share/connetto-dioxus-demo/signed-in`)
//!
//! Signing in sets the flag and restarts the process. The restarted process
//! runs the interactive PKCE login (or silently refreshes if a refresh token is
//! already stored) before opening the window. Signing out calls `forget_device`
//! (credential revoke plus key destroy plus file delete), clears the flag, and
//! restarts into anonymous mode.
//!
//! Configuration environment variables:
//!
//! - `CONNETTO_DEMO_SERVER`: WebSocket host:port of connetto-server
//!   (default `127.0.0.1:7777`).
//! - `CONNETTO_DEMO_PG`: Postgres conninfo for the backend writer buttons
//!   (default `postgres://postgres:postgres@127.0.0.1:55456/postgres`).

use std::path::PathBuf;
use std::sync::Arc;

use connetto_client::auth::{
    KeyringKeyStore, KeyringStore, NativeAuthenticator, ReplicaKeyStore, provision_replica_key,
};
use connetto_client::replica::{Replica, replica_db_name};
use connetto_client::teardown::{ForgetError, PurgeError, forget_device};
use connetto_client::{ClientConfig, ConnettoClient, ConnettoConnection, SqlFunctions};
use connetto_core::transport::WebSocketTransport;
use connetto_dioxus::use_live;
use diesel::prelude::*;
use dioxus::prelude::*;
use rosetta_uuid::Uuid;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Replica template baked by build.rs: the schema pre-applied to a fresh
/// SQLite file. Used for the anonymous plaintext path only.
const REPLICA_TEMPLATE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/replica-template.sqlite"));
/// The translated SQLite DDL, used to seed a fresh encrypted replica on first
/// authenticated boot (the template approach only seeds a plaintext file).
const REPLICA_SQLITE_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/replica-ddl.sql"));
/// The Postgres schema source the connetto-server must be started with
/// (`CONNETTO_PG_DDL`). Its SHA-256 is the schema version presented at the
/// handshake.
const SCHEMA_SQL: &str = include_str!("../schema.sql");

/// connetto-server auth base URL. The native PKCE loopback flow talks here
/// directly: no CORS, no proxy needed.
const AUTH_SERVER: &str = "http://127.0.0.1:18081";
/// Provider name registered on connetto-server's dev IdP.
const AUTH_PROVIDER: &str = "dev-idp";
/// Prefix for per-identity replica file names (passed to `replica_db_name`).
const REPLICA_PREFIX: &str = "connetto-desktop-demo";
/// OS keyring service name for both the refresh token and per-replica keys.
/// One service, one refresh-token entry (user `"refresh"`), and one key entry
/// per replica name (derived from the identity).
const KEYRING_SERVICE: &str = "connetto-dioxus-demo";

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

/// Commands for the backend writer task, standing in for any non-connetto
/// process mutating the source Postgres directly.
enum DemoCmd {
    /// Insert one row into Postgres.
    Insert,
    /// Delete the newest backend-inserted row from Postgres.
    DeleteNewest,
}

/// Cloneable handle the UI uses to reach the backend writer task.
#[derive(Clone)]
struct Backend(mpsc::UnboundedSender<DemoCmd>);

/// Authentication state passed as Dioxus context.
///
/// Clone is cheap: the heavy pieces live behind `Arc`.
#[derive(Clone)]
enum AuthCtx {
    Anonymous,
    Authenticated {
        /// The authenticator that owns the refresh-token store and can revoke
        /// the session server-side.
        authenticator: Arc<NativeAuthenticator>,
        /// Absolute path to the replica SQLite file for this identity.
        db_path: PathBuf,
        /// Key store that holds the per-replica encryption key in the OS
        /// keyring. Shared with the connection opener.
        key_store: Arc<KeyringKeyStore>,
        /// The replica name (from `replica_db_name`), used as both the key
        /// record name in the keyring and the human-readable replica label.
        key_name: String,
    },
}

/// App data directory following XDG conventions on Linux.
///
/// On platforms without XDG, falls back to `$HOME/.local/share` and then to
/// the temp dir. The directory is created on demand before writing the flag.
fn data_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local").join("share")
    } else {
        std::env::temp_dir()
    }
    .join("connetto-dioxus-demo")
}

/// Path to the mode flag file.
fn mode_flag() -> PathBuf {
    data_dir().join("signed-in")
}

/// Restart the current binary and exit this process, so a mode-switch takes
/// effect immediately. A clean exit is performed if the binary path cannot be
/// resolved: the user relaunches manually.
///
/// Declared as returning `()` rather than `!` so that Dioxus onclick closures
/// that call it satisfy `SpawnIfAsync`: `!` as the block type prevents the
/// closure from matching the expected `FnMut(_) -> ()` signature.
/// `process::exit` still terminates immediately at runtime.
fn restart() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe).spawn();
    }
    std::process::exit(0)
}

/// Top-level sync boundary: build the runtime, drive `setup` to completion,
/// then hand everything to the Dioxus event loop.
///
/// `block_on` is correct here because `main` is a sync function that owns the
/// runtime, not a worker task running inside it.
fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let (client, backend, auth_ctx) = rt.block_on(setup());
    let _guard = rt.enter();
    let title = format!("connetto live demo (pid {})", std::process::id());
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            dioxus::desktop::Config::new().with_window(
                dioxus::desktop::WindowBuilder::new()
                    .with_title(title)
                    .with_inner_size(dioxus::desktop::LogicalSize::new(760.0, 760.0)),
            ),
        )
        .with_context(client)
        .with_context(backend)
        .with_context(auth_ctx)
        .launch(app);
}

/// Connect to the server and start the backend writer task. The mode flag
/// selects which path to take; the path is resolved once at startup and never
/// changes while the process is alive.
async fn setup() -> (ConnettoClient<Ws>, Backend, AuthCtx) {
    let server =
        std::env::var("CONNETTO_DEMO_SERVER").unwrap_or_else(|_| "127.0.0.1:7777".to_owned());
    let pg_url = std::env::var("CONNETTO_DEMO_PG")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55456/postgres".to_owned());

    let stream = TcpStream::connect(&server)
        .await
        .expect("connect to server");
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .expect("ws connect");

    let (conn, auth_ctx) = if mode_flag().exists() {
        setup_authenticated(transport).await
    } else {
        (setup_anonymous(transport).await, AuthCtx::Anonymous)
    };

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

    (client, Backend(tx), auth_ctx)
}

/// Anonymous mode: temp file, plaintext, no token, shared replica.
async fn setup_anonymous(transport: WebSocketTransport<TcpStream>) -> ConnettoConnection<Ws> {
    // The replica lives in a per-process temp file. The window loop never
    // returns, so no drop would run for it anyway and the OS temp cleaner
    // owns it.
    let db_path = std::env::temp_dir().join(format!(
        "connetto-desktop-demo-{}.sqlite",
        std::process::id()
    ));
    let db_path = db_path.to_str().expect("utf8 temp path").to_owned();
    let config = ClientConfig {
        client_id: format!("desktop-demo-{}", std::process::id()),
        auth_token: "token".to_owned(),
        schema_version: Some(connetto_core::SchemaVersion::from_source(SCHEMA_SQL)),
        sql_functions: uuidv7_functions(),
    };
    ConnettoConnection::connect_with_plaintext_template(
        transport,
        &db_path,
        REPLICA_TEMPLATE,
        &config,
        None,
    )
    .await
    .expect("anonymous connect")
}

/// Authenticated mode: acquire a session via the native PKCE loopback flow,
/// name the replica from the resolved identity, provision or load the
/// per-replica encryption key, open the replica, and install a silent-refresh
/// token source.
///
/// The sequence mirrors the ordering in `connetto-web/src/workers.rs`:
/// acquire first, name the replica from the identity, resolve the key,
/// then open. Identity must be known before the file is opened because it
/// decides which file to open.
async fn setup_authenticated(
    transport: WebSocketTransport<TcpStream>,
) -> (ConnettoConnection<Ws>, AuthCtx) {
    std::fs::create_dir_all(data_dir()).expect("create data dir");

    // Credential store: one entry per app, user key `"refresh"`.
    let token_store = Arc::new(KeyringStore::new(KEYRING_SERVICE, "refresh"));
    // Key store: one entry per replica name (one per identity on this device).
    let key_store = Arc::new(KeyringKeyStore::new(KEYRING_SERVICE));

    let authenticator = Arc::new(NativeAuthenticator::new(
        AUTH_SERVER,
        AUTH_PROVIDER,
        Arc::clone(&token_store) as Arc<dyn connetto_client::auth::RefreshTokenStore>,
    ));

    // Acquire the session. Silently refreshes from the stored refresh token
    // when one is present; runs the interactive loopback login otherwise.
    let session = authenticator
        .acquire::<String>()
        .await
        .expect("acquire session");

    // Identity is known now. Derive the replica name before opening anything:
    // the name decides which file to open, so it must come first.
    let key_name = replica_db_name(REPLICA_PREFIX, &session.user_id).expect("derive replica name");

    let db_path = data_dir().join(format!("{key_name}.sqlite"));
    let db_path_str = db_path.to_str().expect("utf8 data dir path").to_owned();

    let existing = db_path.exists();

    // Provision-once key custody: an existing replica reads from the keyring
    // (minting a fresh key for it would produce a key that decrypts nothing
    // and would overwrite the slot a backup restore could still use); a new
    // replica mints a fresh key from the platform RNG and caches it.
    let replica_key = if existing {
        key_store
            .load(&key_name)
            .expect("load replica key from keyring")
    } else {
        Some(
            provision_replica_key(key_store.as_ref() as &dyn ReplicaKeyStore, &key_name)
                .expect("provision replica key"),
        )
    };

    let replica =
        Replica::encrypted_file(&db_path_str, replica_key).expect("build encrypted replica");

    let config = ClientConfig {
        // Use the replica name as the client id so the server can correlate
        // this connection to the specific per-identity replica.
        client_id: key_name.clone(),
        auth_token: session.access_token,
        schema_version: Some(connetto_core::SchemaVersion::from_source(SCHEMA_SQL)),
        sql_functions: uuidv7_functions(),
    };

    let conn = if existing {
        // Resume: the replica already carries its schema and cursor.
        ConnettoConnection::connect_existing(transport, &replica, &config, None)
            .await
            .expect("resume encrypted replica")
    } else {
        // First boot: apply the schema DDL to the fresh encrypted file.
        // The plaintext template cannot be used here because the per-replica
        // key does not exist at build time.
        ConnettoConnection::connect(transport, &replica, REPLICA_SQLITE_DDL, &config, None)
            .await
            .expect("first-boot encrypted replica")
    };

    // Install a silent-refresh token source so that every reconnect
    // transparently refreshes the access token from the stored refresh token
    // without opening a browser.
    let conn = conn.with_token_source(authenticator.token_source());

    let auth_ctx = AuthCtx::Authenticated {
        authenticator,
        db_path,
        key_store,
        key_name,
    };
    (conn, auth_ctx)
}

fn app() -> Element {
    let client = use_context::<ConnettoClient<Ws>>();
    let backend = use_context::<Backend>();
    let auth_ctx = use_context::<AuthCtx>();

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
    let write_client = client.clone();
    // A separate clone for the logout handler so the write closure above does
    // not capture the only copy.
    let logout_client = client.clone();

    let mut logout_msg: Signal<Option<String>> = use_signal(|| None);

    // Pre-extract authenticated state so the closures below can be simple
    // `move` captures without needing to match inside the onclick.
    let auth_label = match &auth_ctx {
        AuthCtx::Anonymous => "Anonymous (shared replica, unencrypted)",
        AuthCtx::Authenticated { .. } => "Signed in (private encrypted replica)",
    };
    let is_authenticated = matches!(auth_ctx, AuthCtx::Authenticated { .. });
    let auth_data: Option<(
        Arc<NativeAuthenticator>,
        PathBuf,
        Arc<KeyringKeyStore>,
        String,
    )> = match &auth_ctx {
        AuthCtx::Authenticated {
            authenticator,
            db_path,
            key_store,
            key_name,
        } => Some((
            Arc::clone(authenticator),
            db_path.clone(),
            Arc::clone(key_store),
            key_name.clone(),
        )),
        AuthCtx::Anonymous => None,
    };
    let replica_label = auth_data
        .as_ref()
        .map(|(_, _, _, kn)| kn.clone())
        .unwrap_or_default();

    rsx! {
        div {
            style: "font-family: sans-serif; padding: 16px; max-width: 680px;",

            // Auth control strip.
            div {
                style: "background: #f0f4ff; border: 1px solid #c0c8e8; border-radius: 6px; padding: 10px 14px; margin-bottom: 16px;",
                p {
                    style: "margin: 0 0 6px 0; font-size: 0.9em; color: #444;",
                    "Mode: "
                    strong { {auth_label} }
                }
                if is_authenticated {
                    p {
                        style: "margin: 0 0 8px 0; font-size: 0.85em; color: #555;",
                        "Replica: {replica_label}"
                    }
                    button {
                        onclick: move |_| {
                            // Clone the captured auth_data tuple for the async task.
                            if let Some((auth, path, ks, kn)) = auth_data.clone() {
                                let cl = logout_client.clone();
                                spawn(async move {
                                    let unsynced =
                                        cl.with_conn(|conn| conn.unsynced()).await;
                                    match forget_device(
                                        &auth,
                                        &path,
                                        ks.as_ref() as &dyn ReplicaKeyStore,
                                        &kn,
                                        &unsynced,
                                        false,
                                    )
                                    .await
                                    {
                                        Ok(()) => {
                                            let _ = std::fs::remove_file(mode_flag());
                                            restart();
                                        }
                                        Err(ForgetError::Purge(PurgeError::Unsynced(seqs))) => {
                                            logout_msg.set(Some(format!(
                                                "Logout refused: {} write(s) not yet synced. \
                                                 Wait for sync to complete, then retry.",
                                                seqs.len()
                                            )));
                                        }
                                        Err(err) => {
                                            logout_msg.set(Some(format!(
                                                "Logout error: {err}"
                                            )));
                                        }
                                    }
                                });
                            }
                        },
                        "Sign out (wipe local replica)"
                    }
                    if let Some(msg) = logout_msg.read().clone() {
                        p {
                            style: "color: #b00; margin: 6px 0 0 0; font-size: 0.85em;",
                            {msg}
                        }
                    }
                } else {
                    p {
                        style: "margin: 0 0 8px 0; font-size: 0.85em; color: #666;",
                        "Sign in to switch to a private encrypted replica named after your account."
                    }
                    button {
                        onclick: move |_| {
                            let dir = data_dir();
                            let _ = std::fs::create_dir_all(&dir);
                            let _ = std::fs::write(dir.join("signed-in"), b"");
                            restart();
                        },
                        "Sign in"
                    }
                }
            }

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
