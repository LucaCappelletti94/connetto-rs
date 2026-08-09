//! Windowed desktop demo of connetto live queries with native auth.
//!
//! On launch the app acquires a connetto session via the RFC 8252 loopback
//! PKCE flow against `connetto-server`'s auth endpoints (or silently refreshes
//! if a refresh token is already stored), names the replica from the resolved
//! identity, opens it with an OS-keyring-held encryption key, and installs a
//! silent-refresh token source for reconnects. Signing out calls `forget_device`
//! (credential revoke plus key destroy), then restarts the process so a fresh
//! login begins immediately.
//!
//! Configuration environment variables:
//!
//! - `CONNETTO_DEMO_SERVER`: WebSocket host:port of connetto-server
//!   (default `127.0.0.1:7777`).
//! - `CONNETTO_DEMO_PG`: Postgres conninfo for the backend writer buttons
//!   (default `postgres://postgres:postgres@127.0.0.1:55456/postgres`).
//! - `CONNETTO_READER_URL`: conninfo for the non-owner Postgres role provisioned
//!   by `roles.sql` (required).
//! - `CONNETTO_AUTH`, `CONNETTO_AUTH_BIND`, and `CONNETTO_OIDC_*`: server auth
//!   env from the dev IdP. Start the dev IdP with
//!   `CONNETTO_AUTH_BIND=127.0.0.1:18081` set and source `target/dev-idp.env`
//!   before starting the server.

use std::path::PathBuf;
use std::sync::Arc;

use connetto_client::auth::{
    KeyringKeyStore, KeyringStore, NativeAuthenticator, provision_replica_key,
};
use connetto_client::replica::{Replica, replica_db_name};
use connetto_client::teardown::{ForgetError, PurgeError, forget_device};
use connetto_client::{ClientConfig, ConnettoClient, ConnettoConnection, Grant, SqlFunctions};
use connetto_core::traits::{RefreshTokenStore, ReplicaKeyStore};
use connetto_core::transport::WebSocketTransport;
use connetto_dioxus::use_live;
use diesel::prelude::*;
use dioxus::prelude::*;
use rosetta_uuid::Uuid;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// The translated SQLite DDL, used to seed a replica on first boot.
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
/// One service, one refresh-token entry ([`REFRESH_RECORD`]), and one key entry
/// per replica name (derived from the identity).
const KEYRING_SERVICE: &str = "connetto-dioxus-demo";
/// Keyring record holding the refresh token. A literal rather than an identity,
/// because the token is what reveals the identity.
const REFRESH_RECORD: &str = "refresh";

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        quantity -> diesel::sql_types::BigInt,
        // Postgres holds this as `timestamptz`, which is an absolute instant,
        // and the replica as the text `datetime('now')` writes, which is UTC.
        // Both decode to the same instant. The declared type is the naive
        // `Timestamp` because one `table!` serves both backends here and
        // diesel's SQLite backend has no `Timestamptz`.
        created_at -> diesel::sql_types::Timestamp,
    }
}

#[derive(Queryable, Selectable, Debug, PartialEq, Clone)]
#[diesel(table_name = orders)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct Order {
    id: Uuid,
    quantity: i64,
    /// When the row was created, in UTC. The key cannot answer that: a v4 UUID
    /// is random, so ordering by it is arbitrary. Postgres fills this with
    /// `now()` and the replica with `datetime('now')`, which is second
    /// resolution, so two rows made in the same second tie.
    created_at: chrono::NaiveDateTime,
}

// The synced key generator: `orders.id` bakes to `DEFAULT (uuidv4())`, so a
// local write omits the id and this registered function mints it.
#[diesel::declare_sql_function]
extern "SQL" {
    /// Client-authored primary key: a 16-byte UUID v4 blob.
    fn uuidv4() -> diesel::sql_types::Binary;
}

/// The registrar connetto installs on the replica connection: `uuidv4()` mints
/// a fresh `rosetta_uuid::Uuid` (the same strongly typed key the `orders`
/// schema uses on SQLite and Postgres). Nondeterministic, so SQLite calls it
/// per row instead of folding the DEFAULT to a constant.
fn uuidv4_functions() -> SqlFunctions {
    SqlFunctions::new().with(Arc::new(|conn: &mut diesel::SqliteConnection| {
        uuidv4_utils::register_nondeterministic_impl(conn, Uuid::new_v4)
    }))
}

/// A positive demo quantity, varied by the wall clock so successive rows
/// differ. The key is minted separately (the DEFAULT on a local write, an
/// explicit bind in the backend writer), so quantity is never keyed off
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

/// Authentication context passed as Dioxus context.
///
/// Clone is cheap: the heavy pieces live behind `Arc`.
#[derive(Clone)]
struct AuthCtx {
    /// The authenticator that owns the refresh-token store and can revoke
    /// the session server-side.
    authenticator: Arc<NativeAuthenticator>,
    /// Absolute path to the replica SQLite file for this identity.
    db_path: PathBuf,
    /// Key store that holds the per-replica encryption key in the OS keyring.
    key_store: Arc<KeyringKeyStore>,
    /// The replica name (from `replica_db_name`), used as both the keyring
    /// record name and the human-readable replica label.
    key_name: String,
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

/// Restart the current binary and exit this process, so a sign-out takes
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
    connetto_core::logging::init_stdout();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    // A startup failure opens a window that says so. Aborting here instead would
    // leave nothing on screen to explain itself.
    let started = rt.block_on(setup());
    let (client, backend, auth_ctx) = match started {
        Ok(parts) => parts,
        Err(err) => {
            let _guard = rt.enter();
            launch_startup_failure(&err);
            return;
        }
    };
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

/// Open a window that reports why startup failed, showing the error so the
/// user can diagnose and fix the configuration.
fn launch_startup_failure(err: &anyhow::Error) {
    // The chain, not just the outermost message, so the cause is not hidden behind
    // a summary.
    let detail = err
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ");
    STARTUP_ERROR.set(detail).ok();
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            dioxus::desktop::Config::new().with_window(
                dioxus::desktop::WindowBuilder::new()
                    .with_title("connetto demo: cannot start")
                    .with_inner_size(dioxus::desktop::LogicalSize::new(620.0, 320.0)),
            ),
        )
        .launch(startup_failure_app);
}

/// Set once before the failure window launches, because `launch` takes the
/// component by value and the message has to reach it without a context that the
/// working app also uses.
static STARTUP_ERROR: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn startup_failure_app() -> Element {
    let detail = STARTUP_ERROR
        .get()
        .cloned()
        .unwrap_or_else(|| "unknown startup failure".to_owned());
    rsx! {
        div {
            style: "font-family: system-ui; padding: 20px; line-height: 1.5;",
            h2 { "connetto demo cannot start" }
            p { style: "color: #a33;", {detail} }
            p { "Check that CONNETTO_AUTH, CONNETTO_AUTH_BIND, and the CONNETTO_OIDC_* variables are set correctly, then relaunch." }
        }
    }
}

/// Connect to the server and start the backend writer task. Always runs the
/// authenticated path via the native PKCE loopback flow.
async fn setup() -> anyhow::Result<(ConnettoClient<Ws>, Backend, AuthCtx)> {
    use anyhow::Context as _;

    let server =
        std::env::var("CONNETTO_DEMO_SERVER").unwrap_or_else(|_| "127.0.0.1:7777".to_owned());
    let pg_url = std::env::var("CONNETTO_DEMO_PG")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55456/postgres".to_owned());

    let stream = TcpStream::connect(&server)
        .await
        .with_context(|| format!("connecting to {server}"))?;
    let transport = WebSocketTransport::connect("ws://127.0.0.1/", stream)
        .await
        .map_err(|err| anyhow::anyhow!("websocket handshake: {err}"))?;

    let (conn, auth_ctx) = setup_authenticated(transport).await?;

    let client = ConnettoClient::start(conn);

    // Backend writer: DML straight into Postgres through the SAME typed
    // `orders` schema the frontend live query uses, echoed to every window by
    // the server's logical replication stream. The insert lets Postgres mint
    // both the key and `created_at`. `on_conflict_do_nothing` keeps concurrent
    // button presses harmless.
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
                        .values(orders::quantity.eq(demo_quantity()))
                        .on_conflict_do_nothing(),
                    &mut pg,
                )
                .await
                .map(|_| ()),
                DemoCmd::DeleteNewest => {
                    // The key is random, so `created_at` is the only thing that
                    // orders rows. It is second resolution on a row the client
                    // made, so the id breaks a tie and exactly one row goes.
                    match diesel_async::RunQueryDsl::get_result::<Uuid>(
                        orders::table
                            .select(orders::id)
                            .order((orders::created_at.desc(), orders::id.desc()))
                            .limit(1),
                        &mut pg,
                    )
                    .await
                    {
                        Ok(newest) => diesel_async::RunQueryDsl::execute(
                            diesel::delete(orders::table.filter(orders::id.eq(newest))),
                            &mut pg,
                        )
                        .await
                        .map(|_| ()),
                        Err(diesel::result::Error::NotFound) => Ok(()),
                        Err(err) => Err(err),
                    }
                }
            };
            if let Err(err) = run {
                tracing::error!(error = %err, "backend write failed");
            }
        }
    });

    Ok((client, Backend(tx), auth_ctx))
}

/// Acquire a session via the native PKCE loopback flow, name the replica from
/// the resolved identity, provision or load the per-replica encryption key,
/// open the replica, and install a silent-refresh token source.
///
/// The sequence mirrors the ordering in `connetto-web/src/workers.rs`:
/// acquire first, name the replica from the identity, resolve the key,
/// then open. Identity must be known before the file is opened because it
/// decides which file to open.
async fn setup_authenticated(
    transport: WebSocketTransport<TcpStream>,
) -> anyhow::Result<(ConnettoConnection<Ws>, AuthCtx)> {
    use anyhow::Context as _;

    std::fs::create_dir_all(data_dir()).context("creating the application data directory")?;

    // Credential store: one entry per app, one record per account. This demo
    // signs one account in at a time, so the record is the literal below.
    let token_store = Arc::new(KeyringStore::new(KEYRING_SERVICE));
    // Key store: one entry per replica name (one per identity on this device).
    let key_store = Arc::new(KeyringKeyStore::new(KEYRING_SERVICE));

    let authenticator = Arc::new(NativeAuthenticator::new(
        AUTH_SERVER,
        AUTH_PROVIDER,
        Arc::clone(&token_store)
            as Arc<dyn RefreshTokenStore<Error = connetto_client::ClientError> + Send + Sync>,
        REFRESH_RECORD,
    ));

    // Acquire the session. Silently refreshes from the stored refresh token
    // when one is present; runs the interactive loopback login otherwise.
    let session = authenticator
        .acquire::<String>()
        .await
        .map_err(|err| anyhow::anyhow!("acquiring a session: {err}"))?;

    // Identity is known now. Derive the replica name before opening anything:
    // the name decides which file to open, so it must come first.
    let key_name = replica_db_name(REPLICA_PREFIX, &session.user_id)
        .map_err(|err| anyhow::anyhow!("naming the replica for this identity: {err}"))?;

    let db_path = data_dir().join(format!("{key_name}.sqlite"));
    let db_path_str = db_path
        .to_str()
        .context("the application data directory path is not utf8")?
        .to_owned();

    let existing = db_path.exists();

    // Provision-once key custody: an existing replica reads from the keyring
    // (minting a fresh key for it would produce a key that decrypts nothing
    // and would overwrite the slot a backup restore could still use); a new
    // replica mints a fresh key from the platform RNG and caches it.
    let replica_key = if existing {
        key_store
            .load(&key_name)
            .await
            .map_err(|err| anyhow::anyhow!("reading the replica key from the keyring: {err}"))?
    } else {
        Some(
            provision_replica_key(key_store.as_ref(), &key_name)
                .await
                .map_err(|err| anyhow::anyhow!("storing a new replica key: {err}"))?,
        )
    };

    let replica = Replica::encrypted_file(&db_path_str, replica_key)
        .map_err(|err| anyhow::anyhow!("opening the encrypted replica: {err}"))?;

    let config = ClientConfig::new(key_name.clone())
        // Use the replica name as the client id so the server can correlate
        // this connection to the specific per-identity replica.
        .with_login(Some(Grant::new(session.access_token)))
        .with_schema_version(Some(connetto_core::SchemaVersion::from_source(SCHEMA_SQL)))
        .with_sql_functions(uuidv4_functions());

    let conn = if existing {
        // Resume: the replica already carries its schema and cursor.
        ConnettoConnection::connect_existing(transport, &replica, &config, None)
            .await
            .map_err(|err| match err {
                connetto_client::ClientError::Auth(_) => anyhow::anyhow!(
                    "the server refused the credential; \
                     check CONNETTO_AUTH and OIDC settings"
                ),
                other => anyhow::anyhow!("resuming the encrypted replica: {other}"),
            })?
    } else {
        // First boot: apply the schema DDL to the fresh encrypted file.
        // The plaintext template cannot be used here because the per-replica
        // key does not exist at build time.
        ConnettoConnection::connect(transport, &replica, REPLICA_SQLITE_DDL, &config, None)
            .await
            .map_err(|err| match err {
                connetto_client::ClientError::Auth(_) => anyhow::anyhow!(
                    "the server refused the credential; \
                     check CONNETTO_AUTH and OIDC settings"
                ),
                other => anyhow::anyhow!("first boot of the encrypted replica: {other}"),
            })?
    };

    // Install a silent-refresh token source so that every reconnect
    // transparently refreshes the access token from the stored refresh token
    // without opening a browser.
    let conn = conn.with_token_source(authenticator.token_source());

    let auth_ctx = AuthCtx {
        authenticator,
        db_path,
        key_store,
        key_name,
    };
    Ok((conn, auth_ctx))
}

fn app() -> Element {
    let client = use_context::<ConnettoClient<Ws>>();
    let backend = use_context::<Backend>();
    let auth_ctx = use_context::<AuthCtx>();

    let rows = use_live::<_, _, Order>(
        &client,
        orders::table.order((orders::created_at.asc(), orders::id.asc())),
    );
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

    // Extract auth data for the logout closure and the replica label.
    let auth_data = (
        Arc::clone(&auth_ctx.authenticator),
        auth_ctx.db_path.clone(),
        Arc::clone(&auth_ctx.key_store),
        auth_ctx.key_name.clone(),
    );
    let replica_label = auth_ctx.key_name.clone();

    rsx! {
        div {
            style: "font-family: sans-serif; padding: 16px; max-width: 680px;",

            // Auth control strip.
            div {
                style: "background: #f0f4ff; border: 1px solid #c0c8e8; border-radius: 6px; padding: 10px 14px; margin-bottom: 16px;",
                p {
                    style: "margin: 0 0 6px 0; font-size: 0.9em; color: #444;",
                    "Mode: "
                    strong { "Signed in (private encrypted replica)" }
                }
                p {
                    style: "margin: 0 0 8px 0; font-size: 0.85em; color: #555;",
                    "Replica: {replica_label}"
                }
                button {
                    onclick: move |_| {
                        let (auth, path, ks, kn) = auth_data.clone();
                        let cl = logout_client.clone();
                        spawn(async move {
                            let unsynced =
                                cl.with_conn(|conn| conn.unsynced()).await;
                            match forget_device(
                                &auth,
                                &path,
                                ks.as_ref(),
                                &kn,
                                &unsynced,
                                false,
                            )
                            .await
                            {
                                Ok(()) => {
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
                    },
                    "Sign out (wipe local replica)"
                }
                if let Some(msg) = logout_msg.read().clone() {
                    p {
                        style: "color: #b00; margin: 6px 0 0 0; font-size: 0.85em;",
                        {msg}
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
                                tracing::error!(error = %err, "local insert failed");
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
