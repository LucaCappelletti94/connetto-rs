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
//! - `CONNETTO_AUTH`, `CONNETTO_AUTH_BIND`, and the OIDC provider vars from
//!   `target/dev-idp.env`: server auth env from the dev IdP. Start the dev
//!   IdP with `CONNETTO_AUTH_BIND=127.0.0.1:18081` set and source
//!   `target/dev-idp.env` before starting the server.

use std::path::PathBuf;
use std::sync::Arc;

use connetto_client::auth::{
    KeyringKeyStore, KeyringStore, NativeAuthenticator, provision_replica_key, remembered_account,
};
use connetto_client::replica::{Replica, replica_db_name};
use connetto_client::teardown::{ForgetError, PurgeError, expiry_warning, forget_device};
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, ExportScope, Grant,
    IDENTITY_RECORD, ImportChoices, PolicyTables, SqlFunctions, decode_identity,
};
use connetto_core::messages::FatalErrorReason;
use connetto_core::traits::{RefreshTokenStore, ReplicaKeyStore};
use connetto_core::transport::WebSocketTransport;
use connetto_dioxus::use_live;
use diesel::prelude::*;
use dioxus::prelude::*;
use rosetta_uuid::Uuid;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

include!(concat!(env!("OUT_DIR"), "/replica-tables.rs"));

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
/// OS keyring service name for both refresh tokens and per-replica keys.
/// One service, one refresh-token entry per account (keyed by the encoded user
/// id), connetto's own reserved records, and one key entry per replica name.
const KEYRING_SERVICE: &str = "connetto-dioxus-demo";

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
/// per row instead of folding the DEFAULT to a constant, and `INNOCUOUS`
/// because the replica runs with trusted schema off and a column DEFAULT is a
/// schema object.
fn uuidv4_functions() -> SqlFunctions {
    SqlFunctions::new().with(Arc::new(|conn: &mut diesel::SqliteConnection| {
        uuidv4_utils::register_impl_with_behavior(
            conn,
            diesel::sqlite::SqliteFunctionBehavior::INNOCUOUS,
            Uuid::new_v4,
        )
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
    /// Token store, used to enumerate stored accounts and to update the
    /// last-used pointer when switching accounts.
    token_store: Arc<KeyringStore>,
    /// When the current session lapses if never refreshed again.
    session_expires_at: std::time::SystemTime,
    /// Encoded account key for the signed-in user, matching what
    /// `RefreshTokenStore::accounts` returns for this identity.
    current_account: String,
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

/// Where an export lands. One fixed name per profile, so exporting twice
/// replaces the copy rather than accumulating them.
fn export_path() -> PathBuf {
    data_dir().join("connetto-local-data.zip")
}

/// Write an export archive beside the replica, reporting what the user can go
/// and open. The bytes are handed over whole rather than streamed: they are
/// already in memory, and the archive is the whole point of the call.
fn write_export(bytes: &[u8]) -> std::io::Result<PathBuf> {
    let path = export_path();
    std::fs::create_dir_all(data_dir())?;
    std::fs::write(&path, bytes)?;
    Ok(path)
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
                    .with_inner_size(dioxus::desktop::LogicalSize::new(760.0, 900.0)),
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
            p { "Check that CONNETTO_AUTH, CONNETTO_AUTH_BIND, CONNETTO_OIDC_PROVIDERS, and per-provider vars are set, then relaunch." }
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

    // Credential store: one entry per service, one record per account.
    let token_store = Arc::new(KeyringStore::new(KEYRING_SERVICE));
    // Key store: one entry per replica name (one per identity on this device).
    let key_store = Arc::new(KeyringKeyStore::new(KEYRING_SERVICE));

    let account =
        remembered_account(token_store.as_ref()).context("reading the remembered account")?;
    let authenticator = Arc::new(NativeAuthenticator::new(
        AUTH_SERVER,
        AUTH_PROVIDER,
        Arc::clone(&token_store)
            as Arc<dyn RefreshTokenStore<Error = connetto_client::ClientError> + Send + Sync>,
        account,
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

    // Save the session fields we need before the access token is moved below.
    let session_expires_at = session.session_expires_at;
    let current_account = connetto_client::encode_identity(&session.user_id)
        .map_err(|err| anyhow::anyhow!("encoding current account key: {err}"))?;

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
        .with_sql_functions(uuidv4_functions())
        .with_policy_tables(PolicyTables::from_translation(
            POLICY_TABLES.iter().copied(),
            POLICY_VIEWS.iter().copied(),
        ))
        // A low threshold so the free-up-space button reclaims after a modest
        // deletion, rather than only once the freelist is a quarter of the file.
        // Trimming still runs only when the button is pressed.
        .with_trim_threshold(5);

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
        token_store,
        session_expires_at,
        current_account,
    };
    Ok((conn, auth_ctx))
}

/// The replica's physical footprint: total pages and free pages a trim can reclaim.
async fn replica_footprint(client: &ConnettoClient<Ws>) -> (i64, i64) {
    client
        .with_conn(|conn| {
            let db = conn.conn();
            let pages = db.page_count(None).unwrap_or(0);
            let free = db.freelist_count(None).unwrap_or(0);
            (pages, free)
        })
        .await
}

/// A short status word for one client event, or `None` to ignore it.
///
/// Covers mutation outcomes (feature 5), rate-limit signals (feature 3), and
/// reconnect / close events.
fn status_label(event: &ClientEvent) -> Option<String> {
    match event {
        ClientEvent::Reconnecting { attempt } => Some(format!("reconnecting (attempt {attempt})")),
        ClientEvent::Reconnected => Some("reconnected".to_owned()),
        ClientEvent::MutationApplied { client_seq } => {
            Some(format!("mutation {client_seq} applied"))
        }
        ClientEvent::MutationRejected { client_seq, .. } => {
            Some(format!("mutation {client_seq} rejected"))
        }
        ClientEvent::MutationConflict {
            client_seq,
            server_row,
            ..
        } => Some(server_row.as_ref().map_or_else(
            || format!("mutation {client_seq} conflicted, the server row is gone"),
            |row| {
                format!(
                    "mutation {client_seq} conflicted, server holds {}",
                    row.row_json
                )
            },
        )),
        // The server asked this client to back off before retrying a request.
        // The client's reconnect policy uses a fixed backoff and does not read
        // retry_after_ms, so the value here is informational only.
        ClientEvent::RateLimited { retry_after_ms, .. } => Some(format!(
            "rate limited: server asks {retry_after_ms}ms before retrying \
             (client reconnects on its own fixed schedule)"
        )),
        // Connection-level throttle: the server closed the entire session because
        // this client exceeded a connection-rate limit. Distinct from the
        // per-request RateLimited above.
        ClientEvent::ServerClosed {
            reason: FatalErrorReason::RateLimited { retry_after_ms },
        } => Some(format!(
            "connection closed: rate limit exceeded (server suggests {retry_after_ms}ms wait)"
        )),
        ClientEvent::ServerClosed { reason } => {
            Some(format!("server closed the connection: {reason:?}"))
        }
        ClientEvent::Closed => Some("connection closed".to_owned()),
        _ => None,
    }
}

/// State of the wipe-replica control, including the force-confirm step.
#[derive(Clone, PartialEq)]
enum WipeState {
    /// Showing the wipe button.
    Idle,
    /// Wipe refused because unsynced writes exist: waiting for force confirm.
    ConfirmForce { unsynced_count: usize },
    /// Error from a failed wipe or account switch.
    Error(String),
}

fn app() -> Element {
    let client = use_context::<ConnettoClient<Ws>>();
    let backend = use_context::<Backend>();
    let auth_ctx = use_context::<AuthCtx>();

    // Live queries.
    let rows = use_live::<_, _, Order>(
        &client,
        orders::table.order((orders::created_at.asc(), orders::id.asc())),
    );
    let count = use_live(&client, orders::table.count());

    // Features 3 and 5: status line updated by client events. The receiver is
    // obtained before the hook so `client` is not moved into it.
    let mut status: Signal<String> = use_signal(|| "connected".to_owned());
    let event_rx = client.events();
    use_hook(move || {
        spawn(async move {
            let mut rx = event_rx;
            while let Ok(event) = rx.recv().await {
                if let Some(label) = status_label(&event) {
                    status.set(label);
                }
            }
        })
    });

    // Feature 2: session expiry warning. Rechecked when rows change (live rows
    // are a proxy for "something happened"). Only fires when unsynced writes
    // exist AND the session is within 7 days of lapsing.
    let mut expiry_warn: Signal<Option<String>> = use_signal(|| None);
    {
        let client = client.clone();
        let session_expires_at = auth_ctx.session_expires_at;
        use_effect(move || {
            let _ = rows.value().read().len();
            let client = client.clone();
            spawn(async move {
                let unsynced = client.with_conn(|c| c.unsynced()).await;
                let lead = std::time::Duration::from_secs(7 * 24 * 60 * 60);
                if let Some(w) = expiry_warning(
                    std::time::SystemTime::now(),
                    session_expires_at,
                    lead,
                    unsynced,
                ) {
                    let remaining = w
                        .session_expires_at
                        .duration_since(std::time::SystemTime::now())
                        .unwrap_or_default();
                    let days = remaining.as_secs() / 86400;
                    expiry_warn.set(Some(format!(
                        "Session expires in {days} day(s): {} unsynced write(s) at risk. \
                         Stay connected to extend the deadline automatically.",
                        w.unsynced.len()
                    )));
                } else {
                    expiry_warn.set(None);
                }
            });
        });
    }

    // Feature 4: replica page footprint, refreshed whenever rows change.
    let mut footprint: Signal<(i64, i64)> = use_signal(|| (0_i64, 0_i64));
    {
        let client = client.clone();
        use_effect(move || {
            let _ = rows.value().read().len();
            let client = client.clone();
            spawn(async move {
                footprint.set(replica_footprint(&client).await);
            });
        });
    }

    // Feature 6: state for the force-confirm wipe.
    let mut wipe_state: Signal<WipeState> = use_signal(|| WipeState::Idle);
    let mut add_picking: Signal<bool> = use_signal(|| false);
    // Feature 7: the last export's outcome, shown so the user knows where the
    // archive went without the app opening a file manager.
    let mut export_status: Signal<Option<String>> = use_signal(|| None);
    let mut import_status: Signal<Option<String>> = use_signal(|| None);

    // Feature 1: stored accounts, read from the keyring once on mount.
    let accounts_list = use_signal(|| auth_ctx.token_store.accounts().unwrap_or_default());
    let current_account = auth_ctx.current_account.clone();
    let token_store = Arc::clone(&auth_ctx.token_store);

    // Derive display values from live queries before any closures move them.
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

    let (pages, free) = *footprint.read();
    let kb = pages * 4;
    let pid = std::process::id();
    let replica_label = auth_ctx.key_name.clone();

    // Clones for closures; one purpose each so moves do not conflict.
    let insert_backend = backend.clone();
    let delete_backend = backend;
    let write_client = client.clone();
    let tidy_client = client.clone();
    let wipe_client = client.clone();
    let force_client = client.clone();
    let switch_client = client.clone();
    let add_client = client.clone();
    let export_client = client.clone();
    let import_client = client.clone();

    // Wipe auth data; cloned twice so the Idle and ConfirmForce arms each get
    // their own (each arm's onclick is a separate move closure).
    let auth_data = (
        Arc::clone(&auth_ctx.authenticator),
        auth_ctx.db_path.clone(),
        Arc::clone(&auth_ctx.key_store),
        auth_ctx.key_name.clone(),
    );
    let auth_data_force = auth_data.clone();

    let token_store_add = Arc::clone(&token_store);

    // Pre-compute account rows so per-item clones are plain Rust, not macro magic.
    let accounts_snap = accounts_list.read().clone();
    let account_items: Vec<(String, String, bool)> = accounts_snap
        .iter()
        .map(|key| {
            let display = decode_identity::<String>(key).unwrap_or_else(|_| key.clone());
            let is_current = *key == current_account;
            (key.clone(), display, is_current)
        })
        .collect();

    rsx! {
        div {
            style: "font-family: sans-serif; padding: 16px; max-width: 760px;",

            // Status line: mutation outcomes, rate-limit notices, reconnect events.
            p {
                style: "font-family: monospace; font-size: 0.85em; color: #555; margin: 0 0 8px 0;",
                "status: " {status}
            }

            // Session expiry warning (feature 2).
            if let Some(warn) = expiry_warn.read().clone() {
                p {
                    style: "background: #fff3cd; border: 1px solid #f0ad4e; \
                            border-radius: 4px; padding: 8px 12px; \
                            color: #8a6d3b; margin-bottom: 12px; font-size: 0.9em;",
                    {warn}
                }
            }

            // Auth strip with wipe and force-confirm (features 6).
            div {
                style: "background: #f0f4ff; border: 1px solid #c0c8e8; \
                        border-radius: 6px; padding: 10px 14px; margin-bottom: 16px;",
                p {
                    style: "margin: 0 0 6px 0; font-size: 0.9em; color: #444;",
                    "Mode: " strong { "Signed in (private encrypted replica)" }
                }
                p {
                    style: "margin: 0 0 8px 0; font-size: 0.85em; color: #555;",
                    "Replica: {replica_label}"
                }
                {match wipe_state.read().clone() {
                    WipeState::Idle => rsx! {
                        button {
                            onclick: move |_| {
                                let (auth, path, ks, kn) = auth_data.clone();
                                let cl = wipe_client.clone();
                                spawn(async move {
                                    let unsynced = cl.with_conn(|c| c.unsynced()).await;
                                    match forget_device(
                                        &auth, &path, ks.as_ref(), &kn, &unsynced, false,
                                    )
                                    .await
                                    {
                                        Ok(()) => restart(),
                                        Err(ForgetError::Purge(PurgeError::Unsynced(seqs))) => {
                                            wipe_state.set(WipeState::ConfirmForce {
                                                unsynced_count: seqs.len(),
                                            });
                                        }
                                        Err(err) => {
                                            wipe_state.set(WipeState::Error(format!(
                                                "logout error: {err}"
                                            )));
                                        }
                                    }
                                });
                            },
                            "Sign out (wipe local replica)"
                        }
                    },
                    WipeState::ConfirmForce { unsynced_count } => rsx! {
                        div {
                            style: "background: #fff8e1; border: 1px solid #f0c040; \
                                    border-radius: 6px; padding: 8px 12px; margin-top: 6px;",
                            p {
                                style: "margin: 0 0 6px 0;",
                                "{unsynced_count} write(s) are not yet synced and will be permanently lost."
                            }
                            div {
                                style: "display: flex; gap: 6px;",
                                button {
                                    onclick: move |_| {
                                        let (auth, path, ks, kn) = auth_data_force.clone();
                                        let cl = force_client.clone();
                                        spawn(async move {
                                            let unsynced = cl.with_conn(|c| c.unsynced()).await;
                                            match forget_device(
                                                &auth, &path, ks.as_ref(), &kn, &unsynced, true,
                                            )
                                            .await
                                            {
                                                Ok(()) => restart(),
                                                Err(err) => {
                                                    wipe_state.set(WipeState::Error(format!(
                                                        "logout error: {err}"
                                                    )));
                                                }
                                            }
                                        });
                                    },
                                    "Confirm: discard and wipe"
                                }
                                button {
                                    onclick: move |_| wipe_state.set(WipeState::Idle),
                                    "Cancel"
                                }
                            }
                        }
                    },
                    WipeState::Error(msg) => rsx! {
                        p {
                            style: "color: #b00; margin: 6px 0 0 0; font-size: 0.85em;",
                            {msg}
                        }
                        button {
                            onclick: move |_| wipe_state.set(WipeState::Idle),
                            "Dismiss"
                        }
                    },
                }}
            }

            // Account management pane (feature 1).
            div {
                style: "border: 1px solid #ccc; border-radius: 6px; \
                        padding: 10px 14px; margin-bottom: 16px;",
                h3 {
                    style: "margin: 0 0 8px 0; font-size: 1em;",
                    "Accounts"
                }
                for (acc_key, display, is_current) in account_items {
                    div {
                        key: "{acc_key}",
                        style: "display: flex; align-items: center; gap: 8px; margin-bottom: 4px;",
                        span { style: "flex: 1;", {display} }
                        if is_current {
                            span {
                                style: "font-size: 0.8em; color: #555; font-style: italic;",
                                "(current)"
                            }
                        } else {
                            // Switch to another stored account: check for unsent
                            // writes, update the last-used pointer, then restart
                            // so the next boot silently refreshes as that user.
                            {
                                let ts = Arc::clone(&token_store);
                                let cl = switch_client.clone();
                                let key = acc_key.clone();
                                rsx! {
                                    button {
                                        onclick: move |_| {
                                            let ts = Arc::clone(&ts);
                                            let cl = cl.clone();
                                            let key = key.clone();
                                            spawn(async move {
                                                let unsynced =
                                                    cl.with_conn(|c| c.unsynced()).await;
                                                if !unsynced.is_empty() {
                                                    wipe_state.set(WipeState::Error(format!(
                                                        "Cannot switch: {} write(s) not yet synced.",
                                                        unsynced.len()
                                                    )));
                                                    return;
                                                }
                                                // Update the last-used pointer so the next boot
                                                // silently refreshes as the chosen account.
                                                if let Err(err) =
                                                    ts.store(IDENTITY_RECORD, &key)
                                                {
                                                    wipe_state.set(WipeState::Error(format!(
                                                        "Cannot switch account: {err}"
                                                    )));
                                                    return;
                                                }
                                                restart();
                                            });
                                        },
                                        "Switch"
                                    }
                                }
                            }
                        }
                    }
                }
                // Clears the last-used pointer so the next boot starts a fresh login.
                if *add_picking.read() {
                    div {
                        style: "margin-top: 8px; background: #f5f5ff; \
                                border: 1px solid #c8c8e8; border-radius: 6px; \
                                padding: 10px 14px;",
                        p {
                            style: "margin: 0 0 8px 0; font-size: 0.9em;",
                            "The app will restart and open a browser login page. \
                             Come back after signing in to finish adding the account."
                        }
                        div {
                            style: "display: flex; gap: 6px; flex-wrap: wrap;",
                            button {
                                onclick: move |_| {
                                    let cl = add_client.clone();
                                    let ts = Arc::clone(&token_store_add);
                                    spawn(async move {
                                        let unsynced = cl.with_conn(|c| c.unsynced()).await;
                                        if !unsynced.is_empty() {
                                            wipe_state.set(WipeState::Error(format!(
                                                "Cannot add account: {} write(s) not yet synced.",
                                                unsynced.len()
                                            )));
                                            return;
                                        }
                                        if let Err(err) = ts.clear(IDENTITY_RECORD) {
                                            wipe_state.set(WipeState::Error(format!(
                                                "Cannot clear identity pointer: {err}"
                                            )));
                                            return;
                                        }
                                        restart();
                                    });
                                },
                                "Sign in"
                            }
                            button {
                                onclick: move |_| add_picking.set(false),
                                "Cancel"
                            }
                        }
                    }
                } else {
                    button {
                        style: "margin-top: 6px;",
                        onclick: move |_| add_picking.set(true),
                        "Add another account"
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
                "Local client writes upload to the server, apply to Postgres, and echo back \
                 through logical replication, so every window converges, count included."
            }
            table {
                style: "border-collapse: collapse; min-width: 320px; margin-bottom: 20px;",
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

            // Retention pane (feature 4): page footprint and a trim button.
            div {
                style: "border: 1px solid #ccc; border-radius: 6px; padding: 10px 14px;",
                h2 {
                    style: "margin-top: 0; font-size: 1em;",
                    "Retention"
                }
                p { "Replica: {pages} pages (~{kb} KB total, {free} free to reclaim)." }
                p {
                    style: "color: #666; font-size: 0.9em;",
                    "Ending a subscription evicts rows no live query still covers, \
                     and the trim pass returns those pages to the filesystem."
                }
                button {
                    onclick: move |_| {
                        let client = tidy_client.clone();
                        spawn(async move {
                            if let Err(err) = client.tidy().await {
                                tracing::error!(error = %err, "tidy failed");
                            }
                            footprint.set(replica_footprint(&client).await);
                        });
                    },
                    "Free up space"
                }
            }

            // Export pane (feature 7): a readable copy of the local data.
            div {
                style: "border: 1px solid #ccc; border-radius: 6px; \
                        padding: 10px 14px; margin-top: 16px;",
                h2 {
                    style: "margin-top: 0; font-size: 1em;",
                    "Your data"
                }
                p {
                    style: "color: #666; font-size: 0.9em;",
                    "Save a zip archive of this device's local data. The archive is \
                     not encrypted and holds every row the device can read: whoever \
                     holds the file holds the data."
                }
                button {
                    onclick: move |_| {
                        let client = export_client.clone();
                        spawn(async move {
                            let message = match client
                                .with_conn(|c| c.export_local_data(ExportScope::Everything))
                                .await
                            {
                                Ok(bytes) => match write_export(&bytes) {
                                    Ok(path) => format!(
                                        "Wrote {} bytes to {}",
                                        bytes.len(),
                                        path.display()
                                    ),
                                    Err(err) => format!("could not write the export: {err}"),
                                },
                                Err(err) => format!("export failed: {err}"),
                            };
                            export_status.set(Some(message));
                        });
                    },
                    "Export local data"
                }
                if let Some(message) = export_status.read().clone() {
                    p {
                        style: "font-family: monospace; font-size: 0.85em; \
                                color: #555; margin: 8px 0 0 0;",
                        {message}
                    }
                }
            }

            // Import pane (R56): restore local data from an archive.
            div {
                style: "border: 1px solid #ccc; border-radius: 6px; \
                        padding: 10px 14px; margin-top: 16px;",
                h2 {
                    style: "margin-top: 0; font-size: 1em;",
                    "Restore from file"
                }
                p {
                    style: "color: #666; font-size: 0.9em;",
                    "Pick an archive from this account. The file's version wins every clash."
                }
                button {
                    onclick: move |_| {
                        let client = import_client.clone();
                        spawn(async move {
                            let Some(file) = rfd::AsyncFileDialog::new()
                                .add_filter("archive", &["zip"])
                                .pick_file()
                                .await
                            else {
                                return;
                            };
                            let bytes = file.read().await;
                            let message =
                                match client.with_conn(move |c| c.import_local_data(&bytes)).await
                                {
                                    Err(err) => format!("refused: {err}"),
                                    Ok(plan) => {
                                        let clash_count = plan.collisions().len();
                                        let choices = ImportChoices::keeping_the_file();
                                        match client
                                            .with_conn(move |c| c.apply_import(&plan, &choices))
                                            .await
                                        {
                                            Ok(outcome) => {
                                                let mut msg = format!(
                                                    "{} row(s) restored, {} kept, \
                                                     {} write(s) restored",
                                                    outcome.rows_restored,
                                                    outcome.rows_kept,
                                                    outcome.writes_restored
                                                );
                                                if clash_count > 0 {
                                                    msg.push_str(&format!(
                                                        " ({clash_count} clash(es) \
                                                         resolved to the file)"
                                                    ));
                                                }
                                                msg
                                            }
                                            Err(err) => format!("apply failed: {err}"),
                                        }
                                    }
                                };
                            import_status.set(Some(message));
                        });
                    },
                    "Import from file"
                }
                if let Some(message) = import_status.read().clone() {
                    p {
                        style: "font-family: monospace; font-size: 0.85em; \
                                color: #555; margin: 8px 0 0 0;",
                        {message}
                    }
                }
            }
        }
    }
}
