//! Native demo of connetto live queries with native auth, on the desktop and,
//! built with `dx` for the `mobile` feature, on Android.
//!
//! The window opens first and setup runs as a task behind it. Setup acquires
//! a connetto session via the RFC 8252 loopback PKCE flow against
//! `connetto-server`'s auth endpoints in the system browser (or silently
//! refreshes if a refresh token is already stored), names the replica from the
//! resolved identity, opens it with an OS-keyring-held encryption key, and
//! starts a pump that redials and resumes whenever the link drops. Signing out
//! calls `forget_device` (credential revoke plus key destroy) and runs setup
//! again in the same process, so a fresh login begins immediately.
//!
//! The dev stack is one command from the repository root, which prints the
//! environment a desktop run needs and the `adb reverse` lines a phone needs.
//!
//! ```text
//! cargo run -p connetto-test-harness --bin connetto-demo-stack
//! ```
//!
//! Run as that command's program, `connetto-android-proof` builds this demo
//! for an attached phone or emulator, installs it, and walks sign-in, sync,
//! an offline write and its upload on reconnect.
//!
//! ```text
//! cargo build -p connetto-test-harness --bin connetto-android-proof
//! cargo run -p connetto-test-harness --bin connetto-demo-stack -- \
//!   target/debug/connetto-android-proof --serial SERIAL
//! ```
//!
//! The demo reads `CONNETTO_DEMO_SERVER`, the sync host:port (default
//! `127.0.0.1:7777`), `CONNETTO_DEMO_AUTH_ORIGIN`, the auth server (default
//! `http://127.0.0.1:18081`), and `CONNETTO_DEMO_PG`, the conninfo the backend
//! writer buttons use (default `postgres://postgres:postgres@127.0.0.1:55456/postgres`).
//! Its server runs `schema.sql` and `policies.sql`, with `schema.sql`,
//! `connetto_file_server::DEPLOYMENT_DDL`, `connetto_server::epoch::EPOCH_DDL`,
//! `roles.sql` and `content.sql` applied in that order, and `orders,photos`
//! writable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use base64::Engine as _;
use connetto_client::auth::{
    KeyringKeyStore, KeyringStore, NativeAuthenticator, provision_replica_key, remembered_account,
};
use connetto_client::reconnect::{ReconnectPolicy, TokioSleeper};
use connetto_client::replica::{Replica, replica_db_name};
use connetto_client::teardown::{
    ForgetError, PurgeError, content_dir, expiry_warning, forget_device,
};
use connetto_client::{
    ClientConfig, ClientEvent, ConnettoClient, ConnettoConnection, Grant, IDENTITY_RECORD,
    ImportChoices, PolicyTables, SqlFunctions, decode_identity,
};
use connetto_core::messages::FatalErrorReason;
use connetto_core::traits::{RefreshTokenStore, ReplicaKeyStore};
use connetto_core::transport::WebSocketTransport;
use connetto_dioxus::use_live;
use connetto_dioxus_desktop_demo::{
    Order, Photo, mime_from_extension, orders, photo_file_id, photos, short_hex, stage_photo_row,
};
use connetto_file_client::{ContentClient, ContentEvent, FileId, FsStore, ReqwestHttp, Resolved};
use diesel::prelude::*;
use dioxus::prelude::*;
use rosetta_uuid::Uuid;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

include!(concat!(env!("OUT_DIR"), "/replica-tables.rs"));

/// The translated SQLite DDL, used to seed a replica on first boot.
const REPLICA_SQLITE_DDL: &str = include_str!(concat!(env!("OUT_DIR"), "/replica-ddl.sql"));
/// The Postgres schema source the connetto-server must be started with
/// (`CONNETTO_PG_DDL`).
const SCHEMA_SQL: &str = include_str!("../schema.sql");
/// The row policies the server must be started with (`CONNETTO_PG_POLICIES`).
/// The server hashes them beside the schema into the version presented at the
/// handshake.
const POLICIES_SQL: &str = include_str!("../policies.sql");

const DEFAULT_AUTH_ORIGIN: &str = "http://127.0.0.1:18081";
const AUTH_PROVIDER: &str = "dev-idp";
const REPLICA_PREFIX: &str = "connetto-desktop-demo";
const KEYRING_SERVICE: &str = "connetto-dioxus-demo";

// The synced key generator: `orders.id` bakes to `DEFAULT (uuidv4())`, so a
// local write omits the id and this registered function mints it.
#[diesel::declare_sql_function]
extern "SQL" {
    /// Client-authored primary key: a 16-byte UUID v4 blob.
    fn uuidv4() -> diesel::sql_types::Binary;
}

/// The registrar connetto installs on the replica connection.
fn uuidv4_functions() -> SqlFunctions {
    SqlFunctions::new().with(Arc::new(|conn: &mut diesel::SqliteConnection| {
        uuidv4_utils::register_impl_with_behavior(
            conn,
            diesel::sqlite::SqliteFunctionBehavior::INNOCUOUS,
            Uuid::new_v4,
        )
    }))
}

fn demo_quantity() -> i64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    i64::try_from(millis % 9).unwrap_or(0) * 5 + 5
}

type Ws = WebSocketTransport<TcpStream>;
type Content = Arc<ContentClient<Ws, FsStore, ReqwestHttp>>;

enum DemoCmd {
    Insert,
    DeleteNewest,
}

#[derive(Clone)]
struct Backend(mpsc::UnboundedSender<DemoCmd>);

#[derive(Clone)]
struct AuthCtx {
    authenticator: Arc<NativeAuthenticator>,
    db_path: PathBuf,
    key_store: Arc<KeyringKeyStore>,
    key_name: String,
    token_store: Arc<KeyringStore>,
    session_expires_at: std::time::SystemTime,
    current_account: String,
}

fn data_dir() -> PathBuf {
    app_data_root().join("connetto-dioxus-demo")
}

#[cfg(not(target_os = "android"))]
fn app_data_root() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local").join("share")
    } else {
        std::env::temp_dir()
    }
}

/// The app's private files directory, since Android sets neither `HOME` nor
/// `XDG_DATA_HOME`. A failed lookup is logged and leaves the temp directory,
/// where the first write then fails with an error setup reports.
#[cfg(target_os = "android")]
fn app_data_root() -> PathBuf {
    robius_directories::ProjectDirs::from("", "", "connetto-dioxus-demo").map_or_else(
        || {
            tracing::error!("the app's files directory is unavailable");
            std::env::temp_dir()
        },
        |dirs| dirs.data_dir().to_path_buf(),
    )
}

fn export_path() -> PathBuf {
    data_dir().join("connetto-local-data.zip")
}

fn create_export_file() -> std::io::Result<(PathBuf, std::fs::File)> {
    let path = export_path().with_extension("zip.part");
    std::fs::create_dir_all(data_dir())?;
    let file = std::fs::File::create(&path)?;
    Ok((path, file))
}

fn publish_export(part: &Path) -> std::io::Result<PathBuf> {
    let path = export_path();
    std::fs::rename(part, &path)?;
    Ok(path)
}

fn main() {
    connetto_core::logging::init_stdout();
    // Leaked so it outlives `launch`: every session's tasks run on it for the
    // life of the process.
    let runtime: &'static tokio::runtime::Runtime = Box::leak(Box::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime"),
    ));
    let _guard = runtime.enter();
    let builder = dioxus::LaunchBuilder::new();
    #[cfg(feature = "desktop")]
    let builder = builder.with_cfg(
        dioxus::desktop::Config::new().with_window(
            dioxus::desktop::WindowBuilder::new()
                .with_title(format!("connetto live demo (pid {})", std::process::id()))
                .with_inner_size(dioxus::desktop::LogicalSize::new(760.0, 1100.0)),
        ),
    );
    builder.launch(Shell);
}

/// Everything one signed-in session runs on, and dropping it ends the
/// session. The pump owns the connection and the outbox task holds a client
/// clone, so both are aborted here.
struct Parts {
    client: ConnettoClient<Ws>,
    backend: Backend,
    auth: AuthCtx,
    content: Content,
    pump: tokio::task::JoinHandle<()>,
    outbox: tokio::task::JoinHandle<()>,
}

impl Drop for Parts {
    fn drop(&mut self) {
        self.pump.abort();
        self.outbox.abort();
    }
}

/// One session's parts, equal only to itself, so a new session remounts the UI.
#[derive(Clone)]
struct SessionParts(Rc<Parts>);

impl PartialEq for SessionParts {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

/// Ends the current session and runs setup again, which signs in afresh as
/// whichever account the marker names.
#[derive(Clone, Copy)]
struct Restart(Signal<u64>);

impl Restart {
    fn request(mut self) {
        *self.0.write() += 1;
    }
}

enum Stage {
    Starting,
    Ready(SessionParts),
    Failed(String),
}

/// Opens at once and runs setup as a task behind it. Android calls `main`
/// from the activity's start, so nothing there may wait on the network or on
/// a login in the browser.
#[component]
fn Shell() -> Element {
    let generation = use_signal(|| 0_u64);
    let mut stage = use_signal(|| Stage::Starting);
    use_context_provider(|| Restart(generation));
    let runtime = use_hook(tokio::runtime::Handle::current);
    use_effect(move || {
        let _ = generation();
        stage.set(Stage::Starting);
        let runtime = runtime.clone();
        spawn(async move {
            let outcome = runtime.spawn(setup()).await;
            stage.set(match outcome {
                Ok(Ok(parts)) => Stage::Ready(SessionParts(Rc::new(parts))),
                Ok(Err(err)) => Stage::Failed(
                    err.chain()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(": "),
                ),
                Err(err) => Stage::Failed(format!("the setup task stopped: {err}")),
            });
        });
    });
    let session = *generation.read();
    match &*stage.read() {
        Stage::Starting => rsx! {
            div {
                style: "font-family: system-ui; padding: 20px; line-height: 1.5;",
                h2 { "Signing in" }
                p { "A browser page opens for the login. Come back here once you have signed in." }
            }
        },
        Stage::Failed(detail) => {
            let detail = detail.clone();
            rsx! {
                div {
                    style: "font-family: system-ui; padding: 20px; line-height: 1.5;",
                    h2 { "connetto demo cannot start" }
                    p { style: "color: #a33;", {detail} }
                    p { "Check that the dev stack is up with CONNETTO_AUTH, CONNETTO_AUTH_BIND, CONNETTO_OIDC_PROVIDERS and the per-provider vars set, and on a phone that adb reverse forwards its ports." }
                    button { onclick: move |_| Restart(generation).request(), "Try again" }
                }
            }
        }
        Stage::Ready(parts) => {
            let parts = parts.clone();
            rsx! { Session { key: "{session}", parts } }
        }
    }
}

/// Provides one session's parts to the app for as long as it is mounted.
#[component]
fn Session(parts: SessionParts) -> Element {
    use_context_provider(|| parts.0.client.clone());
    use_context_provider(|| parts.0.backend.clone());
    use_context_provider(|| parts.0.auth.clone());
    use_context_provider(|| parts.0.content.clone());
    rsx! { App {} }
}

async fn setup() -> anyhow::Result<Parts> {
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

    let (conn, auth_ctx, root_key) = setup_authenticated(transport).await?;

    // A dropped link redials the same address and resumes, so writes made
    // while offline upload once the server is reachable again.
    let (client, pump) = ConnettoClient::with_reconnect(
        conn,
        move || {
            let server = server.clone();
            async move {
                let stream = TcpStream::connect(&server)
                    .await
                    .map_err(|err| err.to_string())?;
                WebSocketTransport::connect("ws://127.0.0.1/", stream)
                    .await
                    .map_err(|err| err.to_string())
            }
        },
        TokioSleeper,
        ReconnectPolicy::default(),
    );
    let pump = tokio::spawn(pump);

    let (tx, mut rx) = mpsc::unbounded_channel::<DemoCmd>();
    tokio::spawn(async move {
        use diesel_async::AsyncConnection;
        let mut pg = diesel_async::AsyncPgConnection::establish(&pg_url)
            .await
            .expect("connect to postgres");
        while let Some(cmd) = rx.recv().await {
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

    let store_dir = content_dir(&auth_ctx.db_path);
    let content = Arc::new(
        ContentClient::attach(
            client.clone(),
            FsStore::new(store_dir),
            root_key,
            ReqwestHttp::new(),
        )
        .await
        .map_err(|err| anyhow::anyhow!("attaching content client: {err}"))?
        .heal_lost(
            "SELECT content_id FROM photos WHERE content_state = 'lost'",
            "content_id",
        )
        .await
        .map_err(|err| anyhow::anyhow!("registering the lost-photo query: {err}"))?,
    );
    let cc_drive = Arc::clone(&content);
    let outbox = tokio::spawn(async move { cc_drive.drive_outbox(TokioSleeper).await });

    Ok(Parts {
        client,
        backend: Backend(tx),
        auth: auth_ctx,
        content,
        pump,
        outbox,
    })
}

async fn setup_authenticated(
    transport: WebSocketTransport<TcpStream>,
) -> anyhow::Result<(ConnettoConnection<Ws>, AuthCtx, [u8; 32])> {
    use anyhow::Context as _;

    tokio::fs::create_dir_all(data_dir())
        .await
        .context("creating the application data directory")?;

    let token_store = Arc::new(KeyringStore::new(KEYRING_SERVICE));
    let key_store = Arc::new(KeyringKeyStore::new(KEYRING_SERVICE));

    let account =
        remembered_account(token_store.as_ref()).context("reading the remembered account")?;
    let authenticator = Arc::new(NativeAuthenticator::new(
        std::env::var("CONNETTO_DEMO_AUTH_ORIGIN")
            .unwrap_or_else(|_| DEFAULT_AUTH_ORIGIN.to_owned()),
        AUTH_PROVIDER,
        Arc::clone(&token_store)
            as Arc<dyn RefreshTokenStore<Error = connetto_client::ClientError> + Send + Sync>,
        account,
    ));

    let session = authenticator
        .acquire::<String>()
        .await
        .map_err(|err| anyhow::anyhow!("acquiring a session: {err}"))?;

    let key_name = replica_db_name(REPLICA_PREFIX, &session.user_id)
        .map_err(|err| anyhow::anyhow!("naming the replica for this identity: {err}"))?;

    let session_expires_at = session.session_expires_at;
    let current_account = connetto_client::encode_identity(&session.user_id)
        .map_err(|err| anyhow::anyhow!("encoding current account key: {err}"))?;

    let db_path = data_dir().join(format!("{key_name}.sqlite"));
    let db_path_str = db_path
        .to_str()
        .context("the application data directory path is not utf8")?
        .to_owned();

    let existing = db_path.exists();

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

    // Extract the raw bytes before replica_key is consumed below.
    let root_key = replica_key.as_ref().map_or([0u8; 32], |k| *k.as_bytes());

    let replica = Replica::encrypted_file(&db_path_str, replica_key)
        .map_err(|err| anyhow::anyhow!("opening the encrypted replica: {err}"))?;

    let config = ClientConfig::new(key_name.clone())
        .with_login(Some(Grant::new(session.access_token)))
        .with_schema_version(Some(connetto_core::SchemaVersion::from_sources([
            SCHEMA_SQL,
            POLICIES_SQL,
        ])))
        .with_sql_functions(uuidv4_functions())
        .with_policy_tables(PolicyTables::from_translation(
            POLICY_TABLES.iter().copied(),
            POLICY_VIEWS.iter().copied(),
        ))
        .with_trim_threshold(5);

    let conn = if existing {
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
    Ok((conn, auth_ctx, root_key))
}

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
        ClientEvent::RateLimited { retry_after_ms, .. } => Some(format!(
            "rate limited: server asks {retry_after_ms}ms before retrying \
             (client reconnects on its own fixed schedule)"
        )),
        ClientEvent::ServerClosed {
            reason: FatalErrorReason::RateLimited { retry_after_ms },
        } => Some(format!(
            "connection closed: rate limit exceeded (server suggests {retry_after_ms}ms wait)"
        )),
        ClientEvent::ServerClosed { reason } => {
            Some(format!("server closed the connection: {reason:?}"))
        }
        ClientEvent::Closed => Some("connection closed".to_owned()),
        ClientEvent::AuthenticationRequired => {
            Some("session expired, sign out and sign in again".to_owned())
        }
        _ => None,
    }
}

#[derive(Clone, PartialEq)]
enum WipeState {
    Idle,
    ConfirmForce { unsynced_count: usize },
    Error(String),
}

#[component]
fn App() -> Element {
    let client = use_context::<ConnettoClient<Ws>>();
    let backend = use_context::<Backend>();
    let auth_ctx = use_context::<AuthCtx>();

    let rows = use_live::<_, _, Order>(
        &client,
        orders::table.order((orders::created_at.asc(), orders::id.asc())),
    );
    let count = use_live(&client, orders::table.count());
    let counts_by_quantity = use_live(
        &client,
        orders::table
            .group_by(orders::quantity)
            .select((orders::quantity, diesel::dsl::count_star())),
    );

    // Client event status line.
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

    // Session expiry warning and replica footprint, both refreshed as rows change.
    let mut expiry_warn: Signal<Option<String>> = use_signal(|| None);
    let mut footprint: Signal<(i64, i64)> = use_signal(|| (0_i64, 0_i64));
    {
        let client = client.clone();
        let session_expires_at = auth_ctx.session_expires_at;
        use_effect(move || {
            let _ = rows.value().read().len();
            let client = client.clone();
            spawn(async move {
                expiry_warn.set(expiry_text(&client, session_expires_at).await);
                footprint.set(replica_footprint(&client).await);
            });
        });
    }

    let wipe_state: Signal<WipeState> = use_signal(|| WipeState::Idle);

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
    let grouped_text = grouped_label(&counts_by_quantity.value().read());
    let grouped_error = counts_by_quantity.error().read().clone();
    let pid = std::process::id();

    let insert_backend = backend.clone();
    let delete_backend = backend;
    let write_client = client;

    rsx! {
        div {
            style: "font-family: sans-serif; padding: 16px; max-width: 760px;",

            p {
                style: "font-family: monospace; font-size: 0.85em; color: #555; margin: 0 0 8px 0;",
                "status: " {status}
            }

            if let Some(warn) = expiry_warn.read().clone() {
                p {
                    style: "background: #fff3cd; border: 1px solid #f0ad4e; \
                            border-radius: 4px; padding: 8px 12px; \
                            color: #8a6d3b; margin-bottom: 12px; font-size: 0.9em;",
                    {warn}
                }
            }

            SessionPanel { wipe_state }
            AccountsPanel { wipe_state }

            h1 { "connetto live demo" }
            p {
                style: "color: #666;",
                "window pid {pid}, one client of the shared connetto-server"
            }
            p {
                "COUNT(*) pushed by the server: "
                strong { {count_text} }
            }
            p {
                "COUNT(*) grouped by quantity: "
                strong { {grouped_text} }
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
            if let Some(err) = grouped_error {
                p { style: "color: #b00;", "grouped subscription error: {err}" }
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

            PhotosPanel {}
            RetentionPanel { footprint }
            ExportPanel {}
            ImportPanel {}
        }
    }
}

/// The warning shown while the session nears expiry with local writes unsent.
async fn expiry_text(
    client: &ConnettoClient<Ws>,
    session_expires_at: std::time::SystemTime,
) -> Option<String> {
    let unsynced = client.with_conn(|c| c.unsynced()).await;
    let lead = std::time::Duration::from_secs(7 * 24 * 60 * 60);
    let warning = expiry_warning(
        std::time::SystemTime::now(),
        session_expires_at,
        lead,
        unsynced,
        0,
    )?;
    let remaining = warning
        .session_expires_at
        .duration_since(std::time::SystemTime::now())
        .unwrap_or_default();
    let days = remaining.as_secs() / 86400;
    Some(format!(
        "Session expires in {days} day(s): {} pending local item(s) at risk. \
         Stay connected to extend the deadline automatically.",
        warning.pending_count()
    ))
}

/// `quantity: count` pairs in quantity order, or `pending` before the first answer.
fn grouped_label(counts: &HashMap<i64, i64>) -> String {
    let mut sorted: Vec<(i64, i64)> = counts.iter().map(|(q, c)| (*q, *c)).collect();
    sorted.sort_unstable();
    if sorted.is_empty() {
        return "pending".to_owned();
    }
    sorted
        .iter()
        .map(|(quantity, count)| format!("{quantity}: {count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Sign out of this account, wiping the replica, and start over.
async fn sign_out(
    auth: &AuthCtx,
    client: &ConnettoClient<Ws>,
    discard_unsynced: bool,
    restart: Restart,
    mut wipe_state: Signal<WipeState>,
) {
    let unsynced = client.with_conn(|c| c.unsynced()).await;
    match forget_device(
        &auth.authenticator,
        &auth.db_path,
        auth.key_store.as_ref(),
        &auth.key_name,
        &unsynced,
        discard_unsynced,
    )
    .await
    {
        Ok(()) => restart.request(),
        Err(ForgetError::Purge(PurgeError::Unsynced(seqs))) if !discard_unsynced => {
            wipe_state.set(WipeState::ConfirmForce {
                unsynced_count: seqs.len(),
            });
        }
        Err(err) => wipe_state.set(WipeState::Error(format!("logout error: {err}"))),
    }
}

#[component]
fn SessionPanel(wipe_state: Signal<WipeState>) -> Element {
    let restart = use_context::<Restart>();
    let client = use_context::<ConnettoClient<Ws>>();
    let auth_ctx = use_context::<AuthCtx>();
    let replica_label = auth_ctx.key_name.clone();
    let (wipe_auth, wipe_client) = (auth_ctx.clone(), client.clone());
    let (force_auth, force_client) = (auth_ctx, client);

    rsx! {
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
                            let (auth, cl) = (wipe_auth.clone(), wipe_client.clone());
                            spawn(async move { sign_out(&auth, &cl, false, restart, wipe_state).await });
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
                                    let (auth, cl) = (force_auth.clone(), force_client.clone());
                                    spawn(async move { sign_out(&auth, &cl, true, restart, wipe_state).await });
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
    }
}

/// Point the device at another account, or at none so the next start signs in
/// afresh, and start over. Refused while local writes are unsent.
async fn change_account(
    client: &ConnettoClient<Ws>,
    token_store: &KeyringStore,
    account: Option<&str>,
    restart: Restart,
    mut wipe_state: Signal<WipeState>,
) {
    let unsynced = client.with_conn(|c| c.unsynced()).await;
    if !unsynced.is_empty() {
        wipe_state.set(WipeState::Error(format!(
            "Cannot change account: {} write(s) not yet synced.",
            unsynced.len()
        )));
        return;
    }
    let pointed = match account {
        Some(key) => token_store.store(IDENTITY_RECORD, key),
        None => token_store.clear(IDENTITY_RECORD),
    };
    match pointed {
        Ok(()) => restart.request(),
        Err(err) => wipe_state.set(WipeState::Error(format!("Cannot change account: {err}"))),
    }
}

#[component]
fn AccountsPanel(wipe_state: Signal<WipeState>) -> Element {
    let restart = use_context::<Restart>();
    let client = use_context::<ConnettoClient<Ws>>();
    let auth_ctx = use_context::<AuthCtx>();
    let mut add_picking: Signal<bool> = use_signal(|| false);
    let accounts_list = use_signal(|| auth_ctx.token_store.accounts().unwrap_or_default());
    let current_account = auth_ctx.current_account.clone();
    let token_store = Arc::clone(&auth_ctx.token_store);
    let add_client = client.clone();
    let add_store = Arc::clone(&token_store);

    let account_items: Vec<(String, String, bool)> = accounts_list
        .read()
        .iter()
        .map(|key| {
            let display = decode_identity::<String>(key).unwrap_or_else(|_| key.clone());
            (key.clone(), display, *key == current_account)
        })
        .collect();

    rsx! {
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
                        {
                            let ts = Arc::clone(&token_store);
                            let cl = client.clone();
                            rsx! {
                                button {
                                    onclick: move |_| {
                                        let (ts, cl, key) = (Arc::clone(&ts), cl.clone(), acc_key.clone());
                                        spawn(async move {
                                            change_account(&cl, &ts, Some(&key), restart, wipe_state).await;
                                        });
                                    },
                                    "Switch"
                                }
                            }
                        }
                    }
                }
            }
            if *add_picking.read() {
                div {
                    style: "margin-top: 8px; background: #f5f5ff; \
                            border: 1px solid #c8c8e8; border-radius: 6px; \
                            padding: 10px 14px;",
                    p {
                        style: "margin: 0 0 8px 0; font-size: 0.9em;",
                        "The app will sign in again and open a browser login page. \
                         Come back after signing in to finish adding the account."
                    }
                    div {
                        style: "display: flex; gap: 6px; flex-wrap: wrap;",
                        button {
                            onclick: move |_| {
                                let (cl, ts) = (add_client.clone(), Arc::clone(&add_store));
                                spawn(async move {
                                    change_account(&cl, &ts, None, restart, wipe_state).await;
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
    }
}

/// The status line for one content event.
fn content_label(event: &ContentEvent) -> String {
    match event {
        ContentEvent::Uploaded { file_id } => format!("uploaded {}", short_hex(file_id.as_bytes())),
        ContentEvent::UploadDeferred { file_id, detail } => {
            format!("deferred {}: {detail}", short_hex(file_id.as_bytes()))
        }
        ContentEvent::UploadRefused { file_id, detail } => {
            format!("refused {}: {detail}", short_hex(file_id.as_bytes()))
        }
        ContentEvent::BytesLost {
            file_id,
            unreadable,
        } => format!(
            "bytes lost {} ({unreadable} unreadable chunks)",
            short_hex(file_id.as_bytes())
        ),
        ContentEvent::Fetched { file_id } => format!("fetched {}", short_hex(file_id.as_bytes())),
        ContentEvent::LostRequeued { file_id } => {
            format!("re-uploading lost {}", short_hex(file_id.as_bytes()))
        }
        ContentEvent::IntegrityPassFailed { detail } => format!("integrity check failed: {detail}"),
    }
}

/// What the content client reports, as a status line plus the refused uploads
/// and lost files it names. Both lists start from what the client persisted,
/// so a restart does not hide last run's.
struct ContentFeed {
    status: Signal<String>,
    refused: Signal<Vec<(FileId, String)>>,
    retired: Signal<Vec<FileId>>,
}

fn use_content_feed(content: &Content) -> ContentFeed {
    let mut status: Signal<String> = use_signal(String::new);
    let mut refused: Signal<Vec<(FileId, String)>> = use_signal(Vec::new);
    let mut retired: Signal<Vec<FileId>> = use_signal(Vec::new);
    let event_rx = content.events();
    use_hook(move || {
        spawn(async move {
            let mut rx = event_rx;
            while let Ok(event) = rx.recv().await {
                status.set(content_label(&event));
                match event {
                    ContentEvent::UploadRefused { file_id, detail } => {
                        refused.write().push((file_id, detail));
                    }
                    ContentEvent::BytesLost { file_id, .. } => retired.write().push(file_id),
                    _ => {}
                }
            }
        })
    });
    let cc = content.clone();
    use_hook(move || {
        spawn(async move {
            // The event stream is already live, so a fresh entry may arrive
            // before these queries return.
            for entry in cc.refused_content().await.unwrap_or_default() {
                let seen = refused.read().iter().any(|(id, _)| *id == entry.0);
                if !seen {
                    refused.write().push(entry);
                }
            }
            for id in cc.retired_content().await.unwrap_or_default() {
                let seen = retired.read().contains(&id);
                if !seen {
                    retired.write().push(id);
                }
            }
        });
    });
    ContentFeed {
        status,
        refused,
        retired,
    }
}

/// Display srcs for the listed photos. Local bytes become data URIs at every
/// state, since content this device staged answers as Local while unsent. A
/// signed URL is used only once the server says the row's content is available.
async fn photo_sources(content: &Content, photos: &[Photo]) -> HashMap<Uuid, String> {
    let mut srcs = HashMap::new();
    for photo in photos {
        let Some(fid) = photo_file_id(&photo.content_id) else {
            continue;
        };
        let available = photo.content_state.as_deref() == Some("available");
        match content.resolve(fid).await {
            Ok(Resolved::Local { bytes, .. }) => {
                let enc = base64::engine::general_purpose::STANDARD.encode(&bytes);
                srcs.insert(photo.id, format!("data:image/jpeg;base64,{enc}"));
            }
            Ok(Resolved::Remote { url }) if available => {
                srcs.insert(photo.id, url);
            }
            _ => {}
        }
    }
    srcs
}

/// Stage one picked file as a photo, answering with the line to show.
async fn stage_picked(content: &Content, name: &str, bytes: Result<Vec<u8>, String>) -> String {
    let Some(mime) = mime_from_extension(Path::new(name)) else {
        return "not an image: only .jpg .jpeg .png are accepted".to_owned();
    };
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(err) => return format!("could not read the file: {err}"),
    };
    match content.stage(bytes.as_slice(), mime, stage_photo_row).await {
        Ok(_) => format!("staged: {name}"),
        Err(err) => format!("stage failed: {err}"),
    }
}

#[component]
fn PhotosPanel() -> Element {
    let client = use_context::<ConnettoClient<Ws>>();
    let content = use_context::<Content>();
    let photos_query = use_live::<_, _, Photo>(&client, photos::table.order(photos::id.asc()));
    let feed = use_content_feed(&content);
    let content_status = feed.status;

    let mut photo_srcs: Signal<HashMap<Uuid, String>> = use_signal(HashMap::new);
    {
        let cc = content.clone();
        use_effect(move || {
            let photos = photos_query.value().read().clone();
            let cc = cc.clone();
            spawn(async move { photo_srcs.set(photo_sources(&cc, &photos).await) });
        });
    }

    let mut photo_pick_msg: Signal<Option<String>> = use_signal(|| None);
    let display_photos: Vec<Photo> = photos_query.value().read().iter().cloned().collect();
    let photos_error = photos_query.error().read().clone();
    let srcs_snap = photo_srcs.read().clone();
    let pick_content = content;

    rsx! {
        div {
            style: "border: 1px solid #ccc; border-radius: 6px; \
                    padding: 10px 14px; margin-bottom: 16px;",
            h2 {
                style: "margin-top: 0; font-size: 1em;",
                "Photos"
            }
            if !content_status.read().is_empty() {
                p {
                    style: "font-family: monospace; font-size: 0.85em; color: #555; margin: 0 0 8px 0;",
                    "content: " {content_status}
                }
            }

            // Pick and stage a photo: inserts an order row and a photo row together.
            label {
                "Pick and stage photo: "
                input {
                    r#type: "file",
                    accept: ".jpg,.jpeg,.png",
                    onchange: move |evt: FormEvent| {
                        let cc = pick_content.clone();
                        let files = evt.files();
                        spawn(async move {
                            let Some(file) = files.into_iter().next() else {
                                return;
                            };
                            let name = file.name();
                            let bytes = file
                                .read_bytes()
                                .await
                                .map(|b| b.to_vec())
                                .map_err(|err| err.to_string());
                            photo_pick_msg.set(Some(stage_picked(&cc, &name, bytes).await));
                        });
                    },
                }
            }
            if let Some(msg) = photo_pick_msg.read().clone() {
                p {
                    style: "font-family: monospace; font-size: 0.85em; \
                            color: #555; margin: 6px 0 0 0;",
                    {msg}
                }
            }

            if let Some(err) = photos_error {
                p { style: "color: #b00; margin-top: 8px;", "photos subscription error: {err}" }
            }

            if display_photos.is_empty() {
                p {
                    style: "color: #888; font-size: 0.9em; margin-top: 8px;",
                    "No photos yet."
                }
            } else {
                div {
                    style: "margin-top: 10px;",
                    for photo in display_photos {
                        PhotoCard { key: "{photo.id}", photo: photo.clone(), src: srcs_snap.get(&photo.id).cloned() }
                    }
                }
            }

            PinControls {}
            RefusedUploads { refused: feed.refused }
            LostBytes { retired: feed.retired }
        }
    }
}

#[component]
fn PhotoCard(photo: Photo, src: Option<String>) -> Element {
    let state_label = photo.content_state.as_deref().unwrap_or("pending upload");
    let pid = photo.id;
    rsx! {
        div {
            style: "border: 1px solid #e0e0e0; border-radius: 4px; \
                    padding: 8px; margin-bottom: 8px;",
            p {
                style: "margin: 0 0 4px 0; font-size: 0.85em; color: #555;",
                "id: {pid}  state: {state_label}"
            }
            if let Some(src) = src {
                img {
                    src,
                    style: "max-width: 200px; max-height: 200px; \
                            display: block; margin-top: 4px;",
                    alt: "photo"
                }
            }
        }
    }
}

/// Which content action a pin button runs.
#[derive(Clone, Copy)]
enum PinAction {
    Pin,
    Unpin,
    Fetch,
    Tidy,
}

impl PinAction {
    async fn run(self, content: &Content) -> String {
        match self {
            Self::Pin => content
                .pin_content("photos", "SELECT content_id FROM photos", "content_id")
                .await
                .map_or_else(
                    |err| format!("pin failed: {err}"),
                    |()| "pinned photos".to_owned(),
                ),
            Self::Unpin => content.unpin_content("photos").await.map_or_else(
                |err| format!("unpin failed: {err}"),
                |()| "unpinned photos".to_owned(),
            ),
            Self::Fetch => content.fetch_pinned().await.map_or_else(
                |err| format!("fetch failed: {err}"),
                |ids| format!("fetched {} pinned file(s)", ids.len()),
            ),
            Self::Tidy => content.tidy_content().await.map_or_else(
                |err| format!("tidy failed: {err}"),
                |n| format!("content tidy: {n} file(s) evicted"),
            ),
        }
    }
}

#[component]
fn PinControls() -> Element {
    let content = use_context::<Content>();
    let mut message: Signal<Option<String>> = use_signal(|| None);
    let buttons = [
        (PinAction::Pin, "Pin all photos"),
        (PinAction::Unpin, "Unpin photos"),
        (PinAction::Fetch, "Fetch pinned"),
        (PinAction::Tidy, "Free up content storage"),
    ];
    rsx! {
        div {
            style: "margin-top: 12px; display: flex; gap: 6px; flex-wrap: wrap;",
            for (action, label) in buttons {
                {
                    let cc = content.clone();
                    rsx! {
                        button {
                            key: "{label}",
                            onclick: move |_| {
                                let cc = cc.clone();
                                spawn(async move { message.set(Some(action.run(&cc).await)) });
                            },
                            {label}
                        }
                    }
                }
            }
        }
        if let Some(msg) = message.read().clone() {
            p {
                style: "font-family: monospace; font-size: 0.85em; \
                        color: #555; margin: 6px 0 0 0;",
                {msg}
            }
        }
    }
}

#[component]
fn RefusedUploads(refused: Signal<Vec<(FileId, String)>>) -> Element {
    let content = use_context::<Content>();
    let entries = refused.read().clone();
    if entries.is_empty() {
        return rsx! {};
    }
    rsx! {
        div {
            style: "margin-top: 10px; background: #fff3cd; \
                    border: 1px solid #f0ad4e; border-radius: 4px; padding: 8px;",
            p {
                style: "margin: 0 0 4px 0; font-weight: bold; font-size: 0.9em;",
                "Refused uploads"
            }
            for (fid, detail) in entries {
                {
                    let cc = content.clone();
                    rsx! {
                        div {
                            key: "{short_hex(fid.as_bytes())}",
                            style: "display: flex; align-items: center; gap: 8px; \
                                    margin-bottom: 4px; font-size: 0.85em;",
                            span {
                                style: "flex: 1; font-family: monospace;",
                                "{short_hex(fid.as_bytes())}: {detail}"
                            }
                            button {
                                onclick: move |_| {
                                    let cc = cc.clone();
                                    spawn(async move {
                                        match cc.retry_refused(fid).await {
                                            Ok(_) => refused.write().retain(|(id, _)| *id != fid),
                                            Err(err) => {
                                                tracing::error!(error = %err, "retry refused failed");
                                            }
                                        }
                                    });
                                },
                                "Retry"
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn LostBytes(retired: Signal<Vec<FileId>>) -> Element {
    let content = use_context::<Content>();
    let ids = retired.read().clone();
    if ids.is_empty() {
        return rsx! {};
    }
    let shown = ids.clone();
    rsx! {
        div {
            style: "margin-top: 10px; background: #fdecea; \
                    border: 1px solid #f5c6cb; border-radius: 4px; padding: 8px;",
            p {
                style: "margin: 0 0 4px 0; font-weight: bold; font-size: 0.9em;",
                "Bytes lost"
            }
            p {
                style: "font-size: 0.85em; margin: 0 0 6px 0; color: #666;",
                "These files' chunks are unreadable. Their row still exists. \
                 Acknowledge to clear the record."
            }
            for fid in shown {
                p {
                    style: "font-family: monospace; font-size: 0.85em; margin: 2px 0;",
                    "{short_hex(fid.as_bytes())}"
                }
            }
            button {
                onclick: move |_| {
                    let (ids, cc) = (ids.clone(), content.clone());
                    spawn(async move {
                        match cc.forget_retired_content(&ids).await {
                            Ok(_) => retired.write().retain(|id| !ids.contains(id)),
                            Err(err) => tracing::error!(error = %err, "forget retired failed"),
                        }
                    });
                },
                "Acknowledge all"
            }
        }
    }
}

#[component]
fn RetentionPanel(footprint: Signal<(i64, i64)>) -> Element {
    let client = use_context::<ConnettoClient<Ws>>();
    let (pages, free) = *footprint.read();
    let kb = pages * 4;
    rsx! {
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
                    let client = client.clone();
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
    }
}

/// Write this device's local data to the export file, answering with the line to show.
async fn export_everything(content: &Content) -> String {
    let (part, file) = match create_export_file() {
        Ok(opened) => opened,
        Err(err) => return format!("could not open the export file: {err}"),
    };
    let file = match content
        .export_local_data(connetto_client::ExportScope::Everything, file)
        .await
    {
        Ok(file) => file,
        Err(err) => return format!("export failed: {err}"),
    };
    let written = file.metadata().map(|meta| meta.len());
    drop(file);
    match (publish_export(&part), written) {
        (Ok(path), Ok(bytes)) => format!("Wrote {bytes} bytes to {}", path.display()),
        (Ok(path), Err(err)) => format!("wrote {} but could not measure it: {err}", path.display()),
        (Err(err), _) => format!("could not replace the last export: {err}"),
    }
}

#[component]
fn ExportPanel() -> Element {
    let content = use_context::<Content>();
    let mut status: Signal<Option<String>> = use_signal(|| None);
    rsx! {
        div {
            style: "border: 1px solid #ccc; border-radius: 6px; \
                    padding: 10px 14px; margin-top: 16px;",
            h2 {
                style: "margin-top: 0; font-size: 1em;",
                "Your data"
            }
            p {
                style: "color: #666; font-size: 0.9em;",
                "Save a zip archive of this device's local data, including any unsent \
                 photo bytes. The archive is not encrypted."
            }
            button {
                onclick: move |_| {
                    let cc = content.clone();
                    spawn(async move { status.set(Some(export_everything(&cc).await)) });
                },
                "Export local data"
            }
            if let Some(message) = status.read().clone() {
                p {
                    style: "font-family: monospace; font-size: 0.85em; \
                            color: #555; margin: 8px 0 0 0;",
                    {message}
                }
            }
        }
    }
}

/// Restore one archive, keeping the file's version of every clash, and answer
/// with the line to show.
async fn import_archive(content: &Content, bytes: Result<Vec<u8>, String>) -> String {
    let source = match bytes {
        Ok(bytes) => std::io::Cursor::new(bytes),
        Err(err) => return format!("could not read it: {err}"),
    };
    let mut plan = match content.prepare_local_data_import(source).await {
        Ok(plan) => plan,
        Err(err) => return format!("refused: {err}"),
    };
    let clash_count = plan.replica_plan().collisions().len();
    let choices = ImportChoices::keeping_the_file();
    let outcome = match content.apply_local_data_import(&mut plan, &choices).await {
        Ok(outcome) => outcome,
        Err(err) => return format!("apply failed: {err}"),
    };
    let mut msg = format!(
        "{} row(s) restored, {} kept, {} write(s) restored, {} content file(s)",
        outcome.rows_restored,
        outcome.rows_kept,
        outcome.writes_restored,
        plan.content_files(),
    );
    if clash_count > 0 {
        msg.push_str(&format!(" ({clash_count} clash(es) resolved to the file)"));
    }
    msg
}

#[component]
fn ImportPanel() -> Element {
    let content = use_context::<Content>();
    let mut status: Signal<Option<String>> = use_signal(|| None);
    rsx! {
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
            label {
                "Import from file: "
                input {
                    r#type: "file",
                    accept: ".zip",
                    onchange: move |evt: FormEvent| {
                        let cc = content.clone();
                        let files = evt.files();
                        spawn(async move {
                            let Some(file) = files.into_iter().next() else {
                                return;
                            };
                            let bytes = file
                                .read_bytes()
                                .await
                                .map(|b| b.to_vec())
                                .map_err(|err| err.to_string());
                            status.set(Some(import_archive(&cc, bytes).await));
                        });
                    },
                }
            }
            if let Some(message) = status.read().clone() {
                p {
                    style: "font-family: monospace; font-size: 0.85em; \
                            color: #555; margin: 8px 0 0 0;",
                    {message}
                }
            }
        }
    }
}
