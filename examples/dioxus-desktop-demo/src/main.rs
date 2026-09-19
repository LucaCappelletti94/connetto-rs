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
//! - `CONNETTO_CONTENT_URL`, `CONNETTO_CONTENT_STORE`, `CONNETTO_CONTENT_KEY`:
//!   file server settings; required for photo upload and signed-URL resolve.
//!   The server must also list `photos` in `CONNETTO_WRITABLE`. Apply schema.sql,
//!   `connetto_file_server::DEPLOYMENT_DDL`, roles.sql, content.sql in that order.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use connetto_client::auth::{
    KeyringKeyStore, KeyringStore, NativeAuthenticator, provision_replica_key, remembered_account,
};
use connetto_client::reconnect::TokioSleeper;
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
/// (`CONNETTO_PG_DDL`). Its SHA-256 is the schema version presented at the
/// handshake.
const SCHEMA_SQL: &str = include_str!("../schema.sql");

const AUTH_SERVER: &str = "http://127.0.0.1:18081";
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
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local").join("share")
    } else {
        std::env::temp_dir()
    }
    .join("connetto-dioxus-demo")
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

fn restart() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe).spawn();
    }
    std::process::exit(0)
}

fn main() {
    connetto_core::logging::init_stdout();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let started = rt.block_on(setup());
    let (client, backend, auth_ctx, content) = match started {
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
                    .with_inner_size(dioxus::desktop::LogicalSize::new(760.0, 1100.0)),
            ),
        )
        .with_context(client)
        .with_context(backend)
        .with_context(auth_ctx)
        .with_context(content)
        .launch(app);
}

fn launch_startup_failure(err: &anyhow::Error) {
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

async fn setup() -> anyhow::Result<(ConnettoClient<Ws>, Backend, AuthCtx, Content)> {
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

    let client = ConnettoClient::start(conn);

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
        .map_err(|err| anyhow::anyhow!("attaching content client: {err}"))?,
    );
    let cc_drive = Arc::clone(&content);
    tokio::spawn(async move { cc_drive.drive_outbox(TokioSleeper).await });

    Ok((client, Backend(tx), auth_ctx, content))
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
        AUTH_SERVER,
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
        .with_schema_version(Some(connetto_core::SchemaVersion::from_source(SCHEMA_SQL)))
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
        _ => None,
    }
}

#[derive(Clone, PartialEq)]
enum WipeState {
    Idle,
    ConfirmForce { unsynced_count: usize },
    Error(String),
}

fn app() -> Element {
    let client = use_context::<ConnettoClient<Ws>>();
    let backend = use_context::<Backend>();
    let auth_ctx = use_context::<AuthCtx>();
    let content = use_context::<Content>();

    // Live queries.
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
    let photos_query = use_live::<_, _, Photo>(&client, photos::table.order(photos::id.asc()));

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

    // Content event stream: track uploads, losses, and refusals.
    let mut content_status: Signal<String> = use_signal(String::new);
    let mut retired_files: Signal<Vec<FileId>> = use_signal(Vec::new);
    let mut refused_uploads: Signal<Vec<(FileId, String)>> = use_signal(Vec::new);
    let content_event_rx = content.events();
    use_hook(move || {
        spawn(async move {
            let mut rx = content_event_rx;
            while let Ok(event) = rx.recv().await {
                match event {
                    ContentEvent::Uploaded { file_id } => {
                        content_status.set(format!("uploaded {}", short_hex(file_id.as_bytes())));
                    }
                    ContentEvent::UploadDeferred { file_id, detail } => {
                        content_status.set(format!(
                            "deferred {}: {detail}",
                            short_hex(file_id.as_bytes())
                        ));
                    }
                    ContentEvent::UploadRefused { file_id, detail } => {
                        content_status.set(format!(
                            "refused {}: {detail}",
                            short_hex(file_id.as_bytes())
                        ));
                        refused_uploads.write().push((file_id, detail));
                    }
                    ContentEvent::BytesLost {
                        file_id,
                        unreadable,
                    } => {
                        content_status.set(format!(
                            "bytes lost {} ({unreadable} unreadable chunks)",
                            short_hex(file_id.as_bytes())
                        ));
                        retired_files.write().push(file_id);
                    }
                    ContentEvent::Fetched { file_id } => {
                        content_status.set(format!("fetched {}", short_hex(file_id.as_bytes())));
                    }
                    ContentEvent::IntegrityPassFailed { detail } => {
                        content_status.set(format!("integrity check failed: {detail}"));
                    }
                }
            }
        })
    });

    // Seed the failure lists from what the content client already persists,
    // so a restart does not hide last run's refusals and lost files.
    {
        let cc = content.clone();
        let mut refused_seed = refused_uploads;
        let mut retired_seed = retired_files;
        use_hook(move || {
            spawn(async move {
                if let Ok(list) = cc.refused_content().await {
                    for entry in list {
                        // The event stream is already live, so a fresh
                        // refusal may arrive before this query returns.
                        let seen = refused_seed.read().iter().any(|(id, _)| *id == entry.0);
                        if !seen {
                            refused_seed.write().push(entry);
                        }
                    }
                }
                if let Ok(list) = cc.retired_content().await {
                    for id in list {
                        let seen = retired_seed.read().contains(&id);
                        if !seen {
                            retired_seed.write().push(id);
                        }
                    }
                }
            });
        });
    }

    // Session expiry warning.
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
                    0,
                ) {
                    let remaining = w
                        .session_expires_at
                        .duration_since(std::time::SystemTime::now())
                        .unwrap_or_default();
                    let days = remaining.as_secs() / 86400;
                    expiry_warn.set(Some(format!(
                        "Session expires in {days} day(s): {} pending local item(s) at risk. \
                         Stay connected to extend the deadline automatically.",
                        w.pending_count()
                    )));
                } else {
                    expiry_warn.set(None);
                }
            });
        });
    }

    // Replica page footprint.
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

    // Resolve display srcs for available photos: local bytes become data: URIs,
    // remote signed URLs go straight to the webview.
    let mut photo_srcs: Signal<HashMap<Uuid, String>> = use_signal(HashMap::new);
    {
        let cc = content.clone();
        use_effect(move || {
            let photos = photos_query.value().read().clone();
            let cc = cc.clone();
            spawn(async move {
                let mut srcs = HashMap::new();
                for photo in &photos {
                    let available = photo.content_state.as_deref() == Some("available");
                    let Some(fid) = photo_file_id(&photo.content_id) else {
                        continue;
                    };
                    match cc.resolve(fid).await {
                        // Local bytes render at every state: content this
                        // device staged answers as Local while it is still
                        // unsent, so a freshly picked photo shows immediately.
                        Ok(Resolved::Local { bytes, .. }) => {
                            let enc = base64::engine::general_purpose::STANDARD.encode(&bytes);
                            srcs.insert(photo.id, format!("data:image/jpeg;base64,{enc}"));
                        }
                        // A signed URL is trustworthy only once the server
                        // says the content is available for this row.
                        Ok(Resolved::Remote { url }) if available => {
                            srcs.insert(photo.id, url);
                        }
                        _ => {}
                    }
                }
                photo_srcs.set(srcs);
            });
        });
    }

    let mut wipe_state: Signal<WipeState> = use_signal(|| WipeState::Idle);
    let mut add_picking: Signal<bool> = use_signal(|| false);
    let mut export_status: Signal<Option<String>> = use_signal(|| None);
    let mut import_status: Signal<Option<String>> = use_signal(|| None);
    let mut photo_pick_msg: Signal<Option<String>> = use_signal(|| None);
    let mut photo_pin_msg: Signal<Option<String>> = use_signal(|| None);

    let accounts_list = use_signal(|| auth_ctx.token_store.accounts().unwrap_or_default());
    let current_account = auth_ctx.current_account.clone();
    let token_store = Arc::clone(&auth_ctx.token_store);

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
    let mut grouped_counts: Vec<(i64, i64)> = counts_by_quantity
        .value()
        .read()
        .iter()
        .map(|(quantity, count)| (*quantity, *count))
        .collect();
    grouped_counts.sort_unstable();
    let grouped_text = if grouped_counts.is_empty() {
        "pending".to_owned()
    } else {
        grouped_counts
            .iter()
            .map(|(quantity, count)| format!("{quantity}: {count}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let grouped_error = counts_by_quantity.error().read().clone();

    let display_photos: Vec<Photo> = photos_query.value().read().iter().cloned().collect();
    let photos_error = photos_query.error().read().clone();
    let srcs_snap = photo_srcs.read().clone();
    let retired_snap = retired_files.read().clone();
    let refused_snap = refused_uploads.read().clone();

    let (pages, free) = *footprint.read();
    let kb = pages * 4;
    let pid = std::process::id();
    let replica_label = auth_ctx.key_name.clone();

    let insert_backend = backend.clone();
    let delete_backend = backend;
    let write_client = client.clone();
    let tidy_client = client.clone();
    let wipe_client = client.clone();
    let force_client = client.clone();
    let switch_client = client.clone();
    let add_client = client.clone();
    let export_content = content.clone();
    let import_content = content.clone();
    let pick_content = content.clone();
    let pin_content = content.clone();
    let tidy_content_handle = content.clone();
    let fetch_content = content.clone();
    let unpin_content = content.clone();
    let retry_content = content.clone();
    let forget_content = content.clone();

    let auth_data = (
        Arc::clone(&auth_ctx.authenticator),
        auth_ctx.db_path.clone(),
        Arc::clone(&auth_ctx.key_store),
        auth_ctx.key_name.clone(),
    );
    let auth_data_force = auth_data.clone();

    let token_store_add = Arc::clone(&token_store);

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

            // Photos panel: pick, stage, list, display.
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

                // Pick and stage a photo; inserts an order row and a photo row together.
                button {
                    onclick: move |_| {
                        let cc = pick_content.clone();
                        spawn(async move {
                            let Some(file) = rfd::AsyncFileDialog::new()
                                .add_filter("images", &["jpg", "jpeg", "png"])
                                .pick_file()
                                .await
                            else {
                                return;
                            };
                            let path = file.path().to_owned();
                            let Some(mime) = mime_from_extension(&path) else {
                                photo_pick_msg.set(Some(
                                    "not an image: only .jpg .jpeg .png are accepted".to_owned(),
                                ));
                                return;
                            };
                            let bytes = match tokio::fs::read(&path).await {
                                Ok(b) => b,
                                Err(err) => {
                                    photo_pick_msg
                                        .set(Some(format!("could not read the file: {err}")));
                                    return;
                                }
                            };
                            let name = path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("photo")
                                .to_owned();
                            match cc
                                .stage(bytes.as_slice(), mime, stage_photo_row)
                                .await
                            {
                                Ok(_) => {
                                    photo_pick_msg.set(Some(format!("staged: {name}")));
                                }
                                Err(err) => {
                                    photo_pick_msg
                                        .set(Some(format!("stage failed: {err}")));
                                }
                            }
                        });
                    },
                    "Pick and stage photo"
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

                // Live list of photos with content_state and display.
                if display_photos.is_empty() {
                    p {
                        style: "color: #888; font-size: 0.9em; margin-top: 8px;",
                        "No photos yet."
                    }
                } else {
                    div {
                        style: "margin-top: 10px;",
                        for photo in display_photos {
                            {
                                let state_label = match photo.content_state.as_deref() {
                                    Some("available") => "available",
                                    Some(s) => s,
                                    None => "pending upload",
                                };
                                let src = srcs_snap.get(&photo.id).cloned();
                                let pid = photo.id;
                                rsx! {
                                    div {
                                        key: "{pid}",
                                        style: "border: 1px solid #e0e0e0; border-radius: 4px; \
                                                padding: 8px; margin-bottom: 8px;",
                                        p {
                                            style: "margin: 0 0 4px 0; font-size: 0.85em; color: #555;",
                                            "id: {pid}  state: {state_label}"
                                        }
                                        if let Some(src) = src {
                                            img {
                                                src: {src},
                                                style: "max-width: 200px; max-height: 200px; \
                                                        display: block; margin-top: 4px;",
                                                alt: "photo"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Content pins: pin all photos, fetch pinned bytes, unpin.
                div {
                    style: "margin-top: 12px; display: flex; gap: 6px; flex-wrap: wrap;",
                    button {
                        onclick: move |_| {
                            let cc = pin_content.clone();
                            spawn(async move {
                                match cc
                                    .pin_content(
                                        "photos",
                                        "SELECT content_id FROM photos",
                                        "content_id",
                                    )
                                    .await
                                {
                                    Ok(()) => photo_pin_msg.set(Some("pinned photos".to_owned())),
                                    Err(err) => photo_pin_msg
                                        .set(Some(format!("pin failed: {err}"))),
                                }
                            });
                        },
                        "Pin all photos"
                    }
                    button {
                        onclick: move |_| {
                            let cc = unpin_content.clone();
                            spawn(async move {
                                match cc.unpin_content("photos").await {
                                    Ok(()) => {
                                        photo_pin_msg.set(Some("unpinned photos".to_owned()));
                                    }
                                    Err(err) => photo_pin_msg
                                        .set(Some(format!("unpin failed: {err}"))),
                                }
                            });
                        },
                        "Unpin photos"
                    }
                    button {
                        onclick: move |_| {
                            let cc = fetch_content.clone();
                            spawn(async move {
                                match cc.fetch_pinned().await {
                                    Ok(ids) => photo_pin_msg.set(Some(format!(
                                        "fetched {} pinned file(s)",
                                        ids.len()
                                    ))),
                                    Err(err) => photo_pin_msg
                                        .set(Some(format!("fetch failed: {err}"))),
                                }
                            });
                        },
                        "Fetch pinned"
                    }
                    button {
                        onclick: move |_| {
                            let cc = tidy_content_handle.clone();
                            spawn(async move {
                                match cc.tidy_content().await {
                                    Ok(n) => photo_pin_msg.set(Some(format!(
                                        "content tidy: {n} file(s) evicted"
                                    ))),
                                    Err(err) => photo_pin_msg
                                        .set(Some(format!("tidy failed: {err}"))),
                                }
                            });
                        },
                        "Free up content storage"
                    }
                }
                if let Some(msg) = photo_pin_msg.read().clone() {
                    p {
                        style: "font-family: monospace; font-size: 0.85em; \
                                color: #555; margin: 6px 0 0 0;",
                        {msg}
                    }
                }

                // Refused uploads: show detail and offer retry.
                if !refused_snap.is_empty() {
                    div {
                        style: "margin-top: 10px; background: #fff3cd; \
                                border: 1px solid #f0ad4e; border-radius: 4px; padding: 8px;",
                        p {
                            style: "margin: 0 0 4px 0; font-weight: bold; font-size: 0.9em;",
                            "Refused uploads"
                        }
                        for (fid, detail) in refused_snap {
                            {
                                let fid_clone = fid;
                                let cc = retry_content.clone();
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
                                                    if let Err(err) =
                                                        cc.retry_refused(fid_clone).await
                                                    {
                                                        tracing::error!(
                                                            error = %err,
                                                            "retry refused failed"
                                                        );
                                                    } else {
                                                        refused_uploads
                                                            .write()
                                                            .retain(|(id, _)| *id != fid_clone);
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

                // BytesLost: show lost file IDs and offer acknowledgement.
                if !retired_snap.is_empty() {
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
                        for fid in &retired_snap {
                            p {
                                style: "font-family: monospace; font-size: 0.85em; margin: 2px 0;",
                                "{short_hex(fid.as_bytes())}"
                            }
                        }
                        button {
                            onclick: move |_| {
                                let ids = retired_snap.clone();
                                let cc = forget_content.clone();
                                spawn(async move {
                                    if let Err(err) = cc.forget_retired_content(&ids).await {
                                        tracing::error!(
                                            error = %err,
                                            "forget retired failed"
                                        );
                                    } else {
                                        retired_files.write().retain(|id| !ids.contains(id));
                                    }
                                });
                            },
                            "Acknowledge all"
                        }
                    }
                }
            }

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
                        let cc = export_content.clone();
                        spawn(async move {
                            let message = match create_export_file() {
                                Err(err) => format!("could not open the export file: {err}"),
                                Ok((part, file)) => match cc.export_local_data(
                                    connetto_client::ExportScope::Everything,
                                    file,
                                )
                                .await
                                {
                                    Ok(file) => {
                                        let written = file.metadata().map(|meta| meta.len());
                                        drop(file);
                                        match (publish_export(&part), written) {
                                            (Ok(path), Ok(bytes)) => {
                                                format!(
                                                    "Wrote {bytes} bytes to {}",
                                                    path.display()
                                                )
                                            }
                                            (Ok(path), Err(err)) => format!(
                                                "wrote {} but could not measure it: {err}",
                                                path.display()
                                            ),
                                            (Err(err), _) => {
                                                format!(
                                                    "could not replace the last export: {err}"
                                                )
                                            }
                                        }
                                    }
                                    Err(err) => format!("export failed: {err}"),
                                },
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
                        let cc = import_content.clone();
                        spawn(async move {
                            let Some(file) = rfd::AsyncFileDialog::new()
                                .add_filter("archive", &["zip"])
                                .pick_file()
                                .await
                            else {
                                return;
                            };
                            let source = match std::fs::File::open(file.path()) {
                                Ok(source) => source,
                                Err(err) => {
                                    import_status
                                        .set(Some(format!("could not open it: {err}")));
                                    return;
                                }
                            };
                            let message = match cc.prepare_local_data_import(source).await {
                                Err(err) => format!("refused: {err}"),
                                Ok(mut plan) => {
                                    let clash_count =
                                        plan.replica_plan().collisions().len();
                                    let choices = ImportChoices::keeping_the_file();
                                    match cc
                                        .apply_local_data_import(&mut plan, &choices)
                                        .await
                                    {
                                        Ok(outcome) => {
                                            let mut msg = format!(
                                                "{} row(s) restored, {} kept, \
                                                 {} write(s) restored, {} content file(s)",
                                                outcome.rows_restored,
                                                outcome.rows_kept,
                                                outcome.writes_restored,
                                                plan.content_files(),
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
