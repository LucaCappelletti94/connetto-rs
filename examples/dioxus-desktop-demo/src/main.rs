//! Native demo of connetto live queries with native auth, on the desktop and,
//! built with `dx` for the `mobile` feature, on Android.
//!
//! The window opens first and setup runs as a task behind it. Setup acquires
//! a connetto session through RFC 8252's PKCE flow against `connetto-server`'s
//! auth endpoints, on a desktop in the system browser with a loopback
//! redirect and on a phone in a Custom Tab with the app's own redirect (or
//! silently refreshes if a refresh token is already stored), names the replica from the
//! resolved identity, opens it with an OS-keyring-held encryption key, and
//! starts a pump that redials and resumes whenever the link drops, all through
//! one `NativeClientBuilder` chain. Signing out calls the client's
//! `forget_device` (credential revoke plus key destroy) and runs setup again in
//! the same process, so a fresh login begins immediately.
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
//! The demo reads `CONNETTO_DEMO_WS`, the sync WebSocket URL (default
//! `ws://127.0.0.1:7777/sync`, and `wss://` for any host but loopback),
//! `CONNETTO_DEMO_AUTH_ORIGIN`, the auth server (default
//! `http://127.0.0.1:7777`), and `CONNETTO_DEMO_PG`, the conninfo the backend
//! writer buttons use (default `postgres://postgres:postgres@127.0.0.1:55456/postgres`).
//! A phone runs with no environment of its own, so a build for one can bake
//! each in as `CONNETTO_DEMO_BUILD_WS`, `CONNETTO_DEMO_BUILD_AUTH_ORIGIN` and
//! `CONNETTO_DEMO_BUILD_PG`, which the running environment still overrides. The
//! names differ from the runtime ones so that a shell pointed at a stack never
//! bakes its addresses into a build by accident.
//! Its server runs `schema.sql` and `policies.sql`, with `schema.sql`,
//! `connetto_file_server::DEPLOYMENT_DDL`, `connetto_server::epoch::EPOCH_DDL`,
//! `roles.sql` and `content.sql` applied in that order, and `orders,photos`
//! writable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use base64::Engine as _;
use connetto_client::teardown::{ForgetError, PurgeError, expiry_warning};
use connetto_client::{
    AccountChoice, Auth, ClientError, ClientEvent, ConnettoClient, Gate, ImportChoices,
    KeyringAuth, NativeClient, NativeClientBuilder, NativeTransport, SyncSchema, SyncTuning,
    decode_identity,
};
use connetto_core::messages::FatalErrorReason;
use connetto_dioxus::{use_away_input, use_live};
use connetto_dioxus_desktop_demo::{
    Order, Photo, mime_from_extension, orders, photo_file_id, photos, short_hex, stage_photo_row,
};
use connetto_file_client::{
    Content as ContentPiece, ContentClient, ContentEvent, ContentHandle, FileId, FsStore,
    ReqwestHttp, Resolved,
};
use diesel::prelude::*;
use dioxus::prelude::*;
use rosetta_uuid::Uuid;
use tokio::sync::mpsc;

include!(concat!(env!("OUT_DIR"), "/connetto-schema.rs"));

const DEFAULT_WS: &str = "ws://127.0.0.1:7777/sync";
const DEFAULT_AUTH_ORIGIN: &str = "http://127.0.0.1:7777";
const DEFAULT_PG: &str = "postgres://postgres:postgres@127.0.0.1:55456/postgres";
const AUTH_PROVIDER: &str = "dev-idp";
const KEYRING_SERVICE: &str = "connetto-dioxus-demo";
/// The login redirect on a phone, whose scheme is the app's bundle identifier
/// (`Dioxus.toml`), the scheme the bundled redirect activity claims on Android
/// and the authentication session catches on iOS.
#[cfg(any(target_os = "android", target_os = "ios"))]
const APP_REDIRECT: &str = "dev.connetto.dioxusdemo:/oauth2redirect";
/// How long the app may be away before it asks for Face ID, a fingerprint or
/// the device passcode again, where the platform gates the stored secrets.
const RECHECK_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// How long a login in the browser tab may take.
#[cfg(any(target_os = "android", target_os = "ios"))]
const LOGIN_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

// Declared for `dx`, which bundles `android/`, the module whose manifest turns
// off backup and device transfer. It stands in until Dioxus applies
// `[android.raw] application_attrs` and `[android] resources`, which dx 0.7.10
// parses and drops. Then both settings move into `Dioxus.toml` and this and
// `android/` are deleted.
#[cfg(target_os = "android")]
#[manganis::ffi("android")]
extern "Kotlin" {
    pub type ConnettoDemoBackupPolicy;
}

/// On a phone, sign in through the platform's in-app browser tab and the app's
/// own redirect (RFC 8252 section 7.1).
#[cfg(target_os = "ios")]
fn platform_sign_in(auth: KeyringAuth) -> KeyringAuth {
    auth.with_claimed_redirect(APP_REDIRECT, Arc::new(TabSession))
}

/// On Android, also unlock the Keystore-gated secrets through the platform's
/// biometric or device-credential prompt, which `connetto-auth-session` hosts.
#[cfg(target_os = "android")]
fn platform_sign_in(auth: KeyringAuth) -> KeyringAuth {
    auth.with_claimed_redirect(APP_REDIRECT, Arc::new(TabSession))
        .with_keystore_prompt(Arc::new(KeystoreUnlock))
}

/// How long the unlock prompt may stay up.
#[cfg(target_os = "android")]
const UNLOCK_WINDOW: std::time::Duration = std::time::Duration::from_secs(120);

/// The Keystore unlock prompt, through `connetto-auth-session`.
#[cfg(target_os = "android")]
struct KeystoreUnlock;

#[cfg(target_os = "android")]
impl connetto_client::KeystorePrompt for KeystoreUnlock {
    fn device_secure(&self) -> Result<bool, ClientError> {
        connetto_auth_session::device_secure().map_err(|err| ClientError::Auth(err.to_string()))
    }

    fn approve(&self, cipher: &manganis::jni::objects::GlobalRef) -> Result<bool, ClientError> {
        connetto_auth_session::approve_unlock(
            cipher.as_obj(),
            "Unlock your synced data",
            UNLOCK_WINDOW,
        )
        .map_err(|err| ClientError::Auth(err.to_string()))
    }
}

/// The Custom Tab on Android or the authentication session on iOS, and the
/// app's redirect, through `connetto-auth-session`.
#[cfg(any(target_os = "android", target_os = "ios"))]
struct TabSession;

#[cfg(any(target_os = "android", target_os = "ios"))]
impl connetto_client::AuthorizationSession for TabSession {
    fn authorize(&self, url: String) -> connetto_client::SessionFuture {
        Box::pin(async move {
            connetto_auth_session::authorize(&url, LOGIN_WINDOW)
                .await
                .map_err(|err| connetto_client::ClientError::Auth(err.to_string()))
        })
    }

    fn delivered(&self) -> Option<String> {
        connetto_auth_session::delivered().unwrap_or_else(|err| {
            tracing::warn!(error = %err, "reading a delivered login redirect");
            None
        })
    }
}

/// On a desktop, sign in through the system browser and a loopback listener
/// (RFC 8252 section 7.3), so the user's own browser serves the login with its
/// sessions and password manager.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn platform_sign_in(auth: KeyringAuth) -> KeyringAuth {
    auth
}

fn demo_quantity() -> i64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    i64::try_from(millis % 9).unwrap_or(0) * 5 + 5
}

type Ws = NativeTransport;
type Content = Arc<ContentClient<Ws, FsStore, ReqwestHttp>>;

enum DemoCmd {
    Insert,
    DeleteNewest,
}

#[derive(Clone)]
struct Backend(mpsc::UnboundedSender<DemoCmd>);

/// An endpoint as the running environment sets it, else as the build
/// environment did, else `default`.
fn endpoint(runtime: Option<String>, built: Option<&'static str>, default: &str) -> String {
    runtime
        .or_else(|| built.map(str::to_owned))
        .unwrap_or_else(|| default.to_owned())
}

fn data_dir() -> PathBuf {
    app_data_root().join("connetto-dioxus-demo")
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn app_data_root() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local").join("share")
    } else {
        std::env::temp_dir()
    }
}

/// The app's private data directory on a phone, since Android sets neither
/// `HOME` nor `XDG_DATA_HOME` and the iOS sandbox refuses `HOME/.local`. A
/// failed lookup is logged and leaves the temp directory, where the first
/// write then fails with an error setup reports.
#[cfg(any(target_os = "android", target_os = "ios"))]
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
/// session. The content outbox holds a client clone, so the client is closed
/// here, which ends the pump and the outbox with it.
struct Parts {
    native: NativeClient<Ws, ContentHandle<Ws>>,
    client: ConnettoClient<Ws>,
    backend: Backend,
    content: Content,
    runtime: tokio::runtime::Handle,
}

impl Drop for Parts {
    fn drop(&mut self) {
        let client = self.client.clone();
        self.runtime.spawn(async move { client.close().await });
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

/// Ends the current session and runs setup again, signing in as the account
/// the last request chose.
#[derive(Clone, Copy)]
struct Restart {
    generation: Signal<u64>,
    choice: Signal<AccountChoice>,
}

impl Restart {
    /// Start over as the account last used.
    fn request(self) {
        self.request_as(AccountChoice::LastUsed);
    }

    /// Start over as `choice`.
    fn request_as(mut self, choice: AccountChoice) {
        self.choice.set(choice);
        *self.generation.write() += 1;
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
    let choice = use_signal(|| AccountChoice::LastUsed);
    let restart = Restart { generation, choice };
    let mut stage = use_signal(|| Stage::Starting);
    use_context_provider(|| restart);
    let runtime = use_hook(tokio::runtime::Handle::current);
    // Windows Hello prompts over this window.
    #[cfg(target_os = "windows")]
    let owner = connetto_dioxus::use_hello_owner();
    // The browser holds the front after a login, so the window takes it back.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let window = dioxus::desktop::window();
    use_effect(move || {
        let _ = generation();
        let account = choice.peek().clone();
        stage.set(Stage::Starting);
        let runtime = runtime.clone();
        #[cfg(target_os = "windows")]
        let owner = Arc::clone(&owner);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let window = window.clone();
        spawn(async move {
            let outcome = runtime
                .spawn(setup(
                    account,
                    #[cfg(target_os = "windows")]
                    owner,
                ))
                .await;
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
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            window.set_focus();
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
                    p { "Check that the dev stack is up with CONNETTO_BIND, CONNETTO_AUTH, the JWT key files, CONNETTO_OIDC_PROVIDERS and the per-provider vars set, and on a phone that adb reverse forwards its ports." }
                    button { onclick: move |_| restart.request(), "Try again" }
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
    use_context_provider(|| parts.0.content.clone());
    use_context_provider(|| parts.clone());
    rsx! { App {} }
}

async fn setup(
    account: AccountChoice,
    #[cfg(target_os = "windows")] owner: Arc<dyn connetto_client::HelloOwner>,
) -> anyhow::Result<Parts> {
    use anyhow::Context as _;

    let server = endpoint(
        std::env::var("CONNETTO_DEMO_WS").ok(),
        option_env!("CONNETTO_DEMO_BUILD_WS"),
        DEFAULT_WS,
    );
    let pg_url = endpoint(
        std::env::var("CONNETTO_DEMO_PG").ok(),
        option_env!("CONNETTO_DEMO_BUILD_PG"),
        DEFAULT_PG,
    );
    let auth_origin = endpoint(
        std::env::var("CONNETTO_DEMO_AUTH_ORIGIN").ok(),
        option_env!("CONNETTO_DEMO_BUILD_AUTH_ORIGIN"),
        DEFAULT_AUTH_ORIGIN,
    );

    let sign_in = platform_sign_in(
        Auth::new(auth_origin, AUTH_PROVIDER)
            .with_account(account)
            .keyring(KEYRING_SERVICE),
    );
    #[cfg(target_os = "windows")]
    let sign_in = sign_in.with_hello_owner(owner);

    tokio::fs::create_dir_all(data_dir())
        .await
        .context("creating the application data directory")?;

    // A dropped link redials the same address and resumes, so writes made
    // while offline upload once the server is reachable again.
    let (native, pump) =
        NativeClientBuilder::new(server, SyncSchema::new(connetto_schema_bundle::bundle()))
            .with_tuning(SyncTuning::default().with_trim_threshold(5))
            .with_content(ContentPiece::new().with_heal_lost(
                "SELECT content_id FROM photos WHERE content_state = 'lost'",
                "content_id",
            ))
            .signed_in(sign_in)
            .durable(data_dir())
            .with_gate(Gate::default().with_recheck(Some(RECHECK_AFTER)))
            .connect_with_pump()
            .await
            .map_err(|err| match err {
                ClientError::Auth(_) => anyhow::anyhow!(
                    "the server refused the credential; check CONNETTO_AUTH and OIDC settings"
                ),
                other => anyhow::anyhow!("opening the encrypted replica: {other}"),
            })?;
    tokio::spawn(pump);
    let client = native.client().clone();
    let content = match native.content() {
        Some(ContentHandle::Durable(content)) => Arc::clone(content),
        _ => anyhow::bail!("a durable build keeps its files beside the replica"),
    };

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

    Ok(Parts {
        native,
        client,
        backend: Backend(tx),
        content,
        runtime: tokio::runtime::Handle::current(),
    })
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
        .unwrap_or((0, 0))
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
    use_away_input(&client);
    let backend = use_context::<Backend>();
    let parts = use_context::<SessionParts>();

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

    // Client event status line, and the gate's own line with whether it
    // holds the app locked.
    let mut status: Signal<String> = use_signal(|| "connected".to_owned());
    let mut gate: Signal<&'static str> = use_signal(|| "open");
    let event_rx = client.events();
    use_hook(move || {
        spawn(async move {
            let mut rx = event_rx;
            while let Ok(event) = rx.recv().await {
                match event {
                    ClientEvent::Locked => gate.set("locked, verify it is you to continue"),
                    ClientEvent::UnlockDismissed => gate.set("unlock dismissed, still locked"),
                    ClientEvent::Unlocked => gate.set("open"),
                    _ => {}
                }
                if let Some(label) = status_label(&event) {
                    status.set(label);
                }
            }
        })
    });
    let custody = parts.0.native.custody();
    let unlock_client = client.clone();

    // Session expiry warning and replica footprint, both refreshed as rows change.
    let mut expiry_warn: Signal<Option<String>> = use_signal(|| None);
    let mut footprint: Signal<(i64, i64)> = use_signal(|| (0_i64, 0_i64));
    {
        let client = client.clone();
        let session_expires_at = parts.0.native.session().map(|session| session.expires_at());
        use_effect(move || {
            let _ = rows.value().read().len();
            let client = client.clone();
            spawn(async move {
                expiry_warn.set(match session_expires_at {
                    Some(deadline) => expiry_text(&client, deadline).await,
                    None => None,
                });
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
            p {
                style: "font-family: monospace; font-size: 0.85em; color: #555; margin: 0 0 8px 0;",
                "custody: " {custody.to_string()}
            }
            p {
                style: "font-family: monospace; font-size: 0.85em; color: #555; margin: 0 0 8px 0;",
                "gate: " {gate}
            }
            if gate() != "open" {
                button {
                    onclick: move |_| {
                        let client = unlock_client.clone();
                        spawn(async move { client.unlock().await });
                    },
                    "Unlock"
                }
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
                                .await
                                .and_then(|insert| insert.map_err(Into::into));
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
    let unsynced = client.unsynced().await.unwrap_or_default();
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
    parts: &SessionParts,
    discard_unsynced: bool,
    restart: Restart,
    mut wipe_state: Signal<WipeState>,
) {
    match parts.0.native.forget_device(discard_unsynced).await {
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
    let parts = use_context::<SessionParts>();
    let replica_label = parts
        .0
        .native
        .session()
        .map_or_else(String::new, |session| session.user_id().to_owned());
    let (wipe_parts, force_parts) = (parts.clone(), parts);

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
                "Signed in as: {replica_label}"
            }
            {match wipe_state.read().clone() {
                WipeState::Idle => rsx! {
                    button {
                        onclick: move |_| {
                            let parts = wipe_parts.clone();
                            spawn(async move { sign_out(&parts, false, restart, wipe_state).await });
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
                                    let parts = force_parts.clone();
                                    spawn(async move { sign_out(&parts, true, restart, wipe_state).await });
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

/// Start over as another account, or as a new one, refused while local
/// writes are unsent.
async fn change_account(
    client: &ConnettoClient<Ws>,
    choice: AccountChoice,
    restart: Restart,
    mut wipe_state: Signal<WipeState>,
) {
    let unsynced = match client.unsynced().await {
        Ok(unsynced) => unsynced,
        Err(err) => {
            wipe_state.set(WipeState::Error(format!("Cannot change account: {err}")));
            return;
        }
    };
    if !unsynced.is_empty() {
        wipe_state.set(WipeState::Error(format!(
            "Cannot change account: {} write(s) not yet synced.",
            unsynced.len()
        )));
        return;
    }
    restart.request_as(choice);
}

#[component]
fn AccountsPanel(wipe_state: Signal<WipeState>) -> Element {
    let restart = use_context::<Restart>();
    let client = use_context::<ConnettoClient<Ws>>();
    let parts = use_context::<SessionParts>();
    let mut add_picking: Signal<bool> = use_signal(|| false);
    let session = parts.0.native.session();
    let accounts_list = use_signal(|| {
        session
            .map(|session| session.accounts().to_vec())
            .unwrap_or_default()
    });
    let current_account = session.map_or_else(String::new, |session| session.account().to_owned());
    let add_client = client.clone();

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
                            let cl = client.clone();
                            rsx! {
                                button {
                                    onclick: move |_| {
                                        let (cl, key) = (cl.clone(), acc_key.clone());
                                        spawn(async move {
                                            change_account(&cl, AccountChoice::Account(key), restart, wipe_state).await;
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
                                let cl = add_client.clone();
                                spawn(async move {
                                    change_account(&cl, AccountChoice::New, restart, wipe_state).await;
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

#[cfg(test)]
mod tests {
    use super::endpoint;

    /// The running environment wins, so a desktop build made with the
    /// variables set still follows what it is launched with, and a phone
    /// build falls back to what it was built with.
    #[test]
    fn a_runtime_endpoint_wins_over_the_built_one_and_both_over_the_default() {
        assert_eq!(
            endpoint(Some("run:1".to_owned()), Some("built:2"), "def:3"),
            "run:1"
        );
        assert_eq!(endpoint(None, Some("built:2"), "def:3"), "built:2");
        assert_eq!(endpoint(None, None, "def:3"), "def:3");
    }
}
