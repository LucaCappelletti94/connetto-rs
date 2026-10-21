//! The connetto demo as a Tauri 2 app.
//!
//! The client lives here, in the native core, which keeps running while the
//! platform pauses the WebView. The core turns the client's state into one
//! `View` and emits it to the Leptos UI on every change, and the UI calls
//! back through the commands below. The platform lifecycle drives the
//! client's away input directly, with no UI engine in between.

use std::path::PathBuf;
use std::sync::{Arc, Weak};

use connetto_client::teardown::{ForgetError, PurgeError};
use connetto_client::{
    Auth, ClientError, ClientEvent, ConnettoClient, Gate, KeyringAuth, LiveHandle as _, Moment,
    NativeClient, NativeClientBuilder, NativeTransport, SyncSchema, SyncTuning, SystemClock,
    dsl::Watchable as _,
};
use connetto_core::messages::FatalErrorReason;
use diesel::prelude::*;
use parking_lot::Mutex;
use serde::Serialize;
use tauri::{AppHandle, Emitter as _, Manager as _, RunEvent, WindowEvent};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

include!(concat!(env!("OUT_DIR"), "/connetto-schema.rs"));

diesel::table! {
    orders (id) {
        id -> rosetta_uuid::sql_types::Uuid,
        owner_id -> diesel::sql_types::Text,
        quantity -> diesel::sql_types::BigInt,
        created_at -> diesel::sql_types::Timestamp,
    }
}

const DEFAULT_WS: &str = "ws://127.0.0.1:7777/sync";
const DEFAULT_AUTH_ORIGIN: &str = "http://127.0.0.1:7777";
const DEFAULT_PG: &str = "postgres://postgres:postgres@127.0.0.1:55456/postgres";
const AUTH_PROVIDER: &str = "dev-idp";
const KEYRING_SERVICE: &str = "connetto-tauri-demo";
/// The login redirect, whose scheme is the Android applicationId and the
/// iOS bundle identifier.
#[cfg(any(target_os = "android", target_os = "ios"))]
const APP_REDIRECT: &str = "dev.connetto.tauridemo:/oauth2redirect";
/// The demo's re-check grace, matching the dioxus demo's.
const RECHECK_AFTER: std::time::Duration = std::time::Duration::from_secs(30);
const LOG_FILTER: &str = "info,connetto_client::away=debug,connetto_tauri_demo::away=debug";

#[cfg(feature = "device-identity")]
const DEVICE_ROOT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/device-root.der"));

type Ws = NativeTransport;

/// Everything the UI shows, emitted whole as the `view` event.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct View {
    /// `starting`, `ready` or `failed`.
    stage: &'static str,
    /// Why setup failed, when it did.
    detail: Option<String>,
    /// The signed-in user id, as the server minted it.
    user: String,
    status: String,
    custody: String,
    gate: &'static str,
    device: String,
    /// `COUNT(*)` over the replica's orders, pushed by the server.
    count: Option<i64>,
    /// A live query or write that failed.
    error: Option<String>,
    wipe: Wipe,
}

impl Default for View {
    fn default() -> Self {
        Self {
            stage: "starting",
            detail: None,
            user: String::new(),
            status: "connected".to_owned(),
            custody: String::new(),
            gate: "open",
            device: String::new(),
            count: None,
            error: None,
            wipe: Wipe::Idle,
        }
    }
}

/// Where signing out stands.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Wipe {
    Idle,
    /// The replica holds writes the server has not acknowledged, which only
    /// a confirmed sign-out discards.
    ConfirmForce {
        unsynced: usize,
    },
    Failed {
        message: String,
    },
}

enum BackendCmd {
    Insert,
}

/// One signed-in session. Dropping it aborts the tasks feeding the view.
struct Session {
    native: NativeClient<Ws>,
    backend: mpsc::UnboundedSender<BackendCmd>,
    _tasks: JoinSet<()>,
}

/// Where the core's session stands, as `plans/tauri-leptos-demos.md` tables it.
/// Starting and failed setups both hold no session and serve the same inputs.
#[derive(Default)]
enum Slot {
    #[default]
    Empty,
    Ready(Arc<Session>),
    /// `forget_device` runs on the session, which only the lifecycle reaches.
    SigningOut(Arc<Session>),
}

/// The core's state, managed by Tauri.
#[derive(Default)]
struct Core {
    view: Mutex<View>,
    slot: Mutex<Slot>,
}

impl Core {
    /// Change the view and emit it when it changed. The emission happens under
    /// the view lock, so two tasks' views reach the UI in the order they changed.
    fn update(&self, app: &AppHandle, change: impl FnOnce(&mut View)) {
        let mut view = self.view.lock();
        let before = view.clone();
        change(&mut view);
        if *view != before {
            emit_view(app, &view);
        }
    }

    /// The session, while it is ready to serve commands.
    fn session(&self) -> Option<Arc<Session>> {
        match &*self.slot.lock() {
            Slot::Ready(session) => Some(Arc::clone(session)),
            Slot::Empty | Slot::SigningOut(_) => None,
        }
    }

    fn client(&self) -> Option<ConnettoClient<Ws>> {
        self.session()
            .map(|session| session.native.client().clone())
    }

    /// The client the lifecycle reaches, which a sign-out still in progress keeps.
    fn lifecycle_client(&self) -> Option<ConnettoClient<Ws>> {
        match &*self.slot.lock() {
            Slot::Ready(session) | Slot::SigningOut(session) => {
                Some(session.native.client().clone())
            }
            Slot::Empty => None,
        }
    }

    /// Move a ready session to signing out and hand it over, or `None` when
    /// no session is ready, a sign-out already in progress included.
    fn begin_sign_out(&self) -> Option<Arc<Session>> {
        let mut slot = self.slot.lock();
        let Slot::Ready(session) = &*slot else {
            return None;
        };
        let session = Arc::clone(session);
        *slot = Slot::SigningOut(Arc::clone(&session));
        Some(session)
    }
}

fn emit_view(app: &AppHandle, view: &View) {
    if let Err(err) = app.emit("view", view) {
        tracing::warn!(error = %err, "emitting the view");
    }
}

/// Why a command failed, as the UI is told.
#[derive(Debug, thiserror::Error)]
enum CommandError {
    #[error("the session is not ready yet")]
    NotReady,
    #[error("the backend writer stopped")]
    BackendGone,
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Query(#[from] diesel::result::Error),
}

impl Serialize for CommandError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// Emit the current view through the event every change takes, since a
/// returned value travels apart from events and could land after a newer one.
#[tauri::command]
fn view(app: AppHandle, core: tauri::State<'_, Arc<Core>>) {
    emit_view(&app, &core.view.lock());
}

#[tauri::command]
fn insert_backend(core: tauri::State<'_, Arc<Core>>) -> Result<(), CommandError> {
    let session = core.session().ok_or(CommandError::NotReady)?;
    session
        .backend
        .send(BackendCmd::Insert)
        .map_err(|_| CommandError::BackendGone)
}

#[tauri::command]
async fn insert_local(core: tauri::State<'_, Arc<Core>>) -> Result<(), CommandError> {
    let session = core.session().ok_or(CommandError::NotReady)?;
    let client = session.native.client().clone();
    // The deployment policy names the owner on the row, and created_at must
    // ride the changeset, since a replica default leaves it NULL.
    let user = session
        .native
        .session()
        .map_or_else(String::new, |session| session.user_id().to_owned());
    let quantity = demo_quantity();
    client
        .with_conn(move |conn| {
            diesel::insert_into(orders::table)
                .values((
                    orders::owner_id.eq(user),
                    orders::quantity.eq(quantity),
                    orders::created_at.eq(chrono::Utc::now().to_rfc3339()),
                ))
                .execute(conn.conn())
        })
        .await??;
    Ok(())
}

#[tauri::command]
async fn unlock(core: tauri::State<'_, Arc<Core>>) -> Result<(), CommandError> {
    let client = core.client().ok_or(CommandError::NotReady)?;
    client.unlock().await;
    Ok(())
}

/// Revoke the session, wipe the replica and sign in again. Unsynced writes
/// block the wipe until `discard_unsynced` confirms losing them.
#[tauri::command(rename_all = "snake_case")]
async fn sign_out(
    app: AppHandle,
    core: tauri::State<'_, Arc<Core>>,
    discard_unsynced: bool,
) -> Result<(), CommandError> {
    let session = core.begin_sign_out().ok_or(CommandError::NotReady)?;
    match session.native.forget_device(discard_unsynced).await {
        Ok(()) => {
            *core.slot.lock() = Slot::Empty;
            drop(session);
            core.update(&app, |view| *view = View::default());
            start(app, Arc::clone(&core));
        }
        Err(err) => {
            let wipe = match err {
                ForgetError::Purge(PurgeError::Unsynced(unsynced)) if !discard_unsynced => {
                    Wipe::ConfirmForce {
                        unsynced: unsynced.len(),
                    }
                }
                err => Wipe::Failed {
                    message: format!("logout error: {err}"),
                },
            };
            *core.slot.lock() = Slot::Ready(session);
            core.update(&app, |view| view.wipe = wipe);
        }
    }
    Ok(())
}

/// Back to the sign-out button after a refused or failed sign-out.
#[tauri::command]
fn dismiss_wipe(app: AppHandle, core: tauri::State<'_, Arc<Core>>) {
    core.update(&app, |view| view.wipe = Wipe::Idle);
}

fn demo_quantity() -> i64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    i64::try_from(millis % 9).unwrap_or(0) * 5 + 5
}

/// An endpoint as the running environment sets it, else as the build
/// environment did, else `default`.
fn endpoint(runtime: Option<String>, built: Option<&'static str>, default: &str) -> String {
    runtime
        .or_else(|| built.map(str::to_owned))
        .unwrap_or_else(|| default.to_owned())
}

#[cfg(target_os = "android")]
fn platform_sign_in(auth: KeyringAuth) -> KeyringAuth {
    auth.with_claimed_redirect(APP_REDIRECT, Arc::new(mobile::TabSession))
        .with_keystore_prompt(Arc::new(android::KeystoreUnlock))
}

#[cfg(target_os = "ios")]
fn platform_sign_in(auth: KeyringAuth) -> KeyringAuth {
    auth.with_claimed_redirect(APP_REDIRECT, Arc::new(mobile::TabSession))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn platform_sign_in(auth: KeyringAuth) -> KeyringAuth {
    auth
}

#[cfg(any(target_os = "android", target_os = "ios"))]
mod mobile {
    use connetto_client::ClientError;

    /// How long a login in the browser tab may take.
    const LOGIN_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);

    /// The Custom Tab on Android or the authentication session on iOS, and
    /// the app's redirect, through `connetto-auth-session`.
    pub(crate) struct TabSession;

    impl connetto_client::AuthorizationSession for TabSession {
        fn authorize(&self, url: String) -> connetto_client::SessionFuture {
            Box::pin(async move {
                connetto_auth_session::authorize(&url, LOGIN_WINDOW)
                    .await
                    .map_err(|err| ClientError::Auth(err.to_string()))
            })
        }

        fn delivered(&self) -> Option<String> {
            connetto_auth_session::delivered().unwrap_or_else(|err| {
                tracing::warn!(error = %err, "reading a delivered login redirect");
                None
            })
        }
    }
}

#[cfg(target_os = "android")]
mod android {
    use connetto_client::ClientError;

    /// How long the unlock prompt may stay up.
    const UNLOCK_WINDOW: std::time::Duration = std::time::Duration::from_secs(120);

    /// The Keystore unlock prompt, through `connetto-auth-session`.
    pub(crate) struct KeystoreUnlock;

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
    /// Writes each formatted log line to logcat, since an Android app's
    /// stdout goes nowhere.
    pub(crate) struct Logcat;

    impl std::io::Write for Logcat {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // An interior NUL would end the line early, so it is dropped.
            let line: Vec<u8> = buf
                .iter()
                .copied()
                .filter(|byte| *byte != 0 && *byte != b'\n')
                .collect();
            let message = std::ffi::CString::new(line).expect("NUL bytes were removed");
            // The discriminants are logcat's priorities, 0 to 8, so the cast never truncates.
            let priority = android_log_sys::LogPriority::INFO as std::ffi::c_int;
            // SAFETY: both pointers are NUL-terminated strings that live until
            // the call returns, and logcat only reads them.
            unsafe {
                android_log_sys::__android_log_write(
                    priority,
                    c"RustStdoutStderr".as_ptr(),
                    message.as_ptr(),
                );
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}

fn status_label(event: &ClientEvent) -> Option<String> {
    match event {
        ClientEvent::Reconnecting { attempt } => Some(format!("reconnecting (attempt {attempt})")),
        ClientEvent::Reconnected => Some("reconnected".to_owned()),
        ClientEvent::MutationApplied { client_seq } => {
            Some(format!("mutation {client_seq} applied"))
        }
        ClientEvent::MutationRejected {
            client_seq, reason, ..
        } => Some(format!("mutation {client_seq} rejected: {reason}")),
        ClientEvent::MutationConflict { client_seq, .. } => {
            Some(format!("mutation {client_seq} conflicted"))
        }
        ClientEvent::ServerClosed { reason } => Some(match reason {
            FatalErrorReason::RateLimited { retry_after_ms } => format!(
                "connection closed: rate limit exceeded (server suggests {retry_after_ms}ms wait)"
            ),
            other => format!("server closed the connection: {other:?}"),
        }),
        ClientEvent::Stopped { detail } => Some(format!("the client stopped: {detail}")),
        ClientEvent::Closed => Some("connection closed".to_owned()),
        ClientEvent::AuthenticationRequired => {
            Some("session expired, sign out and sign in again".to_owned())
        }
        _ => None,
    }
}

#[cfg(feature = "device-identity")]
fn device_label(native: &NativeClient<Ws>) -> String {
    use connetto_core::device_cert::KeyHome;

    let home = match native.device_key_home() {
        None => return "opening the device key".to_owned(),
        Some(KeyHome::SecureEnclave) => "the Secure Enclave",
        Some(KeyHome::AndroidKeystore { strongbox: true }) => "StrongBox",
        Some(KeyHome::AndroidKeystore { strongbox: false }) => "the Android Keystore",
        Some(KeyHome::Tpm) => "the TPM",
        Some(KeyHome::Software) => "software in the keyring",
    };
    match native.device_certificate() {
        Some(certificate) => {
            let until = chrono::DateTime::<chrono::Utc>::from(certificate.not_after());
            format!(
                "certified until {}, key in {home}, {}",
                until.format("%Y-%m-%d %H:%M UTC"),
                certificate.attestation()
            )
        }
        None => format!("enrolling, key in {home}"),
    }
}

#[cfg(not(feature = "device-identity"))]
fn device_label(_native: &NativeClient<Ws>) -> String {
    "no device identity in this build".to_owned()
}

/// Sign in, open the replica and start the pump, then feed the view.
async fn setup(app: AppHandle, core: Arc<Core>, data_dir: PathBuf) -> anyhow::Result<()> {
    use anyhow::Context as _;
    #[cfg(target_os = "android")]
    connetto_auth_session::initialize_tls()?;
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
    let sign_in = platform_sign_in(Auth::new(auth_origin, AUTH_PROVIDER).keyring(KEYRING_SERVICE));
    tokio::fs::create_dir_all(&data_dir)
        .await
        .context("creating the application data directory")?;

    let builder =
        NativeClientBuilder::new(server, SyncSchema::new(connetto_schema_bundle::bundle()))
            .with_tuning(SyncTuning::default().with_trim_threshold(5))
            .signed_in(sign_in)
            .durable(&data_dir)
            .with_gate(Gate::default().with_recheck(Some(RECHECK_AFTER)));
    #[cfg(feature = "device-identity")]
    let builder = builder.with_deployment_roots([DEVICE_ROOT.to_vec()]);
    #[cfg(all(feature = "device-identity", target_os = "android"))]
    let builder = builder.with_java_access(connetto_auth_session::java_access());
    let (native, pump) = builder
        .connect_with_pump()
        .await
        .context("opening the encrypted replica")?;
    let client = native.client().clone();
    let custody = native.custody().to_string();
    let user = native
        .session()
        .map_or_else(String::new, |session| session.user_id().to_owned());

    // Reset before the tasks start, since the count is pushed only on change.
    core.update(&app, |view| {
        *view = View {
            stage: "ready",
            user: user.clone(),
            custody,
            ..View::default()
        };
    });
    let (backend, commands) = mpsc::unbounded_channel::<BackendCmd>();
    let session = Arc::new_cyclic(|session| {
        let mut tasks = JoinSet::new();
        tasks.spawn(pump);
        tasks.spawn(feed_events(app.clone(), Arc::clone(&core), client.clone()));
        tasks.spawn(feed_count(app.clone(), Arc::clone(&core), client));
        tasks.spawn(write_backend(pg_url, user, commands));
        tasks.spawn(feed_device(app, Arc::clone(&core), Weak::clone(session)));
        Session {
            native,
            backend,
            _tasks: tasks,
        }
    });
    let mut slot = core.slot.lock();
    // Only setup fills an empty slot, and only one setup runs at a time.
    if !matches!(*slot, Slot::Empty) {
        anyhow::bail!("a second session started");
    }
    *slot = Slot::Ready(session);
    Ok(())
}

/// The client events drive the status and gate lines.
async fn feed_events(app: AppHandle, core: Arc<Core>, client: ConnettoClient<Ws>) {
    let mut events = client.events();
    while let Ok(event) = events.recv().await {
        let gate = match event {
            ClientEvent::Locked => Some("locked, verify it is you to continue"),
            ClientEvent::UnlockDismissed => Some("unlock dismissed, still locked"),
            ClientEvent::Unlocked => Some("open"),
            _ => None,
        };
        let status = status_label(&event);
        core.update(&app, |view| {
            if let Some(gate) = gate {
                view.gate = gate;
            }
            if let Some(status) = status {
                view.status = status;
            }
        });
        // The stop names its cause, and the `Closed` that follows it would
        // only replace that.
        if matches!(event, ClientEvent::Stopped { .. }) {
            break;
        }
    }
}

/// The server-pushed count.
async fn feed_count(app: AppHandle, core: Arc<Core>, client: ConnettoClient<Ws>) {
    match orders::table.count().live(&client).await {
        Ok(mut handle) => loop {
            let count = handle.snapshot();
            core.update(&app, |view| view.count = count);
            if let Err(err) = handle.changed().await {
                core.update(&app, |view| view.error = Some(err.to_string()));
                return;
            }
        },
        Err(err) => core.update(&app, |view| view.error = Some(err.to_string())),
    }
}

/// The backend writer, straight to Postgres, as the signed-in user, since
/// the deployment policy names the owner on the row it writes.
async fn write_backend(
    pg_url: String,
    user: String,
    mut commands: mpsc::UnboundedReceiver<BackendCmd>,
) {
    use diesel_async::AsyncConnection as _;
    let mut pg = match diesel_async::AsyncPgConnection::establish(&pg_url).await {
        Ok(pg) => pg,
        Err(err) => {
            tracing::error!(error = %err, "connecting the backend writer to Postgres");
            return;
        }
    };
    while let Some(BackendCmd::Insert) = commands.recv().await {
        let insert = diesel_async::RunQueryDsl::execute(
            diesel::insert_into(orders::table)
                .values((
                    orders::owner_id.eq(user.as_str()),
                    orders::quantity.eq(demo_quantity()),
                ))
                .on_conflict_do_nothing(),
            &mut pg,
        )
        .await;
        if let Err(err) = insert {
            tracing::error!(error = %err, "backend write failed");
        }
    }
}

/// The device line, read again every second since enrolment runs beside the
/// pump. It holds the session weakly, since the session owns this task.
async fn feed_device(app: AppHandle, core: Arc<Core>, session: Weak<Session>) {
    loop {
        let Some(label) = session
            .upgrade()
            .map(|session| device_label(&session.native))
        else {
            return;
        };
        core.update(&app, |view| view.device = label);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Run setup in the background, showing its failure.
fn start(app: AppHandle, core: Arc<Core>) {
    tauri::async_runtime::spawn(async move {
        let data_dir = match app.path().app_data_dir() {
            Ok(dir) => dir.join("connetto-tauri-demo"),
            Err(err) => {
                fail(&app, &core, &anyhow::Error::from(err));
                return;
            }
        };
        if let Err(err) = setup(app.clone(), Arc::clone(&core), data_dir).await {
            fail(&app, &core, &err);
        }
    });
}

fn fail(app: &AppHandle, core: &Core, err: &anyhow::Error) {
    let detail = err
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ");
    tracing::error!(%detail, "setup failed");
    core.update(app, |view| {
        view.stage = "failed";
        view.detail = Some(detail);
    });
}

fn init_logging() {
    #[cfg(target_os = "android")]
    connetto_core::logging::install(|| android::Logcat, LOG_FILTER);
    // The iOS proof reads the app's log from this file in its data container.
    #[cfg(target_os = "ios")]
    {
        let file = std::env::var_os("HOME").and_then(|home| {
            let dir = PathBuf::from(home).join("Library/Application Support");
            std::fs::create_dir_all(&dir).ok()?;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("connetto-demo.log"))
                .ok()
        });
        match file {
            Some(file) => connetto_core::logging::install(std::sync::Mutex::new(file), LOG_FILTER),
            None => connetto_core::logging::init_stdout_with_default(LOG_FILTER),
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    connetto_core::logging::init_stdout_with_default(LOG_FILTER);
}

/// Feed the client's away input from the platform lifecycle: `onPause` and
/// `onResume` on Android, the window's focus elsewhere.
fn feed_away(core: &Arc<Core>, event: &WindowEvent) {
    let away = match event {
        #[cfg(mobile)]
        WindowEvent::Suspended => true,
        #[cfg(mobile)]
        WindowEvent::Resumed => false,
        #[cfg(not(mobile))]
        WindowEvent::Focused(focused) => !focused,
        _ => return,
    };
    let at = Moment::now(&SystemClock);
    tracing::debug!(target: "connetto_tauri_demo::away", ?at, away, "the platform reported the lifecycle");
    let Some(client) = core.lifecycle_client() else {
        return;
    };
    tauri::async_runtime::spawn(async move {
        if away {
            client.away(at).await;
        } else {
            client.back(at).await;
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    init_logging();
    let core = Arc::new(Core::default());
    let lifecycle = Arc::clone(&core);
    tauri::Builder::default()
        .manage(Arc::clone(&core))
        .invoke_handler(tauri::generate_handler![
            view,
            insert_backend,
            insert_local,
            unlock,
            sign_out,
            dismiss_wipe
        ])
        .setup(move |app| {
            start(app.handle().clone(), Arc::clone(&core));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("building the Tauri app")
        .run(move |_app, event| {
            if let RunEvent::WindowEvent { event, .. } = &event {
                feed_away(&lifecycle, event);
            }
        });
}
