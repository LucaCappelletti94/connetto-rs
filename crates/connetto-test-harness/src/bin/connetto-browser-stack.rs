//! Runs the browser stack and browser suites without hand-started services.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow};
use axum::routing::get;
use connetto_server::{
    AuthConfig, AuthService, DbAuthStore, DefaultUuidResolver, GenericOidcProvider,
    ProviderRegistry, RedirectPolicy, RequestGuard, TokenAuthority, auth_router,
    connetto_auth_tables,
};
use connetto_test_harness::{Fixture, MockOauth, PUBLICATION, SLOT};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};
use tower_http::cors::{Any, CorsLayer};

const SYNC_BIND: &str = "127.0.0.1:7777";
const SYNC_WS: &str = "ws://127.0.0.1:7777/";
const AUTH_BIND: &str = "127.0.0.1:18099";
const AUTH_BASE: &str = "http://127.0.0.1:18099";
const CALLBACK: &str = "http://127.0.0.1:18099/auth/callback";
const LANDING_PATH: &str = "/dev/landing";
const CALLER_FUNCTION: &str = "current_app_user";
const BROWSER_PROVIDER: &str = "dev-idp";

const SCHEMA_SQL: &str = include_str!("../../../../examples/wasm-smoke/schema.sql");
const POLICIES_SQL: &str = include_str!("../../../../examples/wasm-smoke/policies.sql");
const ROLES_SQL: &str = include_str!("../../../../examples/wasm-smoke/roles.sql");

connetto_auth_tables!(String, diesel::sql_types::Text);

struct KeyDir {
    dir: PathBuf,
    private: PathBuf,
    public: PathBuf,
}

impl Drop for KeyDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

struct Services {
    fixture: Fixture,
    idp: MockOauth,
    keys: KeyDir,
    server_bin: PathBuf,
    envs: Vec<(String, String)>,
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

struct TaskGuard {
    handle: JoinHandle<()>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    connetto_core::logging::init_stdout();
    require_free(SYNC_BIND)?;
    require_free(AUTH_BIND)?;

    let server_bin = ensure_server_bin().await?;
    let services = prepare_services(server_bin).await?;
    let command = cli_command();

    if let Some((program, args)) = command {
        let _auth = start_auth_stack(&services).await?;
        let _server = start_sync_server(&services).await?;
        run_process(&program, &args, &services.envs).await?;
    } else {
        run_verified_topology(&services).await?;
        wait_until_closed(SYNC_BIND, Duration::from_secs(5)).await;
        wait_until_closed(AUTH_BIND, Duration::from_secs(5)).await;
        let _auth = start_auth_stack(&services).await?;
        let _server = start_sync_server(&services).await?;
        run_default_browser_suites(&services).await?;
    }

    Ok(())
}

fn cli_command() -> Option<(OsString, Vec<OsString>)> {
    let mut args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "--") {
        args.remove(0);
    }
    if args.is_empty() {
        None
    } else {
        let program = args.remove(0);
        Some((program, args))
    }
}

fn require_free(bind: &str) -> Result<()> {
    let listener = StdTcpListener::bind(bind)
        .with_context(|| format!("{bind} is already in use, stop that process first"))?;
    drop(listener);
    Ok(())
}

async fn prepare_services(server_bin: PathBuf) -> Result<Services> {
    let fixture = Fixture::acquire().await;
    fixture.setup(&[SCHEMA_SQL, POLICIES_SQL]).await;
    provision_auth_tables(&fixture).await;
    fixture.setup(&[ROLES_SQL]).await;
    fixture.start_replication(&["orders", "order_lines"]).await;
    let (fga_url, fga_store) = fixture_fga(&fixture).await;
    let keys = generate_keys().await?;
    let idp = MockOauth::start().await;
    let reader_url = with_user_url(fixture.admin_url(), "connetto_reader", "connetto_reader");
    let schema_file = repo_path(&["examples", "wasm-smoke", "schema.sql"])?;
    let policies_file = repo_path(&["examples", "wasm-smoke", "policies.sql"])?;

    let mut envs = vec![
        ("DATABASE_URL".to_owned(), fixture.admin_url().to_owned()),
        ("CONNETTO_READER_URL".to_owned(), reader_url),
        ("CONNETTO_BIND".to_owned(), SYNC_BIND.to_owned()),
        ("CONNETTO_AUTH_BIND".to_owned(), AUTH_BIND.to_owned()),
        ("CONNETTO_AUTH".to_owned(), "database".to_owned()),
        ("CONNETTO_WRITABLE".to_owned(), "orders".to_owned()),
        ("CONNETTO_PG_DDL".to_owned(), SCHEMA_SQL.to_owned()),
        ("CONNETTO_PG_POLICIES".to_owned(), POLICIES_SQL.to_owned()),
        ("CONNETTO_SLOT".to_owned(), SLOT.to_owned()),
        ("CONNETTO_PUBLICATION".to_owned(), PUBLICATION.to_owned()),
        ("CONNETTO_FGA_URL".to_owned(), fga_url),
        ("CONNETTO_FGA_STORE".to_owned(), fga_store),
        (
            "CONNETTO_JWT_PRIVATE_KEY_FILE".to_owned(),
            keys.private.display().to_string(),
        ),
        (
            "CONNETTO_JWT_PUBLIC_KEY_FILE".to_owned(),
            keys.public.display().to_string(),
        ),
        (
            "CONNETTO_CALLER_FUNCTION".to_owned(),
            CALLER_FUNCTION.to_owned(),
        ),
        ("CONNETTO_SLOT_LAG_SECS".to_owned(), "0".to_owned()),
        ("CONNETTO_TEST_AUTH_BASE".to_owned(), AUTH_BASE.to_owned()),
        ("CONNETTO_TEST_WS".to_owned(), SYNC_WS.to_owned()),
        (
            "CONNETTO_TEST_PROVIDER".to_owned(),
            BROWSER_PROVIDER.to_owned(),
        ),
        (
            "CONNETTO_TEST_PG_DDL_FILE".to_owned(),
            schema_file.display().to_string(),
        ),
        (
            "CONNETTO_TEST_PG_POLICIES_FILE".to_owned(),
            policies_file.display().to_string(),
        ),
        (
            "CONNETTO_SERVER_BIN".to_owned(),
            server_bin.display().to_string(),
        ),
    ];
    envs.extend(idp.env_pairs(BROWSER_PROVIDER, CALLBACK));

    Ok(Services {
        fixture,
        idp,
        keys,
        server_bin,
        envs,
    })
}

async fn fixture_fga(fixture: &Fixture) -> (String, String) {
    let endpoint = fixture.fga_url().await.to_owned();
    let (_, store) = fixture.fga_store().await;
    (endpoint, store)
}

async fn provision_auth_tables(fixture: &Fixture) {
    fixture
        .exec(
            "CREATE TABLE connetto_sessions (\
             session_id UUID PRIMARY KEY, user_id TEXT NOT NULL, \
             current_refresh_hash BYTEA NOT NULL, idle_deadline TIMESTAMPTZ NOT NULL, \
             absolute_deadline TIMESTAMPTZ NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE)",
        )
        .await;
    fixture
        .exec(
            "CREATE TABLE connetto_provider_tokens (\
             session_id UUID PRIMARY KEY REFERENCES connetto_sessions (session_id) ON DELETE CASCADE, \
             issuer TEXT NOT NULL, access_token TEXT NOT NULL, refresh_token TEXT, \
             expires_at TIMESTAMPTZ)",
        )
        .await;
}

async fn start_auth_stack(services: &Services) -> Result<TaskGuard> {
    let listener = tokio::net::TcpListener::bind(AUTH_BIND)
        .await
        .with_context(|| format!("binding {AUTH_BIND}"))?;
    let provider = GenericOidcProvider::discover(
        services.idp.oidc_config(BROWSER_PROVIDER, CALLBACK),
        openidconnect::reqwest::Client::new(),
    )
    .await
    .map_err(|err| anyhow!("discovering the browser provider: {err}"))?;
    let mut registry = ProviderRegistry::new();
    registry.register(Arc::new(provider));
    let registry = Arc::new(registry);

    let config = AuthConfig::default();
    let private = fs::read(&services.keys.private)
        .with_context(|| format!("reading {}", services.keys.private.display()))?;
    let public = fs::read(&services.keys.public)
        .with_context(|| format!("reading {}", services.keys.public.display()))?;
    let authority = TokenAuthority::from_ed_pem(&private, &public, &config)
        .map_err(|err| anyhow!("loading the browser signing keypair: {err}"))?;
    let manager =
        AsyncDieselConnectionManager::<AsyncPgConnection>::new(services.fixture.admin_url());
    let pool = Pool::builder()
        .build(manager)
        .await
        .context("building the browser auth Postgres pool")?;
    let store: DbAuthStore<ConnettoAuthSchema> = DbAuthStore::new(
        pool,
        config.refresh_lifetimes(),
        Arc::new(DefaultUuidResolver),
    );
    let service = Arc::new(
        AuthService::new(
            Arc::new(authority),
            Arc::new(store),
            Arc::new(RequestGuard::default()),
        )
        .with_registry(Arc::clone(&registry)),
    );
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    let app = auth_router(service, registry, RedirectPolicy::default())
        .route(
            LANDING_PATH,
            get(|| async { "connetto dev landing: the code is in this URL" }),
        )
        .layer(cors);
    let handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(listener, app).await {
            eprintln!("browser auth stack stopped: {err}");
        }
    });
    if !wait_for_tcp(AUTH_BIND, Duration::from_secs(20)).await {
        return Err(anyhow!("browser auth stack did not open {AUTH_BIND}"));
    }
    Ok(TaskGuard { handle })
}

async fn start_sync_server(services: &Services) -> Result<ChildGuard> {
    let mut command = Command::new(&services.server_bin);
    command
        .envs(services.envs.iter().cloned())
        .env("CONNETTO_AUTH_BIND", "127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().context("spawning connetto-server")?;
    wait_for_child_port(&mut child, SYNC_BIND, "connetto-server").await?;
    Ok(ChildGuard { child })
}

async fn run_verified_topology(services: &Services) -> Result<()> {
    let args = strings(&[
        "+stable",
        "test",
        "--release",
        "-p",
        "connetto-client",
        "--all-features",
        "--test",
        "verified_topology",
        "--",
        "--ignored",
    ]);
    run_process(OsStr::new("cargo"), &args, &services.envs).await
}

async fn run_default_browser_suites(services: &Services) -> Result<()> {
    let web_args = strings(&["test", "--headless", "--chrome", "crates/connetto-web"]);
    run_process(OsStr::new("wasm-pack"), &web_args, &services.envs).await?;

    for test in wasm_smoke_tests()? {
        let args = vec![
            OsString::from("test"),
            OsString::from("--headless"),
            OsString::from("--chrome"),
            OsString::from("examples/wasm-smoke"),
            OsString::from("--test"),
            test,
        ];
        run_process(OsStr::new("wasm-pack"), &args, &services.envs).await?;
    }
    Ok(())
}

fn wasm_smoke_tests() -> Result<Vec<OsString>> {
    let mut tests = Vec::new();
    for entry in fs::read_dir(repo_path(&["examples", "wasm-smoke", "tests"])?)
        .context("reading wasm smoke tests")?
    {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            tests.push(
                path.file_stem()
                    .ok_or_else(|| anyhow!("wasm smoke test has no file stem"))?
                    .to_owned(),
            );
        }
    }
    tests.sort();
    Ok(tests)
}

async fn run_process(program: &OsStr, args: &[OsString], envs: &[(String, String)]) -> Result<()> {
    let display = display_command(program, args);
    eprintln!("running {display}");
    let status = Command::new(program)
        .args(args)
        .envs(envs.iter().cloned())
        .status()
        .await
        .with_context(|| format!("starting {display}"))?;
    require_success(&display, status)
}

fn require_success(display: &str, status: std::process::ExitStatus) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("{display} exited with {status}"))
    }
}

async fn wait_for_child_port(child: &mut Child, bind: &str, name: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpStream::connect(bind).await.is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait().context("checking child status")? {
            return Err(anyhow!("{name} exited before opening {bind}: {status}"));
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("{name} did not open {bind}"));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_tcp(bind: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(bind).await.is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_until_closed(bind: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(bind).await.is_err() {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn ensure_server_bin() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("CONNETTO_SERVER_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
        return Err(anyhow!("CONNETTO_SERVER_BIN names a missing file"));
    }
    let candidate = target_dir()?
        .join("release")
        .join(exe_name("connetto-server"));
    if !candidate.exists() {
        let args = strings(&[
            "+stable",
            "build",
            "--release",
            "--all-features",
            "-p",
            "connetto-server",
            "--bin",
            "connetto-server",
        ]);
        run_process(OsStr::new("cargo"), &args, &[]).await?;
    }
    if candidate.exists() {
        Ok(candidate)
    } else {
        Err(anyhow!("connetto-server was not found after the build"))
    }
}

async fn generate_keys() -> Result<KeyDir> {
    let dir = std::env::temp_dir().join(format!(
        "connetto-browser-stack-{}-{}",
        std::process::id(),
        now_millis()
    ));
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let private = dir.join("priv.pem");
    let public = dir.join("pub.pem");
    let gen_args = vec![
        OsString::from("genpkey"),
        OsString::from("-algorithm"),
        OsString::from("ed25519"),
        OsString::from("-out"),
        private.as_os_str().to_owned(),
    ];
    run_process(OsStr::new("openssl"), &gen_args, &[]).await?;
    let pub_args = vec![
        OsString::from("pkey"),
        OsString::from("-in"),
        private.as_os_str().to_owned(),
        OsString::from("-pubout"),
        OsString::from("-out"),
        public.as_os_str().to_owned(),
    ];
    run_process(OsStr::new("openssl"), &pub_args, &[]).await?;
    Ok(KeyDir {
        dir,
        private,
        public,
    })
}

fn with_user_url(url: &str, user: &str, password: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("url has a scheme");
    let host = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    format!("{scheme}://{user}:{password}@{host}")
}

fn target_dir() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("CARGO_TARGET_DIR") {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            Ok(path)
        } else {
            Ok(repo_root()?.join(path))
        }
    } else {
        Ok(repo_root()?.join("target"))
    }
}

fn repo_path(parts: &[&str]) -> Result<PathBuf> {
    let mut path = repo_root()?;
    for part in parts {
        path.push(part);
    }
    Ok(path)
}

fn repo_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .context("finding the repository root")
}

fn exe_name(base: &str) -> String {
    format!("{base}{}", std::env::consts::EXE_SUFFIX)
}

fn strings(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn display_command(program: &OsStr, args: &[OsString]) -> String {
    let mut text = program.to_string_lossy().into_owned();
    for arg in args {
        text.push(' ');
        text.push_str(&arg.to_string_lossy());
    }
    text
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}
