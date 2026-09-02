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

/// One slice of the suite list, `--shard I/N`: this process runs every suite
/// whose position lands on `index` round-robin, so N separate machines cover
/// the list exactly once with no shared stack between them. The serial-order
/// rule inside one process is untouched: each shard still runs its suites
/// one at a time against its own stack.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Shard {
    /// 1-based slice index.
    index: usize,
    /// Total slice count.
    count: usize,
}

impl Shard {
    fn admits(self, position: usize) -> bool {
        position % self.count == self.index - 1
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    connetto_core::logging::init_stdout();
    require_free(SYNC_BIND)?;
    require_free(AUTH_BIND)?;

    let (shard, command) = cli_arguments()?;
    let server_bin = ensure_server_bin().await?;
    let services = prepare_services(server_bin).await?;

    if let Some((program, args)) = command {
        let _auth = start_auth_stack(&services).await?;
        let _server = start_sync_server(&services).await?;
        run_process(&program, &args, &services.envs).await?;
    } else {
        // The verified-topology pass is one native run, so only the first
        // shard pays it. A bare invocation is shard 1 of 1 and keeps it.
        if shard.is_none_or(|shard| shard.index == 1) {
            run_verified_topology(&services).await?;
            wait_until_closed(SYNC_BIND, Duration::from_secs(5)).await;
            wait_until_closed(AUTH_BIND, Duration::from_secs(5)).await;
        }
        let _auth = start_auth_stack(&services).await?;
        let _server = start_sync_server(&services).await?;
        run_default_browser_suites(&services, shard).await?;
    }

    Ok(())
}

/// A program with its arguments to run against the stack instead of the
/// default suites.
type StackCommand = (OsString, Vec<OsString>);

/// The optional `--shard I/N` selector, then optionally a [`StackCommand`].
fn cli_arguments() -> Result<(Option<Shard>, Option<StackCommand>)> {
    let mut args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "--") {
        args.remove(0);
    }
    let mut shard = None;
    if args.first().is_some_and(|arg| arg == "--shard") {
        args.remove(0);
        let value = args
            .first()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("--shard needs a value of the form I/N"))?;
        shard = Some(parse_shard(value)?);
        args.remove(0);
        if !args.is_empty() {
            return Err(anyhow!("--shard applies to the default suites only"));
        }
    }
    let command = if args.is_empty() {
        None
    } else {
        let program = args.remove(0);
        Some((program, args))
    };
    Ok((shard, command))
}

fn parse_shard(value: &str) -> Result<Shard> {
    let malformed = || anyhow!("--shard wants I/N with 1 <= I <= N, got {value:?}");
    let (index, count) = value.split_once('/').ok_or_else(malformed)?;
    let index: usize = index.parse().map_err(|_| malformed())?;
    let count: usize = count.parse().map_err(|_| malformed())?;
    if index == 0 || count == 0 || index > count {
        return Err(malformed());
    }
    Ok(Shard { index, count })
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
        "it",
        "--",
        "verified_topology",
        "--ignored",
    ]);
    run_process(OsStr::new("cargo"), &args, &services.envs).await
}

async fn run_default_browser_suites(services: &Services, shard: Option<Shard>) -> Result<()> {
    // A suite that never reports leaves the runner waiting, so the children
    // carry their own deadline unless the caller already set one.
    let mut envs = services.envs.clone();
    if std::env::var_os("WASM_BINDGEN_TEST_TIMEOUT").is_none() {
        envs.push(("WASM_BINDGEN_TEST_TIMEOUT".to_owned(), "60".to_owned()));
    }
    // One shared artifact dir for every wasm invocation: the web crate and the
    // smoke binaries build near-identical dependency graphs, and separate
    // per-workspace target trees rebuilt that graph from scratch each.
    if std::env::var_os("CARGO_TARGET_DIR").is_none() {
        envs.push((
            "CARGO_TARGET_DIR".to_owned(),
            repo_path(&["target-wasm"])?.to_string_lossy().into_owned(),
        ));
    }

    // Every suite is its own wasm-pack invocation, one target each: the R46
    // headless hang and the chromedriver port race strike per session, so a
    // per-suite invocation confines the retry to the one suite that lost its
    // report instead of rolling every suite's dice again. The suites run
    // SERIALLY on purpose: they drive one shared stack as one dev user, and a
    // concurrent sibling's logins and logouts reach the same server-side
    // sessions (measured 2026-08-31 as a mid-suite 404 under four-way
    // parallelism). Their bodies cost seconds each, so serial order costs
    // little beyond the per-invocation overhead.
    let mut suite_args = vec![strings(&[
        "test",
        "--headless",
        "--chrome",
        "crates/connetto-web",
        "--lib",
    ])];
    for test in test_files(&["crates", "connetto-web", "tests"])? {
        suite_args.push(per_test_args("crates/connetto-web", test));
    }
    for test in test_files(&["examples", "wasm-smoke", "tests"])? {
        suite_args.push(per_test_args("examples/wasm-smoke", test));
    }

    let total = suite_args.len();
    if let Some(shard) = shard {
        suite_args = suite_args
            .into_iter()
            .enumerate()
            .filter(|(position, _)| shard.admits(*position))
            .map(|(_, args)| args)
            .collect();
        eprintln!(
            "shard {}/{} runs {} of {total} suites",
            shard.index,
            shard.count,
            suite_args.len()
        );
    }
    for args in &suite_args {
        run_browser_suite(args, &envs).await?;
    }
    Ok(())
}

fn per_test_args(workspace: &str, test: OsString) -> Vec<OsString> {
    vec![
        OsString::from("test"),
        OsString::from("--headless"),
        OsString::from("--chrome"),
        OsString::from(workspace),
        OsString::from("--test"),
        test,
    ]
}

fn test_files(dir: &[&str]) -> Result<Vec<OsString>> {
    let mut tests = Vec::new();
    for entry in fs::read_dir(repo_path(dir)?).context("reading a tests directory")? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            tests.push(
                path.file_stem()
                    .ok_or_else(|| anyhow!("a test file has no stem"))?
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

/// What the headless runner prints when the environment lost the session
/// through no fault of the suite. The first is R46's report loss, documented
/// as an upstream defect (`docs/upstream-wasm-bindgen-headless-hang.md`). The
/// second is a chromedriver startup port race, which concurrent suites can
/// hit because each runner picks its port before binding it. Either is why a
/// browser suite is retried once rather than failing the whole run.
const RETRYABLE_SIGNATURES: [&str; 2] = [
    "Failed to detect test as having been run",
    "driver failed to bind port during startup",
];

/// One child run: how it exited, and whether its output carried the hang.
struct BrowserRun {
    status: std::process::ExitStatus,
    hung: bool,
}

/// Run one browser suite, retrying once when the headless runner lost the
/// report. Any other failure is reported as it happened, so a real one is
/// never retried into looking intermittent.
async fn run_browser_suite(args: &[OsString], envs: &[(String, String)]) -> Result<()> {
    let program = OsStr::new("wasm-pack");
    let display = display_command(program, args);
    let first = run_watching(program, args, envs).await?;
    if first.status.success() {
        return Ok(());
    }
    if !first.hung {
        return Err(anyhow!("{display} exited with {}", first.status));
    }
    eprintln!("{display} lost its report to the headless runner, retrying once");
    let second = run_watching(program, args, envs).await?;
    require_success(&display, second.status)
}

/// Spawn a child, echo its output as it arrives, and report whether the hang
/// signature appeared. Output is echoed rather than swallowed so a long suite
/// still reports progress.
async fn run_watching(
    program: &OsStr,
    args: &[OsString],
    envs: &[(String, String)],
) -> Result<BrowserRun> {
    let display = display_command(program, args);
    eprintln!("running {display}");
    let mut child = Command::new(program)
        .args(args)
        .envs(envs.iter().cloned())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {display}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("{display} gave no stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("{display} gave no stderr"))?;
    let out = tokio::spawn(echo_watching(stdout));
    let err = tokio::spawn(echo_watching(stderr));
    let status = child
        .wait()
        .await
        .with_context(|| format!("waiting for {display}"))?;
    let hung = out.await.context("reading stdout")?? || err.await.context("reading stderr")??;
    Ok(BrowserRun { status, hung })
}

/// Echo every line to stderr, answering whether any carried the hang.
async fn echo_watching<R>(reader: R) -> Result<bool>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncBufReadExt as _;

    let mut lines = tokio::io::BufReader::new(reader).lines();
    let mut hung = false;
    while let Some(line) = lines.next_line().await.context("reading child output")? {
        hung |= RETRYABLE_SIGNATURES
            .iter()
            .any(|signature| line.contains(signature));
        eprintln!("{line}");
    }
    Ok(hung)
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

#[cfg(test)]
mod tests {
    use super::{RETRYABLE_SIGNATURES, echo_watching, parse_shard};

    /// The retry exists for the environment-loss signatures alone, so the
    /// reader has to recognise each among ordinary output and nothing else. A
    /// false positive would retry a real failure and make it look
    /// intermittent.
    #[tokio::test]
    async fn the_reader_recognises_only_the_environment_losses() {
        for signature in RETRYABLE_SIGNATURES {
            let lost = format!("Loading Wasm module...\n{signature}\ndriver status: signal: 9\n");
            assert!(
                echo_watching(lost.as_bytes()).await.expect("read"),
                "the runner's own words are what the retry keys on"
            );
        }
        let failed = "running 1 test\ntest a_real_one ... FAILED\ntest result: FAILED.\n";
        assert!(
            !echo_watching(failed.as_bytes()).await.expect("read"),
            "an ordinary failure is reported, never retried"
        );
    }

    /// Every suite position lands in exactly one shard, whatever the count,
    /// so N machines cover the list once with no overlap and no gap.
    #[test]
    fn shards_partition_every_position_exactly_once() {
        for count in 1..=6 {
            for position in 0..40 {
                let owners = (1..=count)
                    .filter(|index| {
                        parse_shard(&format!("{index}/{count}"))
                            .expect("a valid shard")
                            .admits(position)
                    })
                    .count();
                assert_eq!(owners, 1, "position {position} under {count} shards");
            }
        }
    }

    /// The selector accepts only 1-based I/N with I inside N.
    #[test]
    fn shard_parsing_refuses_malformed_selectors() {
        assert!(parse_shard("2/4").is_ok());
        assert!(parse_shard("1/1").is_ok());
        for bad in ["0/4", "5/4", "0/0", "x/4", "2", "2/", "/4", "2/4/6"] {
            assert!(parse_shard(bad).is_err(), "{bad} was accepted");
        }
    }
}
