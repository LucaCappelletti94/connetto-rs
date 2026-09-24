//! The provisioning and process plumbing the one-command stacks share.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};

use crate::{Fixture, PUBLICATION, SLOT, with_user};

/// The file server's own tables, which every deployment serving content needs.
const DEPLOYMENT_SQL: &str = include_str!("../../connetto-file-server/sql/schema.sql");

/// What one deployment brings to a fresh fixture.
pub struct Deployment {
    /// The Postgres schema, also served as `CONNETTO_PG_DDL`.
    pub schema: &'static str,
    /// The non-owner reader role and its grants.
    pub roles: &'static str,
    /// The content columns and triggers the file server reads.
    pub content: &'static str,
    /// The row policies, also served as `CONNETTO_PG_POLICIES`.
    pub policies: &'static str,
    /// The tables the publication carries.
    pub published: &'static [&'static str],
    /// The tables clients may write, as `CONNETTO_WRITABLE` lists them.
    pub writable: &'static str,
}

/// A temporary directory removed on drop.
pub struct TempDir {
    /// The directory itself.
    pub path: PathBuf,
}

impl TempDir {
    /// Create a directory under the system temp dir named after `label`.
    ///
    /// # Errors
    ///
    /// When the directory cannot be created.
    pub async fn create(label: &str) -> Result<Self> {
        let path =
            std::env::temp_dir().join(format!("{label}-{}-{}", std::process::id(), now_millis()));
        tokio::fs::create_dir_all(&path)
            .await
            .with_context(|| format!("creating {}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// The token signing keypair and the content ticket key, on disk.
pub struct KeyDir {
    /// Holds the three files and removes them on drop.
    pub dir: TempDir,
    /// The ed25519 private key, PEM.
    pub private: PathBuf,
    /// The ed25519 public key, PEM.
    pub public: PathBuf,
    /// The content ticket keypair, PKCS#8 DER.
    pub content_der: PathBuf,
}

/// A deployment provisioned into its own fixture, with the material the
/// server binary reads.
pub struct Provisioned {
    /// The Postgres and authorization service the deployment lives in.
    pub fixture: Fixture,
    /// The signing keys.
    pub keys: KeyDir,
    /// Where the file server stores content.
    pub content_store: TempDir,
    /// The authorization service endpoint.
    pub fga_url: String,
    /// The authorization store created for this deployment.
    pub fga_store: String,
}

/// Provision `deployment` into a fresh fixture and generate its keys.
///
/// # Errors
///
/// When key generation or the content directory fails.
pub async fn provision(deployment: &Deployment, label: &str) -> Result<Provisioned> {
    let fixture = Fixture::acquire().await;
    fixture.setup(&[deployment.schema]).await;
    fixture.setup(&[DEPLOYMENT_SQL]).await;
    provision_auth_tables(&fixture).await;
    fixture.setup(&[deployment.roles]).await;
    fixture.setup(&[deployment.content]).await;
    fixture.setup(&[deployment.policies]).await;
    fixture.start_replication(deployment.published).await;
    let fga_url = fixture.fga_url().await.to_owned();
    let (_, fga_store) = fixture.fga_store().await;
    let keys = generate_keys(&format!("{label}-keys")).await?;
    let content_store = TempDir::create(&format!("{label}-content")).await?;
    Ok(Provisioned {
        fixture,
        keys,
        content_store,
        fga_url,
        fga_store,
    })
}

impl Provisioned {
    /// The environment `connetto-server` runs this deployment with, serving
    /// sync on `sync_bind` and auth plus content on `auth_bind`.
    pub fn server_env(
        &self,
        deployment: &Deployment,
        sync_bind: &str,
        auth_bind: &str,
        content_base: &str,
    ) -> Vec<(String, String)> {
        let admin = self.fixture.admin_url();
        let pairs = [
            ("DATABASE_URL", admin.to_owned()),
            (
                "CONNETTO_READER_URL",
                with_user(admin, "connetto_reader", "connetto_reader"),
            ),
            ("CONNETTO_BIND", sync_bind.to_owned()),
            ("CONNETTO_AUTH_BIND", auth_bind.to_owned()),
            ("CONNETTO_AUTH", "database".to_owned()),
            ("CONNETTO_WRITABLE", deployment.writable.to_owned()),
            ("CONNETTO_CONTENT_URL", content_base.to_owned()),
            (
                "CONNETTO_CONTENT_STORE",
                format!("fs:{}", self.content_store.path.display()),
            ),
            (
                "CONNETTO_CONTENT_KEY",
                self.keys.content_der.display().to_string(),
            ),
            ("CONNETTO_PG_DDL", deployment.schema.to_owned()),
            ("CONNETTO_PG_POLICIES", deployment.policies.to_owned()),
            ("CONNETTO_SLOT", SLOT.to_owned()),
            ("CONNETTO_PUBLICATION", PUBLICATION.to_owned()),
            ("CONNETTO_FGA_URL", self.fga_url.clone()),
            ("CONNETTO_FGA_STORE", self.fga_store.clone()),
            (
                "CONNETTO_JWT_PRIVATE_KEY_FILE",
                self.keys.private.display().to_string(),
            ),
            (
                "CONNETTO_JWT_PUBLIC_KEY_FILE",
                self.keys.public.display().to_string(),
            ),
        ];
        pairs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect()
    }
}

/// Create the session and provider token tables `CONNETTO_AUTH=database`
/// stores its sessions in.
pub async fn provision_auth_tables(fixture: &Fixture) {
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

/// Generate the token signing keypair with `openssl` and the content ticket
/// keypair with `ring`.
///
/// # Errors
///
/// When `openssl` fails or a key cannot be written.
pub async fn generate_keys(label: &str) -> Result<KeyDir> {
    let dir = TempDir::create(label).await?;
    let private = dir.path.join("priv.pem");
    let public = dir.path.join("pub.pem");
    let content_der = dir.path.join("content.der");
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
    let content_key =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|err| anyhow!("generating the content ticket keypair: {err:?}"))?;
    tokio::fs::write(&content_der, content_key.as_ref())
        .await
        .with_context(|| format!("writing {}", content_der.display()))?;
    Ok(KeyDir {
        dir,
        private,
        public,
        content_der,
    })
}

/// A task aborted on drop.
pub struct TaskGuard {
    /// The task.
    pub handle: JoinHandle<()>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Spawn `connetto-server` with `envs`, its auth listener on `auth_bind`,
/// and wait until both listeners accept. Dropping the returned child, or any
/// error on the way, kills the server.
///
/// # Errors
///
/// When the binary cannot start, or exits or stays closed past the deadline.
pub async fn spawn_server(
    server_bin: &Path,
    envs: &[(String, String)],
    sync_bind: &str,
    auth_bind: &str,
) -> Result<Child> {
    let mut child = Command::new(server_bin)
        .envs(envs.iter().cloned())
        .env("CONNETTO_AUTH_BIND", auth_bind)
        // The server logs to stdout. Nulling it hid every server line from CI.
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("spawning connetto-server")?;
    wait_for_child_port(&mut child, sync_bind, "connetto-server").await?;
    if !wait_for_tcp(auth_bind, Duration::from_secs(20)).await {
        return Err(anyhow!("connetto-server did not open {auth_bind}"));
    }
    Ok(child)
}

/// Build the release `connetto-server` unless `CONNETTO_SERVER_BIN` names
/// one, and return its path.
///
/// # Errors
///
/// When the named file is missing or the build fails.
pub async fn ensure_server_bin() -> Result<PathBuf> {
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
    // The build runs even when the binary exists. A cached tree can hold a
    // server from another commit, and cargo's fingerprinting makes the warm
    // case a no-op while a stale exists() shortcut cannot.
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
    if candidate.exists() {
        Ok(candidate)
    } else {
        Err(anyhow!("connetto-server was not found after the build"))
    }
}

/// The variable that moves a stack's sync listener.
pub const SYNC_PORT_VAR: &str = "CONNETTO_STACK_SYNC_PORT";
/// The variable that moves a stack's auth listener.
pub const AUTH_PORT_VAR: &str = "CONNETTO_STACK_AUTH_PORT";
/// The variable that moves a stack's content listener.
pub const CONTENT_PORT_VAR: &str = "CONNETTO_STACK_CONTENT_PORT";

/// Each `(variable, default)` port as `var` reads it.
///
/// # Errors
///
/// When a value is not a port from 1 to 65535, or two ports coincide, since
/// every entry names its own listener.
pub fn ports<const N: usize>(
    var: impl Fn(&str) -> Option<String>,
    wanted: [(&str, u16); N],
) -> Result<[u16; N]> {
    let mut ports = [0; N];
    for (slot, (name, default)) in ports.iter_mut().zip(wanted) {
        *slot = match var(name) {
            None => default,
            Some(value) => value
                .parse()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| anyhow!("{name} wants a port from 1 to 65535, got {value:?}"))?,
        };
    }
    for (index, port) in ports.iter().enumerate() {
        if let Some(earlier) = ports[..index].iter().position(|other| other == port) {
            return Err(anyhow!(
                "{} and {} both name port {port}",
                wanted[earlier].0,
                wanted[index].0
            ));
        }
    }
    Ok(ports)
}

/// Fail when `bind` is taken, naming it and the variable `var` that moves it.
///
/// # Errors
///
/// When the address cannot be bound.
pub fn require_free(bind: &str, var: &str) -> Result<()> {
    let listener = StdTcpListener::bind(bind).with_context(|| {
        format!("{bind} is already in use, stop that process or move the stack with {var}")
    })?;
    drop(listener);
    Ok(())
}

/// Run a program to completion with `envs` added to the inherited ones.
///
/// # Errors
///
/// When it cannot start or exits unsuccessfully.
pub async fn run_process(
    program: &OsStr,
    args: &[OsString],
    envs: &[(String, String)],
) -> Result<()> {
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

/// Turn an unsuccessful exit into an error naming the command.
///
/// # Errors
///
/// When `status` is not a success.
pub fn require_success(display: &str, status: std::process::ExitStatus) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("{display} exited with {status}"))
    }
}

/// Wait until `child` accepts on `bind`.
///
/// # Errors
///
/// When the child exits first or 30 seconds pass.
pub async fn wait_for_child_port(child: &mut Child, bind: &str, name: &str) -> Result<()> {
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

/// Whether `bind` accepts within `timeout`.
pub async fn wait_for_tcp(bind: &str, timeout: Duration) -> bool {
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

/// Wait up to `timeout` for `bind` to stop accepting.
pub async fn wait_until_closed(bind: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(bind).await.is_err() {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

/// The cargo target directory of the root workspace.
///
/// # Errors
///
/// When the repository root cannot be resolved.
pub fn target_dir() -> Result<PathBuf> {
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

/// A path under the repository root.
///
/// # Errors
///
/// When the repository root cannot be resolved.
pub fn repo_path(parts: &[&str]) -> Result<PathBuf> {
    let mut path = repo_root()?;
    for part in parts {
        path.push(part);
    }
    Ok(path)
}

/// The repository root.
///
/// # Errors
///
/// When the path cannot be canonicalized.
pub fn repo_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .context("finding the repository root")
}

/// The platform's executable file name for `base`.
pub fn exe_name(base: &str) -> String {
    format!("{base}{}", std::env::consts::EXE_SUFFIX)
}

/// Owned process arguments.
pub fn strings(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

/// A command line for logs.
pub fn display_command(program: &OsStr, args: &[OsString]) -> String {
    let mut text = program.to_string_lossy().into_owned();
    for arg in args {
        text.push(' ');
        text.push_str(&arg.to_string_lossy());
    }
    text
}

/// Milliseconds since the Unix epoch.
pub fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}
