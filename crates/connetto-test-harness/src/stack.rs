//! The provisioning and process plumbing the one-command stacks share.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Create a directory under the system temp dir named after `label`,
    /// distinct from every other this process creates.
    ///
    /// # Errors
    ///
    /// When the directory cannot be created or already exists.
    pub async fn create(label: &str) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "{label}-{}-{}-{}",
            std::process::id(),
            now_millis(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        tokio::fs::create_dir(&path)
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

/// Provision `deployment` into a fresh fixture, over `running` services when
/// given and in containers otherwise, and generate its keys.
///
/// # Errors
///
/// When key generation or the content directory fails.
pub async fn provision(
    deployment: &Deployment,
    label: &str,
    running: Option<&RunningServices>,
) -> Result<Provisioned> {
    let fixture = match running {
        Some(services) => Fixture::on_cluster(&services.postgres, &services.openfga).await,
        None => Fixture::acquire().await,
    };
    fixture.setup(&[deployment.schema]).await;
    fixture.setup(&[DEPLOYMENT_SQL]).await;
    fixture.setup(&[connetto_server::epoch::EPOCH_DDL]).await;
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
    /// sync, login and file routes on `bind`.
    pub fn server_env(
        &self,
        deployment: &Deployment,
        bind: &str,
        content_base: &str,
    ) -> Vec<(String, String)> {
        let admin = self.fixture.admin_url();
        let pairs = [
            ("DATABASE_URL", admin.to_owned()),
            (
                "CONNETTO_READER_URL",
                with_user(admin, "connetto_reader", "connetto_reader"),
            ),
            ("CONNETTO_BIND", bind.to_owned()),
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

/// The default deployment's enrolment tables, whose descriptor is `()` and so
/// has no columns of its own (R74).
pub const ENROLMENT_DDL: [&str; 3] = [
    "CREATE TABLE connetto_device_enrolments (\
     key_id BYTEA PRIMARY KEY, user_id TEXT NOT NULL, session_id UUID NOT NULL, \
     enrolled_at TIMESTAMPTZ NOT NULL, last_seen TIMESTAMPTZ NOT NULL, \
     revoked_at TIMESTAMPTZ, attestation TEXT NOT NULL)",
    "CREATE TABLE connetto_device_certificates (\
     serial BYTEA PRIMARY KEY, \
     key_id BYTEA NOT NULL REFERENCES connetto_device_enrolments (key_id), \
     issuer BYTEA NOT NULL, expires_at TIMESTAMPTZ NOT NULL)",
    "CREATE TABLE connetto_device_lists (issuer BYTEA PRIMARY KEY, last_number BIGINT NOT NULL)",
];

/// Create [`ENROLMENT_DDL`]'s tables.
pub async fn provision_enrolment_tables(fixture: &Fixture) {
    for statement in ENROLMENT_DDL {
        fixture.exec(statement).await;
    }
}

/// The demo's device certificate authority, a root and its current issuer as
/// `connetto-ca` writes them (R74 decision 30).
#[derive(Debug)]
pub struct DemoDeviceCa {
    /// The root's `root.der`, which a demo build ships.
    pub root: PathBuf,
    /// The directory holding the current `issuer.der` and `issuer.key`.
    pub issuer: PathBuf,
}

/// The variable naming the deployment root a demo build ships, which the demo
/// stack sets.
pub const DEMO_DEVICE_ROOT_VAR: &str = "CONNETTO_DEMO_BUILD_DEVICE_ROOT";

/// The demo's build features for a mobile target, with its device identity
/// and the peer link and hotspot it carries when the stack named a
/// deployment root.
#[must_use]
pub fn demo_mobile_features() -> &'static str {
    if std::env::var_os(DEMO_DEVICE_ROOT_VAR).is_some() {
        "mobile,device-identity,peer"
    } else {
        "mobile"
    }
}

/// Whether the demo under proof was built with its device identity.
#[must_use]
pub fn demo_has_device_identity() -> bool {
    std::env::var_os(DEMO_DEVICE_ROOT_VAR).is_some()
}

/// Not a secret: the demo's root key only ever signs throwaway issuers.
const DEMO_CA_PASSPHRASE: &str = "connetto demo stack";

/// The demo's certificate authority under `target/demo-device-ca`, its root
/// created on the first run and its issuer signed again once it has under
/// sixty days left at `now`.
///
/// # Errors
///
/// When the root or the issuer cannot be created, read or signed.
pub fn demo_device_ca(now: SystemTime) -> Result<DemoDeviceCa> {
    use connetto_core::device_cert::DeviceIssuer;
    use connetto_core::device_cert::layout::{ISSUER_CERTIFICATE, ISSUER_KEY, ROOT_CERTIFICATE};
    use connetto_server::device_cert::DeviceCertConfig;

    let dir = target_dir()?.join("demo-device-ca");
    let root = dir.join(ROOT_CERTIFICATE);
    let issuer = dir.join("issuer");
    if !root.exists() {
        fs::create_dir_all(&dir).context("creating the demo CA directory")?;
        connetto_ca::init(&dir, DEMO_CA_PASSPHRASE, now).context("creating the demo root")?;
    }
    let current = || -> Result<bool> {
        let read =
            |path: &Path| fs::read(path).with_context(|| format!("reading {}", path.display()));
        let issuer = DeviceIssuer::from_pkcs8(
            read(&issuer.join(ISSUER_CERTIFICATE))?,
            &read(&issuer.join(ISSUER_KEY))?,
            &read(&root)?,
        )?;
        Ok(matches!(DeviceCertConfig::new(issuer).check(now), Ok(None)))
    };
    if !issuer.join(ISSUER_CERTIFICATE).exists() || !current()? {
        if issuer.exists() {
            fs::remove_dir_all(&issuer).context("removing the expiring demo issuer")?;
        }
        fs::create_dir_all(&issuer).context("creating the demo issuer directory")?;
        connetto_ca::sign_issuer(&dir, DEMO_CA_PASSPHRASE, &issuer, now)
            .context("signing the demo issuer")?;
    }
    Ok(DemoDeviceCa { root, issuer })
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

/// Spawn `connetto-server` with `envs` and wait until its listener accepts.
/// Dropping the returned child, or any error on the way, kills the server.
///
/// # Errors
///
/// When the binary cannot start, or exits or stays closed past the deadline.
pub async fn spawn_server(
    server_bin: &Path,
    envs: &[(String, String)],
    bind: &str,
) -> Result<Child> {
    let mut child = Command::new(server_bin)
        .envs(envs.iter().cloned())
        // The server logs to stdout. Nulling it hid every server line from CI.
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("spawning connetto-server")?;
    wait_for_child_port(&mut child, bind, "connetto-server").await?;
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

/// The variable that moves a stack's sync, login and file listener.
pub const SYNC_PORT_VAR: &str = "CONNETTO_STACK_SYNC_PORT";
/// The variable that puts a stack on the LAN. Its listeners bind every
/// interface, and every address a client or its browser follows names this
/// host.
pub const PUBLIC_HOST_VAR: &str = "CONNETTO_STACK_PUBLIC_HOST";
/// The variables naming the PEM certificate chain and key a stack on a public
/// host serves its auth listener with over TLS.
pub const TLS_CERT_VAR: &str = "CONNETTO_STACK_TLS_CERT";
/// See [`TLS_CERT_VAR`].
pub const TLS_KEY_VAR: &str = "CONNETTO_STACK_TLS_KEY";
/// The variables naming services a stack uses in place of the containers it
/// would start, all three together. See [`RunningServices`].
pub const POSTGRES_URL_VAR: &str = "CONNETTO_STACK_POSTGRES_URL";
/// See [`POSTGRES_URL_VAR`]. A fixture also uses it alone, see
/// [`Fixture::acquire`](crate::Fixture::acquire).
pub const OPENFGA_URL_VAR: &str = "CONNETTO_STACK_OPENFGA_URL";
/// See [`POSTGRES_URL_VAR`]. A provider also uses it alone, see
/// [`MockOauth::start`](crate::MockOauth::start).
pub const ISSUER_VAR: &str = "CONNETTO_STACK_ISSUER";

/// Services something else started for a stack, where Docker cannot run.
pub struct RunningServices {
    /// The admin URL of a Postgres cluster running with `wal_level=logical`.
    pub postgres: String,
    /// The gRPC endpoint of an authorization service.
    pub openfga: String,
    /// The issuer URL of a mock identity provider configured as its container is.
    pub issuer: String,
}

impl RunningServices {
    /// The services the environment names, or `None` when it names none.
    ///
    /// # Errors
    ///
    /// When it names some of the three but not all.
    pub fn from_env() -> Result<Option<Self>> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// The services `var` names, as [`Self::from_env`] reads them.
    ///
    /// # Errors
    ///
    /// When `var` names some of the three but not all.
    pub fn from_lookup(var: impl Fn(&str) -> Option<String>) -> Result<Option<Self>> {
        match (var(POSTGRES_URL_VAR), var(OPENFGA_URL_VAR), var(ISSUER_VAR)) {
            (Some(postgres), Some(openfga), Some(issuer)) => Ok(Some(Self {
                postgres,
                openfga,
                issuer,
            })),
            (None, None, None) => Ok(None),
            _ => Err(anyhow!(
                "{POSTGRES_URL_VAR}, {OPENFGA_URL_VAR} and {ISSUER_VAR} go together"
            )),
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::{ISSUER_VAR, OPENFGA_URL_VAR, POSTGRES_URL_VAR, RunningServices, TempDir};

    fn lookup(set: &[&str]) -> impl Fn(&str) -> Option<String> {
        let set: Vec<String> = set.iter().map(|name| (*name).to_owned()).collect();
        move |name| {
            set.iter()
                .any(|set| set == name)
                .then(|| format!("{name}-value"))
        }
    }

    #[test]
    fn all_three_variables_name_the_running_services() {
        let services =
            RunningServices::from_lookup(lookup(&[POSTGRES_URL_VAR, OPENFGA_URL_VAR, ISSUER_VAR]))
                .unwrap()
                .expect("all three are set");
        assert_eq!(services.postgres, format!("{POSTGRES_URL_VAR}-value"));
        assert_eq!(services.openfga, format!("{OPENFGA_URL_VAR}-value"));
        assert_eq!(services.issuer, format!("{ISSUER_VAR}-value"));
    }

    /// Fixtures made in one instant each start a cluster in a directory of
    /// their own, so two directories made back to back must differ.
    #[tokio::test]
    async fn directories_made_in_one_instant_are_distinct() {
        for _ in 0..100 {
            let first = TempDir::create("temp-dir-test").await.unwrap();
            let second = TempDir::create("temp-dir-test").await.unwrap();
            assert_ne!(first.path, second.path);
        }
    }

    #[test]
    fn no_variable_leaves_the_containers() {
        assert!(RunningServices::from_lookup(lookup(&[])).unwrap().is_none());
    }

    #[test]
    fn a_partial_set_is_refused_rather_than_falling_back_to_containers() {
        let partial: [&[&str]; 6] = [
            &[POSTGRES_URL_VAR],
            &[OPENFGA_URL_VAR],
            &[ISSUER_VAR],
            &[POSTGRES_URL_VAR, OPENFGA_URL_VAR],
            &[POSTGRES_URL_VAR, ISSUER_VAR],
            &[OPENFGA_URL_VAR, ISSUER_VAR],
        ];
        for set in partial {
            assert!(
                RunningServices::from_lookup(lookup(set)).is_err(),
                "{set:?} was accepted"
            );
        }
    }
}
