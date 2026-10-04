//! Runs the browser stack and browser suites without hand-started services.
//!
//! The stack provisions Postgres, the authorization service and the dev
//! identity provider, then builds the connetto server in this process through
//! `ServerBuilder` and serves the `/sync` route, the login endpoints, the file
//! routes and the development routes on one address, which the suites read
//! from the environment the stack passes them. The suites' own page, the
//! wasm-bindgen-test runner's content server, listens on the page port, and
//! the server lists that origin as the one whose login requests carry
//! credentials.
//!
//! ```text
//! cargo run -p connetto-test-harness --bin connetto-browser-stack
//! cargo run -p connetto-test-harness --bin connetto-browser-stack --shard I/N
//! cargo run -p connetto-test-harness --bin connetto-browser-stack --build-only DIR
//! cargo run -p connetto-test-harness --bin connetto-browser-stack -- <program> [args]
//! ```
//!
//! Bare, it runs the verified-topology step and then the default suites, one
//! at a time through `wasm-pack test --headless --chrome`, each with
//! `WASM_BINDGEN_TEST_TIMEOUT` and a shared `CARGO_TARGET_DIR` unless the
//! caller set them. `--shard I/N` runs the suites whose position lands on `I`
//! round-robin, so N shards cover the list once with no shared stack between
//! them. `--build-only DIR` builds and copies the binaries a shard run needs
//! into DIR. Given a program after `--`, it runs that program against the
//! stack instead of the default suites.
//!
//! `CONNETTO_STACK_SYNC_PORT` moves the server off 7777 and
//! `CONNETTO_STACK_PAGE_PORT` moves the page off 18101. `CONNETTO_SERVER_BIN`
//! names the server binary the verified-topology step spawns and
//! `CONNETTO_TOPOLOGY_BIN` a prebuilt verified-topology binary.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, anyhow};
use axum::Router;
use axum::http::StatusCode;
use axum::routing::{get, post};
use connetto_core::auth::CapabilitySubject;
use connetto_server::builder::{
    ContentSettings, Database, OidcProvider, OpenFga, ServerBuilder, ServerHandle, ServerSchema,
    StoreSpec, TokenKeys,
};
use connetto_server::capability::MintCapabilityKey;
use connetto_server::{CookieSameSite, RuntimeWritableCatalog};
use connetto_test_harness::stack::{
    Deployment, KeyDir, SYNC_PORT_VAR, display_command, ensure_server_bin, exe_name, ports,
    provision, repo_path, require_free, require_success, run_process, strings, wait_for_tcp,
    wait_until_closed,
};
use connetto_test_harness::{Fixture, MockOauth, PUBLICATION, SLOT, with_user};
use diesel_async::AsyncPgConnection;
use tokio::process::Command;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

const LANDING_PATH: &str = "/dev/landing";
/// Where a suite fetches the share key this run minted, standing in for
/// whatever a deployment's own sharing hands a user.
const SHARE_PATH: &str = "/dev/share";
/// Where a suite posts hex file ids whose stored chunks the stack deletes before restarting the server, so the boot reconcile marks those files lost.
const LOSE_CONTENT_PATH: &str = "/dev/lose-content";
const BROWSER_PROVIDER: &str = "dev-idp";
/// The port the wasm-bindgen-test runner's content server listens on unless
/// `CONNETTO_STACK_PAGE_PORT` moves it, the origin the server lists for
/// credentialed logins.
const DEFAULT_PAGE_PORT: u16 = 18101;
const PAGE_PORT_VAR: &str = "CONNETTO_STACK_PAGE_PORT";

const DEPLOYMENT: Deployment = Deployment {
    schema: include_str!("../../../../examples/deployment/schema.sql"),
    roles: include_str!("../../../../examples/deployment/roles.sql"),
    content: include_str!("../../../../examples/wasm-smoke/content.sql"),
    policies: include_str!("../../../../examples/deployment/policies.sql"),
    published: &["orders", "order_lines", "photos"],
    writable: "orders,photos",
};

diesel::table! {
    /// The file server's chunk rows, as the lose-content route reads them.
    _cfs_manifest_chunks (file_id, uploaded_by, position) {
        /// The file the chunk belongs to.
        file_id -> Bytea,
        /// The caller whose manifest names the chunk.
        uploaded_by -> Text,
        /// The chunk's place in the file.
        position -> Integer,
        /// The chunk's content hash, which names its stored bytes.
        chunk_hash -> Bytea,
    }
}

struct Services {
    provisioned: connetto_test_harness::stack::Provisioned,
    idp: MockOauth,
    envs: Vec<(String, String)>,
    addresses: Addresses,
    share: Arc<Share>,
}

/// Every address one run binds and hands its suites, from its two ports. The
/// server serves sync, login and files on one; the test-runner page server
/// keeps its own, and only its origin may carry login credentials.
#[derive(Debug, PartialEq, Eq)]
struct Addresses {
    bind: String,
    page_bind: String,
    sync_ws: String,
    base: String,
    callback: String,
}

impl Addresses {
    fn from_env(var: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let [sync, page] = ports(
            var,
            [(SYNC_PORT_VAR, 7777), (PAGE_PORT_VAR, DEFAULT_PAGE_PORT)],
        )?;
        let base = format!("http://127.0.0.1:{sync}");
        Ok(Self {
            bind: format!("127.0.0.1:{sync}"),
            page_bind: format!("127.0.0.1:{page}"),
            sync_ws: format!("ws://127.0.0.1:{sync}/sync"),
            callback: format!("{base}/auth/callback"),
            base,
        })
    }

    /// What the suites read, the wasm ones at compile time through `option_env!`.
    fn suite_env(&self) -> [(String, String); 3] {
        [
            ("CONNETTO_TEST_WS", &self.sync_ws),
            ("CONNETTO_TEST_AUTH_BASE", &self.base),
            ("WASM_BINDGEN_TEST_ADDRESS", &self.page_bind),
        ]
        .map(|(key, value)| (key.to_owned(), value.clone()))
    }
}

/// The named collaborators the in-process server builds from, held so a
/// restart rebuilds from the same deployment.
struct ServerConfig {
    database: Database,
    schema: ServerSchema,
    keys: TokenKeys,
    openfga: OpenFga,
    provider: OidcProvider,
    writable: RuntimeWritableCatalog,
    content: ContentSettings,
    page_origin: String,
}

impl ServerConfig {
    /// The builder this deployment assembles, ready for `build()`.
    fn builder(&self) -> ServerBuilder {
        ServerBuilder::new(
            self.database.clone(),
            self.schema.clone(),
            self.keys.clone(),
            self.openfga.clone(),
        )
        .slot(SLOT)
        .publication(PUBLICATION)
        .slot_lag_watch(Duration::ZERO)
        .oidc_providers(vec![self.provider.clone()])
        .writable(self.writable.clone())
        .content(Some(self.content.clone()))
        // The suites' page is the only client of the login endpoints, and its
        // runner picks a port this stack pins, so one listed origin suffices.
        // The suites also walk the login with a `fetch`, and the browser presents
        // `Origin: null` on every cross-origin redirect hop of that walk, so the
        // callback hop is answered under that origin too. The cookies are
        // `SameSite: Strict`, so a null-origin request carries none.
        .cors_origins(vec![self.page_origin.clone(), "null".to_owned()])
        .cookie_same_site(CookieSameSite::Strict)
    }
}

/// One running instance, the listener's task, the change stream and the
/// shutdown handle.
struct Running {
    serve: tokio::task::JoinHandle<()>,
    stream: tokio::task::JoinHandle<()>,
    handle: ServerHandle,
}

/// The in-process server, which the lose-content route stops and starts again.
#[derive(Clone)]
struct InProcServer {
    config: Arc<ServerConfig>,
    admin_url: String,
    bind: String,
    share: Arc<Share>,
    state: Arc<tokio::sync::Mutex<Option<Running>>>,
}

impl InProcServer {
    fn new(services: &Services) -> Result<Self> {
        let provisioned = &services.provisioned;
        let keys = &provisioned.keys;
        let admin = provisioned.fixture.admin_url().to_owned();
        let content_dir = provisioned.content_store.path.clone();
        let content = ContentSettings {
            base_url: services.addresses.base.clone(),
            ttl: Duration::from_secs(3600),
            read_ceiling: 1 << 26,
            grace: Duration::from_secs(3600),
            // A per-second sweep so a suite's import never waits on the 3600
            // default cadence.
            cadence: Duration::from_secs(1),
            quota_identity: 0,
            storage_ceiling: 0,
            bandwidth_ceiling: 0,
            bandwidth_window_days: 30,
            warn_fraction: 0.8,
            ceiling_refresh: Duration::from_secs(10),
            owner_pool_size: 10,
            store: StoreSpec::Fs(content_dir.clone()),
            key: fs::read(&keys.content_der)
                .with_context(|| format!("reading {}", keys.content_der.display()))?,
        };
        Ok(Self {
            config: Arc::new(ServerConfig {
                database: Database::new(
                    admin.clone(),
                    with_user(&admin, "connetto_reader", "connetto_reader"),
                ),
                schema: ServerSchema::new(DEPLOYMENT.schema, DEPLOYMENT.policies),
                keys: TokenKeys::from_pem(
                    fs::read(&keys.private)
                        .with_context(|| format!("reading {}", keys.private.display()))?,
                    fs::read(&keys.public)
                        .with_context(|| format!("reading {}", keys.public.display()))?,
                ),
                openfga: OpenFga::new(provisioned.fga_url.clone(), provisioned.fga_store.clone()),
                provider: OidcProvider::Generic(
                    services
                        .idp
                        .oidc_config(BROWSER_PROVIDER, &services.addresses.callback),
                ),
                writable: writable_catalog(DEPLOYMENT.writable),
                content,
                page_origin: format!("http://{}", services.addresses.page_bind),
            }),
            admin_url: admin,
            bind: services.addresses.bind.clone(),
            share: services.share.clone(),
            state: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    /// Build the parts, mount the development routes on them, and serve them
    /// on the stack's one address.
    async fn build_running(&self) -> Result<Running> {
        let parts = self
            .config
            .builder()
            .build()
            .await
            .map_err(|err| anyhow!("assembling the in-process server: {err}"))?;
        let handle = parts.handle.clone();
        let app = parts
            .router
            .merge(dev_routes(self.clone(), (*self.share).clone()));
        let listener = tokio::net::TcpListener::bind(&self.bind)
            .await
            .with_context(|| format!("binding {}", self.bind))?;
        let serve = tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                eprintln!("browser stack server stopped: {err}");
            }
        });
        let stream = tokio::spawn(async move {
            if let Err(err) = parts.change_stream.await {
                eprintln!("the in-process server's change stream stopped: {err}");
            }
        });
        if !wait_for_tcp(&self.bind, Duration::from_secs(20)).await {
            serve.abort();
            stream.abort();
            return Err(anyhow!("the in-process server did not open {}", self.bind));
        }
        Ok(Running {
            serve,
            stream,
            handle,
        })
    }

    /// Build and serve a fresh instance.
    async fn start(&self) -> Result<()> {
        let running = self.build_running().await?;
        let mut slot = self.state.lock().await;
        *slot = Some(running);
        Ok(())
    }

    /// Stops the server, deletes the stored chunks of `file_ids`, and starts it again.
    async fn lose_content_and_restart(&self, file_ids: Vec<Vec<u8>>) -> Result<()> {
        let hashes = self.lost_chunk_hashes(&file_ids).await?;
        if hashes.is_empty() {
            return Err(anyhow!("no stored file matches the ids the request names"));
        }
        let mut slot = self.state.lock().await;
        let Some(running) = slot.take() else {
            return Err(anyhow!("the in-process server is not running"));
        };
        // The listener goes first, so a reconnecting suite cannot land on a
        // manager that is already shutting down.
        running.serve.abort();
        running.handle.shutdown().await;
        running.stream.abort();
        wait_until_closed(&self.bind, Duration::from_secs(10)).await;
        self.delete_chunks(&hashes).await?;
        let running = self.build_running().await?;
        *slot = Some(running);
        Ok(())
    }

    /// The stored chunk hashes the named files' manifests refer to.
    async fn lost_chunk_hashes(&self, file_ids: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        use _cfs_manifest_chunks as chunks;
        use diesel::{ExpressionMethods as _, QueryDsl as _};
        use diesel_async::{AsyncConnection as _, RunQueryDsl as _};

        let mut conn = AsyncPgConnection::establish(&self.admin_url)
            .await
            .context("connecting to name the lost chunks")?;
        chunks::table
            .filter(chunks::file_id.eq_any(file_ids))
            .select(chunks::chunk_hash)
            .distinct()
            .load(&mut conn)
            .await
            .context("reading the files' chunks")
    }

    /// Delete the stored chunks a restart is about to mark lost.
    async fn delete_chunks(&self, hashes: &[Vec<u8>]) -> Result<()> {
        use connetto_file_core::ChunkStore as _;

        let dir = match &self.config.content.store {
            StoreSpec::Fs(dir) => dir,
            StoreSpec::Object(_) => unreachable!("the stack serves a directory store"),
        };
        let store = connetto_file_server::FsStore::new(dir)
            .with_context(|| format!("opening {}", dir.display()))?;
        for hash in hashes {
            let hash: [u8; 32] = hash
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("a stored chunk hash is not 32 bytes"))?;
            store
                .delete_chunk(&connetto_file_core::ChunkHash::from_bytes(hash))
                .await
                .map_err(|err| anyhow!("deleting a lost chunk: {err}"))?;
        }
        Ok(())
    }
}

/// The runtime write policy a comma-separated spec names, each entry a table
/// or a table with its version column.
fn writable_catalog(spec: &str) -> RuntimeWritableCatalog {
    let mut builder = RuntimeWritableCatalog::builder();
    for entry in spec
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        builder = match entry.split_once(':') {
            Some((table, version)) => builder.versioned(table.trim(), version.trim()),
            None => builder.writable(entry),
        };
    }
    builder.build()
}

/// The stack's development routes, mounted on the server's own router.
fn dev_routes(server: InProcServer, share: Share) -> Router {
    // The R90 browser contract fetches with `credentials: "include"`, and a
    // wildcard `Access-Control-Allow-Origin` is hard-rejected with credentials,
    // so the harness echoes the requesting origin instead of `Any`.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_credentials(true)
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request());
    Router::new()
        .route(
            LANDING_PATH,
            get(|| async { "connetto dev landing: the code is in this URL" }),
        )
        // Hand-built rather than serialized, so the stack keeps its
        // dependency list to what it already needs.
        .route(
            SHARE_PATH,
            get(|| async move {
                format!(
                    "{{\"grant\":\"{}\",\"subject\":\"{}\",\"photo\":\"{}\"}}",
                    share.token, share.subject, share.photo
                )
            }),
        )
        .route(
            LOSE_CONTENT_PATH,
            post(|body: String| async move {
                let Some(file_ids) = parse_file_ids(&body).filter(|ids| !ids.is_empty()) else {
                    return (
                        StatusCode::BAD_REQUEST,
                        "the body names hex file ids".to_owned(),
                    );
                };
                match server.lose_content_and_restart(file_ids).await {
                    Ok(()) => (StatusCode::OK, String::new()),
                    Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err:#}")),
                }
            }),
        )
        .layer(cors)
}

/// Parses whitespace-separated 64-character hex file ids.
fn parse_file_ids(body: &str) -> Option<Vec<Vec<u8>>> {
    body.split_whitespace()
        .map(|hex| {
            (hex.len() == 64)
                .then(|| {
                    (0..32)
                        .map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok())
                        .collect::<Option<Vec<u8>>>()
                })
                .flatten()
        })
        .collect()
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
    if let Some(dir) = build_only()? {
        return prebuild(&dir).await;
    }
    let addresses = Addresses::from_env(|name| std::env::var(name).ok())?;
    require_free(&addresses.bind, SYNC_PORT_VAR)?;
    require_free(&addresses.page_bind, PAGE_PORT_VAR)?;

    let (shard, command) = cli_arguments()?;
    let server_bin = ensure_server_bin().await?;
    let services = prepare_services(server_bin, addresses).await?;

    if let Some((program, args)) = command {
        let server = InProcServer::new(&services)?;
        server.start().await?;
        run_process(&program, &args, &services.envs).await?;
    } else {
        // The verified-topology pass is one native run, so only the first
        // shard pays it. A bare invocation is shard 1 of 1 and keeps it.
        if shard.is_none_or(|shard| shard.index == 1) {
            run_verified_topology(&services).await?;
            wait_until_closed(&services.addresses.bind, Duration::from_secs(5)).await;
        }
        let server = InProcServer::new(&services)?;
        server.start().await?;
        run_default_browser_suites(&services, shard).await?;
    }

    Ok(())
}

/// A program with its arguments to run against the stack instead of the
/// default suites.
type StackCommand = (OsString, Vec<OsString>);

/// The directory of `--build-only DIR`, which must be the only argument.
fn build_only() -> Result<Option<PathBuf>> {
    let args: Vec<OsString> = std::env::args_os()
        .skip(1)
        .filter(|arg| arg != "--")
        .collect();
    match args.as_slice() {
        [flag, dir] if flag == "--build-only" => Ok(Some(PathBuf::from(dir))),
        _ if args.iter().any(|arg| arg == "--build-only") => {
            Err(anyhow!("--build-only takes one directory and nothing else"))
        }
        _ => Ok(None),
    }
}

/// Build every native binary a run needs and copy them, with this one, into
/// `dir`, so one CI job builds what every shard then runs.
async fn prebuild(dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("creating {}", dir.display()))?;
    let binaries = [
        (ensure_server_bin().await?, "connetto-server"),
        (build_topology().await?, "verified-topology"),
        (
            std::env::current_exe().context("locating this binary")?,
            "connetto-browser-stack",
        ),
    ];
    for (from, name) in binaries {
        let to = dir.join(exe_name(name));
        tokio::fs::copy(&from, &to)
            .await
            .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    }
    Ok(())
}

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

async fn prepare_services(server_bin: PathBuf, addresses: Addresses) -> Result<Services> {
    let provisioned = provision(&DEPLOYMENT, "connetto-browser-stack", None).await?;
    let share = seed_share(&provisioned.fixture, &provisioned.keys).await?;
    let idp = MockOauth::start().await;
    let schema_file = repo_path(&["examples", "deployment", "schema.sql"])?;
    let policies_file = repo_path(&["examples", "deployment", "policies.sql"])?;

    let mut envs = addresses.suite_env().to_vec();
    envs.extend(
        [
            ("CONNETTO_TEST_PROVIDER", BROWSER_PROVIDER.to_owned()),
            (
                "CONNETTO_TEST_PG_DDL_FILE",
                schema_file.display().to_string(),
            ),
            (
                "CONNETTO_TEST_PG_POLICIES_FILE",
                policies_file.display().to_string(),
            ),
            ("CONNETTO_SERVER_BIN", server_bin.display().to_string()),
        ]
        .map(|(key, value)| (key.to_owned(), value)),
    );
    // The real binary the verified-topology run spawns reads the same
    // single-port contract the in-process server builds from.
    envs.extend(provisioned.server_env(&DEPLOYMENT, &addresses.bind, &addresses.base));
    envs.extend(idp.env_pairs(BROWSER_PROVIDER, &addresses.callback));

    Ok(Services {
        provisioned,
        idp,
        envs,
        addresses,
        share: Arc::new(share),
    })
}

/// The verified-topology run, or with `run` false the build of the binary it runs.
fn topology_args(run: bool) -> Vec<OsString> {
    let mut args = strings(&[
        "+stable",
        "test",
        "--release",
        "-p",
        "connetto-client",
        "--all-features",
        "--test",
        "it",
    ]);
    if run {
        args.extend(strings(&["--", "verified_topology", "--ignored"]));
    } else {
        args.extend(strings(&[
            "--no-run",
            "--message-format=json-render-diagnostics",
        ]));
    }
    args
}

/// Build the verified-topology test binary and return its path.
async fn build_topology() -> Result<PathBuf> {
    let args = topology_args(false);
    let display = display_command(OsStr::new("cargo"), &args);
    eprintln!("running {display}");
    let output = Command::new("cargo")
        .args(&args)
        .stderr(Stdio::inherit())
        .output()
        .await
        .with_context(|| format!("starting {display}"))?;
    require_success(&display, output.status)?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|message| message["target"]["name"] == "it")
        .and_then(|message| message["executable"].as_str().map(PathBuf::from))
        .ok_or_else(|| anyhow!("{display} reported no test executable"))
}

/// Run the verified topology, from the binary `CONNETTO_TOPOLOGY_BIN` names
/// when a build job made it, otherwise through cargo.
async fn run_verified_topology(services: &Services) -> Result<()> {
    match std::env::var_os("CONNETTO_TOPOLOGY_BIN") {
        Some(bin) => {
            let args = strings(&["verified_topology", "--ignored"]);
            run_process(&bin, &args, &services.envs).await
        }
        None => run_process(OsStr::new("cargo"), &topology_args(true), &services.envs).await,
    }
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
    let mut suite_args = vec![
        strings(&[
            "test",
            "--headless",
            "--chrome",
            "crates/connetto-file-client",
            "--lib",
            "--no-default-features",
        ]),
        strings(&[
            "test",
            "--headless",
            "--chrome",
            "crates/connetto-web",
            "--lib",
        ]),
    ];
    for test in test_files(&["crates", "connetto-web", "tests"])? {
        suite_args.push(per_test_args("crates/connetto-web", test));
    }
    for test in test_files(&["examples", "wasm-smoke", "tests"])? {
        suite_args.push(per_test_args("examples/wasm-smoke", test));
    }
    for test in test_files(&["examples", "yew-web-demo", "tests"])? {
        suite_args.push(per_test_args("examples/yew-web-demo", test));
    }
    for test in test_files(&["examples", "dioxus-web-demo", "tests"])? {
        suite_args.push(per_test_args("examples/dioxus-web-demo", test));
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

/// A minted share key, the row only its holder can see, and the token a tab
/// presents to claim it.
#[derive(Clone)]
struct Share {
    subject: String,
    token: String,
    photo: String,
}

/// Mint one share key, and seed a photo owned by it.
///
/// The demo's `photos_p` admits a row whose owner is among the caller's keys,
/// so a row owned by the key's own rendering is reachable by its holder and
/// by nobody else. The sharer writing that row is the application's business,
/// which here is this fixture: connetto mints the key and the deployment
/// decides what it names.
///
/// The token is minted with the same key material and the default issuer and
/// audience the server binary runs with, so the handshake it is presented to
/// resolves it into the caller's subject set.
async fn seed_share(fixture: &Fixture, keys: &KeyDir) -> Result<Share> {
    let subject = <String as MintCapabilityKey>::mint();
    let photo = uuid::Uuid::new_v4().to_string();
    let order = uuid::Uuid::new_v4().to_string();
    fixture
        .setup(&[
            &format!(
                "INSERT INTO orders (id, owner_id, quantity) \
                 VALUES ('{order}', '{subject}', 1)"
            ),
            &format!(
                "INSERT INTO photos (id, order_id, owner_id, content_id, content_state) \
                 VALUES ('{photo}', '{order}', '{subject}', '\\x00', NULL)"
            ),
        ])
        .await;
    let private = tokio::fs::read(&keys.private)
        .await
        .with_context(|| format!("reading {}", keys.private.display()))?;
    let public = tokio::fs::read(&keys.public)
        .await
        .with_context(|| format!("reading {}", keys.public.display()))?;
    let config = connetto_server::AuthConfig::default();
    let authority = connetto_server::TokenAuthority::from_ed_pem(&private, &public, &config)
        .map_err(|err| anyhow!("building the token authority: {err}"))?;
    let token = authority
        .mint_capability(
            &CapabilitySubject::<String>::new(subject.clone()),
            SystemTime::now(),
            config.capability_ttl(),
        )
        .map_err(|err| anyhow!("minting the demo share key: {err}"))?;
    Ok(Share {
        subject,
        token,
        photo,
    })
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::{Addresses, RETRYABLE_SIGNATURES, echo_watching, parse_shard};

    fn read(pairs: &[(&str, &str)]) -> Result<Addresses> {
        Addresses::from_env(|name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    /// A port override moves every address built on that port and no other,
    /// and the suites are handed the ports the stack binds, so an auth
    /// callback or suite base left on a default would send a browser to a
    /// closed port.
    #[test]
    fn each_port_override_moves_only_its_own_addresses() {
        assert_eq!(
            read(&[]).expect("defaults"),
            Addresses {
                bind: "127.0.0.1:7777".to_owned(),
                page_bind: "127.0.0.1:18101".to_owned(),
                sync_ws: "ws://127.0.0.1:7777/sync".to_owned(),
                base: "http://127.0.0.1:7777".to_owned(),
                callback: "http://127.0.0.1:7777/auth/callback".to_owned(),
            }
        );
        assert_eq!(
            read(&[("CONNETTO_STACK_SYNC_PORT", "27777")]).expect("sync only"),
            Addresses {
                bind: "127.0.0.1:27777".to_owned(),
                page_bind: "127.0.0.1:18101".to_owned(),
                sync_ws: "ws://127.0.0.1:27777/sync".to_owned(),
                base: "http://127.0.0.1:27777".to_owned(),
                callback: "http://127.0.0.1:27777/auth/callback".to_owned(),
            }
        );
        let moved = read(&[
            ("CONNETTO_STACK_SYNC_PORT", "27777"),
            ("CONNETTO_STACK_PAGE_PORT", "28101"),
        ])
        .expect("both");
        assert_eq!(
            moved,
            Addresses {
                bind: "127.0.0.1:27777".to_owned(),
                page_bind: "127.0.0.1:28101".to_owned(),
                sync_ws: "ws://127.0.0.1:27777/sync".to_owned(),
                base: "http://127.0.0.1:27777".to_owned(),
                callback: "http://127.0.0.1:27777/auth/callback".to_owned(),
            }
        );
        assert_eq!(
            moved.suite_env(),
            [
                ("CONNETTO_TEST_WS", "ws://127.0.0.1:27777/sync"),
                ("CONNETTO_TEST_AUTH_BASE", "http://127.0.0.1:27777"),
                ("WASM_BINDGEN_TEST_ADDRESS", "127.0.0.1:28101"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
        );
    }

    /// Each port names its own listener, so a value that is no port, or one
    /// that lands on another listener's port, stops the run before any bind.
    #[test]
    fn ports_that_collide_or_are_not_ports_are_refused() {
        let refused: [&[(&str, &str)]; 6] = [
            &[("CONNETTO_STACK_SYNC_PORT", "18101")],
            &[("CONNETTO_STACK_PAGE_PORT", "7777")],
            &[("CONNETTO_STACK_SYNC_PORT", "0")],
            &[("CONNETTO_STACK_SYNC_PORT", "65536")],
            &[("CONNETTO_STACK_PAGE_PORT", "")],
            &[("CONNETTO_STACK_PAGE_PORT", "http://127.0.0.1:28101")],
        ];
        for pairs in refused {
            assert!(read(pairs).is_err(), "{pairs:?} was accepted");
        }
    }

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
