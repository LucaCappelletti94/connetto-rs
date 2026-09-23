//! Runs the browser stack and browser suites without hand-started services.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, Result, anyhow};
use axum::routing::get;
use connetto_core::auth::CapabilitySubject;
use connetto_server::capability::MintCapabilityKey;
use connetto_server::{
    AuthConfig, AuthService, CookieSameSite, DbAuthStore, DefaultUuidResolver, GenericOidcProvider,
    ProviderRegistry, RedirectPolicy, RequestGuard, TokenAuthority, auth_router,
    connetto_auth_tables,
};
use connetto_test_harness::stack::{
    ChildGuard, Deployment, KeyDir, Provisioned, TaskGuard, display_command, ensure_server_bin,
    exe_name, provision, repo_path, require_free, require_success, run_process, spawn_server,
    strings, wait_for_tcp, wait_until_closed,
};
use connetto_test_harness::{Fixture, MockOauth};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::bb8::Pool;
use tokio::process::Command;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

const SYNC_BIND: &str = "127.0.0.1:7777";
const SYNC_WS: &str = "ws://127.0.0.1:7777/";
const AUTH_BIND: &str = "127.0.0.1:18099";
const AUTH_BASE: &str = "http://127.0.0.1:18099";
const CONTENT_BIND: &str = "127.0.0.1:18100";
const CONTENT_BASE: &str = "http://127.0.0.1:18100";
const CALLBACK: &str = "http://127.0.0.1:18099/auth/callback";
const LANDING_PATH: &str = "/dev/landing";
/// Where a suite fetches the share key this run minted, standing in for
/// whatever a deployment's own sharing hands a user.
const SHARE_PATH: &str = "/dev/share";
const CALLER_FUNCTION: &str = "current_app_user";
const BROWSER_PROVIDER: &str = "dev-idp";

const DEPLOYMENT: Deployment = Deployment {
    schema: include_str!("../../../../examples/deployment/schema.sql"),
    roles: include_str!("../../../../examples/deployment/roles.sql"),
    content: include_str!("../../../../examples/wasm-smoke/content.sql"),
    policies: include_str!("../../../../examples/deployment/policies.sql"),
    published: &["orders", "order_lines", "photos"],
    writable: "orders,photos",
};
connetto_auth_tables!(String, diesel::sql_types::Text);

struct Services {
    provisioned: Provisioned,
    idp: MockOauth,
    server_bin: PathBuf,
    envs: Vec<(String, String)>,
    share: Arc<Share>,
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
    require_free(SYNC_BIND)?;
    require_free(AUTH_BIND)?;
    require_free(CONTENT_BIND)?;

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

async fn prepare_services(server_bin: PathBuf) -> Result<Services> {
    let provisioned = provision(&DEPLOYMENT, "connetto-browser-stack").await?;
    let share = seed_share(&provisioned.fixture, &provisioned.keys).await?;
    let idp = MockOauth::start().await;
    let schema_file = repo_path(&["examples", "deployment", "schema.sql"])?;
    let policies_file = repo_path(&["examples", "deployment", "policies.sql"])?;

    let mut envs = provisioned.server_env(&DEPLOYMENT, SYNC_BIND, AUTH_BIND, CONTENT_BASE);
    envs.extend(
        [
            ("CONNETTO_CONTENT_SWEEP_SECS", "1".to_owned()),
            ("CONNETTO_TEST_CONTENT_BASE", CONTENT_BASE.to_owned()),
            ("CONNETTO_CALLER_FUNCTION", CALLER_FUNCTION.to_owned()),
            ("CONNETTO_SLOT_LAG_SECS", "0".to_owned()),
            ("CONNETTO_TEST_AUTH_BASE", AUTH_BASE.to_owned()),
            ("CONNETTO_TEST_WS", SYNC_WS.to_owned()),
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
    envs.extend(idp.env_pairs(BROWSER_PROVIDER, CALLBACK));

    Ok(Services {
        provisioned,
        idp,
        server_bin,
        envs,
        share: Arc::new(share),
    })
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
    let private = tokio::fs::read(&services.provisioned.keys.private)
        .await
        .with_context(|| format!("reading {}", services.provisioned.keys.private.display()))?;
    let public = tokio::fs::read(&services.provisioned.keys.public)
        .await
        .with_context(|| format!("reading {}", services.provisioned.keys.public.display()))?;
    let authority = TokenAuthority::from_ed_pem(&private, &public, &config)
        .map_err(|err| anyhow!("loading the browser signing keypair: {err}"))?;
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(
        services.provisioned.fixture.admin_url(),
    );
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
    // The R90 browser contract fetches with `credentials: "include"`, and a
    // wildcard `Access-Control-Allow-Origin` is hard-rejected with credentials,
    // so the harness echoes the requesting origin instead of `Any`.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_credentials(true)
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request());
    // The share route stands in for whatever a deployment's sharing does. A
    // suite fetches it rather than reading a value baked at compile time,
    // because a stale binary would otherwise carry the previous run's key
    // while the database holds this run's row.
    let share = services.share.clone();
    let app = auth_router(
        service,
        registry,
        RedirectPolicy::default(),
        CookieSameSite::Strict,
    )
    .route(
        LANDING_PATH,
        get(|| async { "connetto dev landing: the code is in this URL" }),
    )
    .route(
        SHARE_PATH,
        get(|| async move {
            // Hand-built rather than serialized, so the stack keeps its
            // dependency list to what it already needs.
            format!(
                "{{\"grant\":\"{}\",\"subject\":\"{}\",\"photo\":\"{}\"}}",
                share.token, share.subject, share.photo
            )
        }),
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
    // The child's auth listener carries the file routes the suites fetch.
    spawn_server(
        &services.server_bin,
        &services.envs,
        SYNC_BIND,
        CONTENT_BIND,
    )
    .await
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
    let config = AuthConfig::default();
    let authority = TokenAuthority::from_ed_pem(&private, &public, &config)
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
