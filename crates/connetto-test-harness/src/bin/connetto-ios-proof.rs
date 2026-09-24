//! Deploys `examples/dioxus-desktop-demo` to an iOS simulator or a paired
//! iPhone or iPad and walks R88's proof on it, which is sign in, sync, write
//! offline and upload on reconnect.
//!
//! It runs on a Mac as the command of `connetto-demo-stack`, which provides the
//! stack and the environment naming it.
//!
//! ```text
//! cargo build -p connetto-test-harness --bin connetto-ios-proof
//! cargo run -p connetto-test-harness --bin connetto-demo-stack -- \
//!   target/debug/connetto-ios-proof [--simulator UDID | --device UDID --identity SHA1] [--app PATH]
//! ```
//!
//! A simulator build links the keychain entitlements into the executable as
//! Xcode does, under the team prefix of the Mac's Apple Development
//! certificate. A device build is signed with the identity
//! `connetto-ios-signing` prepared, whose keychain the driver unlocks, and a
//! device run needs the stack on a host the device reaches, which on the
//! maintainer's tailnet is `CONNETTO_STACK_PUBLIC_HOST` with TLS. The demo and
//! its login page are read and driven through the `WebKit` remote inspector,
//! reached with `ios_webkit_debug_proxy`, which must be on `PATH`. The app
//! dials the sync server through a relay the driver owns, and stopping the
//! relay is the offline step. Evidence lands under
//! `target/ios-proof/<udid>-<millis>/`, screenshots and the app log on a
//! simulator and the demo's page text on a device, where `devicectl` takes
//! no screenshots.
//!
//! Android's killed-process step has no counterpart here, since the session
//! that catches the redirect dies with the process that opened it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use connetto_test_harness::demo::{order_count, wait_for_count};
use connetto_test_harness::inspector::{PageSession, list_pages};
use connetto_test_harness::ios_signing;
use connetto_test_harness::relay::Relay;
use connetto_test_harness::stack::{now_millis, repo_path};
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep};

const BUNDLE: &str = "dev.connetto.dioxusdemo";
const PROCESS: &str = "connetto-dioxus-desktop-demo";
const DEMO_DIR: [&str; 2] = ["examples", "dioxus-desktop-demo"];
const APP: &str = "target/dx/connetto-dioxus-desktop-demo/debug/ios/ConnettoDioxusDesktopDemo.app";
const USER: &str = "alice";
/// The simulator a run uses when none is named.
const DEFAULT_SIMULATOR: &str = "iPhone 17 Pro";

#[tokio::main]
async fn main() -> Result<()> {
    let stack = Stack::from_env()?;
    let (target, app) = cli_arguments().await?;
    let evidence =
        repo_path(&["target", "ios-proof"])?.join(format!("{}-{}", target.udid(), now_millis()));
    tokio::fs::create_dir_all(&evidence)
        .await
        .with_context(|| format!("creating {}", evidence.display()))?;
    eprintln!("evidence in {}", evidence.display());

    let started = std::time::SystemTime::now();
    let outcome = prove(&target, app, &stack, &evidence).await;
    if let Target::Simulator { .. } = &target {
        let log = target.app_log(started).await.unwrap_or_default();
        tokio::fs::write(evidence.join("app-log.txt"), log)
            .await
            .context("writing the app log")?;
    }
    if let Err(err) = &outcome {
        eprintln!("proof failed: {err:#}");
    }
    let _ = target.terminate().await;
    outcome
}

/// What `connetto-demo-stack` tells its command.
struct Stack {
    server: String,
    auth_origin: String,
    pg_url: String,
    issuer: String,
}

impl Stack {
    fn from_env() -> Result<Self> {
        let var = |key: &str| {
            std::env::var(key)
                .with_context(|| format!("{key} is unset, run under connetto-demo-stack"))
        };
        Ok(Self {
            server: var("CONNETTO_DEMO_SERVER")?,
            auth_origin: var("CONNETTO_DEMO_AUTH_ORIGIN")?,
            pg_url: var("CONNETTO_DEMO_PG")?,
            issuer: var("CONNETTO_DEMO_ISSUER")?,
        })
    }

    /// The host clients reach the sync server on.
    fn host(&self) -> Result<&str> {
        self.server
            .rsplit_once(':')
            .map(|(host, _)| host)
            .ok_or_else(|| anyhow!("CONNETTO_DEMO_SERVER names no port: {}", self.server))
    }
}

async fn prove(
    target: &Target,
    app: Option<PathBuf>,
    stack: &Stack,
    evidence: &Path,
) -> Result<()> {
    let app = match app {
        Some(app) => app,
        None => target.build(evidence).await?,
    };
    // A device dials the relay across the network, a simulator on the Mac's
    // loopback.
    let (listen, host) = match target {
        Target::Simulator { .. } => ("127.0.0.1:0", "127.0.0.1"),
        Target::Device { .. } => ("0.0.0.0:0", stack.host()?),
    };
    let mut relay = Relay::start(listen, &stack.server).await?;
    let server = format!("{host}:{}", relay.address().port());

    step("install");
    target.install(&app).await?;
    let mut inspector = Inspector::start(target, evidence).await?;

    step("sign in");
    target
        .launch(&[
            ("CONNETTO_DEMO_SERVER", &server),
            ("CONNETTO_DEMO_AUTH_ORIGIN", &stack.auth_origin),
            ("CONNETTO_DEMO_PG", &stack.pg_url),
        ])
        .await?;
    let login_prefix = format!("{}/authorize?", stack.issuer);
    let mut app = sign_in(target, &mut inspector, &login_prefix, evidence).await?;
    target.record(&mut app, evidence, "signed-in").await?;

    step("sync a backend write");
    let before = order_count(&stack.pg_url).await?;
    app.click("Insert via Postgres (backend writer)").await?;
    wait_for_count(&stack.pg_url, before + 1).await?;
    app.wait_for_text(
        &format!("COUNT(*) pushed by the server: {}", before + 1),
        Duration::from_secs(30),
    )
    .await?;
    target.record(&mut app, evidence, "synced").await?;

    step("write offline");
    relay.stop().await;
    app.wait_for_text("status: reconnecting", Duration::from_secs(60))
        .await?;
    let offline = order_count(&stack.pg_url).await?;
    app.click("Insert locally (client write)").await?;
    sleep(Duration::from_secs(3)).await;
    if order_count(&stack.pg_url).await? != offline {
        bail!("an offline write reached Postgres");
    }
    target.record(&mut app, evidence, "offline-write").await?;

    step("upload on reconnect");
    relay.resume().await?;
    app.wait_for_outcome(
        "applied",
        &[
            "rejected",
            "conflicted",
            "session expired",
            "connection closed",
        ],
        Duration::from_secs(90),
    )
    .await?;
    wait_for_count(&stack.pg_url, offline + 1).await?;
    target.record(&mut app, evidence, "uploaded").await?;

    step("sign out");
    sign_out(&mut app).await?;
    target.record(&mut app, evidence, "signed-out").await?;
    eprintln!("inspector proxy restarts: {}", inspector.restarts);
    step("proof complete");
    Ok(())
}

/// Sign in and return the demo's page. A device keeps keychain items across
/// a reinstall, so a credential from an earlier run can sign the demo in
/// without a login page, which then signs out first.
async fn sign_in(
    target: &Target,
    inspector: &mut Inspector,
    login_prefix: &str,
    evidence: &Path,
) -> Result<PageSession> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut demo = String::from("no demo page");
    loop {
        if let Some(mut login) = inspector
            .try_page(|url| url.starts_with(login_prefix))
            .await?
        {
            target.screenshot(evidence, "login-page").await?;
            submit_login(&mut login).await?;
            let mut app = inspector.page(|url| url.starts_with("dioxus://")).await?;
            app.wait_for_text("status: connected", Duration::from_secs(90))
                .await?;
            return Ok(app);
        }
        if let Some(mut app) = inspector
            .try_page(|url| url.starts_with("dioxus://"))
            .await?
        {
            let text = app.page_text().await?;
            if text.contains("status: connected") {
                eprintln!("an earlier credential signed the demo in, signing out first");
                sign_out(&mut app).await?;
            }
            demo = text.split_whitespace().collect::<Vec<_>>().join(" ");
        }
        if Instant::now() >= deadline {
            let shown: String = demo.chars().take(400).collect();
            bail!(
                "neither the login page nor a signed-in demo appeared within 90s, the demo \
                 showed {shown:?}, {}",
                inspector.state()
            );
        }
        inspector.keep_alive().await?;
        sleep(Duration::from_secs(1)).await;
    }
}

async fn sign_out(app: &mut PageSession) -> Result<()> {
    app.click("Sign out (wipe local replica)").await?;
    app.wait_for_outcome(
        "Signing in",
        &["logout error", "not yet synced"],
        Duration::from_secs(60),
    )
    .await
}

/// Fill the dev user into the identity provider's form and submit it. The
/// authentication session catches the final redirect itself, so no trusted
/// input is needed.
async fn submit_login(login: &mut PageSession) -> Result<()> {
    let script = format!(
        "(() => {{ const u = document.querySelector('input[name=username]'); if (!u) return false; u.value = {}; u.form.submit(); return true; }})()",
        serde_json::Value::String(USER.to_owned())
    );
    if login.evaluate(&script).await? == true {
        Ok(())
    } else {
        bail!("the login page has no username field")
    }
}

fn step(name: &str) {
    eprintln!("== {name}");
}

/// `--simulator`, or `--device` with `--identity`, and `--app`.
async fn cli_arguments() -> Result<(Target, Option<PathBuf>)> {
    let mut simulator = None;
    let mut device = None;
    let mut identity = None;
    let mut app = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--simulator" => simulator = Some(args.next().context("--simulator takes a UDID")?),
            "--device" => device = Some(args.next().context("--device takes a UDID")?),
            "--identity" => identity = Some(args.next().context("--identity takes a SHA-1")?),
            "--app" => app = Some(PathBuf::from(args.next().context("--app takes a path")?)),
            other => bail!("unknown argument {other:?}"),
        }
    }
    let target = match (simulator, device, identity) {
        (simulator, None, None) => Target::simulator(simulator).await?,
        (None, Some(udid), Some(identity)) => Target::Device { udid, identity },
        (None, Some(_), None) => {
            bail!("--device needs the --identity connetto-ios-signing printed")
        }
        _ => bail!("give either --simulator or --device, not both"),
    };
    Ok((target, app))
}

/// Where the proof runs.
enum Target {
    Simulator { udid: String },
    Device { udid: String, identity: String },
}

impl Target {
    /// The named simulator, or the default one, booted.
    async fn simulator(udid: Option<String>) -> Result<Self> {
        let udid = match udid {
            Some(udid) => udid,
            None => default_simulator().await?,
        };
        let _ = xcrun(&["simctl", "boot", &udid]).await;
        xcrun(&["simctl", "bootstatus", &udid, "-b"]).await?;
        Ok(Self::Simulator { udid })
    }

    fn udid(&self) -> &str {
        match self {
            Self::Simulator { udid } | Self::Device { udid, .. } => udid,
        }
    }

    async fn build(&self, evidence: &Path) -> Result<PathBuf> {
        let demo = repo_path(&DEMO_DIR)?;
        step("build");
        let mut dx = Command::new("dx");
        dx.current_dir(&demo).args([
            "build",
            "--ios",
            "--no-default-features",
            "--features",
            "mobile",
        ]);
        match self {
            Self::Simulator { .. } => {
                let entitlements = evidence.join("simulator-entitlements.plist");
                tokio::fs::write(&entitlements, simulator_entitlements(&team_prefix().await?))
                    .await
                    .context("writing the simulator entitlements")?;
                dx.args(["--target", "aarch64-apple-ios-sim"]).env(
                    "CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS",
                    format!(
                        "-C link-arg=-Wl,-sectcreate,__TEXT,__entitlements,{}",
                        entitlements.display()
                    ),
                );
            }
            Self::Device { identity, .. } => {
                ios_signing::unlock().await?;
                dx.args([
                    "--target",
                    "aarch64-apple-ios",
                    "--codesign",
                    "--apple-team-id",
                    identity,
                ]);
            }
        }
        let status = dx.status().await.context("starting dx")?;
        if !status.success() {
            bail!("dx build failed with {status}");
        }
        let app = demo.join(APP);
        if let Self::Device { identity, .. } = self {
            sign_bundled_frameworks(&app, identity, evidence).await?;
        }
        Ok(app)
    }

    /// Install the app afresh.
    async fn install(&self, app: &Path) -> Result<()> {
        let app = app.display().to_string();
        match self {
            Self::Simulator { udid } => {
                let _ = xcrun(&["simctl", "uninstall", udid, BUNDLE]).await;
                xcrun(&["simctl", "keychain", udid, "reset"]).await?;
                xcrun(&["simctl", "install", udid, &app]).await.map(drop)
            }
            Self::Device { udid, .. } => {
                let _ = xcrun(&[
                    "devicectl",
                    "device",
                    "uninstall",
                    "app",
                    "--device",
                    udid,
                    BUNDLE,
                ])
                .await;
                xcrun(&[
                    "devicectl",
                    "device",
                    "install",
                    "app",
                    "--device",
                    udid,
                    &app,
                ])
                .await
                .map(drop)
            }
        }
    }

    /// Launch the demo with `env` in its environment.
    async fn launch(&self, env: &[(&str, &str)]) -> Result<()> {
        match self {
            Self::Simulator { udid } => {
                let output = Command::new("xcrun")
                    .args(["simctl", "launch", udid, BUNDLE])
                    .envs(
                        env.iter()
                            .map(|(key, value)| (format!("SIMCTL_CHILD_{key}"), *value)),
                    )
                    .output()
                    .await
                    .context("starting xcrun simctl launch")?;
                if !output.status.success() {
                    bail!(
                        "launching the demo failed: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                }
                Ok(())
            }
            Self::Device { udid, .. } => {
                let env = serde_json::Value::Object(
                    env.iter()
                        .map(|(key, value)| ((*key).to_owned(), (*value).into()))
                        .collect(),
                )
                .to_string();
                xcrun(&[
                    "devicectl",
                    "device",
                    "process",
                    "launch",
                    "--device",
                    udid,
                    "--terminate-existing",
                    "--environment-variables",
                    &env,
                    BUNDLE,
                ])
                .await
                .map(drop)
            }
        }
    }

    async fn terminate(&self) -> Result<()> {
        match self {
            Self::Simulator { udid } => xcrun(&["simctl", "terminate", udid, BUNDLE])
                .await
                .map(drop),
            Self::Device { .. } => Ok(()),
        }
    }

    /// A screenshot on a simulator. `devicectl` takes none on a device.
    async fn screenshot(&self, evidence: &Path, name: &str) -> Result<()> {
        match self {
            Self::Simulator { udid } => {
                let path = evidence.join(format!("{name}.png"));
                xcrun(&[
                    "simctl",
                    "io",
                    udid,
                    "screenshot",
                    &path.display().to_string(),
                ])
                .await
                .map(drop)
            }
            Self::Device { .. } => Ok(()),
        }
    }

    /// Keep a step's evidence, a screenshot and the demo's page text.
    async fn record(&self, app: &mut PageSession, evidence: &Path, name: &str) -> Result<()> {
        self.screenshot(evidence, name).await?;
        tokio::fs::write(evidence.join(format!("{name}.txt")), app.page_text().await?)
            .await
            .with_context(|| format!("writing the {name} page text"))
    }

    /// The demo's log lines since `since`, on a simulator.
    async fn app_log(&self, since: std::time::SystemTime) -> Result<String> {
        let seconds = since.elapsed().unwrap_or_default().as_secs() + 5;
        xcrun(&[
            "simctl",
            "spawn",
            self.udid(),
            "log",
            "show",
            "--last",
            &format!("{seconds}s"),
            "--style",
            "compact",
            "--predicate",
            &format!("process == \"{PROCESS}\""),
        ])
        .await
    }
}

/// Sign every framework `dx` bundled, then the app again with its own
/// entitlements, in the order Xcode signs, and verify the result so an
/// unsigned bundle is named here rather than by the install. A stand-in
/// awaiting Dioxus, whose dx 0.7.10 leaves the frameworks it bundles unsigned
/// so a device refuses the install. Deleted once a Dioxus release signs them.
async fn sign_bundled_frameworks(app: &Path, identity: &str, evidence: &Path) -> Result<()> {
    let entitlements = evidence.join("device-entitlements.plist");
    let extracted = Command::new("codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(app)
        .output()
        .await
        .context("reading the app's entitlements")?;
    tokio::fs::write(&entitlements, &extracted.stdout)
        .await
        .context("writing the app's entitlements")?;
    let mut frameworks = tokio::fs::read_dir(app.join("Frameworks"))
        .await
        .context("listing the app's frameworks")?;
    while let Some(framework) = frameworks.next_entry().await? {
        codesign(&["--force", "--sign", identity], &framework.path()).await?;
    }
    codesign(
        &[
            "--force",
            "--sign",
            identity,
            "--entitlements",
            &entitlements.display().to_string(),
        ],
        app,
    )
    .await?;
    codesign(&["--verify", "--deep", "--strict", "--verbose=2"], app).await
}

async fn codesign(args: &[&str], path: &Path) -> Result<()> {
    let output = Command::new("codesign")
        .args(args)
        .arg(path)
        .output()
        .await
        .context("starting codesign")?;
    if !output.status.success() {
        bail!(
            "codesign {} {} failed: {}",
            args.first().copied().unwrap_or_default(),
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

async fn xcrun(args: &[&str]) -> Result<String> {
    let output = Command::new("xcrun")
        .args(args)
        .output()
        .await
        .context("starting xcrun")?;
    if !output.status.success() {
        bail!(
            "xcrun {} failed: {}",
            args.iter().take(3).copied().collect::<Vec<_>>().join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The organizational unit of the Mac's Apple Development certificate, which
/// is the team prefix of the app's identifier.
async fn team_prefix() -> Result<String> {
    let pem = Command::new("security")
        .args(["find-certificate", "-c", "Apple Development", "-p"])
        .output()
        .await
        .context("starting security")?;
    if !pem.status.success() {
        bail!("no Apple Development certificate in the keychain");
    }
    let mut openssl = Command::new("openssl")
        .args(["x509", "-noout", "-subject"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("starting openssl")?;
    let mut stdin = openssl.stdin.take().context("openssl stdin")?;
    tokio::io::AsyncWriteExt::write_all(&mut stdin, &pem.stdout)
        .await
        .context("feeding openssl")?;
    drop(stdin);
    let subject = String::from_utf8(openssl.wait_with_output().await?.stdout)
        .context("reading the certificate subject")?;
    organizational_unit(&subject)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("the certificate subject names no team: {subject}"))
}

/// The `OU` of a certificate subject line.
fn organizational_unit(subject: &str) -> Option<&str> {
    subject
        .split([',', '/'])
        .find_map(|part| part.trim().strip_prefix("OU="))
        .map(str::trim)
}

fn simulator_entitlements(team: &str) -> String {
    let id = format!("{team}.{BUNDLE}");
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>application-identifier</key>
    <string>{id}</string>
    <key>keychain-access-groups</key>
    <array>
        <string>{id}</string>
    </array>
</dict>
</plist>
"#
    )
}

/// The first available simulator named [`DEFAULT_SIMULATOR`].
async fn default_simulator() -> Result<String> {
    let listing = xcrun(&["simctl", "list", "devices", "available", "--json"]).await?;
    let listing: serde_json::Value =
        serde_json::from_str(&listing).context("parsing the simulator list")?;
    listing["devices"]
        .as_object()
        .into_iter()
        .flat_map(|runtimes| runtimes.values())
        .filter_map(serde_json::Value::as_array)
        .flatten()
        .find(|device| device["name"] == DEFAULT_SIMULATOR)
        .and_then(|device| device["udid"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("no available simulator named {DEFAULT_SIMULATOR}"))
}

/// `ios_webkit_debug_proxy` for one simulator or device, stopped when dropped.
/// Its output is appended to `ios_webkit_debug_proxy.log` in the evidence.
struct Inspector {
    proxy: Child,
    list_port: u16,
    /// The `deviceId` the proxy lists the target under.
    device: String,
    /// The simulators' inspector socket, which a device run does not use.
    socket: Option<String>,
    log: PathBuf,
    restart_at: Instant,
    restarts: u32,
    /// What the latest search saw, for the error when nothing matches.
    seen: String,
}

/// How long page searches wait before restarting the proxy, which does not
/// reconnect when the inspector it talks to drops it.
const PROXY_RESTART: Duration = Duration::from_secs(15);

impl Inspector {
    async fn start(target: &Target, evidence: &Path) -> Result<Self> {
        let (device, socket) = match target {
            Target::Simulator { .. } => (
                "SIMULATOR".to_owned(),
                Some(simulator_inspector_socket().await?),
            ),
            Target::Device { udid, .. } => (udid.clone(), None),
        };
        let log = evidence.join("ios_webkit_debug_proxy.log");
        let list_port = free_port()?;
        let proxy = spawn_proxy(list_port, socket.as_deref(), &log)?;
        Ok(Self {
            proxy,
            list_port,
            device,
            socket,
            log,
            restart_at: Instant::now() + PROXY_RESTART,
            restarts: 0,
            seen: "nothing yet".to_owned(),
        })
    }

    /// A session on the first page whose URL `wanted` accepts, waiting up to
    /// ninety seconds for it to appear.
    async fn page(&mut self, wanted: impl Fn(&str) -> bool) -> Result<PageSession> {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(page) = self.try_page(&wanted).await? {
                return Ok(page);
            }
            if Instant::now() >= deadline {
                bail!(
                    "no page on {} matched within 90s, {}",
                    self.device,
                    self.state()
                );
            }
            self.keep_alive().await?;
            sleep(Duration::from_secs(1)).await;
        }
    }

    /// A session on a page whose URL `wanted` accepts, if one is listed now.
    async fn try_page(&mut self, wanted: impl Fn(&str) -> bool) -> Result<Option<PageSession>> {
        match self.find(&wanted).await {
            Some(url) => {
                self.restart_at = Instant::now() + PROXY_RESTART;
                PageSession::webkit(&url).await.map(Some)
            }
            None => Ok(None),
        }
    }

    /// Restart the proxy after [`PROXY_RESTART`] without a match.
    async fn keep_alive(&mut self) -> Result<()> {
        if Instant::now() < self.restart_at {
            return Ok(());
        }
        self.restarts += 1;
        eprintln!(
            "restarting ios_webkit_debug_proxy ({}), it last saw {}",
            self.restarts, self.seen
        );
        self.proxy.kill().await.ok();
        if self.socket.is_some() {
            self.socket = Some(simulator_inspector_socket().await?);
        }
        self.list_port = free_port()?;
        self.proxy = spawn_proxy(self.list_port, self.socket.as_deref(), &self.log)?;
        self.restart_at = Instant::now() + PROXY_RESTART;
        Ok(())
    }

    /// The restarts so far and what the latest search saw.
    fn state(&self) -> String {
        format!(
            "after {} proxy restart(s), the last search saw {}, proxy output in {}",
            self.restarts,
            self.seen,
            self.log.display()
        )
    }

    async fn find(&mut self, wanted: &impl Fn(&str) -> bool) -> Option<String> {
        let devices = match list_pages(self.list_port).await {
            Ok(devices) => devices,
            Err(err) => {
                self.seen = format!("no device list ({err:#})");
                return None;
            }
        };
        let Some(target) = devices
            .iter()
            .find(|device| device["deviceId"] == self.device.as_str())
        else {
            let listed: Vec<&str> = devices
                .iter()
                .filter_map(|device| device["deviceId"].as_str())
                .collect();
            self.seen = format!("devices {listed:?} without {}", self.device);
            return None;
        };
        let Some(port) = target["url"]
            .as_str()
            .and_then(|url| url.rsplit_once(':'))
            .and_then(|(_, port)| port.parse().ok())
        else {
            self.seen = format!("{} with no page port in {target}", self.device);
            return None;
        };
        let pages = match list_pages(port).await {
            Ok(pages) => pages,
            Err(err) => {
                self.seen = format!("{} with no page list ({err:#})", self.device);
                return None;
            }
        };
        let found = pages.iter().find_map(|page| {
            wanted(page["url"].as_str()?)
                .then(|| page["webSocketDebuggerUrl"].as_str().map(str::to_owned))?
        });
        if found.is_none() {
            let urls: Vec<&str> = pages
                .iter()
                .filter_map(|page| page["url"].as_str())
                .collect();
            self.seen = format!("pages {urls:?}");
        }
        found
    }
}

/// Start the proxy listing devices on `list_port`, appending its output to
/// `log`.
fn spawn_proxy(list_port: u16, socket: Option<&str>, log: &Path) -> Result<Child> {
    let first_page_port = free_port()?;
    let output = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .with_context(|| format!("opening {}", log.display()))?;
    let mut proxy = Command::new("ios_webkit_debug_proxy");
    if let Some(socket) = socket {
        proxy.args(["-s", &format!("unix:{socket}")]);
    }
    proxy
        .args([
            "-c",
            &format!(
                "null:{list_port},:{first_page_port}-{}",
                first_page_port.saturating_add(100)
            ),
        ])
        .stdout(output.try_clone().context("sharing the proxy log")?)
        .stderr(output)
        .kill_on_drop(true)
        .spawn()
        .context("starting ios_webkit_debug_proxy")
}

/// The `webinspectord` socket the booted simulators share, found among the
/// Unix sockets `launchd_sim` holds.
async fn simulator_inspector_socket() -> Result<String> {
    let output = Command::new("lsof")
        .arg("-U")
        .output()
        .await
        .context("starting lsof")?;
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .find(|field| field.ends_with("com.apple.webinspectord_sim.socket"))
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("no simulator web inspector socket, is a simulator booted?"))
}

fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("finding a free port")?;
    Ok(listener.local_addr()?.port())
}

#[cfg(test)]
mod tests {
    use super::organizational_unit;

    /// Both subject spellings `openssl x509 -subject` prints yield the team.
    #[test]
    fn the_team_is_read_from_either_subject_spelling() {
        assert_eq!(
            organizational_unit(
                "subject=UID=L3523U62Y2, CN=Apple Development: someone (K2335UN485), OU=7W8527FJJE, O=Someone, C=US"
            ),
            Some("7W8527FJJE")
        );
        assert_eq!(
            organizational_unit(
                "subject= /UID=L3523U62Y2/CN=Apple Development/OU=7W8527FJJE/O=Someone/C=US"
            ),
            Some("7W8527FJJE")
        );
    }
}
