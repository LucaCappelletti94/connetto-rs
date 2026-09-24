//! Deploys `examples/dioxus-desktop-demo` to an iOS simulator and walks R88's
//! proof on it, which is sign in, sync, write offline and upload on reconnect.
//!
//! It runs on a Mac as the command of `connetto-demo-stack`, which provides the
//! stack and the environment naming it.
//!
//! ```text
//! cargo build -p connetto-test-harness --bin connetto-ios-proof
//! cargo run -p connetto-test-harness --bin connetto-demo-stack -- \
//!   target/debug/connetto-ios-proof [--simulator UDID] [--app PATH]
//! ```
//!
//! Without `--app` it builds the app with `dx`, linking the keychain
//! entitlements into the executable as Xcode does for a simulator, under the
//! team prefix of the Mac's Apple Development certificate. The demo and its
//! login page are read and driven through the `WebKit` remote inspector, reached
//! with `ios_webkit_debug_proxy`, which must be on `PATH`. The app dials the
//! sync server through a relay the driver owns, and stopping the relay is the
//! offline step. Each step's screenshot and the app's log land under
//! `target/ios-proof/<udid>-<millis>/`.
//!
//! Android's killed-process step has no counterpart here, since the session
//! that catches the redirect dies with the process that opened it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use connetto_test_harness::demo::{order_count, wait_for_count};
use connetto_test_harness::inspector::{PageSession, list_pages};
use connetto_test_harness::relay::Relay;
use connetto_test_harness::stack::{now_millis, repo_path};
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep};

const BUNDLE: &str = "dev.connetto.dioxusdemo";
const PROCESS: &str = "connetto-dioxus-desktop-demo";
const DEMO_DIR: [&str; 2] = ["examples", "dioxus-desktop-demo"];
const TARGET: &str = "aarch64-apple-ios-sim";
const USER: &str = "alice";
/// The simulator a run uses when none is named.
const DEFAULT_SIMULATOR: &str = "iPhone 17 Pro";

#[tokio::main]
async fn main() -> Result<()> {
    let stack = Stack::from_env()?;
    let (simulator, app) = cli_arguments()?;
    let simulator = Simulator::boot(simulator).await?;
    let evidence =
        repo_path(&["target", "ios-proof"])?.join(format!("{}-{}", simulator.udid, now_millis()));
    tokio::fs::create_dir_all(&evidence)
        .await
        .with_context(|| format!("creating {}", evidence.display()))?;
    eprintln!("evidence in {}", evidence.display());

    let started = std::time::SystemTime::now();
    let outcome = prove(&simulator, app, &stack, &evidence).await;
    let log = simulator.app_log(started).await.unwrap_or_default();
    tokio::fs::write(evidence.join("app-log.txt"), log)
        .await
        .context("writing the app log")?;
    if let Err(err) = &outcome {
        let _ = simulator.screenshot(&evidence, "failure").await;
        eprintln!("proof failed: {err:#}");
    }
    let _ = simulator
        .simctl(&["terminate", &simulator.udid, BUNDLE])
        .await;
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
}

async fn prove(
    simulator: &Simulator,
    app: Option<PathBuf>,
    stack: &Stack,
    evidence: &Path,
) -> Result<()> {
    let app = match app {
        Some(app) => app,
        None => build_app(evidence).await?,
    };
    let mut relay = Relay::start("127.0.0.1:0", &stack.server).await?;

    step("install");
    let _ = simulator
        .simctl(&["uninstall", &simulator.udid, BUNDLE])
        .await;
    simulator
        .simctl(&["keychain", &simulator.udid, "reset"])
        .await?;
    simulator
        .simctl(&["install", &simulator.udid, &app.display().to_string()])
        .await?;
    let inspector = Inspector::start().await?;

    step("sign in");
    simulator
        .launch(&[
            ("CONNETTO_DEMO_SERVER", &relay.address().to_string()),
            ("CONNETTO_DEMO_AUTH_ORIGIN", &stack.auth_origin),
            ("CONNETTO_DEMO_PG", &stack.pg_url),
        ])
        .await?;
    let mut login = inspector
        .page(|url| url.starts_with(&format!("{}/authorize?", stack.issuer)))
        .await?;
    simulator.screenshot(evidence, "login-page").await?;
    submit_login(&mut login).await?;
    drop(login);
    let mut app = inspector.page(|url| url.starts_with("dioxus://")).await?;
    app.wait_for_text("status: connected", Duration::from_secs(90))
        .await?;
    simulator.screenshot(evidence, "signed-in").await?;

    step("sync a backend write");
    let before = order_count(&stack.pg_url).await?;
    app.click("Insert via Postgres (backend writer)").await?;
    wait_for_count(&stack.pg_url, before + 1).await?;
    app.wait_for_text(
        &format!("COUNT(*) pushed by the server: {}", before + 1),
        Duration::from_secs(30),
    )
    .await?;
    simulator.screenshot(evidence, "synced").await?;

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
    simulator.screenshot(evidence, "offline-write").await?;

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
    simulator.screenshot(evidence, "uploaded").await?;

    step("sign out");
    app.click("Sign out (wipe local replica)").await?;
    app.wait_for_outcome(
        "Signing in",
        &["logout error", "not yet synced"],
        Duration::from_secs(60),
    )
    .await?;
    simulator.screenshot(evidence, "signed-out").await?;
    step("proof complete");
    Ok(())
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

/// `--simulator` and `--app`, both optional.
fn cli_arguments() -> Result<(Option<String>, Option<PathBuf>)> {
    let mut simulator = None;
    let mut app = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--simulator" => simulator = Some(args.next().context("--simulator takes a UDID")?),
            "--app" => app = Some(PathBuf::from(args.next().context("--app takes a path")?)),
            other => bail!("unknown argument {other:?}"),
        }
    }
    Ok((simulator, app))
}

/// Build the simulator app with the keychain entitlements linked in.
async fn build_app(evidence: &Path) -> Result<PathBuf> {
    let team = team_prefix().await?;
    let entitlements = evidence.join("simulator-entitlements.plist");
    tokio::fs::write(&entitlements, simulator_entitlements(&team))
        .await
        .context("writing the simulator entitlements")?;
    let demo = repo_path(&DEMO_DIR)?;
    step("build");
    let status = Command::new("dx")
        .args([
            "build",
            "--ios",
            "--target",
            TARGET,
            "--no-default-features",
            "--features",
            "mobile",
        ])
        .env(
            "CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUSTFLAGS",
            format!(
                "-C link-arg=-Wl,-sectcreate,__TEXT,__entitlements,{}",
                entitlements.display()
            ),
        )
        .current_dir(&demo)
        .status()
        .await
        .context("starting dx")?;
    if !status.success() {
        bail!("dx build failed with {status}");
    }
    Ok(demo.join("target/dx/connetto-dioxus-desktop-demo/debug/ios/ConnettoDioxusDesktopDemo.app"))
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

struct Simulator {
    udid: String,
}

impl Simulator {
    /// The named simulator, or the default one, booted.
    async fn boot(udid: Option<String>) -> Result<Self> {
        let udid = match udid {
            Some(udid) => udid,
            None => default_simulator().await?,
        };
        let simulator = Self { udid };
        let _ = simulator.simctl(&["boot", &simulator.udid]).await;
        simulator
            .simctl(&["bootstatus", &simulator.udid, "-b"])
            .await?;
        Ok(simulator)
    }

    async fn simctl(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("xcrun")
            .arg("simctl")
            .args(args)
            .output()
            .await
            .context("starting xcrun simctl")?;
        if !output.status.success() {
            bail!(
                "simctl {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Launch the demo with `env` in its environment.
    async fn launch(&self, env: &[(&str, &str)]) -> Result<()> {
        let output = Command::new("xcrun")
            .args(["simctl", "launch", &self.udid, BUNDLE])
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

    async fn screenshot(&self, evidence: &Path, name: &str) -> Result<()> {
        let path = evidence.join(format!("{name}.png"));
        self.simctl(&["io", &self.udid, "screenshot", &path.display().to_string()])
            .await
            .map(drop)
    }

    /// The demo's log lines since `since`.
    async fn app_log(&self, since: std::time::SystemTime) -> Result<String> {
        let seconds = since.elapsed().unwrap_or_default().as_secs() + 5;
        self.simctl(&[
            "spawn",
            &self.udid,
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

/// The first available simulator named [`DEFAULT_SIMULATOR`].
async fn default_simulator() -> Result<String> {
    let output = Command::new("xcrun")
        .args(["simctl", "list", "devices", "available", "--json"])
        .output()
        .await
        .context("listing simulators")?;
    let listing: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("parsing the simulator list")?;
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

/// `ios_webkit_debug_proxy` on the simulator's inspector socket, stopped when
/// dropped.
struct Inspector {
    _proxy: Child,
    list_port: u16,
}

impl Inspector {
    async fn start() -> Result<Self> {
        let socket = simulator_inspector_socket().await?;
        let list_port = free_port()?;
        let first_page_port = free_port()?;
        let proxy = Command::new("ios_webkit_debug_proxy")
            .args([
                "-s",
                &format!("unix:{socket}"),
                "-c",
                &format!(
                    "null:{list_port},:{first_page_port}-{}",
                    first_page_port + 100
                ),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("starting ios_webkit_debug_proxy")?;
        Ok(Self {
            _proxy: proxy,
            list_port,
        })
    }

    /// A session on the first simulator page whose URL `wanted` accepts,
    /// waiting up to ninety seconds for it to appear.
    async fn page(&self, wanted: impl Fn(&str) -> bool) -> Result<PageSession> {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(url) = self.find(&wanted).await {
                return PageSession::webkit(&url).await;
            }
            if Instant::now() >= deadline {
                bail!("no simulator page matched within 90s");
            }
            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn find(&self, wanted: &impl Fn(&str) -> bool) -> Option<String> {
        let devices = list_pages(self.list_port).await.ok()?;
        let simulator = devices
            .iter()
            .find(|device| device["deviceId"] == "SIMULATOR")?;
        let port = simulator["url"]
            .as_str()?
            .rsplit_once(':')?
            .1
            .parse()
            .ok()?;
        list_pages(port).await.ok()?.iter().find_map(|page| {
            wanted(page["url"].as_str()?)
                .then(|| page["webSocketDebuggerUrl"].as_str().map(str::to_owned))?
        })
    }
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
