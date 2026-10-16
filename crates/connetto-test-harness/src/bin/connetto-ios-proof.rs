//! Deploys `examples/dioxus-desktop-demo` to an iOS simulator or a paired
//! iPhone or iPad and walks R88's proof on it, which is sign in, sync, write
//! offline and upload on reconnect, then R51's re-check after time away.
//!
//! With `--peer-device UDID --every-join --hotspot-passphrase PASS` a second
//! paired phone joins the first in one run (R76 slice 9a), the first hosting
//! its Personal Hotspot, which the `XCUITest` tapper under
//! `crates/connetto-test-harness/ios/` switches in Settings, and the second
//! joining it by beacon, payload and form in turn, the tapper tapping the
//! system's prompts, one summary beside the evidence.
//!
//! It runs on a Mac as the command of `connetto-demo-stack`, which provides the
//! stack and the environment naming it.
//!
//! ```text
//! cargo build -p connetto-test-harness --bin connetto-ios-proof
//! cargo run -p connetto-test-harness --bin connetto-demo-stack -- \
//!   target/debug/connetto-ios-proof [--simulator UDID | --device UDID --identity SHA1] [--app PATH]
//!     [--peer-device UDID --every-join --hotspot-passphrase PASS]
//! ```
//!
//! A simulator build links the keychain entitlements into the executable as
//! Xcode does, under the team ID `CONNETTO_IOS_TEAM_ID` names or else the
//! team prefix of the Mac's Apple Development certificate. The simulator
//! checks no signature against that ID, so any ID serves a Mac without the
//! certificate. A device build is signed with the identity
//! `connetto-ios-signing` prepared, whose keychain the driver unlocks, and a
//! device run needs the stack on a host the device reaches, which on the
//! maintainer's tailnet is `CONNETTO_STACK_PUBLIC_HOST` with TLS. The demo and
//! its login page are read and driven through the `WebKit` remote inspector,
//! reached with `ios_webkit_debug_proxy`, which must be on `PATH`. The app
//! dials the sync server through a relay the driver owns, over `wss` with the
//! stack's certificate on a device, and stopping the relay is the offline
//! step. Evidence lands under
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
use connetto_test_harness::peer_devices::{own_identity, read_hotspot_offer, wait_link_ends};
use connetto_test_harness::peer_proof::{HotspotOfferLines, JoinReport, commit, summary};
use connetto_test_harness::relay::Relay;
use connetto_test_harness::stack::{
    TLS_CERT_VAR, TLS_KEY_VAR, demo_has_device_identity, demo_mobile_features, now_millis,
    repo_path,
};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt as _;
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep, timeout};

const DEMO_DIR: [&str; 2] = ["examples", "dioxus-desktop-demo"];
const APP: &str = "target/dx/connetto-dioxus-desktop-demo/debug/ios/ConnettoDioxusDesktopDemo.app";

/// The demo the proof deploys, `--demo dioxus` (the default) or `--demo
/// tauri` (the Tauri + Leptos spike, `examples/tauri-leptos-demo`).
#[derive(Clone, Copy, Default)]
enum Demo {
    #[default]
    Dioxus,
    Tauri,
}

/// The demo this run deploys, set once from the command line.
static DEMO: std::sync::OnceLock<Demo> = std::sync::OnceLock::new();

fn demo() -> Demo {
    DEMO.get().copied().unwrap_or_default()
}

/// The demo's bundle identifier.
fn bundle() -> &'static str {
    match demo() {
        Demo::Dioxus => "dev.connetto.dioxusdemo",
        Demo::Tauri => "dev.connetto.tauridemo",
    }
}

/// The demo's executable, which names its process.
fn process() -> &'static str {
    match demo() {
        Demo::Dioxus => "connetto-dioxus-desktop-demo",
        Demo::Tauri => "connetto-tauri-demo",
    }
}

/// Whether a page URL is the demo's own page rather than the login.
fn is_demo_page(url: &str) -> bool {
    match demo() {
        Demo::Dioxus => url.starts_with("dioxus://"),
        Demo::Tauri => url.starts_with("tauri://"),
    }
}

const USER: &str = "alice";
/// The simulator a run uses when none is named.
const DEFAULT_SIMULATOR: &str = "iPhone 17 Pro";
/// The variable naming the team ID a simulator build's entitlements carry.
const TEAM_ID_VAR: &str = "CONNETTO_IOS_TEAM_ID";
/// The filter a device's demo logs under, the peer link's and the radios'
/// own steps included, which the demo's log file keeps for the evidence.
const DEMO_LOG_FILTER: &str = "info,connetto_client::away=debug,connetto_dioxus::away=debug,connetto_client::bluetooth=debug,connetto_client::hotspot=debug,connetto_peer=debug,connetto_peer_apple=debug";
/// Where the demo's phone log can sit in its data container, the
/// directory the platform names after the app first.
const DEMO_LOG_SOURCES: [&str; 2] = [
    "Library/Application Support/connetto-dioxus-demo/connetto-demo.log",
    "Library/Application Support/connetto-demo.log",
];
/// The system's alert button labels in the runner's locales, which the
/// tapper taps in place of the user (R76).
const ALERT_LABELS: [&str; 6] = ["Join", "Accedi", "Connetti", "Allow", "Consenti", "OK"];
/// The iOS development profile the tapper's runner signs with, as
/// `connetto-ios-signing` names it.
const TAPPER_PROFILE: &str = "connetto tapper development";

#[tokio::main]
async fn main() -> Result<()> {
    let stack = Stack::from_env()?;
    let parsed = parse_arguments(&std::env::args().skip(1).collect::<Vec<_>>())?;
    let identity = parsed.identity;
    let target = match (parsed.simulator, parsed.device) {
        (simulator, None) => Target::simulator(simulator).await?,
        (None, Some(udid)) => Target::Device {
            udid,
            identity: identity
                .clone()
                .context("--device needs the --identity connetto-ios-signing printed")?,
        },
        _ => unreachable!("parse_arguments checked the simulator and device"),
    };
    let evidence =
        repo_path(&["target", "ios-proof"])?.join(format!("{}-{}", target.udid(), now_millis()));
    tokio::fs::create_dir_all(&evidence)
        .await
        .with_context(|| format!("creating {}", evidence.display()))?;
    eprintln!("evidence in {}", evidence.display());

    let app = match parsed.app {
        Some(app) => app,
        None => target.build(&evidence).await?,
    };
    let (mut relay, sync_url) = relay_for(&target, &stack).await?;
    let started = std::time::SystemTime::now();
    let outcome = if parsed.every_join {
        let started = Instant::now();
        let outcome = prove(&target, &app, &stack, &evidence, &mut relay, &sync_url).await;
        let proved = (
            started.elapsed(),
            outcome.as_ref().map_err(|err| format!("{err:#}")).map(drop),
        );
        // The joins run only on a proved phone, and a failed proof keeps its
        // own error.
        match &outcome {
            Ok(()) => {
                let identity = identity.context("a device run names no --identity")?;
                let joiner = Target::Device {
                    udid: parsed
                        .peer
                        .context("a --every-join run names no --peer-device")?,
                    identity: identity.clone(),
                };
                let passphrase = parsed
                    .passphrase
                    .context("a --every-join run names no passphrase")?;
                // A tapper that does not build fails the joins' setup, which
                // the summary records like any other.
                let tappers = async {
                    let host = Tapper::build(target.udid(), &identity, &evidence).await?;
                    let joiner = Tapper::build(joiner.udid(), &identity, &evidence).await?;
                    Ok::<_, anyhow::Error>((host, joiner))
                }
                .await;
                match tappers {
                    Ok((host_tapper, joiner_tapper)) => {
                        joins_with_summary(
                            &target,
                            &joiner,
                            &app,
                            &host_tapper,
                            &joiner_tapper,
                            &stack,
                            &evidence,
                            &passphrase,
                            &sync_url,
                            proved,
                        )
                        .await
                    }
                    Err(err) => {
                        let summary = summary(&commit().await, &proved, Err(&err), Ok(()));
                        eprintln!("{summary}");
                        tokio::fs::write(evidence.join("summary.txt"), &summary)
                            .await
                            .context("writing the summary")?;
                        Err(err)
                    }
                }
            }
            Err(_) => outcome,
        }
    } else {
        prove(&target, &app, &stack, &evidence, &mut relay, &sync_url).await
    };
    if let Target::Simulator { .. } = &target {
        let log = target.app_log(started).await.unwrap_or_default();
        tokio::fs::write(evidence.join("app-log.txt"), log)
            .await
            .context("writing the app log")?;
    }
    if let Err(err) = target.copy_demo_log(&evidence).await {
        eprintln!("the demo's log stayed on {}: {err:#}", target.udid());
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

    /// Whether the stack serves its routes in TLS, which it does on the
    /// network.
    fn on_tls(&self) -> bool {
        self.auth_origin.starts_with("https://")
    }

    /// The host clients reach the sync server on.
    fn host(&self) -> Result<&str> {
        self.server
            .rsplit_once(':')
            .map(|(host, _)| host)
            .ok_or_else(|| anyhow!("CONNETTO_DEMO_SERVER names no port: {}", self.server))
    }
}

/// A relay in front of the sync server, and the URL the demo dials it at.
///
/// A stack on the network terminates TLS on its own listener, so the relay
/// hands the bytes through and the demo dials it in `wss` by the stack's host,
/// which the certificate names. A stack on the loopback speaks plain HTTP,
/// which only a simulator may dial, in `ws` on the Mac's loopback.
async fn relay_for(target: &Target, stack: &Stack) -> Result<(Relay, String)> {
    if stack.on_tls() {
        let relay = Relay::start("0.0.0.0:0", &stack.server).await?;
        let url = format!(
            "wss://{}:{}{}",
            stack.host()?,
            relay.address().port(),
            connetto_server::SYNC_PATH
        );
        return Ok((relay, url));
    }
    if matches!(target, Target::Device { .. }) {
        bail!("a device run needs the stack on TLS, under {TLS_CERT_VAR} and {TLS_KEY_VAR}");
    }
    let relay = Relay::start("127.0.0.1:0", &stack.server).await?;
    let url = format!(
        "ws://127.0.0.1:{}{}",
        relay.address().port(),
        connetto_server::SYNC_PATH
    );
    Ok((relay, url))
}

async fn prove(
    target: &Target,
    app: &Path,
    stack: &Stack,
    evidence: &Path,
    relay: &mut Relay,
    sync_url: &str,
) -> Result<()> {
    step("install");
    target.install(app).await?;
    let mut inspector = Inspector::start(target, evidence).await?;

    step("sign in");
    target
        .launch(&[
            ("CONNETTO_DEMO_WS", sync_url),
            ("CONNETTO_DEMO_AUTH_ORIGIN", &stack.auth_origin),
            ("CONNETTO_DEMO_PG", &stack.pg_url),
        ])
        .await?;
    let login_prefix = format!("{}/authorize?", stack.issuer);
    let mut app = sign_in(target, &mut inspector, &login_prefix, evidence).await?;
    target.record(&mut app, evidence, "signed-in").await?;

    if demo_has_device_identity() {
        step("enrol the device");
        app.wait_for_text("device: certified until", Duration::from_secs(60))
            .await?;
        target
            .record(&mut app, evidence, "device-certified")
            .await?;
    }

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

    let mut app = recheck_after_time_away(target, &mut inspector, stack, evidence).await?;

    // The spike has no session panel, so its proof ends at the re-check.
    if let Demo::Dioxus = demo() {
        step("sign out");
        sign_out(&mut app).await?;
        target.record(&mut app, evidence, "signed-out").await?;
    }
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
            let mut app = inspector.page(is_demo_page).await?;
            app.wait_for_text("status: connected", Duration::from_secs(90))
                .await?;
            // The simulator creates gated keychain items without enforcing
            // them, so the custody reads verified there too. The sheet itself
            // is proven on a device with a person.
            app.wait_for_text(
                "custody: released only after user verification",
                Duration::from_secs(10),
            )
            .await?;
            return Ok(app);
        }
        if let Some(mut app) = inspector.try_page(is_demo_page).await? {
            // A page that does not answer is looked for again through a fresh
            // proxy, since a relaunched app's inspector can stall once.
            match app.page_text().await {
                Ok(text) => {
                    if text.contains("status: connected") {
                        eprintln!("an earlier credential signed the demo in, signing out first");
                        sign_out(&mut app).await?;
                    }
                    demo = text.split_whitespace().collect::<Vec<_>>().join(" ");
                }
                Err(err) => {
                    demo = format!("a page that did not answer ({err:#})");
                    inspector.restart_at = Instant::now();
                }
            }
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

/// Sign the demo out on `phone` when it stands signed in, so a run leaves no
/// account in the keychain's account index, which outlives the demo's
/// uninstall while each run's provider names a new account.
async fn leave_signed_out(phone: &Target, evidence: &Path) -> Result<()> {
    let mut inspector = Inspector::start(phone, evidence).await?;
    let mut app = inspector.page(is_demo_page).await?;
    if app.page_text().await?.contains("Signed in as:") {
        sign_out(&mut app).await?;
    }
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

/// The demo's re-check grace, `RECHECK_AFTER` in its source.
const RECHECK_AFTER: Duration = Duration::from_secs(30);
/// The app the away step brings to the front in the demo's place.
const SETTINGS: &str = "com.apple.Preferences";

/// Leave the demo for longer than its re-check grace and come back: the gate
/// locks and asks once, and the approval opens it with the session kept. A
/// device holds the lock until the person approves, which the step waits to
/// see. A simulator answers the sheet at once, so only the reopening shows.
async fn recheck_after_time_away(
    target: &Target,
    inspector: &mut Inspector,
    stack: &Stack,
    evidence: &Path,
) -> Result<PageSession> {
    step("re-check after time away");
    target.bring_to_front(SETTINGS).await?;
    sleep(RECHECK_AFTER + Duration::from_secs(5)).await;
    target.bring_to_front(bundle()).await?;
    let mut app = inspector.page(is_demo_page).await?;
    if let Target::Device { .. } = target {
        app.wait_for_text("gate: locked", Duration::from_secs(30))
            .await?;
        eprintln!("approve Face ID or the passcode on the device");
    }
    app.wait_for_text("gate: open", Duration::from_secs(120))
        .await?;
    // The session outlived the lock: a backend write still reaches the page.
    let before = order_count(&stack.pg_url).await?;
    app.click("Insert via Postgres (backend writer)").await?;
    app.wait_for_text(
        &format!("COUNT(*) pushed by the server: {}", before + 1),
        Duration::from_secs(30),
    )
    .await?;
    target.record(&mut app, evidence, "rechecked").await?;
    Ok(app)
}

fn step(name: &str) {
    eprintln!("== {name}");
}

/// What the command line names, before anything runs.
#[derive(Default)]
struct ParsedArguments {
    simulator: Option<String>,
    device: Option<String>,
    identity: Option<String>,
    app: Option<PathBuf>,
    peer: Option<String>,
    every_join: bool,
    passphrase: Option<String>,
}

/// `--simulator`, or `--device` with `--identity`, `--app`, and, for the
/// two-phone run, `--peer-device`, `--every-join` and `--hotspot-passphrase`.
fn parse_arguments(args: &[String]) -> Result<ParsedArguments> {
    let mut arguments = ParsedArguments::default();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--simulator" => {
                arguments.simulator = Some(argument_value(&mut args, arg)?.to_owned());
            }
            "--device" => arguments.device = Some(argument_value(&mut args, arg)?.to_owned()),
            "--identity" => {
                arguments.identity = Some(argument_value(&mut args, arg)?.to_owned());
            }
            "--app" => {
                arguments.app = Some(PathBuf::from(argument_value(&mut args, arg)?.to_owned()));
            }
            "--demo" => {
                let chosen = match argument_value(&mut args, arg)? {
                    "dioxus" => Demo::Dioxus,
                    "tauri" => Demo::Tauri,
                    other => bail!("unknown demo {other:?}, expected dioxus or tauri"),
                };
                DEMO.set(chosen)
                    .map_err(|_| anyhow!("--demo given twice"))?;
            }
            "--peer-device" => {
                arguments.peer = Some(argument_value(&mut args, arg)?.to_owned());
            }
            "--hotspot-passphrase" => {
                arguments.passphrase = Some(argument_value(&mut args, arg)?.to_owned());
            }
            "--every-join" => arguments.every_join = true,
            other => bail!("unknown argument {other:?}"),
        }
    }
    if arguments.simulator.is_some() && arguments.device.is_some() {
        bail!("give either --simulator or --device, not both");
    }
    if arguments.device.is_some() && arguments.identity.is_none() {
        bail!("--device needs the --identity connetto-ios-signing printed");
    }
    if arguments.peer.is_some() && !arguments.every_join {
        bail!("--peer-device needs --every-join");
    }
    if arguments.every_join
        && (arguments.device.is_none()
            || arguments.identity.is_none()
            || arguments.peer.is_none()
            || arguments.passphrase.is_none())
    {
        bail!("--every-join needs --device, --identity, --peer-device and --hotspot-passphrase");
    }
    if arguments.every_join && arguments.simulator.is_some() {
        bail!("--every-join runs on a paired phone, so it needs --device, not --simulator");
    }
    if arguments
        .device
        .as_deref()
        .zip(arguments.peer.as_deref())
        .is_some_and(|(device, peer)| device == peer)
    {
        bail!("--peer-device names the same device as --device");
    }
    Ok(arguments)
}

/// The value the argument names, which the argument is not complete without.
fn argument_value<'a>(args: &mut std::slice::Iter<'a, String>, arg: &str) -> Result<&'a str> {
    args.next()
        .map(String::as_str)
        .ok_or_else(|| anyhow!("{arg} needs a value"))
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
        if let Demo::Tauri = demo() {
            bail!(
                "the Tauri demo is built with `cargo tauri ios build` in \
                 examples/tauri-leptos-demo/src-tauri, pass its .app with --app"
            );
        }
        let demo = repo_path(&DEMO_DIR)?;
        step("build");
        let mut dx = Command::new("dx");
        dx.current_dir(&demo).args([
            "build",
            "--ios",
            "--no-default-features",
            "--features",
            demo_mobile_features(),
        ]);
        match self {
            Self::Simulator { .. } => {
                let entitlements = evidence.join("simulator-entitlements.plist");
                let team = signing_team().await?;
                tokio::fs::write(&entitlements, simulator_entitlements(&team))
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
                let _ = xcrun(&["simctl", "uninstall", udid, bundle()]).await;
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
                    bundle(),
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
                    .args(["simctl", "launch", udid, bundle()])
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
                        .chain(&[("RUST_LOG", DEMO_LOG_FILTER)])
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
                    bundle(),
                ])
                .await
                .map(drop)
            }
        }
    }

    /// Bring `bundle` to the front without restarting it.
    async fn bring_to_front(&self, bundle: &str) -> Result<()> {
        match self {
            Self::Simulator { udid } => xcrun(&["simctl", "launch", udid, bundle]).await.map(drop),
            Self::Device { udid, .. } => xcrun(&[
                "devicectl",
                "device",
                "process",
                "launch",
                "--device",
                udid,
                bundle,
            ])
            .await
            .map(drop),
        }
    }

    async fn terminate(&self) -> Result<()> {
        match self {
            Self::Simulator { udid } => xcrun(&["simctl", "terminate", udid, bundle()])
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

    /// Copy the demo's own log off a device into the evidence as
    /// `demo-<udid>.log`, since a device keeps no app's stdout. A simulator
    /// answers through [`Self::app_log`] instead.
    async fn copy_demo_log(&self, evidence: &Path) -> Result<()> {
        let Self::Device { udid, .. } = self else {
            return Ok(());
        };
        let destination = evidence.join(format!("demo-{udid}.log"));
        let destination = destination
            .to_str()
            .context("an evidence path that is not UTF-8")?;
        let mut last = None;
        for source in DEMO_LOG_SOURCES {
            match xcrun(&[
                "devicectl",
                "device",
                "copy",
                "from",
                "--device",
                udid,
                "--domain-type",
                "appDataContainer",
                "--domain-identifier",
                bundle(),
                "--source",
                source,
                "--destination",
                destination,
            ])
            .await
            {
                Ok(_) => return Ok(()),
                Err(err) => last = Some(err),
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("no place to look for the demo's log")))
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
            &format!("process == \"{}\"", process()),
        ])
        .await
    }
}
/// How the second phone learns the hotspot the first one hosts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JoinBy {
    /// The first phone's Bluetooth beacon and the exchange behind it (R76).
    Beacon,
    /// The first phone's `WIFI:` payload pasted into the second's join form
    /// (R76 decision 24).
    Payload,
    /// The first phone's offer lines typed into the second's join form.
    Form,
}

impl JoinBy {
    /// Every join, in the order `--every-join` runs them (R76 slice 9a).
    const EVERY: [Self; 3] = [Self::Beacon, Self::Payload, Self::Form];

    /// The join's name in the summary and the evidence.
    const fn name(self) -> &'static str {
        match self {
            Self::Beacon => "beacon",
            Self::Payload => "payload",
            Self::Form => "form",
        }
    }
}

/// Make the joins, write the summary, and fail when any join failed.
#[expect(
    clippy::too_many_arguments,
    reason = "the two phones, their tappers, the build, the stack, the evidence, the passphrase, the sync url and the proof are each the run's own"
)]
async fn joins_with_summary(
    host: &Target,
    joiner: &Target,
    app: &Path,
    host_tapper: &Tapper,
    joiner_tapper: &Tapper,
    stack: &Stack,
    evidence: &Path,
    passphrase: &str,
    sync_url: &str,
    proved: (Duration, Result<(), String>),
) -> Result<()> {
    let reports = peer_proof(
        host,
        joiner,
        app,
        host_tapper,
        joiner_tapper,
        stack,
        evidence,
        passphrase,
        sync_url,
    )
    .await;
    for phone in [host, joiner] {
        if let Err(err) = leave_signed_out(phone, evidence).await {
            eprintln!("{} stayed signed in: {err:#}", phone.udid());
        }
    }
    if let Err(err) = joiner.copy_demo_log(evidence).await {
        eprintln!("the demo's log stayed on {}: {err:#}", joiner.udid());
    }
    let summary = summary(&commit().await, &proved, reports.as_deref(), Ok(()));
    eprintln!("{summary}");
    tokio::fs::write(evidence.join("summary.txt"), &summary)
        .await
        .context("writing the summary")?;
    let failed: Vec<&str> = reports?
        .iter()
        .filter(|report| report.outcome.is_err())
        .map(|report| report.name)
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("the {} join failed", failed.join(", ")))
    }
}

/// The two-phone peer proof (R76 slice 9a): `host` hosts its Personal
/// Hotspot, switched on by the tapper, and `joiner` signs in as its own
/// account and joins it, the tapper tapping the system's prompts in place of
/// the user, until both pages name the other as linked. It ends with both
/// phones back at rest and the Personal Hotspot off.
#[expect(
    clippy::too_many_arguments,
    reason = "the two phones, their tappers, the build, the stack, the evidence, the passphrase and the sync url are each the walk's own"
)]
async fn peer_proof(
    host: &Target,
    joiner: &Target,
    app: &Path,
    host_tapper: &Tapper,
    joiner_tapper: &Tapper,
    stack: &Stack,
    evidence: &Path,
    passphrase: &str,
    sync_url: &str,
) -> Result<Vec<JoinReport>> {
    if !demo_has_device_identity() {
        bail!("the peer proof needs a demo build with its device identity");
    }
    step("install the demo on the second phone");
    joiner.install(app).await?;
    let mut joiner_inspector = Inspector::start(joiner, evidence).await?;
    joiner
        .launch(&[
            ("CONNETTO_DEMO_WS", sync_url),
            ("CONNETTO_DEMO_AUTH_ORIGIN", &stack.auth_origin),
            ("CONNETTO_DEMO_PG", &stack.pg_url),
        ])
        .await?;
    let login_prefix = format!("{}/authorize?", stack.issuer);
    step("sign in the second phone");
    let mut peer_app = sign_in(joiner, &mut joiner_inspector, &login_prefix, evidence).await?;
    // A local-network prompt can show while the page first browses.
    joiner_tapper
        .run("tap-alert", 40, evidence, "peer-local-network")
        .await?;
    peer_app
        .wait_for_text("device: certified until", Duration::from_secs(60))
        .await?;
    joiner
        .record(&mut peer_app, evidence, "peer-signed-in")
        .await?;
    turn_on_bluetooth(&mut peer_app, joiner_tapper, evidence).await?;

    // The host signed out at the end of its proof, so it signs back in.
    step("sign the host back in");
    host.launch(&[
        ("CONNETTO_DEMO_WS", sync_url),
        ("CONNETTO_DEMO_AUTH_ORIGIN", &stack.auth_origin),
        ("CONNETTO_DEMO_PG", &stack.pg_url),
    ])
    .await?;
    let mut host_inspector = Inspector::start(host, evidence).await?;
    let mut host_app = sign_in(host, &mut host_inspector, &login_prefix, evidence).await?;
    host_app
        .wait_for_text("device: certified until", Duration::from_secs(60))
        .await?;
    host.record(&mut host_app, evidence, "host-signed-in")
        .await?;

    let host_identity = own_identity(&mut host_app).await?;
    let joiner_identity = own_identity(&mut peer_app).await?;
    // The Personal Hotspot names its network after the device.
    let host_name = device_name(host.udid()).await?;

    let mut reports = Vec::with_capacity(JoinBy::EVERY.len());
    for &join in &JoinBy::EVERY {
        let started = Instant::now();
        // Each join takes a fresh page, since the last moved the joiner's network.
        let outcome = match joiner_inspector.reattach().await {
            Ok(page) => {
                peer_app = page;
                one_join(
                    host,
                    joiner,
                    &mut host_app,
                    &mut host_inspector,
                    &mut peer_app,
                    &mut joiner_inspector,
                    host_tapper,
                    joiner_tapper,
                    evidence,
                    (&host_identity, &joiner_identity),
                    &host_name,
                    passphrase,
                    join,
                )
                .await
            }
            Err(err) => Err(err),
        };
        if let Err(err) = &outcome {
            eprintln!("the {} join failed: {err:#}", join.name());
            let _ = host
                .record(
                    &mut host_app,
                    evidence,
                    &format!("{}-failure-host", join.name()),
                )
                .await;
            let _ = joiner
                .record(
                    &mut peer_app,
                    evidence,
                    &format!("{}-failure-peer", join.name()),
                )
                .await;
        }
        reports.push(JoinReport {
            name: join.name(),
            took: Some(started.elapsed()),
            outcome,
        });
    }
    Ok(reports)
}

/// Turn Bluetooth on through the demo, since a fresh install has not been
/// allowed it and the joiner scans only once it is, so the user's own action
/// asks for it (R76 decision 21).
async fn turn_on_bluetooth(app: &mut PageSession, tapper: &Tapper, evidence: &Path) -> Result<()> {
    step("turn on Bluetooth on the second phone");
    app.click("Turn on Bluetooth").await?;
    tapper
        .run("tap-alert", 40, evidence, "peer-bluetooth")
        .await?;
    app.wait_for_text("bluetooth: ready", Duration::from_secs(30))
        .await
}

/// One join, from a Personal Hotspot hosted on the first phone to the link's
/// end, and the phones back at rest whatever happened.
#[expect(
    clippy::too_many_arguments,
    reason = "the two phones, their pages, inspectors and tappers, the evidence, both identities, the hotspot name and password and the join are each the step's own"
)]
async fn one_join(
    host: &Target,
    joiner: &Target,
    host_app: &mut PageSession,
    host_inspector: &mut Inspector,
    peer_app: &mut PageSession,
    joiner_inspector: &mut Inspector,
    host_tapper: &Tapper,
    joiner_tapper: &Tapper,
    evidence: &Path,
    (host_identity, joiner_identity): (&str, &str),
    host_name: &str,
    passphrase: &str,
    join: JoinBy,
) -> Result<()> {
    let shot = |name: &str| format!("{}-{name}", join.name());
    let walked = async {
        step(&format!(
            "turn Personal Hotspot on on the first phone for the {} join",
            join.name()
        ));
        switch_and_reattach(
            true,
            host_tapper,
            host_inspector,
            host_app,
            evidence,
            &shot("hotspot-on"),
        )
        .await?;
        step(&format!(
            "host the Personal Hotspot on the first phone for the {} join",
            join.name()
        ));
        host_app.set_input("personal-ssid", host_name).await?;
        host_app
            .set_input("personal-passphrase", passphrase)
            .await?;
        host_app.click("Host my Personal Hotspot").await?;
        // The call prompts at once when Bluetooth is off, and blocks on it.
        let _ = host_tapper
            .run("tap-alert", 40, evidence, &shot("host-alert"))
            .await;
        let offer = read_hotspot_offer(host_app).await?;
        host.record(host_app, evidence, &shot("host-offer")).await?;

        join_on_second_phone(join, &offer, joiner, peer_app, joiner_tapper, evidence).await?;
        // The joiner moved onto the hotspot, which can reset the links both
        // pages' sessions ride on.
        *peer_app = joiner_inspector.reattach().await?;
        *host_app = host_inspector.reattach().await?;

        step("link through the hotspot");
        wait_linked(host_app, peer_app, host_identity, joiner_identity).await?;
        host.record(host_app, evidence, &shot("host-linked"))
            .await?;
        joiner
            .record(peer_app, evidence, &shot("peer-linked"))
            .await?;

        step("leave the hotspot on the second phone");
        peer_app.click("Leave the hotspot").await?;
        step("stop the hotspot on the first phone");
        host_app.click("Stop the hotspot").await?;
        wait_link_ends(host_app, peer_app).await?;
        host.record(host_app, evidence, &shot("host-unlinked"))
            .await
    }
    .await;
    // Back to rest whatever happened, so the next join starts clean: the
    // pages' own leave and stop, then the Personal Hotspot off, the first
    // failure kept.
    if walked.is_err() {
        let _ = peer_app.click("Leave the hotspot").await;
        let _ = host_app.click("Stop the hotspot").await;
    }
    let off = switch_and_reattach(
        false,
        host_tapper,
        host_inspector,
        host_app,
        evidence,
        &shot("hotspot-off"),
    )
    .await;
    let _ = joiner.record(peer_app, evidence, &shot("peer-clean")).await;
    walked.and(off)
}

/// The second phone's side of one join, up to the system's join prompt
/// tapped.
async fn join_on_second_phone(
    join: JoinBy,
    offer: &HotspotOfferLines,
    joiner: &Target,
    peer_app: &mut PageSession,
    joiner_tapper: &Tapper,
    evidence: &Path,
) -> Result<()> {
    match join {
        JoinBy::Beacon => {
            step("find the beacon on the second phone");
            wait_for_single_nearby(peer_app).await?;
            joiner
                .record(peer_app, evidence, &format!("{}-peer-nearby", join.name()))
                .await?;
            peer_app.click("Join the nearby host").await?;
            // The line shows while the exchange and then the join run,
            // behind which the system's prompts stand.
            peer_app
                .wait_for_text("joining the nearby host", Duration::from_secs(10))
                .await?;
            joiner_tapper
                .run(
                    "tap-alert",
                    40,
                    evidence,
                    &format!("{}-joiner-alert", join.name()),
                )
                .await?;
        }
        JoinBy::Payload => {
            let payload = offer
                .payload
                .as_deref()
                .context("the host shows no WIFI: payload")?;
            step("paste the payload on the second phone");
            peer_app.set_input("payload", payload).await?;
            peer_app.click("Join from the payload").await?;
            peer_app
                .wait_for_text("joining the hotspot", Duration::from_secs(10))
                .await
                .context("the second phone did not take the payload")?;
            joiner_tapper
                .run(
                    "tap-alert",
                    40,
                    evidence,
                    &format!("{}-joiner-alert", join.name()),
                )
                .await?;
        }
        JoinBy::Form => {
            step("fill the join form on the second phone");
            peer_app.set_input("ssid", &offer.ssid).await?;
            peer_app.set_input("passphrase", &offer.passphrase).await?;
            peer_app.set_input("port", &offer.port.to_string()).await?;
            peer_app.click("Join the hotspot").await?;
            peer_app
                .wait_for_text("joining the hotspot", Duration::from_secs(10))
                .await?;
            joiner_tapper
                .run(
                    "tap-alert",
                    40,
                    evidence,
                    &format!("{}-joiner-alert", join.name()),
                )
                .await?;
        }
    }
    Ok(())
}

/// Wait until each phone names the other as linked.
async fn wait_linked(
    host_app: &mut PageSession,
    peer_app: &mut PageSession,
    host_identity: &str,
    joiner_identity: &str,
) -> Result<()> {
    if host_app
        .wait_for_text(
            &format!("linked: {joiner_identity}"),
            Duration::from_secs(90),
        )
        .await
        .is_err()
    {
        let host_page = host_app.page_text().await.unwrap_or_default();
        let peer_page = peer_app.page_text().await.unwrap_or_default();
        bail!(
            "the first phone never named the second as linked, the first phone shows:\n{host_page}\nthe second phone shows:\n{peer_page}"
        );
    }
    peer_app
        .wait_for_text(&format!("linked: {host_identity}"), Duration::from_secs(30))
        .await?;
    Ok(())
}

/// Switch the host's Personal Hotspot and take a fresh session on its page,
/// since the switch resets the USB link the old session rode on.
async fn switch_and_reattach(
    on: bool,
    tapper: &Tapper,
    inspector: &mut Inspector,
    app: &mut PageSession,
    evidence: &Path,
    name: &str,
) -> Result<()> {
    let switched = tapper.switch_hotspot(on, evidence, name).await;
    *app = inspector.reattach().await?;
    switched
}

/// Wait until the joiner lists exactly one nearby host, whose beacon the join
/// button takes as the strongest.
async fn wait_for_single_nearby(app: &mut PageSession) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let page = app.page_text().await?;
        let nearby: Vec<&str> = page
            .lines()
            .filter(|line| line.starts_with("nearby: "))
            .collect();
        if nearby.len() == 1 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the second phone never saw exactly one nearby host, it lists: {nearby:?}");
        }
        sleep(Duration::from_secs(1)).await;
    }
}

/// The name of a paired device, which its Personal Hotspot uses as the
/// network name.
async fn device_name(udid: &str) -> Result<String> {
    let listing = std::env::temp_dir().join("connetto-ios-devices.json");
    xcrun(&[
        "devicectl",
        "list",
        "devices",
        "--json-output",
        &listing.display().to_string(),
    ])
    .await?;
    let listed: Value = serde_json::from_slice(
        &tokio::fs::read(&listing)
            .await
            .with_context(|| format!("reading {}", listing.display()))?,
    )
    .context("parsing the device list")?;
    for device in listed["result"]["devices"].as_array().into_iter().flatten() {
        if device["hardwareProperties"]["udid"] == udid {
            return device["deviceProperties"]["name"]
                .as_str()
                .map(str::to_owned)
                .context("the device list names no device");
        }
    }
    bail!("no paired device with the udid {udid}")
}

/// The `XCUITest` tapper on one phone, which taps the system's alerts and
/// switches Personal Hotspot where the demo and its page cannot.
struct Tapper {
    udid: String,
    xctestrun: PathBuf,
}

impl Tapper {
    /// Build the tapper bundle for the device, signed with the development
    /// profile, into the evidence.
    async fn build(udid: &str, identity: &str, evidence: &Path) -> Result<Self> {
        ios_signing::unlock().await?;
        let project =
            repo_path(&["crates", "connetto-test-harness", "ios"])?.join("Tapper.xcodeproj");
        let derived = evidence.join(format!("tapper-{udid}"));
        step(&format!("build the tapper for {udid}"));
        let team = signing_team().await?;
        let output = Command::new("xcodebuild")
            .arg("build-for-testing")
            .arg("-project")
            .arg(&project)
            .arg("-scheme")
            .arg("Tapper")
            .arg("-configuration")
            .arg("Debug")
            .arg("-destination")
            .arg(format!("id={udid}"))
            .arg("-derivedDataPath")
            .arg(&derived)
            .arg(format!("CODE_SIGN_IDENTITY={identity}"))
            .arg(format!("DEVELOPMENT_TEAM={team}"))
            .arg(format!("PROVISIONING_PROFILE_SPECIFIER={TAPPER_PROFILE}"))
            .output()
            .await
            .context("starting xcodebuild build-for-testing")?;
        if !output.status.success() {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            let lines: Vec<&str> = text.lines().collect();
            let tail = lines[lines.len().saturating_sub(40)..].join("\n");
            bail!("xcodebuild build-for-testing failed:\n{tail}");
        }
        let products = derived.join("Build/Products");
        let mut read = tokio::fs::read_dir(&products)
            .await
            .with_context(|| format!("reading {}", products.display()))?;
        let mut found = Vec::new();
        while let Some(entry) = read.next_entry().await? {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "xctestrun") {
                found.push(path);
            }
        }
        let xctestrun = match found.as_slice() {
            [run] => run.clone(),
            _ => bail!(
                "the build left no single xctestrun in {}",
                products.display()
            ),
        };
        Ok(Self {
            udid: udid.to_owned(),
            xctestrun,
        })
    }

    /// Switch Personal Hotspot on or off. Switching it can reset the USB
    /// link the Mac reaches the phone over, which ends the run before it
    /// reports, so a failed run is followed by one more, which reads the
    /// switch and taps only when the first tap did not land.
    async fn switch_hotspot(&self, on: bool, evidence: &Path, name: &str) -> Result<()> {
        let action = if on { "hotspot-on" } else { "hotspot-off" };
        if let Err(err) = self.run(action, 120, evidence, name).await {
            eprintln!("the tapper's {action} ended without a report ({err}), checking the switch");
            self.run(action, 120, evidence, &format!("{name}-check"))
                .await?;
        }
        Ok(())
    }

    /// Run one action on the device through a run file carrying its
    /// arguments, appending xcodebuild's output to the evidence. The run file
    /// sits beside the built one, since xcodebuild finds the products from
    /// the run file's own folder.
    async fn run(&self, action: &str, bound: u64, evidence: &Path, name: &str) -> Result<()> {
        let run = self
            .xctestrun
            .with_file_name(format!("tapper-{name}.xctestrun"));
        let base = plist_json(&self.xctestrun).await?;
        let edited = inject_environment(&base, &tapper_environment(action, &ALERT_LABELS, bound));
        write_plist_json(&run, &edited).await?;
        step(&format!("the tapper runs {action} on {}", self.udid));
        let log = evidence.join(format!("tapper-{name}.log"));
        let child = Command::new("xcodebuild")
            .arg("test-without-building")
            .arg("-xctestrun")
            .arg(&run)
            .arg("-destination")
            .arg(format!("id={}", self.udid))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("starting xcodebuild test-without-building")?;
        let output = timeout(
            Duration::from_secs(bound.saturating_add(600)),
            child.wait_with_output(),
        )
        .await
        .map_err(|_| anyhow!("the tapper's {action} action outlived its bound"))?
        .context("waiting for the tapper run")?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&log)
            .await
            .with_context(|| format!("writing {}", log.display()))?;
        file.write_all(text.as_bytes())
            .await
            .with_context(|| format!("writing {}", log.display()))?;
        if !output.status.success() {
            bail!(
                "the tapper's {action} action failed, its log in {}",
                log.display()
            );
        }
        Ok(())
    }
}

/// The `TEST_RUNNER_` environment one tapper action carries.
fn tapper_environment(action: &str, labels: &[&str], bound: u64) -> Value {
    json!({
        "TEST_RUNNER_ACTION": action,
        "TEST_RUNNER_LABELS": labels.join(","),
        "TEST_RUNNER_TIMEOUT": bound.to_string(),
    })
}

/// The run file with the action's environment written into each test
/// target's `EnvironmentVariables`, where xcodebuild hands it to the test
/// process on the device.
fn inject_environment(run: &Value, environment: &Value) -> Value {
    let mut run = run.clone();
    let Some(Value::Array(configurations)) = run.get_mut("TestConfigurations") else {
        return run;
    };
    for configuration in configurations.iter_mut().filter_map(Value::as_object_mut) {
        let Some(Value::Array(targets)) = configuration.get_mut("TestTargets") else {
            continue;
        };
        for target in targets.iter_mut().filter_map(Value::as_object_mut) {
            let variables = target
                .entry("EnvironmentVariables")
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let (Value::Object(variables), Value::Object(environment)) = (variables, environment)
            {
                for (key, value) in environment {
                    variables.insert(key.clone(), value.clone());
                }
            }
        }
    }
    run
}

/// Read a plist, in whatever flavor xcodebuild wrote it, as a JSON value.
async fn plist_json(path: &Path) -> Result<Value> {
    let json = plist_json_path(path);
    let status = Command::new("plutil")
        .arg("-convert")
        .arg("json")
        .arg("-o")
        .arg(&json)
        .arg(path)
        .status()
        .await
        .context("starting plutil")?;
    if !status.success() {
        bail!("plutil could not read {}", path.display());
    }
    serde_json::from_slice(
        &tokio::fs::read(&json)
            .await
            .with_context(|| format!("reading {}", json.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))
}

/// Write a JSON value as the XML plist xcodebuild reads back.
async fn write_plist_json(path: &Path, value: &Value) -> Result<()> {
    let json = plist_json_path(path);
    tokio::fs::write(&json, value.to_string())
        .await
        .with_context(|| format!("writing {}", json.display()))?;
    let status = Command::new("plutil")
        .arg("-convert")
        .arg("xml1")
        .arg("-o")
        .arg(path)
        .arg(&json)
        .status()
        .await
        .context("starting plutil")?;
    tokio::fs::remove_file(&json).await?;
    if !status.success() {
        bail!("plutil could not write {}", path.display());
    }
    Ok(())
}

/// The JSON file beside a plist the `plutil` round trip goes through.
fn plist_json_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.json",
        path.file_stem()
            .map_or("plist", |stem| stem.to_str().unwrap_or("plist"))
    ))
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
/// The team the run signs with, `CONNETTO_IOS_TEAM_ID` where it names one,
/// and else the team of the keychain's Apple Development certificate.
async fn signing_team() -> Result<String> {
    match std::env::var(TEAM_ID_VAR) {
        Ok(team) => Ok(team),
        Err(_) => team_prefix().await,
    }
}

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
    let id = format!("{team}.{}", bundle());
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

    /// A fresh session on the demo's page through a restarted proxy, for
    /// after a Personal Hotspot switch, which resets the USB link the proxy
    /// and every page session ride on.
    async fn reattach(&mut self) -> Result<PageSession> {
        self.restart_at = Instant::now();
        self.keep_alive().await?;
        self.page(is_demo_page).await
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

    /// `--every-join` walks the joins in the spec's order.
    #[test]
    fn the_every_join_walks_beacon_payload_form() {
        assert_eq!(
            super::JoinBy::EVERY.map(super::JoinBy::name),
            ["beacon", "payload", "form"]
        );
    }

    /// The argument checks name the missing or clashing flag.
    #[test]
    fn the_peer_arguments_are_checked() {
        let args = |parts: &[&str]| parts.iter().copied().map(String::from).collect::<Vec<_>>();
        assert!(super::parse_arguments(&args(&[])).is_ok());
        assert!(super::parse_arguments(&args(&["--simulator", "SIM-1"])).is_ok());
        assert!(
            super::parse_arguments(&args(&[
                "--device",
                "u1",
                "--identity",
                "sha1",
                "--peer-device",
                "u2"
            ]))
            .is_err(),
            "--peer-device without --every-join"
        );
        let every = [
            "--device",
            "u1",
            "--identity",
            "sha1",
            "--peer-device",
            "u2",
            "--every-join",
        ];
        assert!(
            super::parse_arguments(&every.iter().copied().map(String::from).collect::<Vec<_>>())
                .is_err(),
            "--every-join without the passphrase"
        );
        let complete = [&every[..], &["--hotspot-passphrase", "pass"]].concat();
        assert!(
            super::parse_arguments(
                &complete
                    .iter()
                    .copied()
                    .map(String::from)
                    .collect::<Vec<_>>()
            )
            .is_ok(),
            "a complete two-phone run"
        );
        for broken in [
            args(&["--simulator", "SIM-1", "--device", "u1"]),
            args(&["--device", "u1"]),
            args(&[
                "--device",
                "u1",
                "--identity",
                "sha1",
                "--peer-device",
                "u1",
                "--every-join",
                "--hotspot-passphrase",
                "pass",
            ]),
            args(&["--device", "u1", "--identity", "sha1", "--unknown"]),
        ] {
            assert!(super::parse_arguments(&broken).is_err(), "{broken:?}");
        }
    }

    /// The tapper's arguments write into each test target's
    /// `EnvironmentVariables`, where xcodebuild hands them to the test
    /// process on the device, and keep what is already there.
    #[test]
    fn the_tapper_environment_is_written_into_the_test_targets() {
        let run = serde_json::json!({
            "TestConfigurations": [
                {
                    "Name": "Test Scheme Action",
                    "TestTargets": [
                        {
                            "TestBundlePath": "Tapper.xctest",
                            "EnvironmentVariables": { "OTHER": "kept" }
                        }
                    ]
                }
            ]
        });
        let edited = super::inject_environment(
            &run,
            &super::tapper_environment("hotspot-on", &["Allow", "Consenti", "OK"], 60),
        );
        let variables = &edited["TestConfigurations"][0]["TestTargets"][0]["EnvironmentVariables"];
        assert_eq!(variables["OTHER"], "kept");
        assert_eq!(variables["TEST_RUNNER_ACTION"], "hotspot-on");
        assert_eq!(variables["TEST_RUNNER_LABELS"], "Allow,Consenti,OK");
        assert_eq!(variables["TEST_RUNNER_TIMEOUT"], "60");
        assert_eq!(
            edited["TestConfigurations"][0]["TestTargets"][0]["TestBundlePath"],
            "Tapper.xctest"
        );
        let bare = serde_json::json!({ "Actionable": { "ActionableBundlePath": "x" } });
        let edited = super::inject_environment(
            &bare,
            &super::tapper_environment("tap-alert", &["Join"], 30),
        );
        assert!(edited.get("TestConfigurations").is_none());
        assert_eq!(edited["Actionable"]["ActionableBundlePath"], "x");
    }
}
