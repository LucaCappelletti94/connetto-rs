//! Deploys `examples/dioxus-demo` to an iOS simulator or a paired
//! iPhone or iPad, or with `--demo tauri` `examples/tauri-leptos-demo` to a
//! simulator, and walks R88's proof on it, which is sign in, sync, write
//! offline and upload on reconnect, then R51's re-check after time away.
//!
//! With `--peer-device UDID --every-join --hotspot-passphrase PASS` a second
//! paired phone joins the first in one run (R76 slice 9a), the first hosting
//! its Personal Hotspot, which the `XCUITest` tapper under
//! `crates/connetto-test-harness/ios/` switches in Settings, and the second
//! joining it by beacon, payload and form in turn, the tapper tapping the
//! system's prompts, one summary beside the evidence.
//!
//! With `--device UDID --identity SHA1 --mac-peer --every-join
//! --hotspot-passphrase PASS` the second device is the Mac's own leg
//! (R76 slice 9c). The iPhone hosts its Personal Hotspot as above, and the
//! leg, a headless copy of this binary in the signed `ConnettoProofLeg.app`
//! under `target/proof-leg/`, started through `open` over its standard
//! streams, signs in, enrols, and joins by the typed form, the Bluetooth
//! beacon and the pasted `WIFI:` payload in turn, the Mac's `en0` back on
//! its home network between joins, one summary beside the evidence. The
//! platform's Location Services and Bluetooth prompts stand on the bundle's
//! own responsibility, so the maintainer allows them once, on the first
//! run, and the run itself takes no further taps.
//!
//! `--star` drives an iPhone, an iPad and an Android phone through Android-hosted and iPhone-hosted rounds. Each round requires all six directed peer observations after a 60s freshness interval and preserves its matrix, pages and cleanup result.
//!
//! It runs on a Mac through a private driver script passed to `connetto-demo-stack`, which supplies the stack environment without logging the script's password arguments.
//!
//! ```text
//! cargo build -p connetto-test-harness --bin connetto-ios-proof
//! cargo run -p connetto-test-harness --bin connetto-demo-stack -- sh private-proof.sh
//!
//! # Proof command usage
//! target/debug/connetto-ios-proof [--simulator UDID | --device UDID --identity SHA1] \
//!     [--demo dioxus|tauri] [--app PATH] \
//!     [--peer-device UDID --every-join | --mac-peer --every-join | \
//!      --star --peer-device UDID --android-peer SERIAL --android-apk APK] \
//!     [--hotspot-passphrase PASS]
//! ```
//!
//! A simulator build carries the keychain entitlements under the team ID
//! `CONNETTO_IOS_TEAM_ID` names or else the team prefix of the Mac's Apple
//! Development certificate, linked into the executable for the dioxus demo
//! and embedded by Xcode from the development team for the Tauri demo. The
//! simulator checks no signature against that ID, so any ID serves a Mac
//! without the certificate. A device build is signed with the identity
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

use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use connetto_client::BluetoothState;
use connetto_test_harness::android_phone;
use connetto_test_harness::demo::{order_count, wait_for_count};
use connetto_test_harness::inspector::{PageSession, list_pages};
use connetto_test_harness::ios_signing;
use connetto_test_harness::leg::LegClient;
use connetto_test_harness::leg_wire::parse_default_gateway;
use connetto_test_harness::peer_devices::{
    LINK_END_BOUND, own_identity, read_hotspot_offer, wait_link_ends,
};
use connetto_test_harness::peer_proof::{HotspotOfferLines, JoinReport, commit, summary};
use connetto_test_harness::relay::Relay;
use connetto_test_harness::stack::{
    TLS_CERT_VAR, TLS_KEY_VAR, demo_has_device_identity, demo_mobile_features, now_millis,
    repo_path,
};
use connetto_test_harness::star;
use connetto_test_harness::step;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt as _;
use tokio::process::{Child, Command};
use tokio::time::{Instant, sleep, timeout};

const DEMO_DIR: [&str; 2] = ["examples", "dioxus-demo"];
const APP: &str = "target/dx/connetto-dioxus-demo/debug/ios/ConnettoDioxusDemo.app";
const TAURI_DIR: [&str; 3] = ["examples", "tauri-leptos-demo", "src-tauri"];
/// Where `cargo tauri ios build` leaves a simulator build.
const TAURI_APP: &str = "gen/apple/build/arm64-sim/connetto-tauri-demo.app";

/// The demo the proof deploys, `--demo dioxus` (the default) or `--demo
/// tauri` (`examples/tauri-leptos-demo`).
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
        Demo::Dioxus => "connetto-dioxus-demo",
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
const ALERT_LABELS: [&str; 7] = [
    "Join",
    "Accedi",
    "Connetti",
    "Allow",
    "Consenti",
    "OK",
    "Continua a provare con la rete Wi-Fi",
];
/// The iOS development profile the tapper's runner signs with, as
/// `connetto-ios-signing` names it.
const TAPPER_PROFILE: &str = "connetto tapper development";
/// How long the Mac's `en0` gets to stand back on its home network after a
/// join's leave, measured at 10 s (R76 slice 9c).
const GATEWAY_BACK_BOUND: Duration = Duration::from_secs(60);
/// How long `route` gets to answer.
const ROUTE_BOUND: Duration = Duration::from_secs(10);
/// How long the Mac's Bluetooth gets to stand ready, which the first run's
/// prompt waits on.
const BT_READY_BOUND: Duration = Duration::from_secs(120);

/// The joins the mac walk makes, in the record's order (R76 slice 9c).
const MAC_JOINS: [JoinBy; 3] = [JoinBy::Form, JoinBy::Beacon, JoinBy::Payload];

fn main() -> Result<()> {
    // The leg re-runs this binary in its own process, over its standard
    // streams, which the proof drives with one JSON line per command, and
    // takes none of the runner's arguments.
    #[cfg(target_os = "macos")]
    const LEG_FLAG: &str = "--mac-leg";
    #[cfg(not(target_os = "macos"))]
    const LEG_FLAG: &str = "--linux-leg";
    if std::env::args().nth(1).as_deref() == Some(LEG_FLAG) {
        return connetto_test_harness::leg::leg_process();
    }
    let runtime = tokio::runtime::Runtime::new().context("starting the proof's runtime")?;
    runtime.block_on(driver())
}

/// The proof's own steps, apart from the leg's process.
async fn driver() -> Result<()> {
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
    let evidence = repo_path(&["target", "ios-proof"])?.join(format!(
        "{}{}-{}",
        if parsed.star { "star-" } else { "" },
        target.udid(),
        now_millis()
    ));
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
    let outcome = if parsed.star {
        star_walk(
            &target,
            &app,
            &stack,
            &evidence,
            &mut relay,
            &sync_url,
            identity.as_deref(),
            parsed.peer.as_deref(),
            parsed.android_peer.as_deref(),
            parsed.android_apk.as_deref(),
            parsed.android_unlock_pin.as_deref(),
            parsed.passphrase.as_deref(),
            parsed.join.unwrap_or_default(),
        )
        .await
    } else if parsed.every_join {
        every_join_walk(
            &target,
            &app,
            &stack,
            &evidence,
            &mut relay,
            &sync_url,
            identity.as_deref(),
            parsed.peer.as_deref(),
            parsed.mac_peer,
            parsed.passphrase.as_deref(),
        )
        .await
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

/// The `--every-join` run, which is the proof on the phone and, on a proved phone,
/// the joins beside it, the mac leg standing in the second phone's place
/// when `--mac-peer` stands.
#[expect(
    clippy::too_many_arguments,
    reason = "the phone, its build, the stack, the evidence, the relay, the sync url, the identity, the peer, the mac leg and the passphrase are each the run's own"
)]
async fn every_join_walk(
    target: &Target,
    app: &Path,
    stack: &Stack,
    evidence: &Path,
    relay: &mut Relay,
    sync_url: &str,
    identity: Option<&str>,
    peer: Option<&str>,
    mac_peer: bool,
    passphrase: Option<&str>,
) -> Result<()> {
    let started = Instant::now();
    let outcome = prove(target, app, stack, evidence, relay, sync_url).await;
    let proved = (
        started.elapsed(),
        outcome.as_ref().map_err(|err| format!("{err:#}")).map(drop),
    );
    // The joins run only on a proved phone, and a failed proof keeps its
    // own error.
    match &outcome {
        Ok(()) => {
            let identity = identity.context("a device run names no --identity")?;
            let passphrase = passphrase.context("a --every-join run names no passphrase")?;
            if mac_peer {
                // The mac leg stands in the second phone's place (R76
                // slice 9c), and a tapper that does not build fails the
                // joins' setup, which the summary records like any other.
                match Tapper::build(target.udid(), identity, evidence).await {
                    Ok(host_tapper) => {
                        mac_joins_with_summary(
                            target,
                            identity,
                            &host_tapper,
                            stack,
                            evidence,
                            passphrase,
                            sync_url,
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
            } else {
                let joiner = Target::Device {
                    udid: peer
                        .context("a --every-join run names no --peer-device")?
                        .to_owned(),
                    identity: identity.to_owned(),
                };
                // A tapper that does not build fails the joins' setup,
                // which the summary records like any other.
                let tappers = async {
                    let host = Tapper::build(target.udid(), identity, evidence).await?;
                    let joiner = Tapper::build(joiner.udid(), identity, evidence).await?;
                    Ok::<_, anyhow::Error>((host, joiner))
                }
                .await;
                match tappers {
                    Ok((host_tapper, joiner_tapper)) => {
                        joins_with_summary(
                            target,
                            &joiner,
                            app,
                            &host_tapper,
                            &joiner_tapper,
                            stack,
                            evidence,
                            passphrase,
                            sync_url,
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
        }
        Err(_) => outcome,
    }
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
    // Discovery's first browse asks for the local network after every
    // install, and the alert keeps the app inactive, so no login page opens.
    let tapper = match target {
        Target::Device { udid, identity } => Some(Tapper::build(udid, identity, evidence).await?),
        Target::Simulator { .. } => None,
    };

    step("sign in");
    target
        .launch(&[
            ("CONNETTO_DEMO_WS", sync_url),
            ("CONNETTO_DEMO_AUTH_ORIGIN", &stack.auth_origin),
            ("CONNETTO_DEMO_PG", &stack.pg_url),
        ])
        .await?;
    // A credential an aborted run left signed in starts discovery at launch.
    if let Some(tapper) = &tapper {
        tapper
            .run("tap-alert", 40, evidence, "local-network-at-launch")
            .await?;
    }
    let login_prefix = format!("{}/authorize?", stack.issuer);
    let mut app = sign_in(target, &mut inspector, &login_prefix, evidence, USER).await?;
    target.record(&mut app, evidence, "signed-in").await?;

    if demo_has_device_identity() {
        step("enrol the device");
        app.wait_for_text("device: certified until", Duration::from_secs(60))
            .await?;
        target
            .record(&mut app, evidence, "device-certified")
            .await?;
        if let Some(tapper) = &tapper {
            tapper
                .run("tap-alert", 40, evidence, "local-network")
                .await?;
        }
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
    user: &str,
) -> Result<PageSession> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut demo = String::from("no demo page");
    let observe = async {
        let mut submitted = false;
        loop {
            if !submitted
                && let Some(mut login) = inspector
                    .try_page(|url| url.starts_with(login_prefix))
                    .await?
            {
                target.screenshot(evidence, "login-page").await?;
                submit_login(&mut login, user).await?;
                submitted = true;
                continue;
            }
            if let Some(mut app) = inspector.try_page(is_demo_page).await? {
                match app.page_text().await {
                    Ok(text) => {
                        if text.contains("status: connected") {
                            if !submitted {
                                eprintln!(
                                    "an earlier credential signed the demo in, signing out first"
                                );
                                sign_out(&mut app).await?;
                            } else if text
                                .contains("custody: released only after user verification")
                            {
                                return Ok::<_, anyhow::Error>(app);
                            }
                        }
                        demo = text.split_whitespace().collect::<Vec<_>>().join(" ");
                    }
                    Err(err) => {
                        demo = format!("a page that did not answer ({err:#})");
                        eprintln!("{demo}, reattaching the inspector");
                        inspector.restart_at = Instant::now();
                    }
                }
            }
            inspector.keep_alive().await?;
            sleep(Duration::from_secs(1)).await;
        }
    };
    if let Ok(outcome) = tokio::time::timeout_at(deadline, observe).await {
        outcome
    } else {
        let shown: String = demo.chars().take(400).collect();
        bail!(
            "sign-in did not finish within 90s, the demo showed {shown:?}, {}",
            inspector.state()
        );
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
async fn submit_login(login: &mut PageSession, user: &str) -> Result<()> {
    let script = format!(
        "(() => {{ const u = document.querySelector('input[name=username]'); if (!u) return false; u.value = {}; u.form.submit(); return true; }})()",
        serde_json::Value::String(user.to_owned())
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

/// What the command line names, before anything runs.
#[derive(Default)]
struct ParsedArguments {
    simulator: Option<String>,
    device: Option<String>,
    identity: Option<String>,
    app: Option<PathBuf>,
    peer: Option<String>,
    mac_peer: bool,
    every_join: bool,
    passphrase: Option<String>,
    star: bool,
    android_peer: Option<String>,
    android_apk: Option<PathBuf>,
    android_unlock_pin: Option<String>,
    join: Option<star::Join>,
}

/// `--simulator`, or `--device` with `--identity`, `--app`, and, for the
/// two-phone run, `--peer-device`, `--every-join` and
/// `--hotspot-passphrase`, and, for the mac run, `--mac-peer` beside them,
/// and, for the star, the Android phone's arguments (R76 slice 9f).
#[expect(
    clippy::too_many_lines,
    reason = "mode validation stays beside argument parsing"
)]
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
            "--mac-peer" => arguments.mac_peer = true,
            "--hotspot-passphrase" => {
                arguments.passphrase = Some(argument_value(&mut args, arg)?.to_owned());
            }
            "--every-join" => arguments.every_join = true,
            "--star" => arguments.star = true,
            "--android-peer" => {
                arguments.android_peer = Some(argument_value(&mut args, arg)?.to_owned());
            }
            "--android-apk" => {
                arguments.android_apk =
                    Some(PathBuf::from(argument_value(&mut args, arg)?.to_owned()));
            }
            "--android-unlock-pin" => {
                arguments.android_unlock_pin = Some(argument_value(&mut args, arg)?.to_owned());
            }
            "--join" => {
                arguments.join = Some(star::Join::parse(argument_value(&mut args, arg)?)?);
            }
            other => bail!("unknown argument {other:?}"),
        }
    }
    if arguments.star && arguments.simulator.is_some() {
        bail!(
            "--star drives the iPhone, the iPad and the Android phone, so it needs --device, not --simulator"
        );
    }
    if arguments.star && arguments.every_join {
        bail!("give either --star or --every-join, not both");
    }
    if arguments.star && arguments.mac_peer {
        bail!("give either --star or --mac-peer, not both");
    }
    if arguments.star
        && (arguments.device.is_none()
            || arguments.identity.is_none()
            || arguments.peer.is_none()
            || arguments.android_peer.is_none()
            || arguments.android_apk.is_none()
            || arguments.passphrase.is_none())
    {
        bail!(
            "--star needs --device, --identity, --peer-device, --android-peer, --android-apk and --hotspot-passphrase"
        );
    }
    if arguments.simulator.is_some() && arguments.device.is_some() {
        bail!("give either --simulator or --device, not both");
    }
    if arguments.device.is_some() && arguments.identity.is_none() {
        bail!("--device needs the --identity connetto-ios-signing printed");
    }
    if arguments.mac_peer && arguments.peer.is_some() {
        bail!("give either --mac-peer or --peer-device, not both");
    }
    if arguments.mac_peer && arguments.simulator.is_some() {
        bail!("--mac-peer runs a paired phone and this Mac, so it needs --device, not --simulator");
    }
    if arguments.peer.is_some() && !arguments.every_join && !arguments.star {
        bail!("--peer-device needs --every-join or --star");
    }
    if arguments.mac_peer && !arguments.every_join {
        bail!("--mac-peer needs --every-join");
    }
    if arguments.every_join
        && (arguments.device.is_none()
            || arguments.identity.is_none()
            || arguments.passphrase.is_none()
            || (arguments.peer.is_none() && !arguments.mac_peer))
    {
        bail!(
            "--every-join needs --device, --identity, --hotspot-passphrase and --peer-device or --mac-peer"
        );
    }
    if arguments
        .device
        .as_deref()
        .zip(arguments.peer.as_deref())
        .is_some_and(|(device, peer)| device == peer)
    {
        bail!("--peer-device names the same device as --device");
    }
    if (arguments.every_join || arguments.star) && matches!(demo(), Demo::Tauri) {
        bail!("--every-join and --star need the dioxus demo, whose panel holds the peer controls");
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
            return self.build_tauri().await;
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

    /// Build the Tauri demo for the simulator. Xcode embeds the application
    /// identifier the keychain needs from the development team.
    async fn build_tauri(&self) -> Result<PathBuf> {
        let Self::Simulator { .. } = self else {
            bail!("the Tauri demo is proven on a simulator only");
        };
        let demo = repo_path(&TAURI_DIR)?;
        step("build");
        let mut cargo = Command::new("cargo");
        cargo
            .current_dir(&demo)
            .args([
                "tauri",
                "ios",
                "build",
                "--debug",
                "--target",
                "aarch64-sim",
            ])
            .env("APPLE_DEVELOPMENT_TEAM", signing_team().await?);
        if demo_has_device_identity() {
            cargo.args(["--features", "device-identity"]);
        }
        let status = cargo.status().await.context("starting cargo tauri")?;
        if !status.success() {
            bail!("cargo tauri ios build failed with {status}");
        }
        Ok(demo.join(TAURI_APP))
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

/// Make the joins, write the summary, and fail when any join failed, for
/// the mac leg's run.
#[expect(
    clippy::too_many_arguments,
    reason = "the phone, its tapper, the stack, the evidence, the passphrase, the sync url and the proof are each the run's own"
)]
async fn mac_joins_with_summary(
    host: &Target,
    identity: &str,
    host_tapper: &Tapper,
    stack: &Stack,
    evidence: &Path,
    passphrase: &str,
    sync_url: &str,
    proved: (Duration, Result<(), String>),
) -> Result<()> {
    let reports = mac_peer_proof(
        host,
        identity,
        host_tapper,
        stack,
        evidence,
        passphrase,
        sync_url,
    )
    .await;
    if let Err(err) = leave_signed_out(host, evidence).await {
        eprintln!("{} stayed signed in: {err:#}", host.udid());
    }
    if let Err(err) = host.copy_demo_log(evidence).await {
        eprintln!("the demo's log stayed on {}: {err:#}", host.udid());
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

/// The mac peer proof (R76 slice 9c), where the iPhone hosts its Personal
/// Hotspot, switched on by the tapper, and the mac leg signs in as its own
/// account, then joins it by the typed form, the Bluetooth beacon and the
/// pasted `WIFI:` payload in turn, each ending when both sides name the
/// other as linked. It ends with the iPhone back at rest, the Personal
/// Hotspot off and the Mac's `en0` on its home network.
async fn mac_peer_proof(
    host: &Target,
    identity: &str,
    host_tapper: &Tapper,
    stack: &Stack,
    evidence: &Path,
    passphrase: &str,
    sync_url: &str,
) -> Result<Vec<JoinReport>> {
    if !demo_has_device_identity() {
        bail!("the mac peer proof needs a demo build with its device identity");
    }
    // The Mac's usual gateway, read while it still stands on its home
    // network, which each join's cleanup must bring it back to.
    let home_gateway = mac_default_gateway()
        .await?
        .context("the Mac's default route names no gateway, the run cannot restore it")?;
    eprintln!("the Mac holds the gateway {home_gateway} until the run restores it");
    step("prepare the mac leg");
    let leg = LegClient::spawn(evidence, Some(identity)).await?;
    let (leg_identity, _) = leg.wait_ready().await?;
    mac_bluetooth_ready(&leg).await?;
    // The host signed out at the end of its proof, so it signs back in.
    let (mut host_inspector, mut host_app) =
        host_signed_back_in(host, stack, sync_url, evidence).await?;

    let host_identity = own_identity(&mut host_app).await?;
    // The Personal Hotspot names its network after the device.
    let host_name = device_name(host.udid()).await?;

    let reports = {
        let mut reports = Vec::with_capacity(MAC_JOINS.len());
        // A join whose cleanup failed leaves the joins after it unrun, since
        // the Mac no longer stands on its home network.
        let mut unclean: Option<JoinBy> = None;
        for &join in &MAC_JOINS {
            if let Some(previous) = unclean {
                reports.push(JoinReport {
                    name: join.name(),
                    took: None,
                    outcome: Err(anyhow!(
                        "the {} join's cleanup failed, so the Mac was not at rest",
                        previous.name()
                    )),
                });
                continue;
            }
            let started = Instant::now();
            let mut outcome = one_mac_join(
                host,
                &mut host_app,
                &mut host_inspector,
                &leg,
                host_tapper,
                evidence,
                (&host_identity, &leg_identity),
                &host_name,
                passphrase,
                join,
            )
            .await;
            if let Err(err) = &outcome {
                eprintln!("the {} join failed: {err:#}", join.name());
                let _ = host
                    .record(
                        &mut host_app,
                        evidence,
                        &format!("{}-failure-host", join.name()),
                    )
                    .await;
            }
            // The walk brings the Mac back to rest after each join.
            let cleanup = mac_back_to_rest(
                &mut host_app,
                &mut host_inspector,
                &leg,
                host_tapper,
                evidence,
                join.name(),
                home_gateway,
            )
            .await;
            let outcome = match cleanup {
                Ok(()) => outcome,
                Err(err) => {
                    if outcome.is_ok() {
                        outcome = Err(anyhow!(
                            "the {} join ended clean, but its cleanup failed: {err:#}",
                            join.name()
                        ));
                    } else {
                        eprintln!("the {} join's cleanup also failed: {err:#}", join.name());
                    }
                    unclean = Some(join);
                    outcome
                }
            };
            reports.push(JoinReport {
                name: join.name(),
                took: Some(started.elapsed()),
                outcome,
            });
        }
        reports
    };
    // The leg's close talks to it, so it runs before the walk ends.
    if let Err(err) = leg.close().await {
        eprintln!("the mac leg would not close: {err:#}");
    }
    Ok(reports)
}

/// Turn the Mac's Bluetooth on and hold until it stands ready, which the
/// first run's prompt waits on.
///
/// # Errors
///
/// When Bluetooth will not stand ready within [`BT_READY_BOUND`], or the
/// leg does not answer.
async fn mac_bluetooth_ready(leg: &LegClient) -> Result<()> {
    step("turn on Bluetooth on the mac");
    leg.enable_bluetooth().await?;
    let deadline = Instant::now() + BT_READY_BOUND;
    loop {
        if leg.bluetooth().await? == BluetoothState::Ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let standing = leg.bluetooth().await?;
            bail!(
                "the mac's Bluetooth never stood ready within {BT_READY_BOUND:?}, \
                 it stands: {standing:?}"
            );
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// The host signed out at the end of its proof, so sign it back in, its
/// inspector and its page standing ready at the account's line.
///
/// # Errors
///
/// When the launch, the sign-in or the account's line will not stand
/// within their bounds.
async fn host_signed_back_in(
    host: &Target,
    stack: &Stack,
    sync_url: &str,
    evidence: &Path,
) -> Result<(Inspector, PageSession)> {
    step("sign the host back in");
    host.launch(&[
        ("CONNETTO_DEMO_WS", sync_url),
        ("CONNETTO_DEMO_AUTH_ORIGIN", &stack.auth_origin),
        ("CONNETTO_DEMO_PG", &stack.pg_url),
    ])
    .await?;
    let mut host_inspector = Inspector::start(host, evidence).await?;
    let login_prefix = format!("{}/authorize?", stack.issuer);
    let mut host_app = sign_in(host, &mut host_inspector, &login_prefix, evidence, USER).await?;
    host_app
        .wait_for_text("device: certified until", Duration::from_secs(60))
        .await?;
    host.record(&mut host_app, evidence, "host-signed-in")
        .await?;
    Ok((host_inspector, host_app))
}

/// One join, from a Personal Hotspot hosted on the iPhone to the link's
/// end, and the machines back at rest whatever happened.
#[expect(
    clippy::too_many_arguments,
    reason = "the phone, its page, its inspector, its tapper, the leg, the evidence, both identities, the hotspot name and password and the join are each the step's own"
)]
async fn one_mac_join(
    host: &Target,
    host_app: &mut PageSession,
    host_inspector: &mut Inspector,
    leg: &LegClient,
    host_tapper: &Tapper,
    evidence: &Path,
    (host_identity, leg_identity): (&str, &str),
    host_name: &str,
    passphrase: &str,
    join: JoinBy,
) -> Result<()> {
    let shot = |name: &str| format!("{}-{name}", join.name());
    step(&format!(
        "turn Personal Hotspot on on the iPhone for the {} join",
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
        "host the Personal Hotspot on the iPhone for the {} join",
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
    let walked = async {
        let gateway = match join {
            JoinBy::Form => {
                step("fill the join form on the mac");
                leg.join_form(&offer.ssid, &offer.passphrase, offer.port)
                    .await?
            }
            JoinBy::Beacon => {
                step("find the beacon on the mac");
                // The iPhone's beacon carries no prefix (R76 decision 25),
                // so the lone host in sight is the one to join.
                read_beacon_prefix(host_app).await?;
                let host = leg.wait_nearby(None).await?;
                leg.join_nearby(&host).await?.1
            }
            JoinBy::Payload => {
                let payload = offer
                    .payload
                    .as_deref()
                    .context("the host shows no WIFI: payload")?;
                step("paste the payload on the mac");
                leg.join_payload(payload).await?
            }
        };
        eprintln!("the leg joined through the gateway {gateway}");
        // A client joining the Personal Hotspot resets the USB link the
        // page session rode on, so the link is read through a fresh one.
        *host_app = host_inspector.reattach().await?;
        step("link through the hotspot");
        host_app
            .wait_for_text(&format!("linked: {leg_identity}"), Duration::from_secs(90))
            .await
            .context("the iPhone never named the leg as linked")?;
        leg.wait_linked(host_identity, Duration::from_secs(30))
            .await?;
        host.record(host_app, evidence, &shot("host-linked"))
            .await?;
        step("leave the hotspot on the mac");
        leg.leave().await?;
        // The client leaving resets the USB link as its joining did.
        *host_app = host_inspector.reattach().await?;
        step("stop the hotspot on the iPhone");
        stop_hosting(host_inspector, host_app).await?;
        wait_link_ends_host(host_inspector, host_app, leg, host_identity).await?;
        host.record(host_app, evidence, &shot("host-unlinked"))
            .await
    }
    .await;
    // Back to rest whatever happened, so the next join starts clean, the
    // first failure kept.
    if walked.is_err() {
        if let Ok(fresh) = host_inspector.reattach().await {
            *host_app = fresh;
        }
        let _ = host_app.click("Stop the hotspot").await;
    }
    walked
}

/// The cleanup after one join, the leg's leave, the Personal Hotspot off,
/// and the Mac's `en0` back on its home network.
///
/// # Errors
///
/// When the Personal Hotspot will not switch off, or the gateway never
/// stands back within its bound.
async fn mac_back_to_rest(
    host_app: &mut PageSession,
    host_inspector: &mut Inspector,
    leg: &LegClient,
    host_tapper: &Tapper,
    evidence: &Path,
    join_name: &'static str,
    home_gateway: IpAddr,
) -> Result<()> {
    // The leg's leave is a no-op once the join's clean end did it.
    if let Err(err) = leg.leave().await {
        eprintln!("the mac leg did not answer its leave: {err:#}");
    }
    step(&format!(
        "turn Personal Hotspot off on the iPhone after the {join_name} join"
    ));
    switch_and_reattach(
        false,
        host_tapper,
        host_inspector,
        host_app,
        evidence,
        &format!("{join_name}-hotspot-off"),
    )
    .await?;
    // A host still hosting hides the next join's form, so the cleanup ends
    // only once the page offers that form again.
    stop_hosting(host_inspector, host_app).await?;
    host_app
        .wait_for_text("Host my Personal Hotspot", Duration::from_secs(30))
        .await
        .context("the iPhone's page never offered its host form again")?;
    step("wait for the Mac's gateway back on its home network");
    wait_gateway_back(home_gateway).await
}

/// The host's beacon line off its page, `advertising` with its prefix,
/// bounded.
///
/// # Errors
///
/// When the beacon never advertises, or its line never carries a prefix.
async fn read_beacon_prefix(host_app: &mut PageSession) -> Result<String> {
    host_app
        .wait_for_text("beacon: advertising", Duration::from_secs(60))
        .await
        .context("the host's beacon never advertised")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let page = host_app.page_text().await?;
        if let Some(line) = page
            .lines()
            .find(|line| line.starts_with("beacon: advertising "))
        {
            return Ok(line["beacon: advertising ".len()..].trim().to_owned());
        }
        if Instant::now() >= deadline {
            bail!("the beacon line never carried a prefix, the page shows:\n{page}");
        }
        sleep(Duration::from_millis(500)).await;
    }
}

/// The Mac's default gateway, off `route -n get default`, absent while the
/// answer names none.
///
/// # Errors
///
/// When `route` will not answer within its bound.
async fn mac_default_gateway() -> Result<Option<IpAddr>> {
    let output = timeout(
        ROUTE_BOUND,
        Command::new("route")
            .args(["-n", "get", "default"])
            .output(),
    )
    .await
    .map_err(|_| anyhow!("route gave no answer within {ROUTE_BOUND:?}"))?
    .context("starting route")?;
    Ok(parse_default_gateway(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Hold until the Mac's default gateway stands back at `usual`, which a
/// leave and a Personal Hotspot off bring it back to.
///
/// # Errors
///
/// When the gateway never stands back within [`GATEWAY_BACK_BOUND`].
async fn wait_gateway_back(usual: IpAddr) -> Result<()> {
    let deadline = Instant::now() + GATEWAY_BACK_BOUND;
    loop {
        match mac_default_gateway().await? {
            Some(gateway) if gateway == usual => return Ok(()),
            other => {
                if Instant::now() >= deadline {
                    bail!("the Mac's gateway never stood back at {usual}, it stands: {other:?}");
                }
            }
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Stop the iPhone's hosting where its page still shows it. A client
/// leaving the Personal Hotspot resets the USB link the page session rides
/// on some moments later, so a failed attempt takes a fresh session and
/// tries once more.
///
/// # Errors
///
/// When the page cannot be read or the stop not clicked on a fresh session
/// either.
async fn stop_hosting(host_inspector: &mut Inspector, host_app: &mut PageSession) -> Result<()> {
    let attempt = async |app: &mut PageSession| -> Result<()> {
        if app.page_text().await?.contains("hotspot: hosting") {
            app.click("Stop the hotspot").await?;
        }
        Ok(())
    };
    if let Err(err) = attempt(host_app).await {
        eprintln!("the iPhone's page did not take the stop ({err:#}), on a fresh session");
        *host_app = host_inspector.reattach().await?;
        attempt(host_app).await?;
    }
    Ok(())
}

/// Wait until the iPhone drops its linked line and the leg the iPhone's
/// name, which the leave and the stop end the link. A page read the USB
/// reset breaks is taken again on a fresh session within the bound.
///
/// # Errors
///
/// When a link line stays past [`LINK_END_BOUND`], or the leg does not
/// answer.
async fn wait_link_ends_host(
    host_inspector: &mut Inspector,
    host_app: &mut PageSession,
    leg: &LegClient,
    host_identity: &str,
) -> Result<()> {
    let deadline = Instant::now() + LINK_END_BOUND;
    loop {
        let page = match host_app.page_text().await {
            Ok(page) => Some(page),
            Err(err) => {
                eprintln!("the iPhone's page did not answer ({err:#}), on a fresh session");
                if let Ok(fresh) = host_inspector.reattach().await {
                    *host_app = fresh;
                }
                None
            }
        };
        let linked = leg.linked().await?;
        if let Some(page) = page
            && !page.contains("linked: ")
            && !linked.iter().any(|held| held == host_identity)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the link did not end after the leg left the hotspot");
        }
        sleep(Duration::from_secs(2)).await;
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
    let mut peer_app =
        sign_in(joiner, &mut joiner_inspector, &login_prefix, evidence, USER).await?;
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
    let (mut host_inspector, mut host_app) =
        host_signed_back_in(host, stack, sync_url, evidence).await?;

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

        join_on_second_phone(
            join,
            join.name(),
            &offer,
            joiner,
            peer_app,
            joiner_tapper,
            evidence,
        )
        .await?;
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
/// tapped. The evidence takes the names the caller gives in `shot`, which
/// the star uses to tell its two joiners apart.
async fn join_on_second_phone(
    join: JoinBy,
    shot: &str,
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
                .record(peer_app, evidence, &format!("{shot}-peer-nearby"))
                .await?;
            peer_app.click("Join the nearby host").await?;
            // The line shows while the exchange and then the join run,
            // behind which the system's prompts stand.
            peer_app
                .wait_for_text("joining the nearby host", Duration::from_secs(10))
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
        }
    }
    let bound = if join == JoinBy::Beacon { 90 } else { 60 };
    joiner_tapper
        .run(
            "tap-join-alert",
            bound,
            evidence,
            &format!("{shot}-joiner-alert"),
        )
        .await?;
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

/// Run `action` on the page, once more on a fresh session when the inspector
/// session dropped, since a Personal Hotspot switch resets the USB link some
/// seconds after the runner reattached.
async fn on_page<T>(
    inspector: &mut Inspector,
    app: &mut PageSession,
    mut action: impl AsyncFnMut(&mut PageSession) -> Result<T>,
) -> Result<T> {
    match action(app).await {
        Err(err) if session_dropped(&err) => {
            eprintln!("the page session dropped ({err:#}), on a fresh session");
            *app = inspector.reattach().await?;
            action(app).await
        }
        outcome => outcome,
    }
}

/// Whether the error is the inspector session's own, not the page's answer.
fn session_dropped(err: &anyhow::Error) -> bool {
    let text = format!("{err:#}");
    text.contains("inspector session") || text.contains("inspector request")
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
            // `run` writes its `tapper-<name>.xctestrun` files beside the build's own.
            let own_run = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("tapper-"));
            if path.extension().is_some_and(|ext| ext == "xctestrun") && !own_run {
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
        // A switch that resets the USB link leaves xcodebuild collecting the
        // device's diagnostics until its own ten-minute bound, and asking for
        // a password on the terminal, so it collects none and reads nothing.
        let child = Command::new("xcodebuild")
            .arg("test-without-building")
            .arg("-xctestrun")
            .arg(&run)
            .arg("-destination")
            .arg(format!("id={}", self.udid))
            .arg("-collect-test-diagnostics")
            .arg("never")
            .stdin(std::process::Stdio::null())
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

// The handheld star (R76 slice 9f): the two rounds where the iPhone, the
// iPad and the Android phone share one hotspot at a time.

/// The star's Android phone: its `adb`, and the setting and the network the
/// run restores it to.
struct StarAndroid {
    /// The phone at its `adb`.
    device: android_phone::Device,
    /// The screen-on setting the run restores.
    stay_on: Option<String>,
    /// The error dialogs' setting the run restores.
    error_dialogs: Option<String>,
    /// The browser role holder the run restores.
    browser_holder: Option<String>,
    /// The network the phone stands on before the run.
    usual_ssid: Option<String>,
}

/// One of the star's three pages, read through a session that a broken read
/// replaces from its own inspector or `adb` within the bound.
enum StarPage<'a> {
    /// An iOS handheld's page on its inspector.
    Ios {
        app: &'a mut PageSession,
        inspector: &'a mut Inspector,
    },
    /// The Android phone's page on its `adb` link.
    Android {
        device: &'a android_phone::Device,
        app: &'a mut PageSession,
    },
}

impl StarPage<'_> {
    /// The page's text, on a fresh session when the page did not answer. The
    /// match binds the fields' references through one more level, so each
    /// arm reborrows them at their own depth.
    async fn text(&mut self) -> Result<String> {
        match self {
            Self::Ios { app, inspector } => {
                let app = &mut **app;
                let inspector = &mut **inspector;
                match app.page_text().await {
                    Ok(text) => Ok(text),
                    Err(err) => {
                        eprintln!("the page did not answer ({err:#}), on a fresh session");
                        *app = inspector.reattach().await?;
                        app.page_text().await
                    }
                }
            }
            Self::Android { device, app } => {
                let app = &mut **app;
                let device = &**device;
                match app.page_text().await {
                    Ok(text) => Ok(text),
                    Err(err) => {
                        eprintln!("the Android page did not answer ({err:#}), on a fresh session");
                        *app = device.app().await?;
                        app.page_text().await
                    }
                }
            }
        }
    }

    async fn leave_hotspot(&mut self) -> Result<()> {
        if !self.text().await?.contains("Leave the hotspot") {
            return Ok(());
        }
        match self {
            Self::Ios { app, .. } | Self::Android { app, .. } => {
                app.click("Leave the hotspot").await
            }
        }
    }
}

/// The `JoinBy` a star's join uses on the iOS joiner.
fn join_by(join: star::Join) -> JoinBy {
    match join {
        star::Join::Beacon => JoinBy::Beacon,
        star::Join::Payload => JoinBy::Payload,
        star::Join::Form => JoinBy::Form,
    }
}

/// The name a step's report reads, the way the summary prints it.
fn step_name(round: star::Round, joiner: star::Device, join: star::Join) -> String {
    format!(
        "{} round, the {} joins by the {}",
        round.name(),
        joiner.name(),
        join.name()
    )
}

/// The round whose early steps failed, every step carrying the same error.
fn failed_round(plan: star::RoundPlan, err: &anyhow::Error) -> star::RoundReport {
    let round = plan.round;
    let failed = |name: String| star::StepReport {
        name,
        took: Duration::from_secs(0),
        outcome: Err(format!("{err:#}")),
    };
    star::RoundReport {
        round,
        joins: [
            failed(step_name(round, plan.joiners[0], plan.join)),
            failed(step_name(round, plan.joiners[1], plan.join)),
        ],
        link: failed(format!("{} round, the three-way link", round.name())),
        restore: failed(format!("{} round, the restore", round.name())),
    }
}

async fn read_star_pages(pages: [&mut StarPage<'_>; 3], deadline: Instant) -> [Result<String>; 3] {
    let [first, second, third] = pages;
    let (first, second, third) = tokio::join!(
        tokio::time::timeout_at(deadline, first.text()),
        tokio::time::timeout_at(deadline, second.text()),
        tokio::time::timeout_at(deadline, third.text()),
    );
    [first, second, third]
        .map(|result| result.context("reading a star page exceeded its deadline")?)
}

async fn wait_star_link(
    pages: [&mut StarPage<'_>; 3],
    names: [&str; 3],
    identities: [&str; 3],
    evidence: &Path,
    round: star::Round,
    gateway: &mut Option<std::net::Ipv4Addr>,
) -> Result<()> {
    let [first, second, third] = pages;
    observe_star_link(
        async |deadline| read_star_pages([&mut *first, &mut *second, &mut *third], deadline).await,
        names,
        identities,
        evidence,
        round,
        gateway,
    )
    .await
}

/// Hold until every star page names the other two as linked through the
/// round's hotspot, learning its gateway off a joiner's page, and write the
/// matrix and the three pages to the evidence.
async fn observe_star_link(
    mut read: impl AsyncFnMut(Instant) -> [Result<String>; 3],
    names: [&str; 3],
    identities: [&str; 3],
    evidence: &Path,
    round: star::Round,
    gateway: &mut Option<std::net::Ipv4Addr>,
) -> Result<()> {
    let started = Instant::now();
    let deadline = started + Duration::from_secs(120);
    // Expired home-network links must age past the peer's 45s silence bound.
    let fresh_after = started + Duration::from_secs(60);
    let mut texts: [Option<String>; 3] = [None, None, None];
    let mut failures: [Option<String>; 3] = [None, None, None];
    let mut matrix = star::LinkMatrix::from_pages(identities, ["", "", ""], *gateway);
    let mut passed = false;
    while Instant::now() < deadline {
        let read_started = Instant::now();
        let read_deadline = deadline.min(read_started + Duration::from_secs(15));
        let answers = match tokio::time::timeout_at(deadline, read(read_deadline)).await {
            Ok(answers) => answers,
            Err(_) => std::array::from_fn(|_| Err(anyhow!("the observation deadline expired"))),
        };
        let mut complete = true;
        let mut answered = false;
        for (index, answer) in answers.into_iter().enumerate() {
            match answer {
                Ok(text) => {
                    texts[index] = Some(text);
                    failures[index] = None;
                    answered = true;
                }
                Err(error) => {
                    failures[index] = Some(format!("{error:#}"));
                    complete = false;
                }
            }
        }
        if answered {
            if gateway.is_none() {
                *gateway = texts
                    .iter()
                    .flatten()
                    .find_map(|text| star::hotspot_gateway(text));
            }
            matrix = star::LinkMatrix::from_pages(
                identities,
                texts.each_ref().map(|text| text.as_deref().unwrap_or("")),
                *gateway,
            );
        }
        if complete && read_started >= fresh_after && matrix.holds() {
            passed = true;
            break;
        }
        tokio::time::sleep_until(deadline.min(Instant::now() + Duration::from_secs(2))).await;
    }
    write_star_matrix(&texts, &failures, matrix, names, evidence, round, passed).await?;
    if passed {
        return Ok(());
    }
    let mut missing = matrix.missing(names);
    missing.extend(failures.iter().enumerate().filter_map(|(index, failure)| {
        failure
            .as_ref()
            .map(|failure| format!("{} could not be read ({failure})", names[index]))
    }));
    if missing.is_empty() {
        missing.push("no complete current observation after the freshness boundary".to_owned());
    }
    bail!("the three-way link did not hold, {}", missing.join(", "));
}

async fn write_star_matrix(
    texts: &[Option<String>; 3],
    failures: &[Option<String>; 3],
    matrix: star::LinkMatrix,
    names: [&str; 3],
    evidence: &Path,
    round: star::Round,
    passed: bool,
) -> Result<()> {
    let name = round.name();
    let mut shown = if passed {
        String::new()
    } else {
        "last observed links\n".to_owned()
    };
    shown.push_str(&matrix.text(names));
    shown.push('\n');
    for (index, failure) in failures.iter().enumerate() {
        if let Some(failure) = failure {
            shown.push_str(names[index]);
            shown.push_str(" could not be read (");
            shown.push_str(failure);
            shown.push_str(")\n");
        }
    }
    tokio::fs::write(evidence.join(format!("link-matrix-{name}.txt")), shown)
        .await
        .context("writing the link matrix")?;
    for (index, text) in texts.iter().enumerate() {
        if let Some(text) = text {
            tokio::fs::write(
                evidence.join(format!("link-matrix-{name}-{}.txt", names[index])),
                text,
            )
            .await
            .context("writing a link-matrix page")?;
        }
    }
    Ok(())
}

/// Hold until no star page names a peer through the round's hotspot, which
/// the leaves and the stop end. Links over any other network stay.
async fn wait_star_links_end(
    pages: [&mut StarPage<'_>; 3],
    gateway: Option<std::net::Ipv4Addr>,
) -> Result<()> {
    if gateway.is_none() {
        return Ok(());
    }
    let deadline = Instant::now() + LINK_END_BOUND;
    let [first, second, third] = pages;
    while Instant::now() < deadline {
        let read_deadline = deadline.min(Instant::now() + Duration::from_secs(15));
        let answers =
            read_star_pages([&mut *first, &mut *second, &mut *third], read_deadline).await;
        if answers.iter().all(|answer| {
            answer
                .as_ref()
                .is_ok_and(|text| !star::names_hotspot_link(text, gateway))
        }) {
            return Ok(());
        }
        tokio::time::sleep_until(deadline.min(Instant::now() + Duration::from_secs(2))).await;
    }
    bail!("link termination could not be observed within {LINK_END_BOUND:?}");
}

async fn restore_android_network(android: &StarAndroid) -> Result<()> {
    android
        .device
        .adb(&["shell", "svc", "wifi", "enable"])
        .await?;
    if let Some(ssid) = &android.usual_ssid {
        android.device.restore_network(ssid).await?;
    }
    Ok(())
}

/// The star's one-time Android setup: the phone awake and unlocked, the demo
/// installed clear of its earlier run, the links the demo dials reversed, the
/// Bluetooth permissions granted and its own account signed in.
async fn star_android_setup(
    device: android_phone::Device,
    apk: &Path,
    stack: &Stack,
    evidence: &Path,
    unlock_pin: Option<&str>,
) -> Result<(StarAndroid, Result<(), String>)> {
    // The run's own values of the phone's settings, read before it moves
    // any of them, so a failed setup still brings them back.
    let (device, usual_ssid, stay_on, error_dialogs, browser_holder) = async {
        let usual_ssid = device.current_ssid().await?;
        let stay_on = device.global_setting(android_phone::STAY_ON).await?;
        let error_dialogs = device
            .global_setting(android_phone::HIDE_ERROR_DIALOGS)
            .await?;
        // The login tab is read through Chrome's DevTools socket, so Chrome
        // holds the browser role for the run and the device's own choice
        // returns after.
        let browser_holder = device.browser_role_holder().await?;
        Ok::<
            (
                android_phone::Device,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            ),
            anyhow::Error,
        >((device, usual_ssid, stay_on, error_dialogs, browser_holder))
    }
    .await?;
    let star = StarAndroid {
        device,
        stay_on,
        error_dialogs,
        browser_holder,
        usual_ssid,
    };
    let outcome = async {
        star.device.hide_error_dialogs().await?;
        star.device
            .adb(&["shell", "svc", "power", "stayon", "true"])
            .await?;
        star.device
            .adb(&["shell", "input", "keyevent", "KEYCODE_WAKEUP"])
            .await?;
        let unlock = android_phone::Unlock { pin: unlock_pin };
        unlock.dismiss_keyguard(&star.device).await?;
        step("install the demo on the Android phone");
        let package = android_phone::Demo::Dioxus.package();
        star.device
            .adb(&["install", "-r", "-t", &apk.display().to_string()])
            .await?;
        star.device.adb(&["shell", "pm", "clear", package]).await?;
        star.device.adb(&["logcat", "-c"]).await?;
        star.device.adb(&["reverse", "--remove-all"]).await?;
        let reverse = android_phone::parse_reverse(
            &std::env::var("CONNETTO_DEMO_ADB_REVERSE").with_context(
                || "CONNETTO_DEMO_ADB_REVERSE is unset, run under connetto-demo-stack",
            )?,
        )?;
        for (device_port, host_port) in &reverse {
            star.device.reverse(*device_port, *host_port).await?;
        }
        for permission in android_phone::BT_PERMISSIONS {
            star.device
                .adb(&["shell", "pm", "grant", package, permission])
                .await?;
        }
        star.device
            .adb(&[
                "shell",
                "pm",
                "grant",
                package,
                "android.permission.NEARBY_WIFI_DEVICES",
            ])
            .await?;
        step("sign in the Android phone");
        android_phone::sign_in_phone(
            &star.device,
            star::Device::Android.account(),
            &stack.issuer,
            evidence,
            unlock,
            "android",
        )
        .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    Ok((star, outcome.map_err(|err| format!("{err:#}"))))
}

/// The iPad standing signed in as its own account: its earlier page
/// reattached when it is still up, a fresh install and sign-in otherwise.
async fn ipad_signed_in(
    ipad: &Target,
    fresh: bool,
    app: &Path,
    stack: &Stack,
    evidence: &Path,
    sync_url: &str,
) -> Result<(Inspector, PageSession)> {
    if !fresh {
        let mut inspector = Inspector::start(ipad, evidence).await?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Some(mut page) = inspector.try_page(is_demo_page).await?
                && page.page_text().await?.contains("status: connected")
            {
                return Ok((inspector, page));
            }
            sleep(Duration::from_secs(1)).await;
        }
    }
    step("install the demo on the iPad");
    ipad.install(app).await?;
    let mut inspector = Inspector::start(ipad, evidence).await?;
    ipad.launch(&[
        ("CONNETTO_DEMO_WS", sync_url),
        ("CONNETTO_DEMO_AUTH_ORIGIN", &stack.auth_origin),
        ("CONNETTO_DEMO_PG", &stack.pg_url),
    ])
    .await?;
    step("sign in the iPad");
    let login_prefix = format!("{}/authorize?", stack.issuer);
    let page = sign_in(
        ipad,
        &mut inspector,
        &login_prefix,
        evidence,
        star::Device::IPad.account(),
    )
    .await?;
    Ok((inspector, page))
}

/// The star's round restore, which the round runs whatever its steps did:
/// the joiners leave, the host stops its hotspot, the links end and the
/// network the round moved comes back, the first failure kept.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the two iOS handhelds' pages and inspectors, the Android phone, the round, the host's kind, the tapper and the evidence are each the restore's own"
)]
async fn star_round_restore(
    iphone_app: &mut PageSession,
    iphone_inspector: &mut Inspector,
    ipad_app: &mut PageSession,
    ipad_inspector: &mut Inspector,
    android: &StarAndroid,
    round: star::Round,
    personal_hotspot: bool,
    gateway: Option<std::net::Ipv4Addr>,
    iphone_tapper: &Tapper,
    evidence: &Path,
) -> (Duration, Result<(), String>) {
    let started = Instant::now();
    let outcome = async {
        step("leave the hotspots");
        let mut fail = Ok::<(), anyhow::Error>(());
        if let Err(err) = (StarPage::Ios {
            app: ipad_app,
            inspector: ipad_inspector,
        })
        .leave_hotspot()
        .await
        {
            eprintln!("the iPad's leave: {err:#}");
            fail = fail.and(Err(err));
        }
        if personal_hotspot {
            let android_leave = async {
                let mut android_app = android.device.app().await?;
                StarPage::Android {
                    device: &android.device,
                    app: &mut android_app,
                }
                .leave_hotspot()
                .await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if let Err(err) = android_leave {
                eprintln!("the Android phone's leave: {err:#}");
                fail = fail.and(Err(err));
            }
            if let Err(err) = android
                .device
                .adb(&["shell", "am", "force-stop", "com.android.settings"])
                .await
            {
                eprintln!("closing the Android network approval: {err:#}");
                fail = fail.and(Err(err));
            }
            let stop = stop_hosting(iphone_inspector, iphone_app).await;
            if let Err(err) = stop {
                eprintln!("the iPhone's stop: {err:#}");
                fail = fail.and(Err(err));
            }
            let off = switch_and_reattach(
                false,
                iphone_tapper,
                iphone_inspector,
                iphone_app,
                evidence,
                "iphone-hosts-hotspot-off",
            )
            .await;
            if let Err(err) = off {
                eprintln!("the iPhone's Personal Hotspot off: {err:#}");
                fail = fail.and(Err(err));
            }
        } else {
            if let Err(err) = (StarPage::Ios {
                app: iphone_app,
                inspector: iphone_inspector,
            })
            .leave_hotspot()
            .await
            {
                eprintln!("the iPhone's leave: {err:#}");
                fail = fail.and(Err(err));
            }
            let stop = async {
                let attempt = async |app: &mut PageSession| {
                    if app.page_text().await?.contains("hotspot: hosting") {
                        app.click("Stop the hotspot").await?;
                    }
                    Ok::<(), anyhow::Error>(())
                };
                let mut android_app = android.device.app().await?;
                if let Err(err) = attempt(&mut android_app).await {
                    eprintln!(
                        "the Android page did not take the stop ({err:#}), on a fresh session"
                    );
                    android_app = android.device.app().await?;
                    attempt(&mut android_app).await?;
                }
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if let Err(err) = stop {
                eprintln!("the Android phone's stop: {err:#}");
                fail = fail.and(Err(err));
            }
        }
        let links_end = async {
            let mut android_app = android.device.app().await?;
            wait_star_links_end(
                [
                    &mut StarPage::Ios {
                        app: iphone_app,
                        inspector: iphone_inspector,
                    },
                    &mut StarPage::Ios {
                        app: ipad_app,
                        inspector: ipad_inspector,
                    },
                    &mut StarPage::Android {
                        device: &android.device,
                        app: &mut android_app,
                    },
                ],
                gateway,
            )
            .await
        }
        .await;
        if let Err(err) = links_end {
            eprintln!("the links' end: {err:#}");
            fail = fail.and(Err(err));
        }
        if let Err(err) = restore_android_network(android).await {
            eprintln!("the Android phone's usual network: {err:#}");
            fail = fail.and(Err(err));
        }
        let bluetooth = android_phone::bluetooth_off(&android.device).await;
        if let Err(err) = bluetooth {
            eprintln!("the Android Bluetooth off: {err:#}");
            fail = fail.and(Err(err));
        }
        if let Err(err) = &fail {
            eprintln!("the {} round's restore: {err:#}", round.name());
        }
        fail
    }
    .await;
    (started.elapsed(), outcome.map_err(|err| format!("{err:#}")))
}

/// The round's report whose steps all failed with one error, the restore
/// carrying its own outcome.
fn round_report_failed(
    plan: star::RoundPlan,
    err: &str,
    restore: (Duration, Result<(), String>),
) -> star::RoundReport {
    let round = plan.round;
    let failed = |name: String| star::StepReport {
        name,
        took: Duration::from_secs(0),
        outcome: Err(err.to_owned()),
    };
    star::RoundReport {
        round,
        joins: [
            failed(step_name(round, plan.joiners[0], plan.join)),
            failed(step_name(round, plan.joiners[1], plan.join)),
        ],
        link: failed(format!("{} round, the three-way link", round.name())),
        restore: star::StepReport {
            name: format!("{} round, the restore", round.name()),
            took: restore.0,
            outcome: restore.1,
        },
    }
}

/// The star's first round: the Android phone hosts its local-only hotspot,
/// and the iPhone and the iPad join it and stay joined until every device
/// links to every other. It ends with the hotspot down, every link ended and
/// the Android phone back on its usual network, off Bluetooth.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the plan, the two iOS handhelds, the Android phone, both tappers, the build, the stack, the evidence and the sync url are each the round's own"
)]
async fn android_hosts_round(
    plan: &star::RoundPlan,
    target: &Target,
    ipad: &Target,
    android: &StarAndroid,
    iphone_tapper: &Tapper,
    ipad_tapper: &Tapper,
    app: &Path,
    stack: &Stack,
    evidence: &Path,
    sync_url: &str,
) -> star::RoundReport {
    let round = plan.round;
    let names: [&str; 3] = [
        star::Device::IPhone.name(),
        star::Device::IPad.name(),
        star::Device::Android.name(),
    ];
    // The iPhone signed out at the end of its proof, so it signs back in.
    let (mut iphone_inspector, mut iphone_app) =
        match host_signed_back_in(target, stack, sync_url, evidence).await {
            Ok(pages) => pages,
            Err(err) => return failed_round(*plan, &err),
        };
    // The iPad is the run's fresh third device.
    let (mut ipad_inspector, mut ipad_app) =
        match ipad_signed_in(ipad, true, app, stack, evidence, sync_url).await {
            Ok(pages) => pages,
            Err(err) => return failed_round(*plan, &err),
        };
    let join = join_by(plan.join);
    let setup = async {
        ipad_tapper
            .run(
                "tap-alert",
                40,
                evidence,
                "android-hosts-ipad-local-network",
            )
            .await?;
        ipad_app
            .wait_for_text("device: certified until", Duration::from_secs(60))
            .await?;
        ipad.record(&mut ipad_app, evidence, "android-hosts-ipad-signed-in")
            .await?;
        if join == JoinBy::Beacon {
            turn_on_bluetooth(&mut ipad_app, ipad_tapper, evidence).await?;
        }
        step("take the Android phone off its network");
        android
            .device
            .adb(&["shell", "svc", "wifi", "disable"])
            .await?;
        sleep(Duration::from_secs(5)).await;
        if join == JoinBy::Beacon {
            android_phone::bluetooth_on(&android.device).await?;
        }
        step("host a hotspot on the Android phone");
        let mut android_app = android.device.app().await?;
        android_app.click("Host a hotspot").await?;
        if join == JoinBy::Beacon {
            let beacon = android_phone::read_beacon(&mut android_app).await?;
            eprintln!("{beacon}");
        } else {
            step("decline Bluetooth on the Android phone");
            android
                .device
                .tap_dialog_button(
                    &android_phone::DENY_BUTTONS,
                    "the Bluetooth enable dialog's refusal",
                )
                .await?;
            android_app
                .wait_for_text("hosting, the beacon is off", Duration::from_secs(30))
                .await?;
        }
        let offer = read_hotspot_offer(&mut android_app).await?;
        let iphone_identity = own_identity(&mut iphone_app).await?;
        let ipad_identity = own_identity(&mut ipad_app).await?;
        let android_identity = own_identity(&mut android_app).await?;
        android
            .device
            .screenshot(evidence, "android-hosts-android-offer")
            .await?;
        Ok::<_, anyhow::Error>((
            android_app,
            offer,
            iphone_identity,
            ipad_identity,
            android_identity,
        ))
    }
    .await;
    let (mut android_app, offer, iphone_identity, ipad_identity, android_identity) = match setup {
        Ok(values) => values,
        Err(err) => {
            // The network may have already moved, so the restore still runs.
            eprintln!("the {} round's setup: {err:#}", round.name());
            let restore = star_round_restore(
                &mut iphone_app,
                &mut iphone_inspector,
                &mut ipad_app,
                &mut ipad_inspector,
                android,
                round,
                false,
                None,
                iphone_tapper,
                evidence,
            )
            .await;
            return round_report_failed(*plan, &format!("{err:#}"), restore);
        }
    };
    // The hotspot's gateway, once a joiner's page names it.
    let mut gateway = None;
    let join1 = {
        let started = Instant::now();
        let outcome = async {
            if join == JoinBy::Beacon {
                turn_on_bluetooth(&mut iphone_app, iphone_tapper, evidence).await?;
            }
            step("join the hotspot on the iPhone");
            join_on_second_phone(
                join,
                "android-hosts-iphone",
                &offer,
                target,
                &mut iphone_app,
                iphone_tapper,
                evidence,
            )
            .await?;
            // The joiner moved onto the hotspot, which resets the link its
            // session rides on.
            iphone_app = iphone_inspector.reattach().await?;
            step("link through the hotspot");
            wait_linked(
                &mut android_app,
                &mut iphone_app,
                &android_identity,
                &iphone_identity,
            )
            .await?;
            target
                .record(&mut iphone_app, evidence, "android-hosts-iphone-linked")
                .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        (started.elapsed(), outcome.map_err(|err| format!("{err:#}")))
    };
    let join2 = {
        let started = Instant::now();
        let outcome = async {
            step("join the hotspot on the iPad");
            join_on_second_phone(
                join,
                "android-hosts-ipad",
                &offer,
                ipad,
                &mut ipad_app,
                ipad_tapper,
                evidence,
            )
            .await?;
            ipad_app = ipad_inspector.reattach().await?;
            step("link through the hotspot");
            wait_linked(
                &mut android_app,
                &mut ipad_app,
                &android_identity,
                &ipad_identity,
            )
            .await?;
            ipad.record(&mut ipad_app, evidence, "android-hosts-ipad-linked")
                .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        (started.elapsed(), outcome.map_err(|err| format!("{err:#}")))
    };
    let link = {
        let started = Instant::now();
        let outcome = async {
            step("wait for the three-way link");
            wait_star_link(
                [
                    &mut StarPage::Ios {
                        app: &mut iphone_app,
                        inspector: &mut iphone_inspector,
                    },
                    &mut StarPage::Ios {
                        app: &mut ipad_app,
                        inspector: &mut ipad_inspector,
                    },
                    &mut StarPage::Android {
                        device: &android.device,
                        app: &mut android_app,
                    },
                ],
                names,
                [&iphone_identity, &ipad_identity, &android_identity],
                evidence,
                round,
                &mut gateway,
            )
            .await
        }
        .await;
        (started.elapsed(), outcome.map_err(|err| format!("{err:#}")))
    };
    let restore = star_round_restore(
        &mut iphone_app,
        &mut iphone_inspector,
        &mut ipad_app,
        &mut ipad_inspector,
        android,
        round,
        false,
        gateway,
        iphone_tapper,
        evidence,
    )
    .await;
    star::RoundReport {
        round,
        joins: [
            star::StepReport {
                name: step_name(round, star::Device::IPhone, plan.join),
                took: join1.0,
                outcome: join1.1,
            },
            star::StepReport {
                name: step_name(round, star::Device::IPad, plan.join),
                took: join2.0,
                outcome: join2.1,
            },
        ],
        link: star::StepReport {
            name: format!("{} round, the three-way link", round.name()),
            took: link.0,
            outcome: link.1,
        },
        restore: star::StepReport {
            name: format!("{} round, the restore", round.name()),
            took: restore.0,
            outcome: restore.1,
        },
    }
}

/// The star's second round: the iPhone hosts its Personal Hotspot, and the
/// Android phone and the iPad join it and stay joined until every device
/// links to every other. It ends with the hotspot down, every link ended and
/// the iPhone's Personal Hotspot off.
#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the plan, the two iOS handhelds, the Android phone, both tappers, the build, the stack, the evidence, the sync url and the passphrase are each the round's own"
)]
async fn iphone_hosts_round(
    plan: &star::RoundPlan,
    target: &Target,
    ipad: &Target,
    android: &StarAndroid,
    iphone_tapper: &Tapper,
    ipad_tapper: &Tapper,
    app: &Path,
    stack: &Stack,
    evidence: &Path,
    sync_url: &str,
    passphrase: &str,
) -> star::RoundReport {
    let round = plan.round;
    let names: [&str; 3] = [
        star::Device::IPhone.name(),
        star::Device::IPad.name(),
        star::Device::Android.name(),
    ];
    // The iPhone hosts, so it signs back in fresh, its page standing ready.
    let (mut iphone_inspector, mut iphone_app) =
        match host_signed_back_in(target, stack, sync_url, evidence).await {
            Ok(pages) => pages,
            Err(err) => return failed_round(*plan, &err),
        };
    // The iPad stood signed in through the first round, or it signs in now.
    let (mut ipad_inspector, mut ipad_app) =
        match ipad_signed_in(ipad, false, app, stack, evidence, sync_url).await {
            Ok(pages) => pages,
            Err(err) => return failed_round(*plan, &err),
        };
    let join = join_by(plan.join);
    let setup = async {
        step("host my Personal Hotspot on the iPhone");
        switch_and_reattach(
            true,
            iphone_tapper,
            &mut iphone_inspector,
            &mut iphone_app,
            evidence,
            "iphone-hosts-hotspot-on",
        )
        .await?;
        let name = device_name(target.udid()).await?;
        on_page(&mut iphone_inspector, &mut iphone_app, async |app| {
            app.set_input("personal-ssid", &name).await?;
            app.set_input("personal-passphrase", passphrase).await?;
            app.click("Host my Personal Hotspot").await
        })
        .await?;
        // The host's beacon is always on, and the Bluetooth prompt can block
        // the hosting.
        let _ = iphone_tapper
            .run("tap-alert", 40, evidence, "iphone-hosts-host-alert")
            .await;
        let offer = on_page(&mut iphone_inspector, &mut iphone_app, async |app| {
            read_hotspot_offer(app).await
        })
        .await?;
        let iphone_identity = on_page(&mut iphone_inspector, &mut iphone_app, async |app| {
            own_identity(app).await
        })
        .await?;
        let ipad_identity = on_page(&mut ipad_inspector, &mut ipad_app, async |app| {
            own_identity(app).await
        })
        .await?;
        let android_identity = {
            let mut android_app = android.device.app().await?;
            own_identity(&mut android_app).await?
        };
        on_page(&mut iphone_inspector, &mut iphone_app, async |app| {
            target.record(app, evidence, "iphone-hosts-offer").await
        })
        .await?;
        Ok::<_, anyhow::Error>((offer, iphone_identity, ipad_identity, android_identity))
    }
    .await;
    let (offer, iphone_identity, ipad_identity, android_identity) = match setup {
        Ok(values) => values,
        Err(err) => {
            // The Personal Hotspot may already be on, so the restore still
            // runs.
            eprintln!("the {} round's setup: {err:#}", round.name());
            let restore = star_round_restore(
                &mut iphone_app,
                &mut iphone_inspector,
                &mut ipad_app,
                &mut ipad_inspector,
                android,
                round,
                true,
                None,
                iphone_tapper,
                evidence,
            )
            .await;
            return round_report_failed(*plan, &format!("{err:#}"), restore);
        }
    };
    // A VPN the demo cannot bypass refuses its join's network binding, so
    // the Android's Tailscale, when it holds the VPN, stays off until the
    // round's restore, which puts back only what the round switched.
    let tailscale_held = tailscale_holds_vpn(android).await;
    let tailscale_off = match &tailscale_held {
        Ok(true) => set_tailscale(android, false).await,
        Ok(false) => Ok(()),
        Err(err) => Err(anyhow!("reading the VPN: {err:#}")),
    };
    // The hotspot's gateway, once a joiner's page names it.
    let mut gateway = None;
    let join1 = {
        let started = Instant::now();
        let outcome = async {
            if join == JoinBy::Beacon {
                android_phone::bluetooth_on(&android.device).await?;
            }
            step("join the hotspot on the Android phone");
            let mut android_app = android.device.app().await?;
            match join {
                JoinBy::Beacon => {
                    wait_for_single_nearby(&mut android_app).await?;
                    android
                        .device
                        .screenshot(evidence, "iphone-hosts-android-nearby")
                        .await?;
                    android_app.click("Join the nearby host").await?;
                    android_app
                        .wait_for_text("joining the nearby host", Duration::from_secs(10))
                        .await?;
                }
                JoinBy::Payload => {
                    let payload = offer
                        .payload
                        .as_deref()
                        .ok_or_else(|| anyhow!("the offer shows no payload"))?;
                    android_app.set_input("payload", payload).await?;
                    android_app.click("Join from the payload").await?;
                    android_app
                        .wait_for_text("joining the hotspot", Duration::from_secs(10))
                        .await?;
                }
                JoinBy::Form => {
                    android_app.set_input("ssid", &offer.ssid).await?;
                    android_app
                        .set_input("passphrase", &offer.passphrase)
                        .await?;
                    android_app
                        .set_input("port", &offer.port.to_string())
                        .await?;
                    android_app.click("Join the hotspot").await?;
                    android_app
                        .wait_for_text("joining the hotspot", Duration::from_secs(10))
                        .await?;
                }
            }
            // The host allows the client, and the Android's approval dialog
            // follows.
            iphone_tapper
                .run(
                    "tap-alert",
                    40,
                    evidence,
                    "iphone-hosts-android-joiner-alert",
                )
                .await?;
            // Android skips its dialog for a network it approved before, so
            // the join landing stands in for the tap.
            let joined = async {
                let mut app = android.device.app().await?;
                app.wait_for_text("hotspot: joined", Duration::from_secs(60))
                    .await
            };
            tokio::select! {
                approved = android.device.tap_connect_button() => approved?,
                joined = joined => joined?,
            }
            // The Android joined onto the hotspot, which resets the links
            // both pages' sessions ride on.
            iphone_app = iphone_inspector.reattach().await?;
            let mut android_app = android.device.app().await?;
            step("link through the hotspot");
            wait_linked(
                &mut iphone_app,
                &mut android_app,
                &iphone_identity,
                &android_identity,
            )
            .await?;
            android
                .device
                .screenshot(evidence, "iphone-hosts-android-linked")
                .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        (started.elapsed(), outcome.map_err(|err| format!("{err:#}")))
    };
    let join2 = {
        let started = Instant::now();
        let outcome = async {
            step("join the hotspot on the iPad");
            if join == JoinBy::Beacon {
                // The button is hidden when Bluetooth is already on, so the
                // guard reads the page.
                if !ipad_app.page_text().await?.contains("bluetooth: ready") {
                    turn_on_bluetooth(&mut ipad_app, ipad_tapper, evidence).await?;
                }
            }
            join_on_second_phone(
                join,
                "iphone-hosts-ipad",
                &offer,
                ipad,
                &mut ipad_app,
                ipad_tapper,
                evidence,
            )
            .await?;
            // A client joining the Personal Hotspot resets the host's USB
            // link, and the joiner's page moves onto the hotspot.
            iphone_app = iphone_inspector.reattach().await?;
            ipad_app = ipad_inspector.reattach().await?;
            step("link through the hotspot");
            wait_linked(
                &mut iphone_app,
                &mut ipad_app,
                &iphone_identity,
                &ipad_identity,
            )
            .await?;
            ipad.record(&mut ipad_app, evidence, "iphone-hosts-ipad-linked")
                .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        (started.elapsed(), outcome.map_err(|err| format!("{err:#}")))
    };
    let link = {
        let started = Instant::now();
        let outcome = async {
            step("wait for the three-way link");
            let mut android_app = android.device.app().await?;
            wait_star_link(
                [
                    &mut StarPage::Ios {
                        app: &mut iphone_app,
                        inspector: &mut iphone_inspector,
                    },
                    &mut StarPage::Ios {
                        app: &mut ipad_app,
                        inspector: &mut ipad_inspector,
                    },
                    &mut StarPage::Android {
                        device: &android.device,
                        app: &mut android_app,
                    },
                ],
                names,
                [&iphone_identity, &ipad_identity, &android_identity],
                evidence,
                round,
                &mut gateway,
            )
            .await
        }
        .await;
        (started.elapsed(), outcome.map_err(|err| format!("{err:#}")))
    };
    let restore = star_round_restore(
        &mut iphone_app,
        &mut iphone_inspector,
        &mut ipad_app,
        &mut ipad_inspector,
        android,
        round,
        true,
        gateway,
        iphone_tapper,
        evidence,
    )
    .await;
    let restore = {
        let back_on = match tailscale_held {
            Ok(true) => set_tailscale(android, true).await,
            Ok(false) | Err(_) => Ok(()),
        };
        let failed = tailscale_off
            .and(back_on)
            .map_err(|err| format!("the M52's Tailscale: {err:#}"));
        (restore.0, restore.1.and(failed))
    };
    star::RoundReport {
        round,
        joins: [
            star::StepReport {
                name: step_name(round, star::Device::Android, plan.join),
                took: join1.0,
                outcome: join1.1,
            },
            star::StepReport {
                name: step_name(round, star::Device::IPad, plan.join),
                took: join2.0,
                outcome: join2.1,
            },
        ],
        link: star::StepReport {
            name: format!("{} round, the three-way link", round.name()),
            took: link.0,
            outcome: link.1,
        },
        restore: star::StepReport {
            name: format!("{} round, the restore", round.name()),
            took: restore.0,
            outcome: restore.1,
        },
    }
}

/// Whether the Android phone's connected VPN belongs to its Tailscale.
async fn tailscale_holds_vpn(android: &StarAndroid) -> Result<bool> {
    let connectivity = android
        .device
        .adb(&["shell", "dumpsys", "connectivity"])
        .await?;
    let package = android
        .device
        .adb(&["shell", "dumpsys", "package", "com.tailscale.ipn"])
        .await?;
    Ok(star::tailscale_holds_vpn(&connectivity, &package)?)
}

/// Connect or disconnect the Android phone's Tailscale through its own
/// receiver, holding until the platform reports the VPN in the asked state.
async fn set_tailscale(android: &StarAndroid, on: bool) -> Result<()> {
    let action = if on { "CONNECT_VPN" } else { "DISCONNECT_VPN" };
    step(&format!("the M52's Tailscale {action}"));
    android
        .device
        .adb(&[
            "shell",
            "am",
            "broadcast",
            "-n",
            "com.tailscale.ipn/.IPNReceiver",
            "-a",
            &format!("com.tailscale.ipn.{action}"),
        ])
        .await?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let state = android
            .device
            .adb(&["shell", "dumpsys", "connectivity"])
            .await?;
        if state.contains("ni{VPN CONNECTED") == on {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "the VPN stayed {} after 20s",
                if on { "down" } else { "up" }
            );
        }
        sleep(Duration::from_secs(1)).await;
    }
}

/// The star's end of day: both iOS handhelds signed out, and the Android
/// phone back at rest, every cleanup attempted and the first failure kept.
async fn star_finish(
    target: &Target,
    ipad: &Target,
    android: &StarAndroid,
    evidence: &Path,
) -> Result<()> {
    let mut fail = Ok::<(), anyhow::Error>(());
    step("sign the iPhone back out");
    if let Err(err) = leave_signed_out(target, evidence).await {
        eprintln!("the iPhone's sign out: {err:#}");
        fail = fail.and(Err(err));
    }
    step("sign the iPad back out");
    if let Err(err) = leave_signed_out(ipad, evidence).await {
        eprintln!("the iPad's sign out: {err:#}");
        fail = fail.and(Err(err));
    }
    if let Err(err) = ipad.copy_demo_log(evidence).await {
        eprintln!("the iPad log could not be collected ({err:#})");
        fail = fail.and(Err(err));
    }
    if let Err(err) = android_finish(android, evidence).await {
        eprintln!("the Android phone's rest: {err:#}");
        fail = fail.and(Err(err));
    }
    fail
}

/// The Android phone's way back to rest: its sign-out, its logcat, its
/// settings and its browser role back, its Bluetooth off and its links
/// removed, every cleanup attempted and the first failure kept.
async fn android_finish(android: &StarAndroid, evidence: &Path) -> Result<()> {
    async {
        let mut fail = Ok::<(), anyhow::Error>(());
        if let Err(err) = restore_android_network(android).await {
            eprintln!("the Android phone's network before sign-out: {err:#}");
            fail = fail.and(Err(err));
        }
        step("sign the Android phone back out");
        let signout = async {
            let mut android_app = android.device.app().await?;
            sign_out(&mut android_app).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(err) = signout {
            eprintln!("the Android phone's sign out: {err:#}");
            fail = fail.and(Err(err));
        }
        if let Err(err) = android
            .device
            .adb(&[
                "shell",
                "am",
                "force-stop",
                android_phone::Demo::Dioxus.package(),
            ])
            .await
        {
            eprintln!("stopping the Android demo: {err:#}");
            fail = fail.and(Err(err));
        }
        let logcat = android
            .device
            .adb(&["logcat", "-d"])
            .await
            .unwrap_or_default();
        if let Err(err) = tokio::fs::write(evidence.join("android-logcat.txt"), logcat).await {
            eprintln!("the Android logcat: {err:#}");
            fail = fail.and(Err(
                anyhow::Error::new(err).context("writing the Android logcat")
            ));
        }
        let role = match android.browser_holder.as_deref() {
            Some(holder) => android.device.set_browser_role_holder(holder).await,
            None => android
                .device
                .adb(&[
                    "shell",
                    "cmd",
                    "role",
                    "remove-role-holder",
                    android_phone::BROWSER_ROLE,
                    android_phone::BROWSER,
                ])
                .await
                .map(drop),
        };
        if let Err(err) = role {
            eprintln!("the Android browser's role: {err:#}");
            fail = fail.and(Err(err));
        }
        let screen = android
            .device
            .restore_global_setting(android_phone::STAY_ON, android.stay_on.as_deref())
            .await;
        if let Err(err) = screen {
            eprintln!("the Android screen's setting: {err:#}");
            fail = fail.and(Err(err));
        }
        let dialogs = android
            .device
            .restore_global_setting(
                android_phone::HIDE_ERROR_DIALOGS,
                android.error_dialogs.as_deref(),
            )
            .await;
        if let Err(err) = dialogs {
            eprintln!("the Android error dialogs' setting: {err:#}");
            fail = fail.and(Err(err));
        }
        if let Err(err) = android_phone::bluetooth_off(&android.device).await {
            eprintln!("the Android Bluetooth: {err:#}");
            fail = fail.and(Err(err));
        }
        // The links drop best effort, since the run is over either way.
        let _ = android.device.adb(&["forward", "--remove-all"]).await;
        let _ = android.device.adb(&["reverse", "--remove-all"]).await;
        fail
    }
    .await
}

/// The star's rounds and their end of day: the Android phone's setup and both
/// tappers first, and a failure there brings the phone's own state back and
/// fails the rounds' setup, then the two rounds and the devices' way back to
/// rest, which the run's failure keeps while the summary records the rounds.
#[expect(
    clippy::too_many_arguments,
    reason = "the two iOS handhelds, the build, the stack, the evidence, the sync url, the identity, the Android phone and its arguments, the passphrase and the join are each the run's own"
)]
async fn run_star_rounds(
    target: &Target,
    ipad: &Target,
    app: &Path,
    stack: &Stack,
    evidence: &Path,
    sync_url: &str,
    identity: &str,
    android_serial: &str,
    android_apk: &Path,
    android_unlock_pin: Option<&str>,
    passphrase: &str,
    join: star::Join,
) -> (Vec<star::RoundReport>, Result<(), String>) {
    let prep = async {
        let android = match star_android_setup(
            android_phone::Device::new(android_serial.to_owned(), android_phone::Demo::Dioxus),
            android_apk,
            stack,
            evidence,
            android_unlock_pin,
        )
        .await
        {
            Ok((android, Ok(()))) => android,
            Ok((android, Err(err))) => {
                eprintln!("the Android phone's setup: {err}");
                let rest = android_finish(&android, evidence).await;
                let note = match rest {
                    Ok(()) => String::new(),
                    Err(rest) => format!(", its rest: {rest:#}"),
                };
                return Err(anyhow::anyhow!("the Android phone's setup: {err}{note}"));
            }
            Err(err) => return Err(anyhow::anyhow!("{err}")),
        };
        let iphone_tapper = match Tapper::build(target.udid(), identity, evidence).await {
            Ok(tapper) => tapper,
            Err(err) => {
                let rest = android_finish(&android, evidence).await;
                let note = match rest {
                    Ok(()) => String::new(),
                    Err(rest) => format!(", its rest: {rest:#}"),
                };
                eprintln!("the iPhone's tapper: {err:#}{note}");
                return Err(anyhow::anyhow!("the iPhone's tapper: {err}{note}"));
            }
        };
        let ipad_tapper = match Tapper::build(ipad.udid(), identity, evidence).await {
            Ok(tapper) => tapper,
            Err(err) => {
                let rest = android_finish(&android, evidence).await;
                let note = match rest {
                    Ok(()) => String::new(),
                    Err(rest) => format!(", its rest: {rest:#}"),
                };
                eprintln!("the iPad's tapper: {err:#}{note}");
                return Err(anyhow::anyhow!("the iPad's tapper: {err}{note}"));
            }
        };
        Ok::<(StarAndroid, Tapper, Tapper), anyhow::Error>((android, iphone_tapper, ipad_tapper))
    }
    .await;
    let (android, iphone_tapper, ipad_tapper) = match prep {
        Err(err) => return (Vec::new(), Err(format!("{err:#}"))),
        Ok(values) => values,
    };
    let plans = star::plan(join);
    let mut rounds = vec![
        android_hosts_round(
            &plans[0],
            target,
            ipad,
            &android,
            &iphone_tapper,
            &ipad_tapper,
            app,
            stack,
            evidence,
            sync_url,
        )
        .await,
    ];
    rounds.push(
        iphone_hosts_round(
            &plans[1],
            target,
            ipad,
            &android,
            &iphone_tapper,
            &ipad_tapper,
            app,
            stack,
            evidence,
            sync_url,
            passphrase,
        )
        .await,
    );
    // Both rounds stood or not. The devices' rest runs either way, and a
    // failure there keeps the run's failure while the summary records the
    // rounds.
    let finish = star_finish(target, ipad, &android, evidence).await;
    let finish = finish.map_err(|err| format!("{err:#}"));
    (rounds, finish)
}

/// The handheld star (R76 slice 9f): the iPhone proves, then the two rounds
/// run, the Android phone hosting while the iPhone and the iPad join it, and
/// the iPhone hosting its Personal Hotspot while the Android phone and the
/// iPad join it, and in each round every device links to every other over the
/// one hotspot. It ends with every device back at rest and the summary
/// written.
#[expect(
    clippy::too_many_arguments,
    reason = "the phone, its build, the stack, the evidence, the relay, the sync url, the identity, the peer, the Android phone and its arguments, the passphrase and the join are each the run's own"
)]
async fn star_walk(
    target: &Target,
    app: &Path,
    stack: &Stack,
    evidence: &Path,
    relay: &mut Relay,
    sync_url: &str,
    identity: Option<&str>,
    peer: Option<&str>,
    android_serial: Option<&str>,
    android_apk: Option<&Path>,
    android_unlock_pin: Option<&str>,
    passphrase: Option<&str>,
    join: star::Join,
) -> Result<()> {
    let identity = identity.context("--star needs the --identity connetto-ios-signing printed")?;
    let peer = peer.context("--star needs --peer-device")?;
    let android_serial = android_serial.context("--star needs --android-peer")?;
    let android_apk = android_apk.context("--star needs --android-apk")?;
    let passphrase = passphrase.context("--star needs --hotspot-passphrase")?;
    if !demo_has_device_identity() {
        bail!("the star needs a demo build with its device identity");
    }
    let started = Instant::now();
    let outcome = prove(target, app, stack, evidence, relay, sync_url).await;
    let proved = (
        started.elapsed(),
        outcome.as_ref().map_err(|err| format!("{err:#}")).map(drop),
    );
    let (rounds, rest) = if outcome.is_ok() {
        let ipad = Target::Device {
            udid: peer.to_owned(),
            identity: identity.to_owned(),
        };
        run_star_rounds(
            target,
            &ipad,
            app,
            stack,
            evidence,
            sync_url,
            identity,
            android_serial,
            android_apk,
            android_unlock_pin,
            passphrase,
            join,
        )
        .await
    } else {
        (Vec::new(), Ok(()))
    };
    // The summary records the run either way, and the devices' rest's
    // failure records itself beside the rounds.
    let mut summary = star::summary(&commit().await, &proved, &rounds);
    if let Err(err) = &rest {
        writeln!(&mut summary, "the devices' rest: failed: {err}")?;
    }
    eprintln!("{summary}");
    tokio::fs::write(evidence.join("summary.txt"), &summary)
        .await
        .context("writing the summary")?;
    let mut failed: Vec<String> = rounds
        .iter()
        .flat_map(|report| {
            [
                &report.joins[0],
                &report.joins[1],
                &report.link,
                &report.restore,
            ]
            .into_iter()
            .filter(|step| step.outcome.is_err())
            .map(|step| step.name.clone())
        })
        .collect();
    if let Err(err) = &rest {
        failed.push(format!("the devices' rest: {err}"));
    }
    if failed.is_empty() {
        outcome.map(drop)
    } else {
        bail!("the star's steps failed: {}", failed.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};

    use super::{Stack, Target, organizational_unit, relay_for};

    /// An upstream that echoes every byte back.
    async fn echo() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let address = listener.local_addr().expect("echo address").to_string();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = socket.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        address
    }

    fn stack(server: String, auth_origin: &str) -> Stack {
        Stack {
            server,
            auth_origin: auth_origin.to_owned(),
            pg_url: String::new(),
            issuer: String::new(),
        }
    }

    fn device() -> Target {
        Target::Device {
            udid: String::new(),
            identity: String::new(),
        }
    }

    /// The stack's listener terminates TLS itself, so the relay in front of
    /// it hands the app's bytes over untouched and the app dials it in `wss`
    /// by the stack's host name, which its certificate names.
    #[tokio::test]
    async fn a_relay_before_a_tls_stack_passes_the_bytes_through() {
        let server = echo().await;
        let port = server.rsplit_once(':').expect("port").1.to_owned();
        let host_stack = stack(server, &format!("https://127.0.0.1:{port}"));
        let (relay, url) = relay_for(&device(), &host_stack).await.expect("relay");
        assert_eq!(
            url,
            format!(
                "wss://127.0.0.1:{}{}",
                relay.address().port(),
                connetto_server::SYNC_PATH
            )
        );
        let mut stream = TcpStream::connect(("127.0.0.1", relay.address().port()))
            .await
            .expect("connect");
        stream.write_all(&[0x16, 0x03, 0x01]).await.expect("write");
        let mut back = [0; 3];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut back))
            .await
            .expect("no echo within its bound")
            .expect("read");
        assert_eq!(back, [0x16, 0x03, 0x01]);
    }

    /// A device dials only `wss`, which a plain stack cannot serve.
    #[tokio::test]
    async fn a_device_refuses_a_plain_stack() {
        let plain = stack(echo().await, "http://127.0.0.1:7777");
        let Err(refusal) = relay_for(&device(), &plain).await else {
            panic!("a device run started a relay before a plain stack");
        };
        assert!(
            refusal.to_string().contains("needs the stack on TLS"),
            "the refusal is the TLS guard's, got {refusal:#}"
        );
    }

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

    /// The mac walk's joins stand in the record's order (R76 slice 9c).
    #[test]
    fn the_mac_walk_runs_form_beacon_payload() {
        assert_eq!(
            super::MAC_JOINS.map(super::JoinBy::name),
            ["form", "beacon", "payload"]
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

    /// The star's arguments name the iPhone, the iPad and the Android phone
    /// beside the join, and clash with the other walks.
    #[test]
    fn the_star_arguments_are_checked() {
        let args = |parts: &[&str]| parts.iter().copied().map(String::from).collect::<Vec<_>>();
        let star = [
            "--star",
            "--device",
            "u1",
            "--identity",
            "sha1",
            "--peer-device",
            "u2",
            "--android-peer",
            "192.168.1.10:5555",
            "--android-apk",
            "app.apk",
            "--hotspot-passphrase",
            "pass",
        ];
        assert!(
            super::parse_arguments(&star.iter().copied().map(String::from).collect::<Vec<_>>())
                .is_ok(),
            "a complete star run"
        );
        for join in ["beacon", "payload", "form"] {
            let with_join = [&star[..], &["--join", join]].concat();
            assert!(
                super::parse_arguments(
                    &with_join
                        .iter()
                        .copied()
                        .map(String::from)
                        .collect::<Vec<_>>()
                )
                .is_ok(),
                "the join {join}"
            );
        }
        let with_pin = [&star[..], &["--android-unlock-pin", "1234"]].concat();
        assert!(
            super::parse_arguments(
                &with_pin
                    .iter()
                    .copied()
                    .map(String::from)
                    .collect::<Vec<_>>()
            )
            .is_ok(),
            "the unlock pin"
        );
        for broken in [
            args(&["--star"]),
            args(&["--star", "--simulator", "SIM-1"]),
            args(&["--star", "--every-join"]),
            args(&["--star", "--mac-peer"]),
            args(&[
                "--star",
                "--device",
                "u1",
                "--identity",
                "sha1",
                "--peer-device",
                "u2",
                "--android-peer",
                "192.168.1.10:5555",
                "--hotspot-passphrase",
                "pass",
            ]),
            args(&["--star", "--join", "wifi"]),
        ] {
            assert!(super::parse_arguments(&broken).is_err(), "{broken:?}");
        }
    }

    /// The mac peer's arguments stand beside the two-phone run's, and
    /// clash with its `--peer-device`.
    #[test]
    fn the_mac_peer_arguments_are_checked() {
        let args = |parts: &[&str]| parts.iter().copied().map(String::from).collect::<Vec<_>>();
        let mac = [
            "--device",
            "u1",
            "--identity",
            "sha1",
            "--mac-peer",
            "--every-join",
            "--hotspot-passphrase",
            "pass",
        ];
        assert!(
            super::parse_arguments(&mac.iter().copied().map(String::from).collect::<Vec<_>>())
                .is_ok(),
            "a complete mac run"
        );
        for broken in [
            args(&["--device", "u1", "--identity", "sha1", "--mac-peer"]),
            args(&[
                "--device",
                "u1",
                "--identity",
                "sha1",
                "--mac-peer",
                "--every-join",
                "--hotspot-passphrase",
                "pass",
                "--peer-device",
                "u2",
            ]),
            args(&[
                "--simulator",
                "SIM-1",
                "--mac-peer",
                "--every-join",
                "--hotspot-passphrase",
                "pass",
            ]),
        ] {
            assert!(super::parse_arguments(&broken).is_err(), "{broken:?}");
        }
        let no_passphrase = [
            "--device",
            "u1",
            "--identity",
            "sha1",
            "--mac-peer",
            "--every-join",
        ];
        assert!(
            super::parse_arguments(
                &no_passphrase
                    .iter()
                    .copied()
                    .map(String::from)
                    .collect::<Vec<_>>()
            )
            .is_err(),
            "--mac-peer --every-join without the passphrase"
        );
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

    #[tokio::test(start_paused = true)]
    async fn a_star_matrix_needs_current_answers_after_the_freshness_boundary() {
        let evidence = tempfile::tempdir().expect("the evidence directory");
        let started = tokio::time::Instant::now();
        let outcome = super::observe_star_link(
            async |_| {
                [
                    Ok("linked: b via 10.42.0.7:1\nlinked: c via 10.42.0.1:1".to_owned()),
                    Ok("hotspot: joined through the gateway 10.42.0.1\nlinked: a via 10.42.0.9:1\nlinked: c via 10.42.0.1:1".to_owned()),
                    Ok("linked: a via 10.42.0.9:1\nlinked: b via 10.42.0.7:1".to_owned()),
                ]
            },
            ["iphone", "ipad", "android"],
            ["a", "b", "c"],
            evidence.path(),
            connetto_test_harness::star::Round::AndroidHosts,
            &mut None,
        )
        .await;
        assert!(outcome.is_ok());
        assert_eq!(started.elapsed(), std::time::Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn a_star_matrix_cannot_pass_from_cached_pages_when_a_device_stops_answering() {
        let evidence = tempfile::tempdir().expect("the evidence directory");
        let started = tokio::time::Instant::now();
        let outcome = super::observe_star_link(
            async |_| {
                [
                    if started.elapsed() < std::time::Duration::from_secs(30) {
                        Ok("linked: b via 10.42.0.7:1\nlinked: c via 10.42.0.1:1".to_owned())
                    } else {
                        Err(anyhow::anyhow!("the iphone inspector is unavailable"))
                    },
                    Ok("hotspot: joined through the gateway 10.42.0.1\nlinked: a via 10.42.0.9:1\nlinked: c via 10.42.0.1:1".to_owned()),
                    Ok("linked: a via 10.42.0.9:1\nlinked: b via 10.42.0.7:1".to_owned()),
                ]
            },
            ["iphone", "ipad", "android"],
            ["a", "b", "c"],
            evidence.path(),
            connetto_test_harness::star::Round::AndroidHosts,
            &mut None,
        )
        .await;
        assert!(outcome.is_err());
        assert_eq!(started.elapsed(), std::time::Duration::from_secs(120));
    }
}
