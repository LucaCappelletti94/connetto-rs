//! Deploys `examples/dioxus-desktop-demo` to an attached Android device or
//! emulator and walks R88's proof on it, which is sign in, sync, write
//! offline and upload on reconnect.
//!
//! It runs as the command of `connetto-demo-stack`, which provides the stack
//! and the environment naming it.
//!
//! ```text
//! cargo build -p connetto-test-harness --bin connetto-android-proof
//! cargo run -p connetto-test-harness --bin connetto-demo-stack -- \
//!   target/debug/connetto-android-proof [--serial SERIAL] [--apk PATH] \
//!     [--unlock-pin PIN] [--peer-serial SECOND]
//! ```
//!
//! The demo keeps its secrets behind the Keystore gate (R52), so each launch
//! shows the platform's unlock prompt once, and a return after more than the
//! demo's re-check grace shows it again. With `--unlock-pin` the driver types
//! that PIN into the prompt, which suits an emulator whose throwaway PIN the
//! run may know. Without it a person approves each prompt on the phone, by
//! fingerprint or PIN, while the driver waits and says so.
//!
//! Without `--apk` it builds the APK with `dx` for the device's ABI. The demo
//! and the device's browser are read and driven over the `DevTools` protocol,
//! because neither exposes web content to `uiautomator`. The demo opens the
//! login in a Custom Tab, where the driver types the user with trusted input,
//! so the browser follows the final redirect into the app as it would after a
//! real tap. Each step's screenshot and the
//! device log land under `target/android-proof/<serial>-<millis>/`.
//!
//! The offline step restarts the host's adb server, which drops every other
//! session's forwards and reverses on this machine too. A wireless serial
//! (`host:port`) is reconnected after the restart.
//!
//! With `--peer-serial` a second attached phone joins the proof. The main
//! phone hosts a hotspot from the demo and the second signs in as its own
//! account and joins it through the demo's join form, the driver tapping the
//! system's approval in place of the user (R76 decision 16). Each phone's
//! server path stays over `adb reverse`, so the joiner reaches the server
//! while it is off its usual Wi-Fi. The proof ends with both phones back on
//! their usual networks.
//!
//! With `--bluetooth` the main phone hosts a hotspot after its own proof, and
//! the run requires the demo's beacon on the panel and its legacy advertising
//! set and GATT service in the phone's Bluetooth dump (R76 slice 5a). The
//! proof ends with the phone's Bluetooth off and its Wi-Fi on. With
//! `--peer-serial` as well, the second phone finds the first one's beacon and
//! joins through the exchange behind it in place of the join form (R76 slice
//! 6), and both phones end with their Bluetooth off.
//!
//! With `--payload` and `--peer-serial`, the second phone joins through the
//! first one's `WIFI:` payload pasted into its join form, the first phone's
//! Bluetooth left off as a host whose beacon is down (R76 slice 7).
//!
//! With `--every-join` and `--peer-serial`, one run builds and signs both
//! phones in once and then makes every join in turn, the form, the beacon and
//! the payload, bringing the phones back to rest after each, recording a
//! failed join and going on, and writing `summary.txt` beside the evidence
//! (R76 decision 4). This is the run to make whenever two phones are at hand
//! and before a peer phase closes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use connetto_test_harness::demo::{order_count, wait_for_count};
use connetto_test_harness::inspector::{PageSession, list_pages};
use connetto_test_harness::stack::{
    demo_has_device_identity, demo_mobile_features, now_millis, repo_path,
};
use tokio::process::Command;
use tokio::time::{Instant, sleep};

const PACKAGE: &str = "dev.connetto.dioxusdemo";
const ACTIVITY: &str = "dev.dioxus.main.MainActivity";
const BROWSER: &str = "com.android.chrome";
const DEMO_DIR: [&str; 2] = ["examples", "dioxus-desktop-demo"];
const USER: &str = "alice";
/// The device port the demo's WebSocket dials, removed to take it offline.
const SYNC_PORT: u16 = 7777;
/// Chrome's first-run and permission screens, by resource id so that any
/// device language matches.
const INTERSTITIALS: [&str; 3] = [
    "com.android.chrome:id/signin_fre_dismiss_button",
    "com.android.chrome:id/negative_button",
    "com.android.chrome:id/terms_accept",
];
const BROWSER_ROLE: &str = "android.app.role.BROWSER";
/// The global setting `svc power stayon` writes.
const STAY_ON: &str = "stay_on_while_plugged_in";
/// The global setting that, when nonzero, keeps crash and freeze dialogs off the screen.
const HIDE_ERROR_DIALOGS: &str = "hide_error_dialogs";
/// The log targets of the demo's away and return inputs and of its gate,
/// printed when the proof fails.
const GATE_TRACE_TARGETS: [&str; 2] = [
    "\"target\":\"connetto_client::away\"",
    "\"target\":\"connetto_dioxus::away\"",
];
/// The second phone's account in the peer proof, so each page's `linked:`
/// line names the other phone unambiguously.
const PEER_USER: &str = "bob";
/// The localized texts of the system's network-approval dialog button, for
/// the locales the proof phones run, which the driver taps in place of the
/// user (R76 decision 16).
const CONNECT_BUTTONS: [&str; 3] = ["Connect", "Connetti", "Verbinden"];
/// The Bluetooth enable dialog's refusal in the runner's locales, which a
/// host whose beacon stays down taps (R76 decision 21).
const DENY_BUTTONS: [&str; 6] = [
    "Deny",
    "Don't allow",
    "Rifiuta",
    "Non consentire",
    "Ablehnen",
    "Nicht zulassen",
];
/// The silence a link gets to end after the phones leave the hotspot, on
/// either side.
const LINK_END_BOUND: Duration = Duration::from_secs(120);
/// The beacon's service-data UUID (R76), required in the host's dump.
const BEACON_SERVICE_UUID: &str = "a9952637-85d5-4071-9ed8-c28bd7ba670c";
/// The characteristic the joiner writes to (R76).
const BEACON_INBOX_UUID: &str = "bdd3f20f-a8d0-4003-82db-4f941b4c375b";
/// The characteristic the joiner reads notifications from (R76).
const BEACON_OUTBOX_UUID: &str = "62ba3a58-c377-47f5-93e1-cd6790bc2e53";
/// The Bluetooth permissions the beacon asks for (R76).
const BT_PERMISSIONS: [&str; 3] = [
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
];

#[tokio::main]
async fn main() -> Result<()> {
    let stack = Stack::from_env()?;
    let Arguments {
        serial,
        apk,
        unlock_pin,
        peer_serial,
        bluetooth,
        payload,
        every_join,
    } = cli_arguments()?;
    let device = Device::pick(serial).await?;
    let evidence = repo_path(&["target", "android-proof"])?.join(format!(
        "{}-{}",
        device.serial,
        now_millis()
    ));
    tokio::fs::create_dir_all(&evidence)
        .await
        .with_context(|| format!("creating {}", evidence.display()))?;
    eprintln!("evidence in {}", evidence.display());

    // The login tab is read through Chrome's DevTools socket, so Chrome holds
    // the browser role for the run and the device's own choice returns after.
    let previous = device.browser_role_holder().await?;
    // The proof keeps the screen on, and a phone left on the cable must not stay lit after it.
    let stay_on = device.global_setting(STAY_ON).await?;
    // A system app freezing on a slow device covers every screen the proof taps with a dialog.
    let error_dialogs = device.global_setting(HIDE_ERROR_DIALOGS).await?;
    device.set_browser_role_holder(BROWSER).await?;
    let unlock = Unlock {
        pin: unlock_pin.as_deref(),
    };
    let outcome = match device.hide_error_dialogs().await {
        Ok(()) => {
            let apk = match apk {
                Some(apk) => apk,
                None => build_apk(&device.rust_target().await?).await?,
            };
            let started = Instant::now();
            let outcome = prove(&device, &apk, &stack, &evidence, unlock).await;
            let proved = (
                started.elapsed(),
                outcome.as_ref().map_err(|err| format!("{err:#}")).map(drop),
            );
            // The peer proof runs only on a proved phone, and a failed
            // proof keeps its own error.
            match (bluetooth, peer_serial, outcome) {
                (true, None, Ok(())) => bluetooth_proof(&device, &evidence).await,
                (_, Some(serial), Ok(())) => {
                    let joins = JoinBy::chosen(every_join, bluetooth, payload);
                    let joiner = Device::new(serial);
                    let run = PeerRun {
                        apk: &apk,
                        stack: &stack,
                        evidence: &evidence,
                        unlock,
                    };
                    joins_with_summary(&device, &joiner, &run, joins, &proved).await
                }
                (_, _, outcome) => outcome,
            }
        }
        Err(err) => Err(err),
    };
    let log = device.adb(&["logcat", "-d"]).await.unwrap_or_default();
    if outcome.is_err() {
        for line in log.lines().filter(|line| {
            GATE_TRACE_TARGETS
                .iter()
                .any(|target| line.contains(target))
        }) {
            eprintln!("{line}");
        }
    }
    tokio::fs::write(evidence.join("logcat.txt"), log)
        .await
        .context("writing the device log")?;
    if let Err(err) = &outcome {
        let _ = device.screenshot(&evidence, "failure").await;
        eprintln!("proof failed: {err:#}");
    }
    let _ = device.adb(&["forward", "--remove-all"]).await;
    let _ = device.adb(&["reverse", "--remove-all"]).await;
    let _ = device.adb(&["shell", "am", "force-stop", PACKAGE]).await;
    let restored = match previous.as_deref() {
        Some(holder) => device.set_browser_role_holder(holder).await,
        None => device
            .adb(&[
                "shell",
                "cmd",
                "role",
                "remove-role-holder",
                BROWSER_ROLE,
                BROWSER,
            ])
            .await
            .map(drop),
    };
    let screen = device
        .restore_global_setting(STAY_ON, stay_on.as_deref())
        .await;
    let dialogs = device
        .restore_global_setting(HIDE_ERROR_DIALOGS, error_dialogs.as_deref())
        .await;
    outcome.and(restored).and(screen).and(dialogs)
}

/// What `connetto-demo-stack` tells its command.
struct Stack {
    pg_url: String,
    reverse: Vec<(u16, u16)>,
    issuer: String,
}

impl Stack {
    fn from_env() -> Result<Self> {
        let var = |key: &str| {
            std::env::var(key)
                .with_context(|| format!("{key} is unset, run under connetto-demo-stack"))
        };
        Ok(Self {
            pg_url: var("CONNETTO_DEMO_PG")?,
            reverse: parse_reverse(&var("CONNETTO_DEMO_ADB_REVERSE")?)?,
            issuer: var("CONNETTO_DEMO_ISSUER")?,
        })
    }

    fn host_port(&self, device_port: u16) -> Result<u16> {
        self.reverse
            .iter()
            .find(|(device, _)| *device == device_port)
            .map(|(_, host)| *host)
            .ok_or_else(|| anyhow!("no reverse pair for device port {device_port}"))
    }
}

async fn prove(
    device: &Device,
    apk: &Path,
    stack: &Stack,
    evidence: &Path,
    unlock: Unlock<'_>,
) -> Result<()> {
    // A paused charge ends a `usb` stay-on, and a sleeping screen locks the phone.
    device
        .adb(&["shell", "svc", "power", "stayon", "true"])
        .await?;
    device
        .adb(&["shell", "input", "keyevent", "KEYCODE_WAKEUP"])
        .await?;
    unlock.dismiss_keyguard(device).await?;
    step("install");
    device
        .adb(&["install", "-r", "-t", &apk.display().to_string()])
        .await?;
    device.adb(&["shell", "pm", "clear", PACKAGE]).await?;
    device.adb(&["logcat", "-c"]).await?;
    device.adb(&["reverse", "--remove-all"]).await?;
    for (device_port, host_port) in &stack.reverse {
        device.reverse(*device_port, *host_port).await?;
    }

    step("sign in");
    device.launch().await?;
    let mut tab = device.login_tab(&stack.issuer).await?;
    device.screenshot(evidence, "login-page").await?;
    submit_login(&mut tab, USER).await?;
    drop(tab);
    unlock.approve(device, evidence, "launch-unlock").await?;
    let mut app = device.app().await?;
    app.wait_for_text("status: connected", Duration::from_secs(90))
        .await?;
    app.wait_for_text(
        "custody: released only after user verification",
        Duration::from_secs(10),
    )
    .await?;
    device.screenshot(evidence, "signed-in").await?;

    if demo_has_device_identity() {
        step("enrol the device");
        app.wait_for_text("device: certified until", Duration::from_secs(60))
            .await?;
        device.screenshot(evidence, "device-certified").await?;
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
    device.screenshot(evidence, "synced").await?;

    step("write offline");
    device.drop_sync_link(&stack.reverse).await?;
    let mut app = device.app().await?;
    app.wait_for_text("status: reconnecting", Duration::from_secs(60))
        .await?;
    let offline = order_count(&stack.pg_url).await?;
    app.click("Insert locally (client write)").await?;
    sleep(Duration::from_secs(3)).await;
    if order_count(&stack.pg_url).await? != offline {
        bail!("an offline write reached Postgres");
    }
    device.screenshot(evidence, "offline-write").await?;

    step("upload on reconnect");
    device
        .reverse(SYNC_PORT, stack.host_port(SYNC_PORT)?)
        .await?;
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
    device.screenshot(evidence, "uploaded").await?;
    recheck_after_time_away(device, evidence, unlock).await?;
    let mut app = device.app().await?;
    sign_out(device, &mut app, evidence).await?;
    sign_in_across_a_killed_process(device, &stack.issuer, evidence, unlock).await?;
    step("proof complete");
    Ok(())
}

/// Sign out, which revokes the session and destroys the replica key, and see
/// the demo start over. Only a successful sign-out starts over, since any
/// failure is shown in the session panel instead.
async fn sign_out(device: &Device, app: &mut PageSession, evidence: &Path) -> Result<()> {
    step("sign out");
    app.click("Sign out (wipe local replica)").await?;
    app.wait_for_outcome(
        "Signing in",
        &["logout error", "not yet synced"],
        Duration::from_secs(60),
    )
    .await?;
    device.screenshot(evidence, "signed-out").await
}

/// The system may kill the app while its login is open in the browser tab.
/// Sign-out leaves the demo opening a fresh login, so the driver kills the
/// backgrounded app the way low memory does, then finishes the login in the
/// tab. The redirect starts a new process, and only one that finishes the
/// persisted login reaches `connected`, since a restarted login would open a
/// tab nobody types into.
async fn sign_in_across_a_killed_process(
    device: &Device,
    issuer: &str,
    evidence: &Path,
    unlock: Unlock<'_>,
) -> Result<()> {
    step("sign in across a killed process");
    let mut tab = device.login_tab(issuer).await?;
    let killed = device.adb(&["shell", "pidof", PACKAGE]).await?;
    let deadline = Instant::now() + Duration::from_secs(10);
    // `am kill` spares a visible process, and the app stays visible briefly after the tab opens.
    loop {
        device.adb(&["shell", "am", "kill", PACKAGE]).await?;
        sleep(Duration::from_millis(250)).await;
        if device.adb(&["shell", "pidof", PACKAGE]).await.is_err() {
            break;
        }
        if Instant::now() >= deadline {
            bail!(
                "the backgrounded app (pid {}) was not killed",
                killed.trim()
            );
        }
    }
    submit_login(&mut tab, USER).await?;
    drop(tab);
    unlock.approve(device, evidence, "restart-unlock").await?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut app = loop {
        match device.app().await {
            Ok(app) => break app,
            Err(err) if Instant::now() >= deadline => {
                return Err(err.context("the redirect never started the app again"));
            }
            Err(_) => sleep(Duration::from_millis(500)).await,
        }
    };
    app.wait_for_text("status: connected", Duration::from_secs(90))
        .await?;
    device.screenshot(evidence, "resumed").await
}

/// The demo's re-check grace, `RECHECK_AFTER` in its source.
const RECHECK_AFTER: Duration = Duration::from_secs(30);

/// Leave the app for longer than its re-check grace and come back: the gate
/// locks, asks once, and the approval unlocks it with the session kept.
async fn recheck_after_time_away(
    device: &Device,
    evidence: &Path,
    unlock: Unlock<'_>,
) -> Result<()> {
    step("re-check after time away");
    device
        .adb(&["shell", "input", "keyevent", "KEYCODE_HOME"])
        .await?;
    // The CI emulator draws a frame in seconds, so the app can see its suspension late.
    sleep(RECHECK_AFTER + Duration::from_secs(30)).await;
    device.launch().await?;
    unlock.approve(device, evidence, "recheck-unlock").await?;
    let mut app = device.app().await?;
    app.wait_for_text("gate: open", Duration::from_secs(30))
        .await?;
    device.screenshot(evidence, "unlocked").await
}

/// The offer a hosting phone shows, its lines read off the page.
struct HotspotOfferLines {
    /// The hotspot's ssid.
    ssid: String,
    /// The hotspot's passphrase.
    passphrase: String,
    /// The host's peer port.
    port: u16,
    /// The offer as one `WIFI:` payload, where the page shows it.
    payload: Option<String>,
}

/// The offer a hosting phone shows, its lines read off the page, bounded.
async fn read_hotspot_offer(app: &mut PageSession) -> Result<HotspotOfferLines> {
    app.wait_for_text("hotspot ssid: ", Duration::from_secs(45))
        .await
        .context("the host never showed its offer")?;
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let page = app.page_text().await?;
        if let Some(offer) = parse_offer_lines(&page) {
            return Ok(offer);
        }
        if Instant::now() >= deadline {
            bail!("the offer's lines never finished showing, the page shows:\n{page}");
        }
        sleep(Duration::from_millis(500)).await;
    }
}

/// What every join of a run shares: the build, the stack, the evidence
/// folder and the unlock.
struct PeerRun<'a> {
    apk: &'a Path,
    stack: &'a Stack,
    evidence: &'a Path,
    unlock: Unlock<'a>,
}

/// Make the joins, write the summary, and fail when any join failed.
async fn joins_with_summary(
    host: &Device,
    joiner: &Device,
    run: &PeerRun<'_>,
    joins: &[JoinBy],
    proved: &(Duration, Result<(), String>),
) -> Result<()> {
    let reports = peer_proof(
        host,
        joiner,
        run.apk,
        run.stack,
        run.evidence,
        run.unlock,
        joins,
    )
    .await;
    let summary = summary(&commit().await, proved, reports.as_deref());
    eprintln!("{summary}");
    tokio::fs::write(run.evidence.join("summary.txt"), &summary)
        .await
        .context("writing the summary")?;
    let failed: Vec<&str> = reports?
        .iter()
        .filter(|report| report.outcome.is_err())
        .map(|report| report.join.name())
        .collect();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("the {} join failed", failed.join(", ")))
    }
}

/// How the second phone learns the hotspot the first one hosts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum JoinBy {
    /// The first phone's offer lines typed into the second's join form.
    Form,
    /// The first phone's Bluetooth beacon and the exchange behind it (R76).
    Beacon,
    /// The first phone's `WIFI:` payload pasted into the second's join form
    /// (R76 decision 24).
    Payload,
}

impl JoinBy {
    /// Every join, in the order `--every-join` runs them (R76 decision 4).
    const EVERY: [Self; 3] = [Self::Form, Self::Beacon, Self::Payload];

    /// The joins the command line asks for.
    const fn chosen(every_join: bool, bluetooth: bool, payload: bool) -> &'static [Self] {
        match (every_join, bluetooth, payload) {
            (true, ..) => &Self::EVERY,
            (false, true, _) => &[Self::Beacon],
            (false, false, true) => &[Self::Payload],
            (false, false, false) => &[Self::Form],
        }
    }

    /// The join's name in the summary and the screenshots.
    const fn name(self) -> &'static str {
        match self {
            Self::Form => "form",
            Self::Beacon => "beacon",
            Self::Payload => "payload",
        }
    }
}

/// One join's result, for the run's summary.
struct JoinReport {
    join: JoinBy,
    took: Duration,
    outcome: Result<()>,
}

/// The two-phone peer proof (R76 slice 4): `host` hosts a hotspot from the
/// demo and `joiner` signs in as its own account and joins it, the driver
/// tapping the system's approval in place of the user (decision 16), until
/// both pages name the other as linked. It ends with both phones back on
/// their usual networks.
async fn peer_proof(
    host: &Device,
    joiner: &Device,
    apk: &Path,
    stack: &Stack,
    evidence: &Path,
    unlock: Unlock<'_>,
    joins: &[JoinBy],
) -> Result<Vec<JoinReport>> {
    if !demo_has_device_identity() {
        bail!("the peer proof needs a demo build with its device identity");
    }
    step("prepare the peer phone");
    let (stay_on, previous_role) = prepare_joiner(joiner, &unlock).await?;
    // The joiner's usual network, read after the wireless reconnect, which
    // the cleanup must bring it back to.
    let usual_ssid = joiner.current_ssid().await?;
    let result = run_peer_proof(
        host,
        joiner,
        apk,
        stack,
        evidence,
        &unlock,
        usual_ssid.as_ref(),
        joins,
    )
    .await;

    // The joiner's log for the record, and its state, which the run leaves
    // as it found it.
    let log = joiner.adb(&["logcat", "-d"]).await.unwrap_or_default();
    tokio::fs::write(evidence.join("peer-logcat.txt"), log)
        .await
        .context("writing the peer phone's log")?;
    let restore_role = match &previous_role {
        Some(holder) => joiner.set_browser_role_holder(holder).await,
        None => joiner
            .adb(&[
                "shell",
                "cmd",
                "role",
                "remove-role-holder",
                BROWSER_ROLE,
                BROWSER,
            ])
            .await
            .map(drop),
    };
    let restore_stay = joiner
        .restore_global_setting(STAY_ON, stay_on.as_deref())
        .await;
    let _ = joiner.adb(&["forward", "--remove-all"]).await;
    let _ = joiner.adb(&["reverse", "--remove-all"]).await;
    let _ = joiner.adb(&["shell", "am", "force-stop", PACKAGE]).await;
    let reports = result?;
    restore_role?;
    restore_stay?;
    Ok(reports)
}

/// Reconnect a wireless joiner over `adb connect`, hold it awake and
/// unlocked, and take the browser role the login tab wants, keeping the
/// stay-on and role state the run restores.
async fn prepare_joiner(
    joiner: &Device,
    unlock: &Unlock<'_>,
) -> Result<(Option<String>, Option<String>)> {
    // A wireless joiner lost its transport when the single-phone proof
    // restarted the host's adb server.
    if joiner.serial.contains(':') {
        let status = Command::new("adb")
            .args(["connect", &joiner.serial])
            .status()
            .await
            .context("starting adb")?;
        if !status.success() {
            bail!("adb connect {} exited with {status}", joiner.serial);
        }
    }
    joiner.adb(&["wait-for-device"]).await?;
    let stay_on = joiner.global_setting(STAY_ON).await?;
    let previous_role = joiner.browser_role_holder().await?;
    joiner
        .adb(&["shell", "svc", "power", "stayon", "true"])
        .await?;
    joiner
        .adb(&["shell", "input", "keyevent", "KEYCODE_WAKEUP"])
        .await?;
    unlock.dismiss_keyguard(joiner).await?;
    joiner.set_browser_role_holder(BROWSER).await?;
    Ok((stay_on, previous_role))
}

/// The walk itself: install and sign in the joiner once, then each join in
/// turn, every one recorded, with the phones brought back to rest after each.
#[expect(
    clippy::too_many_arguments,
    reason = "the two phones, the build, the stack, the evidence, the unlock, the joiner's network and the joins are each the walk's own"
)]
async fn run_peer_proof(
    host: &Device,
    joiner: &Device,
    apk: &Path,
    stack: &Stack,
    evidence: &Path,
    unlock: &Unlock<'_>,
    usual_ssid: Option<&String>,
    joins: &[JoinBy],
) -> Result<Vec<JoinReport>> {
    joiner
        .adb(&["install", "-r", "-t", &apk.display().to_string()])
        .await?;
    joiner.adb(&["shell", "pm", "clear", PACKAGE]).await?;
    joiner.adb(&["reverse", "--remove-all"]).await?;
    for (device_port, host_port) in &stack.reverse {
        joiner.reverse(*device_port, *host_port).await?;
    }
    // The users granted the peer link's permissions before, so only the
    // Bluetooth enable dialog stands between a beacon and the radio.
    for phone in [host, joiner] {
        for permission in BT_PERMISSIONS
            .iter()
            .copied()
            .chain(["android.permission.NEARBY_WIFI_DEVICES"])
        {
            phone
                .adb(&["shell", "pm", "grant", PACKAGE, permission])
                .await?;
        }
    }

    let mut peer_app = sign_in_joiner(joiner, stack, evidence, unlock).await?;
    let mut app = host.app().await?;
    app.wait_for_text("device: certified until", Duration::from_secs(60))
        .await?;
    let host_identity = own_identity(&mut app).await?;
    let joiner_identity = own_identity(&mut peer_app).await?;

    let mut reports = Vec::with_capacity(joins.len());
    for &join in joins {
        let started = Instant::now();
        let outcome = one_join(
            host,
            joiner,
            &mut app,
            &mut peer_app,
            evidence,
            (&host_identity, &joiner_identity),
            usual_ssid,
            join,
        )
        .await;
        if let Err(err) = &outcome {
            eprintln!("the {} join failed: {err:#}", join.name());
            let _ = host
                .screenshot(evidence, &format!("{}-failure-host", join.name()))
                .await;
            let _ = joiner
                .screenshot(evidence, &format!("{}-failure-peer", join.name()))
                .await;
        }
        reports.push(JoinReport {
            join,
            took: started.elapsed(),
            outcome,
        });
    }
    Ok(reports)
}

/// One join, from a hotspot hosted on the first phone to the link's end, and
/// the phones back at rest whatever happened.
#[expect(
    clippy::too_many_arguments,
    reason = "the two phones, their pages, the evidence, both identities, the joiner's network and the join are each the step's own"
)]
async fn one_join(
    host: &Device,
    joiner: &Device,
    app: &mut PageSession,
    peer_app: &mut PageSession,
    evidence: &Path,
    identities: (&str, &str),
    usual_ssid: Option<&String>,
    join: JoinBy,
) -> Result<()> {
    if join == JoinBy::Beacon {
        step("turn Bluetooth on on both phones");
        for phone in [host, joiner] {
            bluetooth_on(phone).await?;
        }
    }
    step(&format!(
        "host a hotspot on the first phone for the {} join",
        join.name()
    ));
    // An A35 refuses to start an access point while its own station sits on
    // a 5 GHz channel, measured on eduroam, so the host leaves its network,
    // as a host in the field has none. Its server path stays on USB.
    host.adb(&["shell", "svc", "wifi", "disable"]).await?;
    sleep(Duration::from_secs(5)).await;
    let hosted = host_and_link(host, joiner, app, peer_app, evidence, identities, join).await;
    // Back to rest whatever happened, so the next join starts clean: the
    // pages' own leave and stop, the host's Wi-Fi, Bluetooth off, and the
    // joiner on its usual network.
    if hosted.is_err() {
        let _ = peer_app.click("Leave the hotspot").await;
        let _ = app.click("Stop the hotspot").await;
    }
    let restored = host
        .adb(&["shell", "svc", "wifi", "enable"])
        .await
        .map(drop);
    let mut bluetooth = Ok(());
    for phone in [host, joiner] {
        bluetooth = bluetooth.and(bluetooth_off(phone).await);
    }
    let offer_ssid = hosted?;
    restored?;
    bluetooth?;
    restore_joiner_networks(host, joiner, &offer_ssid, usual_ssid).await?;
    joiner
        .screenshot(evidence, &format!("{}-peer-clean", join.name()))
        .await?;
    Ok(())
}

/// Host on the first phone, join from the second, link, and end the link,
/// answering the hotspot's ssid for the cleanup.
async fn host_and_link(
    host: &Device,
    joiner: &Device,
    app: &mut PageSession,
    peer_app: &mut PageSession,
    evidence: &Path,
    (host_identity, joiner_identity): (&str, &str),
    join_by: JoinBy,
) -> Result<String> {
    let shot = |name: &str| format!("{}-{name}", join_by.name());
    app.click("Host a hotspot").await?;
    // Without the beacon the host's Bluetooth stays off, so hosting opens
    // the system's enable dialog, which the host's user declines.
    if join_by != JoinBy::Beacon {
        step("decline Bluetooth on the first phone");
        host.tap_dialog_button(&DENY_BUTTONS, "the Bluetooth enable dialog's refusal")
            .await?;
        app.wait_for_text("hosting, the beacon is off", Duration::from_secs(30))
            .await?;
    }
    let offer = read_hotspot_offer(app).await?;
    host.screenshot(evidence, &shot("host-offer")).await?;

    match join_by {
        JoinBy::Form => {
            step("fill the join form on the second phone");
            peer_app.set_input("ssid", &offer.ssid).await?;
            peer_app.set_input("passphrase", &offer.passphrase).await?;
            peer_app.set_input("port", &offer.port.to_string()).await?;
            peer_app.click("Join the hotspot").await?;
        }
        JoinBy::Payload => {
            let payload = offer
                .payload
                .as_deref()
                .context("the host shows no WIFI: payload")?;
            step("paste the payload on the second phone");
            peer_app.set_input("payload", payload).await?;
            peer_app.click("Join from the payload").await?;
            if peer_app
                .wait_for_text("joining the hotspot", Duration::from_secs(10))
                .await
                .is_err()
            {
                let page = peer_app.page_text().await.unwrap_or_default();
                bail!("the second phone did not take the payload, its page shows:\n{page}");
            }
        }
        JoinBy::Beacon => {
            let beacon = read_beacon(app).await?;
            let prefix = beacon
                .strip_prefix("beacon: advertising ")
                .context("the beacon line carries no prefix")?
                .to_owned();
            step("find the beacon on the second phone");
            peer_app
                .wait_for_text(&format!("nearby: {prefix}"), Duration::from_secs(60))
                .await
                .context("the second phone never saw the first phone's beacon")?;
            // The join button takes the strongest host, so the first phone's
            // must be the only one in sight.
            let page = peer_app.page_text().await?;
            let nearby: Vec<&str> = page
                .lines()
                .filter(|line| line.starts_with("nearby: "))
                .collect();
            if nearby.len() != 1 {
                bail!("the second phone sees other hosts than the first: {nearby:?}");
            }
            joiner.screenshot(evidence, &shot("peer-nearby")).await?;
            peer_app.click("Join the nearby host").await?;
        }
    }

    step("approve the network on the second phone");
    joiner.tap_connect_button().await?;

    step("link through the hotspot");
    if app
        .wait_for_text(
            &format!("linked: {joiner_identity}"),
            Duration::from_secs(90),
        )
        .await
        .is_err()
    {
        let peer_page = peer_app.page_text().await.unwrap_or_default();
        bail!(
            "the first phone never named the second as linked, the second phone shows:\n{peer_page}"
        );
    }
    peer_app
        .wait_for_text(&format!("linked: {host_identity}"), Duration::from_secs(30))
        .await?;
    host.screenshot(evidence, &shot("host-linked")).await?;
    joiner.screenshot(evidence, &shot("peer-linked")).await?;

    step("leave the hotspot on the second phone");
    peer_app.click("Leave the hotspot").await?;
    step("stop the hotspot on the first phone");
    app.click("Stop the hotspot").await?;
    wait_link_ends(app, peer_app).await?;
    host.screenshot(evidence, &shot("host-unlinked")).await?;
    Ok(offer.ssid)
}

/// The page's own peer identity, `account/key prefix`, from its listening
/// line, which the wait polls until the line carries it.
async fn own_identity(app: &mut PageSession) -> Result<String> {
    // The peer panel updates the listening line on its own poll, which the
    // device label does not wait for, so the wait polls the line itself.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let page = app.page_text().await?;
        if let Some(identity) = page
            .lines()
            .find_map(|line| line.strip_prefix("peer: listening on "))
            .and_then(|rest| rest.split_once(" as "))
            .map(|(_, identity)| identity.trim().to_owned())
        {
            return Ok(identity);
        }
        if Instant::now() >= deadline {
            bail!("the page names no peer identity");
        }
        sleep(Duration::from_millis(500)).await;
    }
}

/// Sign the joiner in as its own account and wait for it to connect and
/// certify, leaving its app page open.
async fn sign_in_joiner(
    joiner: &Device,
    stack: &Stack,
    evidence: &Path,
    unlock: &Unlock<'_>,
) -> Result<PageSession> {
    step("sign in the peer phone");
    joiner.launch().await?;
    let mut tab = joiner.login_tab(&stack.issuer).await?;
    joiner.screenshot(evidence, "peer-login-page").await?;
    submit_login(&mut tab, PEER_USER).await?;
    drop(tab);
    unlock
        .approve(joiner, evidence, "peer-launch-unlock")
        .await?;
    let mut peer_app = joiner.app().await?;
    peer_app
        .wait_for_text("status: connected", Duration::from_secs(90))
        .await?;
    peer_app
        .wait_for_text("device: certified until", Duration::from_secs(60))
        .await?;
    joiner.screenshot(evidence, "peer-signed-in").await?;
    Ok(peer_app)
}

/// Wait for both pages to drop their linked lines, which the leave and stop
/// end the link.
async fn wait_link_ends(app: &mut PageSession, peer_app: &mut PageSession) -> Result<()> {
    let deadline = Instant::now() + LINK_END_BOUND;
    loop {
        let host_page = app.page_text().await?;
        let peer_page = peer_app.page_text().await?;
        if !host_page.contains("linked: ") && !peer_page.contains("linked: ") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the link did not end after the phones left the hotspot");
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Forget the hotspot's saved profile on both phones, best effort, and wait
/// for the joiner to fall back to its usual network.
async fn restore_joiner_networks(
    host: &Device,
    joiner: &Device,
    ssid: &str,
    usual_ssid: Option<&String>,
) -> Result<()> {
    step("clean up the networks");
    // A saved profile the platform may have kept, best effort.
    for phone in [host, joiner] {
        phone.forget_network(ssid).await?;
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let current = joiner.current_ssid().await?;
        if current.as_deref() == usual_ssid.map(String::as_str) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the peer phone is back on {current:?}, not {usual_ssid:?}");
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Turn a phone's Bluetooth off and hold until the platform reports it off,
/// which every run ends with.
async fn bluetooth_off(device: &Device) -> Result<()> {
    device
        .adb(&["shell", "cmd", "bluetooth_manager", "disable"])
        .await?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let on = device
            .adb(&["shell", "settings", "get", "global", "bluetooth_on"])
            .await?;
        if on.trim() == "0" {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "{} never turned its Bluetooth off after it was disabled",
                device.serial
            );
        }
        sleep(Duration::from_millis(500)).await;
    }
}

/// Turn a phone's Bluetooth on and hold until the platform reports it on.
async fn bluetooth_on(device: &Device) -> Result<()> {
    device
        .adb(&["shell", "cmd", "bluetooth_manager", "enable"])
        .await?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let on = device
            .adb(&["shell", "settings", "get", "global", "bluetooth_on"])
            .await?;
        if on.trim() == "1" {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "{} never turned its Bluetooth on after it was enabled",
                device.serial
            );
        }
        sleep(Duration::from_millis(500)).await;
    }
}

/// The host's beacon line off the page, `advertising` with its prefix, bounded.
async fn read_beacon(app: &mut PageSession) -> Result<String> {
    app.wait_for_text("beacon: advertising", Duration::from_secs(60))
        .await
        .context("the host's beacon never advertised")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let page = app.page_text().await?;
        if let Some(line) = page
            .lines()
            .find(|line| line.starts_with("beacon: advertising"))
        {
            return Ok(line.trim().to_owned());
        }
        if Instant::now() >= deadline {
            bail!("the beacon line never carried a prefix, the page shows:\n{page}");
        }
        sleep(Duration::from_millis(500)).await;
    }
}

/// The host-side Bluetooth beacon proof (R76 slice 5a). The phone hosts a
/// hotspot from the demo, which turns on its beacon, and the proof reads the
/// beacon's prefix from the panel and requires the demo's advertising set and
/// GATT service in the phone's Bluetooth dump. It ends with Bluetooth off.
async fn bluetooth_proof(host: &Device, evidence: &Path) -> Result<()> {
    if !demo_has_device_identity() {
        bail!("the bluetooth proof needs a demo build with its device identity");
    }
    let result = run_bluetooth_proof(host, evidence).await;
    let off = bluetooth_off(host).await;
    result.and(off)
}

/// The walk itself: turn Bluetooth on, grant its permissions, host, read the
/// beacon's prefix, and check the advertising set and the service.
async fn run_bluetooth_proof(host: &Device, evidence: &Path) -> Result<()> {
    step("turn Bluetooth on");
    bluetooth_on(host).await?;

    step("grant the Bluetooth permissions");
    for permission in BT_PERMISSIONS {
        host.adb(&["shell", "pm", "grant", PACKAGE, permission])
            .await?;
    }
    host.adb(&[
        "shell",
        "pm",
        "grant",
        PACKAGE,
        "android.permission.NEARBY_WIFI_DEVICES",
    ])
    .await?;

    step("host a hotspot");
    // Some phones refuse to start an access point while their own station
    // sits on a 5 GHz channel, so the host leaves its network, as a host in
    // the field has none.
    host.adb(&["shell", "svc", "wifi", "disable"]).await?;
    let result = host_with_beacon(host, evidence).await;
    let _ = host.adb(&["shell", "svc", "wifi", "enable"]).await;
    result
}

/// Host from the demo and check the beacon, with the phone off its network.
async fn host_with_beacon(host: &Device, evidence: &Path) -> Result<()> {
    sleep(Duration::from_secs(5)).await;
    let mut app = host.app().await?;
    app.wait_for_text("device: certified until", Duration::from_secs(60))
        .await?;
    app.click("Host a hotspot").await?;
    let beacon = read_beacon(&mut app).await?;
    eprintln!("{beacon}");
    host.screenshot(evidence, "bt-beacon").await?;

    step("check the advertising set and the service");
    let dump = host.adb(&["shell", "dumpsys", "bluetooth_manager"]).await?;
    tokio::fs::write(evidence.join("host-bluetooth-dump.txt"), &dump)
        .await
        .context("writing the host's Bluetooth dump")?;
    check_beacon_dump(&dump)?;
    eprintln!(
        "the demo advertises a legacy connectable set with 9 bytes of service data and serves its GATT service"
    );

    step("stop the hotspot");
    app.click("Stop the hotspot").await?;
    host.screenshot(evidence, "bt-clean").await?;
    Ok(())
}

/// The demo's advertising set in a `dumpsys bluetooth_manager` dump: legacy,
/// connectable, carrying 9 bytes of service data under the beacon's UUID,
/// beside the started GATT service with both characteristics. The dump masks
/// the service data UUID past its first group.
fn check_beacon_dump(dump: &str) -> Result<()> {
    let set = dump
        .split_once(&format!("    {PACKAGE}\n"))
        .map(|(_, rest)| rest)
        .context("the dump lists no advertising set of the demo")?;
    let set: Vec<&str> = set
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .collect();
    let field = |name: &str| {
        set.iter()
            .find(|line| line.contains(&format!("\u{2514}{name} ")))
            .and_then(|line| line.rsplit(':').next())
            .map(str::trim)
    };
    if field("Legacy") != Some("true") {
        bail!(
            "the demo's advertising set is not legacy:\n{}",
            set.join("\n")
        );
    }
    if field("Connectable") != Some("true") {
        bail!(
            "the demo's advertising set is not connectable:\n{}",
            set.join("\n")
        );
    }
    let masked = format!(
        "[{}-xxxx-xxxx-xxxx-xxxxxxxxxxxx, 9]",
        &BEACON_SERVICE_UUID[..8]
    );
    if !set.iter().any(|line| line.trim() == masked) {
        bail!(
            "the demo's advertising set carries no 9-byte beacon:\n{}",
            set.join("\n")
        );
    }
    let service = format!("Service {BEACON_SERVICE_UUID}, started true");
    let rest = dump
        .split_once(&service)
        .map(|(_, rest)| rest)
        .context("the dump lists no started beacon service")?;
    for characteristic in [BEACON_INBOX_UUID, BEACON_OUTBOX_UUID] {
        if !rest
            .lines()
            .take(4)
            .any(|line| line.contains(characteristic))
        {
            bail!("the beacon service lacks the characteristic {characteristic}");
        }
    }
    Ok(())
}

/// Who answers the platform's unlock prompt.
#[derive(Clone, Copy)]
struct Unlock<'a> {
    /// The PIN the driver types, for an emulator whose PIN the run knows.
    pin: Option<&'a str>,
}

impl Unlock<'_> {
    /// Clear a PIN keyguard, which waking the device leaves up and which hides
    /// every app and browser tab behind it.
    async fn dismiss_keyguard(self, device: &Device) -> Result<()> {
        let Some(pin) = self.pin else {
            return Ok(());
        };
        if !device.keyguard_showing().await? {
            return Ok(());
        }
        device.adb(&["shell", "wm", "dismiss-keyguard"]).await?;
        // The PIN pad needs a moment to take focus.
        sleep(Duration::from_secs(1)).await;
        device.adb(&["shell", "input", "text", pin]).await?;
        device
            .adb(&["shell", "input", "keyevent", "KEYCODE_ENTER"])
            .await?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while device.keyguard_showing().await? {
            if Instant::now() >= deadline {
                bail!("the keyguard stayed up after the PIN");
            }
            sleep(Duration::from_millis(500)).await;
        }
        Ok(())
    }

    /// Wait for the unlock prompt, answer it, and wait for it to close.
    async fn approve(self, device: &Device, evidence: &Path, name: &str) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !device.unlock_prompt_shown().await? {
            if Instant::now() >= deadline {
                bail!("the unlock prompt never showed");
            }
            sleep(Duration::from_millis(500)).await;
        }
        device.screenshot(evidence, name).await?;
        match self.pin {
            Some(pin) => {
                // The credential pad needs a moment to take focus.
                sleep(Duration::from_secs(1)).await;
                device.adb(&["shell", "input", "text", pin]).await?;
                device
                    .adb(&["shell", "input", "keyevent", "KEYCODE_ENTER"])
                    .await?;
            }
            None => eprintln!("approve the unlock prompt on the phone"),
        }
        let deadline = Instant::now() + Duration::from_secs(120);
        while device.unlock_prompt_shown().await? {
            if Instant::now() >= deadline {
                bail!("the unlock prompt was never answered");
            }
            sleep(Duration::from_millis(500)).await;
        }
        Ok(())
    }
}

/// Type the dev user into the identity provider's form and submit it. Trusted
/// input is a user gesture, so the browser follows the final redirect into the
/// app, which is the path a real tap takes.
async fn submit_login(tab: &mut PageSession, user: &str) -> Result<()> {
    tab.evaluate("document.querySelector('input[name=username]').focus()")
        .await?;
    tab.call("Input.insertText", serde_json::json!({ "text": user }))
        .await?;
    for kind in ["keyDown", "keyUp"] {
        tab.call(
            "Input.dispatchKeyEvent",
            serde_json::json!({
                "type": kind,
                "key": "Enter",
                "code": "Enter",
                "windowsVirtualKeyCode": 13,
                "text": "\r",
            }),
        )
        .await?;
    }
    Ok(())
}

fn step(name: &str) {
    eprintln!("== {name}");
}

/// `--serial` and `--apk`, both optional.
/// What the command line names.
#[derive(Default)]
struct Arguments {
    serial: Option<String>,
    apk: Option<PathBuf>,
    unlock_pin: Option<String>,
    peer_serial: Option<String>,
    /// The Bluetooth beacon proof, host-side alone, and the beacon join with
    /// `--peer-serial`.
    bluetooth: bool,
    /// The two-phone join through the host's pasted `WIFI:` payload, with
    /// `--peer-serial`.
    payload: bool,
    /// Every two-phone join in one run, with `--peer-serial` (R76 decision
    /// 4).
    every_join: bool,
}

fn cli_arguments() -> Result<Arguments> {
    let mut arguments = Arguments::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--bluetooth" {
            arguments.bluetooth = true;
            continue;
        }
        if arg == "--payload" {
            arguments.payload = true;
            continue;
        }
        if arg == "--every-join" {
            arguments.every_join = true;
            continue;
        }
        let value = args.next().ok_or_else(|| anyhow!("{arg} needs a value"))?;
        match arg.as_str() {
            "--serial" => arguments.serial = Some(value),
            "--apk" => arguments.apk = Some(PathBuf::from(value)),
            "--unlock-pin" => arguments.unlock_pin = Some(value),
            "--peer-serial" => arguments.peer_serial = Some(value),
            other => bail!("unknown argument {other}"),
        }
    }
    if arguments.payload && arguments.peer_serial.is_none() {
        bail!("--payload needs --peer-serial");
    }
    if arguments.every_join && arguments.peer_serial.is_none() {
        bail!("--every-join needs --peer-serial");
    }
    if arguments.every_join && (arguments.bluetooth || arguments.payload) {
        bail!("--every-join runs every join, so --bluetooth and --payload name none");
    }
    Ok(arguments)
}

/// The commit the run built, marked `-dirty` over local changes, and
/// `unknown` where git does not answer.
async fn commit() -> String {
    let Ok(root) = repo_path(&[]) else {
        return "unknown".to_owned();
    };
    match Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["describe", "--always", "--dirty", "--abbrev=40"])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        _ => "unknown".to_owned(),
    }
}

/// The run's summary: the commit, the single-phone proof, and each join with
/// its time and, where it failed, why.
fn summary(
    commit: &str,
    (proof_took, proof): &(Duration, Result<(), String>),
    joins: Result<&[JoinReport], &anyhow::Error>,
) -> String {
    let line = |name: &str, took: Duration, outcome: Result<(), String>| match outcome {
        Ok(()) => format!("{name}: passed in {}s\n", took.as_secs()),
        Err(err) => format!("{name}: failed in {}s: {err}\n", took.as_secs()),
    };
    let mut text = format!("commit: {commit}\n");
    text += &line("single-phone proof", *proof_took, proof.clone());
    match joins {
        Ok(reports) => {
            for report in reports {
                text += &line(
                    &format!("{} join", report.join.name()),
                    report.took,
                    report
                        .outcome
                        .as_ref()
                        .map(drop)
                        .map_err(|err| format!("{err:#}")),
                );
            }
        }
        Err(err) => {
            use std::fmt::Write as _;
            let _ = writeln!(text, "joins: not run, the setup failed: {err:#}");
        }
    }
    text
}

/// Comma-separated `device:host` port pairs.
fn parse_reverse(spec: &str) -> Result<Vec<(u16, u16)>> {
    spec.split(',')
        .map(|pair| {
            let (device, host) = pair
                .split_once(':')
                .ok_or_else(|| anyhow!("{pair} is not device:host"))?;
            Ok((device.parse()?, host.parse()?))
        })
        .collect()
}

async fn restart_adb_server() -> Result<()> {
    for command in ["kill-server", "start-server"] {
        let status = Command::new("adb")
            .arg(command)
            .status()
            .await
            .context("starting adb")?;
        if !status.success() {
            bail!("adb {command} exited with {status}");
        }
    }
    Ok(())
}

async fn build_apk(target: &str) -> Result<PathBuf> {
    step("build");
    let demo = repo_path(&DEMO_DIR)?;
    let status = Command::new("dx")
        .args([
            "build",
            "--android",
            "--target",
            target,
            "--no-default-features",
            "--features",
            demo_mobile_features(),
        ])
        .current_dir(&demo)
        .status()
        .await
        .context("starting dx")?;
    if !status.success() {
        bail!("dx build exited with {status}");
    }
    Ok(demo.join(
        "target/dx/connetto-dioxus-desktop-demo/debug/android/app/app/build/outputs/apk/debug/app-debug.apk",
    ))
}

struct Device {
    serial: String,
    /// The `adb` program, a stand-in under test.
    program: PathBuf,
    /// How long a device that dropped offline gets to come back.
    recover_within: Duration,
    /// The browser targets [`Device::login_tab`] returned. A finished login's
    /// tab can stay listed on the authorize URL while it closes, so a later
    /// login must never pick it again.
    spent_tabs: std::sync::Mutex<Vec<String>>,
}

impl Device {
    fn new(serial: String) -> Self {
        Self::with_adb(serial, PathBuf::from("adb"), Duration::from_secs(30))
    }

    fn with_adb(serial: String, program: PathBuf, recover_within: Duration) -> Self {
        Self {
            serial,
            program,
            recover_within,
            spent_tabs: std::sync::Mutex::default(),
        }
    }

    /// The named device, or the only one attached.
    async fn pick(serial: Option<String>) -> Result<Self> {
        if let Some(serial) = serial {
            return Ok(Self::new(serial));
        }
        let output = Command::new("adb")
            .arg("devices")
            .output()
            .await
            .context("starting adb")?;
        let listing = String::from_utf8_lossy(&output.stdout);
        let attached = listing
            .lines()
            .skip(1)
            .filter_map(|line| line.strip_suffix("\tdevice"))
            .collect::<Vec<_>>();
        match attached.as_slice() {
            [serial] => Ok(Self::new((*serial).to_owned())),
            [] => bail!("no authorised device is attached"),
            _ => bail!("several devices are attached, name one with --serial"),
        }
    }

    /// Runs `adb -s SERIAL args`, and once more after reconnecting when the
    /// device had dropped offline, which an emulator's transport does under load.
    async fn adb(&self, args: &[&str]) -> Result<String> {
        let output = self.run(args).await?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("device offline") {
            bail!(
                "adb {} exited with {}: {stderr}",
                args.join(" "),
                output.status
            );
        }
        eprintln!("{} dropped offline, reconnecting", self.serial);
        self.reconnect().await?;
        let output = self.run(args).await?;
        if !output.status.success() {
            bail!(
                "adb {} exited with {} after a reconnect: {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    async fn run(&self, args: &[&str]) -> Result<std::process::Output> {
        Command::new(&self.program)
            .arg("-s")
            .arg(&self.serial)
            .args(args)
            .output()
            .await
            .context("starting adb")
    }

    /// Resets offline transports and waits, up to the bound, for the device to answer.
    async fn reconnect(&self) -> Result<()> {
        // A failed reset still leaves the state poll below to decide.
        let _ = Command::new(&self.program)
            .args(["reconnect", "offline"])
            .output()
            .await;
        let deadline = Instant::now() + self.recover_within;
        loop {
            let state = self.run(&["get-state"]).await?;
            if String::from_utf8_lossy(&state.stdout).trim() == "device" {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "{} stayed offline for {:?} after a reconnect",
                    self.serial,
                    self.recover_within
                );
            }
            sleep(Duration::from_millis(200)).await;
        }
    }

    async fn rust_target(&self) -> Result<String> {
        let abi = self
            .adb(&["shell", "getprop", "ro.product.cpu.abi"])
            .await?;
        match abi.trim() {
            "arm64-v8a" => Ok("aarch64-linux-android".to_owned()),
            "x86_64" => Ok("x86_64-linux-android".to_owned()),
            other => bail!("no Rust target is wired for ABI {other}"),
        }
    }

    /// The package holding the browser role, if any.
    async fn browser_role_holder(&self) -> Result<Option<String>> {
        let holders = self
            .adb(&["shell", "cmd", "role", "get-role-holders", BROWSER_ROLE])
            .await?;
        Ok(holders
            .split(';')
            .map(str::trim)
            .find(|holder| !holder.is_empty())
            .map(ToOwned::to_owned))
    }

    /// The device's own value of a global setting, `None` when it holds none.
    async fn global_setting(&self, name: &str) -> Result<Option<String>> {
        let value = self
            .adb(&["shell", "settings", "get", "global", name])
            .await?;
        Ok(Some(value.trim())
            .filter(|value| *value != "null")
            .map(ToOwned::to_owned))
    }

    /// Put back a global setting read by [`Self::global_setting`].
    async fn restore_global_setting(&self, name: &str, value: Option<&str>) -> Result<()> {
        match value {
            Some(value) => {
                self.adb(&["shell", "settings", "put", "global", name, value])
                    .await
            }
            None => {
                self.adb(&["shell", "settings", "delete", "global", name])
                    .await
            }
        }
        .map(drop)
    }

    /// Keep crash and freeze dialogs off the screen and close any already showing.
    async fn hide_error_dialogs(&self) -> Result<()> {
        self.adb(&[
            "shell",
            "settings",
            "put",
            "global",
            HIDE_ERROR_DIALOGS,
            "1",
        ])
        .await?;
        self.adb(&[
            "shell",
            "am",
            "broadcast",
            "-a",
            "android.intent.action.CLOSE_SYSTEM_DIALOGS",
        ])
        .await
        .map(drop)
    }

    async fn set_browser_role_holder(&self, package: &str) -> Result<()> {
        self.adb(&[
            "shell",
            "cmd",
            "role",
            "add-role-holder",
            BROWSER_ROLE,
            package,
        ])
        .await?;
        match self.browser_role_holder().await? {
            Some(holder) if holder == package => Ok(()),
            other => bail!("the browser role went to {other:?}, not {package}"),
        }
    }

    /// Cut the demo's sync link and keep every other reverse. Removing a
    /// reverse leaves its open streams alone, and the host end of each stream
    /// lives in the adb server, so restarting the server drops them.
    async fn drop_sync_link(&self, reverse: &[(u16, u16)]) -> Result<()> {
        restart_adb_server().await?;
        if self.serial.contains(':') {
            let status = Command::new(&self.program)
                .args(["connect", &self.serial])
                .status()
                .await
                .context("starting adb")?;
            if !status.success() {
                bail!("adb connect {} exited with {status}", self.serial);
            }
        }
        self.adb(&["wait-for-device"]).await?;
        for (device_port, host_port) in reverse {
            if *device_port != SYNC_PORT {
                self.reverse(*device_port, *host_port).await?;
            }
        }
        Ok(())
    }

    async fn reverse(&self, device_port: u16, host_port: u16) -> Result<()> {
        self.adb(&[
            "reverse",
            &format!("tcp:{device_port}"),
            &format!("tcp:{host_port}"),
        ])
        .await
        .map(drop)
    }

    /// The ssid the device is connected to, which its `dumpsys wifi` names,
    /// and `None` while it names none.
    async fn current_ssid(&self) -> Result<Option<String>> {
        let dump = self.adb(&["shell", "dumpsys", "wifi"]).await?;
        Ok(parse_current_ssid(&dump))
    }

    /// Forget a saved network profile by its ssid, best effort, since the
    /// platform's one-shot request keeps none of its own.
    async fn forget_network(&self, ssid: &str) -> Result<()> {
        let listing = self.adb(&["shell", "cmd", "wifi", "list-networks"]).await?;
        let Some(id) = saved_network_id(&listing, ssid) else {
            return Ok(());
        };
        self.adb(&["shell", "cmd", "wifi", "forget-network", &id])
            .await
            .map(drop)
    }

    /// Tap the system's network-approval dialog button, in the user's place
    /// (R76 decision 16), waiting for it to show.
    async fn tap_connect_button(&self) -> Result<()> {
        self.tap_dialog_button(&CONNECT_BUTTONS, "the network approval's connect button")
            .await
    }

    /// Tap the system's dialog button `labels` name in one of the runner's
    /// locales, waiting for it to show.
    async fn tap_dialog_button(&self, labels: &[&str], what: &str) -> Result<()> {
        let locale = self
            .adb(&["shell", "getprop", "persist.sys.locale"])
            .await?;
        eprintln!("{} runs locale {}", self.serial, locale.trim());
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            // A dump can crash while the screen changes under it, so a failed
            // one waits for the next look.
            match self.dialog_button_bounds(labels).await {
                Ok(Some((left, top, right, bottom))) => {
                    self.adb(&[
                        "shell",
                        "input",
                        "tap",
                        &left.midpoint(right).to_string(),
                        &top.midpoint(bottom).to_string(),
                    ])
                    .await?;
                    return Ok(());
                }
                Ok(None) => {}
                Err(err) => eprintln!("{} gave no UI dump, looking again: {err:#}", self.serial),
            }
            if Instant::now() >= deadline {
                bail!(
                    "{what} never showed on {} (locale {})",
                    self.serial,
                    locale.trim()
                );
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    /// The bounds of a system dialog's button, or none while the dialog is
    /// not up, matched by the localized texts `labels` name.
    async fn dialog_button_bounds(&self, labels: &[&str]) -> Result<Option<(i32, i32, i32, i32)>> {
        self.adb(&["shell", "uiautomator", "dump", "/sdcard/connetto-ui.xml"])
            .await?;
        let xml = self
            .adb(&["shell", "cat", "/sdcard/connetto-ui.xml"])
            .await?;
        for node in xml.split("<node ") {
            let Some(text) = attribute(node, "text") else {
                continue;
            };
            if !labels.contains(&text.as_str()) {
                continue;
            }
            let Some(clickable) = attribute(node, "clickable") else {
                continue;
            };
            if clickable != "true" {
                continue;
            }
            let bounds = attribute(node, "bounds")
                .and_then(|bounds| parse_bounds(&bounds))
                .ok_or_else(|| anyhow!("the dialog button {text:?} has no bounds"))?;
            return Ok(Some(bounds));
        }
        Ok(None)
    }

    async fn launch(&self) -> Result<()> {
        self.adb(&[
            "shell",
            "am",
            "start",
            "-W",
            "-n",
            &format!("{PACKAGE}/{ACTIVITY}"),
        ])
        .await
        .map(drop)
    }

    /// Whether the keyguard covers the screen.
    async fn keyguard_showing(&self) -> Result<bool> {
        let window = self.adb(&["shell", "dumpsys", "window"]).await?;
        Ok(window
            .lines()
            .any(|line| line.trim() == "isKeyguardShowing=true"))
    }

    /// Whether the platform's biometric or credential prompt holds the
    /// screen, which System UI draws in a window of its own.
    async fn unlock_prompt_shown(&self) -> Result<bool> {
        let windows = self.adb(&["shell", "dumpsys", "window", "windows"]).await?;
        // AOSP's System UI titles the window `BiometricPrompt`, and Samsung
        // draws it from its own biometrics package. Samsung's keyguard toast
        // window stays listed at all times, so a looser match never clears.
        Ok(windows
            .lines()
            .filter(|line| line.contains("Window{"))
            .any(|line| {
                line.contains("BiometricPrompt")
                    || line.contains("com.samsung.android.biometrics.app.setting")
            }))
    }

    async fn screenshot(&self, dir: &Path, name: &str) -> Result<()> {
        let output = Command::new(&self.program)
            .args(["-s", &self.serial, "exec-out", "screencap", "-p"])
            .output()
            .await
            .context("starting adb")?;
        tokio::fs::write(dir.join(format!("{name}.png")), output.stdout)
            .await
            .context("writing a screenshot")
    }

    /// Forward a free host port to an abstract socket on the device.
    async fn forward(&self, socket: &str) -> Result<u16> {
        let port = self
            .adb(&["forward", "tcp:0", &format!("localabstract:{socket}")])
            .await?;
        port.trim()
            .parse()
            .with_context(|| format!("adb forwarded to {port:?}"))
    }

    /// A `DevTools` session on the login tab the demo opened on `issuer`, never
    /// one an earlier call returned, tapping past the browser's first-run
    /// screens while it appears. The forward lives until [`main`] removes every
    /// forward.
    async fn login_tab(&self, issuer: &str) -> Result<PageSession> {
        let prefix = format!("{issuer}/authorize?");
        let port = self.forward("chrome_devtools_remote").await?;
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let tabs = list_pages(port).await.unwrap_or_default();
            let fresh = {
                let spent = self.spent_tabs.lock().expect("spent tabs");
                tabs.iter().find_map(|tab| {
                    let id = tab["id"].as_str()?;
                    let url = tab["url"].as_str()?;
                    let ws = tab["webSocketDebuggerUrl"].as_str()?;
                    (url.starts_with(&prefix) && !spent.iter().any(|seen| seen == id))
                        .then(|| (id.to_owned(), ws.to_owned()))
                })
            };
            if let Some((id, ws)) = fresh {
                self.spent_tabs.lock().expect("spent tabs").push(id);
                return PageSession::devtools(&ws).await;
            }
            // uiautomator's dump is killed now and then while the system is busy, and the
            // next round retries it until the deadline.
            if let Err(err) = self.tap_interstitial().await {
                eprintln!("looking for the browser's first-run screens: {err:#}");
            }
            if Instant::now() >= deadline {
                bail!("no browser tab opened {prefix}");
            }
            sleep(Duration::from_secs(1)).await;
        }
    }

    async fn tap_interstitial(&self) -> Result<()> {
        self.adb(&["shell", "uiautomator", "dump", "/sdcard/connetto-ui.xml"])
            .await?;
        let xml = self
            .adb(&["shell", "cat", "/sdcard/connetto-ui.xml"])
            .await?;
        let Some((left, top, right, bottom)) = xml.split("<node ").find_map(|node| {
            let id = attribute(node, "resource-id")?;
            INTERSTITIALS
                .contains(&id.as_str())
                .then(|| parse_bounds(&attribute(node, "bounds")?))?
        }) else {
            return Ok(());
        };
        self.adb(&[
            "shell",
            "input",
            "tap",
            &left.midpoint(right).to_string(),
            &top.midpoint(bottom).to_string(),
        ])
        .await
        .map(drop)
    }

    /// A `DevTools` session on the demo's `WebView`, over a forward that lives
    /// until [`main`] removes every forward.
    async fn app(&self) -> Result<PageSession> {
        let pid = self.adb(&["shell", "pidof", PACKAGE]).await?;
        let port = self
            .forward(&format!("webview_devtools_remote_{}", pid.trim()))
            .await?;
        let targets = list_pages(port).await?;
        let ws = targets
            .iter()
            .find(|target| target["type"] == "page")
            .and_then(|target| target["webSocketDebuggerUrl"].as_str())
            .ok_or_else(|| anyhow!("the demo's WebView has no DevTools page"))?;
        PageSession::devtools(ws).await
    }
}

fn attribute(element: &str, name: &str) -> Option<String> {
    let start = element.find(&format!(" {name}=\""))? + name.len() + 3;
    let len = element[start..].find('"')?;
    Some(
        element[start..start + len]
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&#39;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&"),
    )
}

/// `[left,top][right,bottom]`.
fn parse_bounds(text: &str) -> Option<(i32, i32, i32, i32)> {
    let numbers = text
        .split(|ch: char| !ch.is_ascii_digit() && ch != '-')
        .filter(|part| !part.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<i32>, _>>()
        .ok()?;
    match numbers.as_slice() {
        [left, top, right, bottom] => Some((*left, *top, *right, *bottom)),
        _ => None,
    }
}

/// The offer's lines off a page's text, all three present and the port a
/// number, or none while they are not.
fn parse_offer_lines(page: &str) -> Option<HotspotOfferLines> {
    let line = |label: &str| -> Option<String> {
        page.lines()
            .find_map(|line| line.strip_prefix(label).map(|rest| rest.trim().to_owned()))
    };
    let ssid = line("hotspot ssid: ")?;
    let passphrase = line("hotspot passphrase: ")?;
    let port = line("hotspot port: ")?;
    if port == "none" {
        return None;
    }
    Some(HotspotOfferLines {
        ssid,
        passphrase,
        port: port.parse::<u16>().ok()?,
        payload: line("hotspot payload: "),
    })
}

/// The ssid a `dumpsys wifi` names as the connected one, absent while it
/// names `<unknown>` or no line at all.
fn parse_current_ssid(dump: &str) -> Option<String> {
    dump.lines().find_map(|line| {
        let ssid = line
            .strip_prefix("mWifiInfo SSID: \"")?
            .split('"')
            .next()?
            .to_owned();
        (ssid != "<unknown>" && !ssid.is_empty()).then_some(ssid)
    })
}

/// The id of the saved network with `ssid` in a `cmd wifi list-networks`
/// listing, the ssid's spaces making the first and last fields the only
/// safe cuts.
fn saved_network_id(listing: &str, ssid: &str) -> Option<String> {
    listing.lines().skip(1).find_map(|line| {
        let (id, rest) = line.split_once(char::is_whitespace)?;
        let (name, _security) = rest.trim_start().rsplit_once(char::is_whitespace)?;
        (name.trim() == ssid).then(|| id.to_owned())
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_summary_names_every_step_and_why_a_join_failed() {
        use std::time::Duration;
        let reports = [
            super::JoinReport {
                join: super::JoinBy::Form,
                took: Duration::from_secs(201),
                outcome: Ok(()),
            },
            super::JoinReport {
                join: super::JoinBy::Beacon,
                took: Duration::from_secs(95),
                outcome: Err(anyhow::anyhow!(
                    "the second phone never saw the first phone's beacon"
                )),
            },
        ];
        assert_eq!(
            super::summary("c0626b2", &(Duration::from_secs(180), Ok(())), Ok(&reports)),
            "commit: c0626b2\n\
             single-phone proof: passed in 180s\n\
             form join: passed in 201s\n\
             beacon join: failed in 95s: the second phone never saw the first phone's beacon\n"
        );
        let setup = anyhow::anyhow!("adb install exited with 1");
        assert_eq!(
            super::summary("c0626b2", &(Duration::from_secs(180), Ok(())), Err(&setup)),
            "commit: c0626b2\n\
             single-phone proof: passed in 180s\n\
             joins: not run, the setup failed: adb install exited with 1\n"
        );
    }

    /// The demo's set and service as an A35 on Android 15 dumps them.
    const BEACON_DUMP: &str = "    dev.connetto.dioxusdemo
     Advertising ID                                     : 3
      1:
        \u{2514}Start time                                     : 10-09 03:05:30
      \u{2514}Advertising:
        \u{2514}Legacy                                         : true
        \u{2514}Anonymous                                      : false
        \u{2514}Connectable                                    : true
        \u{2514}Scannable                                      : true
        \u{2514}Advertise Data:
          \u{2514}Include Device Name                          : false
          \u{2514}Service Data(UUID, length of data)           : 
            [a9952637-xxxx-xxxx-xxxx-xxxxxxxxxxxx, 9]


  8: [151] Service a9952637-85d5-4071-9ed8-c28bd7ba670c, started true
  8: [153]   Characteristic bdd3f20f-a8d0-4003-82db-4f941b4c375b
  8: [155]   Characteristic 62ba3a58-c377-47f5-93e1-cd6790bc2e53
  8: [156]     Descriptor 00002902-0000-1000-8000-00805f9b34fb
";

    #[test]
    fn the_beacon_dump_check_takes_the_demo_set_and_refuses_its_variants() {
        assert!(super::check_beacon_dump(BEACON_DUMP).is_ok());
        for (from, to) in [
            (
                "Connectable                                    : true",
                "Connectable                                    : false",
            ),
            (
                "Legacy                                         : true",
                "Legacy                                         : false",
            ),
            ("xxxxxxxxxxxx, 9]", "xxxxxxxxxxxx, 27]"),
            ("started true", "started false"),
            ("Characteristic 62ba3a58", "Characteristic 00000000"),
            ("    dev.connetto.dioxusdemo", "    com.example.other"),
        ] {
            let broken = BEACON_DUMP.replace(from, to);
            assert!(
                super::check_beacon_dump(&broken).is_err(),
                "accepted with {to}"
            );
        }
    }

    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::{Device, parse_current_ssid, parse_offer_lines, saved_network_id};

    /// A stand-in `adb` that runs `body` with `$state` naming a scratch directory.
    fn fake_adb(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("adb");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nstate={}\necho \"$*\" >>\"$state/calls\"\n{body}\n",
                dir.display()
            ),
        )
        .expect("write the fake adb");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    fn calls(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("calls")).unwrap_or_default()
    }

    #[tokio::test]
    async fn a_device_that_drops_offline_once_is_reconnected_and_the_command_retried() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adb = fake_adb(
            dir.path(),
            r#"case "$*" in
  "reconnect offline") exit 0 ;;
  *get-state*) echo device; exit 0 ;;
esac
if [ ! -e "$state/dropped" ]; then touch "$state/dropped"; echo "adb: device offline" >&2; exit 1; fi
echo ok"#,
        );
        let device = Device::with_adb("emulator-5554".to_owned(), adb, Duration::from_secs(5));
        let out = device
            .adb(&["shell", "true"])
            .await
            .expect("the retry succeeds");
        assert_eq!(out, "ok\n");
        let calls = calls(dir.path());
        assert!(calls.contains("reconnect offline"), "{calls}");
        assert_eq!(calls.matches("shell true").count(), 2, "{calls}");
    }

    #[tokio::test]
    async fn a_device_that_stays_offline_fails_within_the_bound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adb = fake_adb(
            dir.path(),
            r#"case "$*" in
  "reconnect offline") exit 0 ;;
  *get-state*) echo offline; exit 0 ;;
esac
echo "adb: device offline" >&2; exit 1"#,
        );
        let device = Device::with_adb("emulator-5554".to_owned(), adb, Duration::from_millis(600));
        let started = std::time::Instant::now();
        let err = device
            .adb(&["shell", "true"])
            .await
            .expect_err("still offline");
        assert!(started.elapsed() < Duration::from_secs(5), "bounded wait");
        assert!(format!("{err:#}").contains("offline"), "{err:#}");
    }

    #[tokio::test]
    async fn any_other_adb_failure_is_not_retried() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adb = fake_adb(dir.path(), r#"echo "error: closed" >&2; exit 1"#);
        let device = Device::with_adb("emulator-5554".to_owned(), adb, Duration::from_secs(5));
        device.adb(&["shell", "true"]).await.expect_err("fails");
        let calls = calls(dir.path());
        assert!(!calls.contains("reconnect"), "{calls}");
        assert_eq!(calls.matches("shell true").count(), 1, "{calls}");
    }

    #[test]
    fn the_offer_lines_are_read_off_the_page() {
        let page = "\npeer: listening on 41234\n\
            hotspot ssid: My Hotspot\n\
            hotspot passphrase: s3cr3t pass\n\
            hotspot port: 41234\n\
            hotspot payload: WIFI:T:WPA;S:My Hotspot;P:s3cr3t pass;X:41234;;\n\
            hotspot: hosting\n";
        let offer = parse_offer_lines(page).expect("all three lines are there");
        assert_eq!(offer.ssid, "My Hotspot");
        assert_eq!(offer.passphrase, "s3cr3t pass");
        assert_eq!(offer.port, 41234);
        assert_eq!(
            offer.payload.as_deref(),
            Some("WIFI:T:WPA;S:My Hotspot;P:s3cr3t pass;X:41234;;")
        );
        assert!(parse_offer_lines("hotspot ssid: only\n").is_none());
        assert!(parse_offer_lines("hotspot port: none\n").is_none());
    }

    #[test]
    fn the_connected_ssid_is_read_and_unknown_is_none() {
        let dump = "mWifiInfo SSID: \"eduroam\", BSSID: aa:bb:cc:dd:ee:ff\n";
        assert_eq!(parse_current_ssid(dump), Some("eduroam".to_owned()));
        let unknown = "mWifiInfo SSID: \"<unknown>\", BSSID: <none>\n";
        assert_eq!(parse_current_ssid(unknown), None);
        assert_eq!(parse_current_ssid("no wifi line\n"), None);
    }

    #[test]
    fn the_saved_network_id_is_found_by_its_ssid_with_spaces() {
        let listing = "Network Id      SSID                         Security type\n\
            0            Agy Centre Open                  open\n\
            1            AmadeusWiFree                    wpa2-psk\n";
        assert_eq!(
            saved_network_id(listing, "Agy Centre Open"),
            Some("0".to_owned())
        );
        assert_eq!(saved_network_id(listing, "Absent"), None);
    }
}
