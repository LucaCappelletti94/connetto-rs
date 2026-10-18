//! Deploys `examples/dioxus-desktop-demo`, or with `--app tauri`
//! `examples/tauri-leptos-demo`, to an attached Android device or emulator
//! and walks R88's proof on it, which is sign in, sync, write offline and
//! upload on reconnect.
//!
//! It runs as the command of `connetto-demo-stack`, which provides the stack
//! and the environment naming it.
//!
//! ```text
//! cargo build -p connetto-test-harness --bin connetto-android-proof
//! cargo run -p connetto-test-harness --bin connetto-demo-stack -- \
//!   target/debug/connetto-android-proof [--serial SERIAL] [--app dioxus|tauri] [--apk PATH] \
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
//! Without `--apk` it builds the APK for the device's ABI, with `dx` or with
//! `cargo tauri android build`. The demo
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
//! With `--peer-serial` a second attached phone joins the proof, on the dioxus
//! demo, whose panel holds the peer controls. The main
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

//!
//! With `--linux-peer` and `--every-join`, the second device is pippo
//! itself. The run drives a native client in a child process, signed in as
//! its own account and durable under the evidence directory, beside the
//! phone, and makes every join both ways, linux hosting and the phone
//! joining through the beacon, the payload and the form, then the phone
//! hosting and linux joining the same three ways (R76 slice 9b). The phone
//! stays off its network for the walk, since the home LAN would link the
//! two by discovery, and pippo's station holds its own network throughout,
//! the joins taking their link through the hotspots alone. The run ends
//! with the phone back on its usual network and both Bluetooth adapters
//! off.
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use connetto_client::BluetoothState;
use connetto_test_harness::demo::{order_count, wait_for_count};
use connetto_test_harness::inspector::{PageSession, list_pages};
use connetto_test_harness::linux_leg::{LegClient, run_leg};
use connetto_test_harness::linux_proof::{
    ADAPTER_OFF_BOUND, LegOffer, in_hotspot_subnet, parse_station_name, ss_remote_address,
};
use connetto_test_harness::peer_devices::{
    LINK_END_BOUND, own_identity, read_hotspot_offer, wait_link_ends,
};
use connetto_test_harness::peer_proof::{JoinReport, commit, summary};
use connetto_test_harness::stack::{
    demo_has_device_identity, demo_mobile_features, now_millis, repo_path,
};
use tokio::process::Command;
use tokio::time::{Instant, sleep};

const BROWSER: &str = "com.android.chrome";
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
const GATE_TRACE_TARGETS: [&str; 3] = [
    "\"target\":\"connetto_client::away\"",
    "\"target\":\"connetto_dioxus::away\"",
    "\"target\":\"connetto_tauri_demo::away\"",
];

/// The demo the proof deploys, `--app dioxus` (the default) or `--app tauri`
/// (`examples/tauri-leptos-demo`).
#[derive(Clone, Copy, Default)]
enum DemoApp {
    #[default]
    Dioxus,
    Tauri,
}

impl DemoApp {
    fn parse(name: &str) -> Result<Self> {
        match name {
            "dioxus" => Ok(Self::Dioxus),
            "tauri" => Ok(Self::Tauri),
            other => bail!("unknown app {other}, expected dioxus or tauri"),
        }
    }
}

/// The demo this run deploys, set once from the command line.
static APP: std::sync::OnceLock<DemoApp> = std::sync::OnceLock::new();

fn demo_app() -> DemoApp {
    APP.get().copied().unwrap_or_default()
}

/// The demo's Android package.
fn package() -> &'static str {
    match demo_app() {
        DemoApp::Dioxus => "dev.connetto.dioxusdemo",
        DemoApp::Tauri => "dev.connetto.tauridemo",
    }
}

/// The demo's launch activity.
fn activity() -> &'static str {
    match demo_app() {
        DemoApp::Dioxus => "dev.dioxus.main.MainActivity",
        DemoApp::Tauri => "dev.connetto.tauridemo.MainActivity",
    }
}

/// The second phone's account in the peer proof, so each page's `linked:`
/// line names the other phone unambiguously.
const PEER_USER: &str = "bob";
/// The localized texts of the system's network-approval dialog button, for
/// the locales the proof phones run, which the driver taps in place of the
/// user (R76 decision 16).
const CONNECT_BUTTONS: [&str; 3] = ["Connect", "Connetti", "Verbinden"];
/// The unlock prompt's switch from the fingerprint sensor to the PIN pad in
/// the runner's locales, which a run given the PIN taps on a phone with a
/// fingerprint enrolled.
const PIN_FALLBACK_BUTTONS: [&str; 3] = ["Use PIN", "Usa PIN", "PIN verwenden"];
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
/// How long pippo's station gets to be back on its network after a join.
const STATION_BACK_BOUND: Duration = Duration::from_secs(60);
/// The argument lines `--help` shows.
const USAGE: &str = "\
usage: connetto-android-proof [--serial SERIAL] [--apk PATH] [--unlock-pin PIN] \
[--peer-serial SECOND] [--linux-peer] [--bluetooth] [--payload] [--every-join]

--serial         the phone the proof runs on
--apk            an APK to deploy instead of building one
--unlock-pin     the PIN the driver types into the unlock prompt
--peer-serial    a second attached phone, which joins the first phone's hotspot
--linux-peer     pippo takes the second device's place in the six-join walk
--bluetooth      the host-side beacon proof, and the beacon join with --peer-serial
--payload        the join through the host's WIFI: payload, with --peer-serial
--every-join     every join in one run, with a summary
";

#[tokio::main]
async fn main() -> Result<()> {
    // The proof starts itself again as its Linux leg, a child serving the
    // command stream, which takes none of the runner's arguments.
    if std::env::args().nth(1).as_deref() == Some("--linux-leg") {
        return run_leg().await;
    }
    let stack = Stack::from_env()?;
    let Arguments {
        serial,
        apk,
        unlock_pin,
        peer_serial,
        linux_peer,
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
            match (linux_peer, bluetooth, peer_serial, outcome) {
                (true, _, _, Ok(())) => linux_joins_with_summary(&device, &evidence, &proved).await,
                (false, true, None, Ok(())) => bluetooth_proof(&device, &evidence).await,
                (false, _, Some(serial), Ok(())) => {
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
                (_, _, _, outcome) => outcome,
            }
        }
        Err(err) => Err(err),
    };
    let cleanup = finish(
        &device,
        &evidence,
        previous.as_deref(),
        stay_on.as_deref(),
        error_dialogs.as_deref(),
        &outcome,
    )
    .await;
    outcome.and(cleanup)
}

/// The run's cleanup: the device log, the failure's screenshot, the
/// forwards and reverses, the demo's stop, and the device's settings back.
///
/// # Errors
///
/// When the log will not be written or a setting will not come back.
async fn finish(
    device: &Device,
    evidence: &Path,
    previous: Option<&str>,
    stay_on: Option<&str>,
    error_dialogs: Option<&str>,
    outcome: &Result<()>,
) -> Result<()> {
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
    if let Err(err) = outcome {
        let _ = device.screenshot(evidence, "failure").await;
        eprintln!("proof failed: {err:#}");
    }
    let _ = device.adb(&["forward", "--remove-all"]).await;
    let _ = device.adb(&["reverse", "--remove-all"]).await;
    let _ = device.adb(&["shell", "am", "force-stop", package()]).await;
    let restored = match previous {
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
    let screen = device.restore_global_setting(STAY_ON, stay_on).await;
    let dialogs = device
        .restore_global_setting(HIDE_ERROR_DIALOGS, error_dialogs)
        .await;
    restored.and(screen).and(dialogs)
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
    device.adb(&["shell", "pm", "clear", package()]).await?;
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
    // dioxus-desktop 0.7.10 aborts on any screen rebuild, so only the Tauri demo can show one.
    if let DemoApp::Tauri = demo_app() {
        rebuild_the_screen(device).await?;
    }
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
    let killed = device.adb(&["shell", "pidof", package()]).await?;
    let deadline = Instant::now() + Duration::from_secs(10);
    // `am kill` spares a visible process, and the app stays visible briefly after the tab opens.
    loop {
        device.adb(&["shell", "am", "kill", package()]).await?;
        sleep(Duration::from_millis(250)).await;
        if device.adb(&["shell", "pidof", package()]).await.is_err() {
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

/// The system setting whose change rebuilds the demo's screen, which the
/// demo's manifest leaves out of the configuration changes it handles itself.
const FONT_SCALE: &str = "font_scale";
/// How long Android may take to rebuild the screen after the text size changes.
const REBUILD_WITHIN: Duration = Duration::from_secs(30);

/// Change the text size and change it back. Android rebuilds the demo's screen
/// inside the running process each time, and the re-check after time away
/// that follows then has to prompt on the rebuilt screen. The step fails when
/// no rebuild shows in the events buffer, so it never passes unexercised.
async fn rebuild_the_screen(device: &Device) -> Result<()> {
    step("rebuild the screen");
    let pid = device.adb(&["shell", "pidof", package()]).await?;
    let pid = pid.trim();
    let original = device.system_setting(FONT_SCALE).await?;
    let larger = if original.as_deref() == Some("1.15") {
        "1.3"
    } else {
        "1.15"
    };
    device.adb(&["logcat", "-b", "events", "-c"]).await?;
    device
        .adb(&["shell", "settings", "put", "system", FONT_SCALE, larger])
        .await?;
    let rebuilt = device.wait_for_rebuild(pid).await;
    // The device's text size comes back even when the rebuild was not seen.
    let cleared = device.adb(&["logcat", "-b", "events", "-c"]).await;
    let restored = device
        .restore_system_setting(FONT_SCALE, original.as_deref())
        .await;
    rebuilt?;
    cleared?;
    restored?;
    device.wait_for_rebuild(pid).await
}

/// Whether `events`, the events buffer, shows `activity` destroyed and then
/// created again in process `pid`.
fn rebuilt_in(events: &str, pid: &str, activity: &str) -> bool {
    let in_process = |line: &&str| {
        line.split_whitespace().nth(2) == Some(pid) && line.contains(&format!(",{activity},"))
    };
    let mut lines = events.lines().filter(in_process);
    lines.any(|line| line.contains("wm_on_destroy_called:"))
        && lines.any(|line| line.contains("wm_on_create_called:"))
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
    let PeerOutcome { joins, teardown } = peer_proof(
        host,
        joiner,
        run.apk,
        run.stack,
        run.evidence,
        run.unlock,
        joins,
    )
    .await;
    let summary = summary(
        &commit().await,
        proved,
        joins.as_deref(),
        teardown.as_ref().copied(),
    );
    eprintln!("{summary}");
    tokio::fs::write(run.evidence.join("summary.txt"), &summary)
        .await
        .context("writing the summary")?;
    let failed: Vec<&str> = joins?
        .iter()
        .filter(|report| report.outcome.is_err())
        .map(|report| report.name)
        .collect();
    if !failed.is_empty() {
        bail!("the {} join failed", failed.join(", "));
    }
    teardown.context("restoring the second phone after the joins")
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

/// What the peer proof ran, apart from the second phone's restore after it,
/// so a failed restore never hides the joins that ran.
struct PeerOutcome {
    /// Each join's report, or why none ran.
    joins: Result<Vec<JoinReport>>,
    /// The second phone's log and its restored settings.
    teardown: Result<()>,
}

/// Which side hosts in one join of the linux run.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// The phone hosts and linux joins.
    PhoneHosts,
    /// Linux hosts and the phone joins.
    LinuxHosts,
}

/// The six joins the linux run makes, linux hosting first, then the phone,
/// each through the beacon, the payload and the form.
const LINUX_JOINS: [(Direction, JoinBy); 6] = [
    (Direction::LinuxHosts, JoinBy::Beacon),
    (Direction::LinuxHosts, JoinBy::Payload),
    (Direction::LinuxHosts, JoinBy::Form),
    (Direction::PhoneHosts, JoinBy::Beacon),
    (Direction::PhoneHosts, JoinBy::Payload),
    (Direction::PhoneHosts, JoinBy::Form),
];

/// A join's name in the summary and the evidence, its side named.
const fn join_name(direction: Direction, join: JoinBy) -> &'static str {
    match (direction, join) {
        (Direction::PhoneHosts, JoinBy::Beacon) => "beacon (phone hosts)",
        (Direction::PhoneHosts, JoinBy::Payload) => "payload (phone hosts)",
        (Direction::PhoneHosts, JoinBy::Form) => "form (phone hosts)",
        (Direction::LinuxHosts, JoinBy::Beacon) => "beacon (linux hosts)",
        (Direction::LinuxHosts, JoinBy::Payload) => "payload (linux hosts)",
        (Direction::LinuxHosts, JoinBy::Form) => "form (linux hosts)",
    }
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
) -> PeerOutcome {
    let unrun = |err: anyhow::Error| PeerOutcome {
        joins: Err(err),
        teardown: Ok(()),
    };
    if !demo_has_device_identity() {
        return unrun(anyhow!(
            "the peer proof needs a demo build with its device identity"
        ));
    }
    step("prepare the peer phone");
    let (stay_on, previous_role) = match prepare_joiner(joiner, &unlock).await {
        Ok(prepared) => prepared,
        Err(err) => return unrun(err),
    };
    // The joiner's usual network, read after the wireless reconnect, which
    // the cleanup must bring it back to. A failed read still runs the
    // cleanup below before it reports.
    let result = match joiner.current_ssid().await {
        Ok(usual_ssid) => {
            run_peer_proof(
                host,
                joiner,
                apk,
                stack,
                evidence,
                &unlock,
                usual_ssid.as_ref(),
                joins,
            )
            .await
        }
        Err(err) => Err(err),
    };

    // The joiner's log for the record, and its state, which the run leaves
    // as it found it.
    let log = joiner.adb(&["logcat", "-d"]).await.unwrap_or_default();
    let wrote_log = tokio::fs::write(evidence.join("peer-logcat.txt"), log)
        .await
        .context("writing the peer phone's log");
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
    let _ = joiner.adb(&["shell", "am", "force-stop", package()]).await;
    PeerOutcome {
        joins: result,
        teardown: wrote_log.and(restore_role).and(restore_stay),
    }
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
    joiner.adb(&["shell", "pm", "clear", package()]).await?;
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
                .adb(&["shell", "pm", "grant", package(), permission])
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
    // The join whose cleanup failed, after which no route starts, since
    // the phones no longer stand where a join must begin.
    let mut unclean: Option<JoinBy> = None;
    for &join in joins {
        if let Some(previous) = unclean {
            reports.push(JoinReport {
                name: join.name(),
                took: None,
                outcome: Err(anyhow!(
                    "the {} join's cleanup failed, so the phones were not at rest",
                    previous.name()
                )),
            });
            continue;
        }
        let started = Instant::now();
        let Joined { walked, cleanup } = one_join(
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
        if cleanup.is_err() {
            unclean = Some(join);
        }
        let outcome = walked.and(cleanup);
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
            name: join.name(),
            took: Some(started.elapsed()),
            outcome,
        });
    }
    Ok(reports)
}

/// One join's walk and the cleanup after it, apart, since a failed cleanup
/// stops the routes after it.
struct Joined {
    /// The join from the hosted hotspot to the link's end.
    walked: Result<()>,
    /// The phones brought back to rest.
    cleanup: Result<()>,
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
) -> Joined {
    // The hotspot's ssid, once the host shows it, which the joiner's network
    // cleanup forgets.
    let mut offer_ssid = None;
    let walked = async {
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
        // An A35 refuses to start an access point while its own station sits
        // on a 5 GHz channel, measured on eduroam, so the host leaves its
        // network, as a host in the field has none. Its server path stays on
        // USB.
        host.adb(&["shell", "svc", "wifi", "disable"]).await?;
        sleep(Duration::from_secs(5)).await;
        host_and_link(
            host,
            joiner,
            app,
            peer_app,
            evidence,
            identities,
            join,
            &mut offer_ssid,
        )
        .await
    }
    .await;
    // Back to rest whatever happened, so the next join starts clean: the
    // pages' own leave and stop, the host's Wi-Fi, Bluetooth off, and the
    // joiner on its usual network, the first failure kept.
    if walked.is_err() {
        let _ = peer_app.click("Leave the hotspot").await;
        let _ = app.click("Stop the hotspot").await;
        // An abandoned join leaves the system's "Couldn't connect" notice up,
        // and the next request reuses that dialog in place of its approval, so
        // the cleanup closes it with the Settings process that shows it.
        let _ = joiner
            .adb(&["shell", "am", "force-stop", "com.android.settings"])
            .await;
    }
    let restored = host
        .adb(&["shell", "svc", "wifi", "enable"])
        .await
        .map(drop);
    let mut bluetooth = Ok(());
    for phone in [host, joiner] {
        bluetooth = bluetooth.and(bluetooth_off(phone).await);
    }
    let networks = match &offer_ssid {
        Some(ssid) => restore_joiner_networks(host, joiner, ssid, usual_ssid).await,
        None => Ok(()),
    };
    let cleanup = restored.and(bluetooth).and(networks);
    let cleanup = match cleanup {
        Ok(()) => {
            joiner
                .screenshot(evidence, &format!("{}-peer-clean", join.name()))
                .await
        }
        Err(err) => Err(err),
    };
    Joined { walked, cleanup }
}

/// Host on the first phone, join from the second, link, and end the link,
/// recording the hotspot's ssid in `offer_ssid` as soon as it shows, so the
/// cleanup forgets it even when a later step fails.
#[expect(
    clippy::too_many_arguments,
    reason = "the two phones, their pages, the evidence, both identities, the join and the ssid it records are each the step's own"
)]
async fn host_and_link(
    host: &Device,
    joiner: &Device,
    app: &mut PageSession,
    peer_app: &mut PageSession,
    evidence: &Path,
    (host_identity, joiner_identity): (&str, &str),
    join_by: JoinBy,
    offer_ssid: &mut Option<String>,
) -> Result<()> {
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
    *offer_ssid = Some(offer.ssid.clone());
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
    Ok(())
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
        host.adb(&["shell", "pm", "grant", package(), permission])
            .await?;
    }
    host.adb(&[
        "shell",
        "pm",
        "grant",
        package(),
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
        .split_once(&format!("    {}\n", package()))
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

/// The linux-peer run, the six joins with their summary (R76 slice 9b).
///
/// # Errors
///
/// As [`joins_with_summary`].
async fn linux_joins_with_summary(
    phone: &Device,
    evidence: &Path,
    proved: &(Duration, Result<(), String>),
) -> Result<()> {
    let PeerOutcome { joins, teardown } = match linux_peer_proof(phone, evidence).await {
        Ok(outcome) => outcome,
        Err(err) => PeerOutcome {
            joins: Err(err),
            teardown: Ok(()),
        },
    };
    let summary = summary(
        &commit().await,
        proved,
        joins.as_deref(),
        teardown.as_ref().copied(),
    );
    eprintln!("{summary}");
    tokio::fs::write(evidence.join("summary.txt"), &summary)
        .await
        .context("writing the summary")?;
    let failed: Vec<&str> = joins?
        .iter()
        .filter(|report| report.outcome.is_err())
        .map(|report| report.name)
        .collect();
    if !failed.is_empty() {
        bail!("the {} join failed", failed.join(", "));
    }
    teardown.context("bringing the machines back to rest after the joins")
}

/// The linux-peer proof: the phone's single-phone proof, then pippo in the
/// second device's place, a native client driven in a child process. The
/// outcome holds the walk's reports and the machines' return to rest apart.
///
/// # Errors
///
/// When the phone cannot be readied before its network leaves.
async fn linux_peer_proof(phone: &Device, evidence: &Path) -> Result<PeerOutcome> {
    if !demo_has_device_identity() {
        bail!("the linux peer proof needs a demo build with its device identity");
    }
    step("prepare the linux leg");
    for permission in BT_PERMISSIONS
        .iter()
        .copied()
        .chain(["android.permission.NEARBY_WIFI_DEVICES"])
    {
        phone
            .adb(&["shell", "pm", "grant", package(), permission])
            .await?;
    }
    // The phone's usual network, read while it still holds one, which the
    // run's cleanup brings it back to, and pippo's, which the joins must
    // not keep down.
    let phone_usual = phone.current_ssid().await?;
    let pippo_usual = linux_station()
        .await?
        .context("pippo's station names no connection, the run cannot restore it")?;
    eprintln!(
        "the phone holds {phone_usual:?} and pippo holds {pippo_usual} until the run restores them"
    );
    // The phone leaves the home LAN for the whole section, so the LAN
    // never links the two by discovery. Its demo reaches the server over
    // adb reverse.
    step("take the phone off its network");
    phone.adb(&["shell", "svc", "wifi", "disable"]).await?;
    sleep(Duration::from_secs(5)).await;
    let steps = RealSteps {
        phone,
        phone_usual: phone_usual.clone(),
        pippo_usual: pippo_usual.clone(),
    };
    Ok(linux_section(&steps, evidence).await)
}

/// The linux section's resource steps, the phone and the leg behind them
/// for the setup-failure unit test.
trait LinuxSteps: Send {
    /// The leg's handle, the real client or the test's stand-in.
    type Leg: Send;
    /// Stand the leg.
    fn spawn_leg(&self, evidence: &Path) -> impl Future<Output = Result<Self::Leg>> + Send;
    /// Wait for the leg's ready line.
    fn ready(&self, leg: &Self::Leg) -> impl Future<Output = Result<(String, u16)>> + Send;
    /// The walk itself, the phone's identity read and the joins in turn.
    fn walk(
        &self,
        leg: &Self::Leg,
        linux_identity: &str,
        evidence: &Path,
    ) -> impl Future<Output = Result<Vec<JoinReport>>> + Send;
    /// Write the leg's log to the evidence.
    fn write_leg_log(
        &self,
        leg: &Self::Leg,
        evidence: &Path,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Power the leg's adapter off.
    fn adapter_off(&self, leg: &Self::Leg) -> impl Future<Output = Result<()>> + Send;
    /// Close the leg.
    fn close_leg(&self, leg: &Self::Leg) -> impl Future<Output = Result<()>> + Send;
    /// Bring the phone back to its usual network.
    fn restore_network(&self) -> impl Future<Output = Result<()>> + Send;
    /// Turn the phone's Bluetooth off.
    fn bluetooth_off(&self) -> impl Future<Output = Result<()>> + Send;
}

/// The steps over the real phone and leg.
struct RealSteps<'a> {
    phone: &'a Device,
    phone_usual: Option<String>,
    pippo_usual: String,
}

impl LinuxSteps for RealSteps<'_> {
    type Leg = LegClient;

    async fn spawn_leg(&self, evidence: &Path) -> Result<LegClient> {
        LegClient::spawn(evidence).await
    }

    async fn ready(&self, leg: &LegClient) -> Result<(String, u16)> {
        leg.wait_ready().await
    }

    async fn walk(
        &self,
        leg: &LegClient,
        linux_identity: &str,
        evidence: &Path,
    ) -> Result<Vec<JoinReport>> {
        let mut app = self.phone.app().await?;
        app.wait_for_text("device: certified until", Duration::from_secs(60))
            .await?;
        let phone_identity = own_identity(&mut app).await?;
        run_linux_joins(
            self.phone,
            &mut app,
            leg,
            &phone_identity,
            linux_identity,
            &self.pippo_usual,
            evidence,
        )
        .await
    }

    async fn write_leg_log(&self, leg: &LegClient, evidence: &Path) -> Result<()> {
        let leg_log = leg.take_log();
        tokio::fs::write(evidence.join("linux-leg.log"), leg_log)
            .await
            .context("writing the linux leg's log")
    }

    async fn adapter_off(&self, leg: &LegClient) -> Result<()> {
        linux_adapter_off(leg).await
    }

    async fn close_leg(&self, leg: &LegClient) -> Result<()> {
        leg.close().await
    }

    async fn restore_network(&self) -> Result<()> {
        restore_phone_network(self.phone, self.phone_usual.as_ref()).await
    }

    async fn bluetooth_off(&self) -> Result<()> {
        bluetooth_off(self.phone).await
    }
}

/// The section after the phone's network leaves. Every fallible step
/// stands in the setup, so the restore and the leg cleanup run before the
/// result returns, whatever the step meets.
async fn linux_section<S: LinuxSteps>(steps: &S, evidence: &Path) -> PeerOutcome {
    let (result, leg): (Result<Vec<JoinReport>>, Option<S::Leg>) =
        match steps.spawn_leg(evidence).await {
            Err(err) => (Err(err), None),
            Ok(leg) => {
                // The log stands after the setup whatever it meets, so the
                // evidence holds it on the failure cases, and the setup's
                // error stands over a log-write error.
                let setup = async {
                    let (linux_identity, _) = steps.ready(&leg).await?;
                    steps.walk(&leg, &linux_identity, evidence).await
                }
                .await;
                let log = steps.write_leg_log(&leg, evidence).await;
                (setup.and_then(|reports| log.map(|()| reports)), Some(leg))
            }
        };
    // The adapter power-off talks to the leg, so it runs before the close.
    let adapter = match &leg {
        Some(leg) => steps.adapter_off(leg).await,
        None => Ok(()),
    };
    let leg_closed = match &leg {
        Some(leg) => steps.close_leg(leg).await,
        None => Ok(()),
    };
    let phone_back = steps.restore_network().await;
    let bluetooth = steps.bluetooth_off().await;
    // The walk's outcome stands whatever the cleanup meets, and the first
    // cleanup failure stands beside it as the teardown's.
    let mut teardown = Ok(());
    for (what, outcome) in [
        ("powering the linux adapter off", adapter),
        ("closing the linux leg", leg_closed),
        ("bringing the phone back to its network", phone_back),
        ("turning the phone's Bluetooth off", bluetooth),
    ] {
        if let Err(err) = outcome {
            eprintln!("the cleanup failed {what}: {err:#}");
            if teardown.is_ok() {
                teardown = Err(err.context(what));
            }
        }
    }
    PeerOutcome {
        joins: result,
        teardown,
    }
}

/// The walk itself: each join in turn, every one recorded, with the
/// machines brought back to rest after each.
async fn run_linux_joins(
    phone: &Device,
    app: &mut PageSession,
    leg: &LegClient,
    phone_identity: &str,
    linux_identity: &str,
    pippo_usual: &str,
    evidence: &Path,
) -> Result<Vec<JoinReport>> {
    let mut reports = Vec::with_capacity(LINUX_JOINS.len());
    for (direction, join) in LINUX_JOINS.iter().copied() {
        let started = Instant::now();
        let name = join_name(direction, join);
        let outcome = one_linux_join(
            phone,
            app,
            leg,
            phone_identity,
            linux_identity,
            direction,
            join,
            pippo_usual,
            evidence,
        )
        .await;
        if let Err(err) = &outcome {
            eprintln!("the {name} join failed: {err:#}");
            let _ = phone
                .screenshot(evidence, &format!("{name}-failure-phone"))
                .await;
            let _ = write_linux_state(evidence, &format!("{name}-failure-linux"), leg, None).await;
        }
        reports.push(JoinReport {
            name,
            took: Some(started.elapsed()),
            outcome,
        });
    }
    Ok(reports)
}

/// One join of the linux run, from the offer to the link's end, and the
/// machines back at rest whatever happened.
#[expect(
    clippy::too_many_arguments,
    reason = "the phone, its page, the leg, both identities, the direction, the join, the usual network and the evidence are each the step's own"
)]
async fn one_linux_join(
    phone: &Device,
    app: &mut PageSession,
    leg: &LegClient,
    phone_identity: &str,
    linux_identity: &str,
    direction: Direction,
    join: JoinBy,
    pippo_usual: &str,
    evidence: &Path,
) -> Result<()> {
    let name = join_name(direction, join);
    // The hotspot's ssid, recorded as soon as it shows, so the cleanup
    // forgets it even when a later step fails.
    let mut offer_ssid = None;
    let walked = match direction {
        Direction::PhoneHosts => {
            phone_hosts_walk(
                phone,
                app,
                leg,
                phone_identity,
                linux_identity,
                join,
                name,
                evidence,
                &mut offer_ssid,
            )
            .await
        }
        Direction::LinuxHosts => {
            linux_hosts_walk(
                phone,
                app,
                leg,
                phone_identity,
                linux_identity,
                join,
                name,
                evidence,
                &mut offer_ssid,
            )
            .await
        }
    };
    // Back to rest whatever happened, so the next join starts clean: the
    // pages' own leave and stop, the phone's network left down until the run
    // ends, both adapters off, and pippo's station back, the first failure
    // kept.
    if walked.is_err() {
        // The phone as the failure left it, before the cleanup moves it.
        let name = join_name(direction, join);
        let _ = phone
            .screenshot(evidence, &format!("{name}-failure-moment"))
            .await;
        if let Ok(page) = app.page_text().await {
            let _ = tokio::fs::write(evidence.join(format!("{name}-failure-page.txt")), page).await;
        }
        let _ = leg.leave().await;
        let _ = leg.stop().await;
        let _ = app.click("Leave the hotspot").await;
        let _ = app.click("Stop the hotspot").await;
        // An abandoned join leaves the system's "Couldn't connect" notice up,
        // and the next request reuses that dialog in place of its approval, so
        // the cleanup closes it with the Settings process that shows it.
        let _ = phone
            .adb(&["shell", "am", "force-stop", "com.android.settings"])
            .await;
    }
    let station = wait_linux_station(pippo_usual).await;
    let mut bluetooth = bluetooth_off(phone).await;
    bluetooth = bluetooth.and(linux_adapter_off(leg).await);
    let networks = match &offer_ssid {
        Some(ssid) => phone.forget_network(ssid).await.map(drop),
        None => Ok(()),
    };
    // The phone's network stays down between joins, so the home LAN never
    // links the two by discovery.
    let lan = phone
        .adb(&["shell", "svc", "wifi", "disable"])
        .await
        .map(drop);
    sleep(Duration::from_secs(5)).await;
    walked.and(station).and(bluetooth).and(networks).and(lan)?;
    phone
        .screenshot(evidence, &format!("{name}-peer-clean"))
        .await?;
    Ok(())
}

/// Turn the beacon's radio on on both sides, which the beacon joins need.
///
/// # Errors
///
/// When a side will not power its adapter within the bound.
async fn beacon_on_both_sides(phone: &Device, leg: &LegClient) -> Result<()> {
    step("turn Bluetooth on on both sides");
    bluetooth_on(phone).await?;
    leg.enable_bluetooth().await?;
    Ok(())
}

/// The walk while the phone hosts: the offer from its page, the join from
/// the leg, the link named on both sides and proven over the hotspot, and
/// the link's end.
///
/// # Errors
///
/// When a step's bound runs or a page never shows its line.
#[expect(
    clippy::too_many_arguments,
    reason = "the phone, its page, the leg, both identities, the join, its name, the evidence and the ssid the cleanup forgets are each the walk's own"
)]
async fn phone_hosts_walk(
    phone: &Device,
    app: &mut PageSession,
    leg: &LegClient,
    phone_identity: &str,
    linux_identity: &str,
    join: JoinBy,
    name: &'static str,
    evidence: &Path,
    offer_ssid: &mut Option<String>,
) -> Result<()> {
    if join == JoinBy::Beacon {
        beacon_on_both_sides(phone, leg).await?;
    }
    // The phone's network stays down from the section's start, which an
    // A35 also needs to start an access point.
    step(&format!("host a hotspot on the phone for the {name} join"));
    app.click("Host a hotspot").await?;
    if join != JoinBy::Beacon {
        step("decline Bluetooth on the phone");
        phone
            .tap_dialog_button(&DENY_BUTTONS, "the Bluetooth enable dialog's refusal")
            .await?;
        app.wait_for_text("hosting, the beacon is off", Duration::from_secs(30))
            .await?;
    }
    let offer = read_hotspot_offer(app).await?;
    *offer_ssid = Some(offer.ssid.clone());
    phone
        .screenshot(evidence, &format!("{name}-host-offer"))
        .await?;
    assert_no_link(app, leg).await?;
    let gateway = match join {
        JoinBy::Form => {
            step("join the hotspot from linux");
            leg.join_form(&offer.ssid, &offer.passphrase, offer.port)
                .await?
        }
        JoinBy::Payload => {
            let payload = offer
                .payload
                .as_deref()
                .context("the phone shows no WIFI: payload")?;
            step("join the hotspot from the payload on linux");
            leg.join_payload(payload).await?
        }
        JoinBy::Beacon => {
            let beacon = read_beacon(app).await?;
            let prefix = beacon
                .strip_prefix("beacon: advertising ")
                .context("the beacon line carries no prefix")?
                .to_owned();
            step("find the beacon on linux");
            let host = leg.wait_nearby(&prefix).await?;
            leg.join_nearby(&host).await?.1
        }
    };
    step("link through the hotspot");
    if app
        .wait_for_text(
            &format!("linked: {linux_identity}"),
            Duration::from_secs(90),
        )
        .await
        .is_err()
    {
        let linked = leg.linked().await.unwrap_or_default();
        bail!("the phone never named linux as linked, linux names no peer or:\n{linked:?}");
    }
    leg.wait_linked(phone_identity, Duration::from_secs(30))
        .await?;
    step("prove the link runs over the hotspot");
    let ss_line = ss_link_line(move |remote| remote == gateway).await?;
    phone
        .screenshot(evidence, &format!("{name}-host-linked"))
        .await?;
    write_linux_state(
        evidence,
        &format!("{name}-linux-linked"),
        leg,
        Some(ss_line.as_str()),
    )
    .await?;
    step("leave the hotspot on linux");
    leg.leave().await?;
    step("stop the hotspot on the phone");
    app.click("Stop the hotspot").await?;
    wait_link_ends_leg(app, leg, phone_identity).await?;
    phone
        .screenshot(evidence, &format!("{name}-host-unlinked"))
        .await?;
    Ok(())
}

/// The walk while linux hosts: the offer stood up on pippo, then the
/// phone's side of it.
///
/// # Errors
///
/// As [`linux_hosts_preamble`] and [`linux_hosts_join`].
#[expect(
    clippy::too_many_arguments,
    reason = "the phone, its page, the leg, both identities, the join, its name, the evidence and the ssid the cleanup forgets are each the walk's own"
)]
async fn linux_hosts_walk(
    phone: &Device,
    app: &mut PageSession,
    leg: &LegClient,
    phone_identity: &str,
    linux_identity: &str,
    join: JoinBy,
    name: &'static str,
    evidence: &Path,
    offer_ssid: &mut Option<String>,
) -> Result<()> {
    let (offer, port) =
        linux_hosts_preamble(phone, app, leg, join, name, evidence, offer_ssid).await?;
    linux_hosts_join(
        phone,
        app,
        leg,
        phone_identity,
        linux_identity,
        join,
        name,
        &offer,
        port,
        evidence,
    )
    .await
}

/// The linux host's start: the beacon's sides, the phone off its network,
/// the offer stood up with its beacon standing asserted, and its port.
///
/// # Errors
///
/// When the hotspot will not host, the beacon stands down where the join
/// needs it up, or a step's bound runs.
async fn linux_hosts_preamble(
    phone: &Device,
    app: &mut PageSession,
    leg: &LegClient,
    join: JoinBy,
    name: &'static str,
    evidence: &Path,
    offer_ssid: &mut Option<String>,
) -> Result<(LegOffer, u16)> {
    // `host_hotspot` powers the adapter on Linux (decision 21), where no
    // dialog stands to decline, so the payload and form joins run beside a
    // live beacon the phone leaves unused.
    if join == JoinBy::Beacon {
        beacon_on_both_sides(phone, leg).await?;
    }
    assert_no_link(app, leg).await?;
    step(&format!("host a hotspot on linux for the {name} join"));
    let offer = leg.host().await?;
    *offer_ssid = Some(offer.ssid.clone());
    if let (JoinBy::Beacon, Some(reason)) = (join, offer.beacon_off.as_deref()) {
        bail!("linux hosted the beacon join with its beacon down: {reason}");
    }
    write_linux_state(evidence, &format!("{name}-linux-offer"), leg, None).await?;
    let port = match offer.port {
        Some(port) => port,
        None => leg.wait_serving().await?,
    };
    Ok((offer, port))
}

/// The linux host's link: the phone shown the offer and joined by its way,
/// the system's approval, the link named on both sides and proven over the
/// hotspot, and the link's end.
///
/// # Errors
///
/// When the phone will not take the offer, the link never shows, no
/// established connection names the hotspot, or a step's bound runs.
#[expect(
    clippy::too_many_arguments,
    reason = "the phone, its page, the leg, both identities, the join, its name, the offer, its port and the evidence are each the link's own"
)]
async fn linux_hosts_join(
    phone: &Device,
    app: &mut PageSession,
    leg: &LegClient,
    phone_identity: &str,
    linux_identity: &str,
    join: JoinBy,
    name: &'static str,
    offer: &LegOffer,
    port: u16,
    evidence: &Path,
) -> Result<()> {
    // The phone's network comes back for the join, which moves it from its
    // own network to linux's hotspot.
    step("bring the phone's network back for the join");
    phone.adb(&["shell", "svc", "wifi", "enable"]).await?;
    sleep(Duration::from_secs(5)).await;
    match join {
        JoinBy::Form => {
            step("fill the join form on the phone");
            app.set_input("ssid", &offer.ssid).await?;
            app.set_input("passphrase", &offer.passphrase).await?;
            app.set_input("port", &port.to_string()).await?;
            app.click("Join the hotspot").await?;
        }
        JoinBy::Payload => {
            step("paste the payload on the phone");
            app.set_input("payload", &offer.payload).await?;
            app.click("Join from the payload").await?;
            if app
                .wait_for_text("joining the hotspot", Duration::from_secs(10))
                .await
                .is_err()
            {
                let page = app.page_text().await.unwrap_or_default();
                bail!("the phone did not take the payload, its page shows:\n{page}");
            }
        }
        JoinBy::Beacon => {
            let prefix = leg.wait_beacon().await?;
            step("find the beacon on the phone");
            app.wait_for_text(&format!("nearby: {prefix}"), Duration::from_secs(60))
                .await
                .context("the phone never saw linux's beacon")?;
            // The join button takes the strongest host, so linux's
            // must be the only one in sight.
            let page = app.page_text().await?;
            let nearby: Vec<&str> = page
                .lines()
                .filter(|line| line.starts_with("nearby: "))
                .collect();
            if nearby.len() != 1 {
                bail!("the phone sees other hosts than linux: {nearby:?}");
            }
            phone
                .screenshot(evidence, &format!("{name}-peer-nearby"))
                .await?;
            app.click("Join the nearby host").await?;
        }
    }
    step("approve the network on the phone");
    phone.tap_connect_button().await?;
    step("link through the hotspot");
    leg.wait_linked(phone_identity, Duration::from_secs(90))
        .await?;
    if app
        .wait_for_text(
            &format!("linked: {linux_identity}"),
            Duration::from_secs(30),
        )
        .await
        .is_err()
    {
        let linked = leg.linked().await.unwrap_or_default();
        bail!("linux never named the phone as linked, the phone names:\n{linked:?}");
    }
    step("prove the link runs over the hotspot");
    let ss_line = ss_link_line(in_hotspot_subnet).await?;
    phone
        .screenshot(evidence, &format!("{name}-peer-linked"))
        .await?;
    write_linux_state(
        evidence,
        &format!("{name}-linux-linked"),
        leg,
        Some(ss_line.as_str()),
    )
    .await?;
    step("leave the hotspot on the phone");
    app.click("Leave the hotspot").await?;
    step("stop the hotspot on linux");
    leg.stop().await?;
    // Leaving the hotspot hands the phone's station back to its home
    // network, where discovery would link it to pippo over the LAN, so the
    // phone goes off Wi-Fi before the link's end is awaited.
    step("take the phone off its network");
    phone.adb(&["shell", "svc", "wifi", "disable"]).await?;
    wait_link_ends_leg(app, leg, phone_identity).await?;
    phone
        .screenshot(evidence, &format!("{name}-host-unlinked"))
        .await?;
    Ok(())
}

/// No link may stand before a join's join step, so the run proves the join
/// made the link: a stale link closes after 45 s of silence, and the wait
/// fails only past [`LINK_END_BOUND`].
///
/// # Errors
///
/// When a link still stands past the bound, or a side does not answer.
async fn assert_no_link(app: &mut PageSession, leg: &LegClient) -> Result<()> {
    let deadline = Instant::now() + LINK_END_BOUND;
    loop {
        let page = app.page_text().await?;
        let phone_linked = page.lines().any(|line| line.starts_with("linked: "));
        let linked = leg.linked().await?;
        if !phone_linked && linked.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "a link stands before the join step, the phone names a link, \
                 linux names: {linked:?}"
            );
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Wait for the phone's page to drop its linked line and the leg to drop the
/// phone from its linked list, which the leave and the stop end the link.
///
/// # Errors
///
/// When a link stands past [`LINK_END_BOUND`], or a side does not answer.
async fn wait_link_ends_leg(app: &mut PageSession, leg: &LegClient, peer: &str) -> Result<()> {
    let deadline = Instant::now() + LINK_END_BOUND;
    loop {
        let page = app.page_text().await?;
        let linked = leg.linked().await?;
        if !page.contains("linked: ") && !linked.iter().any(|held| held == peer) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the link did not end after the leave and the stop");
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// pippo's station's connection name, which `nmcli dev status` names while
/// the Wi-Fi device holds one.
///
/// # Errors
///
/// When `nmcli` fails.
async fn linux_station() -> Result<Option<String>> {
    let output = Command::new("nmcli")
        .args(["dev", "status"])
        .output()
        .await?;
    if !output.status.success() {
        bail!("nmcli dev status exited with {}", output.status);
    }
    Ok(parse_station_name(&String::from_utf8_lossy(&output.stdout)))
}

/// One line of pippo's established TCP connections whose remote endpoint
/// satisfies `expect`, which the run's link proof reads.
///
/// # Errors
///
/// When `ss` will not run or no line satisfies `expect`.
async fn ss_link_line(expect: impl Fn(IpAddr) -> bool) -> Result<String> {
    let output = Command::new("ss")
        .args(["-tnH", "state", "established"])
        .output()
        .await?;
    if !output.status.success() {
        bail!("ss -tnH state established exited with {}", output.status);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find(|line| ss_remote_address(line).is_some_and(&expect))
        .map(str::to_owned)
        .context("no established connection on pippo matches the hotspot link")
}

/// Hold until pippo's station is back on `usual`, which `NetworkManager`
/// reconnects on its own once a join's connection is gone.
///
/// # Errors
///
/// When the station never comes back within the bound.
async fn wait_linux_station(usual: &str) -> Result<()> {
    let deadline = Instant::now() + STATION_BACK_BOUND;
    loop {
        if linux_station().await?.as_deref() == Some(usual) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("pippo's station never came back on {usual}");
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Power the linux adapter off where it stands on, and hold until it reports
/// itself off.
///
/// # Errors
///
/// When `bluetoothctl` fails or the adapter never reports itself off.
async fn linux_adapter_off(leg: &LegClient) -> Result<()> {
    if leg.bluetooth().await? == BluetoothState::Off {
        return Ok(());
    }
    step("power the linux adapter off");
    let output = Command::new("bluetoothctl")
        .args(["power", "off"])
        .output()
        .await?;
    if !output.status.success() {
        bail!("bluetoothctl power off exited with {}", output.status);
    }
    let deadline = Instant::now() + ADAPTER_OFF_BOUND;
    loop {
        if leg.bluetooth().await? == BluetoothState::Off {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the linux adapter never reported itself off");
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Bring the phone back to its usual network at the end of the run, where
/// the joins kept it down.
///
/// # Errors
///
/// When the phone never comes back on its usual network within the bound.
async fn restore_phone_network(phone: &Device, usual: Option<&String>) -> Result<()> {
    if usual.is_none() {
        return Ok(());
    }
    let _ = phone.adb(&["shell", "svc", "wifi", "enable"]).await;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let current = phone.current_ssid().await?;
        if current.as_deref() == usual.map(String::as_str) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the phone is back on {current:?}, not {usual:?}");
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// The leg's full standing as a text file beside the run's evidence, which a
/// headless machine shows in place of a screenshot.
///
/// # Errors
///
/// When the file cannot be written.
async fn write_linux_state(
    evidence: &Path,
    name: &str,
    leg: &LegClient,
    ss_line: Option<&str>,
) -> Result<()> {
    let mut text = match leg.state().await {
        Ok(state) => format!("{state}\n"),
        Err(err) => format!("the leg answered no state: {err:#}\n"),
    };
    if let Some(line) = ss_line {
        text.push_str("ss: ");
        text.push_str(line);
        text.push('\n');
    }
    tokio::fs::write(evidence.join(format!("{name}.txt")), text)
        .await
        .with_context(|| format!("writing the leg's state file {name}"))
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
                device.tap_pin_fallback().await?;
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

/// What the command line names.
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag names one run mode the command line takes, and none groups into a mode of its own"
)]
struct Arguments {
    serial: Option<String>,
    apk: Option<PathBuf>,
    unlock_pin: Option<String>,
    peer_serial: Option<String>,
    /// Pippo takes the second device's place in the six-join walk, which
    /// needs `--every-join` (R76 slice 9b).
    linux_peer: bool,
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
    if std::env::args().any(|arg| arg == "--help" || arg == "-h") {
        eprintln!("{USAGE}");
        std::process::exit(0);
    }
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
        if arg == "--linux-peer" {
            arguments.linux_peer = true;
            continue;
        }
        let value = args.next().ok_or_else(|| anyhow!("{arg} needs a value"))?;
        match arg.as_str() {
            "--serial" => arguments.serial = Some(value),
            "--apk" => arguments.apk = Some(PathBuf::from(value)),
            "--app" => APP
                .set(DemoApp::parse(&value)?)
                .map_err(|_| anyhow!("--app given twice"))?,
            "--unlock-pin" => arguments.unlock_pin = Some(value),
            "--peer-serial" => arguments.peer_serial = Some(value),
            other => bail!("unknown argument {other}"),
        }
    }
    validate_arguments(&arguments, demo_app())?;
    Ok(arguments)
}

/// The argument rules, checked before the run starts.
fn validate_arguments(arguments: &Arguments, app: DemoApp) -> Result<()> {
    if arguments.linux_peer && arguments.peer_serial.is_some() {
        bail!("--linux-peer and --peer-serial name the same side twice, pick one");
    }
    if arguments.linux_peer && !arguments.every_join {
        bail!("--linux-peer runs the six-join walk, so it needs --every-join");
    }
    if arguments.linux_peer && (arguments.bluetooth || arguments.payload) {
        bail!("--linux-peer walks every join both ways, so --bluetooth and --payload name none");
    }
    if arguments.payload && arguments.peer_serial.is_none() {
        bail!("--payload needs --peer-serial");
    }
    if arguments.every_join && arguments.peer_serial.is_none() && !arguments.linux_peer {
        bail!("--every-join needs --peer-serial");
    }
    if arguments.every_join && (arguments.bluetooth || arguments.payload) {
        bail!("--every-join runs every join, so --bluetooth and --payload name none");
    }
    if (arguments.peer_serial.is_some() || arguments.bluetooth || arguments.linux_peer)
        && matches!(app, DemoApp::Tauri)
    {
        bail!(
            "--peer-serial, --linux-peer and --bluetooth need the dioxus demo, whose panel holds the peer controls"
        );
    }
    Ok(())
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
    if let DemoApp::Tauri = demo_app() {
        return build_tauri_apk(target).await;
    }
    let demo = repo_path(&["examples", "dioxus-desktop-demo"])?;
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

/// Build the Tauri demo's debug APK for the one ABI of `target`.
async fn build_tauri_apk(target: &str) -> Result<PathBuf> {
    let abi = match target {
        "aarch64-linux-android" => "aarch64",
        "x86_64-linux-android" => "x86_64",
        other => bail!("the Tauri build names no ABI for {other}"),
    };
    let demo = repo_path(&["examples", "tauri-leptos-demo", "src-tauri"])?;
    let mut cargo = Command::new("cargo");
    cargo.current_dir(&demo).args([
        "tauri", "android", "build", "--debug", "--apk", "--target", abi,
    ]);
    if demo_has_device_identity() {
        cargo.args(["--features", "device-identity"]);
    }
    let status = cargo.status().await.context("starting cargo tauri")?;
    if !status.success() {
        bail!("cargo tauri android build exited with {status}");
    }
    Ok(demo.join("gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"))
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

    /// The device's own value of a system setting, `None` when it holds none.
    async fn system_setting(&self, name: &str) -> Result<Option<String>> {
        let value = self
            .adb(&["shell", "settings", "get", "system", name])
            .await?;
        Ok(Some(value.trim())
            .filter(|value| *value != "null")
            .map(ToOwned::to_owned))
    }

    /// Put back a system setting read by [`Self::system_setting`].
    async fn restore_system_setting(&self, name: &str, value: Option<&str>) -> Result<()> {
        match value {
            Some(value) => {
                self.adb(&["shell", "settings", "put", "system", name, value])
                    .await
            }
            None => {
                self.adb(&["shell", "settings", "delete", "system", name])
                    .await
            }
        }
        .map(drop)
    }

    /// Wait until the events buffer shows the demo's screen destroyed and
    /// created again inside process `pid`.
    async fn wait_for_rebuild(&self, pid: &str) -> Result<()> {
        let deadline = Instant::now() + REBUILD_WITHIN;
        loop {
            let events = self.adb(&["logcat", "-b", "events", "-d"]).await?;
            if rebuilt_in(&events, pid, activity()) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "the demo's screen was not rebuilt in process {pid} within {REBUILD_WITHIN:?}"
                );
            }
            sleep(Duration::from_millis(500)).await;
        }
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
    /// Open the PIN pad a phone with a fingerprint enrolled keeps behind
    /// the prompt's own button.
    ///
    /// # Errors
    ///
    /// When the tap fails.
    async fn tap_pin_fallback(&self) -> Result<()> {
        // A dump can crash while the prompt animates in, which reads as no
        // button, so the PIN entry goes on.
        let fallback = self
            .dialog_button_bounds(&PIN_FALLBACK_BUTTONS)
            .await
            .unwrap_or_else(|err| {
                eprintln!(
                    "{} gave no UI dump for the PIN fallback: {err:#}",
                    self.serial
                );
                None
            });
        if let Some((left, top, right, bottom)) = fallback {
            let x = i32::midpoint(left, right).to_string();
            let y = i32::midpoint(top, bottom).to_string();
            self.adb(&["shell", "input", "tap", &x, &y]).await?;
        }
        Ok(())
    }

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
            &format!("{}/{}", package(), activity()),
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
        let pid = self.adb(&["shell", "pidof", package()]).await?;
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

    use super::{Device, parse_current_ssid, rebuilt_in, saved_network_id};

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

    /// A UI dump that fails while the prompt animates in leaves the PIN
    /// entry to go on, with no tap.
    #[tokio::test]
    async fn a_failed_dump_leaves_the_pin_entry_to_go_on() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adb = fake_adb(
            dir.path(),
            r#"case "$*" in
  *"uiautomator dump"*) echo "ERROR: could not get idle state." >&2; exit 1 ;;
esac
exit 0"#,
        );
        let device = Device::with_adb("emulator-5554".to_owned(), adb, Duration::from_secs(5));
        device
            .tap_pin_fallback()
            .await
            .expect("a failed dump is no failure");
        let calls = calls(dir.path());
        assert!(!calls.contains("input tap"), "{calls}");
    }

    /// The fallback button a dump shows is tapped at its centre.
    #[tokio::test]
    async fn the_pin_fallback_button_is_tapped_at_its_centre() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adb = fake_adb(
            dir.path(),
            &format!(
                r#"case "$*" in
  *"cat /sdcard/connetto-ui.xml"*) echo '<node index="0" text="{}" clickable="true" bounds="[100,200][300,400]" />' ;;
esac
exit 0"#,
                super::PIN_FALLBACK_BUTTONS[0]
            ),
        );
        let device = Device::with_adb("emulator-5554".to_owned(), adb, Duration::from_secs(5));
        device.tap_pin_fallback().await.expect("the tap stands");
        let calls = calls(dir.path());
        assert!(calls.contains("input tap 200 300"), "{calls}");
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

    const TAURI_ACTIVITY: &str = "dev.connetto.tauridemo.MainActivity";

    #[test]
    fn a_rebuild_is_a_destroy_then_a_create_in_the_same_process() {
        let events = "\
10-17 11:35:38.696  4447  4447 I wm_on_create_called: [58122755,dev.connetto.tauridemo.MainActivity,performCreate,115]
10-17 11:35:54.520   571   599 I wm_relaunch_resume_activity: [0,58122755,94,dev.connetto.tauridemo/.MainActivity,40000000]
10-17 11:35:54.534  4447  4447 I wm_on_destroy_called: [58122755,dev.connetto.tauridemo.MainActivity,performDestroy,4]
10-17 11:35:54.565  4447  4447 I wm_on_create_called: [58122755,dev.connetto.tauridemo.MainActivity,performCreate,10]
";
        assert!(rebuilt_in(events, "4447", TAURI_ACTIVITY));
    }

    #[test]
    fn a_back_press_is_no_rebuild() {
        let events = "\
10-17 11:39:15.002  5214  5214 I wm_on_create_called: [60563097,dev.connetto.tauridemo.MainActivity,performCreate,74]
10-17 11:39:44.218  5214  5214 I wm_on_stop_called: [60563097,dev.connetto.tauridemo.MainActivity,LIFECYCLER_STOP_ACTIVITY,1]
10-17 11:39:44.229  5214  5214 I wm_on_destroy_called: [60563097,dev.connetto.tauridemo.MainActivity,performDestroy,10]
";
        assert!(!rebuilt_in(events, "5214", TAURI_ACTIVITY));
    }

    #[test]
    fn a_create_in_a_new_process_is_no_rebuild() {
        let events = "\
10-17 11:39:44.229  5214  5214 I wm_on_destroy_called: [60563097,dev.connetto.tauridemo.MainActivity,performDestroy,10]
10-17 11:39:48.308  5361  5361 I wm_on_create_called: [198079543,dev.connetto.tauridemo.MainActivity,performCreate,73]
";
        assert!(!rebuilt_in(events, "5214", TAURI_ACTIVITY));
    }

    #[test]
    fn another_screens_rebuild_is_not_the_demos() {
        let events = "\
10-17 11:34:10.298  4447  4447 I wm_on_destroy_called: [211010610,dev.connetto.authsession.RedirectActivity,performDestroy,4]
10-17 11:34:10.446  4447  4447 I wm_on_create_called: [211010611,dev.connetto.authsession.RedirectActivity,performCreate,108]
";
        assert!(!rebuilt_in(events, "4447", TAURI_ACTIVITY));
    }

    /// The resource step the test refuses.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FakeRefusal {
        /// The leg's launch.
        Spawn,
        /// The leg's ready line.
        Ready,
        /// The six-join walk.
        Walk,
        /// The leg's log write.
        Log,
        /// The phone's return to its network, a cleanup step.
        Restore,
    }

    /// The calls the section made, its setup and its cleanup.
    #[derive(Clone, Default)]
    #[expect(
        clippy::struct_excessive_bools,
        reason = "the flags record the section's six calls, one per step"
    )]
    struct FakeFlags {
        walk: bool,
        log: bool,
        adapter_off: bool,
        close: bool,
        restore: bool,
        bluetooth_off: bool,
    }

    /// The section's steps, the failures injected and the cleanup calls
    /// recorded.
    struct FakeSteps {
        refusal: FakeRefusal,
        flags: parking_lot::Mutex<FakeFlags>,
    }

    impl FakeSteps {
        fn new(refusal: FakeRefusal) -> Self {
            Self {
                refusal,
                flags: parking_lot::Mutex::new(FakeFlags::default()),
            }
        }

        fn flags(&self) -> FakeFlags {
            self.flags.lock().clone()
        }
    }

    struct FakeLeg;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the fake steps answer without a device or bus round trip"
    )]
    impl super::LinuxSteps for FakeSteps {
        type Leg = FakeLeg;

        async fn spawn_leg(&self, _evidence: &Path) -> anyhow::Result<FakeLeg> {
            if self.refusal == FakeRefusal::Spawn {
                anyhow::bail!("the injected leg launch failure");
            }
            Ok(FakeLeg)
        }

        async fn ready(&self, _leg: &FakeLeg) -> anyhow::Result<(String, u16)> {
            if self.refusal == FakeRefusal::Ready {
                anyhow::bail!("the injected readiness failure");
            }
            Ok(("linux".into(), 8080))
        }

        async fn walk(
            &self,
            _leg: &FakeLeg,
            _linux_identity: &str,
            _evidence: &Path,
        ) -> anyhow::Result<Vec<connetto_test_harness::peer_proof::JoinReport>> {
            self.flags.lock().walk = true;
            if self.refusal == FakeRefusal::Walk {
                anyhow::bail!("the injected walk failure");
            }
            Ok(Vec::new())
        }

        async fn write_leg_log(&self, _leg: &FakeLeg, _evidence: &Path) -> anyhow::Result<()> {
            self.flags.lock().log = true;
            if self.refusal == FakeRefusal::Log {
                anyhow::bail!("the injected evidence write failure");
            }
            Ok(())
        }

        async fn adapter_off(&self, _leg: &FakeLeg) -> anyhow::Result<()> {
            self.flags.lock().adapter_off = true;
            Ok(())
        }

        async fn close_leg(&self, _leg: &FakeLeg) -> anyhow::Result<()> {
            self.flags.lock().close = true;
            Ok(())
        }

        async fn restore_network(&self) -> anyhow::Result<()> {
            self.flags.lock().restore = true;
            if self.refusal == FakeRefusal::Restore {
                anyhow::bail!("the injected restore failure");
            }
            Ok(())
        }

        async fn bluetooth_off(&self) -> anyhow::Result<()> {
            self.flags.lock().bluetooth_off = true;
            Ok(())
        }
    }

    /// A setup failure leaves the phone back on its network, its Bluetooth
    /// off, and the leg's cleanup run once the leg stood, and the leg's log
    /// stands whatever the setup meets.
    #[tokio::test]
    async fn setup_failures_leave_the_phone_restored_and_the_leg_released() {
        for (refusal, leg_up, walk_ran, log_written) in [
            (FakeRefusal::Spawn, false, false, false),
            (FakeRefusal::Ready, true, false, true),
            (FakeRefusal::Walk, true, true, true),
            (FakeRefusal::Log, true, true, true),
        ] {
            let steps = FakeSteps::new(refusal);
            let outcome = super::linux_section(&steps, Path::new("evidence")).await;
            assert!(outcome.joins.is_err(), "the {refusal:?} refusal stands");
            assert!(
                outcome.teardown.is_ok(),
                "the {refusal:?} refusal's cleanup stood"
            );
            let flags = steps.flags();
            assert!(
                flags.restore,
                "the {refusal:?} refusal left the phone off its network"
            );
            assert!(
                flags.bluetooth_off,
                "the {refusal:?} refusal left the phone's Bluetooth on"
            );
            assert_eq!(
                flags.adapter_off, leg_up,
                "the {refusal:?} refusal mis-ran the adapter power-off"
            );
            assert_eq!(
                flags.close, leg_up,
                "the {refusal:?} refusal mis-ran the leg close"
            );
            assert_eq!(
                flags.walk, walk_ran,
                "the {refusal:?} refusal mis-ran the walk"
            );
            assert_eq!(
                flags.log, log_written,
                "the {refusal:?} refusal mis-wrote the leg's log"
            );
        }
    }

    /// A cleanup step that fails stands as the teardown's error beside the
    /// walk's reports, and the cleanup after it still runs.
    #[tokio::test]
    async fn a_cleanup_failure_stands_beside_the_walk() {
        let steps = FakeSteps::new(FakeRefusal::Restore);
        let outcome = super::linux_section(&steps, Path::new("evidence")).await;
        assert!(outcome.joins.is_ok(), "the walk's reports stand");
        let err = outcome.teardown.expect_err("the restore's failure stands");
        assert_eq!(err.root_cause().to_string(), "the injected restore failure");
        assert!(
            steps.flags().bluetooth_off,
            "the cleanup after the failure still ran"
        );
    }

    /// The walk's mode needs the dioxus panel, so `--linux-peer` with the
    /// Tauri demo is refused before the run starts.
    #[test]
    fn linux_peer_with_the_tauri_demo_is_refused() {
        let arguments = super::Arguments {
            linux_peer: true,
            every_join: true,
            ..Default::default()
        };
        assert!(
            super::validate_arguments(&arguments, super::DemoApp::Dioxus).is_ok(),
            "the dioxus demo carries the peer panel"
        );
        let err = super::validate_arguments(&arguments, super::DemoApp::Tauri)
            .expect_err("the tauri demo has no peer panel");
        let text = format!("{err:#}");
        assert!(
            text.contains("--peer-serial, --linux-peer and --bluetooth"),
            "{text}"
        );
    }
}
