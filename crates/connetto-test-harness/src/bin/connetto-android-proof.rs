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
//!   target/debug/connetto-android-proof [--serial SERIAL] [--apk PATH] [--unlock-pin PIN]
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

#[tokio::main]
async fn main() -> Result<()> {
    let stack = Stack::from_env()?;
    let Arguments {
        serial,
        apk,
        unlock_pin,
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
        Ok(()) => prove(&device, apk, &stack, &evidence, unlock).await,
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
    apk: Option<PathBuf>,
    stack: &Stack,
    evidence: &Path,
    unlock: Unlock<'_>,
) -> Result<()> {
    let apk = match apk {
        Some(apk) => apk,
        None => build_apk(&device.rust_target().await?).await?,
    };
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
    submit_login(&mut tab).await?;
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
    submit_login(&mut tab).await?;
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
async fn submit_login(tab: &mut PageSession) -> Result<()> {
    tab.evaluate("document.querySelector('input[name=username]').focus()")
        .await?;
    tab.call("Input.insertText", serde_json::json!({ "text": USER }))
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
}

fn cli_arguments() -> Result<Arguments> {
    let mut arguments = Arguments::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args.next().ok_or_else(|| anyhow!("{arg} needs a value"))?;
        match arg.as_str() {
            "--serial" => arguments.serial = Some(value),
            "--apk" => arguments.apk = Some(PathBuf::from(value)),
            "--unlock-pin" => arguments.unlock_pin = Some(value),
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(arguments)
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

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::Device;

    /// A stand-in `adb` that runs `body` with `$state` naming a scratch directory.
    fn fake_adb(dir: &Path, body: &str) -> PathBuf {
        use std::io::Write as _;
        let path = dir.join("adb");
        let script = format!(
            "#!/bin/sh\nstate={}\necho \"$*\" >>\"$state/calls\"\n{body}\n",
            dir.display()
        );
        // A child process writes the script, so no descriptor open for
        // writing it lives in this process, where another test's fork could
        // inherit it and make the exec fail with "Text file busy".
        let mut writer = std::process::Command::new("sh")
            .arg("-c")
            .arg("cat >\"$0\" && chmod 755 \"$0\"")
            .arg(&path)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("start the writer");
        writer
            .stdin
            .take()
            .expect("the writer's input")
            .write_all(script.as_bytes())
            .expect("write the fake adb");
        assert!(
            writer.wait().expect("the writer ends").success(),
            "the writer fails"
        );
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
}
