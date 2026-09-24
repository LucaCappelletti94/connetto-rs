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
//!   target/debug/connetto-android-proof [--serial SERIAL] [--apk PATH]
//! ```
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
use connetto_test_harness::stack::{now_millis, repo_path};
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

#[tokio::main]
async fn main() -> Result<()> {
    let stack = Stack::from_env()?;
    let (serial, apk) = cli_arguments()?;
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
    device.set_browser_role_holder(BROWSER).await?;
    let outcome = prove(&device, apk, &stack, &evidence).await;
    let log = device.adb(&["logcat", "-d"]).await.unwrap_or_default();
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
    outcome.and(restored)
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
) -> Result<()> {
    device
        .adb(&["shell", "svc", "power", "stayon", "usb"])
        .await?;
    device
        .adb(&["shell", "input", "keyevent", "KEYCODE_WAKEUP"])
        .await?;
    let apk = match apk {
        Some(apk) => apk,
        None => build_apk(&device.rust_target().await?).await?,
    };
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
    let mut app = device.app().await?;
    app.wait_for_text("status: connected", Duration::from_secs(90))
        .await?;
    device.screenshot(evidence, "signed-in").await?;

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
    sign_out(device, &mut app, evidence).await?;
    sign_in_across_a_killed_process(device, &stack.issuer, evidence).await?;
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
) -> Result<()> {
    step("sign in across a killed process");
    let mut tab = device.login_tab(issuer).await?;
    let killed = device.adb(&["shell", "pidof", PACKAGE]).await?;
    device.adb(&["shell", "am", "kill", PACKAGE]).await?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while device.adb(&["shell", "pidof", PACKAGE]).await.is_ok() {
        if Instant::now() >= deadline {
            bail!(
                "the backgrounded app (pid {}) was not killed",
                killed.trim()
            );
        }
        sleep(Duration::from_millis(250)).await;
    }
    submit_login(&mut tab).await?;
    drop(tab);
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
fn cli_arguments() -> Result<(Option<String>, Option<PathBuf>)> {
    let mut serial = None;
    let mut apk = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args.next().ok_or_else(|| anyhow!("{arg} needs a value"))?;
        match arg.as_str() {
            "--serial" => serial = Some(value),
            "--apk" => apk = Some(PathBuf::from(value)),
            other => bail!("unknown argument {other}"),
        }
    }
    Ok((serial, apk))
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
            "mobile",
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
    /// The browser targets [`Device::login_tab`] returned. A finished login's
    /// tab can stay listed on the authorize URL while it closes, so a later
    /// login must never pick it again.
    spent_tabs: std::sync::Mutex<Vec<String>>,
}

impl Device {
    fn new(serial: String) -> Self {
        Self {
            serial,
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

    async fn adb(&self, args: &[&str]) -> Result<String> {
        let output = Command::new("adb")
            .arg("-s")
            .arg(&self.serial)
            .args(args)
            .output()
            .await
            .context("starting adb")?;
        if !output.status.success() {
            bail!(
                "adb {} exited with {}: {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
            let status = Command::new("adb")
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

    async fn screenshot(&self, dir: &Path, name: &str) -> Result<()> {
        let output = Command::new("adb")
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
            self.tap_interstitial().await?;
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
