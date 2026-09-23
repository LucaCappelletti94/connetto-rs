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
//! because neither exposes web content to `uiautomator`. The login form is
//! answered from the host with the authorize URL the browser tab shows, and
//! the browser is sent to the resulting callback so the demo's loopback
//! listener on the device receives the code. Each step's screenshot and the
//! device log land under `target/android-proof/<serial>-<millis>/`.
//!
//! The offline step restarts the host's adb server, which drops every other
//! session's forwards and reverses on this machine too. A wireless serial
//! (`host:port`) is reconnected after the restart.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use connetto_test_harness::pool_for;
use connetto_test_harness::stack::{now_millis, repo_path};
use diesel::QueryDsl as _;
use diesel_async::RunQueryDsl as _;
use futures_util::{SinkExt as _, StreamExt as _};
use openidconnect::reqwest;
use tokio::process::Command;
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;

const PACKAGE: &str = "com.example.ConnettoDioxusDesktopDemo";
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
/// How long one `DevTools` request may take to answer.
const CDP_REPLY: Duration = Duration::from_secs(10);

diesel::table! {
    /// The demo's orders, as far as the proof counts them.
    orders (id) {
        /// Key.
        id -> diesel::sql_types::Uuid,
        /// Ordered amount.
        quantity -> diesel::sql_types::BigInt,
    }
}

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
    std::fs::create_dir_all(&evidence)
        .with_context(|| format!("creating {}", evidence.display()))?;
    eprintln!("evidence in {}", evidence.display());

    // The login tab is read through Chrome's DevTools socket, so Chrome holds
    // the browser role for the run and the device's own choice returns after.
    let previous = device.browser_role_holder().await?;
    device.set_browser_role_holder(BROWSER).await?;
    let outcome = prove(&device, apk, &stack, &evidence).await;
    let log = device.adb(&["logcat", "-d"]).await.unwrap_or_default();
    std::fs::write(evidence.join("logcat.txt"), log).context("writing the device log")?;
    if let Err(err) = &outcome {
        let _ = device.screenshot(&evidence, "failure").await;
        eprintln!("proof failed: {err:#}");
    }
    let _ = device.adb(&["forward", "--remove-all"]).await;
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
    let authorize = device.authorize_url(&stack.issuer).await?;
    device.screenshot(evidence, "login-page").await?;
    let callback = answer_login(&authorize).await?;
    device
        .adb(&[
            "shell",
            "am",
            "start",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            &format!("'{callback}'"),
            BROWSER,
        ])
        .await?;
    sleep(Duration::from_secs(3)).await;
    device.launch().await?;
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
    step("proof complete");
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

/// Submit the dev identity provider's login form as [`USER`] and return
/// where it redirects, the server's callback carrying the code.
async fn answer_login(authorize: &str) -> Result<String> {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("building the HTTP client")?;
    let response = http
        .post(authorize)
        .form(&[("username", USER)])
        .send()
        .await
        .context("submitting the login form")?;
    response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|location| location.to_str().ok())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            anyhow!(
                "the login answered {} without a redirect",
                response.status()
            )
        })
}

async fn order_count(pg_url: &str) -> Result<i64> {
    let pool = pool_for(pg_url).await;
    let mut conn = pool.get().await.context("a Postgres connection")?;
    orders::table
        .count()
        .get_result(&mut conn)
        .await
        .context("counting orders")
}

async fn wait_for_count(pg_url: &str, expected: i64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let count = order_count(pg_url).await?;
        if count == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("Postgres holds {count} orders, expected {expected}");
        }
        sleep(Duration::from_millis(500)).await;
    }
}

struct Device {
    serial: String,
}

impl Device {
    /// The named device, or the only one attached.
    async fn pick(serial: Option<String>) -> Result<Self> {
        if let Some(serial) = serial {
            return Ok(Self { serial });
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
            [serial] => Ok(Self {
                serial: (*serial).to_owned(),
            }),
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
        std::fs::write(dir.join(format!("{name}.png")), output.stdout)
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

    /// The `DevTools` targets behind one abstract socket on the device.
    async fn targets(&self, socket: &str) -> Result<Vec<serde_json::Value>> {
        let port = self.forward(socket).await?;
        let listing = list_targets(port).await;
        let _ = self
            .adb(&["forward", "--remove", &format!("tcp:{port}")])
            .await;
        listing
    }

    /// Wait for the browser tab the demo opened on `issuer`, tapping past
    /// the browser's first-run screens, and return its full URL.
    async fn authorize_url(&self, issuer: &str) -> Result<String> {
        let prefix = format!("{issuer}/authorize?");
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let tabs = self
                .targets("chrome_devtools_remote")
                .await
                .unwrap_or_default();
            if let Some(url) = tabs
                .iter()
                .filter_map(|tab| tab["url"].as_str())
                .find(|url| url.starts_with(&prefix))
            {
                return Ok(url.to_owned());
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
    async fn app(&self) -> Result<Cdp> {
        let pid = self.adb(&["shell", "pidof", PACKAGE]).await?;
        let port = self
            .forward(&format!("webview_devtools_remote_{}", pid.trim()))
            .await?;
        let targets = list_targets(port).await?;
        let ws = targets
            .iter()
            .find(|target| target["type"] == "page")
            .and_then(|target| target["webSocketDebuggerUrl"].as_str())
            .ok_or_else(|| anyhow!("the demo's WebView has no DevTools page"))?;
        Cdp::connect(ws).await
    }
}

async fn list_targets(port: u16) -> Result<Vec<serde_json::Value>> {
    reqwest::get(format!("http://127.0.0.1:{port}/json"))
        .await
        .context("listing DevTools targets")?
        .json()
        .await
        .context("reading DevTools targets")
}

/// One `DevTools` protocol session. Each request carries an id its reply
/// quotes, and each wait for a reply is bounded by [`CDP_REPLY`].
struct Cdp {
    socket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    next_id: u64,
}

impl Cdp {
    async fn connect(url: &str) -> Result<Self> {
        let (socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .context("opening the DevTools session")?;
        Ok(Self { socket, next_id: 0 })
    }

    /// Evaluate `expression` in the page and return its value.
    async fn evaluate(&mut self, expression: &str) -> Result<serde_json::Value> {
        self.next_id += 1;
        let id = self.next_id;
        let request = serde_json::json!({
            "id": id,
            "method": "Runtime.evaluate",
            "params": { "expression": expression, "returnByValue": true },
        });
        self.socket
            .send(Message::Text(request.to_string()))
            .await
            .context("sending a DevTools request")?;
        let deadline = tokio::time::Instant::now() + CDP_REPLY;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let frame = timeout(remaining, self.socket.next())
                .await
                .map_err(|_| anyhow!("DevTools request {id} got no reply within {CDP_REPLY:?}"))?
                .ok_or_else(|| anyhow!("the DevTools session closed"))?
                .context("reading the DevTools session")?;
            let Message::Text(text) = frame else {
                continue;
            };
            let reply: serde_json::Value =
                serde_json::from_str(&text).context("parsing a DevTools reply")?;
            if reply["id"] == id {
                if let Some(error) = reply.get("error") {
                    bail!("DevTools request {id} failed: {error}");
                }
                return Ok(reply["result"]["result"]["value"].clone());
            }
        }
    }

    async fn page_text(&mut self) -> Result<String> {
        Ok(self
            .evaluate("document.body.innerText")
            .await?
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }

    async fn wait_for_text(&mut self, text: &str, limit: Duration) -> Result<()> {
        self.wait_for_outcome(text, &[], limit).await
    }

    /// Wait until the page shows `text`, failing at once when it shows one of
    /// `refusals` instead.
    async fn wait_for_outcome(
        &mut self,
        text: &str,
        refusals: &[&str],
        limit: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + limit;
        loop {
            let page = self.page_text().await?;
            if page.contains(text) {
                return Ok(());
            }
            if let Some(refusal) = refusals.iter().find(|refusal| page.contains(**refusal)) {
                bail!("the demo showed {refusal:?} rather than {text:?}, it shows:\n{page}");
            }
            if Instant::now() >= deadline {
                bail!("the demo never showed {text:?}, it shows:\n{page}");
            }
            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Click the button labelled `label`.
    async fn click(&mut self, label: &str) -> Result<()> {
        let script = format!(
            "(() => {{ const b = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === {}); if (!b) return false; b.click(); return true; }})()",
            serde_json::Value::String(label.to_owned())
        );
        if self.evaluate(&script).await? == true {
            Ok(())
        } else {
            bail!("the demo has no button {label:?}")
        }
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
