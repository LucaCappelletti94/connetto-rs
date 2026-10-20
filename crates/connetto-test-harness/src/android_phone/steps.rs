//! The steps a proof takes on a real Android phone over `adb`: its settings
//! and networks, the system dialogs it taps, its Bluetooth, the demo's page
//! and the sign-in. Only a phone reaches them, so coverage leaves this file
//! out, while the `adb` plumbing and the parsing they rest on stay in the
//! parent module under its fake-`adb` tests.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::process::Command;
use tokio::time::{Instant, sleep, timeout};

use super::{
    ADB_COMMAND_BOUND, BROWSER_ROLE, Demo, Device, HIDE_ERROR_DIALOGS, SYNC_PORT, attribute,
    bounded_output, bounded_status, parse_bounds, parse_current_ssid, rebuilt_in, saved_network_id,
};
use crate::inspector::{PageSession, list_pages};

/// Chrome's first-run and permission screens, by resource id so that any
/// device language matches.
const INTERSTITIALS: [&str; 3] = [
    "com.android.chrome:id/signin_fre_dismiss_button",
    "com.android.chrome:id/negative_button",
    "com.android.chrome:id/terms_accept",
];
/// The localized texts of the system's network-approval dialog button, for
/// the locales the proof phones run, which the driver taps in place of the
/// user (R76 decision 16).
const CONNECT_BUTTONS: [&str; 3] = ["Connect", "Connetti", "Verbinden"];

impl Device {
    /// A phone at its `adb` on the `PATH`, with the run's demo.
    pub fn new(serial: String, demo: Demo) -> Self {
        Self::with_adb(
            serial,
            demo,
            PathBuf::from("adb"),
            Duration::from_secs(30),
            ADB_COMMAND_BOUND,
        )
    }

    /// The named device, or the only one attached.
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or no unique authorized device exists.
    pub async fn pick(serial: Option<String>, demo: Demo) -> Result<Self> {
        if let Some(serial) = serial {
            return Ok(Self::new(serial, demo));
        }
        let output = bounded_output(
            Command::new("adb").arg("devices"),
            ADB_COMMAND_BOUND,
            "adb devices",
        )
        .await?;
        let listing = String::from_utf8_lossy(&output.stdout);
        let attached = listing
            .lines()
            .skip(1)
            .filter_map(|line| line.strip_suffix("\tdevice"))
            .collect::<Vec<_>>();
        match attached.as_slice() {
            [serial] => Ok(Self::new((*serial).to_owned(), demo)),
            [] => bail!("no authorised device is attached"),
            _ => bail!("several devices are attached, name one with --serial"),
        }
    }

    /// The Rust target the phone's ABI builds to, for the demo's APK.
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or the ABI is unsupported.
    pub async fn rust_target(&self) -> Result<String> {
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
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or exceeds its deadline.
    pub async fn browser_role_holder(&self) -> Result<Option<String>> {
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
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or exceeds its deadline.
    pub async fn global_setting(&self, name: &str) -> Result<Option<String>> {
        let value = self
            .adb(&["shell", "settings", "get", "global", name])
            .await?;
        Ok(Some(value.trim())
            .filter(|value| *value != "null")
            .map(ToOwned::to_owned))
    }

    /// Put back a global setting read by [`Self::global_setting`].
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or exceeds its deadline.
    pub async fn restore_global_setting(&self, name: &str, value: Option<&str>) -> Result<()> {
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
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or exceeds its deadline.
    pub async fn system_setting(&self, name: &str) -> Result<Option<String>> {
        let value = self
            .adb(&["shell", "settings", "get", "system", name])
            .await?;
        Ok(Some(value.trim())
            .filter(|value| *value != "null")
            .map(ToOwned::to_owned))
    }

    /// Put back a system setting read by [`Self::system_setting`].
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or exceeds its deadline.
    pub async fn restore_system_setting(&self, name: &str, value: Option<&str>) -> Result<()> {
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

    /// Keep crash and freeze dialogs off the screen and close any already
    /// showing.
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or exceeds its deadline.
    pub async fn hide_error_dialogs(&self) -> Result<()> {
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

    /// Make `package` the browser role's holder and check it took.
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or the browser role does not change.
    pub async fn set_browser_role_holder(&self, package: &str) -> Result<()> {
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

    /// Reverse a device port to the host port, so the demo dials the stack
    /// at its own address.
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or exceeds its deadline.
    pub async fn reverse(&self, device_port: u16, host_port: u16) -> Result<()> {
        self.adb(&[
            "reverse",
            &format!("tcp:{device_port}"),
            &format!("tcp:{host_port}"),
        ])
        .await
        .map(drop)
    }

    /// Cut the demo's sync link and keep every other reverse. Removing a
    /// reverse leaves its open streams alone, and the host end of each stream
    /// lives in the adb server, so restarting the server drops them.
    ///
    /// # Errors
    ///
    /// Returns an error if the server restart, reconnection or port reversal fails.
    pub async fn drop_sync_link(&self, reverse: &[(u16, u16)]) -> Result<()> {
        restart_adb_server().await?;
        if self.serial.contains(':') {
            let status = bounded_status(
                Command::new(&self.program).args(["connect", &self.serial]),
                self.command_within,
                &format!("adb connect {}", self.serial),
            )
            .await?;
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

    /// The ssid the device is connected to, which its `dumpsys wifi` names,
    /// and `None` while it names none.
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or exceeds its deadline.
    pub async fn current_ssid(&self) -> Result<Option<String>> {
        let dump = self.adb(&["shell", "dumpsys", "wifi"]).await?;
        Ok(parse_current_ssid(&dump))
    }

    /// Restore a saved Wi-Fi network through Settings and return to the demo within 60 seconds.
    ///
    /// # Errors
    ///
    /// Returns an error if association or returning to the demo fails within its bound.
    pub async fn restore_network(&self, ssid: &str) -> Result<()> {
        enum Stage {
            Network,
            Approval,
            Connecting,
        }

        let mut settings_opened = false;
        let network = timeout(Duration::from_secs(45), async {
            if self.current_ssid().await?.as_deref() == Some(ssid) {
                return Ok(());
            }
            settings_opened = true;
            self.adb(&[
                "shell",
                "am",
                "start",
                "-a",
                "android.settings.WIFI_SETTINGS",
            ])
            .await?;
            let network_label = [ssid];
            let mut stage = Stage::Network;
            loop {
                if self.current_ssid().await?.as_deref() == Some(ssid) {
                    return Ok::<(), anyhow::Error>(());
                }
                let target = match stage {
                    Stage::Network => Some((network_label.as_slice(), false)),
                    Stage::Approval => Some((CONNECT_BUTTONS.as_slice(), true)),
                    Stage::Connecting => None,
                };
                if let Some((labels, clickable)) = target {
                    match self.element_bounds(labels, clickable).await {
                        Ok(Some((left, top, right, bottom))) => {
                            self.adb(&[
                                "shell",
                                "input",
                                "tap",
                                &left.midpoint(right).to_string(),
                                &top.midpoint(bottom).to_string(),
                            ])
                            .await?;
                            stage = if matches!(stage, Stage::Network) {
                                Stage::Approval
                            } else {
                                Stage::Connecting
                            };
                        }
                        Ok(None) => {}
                        Err(err) => eprintln!("the Wi-Fi settings are not readable yet ({err:#})"),
                    }
                }
                sleep(Duration::from_secs(2)).await;
            }
        })
        .await
        .with_context(|| format!("restoring the saved network {ssid}"))
        .and_then(|result| result);
        let foreground = if settings_opened {
            timeout(Duration::from_secs(15), self.launch())
                .await
                .context("returning to the demo after Wi-Fi Settings")
                .and_then(|result| result)
        } else {
            Ok(())
        };
        network.and(foreground)
    }

    /// Forget a saved network profile by its ssid, best effort, since the
    /// platform's one-shot request keeps none of its own.
    ///
    /// # Errors
    ///
    /// Returns an error if listing or removing saved networks fails.
    pub async fn forget_network(&self, ssid: &str) -> Result<()> {
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
    ///
    /// # Errors
    ///
    /// Returns an error if the approval dialog cannot be found or tapped.
    pub async fn tap_connect_button(&self) -> Result<()> {
        self.tap_dialog_button(&CONNECT_BUTTONS, "the network approval's connect button")
            .await
    }

    /// Tap the system's dialog button `labels` name in one of the runner's
    /// locales, waiting for it to show.
    ///
    /// # Errors
    ///
    /// Returns an error if a dialog cannot be read or the button stays absent.
    pub async fn tap_dialog_button(&self, labels: &[&str], what: &str) -> Result<()> {
        let locale = self
            .adb(&["shell", "getprop", "persist.sys.locale"])
            .await?;
        eprintln!("{} runs locale {}", self.serial, locale.trim());
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            // A dump can crash while the screen changes under it, so a failed
            // one waits for the next look.
            match self.element_bounds(labels, true).await {
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

    /// Start the demo's launch activity.
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or exceeds its deadline.
    pub async fn launch(&self) -> Result<()> {
        self.adb(&[
            "shell",
            "am",
            "start",
            "-W",
            "-n",
            &format!("{}/{}", self.demo.package(), self.demo.activity()),
        ])
        .await
        .map(drop)
    }

    /// Whether the keyguard covers the screen.
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or exceeds its deadline.
    pub async fn keyguard_showing(&self) -> Result<bool> {
        let window = self.adb(&["shell", "dumpsys", "window"]).await?;
        Ok(window
            .lines()
            .any(|line| line.trim() == "isKeyguardShowing=true"))
    }

    /// Whether the platform's biometric or credential prompt holds the
    /// screen, which System UI draws in a window of its own.
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or exceeds its deadline.
    pub async fn unlock_prompt_shown(&self) -> Result<bool> {
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

    /// A screenshot of the screen, into the run's evidence.
    ///
    /// # Errors
    ///
    /// Returns an error if screen capture or writing its file fails.
    pub async fn screenshot(&self, dir: &Path, name: &str) -> Result<()> {
        let output = bounded_output(
            Command::new(&self.program).args(["-s", &self.serial, "exec-out", "screencap", "-p"]),
            self.command_within,
            "adb exec-out screencap",
        )
        .await?;
        tokio::fs::write(dir.join(format!("{name}.png")), output.stdout)
            .await
            .context("writing a screenshot")
    }

    /// Forward a free host port to an abstract socket on the device.
    ///
    /// # Errors
    ///
    /// Returns an error if forwarding fails or the returned port is invalid.
    pub async fn forward(&self, socket: &str) -> Result<u16> {
        let port = self
            .adb(&["forward", "tcp:0", &format!("localabstract:{socket}")])
            .await?;
        port.trim()
            .parse()
            .with_context(|| format!("adb forwarded to {port:?}"))
    }

    /// A `DevTools` session on the login tab the demo opened on `issuer`, never
    /// one an earlier call returned, tapping past the browser's first-run
    /// screens while it appears. The forward lives until the run removes every
    /// forward.
    ///
    /// # Errors
    ///
    /// Returns an error if the login page cannot be inspected within its deadline.
    pub async fn login_tab(&self, issuer: &str) -> Result<PageSession> {
        let prefix = format!("{issuer}/authorize?");
        let port = self.forward("chrome_devtools_remote").await?;
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let tabs = list_pages(port).await.unwrap_or_default();
            let fresh = {
                let spent = self.spent_tabs.lock();
                tabs.iter().find_map(|tab| {
                    let id = tab["id"].as_str()?;
                    let url = tab["url"].as_str()?;
                    let ws = tab["webSocketDebuggerUrl"].as_str()?;
                    (url.starts_with(&prefix) && !spent.iter().any(|seen| seen == id))
                        .then(|| (id.to_owned(), ws.to_owned()))
                })
            };
            if let Some((id, ws)) = fresh {
                self.spent_tabs.lock().push(id);
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
    /// until the run removes every forward.
    ///
    /// # Errors
    ///
    /// Returns an error if the application or its inspectable page is unavailable.
    pub async fn app(&self) -> Result<PageSession> {
        let pid = self.adb(&["shell", "pidof", self.demo.package()]).await?;
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

/// Reset the `adb` server, which drops the streams every reverse hosts.
///
/// # Errors
///
/// Returns an error if either server command fails or exceeds its deadline.
pub async fn restart_adb_server() -> Result<()> {
    for command in ["kill-server", "start-server"] {
        let status = bounded_status(
            Command::new("adb").arg(command),
            ADB_COMMAND_BOUND,
            &format!("adb {command}"),
        )
        .await?;
        if !status.success() {
            bail!("adb {command} exited with {status}");
        }
    }
    Ok(())
}

/// The unlock the run answers on the phone's screen, its PIN where the run
/// holds one.
#[derive(Clone, Copy)]
pub struct Unlock<'a> {
    /// The PIN the driver types, for an emulator whose PIN the run knows.
    pub pin: Option<&'a str>,
}

impl Unlock<'_> {
    /// Clear a PIN keyguard, which waking the device leaves up and which hides
    /// every app and browser tab behind it.
    ///
    /// # Errors
    ///
    /// Returns an error if `adb` fails or the keyguard stays locked.
    pub async fn dismiss_keyguard(self, device: &Device) -> Result<()> {
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
    ///
    /// # Errors
    ///
    /// Returns an error if the prompt cannot be captured or approved within its deadline.
    pub async fn approve(self, device: &Device, evidence: &Path, name: &str) -> Result<()> {
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
///
/// # Errors
///
/// Returns an error if the login page cannot accept the input.
pub async fn submit_login(tab: &mut PageSession, user: &str) -> Result<()> {
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

/// Sign the phone in as the user named and wait for it to connect and
/// certify, leaving its app page open. The screenshots take the prefix
/// `shot`, which the caller names after its own role in the run.
///
/// # Errors
///
/// When the login, the connection or the certificate will not stand within
/// their bounds.
pub async fn sign_in_phone(
    phone: &Device,
    user: &str,
    issuer: &str,
    evidence: &Path,
    unlock: Unlock<'_>,
    shot: &str,
) -> Result<PageSession> {
    crate::step(&format!("sign in {user} on {}", phone.serial));
    phone.launch().await?;
    let mut tab = phone.login_tab(issuer).await?;
    phone
        .screenshot(evidence, &format!("{shot}-login-page"))
        .await?;
    submit_login(&mut tab, user).await?;
    drop(tab);
    unlock
        .approve(phone, evidence, &format!("{shot}-launch-unlock"))
        .await?;
    let mut app = phone.app().await?;
    app.wait_for_text("status: connected", Duration::from_secs(90))
        .await?;
    app.wait_for_text("device: certified until", Duration::from_secs(60))
        .await?;
    phone
        .screenshot(evidence, &format!("{shot}-signed-in"))
        .await?;
    Ok(app)
}

/// Forget the hotspot's saved profile on both phones, best effort, and wait
/// for the joiner to fall back to its usual network.
///
/// # Errors
///
/// When the joiner is not back on its usual network within the bound.
pub async fn restore_joiner_networks(
    host: &Device,
    joiner: &Device,
    ssid: &str,
    usual_ssid: Option<&str>,
) -> Result<()> {
    crate::step("clean up the networks");
    // A saved profile the platform may have kept, best effort.
    for phone in [host, joiner] {
        phone.forget_network(ssid).await?;
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let current = joiner.current_ssid().await?;
        if current.as_deref() == usual_ssid {
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
///
/// # Errors
///
/// When Bluetooth will not stand off within the bound.
pub async fn bluetooth_off(device: &Device) -> Result<()> {
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
///
/// # Errors
///
/// When Bluetooth will not stand on within the bound.
pub async fn bluetooth_on(device: &Device) -> Result<()> {
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
///
/// # Errors
///
/// When the beacon never advertises, or its line never carries a prefix.
pub async fn read_beacon(app: &mut PageSession) -> Result<String> {
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

/// The demo's screen destroyed and created again in process `pid` inside
/// `REBUILD_WITHIN`, which a screen rebuild shows in the events buffer.
///
/// # Errors
///
/// When the rebuild never stands within the bound.
pub async fn wait_for_rebuild(device: &Device, pid: &str) -> Result<()> {
    const REBUILD_WITHIN: Duration = Duration::from_secs(30);
    let deadline = Instant::now() + REBUILD_WITHIN;
    loop {
        let events = device.adb(&["logcat", "-b", "events", "-d"]).await?;
        if rebuilt_in(&events, pid, device.demo.activity()) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the demo's screen was not rebuilt in process {pid} within {REBUILD_WITHIN:?}");
        }
        sleep(Duration::from_millis(500)).await;
    }
}
