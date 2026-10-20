//! The Android phone the proofs drive over `adb` (R76): its `adb` calls,
//! screen and page, the system's dialog taps, its Bluetooth and networks,
//! and the sign-in that leaves its demo page open. The two-phone proof and
//! the handheld star (R76 slice 9f) share it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::process::Command;
use tokio::time::{Instant, sleep, timeout};

use crate::inspector::{PageSession, list_pages};

/// The package that holds the browser role, so the demo's login page opens
/// in it, which the run restores.
pub const BROWSER: &str = "com.android.chrome";
/// The app role the demo's login page asks for, held by the browser for the
/// run and returned after.
pub const BROWSER_ROLE: &str = "android.app.role.BROWSER";
/// The global setting `svc power stayon` writes.
pub const STAY_ON: &str = "stay_on_while_plugged_in";
/// The global setting that, when nonzero, keeps crash and freeze dialogs off
/// the screen.
pub const HIDE_ERROR_DIALOGS: &str = "hide_error_dialogs";
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
/// The unlock prompt's switch from the fingerprint sensor to the PIN pad in
/// the runner's locales, which a run given the PIN taps on a phone with a
/// fingerprint enrolled.
pub const PIN_FALLBACK_BUTTONS: [&str; 3] = ["Use PIN", "Usa PIN", "PIN verwenden"];
/// The Bluetooth enable dialog's refusal in the runner's locales, which a
/// host whose beacon stays down taps (R76 decision 21).
pub const DENY_BUTTONS: [&str; 6] = [
    "Deny",
    "Don't allow",
    "Rifiuta",
    "Non consentire",
    "Ablehnen",
    "Nicht zulassen",
];
/// The Bluetooth permissions the beacon and the joined-network sockets ask
/// for (R76).
pub const BT_PERMISSIONS: [&str; 3] = [
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
];

/// The device port the demo's WebSocket dials, removed to take it offline.
pub const SYNC_PORT: u16 = 7777;

/// The bound of one adb command's child wait, which a hung adb must not
/// outlive.
const ADB_COMMAND_BOUND: Duration = Duration::from_secs(60);
/// The bound of the commands that wait on the device itself, the install and
/// the wait-for-device after a server restart.
const ADB_DEVICE_WAIT_BOUND: Duration = Duration::from_secs(120);

/// The bound of the adb command `args` name, which the device's own bound
/// covers.
fn adb_bound(args: &[&str], command_within: Duration) -> Duration {
    match args.first().copied() {
        Some("install" | "wait-for-device") => ADB_DEVICE_WAIT_BOUND,
        _ => command_within,
    }
}

/// Run `command` with its child wait bounded at `bound`, the child killed on
/// the timeout, so a hung adb never stalls the run.
async fn bounded_output(
    command: &mut Command,
    bound: Duration,
    what: &str,
) -> Result<std::process::Output> {
    let command = command.kill_on_drop(true);
    match timeout(bound, command.output()).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(err)) => bail!("{what} did not start: {err}"),
        Err(_) => bail!("{what} outlived its bound of {bound:?}"),
    }
}

/// [`bounded_output`] for a command whose only result is its exit status.
async fn bounded_status(
    command: &mut Command,
    bound: Duration,
    what: &str,
) -> Result<std::process::ExitStatus> {
    let command = command.kill_on_drop(true);
    match timeout(bound, command.status()).await {
        Ok(Ok(status)) => Ok(status),
        Ok(Err(err)) => bail!("{what} did not start: {err}"),
        Err(_) => bail!("{what} outlived its bound of {bound:?}"),
    }
}

/// The demo the proof deploys on the phone, `dioxus` (the default) or `tauri`
/// (`examples/tauri-leptos-demo`).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Demo {
    /// The Dioxus demo, the default.
    #[default]
    Dioxus,
    /// The Tauri demo.
    Tauri,
}

impl Demo {
    /// The command line's spelling of the demo.
    ///
    /// # Errors
    ///
    /// When the name is neither demo.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "dioxus" => Ok(Self::Dioxus),
            "tauri" => Ok(Self::Tauri),
            other => bail!("unknown app {other}, expected dioxus or tauri"),
        }
    }

    /// The demo's Android package.
    pub fn package(self) -> &'static str {
        match self {
            Self::Dioxus => "dev.connetto.dioxusdemo",
            Self::Tauri => "dev.connetto.tauridemo",
        }
    }

    /// The demo's launch activity.
    pub fn activity(self) -> &'static str {
        match self {
            Self::Dioxus => "dev.dioxus.main.MainActivity",
            Self::Tauri => "dev.connetto.tauridemo.MainActivity",
        }
    }
}
/// The Android phone over `adb`, its screen, its pages and its dialogs.
pub struct Device {
    /// The phone's `adb` serial.
    pub serial: String,
    /// The `adb` program, a stand-in under test.
    pub(crate) program: PathBuf,
    /// How long a device that dropped offline gets to come back.
    pub(crate) recover_within: Duration,
    /// The bound of one of its adb commands' child waits.
    pub(crate) command_within: Duration,
    /// The demo the run deployed, which names its package and activity.
    pub(crate) demo: Demo,
    /// The browser targets [`Device::login_tab`] returned. A finished login's
    /// tab can stay listed on the authorize URL while it closes, so a later
    /// login must never pick it again.
    spent_tabs: parking_lot::Mutex<Vec<String>>,
}

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

    pub(crate) fn with_adb(
        serial: String,
        demo: Demo,
        program: PathBuf,
        recover_within: Duration,
        command_within: Duration,
    ) -> Self {
        Self {
            serial,
            program,
            recover_within,
            command_within,
            demo,
            spent_tabs: parking_lot::Mutex::default(),
        }
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

    /// Runs `adb -s SERIAL args`, and once more after reconnecting when the
    /// device had dropped offline, which an emulator's transport does under load.
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails or exceeds its deadline.
    pub async fn adb(&self, args: &[&str]) -> Result<String> {
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
        let what = format!("adb -s {} {}", self.serial, args.join(" "));
        bounded_output(
            Command::new(&self.program)
                .arg("-s")
                .arg(&self.serial)
                .args(args),
            adb_bound(args, self.command_within),
            &what,
        )
        .await
    }

    /// Resets offline transports and waits, up to the bound, for the device to answer.
    async fn reconnect(&self) -> Result<()> {
        // A failed reset still leaves the state poll below to decide.
        let _ = bounded_status(
            Command::new(&self.program).args(["reconnect", "offline"]),
            self.command_within,
            "adb reconnect offline",
        )
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
            .element_bounds(&PIN_FALLBACK_BUTTONS, true)
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

    /// A matching UI element's bounds, optionally requiring it to be clickable.
    async fn element_bounds(
        &self,
        labels: &[&str],
        require_clickable: bool,
    ) -> Result<Option<(i32, i32, i32, i32)>> {
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
            if require_clickable && attribute(node, "clickable").as_deref() != Some("true") {
                continue;
            }
            let bounds = attribute(node, "bounds")
                .and_then(|bounds| parse_bounds(&bounds))
                .ok_or_else(|| anyhow!("the UI element {text:?} has no bounds"))?;
            return Ok(Some(bounds));
        }
        Ok(None)
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

/// Comma-separated `device:host` port pairs.
///
/// # Errors
///
/// Returns an error if a pair is missing its separator or contains an invalid port.
pub fn parse_reverse(spec: &str) -> Result<Vec<(u16, u16)>> {
    spec.split(',')
        .map(|pair| {
            let (device, host) = pair
                .split_once(':')
                .ok_or_else(|| anyhow!("{pair} is not device:host"))?;
            Ok((device.parse()?, host.parse()?))
        })
        .collect()
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

/// Whether the events buffer shows `activity` destroyed and then created
/// again in process `pid`.
pub fn rebuilt_in(events: &str, pid: &str, activity: &str) -> bool {
    let in_process = |line: &&str| {
        line.split_whitespace().nth(2) == Some(pid) && line.contains(&format!(",{activity},"))
    };
    let mut lines = events.lines().filter(in_process);
    lines.any(|line| line.contains("wm_on_destroy_called:"))
        && lines.any(|line| line.contains("wm_on_create_called:"))
}

/// A UI dump's `name` attribute, entity-decoded.
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
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::{Demo, Device, parse_current_ssid, rebuilt_in, saved_network_id};

    /// A stand-in `adb` that runs `body` with `$state` naming a scratch directory.
    fn fake_adb(dir: &Path, body: &str) -> PathBuf {
        use std::io::Write as _;
        let path = dir.join("adb");
        // Single-quoted, so a path with spaces or shell characters stays one
        // word, and each quote inside it closes, escapes and reopens.
        let state = dir.display().to_string().replace('\'', r"'\''");
        let script =
            format!("#!/bin/sh\nstate='{state}'\necho \"$*\" >>\"$state/calls\"\n{body}\n");
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
        let device = Device::with_adb(
            "emulator-5554".to_owned(),
            Demo::Dioxus,
            adb,
            Duration::from_secs(5),
            super::ADB_COMMAND_BOUND,
        );
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
        let device = Device::with_adb(
            "emulator-5554".to_owned(),
            Demo::Dioxus,
            adb,
            Duration::from_secs(5),
            super::ADB_COMMAND_BOUND,
        );
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
        let device = Device::with_adb(
            "emulator-5554".to_owned(),
            Demo::Dioxus,
            adb,
            Duration::from_secs(5),
            super::ADB_COMMAND_BOUND,
        );
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
        let device = Device::with_adb(
            "emulator-5554".to_owned(),
            Demo::Dioxus,
            adb,
            Duration::from_millis(600),
            super::ADB_COMMAND_BOUND,
        );
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
        let device = Device::with_adb(
            "emulator-5554".to_owned(),
            Demo::Dioxus,
            adb,
            Duration::from_secs(5),
            super::ADB_COMMAND_BOUND,
        );
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

    /// A hung adb child is killed at the command's bound, which the run keeps
    /// waiting no longer.
    #[tokio::test]
    async fn a_hung_adb_child_is_killed_at_its_bound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adb = fake_adb(
            dir.path(),
            r#"case "$*" in
  *"get-state"*) sleep 100 ;;
esac
exit 0"#,
        );
        let device = Device::with_adb(
            "emulator-5554".to_owned(),
            Demo::Dioxus,
            adb,
            Duration::from_secs(5),
            Duration::from_millis(300),
        );
        let err = device
            .adb(&["get-state"])
            .await
            .expect_err("a hung adb fails");
        assert!(err.root_cause().to_string().contains("outlived"), "{err:#}");
    }
}
