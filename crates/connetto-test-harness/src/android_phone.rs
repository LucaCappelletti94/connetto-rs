//! The Android phone the proofs drive over `adb` (R76): its `adb` calls,
//! screen and page, the system's dialog taps, its Bluetooth and networks,
//! and the sign-in that leaves its demo page open. The two-phone proof and
//! the handheld star (R76 slice 9f) share it.
//! The phone-only steps live in the `steps` child module.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use tokio::process::Command;
use tokio::time::{Instant, sleep, timeout};

mod steps;

pub use steps::{
    Unlock, bluetooth_off, bluetooth_on, read_beacon, restart_adb_server, restore_joiner_networks,
    sign_in_phone, submit_login, wait_for_rebuild,
};

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

    use super::{Demo, Device, parse_current_ssid, parse_reverse, rebuilt_in, saved_network_id};

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

    #[test]
    fn the_reverse_spec_reads_port_pairs_and_refuses_a_broken_pair() {
        assert_eq!(
            parse_reverse("7777:7777,8080:18080").unwrap(),
            [(7777, 7777), (8080, 18_080)]
        );
        let missing = parse_reverse("7777:7777,8080").unwrap_err();
        assert_eq!(missing.to_string(), "8080 is not device:host");
        assert!(
            parse_reverse("7777:70000").is_err(),
            "a port past u16 is refused"
        );
    }

    #[test]
    fn each_demo_name_picks_its_own_package_and_activity() {
        let tauri = Demo::parse("tauri").unwrap();
        assert_eq!(tauri.package(), "dev.connetto.tauridemo");
        assert_eq!(tauri.activity(), TAURI_ACTIVITY);
        let dioxus = Demo::parse("dioxus").unwrap();
        assert_eq!(dioxus.package(), "dev.connetto.dioxusdemo");
        assert_eq!(dioxus.activity(), "dev.dioxus.main.MainActivity");
        let unknown = Demo::parse("yew")
            .err()
            .expect("an unknown demo is refused");
        assert!(unknown.to_string().contains("yew"));
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
