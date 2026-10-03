//! Builds `examples/dioxus-desktop-demo` as a macOS `.app` the data protection
//! keychain admits, so its secrets sit behind Touch ID or the login password
//! (R51).
//!
//! ```text
//! cargo run -p connetto-test-harness --bin connetto-macos-app
//! ```
//!
//! The data protection keychain answers only an app carrying the
//! `keychain-access-groups` entitlement, and macOS kills a signed program
//! claiming it at launch unless an embedded development profile covers both
//! the entitlement and this Mac. `connetto-ios-signing` prepares the signing
//! identity and that profile. This builds the demo with `dx`, embeds the
//! newest profile, signs the bundle with the entitlements the profile allows,
//! verifies the signature, and prints the bundle's path. A build without the
//! profile still runs, with its secrets in the login keychain and its custody
//! reporting no gate.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use connetto_test_harness::ios_signing;
use connetto_test_harness::stack::repo_path;
use tokio::process::Command;

const BUNDLE: &str = "dev.connetto.dioxusdemo";
const PROFILE_NAME: &str = "connetto dioxus demo macos development";
const DEMO_DIR: [&str; 2] = ["examples", "dioxus-desktop-demo"];
const APP: &str =
    "target/dx/connetto-dioxus-desktop-demo/debug/macos/ConnettoDioxusDesktopDemo.app";

#[tokio::main]
async fn main() -> Result<()> {
    let demo = repo_path(&DEMO_DIR)?;
    let status = Command::new("dx")
        .args(["build", "--platform", "desktop"])
        .current_dir(&demo)
        // The bundle's path is this program's only output.
        .stdout(std::process::Stdio::from(std::io::stderr()))
        .status()
        .await
        .context("starting dx")?;
    if !status.success() {
        bail!("dx build exited with {status}");
    }
    let app = demo.join(APP);
    let profile = newest_profile().await?;
    let team = team(&profile).await?;
    tokio::fs::copy(&profile, app.join("Contents/embedded.provisionprofile"))
        .await
        .context("embedding the profile")?;
    let entitlements = std::env::temp_dir().join("connetto-macos-entitlements.plist");
    tokio::fs::write(&entitlements, entitlements_plist(&team))
        .await
        .context("writing the entitlements")?;
    ios_signing::unlock().await?;
    let identity = ios_signing::identity()
        .await?
        .context("the signing keychain holds no identity, run connetto-ios-signing")?;
    let keychain = ios_signing::keychain()?.display().to_string();
    let entitlements = entitlements.display().to_string();
    codesign(
        &[
            "--force",
            "--sign",
            &identity,
            "--keychain",
            &keychain,
            "--entitlements",
            &entitlements,
        ],
        &app,
    )
    .await?;
    codesign(&["--verify", "--deep", "--strict"], &app).await?;
    println!("{}", app.display());
    Ok(())
}

/// The newest development profile covering this Mac, which
/// `connetto-ios-signing` wrote.
async fn newest_profile() -> Result<PathBuf> {
    let folder = PathBuf::from(std::env::var_os("HOME").context("HOME is unset")?)
        .join("Library/Developer/Xcode/UserData/Provisioning Profiles");
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    let mut entries = tokio::fs::read_dir(&folder)
        .await
        .with_context(|| format!("listing {}", folder.display()))?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "provisionprofile")
        {
            continue;
        }
        if read_profile(&path, "Name").await? != PROFILE_NAME {
            continue;
        }
        let modified = entry.metadata().await?.modified()?;
        if newest.as_ref().is_none_or(|(at, _)| modified > *at) {
            newest = Some((modified, path));
        }
    }
    newest
        .map(|(_, path)| path)
        .context("no macOS development profile, run connetto-ios-signing on this Mac")
}

/// The team the profile belongs to.
async fn team(profile: &Path) -> Result<String> {
    let team = read_profile(profile, "Entitlements:com.apple.developer.team-identifier").await?;
    if team.is_empty() {
        bail!("the profile names no team");
    }
    Ok(team)
}

/// One key of a profile's signed plist, through `security` and `PlistBuddy`.
async fn read_profile(profile: &Path, key: &str) -> Result<String> {
    let decoded = Command::new("security")
        .args(["cms", "-D", "-i"])
        .arg(profile)
        .output()
        .await
        .context("starting security")?;
    if !decoded.status.success() {
        bail!("decoding {} failed", profile.display());
    }
    let plist = std::env::temp_dir().join("connetto-macos-profile.plist");
    tokio::fs::write(&plist, &decoded.stdout).await?;
    let value = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", &format!("Print :{key}")])
        .arg(&plist)
        .output()
        .await
        .context("starting PlistBuddy")?;
    Ok(String::from_utf8_lossy(&value.stdout).trim().to_owned())
}

/// The entitlements the profile allows the demo.
fn entitlements_plist(team: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.application-identifier</key>
    <string>{team}.{BUNDLE}</string>
    <key>com.apple.developer.team-identifier</key>
    <string>{team}</string>
    <key>keychain-access-groups</key>
    <array>
        <string>{team}.{BUNDLE}</string>
    </array>
</dict>
</plist>
"#
    )
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
            "codesign {} failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
