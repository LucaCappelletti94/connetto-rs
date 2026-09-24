//! Where `connetto-ios-signing` keeps the iOS signing identity on a Mac, so
//! the proof driver finds and unlocks the same one.

use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};

/// The keychain holding the signing identity, in `~/Library/Keychains`.
pub const KEYCHAIN: &str = "connetto-signing.keychain-db";

/// The folder holding the signing key, the certificate and the keychain's
/// password.
///
/// # Errors
///
/// When `HOME` is unset.
pub fn folder() -> Result<PathBuf> {
    Ok(home()?.join(".local/share/connetto-r88/signing"))
}

/// The keychain's path.
///
/// # Errors
///
/// When `HOME` is unset.
pub fn keychain() -> Result<PathBuf> {
    Ok(home()?.join("Library/Keychains").join(KEYCHAIN))
}

/// Unlock the signing keychain for this session, so `codesign` can use it
/// from SSH.
///
/// # Errors
///
/// When the password file is missing, which means `connetto-ios-signing` has
/// not run, or the keychain refuses it.
pub async fn unlock() -> Result<()> {
    let password = tokio::fs::read_to_string(folder()?.join("keychain-password"))
        .await
        .context("reading the signing keychain's password, run connetto-ios-signing first")?;
    let output = tokio::process::Command::new("security")
        .args(["unlock-keychain", "-p", password.trim()])
        .arg(keychain()?)
        .output()
        .await
        .context("starting security")?;
    if !output.status.success() {
        bail!(
            "unlocking the signing keychain failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// The SHA-1 of the valid code-signing identity in the keychain, which
/// `dx build --apple-team-id` takes. It is public, the certificate's
/// fingerprint.
///
/// # Errors
///
/// When `security` cannot list the keychain.
pub async fn identity() -> Result<Option<String>> {
    let output = tokio::process::Command::new("security")
        .args(["find-identity", "-v", "-p", "codesigning"])
        .arg(keychain()?)
        .output()
        .await
        .context("starting security")?;
    if !output.status.success() {
        bail!(
            "listing the signing keychain failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let hash = line.split_whitespace().nth(1)?;
            (hash.len() == 40 && hash.chars().all(|c| c.is_ascii_hexdigit()))
                .then(|| hash.to_owned())
        }))
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is unset")
}
