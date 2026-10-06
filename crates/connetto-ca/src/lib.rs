#![doc = include_str!("../README.md")]

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use connetto_core::device_cert::layout::{
    ISSUER_CERTIFICATE, ISSUER_KEY, ROOT_CERTIFICATE, ROOT_LIST,
};
use connetto_core::device_cert::{
    DeploymentId, IssuerError, ListError, RevocationList, Revoked, RootCa, RootError,
    certificate_serial, verify_signer,
};
use pkcs8::{EncryptedPrivateKeyInfo, PrivateKeyInfo};
use rand_core::{OsRng, RngCore as _};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData as _};
use zeroize::Zeroizing;

/// The root key, PKCS #8 encrypted under the operator's passphrase.
pub const ROOT_KEY: &str = "root.key.p8e";

/// How long a root lasts (R74 decision 14).
pub const ROOT_VALIDITY: Duration = Duration::from_hours(24 * 365 * 10);
/// How long an issuer lasts, a year plus the default certificate ceiling, so
/// the last certificates it signs stay checkable (R74 decision 14).
pub const ISSUER_VALIDITY: Duration = Duration::from_hours(24 * (365 + 30));

/// Why a ceremony failed.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    /// A file the ceremony would write already exists.
    #[error("{} already exists, refusing to overwrite it", .0.display())]
    Exists(PathBuf),
    /// The passphrase does not open the root key.
    #[error("the passphrase does not open the root key")]
    Passphrase,
    /// The root key file is not encrypted PKCS #8.
    #[error("the root key file is not an encrypted PKCS #8 key")]
    RootKey,
    /// The root certificate or its key were refused.
    #[error(transparent)]
    Root(#[from] RootError),
    /// The issuer just signed failed the server's own checks.
    #[error(transparent)]
    Issuer(#[from] IssuerError),
    /// Generating or parsing a key failed.
    #[error("the key could not be generated or parsed")]
    Key(#[from] rcgen::Error),
    /// Encrypting the root key failed.
    #[error("the root key could not be encrypted")]
    Encrypt(#[source] pkcs8::Error),
    /// The issuer to revoke was not signed by this root.
    #[error("the issuer was not signed by this root")]
    NotThisRootsIssuer,
    /// The issuer is already on the root's list.
    #[error("the issuer is already revoked")]
    AlreadyRevoked,
    /// The list could not be read back or signed.
    #[error(transparent)]
    List(#[from] ListError),
    /// Reading or writing a file failed.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The failure.
        source: std::io::Error,
    },
}

/// Create the deployment's root in `dir`, valid from `now` for [`ROOT_VALIDITY`].
///
/// # Errors
///
/// [`CaError::Exists`] when `dir` already holds a root, or the error of a
/// step that failed.
pub fn init(dir: &Path, passphrase: &str, now: SystemTime) -> Result<DeploymentId, CaError> {
    let certificate_path = dir.join(ROOT_CERTIFICATE);
    let key_path = dir.join(ROOT_KEY);
    refuse_existing(&[&certificate_path, &key_path])?;
    let deployment = DeploymentId::from_uuid(uuid::Uuid::new_v4());
    let root = RootCa::create(deployment, now, ROOT_VALIDITY)?;
    let encrypted = PrivateKeyInfo::try_from(root.private_key_der().as_slice())
        .and_then(|info| info.encrypt(OsRng, passphrase.as_bytes()))
        .map_err(CaError::Encrypt)?;
    write_new(&[
        (&key_path, encrypted.as_bytes(), true),
        (&certificate_path, root.certificate(), false),
    ])?;
    Ok(deployment)
}

/// Sign a new issuer with the root in `ca_dir` and write it to `out_dir`,
/// valid from `now` for [`ISSUER_VALIDITY`].
///
/// # Errors
///
/// [`CaError::Passphrase`] when the passphrase does not open the root key,
/// [`CaError::Exists`] when `out_dir` already holds an issuer, or the error
/// of a step that failed.
pub fn sign_issuer(
    ca_dir: &Path,
    passphrase: &str,
    out_dir: &Path,
    now: SystemTime,
) -> Result<(), CaError> {
    let certificate_path = out_dir.join(ISSUER_CERTIFICATE);
    let key_path = out_dir.join(ISSUER_KEY);
    refuse_existing(&[&certificate_path, &key_path])?;
    let root = open_root(ca_dir, passphrase)?;
    let issuer_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut serial = [0_u8; 16];
    OsRng.fill_bytes(&mut serial);
    let certificate = root.sign_issuer(
        &issuer_key.subject_public_key_info(),
        now,
        ISSUER_VALIDITY,
        serial,
    )?;
    let key_der = Zeroizing::new(issuer_key.serialize_der());
    connetto_core::device_cert::DeviceIssuer::new(
        certificate.clone(),
        KeyPair::try_from(key_der.as_slice())?,
        root.certificate(),
    )?;
    write_new(&[
        (&key_path, &key_der, true),
        (&certificate_path, &certificate, false),
    ])
}

/// Add the issuer whose certificate is at `issuer` to the root's list in
/// `ca_dir`, revoked at `now`, and sign the complete list under the next
/// number, replacing [`ROOT_LIST`]. The list promises its next within
/// [`ISSUER_VALIDITY`], the longest any issuer it names lives.
///
/// # Errors
///
/// [`CaError::Passphrase`] when the passphrase does not open the root key,
/// [`CaError::NotThisRootsIssuer`] for an issuer another root signed,
/// [`CaError::AlreadyRevoked`] for one already listed, or the error of a
/// step that failed.
pub fn revoke_issuer(
    ca_dir: &Path,
    passphrase: &str,
    issuer: &Path,
    now: SystemTime,
) -> Result<(), CaError> {
    let root = open_root(ca_dir, passphrase)?;
    let issuer = read(issuer)?;
    let roots = [root.certificate().to_vec()];
    match verify_signer(&issuer, &roots) {
        Ok(()) if issuer.as_slice() != root.certificate() => {}
        Ok(()) | Err(ListError::Untrusted) => return Err(CaError::NotThisRootsIssuer),
        Err(other) => return Err(other.into()),
    }
    let serial = certificate_serial(&issuer)?;
    let path = ca_dir.join(ROOT_LIST);
    let (number, mut revoked) = if path.exists() {
        let kept = RevocationList::verify(&read(&path)?, root.certificate(), &roots)?;
        (kept.number(), kept.revoked().to_vec())
    } else {
        (0, Vec::new())
    };
    if revoked.iter().any(|entry| entry.serial == serial) {
        return Err(CaError::AlreadyRevoked);
    }
    revoked.push(Revoked { serial, at: now });
    let list = root.sign_list(number + 1, &revoked, now, now + ISSUER_VALIDITY)?;
    // Written beside, then moved over, so a failed write keeps the old list.
    let staged = ca_dir.join(format!("{ROOT_LIST}.new"));
    let _ = std::fs::remove_file(&staged);
    write_new(&[(&staged, &list, false)])?;
    std::fs::rename(&staged, &path).map_err(|source| CaError::Io { path, source })
}

/// Open the root in `dir` with the operator's passphrase.
fn open_root(dir: &Path, passphrase: &str) -> Result<RootCa, CaError> {
    let certificate = read(&dir.join(ROOT_CERTIFICATE))?;
    let stored = read(&dir.join(ROOT_KEY))?;
    let encrypted =
        EncryptedPrivateKeyInfo::try_from(stored.as_slice()).map_err(|_| CaError::RootKey)?;
    let key_der = encrypted
        .decrypt(passphrase.as_bytes())
        .map_err(|_| CaError::Passphrase)?;
    let key = KeyPair::try_from(key_der.as_bytes())?;
    Ok(RootCa::from_parts(certificate, key)?)
}

fn refuse_existing(paths: &[&Path]) -> Result<(), CaError> {
    match paths.iter().find(|path| path.exists()) {
        Some(path) => Err(CaError::Exists(path.to_path_buf())),
        None => Ok(()),
    }
}

fn read(path: &Path) -> Result<Vec<u8>, CaError> {
    std::fs::read(path).map_err(|source| CaError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Write each `(path, bytes, private)` as a new file, a private one readable
/// by its owner only, removing what was written if a later file fails.
fn write_new(files: &[(&Path, &[u8], bool)]) -> Result<(), CaError> {
    for (index, (path, bytes, private)) in files.iter().enumerate() {
        if let Err(source) = write_one(path, bytes, *private) {
            for (written, _, _) in &files[..index] {
                let _ = std::fs::remove_file(written);
            }
            return Err(CaError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    Ok(())
}

fn write_one(path: &Path, bytes: &[u8], private: bool) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests;
