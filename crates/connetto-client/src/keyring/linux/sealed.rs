//! Secrets sealed with XChaCha20-Poly1305 under a 32-byte wrap key, one file
//! per record (R71 decisions 4, 11 and 13).
//!
//! A record's file name is the SHA-256 of its store's service and its record
//! name, and that name is the associated data, so a file renamed onto another
//! record's name, or read by another store, fails to open.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::ClientError;
use crate::keyring::SecretStoreError;

/// The length of a wrap key.
pub(super) const WRAP_KEY_LEN: usize = 32;
/// The first bytes of every record file.
const MAGIC: &[u8] = b"CNTS\x01";
const NONCE_LEN: usize = 24;
/// Held exclusively around every change, so a reseal never overwrites a newer write.
const LOCK: &str = ".lock";
/// Marks a record file not yet renamed into place.
const TEMPORARY: &str = ".tmp-";

/// The wrap key in the file at `path`.
pub(super) fn read_wrap_key(path: &Path) -> Result<Zeroizing<[u8; WRAP_KEY_LEN]>, ClientError> {
    let bytes =
        Zeroizing::new(fs::read(path).map_err(|err| io("reading the wrap key", path, &err))?);
    let key: [u8; WRAP_KEY_LEN] =
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| SecretStoreError::WrapKeyLength {
                path: path.to_owned(),
                len: bytes.len(),
            })?;
    Ok(Zeroizing::new(key))
}

pub(super) struct Sealed {
    dir: PathBuf,
    current: XChaCha20Poly1305,
    previous: Option<XChaCha20Poly1305>,
    previous_needed: bool,
}

impl Sealed {
    /// The records in `dir`, resealing any still under `previous` (decision 13).
    pub(super) fn open(
        dir: PathBuf,
        current: &[u8; WRAP_KEY_LEN],
        previous: Option<&[u8; WRAP_KEY_LEN]>,
    ) -> Result<Self, ClientError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|err| io("creating the state directory", &dir, &err))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|err| io("closing the state directory", &dir, &err))?;
        let mut sealed = Self {
            dir,
            current: XChaCha20Poly1305::new(current.into()),
            previous: previous.map(|key| XChaCha20Poly1305::new(key.into())),
            previous_needed: false,
        };
        let _lock = sealed.lock()?;
        sealed.previous_needed = sealed.sweep()?;
        Ok(sealed)
    }

    /// Whether a record still opens only under the previous key.
    pub(super) const fn previous_key_needed(&self) -> bool {
        self.previous_needed
    }

    pub(super) fn read(
        &self,
        service: &str,
        name: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ClientError> {
        let stem = stem(service, name);
        let _lock = self.lock()?;
        let path = self.dir.join(&stem);
        let blob = match fs::read(&path) {
            Ok(blob) => blob,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(io("reading a sealed record", &path, &err)),
        };
        if let Some(secret) = unseal(&self.current, &stem, &blob) {
            return Ok(Some(secret));
        }
        let Some(secret) = self
            .previous
            .as_ref()
            .and_then(|previous| unseal(previous, &stem, &blob))
        else {
            return Err(SecretStoreError::Unsealable { record: stem }.into());
        };
        self.put(&stem, &secret)?;
        Ok(Some(secret))
    }

    pub(super) fn write(
        &self,
        service: &str,
        name: &str,
        secret: &[u8],
    ) -> Result<(), ClientError> {
        let _lock = self.lock()?;
        self.put(&stem(service, name), secret)
    }

    pub(super) fn clear(&self, service: &str, name: &str) -> Result<(), ClientError> {
        let _lock = self.lock()?;
        let path = self.dir.join(stem(service, name));
        match fs::remove_file(&path) {
            Ok(()) => self.sync_dir(),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(io("removing a sealed record", &path, &err)),
        }
    }

    /// Drops files a crash left before their rename and reseals records still
    /// under the previous key, answering whether a reseal failed and left one
    /// under it.
    fn sweep(&self) -> Result<bool, ClientError> {
        let entries = fs::read_dir(&self.dir)
            .map_err(|err| io("listing the state directory", &self.dir, &err))?;
        let mut left_under_previous = false;
        for entry in entries {
            let entry = entry.map_err(|err| io("listing the state directory", &self.dir, &err))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name.contains(TEMPORARY) {
                fs::remove_file(entry.path())
                    .map_err(|err| io("removing a stale record", &entry.path(), &err))?;
                continue;
            }
            let Some(previous) = &self.previous else {
                continue;
            };
            if !is_stem(&name) {
                continue;
            }
            let blob = fs::read(entry.path())
                .map_err(|err| io("reading a sealed record", &entry.path(), &err))?;
            if unseal(&self.current, &name, &blob).is_some() {
                continue;
            }
            if let Some(secret) = unseal(previous, &name, &blob) {
                // A failed reseal leaves the record readable under the previous key, which the report says.
                left_under_previous |= self.put(&name, &secret).is_err();
            }
        }
        Ok(left_under_previous)
    }

    /// Writes `secret` under the current key through a temporary file and a rename.
    fn put(&self, stem: &str, secret: &[u8]) -> Result<(), ClientError> {
        let mut nonce = [0_u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|err| SecretStoreError::Backend(format!("platform RNG: {err}")))?;
        let sealed = self
            .current
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: stem.as_bytes(),
                },
            )
            .map_err(|_| SecretStoreError::Backend("sealing a record failed".to_owned()))?;
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix)
            .map_err(|err| SecretStoreError::Backend(format!("platform RNG: {err}")))?;
        let temporary = self.dir.join(format!("{stem}{TEMPORARY}{}", hex(&suffix)));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|err| io("creating a sealed record", &temporary, &err))?;
        file.write_all(MAGIC)
            .and_then(|()| file.write_all(&nonce))
            .and_then(|()| file.write_all(&sealed))
            .and_then(|()| file.sync_all())
            .map_err(|err| io("writing a sealed record", &temporary, &err))?;
        let path = self.dir.join(stem);
        fs::rename(&temporary, &path)
            .map_err(|err| io("replacing a sealed record", &path, &err))?;
        self.sync_dir()
    }

    fn sync_dir(&self) -> Result<(), ClientError> {
        File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|err| io("syncing the state directory", &self.dir, &err))
    }

    fn lock(&self) -> Result<File, ClientError> {
        let path = self.dir.join(LOCK);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|err| io("opening the state lock", &path, &err))?;
        file.lock()
            .map_err(|err| io("locking the state directory", &path, &err))?;
        Ok(file)
    }
}

fn unseal(cipher: &XChaCha20Poly1305, stem: &str, blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let rest = blob.strip_prefix(MAGIC)?;
    let (nonce, sealed) = rest.split_at_checked(NONCE_LEN)?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: stem.as_bytes(),
            },
        )
        .ok()
        .map(Zeroizing::new)
}

/// A record's file name, from its store's service and its record name.
pub(super) fn stem(service: &str, name: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(
        u64::try_from(service.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(service.as_bytes());
    digest.update(name.as_bytes());
    hex(&digest.finalize())
}

fn is_stem(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn io(what: &str, path: &Path, err: &std::io::Error) -> ClientError {
    SecretStoreError::Backend(format!("{what} {}: {err}", path.display())).into()
}
