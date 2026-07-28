//! Phase E0 de-risking spike for connetto replica encryption at rest.
//!
//! The plan of record in `docs/handoff-auth-at-rest-encryption.md` proposed a
//! hand-written synchronous page-encrypting VFS layered over the OPFS sahpool
//! VFS, doing AES-GCM with `RustCrypto`. This spike takes the alternative the
//! same document recorded as unverified, an off-the-shelf `SQLCipher` page
//! codec, and establishes that it exists and works on both backends:
//!
//! - Native, the codec is `SQLCipher` 3.50.4, vendored by `libsqlite3-sys` under
//!   its `bundled-sqlcipher` feature and linked in place of the vanilla
//!   amalgamation diesel would otherwise compile.
//! - In the browser, the codec is `SQLite3` Multiple Ciphers 2.3.3, vendored by
//!   `sqlite-wasm-rs` under its `sqlite3mc` feature. That is the same crate
//!   `connetto-web` already links, so the feature unifies with diesel's own
//!   wasm SQLite dependency and one C library is built. It reproduces the
//!   native page layout exactly, but only once pinned by [`CIPHER_PRAGMAS`].
//!
//! Both are page codecs, not VFS layers, so neither needs a fork of
//! `sqlite-wasm-vfs`, neither needs a nonce scheme invented here, and neither
//! needs a single line of `unsafe` in this crate (`unsafe_code` stays at
//! `forbid`). In the browser the codec composes with sahpool through a URI:
//! opening `file:<name>?vfs=multipleciphers-opfs-sahpool` makes SQLite build
//! the codec shim over the already registered `opfs-sahpool` VFS.
//!
//! The construction both sides run is `SQLCipher` version 4: AES-256-CBC with a
//! fresh 16-byte random IV generated on every single page write, plus a
//! 64-byte HMAC-SHA512 over the ciphertext, the IV, and the page number. Both
//! live in the 80 reserved bytes at the end of each page, which SQLite itself
//! accounts for, so no header page is added and no offset is remapped. Page 1
//! carries a 16-byte random salt in the clear, and nothing else is plaintext.
//! Rewriting a page in place therefore never reuses an IV, which is the
//! failure mode a page-number-derived nonce would have.
//!
//! The key is supplied in memory as 32 raw bytes and applied through the raw
//! key form of `PRAGMA key`, which skips the passphrase KDF over the page key:
//! a server-provisioned key is already uniformly random, so stretching it
//! would buy nothing and cost every cold start.

use diesel::connection::SimpleConnection;
use std::fmt::Write as _;
use zeroize::{Zeroize, Zeroizing};

/// The name SQLite resolves to the browser OPFS sahpool VFS.
pub const SAHPOOL_VFS: &str = "opfs-sahpool";

/// The VFS-name prefix `SQLite3` Multiple Ciphers recognises. Opening a database
/// under `<PREFIX>-<real vfs>` builds the codec shim over that real VFS.
pub const CIPHER_VFS_PREFIX: &str = "multipleciphers";

/// A per-replica page-encryption key: 32 raw bytes, never a passphrase.
///
/// The bytes are wiped when the key is dropped. This is custody hygiene, not a
/// defence against a resident in-process attacker, who can drive the open
/// connection anyway.
pub struct ReplicaKey([u8; Self::LEN]);

impl ReplicaKey {
    /// Length of the raw key in bytes, fixed by the AES-256 page cipher.
    pub const LEN: usize = 32;

    /// Take ownership of raw key bytes.
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The `PRAGMA key` statement that unlocks a connection with this key.
    ///
    /// The hex literal form (`x'...'`) with exactly 64 digits is `SQLCipher`'s
    /// raw key form: the bytes are used as the page key directly.
    fn unlock_statement(&self) -> Zeroizing<String> {
        let mut statement = Zeroizing::new(String::with_capacity(32 + Self::LEN * 2));
        statement.push_str("PRAGMA key = \"x'");
        for byte in self.0 {
            let _ = write!(&mut *statement, "{byte:02x}");
        }
        statement.push_str("'\";");
        statement
    }
}

impl Drop for ReplicaKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for ReplicaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReplicaKey(<redacted>)")
    }
}

/// Why unlocking a replica failed.
#[derive(Debug)]
pub enum UnlockError {
    /// Applying the key, or selecting the cipher scheme, failed outright.
    Pragma(diesel::result::Error),
    /// The key was accepted syntactically but does not decrypt this file, so
    /// the first read of the schema failed. A wrong key and a corrupt file are
    /// indistinguishable to the codec, which is by design.
    WrongKey(diesel::result::Error),
}

impl std::fmt::Display for UnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pragma(err) => write!(f, "applying the replica key failed: {err}"),
            Self::WrongKey(err) => write!(f, "the replica key does not decrypt this file: {err}"),
        }
    }
}

impl std::error::Error for UnlockError {}

/// The pragmas that pin the browser codec to the construction the native codec
/// already implements.
///
/// `SQLite3` Multiple Ciphers defaults to ChaCha20-Poly1305, so the scheme has to
/// be named. Naming it is not enough: its own `sqlcipher` scheme defaults to a
/// non-legacy variant that leaves the first 24 bytes of page 1 in the clear
/// rather than `SQLCipher`'s 16, and that variant cannot read a real `SQLCipher`
/// file. `legacy = 4` selects the byte-compatible `SQLCipher` version 4 layout.
///
/// The native codec is `SQLCipher` itself and needs no pinning, so [`unlock`]
/// applies these only on wasm.
pub const CIPHER_PRAGMAS: &str = "PRAGMA cipher = 'sqlcipher'; PRAGMA legacy = 4;";

/// Apply `key` to a freshly established connection and prove it decrypts.
///
/// This must be the first statement run against the connection: any statement
/// that reads the schema before the key is set fails on an encrypted file.
/// Diesel's `establish` only registers SQL functions, so it is safe to call
/// straight after.
pub fn unlock<C>(conn: &mut C, key: &ReplicaKey) -> Result<(), UnlockError>
where
    C: SimpleConnection,
{
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    conn.batch_execute(CIPHER_PRAGMAS)
        .map_err(UnlockError::Pragma)?;

    conn.batch_execute(key.unlock_statement().as_str())
        .map_err(UnlockError::Pragma)?;

    // The codec only reports a bad key on the first read of a real page.
    conn.batch_execute("SELECT count(*) FROM sqlite_schema;")
        .map_err(UnlockError::WrongKey)
}

/// The database URL that opens `name` through the `SQLCipher` codec layered over
/// the browser OPFS sahpool VFS.
///
/// SQLite builds the shim on demand while parsing this URI, so the sahpool VFS
/// only has to be installed first, under its usual name.
pub fn sahpool_cipher_url(name: &str) -> String {
    format!("file:{name}?vfs={CIPHER_VFS_PREFIX}-{SAHPOOL_VFS}")
}
