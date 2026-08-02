//! The page codec that makes a local database ciphertext at rest.
//!
//! connetto does not implement encryption. It states, at every connect, whether
//! the database it is about to open holds encrypted pages, and hands the key to
//! an off-the-shelf codec compiled into the SQLite it links. Natively that codec
//! is `SQLCipher`, vendored by `libsqlite3-sys` under `bundled-sqlcipher`. In the
//! browser it is `SQLite3` Multiple Ciphers, vendored by `sqlite-wasm-rs` under
//! `sqlite3mc`. Both are page codecs rather than VFS layers, so neither needs a
//! nonce scheme invented here and neither needs a line of `unsafe`.
//!
//! The construction is `SQLCipher` version 4 on both sides: AES-256-CBC per page
//! with a fresh 16-byte random IV on every page write, plus a 64-byte
//! HMAC-SHA512, both living in the 80 reserved bytes per page that SQLite itself
//! accounts for. No header page is added and no offset is remapped. Page 1
//! carries a 16-byte random per-database salt in the clear and nothing else.
//! Rewriting a page in place therefore never reuses an IV, which is the failure
//! a page-number-derived nonce would have caused.
//!
//! The key is supplied as 32 raw bytes through the `x'...'` form of `PRAGMA key`,
//! which skips the passphrase KDF over the page key: a server-provisioned key is
//! already uniformly random, so stretching it would buy nothing and cost every
//! cold start.
//!
//! Scope of protection, stated plainly because the alternative is theatre. The
//! codec is synchronous C in the same address space as the application, so the
//! raw key is in memory for the life of the connection. This does not defend
//! against an attacker already resident in the process, who can drive the open
//! connection anyway, and it does not separate accounts on one device, which is
//! the operating system's user boundary. It defends the at-rest, off-device and
//! post-logout cases: a copied file, a recovered disk, a backup already taken.

use diesel::SqliteConnection;
use diesel::connection::SimpleConnection;
use std::fmt::Write as _;
use zeroize::Zeroizing;

/// The per-replica key, re-exported from `connetto-core` so a caller building a
/// [`Replica`](crate::replica::Replica) needs one import rather than two
/// matching crate versions.
pub use connetto_core::ReplicaKey;

/// The VFS-name prefix `SQLite3` Multiple Ciphers recognises. Opening a database
/// under `<PREFIX>-<real vfs>` builds the codec shim over that real VFS.
///
/// Browser only, and mandatory there: the codec intercepts through a VFS shim,
/// so a plain file name opens the real VFS with no codec in the stack and
/// `PRAGMA key` has nothing to talk to. Compose the URL with [`cipher_url`].
pub const CIPHER_VFS_PREFIX: &str = "multipleciphers";

/// The pragmas that pin the browser codec to the construction the native codec
/// already implements.
///
/// `SQLite3` Multiple Ciphers defaults to ChaCha20-Poly1305, so the scheme has
/// to be named. Naming it is not enough: its own `sqlcipher` scheme defaults to
/// a non-legacy variant that leaves the first 24 bytes of page 1 in the clear
/// rather than `SQLCipher`'s 16, and that variant cannot read a real `SQLCipher`
/// file. `legacy = 4` selects the byte-compatible layout, which phase E0 proved
/// by having the browser codec read a file the native codec wrote.
///
/// The native codec is `SQLCipher` itself and needs no pinning, so [`unlock`]
/// applies these only on wasm.
pub const CIPHER_PRAGMAS: &str = "PRAGMA cipher = 'sqlcipher'; PRAGMA legacy = 4;";

/// Why applying a cipher to a connection failed.
#[derive(Debug)]
pub enum UnlockError {
    /// The linked SQLite carries no page codec, so an encrypted database is not
    /// merely unreadable, it is impossible. This is a build or deployment fault
    /// rather than a runtime condition, and it is checked because the failure it
    /// replaces is silent: in a codec-less SQLite `PRAGMA key` is an
    /// unrecognised pragma, which succeeds and leaves every page in the clear.
    CodecMissing,
    /// Applying the key, or selecting the cipher scheme, failed outright.
    Pragma(diesel::result::Error),
    /// The key was accepted syntactically but does not decrypt this file, so the
    /// first read of the schema failed. A wrong key and a corrupt file are
    /// indistinguishable to the codec, by design.
    WrongKey(diesel::result::Error),
}

impl std::fmt::Display for UnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CodecMissing => f.write_str(
                "this build links a SQLite with no page codec, so it cannot open an encrypted database",
            ),
            Self::Pragma(err) => write!(f, "applying the replica key failed: {err}"),
            Self::WrongKey(err) => write!(f, "the replica key does not decrypt this file: {err}"),
        }
    }
}

impl std::error::Error for UnlockError {}

/// Apply `key` to a freshly established connection and prove it decrypts.
///
/// This must be the first statement run against the connection. Anything that
/// reads the database header, `PRAGMA journal_mode` included, fails on an
/// encrypted file before the key is set. Diesel's `establish` only registers SQL
/// functions and never reads the schema, so straight after it is both safe and
/// the last safe moment.
///
/// # Errors
///
/// [`UnlockError::CodecMissing`] when no page codec is linked,
/// [`UnlockError::Pragma`] when a pragma is rejected, and
/// [`UnlockError::WrongKey`] when the file does not decrypt.
pub fn unlock(conn: &mut SqliteConnection, key: &ReplicaKey) -> Result<(), UnlockError> {
    codec_present(conn)?;

    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    conn.batch_execute(CIPHER_PRAGMAS)
        .map_err(UnlockError::Pragma)?;

    conn.batch_execute(unlock_statement(key).as_str())
        .map_err(UnlockError::Pragma)?;

    // The codec only reports a bad key on the first read of a real page. An
    // empty new database passes trivially, which is correct: there is nothing
    // yet to decrypt.
    conn.batch_execute("SELECT count(*) FROM sqlite_schema;")
        .map_err(UnlockError::WrongKey)
}

/// The `PRAGMA key` statement that unlocks a connection with `key`.
///
/// The hex literal form (`x'...'`) with exactly 64 digits is the raw key form:
/// the bytes become the page key directly, with no KDF. The rendered statement
/// is wiped when it drops, so the material does not linger in the allocator.
fn unlock_statement(key: &ReplicaKey) -> Zeroizing<String> {
    let mut statement = Zeroizing::new(String::with_capacity(20 + ReplicaKey::LEN * 2));
    statement.push_str("PRAGMA key = \"x'");
    for byte in key.as_bytes() {
        let _ = write!(&mut *statement, "{byte:02x}");
    }
    statement.push_str("'\";");
    statement
}

/// The database URL that opens `name` through the page codec layered over the
/// already installed browser VFS `vfs`.
///
/// SQLite builds the codec shim on demand while parsing this URI, so `vfs` only
/// has to be registered first, under its usual name (`opfs-sahpool` for OPFS,
/// `memvfs` for the in-memory fallback). A plaintext database needs no URL and
/// opens under its bare name.
#[must_use]
pub fn cipher_url(name: &str, vfs: &str) -> String {
    format!("file:{name}?vfs={CIPHER_VFS_PREFIX}-{vfs}")
}

/// Prove a page codec is actually linked, so [`ReplicaCipher::Encrypted`] cannot
/// quietly degrade to plaintext.
///
/// The two codecs answer different probes, and each probe is chosen so that a
/// codec-less SQLite fails it rather than passing by silence.
///
/// Natively, `SQLCipher` patches `PRAGMA cipher_version` into the pragma parser
/// and returns its version under a column of that name. Vanilla SQLite ignores
/// the unknown pragma and returns no row at all, so an absent row is the answer.
///
/// In the browser, `SQLite3` Multiple Ciphers handles its pragmas through the
/// VFS shim's file control, which reports a rejected value as a statement error.
/// A cipher name it does not know is therefore an error when the codec is in the
/// stack and silence when it is not, so this probe succeeds only when the pragma
/// fails.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn codec_present(conn: &mut SqliteConnection) -> Result<(), UnlockError> {
    use diesel::RunQueryDsl as _;

    /// The single text column `PRAGMA cipher_version` returns.
    #[derive(diesel::QueryableByName)]
    struct CipherVersion {
        #[diesel(sql_type = diesel::sql_types::Text)]
        #[diesel(column_name = cipher_version)]
        version: String,
    }

    // A vendor pragma has no typed DSL form, which is the one case the raw
    // query escape hatch exists for. Nothing here is a schema reference.
    let probe: Vec<CipherVersion> = diesel::sql_query("PRAGMA cipher_version")
        .load(conn)
        .map_err(UnlockError::Pragma)?;
    if probe.iter().any(|row| !row.version.is_empty()) {
        Ok(())
    } else {
        Err(UnlockError::CodecMissing)
    }
}

/// See the native twin of this function for why the browser probe is inverted.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
fn codec_present(conn: &mut SqliteConnection) -> Result<(), UnlockError> {
    // A name no cipher registry can hold, so the only way this succeeds is that
    // nothing was listening.
    if conn
        .batch_execute("PRAGMA cipher = 'connetto-codec-probe';")
        .is_err()
    {
        Ok(())
    } else {
        Err(UnlockError::CodecMissing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unlock_statement_is_the_raw_hex_key_form() {
        let mut bytes = [0u8; ReplicaKey::LEN];
        bytes[0] = 0x0a;
        bytes[ReplicaKey::LEN - 1] = 0xff;
        let rendered = unlock_statement(&ReplicaKey::from_bytes(bytes));
        // One hex pair per key byte and nothing else inside `x'...'`, which is
        // what selects the raw key form over the passphrase KDF. The middle is
        // built by repetition so the digit count is expressed, not typed.
        assert_eq!(
            rendered.as_str(),
            format!(
                "PRAGMA key = \"x'0a{}ff'\";",
                "00".repeat(ReplicaKey::LEN - 2)
            ),
        );
        assert_eq!(
            rendered.len(),
            "PRAGMA key = \"x''\";".len() + ReplicaKey::LEN * 2
        );
    }

    #[test]
    fn a_cipher_url_names_the_codec_shim_over_the_real_vfs() {
        assert_eq!(
            cipher_url("replica.sqlite", "opfs-sahpool"),
            "file:replica.sqlite?vfs=multipleciphers-opfs-sahpool"
        );
        assert_eq!(
            cipher_url("replica.sqlite", "memvfs"),
            "file:replica.sqlite?vfs=multipleciphers-memvfs"
        );
    }
}
