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
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// The linked SQLite carries no page codec, so an encrypted database is not
    /// merely unreadable, it is impossible. This is a build or deployment fault
    /// rather than a runtime condition, and it is checked because the failure it
    /// replaces is silent: in a codec-less SQLite `PRAGMA key` is an
    /// unrecognised pragma, which succeeds and leaves every page in the clear.
    #[error(
        "this build links a SQLite with no page codec, so it cannot open an encrypted database"
    )]
    CodecMissing,
    /// Applying the key, or selecting the cipher scheme, failed outright.
    #[error("applying the replica key failed: {0}")]
    Pragma(diesel::result::Error),
    /// The key was accepted syntactically but does not decrypt this file, so the
    /// first read of the schema failed. A wrong key and a corrupt file are
    /// indistinguishable to the codec, by design.
    #[error("the replica key does not decrypt this file: {0}")]
    WrongKey(diesel::result::Error),
    /// Another connection held the file locked for longer than the open waits,
    /// so nothing is known about the key and the open may simply be retried.
    #[error("another connection holds the replica locked: {0}")]
    Busy(diesel::result::Error),
}

/// How long opening a replica waits for another connection's lock.
pub(crate) const BUSY_WAIT: core::time::Duration = core::time::Duration::from_secs(5);

/// The pause between two attempts while the file is locked.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
const BUSY_POLL: core::time::Duration = core::time::Duration::from_millis(10);

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
/// [`UnlockError::Pragma`] when a pragma is rejected,
/// [`UnlockError::Busy`] when another connection holds the file locked for
/// longer than five seconds, and [`UnlockError::WrongKey`] when the file does
/// not decrypt.
pub fn unlock(conn: &mut SqliteConnection, key: &ReplicaKey) -> Result<(), UnlockError> {
    unlock_within(conn, key, BUSY_WAIT)
}

/// [`unlock`], waiting at most `wait` for another connection's lock.
fn unlock_within(
    conn: &mut SqliteConnection,
    key: &ReplicaKey,
    wait: core::time::Duration,
) -> Result<(), UnlockError> {
    codec_present(conn)?;

    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    conn.batch_execute(CIPHER_PRAGMAS)
        .map_err(UnlockError::Pragma)?;

    conn.batch_execute(unlock_statement(key).as_str())
        .map_err(UnlockError::Pragma)?;

    // SQLite runs the handler only on `SQLITE_BUSY`, the one way to tell a lock from a wrong key here.
    let busy = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    conn.on_busy(busy_handler(std::sync::Arc::clone(&busy), wait));
    // The codec only reports a bad key on the first read of a real page. An
    // empty new database passes trivially, which is correct: there is nothing
    // yet to decrypt.
    let probed = conn.batch_execute("SELECT count(*) FROM sqlite_schema;");
    keep_waiting(conn, wait);
    probed.map_err(|err| {
        if busy.load(core::sync::atomic::Ordering::Relaxed) {
            UnlockError::Busy(err)
        } else {
            UnlockError::WrongKey(err)
        }
    })
}

/// A busy handler that records it ran and retries until `wait` has passed.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn busy_handler(
    busy: std::sync::Arc<core::sync::atomic::AtomicBool>,
    wait: core::time::Duration,
) -> impl FnMut(i32) -> diesel::sqlite::BusyDecision + Send + 'static {
    let attempts = wait.as_millis() / BUSY_POLL.as_millis();
    move |retries| {
        busy.store(true, core::sync::atomic::Ordering::Relaxed);
        if u128::try_from(retries).unwrap_or(u128::MAX) < attempts {
            std::thread::sleep(BUSY_POLL);
            diesel::sqlite::BusyDecision::Retry
        } else {
            diesel::sqlite::BusyDecision::GiveUp
        }
    }
}

/// A busy handler that records it ran and gives up at once, since a browser worker cannot block.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
fn busy_handler(
    busy: std::sync::Arc<core::sync::atomic::AtomicBool>,
    _wait: core::time::Duration,
) -> impl FnMut(i32) -> diesel::sqlite::BusyDecision + Send + 'static {
    move |_| {
        busy.store(true, core::sync::atomic::Ordering::Relaxed);
        diesel::sqlite::BusyDecision::GiveUp
    }
}

/// Replace the probe's handler with a plain timeout, so the open's later statements wait the same way.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn keep_waiting(conn: &mut SqliteConnection, wait: core::time::Duration) {
    conn.set_busy_timeout(i32::try_from(wait.as_millis()).unwrap_or(i32::MAX));
}

/// Drop the probe's handler, since a browser worker cannot block on a lock.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
fn keep_waiting(conn: &mut SqliteConnection, _wait: core::time::Duration) {
    conn.remove_busy_handler();
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

    /// A file another connection holds locked past the wait is reported busy, never as a key that does not decrypt.
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    #[test]
    fn a_locked_replica_is_busy_and_opens_once_released() {
        use diesel::Connection as _;

        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("replica.db");
        let url = path.to_str().expect("utf-8 path");
        let key = ReplicaKey::from_bytes([0x5a; ReplicaKey::LEN]);
        let mut holder = SqliteConnection::establish(url).expect("open the holder");
        unlock(&mut holder, &key).expect("unlock the holder");
        holder
            .batch_execute("CREATE TABLE t (id INTEGER PRIMARY KEY); BEGIN EXCLUSIVE;")
            .expect("hold the file locked");

        let mut opener = SqliteConnection::establish(url).expect("open the second connection");
        let refused = unlock_within(&mut opener, &key, core::time::Duration::from_millis(50));
        assert!(
            matches!(refused, Err(UnlockError::Busy(_))),
            "a locked file is busy, got {refused:?}"
        );

        holder.batch_execute("COMMIT;").expect("release the lock");
        let mut opener = SqliteConnection::establish(url).expect("open again");
        unlock_within(&mut opener, &key, core::time::Duration::from_millis(50))
            .expect("the released file opens under its key");
    }
}
