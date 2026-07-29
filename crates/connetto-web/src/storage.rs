//! Where the worker's durable databases live, and how a data wipe removes one.
//!
//! One [`ReplicaStorage`] per worker: OPFS through the sahpool VFS is the durable
//! default, and when OPFS is unavailable (a Firefox private window refuses
//! `getDirectory` with a `SecurityError`, for one) the same code runs against the
//! in-memory VFS, so the app boots instead of dying. That session gets no
//! persistence and no cross-window OPFS sharing, but the live topology over
//! `BroadcastChannel` and Web Locks stays intact, and both backends carry the
//! page codec, so the fallback stays encrypted rather than silently degrading.
//!
//! This is a public seam because a data wipe needs it: the browser's replica is
//! not a filesystem path a caller could delete on its own, it is an entry in a
//! VFS pool addressed by name. [`wipe_replica`] is the browser mirror of
//! `connetto_client::teardown::wipe_replica`.
//!
//! There is deliberately no browser `forget_device`, the one convenience the
//! native side offers. Its whole value there is owning the order of a set of
//! steps the application can run itself, and in the browser it could not run the
//! first one: the replica connection lives inside the relay hub's pump for the
//! worker's whole life, so nothing outside `boot_db_worker` can drop it, and a
//! wipe with a live connection to the same name is the one thing this module's
//! delete refuses to survive. A worker-side wipe therefore needs a hub shutdown
//! seam, which does not exist yet. The primitives here are complete and
//! independently usable, and the ordering they encode is documented on each.

use connetto_core::ReplicaKey;

use crate::auth::{AuthError, ReplicaKeyStore};
use connetto_client::cipher::cipher_url;

/// The worker's SQLite storage backend.
///
/// Installing is idempotent: the sahpool VFS registers once per worker and a
/// second [`install`](Self::install) hands back another management handle over
/// the same pool, so a wipe path may install rather than thread the boot's
/// handle through the application.
pub enum ReplicaStorage {
    /// OPFS through the sahpool VFS, the durable default.
    Opfs(sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil),
    /// The in-memory VFS, used only when OPFS is unavailable.
    Memory(sqlite_wasm_rs::MemVfsUtil<sqlite_wasm_rs::WasmOsCallback>),
}

impl ReplicaStorage {
    /// Install OPFS if the browser allows it, otherwise the in-memory VFS
    /// (already registered as the default VFS at SQLite init, so plain file
    /// names resolve to it once sahpool declines to take over the default).
    pub async fn install() -> Self {
        match sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
            &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
            true,
        )
        .await
        {
            Ok(util) => Self::Opfs(util),
            Err(err) => {
                web_sys::console::warn_1(
                    &format!(
                        "db worker: OPFS unavailable ({err:?}), using an in-memory replica: no persistence and no cross-window OPFS sharing this session"
                    )
                    .into(),
                );
                Self::Memory(sqlite_wasm_rs::MemVfsUtil::new())
            }
        }
    }

    /// Whether a database file of this name already exists in the backend.
    #[must_use]
    pub fn exists(&self, name: &str) -> bool {
        match self {
            Self::Opfs(util) => util.exists(name).unwrap_or(false),
            Self::Memory(util) => util.exists(name),
        }
    }

    /// Every database name this backend currently holds.
    ///
    /// A wipe proves itself with this: the claim is that a name is gone and a
    /// second identity's is not, which is a statement about the pool rather than
    /// about what a delete returned.
    #[must_use]
    pub fn list(&self) -> Vec<String> {
        match self {
            Self::Opfs(util) => util.list(),
            Self::Memory(util) => util.list(),
        }
    }

    /// The name SQLite resolves to this backend's VFS.
    #[must_use]
    pub const fn vfs_name(&self) -> &'static str {
        match self {
            Self::Opfs(_) => "opfs-sahpool",
            Self::Memory(_) => "memvfs",
        }
    }

    /// The database URL that opens `name` in this backend, encrypted or not.
    ///
    /// A plaintext database opens under its bare name, which resolves through
    /// whichever VFS is the default. An encrypted one must name the codec shim
    /// over this backend's VFS explicitly, because the codec intercepts as a VFS
    /// layer: a bare name would open the real VFS with no codec in the stack, and
    /// `PRAGMA key` would have nothing to talk to. Both backends are covered, so
    /// the OPFS-unavailable fallback stays encrypted too.
    #[must_use]
    pub fn db_url(&self, name: &str, encrypted: bool) -> String {
        if encrypted {
            cipher_url(name, self.vfs_name())
        } else {
            name.to_owned()
        }
    }

    /// Delete the database `name` and any journal or WAL sidecar it left, by
    /// name, touching nothing else in the pool.
    ///
    /// **Every connection to `name` must be dropped first.** `sqlite-wasm-rs`
    /// allows one connection per database and the sahpool VFS keys its open-file
    /// bookkeeping by name, so a second live handle trips a `debug_assert` rather
    /// than reporting an error. Dropping is enough and needs no await: the
    /// sahpool sync access handle is released synchronously when the connection
    /// drops, with the codec shim in the stack.
    ///
    /// A name that is not in the pool is not an error, so the call is idempotent.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the backend refuses a delete.
    pub fn delete_db(&self, name: &str) -> Result<(), AuthError> {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let entry = format!("{name}{suffix}");
            match self {
                Self::Opfs(util) => {
                    util.delete_db(&entry)
                        .map_err(|err| AuthError::Store(format!("delete {entry}: {err:?}")))?;
                }
                Self::Memory(util) => util.delete_db(&entry),
            }
        }
        Ok(())
    }
}

/// Failure to wipe a browser replica.
#[derive(Debug, thiserror::Error)]
pub enum WipeError {
    /// The replica still holds unsynced mutations and `force` was not set, so
    /// the wipe is refused rather than silently discarding them.
    #[error("wipe blocked: {} unsynced mutation(s) would be lost", .0.len())]
    Unsynced(Vec<u64>),
    /// Destroying the replica's key-store record failed, so the ciphertext is
    /// not crypto-shredded.
    #[error("wipe key store error: {0}")]
    KeyStore(String),
    /// Deleting the replica from the storage backend failed.
    #[error("wipe storage error: {0}")]
    Storage(String),
}

/// Data teardown: destroy the replica's key, then delete the replica.
///
/// The browser mirror of `connetto_client::teardown::wipe_replica`, and the
/// crypto-shredding half of the logout grid. Deleting the pool entry alone
/// leaves recoverable ciphertext behind, and destroying the key alone leaves an
/// entry nothing can open, so the two are one primitive.
///
/// `name` is both the pool entry and the key-store record, which is the value
/// `connetto_client::replica_db_name` produced for this identity. Only that entry
/// and that record are touched, so a second identity signed in on the same device
/// keeps its replica and its key.
///
/// The key goes first, so a failed delete leaves inert ciphertext rather than a
/// readable database.
///
/// Blocks on `unsynced`: when it is non-empty and `force` is false nothing is
/// destroyed. Pass the connection's `unsynced` captured before the connection was
/// dropped, and drop it before calling, since a live connection to `name` makes
/// the delete unsafe.
///
/// # Errors
///
/// [`WipeError::Unsynced`] when unsynced writes remain and `force` is false,
/// [`WipeError::KeyStore`] when the record cannot be cleared, or
/// [`WipeError::Storage`] when the delete fails.
pub async fn wipe_replica(
    storage: &ReplicaStorage,
    key_store: &ReplicaKeyStore,
    name: &str,
    unsynced: &[u64],
    force: bool,
) -> Result<(), WipeError> {
    if !unsynced.is_empty() && !force {
        return Err(WipeError::Unsynced(unsynced.to_vec()));
    }
    key_store
        .clear(name)
        .await
        .map_err(|err| WipeError::KeyStore(err.to_string()))?;
    storage
        .delete_db(name)
        .map_err(|err| WipeError::Storage(err.to_string()))
}

/// The key-store record holding this device's own key, the one that is not
/// addressed by an identity.
///
/// A derived replica name is always a prefix followed by a hash, so it can never
/// collide with this literal.
const DEVICE_KEY_RECORD: &str = "connetto-device-key";

/// This device's own key, minted on first use and cached like a replica key.
///
/// Distinct from a per-replica key in what it is addressed by, not in how it is
/// kept: a replica key is named after an identity, and this one cannot be,
/// because it protects the store that has to be read *before* any identity is
/// known. The refresh store is exactly that case.
///
/// # Errors
///
/// [`AuthError::Store`] if the key store cannot be read or written, or
/// [`AuthError::Context`] if the platform RNG fails.
pub async fn device_key(key_store: &ReplicaKeyStore) -> Result<ReplicaKey, AuthError> {
    crate::auth::provision_replica_key(key_store, DEVICE_KEY_RECORD).await
}

/// Destroy this device's own key, which crypto-shreds the refresh store.
///
/// Part of credential teardown rather than data teardown, and safe to leave in
/// place: the refresh store holds a rotating, server-revocable credential, so
/// clearing the store is what ends the session and this only makes the leftover
/// bytes inert. A later boot mints a fresh device key and starts a fresh store.
///
/// # Errors
///
/// [`AuthError::Store`] if the key store cannot be cleared.
pub async fn clear_device_key(key_store: &ReplicaKeyStore) -> Result<(), AuthError> {
    key_store.clear(DEVICE_KEY_RECORD).await
}
