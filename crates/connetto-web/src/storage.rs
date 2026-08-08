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
use indexed_db_futures::database::Database as IdbDatabase;
use indexed_db_futures::prelude::*;
use indexed_db_futures::transaction::TransactionMode;
use wasm_bindgen::JsValue;

use crate::auth::AuthError;
use connetto_client::cipher::cipher_url;
use connetto_core::traits::ReplicaKeyStore;

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
                tracing::warn!(
                    error = ?err,
                    "db worker: OPFS unavailable, using an in-memory replica with no persistence \
                     and no cross-window OPFS sharing this session"
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

    /// The database URL that opens `name` in this backend.
    ///
    /// Always the codec shim over this backend's VFS, named explicitly, because
    /// the codec intercepts as a VFS layer: a bare name would open the real VFS
    /// with no codec in the stack and `PRAGMA key` would have nothing to talk to.
    /// Both backends are covered, so the OPFS-unavailable fallback stays
    /// encrypted too.
    #[must_use]
    pub fn db_url(&self, name: &str) -> String {
        cipher_url(name, self.vfs_name())
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

    /// Grow the pool so it can hold `headroom` files beyond the ones it holds now.
    ///
    /// The sahpool hands out a fixed number of preallocated slots, six by
    /// default, and its open path is synchronous, so it cannot grow itself when
    /// the last one goes: the open past it fails with `unable to open database
    /// file` rather than waiting for room. Nothing frees a slot on its own,
    /// because every account that signs in leaves a replica and the
    /// device-private database beside it, both kept deliberately so switching
    /// back resumes rather than re-snapshots. So the count grows with the number
    /// of accounts and the default runs out on the third.
    ///
    /// Reserve before opening anything, and count a rollback journal as a file:
    /// the pool gives it a slot of its own and a write cannot proceed without
    /// one, so a database that is written to costs two. Over-reserve rather than
    /// under, because a spare slot is an empty file and running out inside a
    /// worker is a boot that dies with a string nobody reads. The in-memory
    /// backend has no such limit and this does nothing there.
    ///
    /// # Errors
    ///
    /// [`AuthError::Store`] if the backend refuses to grow.
    pub async fn reserve(&self, headroom: u32) -> Result<(), AuthError> {
        let Self::Opfs(util) = self else {
            return Ok(());
        };
        let held = u32::try_from(self.list().len()).unwrap_or(u32::MAX);
        let want = held.saturating_add(headroom);
        let have = util.get_capacity();
        if want > have {
            util.add_capacity(want - have)
                .await
                .map_err(|err| AuthError::Store(format!("grow the pool to {want}: {err:?}")))?;
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

/// The device-private database that sits beside the replica `name`.
///
/// Derived rather than configured, so its name and the key it is opened under
/// have one scope. The key is the replica's own, minted per identity, and the
/// replica name already carries that identity, so computing one from the other
/// is what makes a second identity on the same device open a file it can
/// actually unlock. A name the application chose could not track the identity
/// without being told about it.
///
/// Two consequences the derivation buys rather than enforces. There is no second
/// prefix, so no configuration can collide the two files. And a caller holding
/// only the replica name can reach the tier, which is what lets
/// [`wipe_replica`] destroy both from the one name its pending-delete record
/// keeps.
#[must_use]
pub fn tier_db_name(replica: &str) -> String {
    format!("{replica}-tier")
}

/// Data teardown: destroy the replica's key, then delete the replica and the
/// device-private database beside it.
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
/// The tier goes too, at [`tier_db_name`], because it shares the key being
/// destroyed and has no record of its own. Left behind it would outlive the key
/// that opens it, and the next boot for this identity would mint a fresh key,
/// meet the surviving file and fail to unlock it.
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
/// [`WipeError::Storage`] when either delete fails.
pub async fn wipe_replica<S>(
    storage: &ReplicaStorage,
    key_store: &S,
    name: &str,
    unsynced: &[u64],
    force: bool,
) -> Result<(), WipeError>
where
    S: ReplicaKeyStore<Error = AuthError>,
{
    if !unsynced.is_empty() && !force {
        return Err(WipeError::Unsynced(unsynced.to_vec()));
    }
    key_store
        .clear(name)
        .await
        .map_err(|err| WipeError::KeyStore(err.to_string()))?;
    storage
        .delete_db(&tier_db_name(name))
        .map_err(|err| WipeError::Storage(err.to_string()))?;
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
pub async fn device_key<S>(key_store: &S) -> Result<ReplicaKey, AuthError>
where
    S: ReplicaKeyStore<Error = AuthError>,
{
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
pub async fn clear_device_key<S>(key_store: &S) -> Result<(), AuthError>
where
    S: ReplicaKeyStore<Error = AuthError>,
{
    key_store.clear(DEVICE_KEY_RECORD).await
}

/// `IndexedDB` database naming replicas a wipe has been asked for but not yet
/// performed. Its own database rather than a third store in the key store's,
/// so no key-store version bump and no two record kinds in one object store.
const WIPE_DB: &str = "connetto-pending-wipes";
/// The object store holding one record per replica name awaiting a wipe.
const WIPE_STORE: &str = "pending";

/// Open (creating if needed) the pending-wipe database.
async fn pending_wipes() -> Result<IdbDatabase, AuthError> {
    IdbDatabase::open(WIPE_DB)
        .with_version(1u8)
        .with_on_upgrade_needed(|_event, db| {
            db.create_object_store(WIPE_STORE).build()?;
            Ok(())
        })
        .await
        .map_err(|err| AuthError::Store(format!("open the pending-wipe store: {err}")))
}

/// Record that the replica `name` must be wiped before it is next opened, and
/// refuse when that would discard unsynced writes.
///
/// This exists because a browser wipe cannot happen where the application asks
/// for it. The replica connection lives inside the relay hub's pump for the DB
/// worker's whole life, and the OPFS delete cannot run while a connection to that
/// name is live, so the wipe is deferred to the next boot, where nothing is open
/// yet. [`boot_db_worker`](crate::workers::boot_db_worker) performs it before it
/// opens anything, and the marker survives a reload, so a tab closing mid-wipe
/// leaves the wipe to happen on the boot after that rather than half done.
///
/// **The unsynced guard lives here, and it has to.** At boot the replica is closed
/// and its pending mutations are unreadable, so nothing there can distinguish a
/// clean replica from one with queued writes. Here the connection is still open
/// and the credential still works, which is the one moment the queued writes could
/// still be uploaded. Pass the connection's `unsynced` and only set `force` when
/// the user has been told what is being discarded.
///
/// Marking twice is the same as marking once.
///
/// # Errors
///
/// [`WipeError::Unsynced`] when unsynced writes remain and `force` is false, or
/// [`WipeError::KeyStore`] when the marker cannot be written.
pub async fn mark_wipe_pending(name: &str, unsynced: &[u64], force: bool) -> Result<(), WipeError> {
    if !unsynced.is_empty() && !force {
        return Err(WipeError::Unsynced(unsynced.to_vec()));
    }
    let db = pending_wipes()
        .await
        .map_err(|err| WipeError::KeyStore(err.to_string()))?;
    let tx = db
        .transaction(WIPE_STORE)
        .with_mode(TransactionMode::Readwrite)
        .build()
        .map_err(|err| WipeError::KeyStore(format!("mark tx: {err}")))?;
    let store = tx
        .object_store(WIPE_STORE)
        .map_err(|err| WipeError::KeyStore(format!("mark store: {err}")))?;
    store
        .put(JsValue::from_str(name))
        .with_key(name)
        .primitive()
        .map_err(|err| WipeError::KeyStore(format!("mark put: {err}")))?
        .await
        .map_err(|err| WipeError::KeyStore(format!("mark put await: {err}")))?;
    tx.commit()
        .await
        .map_err(|err| WipeError::KeyStore(format!("mark commit: {err}")))
}

/// Every replica name with a wipe outstanding, clearing the records as it reports
/// them.
///
/// Deliberately not addressed by name, and this is the whole point of the design.
/// Each record already carries the name it refers to, so nothing about acting on it
/// needs an identity, which means the wipe can happen at the very start of a boot,
/// before any login. A version of this that looked up one name would only fire on
/// a boot where that same person logged in again, so someone who asked for a wipe
/// and never came back would keep their data, and a different person logging in on
/// the same device would leave the first person's data untouched. Neither is what
/// "delete my data" means.
///
/// Taken rather than read, so a wipe that has been carried out is not repeated on
/// the boot after it. The caller performs the wipe after this returns: if it fails,
/// the record is already gone and a later boot would open a replica the user asked
/// to destroy, so treat a failed wipe as fatal to the boot rather than logging past
/// it.
///
/// # Errors
///
/// [`AuthError::Store`] when the records cannot be read or cleared.
pub async fn take_pending_wipes() -> Result<Vec<String>, AuthError> {
    let db = pending_wipes().await?;
    let tx = db
        .transaction(WIPE_STORE)
        .with_mode(TransactionMode::Readwrite)
        .build()
        .map_err(|err| AuthError::Store(format!("take tx: {err}")))?;
    let store = tx
        .object_store(WIPE_STORE)
        .map_err(|err| AuthError::Store(format!("take store: {err}")))?;
    // The listing arrives as an iterator of fallible conversions, since each key
    // comes back as a JS value.
    let pending: Vec<String> = store
        .get_all_keys::<String>()
        .primitive()
        .map_err(|err| AuthError::Store(format!("take list: {err}")))?
        .await
        .map_err(|err| AuthError::Store(format!("take list await: {err}")))?
        .collect::<Result<Vec<String>, _>>()
        .map_err(|err| AuthError::Store(format!("take list decode: {err}")))?;
    for name in &pending {
        store
            .delete(name.as_str())
            .primitive()
            .map_err(|err| AuthError::Store(format!("take delete: {err}")))?
            .await
            .map_err(|err| AuthError::Store(format!("take delete await: {err}")))?;
    }
    tx.commit()
        .await
        .map_err(|err| AuthError::Store(format!("take commit: {err}")))?;
    Ok(pending)
}
