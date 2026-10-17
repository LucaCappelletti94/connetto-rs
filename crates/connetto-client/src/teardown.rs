//! Teardown primitives: the two axes of logout, and the offline-expiry warning.
//!
//! Logout is two orthogonal choices, and connetto ships mechanisms rather than
//! policy (see `docs/architecture/11-authentication.md`). Credential teardown is
//! [`NativeAuthenticator::logout`](crate::auth::NativeAuthenticator::logout):
//! revoke the session and clear the stored refresh token. Data teardown is
//! [`wipe_replica`]: delete the replica and destroy its key, which crypto-shreds
//! it so any ciphertext a forensic recovery turns up is inert. The application
//! composes the two behind its own prompt, or runs both under one guard with
//! [`NativeClient::forget_device`](crate::NativeClient::forget_device).
//!
//! Keeping both the credential and the data is not a logout at all, it is a lock
//! or an app close, and connetto does nothing durable there.
//!
//! Every destructive primitive here refuses to discard unsynced writes unless
//! forced. That guard is meaningful at exactly one moment, logout, when the
//! user's own credential still works and the queued writes could still be
//! uploaded. It is deliberately not copied to triggers where it cannot help: an
//! account switch deletes nothing at all.
//!
//! Two data-loss edges are honest rather than guarded. A device offline past its
//! whole session length is made loud by [`expiry_warning`], which prompts before
//! the lapse. An undecryptable replica
//! ([`ClientError::ReplicaUndecryptable`](crate::ClientError::ReplicaUndecryptable))
//! keeps its pending mutations inside the file the key will not open, so they are
//! unreadable and already lost, and no guard can pretend otherwise: the
//! documented recovery is [`purge_replica`] with `force`.

use crate::UnsyncedWrite;
use std::time::{Duration, SystemTime};

/// A proactive warning that the local session is near its end while local work
/// remains, so a teardown now would lose it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryWarning {
    /// When the session (refresh-token lifetime) lapses if never refreshed.
    pub session_expires_at: SystemTime,
    /// The unsynced (writer, sequence) pairs at risk.
    pub unsynced: Vec<UnsyncedWrite>,
    /// Additional local items at risk outside the mutation queue.
    pub additional_pending: u64,
}

impl ExpiryWarning {
    /// Counts every local item at risk.
    #[must_use]
    pub fn pending_count(&self) -> u64 {
        u64::try_from(self.unsynced.len())
            .unwrap_or(u64::MAX)
            .saturating_add(self.additional_pending)
    }
}

/// Warns near session expiry when mutations or additional local work remain.
#[must_use]
pub fn expiry_warning(
    now: SystemTime,
    session_expires_at: SystemTime,
    lead: Duration,
    unsynced: Vec<UnsyncedWrite>,
    additional_pending: u64,
) -> Option<ExpiryWarning> {
    if unsynced.is_empty() && additional_pending == 0 {
        return None;
    }
    let warn_from = session_expires_at
        .checked_sub(lead)
        .unwrap_or(session_expires_at);
    (now >= warn_from).then_some(ExpiryWarning {
        session_expires_at,
        unsynced,
        additional_pending,
    })
}

/// Failure to purge a replica.
#[cfg(feature = "native-transport")]
#[derive(Debug, thiserror::Error)]
pub enum PurgeError {
    /// The replica still holds unsynced mutations and `force` was not set, so
    /// the purge is refused rather than silently discarding them.
    #[error("purge blocked: {} unsynced mutation(s) would be lost", .0.len())]
    Unsynced(Vec<UnsyncedWrite>),
    /// Deleting a replica file failed.
    #[error("purge io error: {0}")]
    Io(String),
    /// Destroying the replica's key-store record failed, so the ciphertext is
    /// not crypto-shredded. Only `wipe_replica` raises this.
    #[error("purge key store error: {0}")]
    KeyStore(String),
}

/// The directory holding this replica's content chunks, beside the replica at
/// `db_path` and named by derivation, where R69 builds its `FsStore`.
#[cfg(feature = "native-transport")]
#[must_use]
pub fn content_dir(db_path: &std::path::Path) -> std::path::PathBuf {
    with_suffix(db_path, "-content")
}

/// The device-private tier beside the replica at `db_path`, named by derivation.
#[cfg(feature = "native-transport")]
fn tier_path(db_path: &std::path::Path) -> std::path::PathBuf {
    with_suffix(db_path, "-tier")
}

/// `base` with `suffix` joined onto its final component rather than as a child.
#[cfg(feature = "native-transport")]
fn with_suffix(base: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut name = base.as_os_str().to_owned();
    name.push(suffix);
    std::path::PathBuf::from(name)
}

/// Remove the file at `path`, treating an absent file as success so a retry
/// after a partial failure is the same call again.
#[cfg(feature = "native-transport")]
fn remove_absent_ok(path: &std::path::Path) -> Result<(), PurgeError> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(PurgeError::Io(err.to_string())),
    }
    Ok(())
}

/// Purge (delete) the replica at `db_path` and everything named beside it.
///
/// The replica goes with its WAL and SHM sidecars, the device-private tier at
/// `db_path-tier` goes with its own, and the content directory [`content_dir`]
/// is removed whole. Order is tier, replica, content, every one named by
/// derivation so the call needs no second path. The content directory goes even
/// though `purge_replica` keeps the key, because a fresh replica has empty
/// manifest tables and every chunk under the old directory is an orphan.
///
/// Blocks on `unsynced`: when it is non-empty and `force` is false, returns
/// [`PurgeError::Unsynced`] and deletes nothing, so logout and expiry never
/// silently drop queued writes. Pass the connection's
/// [`unsynced`](crate::ConnettoConnection::unsynced) captured before dropping
/// the connection, since the file must be closed before deletion. A missing
/// file is not an error, so the call is idempotent.
///
/// # Errors
///
/// [`PurgeError::Unsynced`] when unsynced writes remain and `force` is false,
/// or [`PurgeError::Io`] when a delete fails for any reason but absence.
#[cfg(feature = "native-transport")]
pub fn purge_replica(
    db_path: &std::path::Path,
    unsynced: &[UnsyncedWrite],
    force: bool,
) -> Result<(), PurgeError> {
    if !unsynced.is_empty() && !force {
        return Err(PurgeError::Unsynced(unsynced.to_vec()));
    }
    // Tier before replica, each with its own WAL and SHM sidecars.
    for base in [tier_path(db_path), db_path.to_path_buf()] {
        for suffix in ["", "-wal", "-shm"] {
            remove_absent_ok(&with_suffix(&base, suffix))?;
        }
    }
    // The content chunks are orphaned once the replica's manifest tables go, so
    // the whole directory is removed even when the key is kept.
    match std::fs::remove_dir_all(content_dir(db_path)) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(PurgeError::Io(err.to_string())),
    }
    Ok(())
}

/// Data teardown: destroy the replica's key, then delete the replica.
///
/// This is the crypto-shredding half of the logout grid. Deleting the file alone
/// leaves recoverable ciphertext behind on media that does not honour deletes,
/// and destroying the key alone leaves a file nothing can open, so the two are
/// one primitive rather than two the caller has to remember to pair.
///
/// `key_name` is the key-store record for this replica, which is the same value
/// [`replica_db_name`](crate::replica::replica_db_name) produced for the file.
/// Only that one record is cleared, so a second identity signed in on the same
/// device keeps its own replica and its own key.
///
/// The key goes first. If the delete then fails, what is left is inert
/// ciphertext, and the wipe's promise still holds; the reverse order would leave
/// a readable file whenever the delete failed. The cost is that a failed delete
/// leaves a replica that reports
/// [`ClientError::ReplicaUndecryptable`](crate::ClientError::ReplicaUndecryptable)
/// on the next connect, whose recovery is [`purge_replica`] with `force`.
///
/// Blocks on `unsynced` exactly as [`purge_replica`] does, and nothing is
/// destroyed when it refuses. Pass the connection's
/// [`unsynced`](crate::ConnettoConnection::unsynced) captured before the
/// connection dropped, since the file has to be closed before it can be deleted.
/// Idempotent: an absent file and an absent record are both fine.
///
/// # Errors
///
/// [`PurgeError::Unsynced`] when unsynced writes remain and `force` is false,
/// [`PurgeError::KeyStore`] when the record cannot be cleared, or
/// [`PurgeError::Io`] when a delete fails for any reason but absence.
#[cfg(feature = "native-auth")]
pub async fn wipe_replica<S>(
    db_path: &std::path::Path,
    key_store: &S,
    key_name: &str,
    unsynced: &[UnsyncedWrite],
    force: bool,
) -> Result<(), PurgeError>
where
    S: connetto_core::traits::ReplicaKeyStore,
{
    if !unsynced.is_empty() && !force {
        return Err(PurgeError::Unsynced(unsynced.to_vec()));
    }
    key_store
        .clear(key_name)
        .await
        .map_err(|err| PurgeError::KeyStore(err.to_string()))?;
    purge_replica(db_path, unsynced, force)
}

/// Failure to forget a device, split by whether the client still works.
#[cfg(feature = "native-auth")]
#[derive(Debug, thiserror::Error)]
pub enum ForgetError {
    /// Nothing was destroyed and the client still works, so the application
    /// keeps it.
    #[error(transparent)]
    Refused(#[from] ForgetRefusal),
    /// The client is closed and part of the teardown failed. The application
    /// drops the client and signs in again.
    #[error(transparent)]
    Incomplete(Box<ForgetIncomplete>),
}

/// Why a forget destroyed nothing.
#[cfg(feature = "native-auth")]
#[derive(Debug, thiserror::Error)]
pub enum ForgetRefusal {
    /// The build kept no replica on this device, so there is nothing to forget.
    #[error("the build kept no replica on this device")]
    NoReplica,
    /// The replica holds writes the server has not acknowledged and `force`
    /// was not set.
    #[error("{} unsynced mutation(s) would be lost", .0.len())]
    Unsynced(Vec<UnsyncedWrite>),
    /// The client could not read the writes the server has not acknowledged.
    #[error("reading the unsynced writes: {0}")]
    Unreadable(crate::ClientError),
}

/// What failed in a forget that went past closing the client. Every part runs
/// even when an earlier one failed, except the share keys and the device key,
/// which go only once the wipe stands. A part is `None` when it succeeded or
/// had nothing to do, and `share_keys` and `device_key` are also `None` when
/// a failed wipe kept them.
#[cfg(feature = "native-auth")]
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ForgetIncomplete {
    /// Releasing the replica's file handles failed, so a platform that refuses
    /// to delete an open file keeps the replica.
    pub release: Option<crate::ClientError>,
    /// Reading or clearing the stored credential failed, so it may remain.
    pub credential: Option<crate::ClientError>,
    /// The server was not reached, so the session stays live until it
    /// expires on its own.
    pub revoke: Option<crate::ClientError>,
    /// The replica's key or files could not be removed.
    pub wipe: Option<PurgeError>,
    /// The share keys could not be cleared, so they may remain.
    pub share_keys: Option<crate::ClientError>,
    /// The device key could not be deleted.
    pub device_key: Option<crate::ClientError>,
}

#[cfg(feature = "native-auth")]
impl ForgetIncomplete {
    /// Whether every part succeeded.
    pub(crate) fn is_complete(&self) -> bool {
        self.release.is_none()
            && self.credential.is_none()
            && self.revoke.is_none()
            && self.wipe.is_none()
            && self.share_keys.is_none()
            && self.device_key.is_none()
    }
}

#[cfg(feature = "native-auth")]
impl core::fmt::Display for ForgetIncomplete {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the client is closed, but")?;
        let parts: [(&str, Option<&dyn core::fmt::Display>); 6] = [
            (
                "releasing the replica",
                self.release.as_ref().map(|err| err as _),
            ),
            (
                "clearing the stored credential",
                self.credential.as_ref().map(|err| err as _),
            ),
            (
                "revoking the session",
                self.revoke.as_ref().map(|err| err as _),
            ),
            ("wiping the replica", self.wipe.as_ref().map(|err| err as _)),
            (
                "clearing the share keys",
                self.share_keys.as_ref().map(|err| err as _),
            ),
            (
                "deleting the device key",
                self.device_key.as_ref().map(|err| err as _),
            ),
        ];
        let mut first = true;
        for (part, err) in parts {
            if let Some(err) = err {
                let joint = if first { " " } else { ", and " };
                write!(f, "{joint}{part} failed: {err}")?;
                first = false;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "native-auth")]
impl std::error::Error for ForgetIncomplete {}

/// Revoke and clear the credential, then destroy the key and delete the
/// replica, filling in the parts of `report` that fail. Both run even when the
/// other fails: a revoke that never reached the server does not keep the data,
/// and data that could not be wiped does not keep the session.
///
/// The unsynced guard is the caller's, run before the client closed, because
/// once the refresh token is gone the queued writes can no longer be uploaded.
#[cfg(feature = "native-auth")]
pub(crate) async fn forget_device<S>(
    authenticator: Option<&crate::auth::NativeAuthenticator>,
    db_path: &std::path::Path,
    key_store: &S,
    key_name: &str,
    unsynced: &[UnsyncedWrite],
    report: &mut ForgetIncomplete,
) where
    S: connetto_core::traits::ReplicaKeyStore,
{
    if let Some(authenticator) = authenticator {
        let signed_out = authenticator.sign_out().await;
        report.credential = signed_out.credential.err();
        report.revoke = signed_out.revoke.err();
    }
    report.wipe = wipe_replica(db_path, key_store, key_name, unsynced, true)
        .await
        .err();
}

#[cfg(all(test, feature = "native-transport"))]
mod tests {
    use super::{PurgeError, expiry_warning, purge_replica};
    use crate::{UnsyncedWrite, WriterRef};
    use std::time::{Duration, SystemTime};

    fn pair(number: u64, seq: u64) -> UnsyncedWrite {
        UnsyncedWrite {
            writer: WriterRef::Number(number),
            seq,
        }
    }

    #[test]
    fn warns_only_when_near_expiry_with_unsynced() {
        let now = SystemTime::now();
        let lead = Duration::from_secs(60);
        let expires_soon = now + Duration::from_secs(30);
        let expires_far = now + Duration::from_secs(600);

        // Near expiry with queued work: warn, carrying the deadline and seqs.
        let warning =
            expiry_warning(now, expires_soon, lead, vec![pair(1, 1), pair(1, 2)], 0).expect("warn");
        assert_eq!(warning.session_expires_at, expires_soon);
        assert_eq!(warning.unsynced, vec![pair(1, 1), pair(1, 2)]);

        assert!(expiry_warning(now, expires_soon, lead, Vec::new(), 0).is_none());
        assert!(expiry_warning(now, expires_far, lead, vec![pair(1, 1)], 0).is_none());
        let content = expiry_warning(now, expires_soon, lead, Vec::new(), 1).expect("warn");
        assert_eq!(content.additional_pending, 1);
    }

    #[test]
    fn purge_blocks_on_unsynced_unless_forced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("replica.sqlite");
        std::fs::write(&db, b"not really sqlite").expect("seed file");
        std::fs::write(dir.path().join("replica.sqlite-wal"), b"wal").expect("seed wal");

        // Unsynced work without force is refused, and nothing is deleted.
        match purge_replica(&db, &[pair(1, 7)], false) {
            Err(PurgeError::Unsynced(unsynced)) => assert_eq!(unsynced, vec![pair(1, 7)]),
            other => panic!("expected Unsynced, got {other:?}"),
        }
        assert!(db.exists(), "blocked purge deletes nothing");

        // Forcing past unsynced work removes the file and its sidecar.
        purge_replica(&db, &[pair(1, 7)], true).expect("forced purge");
        assert!(!db.exists(), "forced purge removes the replica");
        assert!(
            !dir.path().join("replica.sqlite-wal").exists(),
            "sidecar gone"
        );

        // A clean replica purges with no force, idempotent when already gone.
        purge_replica(&db, &[], false).expect("idempotent purge of a missing file");
    }
}
