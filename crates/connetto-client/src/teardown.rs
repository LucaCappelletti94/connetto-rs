//! Teardown primitives: the two axes of logout, and the offline-expiry warning.
//!
//! Logout is two orthogonal choices, and connetto ships mechanisms rather than
//! policy (see `docs/architecture/11-authentication.md`). Credential teardown is
//! [`NativeAuthenticator::logout`](crate::auth::NativeAuthenticator::logout):
//! revoke the session and clear the stored refresh token. Data teardown is
//! [`wipe_replica`]: delete the replica and destroy its key, which crypto-shreds
//! it so any ciphertext a forensic recovery turns up is inert. The application
//! composes the two behind its own prompt, or runs both under one guard with
//! [`forget_device`].
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

use std::time::{Duration, SystemTime};

/// A proactive warning that the local session is near its end while unsynced
/// mutations are still queued, so a teardown now would lose them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryWarning {
    /// When the session (refresh-token lifetime) lapses if never refreshed.
    pub session_expires_at: SystemTime,
    /// The unsynced mutation sequence numbers at risk.
    pub unsynced: Vec<u64>,
}

/// Warn when `now` is within `lead` of `session_expires_at` and `unsynced` is
/// non-empty, otherwise `None` (not near expiry, or nothing at risk).
///
/// `session_expires_at` is the instant connetto-server returns with each token
/// pair: when the current refresh token stops working if never used again. An
/// online client keeps sliding it forward on every refresh, so this only bites
/// while offline, the one time a session can lapse unrefreshed. The app polls
/// this to prompt the user to reconnect before the queued writes are lost.
#[must_use]
pub fn expiry_warning(
    now: SystemTime,
    session_expires_at: SystemTime,
    lead: Duration,
    unsynced: Vec<u64>,
) -> Option<ExpiryWarning> {
    if unsynced.is_empty() {
        return None;
    }
    let warn_from = session_expires_at
        .checked_sub(lead)
        .unwrap_or(session_expires_at);
    (now >= warn_from).then_some(ExpiryWarning {
        session_expires_at,
        unsynced,
    })
}

/// Failure to purge a replica.
#[cfg(feature = "native-transport")]
#[derive(Debug, thiserror::Error)]
pub enum PurgeError {
    /// The replica still holds unsynced mutations and `force` was not set, so
    /// the purge is refused rather than silently discarding them.
    #[error("purge blocked: {} unsynced mutation(s) would be lost", .0.len())]
    Unsynced(Vec<u64>),
    /// Deleting a replica file failed.
    #[error("purge io error: {0}")]
    Io(String),
    /// Destroying the replica's key-store record failed, so the ciphertext is
    /// not crypto-shredded. Only `wipe_replica` raises this.
    #[error("purge key store error: {0}")]
    KeyStore(String),
}

/// Purge (delete) the replica at `db_path` and its WAL and SHM sidecars.
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
    unsynced: &[u64],
    force: bool,
) -> Result<(), PurgeError> {
    if !unsynced.is_empty() && !force {
        return Err(PurgeError::Unsynced(unsynced.to_vec()));
    }
    for suffix in ["", "-wal", "-shm"] {
        let mut name = db_path.as_os_str().to_owned();
        name.push(suffix);
        match std::fs::remove_file(std::path::PathBuf::from(name)) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(PurgeError::Io(err.to_string())),
        }
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
pub fn wipe_replica(
    db_path: &std::path::Path,
    key_store: &dyn crate::auth::ReplicaKeyStore,
    key_name: &str,
    unsynced: &[u64],
    force: bool,
) -> Result<(), PurgeError> {
    if !unsynced.is_empty() && !force {
        return Err(PurgeError::Unsynced(unsynced.to_vec()));
    }
    key_store
        .clear(key_name)
        .map_err(|err| PurgeError::KeyStore(err.to_string()))?;
    purge_replica(db_path, unsynced, force)
}

/// Failure to forget a device.
#[cfg(feature = "native-auth")]
#[derive(Debug, thiserror::Error)]
pub enum ForgetError {
    /// The data teardown failed, so the replica may still be present.
    #[error(transparent)]
    Purge(#[from] PurgeError),
    /// The local credential was cleared but the server was not reached, so the
    /// session stays live until it expires on its own.
    #[error("logged out locally but the session was not revoked: {0}")]
    NotRevoked(String),
}

/// Both destructive axes under one guard: revoke and clear the credential, then
/// destroy the key and delete the replica.
///
/// The one convenience this module offers, and it exists for the ordering rather
/// than the line count. The unsynced guard is checked **first**, before the
/// credential is destroyed, because once the refresh token is gone the queued
/// writes can no longer be uploaded and the guard would be protecting nothing.
///
/// A revoke that never reached the server does not abort the wipe: the local
/// credential is already gone and the caller asked for the data to go too. The
/// wipe failure wins the report if both fail, because leftover data is the more
/// serious outcome, and [`ForgetError::NotRevoked`] surfaces only once the data
/// is confirmed gone.
///
/// # Errors
///
/// [`ForgetError::Purge`] if the guard refuses or the wipe fails, or
/// [`ForgetError::NotRevoked`] if the wipe succeeded but the revoke did not.
#[cfg(feature = "native-auth")]
pub async fn forget_device(
    authenticator: &crate::auth::NativeAuthenticator,
    db_path: &std::path::Path,
    key_store: &dyn crate::auth::ReplicaKeyStore,
    key_name: &str,
    unsynced: &[u64],
    force: bool,
) -> Result<(), ForgetError> {
    if !unsynced.is_empty() && !force {
        return Err(ForgetError::Purge(PurgeError::Unsynced(unsynced.to_vec())));
    }
    let revoked = authenticator.logout().await;
    wipe_replica(db_path, key_store, key_name, unsynced, force)?;
    revoked.map_err(|err| ForgetError::NotRevoked(err.to_string()))
}

#[cfg(all(test, feature = "native-transport"))]
mod tests {
    use super::{PurgeError, expiry_warning, purge_replica};
    use std::time::{Duration, SystemTime};

    #[test]
    fn warns_only_when_near_expiry_with_unsynced() {
        let now = SystemTime::now();
        let lead = Duration::from_secs(60);
        let expires_soon = now + Duration::from_secs(30);
        let expires_far = now + Duration::from_secs(600);

        // Near expiry with queued work: warn, carrying the deadline and seqs.
        let warning = expiry_warning(now, expires_soon, lead, vec![1, 2]).expect("warn");
        assert_eq!(warning.session_expires_at, expires_soon);
        assert_eq!(warning.unsynced, vec![1, 2]);

        // Near expiry but nothing at risk: silent.
        assert!(expiry_warning(now, expires_soon, lead, Vec::new()).is_none());
        // Queued work but expiry is comfortably far: silent.
        assert!(expiry_warning(now, expires_far, lead, vec![1]).is_none());
    }

    #[test]
    fn purge_blocks_on_unsynced_unless_forced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = dir.path().join("replica.sqlite");
        std::fs::write(&db, b"not really sqlite").expect("seed file");
        std::fs::write(dir.path().join("replica.sqlite-wal"), b"wal").expect("seed wal");

        // Unsynced work without force is refused, and nothing is deleted.
        match purge_replica(&db, &[7], false) {
            Err(PurgeError::Unsynced(unsynced)) => assert_eq!(unsynced, vec![7]),
            other => panic!("expected Unsynced, got {other:?}"),
        }
        assert!(db.exists(), "blocked purge deletes nothing");

        // Forcing past unsynced work removes the file and its sidecar.
        purge_replica(&db, &[7], true).expect("forced purge");
        assert!(!db.exists(), "forced purge removes the replica");
        assert!(
            !dir.path().join("replica.sqlite-wal").exists(),
            "sidecar gone"
        );

        // A clean replica purges with no force, idempotent when already gone.
        purge_replica(&db, &[], false).expect("idempotent purge of a missing file");
    }
}
