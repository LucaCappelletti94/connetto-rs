//! Session teardown: purge a replica on logout or refresh-token expiry, and
//! warn before an offline session lapses with unsynced data.
//!
//! Logout and refresh-token expiry are one event (see
//! `docs/architecture/11-authentication.md`): the local session is over. Both
//! surface any unsynced pending mutations, then purge the identity's replica,
//! then require a fresh interactive login that rebuilds the replica from the
//! template. The one honest data-loss edge, a device offline past its whole
//! session length, is made loud here: [`expiry_warning`] prompts before the
//! lapse, and [`purge_replica`] refuses to discard unsynced writes silently.

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
