//! The cluster a deployment's database belongs to, recorded so a restore into another cluster is seen (R70).
//!
//! A restore rewinds this row with everything else, so the recorded identifier
//! is the one the backup was taken under, and a database answering another one
//! was restored into a fresh cluster.

use diesel::prelude::*;

use crate::session::StreamCheck;
use diesel_async::pooled_connection::bb8::Pool;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

/// The table recording the cluster, which the deployment's migration creates and the server's preflight requires.
pub const EPOCH_TABLE: &str = "connetto_epoch";

/// The migration that creates [`EPOCH_TABLE`], one row at most.
pub const EPOCH_DDL: &str = "CREATE TABLE IF NOT EXISTS connetto_epoch (\
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton), \
    system_identifier TEXT NOT NULL)";

diesel::table! {
    /// The cluster the deployment last served from.
    connetto_epoch (singleton) {
        /// Always true, which keeps the table to one row.
        singleton -> Bool,
        /// The cluster's system identifier in decimal, since it exceeds a signed integer.
        system_identifier -> Text,
    }
}

/// The recorded cluster against the one the database reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Epoch {
    /// Nothing was recorded, so this is the deployment's first boot.
    First,
    /// The database reports the recorded cluster.
    Same,
    /// The database reports another cluster than the recorded one.
    Changed {
        /// The identifier the row held.
        recorded: u64,
    },
}

/// A failure while reading or recording the cluster.
#[derive(Debug, thiserror::Error)]
pub enum EpochError {
    /// The connection pool could not hand out a connection.
    #[error("epoch pool error: {0}")]
    Pool(String),
    /// The read or the write failed.
    #[error(transparent)]
    Query(#[from] diesel::result::Error),
    /// The row holds something that is not a system identifier.
    #[error("connetto_epoch holds {0:?}, which is not a system identifier")]
    Malformed(String),
}

/// Compare `system` with the recorded cluster, writing nothing.
///
/// The caller records the cluster with [`record`] only once whatever the comparison asks for has held, so a failure leaves the old identifier for the next try to meet.
///
/// # Errors
///
/// [`EpochError`] when the pool or the read fails, or the row is malformed.
pub async fn compare(pool: &Pool<AsyncPgConnection>, system: u64) -> Result<Epoch, EpochError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|err| EpochError::Pool(err.to_string()))?;
    let recorded: Option<String> = connetto_epoch::table
        .select(connetto_epoch::system_identifier)
        .first(&mut conn)
        .await
        .optional()?;
    match recorded {
        None => Ok(Epoch::First),
        Some(recorded) if recorded == system.to_string() => Ok(Epoch::Same),
        Some(recorded) => recorded
            .parse()
            .map(|recorded| Epoch::Changed { recorded })
            .map_err(|_| EpochError::Malformed(recorded)),
    }
}

/// Record `system` as the cluster the deployment serves from.
///
/// # Errors
///
/// [`EpochError`] when the pool or the write fails.
pub async fn record(pool: &Pool<AsyncPgConnection>, system: u64) -> Result<(), EpochError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|err| EpochError::Pool(err.to_string()))?;
    let current = system.to_string();
    diesel::insert_into(connetto_epoch::table)
        .values(connetto_epoch::system_identifier.eq(&current))
        .on_conflict(connetto_epoch::singleton)
        .do_update()
        .set(connetto_epoch::system_identifier.eq(&current))
        .execute(&mut conn)
        .await?;
    Ok(())
}

/// When the change feed was settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// Before either listener opened.
    AtBoot,
    /// On a reconnect of the feed under a running server.
    WhileRunning,
}

/// Why every login session is revoked, since a restore rewound the session store with the rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Revocation {
    /// The database belongs to another cluster than the recorded one (decisions 5 and 18).
    #[error("the database belongs to cluster {current}, not {recorded}")]
    AnotherCluster {
        /// The identifier the row held.
        recorded: u64,
        /// The identifier the database reports.
        current: u64,
    },
    /// The slot resumed past the reconnect log at boot (decision 10).
    #[error("the replication slot resumes at {boundary}, past the reconnect log")]
    SlotPastTheLog {
        /// Where the slot resumed.
        boundary: u64,
    },
}

/// Whether what settling the feed found revokes every session, and why.
#[must_use]
pub const fn revocation(settled: Epoch, check: StreamCheck, found: Found) -> Option<Revocation> {
    match (settled, check.gap, found) {
        (Epoch::Changed { recorded }, _, _) => Some(Revocation::AnotherCluster {
            recorded,
            current: check.system,
        }),
        (_, Some(boundary), Found::AtBoot) => Some(Revocation::SlotPastTheLog { boundary }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Epoch, Found, Revocation, revocation};
    use crate::session::StreamCheck;

    const fn check(gap: Option<u64>) -> StreamCheck {
        StreamCheck { system: 9, gap }
    }

    /// Each boot and feed-connect row of the plan's R70 table that touches login sessions.
    #[test]
    fn a_restore_revokes_sessions_and_a_failover_or_a_running_gap_does_not() {
        let another = Some(Revocation::AnotherCluster {
            recorded: 7,
            current: 9,
        });
        let changed = Epoch::Changed { recorded: 7 };
        for found in [Found::AtBoot, Found::WhileRunning] {
            assert_eq!(revocation(changed, check(None), found), another);
            assert_eq!(revocation(changed, check(Some(5)), found), another);
            assert_eq!(revocation(Epoch::Same, check(None), found), None);
            assert_eq!(revocation(Epoch::First, check(None), found), None);
        }
        for settled in [Epoch::Same, Epoch::First] {
            assert_eq!(
                revocation(settled, check(Some(5)), Found::AtBoot),
                Some(Revocation::SlotPastTheLog { boundary: 5 })
            );
            assert_eq!(
                revocation(settled, check(Some(5)), Found::WhileRunning),
                None,
                "a running server was not restored"
            );
        }
    }
}
