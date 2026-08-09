//! Startup checks against the deployment's Postgres.
//!
//! connetto emits no server DDL on any path a deployment runs, so everything it
//! reads from must already be there. A missing piece is refused at startup,
//! naming which one, because the alternatives are all worse: a replication
//! stream against an absent slot becomes a retry loop that never succeeds and
//! never says why, and an absent oplog table becomes a failure on the first
//! change rather than on the boot that introduced it.
//!
//! One entry point rather than a check per caller, so a later requirement is a
//! variant and a list entry instead of a seventh hand-rolled refusal.

use diesel::sql_types::{Bool, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::bb8::Pool;

/// Something the deployment provisions and connetto only reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Artifact<'a> {
    /// A logical replication slot, by `slot_name`.
    ReplicationSlot(&'a str),
    /// A publication, by `pubname`.
    Publication(&'a str),
    /// A table, by name, resolved through the connection's own `search_path`.
    Table(&'a str),
}

impl Artifact<'_> {
    /// How the refusal names this, in the words a deployment would use.
    const fn noun(&self) -> &'static str {
        match self {
            Self::ReplicationSlot(_) => "replication slot",
            Self::Publication(_) => "publication",
            Self::Table(_) => "table",
        }
    }

    /// The name the deployment gave it.
    const fn name(&self) -> &str {
        match self {
            Self::ReplicationSlot(name) | Self::Publication(name) | Self::Table(name) => name,
        }
    }

    /// A statement returning one boolean row: whether this exists.
    ///
    /// The name is bound rather than interpolated in every case, including the
    /// table, where `to_regclass` takes it as text and so needs no identifier
    /// quoting of its own.
    ///
    /// **The slot probe filters on the database and that is load-bearing.**
    /// `pg_replication_slots` lists the whole cluster, and a logical slot name
    /// is unique cluster-wide rather than per database, so a slot of the same
    /// name bound to a neighbouring database satisfied a bare name match while
    /// being unusable from here. Found by running this against a cluster that
    /// had one. The same clause rejects a physical slot, whose `database` is
    /// null, which is equally unusable for logical decoding.
    ///
    /// Not checked: that the slot's output plugin is `pgoutput`. A slot on the
    /// wrong plugin fails at stream time rather than here.
    const fn probe(&self) -> &'static str {
        match self {
            Self::ReplicationSlot(_) => {
                "SELECT EXISTS (SELECT 1 FROM pg_replication_slots \
                 WHERE slot_name = $1 AND database = current_database()) AS present"
            }
            Self::Publication(_) => {
                "SELECT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = $1) AS present"
            }
            Self::Table(_) => "SELECT to_regclass($1) IS NOT NULL AS present",
        }
    }
}

/// Why the server refused to start.
#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    /// The connection pool could not hand out a connection.
    #[error("preflight pool error: {0}")]
    Pool(String),
    /// The probe itself failed, so whether the artifact exists is unknown.
    #[error("checking for {noun} {name}: {source}")]
    Probe {
        /// What was being looked for.
        noun: &'static str,
        /// Its name.
        name: String,
        /// The underlying failure.
        source: diesel::result::Error,
    },
    /// The artifact is absent. The deployment owns creating it.
    #[error(
        "{noun} {name} does not exist. connetto creates no server objects, so the \
         deployment must provision it before the server will start"
    )]
    Missing {
        /// What was being looked for.
        noun: &'static str,
        /// Its name.
        name: String,
    },
}

#[derive(QueryableByName)]
struct Present {
    #[diesel(sql_type = Bool)]
    present: bool,
}

/// Refuse unless every artifact exists, naming the first that does not.
///
/// Checked in the order given, so a caller lists the piece a reader would want
/// named first when several are absent at once, which on a fresh database is
/// all of them.
///
/// # Errors
///
/// [`PreflightError::Missing`] naming the absent artifact,
/// [`PreflightError::Probe`] when the check could not be answered, and
/// [`PreflightError::Pool`] when no connection was available.
pub async fn require(
    pool: &Pool<AsyncPgConnection>,
    artifacts: &[Artifact<'_>],
) -> Result<(), PreflightError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|err| PreflightError::Pool(err.to_string()))?;
    for artifact in artifacts {
        let rows: Vec<Present> = sql_query(artifact.probe())
            .bind::<Text, _>(artifact.name())
            .load(&mut *conn)
            .await
            .map_err(|source| PreflightError::Probe {
                noun: artifact.noun(),
                name: artifact.name().to_owned(),
                source,
            })?;
        if !rows.into_iter().next().is_some_and(|row| row.present) {
            return Err(PreflightError::Missing {
                noun: artifact.noun(),
                name: artifact.name().to_owned(),
            });
        }
    }
    Ok(())
}
