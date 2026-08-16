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
//! variant and a list entry instead of a seventh hand-rolled refusal. Not every
//! requirement is a thing that exists or does not: a table can be there and
//! still be unfit to stream, which is why a probe reports three outcomes rather
//! than a bool.

use diesel::prelude::*;
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
    /// A table the change stream must carry, by publication and table name.
    ///
    /// Distinct from [`Table`](Self::Table), which asks only whether the table
    /// exists. A policy reading a table the publication leaves out learns
    /// nothing when a grant is given or taken away, so the store goes stale
    /// and then answers confidently and wrongly, which is silent rather than
    /// loud.
    PublishedTable {
        /// The publication the change stream reads.
        publication: &'a str,
        /// The table a policy reads and the publication must carry.
        table: &'a str,
    },
    /// Every table the publication carries records the row as it was, which
    /// Postgres does only under `REPLICA IDENTITY FULL`.
    ///
    /// Not a thing the deployment creates but a property of the tables it
    /// already streams, so its refusal names the tables to fix rather than
    /// offering to have one provisioned.
    ///
    /// **Scoped to the publication rather than the database, and that is
    /// decision 2 of R6.** subql ships the database-wide audit
    /// (`REPLICA_IDENTITY_AUDIT_SQL`), which also reports connetto's own
    /// bookkeeping tables: the watermark, the sessions, the provider tokens,
    /// the audit log, the ban list and the change log all sit in the same
    /// database, none of them is replicated, and setting the property on them
    /// would mean nothing. What connetto needs the previous row image for is
    /// the change stream, so the tables the change stream carries are exactly
    /// the tables that must have it.
    PreviousImages {
        /// The publication whose tables must all record their previous image.
        publication: &'a str,
    },
}

/// What a probe found.
enum Found {
    /// There, and fit to serve.
    Fit,
    /// Absent. The deployment provisions it.
    Absent,
    /// There and unfit, naming what has to be fixed.
    Unfit(Vec<String>),
}

impl Artifact<'_> {
    /// How the refusal names this, in the words a deployment would use.
    const fn noun(&self) -> &'static str {
        match self {
            Self::ReplicationSlot(_) => "replication slot",
            Self::Publication(_) | Self::PreviousImages { .. } => "publication",
            Self::Table(_) => "table",
            Self::PublishedTable { .. } => "replicated table",
        }
    }

    /// The name the deployment gave it.
    const fn name(&self) -> &str {
        match self {
            Self::ReplicationSlot(name) | Self::Publication(name) | Self::Table(name) => name,
            Self::PublishedTable { table, .. } => table,
            Self::PreviousImages { publication } => publication,
        }
    }

    /// What `conn` says about this artifact.
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
    ///
    /// The catalog probes are raw statements because they read `pg_catalog`
    /// views that exist to be queried this way, and each binds only its own
    /// name. The publication membership check needs two binds and gets a
    /// modelled view instead. The replica-identity probe joins the view to
    /// `pg_class` on schema and name, so it reads three catalogs and stays a
    /// statement of its own.
    async fn probe(&self, conn: &mut AsyncPgConnection) -> Result<Found, diesel::result::Error> {
        let probe = match self {
            Self::PublishedTable { publication, table } => {
                let present: bool = diesel::select(diesel::dsl::exists(
                    pg_publication_tables::table
                        .filter(pg_publication_tables::pubname.eq(publication))
                        .filter(pg_publication_tables::tablename.eq(table)),
                ))
                .get_result(conn)
                .await?;
                return Ok(if present { Found::Fit } else { Found::Absent });
            }
            Self::PreviousImages { publication } => {
                let deficient: Vec<Named> = sql_query(
                    "SELECT c.relname AS name FROM pg_publication_tables p \
                     JOIN pg_namespace n ON n.nspname = p.schemaname \
                     JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = p.tablename \
                     WHERE p.pubname = $1 AND c.relreplident <> 'f' \
                     ORDER BY c.relname",
                )
                .bind::<Text, _>(publication)
                .load(conn)
                .await?;
                return Ok(if deficient.is_empty() {
                    Found::Fit
                } else {
                    Found::Unfit(deficient.into_iter().map(|row| row.name).collect())
                });
            }
            Self::ReplicationSlot(_) => {
                "SELECT EXISTS (SELECT 1 FROM pg_replication_slots \
                 WHERE slot_name = $1 AND database = current_database()) AS present"
            }
            Self::Publication(_) => {
                "SELECT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = $1) AS present"
            }
            Self::Table(_) => "SELECT to_regclass($1) IS NOT NULL AS present",
        };
        let rows: Vec<Present> = sql_query(probe)
            .bind::<Text, _>(self.name())
            .load(conn)
            .await?;
        Ok(if rows.into_iter().next().is_some_and(|row| row.present) {
            Found::Fit
        } else {
            Found::Absent
        })
    }
}

diesel::table! {
    /// The catalog view naming which tables a publication carries.
    ///
    /// A view rather than a table, and read-only, so only the two columns this
    /// check reads are modelled. `pubname` is the key diesel needs and is not
    /// unique here, which costs nothing: nothing loads a row, only `EXISTS`.
    pg_publication_tables (pubname) {
        /// The publication's name.
        pubname -> Text,
        /// One table it carries, unqualified.
        tablename -> Text,
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
    /// Every table the publication carries is there, and some of them do not
    /// record the row as it was.
    ///
    /// Its own variant because [`Missing`](Self::Missing) offers to have the
    /// deployment provision the artifact, which is the wrong instruction for a
    /// table that exists and is configured the wrong way.
    #[error(
        "publication {publication} carries tables that do not record the row as it \
         was before a change: {tables}. connetto has to know that to take a row \
         back from a caller who may no longer see it, and Postgres records it only \
         under REPLICA IDENTITY FULL, so run ALTER TABLE <name> REPLICA IDENTITY \
         FULL on each before the server will start"
    )]
    PreviousImage {
        /// The publication whose tables were audited.
        publication: String,
        /// The tables to fix, comma separated.
        tables: String,
    },
}

#[derive(QueryableByName)]
struct Present {
    #[diesel(sql_type = Bool)]
    present: bool,
}

/// One name a probe reported.
#[derive(QueryableByName)]
struct Named {
    #[diesel(sql_type = Text)]
    name: String,
}

/// Refuse unless every artifact is there and fit to serve, naming the first
/// that is not.
///
/// Checked in the order given, so a caller lists the piece a reader would want
/// named first when several are absent at once, which on a fresh database is
/// all of them.
///
/// # Errors
///
/// [`PreflightError::Missing`] naming the absent artifact,
/// [`PreflightError::PreviousImage`] naming the replicated tables that cannot
/// report an old row, [`PreflightError::Probe`] when the check could not be
/// answered, and [`PreflightError::Pool`] when no connection was available.
pub async fn require(
    pool: &Pool<AsyncPgConnection>,
    artifacts: &[Artifact<'_>],
) -> Result<(), PreflightError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|err| PreflightError::Pool(err.to_string()))?;
    for artifact in artifacts {
        let found = artifact
            .probe(&mut conn)
            .await
            .map_err(|source| PreflightError::Probe {
                noun: artifact.noun(),
                name: artifact.name().to_owned(),
                source,
            })?;
        match found {
            Found::Fit => {}
            Found::Absent => {
                return Err(PreflightError::Missing {
                    noun: artifact.noun(),
                    name: artifact.name().to_owned(),
                });
            }
            Found::Unfit(tables) => {
                return Err(PreflightError::PreviousImage {
                    publication: artifact.name().to_owned(),
                    tables: tables.join(", "),
                });
            }
        }
    }
    Ok(())
}
