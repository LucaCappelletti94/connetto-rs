//! The application schema major a replica records, and the in-place rebuild a
//! build at a newer major runs (R31).
//!
//! The replica records its major in `main`'s `PRAGMA user_version`, the
//! bundle hash it was built from in the one-row `_connetto_build` table, and
//! its split tables' wire names in `_connetto_build_renames`, all written in
//! the transaction that creates or rebuilds it. A rebuild keeps the file,
//! because the device-private tier was created through this file's `ATTACH`
//! and carries its key salt, so a new file would orphan the tier.
//!
//! An old major's queued write is stored in its wire form. The renames that
//! turn a captured changeset's physical table names into the names its server
//! reads belong to the build that captured it, and the build draining it is
//! another one.

use std::collections::HashMap;

use connetto_core::{Major, SchemaVersion, quote_ident};
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::{_connetto_pending, ClientError, PolicyTables, rename_diffset, sqlite_catalog};

/// The record of the build a replica was made under: its bundle hash, and the
/// wire name of each split table.
pub(crate) const BUILD_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_build \
    (id INTEGER PRIMARY KEY CHECK (id = 1), version BLOB NOT NULL); \
    CREATE TABLE IF NOT EXISTS _connetto_build_renames \
    (physical TEXT PRIMARY KEY, logical TEXT NOT NULL)";

/// The old majors a rebuild left work for, one batch row each with the bundle
/// hash its drain presents.
pub(crate) const HELD_DDL: &str = "CREATE TABLE IF NOT EXISTS _connetto_held_batch \
    (major INTEGER PRIMARY KEY, version BLOB NOT NULL)";

/// What the content layer does with an old major's unsent files across a
/// rebuild and its drain (R31). The content layer owns its tables, so it
/// supplies these, and a build that attaches no content uses
/// [`HeldContent::NONE`].
#[derive(Clone, Copy, Debug)]
pub struct HeldContent {
    /// Moves the unsent files of a major aside inside the rebuild
    /// transaction, and says whether it held any.
    pub hold: fn(&mut SqliteConnection, Major) -> Result<bool, ClientError>,
    /// How many files are still held for a major.
    pub count: fn(&mut SqliteConnection, Major) -> Result<u64, ClientError>,
    /// Forgets a major's held files and says how many there were.
    pub forget: fn(&mut SqliteConnection, Major) -> Result<u64, ClientError>,
}

impl HeldContent {
    /// A build that attaches no content, which holds no file.
    pub const NONE: Self = Self {
        hold: |_, _| Ok(false),
        count: |_, _| Ok(0),
        forget: |_, _| Ok(0),
    };
}

diesel::table! {
    /// The bundle hash a replica was built from.
    #[sql_name = "_connetto_build"]
    connetto_build (id) {
        /// Always 1.
        id -> Integer,
        /// The bundle hash.
        version -> Binary,
    }
}

diesel::table! {
    /// The wire name of each split table, as the recording build renamed it.
    #[sql_name = "_connetto_build_renames"]
    build_renames (physical) {
        /// The backing table on the replica.
        physical -> Text,
        /// The name the server reads.
        logical -> Text,
    }
}

diesel::table! {
    /// One old major whose work a rebuild held, with that build's hash.
    #[sql_name = "_connetto_held_batch"]
    held_batch (major) {
        /// The old major.
        major -> BigInt,
        /// Its bundle hash, which the drain presents.
        version -> Binary,
    }
}

/// Connetto's own tables a rebuild keeps beside the held batches: the build
/// record, the device's enrolment, and the writer queues with their
/// retirement bookkeeping, whose frontiers the server keeps across majors.
const KEPT: [&str; 8] = [
    "_connetto_build",
    "_connetto_build_renames",
    "_connetto_device_certificate",
    "_connetto_revocation_list",
    "_connetto_writers",
    "_connetto_pending",
    "_connetto_retire",
    "_connetto_retired_keys",
];

/// What an existing replica needs before this build can serve it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Record {
    /// Recorded at this build's major and hash.
    Current,
    /// Made before majors existed, so it takes this build's record.
    Unrecorded,
    /// Recorded at an older major, so it is rebuilt in place.
    Behind(Recorded),
}

/// What an older replica recorded about the build that made it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Recorded {
    /// The major it was built under.
    pub(crate) major: Major,
    /// The bundle hash it was built from.
    pub(crate) version: SchemaVersion,
    /// Its split tables' wire names, physical to logical.
    renames: HashMap<String, String>,
}

/// One `user_version` reading.
#[derive(QueryableByName)]
struct UserVersion {
    #[diesel(sql_type = diesel::sql_types::Integer)]
    user_version: i32,
}

/// The major `main` records, 0 for none.
fn recorded_major(db: &mut SqliteConnection) -> Result<u32, ClientError> {
    // A vendor pragma, which the typed DSL cannot express.
    let reading: UserVersion = diesel::sql_query("PRAGMA main.user_version").get_result(db)?;
    // A negative reading is no major connetto wrote.
    Ok(u32::try_from(reading.user_version).unwrap_or(0))
}

/// Whether `main` holds a table named `name`.
fn has_table(db: &mut SqliteConnection, name: &str) -> Result<bool, ClientError> {
    let count: i64 = sqlite_catalog::table
        .filter(sqlite_catalog::kind.eq("table"))
        .filter(sqlite_catalog::name.eq(name))
        .count()
        .get_result(db)?;
    Ok(count > 0)
}

/// Read what an existing replica records against `build` and `version`.
///
/// # Errors
///
/// [`ClientError::ReplicaNewer`] for a replica at a newer major,
/// [`ClientError::ReplicaSchemaChanged`] for one at this major built from
/// another schema, [`ClientError::ReplicaRecordMissing`] for one recording a
/// major without the hash beside it, and a database failure.
pub(crate) fn read(
    db: &mut SqliteConnection,
    build: Major,
    version: &SchemaVersion,
) -> Result<Record, ClientError> {
    let recorded = recorded_major(db)?;
    let hash: Option<Vec<u8>> = if has_table(db, "_connetto_build")? {
        connetto_build::table
            .select(connetto_build::version)
            .first(db)
            .optional()?
    } else {
        None
    };
    let Some(major) = Major::new(recorded) else {
        return Ok(Record::Unrecorded);
    };
    let Some(hash) = hash else {
        return Err(ClientError::ReplicaRecordMissing { recorded: major });
    };
    let recorded_version = SchemaVersion::from_hash(hash);
    if major > build {
        return Err(ClientError::ReplicaNewer {
            recorded: major,
            build,
        });
    }
    if major == build {
        return if &recorded_version == version {
            Ok(Record::Current)
        } else {
            Err(ClientError::ReplicaSchemaChanged {
                major,
                recorded: recorded_version,
                build: version.clone(),
            })
        };
    }
    let renames = if has_table(db, "_connetto_build_renames")? {
        build_renames::table
            .select((build_renames::physical, build_renames::logical))
            .load::<(String, String)>(db)?
            .into_iter()
            .collect()
    } else {
        HashMap::new()
    };
    Ok(Record::Behind(Recorded {
        major,
        version: recorded_version,
        renames,
    }))
}

/// Write this build's major, hash and split-table names, the record a fresh
/// or rebuilt replica carries.
///
/// # Errors
///
/// A database failure.
pub(crate) fn stamp(
    db: &mut SqliteConnection,
    build: Major,
    version: &SchemaVersion,
    tables: &PolicyTables,
) -> Result<(), ClientError> {
    db.batch_execute(BUILD_DDL)?;
    diesel::insert_into(connetto_build::table)
        .values((
            connetto_build::id.eq(1),
            connetto_build::version.eq(version.hash()),
        ))
        .on_conflict(connetto_build::id)
        .do_update()
        .set(connetto_build::version.eq(version.hash()))
        .execute(db)?;
    diesel::delete(build_renames::table).execute(db)?;
    let renames: Vec<_> = tables
        .renames()
        .map(|(physical, logical)| {
            (
                build_renames::physical.eq(physical),
                build_renames::logical.eq(logical),
            )
        })
        .collect();
    diesel::insert_into(build_renames::table)
        .values(renames)
        .execute(db)?;
    // A vendor pragma, which the typed DSL cannot express. The value is a
    // number, so formatting it in is no injection.
    db.batch_execute(&format!("PRAGMA main.user_version = {}", build.get()))?;
    Ok(())
}

/// Rebuild the replica in place for `build`, in one transaction: turn the old
/// major's queued writes into their wire form and hold its unsent content,
/// drop every synced object and connetto's resume point, apply `ddl`, and
/// stamp the new record. The writer queues stay where they are, each entry
/// keeping the major it was captured under, so the old major's writes drain
/// in their chains.
///
/// # Errors
///
/// The first failure, after which nothing has changed.
pub(crate) fn rebuild(
    db: &mut SqliteConnection,
    ddl: &str,
    from: &Recorded,
    build: (Major, &SchemaVersion, &PolicyTables),
    content: HeldContent,
) -> Result<(), ClientError> {
    let (build, version, tables) = build;
    db.immediate_transaction(|db| {
        db.batch_execute(HELD_DDL)?;
        let old_major = i64::from(from.major.get());
        let writes: Vec<(String, i64, Vec<u8>)> = _connetto_pending::table
            .filter(_connetto_pending::major.eq(old_major))
            .select((
                _connetto_pending::writer,
                _connetto_pending::seq,
                _connetto_pending::changeset,
            ))
            .load(db)?;
        let held_writes = !writes.is_empty();
        if !from.renames.is_empty() {
            for (writer, seq, changeset) in writes {
                // The same rename the old build's upload applied, so the bytes are the ones its chain hash covers.
                let wire = rename_diffset(changeset, |name| {
                    from.renames.get(&name.to_lowercase()).cloned()
                })?;
                diesel::update(
                    _connetto_pending::table
                        .filter(_connetto_pending::writer.eq(&writer))
                        .filter(_connetto_pending::seq.eq(seq)),
                )
                .set(_connetto_pending::changeset.eq(wire))
                .execute(db)?;
            }
        }
        let held_content = (content.hold)(db, from.major)?;
        if held_writes || held_content {
            diesel::insert_into(held_batch::table)
                .values((
                    held_batch::major.eq(old_major),
                    held_batch::version.eq(from.version.hash()),
                ))
                .execute(db)?;
        }
        drop_synced(db)?;
        db.batch_execute(ddl)?;
        stamp(db, build, version, tables)
    })
}

/// Drop every object in `main` except SQLite's own, the held work and the
/// kept tables: triggers first, then views, then tables, whose indexes go with
/// them.
fn drop_synced(db: &mut SqliteConnection) -> Result<(), ClientError> {
    let objects: Vec<(String, String)> = sqlite_catalog::table
        .select((sqlite_catalog::kind, sqlite_catalog::name))
        .load(db)?;
    for kind in ["trigger", "view", "table"] {
        for (_, name) in objects.iter().filter(|(found, name)| {
            found == kind
                && !name.starts_with("sqlite_")
                && !name.starts_with("_connetto_held_")
                && !KEPT.contains(&name.as_str())
        }) {
            // DDL naming a catalogue object, which the typed DSL cannot express.
            db.batch_execute(&format!(
                "DROP {} IF EXISTS main.{}",
                kind.to_uppercase(),
                quote_ident(name)
            ))?;
        }
    }
    Ok(())
}
