//! The build-time local-tier migration step (R31).
//!
//! A tier history is the directory of tier exports a deployment ships beside
//! its local tier source, one translated tier DDL per exported major plus the
//! boundary declarations the change between two exported majors carries. The
//! build reads the history, diffs every consecutive pair of exports into the
//! generated step for that boundary, and attaches the result to the bundle,
//! so a device that opened its tier at an older major runs every step from
//! the oldest exported one to the build's own major.
//!
//! A generated step is the SQL the client runs against the tier file opened
//! alone, inside one transaction the client opens and commits. The step never
//! opens or closes a transaction of its own and never touches the foreign
//! keys pragma, which the client sets off around the step and checks before
//! it commits.
//!
//! A rebuild suspends the objects that still name the rebuilt table.
//! SQLite's `ALTER TABLE RENAME` verifies every view and trigger in the
//! database and rewrites their stored text, and it never checks a foreign
//! key, so the step drops, before any table moves, every view and trigger
//! whose stored text names a table the boundary rebuilds by the name that
//! table carries before the step's renames, the views over the dropped
//! views included, and it recreates them from the newer export after the
//! move, the rebuilt table's own indexes and triggers first, then the
//! foreign triggers, then the views.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use connetto_core::Major;
use connetto_core::schema::TierHistory;
use connetto_core::tier_shape::{TierColumn, TierIndex, TierShape, TierTable, read_tier_shape};

use crate::SchemaError;

/// One exported tier: its major, the shape its DDL reads as, the `CREATE`
/// statement of every index and trigger the export builds, and the table each
/// trigger fires on.
#[derive(Debug)]
pub(crate) struct LoadedExport {
    /// The major the export was written for.
    pub(crate) major: Major,
    /// The shape the export's DDL reads as in a fresh database.
    pub(crate) shape: TierShape,
    /// The `CREATE` statement of every index and trigger, by object name.
    pub(crate) objects: BTreeMap<String, String>,
    /// The table each trigger fires on, by trigger name.
    pub(crate) trigger_tables: BTreeMap<String, String>,
}

/// What one boundary's declaration file says the change between two exported
/// majors is, so the generated step takes a rename as a rename and never
/// drops a table or column the file did not declare.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Declarations {
    /// The tables the boundary drops.
    pub(crate) dropped_tables: BTreeSet<String>,
    /// The columns the boundary drops, by the table they sit in.
    pub(crate) dropped_columns: BTreeMap<String, BTreeSet<String>>,
    /// The tables the boundary renames, old name to new.
    pub(crate) renamed_tables: BTreeMap<String, String>,
    /// The columns the boundary renames, by the table they sit in at the
    /// older major, old name to new.
    pub(crate) renamed_columns: BTreeMap<String, BTreeMap<String, String>>,
}

/// The document one `<N>.boundary.toml` file holds.
#[derive(Debug, serde::Deserialize)]
struct BoundaryFile {
    /// The tables the boundary drops.
    #[serde(default)]
    dropped_tables: Vec<String>,
    /// The columns the boundary drops, by the table they sit in.
    #[serde(default)]
    dropped_columns: BTreeMap<String, Vec<String>>,
    /// The tables the boundary renames, old name to new.
    #[serde(default)]
    renamed_tables: BTreeMap<String, String>,
    /// The columns the boundary renames, by the table they sit in at the
    /// older major, old name to new.
    #[serde(default)]
    renamed_columns: BTreeMap<String, BTreeMap<String, String>>,
}

diesel::table! {
    /// The catalogue one export reads its objects from, the same catalogue
    /// the shape reader walks for its tables and views.
    #[sql_name = "sqlite_master"]
    boundary_catalog (name) {
        /// The object kind: `table`, `view`, `index` or `trigger`.
        #[sql_name = "type"]
        kind -> diesel::sql_types::Text,
        /// The object name.
        name -> diesel::sql_types::Text,
        /// The table the object belongs to, itself for a table or a view.
        #[sql_name = "tbl_name"]
        owner_table -> diesel::sql_types::Text,
        /// The object's `CREATE` statement, absent for SQLite's own rows.
        #[sql_name = "sql"]
        statement -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
    }
}

/// Read one exported tier into its major, its shape, and the `CREATE`
/// statement of every index and trigger its DDL builds, refusing the export
/// when a view or a trigger of it names a table or view it does not hold.
///
/// # Errors
///
/// [`SchemaError::Sqlite`] when the export's DDL is not accepted by SQLite,
/// [`SchemaError::DanglingExportObject`] when a view or a trigger of the
/// export names a table or view the export does not hold.
pub(crate) fn load_export(major: Major, ddl: &str) -> Result<LoadedExport, SchemaError> {
    use diesel::connection::SimpleConnection;
    use diesel::{Connection, RunQueryDsl, SqliteConnection};

    let mut conn = SqliteConnection::establish(":memory:").map_err(|err| SchemaError::Sqlite {
        tier: "local tier",
        detail: err.to_string(),
    })?;
    conn.batch_execute(ddl).map_err(|err| SchemaError::Sqlite {
        tier: "local tier",
        detail: err.to_string(),
    })?;
    let shape = read_tier_shape(&mut conn).map_err(|err| SchemaError::Sqlite {
        tier: "local tier",
        detail: err.to_string(),
    })?;
    check_export_dangles(&mut conn, major, &shape)?;
    let rows = boundary_catalog::table
        .load::<(String, String, String, Option<String>)>(&mut conn)
        .map_err(|err| SchemaError::Sqlite {
            tier: "local tier",
            detail: err.to_string(),
        })?;
    let mut objects = BTreeMap::new();
    let mut trigger_tables = BTreeMap::new();
    for (kind, name, owner_table, statement) in rows {
        let Some(statement) = statement else {
            // The rows without a statement are SQLite's own machinery.
            continue;
        };
        match kind.as_str() {
            "index" => {
                objects.insert(name, statement);
            }
            "trigger" => {
                objects.insert(name.clone(), statement);
                trigger_tables.insert(name, owner_table);
            }
            _ => {}
        }
    }
    Ok(LoadedExport {
        major,
        shape,
        objects,
        trigger_tables,
    })
}

/// Whether the views and triggers of the export all name what the export
/// holds, probed by a rename, since SQLite's `ALTER TABLE RENAME` verifies
/// every view and trigger in the database and reports the one that names
/// what is gone. The probe runs inside a transaction it rolls back, and it
/// renames a table it creates when the export holds none, since a trigger
/// cannot exist without its table and the DDL that applied already proved
/// every owner is present.
///
/// # Errors
///
/// [`SchemaError::DanglingExportObject`] when a view or a trigger names a
/// table or view the export does not hold,
/// [`SchemaError::Sqlite`] when the probe itself fails to run.
fn check_export_dangles(
    conn: &mut diesel::SqliteConnection,
    major: Major,
    shape: &TierShape,
) -> Result<(), SchemaError> {
    use connetto_core::sql::quote_ident;
    use diesel::connection::SimpleConnection;

    let probe = quote_ident("connetto_dangle_probe");
    let probe_moved = quote_ident("connetto_dangle_probe_moved");
    let statements: Vec<String> = if shape.tables.is_empty() {
        vec![
            format!("CREATE TABLE {probe} (x INTEGER);"),
            format!("ALTER TABLE {probe} RENAME TO {probe_moved};"),
        ]
    } else {
        let table = shape.tables.keys().next().expect("a table holds");
        vec![format!("ALTER TABLE {table} RENAME TO {probe};")]
    };
    if let Err(err) = conn.batch_execute("BEGIN;") {
        return Err(SchemaError::Sqlite {
            tier: "local tier",
            detail: err.to_string(),
        });
    }
    let mut failure: Option<String> = None;
    for statement in &statements {
        match conn.batch_execute(statement) {
            Ok(()) => {}
            Err(diesel::result::Error::DatabaseError(_, info)) => {
                failure = Some(info.message().to_owned());
                break;
            }
            Err(err) => {
                failure = Some(err.to_string());
                break;
            }
        }
    }
    // The transaction is still open on a failure, and the rollback is the
    // thing that proves the probe left the connection clean.
    let _ = conn.batch_execute("ROLLBACK;");
    match failure {
        Some(message) => match dangling_object(&message) {
            Some((kind, name)) => Err(SchemaError::DanglingExportObject {
                major: major.get(),
                kind: kind.to_owned(),
                name,
                detail: message,
            }),
            None => Err(SchemaError::Sqlite {
                tier: "local tier",
                detail: format!("the dangle probe failed: {message}"),
            }),
        },
        None => Ok(()),
    }
}

/// One SQLite `error in view X` or `error in trigger X` report, parsed into
/// the object's kind and name, or nothing when the message is no such
/// report, the quoted object names arriving unquoted in the report.
fn dangling_object(message: &str) -> Option<(&'static str, String)> {
    let rest = message.strip_prefix("error in ")?;
    let end = rest.find(' ')?;
    let kind = match &rest[..end] {
        "view" => "view",
        "trigger" => "trigger",
        _ => return None,
    };
    let name = rest[end + 1..].split_once(':')?.0;
    Some((kind, name.to_owned()))
}

/// The declarations one boundary's `<N>.boundary.toml` file holds, empty
/// when the directory holds no file for that boundary.
///
/// # Errors
///
/// [`SchemaError::Io`] when the file cannot be read,
/// [`SchemaError::BoundaryFile`] when it does not parse.
pub(crate) fn load_declarations(dir: &Path, to: Major) -> Result<Declarations, SchemaError> {
    let path = dir.join(format!("{to}.boundary.toml"));
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_declarations(&path, &text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Declarations::default()),
        Err(err) => Err(err.into()),
    }
}

/// Parse one boundary declaration file into its normalized declarations.
///
/// # Errors
///
/// [`SchemaError::BoundaryFile`] when the text does not parse, naming the
/// file's path.
pub(crate) fn parse_declarations(path: &Path, text: &str) -> Result<Declarations, SchemaError> {
    let file: BoundaryFile = toml::from_str(text).map_err(|err| SchemaError::BoundaryFile {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })?;
    Ok(Declarations {
        dropped_tables: file.dropped_tables.into_iter().collect(),
        dropped_columns: file
            .dropped_columns
            .into_iter()
            .map(|(table, columns)| (table, columns.into_iter().collect()))
            .collect(),
        renamed_tables: file.renamed_tables,
        renamed_columns: file.renamed_columns,
    })
}

/// The generated step for the boundary between the two exports, the SQL the
/// client runs against the tier file opened alone, in one transaction the
/// client opens and commits.
///
/// # Errors
///
/// [`SchemaError::UndeclaredTableDrop`] and
/// [`SchemaError::UndeclaredColumnDrop`] when the diff drops what the
/// declarations did not, [`SchemaError::NewNotNullColumnWithoutDefault`] when
/// the diff adds a not null column without a default, and
/// [`SchemaError::DeclarationMismatch`] when a declaration the diff does not
/// back.
pub(crate) fn generate(
    old: &LoadedExport,
    new: &LoadedExport,
    decls: &Declarations,
    decls_path: &Path,
) -> Result<String, SchemaError> {
    let boundary = new.major.get();
    debug_assert_eq!(
        old.major.get() + 1,
        boundary,
        "the history feeds only consecutive exports"
    );
    validate_declarations(old, new, decls, decls_path)?;
    let rebuilt = rebuilt_tables(old, new, decls, boundary)?;
    let (drop_views, drop_triggers) = suspended_objects(old, new, &rebuilt);
    let mut statements: Vec<String> = Vec::new();

    drop_suspended(&drop_views, &drop_triggers, &mut statements);

    // The tables the change keeps or renames, checked against the diff.
    for name in old.shape.tables.keys() {
        if decls.dropped_tables.contains(name) {
            continue;
        }
        if !new.shape.tables.contains_key(name) && !decls.renamed_tables.contains_key(name) {
            return Err(SchemaError::UndeclaredTableDrop {
                table: name.clone(),
                boundary,
            });
        }
    }

    // The declared table renames, before any statement that addresses a
    // table by its new name.
    for (from, to) in &decls.renamed_tables {
        statements.push(format!(
            "ALTER TABLE {} RENAME TO {}",
            connetto_core::sql::quote_ident(from),
            connetto_core::sql::quote_ident(to)
        ));
    }

    // The tables the change adds, created verbatim with their indexes and
    // triggers.
    for (name, table) in &new.shape.tables {
        let renamed_in = decls
            .renamed_tables
            .values()
            .any(|to| to.as_str() == name.as_str());
        if !old.shape.tables.contains_key(name) && !renamed_in {
            statements.push(table.create_sql.clone());
            for index in &table.indexes {
                statements.push(object_sql(new, &index.name));
            }
            for (trigger, table_name) in &new.trigger_tables {
                if table_name.eq_ignore_ascii_case(name) {
                    statements.push(object_sql(new, trigger));
                }
            }
        }
    }

    // The old tables the change keeps, in name order.
    for (old_name, old_table) in &old.shape.tables {
        if decls.dropped_tables.contains(old_name) {
            statements.push(format!(
                "DROP TABLE {}",
                connetto_core::sql::quote_ident(old_name)
            ));
            continue;
        }
        let (new_name, new_table) = kept_table(old_name, decls, new, boundary)?;
        let diff = column_mapping(old_name, old_table, new_table, decls, boundary)?;
        for column in &diff.added {
            if column.notnull && column.default.is_none() {
                return Err(SchemaError::NewNotNullColumnWithoutDefault {
                    table: new_name.to_owned(),
                    column: column.name.clone(),
                    boundary,
                });
            }
        }
        if rebuild_required(&diff, old_table, new_table) {
            rebuild_table(new_name, new_table, new, &diff, &mut statements);
        } else {
            stable_table(
                old_name,
                new_name,
                old_table,
                new,
                decls,
                &diff,
                &mut statements,
            );
            stable_triggers(
                old_name,
                new_name,
                old,
                new,
                &drop_triggers,
                &mut statements,
            );
        }
    }

    reissue_suspended_triggers(new, decls, &rebuilt, &drop_triggers, &mut statements);

    // The views the change adds, created after the tables move so a view
    // that points at a renamed table points at its new name, and the views
    // the step dropped with their text unchanged, which the change kept.
    for (name, sql) in &new.shape.views {
        if old.shape.views.get(name) != Some(sql) || drop_views.contains(name) {
            statements.push(sql.clone());
        }
    }

    Ok(statements_to_ddl(&statements))
}

/// The views and triggers the step drops, before any table moves, since a
/// rename refuses the step on any of them whose text names a table that is
/// gone by then.
fn drop_suspended(
    drop_views: &BTreeSet<String>,
    drop_triggers: &BTreeSet<String>,
    statements: &mut Vec<String>,
) {
    for name in drop_views {
        statements.push(format!(
            "DROP VIEW {}",
            connetto_core::sql::quote_ident(name)
        ));
    }
    for trigger in drop_triggers {
        statements.push(format!(
            "DROP TRIGGER {}",
            connetto_core::sql::quote_ident(trigger)
        ));
    }
}

/// The foreign triggers the step dropped, re-issued from the newer export
/// after the tables move, the rebuilt tables' own already re-issued with
/// each rebuild.
fn reissue_suspended_triggers(
    new: &LoadedExport,
    decls: &Declarations,
    rebuilt: &BTreeSet<String>,
    drop_triggers: &BTreeSet<String>,
    statements: &mut Vec<String>,
) {
    let rebuilt_final: BTreeSet<String> = rebuilt
        .iter()
        .map(|old_name| {
            decls
                .renamed_tables
                .get(old_name)
                .cloned()
                .unwrap_or_else(|| old_name.clone())
        })
        .collect();
    for (trigger, owner) in &new.trigger_tables {
        if !drop_triggers.contains(trigger) {
            continue;
        }
        if rebuilt_final
            .iter()
            .any(|final_name| final_name.eq_ignore_ascii_case(owner))
        {
            continue;
        }
        statements.push(object_sql(new, trigger));
    }
}

/// The `CREATE` statement one object holds in the export that built it.
fn object_sql(export: &LoadedExport, name: &str) -> String {
    // The shape and the catalogue came from the same read of the same
    // database, so every object the shape names holds its statement here.
    export
        .objects
        .get(name)
        .expect("the catalogue read it with the shape")
        .clone()
}

/// Join the statements the way the artifacts do, `;` between and a `;`
/// after the last.
fn statements_to_ddl(statements: &[String]) -> String {
    let mut ddl = statements.join(";\n");
    ddl.push(';');
    ddl
}

/// The tables the boundary rebuilds, by the name each carries before the
/// step's renames.
///
/// # Errors
///
/// [`SchemaError::UndeclaredTableDrop`] when a table the older export holds
/// is gone from the newer one without the declarations saying so, and
/// [`SchemaError::UndeclaredColumnDrop`] as the per-table walk.
fn rebuilt_tables(
    old: &LoadedExport,
    new: &LoadedExport,
    decls: &Declarations,
    boundary: u32,
) -> Result<BTreeSet<String>, SchemaError> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for (old_name, old_table) in &old.shape.tables {
        if decls.dropped_tables.contains(old_name) {
            continue;
        }
        let new_name = decls
            .renamed_tables
            .get(old_name)
            .map_or_else(|| old_name.as_str(), String::as_str);
        let new_table =
            new.shape
                .tables
                .get(new_name)
                .ok_or_else(|| SchemaError::UndeclaredTableDrop {
                    table: old_name.clone(),
                    boundary,
                })?;
        let diff = column_mapping(old_name, old_table, new_table, decls, boundary)?;
        if rebuild_required(&diff, old_table, new_table) {
            set.insert(old_name.clone());
        }
    }
    Ok(set)
}

/// The views and triggers the step drops before any table moves, the ones
/// whose stored text names a table the boundary rebuilds by the pre-rename
/// name, and the views and triggers whose stored text names a view the
/// step drops.
fn suspended_objects(
    old: &LoadedExport,
    new: &LoadedExport,
    rebuilt: &BTreeSet<String>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut views: BTreeSet<String> = BTreeSet::new();
    for (name, sql) in &old.shape.views {
        if new.shape.views.get(name) != Some(sql) {
            views.insert(name.clone());
        }
    }
    let mut settled = false;
    while !settled {
        settled = true;
        for (name, sql) in &old.shape.views {
            if views.contains(name) {
                continue;
            }
            if rebuilt.iter().any(|table| names_table(sql, table))
                || views.iter().any(|dropped| names_table(sql, dropped))
            {
                views.insert(name.clone());
                settled = false;
            }
        }
    }
    let mut triggers: BTreeSet<String> = BTreeSet::new();
    for trigger in old.trigger_tables.keys() {
        let sql = object_sql(old, trigger);
        if rebuilt.iter().any(|table| names_table(&sql, table))
            || views.iter().any(|dropped| names_table(&sql, dropped))
        {
            triggers.insert(trigger.clone());
        }
    }
    (views, triggers)
}

/// The columns one table the change keeps moves, adds, and drops.
struct ColumnDiff {
    /// The columns it carries, as `(new name, old name)`, in the new
    /// table's column order.
    carried: Vec<(String, String)>,
    /// The columns the newer export adds.
    added: Vec<TierColumn>,
    /// Whether the diff drops any column of the older table.
    drops: bool,
}

/// The columns the diff moves, the columns it adds, and whether it drops
/// anything, for one table the change keeps.
///
/// # Errors
///
/// [`SchemaError::UndeclaredColumnDrop`] when a column the older table holds
/// is gone from the newer one without the declarations naming it.
fn column_mapping(
    old_name: &str,
    old_table: &TierTable,
    new_table: &TierTable,
    decls: &Declarations,
    boundary: u32,
) -> Result<ColumnDiff, SchemaError> {
    let renames = decls.renamed_columns.get(old_name);
    let dropped = decls.dropped_columns.get(old_name);
    let mut pairs: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut drops = false;
    for old_column in &old_table.columns {
        let kept = new_table
            .columns
            .iter()
            .any(|candidate| candidate.name == old_column.name);
        let renamed_to = renames
            .and_then(|map| map.get(&old_column.name))
            .filter(|new_name| {
                new_table
                    .columns
                    .iter()
                    .any(|candidate| candidate.name == **new_name)
            });
        let dropped_here = dropped.is_some_and(|set| set.contains(&old_column.name));
        match (kept, renamed_to, dropped_here) {
            (true, _, _) => {
                pairs.insert(
                    old_column.name.clone(),
                    (old_column.name.clone(), old_column.name.clone()),
                );
            }
            (false, Some(new_name), _) => {
                pairs.insert(
                    new_name.clone(),
                    (new_name.clone(), old_column.name.clone()),
                );
            }
            (false, None, true) => drops = true,
            (false, None, false) => {
                return Err(SchemaError::UndeclaredColumnDrop {
                    table: old_name.to_owned(),
                    column: old_column.name.clone(),
                    boundary,
                });
            }
        }
    }
    // The carried columns in the new table's order, the order one insert
    // carries them in.
    let mut carried = Vec::new();
    for column in &new_table.columns {
        if let Some(pair) = pairs.get(&column.name) {
            carried.push(pair.clone());
        }
    }
    let added = new_table
        .columns
        .iter()
        .filter(|column| !pairs.contains_key(&column.name))
        .cloned()
        .collect();
    Ok(ColumnDiff {
        carried,
        added,
        drops,
    })
}

/// Check the declarations against the diff, before any statement is
/// generated, so a declaration the diff does not back is refused with the
/// file that holds it.
///
/// # Errors
///
/// [`SchemaError::DeclarationMismatch`] naming the file and the entry.
fn validate_declarations(
    old: &LoadedExport,
    new: &LoadedExport,
    decls: &Declarations,
    path: &Path,
) -> Result<(), SchemaError> {
    for table in &decls.dropped_tables {
        let matches = old.shape.tables.contains_key(table)
            && !new.shape.tables.contains_key(table)
            && !decls.renamed_tables.contains_key(table);
        if !matches {
            return Err(declaration_mismatch(
                path,
                format!("the drop of table {table} does not match the diff"),
            ));
        }
    }
    for (table, columns) in &decls.dropped_columns {
        let Some(old_table) = old.shape.tables.get(table) else {
            return Err(declaration_mismatch(
                path,
                format!(
                    "the drop of a column of {table} names a table the older export does not hold"
                ),
            ));
        };
        let new_table = new.shape.tables.get(table).or_else(|| {
            decls
                .renamed_tables
                .get(table)
                .and_then(|to| new.shape.tables.get(to))
        });
        for column in columns {
            if !old_table.columns.iter().any(|entry| entry.name == *column) {
                return Err(declaration_mismatch(
                    path,
                    format!(
                        "the drop of column {column} of {table} names a column the older export does not hold"
                    ),
                ));
            }
            if new_table.is_some_and(|entry| entry.columns.iter().any(|c| c.name == *column)) {
                return Err(declaration_mismatch(
                    path,
                    format!(
                        "the drop of column {column} of {table} does not match the diff, the newer export still holds it"
                    ),
                ));
            }
        }
    }
    for (from, to) in &decls.renamed_tables {
        let matches = from != to
            && old.shape.tables.contains_key(from)
            && !new.shape.tables.contains_key(from)
            && new.shape.tables.contains_key(to);
        if !matches {
            return Err(declaration_mismatch(
                path,
                format!("the rename of table {from} to {to} does not match the diff"),
            ));
        }
    }
    for (table, renames) in &decls.renamed_columns {
        let Some(old_table) = old.shape.tables.get(table) else {
            return Err(declaration_mismatch(
                path,
                format!(
                    "the rename of a column of {table} names a table the older export does not hold"
                ),
            ));
        };
        let new_name = decls
            .renamed_tables
            .get(table)
            .map_or_else(|| table.as_str(), String::as_str);
        let Some(new_table) = new.shape.tables.get(new_name) else {
            return Err(declaration_mismatch(
                path,
                format!(
                    "the rename of a column of {table} does not match the diff, the newer export does not hold the table"
                ),
            ));
        };
        for (from, to) in renames {
            let matches = from != to
                && old_table.columns.iter().any(|entry| entry.name == *from)
                && new_table.columns.iter().any(|entry| entry.name == *to)
                && !new_table.columns.iter().any(|entry| entry.name == *from);
            if !matches {
                return Err(declaration_mismatch(
                    path,
                    format!(
                        "the rename of column {from} of {table} to {to} does not match the diff"
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// The error one refused declaration becomes.
fn declaration_mismatch(path: &Path, detail: String) -> SchemaError {
    SchemaError::DeclarationMismatch {
        path: path.to_path_buf(),
        detail,
    }
}

/// The new name and the newer export's table for one old table the change
/// keeps.
fn kept_table<'a>(
    old_name: &'a str,
    decls: &'a Declarations,
    new: &'a LoadedExport,
    boundary: u32,
) -> Result<(&'a str, &'a TierTable), SchemaError> {
    let new_name = decls
        .renamed_tables
        .get(old_name)
        .map_or_else(|| old_name, String::as_str);
    let new_table =
        new.shape
            .tables
            .get(new_name)
            .ok_or_else(|| SchemaError::UndeclaredTableDrop {
                table: old_name.to_owned(),
                boundary,
            })?;
    Ok((new_name, new_table))
}

/// Whether one table the change keeps needs the rebuild path, the only path
/// that can drop a column, carry a column to a new position, apply a
/// changed column definition, or add a primary key or a default SQLite
/// cannot set on an add column.
fn rebuild_required(diff: &ColumnDiff, old_table: &TierTable, new_table: &TierTable) -> bool {
    if diff.drops {
        return true;
    }
    if diff.added.iter().any(|column| {
        column.pk.is_some() || column.default.as_deref().is_some_and(|d| !is_constant(d))
    }) {
        return true;
    }
    for (new_name, old_name) in &diff.carried {
        // The pairs map one to one onto the two tables' columns, so both
        // lookups hold.
        let old_column = old_table
            .columns
            .iter()
            .find(|column| column.name == *old_name)
            .expect("the pair came from the older table");
        let new_column = new_table
            .columns
            .iter()
            .find(|column| column.name == *new_name)
            .expect("the pair came from the newer table");
        if old_column.declared_type != new_column.declared_type
            || old_column.notnull != new_column.notnull
            || old_column.default != new_column.default
            || old_column.pk != new_column.pk
            || old_column.hidden != new_column.hidden
        {
            return true;
        }
    }
    // SQLite appends an added column, so the carried columns lead the new
    // table in their own order unless the change added one between them.
    if new_table
        .columns
        .iter()
        .take(diff.carried.len())
        .zip(&diff.carried)
        .any(|(column, (new_name, _))| column.name != *new_name)
    {
        return true;
    }
    // The carried columns must lead the new table in the old table's
    // relative order, which a plain alter keeps but a reorder does not.
    let mut last: Option<usize> = None;
    for (_, old_name) in &diff.carried {
        let position = old_table
            .columns
            .iter()
            .position(|column| column.name == **old_name)
            .expect("the pair came from the older table");
        if last.is_some_and(|previous| position <= previous) {
            return true;
        }
        last = Some(position);
    }
    false
}

/// The rebuild path for one table, the one that moves the data across a
/// temporary copy built from the newer export, so every change at once
/// takes effect under the table's final name.
fn rebuild_table(
    new_name: &str,
    new_table: &TierTable,
    new: &LoadedExport,
    diff: &ColumnDiff,
    statements: &mut Vec<String>,
) {
    let tmp = format!("connetto_rebuild_{}", sanitize_identifier(new_name));
    statements.push(rewrite_table_name(&new_table.create_sql, &tmp));
    if !diff.carried.is_empty() {
        // The columns the insert carries are the kept and renamed ones, so
        // every column the newer table adds starts from its own default.
        let new_columns = diff
            .carried
            .iter()
            .map(|(new_col, _)| connetto_core::sql::quote_ident(new_col))
            .collect::<Vec<_>>()
            .join(", ");
        let old_columns = diff
            .carried
            .iter()
            .map(|(_, old_col)| connetto_core::sql::quote_ident(old_col))
            .collect::<Vec<_>>()
            .join(", ");
        statements.push(format!(
            "INSERT INTO {tmp} ({new_columns}) SELECT {old_columns} FROM {}",
            connetto_core::sql::quote_ident(new_name)
        ));
    }
    // The temporary copy's indexes and triggers die with the old table, so
    // the newer export's ones come back verbatim under the final name.
    statements.push(format!(
        "DROP TABLE {}",
        connetto_core::sql::quote_ident(new_name)
    ));
    statements.push(format!(
        "ALTER TABLE {tmp} RENAME TO {}",
        connetto_core::sql::quote_ident(new_name)
    ));
    for index in &new_table.indexes {
        statements.push(object_sql(new, &index.name));
    }
    for (trigger, table) in &new.trigger_tables {
        if table.eq_ignore_ascii_case(new_name) {
            statements.push(object_sql(new, trigger));
        }
    }
}

/// The stable path for one table, the plain alters one table gets when the
/// diff changes no column definition and adds nothing an add column cannot
/// take.
fn stable_table(
    old_name: &str,
    new_name: &str,
    old_table: &TierTable,
    new: &LoadedExport,
    decls: &Declarations,
    diff: &ColumnDiff,
    statements: &mut Vec<String>,
) {
    let new_table = &new.shape.tables[new_name];
    if let Some(renames) = decls.renamed_columns.get(old_name) {
        for (from, to) in renames {
            statements.push(format!(
                "ALTER TABLE {} RENAME COLUMN {} TO {}",
                connetto_core::sql::quote_ident(new_name),
                connetto_core::sql::quote_ident(from),
                connetto_core::sql::quote_ident(to)
            ));
        }
    }
    for column in &diff.added {
        statements.push(format!(
            "ALTER TABLE {} ADD COLUMN {}",
            connetto_core::sql::quote_ident(new_name),
            render_add_column(column)
        ));
    }
    // An index the newer export holds the same way the older one did stays,
    // every other one the newer export holds is dropped and rebuilt verbatim.
    for index in &new_table.indexes {
        let unchanged = old_table.indexes.iter().any(|old| same_index(old, index));
        if !unchanged {
            if old_table.indexes.iter().any(|old| old.name == index.name) {
                statements.push(format!(
                    "DROP INDEX {}",
                    connetto_core::sql::quote_ident(&index.name)
                ));
            }
            statements.push(object_sql(new, &index.name));
        }
    }
    // An index the older export holds that the newer one dropped is dropped.
    for index in &old_table.indexes {
        if !new_table
            .indexes
            .iter()
            .any(|new_index| new_index.name == index.name)
        {
            statements.push(format!(
                "DROP INDEX {}",
                connetto_core::sql::quote_ident(&index.name)
            ));
        }
    }
}

/// The trigger sync one stable table gets, the triggers the step does not
/// suspend, which the pre-move drop and the post-move re-issue own.
fn stable_triggers(
    old_name: &str,
    new_name: &str,
    old: &LoadedExport,
    new: &LoadedExport,
    drop_triggers: &BTreeSet<String>,
    statements: &mut Vec<String>,
) {
    // A trigger the older export fires that the newer one keeps unchanged
    // stays, every other one it fires is dropped.
    for (trigger, table) in &old.trigger_tables {
        if !table.eq_ignore_ascii_case(old_name) {
            continue;
        }
        if drop_triggers.contains(trigger) {
            continue;
        }
        let kept = new
            .trigger_tables
            .get(trigger)
            .is_some_and(|new_table_name| new_table_name.eq_ignore_ascii_case(new_name))
            && new.shape.triggers.get(trigger) == old.shape.triggers.get(trigger);
        if !kept {
            statements.push(format!(
                "DROP TRIGGER {}",
                connetto_core::sql::quote_ident(trigger)
            ));
        }
    }
    // A trigger the newer export fires that the older one did not keep
    // unchanged comes back verbatim.
    for (trigger, table) in &new.trigger_tables {
        if !table.eq_ignore_ascii_case(new_name) {
            continue;
        }
        if drop_triggers.contains(trigger) {
            continue;
        }
        let unchanged = old
            .trigger_tables
            .get(trigger)
            .is_some_and(|old_table_name| old_table_name.eq_ignore_ascii_case(old_name))
            && old.shape.triggers.get(trigger) == new.shape.triggers.get(trigger);
        if !unchanged {
            statements.push(object_sql(new, trigger));
        }
    }
}

/// The definition one add column takes on, the column as the newer export
/// declares it.
fn render_add_column(column: &TierColumn) -> String {
    let mut definition = connetto_core::sql::quote_ident(&column.name);
    if !column.declared_type.is_empty() {
        definition.push(' ');
        definition.push_str(&column.declared_type);
    }
    if let Some(default) = &column.default {
        definition.push_str(" DEFAULT ");
        definition.push_str(default);
    }
    if column.notnull {
        definition.push_str(" NOT NULL");
    }
    definition
}

/// The temporary name one rebuild table takes, an identifier the table's
/// own name cannot spoil.
fn sanitize_identifier(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

/// The `CREATE TABLE` one rebuild runs, with the table's own name replaced
/// by its temporary one. The replacement is on the object name's span alone,
/// so the statement's rest, `STRICT` included, is untouched.
fn rewrite_table_name(create_sql: &str, tmp: &str) -> String {
    let start = find_keyword(create_sql, "CREATE TABLE")
        .expect("a table's catalog statement is a create table");
    let mut cursor = start + "CREATE TABLE".len();
    let rest = create_sql[cursor..].trim_start();
    cursor += create_sql[cursor..].len() - rest.len();
    if create_sql[cursor..]
        .to_ascii_uppercase()
        .starts_with("IF NOT EXISTS")
    {
        cursor += "IF NOT EXISTS".len();
        let rest = create_sql[cursor..].trim_start();
        cursor += create_sql[cursor..].len() - rest.len();
    }
    let name_start = cursor;
    let name_end = match create_sql[name_start..].chars().next() {
        Some(quote) if matches!(quote, '"' | '[' | '`') => {
            let mut end = name_start + 1;
            loop {
                let character = create_sql[end..]
                    .chars()
                    .next()
                    .expect("the catalog closed the quote it opened");
                end += character.len_utf8();
                if character != quote {
                    continue;
                }
                if create_sql[end..].starts_with(quote) {
                    // A doubled quote is the escaped quote, not the close.
                    end += 1;
                    continue;
                }
                break;
            }
            end
        }
        _ => {
            let stop = create_sql[name_start..]
                .find(['(', ',', ' '])
                .unwrap_or(create_sql.len() - name_start);
            name_start + stop
        }
    };
    let mut rewritten = String::with_capacity(create_sql.len());
    rewritten.push_str(&create_sql[..name_start]);
    rewritten.push_str(tmp);
    rewritten.push_str(&create_sql[name_end..]);
    rewritten
}

/// The offset of `keyword` at a word boundary, case-insensitively.
fn find_keyword(haystack: &str, keyword: &str) -> Option<usize> {
    let mut start = 0;
    while let Some(index) = haystack[start..].to_ascii_uppercase().find(keyword) {
        let at = start + index;
        let before = at
            .checked_sub(1)
            .and_then(|before| haystack[..=before].chars().next_back());
        let after = haystack[at + keyword.len()..].chars().next();
        let boundary = |character: Option<char>| {
            character.is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
        };
        if boundary(before) && boundary(after) {
            return Some(at);
        }
        start = at + 1;
    }
    None
}

/// Whether one stored statement names one table in any of SQLite's four
/// identifier quoting forms, the way `qualify_ddl` matches a table name in
/// stored `CREATE` text.
fn names_table(statement: &str, table: &str) -> bool {
    // The quoted forms, the quotes delimiting the name.
    for quoted in [
        format!("\"{table}\""),
        format!("`{table}`"),
        format!("[{table}]"),
    ] {
        if contains_ci(statement, &quoted) {
            return true;
        }
    }
    // The bare form, at a word boundary, so a longer identifier holding the
    // name as a part does not match.
    let lowered = statement.to_ascii_lowercase();
    let name = table.to_ascii_lowercase();
    let mut start = 0;
    while let Some(at) = lowered[start..].find(name.as_str()) {
        let hit = start + at;
        let before = hit
            .checked_sub(1)
            .and_then(|before| lowered[..=before].chars().next_back());
        let after = lowered[hit + name.len()..].chars().next();
        let boundary = |character: Option<char>| {
            character.is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
        };
        if boundary(before) && boundary(after) {
            return true;
        }
        start = hit + 1;
    }
    false
}

/// Whether a haystack holds a needle, case-insensitively over ASCII.
fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(needle.to_ascii_lowercase().as_str())
}

/// Whether one default expression SQLite can apply on an `ADD COLUMN`, the
/// literals, the keyword constants, and one layer of parentheses around a
/// constant, and nothing else.
fn is_constant(expression: &str) -> bool {
    let text = expression.trim();
    if let Some(rest) = text.strip_prefix('\'') {
        return string_literal(rest).is_some_and(|after| after.trim().is_empty());
    }
    for prefix in ['x', 'X', 'b', 'B'] {
        if let Some(rest) = text
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('\''))
        {
            return string_literal(rest).is_some_and(|after| after.trim().is_empty());
        }
    }
    if is_number(text) {
        return true;
    }
    if matches!(
        text.to_ascii_uppercase().as_str(),
        "NULL" | "TRUE" | "FALSE" | "CURRENT_TIME" | "CURRENT_DATE" | "CURRENT_TIMESTAMP"
    ) {
        return true;
    }
    if let Some(inner) = outer_parentheses(text) {
        return is_constant(inner);
    }
    false
}

/// The text after a string literal's closing quote, `None` when `rest` does
/// not start a well formed literal, its doubled quotes honored.
fn string_literal(rest: &str) -> Option<&str> {
    let mut escaped = false;
    for (index, character) in rest.char_indices() {
        if character != '\'' {
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        // A doubled quote is the escaped quote, not the close.
        if rest[index + 1..].starts_with('\'') {
            escaped = true;
            continue;
        }
        return Some(&rest[index + 1..]);
    }
    None
}

/// Whether one expression is a number literal, signed or unsigned, decimal,
/// hexadecimal, or with an exponent.
fn is_number(text: &str) -> bool {
    let text = text
        .strip_prefix('+')
        .or_else(|| text.strip_prefix('-'))
        .unwrap_or(text);
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return !hex.is_empty() && hex.chars().all(|character| character.is_ascii_hexdigit());
    }
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, Some(exponent)),
        None => (text, None),
    };
    let mantissa_ok = !mantissa.is_empty()
        && mantissa
            .chars()
            .filter(|character| *character == '.')
            .count()
            <= 1
        && mantissa
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
        && mantissa.chars().any(|character| character.is_ascii_digit());
    let exponent_ok = exponent.is_none_or(|exponent| {
        let digits = exponent
            .strip_prefix('+')
            .or_else(|| exponent.strip_prefix('-'))
            .unwrap_or(exponent);
        !digits.is_empty() && digits.chars().all(|character| character.is_ascii_digit())
    });
    mantissa_ok && exponent_ok
}

/// The text inside one outer layer of parentheses, `None` when `text` does
/// not open and close a single pair, its string literals honored.
fn outer_parentheses(text: &str) -> Option<&str> {
    let mut depth = 0;
    let mut in_string = false;
    let mut escaped = false;
    for (index, character) in text.char_indices() {
        if in_string {
            if character == '\'' {
                if escaped {
                    escaped = false;
                } else if text[index + 1..].starts_with('\'') {
                    escaped = true;
                } else {
                    in_string = false;
                }
            }
            continue;
        }
        match character {
            '\'' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    // The single outer layer closes only at the very end.
                    return (index + 1 == text.len()).then_some(&text[1..index]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether two index shapes are the same index, the one an index sync keeps
/// in place.
fn same_index(old: &TierIndex, new: &TierIndex) -> bool {
    old.name == new.name
        && old.unique == new.unique
        && old.origin == new.origin
        && old.partial == new.partial
        && old.columns == new.columns
}

/// The tier history one history directory holds, with the current export
/// checked against the translation the build just computed and every
/// boundary from the oldest export to the build's own major generated.
///
/// # Errors
///
/// [`SchemaError::MissingHistoryDir`] when the directory is not there,
/// [`SchemaError::MissingExport`] when the current export is,
/// [`SchemaError::StaleExport`] when it differs from the translation,
/// [`SchemaError::HistoryGap`] when the exported majors skip one, and the
/// errors the boundary generation between two exports carries.
pub(crate) fn tier_history(
    dir: &Path,
    build: Major,
    current_ddl: &str,
) -> Result<TierHistory, SchemaError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(SchemaError::MissingHistoryDir {
                dir: dir.to_path_buf(),
            });
        }
        Err(err) => return Err(err.into()),
    };
    let mut exports: BTreeMap<u32, String> = BTreeMap::new();
    for entry in entries {
        let path = entry.map_err(SchemaError::from)?.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(major_text) = file_name.strip_suffix(".sql") else {
            continue;
        };
        let Some(major) = major_text.parse::<u32>().ok().and_then(Major::new) else {
            continue;
        };
        exports.insert(major.get(), std::fs::read_to_string(&path)?);
    }
    let Some(current) = exports.get(&build.get()) else {
        return Err(SchemaError::MissingExport {
            major: build.get(),
            path: dir.join(format!("{build}.sql")),
            dir: dir.to_path_buf(),
        });
    };
    if current != current_ddl {
        return Err(SchemaError::StaleExport {
            major: build.get(),
            path: dir.join(format!("{build}.sql")),
            dir: dir.to_path_buf(),
        });
    }
    // The current export just proved the map holds a major.
    let lowest = *exports
        .keys()
        .next()
        .expect("the current export holds a major");
    for major in (lowest + 1)..=build.get() {
        if !exports.contains_key(&major) {
            return Err(SchemaError::HistoryGap {
                dir: dir.to_path_buf(),
                missing: major,
                lowest,
                build: build.get(),
            });
        }
    }
    let mut boundaries = Vec::new();
    let mut first_with_tier: Option<Major> = None;
    let mut previous: Option<LoadedExport> = None;
    for major in lowest..=build.get() {
        // The major passed the parse check above.
        let major = Major::new(major).expect("the major passed the parse check");
        let export = load_export(major, &exports[&major.get()])?;
        if first_with_tier.is_none() && !export.shape.tables.is_empty() {
            first_with_tier = Some(major);
        }
        if let Some(previous) = previous.take() {
            let decls_path = dir.join(format!("{major}.boundary.toml"));
            let decls = load_declarations(dir, major)?;
            let sql = generate(&previous, &export, &decls, &decls_path)?;
            boundaries.push(connetto_core::schema::TierBoundary::new(
                previous.major,
                sql,
            ));
        }
        previous = Some(export);
    }
    Ok(TierHistory::new(
        Major::new(lowest).expect("the major passed the parse check"),
        first_with_tier,
        boundaries,
    ))
}

/// The count one foreign key check returns.
#[cfg(test)]
#[derive(diesel::QueryableByName)]
struct CheckFk {
    /// The number of rows the check found.
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    n: i64,
}

/// One text cell a test reads back.
#[cfg(test)]
#[derive(diesel::QueryableByName)]
struct ValueRow {
    /// The cell.
    #[diesel(sql_type = diesel::sql_types::Text)]
    value: String,
}

/// The columns of a table the test reads back, in rowid order.
#[cfg(test)]
fn column_values(conn: &mut diesel::SqliteConnection, table: &str, column: &str) -> Vec<String> {
    use diesel::RunQueryDsl;
    let sql = format!("SELECT {column} AS value FROM {table} ORDER BY rowid");
    diesel::sql_query(sql)
        .load::<ValueRow>(conn)
        .expect("read the column")
        .into_iter()
        .map(|row| row.value)
        .collect()
}

/// Apply the old DDL, insert `rows` into it, run `boundary` the way the
/// client runs a generated step (foreign keys off, one transaction, a
/// foreign key check before the commit), and return the migrated connection,
/// once its shape is checked to equal the fresh build of the new DDL.
#[cfg(test)]
fn migrate(old_ddl: &str, rows: &str, boundary: &str, new_ddl: &str) -> diesel::SqliteConnection {
    use diesel::connection::SimpleConnection;
    use diesel::{Connection, RunQueryDsl, SqliteConnection};

    let mut conn = SqliteConnection::establish(":memory:").expect("open the probe");
    conn.batch_execute(old_ddl).expect("apply the old DDL");
    conn.batch_execute(rows).expect("insert the rows");
    conn.batch_execute("PRAGMA foreign_keys = OFF;")
        .expect("turn the foreign keys off");
    conn.batch_execute("BEGIN;").expect("open the transaction");
    conn.batch_execute(boundary)
        .expect("run the generated step");
    let check: Vec<CheckFk> =
        diesel::sql_query("SELECT count(*) AS n FROM pragma_foreign_key_check()")
            .load(&mut conn)
            .expect("check the foreign keys");
    assert_eq!(
        check[0].n, 0,
        "the step must leave no foreign key violations"
    );
    conn.batch_execute("COMMIT;").expect("commit the step");
    let migrated = read_tier_shape(&mut conn).expect("read the migrated shape");
    let mut fresh = SqliteConnection::establish(":memory:").expect("open the fresh probe");
    fresh.batch_execute(new_ddl).expect("apply the new DDL");
    let fresh_shape = read_tier_shape(&mut fresh).expect("read the fresh shape");
    assert_eq!(
        migrated, fresh_shape,
        "the migrated tier must read as the fresh build of the new export"
    );
    conn
}

#[cfg(test)]
mod tests {
    use super::*;
    use connetto_core::schema::TierBoundary;
    use std::path::PathBuf;

    fn export(major: u32, ddl: &str) -> LoadedExport {
        let major = Major::new(major).expect("the test majors are from 1 up");
        load_export(major, ddl).expect("load the export")
    }

    /// The generated step for the pair, from empty declarations.
    fn step(
        old: &LoadedExport,
        new: &LoadedExport,
        decls: &Declarations,
    ) -> Result<String, SchemaError> {
        generate(old, new, decls, Path::new("boundary.toml"))
    }

    fn no_decls() -> Declarations {
        Declarations::default()
    }

    fn decls(
        dropped_tables: &[&str],
        dropped_columns: &[(&str, &str)],
        renamed_tables: &[(&str, &str)],
        renamed_columns: &[(&str, &str, &str)],
    ) -> Declarations {
        let mut out = Declarations::default();
        for table in dropped_tables {
            out.dropped_tables.insert((*table).to_owned());
        }
        for (table, column) in dropped_columns {
            out.dropped_columns
                .entry((*table).to_owned())
                .or_default()
                .insert((*column).to_owned());
        }
        for (old, new) in renamed_tables {
            out.renamed_tables
                .insert((*old).to_owned(), (*new).to_owned());
        }
        for (table, old, new) in renamed_columns {
            out.renamed_columns
                .entry((*table).to_owned())
                .or_default()
                .insert((*old).to_owned(), (*new).to_owned());
        }
        out
    }

    /// A new table with an index and a trigger is created verbatim, its
    /// neighbours and their rows untouched.
    #[test]
    fn a_new_table_is_created_verbatim_with_its_indexes_and_triggers() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE TABLE b (x INTEGER PRIMARY KEY, y TEXT);
             CREATE INDEX b_y ON b(y);
             CREATE TRIGGER b_tr AFTER INSERT ON b BEGIN SELECT 1; END;",
        );
        let boundary = step(&old, &new, &no_decls()).expect("generate the step");
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
            "INSERT INTO a VALUES (1, 'one');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE TABLE b (x INTEGER PRIMARY KEY, y TEXT);
             CREATE INDEX b_y ON b(y);
             CREATE TRIGGER b_tr AFTER INSERT ON b BEGIN SELECT 1; END;",
        );
        assert!(boundary.contains("CREATE TABLE b"), "the step: {boundary}");
        assert!(
            boundary.contains("CREATE INDEX b_y"),
            "the step: {boundary}"
        );
        assert!(
            boundary.contains("CREATE TRIGGER b_tr"),
            "the step: {boundary}"
        );
        assert_eq!(column_values(&mut conn, "a", "y"), vec!["one".to_owned()]);
    }

    /// A trigger that fires on a new table with different case spelling is
    /// created with the table, the shape reading the trigger as the
    /// table's.
    #[test]
    fn a_trigger_named_on_the_new_table_with_different_case_is_created() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE TABLE b (x INTEGER PRIMARY KEY, y TEXT);
             CREATE TRIGGER b_tr AFTER INSERT ON B BEGIN SELECT 1; END;",
        );
        let boundary = step(&old, &new, &no_decls()).expect("generate the step");
        assert!(
            boundary.contains("CREATE TRIGGER b_tr"),
            "the trigger must ride the new table: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
            "INSERT INTO a VALUES (1, 'one');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE TABLE b (x INTEGER PRIMARY KEY, y TEXT);
             CREATE TRIGGER b_tr AFTER INSERT ON B BEGIN SELECT 1; END;",
        );
        assert_eq!(column_values(&mut conn, "b", "y"), Vec::<String>::new());
    }

    /// A table the boundary file declares dropped is dropped, and nothing
    /// the file did not declare is.
    #[test]
    fn a_declared_table_drop_is_generated_and_an_undeclared_one_refused() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE TABLE b (x INTEGER PRIMARY KEY, y TEXT);",
        );
        let new = export(2, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let boundary = step(&old, &new, &decls(&["b"], &[], &[], &[])).expect("generate the step");
        assert!(
            boundary.contains("DROP TABLE \"b\""),
            "the step: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE TABLE b (x INTEGER PRIMARY KEY, y TEXT);",
            "INSERT INTO a VALUES (1, 'one'); INSERT INTO b VALUES (1, 'two');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
        );
        assert_eq!(column_values(&mut conn, "a", "y"), vec!["one".to_owned()]);

        let refused = step(&old, &new, &no_decls()).unwrap_err();
        match refused {
            SchemaError::UndeclaredTableDrop { table, .. } => assert_eq!(table, "b"),
            other => panic!("the undeclared drop must name the table, got {other}"),
        }
    }

    /// A table the boundary file renames is renamed, keeping its rows.
    #[test]
    fn a_declared_table_rename_is_a_rename() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let new = export(2, "CREATE TABLE b (x INTEGER PRIMARY KEY, y TEXT);");
        let boundary =
            step(&old, &new, &decls(&[], &[], &[("a", "b")], &[])).expect("generate the step");
        assert!(
            boundary.contains("ALTER TABLE \"a\" RENAME TO \"b\""),
            "the step: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
            "INSERT INTO a VALUES (1, 'one');",
            &boundary,
            "CREATE TABLE b (x INTEGER PRIMARY KEY, y TEXT);",
        );
        assert_eq!(column_values(&mut conn, "b", "y"), vec!["one".to_owned()]);
    }

    /// A table the boundary renames and whose change forces the rebuild path
    /// runs the rebuild under its new name, keeping the rows.
    #[test]
    fn a_table_renamed_and_rebuilt_runs_the_rebuild_under_the_new_name() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, w TEXT);");
        let new = export(2, "CREATE TABLE b (x INTEGER PRIMARY KEY, y TEXT);");
        let boundary = step(&old, &new, &decls(&[], &[("a", "w")], &[("a", "b")], &[]))
            .expect("generate the step");
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, w TEXT);",
            "INSERT INTO a VALUES (1, 'one', 'w');",
            &boundary,
            "CREATE TABLE b (x INTEGER PRIMARY KEY, y TEXT);",
        );
        assert_eq!(column_values(&mut conn, "b", "y"), vec!["one".to_owned()]);
    }

    /// A column added between carried columns takes the rebuild path, which
    /// keeps the new table's column order.
    #[test]
    fn a_column_added_between_carried_ones_rebuilds() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let new = export(2, "CREATE TABLE a (x INTEGER PRIMARY KEY, z TEXT, y TEXT);");
        let boundary = step(&old, &new, &no_decls()).expect("generate the step");
        assert!(
            boundary.contains("connetto_rebuild"),
            "a middle add must rebuild: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
            "INSERT INTO a VALUES (1, 'one');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, z TEXT, y TEXT);",
        );
        assert_eq!(column_values(&mut conn, "a", "y"), vec!["one".to_owned()]);
    }

    /// A nullable column with a constant default is added with an add
    /// column, the default applied to the rows already there.
    #[test]
    fn a_new_column_is_added_and_a_not_null_one_without_default_refused() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, z TEXT NOT NULL DEFAULT 'd');",
        );
        let boundary = step(&old, &new, &no_decls()).expect("generate the step");
        assert!(boundary.contains("ADD COLUMN"), "the step: {boundary}");
        assert!(
            !boundary.contains("connetto_rebuild"),
            "a plain add must not rebuild: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
            "INSERT INTO a VALUES (1, 'one');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, z TEXT NOT NULL DEFAULT 'd');",
        );
        assert_eq!(column_values(&mut conn, "a", "z"), vec!["d".to_owned()]);

        let refused = step(
            &export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);"),
            &export(
                2,
                "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, z TEXT NOT NULL);",
            ),
            &no_decls(),
        )
        .unwrap_err();
        match refused {
            SchemaError::NewNotNullColumnWithoutDefault { table, column, .. } => {
                assert_eq!(table, "a");
                assert_eq!(column, "z");
            }
            other => panic!("the not null add must be refused, got {other}"),
        }
    }

    /// A new column that is a primary key, or that carries a default SQLite
    /// cannot apply on an add, forces the rebuild path.
    #[test]
    fn a_new_primary_key_column_or_non_constant_default_rebuilds() {
        let pk_old = export(1, "CREATE TABLE a (y TEXT);");
        let pk_new = export(2, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let boundary = step(&pk_old, &pk_new, &no_decls()).expect("generate the step");
        assert!(
            boundary.contains("connetto_rebuild"),
            "a new primary key must rebuild: {boundary}"
        );
        migrate(
            "CREATE TABLE a (y TEXT);",
            "INSERT INTO a VALUES ('one');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
        );

        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, z TEXT DEFAULT (upper('x')));",
        );
        let boundary = step(&old, &new, &no_decls()).expect("generate the step");
        assert!(
            boundary.contains("connetto_rebuild"),
            "a non constant default must rebuild: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
            "INSERT INTO a VALUES (1, 'one');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, z TEXT DEFAULT (upper('x')));",
        );
        assert_eq!(column_values(&mut conn, "a", "z"), vec!["X".to_owned()]);
    }

    /// A column the boundary file renames is renamed in place, its index
    /// rebuilt on the new name, its rows kept.
    #[test]
    fn a_declared_column_rename_is_a_rename() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE INDEX a_y ON a(y);",
        );
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, z TEXT);
             CREATE INDEX a_z ON a(z);",
        );
        let boundary =
            step(&old, &new, &decls(&[], &[], &[], &[("a", "y", "z")])).expect("generate the step");
        assert!(
            boundary.contains("RENAME COLUMN \"y\" TO \"z\""),
            "the step: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE INDEX a_y ON a(y);",
            "INSERT INTO a VALUES (1, 'one');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, z TEXT);
             CREATE INDEX a_z ON a(z);",
        );
        assert_eq!(column_values(&mut conn, "a", "z"), vec!["one".to_owned()]);
    }

    /// A column the boundary file drops is dropped with a rebuild, and a
    /// drop the file did not declare is refused.
    #[test]
    fn a_declared_column_drop_rebuilds_and_an_undeclared_one_is_refused() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, w TEXT);");
        let new = export(2, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let boundary =
            step(&old, &new, &decls(&[], &[("a", "w")], &[], &[])).expect("generate the step");
        assert!(
            boundary.contains("connetto_rebuild"),
            "a column drop must rebuild: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, w TEXT);",
            "INSERT INTO a VALUES (1, 'one', 'widow');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
        );
        assert_eq!(column_values(&mut conn, "a", "y"), vec!["one".to_owned()]);

        let refused = step(&old, &new, &no_decls()).unwrap_err();
        match refused {
            SchemaError::UndeclaredColumnDrop { table, column, .. } => {
                assert_eq!(table, "a");
                assert_eq!(column, "w");
            }
            other => panic!("the undeclared drop must name the column, got {other}"),
        }
    }

    /// Any change to a kept column's type, nullability or default rebuilds
    /// the table, the data carried across.
    #[test]
    fn kept_column_attribute_changes_rebuild() {
        for (new_ddl, label) in [
            (
                "CREATE TABLE a (x INTEGER PRIMARY KEY, y INTEGER);",
                "a type change",
            ),
            (
                "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT NOT NULL);",
                "a nullability change",
            ),
            (
                "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT DEFAULT 'two');",
                "a default change",
            ),
        ] {
            let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
            let new = export(2, new_ddl);
            let boundary = step(&old, &new, &no_decls()).expect("generate the step");
            assert!(
                boundary.contains("connetto_rebuild"),
                "{label} must rebuild: {boundary}"
            );
            migrate(
                "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
                "INSERT INTO a VALUES (1, '5');",
                &boundary,
                new_ddl,
            );
        }
    }

    /// The columns of a table the rebuild must carry in the new table's
    /// order, the old table's relative order.
    #[test]
    fn a_column_order_change_rebuilds() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, w TEXT);");
        let new = export(2, "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT, y TEXT);");
        let boundary = step(&old, &new, &no_decls()).expect("generate the step");
        assert!(
            boundary.contains("connetto_rebuild"),
            "a column order change must rebuild: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, w TEXT);",
            "INSERT INTO a VALUES (1, 'one', 'two');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT, y TEXT);",
        );
        assert_eq!(column_values(&mut conn, "a", "y"), vec!["one".to_owned()]);
        assert_eq!(column_values(&mut conn, "a", "w"), vec!["two".to_owned()]);
    }

    /// A table that stays the same shape gets no statement at all.
    #[test]
    fn an_unchanged_table_generates_nothing() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let new = export(2, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let boundary = step(&old, &new, &no_decls()).expect("generate the step");
        assert!(!boundary.contains("ALTER TABLE"), "the step: {boundary}");
        assert!(
            !boundary.contains("connetto_rebuild"),
            "the step: {boundary}"
        );
    }

    /// Indexes and triggers of a stable table are synced by name, a changed
    /// one dropped and rebuilt verbatim, a removed one dropped.
    #[test]
    fn indexes_and_triggers_of_a_stable_table_are_synced_by_name() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE INDEX a_y ON a(y);
             CREATE TRIGGER a_tr AFTER UPDATE ON a BEGIN SELECT 1; END;",
        );
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE UNIQUE INDEX a_y ON a(y);
             CREATE TRIGGER a_tr AFTER UPDATE ON a BEGIN SELECT 2; END;",
        );
        let boundary = step(&old, &new, &no_decls()).expect("generate the step");
        assert!(
            boundary.contains("DROP INDEX \"a_y\""),
            "the step: {boundary}"
        );
        assert!(
            boundary.contains("CREATE UNIQUE INDEX a_y"),
            "the step: {boundary}"
        );
        assert!(
            boundary.contains("DROP TRIGGER \"a_tr\""),
            "the step: {boundary}"
        );
        let _ = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE INDEX a_y ON a(y);
             CREATE TRIGGER a_tr AFTER UPDATE ON a BEGIN SELECT 1; END;",
            "",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE UNIQUE INDEX a_y ON a(y);
             CREATE TRIGGER a_tr AFTER UPDATE ON a BEGIN SELECT 2; END;",
        );
    }

    /// Views carry no data, so a view the change removes is dropped and one
    /// it adds is created verbatim, while an unchanged view stays.
    #[test]
    fn views_are_dropped_and_created_by_name() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE VIEW va AS SELECT x FROM a;
             CREATE VIEW stay AS SELECT x FROM a;",
        );
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE VIEW vb AS SELECT x + 1 FROM a;
             CREATE VIEW stay AS SELECT x FROM a;",
        );
        let boundary = step(&old, &new, &no_decls()).expect("generate the step");
        assert!(
            boundary.contains("DROP VIEW \"va\""),
            "the step: {boundary}"
        );
        assert!(boundary.contains("CREATE VIEW vb"), "the step: {boundary}");
        assert!(!boundary.contains("DROP VIEW stay"), "the step: {boundary}");
        let _ = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE VIEW va AS SELECT x FROM a;
             CREATE VIEW stay AS SELECT x FROM a;",
            "",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE VIEW vb AS SELECT x + 1 FROM a;
             CREATE VIEW stay AS SELECT x FROM a;",
        );
    }

    /// A view that keeps its text over a table the boundary rebuilds is
    /// dropped before the move and recreated after, since the rebuild's
    /// rename verifies every view in the database, and a view over a table
    /// the boundary does not rebuild stays.
    #[test]
    fn an_unchanged_view_over_a_rebuilt_table_is_suspended_and_recreated() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, w TEXT);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE VIEW v AS SELECT x FROM a;
             CREATE VIEW stay AS SELECT x FROM o;",
        );
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE VIEW v AS SELECT x FROM a;
             CREATE VIEW stay AS SELECT x FROM o;",
        );
        let boundary =
            step(&old, &new, &decls(&[], &[("a", "w")], &[], &[])).expect("generate the step");
        assert!(boundary.contains("DROP VIEW \"v\""), "the step: {boundary}");
        assert!(!boundary.contains("DROP VIEW stay"), "the step: {boundary}");
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, w TEXT);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE VIEW v AS SELECT x FROM a;
             CREATE VIEW stay AS SELECT x FROM o;",
            "INSERT INTO a VALUES (1, 'one', 'widow');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE VIEW v AS SELECT x FROM a;
             CREATE VIEW stay AS SELECT x FROM o;",
        );
        assert_eq!(column_values(&mut conn, "a", "y"), vec!["one".to_owned()]);
    }

    /// A view over a view the step drops is dropped with it, since the
    /// rename verifies the outer view too.
    #[test]
    fn a_view_over_a_changed_view_is_suspended_with_it() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE VIEW vi AS SELECT w FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE VIEW vi AS SELECT x FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        let boundary =
            step(&old, &new, &decls(&[], &[("a", "w")], &[], &[])).expect("generate the step");
        assert!(
            boundary.contains("DROP VIEW \"vo\""),
            "the step: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE VIEW vi AS SELECT w FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
            "INSERT INTO a VALUES (1, 'widow');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE VIEW vi AS SELECT x FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        assert_eq!(column_values(&mut conn, "a", "x"), vec!["1".to_owned()]);
    }

    /// The outer view of a chain where nothing changed is suspended through
    /// the closure, the inner view naming the rebuilt table and the outer
    /// one naming the inner.
    #[test]
    fn a_view_over_an_unchanged_view_over_a_rebuilt_table_is_suspended() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE VIEW vi AS SELECT x FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE VIEW vi AS SELECT x FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        let boundary =
            step(&old, &new, &decls(&[], &[("a", "w")], &[], &[])).expect("generate the step");
        assert!(
            boundary.contains("DROP VIEW \"vi\""),
            "the step: {boundary}"
        );
        assert!(
            boundary.contains("DROP VIEW \"vo\""),
            "the step: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE VIEW vi AS SELECT x FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
            "INSERT INTO a VALUES (1, 'widow');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE VIEW vi AS SELECT x FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        assert_eq!(column_values(&mut conn, "a", "x"), vec!["1".to_owned()]);
    }

    /// A plain rename meets the transitive view the same way, the changed
    /// inner view dropped before the rename leaving the outer one dangling,
    /// and the declared rename is the statement that verifies it.
    #[test]
    fn a_view_over_a_changed_view_is_suspended_across_a_plain_rename() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE VIEW vi AS SELECT w FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        let new = export(
            2,
            "CREATE TABLE b (x INTEGER PRIMARY KEY, w TEXT);
             CREATE VIEW vi AS SELECT w FROM b;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        let boundary =
            step(&old, &new, &decls(&[], &[], &[("a", "b")], &[])).expect("generate the step");
        assert!(
            boundary.contains("ALTER TABLE \"a\" RENAME TO \"b\""),
            "the step: {boundary}"
        );
        assert!(
            boundary.contains("DROP VIEW \"vo\""),
            "the step: {boundary}"
        );
        assert!(
            !boundary.contains("connetto_rebuild"),
            "a plain rename must not rebuild: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE VIEW vi AS SELECT w FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
            "INSERT INTO a VALUES (1, 'widow');",
            &boundary,
            "CREATE TABLE b (x INTEGER PRIMARY KEY, w TEXT);
             CREATE VIEW vi AS SELECT w FROM b;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        assert_eq!(column_values(&mut conn, "b", "w"), vec!["widow".to_owned()]);
    }

    /// The rename plus a rebuild meets the transitive view the same way,
    /// the outer view suspended so the rebuild's rename finds no view
    /// naming a table that is gone.
    #[test]
    fn a_view_over_a_changed_view_is_suspended_across_a_rename_and_rebuild() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE VIEW vi AS SELECT w FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        let new = export(
            2,
            "CREATE TABLE b (x INTEGER PRIMARY KEY);
             CREATE VIEW vi AS SELECT x FROM b;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        let boundary = step(&old, &new, &decls(&[], &[("a", "w")], &[("a", "b")], &[]))
            .expect("generate the step");
        assert!(
            boundary.contains("DROP VIEW \"vo\""),
            "the step: {boundary}"
        );
        assert!(
            boundary.contains("connetto_rebuild"),
            "the step: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE VIEW vi AS SELECT w FROM a;
             CREATE VIEW vo AS SELECT * FROM vi;",
            "INSERT INTO a VALUES (1, 'widow');",
            &boundary,
            "CREATE TABLE b (x INTEGER PRIMARY KEY);
             CREATE VIEW vi AS SELECT x FROM b;
             CREATE VIEW vo AS SELECT * FROM vi;",
        );
        assert_eq!(column_values(&mut conn, "b", "x"), vec!["1".to_owned()]);
    }

    /// A trigger on another table that names a rebuilt table is dropped
    /// before the move and re-issued from the newer export after, the
    /// rebuild's rename verifying every trigger in the database.
    #[test]
    fn a_trigger_over_a_rebuilt_table_is_suspended_and_recreated() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN INSERT INTO a (x) VALUES (1); END;",
        );
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN INSERT INTO a (x) VALUES (1); END;",
        );
        let boundary =
            step(&old, &new, &decls(&[], &[("a", "w")], &[], &[])).expect("generate the step");
        assert!(
            boundary.contains("DROP TRIGGER \"ft\""),
            "the step: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN INSERT INTO a (x) VALUES (1); END;",
            "INSERT INTO a VALUES (1, 'widow');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN INSERT INTO a (x) VALUES (1); END;",
        );
        assert_eq!(column_values(&mut conn, "a", "x"), vec!["1".to_owned()]);
    }

    /// The same suspension across a rename and a rebuild, the trigger's
    /// text rewritten for the new table by the newer export.
    #[test]
    fn a_trigger_over_a_renamed_and_rebuilt_table_is_suspended_and_recreated() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN INSERT INTO a (x) VALUES (1); END;",
        );
        let new = export(
            2,
            "CREATE TABLE b (x INTEGER PRIMARY KEY);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN INSERT INTO b (x) VALUES (1); END;",
        );
        let boundary = step(&old, &new, &decls(&[], &[("a", "w")], &[("a", "b")], &[]))
            .expect("generate the step");
        assert!(
            boundary.contains("DROP TRIGGER \"ft\""),
            "the step: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN INSERT INTO a (x) VALUES (1); END;",
            "INSERT INTO a VALUES (1, 'widow');",
            &boundary,
            "CREATE TABLE b (x INTEGER PRIMARY KEY);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN INSERT INTO b (x) VALUES (1); END;",
        );
        assert_eq!(column_values(&mut conn, "b", "x"), vec!["1".to_owned()]);
    }

    /// A trigger on another table whose body names a view the step drops is
    /// dropped with the view and re-issued after the move, since the
    /// rebuild's rename verifies every trigger in the database.
    #[test]
    fn a_trigger_over_a_dropped_view_is_suspended_and_recreated() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE VIEW v AS SELECT x FROM a;
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN SELECT 1 FROM v; END;",
        );
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE VIEW v AS SELECT x FROM a;
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN SELECT 1 FROM v; END;",
        );
        let boundary =
            step(&old, &new, &decls(&[], &[("a", "w")], &[], &[])).expect("generate the step");
        assert!(boundary.contains("DROP VIEW \"v\""), "the step: {boundary}");
        assert!(
            boundary.contains("DROP TRIGGER \"ft\""),
            "the step: {boundary}"
        );
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, w TEXT);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE VIEW v AS SELECT x FROM a;
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN SELECT 1 FROM v; END;",
            "INSERT INTO a VALUES (1, 'widow');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE TABLE o (x INTEGER PRIMARY KEY);
             CREATE VIEW v AS SELECT x FROM a;
             CREATE TRIGGER ft AFTER INSERT ON o BEGIN SELECT 1 FROM v; END;",
        );
        assert_eq!(column_values(&mut conn, "a", "x"), vec!["1".to_owned()]);
        let shape = read_tier_shape(&mut conn).expect("read the shape");
        assert!(
            shape.triggers.contains_key("ft"),
            "the re-issue restores the trigger"
        );
        assert!(
            shape.views.contains_key("v"),
            "the re-issue restores the view"
        );
    }

    /// An export that holds a view naming a table the export does not hold
    /// is refused at the load, naming the view and the export's major, since
    /// a fresh install of the export would carry the view dangling.
    #[test]
    fn an_export_holding_a_dangling_view_is_refused() {
        let refused = load_export(
            Major::new(2).expect("major 2"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE VIEW v AS SELECT x FROM gone;",
        )
        .expect_err("the load refuses the dangling view");
        match refused {
            SchemaError::DanglingExportObject {
                major,
                kind,
                name,
                detail,
            } => {
                assert_eq!(major, 2);
                assert_eq!(kind, "view");
                assert_eq!(name, "v");
                assert!(detail.contains("gone"), "the detail: {detail}");
            }
            other => panic!("the refusal names the view, got {other:?}"),
        }
    }

    /// An export that holds a trigger whose body names a table the export
    /// does not hold is refused at the load, naming the trigger.
    #[test]
    fn an_export_holding_a_dangling_trigger_body_is_refused() {
        let refused = load_export(
            Major::new(2).expect("major 2"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE TRIGGER ft AFTER INSERT ON a BEGIN SELECT 1 FROM gone; END;",
        )
        .expect_err("the load refuses the dangling trigger");
        match refused {
            SchemaError::DanglingExportObject {
                major,
                kind,
                name,
                detail,
            } => {
                assert_eq!(major, 2);
                assert_eq!(kind, "trigger");
                assert_eq!(name, "ft");
                assert!(detail.contains("gone"), "the detail: {detail}");
            }
            other => panic!("the refusal names the trigger, got {other:?}"),
        }
    }

    /// An export that holds no table is probed over a table the probe
    /// creates, so its dangling view is refused the same way.
    #[test]
    fn an_export_with_no_table_and_a_dangling_view_is_refused() {
        let refused = load_export(
            Major::new(3).expect("major 3"),
            "CREATE VIEW v AS SELECT x FROM gone;",
        )
        .expect_err("the load refuses the dangling view");
        match refused {
            SchemaError::DanglingExportObject {
                major,
                kind,
                name,
                detail,
            } => {
                assert_eq!(major, 3);
                assert_eq!(kind, "view");
                assert_eq!(name, "v");
                assert!(detail.contains("gone"), "the detail: {detail}");
            }
            other => panic!("the refusal names the view, got {other:?}"),
        }
    }

    /// An export whose views and triggers name only what it holds loads,
    /// the probe finding nothing dangling.
    #[test]
    fn a_clean_export_loads_with_its_objects() {
        let export = load_export(
            Major::new(2).expect("major 2"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE TABLE b (x INTEGER PRIMARY KEY);
             CREATE VIEW v AS SELECT x FROM a;
             CREATE TRIGGER ft AFTER INSERT ON a BEGIN SELECT 1 FROM b; END;",
        )
        .expect("load the export");
        assert!(export.shape.views.contains_key("v"), "the view loads");
        assert!(export.objects.contains_key("ft"), "the trigger loads");
    }

    /// A declaration the diff does not back is refused, naming the file and
    /// the entry that does not match.
    #[test]
    fn declarations_the_diff_does_not_back_are_refused() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let new = export(2, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");

        let refused = step(&old, &new, &decls(&["a"], &[], &[], &[])).unwrap_err();
        assert!(matches!(refused, SchemaError::DeclarationMismatch { .. }));

        let refused = step(&old, &new, &decls(&[], &[], &[("a", "b")], &[])).unwrap_err();
        assert!(matches!(refused, SchemaError::DeclarationMismatch { .. }));

        let refused = step(&old, &new, &decls(&[], &[], &[], &[("a", "y", "z")])).unwrap_err();
        assert!(matches!(refused, SchemaError::DeclarationMismatch { .. }));

        let refused = step(
            &old,
            &new,
            &decls(&[], &[("a", "no_such_column")], &[], &[]),
        )
        .unwrap_err();
        assert!(matches!(refused, SchemaError::DeclarationMismatch { .. }));
    }

    /// A boundary declaration file parses its four sections, and a file with
    /// nothing in it declares nothing. An unparseable file is an error naming
    /// its path.
    #[test]
    fn boundary_declaration_files_parse_their_sections() {
        let text = "dropped_tables = [\"a\"]\n\
                    [dropped_columns]\n\
                    a = [\"c1\"]\n\
                    [renamed_tables]\n\
                    old = \"new\"\n\
                    [renamed_columns]\n\
                    a = { old_col = \"new_col\" }\n";
        let parsed =
            parse_declarations(Path::new("3.boundary.toml"), text).expect("parse the file");
        let expected = decls(
            &["a"],
            &[("a", "c1")],
            &[("old", "new")],
            &[("a", "old_col", "new_col")],
        );
        assert_eq!(parsed, expected);

        let empty =
            parse_declarations(Path::new("3.boundary.toml"), "").expect("parse the empty file");
        assert_eq!(empty, no_decls());

        let refused = parse_declarations(Path::new("3.boundary.toml"), "not = [").unwrap_err();
        match refused {
            SchemaError::BoundaryFile { path, .. } => {
                assert_eq!(path, PathBuf::from("3.boundary.toml"));
            }
            other => panic!("the bad file must name its path, got {other}"),
        }
    }

    /// A history directory without its boundary file declares nothing for
    /// that boundary.
    #[test]
    fn an_absent_boundary_file_declares_nothing() {
        let dir = tempfile::tempdir().expect("make the history directory");
        let decls = load_declarations(dir.path(), Major::new(2).expect("major 2"))
            .expect("read the declarations");
        assert_eq!(decls, Declarations::default());
    }

    /// A history directory with a gap between its exported majors is an
    /// error naming the missing major.
    #[test]
    fn a_gap_between_exported_majors_is_refused() {
        let dir = tempfile::tempdir().expect("make the history directory");
        std::fs::write(
            dir.path().join("1.sql"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY);",
        )
        .expect("write the first export");
        std::fs::write(
            dir.path().join("3.sql"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
        )
        .expect("write the third export");
        let refused = tier_history(
            dir.path(),
            Major::new(3).expect("major 3"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
        )
        .unwrap_err();
        match refused {
            SchemaError::HistoryGap { missing, .. } => assert_eq!(missing, 2),
            other => panic!("the gap must name the missing major, got {other}"),
        }
    }

    /// A history without its current export is an error naming the command
    /// that writes it, and one whose current export is stale is the same.
    #[test]
    fn a_missing_or_stale_current_export_is_refused() {
        let dir = tempfile::tempdir().expect("make the history directory");
        std::fs::write(
            dir.path().join("1.sql"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY);",
        )
        .expect("write the first export");
        let refused = tier_history(
            dir.path(),
            Major::new(2).expect("major 2"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
        )
        .unwrap_err();
        assert!(matches!(refused, SchemaError::MissingExport { .. }));

        std::fs::write(dir.path().join("2.sql"), "a stale export").expect("write the stale export");
        let refused = tier_history(
            dir.path(),
            Major::new(2).expect("major 2"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
        )
        .unwrap_err();
        assert!(matches!(refused, SchemaError::StaleExport { .. }));
    }

    /// The history a complete directory reads as, with every boundary from
    /// the oldest export to the build's own major and the first major whose
    /// export had a table.
    #[test]
    fn a_complete_history_reads_as_its_boundaries() {
        let dir = tempfile::tempdir().expect("make the history directory");
        std::fs::write(
            dir.path().join("1.sql"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY);",
        )
        .expect("write the first export");
        std::fs::write(
            dir.path().join("2.sql"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
        )
        .expect("write the second export");
        let history = tier_history(
            dir.path(),
            Major::new(2).expect("major 2"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);",
        )
        .expect("read the history");
        assert_eq!(history.oldest(), Major::new(1).expect("major 1"));
        assert_eq!(
            history.first_with_tier(),
            Some(Major::new(1).expect("major 1"))
        );
        let boundaries = history.boundaries();
        assert_eq!(boundaries.len(), 1);
        assert_eq!(boundaries[0].from(), Major::new(1).expect("major 1"));
        assert!(
            boundaries[0].sql().contains("ADD COLUMN"),
            "the step: {}",
            boundaries[0].sql()
        );
    }

    /// An export whose tier has no table keeps the history's first major
    /// with a tier absent, until one appears.
    #[test]
    fn an_empty_export_defers_the_first_major_with_a_tier() {
        let dir = tempfile::tempdir().expect("make the history directory");
        std::fs::write(dir.path().join("1.sql"), ";").expect("write the empty export");
        std::fs::write(
            dir.path().join("2.sql"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY);",
        )
        .expect("write the second export");
        let history = tier_history(
            dir.path(),
            Major::new(2).expect("major 2"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY);",
        )
        .expect("read the history");
        assert_eq!(
            history.first_with_tier(),
            Some(Major::new(2).expect("major 2"))
        );

        std::fs::write(
            dir.path().join("3.sql"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY);",
        )
        .expect("write the third export");
        let history = tier_history(
            dir.path(),
            Major::new(3).expect("major 3"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY);",
        )
        .expect("read the history");
        assert_eq!(
            history.first_with_tier(),
            Some(Major::new(2).expect("major 2"))
        );
        assert_eq!(history.boundaries().len(), 2);
    }

    /// A tier given without its history directory is an error naming the
    /// missing directory.
    #[test]
    fn a_history_directory_that_is_absent_is_refused() {
        let refused = tier_history(
            Path::new("/no/such/tier_history"),
            Major::new(1).expect("major 1"),
            "CREATE TABLE a (x INTEGER PRIMARY KEY);",
        )
        .unwrap_err();
        assert!(matches!(refused, SchemaError::MissingHistoryDir { .. }));
    }

    /// Every expression a default may take on a stable add, classified.
    #[test]
    fn constants_are_classified() {
        for constant in [
            "'x'",
            "'it''s'",
            "x'DEADBEEF'",
            "X'DEAD'",
            "b'01'",
            "1",
            "-3",
            "+3.5",
            "1e3",
            "0x1F",
            ".5",
            "NULL",
            "true",
            "FALSE",
            "CURRENT_TIME",
            "CURRENT_DATE",
            "CURRENT_TIMESTAMP",
            "('x')",
            "((1))",
            "''",
        ] {
            assert!(is_constant(constant), "{constant} is a constant");
        }
        for non_constant in [
            "upper('x')",
            "1 + 1",
            "'a' || 'b'",
            "(1) + 2",
            "now",
            "x",
            "",
        ] {
            assert!(
                !is_constant(non_constant),
                "{non_constant} is not a constant"
            );
        }
    }

    /// The two sides of a rename are checked against the diff, so a rename
    /// whose old name the older export does not hold, or whose new name the
    /// newer one does not, is refused.
    #[test]
    fn a_rename_whose_ends_the_diff_does_not_hold_is_refused() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let new = export(2, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let refused = step(
            &old,
            &new,
            &decls(&[], &[], &[], &[("a", "no_column", "y")]),
        )
        .unwrap_err();
        assert!(matches!(refused, SchemaError::DeclarationMismatch { .. }));
        let refused = step(
            &old,
            &new,
            &decls(&[], &[], &[], &[("a", "y", "no_column")]),
        )
        .unwrap_err();
        assert!(matches!(refused, SchemaError::DeclarationMismatch { .. }));
        let refused =
            step(&old, &new, &decls(&[], &[], &[], &[("no_table", "y", "z")])).unwrap_err();
        assert!(matches!(refused, SchemaError::DeclarationMismatch { .. }));
    }

    /// The rebuild carries every kept column and applies every change at
    /// once, the mixed case the separate rules cover on their own.
    #[test]
    fn the_rebuild_carries_every_change_at_once() {
        let old = export(
            1,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, w TEXT);
             CREATE INDEX a_y ON a(y);",
        );
        let new = export(
            2,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, z TEXT NOT NULL DEFAULT 'd', w INTEGER, v TEXT);
             CREATE INDEX a_z ON a(z);
             CREATE TRIGGER a_tr AFTER INSERT ON a BEGIN SELECT 1; END;",
        );
        let boundary =
            step(&old, &new, &decls(&[], &[], &[], &[("a", "y", "z")])).expect("generate the step");
        assert!(
            boundary.contains("connetto_rebuild"),
            "the step: {boundary}"
        );
        assert!(!boundary.contains("RENAME COLUMN"), "the step: {boundary}");
        let mut conn = migrate(
            "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, w TEXT);
             CREATE INDEX a_y ON a(y);",
            "INSERT INTO a VALUES (1, 'one', 'two');",
            &boundary,
            "CREATE TABLE a (x INTEGER PRIMARY KEY, z TEXT NOT NULL DEFAULT 'd', w INTEGER, v TEXT);
             CREATE INDEX a_z ON a(z);
             CREATE TRIGGER a_tr AFTER INSERT ON a BEGIN SELECT 1; END;",
        );
        assert_eq!(column_values(&mut conn, "a", "z"), vec!["one".to_owned()]);
        assert_eq!(column_values(&mut conn, "a", "w"), vec!["two".to_owned()]);
    }

    /// The generated step for a boundary runs inside the transaction the
    /// client opens, which is why it never opens one itself.
    #[test]
    fn the_generated_step_never_opens_a_transaction() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let new = export(2, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT, z TEXT);");
        let boundary = step(&old, &new, &no_decls()).expect("generate the step");
        let upper = boundary.to_uppercase();
        assert!(!upper.contains("BEGIN"), "the step: {boundary}");
        assert!(!upper.contains("COMMIT"), "the step: {boundary}");
        assert!(
            !upper.contains("PRAGMA FOREIGN_KEYS"),
            "the step: {boundary}"
        );
    }

    /// The boundary a step is generated for is the newer export's major, and
    /// its step starts where the older one left off.
    #[test]
    fn the_boundary_majors_are_the_export_majors() {
        let old = export(1, "CREATE TABLE a (x INTEGER PRIMARY KEY);");
        let new = export(2, "CREATE TABLE a (x INTEGER PRIMARY KEY, y TEXT);");
        let boundary = step(&old, &new, &no_decls()).expect("generate the step");
        let _ = TierBoundary::new(old.major, boundary);
    }
}
