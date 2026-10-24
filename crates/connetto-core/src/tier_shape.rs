//! The shape of a SQLite tier's `main` schema, read for the two sides of the
//! R31 local-tier migration.
//!
//! The build step diffs one exported major's shape against the next to
//! generate the boundary's structural step, and the client checks a migrated
//! tier against a scratch database built from the build's tier DDL through
//! the same read. [`read_tier_shape`] collects every table, index, trigger
//! and view of the `main` schema into a [`TierShape`], in name order, so two
//! databases holding the same objects compare equal in whichever order they
//! were created. [`TierShape::diff`] reports the same comparison as a
//! readable list for a typed refusal.
//!
//! Equality and the diff compare structure, the tables with their columns in
//! order, the indexes with their columns, and the triggers and views with
//! their `CREATE` text. A table's own `CREATE` text is carried by
//! [`TierTable::create_sql`] but not compared, since SQLite rewrites it on
//! every `ALTER` and a rebuild, and the migration contract is the structure
//! rather than the spelling.
use std::collections::{BTreeMap, BTreeSet};

use diesel::SqliteConnection;
use diesel::dsl::sql_query;

use crate::sql::quote_ident;

diesel::table! {
    /// SQLite's own catalogue, the typed read behind the shape. The pragma
    /// columns the shape needs beside it are read raw, since diesel has no
    /// query type for a pragma.
    #[sql_name = "sqlite_master"]
    tier_sqlite_schema (name) {
        /// The object kind, `table`, `view`, `index` or `trigger`.
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

/// A column of a tier table, as `PRAGMA table_xinfo` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierColumn {
    /// The column name.
    pub name: String,
    /// The declared type, empty when the column declares none.
    pub declared_type: String,
    /// The column carries a `NOT NULL` constraint.
    pub notnull: bool,
    /// The default expression, as declared.
    pub default: Option<String>,
    /// The column's position in the primary key, one-based, `None` when it
    /// is not part of one.
    pub pk: Option<u32>,
    /// The `hidden` flag `table_xinfo` reports for the column, zero for an
    /// ordinary one, where bit `2` marks a generated column.
    pub hidden: i64,
}

/// An index on a tier table, from `PRAGMA index_list` and `index_xinfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierIndex {
    /// The index name.
    pub name: String,
    /// The index enforces uniqueness.
    pub unique: bool,
    /// Where the index came from, `c` for a created index, `u` for a unique
    /// constraint and `pk` for a primary key.
    pub origin: String,
    /// The index covers a `WHERE` expression.
    pub partial: bool,
    /// The indexed columns in index order, an empty name for an index term
    /// that is an expression rather than a column.
    pub columns: Vec<String>,
}

/// A table of the tier's `main` schema.
#[derive(Clone, Debug)]
pub struct TierTable {
    /// The table name.
    pub name: String,
    /// The columns in declared order.
    pub columns: Vec<TierColumn>,
    /// The table's indexes, by name, SQLite's own autoindexes excluded.
    pub indexes: Vec<TierIndex>,
    /// The table's `CREATE` statement, as SQLite holds it in `sqlite_master`.
    pub create_sql: String,
}

impl PartialEq for TierTable {
    /// The structure is what a migration must preserve, so the comparison
    /// covers the columns and the indexes and leaves the `CREATE` text,
    /// which SQLite rewrites on every `ALTER` and a rebuild.
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.columns == other.columns && self.indexes == other.indexes
    }
}

impl Eq for TierTable {}

/// The shape of a SQLite tier's `main` schema, its tables, triggers and
/// views in name order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierShape {
    /// The tables, excluding SQLite's own `sqlite_%` tables and connetto's
    /// internal `_connetto%` tables.
    pub tables: BTreeMap<String, TierTable>,
    /// The triggers on the tier's tables, by name.
    pub triggers: BTreeMap<String, String>,
    /// The views of the tier, by name.
    pub views: BTreeMap<String, String>,
}

/// One difference [`TierShape::diff`] reports between two shapes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ShapeDifference {
    /// The table is in the shape that asks the diff, absent from the one it
    /// compares against.
    #[error("table {table} is on this side only")]
    TableOnlyHere {
        /// The table name.
        table: String,
    },
    /// The table is in the shape compared against, absent from the one that
    /// asks.
    #[error("table {table} is on the other side only")]
    TableOnlyThere {
        /// The table name.
        table: String,
    },
    /// A table both shapes hold carries different columns.
    #[error("table {table} columns differ, {detail}")]
    ColumnsDiffer {
        /// The table name.
        table: String,
        /// The column differences, readable.
        detail: String,
    },
    /// A table both shapes hold carries different indexes.
    #[error("table {table} indexes differ, {detail}")]
    IndexesDiffer {
        /// The table name.
        table: String,
        /// The index differences, readable.
        detail: String,
    },
    /// The trigger is on this side only.
    #[error("trigger {trigger} is on this side only")]
    TriggerOnlyHere {
        /// The trigger name.
        trigger: String,
    },
    /// The trigger is on the other side only.
    #[error("trigger {trigger} is on the other side only")]
    TriggerOnlyThere {
        /// The trigger name.
        trigger: String,
    },
    /// Both shapes hold the trigger but its `CREATE` differs.
    #[error("trigger {trigger} SQL differs")]
    TriggerSqlDiffer {
        /// The trigger name.
        trigger: String,
    },
    /// The view is on this side only.
    #[error("view {view} is on this side only")]
    ViewOnlyHere {
        /// The view name.
        view: String,
    },
    /// The view is on the other side only.
    #[error("view {view} is on the other side only")]
    ViewOnlyThere {
        /// The view name.
        view: String,
    },
    /// Both shapes hold the view but its `CREATE` differs.
    #[error("view {view} SQL differs")]
    ViewSqlDiffer {
        /// The view name.
        view: String,
    },
}

/// A failure to read the shape of an open SQLite database.
#[derive(Debug, thiserror::Error)]
pub enum ShapeError {
    /// SQLite refused a catalogue read or a pragma.
    #[error("reading the tier shape from SQLite, {0}")]
    Sqlite(#[from] diesel::result::Error),
}

/// Read the shape of the `main` schema of an open SQLite database.
///
/// The tables named `sqlite_%` and `_connetto%` are the database's own
/// machinery and connetto's internal tables, so the shape excludes them,
/// together with the autoindexes SQLite builds for its own constraints. The
/// result is in name order, independent of the order the objects were
/// created.
///
/// # Errors
///
/// [`ShapeError::Sqlite`] when a catalogue read or a pragma fails.
pub fn read_tier_shape(conn: &mut SqliteConnection) -> Result<TierShape, ShapeError> {
    use diesel::{QueryDsl, RunQueryDsl};

    let rows = tier_sqlite_schema::table
        .select((
            tier_sqlite_schema::kind,
            tier_sqlite_schema::name,
            tier_sqlite_schema::owner_table,
            tier_sqlite_schema::statement,
        ))
        .load::<(String, String, String, Option<String>)>(conn)?;

    let mut tables = BTreeMap::new();
    let mut triggers = BTreeMap::new();
    let mut views = BTreeMap::new();

    for (kind, name, table, statement) in rows {
        let Some(statement) = statement else {
            // The rows without a statement are SQLite's own machinery, which
            // the name filters below drop anyway.
            continue;
        };
        match kind.as_str() {
            "table" if table == name => {
                if name.starts_with("sqlite_") || name.starts_with("_connetto") {
                    continue;
                }
                let columns = table_xinfo(conn, &name)?;
                let indexes = table_indexes(conn, &name)?;
                tables.insert(
                    name.clone(),
                    TierTable {
                        name,
                        columns,
                        indexes,
                        create_sql: statement,
                    },
                );
            }
            "trigger" => {
                if tables
                    .keys()
                    .any(|owner| owner.eq_ignore_ascii_case(&table))
                {
                    triggers.insert(name, statement);
                }
            }
            "view" => {
                views.insert(name, statement);
            }
            _ => {}
        }
    }

    Ok(TierShape {
        tables,
        triggers,
        views,
    })
}

/// The rows `PRAGMA table_xinfo` reports for one table.
#[derive(diesel::QueryableByName)]
struct TableXinfoRow {
    /// The column's position in the table.
    #[diesel(column_name = "cid")]
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    _cid: i64,
    /// The column name.
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
    /// The declared type.
    #[diesel(column_name = "type")]
    #[diesel(sql_type = diesel::sql_types::Text)]
    declared_type: String,
    /// The `NOT NULL` flag.
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    notnull: i64,
    /// The default expression.
    #[diesel(column_name = "dflt_value")]
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    default: Option<String>,
    /// The primary key position.
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    pk: i64,
    /// The hidden flag.
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    hidden: i64,
}

/// The rows `PRAGMA index_list` reports for one table.
#[derive(diesel::QueryableByName)]
struct IndexListRow {
    /// The index's position in the list.
    #[diesel(column_name = "seq")]
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    _seq: i64,
    /// The index name.
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
    /// The unique flag.
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    unique: i64,
    /// Where the index came from.
    #[diesel(sql_type = diesel::sql_types::Text)]
    origin: String,
    /// The partial flag.
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    partial: i64,
}

/// The rows `PRAGMA index_xinfo` reports for one index.
#[derive(diesel::QueryableByName)]
struct IndexXinfoRow {
    /// The term's position in the index.
    #[diesel(column_name = "seqno")]
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    _seqno: i64,
    /// The term's column position, -2 for an expression and -1 for the pragma's implicit rowid row.
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    cid: i64,
    /// The term's column name, absent for an expression.
    #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
    name: Option<String>,
}

/// The columns of one table, from `table_xinfo`, which diesel has no query
/// type for since it is a pragma.
fn table_xinfo(conn: &mut SqliteConnection, table: &str) -> Result<Vec<TierColumn>, ShapeError> {
    use diesel::RunQueryDsl;
    let sql = format!("PRAGMA table_xinfo({})", quote_ident(table));
    let rows = sql_query(&sql).load::<TableXinfoRow>(conn)?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let pk = if row.pk > 0 {
                Some(u32::try_from(row.pk).expect("a primary key position fits in u32"))
            } else {
                None
            };
            TierColumn {
                name: row.name,
                declared_type: row.declared_type,
                notnull: row.notnull != 0,
                default: row.default,
                pk,
                hidden: row.hidden,
            }
        })
        .collect())
}

/// The indexes of one table, from `index_list` and `index_xinfo`, the two
/// pragmas diesel has no query type for. The `index_xinfo` read selects its
/// own columns, so it is stable across the pragma's shape changes.
fn table_indexes(conn: &mut SqliteConnection, table: &str) -> Result<Vec<TierIndex>, ShapeError> {
    use diesel::RunQueryDsl;
    let list_sql = format!("PRAGMA index_list({})", quote_ident(table));
    let listed = sql_query(&list_sql).load::<IndexListRow>(conn)?;
    let mut indexes = Vec::new();
    for row in listed {
        if row.name.starts_with("sqlite_autoindex_") {
            continue;
        }
        // The pragma argument is a string naming the object, so the name is
        // embedded as a literal with its own quotes doubled.
        let xinfo_sql = format!(
            "SELECT seqno, cid, name FROM pragma_index_xinfo('{}')",
            row.name.replace('\'', "''")
        );
        let columns = sql_query(&xinfo_sql)
            .load::<IndexXinfoRow>(conn)?
            .into_iter()
            // The row the pragma appends for the table's implicit rowid is
            // not a term the index declares, so it does not name a column.
            .filter(|row| row.cid != -1)
            .map(|row| row.name.unwrap_or_default())
            .collect::<Vec<String>>();
        indexes.push(TierIndex {
            name: row.name,
            unique: row.unique != 0,
            origin: row.origin,
            partial: row.partial != 0,
            columns,
        });
    }
    indexes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(indexes)
}

impl TierShape {
    /// The differences between this shape and `other`, readable, in the
    /// order tables, then triggers, then views, each by name.
    #[must_use]
    pub fn diff(&self, other: &TierShape) -> Vec<ShapeDifference> {
        let mut diff = Vec::new();
        for (name, table) in &self.tables {
            match other.tables.get(name) {
                Some(other_table) => {
                    let detail = columns_detail(&table.columns, &other_table.columns);
                    if !detail.is_empty() {
                        diff.push(ShapeDifference::ColumnsDiffer {
                            table: name.clone(),
                            detail,
                        });
                    }
                    let detail = indexes_detail(&table.indexes, &other_table.indexes);
                    if !detail.is_empty() {
                        diff.push(ShapeDifference::IndexesDiffer {
                            table: name.clone(),
                            detail,
                        });
                    }
                }
                None => diff.push(ShapeDifference::TableOnlyHere {
                    table: name.clone(),
                }),
            }
        }
        for name in other.tables.keys() {
            if !self.tables.contains_key(name) {
                diff.push(ShapeDifference::TableOnlyThere {
                    table: name.clone(),
                });
            }
        }
        for (name, statement) in &self.triggers {
            match other.triggers.get(name) {
                Some(other_statement) if other_statement == statement => {}
                Some(_) => diff.push(ShapeDifference::TriggerSqlDiffer {
                    trigger: name.clone(),
                }),
                None => diff.push(ShapeDifference::TriggerOnlyHere {
                    trigger: name.clone(),
                }),
            }
        }
        for name in other.triggers.keys() {
            if !self.triggers.contains_key(name) {
                diff.push(ShapeDifference::TriggerOnlyThere {
                    trigger: name.clone(),
                });
            }
        }
        for (name, statement) in &self.views {
            match other.views.get(name) {
                Some(other_statement) if other_statement == statement => {}
                Some(_) => diff.push(ShapeDifference::ViewSqlDiffer { view: name.clone() }),
                None => diff.push(ShapeDifference::ViewOnlyHere { view: name.clone() }),
            }
        }
        for name in other.views.keys() {
            if !self.views.contains_key(name) {
                diff.push(ShapeDifference::ViewOnlyThere { view: name.clone() });
            }
        }
        diff
    }
}

/// The column differences between two tables' columns, readable, or empty
/// when they agree.
fn columns_detail(here: &[TierColumn], there: &[TierColumn]) -> String {
    let here_map: BTreeMap<&str, &TierColumn> = here
        .iter()
        .map(|column| (column.name.as_str(), column))
        .collect();
    let there_map: BTreeMap<&str, &TierColumn> = there
        .iter()
        .map(|column| (column.name.as_str(), column))
        .collect();
    let mut names: BTreeSet<&str> = here_map.keys().copied().collect();
    names.extend(there_map.keys().copied());
    let mut notes = Vec::new();
    for name in names {
        match (here_map.get(name), there_map.get(name)) {
            (Some(left), Some(right)) => {
                if left.declared_type != right.declared_type {
                    notes.push(format!(
                        "column {name} type changed from {} to {}",
                        left.declared_type, right.declared_type
                    ));
                }
                if left.notnull != right.notnull {
                    notes.push(format!(
                        "column {name} NOT NULL changed from {} to {}",
                        left.notnull, right.notnull
                    ));
                }
                if left.default != right.default {
                    notes.push(format!(
                        "column {name} default changed from {} to {}",
                        display_default(left.default.as_deref()),
                        display_default(right.default.as_deref())
                    ));
                }
                if left.pk != right.pk {
                    notes.push(format!(
                        "column {name} primary key position changed from {} to {}",
                        display_position(left.pk),
                        display_position(right.pk)
                    ));
                }
                if left.hidden != right.hidden {
                    notes.push(format!(
                        "column {name} hidden flag changed from {} to {}",
                        left.hidden, right.hidden
                    ));
                }
            }
            (Some(_), None) => notes.push(format!("column {name} was dropped")),
            (None, Some(_)) => notes.push(format!("column {name} was added")),
            (None, None) => {}
        }
    }
    notes.join(", ")
}

/// The index differences between two tables' indexes, readable, or empty
/// when they agree.
fn indexes_detail(here: &[TierIndex], there: &[TierIndex]) -> String {
    let here_map: BTreeMap<&str, &TierIndex> = here
        .iter()
        .map(|index| (index.name.as_str(), index))
        .collect();
    let there_map: BTreeMap<&str, &TierIndex> = there
        .iter()
        .map(|index| (index.name.as_str(), index))
        .collect();
    let mut names: BTreeSet<&str> = here_map.keys().copied().collect();
    names.extend(there_map.keys().copied());
    let mut notes = Vec::new();
    for name in names {
        match (here_map.get(name), there_map.get(name)) {
            (Some(left), Some(right)) => {
                if left.unique != right.unique {
                    notes.push(format!(
                        "index {name} unique changed from {} to {}",
                        left.unique, right.unique
                    ));
                }
                if left.partial != right.partial {
                    notes.push(format!(
                        "index {name} partial changed from {} to {}",
                        left.partial, right.partial
                    ));
                }
                if left.columns != right.columns {
                    notes.push(format!(
                        "index {name} columns changed from {:?} to {:?}",
                        left.columns, right.columns
                    ));
                }
            }
            (Some(_), None) => notes.push(format!("index {name} was dropped")),
            (None, Some(_)) => notes.push(format!("index {name} was added")),
            (None, None) => {}
        }
    }
    notes.join(", ")
}

/// A default expression for a diff note, `none` when there is none.
fn display_default(default: Option<&str>) -> String {
    default.unwrap_or("none").to_string()
}

/// A primary key position for a diff note, `none` when the column holds
/// none.
fn display_position(position: Option<u32>) -> String {
    position.map_or_else(|| "none".to_string(), |position| position.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::Connection;
    use diesel::connection::SimpleConnection;

    fn open(ddl: &str) -> SqliteConnection {
        let mut conn = SqliteConnection::establish(":memory:").expect("open the probe");
        conn.batch_execute(ddl).expect("apply the DDL");
        conn
    }

    /// A shape read covers tables, columns, indexes, triggers and views, and
    /// excludes connetto's internal tables.
    #[test]
    fn a_shape_read_covers_the_schema_and_excludes_internal_machinery() {
        let mut conn = open(
            "CREATE TABLE notes (\
                 id INTEGER PRIMARY KEY, \
                 body TEXT DEFAULT 'x', \
                 note INTEGER GENERATED ALWAYS AS (id + 1) VIRTUAL);
             CREATE INDEX notes_body ON notes(body);
             CREATE TRIGGER notes_touch AFTER INSERT ON notes BEGIN SELECT 1; END;
             CREATE VIEW note_words AS SELECT body FROM notes;
             CREATE TABLE _connetto_build (hash TEXT);",
        );
        let shape = read_tier_shape(&mut conn).expect("read the shape");
        assert_eq!(
            shape.tables.len(),
            1,
            "only the tier's table survives the filter"
        );
        let notes = shape.tables.get("notes").expect("the tier's table is read");
        assert_eq!(
            notes.columns,
            vec![
                TierColumn {
                    name: "id".into(),
                    declared_type: "INTEGER".into(),
                    notnull: false,
                    default: None,
                    pk: Some(1),
                    hidden: 0,
                },
                TierColumn {
                    name: "body".into(),
                    declared_type: "TEXT".into(),
                    notnull: false,
                    default: Some("'x'".into()),
                    pk: None,
                    hidden: 0,
                },
                TierColumn {
                    name: "note".into(),
                    declared_type: "INTEGER".into(),
                    notnull: false,
                    default: None,
                    pk: None,
                    hidden: 2,
                },
            ]
        );
        assert_eq!(
            notes.indexes,
            vec![TierIndex {
                name: "notes_body".into(),
                unique: false,
                origin: "c".into(),
                partial: false,
                columns: vec!["body".into()],
            }]
        );
        assert_eq!(
            shape.triggers.get("notes_touch"),
            Some(
                &"CREATE TRIGGER notes_touch AFTER INSERT ON notes \
                 BEGIN SELECT 1; END"
                    .to_string()
            )
        );
        assert_eq!(
            shape.views.get("note_words"),
            Some(&"CREATE VIEW note_words AS SELECT body FROM notes".to_string())
        );
    }

    /// A trigger that fires on the table with different case spelling
    /// counts as the table's, so it stays in the shape.
    #[test]
    fn a_trigger_named_on_the_table_with_different_case_is_in_the_shape() {
        let mut conn = open(
            "CREATE TABLE notes (a TEXT);
             CREATE TRIGGER notes_touch AFTER INSERT ON NOTES BEGIN SELECT 1; END;",
        );
        let shape = read_tier_shape(&mut conn).expect("read the shape");
        assert_eq!(
            shape.triggers.len(),
            1,
            "the trigger stays in the shape under the table's own spelling"
        );
        assert!(shape.triggers.contains_key("notes_touch"));
    }

    /// SQLite's own indexes, built for its own constraints, stay out of the
    /// shape while a named index survives with its columns in index order.
    #[test]
    fn the_shape_ignores_autoindexes_and_keeps_named_indexes() {
        let mut conn = open(
            "CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT UNIQUE, c TEXT);
             CREATE UNIQUE INDEX t_b_c ON t(b, c);",
        );
        let shape = read_tier_shape(&mut conn).expect("read the shape");
        let t = shape.tables.get("t").expect("the table is read");
        assert_eq!(
            t.indexes.len(),
            1,
            "the autoindexes are excluded: {:?}",
            t.indexes
        );
        let index = &t.indexes[0];
        assert_eq!(index.name, "t_b_c");
        assert!(index.unique);
        assert_eq!(index.columns, vec!["b".to_string(), "c".to_string()]);
    }

    /// An expression index term names no column, so the shape records it as
    /// the empty term and keeps the rest of the index's columns.
    #[test]
    fn the_shape_records_expression_terms_as_empty_names() {
        let mut conn = open(
            "CREATE TABLE t (a TEXT, b TEXT, c TEXT);
             CREATE INDEX t_terms ON t(length(a), c);",
        );
        let shape = read_tier_shape(&mut conn).expect("read the shape");
        let t = shape.tables.get("t").expect("the table is read");
        assert_eq!(t.indexes.len(), 1);
        assert_eq!(t.indexes[0].name, "t_terms");
        assert_eq!(t.indexes[0].columns, vec![String::new(), "c".to_string()]);
    }

    /// The same objects built in different orders read as the same shape, so
    /// a migrated tier compares against a scratch built from the DDL.
    #[test]
    fn the_shape_is_deterministic_and_order_independent() {
        let mut first = open(
            "CREATE TABLE b (x INTEGER PRIMARY KEY);
             CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE INDEX a_i ON a(x);",
        );
        let mut second = open(
            "CREATE TABLE a (x INTEGER PRIMARY KEY);
             CREATE INDEX a_i ON a(x);
             CREATE TABLE b (x INTEGER PRIMARY KEY);",
        );
        assert_eq!(
            read_tier_shape(&mut first).expect("read the first"),
            read_tier_shape(&mut second).expect("read the second")
        );
    }

    /// An empty database reads as an empty shape and diffs as no difference.
    #[test]
    fn an_empty_database_reads_an_empty_shape() {
        let mut conn = SqliteConnection::establish(":memory:").expect("open the probe");
        let shape = read_tier_shape(&mut conn).expect("read the shape");
        assert!(shape.tables.is_empty());
        assert!(shape.triggers.is_empty());
        assert!(shape.views.is_empty());
        assert_eq!(shape.diff(&shape), Vec::new());
    }

    /// A diff reports a changed column with a detail that names it, a table
    /// only one side holds, and nothing when the shapes agree.
    #[test]
    fn a_diff_reports_column_and_table_differences_readably() {
        let mut here = open("CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT);");
        let mut there = open(
            "CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT DEFAULT 'x');
             CREATE TABLE extra (x INTEGER PRIMARY KEY);",
        );
        let here_shape = read_tier_shape(&mut here).expect("read the first");
        let there_shape = read_tier_shape(&mut there).expect("read the second");
        let diff = here_shape.diff(&there_shape);
        let columns = diff
            .iter()
            .find_map(|difference| match difference {
                ShapeDifference::ColumnsDiffer { table, detail } if table == "t" => {
                    Some(detail.as_str())
                }
                _ => None,
            })
            .expect("the changed column is reported");
        assert!(
            columns.contains('b'),
            "the detail names the column: {columns}"
        );
        assert!(diff.iter().any(|difference| {
            matches!(
                difference,
                ShapeDifference::TableOnlyThere { table } if table == "extra"
            )
        }));
        assert!(there_shape.diff(&here_shape).iter().any(|difference| {
            matches!(
                difference,
                ShapeDifference::TableOnlyHere { table } if table == "extra"
            )
        }));
    }

    /// Index, trigger and view differences each reach the diff with their
    /// object named.
    #[test]
    fn a_diff_reports_index_trigger_and_view_differences() {
        let mut here = open(
            "CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT);
             CREATE INDEX t_i ON t(b);
             CREATE TRIGGER tr AFTER INSERT ON t BEGIN SELECT 1; END;
             CREATE VIEW v AS SELECT * FROM t;",
        );
        let mut there = open(
            "CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT);
             CREATE INDEX t_i ON t(a, b);
             CREATE TRIGGER tr AFTER UPDATE ON t BEGIN SELECT 1; END;",
        );
        let here_shape = read_tier_shape(&mut here).expect("read the first");
        let there_shape = read_tier_shape(&mut there).expect("read the second");
        let diff = here_shape.diff(&there_shape);
        assert!(diff.iter().any(|difference| {
            matches!(
                difference,
                ShapeDifference::IndexesDiffer { table, .. } if table == "t"
            )
        }));
        assert!(diff.iter().any(|difference| {
            matches!(
                difference,
                ShapeDifference::TriggerSqlDiffer { trigger } if trigger == "tr"
            )
        }));
        assert!(diff.iter().any(|difference| {
            matches!(
                difference,
                ShapeDifference::ViewOnlyHere { view } if view == "v"
            )
        }));
    }
}
