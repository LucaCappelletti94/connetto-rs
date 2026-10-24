//! Replay the shared subset of one server frame into the attached
//! `connetto_shared` store under the same server-wins policy as the native
//! apply.
//!
//! The native apply targets only the `main` schema, so a shared table's rows
//! would be dropped. This re-applies just the operations that name a shared
//! table, with hand-built SQL against `connetto_shared`, so the shared store
//! ends up row-for-row with what the native apply would have done had the
//! table lived in `main`.

use std::collections::{HashMap, HashSet};

use diesel::SqliteConnection;
use diesel::connection::SimpleConnection;
use diesel::prelude::*;
use diesel::query_builder::{BoxedSqlQuery, SqlQuery};
use diesel::sql_types::{BigInt, Binary, Double, Nullable, Text};
use sqlite_diff_rs::{
    ChangesetFormat, ChangesetOp, DiffSet, DynTable, ParsedDiffSet, PatchsetFormat, PatchsetOp,
    TableSchema, Value,
};

use crate::quote_ident;
use crate::{ClientError, SHARED_SCHEMA};

/// Savepoint bounding one shared replay, mirroring the native apply's
/// `changeset_apply` savepoint (sqlite3.c `sessionChangesetApply`).
const REPLAY_SAVEPOINT: &str = "_connetto_shared_replay";

/// Replay the shared subset of `bytes` into `connetto_shared`, keeping only the
/// tables named in `shared_tables` and applying them under the same server-wins
/// policy the native apply uses.
pub(crate) fn apply(
    conn: &mut SqliteConnection,
    bytes: &[u8],
    shared_tables: &HashSet<String>,
) -> Result<(), ClientError> {
    let parsed = ParsedDiffSet::parse(bytes).map_err(|err| {
        ClientError::Apply(format!("parsing a frame for its shared replay: {err:?}"))
    })?;
    conn.batch_execute(&format!("SAVEPOINT {REPLAY_SAVEPOINT}"))?;
    conn.batch_execute("PRAGMA defer_foreign_keys = 1")?;
    let result = match &parsed {
        ParsedDiffSet::Changeset(diff) => replay_changeset(conn, diff, shared_tables),
        ParsedDiffSet::Patchset(diff) => replay_patchset(conn, diff, shared_tables),
    };
    // Reset the deferral and settle the savepoint without clobbering the
    // replay's own outcome.
    let _ = conn.batch_execute("PRAGMA defer_foreign_keys = 0");
    if result.is_ok() {
        conn.batch_execute(&format!("RELEASE {REPLAY_SAVEPOINT}"))?;
    } else {
        let _ = conn.batch_execute(&format!("ROLLBACK TO {REPLAY_SAVEPOINT}"));
        let _ = conn.batch_execute(&format!("RELEASE {REPLAY_SAVEPOINT}"));
    }
    result
}

/// The local shape of a shared table as the native apply sees it: the
/// effective column names and primary-key ordinals, with a synthetic rowid
/// slot first when the table declares no primary key (sqlite3.c
/// `sessionTableInfo`).
struct TableShape {
    columns: Vec<String>,
    pk: Vec<u8>,
}

#[derive(diesel::QueryableByName)]
struct ColumnRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pk: i32,
}

/// Read one shared table's effective shape, or `None` when it is absent.
/// The table name and column layout are runtime values carried by the
/// frame, so the statements below are raw `sql_query`, the same necessity
/// as the archive's `write_row`; a `table!` schema cannot name them.
fn table_shape(
    conn: &mut SqliteConnection,
    table: &str,
) -> Result<Option<TableShape>, ClientError> {
    let rows: Vec<ColumnRow> = diesel::sql_query(format!(
        "SELECT name, pk FROM {}.pragma_table_info(?) ORDER BY cid",
        quote_ident(SHARED_SCHEMA)
    ))
    .bind::<Text, _>(table)
    .load(conn)?;
    if rows.is_empty() {
        return Ok(None);
    }
    let has_pk = rows.iter().any(|row| row.pk != 0);
    let mut columns = Vec::with_capacity(rows.len() + usize::from(!has_pk));
    let mut pk = Vec::with_capacity(rows.len() + usize::from(!has_pk));
    if !has_pk {
        // No declared primary key: the native apply keys the table by its
        // implicit rowid, which it models as a column of its own ahead of the
        // declared ones, so a frame that names no key can never match it.
        columns.push("rowid".to_owned());
        pk.push(1);
    }
    for row in rows {
        columns.push(row.name);
        pk.push(u8::try_from(row.pk).map_err(|_| {
            ClientError::Apply(format!("{table} declares an out-of-range key ordinal"))
        })?);
    }
    Ok(Some(TableShape { columns, pk }))
}

/// Whether the frame section's width and primary-key ordinals fit the local
/// shape. A table is skipped, not an error, when it is absent, narrower than
/// the frame, missing a primary-key column the frame carries, or disagreeing
/// on the primary-key flags (sqlite3.c `sessionChangesetApply`).
fn shape_matches(shape: &TableShape, frame_ncol: usize, frame_pk: &[u8]) -> bool {
    let local_ncol = shape.columns.len();
    if local_ncol == 0 || local_ncol < frame_ncol {
        return false;
    }
    let mut min_col = 0;
    for (i, &flag) in shape.pk.iter().enumerate() {
        if flag != 0 {
            min_col = i + 1;
        }
    }
    if frame_ncol < min_col {
        return false;
    }
    shape.pk[..frame_ncol] == frame_pk[..frame_ncol]
}

/// The shared tables of one frame and their local shapes, keyed by lowercased
/// name, holding only the tables the native apply would actually apply.
fn shared_shapes<'a>(
    conn: &mut SqliteConnection,
    tables: impl Iterator<Item = &'a TableSchema<String>>,
    shared_tables: &HashSet<String>,
) -> Result<HashMap<String, TableShape>, ClientError> {
    let mut shapes = HashMap::new();
    for table in tables {
        let name = table.name();
        let key = name.to_lowercase();
        if !shared_tables.contains(&key) || shapes.contains_key(&key) {
            continue;
        }
        let Some(shape) = table_shape(conn, name)? else {
            continue;
        };
        if shape_matches(&shape, table.number_of_columns(), table.pk_flags()) {
            shapes.insert(key, shape);
        }
    }
    Ok(shapes)
}

fn replay_changeset(
    conn: &mut SqliteConnection,
    diff: &DiffSet<ChangesetFormat, TableSchema<String>, String, Vec<u8>>,
    shared_tables: &HashSet<String>,
) -> Result<(), ClientError> {
    let shapes = shared_shapes(conn, diff.tables(), shared_tables)?;
    for op in diff.iter() {
        let table = op.table();
        let key = table.name().to_lowercase();
        let Some(shape) = shapes.get(&key) else {
            continue;
        };
        let frame_pk = table.pk_flags();
        match op {
            ChangesetOp::Insert { values, .. } => {
                let key_vals = pk_values_by_column(frame_pk, |i| values[i].clone());
                apply_insert(conn, shape, table.name(), values, &key_vals)?;
            }
            ChangesetOp::Update { values, .. } => {
                let set_cols = values
                    .iter()
                    .enumerate()
                    .filter(|(_, (old, new))| is_changed(old.as_ref(), new.as_ref()))
                    .map(|(i, (_, new))| {
                        (
                            i,
                            new.clone().expect("a changed column carries a new value"),
                        )
                    })
                    .collect::<Vec<_>>();
                let key_vals = pk_values_by_column(frame_pk, |i| {
                    values[i]
                        .0
                        .clone()
                        .or_else(|| values[i].1.clone())
                        .unwrap_or(Value::Null)
                });
                apply_update(conn, shape, table.name(), &set_cols, &key_vals)?;
            }
            ChangesetOp::Delete { old_values, .. } => {
                let key_vals = pk_values_by_column(frame_pk, |i| old_values[i].clone());
                delete_by_key(conn, shape, table.name(), &key_vals)?;
            }
        }
    }
    Ok(())
}

fn replay_patchset(
    conn: &mut SqliteConnection,
    diff: &DiffSet<PatchsetFormat, TableSchema<String>, String, Vec<u8>>,
    shared_tables: &HashSet<String>,
) -> Result<(), ClientError> {
    let shapes = shared_shapes(conn, diff.tables(), shared_tables)?;
    for op in diff.iter() {
        let table = op.table();
        let key = table.name().to_lowercase();
        let Some(shape) = shapes.get(&key) else {
            continue;
        };
        let frame_pk = table.pk_flags();
        match op {
            PatchsetOp::Insert { values, .. } => {
                let key_vals = pk_values_by_column(frame_pk, |i| values[i].clone());
                apply_insert(conn, shape, table.name(), values, &key_vals)?;
            }
            PatchsetOp::Update { pk, entries, .. } => {
                let set_cols = entries
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| frame_pk[*i] == 0)
                    .filter_map(|(i, ((), new))| new.clone().map(|value| (i, value)))
                    .collect::<Vec<_>>();
                let key_vals = patchset_key_vals(frame_pk, pk);
                apply_update(conn, shape, table.name(), &set_cols, &key_vals)?;
            }
            PatchsetOp::Delete { pk, .. } => {
                let key_vals = patchset_key_vals(frame_pk, pk);
                delete_by_key(conn, shape, table.name(), &key_vals)?;
            }
        }
    }
    Ok(())
}

/// Bind one value to a boxed SQL query by its own storage class, so a blob
/// stays a blob and text holding a NUL survives.
fn bind_one<'a>(
    query: BoxedSqlQuery<'a, diesel::sqlite::Sqlite, SqlQuery>,
    value: &Value<String, Vec<u8>>,
) -> BoxedSqlQuery<'a, diesel::sqlite::Sqlite, SqlQuery> {
    match value {
        Value::Null => query.bind::<Nullable<Text>, _>(None::<String>),
        Value::Integer(number) => query.bind::<BigInt, _>(*number),
        Value::Real(number) => query.bind::<Double, _>(*number),
        Value::Text(text) => query.bind::<Text, _>(text.clone()),
        Value::Blob(bytes) => query.bind::<Binary, _>(bytes.clone()),
    }
}

/// The primary-key conjunction of one operation, in the order the keys were
/// collected.
fn where_clause(shape: &TableShape, key_vals: &[(usize, Value<String, Vec<u8>>)]) -> String {
    key_vals
        .iter()
        .map(|(i, _)| format!("{} = ?", quote_ident(&shape.columns[*i])))
        .collect::<Vec<_>>()
        .join(" AND ")
}

/// Delete the row the key names; a no-op when it is absent. A row-level
/// constraint failure is dropped like the native apply does.
fn delete_by_key(
    conn: &mut SqliteConnection,
    shape: &TableShape,
    table: &str,
    key_vals: &[(usize, Value<String, Vec<u8>>)],
) -> Result<(), ClientError> {
    let sql = format!(
        "DELETE FROM {} WHERE {}",
        table_ref(table),
        where_clause(shape, key_vals)
    );
    let mut query = diesel::sql_query(sql).into_boxed::<diesel::sqlite::Sqlite>();
    for (_, value) in key_vals {
        query = bind_one(query, value);
    }
    match query.execute(conn) {
        Ok(_) => Ok(()),
        Err(err) if omit_on_constraint(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Insert one row, replacing the row its key names, under the native apply's
/// conflict outcome.
fn apply_insert(
    conn: &mut SqliteConnection,
    shape: &TableShape,
    table: &str,
    values: &[Value<String, Vec<u8>>],
    key_vals: &[(usize, Value<String, Vec<u8>>)],
) -> Result<(), ClientError> {
    delete_by_key(conn, shape, table, key_vals)?;
    let cols = shape
        .columns
        .iter()
        .take(values.len())
        .map(|column| quote_ident(column))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "INSERT INTO {} ({}) VALUES({})",
        table_ref(table),
        cols,
        vec!["?"; values.len()].join(",")
    );
    let mut query = diesel::sql_query(sql).into_boxed::<diesel::sqlite::Sqlite>();
    for value in values {
        query = bind_one(query, value);
    }
    match query.execute(conn) {
        Ok(_) => Ok(()),
        Err(err) if omit_on_constraint(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Update the carried columns of the row the key names; a no-op when the key is
/// absent or nothing was carried.
fn apply_update(
    conn: &mut SqliteConnection,
    shape: &TableShape,
    table: &str,
    set_cols: &[(usize, Value<String, Vec<u8>>)],
    key_vals: &[(usize, Value<String, Vec<u8>>)],
) -> Result<(), ClientError> {
    if set_cols.is_empty() {
        return Ok(());
    }
    let set_sql = set_cols
        .iter()
        .map(|(i, _)| format!("{} = ?", quote_ident(&shape.columns[*i])))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "UPDATE {} SET {} WHERE {}",
        table_ref(table),
        set_sql,
        where_clause(shape, key_vals)
    );
    let mut query = diesel::sql_query(sql).into_boxed::<diesel::sqlite::Sqlite>();
    for (_, value) in set_cols {
        query = bind_one(query, value);
    }
    for (_, value) in key_vals {
        query = bind_one(query, value);
    }
    match query.execute(conn) {
        Ok(_) => Ok(()),
        Err(err) if omit_on_constraint(&err) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Whether a statement error is a row-level constraint the server-wins policy
/// drops (Omit) rather than aborting on: a uniqueness, not-null, or check
/// failure. Foreign keys are deferred, so they never surface mid-statement, and
/// anything else is a hard failure.
fn omit_on_constraint(err: &diesel::result::Error) -> bool {
    use diesel::result::{DatabaseErrorKind, Error};
    matches!(
        err,
        Error::DatabaseError(
            DatabaseErrorKind::UniqueViolation
                | DatabaseErrorKind::NotNullViolation
                | DatabaseErrorKind::CheckViolation,
            _
        )
    )
}

/// The qualified name of a shared table.
fn table_ref(table: &str) -> String {
    format!("{}.{}", quote_ident(SHARED_SCHEMA), quote_ident(table))
}

/// A changeset (old, new) pair changed, by the same rule the wire uses:
/// undefined-new is unchanged, both-present changed on difference, and
/// new-without-old is changed.
fn is_changed(old: Option<&Value<String, Vec<u8>>>, new: Option<&Value<String, Vec<u8>>>) -> bool {
    match (old, new) {
        (_, None) => false,
        (Some(o), Some(n)) => o != n,
        (None, Some(_)) => true,
    }
}

/// The primary-key columns and their values, in frame-column order, reading the
/// value at each column from `value_at`.
fn pk_values_by_column<F>(frame_pk: &[u8], value_at: F) -> Vec<(usize, Value<String, Vec<u8>>)>
where
    F: Fn(usize) -> Value<String, Vec<u8>>,
{
    frame_pk
        .iter()
        .enumerate()
        .filter(|(_, flag)| **flag != 0)
        .map(|(i, _)| (i, value_at(i)))
        .collect()
}

/// The primary-key columns and their values, in frame-column order, from a
/// patchset's key-ordered `pk` list.
fn patchset_key_vals(
    frame_pk: &[u8],
    pk: &[Value<String, Vec<u8>>],
) -> Vec<(usize, Value<String, Vec<u8>>)> {
    frame_pk
        .iter()
        .enumerate()
        .filter(|(_, flag)| **flag != 0)
        .map(|(i, &flag)| (i, pk[usize::from(flag - 1)].clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_wins;
    use diesel_sqlite_session::SqliteSessionExt;
    use sqlite_diff_rs::{DiffOps, Insert, PatchDelete, PatchSet, SimpleTable, Update};

    type PatchInsert = Insert<SimpleTable, String, Vec<u8>>;
    type PatchUpdate = Update<SimpleTable, PatchsetFormat, String, Vec<u8>>;
    type Patchset = PatchSet<SimpleTable, String, Vec<u8>>;

    const NOTES: &str = "(id INTEGER PRIMARY KEY, title TEXT, body TEXT)";
    const PAYLOAD: &str = "(id INTEGER PRIMARY KEY, payload BLOB, label TEXT)";
    const COMP: &str = "(a TEXT, b INTEGER, c TEXT, PRIMARY KEY (a, b))";
    const CHECKED: &str = "(id INTEGER PRIMARY KEY, val INTEGER, CHECK (val > 0))";

    fn notes_schema() -> SimpleTable {
        SimpleTable::new("notes", &["id", "title", "body"], &[0])
    }

    fn shared_set() -> HashSet<String> {
        HashSet::from(["notes".to_owned()])
    }

    fn insert(schema: &SimpleTable, id: i64, title: &str, body: &str) -> PatchInsert {
        PatchInsert::from(schema.clone())
            .set(0, id)
            .expect("id")
            .set(1, title)
            .expect("title")
            .set(2, body)
            .expect("body")
    }

    fn new_conn() -> SqliteConnection {
        SqliteConnection::establish(":memory:").expect("an in-memory database")
    }

    /// Apply the same frame both ways and let `compare` check the outcome:
    /// natively into `main` on one connection, and through the shared replay
    /// into `connetto_shared` on another.
    fn differential<R>(
        frame: &[u8],
        ddl: &str,
        shared_ddl: Option<&str>,
        seed: impl Fn(&str) -> Vec<String>,
        compare: impl Fn(&mut SqliteConnection, &mut SqliteConnection) -> R,
    ) {
        let mut native = new_conn();
        native
            .batch_execute(&format!("CREATE TABLE main.notes {ddl}"))
            .expect("create the native table");
        for statement in seed("main") {
            native
                .batch_execute(&statement)
                .expect("seed the native table");
        }
        native
            .apply_patchset(frame, server_wins)
            .expect("the native apply");

        let mut shared = new_conn();
        shared
            .batch_execute("ATTACH DATABASE ':memory:' AS connetto_shared")
            .expect("attach the shared store");
        if let Some(shared_ddl) = shared_ddl {
            shared
                .batch_execute(&format!("CREATE TABLE connetto_shared.notes {shared_ddl}"))
                .expect("create the shared table");
        }
        for statement in seed("connetto_shared") {
            shared
                .batch_execute(&statement)
                .expect("seed the shared table");
        }
        apply(&mut shared, frame, &shared_set()).expect("the shared replay");

        compare(&mut native, &mut shared);
    }

    #[derive(diesel::QueryableByName, PartialEq, Debug)]
    struct NoteRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        id: i64,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        title: Option<String>,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        body: Option<String>,
    }

    fn read_notes(conn: &mut SqliteConnection, schema: &str) -> Vec<NoteRow> {
        diesel::sql_query(format!(
            "SELECT id, title, body FROM {schema}.notes ORDER BY id"
        ))
        .load(conn)
        .expect("read the notes rows")
    }

    fn same_notes(native: &mut SqliteConnection, shared: &mut SqliteConnection) {
        assert_eq!(
            read_notes(native, "main"),
            read_notes(shared, "connetto_shared"),
            "the shared replay must land the rows the native apply lands"
        );
    }

    #[test]
    fn inserts_and_replaces_match_native() {
        let schema = notes_schema();
        let frame: Vec<u8> = Patchset::new()
            .insert(insert(&schema, 1, "one", "first"))
            .insert(insert(&schema, 2, "two", "second"))
            // Re-inserting id 1 replaces the row it conflicts with.
            .insert(insert(&schema, 1, "one", "replaced"))
            .build();
        differential(&frame, NOTES, Some(NOTES), |_| Vec::new(), same_notes);
    }

    fn seeded_notes(schema: &str) -> Vec<String> {
        vec![format!(
            "INSERT INTO {schema}.notes VALUES (1, 'one', 'first'), (2, 'two', 'second'), (3, 'three', NULL)"
        )]
    }

    #[test]
    fn updates_to_stored_rows_match_native() {
        let schema = notes_schema();
        let update = |id: i64, column: usize, value: &str| {
            PatchUpdate::from(schema.clone())
                .set(0, id)
                .expect("key")
                .set(column, value)
                .expect("value")
        };
        let frame: Vec<u8> = Patchset::new()
            .update(update(1, 2, "updated"))
            .update(update(3, 1, "retitled"))
            // An update naming a key that is not stored changes nothing.
            .update(update(99, 2, "ghost"))
            .build();
        differential(&frame, NOTES, Some(NOTES), seeded_notes, same_notes);
    }

    #[test]
    fn a_captured_changeset_matches_native() {
        let mut source = new_conn();
        source
            .batch_execute(&format!("CREATE TABLE notes {NOTES}"))
            .expect("create the source table");
        for statement in seeded_notes("main") {
            source.batch_execute(&statement).expect("seed the source");
        }
        let mut session = source.create_session().expect("a capture session");
        session.attach_all().expect("capture every table");
        source
            .batch_execute(
                "UPDATE notes SET title = 'renamed' WHERE id = 1;
                 DELETE FROM notes WHERE id = 2;
                 UPDATE notes SET body = 'filled' WHERE id = 3;
                 INSERT INTO notes VALUES (4, 'four', 'fourth');",
            )
            .expect("change the source");
        let frame = session.changeset().expect("the captured changeset");
        drop(session);
        differential(&frame, NOTES, Some(NOTES), seeded_notes, same_notes);
    }

    #[test]
    fn deletes_match_native() {
        let schema = notes_schema();
        let frame: Vec<u8> = Patchset::new()
            .insert(insert(&schema, 1, "one", "first"))
            .insert(insert(&schema, 2, "two", "second"))
            .delete(PatchDelete::new(schema.clone(), vec![1i64.into()]))
            // Deleting a key that is not there is a no-op on both sides.
            .delete(PatchDelete::new(schema.clone(), vec![99i64.into()]))
            .build();
        differential(&frame, NOTES, Some(NOTES), |_| Vec::new(), same_notes);
    }

    #[test]
    fn a_wider_frame_is_skipped_like_native() {
        // The local table has three columns; the frame section has four, so
        // both sides must skip it and leave the seeded row standing.
        let wide = SimpleTable::new("notes", &["id", "title", "body", "extra"], &[0]);
        let frame: Vec<u8> = Patchset::new()
            .insert(
                PatchInsert::from(wide.clone())
                    .set(0, 1i64)
                    .expect("id")
                    .set(1, "one")
                    .expect("title")
                    .set(2, "first")
                    .expect("body")
                    .set(3, "extra")
                    .expect("extra"),
            )
            .build();
        differential(
            &frame,
            NOTES,
            Some(NOTES),
            |schema| {
                vec![format!(
                    "INSERT INTO {schema}.notes VALUES (1, 'keep', 'me')"
                )]
            },
            same_notes,
        );
    }

    #[test]
    fn a_missing_shared_table_is_skipped_like_native() {
        let schema = notes_schema();
        let frame: Vec<u8> = Patchset::new()
            .insert(insert(&schema, 1, "one", "first"))
            .build();
        // The shared store has no table the frame names: the replay skips it
        // and lands nothing, while the native apply applies to its table.
        differential(
            &frame,
            NOTES,
            None,
            |_| Vec::new(),
            |native, shared| {
                assert_eq!(
                    read_notes(native, "main").len(),
                    1,
                    "the native apply lands the row its table can hold"
                );
                let tables: Vec<Name> = diesel::sql_query(
                    "SELECT name FROM connetto_shared.sqlite_master WHERE type = 'table'",
                )
                .load(shared)
                .expect("read the shared store's tables");
                assert!(tables.is_empty(), "an absent shared table takes no rows");
            },
        );
    }

    #[derive(diesel::QueryableByName)]
    struct Name {
        #[diesel(sql_type = diesel::sql_types::Text)]
        #[expect(dead_code, reason = "only the row count is asserted")]
        name: String,
    }
    #[derive(diesel::QueryableByName, PartialEq, Debug)]
    struct PayloadRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        id: i64,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Binary>)]
        payload: Option<Vec<u8>>,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        label: Option<String>,
    }

    fn read_payload(conn: &mut SqliteConnection, schema: &str) -> Vec<PayloadRow> {
        diesel::sql_query(format!(
            "SELECT id, payload, label FROM {schema}.notes ORDER BY id"
        ))
        .load(conn)
        .expect("read the payload rows")
    }

    #[test]
    fn nulls_and_blobs_match_native() {
        let schema = SimpleTable::new("notes", &["id", "payload", "label"], &[0]);
        let frame: Vec<u8> = Patchset::new()
            .insert(
                PatchInsert::from(schema.clone())
                    .set(0, 1i64)
                    .expect("id")
                    .set(1, vec![0u8, 1, 2, 3])
                    .expect("blob")
                    .set(2, Value::Null)
                    .expect("null label"),
            )
            .insert(
                PatchInsert::from(schema.clone())
                    .set(0, 2i64)
                    .expect("id")
                    .set(1, Value::Null)
                    .expect("null blob")
                    .set(2, "hi")
                    .expect("label"),
            )
            .build();
        differential(
            &frame,
            PAYLOAD,
            Some(PAYLOAD),
            |_| Vec::new(),
            |native, shared| {
                assert_eq!(
                    read_payload(native, "main"),
                    read_payload(shared, "connetto_shared")
                );
            },
        );
    }

    #[derive(diesel::QueryableByName, PartialEq, Debug)]
    struct CompRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        a: String,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        b: i64,
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::Text>)]
        c: Option<String>,
    }

    fn read_comp(conn: &mut SqliteConnection, schema: &str) -> Vec<CompRow> {
        diesel::sql_query(format!("SELECT a, b, c FROM {schema}.notes ORDER BY a, b"))
            .load(conn)
            .expect("read the composite rows")
    }

    #[test]
    fn composite_keys_match_native() {
        let schema = SimpleTable::new("notes", &["a", "b", "c"], &[0, 1]);
        let comp_insert = |schema: &SimpleTable, a: &str, b: i64, c: &str| {
            PatchInsert::from(schema.clone())
                .set(0, a)
                .expect("a")
                .set(1, b)
                .expect("b")
                .set(2, c)
                .expect("c")
        };
        let frame: Vec<u8> = Patchset::new()
            .insert(comp_insert(&schema, "one", 1, "x"))
            .insert(comp_insert(&schema, "one", 2, "y"))
            .update(
                PatchUpdate::from(schema.clone())
                    .set(0, "one")
                    .expect("a")
                    .set(1, 1i64)
                    .expect("b")
                    .set(2, "z")
                    .expect("c"),
            )
            .delete(PatchDelete::new(
                schema.clone(),
                vec!["one".into(), 2i64.into()],
            ))
            .build();
        differential(
            &frame,
            COMP,
            Some(COMP),
            |_| Vec::new(),
            |native, shared| {
                assert_eq!(
                    read_comp(native, "main"),
                    read_comp(shared, "connetto_shared")
                );
            },
        );
    }

    #[derive(diesel::QueryableByName, PartialEq, Debug)]
    struct CheckedRow {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        id: i64,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        val: i64,
    }

    fn read_checked(conn: &mut SqliteConnection, schema: &str) -> Vec<CheckedRow> {
        diesel::sql_query(format!("SELECT id, val FROM {schema}.notes ORDER BY id"))
            .load(conn)
            .expect("read the checked rows")
    }

    #[test]
    fn a_check_violation_is_omitted_like_native() {
        let schema = SimpleTable::new("notes", &["id", "val"], &[0]);
        let checked_insert = |schema: &SimpleTable, id: i64, val: i64| {
            PatchInsert::from(schema.clone())
                .set(0, id)
                .expect("id")
                .set(1, val)
                .expect("val")
        };
        let frame: Vec<u8> = Patchset::new()
            .insert(checked_insert(&schema, 1, 5))
            // Violates CHECK (val > 0): both sides must drop it, leaving the
            // valid row standing.
            .insert(checked_insert(&schema, 2, -3))
            .build();
        differential(
            &frame,
            CHECKED,
            Some(CHECKED),
            |_| Vec::new(),
            |native, shared| {
                assert_eq!(
                    read_checked(native, "main"),
                    read_checked(shared, "connetto_shared"),
                    "a check violation is omitted on both sides"
                );
                assert_eq!(
                    read_checked(shared, "connetto_shared").len(),
                    1,
                    "only the valid row survives the check violation"
                );
            },
        );
    }

    #[test]
    fn a_replace_conflict_omitted_by_check_matches_native() {
        // A stored id 1 meets an incoming id 1 the CHECK refuses: the native
        // apply is the oracle for whether the stored row survives.
        let schema = SimpleTable::new("notes", &["id", "val"], &[0]);
        let frame: Vec<u8> = Patchset::new()
            .insert(
                PatchInsert::from(schema)
                    .set(0, 1i64)
                    .expect("id")
                    .set(1, -3i64)
                    .expect("val"),
            )
            .build();
        let seed = |schema: &str| vec![format!("INSERT INTO {schema}.notes VALUES (1, 5)")];
        differential(&frame, CHECKED, Some(CHECKED), seed, |native, shared| {
            assert_eq!(
                read_checked(native, "main"),
                read_checked(shared, "connetto_shared"),
                "a refused replace leaves the same rows on both sides"
            );
        });
    }
}
