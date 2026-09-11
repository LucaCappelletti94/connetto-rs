use std::collections::HashSet;

use diesel::SqliteConnection;
use diesel::prelude::*;
use sha2::{Digest, Sha256};
use sqlite_diff_rs::{DynTable, PatchsetOp};

use crate::ClientError;
use crate::quote_ident;

use super::Cell;

/// One row a record carries.
pub(crate) struct IncomingRow {
    /// The table it belongs to.
    pub(crate) table: String,
    /// That table's columns, in table order.
    pub(crate) columns: Vec<String>,
    /// The primary-key columns, in key order.
    pub(crate) key_columns: Vec<String>,
    /// The primary-key values, in key order.
    pub(crate) key: Vec<Cell>,
    /// Every value, in table order.
    pub(crate) values: Vec<Cell>,
}

/// Index one schema's current rows by table and primary key, read through the
/// same session mechanism the export uses so both sides of a comparison are
/// typed the same way.
pub(crate) type RowIndex = std::collections::HashMap<(String, Vec<Cell>), Vec<Cell>>;

#[derive(diesel::QueryableByName)]
struct SchemaRow {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    sql: String,
}

/// Read the ops of a row record, refusing a table this build does not have or
/// one whose column count differs.
///
/// The table set is checked because the session extension **skips** a table
/// absent from the target rather than reporting it, which is the same
/// silent-loss shape `R40` and `R26` were both bitten by (R56 decision 6).
pub(crate) fn read_rows(
    patchset: &[u8],
    known: &std::collections::HashMap<String, Vec<String>>,
) -> Result<Vec<IncomingRow>, ClientError> {
    if patchset.is_empty() {
        return Ok(Vec::new());
    }
    let parsed = sqlite_diff_rs::ParsedDiffSet::parse(patchset)
        .map_err(|err| ClientError::Import(format!("the row record does not parse: {err}")))?;
    let sqlite_diff_rs::ParsedDiffSet::Patchset(set) = parsed else {
        return Err(ClientError::Import(
            "a tier's rows must travel as a patchset".to_owned(),
        ));
    };
    let mut rows = Vec::new();
    for op in set.iter() {
        let PatchsetOp::Insert { table, values, .. } = op else {
            return Err(ClientError::Import(
                "a tier's rows must be inserts only".to_owned(),
            ));
        };
        rows.push(decode_insert(table, values, known)?);
    }
    Ok(rows)
}

fn decode_insert(
    table: &impl DynTable,
    values: &[Cell],
    known: &std::collections::HashMap<String, Vec<String>>,
) -> Result<IncomingRow, ClientError> {
    let name = table.name().to_owned();
    let Some(columns) = known.get(&name.to_lowercase()) else {
        return Err(ClientError::Import(format!(
            "the archive carries table {name}, which this build does not have"
        )));
    };
    if columns.len() != values.len() {
        return Err(ClientError::Import(format!(
            "the archive's table {name} has {} columns and this build's has {}",
            values.len(),
            columns.len()
        )));
    }
    let mut flags = vec![0u8; table.number_of_columns()];
    table.write_pk_flags(&mut flags);
    // The flag is the column's 1-based position in the key, so sorting by
    // it puts a composite key in key order rather than table order.
    let mut key: Vec<(u8, String, Cell)> = flags
        .iter()
        .zip(columns.iter().zip(values.iter()))
        .filter(|(flag, _)| **flag > 0)
        .map(|(flag, (column, value))| (*flag, column.clone(), value.clone()))
        .collect();
    key.sort_by_key(|(flag, _, _)| *flag);
    Ok(IncomingRow {
        table: name,
        columns: columns.clone(),
        key_columns: key.iter().map(|(_, column, _)| column.clone()).collect(),
        key: key.into_iter().map(|(_, _, value)| value).collect(),
        values: values.to_vec(),
    })
}

/// Index the rows a record carries, for comparing the two sides of a clash.
pub(crate) fn index_rows(
    patchset: &[u8],
    known: &std::collections::HashMap<String, Vec<String>>,
) -> Result<RowIndex, ClientError> {
    Ok(read_rows(patchset, known)?
        .into_iter()
        .map(|row| ((row.table, row.key), row.values))
        .collect())
}

/// The columns of every table of one schema, keyed by lowercased name.
pub(crate) fn schema_columns(
    db: &mut SqliteConnection,
    schema: &str,
    include: Option<&HashSet<String>>,
    hidden: &HashSet<String>,
) -> Result<std::collections::HashMap<String, Vec<String>>, ClientError> {
    #[derive(diesel::QueryableByName)]
    struct NameRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        name: String,
    }
    // sqlite_schema and pragma_table_info are SQLite system objects with no
    // Diesel table! schema; the schema name is determined at runtime, so the
    // typed DSL cannot express these queries.
    let tables: Vec<NameRow> = diesel::sql_query(format!(
        "SELECT name FROM {}.sqlite_schema WHERE type = 'table' ORDER BY name",
        quote_ident(schema)
    ))
    .load(db)?;
    let mut out = std::collections::HashMap::new();
    for table in tables {
        if !crate::export_table_allowed(&table.name, include, hidden) {
            continue;
        }
        let columns: Vec<NameRow> = diesel::sql_query(format!(
            "SELECT name FROM {}.pragma_table_info(?) ORDER BY cid",
            quote_ident(schema)
        ))
        .bind::<diesel::sql_types::Text, _>(&table.name)
        .load(db)?;
        out.insert(
            table.name.to_lowercase(),
            columns.into_iter().map(|column| column.name).collect(),
        );
    }
    Ok(out)
}

/// The schema, table, and column data for one upsert.
pub(crate) struct RowWrite<'a> {
    pub(crate) schema: &'a str,
    pub(crate) table: &'a str,
    pub(crate) columns: &'a [String],
    pub(crate) key_columns: &'a [String],
    pub(crate) values: &'a [Cell],
}

/// Write one row into its target schema, updating the row already there.
///
/// An upsert rather than `INSERT OR REPLACE`, which deletes the row it
/// replaces: that fires the table's delete triggers and takes any
/// `ON DELETE CASCADE` children with it, so restoring a row would destroy rows
/// nobody asked about.
///
/// Values bind by their own storage class, so a blob stays a blob and text
/// holding a `NUL` survives.
pub(crate) fn write_row(db: &mut SqliteConnection, row: &RowWrite<'_>) -> Result<(), ClientError> {
    use diesel::sql_types::{Binary, Double, Nullable, Text};
    // The table and column names are runtime values from the archive; the
    // ON CONFLICT (excluded.*) pattern is not expressible in Diesel's typed
    // DSL without a compile-time table! schema.
    let sql = build_upsert_sql(row.schema, row.table, row.columns, row.key_columns);
    let mut query = diesel::sql_query(sql).into_boxed::<diesel::sqlite::Sqlite>();
    for value in row.values {
        query = match value {
            sqlite_diff_rs::Value::Null => query.bind::<Nullable<Text>, _>(None::<String>),
            sqlite_diff_rs::Value::Integer(number) => {
                query.bind::<diesel::sql_types::BigInt, _>(*number)
            }
            sqlite_diff_rs::Value::Real(number) => query.bind::<Double, _>(*number),
            sqlite_diff_rs::Value::Text(text) => query.bind::<Text, _>(text.clone()),
            sqlite_diff_rs::Value::Blob(bytes) => query.bind::<Binary, _>(bytes.clone()),
        };
    }
    query.execute(db)?;
    Ok(())
}

fn build_upsert_sql(
    schema: &str,
    table: &str,
    columns: &[String],
    key_columns: &[String],
) -> String {
    let names = columns
        .iter()
        .map(|column| quote_ident(column))
        .collect::<Vec<_>>()
        .join(", ");
    let places = vec!["?"; columns.len()].join(", ");
    let key = key_columns
        .iter()
        .map(|column| quote_ident(column))
        .collect::<Vec<_>>()
        .join(", ");
    let updates = columns
        .iter()
        .filter(|column| !key_columns.iter().any(|k| k == *column))
        .map(|column| {
            let column = quote_ident(column);
            format!("{column} = excluded.{column}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    // A table whose every column is in the key has nothing to update, and its
    // row is already exactly what the file carries.
    let resolution = if updates.is_empty() {
        "NOTHING".to_owned()
    } else {
        format!("UPDATE SET {updates}")
    };
    format!(
        "INSERT INTO {}.{} ({names}) VALUES ({places}) \
         ON CONFLICT ({key}) DO {resolution}",
        quote_ident(schema),
        quote_ident(table)
    )
}

/// A fingerprint of the schema an archive was made under, over both the
/// replica and the device-private tier.
///
/// Structural rather than declared: an import has to refuse any schema that
/// differs, and a deployment's declared version can stay the same across a
/// changed table (R56 decision 4). The stored `CREATE TABLE` text is what
/// SQLite kept verbatim, so two devices of one build hash the same and a
/// changed column changes the digest.
pub(crate) fn fingerprint(
    db: &mut SqliteConnection,
    schemas: &[(&str, Option<&HashSet<String>>)],
    hidden: &HashSet<String>,
) -> Result<String, ClientError> {
    let mut digest = Sha256::new();
    for (schema, include) in schemas {
        // sqlite_schema is a SQLite system table with no Diesel table! schema;
        // the schema name is determined at runtime.
        let rows: Vec<SchemaRow> = diesel::sql_query(format!(
            "SELECT name, sql FROM {}.sqlite_schema \
             WHERE type = 'table' AND sql IS NOT NULL ORDER BY name",
            quote_ident(schema)
        ))
        .load(db)?;
        digest.update(schema.as_bytes());
        for row in rows {
            if !crate::export_table_allowed(&row.name, *include, hidden) {
                continue;
            }
            digest.update(row.name.as_bytes());
            digest.update([0]);
            digest.update(row.sql.as_bytes());
            digest.update([0]);
        }
    }
    Ok(digest
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            use core::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        }))
}
