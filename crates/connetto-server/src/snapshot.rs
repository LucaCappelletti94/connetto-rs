//! Backend-read initial snapshots.
//!
//! Fills the [`SnapshotSource`](crate::session::SnapshotSource) seam with a real
//! Postgres read: run the
//! subscription's `SELECT` on the backend, take each result row as a single
//! `jsonb` value, and encode the rows into an insert-patchset with
//! `sqlite-diff-rs`. The rows and the LSN are read in one read-only
//! repeatable-read transaction, so the snapshot cursor names a consistent WAL
//! position. The client applies the patchset, then live patches with a greater
//! cursor land on top.
//!
//! `subql`'s async connector does not implement row reads (`execute_rows` is
//! reserved for total row re-execution), so the materializer owns this read, as
//! the boundary intends. No SQLite lives on the backend: the catalog supplies
//! the column order and primary key for the patchset shape.

use sqlite_diff_rs::{DiffOps, Insert, PatchSet, SimpleTable, Value as WireValue};
#[cfg(feature = "pg-async")]
use sqlparser::ast::{SetExpr, Statement, TableFactor};
#[cfg(feature = "pg-async")]
use sqlparser::dialect::PostgreSqlDialect;
#[cfg(feature = "pg-async")]
use sqlparser::parser::Parser;
use subql::{DatabaseLike, catalog_helpers};

/// Failure surfaced while producing a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// The Postgres DDL handed to a `from_ddl` constructor did not parse.
    #[error("catalog parse failed: {0}")]
    Catalog(String),
    /// The subscription SQL could not be parsed to find its table.
    #[error("could not read the subscription table: {0}")]
    Sql(String),
    /// The subscription targets a table absent from the catalog.
    #[error("unknown table `{0}`")]
    UnknownTable(String),
    /// A returned row was not a JSON object.
    #[error("snapshot row was not a JSON object")]
    Row,
    /// Building the insert-patchset failed.
    #[error("patchset build failed: {0}")]
    Encode(String),
    /// The backend read failed.
    #[error("backend read failed: {0}")]
    Backend(String),
}

/// Encode backend rows (each a JSON object keyed by column name) for `table`
/// into an insert-patchset.
///
/// Column order and primary key come from the catalog. A column absent from a
/// row's object is stored as NULL. The value's JSON shape already reflects its
/// column type (Postgres `to_jsonb` encodes per column), so numbers become
/// integer or real values, booleans become `0`/`1`, and everything else rides
/// as text.
///
/// # Errors
///
/// [`SnapshotError::UnknownTable`] when the table is absent from the catalog,
/// [`SnapshotError::Row`] when a row is not a JSON object, and
/// [`SnapshotError::Encode`] when a value cannot be set.
pub fn encode_json_rows<DB: DatabaseLike>(
    db: &DB,
    table: &str,
    rows: &[serde_json::Value],
) -> Result<Vec<u8>, SnapshotError> {
    let table_id = catalog_helpers::table_id(db, table)
        .ok_or_else(|| SnapshotError::UnknownTable(table.to_owned()))?;
    let simple = catalog_helpers::simple_table(db, table_id)
        .ok_or_else(|| SnapshotError::UnknownTable(table.to_owned()))?;
    let arity = catalog_helpers::table_arity(db, table_id)
        .ok_or_else(|| SnapshotError::UnknownTable(table.to_owned()))?;

    let mut columns: Vec<String> = Vec::with_capacity(arity);
    for ordinal in 0..arity {
        let column_id =
            u16::try_from(ordinal).map_err(|_| SnapshotError::UnknownTable(table.to_owned()))?;
        let name = catalog_helpers::column_name(db, table_id, column_id)
            .ok_or_else(|| SnapshotError::UnknownTable(table.to_owned()))?;
        columns.push(name);
    }

    let mut patchset = PatchSet::<SimpleTable, String, Vec<u8>>::new();
    for row in rows {
        let object = row.as_object().ok_or(SnapshotError::Row)?;
        let mut insert = Insert::<_, String, Vec<u8>>::from(simple.clone());
        for (index, name) in columns.iter().enumerate() {
            let wire = object.get(name).map_or(WireValue::Null, json_to_wire);
            insert = insert
                .set(index, wire)
                .map_err(|err| SnapshotError::Encode(format!("{err:?}")))?;
        }
        patchset = patchset.insert(insert);
    }
    Ok(patchset.build())
}

/// Convert one JSON scalar into its `sqlite-diff-rs` wire value.
fn json_to_wire(value: &serde_json::Value) -> WireValue<String, Vec<u8>> {
    match value {
        serde_json::Value::Null => WireValue::Null,
        serde_json::Value::Bool(b) => WireValue::Integer(i64::from(*b)),
        serde_json::Value::Number(n) => n.as_i64().map_or_else(
            || WireValue::Real(n.as_f64().unwrap_or(0.0)),
            WireValue::Integer,
        ),
        serde_json::Value::String(s) => WireValue::Text(s.clone()),
        other => WireValue::Text(other.to_string()),
    }
}

/// Extract the single table a `SELECT` reads from.
#[cfg(feature = "pg-async")]
fn table_from_select(sql: &str) -> Result<String, SnapshotError> {
    let statements = Parser::parse_sql(&PostgreSqlDialect {}, sql)
        .map_err(|err| SnapshotError::Sql(err.to_string()))?;
    let Some(Statement::Query(query)) = statements.into_iter().next() else {
        return Err(SnapshotError::Sql("expected a SELECT statement".into()));
    };
    let SetExpr::Select(select) = *query.body else {
        return Err(SnapshotError::Sql("expected a plain SELECT".into()));
    };
    let Some(from) = select.from.first() else {
        return Err(SnapshotError::Sql("SELECT has no FROM clause".into()));
    };
    match &from.relation {
        TableFactor::Table { name, .. } => Ok(name.to_string()),
        _ => Err(SnapshotError::Sql("unsupported FROM relation".into())),
    }
}

#[cfg(feature = "pg-async")]
pub use pg::PgSnapshotSource;

#[cfg(feature = "pg-async")]
mod pg {
    use diesel::sql_types::{Jsonb, Text};
    use diesel::{QueryableByName, sql_query};
    use diesel_async::pooled_connection::bb8::Pool;
    use diesel_async::scoped_futures::ScopedFutureExt;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
    use sqlparser::dialect::PostgreSqlDialect;
    use subql::{DatabaseLike, ParserDB, PgLsn};

    use connetto_core::Cursor;

    use super::{SnapshotError, encode_json_rows, table_from_select};
    use crate::session::{Snapshot, SnapshotSource};

    /// A [`SnapshotSource`] that reads initial rows from Postgres over a
    /// bb8-pooled `AsyncPgConnection`.
    pub struct PgSnapshotSource<DB = ParserDB> {
        pool: Pool<AsyncPgConnection>,
        catalog: DB,
    }

    impl PgSnapshotSource<ParserDB> {
        /// Build over a connection pool and a Postgres DDL catalog.
        ///
        /// # Errors
        ///
        /// [`SnapshotError::Catalog`] when the DDL does not parse.
        pub fn from_ddl(
            pool: Pool<AsyncPgConnection>,
            pg_ddl: &str,
        ) -> Result<Self, SnapshotError> {
            let catalog = ParserDB::parse::<PostgreSqlDialect>(pg_ddl)
                .map_err(|err| SnapshotError::Catalog(format!("{err:?}")))?;
            Ok(Self { pool, catalog })
        }
    }

    impl<DB> PgSnapshotSource<DB> {
        /// Build over a connection pool and an existing catalog.
        pub const fn new(pool: Pool<AsyncPgConnection>, catalog: DB) -> Self {
            Self { pool, catalog }
        }
    }

    #[derive(QueryableByName)]
    struct JsonRow {
        #[diesel(sql_type = Jsonb)]
        row: serde_json::Value,
    }

    #[derive(QueryableByName)]
    struct LsnRow {
        #[diesel(sql_type = Text)]
        lsn: String,
    }

    impl<DB: DatabaseLike + Send + Sync> SnapshotSource for PgSnapshotSource<DB> {
        type Error = SnapshotError;

        async fn snapshot(&self, select_sql: &str) -> Result<Snapshot, Self::Error> {
            let table = table_from_select(select_sql)?;
            let wrapped = format!("SELECT to_jsonb(_snap) AS row FROM ({select_sql}) AS _snap");
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;
            let (rows, lsn) = conn
                .transaction::<(Vec<JsonRow>, String), diesel::result::Error, _>(|c| {
                    async move {
                        // Pin one MVCC snapshot so the rows and the LSN agree.
                        sql_query("SET TRANSACTION READ ONLY ISOLATION LEVEL REPEATABLE READ")
                            .execute(c)
                            .await?;
                        let rows: Vec<JsonRow> = sql_query(&wrapped).load(c).await?;
                        let lsn: LsnRow = sql_query("SELECT pg_current_wal_lsn()::text AS lsn")
                            .get_result(c)
                            .await?;
                        Ok((rows, lsn.lsn))
                    }
                    .scope_boxed()
                })
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;

            let rows: Vec<serde_json::Value> = rows.into_iter().map(|r| r.row).collect();
            let patchset = encode_json_rows(&self.catalog, &table, &rows)?;
            let cursor = PgLsn::parse(&lsn)
                .map(|lsn| lsn.0.to_be_bytes().to_vec())
                .unwrap_or_default();
            Ok(Snapshot {
                patchset,
                cursor: Cursor::new(cursor),
            })
        }
    }
}
