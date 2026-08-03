//! Backend-read initial snapshots.
//!
//! Fills the [`SnapshotSource`](crate::session::SnapshotSource) seam with a real
//! Postgres read: run the subscription's `SELECT` on the backend, take each
//! result column as its raw Postgres binary bytes, and encode the rows into an
//! insert-patchset with [`subql::emit::pgbinary_patchset`]. The rows and the LSN
//! are read in one read-only repeatable-read transaction, so the snapshot cursor
//! names a consistent WAL position. The client applies the patchset, then live
//! patches with a greater cursor land on top.
//!
//! Reading binary and lowering it through the same encoder the CDC path uses
//! (`pgbinary_patchset` shares the catalog wire-type source with
//! `pgoutput_patchset`) makes the snapshot and the live stream agree on every
//! value by construction: a `uuid` snapshots as the same 16-byte
//! [`Value::Blob`](sqlite_diff_rs::Value) the replication path emits, so a row
//! present in both a snapshot and a later CDC patch has one identity, not two.
//! connetto carries no per-type wire knowledge of its own: both the catalog walk
//! and the per-column decode live in `subql`.
//!
//! `subql`'s async connector does not implement row reads (`execute_rows` is
//! reserved for total row re-execution), so the materializer owns this read, as
//! the boundary intends. No SQLite lives on the backend: the catalog supplies
//! the column order and primary key for the patchset shape.

use sqlparser::ast::{SetExpr, Statement, TableFactor};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

/// Failure surfaced while producing a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// The Postgres DDL handed to a `from_ddl` constructor did not parse.
    #[error("catalog parse failed: {0}")]
    Catalog(String),
    /// The subscription SQL could not be parsed to find its table.
    #[error("could not read the subscription table: {0}")]
    Sql(String),
    /// Building the insert-patchset from the binary rows failed.
    #[error("patchset build failed: {0}")]
    Encode(String),
    /// The backend read failed.
    #[error("backend read failed: {0}")]
    Backend(String),
}

/// Extract the single table a `SELECT` reads from, as its bare catalog name.
///
/// The translated SQL quotes identifiers, so this takes the ident value,
/// never its rendering, and the last dotted segment so a schema-qualified
/// table resolves to the name the catalog knows.
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
        TableFactor::Table { name, .. } => name
            .0
            .last()
            .and_then(|part| part.as_ident())
            .map(|ident| ident.value.clone())
            .ok_or_else(|| SnapshotError::Sql("unsupported FROM relation".into())),
        _ => Err(SnapshotError::Sql("unsupported FROM relation".into())),
    }
}

pub use pg::PgSnapshotSource;

mod pg {
    use diesel::row::{Field, NamedRow, Row};
    use diesel::sql_types::{BigInt, Binary, Double, Nullable, Text};
    use diesel::{QueryableByName, sql_query};
    use diesel_async::pooled_connection::bb8::Pool;
    use diesel_async::scoped_futures::ScopedFutureExt;
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
    use sqlparser::dialect::PostgreSqlDialect;
    use subql::{DatabaseLike, ParserDB, PgLsn};

    use connetto_core::messages::BindValue;
    use connetto_core::{Cursor, Principal};

    use super::{SnapshotError, table_from_select};
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

    /// One backend result row read in Postgres binary: the result column names
    /// and the raw wire bytes per column, `None` for a SQL NULL.
    ///
    /// The read is dynamic (the subscription's projection is not known at
    /// compile time), so this walks the diesel [`Row`] API by ordinal rather
    /// than deriving a typed row. `field.value()` hands back the exact bytes
    /// tokio-postgres received in binary format, which is what
    /// [`subql::emit::pgbinary_patchset`] decodes.
    struct BinaryRow {
        names: Vec<String>,
        cells: Vec<Option<Vec<u8>>>,
    }

    impl QueryableByName<diesel::pg::Pg> for BinaryRow {
        fn build<'a>(row: &impl NamedRow<'a, diesel::pg::Pg>) -> diesel::deserialize::Result<Self> {
            let arity = row.field_count();
            let mut names = Vec::with_capacity(arity);
            let mut cells = Vec::with_capacity(arity);
            for ordinal in 0..arity {
                let field = Row::get(row, ordinal).ok_or(diesel::result::UnexpectedEndOfRow)?;
                names.push(field.field_name().unwrap_or_default().to_owned());
                cells.push(field.value().map(|value| value.as_bytes().to_vec()));
            }
            Ok(Self { names, cells })
        }
    }

    #[derive(QueryableByName)]
    struct LsnRow {
        #[diesel(sql_type = Text)]
        lsn: String,
    }

    impl<DB: DatabaseLike + Send + Sync> SnapshotSource for PgSnapshotSource<DB> {
        type Error = SnapshotError;

        async fn snapshot(
            &self,
            select_sql: &str,
            binds: &[BindValue],
            caller: &Principal,
        ) -> Result<Snapshot, Self::Error> {
            let table = table_from_select(select_sql)?;
            let user_id = caller.identity().map(|identity| identity.user_id.clone());
            let binds = binds.to_vec();
            let select_sql = select_sql.to_owned();
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;
            let (rows, lsn) = conn
                .transaction::<(Vec<BinaryRow>, String), diesel::result::Error, _>(|c| {
                    async move {
                        // Pin one MVCC snapshot so the rows and the LSN agree.
                        sql_query("SET TRANSACTION READ ONLY ISOLATION LEVEL REPEATABLE READ")
                            .execute(c)
                            .await?;
                        // Establish the requesting caller's RLS context so the
                        // read returns only rows it may see. A caller with no
                        // identity binds nothing, leaving the setting unset for
                        // the whole transaction, so an owner comparison is NULL
                        // and hides the row while a public predicate still
                        // returns its own.
                        if let Some(user_id) = user_id {
                            sql_query("SELECT set_config('app.user_id', $1, true)")
                                .bind::<Text, _>(user_id)
                                .execute(c)
                                .await?;
                        }
                        // Read the subscription SELECT verbatim (no jsonb wrap) so
                        // every column comes back in Postgres binary. The
                        // translated query carries `$N` placeholders. Attach the
                        // wire binds in order, each with its natural Postgres type.
                        // A NULL bind has no inherent type and rides as nullable
                        // text, which diesel-rendered queries never produce (they
                        // render IS NULL instead of binding NULL).
                        let mut query = sql_query(select_sql).into_boxed::<diesel::pg::Pg>();
                        for bind in binds {
                            query = match bind {
                                BindValue::Null => query.bind::<Nullable<Text>, _>(None::<String>),
                                BindValue::Integer(value) => query.bind::<BigInt, _>(value),
                                BindValue::Real(value) => query.bind::<Double, _>(value),
                                BindValue::Text(value) => query.bind::<Text, _>(value),
                                BindValue::Blob(bytes) => query.bind::<Binary, _>(bytes),
                            };
                        }
                        let rows: Vec<BinaryRow> = query.load(c).await?;
                        let lsn: LsnRow = sql_query("SELECT pg_current_wal_lsn()::text AS lsn")
                            .get_result(c)
                            .await?;
                        Ok((rows, lsn.lsn))
                    }
                    .scope_boxed()
                })
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;

            // Column names come from the first row; a zero-row snapshot has none,
            // and `pgbinary_patchset` returns an empty patchset for that, which is
            // correct (nothing to insert).
            let column_names: Vec<&str> = rows
                .as_slice()
                .first()
                .map(|r| r.names.iter().map(String::as_str).collect())
                .unwrap_or_default();
            let row_cells: Vec<Vec<Option<&[u8]>>> = rows
                .iter()
                .map(|r| r.cells.iter().map(|c| c.as_deref()).collect())
                .collect();
            let patchset =
                subql::emit::pgbinary_patchset(&self.catalog, &table, &column_names, &row_cells)
                    .map_err(|err| SnapshotError::Encode(err.to_string()))?;
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
