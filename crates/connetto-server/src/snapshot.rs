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

use connetto_core::Principal;
use sqlparser::ast::{SelectItem, SetExpr, Statement, TableFactor};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;
use subql::TableId;
use subql::backend::{Postgres, Value};

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
///
/// # Errors
///
/// [`SnapshotError::Sql`] when the statement is not a plain single-table
/// `SELECT`.
pub(crate) fn table_from_select(sql: &str) -> Result<String, SnapshotError> {
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

/// Whether the `SELECT`'s own projection returns every column in `columns`,
/// which decides whether a read of it can be paged (R58).
///
/// A page is a wrap around the subscription's query, so the wrap can only
/// name columns the inner query returns. A wildcard returns all of them. An
/// explicit list is compared on the column's own name, taking an alias where
/// one is written and the last segment of a qualified name otherwise, which
/// is the shape the reverse translation emits.
///
/// A query this cannot parse is treated as exposing nothing, so the read
/// stays a single capped page rather than being wrapped in a predicate
/// Postgres would refuse.
pub(crate) fn projection_exposes(sql: &str, columns: &[String]) -> bool {
    if columns.is_empty() {
        return false;
    }
    let Ok(statements) = Parser::parse_sql(&PostgreSqlDialect {}, sql) else {
        return false;
    };
    let Some(Statement::Query(query)) = statements.into_iter().next() else {
        return false;
    };
    let SetExpr::Select(select) = *query.body else {
        return false;
    };
    let mut named = Vec::with_capacity(select.projection.len());
    for item in &select.projection {
        match item {
            SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..) => return true,
            SelectItem::ExprWithAlias { alias, .. } => named.push(alias.value.clone()),
            SelectItem::UnnamedExpr(expr) => match expr {
                sqlparser::ast::Expr::Identifier(ident) => named.push(ident.value.clone()),
                sqlparser::ast::Expr::CompoundIdentifier(parts) => {
                    if let Some(last) = parts.last() {
                        named.push(last.value.clone());
                    }
                }
                _ => {}
            },
            // Anything else names no plain column, so it cannot carry a key.
            SelectItem::ExprWithAliases { .. } => {}
        }
    }
    columns
        .iter()
        .all(|column| named.iter().any(|name| name == column))
}

/// The alias the page wrap gives the subscription's own query.
///
/// Long enough that it cannot collide with a deployment's own table name,
/// which would shadow it inside the wrap's `WHERE`.
const PAGE_ALIAS: &str = "connetto_page";

/// Wrap `inner` as one page: at most `cap` rows, ordered by the key the page
/// resumes on, past `after` when a previous page named one.
///
/// Textual rather than an AST rewrite (R58 decision 4): the translation
/// already refuses anything but a single statement, so an inner query is safe
/// to wrap without understanding it, and Postgres flattens the wrap. The
/// predicate is a keyset comparison and never an `OFFSET`, because offset
/// paging costs O(offset) per page: measured at 703 ms for the thousandth
/// page of a two-million-row table against 0.377 ms for a keyset page at any
/// position.
///
/// With no key columns the page carries no ordering and no resume point, so
/// it is one capped read that refuses when it comes back full.
pub(crate) fn page_sql(
    inner: &str,
    key_columns: &[String],
    after: Option<&str>,
    cap: u32,
) -> String {
    if key_columns.is_empty() {
        return format!("SELECT * FROM ({inner}) {PAGE_ALIAS} LIMIT {cap}");
    }
    let order = key_columns
        .iter()
        .map(|name| connetto_core::quote_ident(name))
        .collect::<Vec<_>>()
        .join(", ");
    match after {
        Some(predicate) => format!(
            "SELECT * FROM ({inner}) {PAGE_ALIAS} WHERE {predicate} ORDER BY {order} LIMIT {cap}"
        ),
        None => format!("SELECT * FROM ({inner}) {PAGE_ALIAS} ORDER BY {order} LIMIT {cap}"),
    }
}

/// One row of the source database, read back completely.
pub struct SourceRow {
    /// Catalog id of the table the row belongs to.
    pub table_id: TableId,
    /// The row's values, in catalog column order.
    pub values: Vec<Value<Postgres>>,
}

/// Reads one row of the source database, completely, as the caller.
///
/// The minting path is handed a key rather than a row, and the visibility
/// question is about the row, so the row is read before the question is asked.
/// The read runs as the caller, so a row the caller may not see is
/// indistinguishable from one that is not there and minting cannot be turned
/// into a probe for rows.
#[allow(async_fn_in_trait)]
pub trait RowSource<Id = String, Key = String> {
    /// Failure to reach the row, as distinct from not finding one.
    type Error: core::fmt::Display;

    /// The row `key` names in `table`, or [`None`] when the caller sees none.
    async fn read_row(
        &self,
        caller: &Principal<Id, Key>,
        table: &str,
        key: &[Value<Postgres>],
    ) -> Result<Option<SourceRow>, Self::Error>;
}

pub use pg::PgSnapshotSource;

mod pg {
    use core::fmt::Display;

    use diesel::row::{Field, NamedRow, Row};
    use diesel::sql_types::{BigInt, Binary, Double, Nullable, Text};
    use diesel::{ExpressionMethods, QueryDsl, QueryableByName, sql_query};
    use diesel_async::pooled_connection::bb8::Pool;
    use diesel_async::scoped_futures::ScopedFutureExt;
    use diesel_async::{AsyncConnection, AsyncConnectionCore, AsyncPgConnection, RunQueryDsl};
    use sqlite_diff_rs::PatchsetOp;
    use sqlparser::dialect::PostgreSqlDialect;
    use subql::backend::{Postgres, Value};
    use subql::{ColumnId, DatabaseLike, ParserDB, PgLsn, TableId, catalog_helpers};

    use connetto_core::messages::BindValue;
    use connetto_core::{Cursor, Principal};

    use super::{
        RowSource, SnapshotError, SourceRow, page_sql, projection_exposes, table_from_select,
    };
    use crate::capability::{CallerBinding, CapabilityKey};
    use crate::key_filter::KeyFilter;
    use crate::session::{
        PageKey, PageSpec, SnapshotEstimate, SnapshotPage, SnapshotSource, TermSeedRead,
    };
    use connetto_core::quote_ident;

    /// A [`SnapshotSource`] that reads initial rows from Postgres over a
    /// bb8-pooled `AsyncPgConnection`.
    pub struct PgSnapshotSource<DB = ParserDB> {
        pool: Pool<AsyncPgConnection>,
        catalog: DB,
        /// The setting a policy reads the caller's identity from.
        user_setting: std::sync::Arc<str>,
        /// The publication the change stream reads, when the deployment named
        /// it, so a membership term's table can be verified as replicated at
        /// registration (R27). Without one, every membership term is refused.
        publication: Option<std::sync::Arc<str>>,
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
            Ok(Self {
                pool,
                catalog,
                user_setting: crate::capability::DEFAULT_USER_SETTING.into(),
                publication: None,
            })
        }
    }

    impl<DB> PgSnapshotSource<DB> {
        /// Read the caller's identity from `setting` rather than the default.
        ///
        /// The share-key setting has been the application's choice since R4; this
        /// is its counterpart, so an application fitting connetto into rules that
        /// already name things its own way can rename both.
        #[must_use]
        pub fn with_user_setting(mut self, setting: impl Into<std::sync::Arc<str>>) -> Self {
            self.user_setting = setting.into();
            self
        }

        /// Name the publication the change stream reads, so a membership
        /// term's table can be verified as replicated at registration (R27).
        #[must_use]
        pub fn with_publication(mut self, publication: impl Into<std::sync::Arc<str>>) -> Self {
            self.publication = Some(publication.into());
            self
        }

        /// Build over a connection pool and an existing catalog.
        ///
        /// Not `const`: the default identity setting is a shared string, which
        /// cannot be built in a constant. This runs once at startup.
        pub fn new(pool: Pool<AsyncPgConnection>, catalog: DB) -> Self {
            Self {
                pool,
                catalog,
                user_setting: crate::capability::DEFAULT_USER_SETTING.into(),
                publication: None,
            }
        }
    }

    /// One page's read, resolved: the table it names, the key it resumes on,
    /// whether it can resume at all, and the query to run.
    struct PagePlan<'a> {
        /// The table the subscription reads, as the catalog names it.
        table: String,
        /// Its catalog id.
        table_id: TableId,
        /// Its primary-key column ordinals, in key order.
        key: Vec<ColumnId>,
        /// Whether the query's own projection carries the key, without which
        /// no wrap can resume past a row.
        pageable: bool,
        /// The wrapped query, binds attached.
        query: Boxed<'a>,
    }

    impl<DB: DatabaseLike> PgSnapshotSource<DB> {
        /// Resolve one page's read: the key it orders and resumes on, and the
        /// wrap around the subscription's own query.
        fn plan_page<'a>(
            &self,
            select_sql: &str,
            binds: &[BindValue],
            page: &PageSpec,
        ) -> Result<PagePlan<'a>, SnapshotError> {
            let table = table_from_select(select_sql)?;
            let table_id = catalog_helpers::table_id(&self.catalog, &table).ok_or_else(|| {
                SnapshotError::Backend(format!("the catalog does not know table {table}"))
            })?;
            let key =
                catalog_helpers::primary_key_columns(&self.catalog, table_id).unwrap_or_default();
            let names: Vec<String> = key
                .iter()
                .filter_map(|column| catalog_helpers::column_name(&self.catalog, table_id, *column))
                .collect();
            // A wrap can only name what the inner query returns, so a
            // projection without the key is read as one capped page and
            // refused when it fills (R58).
            let pageable = names.len() == key.len()
                && projection_exposes(select_sql, &names)
                && !key.is_empty();
            let key_columns = if pageable { names } else { Vec::new() };
            let resume = match &page.after {
                Some(after) if pageable => KeyFilter::after(
                    &self.catalog,
                    table_id,
                    &table,
                    binds.len() + 1,
                    |position, _| {
                        Ok(after
                            .values
                            .get(position)
                            .cloned()
                            .unwrap_or(Value::Missing))
                    },
                )
                .map_err(|err| SnapshotError::Backend(err.to_string()))?,
                _ => None,
            };
            // One row past the page, so a page that fills says whether there
            // is a next one without a second query.
            let sql = page_sql(
                select_sql,
                &key_columns,
                resume.as_ref().map(KeyFilter::predicate),
                page.max_rows.max(1).saturating_add(1),
            );
            // The translated query carries `$N` placeholders, so the wire
            // binds go on first and the resume key takes the numbers after
            // them. A NULL bind has no inherent type and rides as nullable
            // text, which diesel-rendered queries never produce (they render
            // IS NULL instead of binding NULL).
            let mut query = attach_binds(
                sql_query(sql).into_boxed::<diesel::pg::Pg>(),
                binds.to_vec(),
            );
            if let Some(resume) = &resume {
                query = resume.bind(query);
            }
            Ok(PagePlan {
                table,
                table_id,
                key,
                pageable,
                query,
            })
        }
    }

    /// One backend result set read in Postgres binary: the column names once,
    /// and the raw wire bytes per row, `None` for a SQL NULL.
    ///
    /// The read is dynamic (the subscription's projection is not known at
    /// compile time), so it walks the diesel [`Row`] API by ordinal rather than
    /// deriving a typed row. `field.value()` hands back the exact bytes
    /// tokio-postgres received in binary format, which is what
    /// [`subql::emit::pgbinary_patchset`] decodes.
    ///
    /// The names live beside the rows rather than inside each one. Every row of
    /// one result carries the same names, so deserializing them per row
    /// allocated a copy per row and read only the first set (R58 review): a
    /// page of a million narrow rows paid a million allocations to say the same
    /// five words.
    #[derive(Default)]
    struct BinaryRows {
        names: Vec<String>,
        rows: Vec<Vec<Option<Vec<u8>>>>,
    }

    impl BinaryRows {
        /// Read every row of `query` as raw Postgres binary.
        ///
        /// Uses diesel-async's own row stream rather than a deserialized row
        /// type, because the column names are on the row and a deserialized
        /// type has nowhere to put them once.
        async fn load(
            conn: &mut AsyncPgConnection,
            query: Boxed<'_>,
        ) -> Result<Self, diesel::result::Error> {
            use futures_util::StreamExt as _;

            let mut stream = Box::pin(AsyncConnectionCore::load(conn, query).await?);
            let mut read = Self::default();
            while let Some(row) = stream.next().await {
                let row = row?;
                let arity = Row::field_count(&row);
                if read.names.is_empty() {
                    read.names = (0..arity)
                        .map(|ordinal| {
                            Row::get(&row, ordinal)
                                .and_then(|field| field.field_name().map(ToOwned::to_owned))
                                .unwrap_or_default()
                        })
                        .collect();
                }
                let mut cells = Vec::with_capacity(arity);
                for ordinal in 0..arity {
                    let field = Row::get(&row, ordinal).ok_or(
                        diesel::result::Error::DeserializationError(Box::new(
                            diesel::result::UnexpectedEndOfRow,
                        )),
                    )?;
                    cells.push(field.value().map(|value| value.as_bytes().to_vec()));
                }
                read.rows.push(cells);
            }
            Ok(read)
        }

        /// The column names as the encoder wants them.
        fn column_names(&self) -> Vec<&str> {
            self.names.iter().map(String::as_str).collect()
        }

        /// The rows as the encoder wants them.
        fn cells(&self) -> Vec<Vec<Option<&[u8]>>> {
            self.rows
                .iter()
                .map(|row| row.iter().map(|cell| cell.as_deref()).collect())
                .collect()
        }
    }

    #[derive(QueryableByName)]
    struct LsnRow {
        #[diesel(sql_type = Text)]
        lsn: String,
    }

    /// One `EXPLAIN (FORMAT JSON)` row.
    ///
    /// Read by ordinal because the column Postgres names it, `QUERY PLAN`,
    /// carries a space and cannot be a diesel field attribute. The value is
    /// text even under `FORMAT JSON`.
    struct PlanRow {
        plan: String,
    }

    impl QueryableByName<diesel::pg::Pg> for PlanRow {
        fn build<'a>(row: &impl NamedRow<'a, diesel::pg::Pg>) -> diesel::deserialize::Result<Self> {
            let field = Row::get(row, 0).ok_or(diesel::result::UnexpectedEndOfRow)?;
            let bytes = field.value().map_or(&[][..], |value| value.as_bytes());
            Ok(Self {
                plan: String::from_utf8(bytes.to_vec())?,
            })
        }
    }

    /// The table's physical bytes per row, including what is stored out of
    /// line.
    #[derive(QueryableByName)]
    struct WidthRow {
        #[diesel(sql_type = BigInt)]
        bytes: i64,
    }

    /// Read the planner's predicted rows and average row width out of one
    /// `EXPLAIN (FORMAT JSON)` plan.
    ///
    /// One round trip yields both, which is what makes deriving a row cap from
    /// a byte budget free (R58 decision 3). A plan missing either number reads
    /// as zero, so a page falls back to one row rather than to no limit.
    fn plan_estimate(plan: &str) -> Result<SnapshotEstimate, SnapshotError> {
        let parsed: serde_json::Value = serde_json::from_str(plan)
            .map_err(|err| SnapshotError::Backend(format!("the plan did not parse: {err}")))?;
        let node = parsed
            .get(0)
            .and_then(|entry| entry.get("Plan"))
            .ok_or_else(|| SnapshotError::Backend("the plan carried no root node".into()))?;
        let rows = node
            .get("Plan Rows")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or_default();
        let width = node
            .get("Plan Width")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        Ok(SnapshotEstimate {
            rows,
            width: u32::try_from(width).unwrap_or(u32::MAX),
        })
    }

    /// One raw query with its binds still to be attached.
    type Boxed<'a> =
        diesel::query_builder::BoxedSqlQuery<'a, diesel::pg::Pg, diesel::query_builder::SqlQuery>;

    /// Attach the wire binds to `query` in placeholder order, each with its
    /// natural Postgres type.
    fn attach_binds(query: Boxed<'_>, binds: Vec<BindValue>) -> Boxed<'_> {
        binds.into_iter().fold(query, |query, bind| match bind {
            BindValue::Null => query.bind::<Nullable<Text>, _>(None::<String>),
            BindValue::Integer(value) => query.bind::<BigInt, _>(value),
            BindValue::Real(value) => query.bind::<Double, _>(value),
            BindValue::Text(value) => query.bind::<Text, _>(value),
            BindValue::Blob(bytes) => query.bind::<Binary, _>(bytes),
        })
    }

    impl<DB, Id, Key> RowSource<Id, Key> for PgSnapshotSource<DB>
    where
        DB: DatabaseLike + Send + Sync,
        Id: Display + Send + Sync,
        Key: CapabilityKey,
    {
        type Error = SnapshotError;

        async fn read_row(
            &self,
            caller: &Principal<Id, Key>,
            table: &str,
            key: &[Value<Postgres>],
        ) -> Result<Option<SourceRow>, SnapshotError> {
            let Some(table_id) = catalog_helpers::table_id(&self.catalog, table) else {
                return Ok(None);
            };
            let filter = KeyFilter::build(&self.catalog, table_id, table, |position, _| {
                Ok(key.get(position).cloned().unwrap_or(Value::Missing))
            })
            .map_err(|err| SnapshotError::Backend(err.to_string()))?;
            let Some(filter) = filter else {
                return Ok(None);
            };
            let arity = catalog_helpers::table_arity(&self.catalog, table_id).unwrap_or_default();
            let mut columns = Vec::with_capacity(arity);
            for ordinal in 0..arity {
                let Ok(column) = ColumnId::try_from(ordinal) else {
                    return Ok(None);
                };
                let Some(name) = catalog_helpers::column_name(&self.catalog, table_id, column)
                else {
                    return Ok(None);
                };
                columns.push(quote_ident(&name));
            }
            if columns.is_empty() {
                return Ok(None);
            }
            // Raw SQL for the same reason the read filter is: the table and its
            // columns come from the deployment's runtime DDL, so no `table!`
            // schema names them.
            let sql = format!(
                "SELECT {} FROM {} WHERE {}",
                columns.join(", "),
                quote_ident(table),
                filter.predicate(),
            );
            let query = filter.bind(sql_query(sql).into_boxed::<diesel::pg::Pg>());
            let binding = CallerBinding::of(caller, std::sync::Arc::clone(&self.user_setting));
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;
            let read = conn
                .transaction::<BinaryRows, diesel::result::Error, _>(|c| {
                    async move {
                        sql_query("SET TRANSACTION READ ONLY").execute(c).await?;
                        binding.apply(c).await?;
                        BinaryRows::load(c, query).await
                    }
                    .scope_boxed()
                })
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;
            let cells = read.cells();
            let Some(row) = cells.into_iter().next() else {
                return Ok(None);
            };
            // Lower through the same encoder the snapshot uses, so a value read
            // here and the same value delivered to a client are one value. The
            // builder's ops are the encoder's own, so nothing is serialized and
            // parsed back to reach them.
            let built = subql::emit::pgbinary_patchset_builder(
                &self.catalog,
                table,
                &read.column_names(),
                &[row],
            )
            .map_err(|err| SnapshotError::Encode(err.to_string()))?;
            let Some(PatchsetOp::Insert { values, .. }) = built.iter().next() else {
                return Err(SnapshotError::Encode(
                    "the row encoder produced no insert".into(),
                ));
            };
            Ok(Some(SourceRow {
                table_id,
                values: crate::pk::row_from_wire(&self.catalog, table_id, values),
            }))
        }
    }

    impl<DB, Id, Key> SnapshotSource<Id, Key> for PgSnapshotSource<DB>
    where
        DB: DatabaseLike + Send + Sync,
        Id: Display + Send + Sync,
        Key: CapabilityKey,
    {
        type Error = SnapshotError;

        async fn estimate(
            &self,
            select_sql: &str,
            binds: &[BindValue],
            caller: &Principal<Id, Key>,
        ) -> Result<SnapshotEstimate, Self::Error> {
            let table = table_from_select(select_sql)?;
            let binding = CallerBinding::of(caller, std::sync::Arc::clone(&self.user_setting));
            // The plan is asked for as the caller, because row-level security
            // changes what the planner expects to return.
            let query = attach_binds(
                sql_query(format!("EXPLAIN (FORMAT JSON) {select_sql}"))
                    .into_boxed::<diesel::pg::Pg>(),
                binds.to_vec(),
            );
            // Measured 2026-08-21, and it decides the shape of this method: the
            // planner's own width counts a value stored out of line as its
            // pointer, so a table of four-kilobyte rows predicted 22 bytes a
            // row. Sizing a page from that alone would fetch a thousand times
            // the budget. The table's physical size over its row count includes
            // what is stored out of line, so the wider of the two is used, and
            // a table whose row count is unknown reads as one row wide, which
            // errs towards a small page.
            //
            // The name is bare, because the catalog knows tables by their bare
            // name, so `regclass` resolves it through the reading role's own
            // search path, and a deployment whose tables sit outside that path
            // resolves nothing. So this read is an improvement to the estimate
            // rather than a condition of serving: it runs on its own and its
            // failure costs the physical half, never the subscription.
            let physical = sql_query(
                "SELECT CASE WHEN c.reltuples > 0 \
                 THEN (pg_table_size(c.oid) / c.reltuples)::bigint \
                 ELSE pg_table_size(c.oid)::bigint END AS bytes \
                 FROM pg_class c WHERE c.oid = $1::regclass",
            )
            .into_boxed::<diesel::pg::Pg>()
            .bind::<Text, _>(table.clone());
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;
            let plan = conn
                .transaction::<PlanRow, diesel::result::Error, _>(|c| {
                    async move {
                        sql_query("SET TRANSACTION READ ONLY").execute(c).await?;
                        binding.apply(c).await?;
                        query.get_result(c).await
                    }
                    .scope_boxed()
                })
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;
            let physical = conn
                .transaction::<WidthRow, diesel::result::Error, _>(|c| {
                    async move {
                        sql_query("SET TRANSACTION READ ONLY").execute(c).await?;
                        physical.get_result(c).await
                    }
                    .scope_boxed()
                })
                .await;
            let mut estimate = plan_estimate(&plan.plan)?;
            match physical {
                Ok(physical) => {
                    estimate.width = estimate
                        .width
                        .max(u32::try_from(physical.bytes.max(0)).unwrap_or(u32::MAX));
                }
                Err(err) => {
                    tracing::debug!(
                        table = %table,
                        error = %err,
                        "the table's physical size is unreadable, so the page is sized from the planner's width alone and then from what the first page measures"
                    );
                }
            }
            Ok(estimate)
        }

        async fn snapshot_page(
            &self,
            select_sql: &str,
            binds: &[BindValue],
            caller: &Principal<Id, Key>,
            page: &PageSpec,
        ) -> Result<SnapshotPage, Self::Error> {
            let plan = self.plan_page(select_sql, binds, page)?;
            let PagePlan {
                table,
                table_id,
                key,
                pageable,
                query,
            } = plan;
            let max_rows = page.max_rows.max(1);
            let binding = CallerBinding::of(caller, std::sync::Arc::clone(&self.user_setting));
            // Milliseconds, and never zero: Postgres reads zero as no limit
            // at all, which is the opposite of a tight budget.
            let timeout_ms = u64::try_from(page.timeout.as_millis())
                .unwrap_or(u64::MAX)
                .max(1);
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;
            let (read, lsn) = conn
                .transaction::<(BinaryRows, String), diesel::result::Error, _>(|c| {
                    async move {
                        // Pin one MVCC snapshot so this page's rows and its LSN
                        // agree. Successive pages are separate moments by
                        // design (R58 decision 9): a page is read after every
                        // frame already sent, so it can never carry a value
                        // older than one the client has applied.
                        sql_query("SET TRANSACTION READ ONLY ISOLATION LEVEL REPEATABLE READ")
                            .execute(c)
                            .await?;
                        // The row cap bounds connetto's memory and the wire and
                        // not Postgres's work: a sort on an unindexed column
                        // reads the whole table to return a capped page, so the
                        // dimension the cap leaves open is bounded here.
                        sql_query(format!("SET LOCAL statement_timeout = {timeout_ms}"))
                            .execute(c)
                            .await?;
                        // Establish the requesting caller's RLS context so the
                        // read returns only rows it may see.
                        binding.apply(c).await?;
                        let read = BinaryRows::load(c, query).await?;
                        let lsn: LsnRow = sql_query("SELECT pg_current_wal_lsn()::text AS lsn")
                            .get_result(c)
                            .await?;
                        Ok((read, lsn.lsn))
                    }
                    .scope_boxed()
                })
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;

            // A page that filled is reported as filled whether or not it can
            // resume, so the caller refuses a read it cannot page rather than
            // taking these rows for a complete answer.
            let filled = read.rows.len() > max_rows as usize;
            let rows = &read.rows[..read.rows.len().min(max_rows as usize)];
            let sizes = rows.iter().map(|row| {
                row.iter()
                    .map(|cell| cell.as_ref().map_or(0, |value| value.len() as u64))
                    .sum::<u64>()
            });
            let (widest_row, bytes) = sizes.fold((0, 0), |(widest, total): (u64, u64), size| {
                (widest.max(size), total.saturating_add(size))
            });
            // A zero-row page carries no names either, and the encoder returns
            // an empty patchset for that, which is correct (nothing to insert).
            let row_cells: Vec<Vec<Option<&[u8]>>> = rows
                .iter()
                .map(|row| row.iter().map(|cell| cell.as_deref()).collect())
                .collect();
            let built = subql::emit::pgbinary_patchset_builder(
                &self.catalog,
                &table,
                &read.column_names(),
                &row_cells,
            )
            .map_err(|err| SnapshotError::Encode(err.to_string()))?;
            let next = if filled && pageable {
                let Some(PatchsetOp::Insert { values, .. }) = built.iter().last() else {
                    return Err(SnapshotError::Encode(
                        "a filled page produced no insert to resume from".into(),
                    ));
                };
                let row = crate::pk::row_from_wire(&self.catalog, table_id, values);
                Some(PageKey {
                    values: key
                        .iter()
                        .map(|column| {
                            row.get(usize::from(*column))
                                .cloned()
                                .unwrap_or(Value::Missing)
                        })
                        .collect(),
                })
            } else {
                None
            };
            let cursor = PgLsn::parse(&lsn)
                .map(|lsn| lsn.0.to_be_bytes().to_vec())
                .unwrap_or_default();
            Ok(SnapshotPage {
                patchset: built.build(),
                cursor: Cursor::new(cursor),
                next,
                filled,
                widest_row,
                rows: u32::try_from(rows.len()).unwrap_or(u32::MAX),
                bytes,
            })
        }

        async fn term_seed(
            &self,
            seed_sql: &str,
            member_table: &str,
            caller: &Principal<Id, Key>,
        ) -> Result<Option<TermSeedRead>, SnapshotError> {
            let binding = CallerBinding::of(caller, std::sync::Arc::clone(&self.user_setting));
            let seed = seed_sql.to_owned();
            let probe_table = member_table.to_owned();
            let publication = self.publication.clone();
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;
            let (read, published) = conn
                .transaction::<(BinaryRows, Option<bool>), diesel::result::Error, _>(|c| {
                    async move {
                        sql_query("SET TRANSACTION READ ONLY").execute(c).await?;
                        // The caller's own binding, so the seed and the
                        // snapshot answer from the same identity by
                        // construction.
                        binding.apply(c).await?;
                        // Raw SQL for the same reason the snapshot read is:
                        // the query text and the table it reads come from the
                        // deployment's runtime DDL, so no `table!` schema can
                        // name them at compile time.
                        let read =
                            BinaryRows::load(c, sql_query(seed).into_boxed::<diesel::pg::Pg>())
                                .await?;
                        // The publication probe is typed against preflight's
                        // modelled catalog view, in the same transaction as
                        // the seed so the two answers name one moment.
                        let published = match publication {
                            Some(publication) => {
                                use crate::preflight::pg_publication_tables as pubs;
                                let present: bool = diesel::select(diesel::dsl::exists(
                                    pubs::table
                                        .filter(pubs::pubname.eq(&*publication))
                                        .filter(pubs::tablename.eq(&probe_table)),
                                ))
                                .get_result(c)
                                .await?;
                                Some(present)
                            }
                            None => None,
                        };
                        Ok((read, published))
                    }
                    .scope_boxed()
                })
                .await
                .map_err(|err| SnapshotError::Backend(err.to_string()))?;
            // Lower through the same encoder the snapshot uses, so a seed
            // value and the same value delivered on the change path are one
            // value, and the term lookup keyed by it matches.
            let column_names = read.column_names();
            let cells = read.cells();
            let mut decoded = Vec::with_capacity(cells.len());
            if !cells.is_empty() {
                let member_table_id = catalog_helpers::table_id(&self.catalog, member_table);
                let built = subql::emit::pgbinary_patchset_builder(
                    &self.catalog,
                    member_table,
                    &column_names,
                    &cells,
                )
                .map_err(|err| SnapshotError::Encode(err.to_string()))?;
                for op in built.iter() {
                    let PatchsetOp::Insert { values, .. } = op else {
                        return Err(SnapshotError::Encode(
                            "the seed encoder produced something other than an insert".into(),
                        ));
                    };
                    let row = match member_table_id {
                        Some(table_id) => crate::pk::row_from_wire(&self.catalog, table_id, values),
                        None => values
                            .iter()
                            .map(|value| crate::pk::from_wire(value, None))
                            .collect(),
                    };
                    decoded.push(row);
                }
            }
            Ok(Some(TermSeedRead {
                rows: decoded,
                published,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{page_sql, projection_exposes};

    /// A page is cut by a keyset comparison, never by an offset, because the
    /// cost of an offset grows with the page's position: measured at 703 ms for
    /// the thousandth page of a two-million-row table against 0.377 ms for a
    /// keyset page anywhere in it.
    #[test]
    fn a_page_never_uses_an_offset() {
        let first = page_sql("SELECT * FROM orders", &["id".to_owned()], None, 100);
        let next = page_sql(
            "SELECT * FROM orders",
            &["id".to_owned()],
            Some("(\"id\") > ($1)"),
            100,
        );
        for sql in [&first, &next] {
            assert!(
                !sql.to_uppercase().contains("OFFSET"),
                "a page must not offset: {sql}"
            );
        }
        assert!(
            next.contains("(\"id\") > ($1)") && next.contains("ORDER BY \"id\""),
            "a resumed page carries the keyset predicate and its ordering: {next}"
        );
        assert!(
            first.contains("ORDER BY \"id\"") && first.contains("LIMIT 100"),
            "the first page orders by the resume key and caps its rows: {first}"
        );
    }

    /// A composite key orders and resumes on every column, in key order.
    #[test]
    fn a_composite_key_orders_on_every_column() {
        let sql = page_sql(
            "SELECT * FROM lines",
            &["order_id".to_owned(), "line".to_owned()],
            Some("(\"order_id\", \"line\") > ($1, $2)"),
            10,
        );
        assert!(
            sql.contains("ORDER BY \"order_id\", \"line\""),
            "both key columns order the page: {sql}"
        );
    }

    /// With no key there is nothing to resume from, so the read is one capped
    /// page and the wrap carries no ordering.
    #[test]
    fn a_keyless_read_is_one_capped_page() {
        let sql = page_sql("SELECT * FROM audit", &[], None, 50);
        assert!(
            !sql.contains("ORDER BY") && sql.contains("LIMIT 50"),
            "a keyless page is capped and unordered: {sql}"
        );
    }

    /// A page can only name what the inner query returns, so the projection
    /// decides whether a read is pageable at all.
    #[test]
    fn only_a_projection_carrying_the_key_can_be_paged() {
        let key = vec!["id".to_owned()];
        assert!(projection_exposes("SELECT * FROM orders", &key));
        assert!(projection_exposes("SELECT t.* FROM orders t", &key));
        assert!(projection_exposes(
            "SELECT \"t\".\"id\", \"t\".\"total\" FROM \"orders\" \"t\"",
            &key
        ));
        assert!(projection_exposes("SELECT id AS id FROM orders", &key));
        assert!(
            !projection_exposes("SELECT total FROM orders", &key),
            "a projection without the key cannot be resumed"
        );
        assert!(
            !projection_exposes("SELECT COUNT(*) FROM orders", &key),
            "an expression is not a key column"
        );
        assert!(
            !projection_exposes("SELECT ((( FROM", &key),
            "an unparseable query exposes nothing"
        );
    }
}
