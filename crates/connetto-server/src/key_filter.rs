//! The primary-key equality filter every caller-scoped Postgres read builds.
//!
//! The table and its key columns come from the deployment's own runtime DDL, so
//! there is no `table!` schema to express these reads against and they are raw
//! SQL. This is the one place that renders the predicate and binds the values,
//! so the visibility check and the row the minting path reads cannot drift
//! apart. Identifiers come from the parsed catalog and every value binds
//! positionally with the scalar type the catalog gave it, so the row's own
//! primary-key index answers the read.

use core::fmt::Write as _;

use connetto_core::quote_ident;
use diesel::pg::Pg;
use diesel::query_builder::{BoxedSqlQuery, SqlQuery};
use diesel::sql_types::{BigInt, Binary, Bool, Double, Text};
use subql::backend::{Postgres, Value};
use subql::{ColumnId, DatabaseLike, TableId, ValueError, catalog_helpers};

/// A key column could not be read, or carried a type the filter cannot bind.
#[derive(Debug, thiserror::Error)]
pub(crate) enum KeyError {
    /// A primary-key cell of the row could not be decoded.
    #[error(transparent)]
    Value(#[from] ValueError),
    /// A primary-key column has a type the filter cannot bind yet.
    #[error("unsupported primary-key type {kind} on table {table}")]
    Unsupported {
        /// Table whose key could not be bound.
        table: String,
        /// The scalar kind that is not yet bindable.
        kind: String,
    },
}

/// One primary-key value in a shape the filter can bind.
///
/// The bindable set is exactly this enum, so an unsupported key type is
/// reported once while the filter is built rather than rediscovered per use.
enum KeyBind {
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Uuid(uuid::Uuid),
}

/// One row's key columns, in key order, with the value each binds.
type CollectedKey = (Vec<String>, Vec<KeyBind>);

/// A predicate over a table's primary key, plus the values it binds.
///
/// Two shapes, both key-shaped and both answered by the primary-key index:
/// [`build`](Self::build) renders `"col" = $1 AND "col2" = $2` to name one
/// row, and [`after`](Self::after) renders `("col", "col2") > ($1, $2)` to
/// resume a snapshot page past the last row it delivered (R58).
pub(crate) struct KeyFilter {
    predicate: String,
    binds: Vec<KeyBind>,
}

impl KeyFilter {
    /// Build the filter for `table`'s primary key, reading each key cell
    /// through `value_at`.
    ///
    /// [`None`] where no row can be named at all: a table with no primary key,
    /// or a key cell carrying no value. Every caller treats that as a denial,
    /// which is what asking the database would have returned.
    pub(crate) fn build<DB, F>(
        catalog: &DB,
        table_id: TableId,
        table: &str,
        value_at: F,
    ) -> Result<Option<Self>, KeyError>
    where
        DB: DatabaseLike,
        F: FnMut(usize, ColumnId) -> Result<Value<Postgres>, ValueError>,
    {
        let Some((columns, binds)) = Self::collect(catalog, table_id, table, value_at)? else {
            return Ok(None);
        };
        let mut predicate = String::new();
        for (position, name) in columns.iter().enumerate() {
            if position > 0 {
                predicate.push_str(" AND ");
            }
            let _ = write!(predicate, "{} = ${}", quote_ident(name), position + 1);
        }
        Ok(Some(Self { predicate, binds }))
    }

    /// The keyset predicate resuming past one row: a row-value comparison
    /// over the whole primary key, with placeholders starting at `first` so
    /// the subscription's own binds keep the numbers they were translated
    /// with.
    ///
    /// A row-value comparison is lexicographic, which is the order a
    /// composite key's own index is in, so a page resumes at one index
    /// descent whatever the key's arity.
    ///
    /// [`None`] on the same terms as [`build`](Self::build).
    pub(crate) fn after<DB, F>(
        catalog: &DB,
        table_id: TableId,
        table: &str,
        first: usize,
        value_at: F,
    ) -> Result<Option<Self>, KeyError>
    where
        DB: DatabaseLike,
        F: FnMut(usize, ColumnId) -> Result<Value<Postgres>, ValueError>,
    {
        let Some((columns, binds)) = Self::collect(catalog, table_id, table, value_at)? else {
            return Ok(None);
        };
        let names = columns
            .iter()
            .map(|name| quote_ident(name))
            .collect::<Vec<_>>()
            .join(", ");
        let places = (first..first + columns.len())
            .map(|place| format!("${place}"))
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Some(Self {
            predicate: format!("({names}) > ({places})"),
            binds,
        }))
    }

    /// Read every key cell of the row through `value_at`, in key order.
    ///
    /// [`None`] where no row can be named at all: a table with no primary
    /// key, a key cell carrying no value, or a key column the catalog cannot
    /// name.
    fn collect<DB, F>(
        catalog: &DB,
        table_id: TableId,
        table: &str,
        mut value_at: F,
    ) -> Result<Option<CollectedKey>, KeyError>
    where
        DB: DatabaseLike,
        F: FnMut(usize, ColumnId) -> Result<Value<Postgres>, ValueError>,
    {
        let columns = catalog_helpers::primary_key_columns(catalog, table_id).unwrap_or_default();
        if columns.is_empty() {
            return Ok(None);
        }
        let mut binds = Vec::with_capacity(columns.len());
        let mut names = Vec::with_capacity(columns.len());
        for (position, column) in columns.into_iter().enumerate() {
            let bind = match value_at(position, column)? {
                Value::Bool(value) => KeyBind::Bool(value),
                Value::Int(value) => KeyBind::Int(value),
                Value::Float(value) => KeyBind::Float(value),
                Value::String(value) => KeyBind::Text(value),
                Value::Bytes(value) => KeyBind::Bytes(value),
                Value::Uuid(value) => KeyBind::Uuid(value),
                Value::Null | Value::Missing => return Ok(None),
                other => {
                    return Err(KeyError::Unsupported {
                        table: table.to_owned(),
                        kind: format!("{:?}", other.scalar_kind()),
                    });
                }
            };
            let Some(name) = catalog_helpers::column_name(catalog, table_id, column) else {
                return Ok(None);
            };
            names.push(name);
            binds.push(bind);
        }
        Ok(Some((names, binds)))
    }

    /// The rendered `WHERE` body, with `$n` placeholders in bind order.
    pub(crate) fn predicate(&self) -> &str {
        &self.predicate
    }

    /// Attach the key values to `query`, in placeholder order.
    pub(crate) fn bind<'a>(
        &self,
        query: BoxedSqlQuery<'a, Pg, SqlQuery>,
    ) -> BoxedSqlQuery<'a, Pg, SqlQuery> {
        self.binds.iter().fold(query, |query, value| match value {
            KeyBind::Bool(value) => query.bind::<Bool, _>(*value),
            KeyBind::Int(value) => query.bind::<BigInt, _>(*value),
            KeyBind::Float(value) => query.bind::<Double, _>(*value),
            KeyBind::Text(value) => query.bind::<Text, _>(value.clone()),
            KeyBind::Bytes(value) => query.bind::<Binary, _>(value.clone()),
            KeyBind::Uuid(value) => query.bind::<diesel::sql_types::Uuid, _>(*value),
        })
    }
}
