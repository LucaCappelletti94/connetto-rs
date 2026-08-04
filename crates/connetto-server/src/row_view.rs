//! A row view over values connetto already holds.
//!
//! subql views a replication event through its own `EventRow`, which covers the
//! change and the catchup paths. The write path holds an uploaded op and the
//! minting path a row it read back, and neither is an event, so both view their
//! values through [`ValuesRow`].

use subql::backend::{Postgres, Value};
use subql::visibility::RowView;
use subql::{ColumnId, TableId, ValueError};

/// One row's column values in catalog column order.
///
/// Reading a column clones its value, which is what
/// [`RowView::value_at`] returns, so nothing is copied for a column nobody
/// asks about.
pub struct ValuesRow<'a> {
    table: TableId,
    values: &'a [Value<Postgres>],
}

impl<'a> ValuesRow<'a> {
    /// View `values` as the row of `table`, indexed by column ordinal.
    pub const fn new(table: TableId, values: &'a [Value<Postgres>]) -> Self {
        Self { table, values }
    }
}

impl RowView for ValuesRow<'_> {
    type Backend = Postgres;

    fn table_id(&self) -> TableId {
        self.table
    }

    fn value_at(&self, col: ColumnId) -> Result<Value<Postgres>, ValueError> {
        Ok(self
            .values
            .get(usize::from(col))
            .cloned()
            .unwrap_or(Value::Missing))
    }
}
