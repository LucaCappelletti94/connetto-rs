//! SQL expressions for the database's own clock (chapter 21, class H).
//!
//! A deadline that Postgres holds is written as `now() + interval` and
//! compared against Postgres `now()` in the statement that reads it. The
//! process clock never appears on either side of such a comparison. A
//! statement needing the interval form writes the literal inline, since the
//! chained `bind` call shapes the expression the query builder types.

use diesel::dsl::sql;
use diesel::expression::SqlLiteral;
use diesel::sql_types::Timestamptz;

/// [`connetto_core::clock::DEVICE_SKEW`] in seconds, for `make_interval`.
pub const DEVICE_SKEW_SECS: f64 = connetto_core::clock::DEVICE_SKEW.as_secs_f64();

/// The database's current time, typed for a `TIMESTAMPTZ` column.
pub fn now() -> SqlLiteral<Timestamptz> {
    sql("now()")
}
