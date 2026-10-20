//! The replica's wall clock, which every countdown the replica stores reads.
//!
//! Native-only code may read the host clock, as certificate windows and the
//! away gate do, and wasm code never calls `SystemTime::now`, which panics in
//! the browser (`docs/architecture/21-clocks.md`).

use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;

use crate::ClientError;

/// Seconds since the epoch, read from SQLite rather than from the host.
///
/// # Errors
///
/// [`ClientError::Session`] when the replica cannot be read.
pub(crate) fn now_secs(db: &mut SqliteConnection) -> Result<i64, ClientError> {
    // A scalar SELECT over a SQLite built-in with no table to name, so there is
    // no `table!` for the DSL to go through.
    #[derive(diesel::QueryableByName)]
    struct Now {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        secs: i64,
    }
    let row: Now =
        diesel::sql_query("SELECT CAST(strftime('%s','now') AS INTEGER) AS secs").get_result(db)?;
    Ok(row.secs)
}
